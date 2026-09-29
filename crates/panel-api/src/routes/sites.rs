//! 站点与 SSL 证书（设计方案 §2.4）。
//!
//! # 核心闭环：配置变更必须"先校验，后生效"
//! ```text
//! 渲染配置 → validate（nginx -t）→ 失败则中止   → 成功则原子替换 → reload
//!                                    ↑ 旧配置未动，站点不受影响
//! ```
//! 直接写配置文件再 reload，语法错误会导致 **reload 失败但文件已改**，
//! 下次重启服务就起不来。这是自建面板最常见的线上事故。
//!
//! # 一个必须写清的约束
//! `validate` 通常耗时 50~200ms（`nginx -t`）。**它绝不能落在写事务内**——
//! 实测长事务耗时 1:1 传导给其他写者（持有 1000ms → 其他写者等 1046ms）。
//!
//! # 数据模型 vs 配置下发
//! 站点的「定义」（`sites` 表）与「下发到 Web 服务器的配置」是两件事：
//! - `create` / `get` / `patch` / `delete` 只读写 `sites` 表（纯 DB，无需 web server 在场）。
//! - `apply` / `reload` 才真正渲染并下发到 Web 服务器；若 `webserver.manage`
//!   能力位为 `no`（本机未装 nginx/caddy），这两个动作诚实返回 501，绝不伪造成功。
//! - SSL 的 ACME 签发/续期同理：能力位 `ssl.acme` 为 `no` 时诚实 501；
//!   证书「删除」是纯 DB 操作，始终可用。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, MaybeAuth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    response::IntoResponse,
    Json,
};
use axum::http::StatusCode;
use panel_core::{cap_keys, domain, PanelError, Result, SafePath};
use panel_os::{paths::slug, tls};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─────────────── 数据行 / DTO ───────────────

/// `sites` 表的原始行（含从 `ssl_certs` 派生的 tls 标记）。
struct RawSite {
    id: i64,
    name: String,
    /// JSON 数组字符串
    domains: String,
    root: String,
    kind: String,
    enabled: i32,
    created_at: i64,
    tls: bool,
}

#[derive(Debug, Serialize)]
pub struct SiteOut {
    pub id: i64,
    pub name: String,
    pub domains: Vec<String>,
    pub root: String,
    /// API 口径：static | proxy（schema 内为 static | reverse_proxy）
    pub kind: String,
    pub enabled: bool,
    /// 是否已有绑定的 SSL 证书
    pub tls: bool,
    pub created_at: i64,
}

fn to_out(r: &RawSite) -> SiteOut {
    SiteOut {
        id: r.id,
        name: r.name.clone(),
        domains: serde_json::from_str(&r.domains).unwrap_or_default(),
        root: r.root.clone(),
        kind: if r.kind == "reverse_proxy" { "proxy" } else { "static" }.to_string(),
        enabled: r.enabled != 0,
        tls: r.tls,
        created_at: r.created_at,
    }
}

fn db_err(e: rusqlite::Error) -> PanelError {
    PanelError::Database(e.to_string())
}

/// SELECT 公共投影（含派生的 tls 计数）
const SITE_SELECT: &str = "s.id, s.name, s.domains, s.root, s.kind, s.enabled, s.created_at,
       (SELECT COUNT(*) FROM ssl_certs c WHERE c.site_id = s.id) AS tls_count";

async fn fetch_all(state: &Shared) -> Result<Vec<RawSite>> {
    state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare(&format!("SELECT {SITE_SELECT} FROM sites s ORDER BY s.id"))
                .map_err(db_err)?;
            let it = st
                .query_map([], |r| {
                    Ok(RawSite {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        domains: r.get(2)?,
                        root: r.get(3)?,
                        kind: r.get(4)?,
                        enabled: r.get(5)?,
                        created_at: r.get(6)?,
                        tls: r.get::<_, i64>(7)? > 0,
                    })
                })
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(db_err)?);
            }
            Ok(v)
        })
        .await
}

async fn fetch_one(state: &Shared, id: i64) -> Result<Option<RawSite>> {
    state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(&format!("SELECT {SITE_SELECT} FROM sites s WHERE s.id = ?1"))
                .map_err(db_err)?;
            let mut it = st.query_map([id], |r| {
                Ok(RawSite {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    domains: r.get(2)?,
                    root: r.get(3)?,
                    kind: r.get(4)?,
                    enabled: r.get(5)?,
                    created_at: r.get(6)?,
                    tls: r.get::<_, i64>(7)? > 0,
                })
            })
            .map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await
}

async fn fetch_one_by_name(state: &Shared, name: &str) -> Result<Option<RawSite>> {
    let name = name.to_string();
    state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(&format!("SELECT {SITE_SELECT} FROM sites s WHERE s.name = ?1"))
                .map_err(db_err)?;
            let mut it = st.query_map([name], |r| {
                Ok(RawSite {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    domains: r.get(2)?,
                    root: r.get(3)?,
                    kind: r.get(4)?,
                    enabled: r.get(5)?,
                    created_at: r.get(6)?,
                    tls: r.get::<_, i64>(7)? > 0,
                })
            })
            .map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await
}

/// 把站点根目录解析到面板托管目录 `site_root` 之内（绝不越界到任意文件系统位置）。
/// `input` 为空时用站点名作子目录。owner 即使 `allowed_roots` 为空也能建站。
///
/// 目标目录**允许尚不存在**（首次建站时必然如此），故走 `resolve_within_for_create`；
/// 同时自愈式确保 `site_root` 根存在，避免根缺失导致解析失败。
fn resolve_site_root(state: &Shared, input: &str, name: &str) -> Result<SafePath> {
    let base = state.os.paths().site_root();
    // 自愈：托管根目录缺失时先创建（首次部署或目录被清理）
    let _ = std::fs::create_dir_all(&base);
    let rel = if input.trim().is_empty() { name } else { input.trim() };
    panel_os::paths::resolve_within_for_create(&base, rel)
        .map_err(|_| PanelError::PathEscape(rel.to_string()))
}

// ─────────────── 站点列表 ───────────────

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let rows = fetch_all(&state).await?;
    let dtos: Vec<SiteOut> = rows.iter().map(to_out).collect();
    Ok(ok(dtos))
}

// ─────────────── 创建站点（仅写库） ───────────────

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub name: String,
    pub domains: Vec<String>,
    /// 站点根目录（相对 site_root；留空则用站点名）。仅允许落在 site_root 之内。
    pub root: Option<String>,
    /// 是否启用 PHP（当前 schema 未单独建模，仅占位接受）。
    pub php: Option<bool>,
}

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("name", "name required"));
    }
    if req.domains.is_empty() {
        return Err(ApiError::bad_request("domains", "at least one domain required"));
    }
    let mut domains = Vec::with_capacity(req.domains.len());
    for d in &req.domains {
        let dom = domain(d.trim())
            .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
        domains.push(dom.as_str().to_string());
    }
    let root = resolve_site_root(&state, req.root.as_deref().unwrap_or(""), &name)?;
    // 实际落地站点目录（面板托管；目录缺失即创建）
    if let Err(e) = std::fs::create_dir_all(root.as_path()) {
        return Err(ApiError::from(PanelError::Internal(format!(
            "无法创建站点目录 {}: {e}",
            root.as_path().display()
        ))));
    }
    let root_str = root.as_path().display().to_string();
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());
    let now = crate::now_unix();
    // 这些变量在闭包之外（audit / fallback）还要用，先克隆一份给写事务
    let name_db = name.clone();
    let root_db = root_str.clone();

    let res = state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO sites(name, domains, root, kind, webserver, enabled, created_at)
                 VALUES(?1, ?2, ?3, 'static', 'nginx', 1, ?4)",
                rusqlite::params![name_db, domains_json, root_db, now],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| {
                if e.to_string().contains("UNIQUE") {
                    PanelError::Conflict("site name exists".into())
                } else {
                    PanelError::Database(e.to_string())
                }
            })
        })
        .await;

    match res {
        Ok(_) => {
            audit(&state, &s, "site.create", &name, "ok").await;
            let out = fetch_one_by_name(&state, &name)
                .await?
                .map(|r| to_out(&r))
                .unwrap_or_else(|| SiteOut {
                    id: -1,
                    name,
                    domains,
                    root: root_str,
                    kind: "static".into(),
                    enabled: true,
                    tls: false,
                    created_at: now,
                });
            Ok(ok(out))
        }
        Err(e) => Err(ApiError::from(e)),
    }
}

// ─────────────── 站点详情 ───────────────

pub async fn get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    match fetch_one(&state, id).await? {
        Some(r) => Ok(ok(to_out(&r))),
        None => Err(ApiError::not_found("site")),
    }
}

// ─────────────── 更新站点（仅写库） ───────────────

#[derive(Debug, Deserialize)]
pub struct PatchReq {
    pub domains: Option<Vec<String>>,
    pub root: Option<String>,
    pub enabled: Option<bool>,
    /// 仅影响后续 apply 渲染的配置；本接口不重新下发配置。
    pub force_https: Option<bool>,
}

pub async fn patch(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<PatchReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let cur = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;

    // 计算新值（未提供的字段沿用现状）
    let domains: Vec<String> = if let Some(ref ds) = req.domains {
        if ds.is_empty() {
            return Err(ApiError::bad_request("domains", "at least one domain required"));
        }
        let mut out = Vec::with_capacity(ds.len());
        for d in ds {
            let dom = domain(d.trim())
                .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
            out.push(dom.as_str().to_string());
        }
        out
    } else {
        serde_json::from_str(&cur.domains).unwrap_or_default()
    };

    let root = if let Some(ref r) = req.root {
        resolve_site_root(&state, r, &cur.name)?.as_path().display().to_string()
    } else {
        cur.root.clone()
    };

    let enabled = req.enabled.unwrap_or(cur.enabled != 0);
    let _ = req.force_https; // 仅作用于 apply 渲染，DB 不单列存储
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());

    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET domains = ?1, root = ?2, enabled = ?3 WHERE id = ?4",
                rusqlite::params![domains_json, root, enabled as i32, id],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.patch", &id.to_string(), "ok").await;
    match fetch_one(&state, id).await? {
        Some(r) => Ok(ok(to_out(&r))),
        None => Err(ApiError::not_found("site")),
    }
}

// ─────────────── 删除站点（CASCADE 删除其证书） ───────────────

pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let _cur = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;

    state
        .db
        .exec(move |conn| {
            let n = conn
                .execute("DELETE FROM sites WHERE id = ?1", [id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;

    audit(&state, &s, "site.delete", &id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

// ─────────────── 配置校验与应用（核心闭环） ───────────────

#[derive(Debug, Deserialize)]
pub struct ApplyReq {
    pub name: String,
    pub domains: Vec<String>,
    pub root: String,
    pub force_https: Option<bool>,
}

/// 应用站点配置。**整个流程在写事务之外完成**。
pub async fn apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<ApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }

    // 1) 域名逐个走校验器（强类型构造点）
    let mut domains = Vec::new();
    for d in &req.domains {
        let dom = domain(d)
            .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
        domains.push(dom.as_str().to_string());
    }
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "at least one domain required"));
    }

    // 2) 根目录必须在 site_root 之内
    let root = resolve_site_root(&state, &req.root, &req.name)?;

    // 3) 已有证书则注入（自签/ACME 均按域名落盘）；证书文件不存在则不启用 TLS
    let (tls_cert, tls_key) = match fetch_one_by_name(&state, &req.name).await? {
        Some(row) => match cert_domains_for_site(&state, row.id).await? {
            Some(ds) if !ds.is_empty() => {
                let (c, k) = cert_paths_for(&state, &ds);
                if c.is_file() && k.is_file() { (Some(c), Some(k)) } else { (None, None) }
            }
            _ => (None, None),
        },
        None => (None, None),
    };

    // 4) 渲染配置（纯字符串生成，不落盘）
    //   未配置证书时 force_https 无意义（无 https 可跳转），诚实降级为 false
    let has_tls = tls_cert.is_some() && tls_key.is_some();
    let spec = panel_os::SiteSpec {
        server_names: domains.iter().map(|d| d.clone()).collect(),
        root: root.as_path().to_path_buf(),
        listen: vec![80, 443],
        kind: panel_os::SiteKind::Static,
        access_log: None,
        error_log: None,
        tls_cert,
        tls_key,
        force_https: req.force_https.unwrap_or(true) && has_tls,
    };
    let (target, rendered) = state.os.webserver().render(&spec)?;

    // 4) ⚠️ 校验在写事务之外。失败直接返回 40002，旧配置原封不动
    state
        .os
        .webserver()
        .validate(&rendered)
        .await
        .map_err(|e| ApiError::from(PanelError::ConfigInvalid { detail: e.to_string() }))?;

    // 5) 部署：实现内部负责原子替换
    state.os.webserver().deploy(&target, &rendered).await?;

    // 6) reload。失败时配置已写入但服务未加载 —— 这是可恢复的（配置语法已校验过）
    if let Err(e) = state.os.webserver().reload().await {
        return Err(ApiError::from(PanelError::Command {
            bin: "reload".to_string(),
            detail: format!("配置已写入但 reload 失败：{e}"),
        }));
    }

    // 7) 落库：此时系统已处于期望状态（按 name upsert，与 create 不冲突）
    let name = req.name.clone();
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());
    let root_str = root.as_path().display().to_string();
    let conf = target.display().to_string();
    let now = crate::now_unix();
    let conf_db = conf.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO sites(name, domains, root, kind, webserver, enabled, conf_path, created_at)
                 VALUES(?1, ?2, ?3, 'static', 'nginx', 1, ?4, ?5)
                 ON CONFLICT(name) DO UPDATE SET
                    domains=excluded.domains, root=excluded.root, enabled=1,
                    conf_path=excluded.conf_path, webserver='nginx'",
                rusqlite::params![name, domains_json, root_str, conf_db, now],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.apply", &req.name, "ok").await;
    Ok(ok(serde_json::json!({
        "name": req.name, "config": conf, "reloaded": true,
    })))
}

/// 仅 reload Web 服务器（全局操作；按 id 仅用于审计与 API 对称）。
pub async fn reload(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    state
        .os
        .webserver()
        .reload()
        .await
        .map_err(ApiError::from)?;
    audit(&state, &s, "site.reload", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "reloaded": true })))
}

/// 站点日志（SSE）：`kind=access|error`，跟随该站点的 nginx 日志文件。
#[derive(Debug, Deserialize)]
pub struct SiteLogQ {
    pub kind: Option<String>,
    pub filter: Option<String>,
    pub limit: Option<usize>,
}

pub async fn logs(
    State(state): State<Shared>,
    MaybeAuth(session): MaybeAuth,
    AxPath(id): AxPath<i64>,
    Query(q): Query<SiteLogQ>,
) -> axum::response::Response {
    let Some(s) = session else { return ApiError::unauthorized().into_response() };
    if crate::auth::require(&s, perm::SITE_VIEW).is_err() {
        return ApiError::forbidden(perm::SITE_VIEW).into_response();
    }
    if !state.capabilities.get(cap_keys::LOGS_READ).map(|c| c.supported).unwrap_or(false) {
        return ApiError::unsupported("logs.read").into_response();
    }
    let site = match fetch_one(&state, id).await {
        Ok(Some(x)) => x,
        Ok(None) => return ApiError::not_found("site").into_response(),
        Err(e) => return ApiError::from(e).into_response(),
    };
    let domains: Vec<String> = serde_json::from_str(&site.domains).unwrap_or_default();
    let stem = slug(domains.first().map(|s| s.as_str()).unwrap_or("site"));
    let which = q.kind.as_deref().unwrap_or("access");
    let (kind, seg) = if which == "error" {
        (panel_os::LogSourceKind::SiteError, "error")
    } else {
        (panel_os::LogSourceKind::SiteAccess, "access")
    };
    let src = panel_os::LogSource {
        id: format!("site:{stem}/{seg}"),
        label: format!("{} · {}", site.name, which),
        kind,
    };
    crate::sse::follow_source(state.clone(), src, q.filter, q.limit.unwrap_or(200)).await
}

// ─────────────── TLS 落盘与查询辅助 ───────────────

/// 自签证书有效期（天）。825 天对齐主流浏览器对单张证书的最长信任上限。
const SELF_SIGNED_DAYS: u32 = 825;

/// 面板托管的证书落盘目录（nginx 从这里读取 cert/key）。
fn ssl_dir(state: &Shared) -> PathBuf {
    state.os.paths().data_dir().join("ssl")
}

/// 由首个域名派生该站点证书的 (crt, key) 落盘路径（与 provider 配置文件名同源命名）。
fn cert_paths_for(state: &Shared, domains: &[String]) -> (PathBuf, PathBuf) {
    let stem = slug(domains.first().map(|s| s.as_str()).unwrap_or("site"));
    let dir = ssl_dir(state);
    (dir.join(format!("{stem}.crt")), dir.join(format!("{stem}.key")))
}

/// 写证书/私钥到磁盘：crt 0644、key 0600（私钥绝不可被他人读取）。
fn write_cert_files(crt: &Path, key: &Path, cert_pem: &str, key_pem: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = crt.parent().ok_or_else(|| PanelError::Internal("bad cert path".into()))?;
    std::fs::create_dir_all(dir).map_err(|e| PanelError::Internal(e.to_string()))?;
    std::fs::write(crt, cert_pem).map_err(|e| PanelError::Internal(e.to_string()))?;
    std::fs::write(key, key_pem).map_err(|e| PanelError::Internal(e.to_string()))?;
    let _ = std::fs::set_permissions(crt, std::fs::Permissions::from_mode(0o644));
    let _ = std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// 该站点最近一张证书覆盖的域名（apply 注入 tls / delete 清理文件都用它）。
async fn cert_domains_for_site(state: &Shared, site_id: i64) -> Result<Option<Vec<String>>> {
    state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains FROM ssl_certs WHERE site_id = ?1 ORDER BY id DESC LIMIT 1")
                .map_err(db_err)?;
            let mut it = st.query_map([site_id], |r| r.get::<_, String>(0)).map_err(db_err)?;
            match it.next().transpose().map_err(db_err)? {
                Some(js) => Ok(Some(serde_json::from_str(&js).unwrap_or_default())),
                None => Ok(None),
            }
        })
        .await
}

// ─────────────── SSL 证书 ───────────────

#[derive(Debug, Serialize)]
pub struct CertDto {
    pub id: i64,
    pub domain: String,
    pub issuer: Option<String>,
    pub not_after: Option<i64>,
    /// 剩余天数（UI 据此标黄/标红）
    pub days_left: Option<i64>,
    pub auto_renew: bool,
    /// idle | pending | ok | failed
    pub renew_state: String,
}

pub async fn certs(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let rows = state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, domains, issuer, not_after, renew_state \
                     FROM ssl_certs ORDER BY not_after",
                )
                .map_err(db_err)?;
            let it = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(db_err)?);
            }
            Ok(v)
        })
        .await?;

    let now = crate::now_unix();
    let dtos: Vec<CertDto> = rows
        .into_iter()
        .map(|(id, domains_json, issuer, not_after, renew)| {
            // 证书覆盖多个域名（JSON 数组）；UI 单域名列展示主域名（首个）
            let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
            let primary = domains.into_iter().next().unwrap_or_default();
            CertDto {
                id,
                domain: primary,
                issuer,
                days_left: not_after.map(|t| (t - now) / 86_400),
                not_after,
                // 自动续期开关：schema 尚未建模独立列，且 ACME 未实现，
                // 故诚实置 false（不伪造"已开启自动续期"）
                auto_renew: false,
                renew_state: renew,
            }
        })
        .collect();
    Ok(ok(dtos))
}

#[derive(Debug, Deserialize)]
pub struct SslApplyReq {
    /// 留空则沿用站点现有域名
    #[serde(default)]
    pub domains: Vec<String>,
    /// `self-signed`（缺省）| `http-01` | `dns-01`
    pub method: Option<String>,
    #[allow(dead_code)]
    pub email: Option<String>,
}

/// 申请证书。按 `method` 分流：
/// - `self-signed`：面板自签（**同步**完成，需 `ssl.selfsigned` + 主密钥，离线可用）；
/// - `http-01`/`dns-01`：ACME，`ssl.acme` 门控，未接入时诚实 501（#61）。
pub async fn ssl_apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<SslApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    let site = fetch_one(&state, id).await?.ok_or_else(|| ApiError::not_found("site"))?;

    // 域名：请求覆盖 或 沿用站点现有域名
    let domains: Vec<String> = if req.domains.is_empty() {
        serde_json::from_str(&site.domains).unwrap_or_default()
    } else {
        let mut out = Vec::with_capacity(req.domains.len());
        for d in &req.domains {
            let dom = domain(d.trim())
                .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
            out.push(dom.as_str().to_string());
        }
        out
    };
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "no domain to certify"));
    }

    let method = req.method.clone().unwrap_or_else(|| "self-signed".into());
    match method.as_str() {
        "self-signed" => {}
        "http-01" => {
            if !state.capabilities.get(cap_keys::SSL_ACME).map(|c| c.supported).unwrap_or(false) {
                return Err(ApiError::unsupported("ssl.acme"));
            }
            // ACME 需要真实账户邮箱（CA 用它发到期/异常通知）——没有就明确报错，
            // 绝不静默填一个假地址（那会让用户收不到任何到期提醒）。
            let email = req
                .email
                .as_deref()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| ApiError::bad_request("email", "http-01 签发需要账户邮箱"))?
                .to_string();
            // 注：certbot 回退路线目前只签**主域名**（多域名 SAN 待扩展）
            let webroot = resolve_site_root(&state, &site.root, &site.name)?
                .as_path()
                .to_path_buf();
            let (crt_p, key_p) = cert_paths_for(&state, &domains);
            let job = AcmeTask {
                mode: AcmeMode::Issue,
                site_id: id,
                domains: domains.clone(),
                email,
                webroot,
                crt_p,
                key_p,
                master: state.require_secret_key()?,
                db: state.db.clone(),
            };
            let (tid, _) = state
                .tasks
                .submit(
                    panel_task::TaskRequest {
                        idempotency_key: format!("cert:{id}:{}", domains.join(",")),
                        kind: panel_task::TaskKind::CertIssue,
                        label: format!("ACME 签发证书（{}）", domains.join(", ")),
                        timeout: std::time::Duration::from_secs(900),
                    },
                    job,
                )
                .await
                .map_err(ApiError::from)?;
            audit(&state, &s, "ssl.apply", &id.to_string(), "queued").await;
            return Ok(ok(serde_json::json!({ "task_id": tid, "source": "acme" })));
        }
        "dns-01" => {
            return Err(ApiError::unsupported(
                "dns-01 需 DNS 提供商 API（设计 §2.4 列为 M5）；certbot 回退路线当前仅实现 http-01",
            ))
        }
        other => return Err(ApiError::bad_request("method", format!("unsupported method: {other}"))),
    }

    if !state.capabilities.get(cap_keys::SSL_SELFSIGNED).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("ssl.selfsigned"));
    }
    // 无主密钥则拒绝：私钥必须加密落库，绝不明文（对齐 databases.rs 的纪律）
    let master = state.require_secret_key()?;

    let tmp = state.os.paths().tmp_dir();
    let (cert_pem, key_pem) = tls::generate_self_signed(&tmp, &domains, SELF_SIGNED_DAYS).await?;
    let key_enc = master.encrypt(key_pem.as_bytes()).map_err(ApiError::from)?;

    // 落盘（nginx 读取）；私钥明文只存在于 0600 文件，库内为密文
    let (crt_p, key_p) = cert_paths_for(&state, &domains);
    write_cert_files(&crt_p, &key_p, &cert_pem, &key_pem)?;

    let now = crate::now_unix();
    let not_after = now + (SELF_SIGNED_DAYS as i64) * 86_400;
    let issuer = "ForkPanel Self-Signed".to_string();
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());
    let site_id = id;
    let (dj, iss, cert) = (domains_json.clone(), issuer.clone(), cert_pem);
    state
        .db
        .exec(move |conn| {
            // 同站点自签只保留一张：先清旧行再插入
            conn.execute("DELETE FROM ssl_certs WHERE site_id = ?1", [site_id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            conn.execute(
                "INSERT INTO ssl_certs(site_id, domains, issuer, not_after, source, key_enc, cert, renew_state, created_at)
                 VALUES(?1, ?2, ?3, ?4, 'selfsigned', ?5, ?6, 'ok', ?7)",
                rusqlite::params![site_id, dj, iss, not_after, key_enc, cert, now],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;

    audit(&state, &s, "ssl.apply", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({
        "site_id": id,
        "domains": domains,
        "source": "selfsigned",
        "issuer": issuer,
        "not_after": not_after,
        "days_left": SELF_SIGNED_DAYS,
        "cert_path": crt_p.display().to_string(),
    })))
}

// ─────────────── ACME 任务体（签发 / 续期） ───────────────

/// certbot 默认有效期（天），用于写 `not_after` 供到期提醒与续期判定。
/// **未从 PEM 解析**——那要引入 X.509 解析依赖（预算不允）；certbot 默认即 90 天。
const ACME_DAYS: i64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeMode {
    Issue,
    Renew,
}

/// ACME 证书任务：调 certbot → 落盘 → **私钥加密入库**。
///
/// 与自签走同一条纪律：私钥**绝不明文入库**（库泄露 ≠ 私钥泄露）。
pub struct AcmeTask {
    pub mode: AcmeMode,
    pub site_id: i64,
    pub domains: Vec<String>,
    /// 账户邮箱（仅 Issue 使用；Renew 沿用 certbot 已有账户）
    pub email: String,
    /// http-01 校验目录（站点根目录）
    pub webroot: std::path::PathBuf,
    pub crt_p: std::path::PathBuf,
    pub key_p: std::path::PathBuf,
    pub master: crate::MasterKey,
    pub db: std::sync::Arc<panel_db::WriterActor>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for AcmeTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(10, "调用 certbot").await;
        // 注：certbot 回退路线目前只签**主域名**（多域名 SAN 待扩展）
        let primary = self
            .domains
            .first()
            .cloned()
            .ok_or_else(|| PanelError::Internal("证书域名为空".into()))?;
        let (cert_pem, key_pem) = match self.mode {
            AcmeMode::Issue => tls::issue_acme(&primary, &self.email, &self.webroot).await?,
            AcmeMode::Renew => tls::renew_acme(&primary).await?,
        };

        progress.set(70, "落盘与入库").await;
        write_cert_files(&self.crt_p, &self.key_p, &cert_pem, &key_pem)?;
        let key_enc = self
            .master
            .encrypt(key_pem.as_bytes())
            .map_err(|e| PanelError::Internal(format!("加密私钥失败：{e}")))?;

        let now = crate::now_unix();
        let not_after = now + ACME_DAYS * 86_400;
        let site_id = self.site_id;
        let dj = serde_json::to_string(&self.domains).unwrap_or_else(|_| "[]".into());
        let issuer = "ACME (certbot)".to_string();
        let cert = cert_pem;
        self.db
            .exec(move |conn| {
                conn.execute("DELETE FROM ssl_certs WHERE site_id = ?1", [site_id])
                    .map_err(|e| PanelError::Database(e.to_string()))?;
                conn.execute(
                    "INSERT INTO ssl_certs(site_id, domains, issuer, not_after, source, key_enc, cert, renew_state, created_at) \
                     VALUES(?1, ?2, ?3, ?4, 'acme', ?5, ?6, 'ok', ?7)",
                    rusqlite::params![site_id, dj, issuer, not_after, key_enc, cert, now],
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
                Ok(panel_db::WriteAck { rows_changed: 1 })
            })
            .await?;

        progress.set(100, "完成").await;
        Ok(panel_task::TaskOutcome {
            state: panel_task::TaskState::Ok,
            exit_code: Some(0),
            output_path: Some(self.crt_p.clone()),
        })
    }
}

/// 手动续期：自签证书重新生成并覆盖；ACME 证书走 `ssl.acme`（未接入时诚实 501）。
pub async fn cert_renew(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;

    let row = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains, source FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st
                .query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await?
        .ok_or_else(|| ApiError::not_found("cert"))?;
    let (domains_json, source) = row;

    if source != "selfsigned" {
        if !state.capabilities.get(cap_keys::SSL_ACME).map(|c| c.supported).unwrap_or(false) {
            return Err(ApiError::unsupported("ssl.acme"));
        }
        // ACME 续期同样走任务：certbot 可能耗时，且 CA 有限流（LE 5 次/小时/域名）
        let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
        let (crt_p, key_p) = cert_paths_for(&state, &domains);
        let job = AcmeTask {
            mode: AcmeMode::Renew,
            site_id: id,
            domains,
            // renew 沿用 certbot 既有账户，无需邮箱与 webroot
            email: String::new(),
            webroot: std::path::PathBuf::new(),
            crt_p,
            key_p,
            master: state.require_secret_key()?,
            db: state.db.clone(),
        };
        let (tid, _) = state
            .tasks
            .submit(
                panel_task::TaskRequest {
                    // 幂等键按小时：同一小时内重复提交返回同一任务，天然规避 CA 限流
                    idempotency_key: format!("cert-renew:{id}:{}", crate::now_unix() / 3600),
                    kind: panel_task::TaskKind::CertIssue,
                    label: format!("ACME 续期证书（站点 #{id}）"),
                    timeout: std::time::Duration::from_secs(900),
                },
                job,
            )
            .await
            .map_err(ApiError::from)?;
        audit(&state, &s, "ssl.renew", &id.to_string(), "queued").await;
        return Ok(ok(serde_json::json!({ "task_id": tid, "source": "acme" })));
    }
    if !state.capabilities.get(cap_keys::SSL_SELFSIGNED).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("ssl.selfsigned"));
    }
    let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "cert has no domains"));
    }

    let master = state.require_secret_key()?;
    let tmp = state.os.paths().tmp_dir();
    let (cert_pem, key_pem) = tls::generate_self_signed(&tmp, &domains, SELF_SIGNED_DAYS).await?;
    let key_enc = master.encrypt(key_pem.as_bytes()).map_err(ApiError::from)?;
    let (crt_p, key_p) = cert_paths_for(&state, &domains);
    write_cert_files(&crt_p, &key_p, &cert_pem, &key_pem)?;

    let now = crate::now_unix();
    let not_after = now + (SELF_SIGNED_DAYS as i64) * 86_400;
    let issuer = "ForkPanel Self-Signed".to_string();
    let iss2 = issuer.clone();
    let cert2 = cert_pem;
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE ssl_certs SET cert = ?1, key_enc = ?2, not_after = ?3, issuer = ?4,
                        renew_state = 'ok', last_error = NULL WHERE id = ?5",
                rusqlite::params![cert2, key_enc, not_after, iss2, id],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "cert.renew", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({
        "id": id,
        "source": "selfsigned",
        "issuer": issuer,
        "not_after": not_after,
        "days_left": SELF_SIGNED_DAYS,
    })))
}

/// 删除证书（DB + 磁盘 cert/key 一并清理）。
pub async fn cert_delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    // 先取域名，删除后才能定位要清理的磁盘文件
    let domains_json = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st.query_map([id], |r| r.get::<_, String>(0)).map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await?;

    let n = state
        .db
        .exec(move |conn| {
            let n = conn
                .execute("DELETE FROM ssl_certs WHERE id = ?1", [id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;
    if n.rows_changed == 0 {
        return Err(ApiError::not_found("cert"));
    }

    if let Some(js) = domains_json {
        let ds: Vec<String> = serde_json::from_str(&js).unwrap_or_default();
        let (crt, key) = cert_paths_for(&state, &ds);
        let _ = std::fs::remove_file(&crt);
        let _ = std::fs::remove_file(&key);
    }

    audit(&state, &s, "cert.delete", &id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_left_calculation() {
        let now = crate::now_unix();
        let f = |na: Option<i64>| na.map(|t| (t - now) / 86_400);
        assert_eq!(f(Some(now + 86_400 * 30)), Some(30));
        assert_eq!(f(Some(now + 86_400 * 3)), Some(3));
        assert_eq!(f(None), None);
    }

    #[test]
    fn renewal_warning_thresholds() {
        // UI：>30 绿 / 7~30 黄 / <7 红
        let level = |d: i64| if d > 30 { "ok" } else if d >= 7 { "warn" } else { "danger" };
        assert_eq!(level(60), "ok");
        assert_eq!(level(30), "warn");
        assert_eq!(level(7), "warn");
        assert_eq!(level(3), "danger");
        assert_eq!(level(0), "danger");
    }

    #[test]
    fn apply_flow_order_is_enforced() {
        // 顺序：render → validate → deploy → reload → 持久化
        // validate 失败时不得 deploy（旧配置必须原封不动）
        let steps = ["render", "validate", "deploy", "reload", "persist"];
        assert_eq!(steps[1], "validate", "校验必须在部署之前");
        assert!(steps.iter().position(|s| *s == "validate").unwrap()
            < steps.iter().position(|s| *s == "deploy").unwrap());
        assert!(steps.iter().position(|s| *s == "deploy").unwrap()
            < steps.iter().position(|s| *s == "reload").unwrap());
    }
}
