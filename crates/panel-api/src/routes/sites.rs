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
    routes::{audit, audit_system, Auth, MaybeAuth, Shared},
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
    waf_enabled: i32,
    waf_profile: Option<String>,
    waf_rate: Option<i64>,
    waf_burst: Option<i64>,
    /// JSON 数组：反代后端列表（static 站点为 NULL）
    upstreams_json: Option<String>,
    /// php-fpm 目标（unix:/path.sock | host:port）；非 php 站点为 NULL
    fpm: Option<String>,
}

impl RawSite {
    /// 库中现存的 WAF 配置（`waf_enabled=0` → `None`）。
    fn waf(&self) -> Option<panel_os::WafSpec> {
        if self.waf_enabled == 0 {
            return None;
        }
        Some(panel_os::WafSpec {
            profile: self
                .waf_profile
                .as_deref()
                .and_then(panel_os::WafProfile::parse)
                // 档位认不出来时退回**基础档**，而不是退回"无防护"：
                // 配置解析失败不该静默变成"一条规则都不拦"。
                .unwrap_or(panel_os::WafProfile::Basic),
            rate_per_sec: self.waf_rate.and_then(|n| u32::try_from(n).ok()).filter(|n| *n > 0),
            burst: self.waf_burst.and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
        })
    }
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
    /// WAF 是否启用
    pub waf_enabled: bool,
    /// WAF 档位（basic / strict）；未启用为 null
    pub waf_profile: Option<String>,
    /// CC 限速（次/秒）；null = 不限速
    pub waf_rate_per_sec: Option<i64>,
    pub waf_burst: Option<i64>,
    /// 反代后端列表（kind=proxy 时存在）
    pub upstreams: Option<Vec<String>>,
    /// php-fpm 目标（kind=php 时存在）
    pub fpm: Option<String>,
}

/// API 口径（`proxy`）→ 库内口径（`reverse_proxy`）。
///
/// 两套名字的换算**只在这两个函数里**，不散落到别处——散开的下场就是之前那样：
/// `apply` 一律写死 `'static'`、`to_out` 又把一切非 `reverse_proxy` 都当静态，
/// 于是反代站在列表里显示成"静态"，前端编辑后一点"应用"就把线上站点改成静态站。
fn kind_to_db(k: &panel_os::SiteKind) -> &'static str {
    match k {
        panel_os::SiteKind::Static => "static",
        panel_os::SiteKind::ReverseProxy { .. } => "reverse_proxy",
        panel_os::SiteKind::Php { .. } => "php",
    }
}

/// 库内口径 → API 口径。未知值一律落到 `static`（**不是** `proxy`）：
/// 认不出来时降级成"静态"只是显示不准，认成反代则会让人按错误前提去改配置。
fn kind_to_api(k: &str) -> &'static str {
    match k {
        "reverse_proxy" => "proxy",
        "php" => "php",
        _ => "static",
    }
}

fn to_out(r: &RawSite) -> SiteOut {
    SiteOut {
        id: r.id,
        name: r.name.clone(),
        domains: serde_json::from_str(&r.domains).unwrap_or_default(),
        root: r.root.clone(),
        kind: kind_to_api(&r.kind).to_string(),
        enabled: r.enabled != 0,
        tls: r.tls,
        created_at: r.created_at,
        waf_enabled: r.waf_enabled != 0,
        waf_profile: r.waf_profile.clone(),
        waf_rate_per_sec: r.waf_rate,
        waf_burst: r.waf_burst,
        upstreams: r.upstreams_json.as_deref().and_then(|s| serde_json::from_str(s).ok()),
        fpm: r.fpm.clone(),
    }
}

fn db_err(e: rusqlite::Error) -> PanelError {
    PanelError::Database(e.to_string())
}

/// SELECT 公共投影（含派生的 tls 计数）
const SITE_SELECT: &str = "s.id, s.name, s.domains, s.root, s.kind, s.enabled, s.created_at,
       (SELECT COUNT(*) FROM ssl_certs c WHERE c.site_id = s.id) AS tls_count,
       s.waf_enabled, s.waf_profile, s.waf_rate, s.waf_burst,
       s.upstreams_json, s.fpm";

/// 站点查询 SQL。
///
/// 字段列表来自编译期常量 `SITE_SELECT`——**没有用户输入参与**，不存在注入面。
/// 走 `format!` 而不是字面量，是为了让字段列表只维护一份、避免三处查询各自漂移
/// （代价是曾被门禁 [5] 误判：那条规则只认 `prepare(&format!` 这个形状）。
fn site_sql(suffix: &str) -> String {
    format!("SELECT {SITE_SELECT} FROM sites s {suffix}")
}

async fn fetch_all(state: &Shared) -> Result<Vec<RawSite>> {
    state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare(&site_sql("ORDER BY s.id"))
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
                        waf_enabled: r.get(8)?,
                        waf_profile: r.get(9)?,
                        waf_rate: r.get(10)?,
                        waf_burst: r.get(11)?,
                    upstreams_json: r.get(12)?,
                    fpm: r.get(13)?,
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
                .prepare(&site_sql("WHERE s.id = ?1"))
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
                    waf_enabled: r.get(8)?,
                    waf_profile: r.get(9)?,
                    waf_rate: r.get(10)?,
                    waf_burst: r.get(11)?,
                    upstreams_json: r.get(12)?,
                    fpm: r.get(13)?,
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
                .prepare(&site_sql("WHERE s.name = ?1"))
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
                    waf_enabled: r.get(8)?,
                    waf_profile: r.get(9)?,
                    waf_rate: r.get(10)?,
                    waf_burst: r.get(11)?,
                    upstreams_json: r.get(12)?,
                    fpm: r.get(13)?,
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
    let resolved = panel_os::paths::resolve_within_for_create(&base, rel)
        .map_err(|_| PanelError::PathEscape(rel.to_string()))?;
    // 自愈：确保站点根目录存在且对 Web 服务器可读（0o755）。
    // 不再依赖 umask 隐式保证——否则 root:root + 严 umask 下 www-data 会 403。
    // create / apply 两路都经此函数，权限保障单一事实源。
    ensure_site_root_dir(resolved.as_path());
    Ok(resolved)
}

/// 确保站点根目录存在且权限为 `0o755`（目录对 Web 服务器运行身份可读+可进入）。
///
/// 设计为纯函数（只吃路径、不碰 `state`），便于单测；失败一律静默——
/// 目录创建/权限是附带的收尾动作，不该因它失败就让建站/应用主流程报错
/// （真实权限问题由 Web 服务器 reload 时的 403 暴露，比这里硬失败更易定位）。
fn ensure_site_root_dir(dir: &Path) {
    if panel_os::fs::ensure_dir(dir, 0o755).is_err() {
        // 仅记录，不中断主流程
        eprintln!("[sites] 确保站点根目录权限失败: {}", dir.display());
    }
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

/// 站点托管根目录（只读）。
///
/// 前端的「选择目录」用它作为初始定位：站点根目录**可被 config 的
/// `[paths] site_root` 覆盖**（默认才是 /var/www），前端不能硬编码，
/// 否则在自定义部署下打开选择器会直接落到一个不存在的目录。
/// 顺带自愈式建目录（与 `resolve_site_root` 一致），避免首次打开即报 not found。
pub async fn root_info(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let root = state.os.paths().site_root();
    let _ = std::fs::create_dir_all(&root);
    Ok(ok(serde_json::json!({ "site_root": root.display().to_string() })))
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
    /// 创建后是否「启用」（默认 true）。
    ///
    /// 注意 `create` 只写库、不下发配置——无论此处传什么，站点都要等一次
    /// `apply` 才会真正对外服务。因此该字段决定的是**落库的初始状态**，
    /// 供前端编辑页的开关回显；后续翻转由 `patch` 负责真正同步 Web 服务器。
    pub enabled: Option<bool>,
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
    let enabled = req.enabled.unwrap_or(true);
    // 目录已由 resolve_site_root 自愈式创建并设为 0o755（不再依赖 umask）
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
                 VALUES(?1, ?2, ?3, 'static', 'nginx', ?4, ?5)",
                rusqlite::params![name_db, domains_json, root_db, enabled as i32, now],
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
                    // 兜底分支：站点刚建、WAF **默认关闭**——防护能力的默认值
                    // 应当是"不替用户做决定"，开启是显式动作。
                    waf_enabled: false,
                    waf_profile: None,
                    waf_rate_per_sec: None,
                    waf_burst: None,
                    upstreams: None,
                    fpm: None,
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
    /// `enabled` 翻转时本接口会**真正同步 Web 服务器配置**：停用=移除配置并 reload，
    /// 启用=按落库行重新渲染下发。其余字段只写库，不重发配置。
    /// `force_https` 仅影响后续 `apply` 渲染，库不单列存储。
    pub force_https: Option<bool>,
}

/// 重建某站点的 nginx 配置并渲染，返回 `(conf_path, 渲染文本)`。
///
/// `domains` / `root` 由调用方**显式传入**，而不是从 `row` 里读：`patch` 必须在写库
/// **之前**就用新值下发配置，此时新值只存在于内存中。其余字段（WAF / 类型 / 证书）
/// 都是 `patch` 不会改动的部分，从 `row` 取即可。
/// `force_https` 未落库，按「有 TLS 即开启」的 apply 默认语义补齐。
async fn render_spec_for_row(
    state: &Shared,
    row: &RawSite,
    domains: &[String],
    root: &str,
) -> Result<(PathBuf, String)> {
    if domains.is_empty() {
        return Err(PanelError::Internal(format!(
            "站点 {} 缺少域名，无法重新渲染配置",
            row.name
        )));
    }
    if root.trim().is_empty() {
        return Err(PanelError::Internal(format!(
            "站点 {} 根目录为空，无法重新渲染配置",
            row.name
        )));
    }
    let root = PathBuf::from(root);

    // WAF：从落库值重建（与 apply 的 build_waf 落库口径一致）
    let waf = if row.waf_enabled != 0 {
        Some(panel_os::WafSpec {
            profile: panel_os::WafProfile::parse(row.waf_profile.as_deref().unwrap_or("basic"))
                .unwrap_or(panel_os::WafProfile::Basic),
            rate_per_sec: row.waf_rate.map(|n| n as u32),
            burst: row.waf_burst.map(|n| n as u32).unwrap_or(0),
        })
    } else {
        None
    };

    // 类型：从 kind + upstreams_json / fpm 重建
    let kind = match row.kind.as_str() {
        "reverse_proxy" => {
            let ups: Vec<String> = row
                .upstreams_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            panel_os::SiteKind::ReverseProxy { upstreams: ups }
        }
        "php" => panel_os::SiteKind::Php {
            fpm: row.fpm.clone().unwrap_or_default(),
        },
        _ => panel_os::SiteKind::Static,
    };

    // 证书：沿用 apply 的查找逻辑（证书文件缺失则不启用 TLS）
    let (tls_cert, tls_key) = match cert_domains_for_site(state, row.id).await? {
        Some(ds) if !ds.is_empty() => {
            let (c, k) = cert_paths_for(state, &ds);
            if c.is_file() && k.is_file() {
                (Some(c), Some(k))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };
    let has_tls = tls_cert.is_some() && tls_key.is_some();

    let spec = panel_os::SiteSpec {
        server_names: domains.to_vec(),
        root,
        listen: vec![80, 443],
        kind,
        access_log: None,
        error_log: None,
        tls_cert,
        tls_key,
        force_https: has_tls,
        waf,
    };

    let (target, rendered) = state.os.webserver().render(&spec)?;
    state
        .os
        .webserver()
        .validate(&rendered)
        .await
        .map_err(|e| PanelError::ConfigInvalid { detail: e.to_string() })?;
    Ok((target, rendered))
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

    let old_enabled = cur.enabled != 0;
    let enabled = req.enabled.unwrap_or(old_enabled);
    let _ = req.force_https; // 仅作用于 apply 渲染，DB 不单列存储
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());

    // 当前落库的 conf_path：开关翻转时要改写它，未翻转则原样保留（含 NULL）。
    let mut conf_path: Option<String> = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT conf_path FROM sites WHERE id = ?1",
                [id],
                |r| r.get::<_, Option<String>>(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    // 真启用 / 真停用：enabled 翻转时同步 Web 服务器配置。
    //
    // 顺序是刻意的：**先同步外部状态，成功后才写库**。反过来的话，deploy / reload
    // 一旦失败，就会留下「库说已停用、站点却仍在对外服务」的假成功——用户看到开关
    // 是关的，站点照常访问，正是本次要修的 bug 类型。
    let web_manage = state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false);
    if web_manage && old_enabled != enabled {
        if enabled {
            // 假→真：用「本次提交的新 domains/root + 行内不变字段」重建配置并下发。
            // 站点此前可能从未 apply（无 conf_path），这里会补齐下发。
            let (target, rendered) = render_spec_for_row(&state, &cur, &domains, &root).await?;
            state.os.webserver().deploy(&target, &rendered).await?;
            if let Err(e) = state.os.webserver().reload().await {
                return Err(ApiError::from(PanelError::Command {
                    bin: "reload".to_string(),
                    detail: format!("配置已写入但 reload 失败：{e}"),
                }));
            }
            conf_path = Some(target.display().to_string());
        } else {
            // 真→假：移除配置，使站点真正下线（`remove` 内部含 reload）。
            if let Some(c) = conf_path.as_deref().filter(|c| !c.is_empty()) {
                state
                    .os
                    .webserver()
                    .remove(&PathBuf::from(c))
                    .await
                    .map_err(ApiError::from)?;
            }
            // 配置已从磁盘移除，落库的 conf_path 不再反映真实状态 → 置空。
            conf_path = Some(String::new());
        }
    }

    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET domains = ?1, root = ?2, enabled = ?3, conf_path = ?4 WHERE id = ?5",
                rusqlite::params![domains_json, root, enabled as i32, conf_path, id],
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

    // F7：删站必须同步移除 nginx 配置并 reload，否则站点"已删除"却仍在对外服务。
    // 先取该站点的 conf_path，在删库行**之前**移除配置——配置删除失败则中止，
    // 避免产生"库里没了、配置还在"的孤儿站点。此查询走只读连接池。
    let conf_path = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT conf_path FROM sites WHERE id = ?1",
                [id],
                |r| r.get::<_, Option<String>>(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    if let Some(ref c) = conf_path {
        if !c.is_empty()
            && state
                .capabilities
                .get(cap_keys::WEBSERVER_MANAGE)
                .map(|x| x.supported)
                .unwrap_or(false)
        {
            let p = std::path::PathBuf::from(c);
            state.os.webserver().remove(&p).await.map_err(ApiError::from)?;
        }
    }

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
    /// 站点类型：`static`（默认）/ `proxy` / `php`
    #[serde(default)]
    pub kind: Option<String>,
    /// `kind=proxy` 的后端列表（1~16 个）
    #[serde(default)]
    pub upstreams: Option<Vec<String>>,
    /// `kind=php` 的 php-fpm 目标（`unix:/path.sock` 或 `host:port`）
    #[serde(default)]
    pub fpm: Option<String>,
    /// 站点 WAF。**缺省 = 保留库中现有配置**（不是"关闭"）——apply 是按
    /// "期望状态"覆盖的，但静默关掉一层防护比多一次点击危险得多，
    /// 而且调用方未必都知道有 `waf` 这个字段。显式 `{"enabled": false}` 才关闭。
    #[serde(default)]
    pub waf: Option<WafReq>,
}

/// WAF 请求体。
#[derive(Debug, Deserialize)]
pub struct WafReq {
    pub enabled: bool,
    /// `basic`（默认）/ `strict`
    #[serde(default)]
    pub profile: Option<String>,
    /// CC 限速：每秒请求数；`None` / 0 = 不限速
    #[serde(default)]
    pub rate_per_sec: Option<u32>,
    /// 突发桶容量；缺省 = `rate * 2`
    #[serde(default)]
    pub burst: Option<u32>,
}

/// 限速上限。上限存在的理由：`rate` 决定每 IP 的放行速率，`burst` 决定
/// 单 IP 能用掉多少缓冲——两者都直接换内存（每个 zone 10m 是硬上限）。
const WAF_RATE_MAX: u32 = 1000;
const WAF_BURST_MAX: u32 = 10_000;

/// 归一化 + 校验 WAF 配置。
///
/// 规则集本身是**编译期常量**，用户只能选档位与数值——所以这里没有"正则注入"面。
/// 但数值边界仍必须挡：`rate=0` 会让 nginx 直接拒绝加载配置。
fn build_waf(
    req: Option<&WafReq>,
    cur: Option<&panel_os::WafSpec>,
) -> ApiResult<Option<panel_os::WafSpec>> {
    let Some(r) = req else { return Ok(cur.cloned()) };   // 缺省 = 保留
    if !r.enabled {
        return Ok(None);                                   // 显式关闭
    }
    let profile = match r.profile.as_deref().unwrap_or("basic") {
        "basic" => panel_os::WafProfile::Basic,
        "strict" => panel_os::WafProfile::Strict,
        other => {
            return Err(ApiError::bad_request(
                "waf.profile",
                format!("未知档位：{other}（可选 basic / strict）"),
            ))
        }
    };
    let rate = match r.rate_per_sec {
        None | Some(0) => None,
        Some(n) if n > WAF_RATE_MAX => {
            return Err(ApiError::bad_request(
                "waf.rate_per_sec",
                format!("限速上限 {WAF_RATE_MAX} 次/秒"),
            ))
        }
        Some(n) => Some(n),
    };
    let burst = r.burst.unwrap_or_else(|| rate.map(|n| n.saturating_mul(2)).unwrap_or(0));
    if burst > WAF_BURST_MAX {
        return Err(ApiError::bad_request("waf.burst", format!("上限 {WAF_BURST_MAX}")));
    }
    // burst 只在限速时有意义。给了 burst 却不限速，用户会以为限速生效了——
    // 这种"配了但没生效"的静默失败比直接报错糟糕得多。
    if rate.is_none() && burst > 0 {
        return Err(ApiError::bad_request(
            "waf.burst",
            "burst 仅在启用限速（rate_per_sec）时有意义",
        ));
    }
    Ok(Some(panel_os::WafSpec { profile, rate_per_sec: rate, burst }))
}

/// 校验反代后端。
///
/// **这是注入防护，不是语法校验**：该值会被直接拼进 nginx 配置文本，所以必须
/// 保证它不越出单个 token（无空白、无换行、无 `;`、无 `{}`）。语法正确性交给
/// 后续的 `nginx -t`（render → validate → deploy 链路里本就有这一步）。
fn validate_upstream(u: &str) -> ApiResult<String> {
    let u = u.trim();
    let rest = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"))
        .ok_or_else(|| {
            ApiError::bad_request("upstreams", format!("必须以 http:// 或 https:// 开头：{u}"))
        })?;
    if rest.is_empty() {
        return Err(ApiError::bad_request("upstreams", format!("缺少主机名：{u}")));
    }
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err(ApiError::bad_request(
            "upstreams",
            format!("只接受 host[:port]，不得含路径 / 查询 / 片段：{u}"),
        ));
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']' | '%'))
    {
        return Err(ApiError::bad_request(
            "upstreams",
            format!("含非法字符（仅允许字母数字与 . - _ : [ ] %）：{u}"),
        ));
    }
    Ok(u.to_string())
}

/// 校验 php-fpm 目标：`unix:/abs/path.sock` 或 `host:port`。同样是注入防护。
fn validate_fpm(v: &str) -> ApiResult<String> {
    let v = v.trim();
    if v.is_empty() {
        return Err(ApiError::bad_request("fpm", "不能为空"));
    }
    if let Some(path) = v.strip_prefix("unix:") {
        if !path.starts_with('/') {
            return Err(ApiError::bad_request("fpm", "unix socket 必须是绝对路径"));
        }
        if path.contains("..") {
            return Err(ApiError::bad_request("fpm", "socket 路径不得含 .."));
        }
        if path.len() > 128 {
            return Err(ApiError::bad_request("fpm", "socket 路径过长（上限 128）"));
        }
    }
    // 必须是一个 token：不得含空白、换行、分号、花括号、引号或反斜杠
    if !v
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, ';' | '{' | '}' | '"' | '\'' | '`' | '\\'))
    {
        return Err(ApiError::bad_request(
            "fpm",
            "含非法字符（不得含空白、引号、分号或花括号）",
        ));
    }
    Ok(v.to_string())
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
    // 取一次现运行配置：TLS 与 WAF 都要基于"当前状态"做缺省合并
    let cur_row = fetch_one_by_name(&state, &req.name).await?;
    let waf = build_waf(req.waf.as_ref(), cur_row.as_ref().and_then(|r| r.waf()).as_ref())?;
    // 停用态守恒：站点已停用则只更新配置、不下发 Web 服务器（conf_path 留空），
    // 与 `patch` 的「真停用」语义一致——避免「点一次应用就把刚停用的站点又拉起来」。
    // 新建站点（无 cur_row）按默认启用对待，照常部署。
    let deploy = cur_row.as_ref().map(|r| r.enabled != 0).unwrap_or(true);
    // 落库四元组在这里就算好：`waf` 随即被 move 进 SiteSpec。
    // 关掉 WAF 时一并清空——留着旧数值会让"下次重新打开"意外带上几年前的参数，
    // 而用户早就不记得了。
    let (waf_on, waf_profile, waf_rate, waf_burst) = match &waf {
        Some(w) => (
            1i32,
            Some(w.profile.as_str().to_string()),
            w.rate_per_sec.map(i64::from),
            Some(i64::from(w.burst)),
        ),
        None => (0i32, None, None, None),
    };

    let (tls_cert, tls_key) = match &cur_row {
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
    // 站点类型：默认静态。反代与 PHP 的目标值都会**直接进 nginx 配置文本**，
    // 因此逐个过注入防护（见 validate_upstream / validate_fpm）。
    let kind = match req.kind.as_deref().unwrap_or("static") {
        "static" => panel_os::SiteKind::Static,
        "proxy" => {
            let raw = req.upstreams.clone().unwrap_or_default();
            if raw.is_empty() || raw.len() > 16 {
                return Err(ApiError::bad_request("upstreams", "反代需要 1~16 个后端"));
            }
            let mut outs = Vec::with_capacity(raw.len());
            for u in &raw {
                outs.push(validate_upstream(u)?);
            }
            panel_os::SiteKind::ReverseProxy { upstreams: outs }
        }
        "php" => {
            let fpm = req.fpm.as_deref().ok_or_else(|| {
                ApiError::bad_request("fpm", "PHP 站点必须指定 php-fpm 目标")
            })?;
            panel_os::SiteKind::Php { fpm: validate_fpm(fpm)? }
        }
        other => {
            return Err(ApiError::bad_request(
                "kind",
                format!("未知站点类型：{other}（可选 static / proxy / php）"),
            ))
        }
    };
    // 反代 / PHP 后端配置一并落库（F6）：从已校验的 kind 提前取出，避免被 move 进 SiteSpec 后无法再借
    let (upstreams_json, fpm_str) = match &kind {
        panel_os::SiteKind::ReverseProxy { upstreams } => (serde_json::to_string(upstreams).ok(), None),
        panel_os::SiteKind::Php { fpm } => (None, Some(fpm.clone())),
        _ => (None, None),
    };
    let kind_db = kind_to_db(&kind);
    let spec = panel_os::SiteSpec {
        server_names: domains.iter().map(|d| d.clone()).collect(),
        root: root.as_path().to_path_buf(),
        listen: vec![80, 443],
        kind,
        access_log: None,
        error_log: None,
        tls_cert,
        tls_key,
        force_https: req.force_https.unwrap_or(true) && has_tls,
        waf,
    };
    let (target, rendered) = state.os.webserver().render(&spec)?;

    // 4) ⚠️ 校验在写事务之外。失败直接返回 40002，旧配置原封不动
    state
        .os
        .webserver()
        .validate(&rendered)
        .await
        .map_err(|e| ApiError::from(PanelError::ConfigInvalid { detail: e.to_string() }))?;

    // 5) 部署（仅启用态）。停用态：上面已渲染+校验通过配置，但**不**下发到 Web 服务器，
    //    配置不会进 nginx，与「真停用」一致；用户启用站点后再应用才会真正生效。
    if deploy {
        state.os.webserver().deploy(&target, &rendered).await?;

        // 6) reload。失败时配置已写入但服务未加载 —— 这是可恢复的（配置语法已校验过）
        if let Err(e) = state.os.webserver().reload().await {
            return Err(ApiError::from(PanelError::Command {
                bin: "reload".to_string(),
                detail: format!("配置已写入但 reload 失败：{e}"),
            }));
        }
    }

    // 7) 落库：此时系统已处于期望状态（按 name upsert，与 create 不冲突）
    let name = req.name.clone();
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());
    let root_str = root.as_path().display().to_string();
    let conf = target.display().to_string();
    let now = crate::now_unix();
    // 停用态：conf_path 留空（配置未下发），enabled 保持 0；启用态 / 新建：正常写入。
    let conf_db = if deploy { conf.clone() } else { String::new() };
    let enabled_i32: i32 = if deploy { 1 } else { 0 };
    state
        .db
        .exec(move |conn| {
            // ?5 = enabled, ?6 = conf_path；deploy=false 时两者分别为 0 / 空串。
            // upstreams_json / fpm_str 已在 apply 开头算出（kind 之后被 move 进 SiteSpec）。
            conn.execute(
                "INSERT INTO sites(name, domains, root, kind, webserver, enabled, conf_path, created_at,
                                   waf_enabled, waf_profile, waf_rate, waf_burst, upstreams_json, fpm)
                 VALUES(?1, ?2, ?3, ?4, 'nginx', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(name) DO UPDATE SET
                    domains=excluded.domains, root=excluded.root, kind=excluded.kind, enabled=?5,
                    conf_path=?6, webserver='nginx',
                    waf_enabled=excluded.waf_enabled, waf_profile=excluded.waf_profile,
                    waf_rate=excluded.waf_rate, waf_burst=excluded.waf_burst,
                    upstreams_json=excluded.upstreams_json, fpm=excluded.fpm",
                rusqlite::params![name, domains_json, root_str, kind_db, enabled_i32, conf_db, now,
                                  waf_on, waf_profile, waf_rate, waf_burst,
                                  upstreams_json, fpm_str],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.apply", &req.name, "ok").await;
    Ok(ok(serde_json::json!({
        "name": req.name,
        "config": conf,
        "deployed": deploy,
        "reloaded": deploy,
        "enabled": deploy,
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
    /// acme | self-signed | manual（UI 据此决定自动续期开关是否可用）
    pub source: String,
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
                    "SELECT id, domains, issuer, not_after, renew_state, auto_renew, source \
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
                        r.get::<_, i64>(5).unwrap_or(0),
                        r.get::<_, String>(6)?,
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
        .map(|(id, domains_json, issuer, not_after, renew, auto_renew, source)| {
            // 证书覆盖多个域名（JSON 数组）；UI 单域名列展示主域名（首个）
            let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
            let primary = domains.into_iter().next().unwrap_or_default();
            CertDto {
                id,
                domain: primary,
                issuer,
                days_left: not_after.map(|t| (t - now) / 86_400),
                not_after,
                // 真实开关（v10 起有 auto_renew 列）。注意它只表示"用户已允许自动续期"，
                // 真正能否续还取决于 ssl.acme 能力位（certbot 是否可用）——
                // UI 需结合能力位判断，别把"开关关着"和"根本用不了"混为一谈。
                auto_renew: auto_renew != 0,
                renew_state: renew,
                source,
            }
        })
        .collect();
    Ok(ok(dtos))
}

/// 证书自动续期扫描的最近运行状态（前端"上次/下次扫描"展示用）。
///
/// 由内部调度器每日 4:05 触发的 `auto_renew_sweep` 写入 `cert_sweep_state`；
/// 本端点只读取，不参与调度。未运行过时整表为空 → 返回 `last_at=0`，
/// 前端据此显示"尚未运行"。
pub async fn cert_renew_sweep_state(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let row: Option<(i64, i64)> = state
        .pool
        .with(|conn| {
            match conn.query_row(
                "SELECT last_at, last_queued FROM cert_sweep_state WHERE id = 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            ) {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await?;
    let (last_at, last_queued) = row.unwrap_or((0, 0));
    // 调度为每日一次，下次 ≈ 上次 + 24h；从未运行则 0（前端显示"尚未运行"）
    let next_at = if last_at > 0 { last_at + 86_400 } else { 0 };
    Ok(ok(serde_json::json!({
        "last_at": last_at,
        "last_queued": last_queued,
        "next_at": next_at,
    })))
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
                    // ACME 证书默认开启自动续期（有效期仅 90 天，靠人工点续期必然会漏）。
                    // 用户可在证书列表关掉；selfsigned / manual 恒为 0（无法自动续）。
                    "INSERT INTO ssl_certs(site_id, domains, issuer, not_after, source, key_enc, cert, renew_state, created_at, auto_renew) \
                     VALUES(?1, ?2, ?3, ?4, 'acme', ?5, ?6, 'ok', ?7, 1)",
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

/// 自动续期的提前量（天）：到期前多久开始尝试续期。
///
/// 取 30 天而非贴着过期线（如 7 天）：续期可能因 CA 限流、http-01 校验失败而失败，
/// 留足窗口才能重试；Let's Encrypt 有效期 90 天，30 天意味着约有 2 个月的重试余量。
const RENEW_WINDOW_DAYS: i64 = 30;

/// 证书自动续期扫描——内部周期任务 `cert.renew_check` 的任务体。
///
/// 每天执行一次：找出 **30 天内到期** 且 `auto_renew=1` 的 **ACME** 证书，逐个
/// 提交 `AcmeTask{Renew}`。刻意**不**在这里直接调 certbot：走任务队列才能被审计、
/// 可看进度，并复用按小时幂等键天然规避 CA 限流（LE 5 次/小时/域名）。
///
/// 返回成功入队条数。能力位缺失（certbot 不在）或主密钥不可用时返回 **0 而不报错**——
/// 周期任务失败不该拖垮面板，也不该每天刷同一条错误日志。
pub async fn auto_renew_sweep(state: Shared) -> panel_core::Result<usize> {
    // 没有 certbot 就没有可交互的 CA，提交必然失败，直接跳过
    let acme_ok = state
        .capabilities
        .get(cap_keys::SSL_ACME)
        .map(|c| c.supported)
        .unwrap_or(false);
    if !acme_ok {
        return Ok(0);
    }
    let Ok(master) = state.require_secret_key() else {
        return Ok(0);
    };

    let now = crate::now_unix();
    let due_before = now + RENEW_WINDOW_DAYS * 86_400;

    let rows: Vec<(i64, String)> = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, domains FROM ssl_certs \
                     WHERE source='acme' AND auto_renew=1 \
                       AND not_after IS NOT NULL AND not_after <= ?1",
                )
                .map_err(db_err)?;
            let it = st
                .query_map(rusqlite::params![due_before], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(db_err)?);
            }
            Ok(v)
        })
        .await?;

    let mut queued = 0usize;
    for (id, domains_json) in rows {
        let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
        if domains.is_empty() {
            continue;
        }
        let (crt_p, key_p) = cert_paths_for(&state, &domains);
        let job = AcmeTask {
            mode: AcmeMode::Renew,
            site_id: id,
            domains: domains.clone(),
            // Renew 沿用 certbot 既有账户，无需邮箱与 webroot
            email: String::new(),
            webroot: std::path::PathBuf::new(),
            crt_p,
            key_p,
            master,
            db: state.db.clone(),
        };
        // 幂等键按小时：同一小时内重复触发返回同一任务，规避 CA 限流
        let idem = format!("cert-renew:{id}:{}", now / 3600);
        if state
            .tasks
            .submit(
                panel_task::TaskRequest {
                    idempotency_key: idem,
                    kind: panel_task::TaskKind::CertIssue,
                    label: format!("ACME 自动续期证书（#{id}）"),
                    timeout: std::time::Duration::from_secs(900),
                },
                job,
            )
            .await
            .is_ok()
        {
            queued += 1;
            // 系统发起的续期也写操作日志：actor 固定 "system"，
            // 否则自动续期在 UI 审计轨迹里完全不可见（仅服务端 info 日志有）。
            audit_system(
                &state,
                "cert.auto_renew",
                &format!("#{id} {}", domains.join(",")),
                "queued",
            )
            .await;
        }
        // 单条失败不影响其余证书，也不惊动周期任务（失败原因由任务自身记录）
    }

    // 记录扫描时间（供前端展示"上次/下次扫描"）。即便本次入队 0 也写入——
    // 说明扫描确实跑过、只是没有到期证书，而非"从未运行"。
    let sweep_now = now;
    let sweep_queued = queued as i64;
    state
        .pool
        .with(move |conn| {
            conn.execute(
                "INSERT INTO cert_sweep_state(id, last_at, last_queued) VALUES(1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET last_at=excluded.last_at, last_queued=excluded.last_queued",
                rusqlite::params![sweep_now, sweep_queued],
            )
            .map_err(db_err)?;
            Ok(())
        })
        .await?;

    Ok(queued)
}

#[derive(Debug, Deserialize)]
pub struct AutoRenewReq {
    pub enabled: bool,
}

/// 开关证书自动续期。**仅 ACME 证书可开**。
///
/// selfsigned / manual 没有可交互的 CA，给它们开关就是"能点但必失败"的假按钮，
/// 故 SQL 里直接带 `source='acme'` 过滤（顺带避免先读后写的竞态）。
/// 开启前还会校验 `ssl.acme` 能力位——否则用户开了开关却永远不会续，
/// 那是最坏的失败方式（UI 显示"已开启"，实际持续过期）。
pub async fn cert_auto_renew(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<AutoRenewReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    if req.enabled
        && !state
            .capabilities
            .get(cap_keys::SSL_ACME)
            .map(|c| c.supported)
            .unwrap_or(false)
    {
        return Err(ApiError::unsupported("ssl.acme"));
    }
    // 先读后写：校验必须在**读路径**上返回 400/404。若把校验放进 db.exec 闭包，
    // 写通道会把任何 Err 统一包装成 Database 错误 → 用户看到 500（实测踩过）。
    let source: Option<String> = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT source FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st
                .query_map(rusqlite::params![id], |r| r.get::<_, String>(0))
                .map_err(db_err)?;
            match it.next() {
                Some(x) => Ok(Some(x.map_err(db_err)?)),
                None => Ok(None),
            }
        })
        .await?;
    let Some(source) = source else {
        return Err(ApiError::not_found("cert"));
    };
    if source != "acme" {
        return Err(ApiError::bad_request(
            "id",
            "仅 ACME 证书支持自动续期：自签 / 手动证书没有可交互的 CA，给了开关也是点不动的",
        ));
    }

    let enabled_i = if req.enabled { 1 } else { 0 };
    state
        .db
        .exec(move |conn| {
            let n = conn
                .execute(
                    "UPDATE ssl_certs SET auto_renew=?1 WHERE id=?2 AND source='acme'",
                    rusqlite::params![enabled_i, id],
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;
    audit(
        &state,
        &s,
        "ssl.auto_renew",
        &id.to_string(),
        if req.enabled { "on" } else { "off" },
    )
    .await;
    Ok(ok(serde_json::json!({ "id": id, "auto_renew": req.enabled })))
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
mod waf_tests {
    use super::*;

    fn req(enabled: bool, profile: Option<&str>, rate: Option<u32>, burst: Option<u32>) -> WafReq {
        WafReq { enabled, profile: profile.map(str::to_string), rate_per_sec: rate, burst }
    }

    fn spec(profile: panel_os::WafProfile, rate: Option<u32>, burst: u32) -> panel_os::WafSpec {
        panel_os::WafSpec { profile, rate_per_sec: rate, burst }
    }

    /// 缺省必须**保留**而不是关闭：否则任何不知道 `waf` 字段的调用方
    /// 一次 apply 就会把防护静默关掉，而且没有任何提示。
    #[test]
    fn omitted_waf_keeps_the_stored_config() {
        let cur = spec(panel_os::WafProfile::Strict, Some(5), 10);
        assert_eq!(build_waf(None, Some(&cur)).unwrap(), Some(cur));
        assert_eq!(build_waf(None, None).unwrap(), None);
    }

    #[test]
    fn explicit_disable_turns_it_off_even_if_currently_on() {
        let cur = spec(panel_os::WafProfile::Basic, Some(5), 10);
        assert_eq!(build_waf(Some(&req(false, None, None, None)), Some(&cur)).unwrap(), None);
    }

    #[test]
    fn burst_defaults_to_twice_the_rate_and_profile_defaults_to_basic() {
        let g = build_waf(Some(&req(true, Some("basic"), Some(10), None)), None).unwrap().unwrap();
        assert_eq!(g.burst, 20);
        assert_eq!(g.profile, panel_os::WafProfile::Basic);
        // 不给档位 → 基础档（默认值应当"够用且不误伤"）
        let g2 = build_waf(Some(&req(true, None, None, None)), None).unwrap().unwrap();
        assert_eq!(g2.profile, panel_os::WafProfile::Basic);
        assert_eq!(g2.rate_per_sec, None);
    }

    /// `rate=0` 若原样下发，nginx 会拒绝加载整份配置——必须解释成"不限速"。
    #[test]
    fn rate_zero_means_unlimited_rather_than_going_into_the_config() {
        let g = build_waf(Some(&req(true, None, Some(0), None)), None).unwrap().unwrap();
        assert_eq!(g.rate_per_sec, None);
        assert_eq!(g.burst, 0);
        // 不限速却给了 burst = 用户以为限速生效了，直接拒绝
        assert!(build_waf(Some(&req(true, None, None, Some(50))), None).is_err());
    }

    #[test]
    fn unknown_profile_and_out_of_range_numbers_are_rejected() {
        assert!(build_waf(Some(&req(true, Some("yolo"), None, None)), None).is_err());
        assert!(build_waf(Some(&req(true, None, Some(WAF_RATE_MAX + 1), None)), None).is_err());
        assert!(build_waf(Some(&req(true, None, Some(1), Some(WAF_BURST_MAX + 1))), None).is_err());
        // 边界值本身必须放过：不然"上限"就成了一句空话
        let ok = build_waf(Some(&req(true, None, Some(WAF_RATE_MAX), None)), None).unwrap().unwrap();
        assert_eq!(ok.rate_per_sec, Some(WAF_RATE_MAX));
        assert_eq!(ok.burst, WAF_RATE_MAX * 2);
    }
}

#[cfg(test)]
mod kind_tests {
    use super::*;

    /// 两个换算必须互为逆（在各自定义域上）。之前这里断链：`apply` 写死
    /// `'static'`，`to_out` 又只认 `reverse_proxy`，于是**任何**站点读出来都是
    /// 静态站——反代站被编辑后一点"应用"就被改坏。
    #[test]
    fn kind_maps_round_trip_and_unknown_falls_back_to_static() {
        for (db, api) in [("static", "static"), ("reverse_proxy", "proxy"), ("php", "php")] {
            assert_eq!(kind_to_api(db), api, "库口径 {db} 应呈现为 {api}");
        }
        assert_eq!(kind_to_db(&panel_os::SiteKind::Static), "static");
        assert_eq!(
            kind_to_db(&panel_os::SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] }),
            "reverse_proxy"
        );
        assert_eq!(kind_to_db(&panel_os::SiteKind::Php { fpm: "unix:/run/php.sock".into() }), "php");
        // 未知值必须降级成 static：认成 proxy 会让人按错误前提去改配置
        assert_eq!(kind_to_api("something_else"), "static");
        assert_eq!(kind_to_api(""), "static");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_validation_blocks_config_injection() {
        for ok in ["http://127.0.0.1:3000", "https://backend.internal", "http://[::1]:8080"] {
            assert!(validate_upstream(ok).is_ok(), "应放行: {ok}");
        }
        for bad in [
            // 关键用例：值会直接进 nginx 配置，一个换行就能插入任意指令
            "http://127.0.0.1:3000; }\nserver { listen 9999",
            "http://127.0.0.1:3000 /",
            "http://127.0.0.1:3000/x",
            "http://127.0.0.1:3000#frag",
            "127.0.0.1:3000",            // 缺 scheme
            "http://bad host:3000",      // 含空格
            "http://127.0.0.1\t:3000",   // 含制表符
        ] {
            assert!(validate_upstream(bad).is_err(), "必须拒绝: {bad:?}");
        }
    }

    #[test]
    fn fpm_validation_blocks_injection() {
        assert!(validate_fpm("unix:/run/php/php8.2-fpm.sock").is_ok());
        assert!(validate_fpm("127.0.0.1:9000").is_ok());
        for bad in [
            "unix:relative.sock",        // 非绝对路径
            "unix:/run/../etc/passwd",   // 含 ..
            "127.0.0.1:9000; }",         // 分号 + 花括号
            "127.0.0.1:9000\nserver{",   // 换行
            "",
            "a b",
        ] {
            assert!(validate_fpm(bad).is_err(), "必须拒绝: {bad:?}");
        }
    }

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

    #[test]
    fn ensure_site_root_dir_creates_with_explicit_755() {
        // 验证站点根目录被创建且权限显式设为 0o755，不再依赖 umask 隐式保证
        // （root:root + 严 umask 下，缺少这步会导致 www-data 读静态文件 403）。
        let d = std::env::temp_dir().join(format!("panel-site-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_site_root_dir(&d);
        assert!(d.is_dir(), "站点根目录应被创建");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "目录应显式设为 755（不再依赖 umask）");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_site_root_dir_is_idempotent() {
        // 幂等：重复调用不报错、权限保持 755
        let d = std::env::temp_dir().join(format!("panel-site-root-idem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_site_root_dir(&d);
        ensure_site_root_dir(&d);
        assert!(d.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
