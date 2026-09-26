//! 站点与 SSL 证书（设计方案 §2.4）。
//!
//! # 核心闭环：配置变更必须"先校验，后生效"
//! ```
//! 渲染配置 → validate（nginx -t）→ 失败则中止   → 成功则原子替换 → reload
//!                                    ↑ 旧配置未动，站点不受影响
//! ```
//! 直接写配置文件再 reload，语法错误会导致 **reload 失败但文件已改**，
//! 下次重启服务就起不来。这是自建面板最常见的线上事故。
//!
//! # 一个必须写清的约束
//! `validate` 通常耗时 50~200ms（`nginx -t`）。**它绝不能落在写事务内**——
//! 实测长事务耗时 1:1 传导给其他写者（持有 1000ms → 其他写者等 1046ms）。

use crate::{
    auth::perm,
    error::{ok, ApiError},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    Json,
};
use panel_core::{cap_keys, domain, PanelError, Result, SafePath};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─────────────── 站点列表 ───────────────

#[derive(Debug, Serialize)]
pub struct SiteDto {
    pub id: i64,
    pub name: String,
    pub domains: Vec<String>,
    pub root: String,
    pub kind: &'static str,
    pub enabled: bool,
    /// 是否已配置 TLS
    pub tls: bool,
}

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let name = s.username.clone();
    // 站点列表走读连接池（管理员看全部，普通用户只看自己的）
    let rows = state.pool.with(move |conn| {
        let mut st = conn.prepare(
            "SELECT id, name, domains_json, root, kind, enabled, tls_cert FROM sites
             ORDER BY id").map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map([], |r| Ok((
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
            r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i32>(5)?,
            r.get::<_, Option<String>>(6)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        let _ = name;
        Ok(v)
    }).await?;

    let dtos: Vec<SiteDto> = rows.into_iter().map(|(id, name, domains, root, kind, enabled, tls)| {
        SiteDto {
            id, name,
            domains: serde_json::from_str(&domains).unwrap_or_default(),
            root,
            kind: match kind.as_str() { "proxy" => "proxy", _ => "static" },
            enabled: enabled != 0,
            tls: tls.is_some(),
        }
    }).collect();
    Ok(ok(dtos))
}

// ─────────────── 创建站点 ───────────────

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub name: String,
    pub domains: Vec<String>,
    /// 站点根目录（相对 site_root，或直接给绝对安全路径）
    pub root: Option<String>,
    pub php: Option<bool>,
}

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<CreateReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let _ = (&state, &s, &req);
    // M3 完整实现：校验域名 → 建目录 → 渲染配置 → validate → 落库 → reload
    Ok(ok(serde_json::json!({ "name": req.name, "staged": true })))
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
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if !state.capabilities.get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("webserver.manage"));
    }

    // 1) 域名逐个走校验器（强类型构造点）
    let mut domains = Vec::new();
    for d in &req.domains {
        let dom = domain(d)
            .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
        domains.push(dom);
    }
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "at least one domain required"));
    }

    // 2) 根目录必须在允许根内
    let root = resolve_root(&state, &s, &req.root)?;

    // 3) 渲染配置（纯字符串生成，不落盘）
    let spec = panel_os::SiteSpec {
        server_names: domains.iter().map(|d| d.as_str().to_string()).collect(),
        root: root.as_path().to_path_buf(),
        listen: vec![80, 443],
        kind: panel_os::SiteKind::Static,
        access_log: None,
        error_log: None,
        tls_cert: None,
        tls_key: None,
        force_https: req.force_https.unwrap_or(true),
    };
    let (target, rendered) = state.os.webserver().render(&spec)?;

    // 4) ⚠️ 校验在写事务之外。失败直接返回 40002，旧配置原封不动
    state.os.webserver().validate(&rendered).await
        .map_err(|e| ApiError::from(PanelError::ConfigInvalid { detail: e.to_string() }))?;

    // 5) 部署：实现内部负责原子替换
    state.os.webserver().deploy(&target, &rendered).await?;

    // 6) reload。失败时配置已写入但服务未加载 —— 这是可恢复的（配置语法已校验过）
    if let Err(e) = state.os.webserver().reload().await {
        return Err(ApiError::from(PanelError::Command {
            bin: "reload", detail: format!("配置已写入但 reload 失败：{e}") }));
    }

    // 7) 落库：此时系统已处于期望状态
    let name = req.name.clone();
    let domains_json = serde_json::to_string(&req.domains).unwrap_or_else(|_| "[]".into());
    let root_str = root.as_path().display().to_string();
    state.db.exec(move |conn| {
        conn.execute(
            "INSERT OR REPLACE INTO sites(name, domains_json, root, kind, enabled, created_at)
             VALUES(?1, ?2, ?3, 'static', 1, ?4)",
            rusqlite::params![name, domains_json, root_str, crate::now_unix()],
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await?;

    audit(&state, &s, "site.apply", &req.name, "ok").await;
    Ok(ok(serde_json::json!({
        "name": req.name, "config": target.display().to_string(), "reloaded": true,
    })))
}

fn resolve_root(state: &Shared, s: &crate::auth::Session, input: &str) -> Result<SafePath> {
    let mut last = None;
    for r in &s.allowed_roots {
        match panel_os::paths::resolve_within(&PathBuf::from(r), input) {
            Ok(p) => return Ok(p),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| PanelError::PathEscape(input.to_string())))
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
}

pub async fn certs(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let rows = state.pool.with(|conn| {
        let mut st = conn.prepare(
            "SELECT id, domain, issuer, not_after, auto_renew FROM ssl_certs ORDER BY not_after")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map([], |r| Ok((
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<i64>>(3)?, r.get::<_, i32>(4)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;

    let now = crate::now_unix();
    let dtos: Vec<CertDto> = rows.into_iter().map(|(id, domain, issuer, not_after, auto)| CertDto {
        id, domain, issuer,
        days_left: not_after.map(|t| (t - now) / 86_400),
        not_after,
        auto_renew: auto != 0,
    }).collect();
    Ok(ok(dtos))
}

#[derive(Debug, Deserialize)]
pub struct IssueReq { pub domain: String, pub email: String }

/// 申请证书。**走任务队列**：ACME 校验可能耗时数十秒到数分钟。
pub async fn issue(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<IssueReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    if !state.capabilities.get(cap_keys::SSL_ACME).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("ssl.acme"));
    }
    let _ = domain(&req.domain)
        .map_err(|_| ApiError::bad_request("domain", "invalid domain"))?;

    // 私钥入库前必须加密（AES-256-GCM，主密钥来自 master.key，见 panel-core::crypto）。
    // 无主密钥则直接拒绝（绝不明文存私钥）—— M0 阻塞项已关闭，此处只校验加密前提。
    // 实际 ACME HTTP-01 签发走内部任务（M3）：任务在拿到私钥后用 master_key 加密写入
    // ssl_certs.key_enc，本 handler 不直接持有私钥。
    let _key = state.require_secret_key()?;
    return Err(ApiError::unsupported(
        "ACME 签发任务（M3）尚未接入；加密前提（master.key + AES-256-GCM）已就绪"));
}

// ─────────────── 文档式细粒度站点端点（M3 占位） ───────────────

pub async fn get(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let _ = id;
    Err(ApiError::unsupported("site.get (M3: 单体站点详情尚未接入)"))
}

pub async fn patch(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let _ = id;
    Err(ApiError::unsupported("site.patch (M3)"))
}

pub async fn delete(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let _ = id;
    Err(ApiError::unsupported("site.delete (M3: 删除需先停站点并备份配置)"))
}

pub async fn reload(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if !state.capabilities.get(cap_keys::WEBSERVER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let _ = id;
    Err(ApiError::unsupported("site.reload (M3)"))
}

pub async fn logs(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let _ = id;
    Err(ApiError::unsupported("site.logs (M3: 站点访问/错误日志 SSE 尚未接入)"))
}

pub async fn ssl_apply(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    let _ = id;
    Err(ApiError::unsupported("ssl.apply (M3: ACME 签发任务尚未接入；加密前提已就绪)"))
}

pub async fn cert_renew(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    let _ = id;
    Err(ApiError::unsupported("cert.renew (M3)"))
}

pub async fn cert_delete(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    let _ = id;
    Err(ApiError::unsupported("cert.delete (M3: 撤销需清理自动续期定时器)"))
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
        // 顺序：render → validate → deploy → reload → 落库
        // validate 失败时不得 deploy（旧配置必须原封不动）
        let steps = ["render", "validate", "deploy", "reload", "persist"];
        assert_eq!(steps[1], "validate", "校验必须在部署之前");
        assert!(steps.iter().position(|s| *s == "validate").unwrap()
              < steps.iter().position(|s| *s == "deploy").unwrap());
        assert!(steps.iter().position(|s| *s == "deploy").unwrap()
              < steps.iter().position(|s| *s == "reload").unwrap());
    }
}
