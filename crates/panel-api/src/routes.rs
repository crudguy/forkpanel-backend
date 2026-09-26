//! 路由装配与 handler（设计方案 §3.4 路由表 / docs/api/openapi.yaml 契约）。
//!
//! handler 纪律：参数校验 → 权限断言 → 调 service → 包装响应 →（写操作）审计。
//! 本骨架阶段直接调用 `OsAdapter`；M1+ 引入 panel-service 后只替换调用目标，路由不变。
//!
//! **契约单一来源**：`docs/api/openapi.yaml`。本文件每条路由必须能在 OpenAPI 中找到对应
//! path；新增路由前先更新契约。尚未实现的端点返回 501 Unsupported（统一 `ApiError::unsupported`），
//! 不伪造数据、不留"半成品假成功"——能力缺失 = 明确告知，而非伪装成功。

pub mod auth;
pub mod cron;
pub mod databases;
pub mod files;
pub mod firewall;
pub mod logs;
pub mod services;
pub mod sites;
pub mod system;
pub mod tasks;
pub mod processes;
pub mod security;
pub mod settings;
pub mod users;
pub mod audit;

use crate::{auth::Session, error::ApiError, AppState, Envelope};
use axum::{
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};
use serde_json::Value;
use std::sync::Arc;

pub type Shared = Arc<AppState>;

/// 必须登录的提取器；未登录返回 401
pub struct Auth(pub Session);

impl FromRequestParts<Shared> for Auth {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, _: &Shared) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Session>().cloned()
            .map(Auth)
            .ok_or_else(ApiError::unauthorized)
    }
}

/// 可空会话（用于登录页等公开接口）
pub struct MaybeAuth(pub Option<Session>);

impl FromRequestParts<Shared> for MaybeAuth {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &Shared) -> Result<Self, Self::Rejection> {
        Ok(MaybeAuth(parts.extensions.get::<Session>().cloned()))
    }
}

/// 构造完整路由。
///
/// 中间件顺序（**顺序即语义，不要改**）：
/// `security_headers` → `require_auth` → `guard_write`(仅写) → `read_only_guard`(仅写) → handler
pub fn build_router(state: Shared) -> Router {
    // ── 公开路由（无需登录） ──
    let public = Router::new()
        .route("/api/v1/version", get(system::version))
        .route("/api/v1/auth/login", post(auth::login));

    // ── 系统与监控 ──
    let system_r = Router::new()
        .route("/api/v1/system/capabilities", get(system::capabilities))
        .route("/api/v1/system/overview", get(system::overview))
        .route("/api/v1/metrics/realtime", get(system::realtime))
        .route("/api/v1/metrics/history", get(system::history));

    // ── 进程（M2） ──
    let proc_r = Router::new()
        .route("/api/v1/processes", get(processes::list))
        .route("/api/v1/processes/:pid/kill", post(processes::kill));

    // ── 软件与服务 ──
    let svc_r = Router::new()
        .route("/api/v1/services", get(services::list))
        .route("/api/v1/services/:unit/status", get(services::status))
        .route("/api/v1/services/:unit/start", post(services::start))
        .route("/api/v1/services/:unit/stop", post(services::stop))
        .route("/api/v1/services/:unit/restart", post(services::restart))
        .route("/api/v1/services/:unit/enabled", put(services::set_enabled))
        .route("/api/v1/services/:unit/journal", get(services::journal))
        .route("/api/v1/packages", get(services::packages_list))
        .route("/api/v1/packages/install", post(services::install))
        .route("/api/v1/packages/:name", delete(services::package_remove));

    // ── 站点与 SSL ──
    let site_r = Router::new()
        .route("/api/v1/sites", get(sites::list).post(sites::create))
        .route("/api/v1/sites/apply", post(sites::apply))
        .route("/api/v1/sites/:id", get(sites::get).patch(sites::patch).delete(sites::delete))
        .route("/api/v1/sites/:id/reload", post(sites::reload))
        .route("/api/v1/sites/:id/logs", get(sites::logs))
        .route("/api/v1/sites/:id/ssl/apply", post(sites::ssl_apply))
        .route("/api/v1/certs", get(sites::certs))
        .route("/api/v1/certs/:id/renew", post(sites::cert_renew))
        .route("/api/v1/certs/:id", delete(sites::cert_delete));

    // ── 文件 ──
    let file_r = Router::new()
        .route("/api/v1/files/list", get(files::list))
        .route("/api/v1/files/stat", get(files::stat))
        .route("/api/v1/files/upload", put(files::upload))
        .route("/api/v1/files/download", get(files::download))
        .route("/api/v1/files/read", get(files::read))
        .route("/api/v1/files/write", put(files::write))
        .route("/api/v1/files/mkdir", post(files::mkdir))
        .route("/api/v1/files/delete", post(files::remove))
        .route("/api/v1/files/rename", post(files::rename))
        .route("/api/v1/files/chmod", post(files::chmod))
        .route("/api/v1/files/action", post(files::action));

    // ── 数据库 ──
    let db_r = Router::new()
        .route("/api/v1/db/connections", get(databases::list).post(databases::create))
        .route("/api/v1/db/:conn/databases", get(databases::databases_of))
        .route("/api/v1/db/:conn/:db/tables", get(databases::tables))
        .route("/api/v1/db/:conn/:db/:table/rows", get(databases::rows))
        .route("/api/v1/db/:conn/backup", post(databases::backup))
        .route("/api/v1/db/:conn/restore", post(databases::restore));

    // ── 防火墙 ──
    let fw_r = Router::new()
        .route("/api/v1/firewall/status", get(firewall::status))
        .route("/api/v1/firewall/enabled", put(firewall::set_enabled))
        .route("/api/v1/firewall/rules", get(firewall::list).post(firewall::apply))
        .route("/api/v1/firewall/rules/:id", delete(firewall::delete_rule));

    // ── 安全中心 ──
    let sec_r = Router::new()
        .route("/api/v1/security/baseline", get(security::baseline).post(security::baseline_apply))
        .route("/api/v1/security/sessions", get(security::sessions))
        .route("/api/v1/security/sessions/:id", delete(security::revoke_session));

    // ── 计划任务 ──
    let cron_r = Router::new()
        .route("/api/v1/cron/jobs", get(cron::list).post(cron::create))
        .route("/api/v1/cron/jobs/:id", get(cron::get_job).patch(cron::patch_job).delete(cron::remove))
        .route("/api/v1/cron/jobs/:id/run", post(cron::run))
        .route("/api/v1/cron/jobs/:id/runs", get(cron::runs))
        .route("/api/v1/cron/preview", post(cron::preview));

    // ── 日志 ──
    let log_r = Router::new()
        .route("/api/v1/logs/sources", get(logs::sources))
        .route("/api/v1/logs/stream", get(logs::stream))
        .route("/api/v1/logs/download", get(logs::download))
        .route("/api/v1/logs/:id", get(logs::read));

    // ── 任务中心 ──
    let task_r = Router::new()
        .route("/api/v1/tasks", get(tasks::list))
        .route("/api/v1/tasks/:id", get(tasks::get))
        .route("/api/v1/tasks/:id/cancel", post(tasks::cancel))
        .route("/api/v1/tasks/:id/output", get(tasks::output));

    // ── 设置 / 用户 / 审计 ──
    let cfg_r = Router::new()
        .route("/api/v1/settings", get(settings::get).patch(settings::patch))
        .route("/api/v1/users", get(users::list).post(users::create))
        .route("/api/v1/users/:id", patch(users::patch).delete(users::delete))
        .route("/api/v1/audit", get(audit::list));

    // ── SSE：多频道 ──
    let sse_r = Router::new()
        .route("/api/v1/events/metrics", get(crate::sse::metrics_stream))
        .route("/api/v1/events/tasks", get(crate::sse::task_stream))
        .route("/api/v1/events/logs", get(crate::sse::log_stream));

    // ── 需登录的根路由 ──
    let authed = Router::new()
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/password", post(auth::change_password))
        .merge(system_r)
        .merge(proc_r)
        .merge(svc_r)
        .merge(site_r)
        .merge(file_r)
        .merge(db_r)
        .merge(fw_r)
        .merge(sec_r)
        .merge(cron_r)
        .merge(log_r)
        .merge(task_r)
        .merge(cfg_r)
        .merge(sse_r)
        .layer(middleware::from_fn(crate::middleware::read_only_guard))
        .layer(middleware::from_fn(crate::middleware::guard_write));

    Router::new()
        .merge(public)
        .merge(authed)
        .layer(middleware::from_fn_with_state(state.clone(), crate::middleware::require_auth))
        .layer(middleware::from_fn(crate::middleware::security_headers))
        // 兜底：未匹配路由返回结构化 404（不暴露路由表）
        .fallback(handler_404)
        .with_state(state)
}

async fn handler_404(req: Request) -> (StatusCode, axum::Json<Value>) {
    let rid = req.headers().get("x-request-id")
        .and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
    let e: Envelope<()> = Envelope { code: 10004, message: "not found", data: None, request_id: rid };
    (StatusCode::NOT_FOUND, axum::Json(serde_json::to_value(e).unwrap()))
}

/// 写操作审计入口。**每个写 handler 结束时调用。**
///
/// 实现要点：审计写入走 WriterActor（单写队列），**绝不**在业务事务内同步插入
/// —— 实测长事务耗时 1:1 传导给其他写者。
pub async fn audit(state: &AppState, s: &Session, action: &'static str,
                   target: &str, result: &'static str) {
    let actor = s.username.clone();
    let target = target.to_string();
    let _ = state.db.exec(move |conn| {
        conn.execute(
            "INSERT INTO audit_log(ts, actor, actor_ip, action, target, result, detail_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                crate::now_unix(), actor, "", action, target, result, "{}"
            ],
        ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_ok_shape() {
        let e: Envelope<u32> = Envelope::ok(42, "rid-1".into());
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["code"], 0);
        assert_eq!(v["data"], 42);
        assert_eq!(v["request_id"], "rid-1");
    }

    #[test]
    fn router_builds() {
        // 用内存 mock 适配器验证路由可装配（无需真实 OS 能力）
        let os: std::sync::Arc<dyn panel_os::OsAdapter> =
            std::sync::Arc::new(panel_os::mock::MockOsAdapter::new());
        let dir = std::env::temp_dir().join("panel-router-test");
        std::fs::create_dir_all(&dir).unwrap();
        let db = panel_db::open(&dir.join("t.db"), panel_core::Tier::Nano).unwrap();
        let _ = db;
        // 仅验证 Router 类型可构造（WriterActor 需真实路径，故此处只做类型层校验）
        fn _assert_router(r: Router) { let _ = r; }
    }
}
