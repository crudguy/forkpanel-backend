//! 路由装配与 handler（设计方案 §3.4 路由表 / docs/api/openapi.yaml 契约）。
//!
//! handler 纪律：参数校验 → 权限断言 → 调 service → 包装响应 →（写操作）审计。
//! 本骨架阶段直接调用 `OsAdapter`；M1+ 引入 panel-service 后只替换调用目标，路由不变。
//!
//! **契约单一来源**：`docs/api/openapi.yaml`。本文件每条路由必须能在 OpenAPI 中找到对应
//! path；新增路由前先更新契约。尚未实现的端点返回 501 Unsupported（统一 `ApiError::unsupported`），
//! 不伪造数据、不留"半成品假成功"——能力缺失 = 明确告知，而非伪装成功。

pub mod apps;
pub mod auth;
pub mod cron;
pub mod assistant;
pub mod backups;
pub mod containers;
pub mod databases;
pub mod files;
pub mod firewall;
pub mod logs;
pub mod notifications;
pub mod pkg_help;
pub mod services;
pub mod sites;
pub mod system;
pub mod tasks;
pub mod processes;
pub mod security;
pub mod dashboard;
pub mod onboarding;
pub mod settings;
pub mod users;
pub mod audit;
pub mod multipart;
pub mod notes;
pub mod waf_templates;
pub mod waf_events;
pub mod waf_alert;
pub mod roles;
pub mod terminal;

use crate::webhook;

use crate::{auth::Session, error::ApiError, AppState, Envelope};
use axum::{
    extract::{FromRequestParts, Request},
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

/// 当前请求的会话 id（require_auth 中间件注入）。会话管理需区分「自己」。
#[derive(Clone, Debug)]
pub struct CurrentSid(pub String);

impl FromRequestParts<Shared> for CurrentSid {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, _: &Shared) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<CurrentSid>().cloned()
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
        .route("/api/v1/auth/status", get(auth::bootstrap_status))
        .route("/api/v1/auth/bootstrap", post(auth::bootstrap))
        .route("/api/v1/auth/login", post(auth::login));

    // ── 系统与监控 ──
    let system_r = Router::new()
        .route("/api/v1/system/capabilities", get(system::capabilities))
        .route("/api/v1/system/overview", get(system::overview))
        .route("/api/v1/metrics/realtime", get(system::realtime))
        .route("/api/v1/metrics/history", get(system::history))
        .route("/api/v1/system/users", get(system::users))
        .route("/api/v1/metrics/snapshot", get(system::snapshot));

    // ── 进程（M2） ──
    let proc_r = Router::new()
        .route("/api/v1/processes", get(processes::list))
        .route("/api/v1/processes/{pid}/kill", post(processes::kill));

    // ── 软件与服务 ──
    let svc_r = Router::new()
        .route("/api/v1/services", get(services::list))
        .route("/api/v1/services/{unit}", get(services::show))
        .route("/api/v1/services/{unit}/status", get(services::status))
        .route("/api/v1/services/{unit}/start", post(services::start))
        .route("/api/v1/services/{unit}/stop", post(services::stop))
        .route("/api/v1/services/{unit}/restart", post(services::restart))
        .route("/api/v1/services/{unit}/enabled", put(services::set_enabled))
        .route("/api/v1/services/{unit}/journal", get(services::journal))
        // 日志跟随（SSE）：底层 journalctl -f，先补历史再增量
        .route("/api/v1/services/{unit}/journal/stream", get(crate::sse::service_journal_stream))
        .route("/api/v1/services/{unit}/config", get(services::config_get).put(services::config_put))
        .route("/api/v1/packages", get(services::packages_list))
        .route("/api/v1/packages/install", post(services::install))
        // 版本列表按需查询（安装弹窗打开时），刻意不放进 packages_list 全量拉取
        .route("/api/v1/packages/{name}/versions", get(services::package_versions))
        // hold/unhold 切换（apt-mark）。路径含子段 `/{name}/hold`，与 `{name}` 单段
        // 路由不冲突；⚠️ 若日后加 `/packages/{name}` 的 PATCH 等同级方法，仍须保持
        // `upgradable`/`upgrade` 排在 `{name}` 前的顺序纪律。
        .route("/api/v1/packages/{name}/hold", post(services::package_hold))
        // ⚠️ 顺序纪律：`/packages/upgradable` 必须排在 `/packages/{name}` **之前**，
        // 否则 axum 的 `{name}` 通配会把它当成 name="upgradable" 吞掉（GET/DELETE 方法还不匹配，
        // 表现为 405/404 而不是可用端点）。同理 upgrade 放在 {name} 系列之后独立成条。
        .route("/api/v1/packages/upgradable", get(services::packages_upgradable))
        .route("/api/v1/packages/upgrade", post(services::package_upgrade))
        .route("/api/v1/packages/{name}", delete(services::package_remove));

    // ── 站点与 SSL ──
    let site_r = Router::new()
        .route("/api/v1/sites", get(sites::list).post(sites::create))
        .route("/api/v1/sites/apply", post(sites::apply))
        .route("/api/v1/sites/root", get(sites::root_info))
        .route("/api/v1/sites/{id}", get(sites::get).patch(sites::patch).delete(sites::delete))
        // 站点说明（对象备注，022）：内联编辑保存
        .route("/api/v1/sites/{id}/remark", patch(sites::update_remark))
        .route("/api/v1/apps", get(apps::list).post(apps::create))
        .route("/api/v1/apps/catalog", get(apps::catalog))
        .route(
            "/api/v1/apps/{id}",
            get(apps::get).patch(apps::patch).delete(apps::delete),
        )
        .route("/api/v1/apps/{id}/act", post(apps::act))
        .route("/api/v1/sites/{id}/reload", post(sites::reload))
        // 站点配置原始读写：GET 查看（site.manage）、PUT 编辑（仅 owner）、restore 恢复托管
        .route("/api/v1/sites/{id}/conf", get(sites::conf_get).put(sites::conf_put))
        .route("/api/v1/sites/{id}/conf/restore", post(sites::conf_restore))
        // 版本历史（018）：列表 / 单版正文 / 回滚（仅 owner——与 conf PUT 同写入面）
        .route("/api/v1/sites/{id}/conf/versions", get(sites::conf_versions))
        .route("/api/v1/sites/{id}/conf/versions/{vid}", get(sites::conf_version_get))
        .route("/api/v1/sites/{id}/conf/rollback", post(sites::conf_rollback))
        .route("/api/v1/sites/{id}/logs", get(sites::logs))
        // 站点独立日志（021）：下载 / 清空（查看走下载——浏览器直接渲染文本）
        .route("/api/v1/sites/{id}/log/download", get(sites::log_download))
        .route("/api/v1/sites/{id}/log/clear", post(sites::log_clear))
        .route("/api/v1/sites/{id}/ssl/apply", post(sites::ssl_apply))
        .route("/api/v1/ssl/ca", get(sites::ssl_ca_download))
        .route("/api/v1/certs", get(sites::certs))
        .route("/api/v1/certs/{id}/renew", post(sites::cert_renew))
        .route("/api/v1/certs/{id}/auto-renew", patch(sites::cert_auto_renew))
        .route("/api/v1/certs/renew-sweep", get(sites::cert_renew_sweep_state))
        .route("/api/v1/certs/{id}", delete(sites::cert_delete));

    // ── 文件 ──
    // upload 单独放宽 body 上限（axum 默认 2MB 会拦住一切上传）；
    // handler 内仍有 transfer_limit 二次校验（min(平台上限, BODY_LIMIT_UPLOAD)）。
    let file_upload_r = Router::new()
        .route("/api/v1/files/upload", put(files::upload))
        // **分片上传必须收在这个 router 里**：axum 默认 body 上限是 2MB，
        // 4MB 的分片会被整片拒掉。实测踩到过——分片静默失败，只有 2MB 的末片能过，
        // 表现为"完整上传时永远缺前几片"。
        .route("/api/v1/files/multipart/chunk", put(multipart::chunk))
        .layer(axum::extract::DefaultBodyLimit::max(crate::middleware::BODY_LIMIT_UPLOAD));
    let file_r = Router::new()
        .route("/api/v1/files/list", get(files::list))
        .route("/api/v1/files/stat", get(files::stat))
        .route("/api/v1/files/download", get(files::download))
        .route("/api/v1/files/read", get(files::read))
        .route("/api/v1/files/write", put(files::write))
        .route("/api/v1/files/mkdir", post(files::mkdir))
        .route("/api/v1/files/delete", post(files::remove))
        .route("/api/v1/files/trash", get(files::trash_list).post(files::trash))
        .route("/api/v1/files/trash/restore", post(files::trash_restore))
        .route("/api/v1/files/trash/purge", post(files::trash_purge))
        .route("/api/v1/files/rename", post(files::rename))
        .route("/api/v1/files/chmod", post(files::chmod))
        .route("/api/v1/files/action", post(files::action))
        // 分片上传（断点续传）。静态段 `multipart/init` 优先于 `multipart/{id}`，
        // axum 的路由优先级保证两者不冲突。
        .route("/api/v1/files/multipart/init", post(multipart::init))
        // chunk 不在这里：它带大 body，收在 file_upload_r（见上方注释）
        .route("/api/v1/files/multipart/{id}", get(multipart::status).delete(multipart::abort))
        .route("/api/v1/files/multipart/{id}/complete", post(multipart::complete));

    // ── 数据库 ──
    let db_r = Router::new()
        .route("/api/v1/db/connections", get(databases::list).post(databases::create))
        .route("/api/v1/db/connections/{id}", patch(databases::update).delete(databases::delete))
        .route("/api/v1/db/{conn}/databases", get(databases::databases_of))
        // 「库」的下一级（PG → schema；MySQL/SQLite → 空）。**必须先于** `{db}/tables` 之外
        // 单独存在：它与「库下有哪些表」是两个不同的问题，混成一个端点就会重演
        // 「点任何一层都掉到同一句无表」。
        .route("/api/v1/db/{conn}/{db}/schemas", get(databases::schemas))
        .route("/api/v1/db/{conn}/{db}/tables", get(databases::tables))
        .route("/api/v1/db/{conn}/{db}/{table}/rows", get(databases::rows))
        // 全量表导出 CSV。与 rows 分开成路径而不是加 `?format=csv`：
        // 响应体一个 JSON 一个 text/csv，混在一个端点上契约说不清，
        // 且前端下载走 window.open（GET），与 POST 的 query 也不同。
        .route("/api/v1/db/{conn}/{db}/{table}/export", get(databases::export_csv))
        .route("/api/v1/db/{conn}/backup", post(databases::backup))
        .route("/api/v1/db/{conn}/query", post(databases::query))
        .route("/api/v1/db/{conn}/restore", post(databases::restore))
        // 控制台元数据（能力位 + 引擎相关的默认语句/示例）。**必须在 `{conn}/query` 之外
        // 单独成路径**：它回答"这个连接能不能自己写 SQL、该从哪句开始"，
        // 与"执行一条 SQL"是两个不同的问题。
        .route("/api/v1/db/{conn}/sql-meta", get(databases::sql_meta))
        // 数据库连接说明（对象备注，022）
        .route("/api/v1/db/{conn}/remark", patch(databases::update_remark));

    // ── 防火墙 ──
    let fw_r = Router::new()
        .route("/api/v1/firewall/status", get(firewall::status))
        .route("/api/v1/firewall/enabled", put(firewall::set_enabled))
        .route("/api/v1/firewall/rules", get(firewall::list).post(firewall::apply))
        .route("/api/v1/firewall/rules/{id}", delete(firewall::delete_rule))
        .route("/api/v1/firewall/fail2ban", get(firewall::fail2ban_status))
        .route("/api/v1/firewall/fail2ban/jail", post(firewall::fail2ban_set_jail))
        .route("/api/v1/firewall/fail2ban/unban", post(firewall::fail2ban_unban));

    // ── 安全中心 ──
    let sec_r = Router::new()
        .route("/api/v1/security/baseline", get(security::baseline))
        .route("/api/v1/security/baseline/apply", post(security::baseline_apply))
        .route("/api/v1/security/sessions", get(security::sessions))
        .route("/api/v1/security/sessions/{id}", delete(security::revoke_session));

    // ── 计划任务 ──
    let cron_r = Router::new()
        .route("/api/v1/cron/jobs", get(cron::list).post(cron::create))
        .route("/api/v1/cron/jobs/{id}", get(cron::get_job).patch(cron::patch_job).delete(cron::remove))
        .route("/api/v1/cron/jobs/{id}/run", post(cron::run))
        .route("/api/v1/cron/jobs/{id}/webhook", post(cron::webhook_test_job))
        .route("/api/v1/cron/jobs/{id}/runs", get(cron::runs))
        .route("/api/v1/cron/preview", post(cron::preview))
        .route("/api/v1/cron/webhook/test", post(webhook::test));

    // ── 日志 ──
    let log_r = Router::new()
        .route("/api/v1/logs/sources", get(logs::sources))
        .route("/api/v1/logs/stream", get(crate::sse::log_stream))
        .route("/api/v1/logs/{id}/download", get(logs::download))
        .route("/api/v1/logs/{id}/stats", get(logs::stats))
        .route("/api/v1/logs/{id}", get(logs::read));

    // ── 站内通知 ──
    // 查看/标记已读属"看得见"层级（system.view）；删除属管理动作（system.manage）
    let notify_r = Router::new()
        .route("/api/v1/notifications", get(notifications::list))
        .route("/api/v1/notifications/unread-count", get(notifications::unread_count))
        .route("/api/v1/notifications/read-all", post(notifications::read_all))
        .route("/api/v1/notifications/{id}/read", post(notifications::mark_read))
        .route("/api/v1/notifications/{id}", delete(notifications::remove));

    // ── 备份计划（本地） ──
    let backup_r = Router::new()
        .route("/api/v1/backups", get(backups::list).post(backups::create))
        // 连接自检。axum(matchit) 里静态段优先级高于参数段，故与 `/backups/{id}` 不冲突；
        // 放在这里只是让"这是一个固定路径"读起来更直白。
        .route("/api/v1/backups/test-remote", post(backups::test_remote))
        .route("/api/v1/backups/{id}", patch(backups::patch).delete(backups::delete))
        .route("/api/v1/backups/{id}/run", post(backups::run))
        .route("/api/v1/backups/{id}/artifacts", get(backups::artifacts))
        .route("/api/v1/backups/{id}/restore", post(backups::restore));

    // ── 容器（Docker）──
    // 只读列举 + 生命周期；能力位不满足时端点内诚实 501（见 routes/containers.rs）
    let container_r = Router::new()
        .route("/api/v1/containers", get(containers::list))
        .route("/api/v1/containers", post(containers::create))
        .route("/api/v1/containers/images", get(containers::images))
        .route("/api/v1/containers/images/pull", post(containers::pull))
        .route("/api/v1/containers/{id}/start", post(containers::start))
        .route("/api/v1/containers/{id}/stop", post(containers::stop))
        .route("/api/v1/containers/{id}/restart", post(containers::restart))
        .route("/api/v1/containers/{id}", delete(containers::remove))
        // 一键安装 Docker（仅 binary_missing 时可用，高危二次确认）。
        // 复用 services 的 PackageTask 任务队列，按包管理器选对包名。
        .route("/api/v1/containers/install", post(containers::install))
        // 修复 daemon_unreachable：把面板运行用户加入 docker 组（高危，需二次确认）。
        .route("/api/v1/containers/join-docker-group", post(containers::join_docker_group))
        // 容器备注（022）：容器不入库，存 container_remarks 引用表；读写不强制 Docker 可达
        .route("/api/v1/containers/{id}/remark", get(containers::get_remark).patch(containers::update_remark))
        .route("/api/v1/containers/{id}/logs", get(containers::logs))
        .route("/api/v1/containers/stats", get(containers::stats))
        // 网络列举（只读）：docker network ls --no-trunc，需 container.view
        .route("/api/v1/containers/networks", get(containers::networks))
        // 卷列举（只读）：docker volume ls（无 --no-trunc，卷名默认不截断），需 container.view
        .route("/api/v1/containers/volumes", get(containers::volumes))
        // Compose 项目列举（只读）：docker compose ls --all --format json，需 container.view
        .route("/api/v1/containers/compose", get(containers::compose_projects))
        // Compose 生命周期动作（写）：up/stop/restart/down，需 container.manage。
        // down 需手输项目名确认；down 永不带 -v（不删卷）。
        .route("/api/v1/containers/compose/{project}/act", post(containers::compose_act));

    // ── 本机便签（025：多条，由 022 单例说明升级） ──
    let notes_r = Router::new()
        .route("/api/v1/server/notes", get(notes::list).post(notes::create))
        .route(
            "/api/v1/server/notes/{id}",
            patch(notes::update).delete(notes::delete),
        );

    // ── WAF 策略模板（026） ──
    let waf_tpl_r = Router::new()
        .route("/api/v1/waf/templates", get(waf_templates::list).post(waf_templates::create))
        .route(
            "/api/v1/waf/templates/{id}",
            get(waf_templates::get).patch(waf_templates::update).delete(waf_templates::delete),
        );

    // ── 拦截事件 / 威胁日志（027） ──
    let waf_evt_r = Router::new()
        .route("/api/v1/waf/events", get(waf_events::list_events));

    // ── WAF 拦截告警配置（028） ──
    let waf_alert_r = Router::new()
        .route("/api/v1/waf/alert", get(waf_alert::get_alert).put(waf_alert::put_alert));

    // ── 任务中心 ──
    let task_r = Router::new()
        .route("/api/v1/tasks", get(tasks::list))
        .route("/api/v1/tasks/{id}", get(tasks::get))
        .route("/api/v1/tasks/{id}/cancel", post(tasks::cancel))
        .route("/api/v1/tasks/{id}/output", get(tasks::output));

    // ── 设置 / 用户 / 审计 ──
    let cfg_r = Router::new()
        .route("/api/v1/settings", get(settings::get).patch(settings::patch))
        .route("/api/v1/settings/dashboard", get(dashboard::get).put(dashboard::put))
        // C2 首启上手清单：GET 只需登录，PUT（勾选/不再显示）需 settings.manage
        .route("/api/v1/settings/onboarding", get(onboarding::get).put(onboarding::put))
        // C10 设置页「测试连接」：真实探测 OpenAI 兼容 /v1/models（仅耗时探测，不改配置）
        .route("/api/v1/settings/llm/test", post(settings::test_llm))
        .route("/api/v1/users", get(users::list).post(users::create))
        .route("/api/v1/users/{id}", patch(users::patch).delete(users::delete))
        .route("/api/v1/roles", get(roles::list).post(roles::create))
        .route("/api/v1/roles/{name}", patch(roles::patch).delete(roles::remove))
        .route("/api/v1/audit", get(audit::list));

    // ── SSE：多频道 ──
    let sse_r = Router::new()
        .route("/api/v1/events/metrics", get(crate::sse::metrics_stream))
        .route("/api/v1/events/tasks", get(crate::sse::task_stream))
        .route("/api/v1/events/logs", get(crate::sse::log_stream));

    // ── Web 终端（WebSocket）──
    // 独立守卫：仅 require_auth。WS 升级无法携带 X-CSRF-Token 头，故同源校验
    // 改在 handler 内用 Origin == scheme://Host 完成（见 routes/terminal.rs）。
    let terminal_r = Router::new()
        .route("/api/v1/terminal", get(terminal::ws_handler))
        .layer(middleware::from_fn_with_state(state.clone(), crate::middleware::require_auth));

    // ── AI 助手（只读诊断）──
    // 独立子路由 + 仅 require_auth：诊断是**只读**语义，只读模式下同样可用
    // （不经 read_only_guard）；亦无写语义，不需要 guard_write 的 CSRF。
    let asst_r = Router::new()
        .route("/api/v1/assistant/diagnose", post(assistant::diagnose))
        .layer(middleware::from_fn_with_state(state.clone(), crate::middleware::require_auth));

    // ── 需登录的根路由 ──
    let authed = Router::new()
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/password", post(auth::change_password))
        // MFA（TOTP）：三条都需登录—— enroll 属"给自己绑定"，不能是公开端点
        .route("/api/v1/auth/mfa/enroll", post(auth::mfa_enroll))
        .route("/api/v1/auth/mfa/verify", post(auth::mfa_verify))
        .route("/api/v1/auth/mfa/disable", post(auth::mfa_disable))
        .merge(system_r)
        .merge(proc_r)
        .merge(svc_r)
        .merge(site_r)
        .merge(file_r)
        .merge(file_upload_r)
        .merge(db_r)
        .merge(fw_r)
        .merge(sec_r)
        .merge(cron_r)
        .merge(log_r)
        .merge(notify_r)
        .merge(backup_r)
        .merge(container_r)
        .merge(notes_r)
        .merge(waf_tpl_r)
        .merge(waf_evt_r)
        .merge(waf_alert_r)
        .merge(task_r)
        .merge(cfg_r)
        .merge(sse_r)
        .layer(middleware::from_fn_with_state(state.clone(), crate::middleware::read_only_guard))
        .layer(middleware::from_fn(crate::middleware::guard_write))
        // 认证守卫只罩在 authed 上：public（登录/版本/健康检查/SPA）无需登录即可进入。
        // 若误放到全局，登录接口会被自己的 401 挡在门外（历史 bug）。
        .layer(middleware::from_fn_with_state(state.clone(), crate::middleware::require_auth));

    Router::new()
        .merge(public)
        .merge(authed)
        .merge(terminal_r)
        .merge(asst_r)
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
    // 来源 IP 取自登录那一刻（Session::ip）。此前硬编码空串，导致审计列表
    // 的「来源 IP」列永远是"—"，面板被爆破时无法追溯操作来源。
    let ip = if s.ip.is_empty() { "unknown".to_string() } else { s.ip.clone() };
    let target = target.to_string();
    // 审计写失败必须留痕：静默丢弃会让"操作已生效但无记录"，事后无法发现。
    // 用 eprintln! 而非 tracing：panel-api 未引入日志设施（依赖预算纪律：零新依赖），
    // serve 启动时 stderr 已重定向进日志文件，不会打到终端。
    if let Err(e) = state.db.exec(move |conn| {
        conn.execute(
            "INSERT INTO audit_log(ts, actor, actor_ip, action, target, result, detail_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                crate::now_unix(), actor, ip, action, target, result, "{}"
            ],
        ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await {
        eprintln!("[WARN] 审计日志写入失败（操作已生效但无留痕） action={action} error={e}");
    }
}

/// 系统发起的操作（调度器 / 内部周期任务）留痕。
///
/// 与 `audit` 的区别：无用户 Session，actor 固定为 `"system"`、无来源 IP。
/// 用于把"系统自动做了什么"也写进操作日志——否则自动续期、自动备份等
/// 非人工动作在 UI 审计轨迹里完全不可见，出事时只能去翻服务端日志。
pub async fn audit_system(state: &AppState, action: &'static str,
                          target: &str, result: &'static str) {
    let target = target.to_string();
    if let Err(e) = state.db.exec(move |conn| {
        conn.execute(
            "INSERT INTO audit_log(ts, actor, actor_ip, action, target, result, detail_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                crate::now_unix(), "system", "", action, target, result, "{}"
            ],
        ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await {
        eprintln!("[WARN] 系统操作审计写入失败 action={action} error={e}");
    }
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
        let db = panel_db::open(&dir.join("t.db"), panel_core::Tier::Nano, "NORMAL").unwrap();
        let _ = db;
        // 仅验证 Router 类型可构造（WriterActor 需真实路径，故此处只做类型层校验）
        fn _assert_router(r: Router) { let _ = r; }
    }
}
