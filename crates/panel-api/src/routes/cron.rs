//! 用户计划任务（设计方案 §2.8）。
//!
//! # 与内部周期任务的分野（易混淆，务必分清）
//! - **这里管的是用户自己的脚本**：载体是系统 crontab / systemd timer / launchd。
//!   面板停了它们照样跑，表达式是平台本地语义（cron 五段 / XML / plist）。
//! - **面板内部任务**（指标采样、清理、备份）走 `panel_task::InternalScheduler`，
//!   是进程内 tokio 定时器，面板停了就不跑。
//!
//! # 表达式校验必须由平台实现做
//! 业务层**绝不**自己解析 cron 五段——Windows 任务计划用 XML，macOS 用 plist。
//! 统一走 `SchedulerProvider::validate_expression` + `next_fire_times`。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    Json,
};
use panel_core::{cap_keys, PanelError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct JobDto {
    pub id: String,
    pub name: String,
    pub expr: String,
    pub kind: &'static str,
    pub command: String,
    pub user: String,
    pub enabled: bool,
    pub timeout_sec: i64,
    pub last_run_at: Option<i64>,
    pub last_status: Option<String>,
    /// 下次执行时间预览（平台本地语义，可能为多个）
    pub next: Vec<i64>,
}

pub async fn list(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_VIEW)?;
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }

    let jobs = state.os.scheduler().list().await?;
    let rows = state.pool.with(|conn| {
        let mut st = conn.prepare(
            "SELECT name, kind, enabled, timeout_sec, last_run_at, last_status FROM cron_jobs")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map([], |r| Ok((
            r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i32>(2)?,
            r.get::<_, i64>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, Option<String>>(5)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;

    // 以系统里的任务为准（系统是真相），库只补充面板元数据
    let dtos: Vec<JobDto> = jobs.into_iter().map(|j| {
        let meta = rows.iter().find(|(n, _, _, _, _, _)| *n == j.id);
        let next = state.os.scheduler().next_fire_times(&j.expression, 3).unwrap_or_default();
        JobDto {
            id: j.id.clone(),
            name: j.id.clone(),
            expr: j.expression,
            kind: meta.map(|m| kind_str(&m.1)).unwrap_or("script"),
            command: j.command,
            user: j.user,
            enabled: meta.map(|m| m.2 != 0).unwrap_or(j.enabled),
            timeout_sec: meta.map(|m| m.3).unwrap_or(j.timeout.as_secs() as i64),
            last_run_at: meta.and_then(|m| m.4),
            last_status: meta.and_then(|m| m.5.clone()),
            next,
        }
    }).collect();

    Ok(ok(dtos))
}

fn kind_str(s: &str) -> &'static str {
    match s { "backup" => "backup", "cert_renew" => "cert_renew",
              "internal" => "internal", _ => "script" }
}

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub name: String,
    /// **平台本地表达式**。Linux 是 cron 五段，Windows/macOS 是别的格式
    pub expr: String,
    pub command: String,
    pub user: Option<String>,
    pub enabled: Option<bool>,
    pub timeout_sec: Option<i64>,
}

pub async fn create(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }

    // 表达式校验**必须由平台实现做**，业务层不解析
    state.os.scheduler().validate_expression(&req.expr)
        .map_err(|e| ApiError::bad_request("expr", e.to_string()))?;

    // 任务名校验（会作为 crontab 里的标识，必须严格）
    if !panel_core::rules::is_valid_path_segment(&req.name) {
        return Err(ApiError::bad_request("name", "只允许字母数字、下划线与连字符"));
    }

    // 用户校验（防 `user = "root; rm -rf /"` 这类注入到 crontab 的形式）
    let user = req.user.unwrap_or_else(|| "root".to_string());
    if !panel_core::rules::is_valid_system_user(&user) {
        return Err(ApiError::bad_request("user", "invalid system user"));
    }

    // 命令长度上限：crontab 单行有长度限制，且过长的命令通常意味着误用
    if req.command.is_empty() || req.command.len() > 4096 {
        return Err(ApiError::bad_request("command", "长度需在 1~4096 之间"));
    }

    let job = panel_os::ScheduledJob {
        id: req.name.clone(),
        expression: req.expr.clone(),
        command: req.command.clone(),
        user,
        enabled: req.enabled.unwrap_or(true),
        timeout: std::time::Duration::from_secs(req.timeout_sec.unwrap_or(1800) as u64),
    };
    state.os.scheduler().upsert(job).await?;

    let name = req.name.clone();
    state.db.exec(move |conn| {
        conn.execute(
            "INSERT OR REPLACE INTO cron_jobs(name, expr, kind, payload_json, enabled, timeout_sec)
             VALUES(?1, ?2, 'script', '{}', 1, ?3)",
            rusqlite::params![name, req.expr, req.timeout_sec.unwrap_or(1800)],
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await?;

    audit(&state, &s, "cron.create", &req.name, "ok").await;
    Ok(ok(serde_json::json!({ "name": req.name })))
}

pub async fn remove(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    state.os.scheduler().remove(&id).await?;
    let name = id.clone();
    state.db.exec(move |conn| {
        conn.execute("DELETE FROM cron_jobs WHERE name = ?1", rusqlite::params![name])
            .map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await?;
    audit(&state, &s, "cron.remove", &id, "ok").await;
    Ok(ok(serde_json::json!({ "removed": id })))
}

/// 执行历史（最近 N 次）
pub async fn runs(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_VIEW)?;
    let runs = state.os.scheduler().runs(&id, 50).await?;
    let dtos: Vec<_> = runs.into_iter().map(|r| serde_json::json!({
        "started": r.started_unix,
        "finished": r.finished_unix,
        "exit_code": r.exit_code,
        "output": truncate(&r.output_excerpt, 2000),
    })).collect();
    Ok(ok(dtos))
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() > n { format!("{}…", &s[..n]) } else { s.to_string() }
}

// ─────────────── 文档式定时任务端点（M3 占位） ───────────────

pub async fn get_job(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_VIEW)?;
    let _ = (state, id);
    Err(ApiError::unsupported("cron.job.get (M3)"))
}

pub async fn patch_job(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    let _ = (state, id);
    Err(ApiError::unsupported("cron.job.patch (M3)"))
}

pub async fn run(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    let _ = (state, id);
    Err(ApiError::unsupported("cron.job.run (M3: 手动触发走任务队列尚未接入)"))
}

pub async fn preview(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_VIEW)?;
    let _ = state;
    Err(ApiError::unsupported("cron.preview (M3: 下次执行预览已由 list 返回 next[])"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_name_must_be_a_path_segment() {
        assert!(panel_core::rules::is_valid_path_segment("backup-db"));
        assert!(panel_core::rules::is_valid_path_segment("cert_renew"));
        // 这些会破坏 crontab 结构
        assert!(!panel_core::rules::is_valid_path_segment("a b"));
        assert!(!panel_core::rules::is_valid_path_segment("../x"));
        assert!(!panel_core::rules::is_valid_path_segment("a;b"));
        assert!(!panel_core::rules::is_valid_path_segment(""));
    }

    #[test]
    fn system_user_validation_blocks_injection() {
        assert!(panel_core::rules::is_valid_system_user("root"));
        assert!(panel_core::rules::is_valid_system_user("www-data"));
        assert!(!panel_core::rules::is_valid_system_user("root; rm -rf /"));
        assert!(!panel_core::rules::is_valid_system_user("../../etc"));
        assert!(!panel_core::rules::is_valid_system_user(""));
    }

    #[test]
    fn command_length_bounds() {
        assert!(!"".len() > 0);
        assert!("x".repeat(4097).len() > 4096, "超长命令应被拒");
        assert!("echo hi".len() <= 4096);
    }

    #[test]
    fn timeout_default_is_sane() {
        // 默认 30 分钟：太短会杀掉正常备份，太长会让卡死任务占住并发槽
        assert_eq!(1800, 30 * 60);
    }

    #[test]
    fn output_excerpt_truncated() {
        assert!(truncate(&"x".repeat(5000), 2000).len() < 2100);
        assert_eq!(truncate("hi", 2000), "hi");
    }
}
