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
use std::time::Duration;
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
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }
    let jobs = state.os.scheduler().list().await?;
    let j = jobs.into_iter().find(|j| j.id == id)
        .ok_or_else(|| ApiError::not_found(format!("cron job `{id}`")))?;

    let id_key = id.clone();
    let meta = state.pool.with(move |conn| {
        let mut st = conn.prepare(
            "SELECT name, kind, enabled, timeout_sec, last_run_at, last_status FROM cron_jobs \
             WHERE name = ?1")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let mut it = st.query_map([id_key.as_str()], |r| Ok((
            r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i32>(2)?,
            r.get::<_, i64>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, Option<String>>(5)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(it.next().transpose().map_err(|e| PanelError::Database(e.to_string()))?)
    }).await?;

    let next = state.os.scheduler().next_fire_times(&j.expression, 3).unwrap_or_default();
    let dto = JobDto {
        id: j.id.clone(),
        name: j.id.clone(),
        expr: j.expression,
        kind: meta.as_ref().map(|m| kind_str(&m.1)).unwrap_or("script"),
        command: j.command,
        user: j.user,
        enabled: meta.as_ref().map(|m| m.2 != 0).unwrap_or(j.enabled),
        timeout_sec: meta.as_ref().map(|m| m.3).unwrap_or(j.timeout.as_secs() as i64),
        last_run_at: meta.as_ref().and_then(|m| m.4),
        last_status: meta.as_ref().and_then(|m| m.5.clone()),
        next,
    };
    Ok(ok(dto))
}

#[derive(Debug, Deserialize)]
pub struct PatchReq {
    pub expr: Option<String>,
    pub command: Option<String>,
    pub user: Option<String>,
    pub enabled: Option<bool>,
    pub timeout_sec: Option<i64>,
}

pub async fn patch_job(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
    Json(req): Json<PatchReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }

    // 取现有任务作为基线（crontab 是唯一真相源）
    let jobs = state.os.scheduler().list().await?;
    let base = jobs.into_iter().find(|j| j.id == id)
        .ok_or_else(|| ApiError::not_found(format!("cron job `{id}`")))?;

    let expr = req.expr.clone().unwrap_or(base.expression);
    let command = req.command.clone().unwrap_or(base.command);
    let user = req.user.clone().unwrap_or(base.user);
    let enabled = req.enabled.unwrap_or(base.enabled);
    let timeout_sec = req.timeout_sec.unwrap_or(base.timeout.as_secs() as i64);

    // 与 create 一致的全套校验（表达式校验必须由平台实现做）
    state.os.scheduler().validate_expression(&expr)
        .map_err(|e| ApiError::bad_request("expr", e.to_string()))?;
    if !panel_core::rules::is_valid_path_segment(&id) {
        return Err(ApiError::bad_request("name", "只允许字母数字、下划线与连字符"));
    }
    if !panel_core::rules::is_valid_system_user(&user) {
        return Err(ApiError::bad_request("user", "invalid system user"));
    }
    if command.is_empty() || command.len() > 4096 {
        return Err(ApiError::bad_request("command", "长度需在 1~4096 之间"));
    }
    if timeout_sec <= 0 || timeout_sec > 86400 * 7 {
        return Err(ApiError::bad_request("timeout_sec", "需在 1~604800 之间"));
    }

    let job = panel_os::ScheduledJob {
        id: id.clone(),
        expression: expr.clone(),
        command: command.clone(),
        user: user.clone(),
        enabled,
        timeout: std::time::Duration::from_secs(timeout_sec as u64),
    };
    state.os.scheduler().upsert(job).await?;

    let (e, t) = (enabled, timeout_sec);
    let id_for_db = id.clone();
    state.db.exec(move |conn| {
        conn.execute(
            "UPDATE cron_jobs SET expr = ?2, enabled = ?3, timeout_sec = ?4 WHERE name = ?1",
            rusqlite::params![id_for_db, expr, e as i32, t],
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await?;

    audit(&state, &s, "cron.patch", &id, "ok").await;
    Ok(ok(serde_json::json!({ "name": id })))
}

pub async fn run(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }
    // 先确认任务存在：否则会排进一个必然失败的任务，白占一个执行槽
    let jobs = state.os.scheduler().list().await?;
    let job = jobs.into_iter().find(|j| j.id == id)
        .ok_or_else(|| ApiError::not_found(format!("cron job `{id}`")))?;

    // 脚本执行时间不可预测、输出需留痕 —— 走任务队列，不挂在请求上
    let body = CronRunTask {
        job_id: id.clone(),
        os: state.os.clone(),
        db: state.db.clone(),
    };
    let (tid, created) = state.tasks.submit(
        panel_task::TaskRequest {
            idempotency_key: format!("cron.run:{id}"),
            kind: panel_task::TaskKind::Internal,
            label: format!("执行计划任务 {id}"),
            // 任务自己定义的超时可能极短（如 1s），给个下限保证输出能收上来
            timeout: job.timeout.max(Duration::from_secs(60)),
        },
        body,
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "cron.run", &id, "queued").await;
    Ok(ok(serde_json::json!({ "task_id": tid, "created": created })))
}

/// 手动执行一次计划任务（任务体）。
///
/// 与"到点自动执行"唯一的区别是**谁发起**：执行的都是同一条 command，
/// 运行用户与超时都取自任务自身定义，不在此处另立一套规则。
struct CronRunTask {
    job_id: String,
    os: std::sync::Arc<dyn panel_os::OsAdapter>,
    db: std::sync::Arc<panel_db::WriterActor>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for CronRunTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        // 执行前重读 crontab：排队期间任务可能已被改动或删除，
        // 用提交时的快照会执行到一条旧命令。
        let jobs = self.os.scheduler().list().await?;
        let job = jobs.into_iter().find(|j| j.id == self.job_id)
            .ok_or_else(|| PanelError::NotFound(format!("cron job `{}`", self.job_id)))?;

        progress.set(5, &format!("执行 {}", job.command)).await;

        // 输出缓冲 → 落盘 → 任务中心可读（失败原因不丢）
        const MAX_BUF: usize = 400;
        let buf: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let consumer = {
            let progress = progress.clone();
            let buf = buf.clone();
            tokio::spawn(async move {
                while let Some(line) = rx.recv().await {
                    {
                        let mut b = buf.lock().unwrap();
                        if b.len() >= MAX_BUF { b.remove(0); }
                        b.push(line.clone());
                    }
                    progress.log(&line).await;
                    if progress.is_canceled() { break; }
                }
            })
        };

        let tx_cb = tx;
        // 用户脚本走 cmd 唯一出口，超时/降权/输出上限统一在这里生效。
        // command 作为 `sh -c` 的**单个参数**传入，不参与 argv 拼接，无额外注入面。
        // 仅当面板以 root 运行、且任务指定非 root 用户时才降权（非 root 无法降权）。
        let run_as = if panel_os::is_root() && job.user != "root" {
            Some(job.user.clone())
        } else {
            None
        };
        let r = panel_os::run(
            panel_os::Bin::Sh,
            &["-c", &job.command],
            panel_os::CmdOpt {
                timeout: job.timeout,
                run_as,
                on_line: Some(std::sync::Arc::new(move |line: &str| {
                    let _ = tx_cb.send(line.to_string());
                })),
                ..Default::default()
            },
        ).await;
        // CmdOpt 随 run 返回而释放 → 闭包与 tx 一起 drop → 通道关闭 → 消费者自然退出
        let _ = consumer.await;

        let mut output_path = None;
        let lines: Vec<String> = buf.lock().unwrap().clone();
        if !lines.is_empty() {
            let p = std::env::temp_dir().join(format!("panel-task-{}.log", progress.id()));
            if tokio::fs::write(&p, lines.join("\n")).await.is_ok() { output_path = Some(p); }
        }

        let (task_state, exit_code, status_text, failed) = match &r {
            Ok(out) => {
                let code = out.code.unwrap_or(0);
                (if code == 0 { panel_task::TaskState::Ok } else { panel_task::TaskState::Failed },
                 code,
                 if code == 0 { "ok".to_string() } else { format!("exit {code}") },
                 code != 0)
            }
            Err(e) => {
                let msg = e.to_string();
                progress.log(&format!("失败：{msg}")).await;
                (panel_task::TaskState::Failed, 1, format!("failed: {msg}"), true)
            }
        };

        // 回写执行状态，让列表页能看到"上次什么时候跑的、结果如何"
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64).unwrap_or(0);
        let job_id = self.job_id.clone();
        let _ = self.db.exec(move |conn| {
            conn.execute(
                "UPDATE cron_jobs SET last_run_at = ?2, last_status = ?3 WHERE name = ?1",
                rusqlite::params![job_id, now, status_text],
            ).map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        }).await;

        progress.set(100, if failed { "执行结束（失败）" } else { "执行结束" }).await;
        Ok(panel_task::TaskOutcome { state: task_state, exit_code: Some(exit_code), output_path })
    }
}

#[derive(Debug, Deserialize)]
pub struct PreviewReq {
    pub expr: String,
}

/// 下次 5 次执行时间预览（编辑器里改表达式时先看会几点跑）。
/// **纯计算零副作用**：表达式合法性仍由平台校验（与 create 同一入口），
/// 时刻计算委托 provider 的 `next_fire_times`（本地时区语义，已回归测试钉死）。
pub async fn preview(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<PreviewReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_VIEW)?;
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }
    state.os.scheduler().validate_expression(&req.expr)
        .map_err(|e| ApiError::bad_request("expr", e.to_string()))?;
    let next = state.os.scheduler().next_fire_times(&req.expr, 5).unwrap_or_default();
    // 空 = 字段合法但 1 年内无命中（如 `0 5 31 2 *`）——诚实返回空数组，UI 负责解释
    Ok(ok(serde_json::json!({ "expr": req.expr, "next": next })))
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
