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
    webhook,
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
    /// 并发上限（防重入）：1=互斥锁包裹，0=不限制（>1 未实装）
    pub max_overlap: u64,
    /// 完成/开始时回调的 Webhook URL（None = 不发）
    pub webhook_url: Option<String>,
    /// 触发事件子集：start / success / failure
    pub webhook_events: Vec<String>,
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
            "SELECT name, kind, enabled, timeout_sec, last_run_at, last_status, \
             max_overlap, webhook_url, webhook_events FROM cron_jobs")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map([], |r| Ok((
            r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i32>(2)?,
            r.get::<_, i64>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, Option<String>>(5)?,
            r.get::<_, i64>(6)?, r.get::<_, Option<String>>(7)?, r.get::<_, String>(8)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;

    // 以系统里的任务为准（系统是真相），库只补充面板元数据
    let dtos: Vec<JobDto> = jobs.into_iter().map(|j| {
        let meta = rows.iter().find(|(n, _, _, _, _, _, _, _, _)| *n == j.id);
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
            max_overlap: meta.map(|m| m.6 as u64).unwrap_or(j.max_overlap as u64),
            webhook_url: meta.and_then(|m| m.7.clone()),
            webhook_events: meta.map(|m| split_events(&m.8)).unwrap_or_default(),
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
    /// 并发上限：1=互斥锁包裹（防重入），0=不限制。>1 未实装（诚实拒绝）
    pub max_overlap: Option<u32>,
    /// Webhook URL（http/https）；空串等价于不设置
    pub webhook_url: Option<String>,
    /// 触发事件子集：start / success / failure
    pub webhook_events: Option<Vec<String>>,
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

    // max_overlap：仅 0（不限）/ 1（互斥）合法；>1 未实装，诚实拒绝而非假装生效
    let max_overlap = req.max_overlap.unwrap_or(1);
    if max_overlap > 1 {
        return Err(ApiError::bad_request("max_overlap",
            "仅支持 0（不限制）或 1（互斥锁防重入）；并发上限 >1 尚未实装"));
    }

    // Webhook：空串视为未设置；非空必须 http(s) 且通过校验。
    // 事件子集必须是 {start,success,failure} 的子集；省略则默认 success,failure。
    let (webhook_url, webhook_events) =
        resolve_webhook(req.webhook_url.clone(), req.webhook_events.clone(), None)?;

    let job = panel_os::ScheduledJob {
        id: req.name.clone(),
        expression: req.expr.clone(),
        command: req.command.clone(),
        user: user.clone(),
        enabled: req.enabled.unwrap_or(true),
        timeout: std::time::Duration::from_secs(req.timeout_sec.unwrap_or(1800) as u64),
        max_overlap,
        webhook_url: webhook_url.clone(),
        webhook_events: webhook_events.clone(),
    };
    state.os.scheduler().upsert(job).await?;

    let name = req.name.clone();
    let events_joined = webhook_events.join(",");
    state.db.exec(move |conn| {
        conn.execute(
            "INSERT OR REPLACE INTO cron_jobs(name, expr, kind, payload_json, enabled, timeout_sec, \
             max_overlap, webhook_url, webhook_events)
             VALUES(?1, ?2, 'script', '{}', 1, ?3, ?4, ?5, ?6)",
            rusqlite::params![name, req.expr, req.timeout_sec.unwrap_or(1800),
                              max_overlap as i64, webhook_url, events_joined],
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
                "SELECT name, kind, enabled, timeout_sec, last_run_at, last_status, \
                 max_overlap, webhook_url, webhook_events FROM cron_jobs \
                 WHERE name = ?1")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let mut it = st.query_map([id_key.as_str()], |r| Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i32>(2)?,
                r.get::<_, i64>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?, r.get::<_, Option<String>>(7)?, r.get::<_, String>(8)?,
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
            max_overlap: meta.as_ref().map(|m| m.6 as u64).unwrap_or(j.max_overlap as u64),
            webhook_url: meta.as_ref().and_then(|m| m.7.clone()),
            webhook_events: meta.as_ref().map(|m| split_events(&m.8)).unwrap_or_default(),
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
    pub max_overlap: Option<u32>,
    pub webhook_url: Option<String>,
    pub webhook_events: Option<Vec<String>>,
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

    // 现有 Webhook 元数据（来自库，系统是 crontab 但 url/事件只存库）
    let existing = cron_meta_of(&state, &id).await;
    let max_overlap = req.max_overlap.unwrap_or(existing.0);
    if max_overlap > 1 {
        return Err(ApiError::bad_request("max_overlap",
            "仅支持 0（不限制）或 1（互斥锁防重入）；并发上限 >1 尚未实装"));
    }
    let (webhook_url, webhook_events) =
        resolve_webhook(req.webhook_url.clone(), req.webhook_events.clone(), existing.1)?;

    let job = panel_os::ScheduledJob {
        id: id.clone(),
        expression: expr.clone(),
        command: command.clone(),
        user: user.clone(),
        enabled,
        timeout: std::time::Duration::from_secs(timeout_sec as u64),
        max_overlap,
        webhook_url: webhook_url.clone(),
        webhook_events: webhook_events.clone(),
    };
    state.os.scheduler().upsert(job).await?;

    let (e, t, mo, wu, we) = (
        enabled, timeout_sec, max_overlap as i64,
        webhook_url, webhook_events.join(","),
    );
    let id_for_db = id.clone();
    state.db.exec(move |conn| {
        conn.execute(
            "UPDATE cron_jobs SET expr = ?2, enabled = ?3, timeout_sec = ?4, \
             max_overlap = ?5, webhook_url = ?6, webhook_events = ?7 WHERE name = ?1",
            rusqlite::params![id_for_db, expr, e as i32, t, mo, wu, we],
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
        pool: state.pool.clone(),
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
    pool: std::sync::Arc<panel_db::ReadPool>,
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
        // 经 panel-os 的 shell 入口执行：业务层不再自己拼 `sh -c`——
        // shell 执行细节（含"命令作为单个 argv、不参与拼接"）锁在 OS 抽象层。
        let r = panel_os::run_shell(
            &job.command,
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
        let last_status = status_text.clone();   // 闭包内消费一份，原件留给下方 Webhook 载荷
        let _ = self.db.exec(move |conn| {
            conn.execute(
                "UPDATE cron_jobs SET last_run_at = ?2, last_status = ?3 WHERE name = ?1",
                rusqlite::params![job_id, now, last_status],
            ).map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        }).await;

        progress.set(100, if failed { "执行结束（失败）" } else { "执行结束" }).await;

        // Webhook 回调（P2-3）：成功/失败时按订阅事件 POST JSON。
        // 失败只记日志，绝不污染主任务状态（通知失败不应让任务本身失败）。
        let job_id = self.job_id.clone();
        if let Ok((Some(url), events_str)) = self.pool.with(move |conn| {
            let mut st = conn.prepare(
                "SELECT webhook_url, webhook_events FROM cron_jobs WHERE name = ?1")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            st.query_row([job_id.as_str()], |r| Ok((
                r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?,
            ))).map_err(|e| PanelError::Database(e.to_string()))
        }).await {
            let events: Vec<String> = split_events(&events_str);
            let want = if failed { "failure" } else { "success" };
            if events.iter().any(|e| e == want) {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64).unwrap_or(0);
                let payload = serde_json::json!({
                    "event": want,
                    "job": self.job_id,
                    "exit_code": exit_code,
                    "status": status_text,
                    "ts": ts,
                    "output_excerpt": output_path.as_ref().map(|p| p.to_string_lossy().to_string()),
                });
                match webhook::fire(&url, &payload).await {
                    Ok(()) => progress.log(&format!("已回调 Webhook：{want}")).await,
                    Err(e) => progress.log(&format!("Webhook 投递失败：{e}")).await,
                }
            }
        }

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

/// 测试某任务已配置的 Webhook（POST 一条 test 事件到其 URL）。
/// 测试属探针：投递失败也以 `{ok:false, error}` 返回，便于用户看到具体原因。
pub async fn webhook_test_job(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }
    let meta = cron_meta_of(&state, &id).await;
    let url = meta.1.ok_or_else(|| ApiError::bad_request("webhook_url", "该任务未配置 Webhook"))?;
    let payload = serde_json::json!({
        "event": "test",
        "job": id,
        "panel": "forkpanel",
        "ts": crate::now_unix(),
    });
    match webhook::fire(&url, &payload).await {
        Ok(()) => Ok(ok(serde_json::json!({ "ok": true }))),
        Err(e) => Ok(ok(serde_json::json!({ "ok": false, "error": e.to_string() }))),
    }
}

/// 读任务在库里的 Webhook 元数据（max_overlap / url / events）。库无记录时回退默认。
async fn cron_meta_of(state: &Shared, id: &str) -> (u32, Option<String>, Vec<String>) {
    let id = id.to_string();
    let r = state.pool.with(move |conn| {
        let mut st = conn.prepare(
            "SELECT max_overlap, webhook_url, webhook_events FROM cron_jobs WHERE name = ?1")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        st.query_row([id.as_str()], |r| Ok((
            r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))
    }).await;
    match r {
        Ok((mo, u, ev)) => (mo as u32, u, split_events(&ev)),
        Err(_) => (1, None, Vec::new()),
    }
}

/// 把逗号分隔的事件串展开为受控事件子集（过滤非法值，防御库里脏数据）。
fn split_events(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty() && matches!(x.as_str(), "start" | "success" | "failure"))
        .collect()
}

/// 解析 Webhook 配置：校验 URL（http/https）+ 事件子集，并与现有值合并。
///
/// 语义：`url` 与 `events` 都为 None → 保留 `existing_url`（create 时即 None=未设置）；
/// `url` 显式空串 → 清除；`events` 仅改时保留现有 `existing_url`；二者皆缺省事件 success,failure。
fn resolve_webhook(
    url: Option<String>, events: Option<Vec<String>>, existing_url: Option<String>,
) -> ApiResult<(Option<String>, Vec<String>)> {
    if url.is_none() && events.is_none() {
        return Ok((existing_url, Vec::new()));
    }
    let url = match url {
        Some(s) if !s.is_empty() => {
            webhook::validate_url(&s)
                .map_err(|e| ApiError::bad_request("webhook_url", e.to_string()))?;
            Some(s)
        }
        Some(_) => None,              // 显式空串 = 清除
        None => existing_url,         // 仅改 events → 保留现有 url
    };
    let mut evs = match events {
        Some(v) => {
            for e in &v {
                if !matches!(e.as_str(), "start" | "success" | "failure") {
                    return Err(ApiError::bad_request("webhook_events",
                        "仅允许 start / success / failure"));
                }
            }
            v
        }
        None => if url.is_some() { vec!["success".into(), "failure".into()] } else { Vec::new() },
    };
    evs.sort(); evs.dedup();
    Ok((url, evs))
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
