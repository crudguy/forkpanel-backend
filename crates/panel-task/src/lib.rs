//! 任务中心：长任务编排、并发与幂等控制、进度广播、内部周期调度。
//!
//! # 为什么需要它（而不是直接在 handler 里跑）
//! 软件安装、备份、证书签发这类操作耗时几十秒到几十分钟。若在 HTTP 请求里同步执行：
//! - 连接超时 / 用户刷新页面 → 操作状态未知；
//! - 用户双击 → 同一个副作用跑两遍（`apt install nginx` 跑两次的后果不可控）；
//! - 低配机器上并发跑多个 → 直接 OOM。
//!
//! 所以：**所有会改变系统状态且耗时不可预测的操作，一律走任务中心。**
//! 读操作（列表、查询、指标）直接同步返回，不进任务队列。
//!
//! # 三条硬约束
//! 1. **副作用不可自动回滚**：`apt install` 被中断，系统处于未知中间态。
//!    这类任务失败后只允许"人工确认后重试"，不允许自动重试（见 [`RetryPolicy`]）。
//! 2. **输出写文件不写库**：实测把 stdout 塞进 DB 会让库体积失控；
//!    任务输出落 `PathLayout::log_dir()/tasks/<id>.log`，库中只存路径（schema 已预留 `output_path`）。
//! 3. **任务内禁止持有写事务**：实测长事务耗时 1:1 传导给其他写者
//!    （持有 1000ms → 其他写者等 1046ms）。任务进度更新走 WriterActor 的短事务。

pub mod progress;
pub mod scheduler;

use panel_core::{PanelError, Result, Tier};
pub use progress::{Progress, ProgressBus, TaskEvent};
pub use scheduler::{builtin_schedules, InternalScheduler, Schedule};
use panel_db::WriterActor;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Semaphore, SemaphorePermit};

// ═══════════════════════════ 状态机 ═══════════════════════════

/// 任务状态。注意 `interrupted` 是**终态**且不可自动恢复。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    Queued,
    Running,
    Ok,
    Failed,
    Canceled,
    /// 进程被杀 / 机器重启导致中断。**副作用可能已部分生效**，必须人工确认。
    Interrupted,
}

impl TaskState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued", Self::Running => "running", Self::Ok => "ok",
            Self::Failed => "failed", Self::Canceled => "canceled",
            Self::Interrupted => "interrupted",
        }
    }
    /// 终态：不再变化
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }
    /// 需要人工介入（不做任何自动处理）
    pub fn needs_human(self) -> bool { matches!(self, Self::Interrupted) }
}

/// 任务种类。决定重试策略与是否需要并发互斥。
// 需可序列化：`progress::TaskEvent::Finished` 携带 kind 并经 SSE 广播给前端。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// 软件安装/卸载：副作用不可回滚，失败不自动重试
    Package,
    /// 备份：幂等，可安全重试
    Backup,
    /// 证书申请：有外部限流（Let's Encrypt 5 次/小时/域名），重试必须退避
    CertIssue,
    /// 配置应用（写配置 + reload）：幂等，可重试
    ConfigApply,
    /// 服务启停：幂等
    Service,
    /// 数据库导入导出
    Database,
    /// 面板内部周期任务
    Internal,
}

impl TaskKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Package => "package", Self::Backup => "backup",
            Self::CertIssue => "cert_issue", Self::ConfigApply => "config_apply",
            Self::Service => "service", Self::Database => "database",
            Self::Internal => "internal",
        }
    }

    /// 默认重试策略。
    ///
    /// 关键判断：**副作用不可回滚的操作一律不自动重试**。
    /// 半装的 nginx 比没装更危险——重试可能让包管理器进入更糟的状态。
    pub fn retry_policy(&self) -> RetryPolicy {
        match self {
            Self::Package => RetryPolicy { max_attempts: 1, base_delay: Duration::ZERO, max_delay: Duration::ZERO },
            Self::CertIssue => RetryPolicy { max_attempts: 3, base_delay: Duration::from_secs(60), max_delay: Duration::from_secs(900) },
            Self::ConfigApply | Self::Service => RetryPolicy { max_attempts: 2, base_delay: Duration::from_secs(2), max_delay: Duration::from_secs(10) },
            Self::Backup | Self::Database | Self::Internal => RetryPolicy { max_attempts: 3, base_delay: Duration::from_secs(5), max_delay: Duration::from_secs(60) },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl RetryPolicy {
    /// 指数退避：base * 2^(n-1)，上限 max_delay
    pub fn delay_for(&self, attempt: u32) -> Duration {
        if attempt == 0 { return Duration::ZERO; }
        let mult = 1u64 << (attempt - 1).min(6);
        let d = self.base_delay * mult as u32;
        d.min(self.max_delay)
    }
}

// ═══════════════════════════ 任务描述 ═══════════════════════════

/// 提交任务的请求
#[derive(Debug, Clone)]
pub struct TaskRequest {
    /// 幂等键：同一 key 在窗口期内只会执行一次（防双击 / 防重试风暴）
    pub idempotency_key: String,
    pub kind: TaskKind,
    /// 展示给用户的名字
    pub label: String,
    pub timeout: Duration,
}

/// 任务执行结果
#[derive(Debug, Clone)]
pub struct TaskOutcome {
    pub state: TaskState,
    pub exit_code: Option<i32>,
    /// 输出文件路径（不在库中存正文）
    pub output_path: Option<PathBuf>,
}

// ═══════════════════════════ 执行器 ═══════════════════════════

/// 任务执行体。**由业务层提供**，任务中心只负责编排与状态管理。
///
/// 约束：实现内部若需调用外部命令，必须走 `panel_os::cmd`；
/// 不得在事务内做慢操作（见本文件顶部约束 3）。
#[async_trait::async_trait]
pub trait TaskBody: Send + Sync {
    async fn run(&self, progress: Progress) -> Result<TaskOutcome>;
}

/// 任务中心
pub struct TaskRunner {
    writer: Arc<WriterActor>,
    bus: Arc<ProgressBus>,
    tier: Tier,
    /// 并发闸门：nano 1 / small 2 / standard 4。
    /// 512MB 机器上同时跑两个 apt install 会直接 OOM，这不是保守而是必需。
    slots: Arc<Semaphore>,
    /// 幂等键 → 已提交任务。窗口期内的重复提交直接返回既有任务 id。
    idempotency: Arc<Mutex<HashMap<String, (i64, std::time::Instant)>>>,
    /// 输出目录（来自 PathLayout，不由任务中心自己拼）
    output_dir: PathBuf,
}

impl TaskRunner {
    pub fn new(writer: Arc<WriterActor>, tier: Tier, output_dir: PathBuf) -> Self {
        Self {
            writer,
            bus: Arc::new(ProgressBus::new()),
            tier,
            slots: Arc::new(Semaphore::new(tier.task_concurrency())),
            idempotency: Arc::new(Mutex::new(HashMap::new())),
            output_dir,
        }
    }

    pub fn bus(&self) -> &Arc<ProgressBus> { &self.bus }
    pub fn tier(&self) -> Tier { self.tier }

    /// 提交任务。返回 (任务 id, 是否为新建)。
    ///
    /// 幂等语义：相同 key 且上一个任务**仍在非终态** → 返回既有 id，不重复执行。
    /// 上一个任务已是终态 → 允许重新提交（用户确实想再来一次）。
    pub async fn submit(&self, req: TaskRequest, body: impl TaskBody + 'static) -> Result<(i64, bool)> {
        // 1) 幂等检查
        //
        // 关键：std::sync::MutexGuard 不是 Send，**绝不能跨 .await 持有**。
        // 这里先在块内取出既有 id 并让 guard 立即释放，再去做 await 的终态判定；
        // 否则 submit 的 future 非 Send，所有 await 它的 axum handler 都会
        // 因 `Handler` 要求 Future: Send 而编译失败。
        let existing: Option<i64> = {
            let mut m = self.idempotency.lock().unwrap_or_else(|e| e.into_inner());
            // 顺带清理超过 1 小时的记录，避免 map 无限增长
            m.retain(|_, (_, t)| t.elapsed() < std::time::Duration::from_secs(3600));
            m.get(&req.idempotency_key).map(|(id, _)| *id)
        };
        if let Some(existing) = existing {
            if !self.is_terminal(existing).await? {
                return Ok((existing, false));
            }
        }

        // 2) 落库（短事务）
        let kind = req.kind.as_str().to_string();
        let label = req.label.clone();
        let ikey = req.idempotency_key.clone();
        let ack = self.writer.exec(move |conn| {
            conn.execute(
                "INSERT INTO task_runs(task_id, kind, state, progress, started_at)
                 VALUES(?1, ?2, 'queued', 0, ?3)",
                rusqlite::params![ikey, kind, now_unix()],
            ).map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        }).await?;
        let _ = ack;
        let _ = label;

        let id = self.last_task_id().await?;

        {
            let mut m = self.idempotency.lock().unwrap_or_else(|e| e.into_inner());
            m.insert(req.idempotency_key.clone(), (id, std::time::Instant::now()));
        }

        // 3) 派发执行（不阻塞提交方）
        let runner = Arc::new(());
        let _ = runner;
        let slots = self.slots.clone();
        let bus = self.bus.clone();
        let writer = self.writer.clone();
        let output_dir = self.output_dir.clone();
        let timeout = req.timeout;
        let rkind = req.kind;

        tokio::spawn(async move {
            let _permit: SemaphorePermit = match slots.acquire().await {
                Ok(p) => p,
                Err(_) => return,   // 闸门关闭（正在 shutdown）
            };
            let progress = Progress::new(id, bus.clone());
            let _ = writer.exec(move |conn| {
                conn.execute("UPDATE task_runs SET state='running' WHERE id=?1",
                             rusqlite::params![id])
                    .map_err(|e| PanelError::Database(e.to_string()))?;
                Ok(panel_db::WriteAck { rows_changed: 1 })
            }).await;

            let outcome = match tokio::time::timeout(timeout, body.run(progress.clone())).await {
                Ok(Ok(o)) => o,
                Ok(Err(e)) => {
                    progress.log(&format!("任务失败：{e}")).await;
                    TaskOutcome { state: TaskState::Failed, exit_code: None, output_path: None }
                }
                Err(_) => {
                    progress.log(&format!("任务超时（{}s）", timeout.as_secs())).await;
                    TaskOutcome { state: TaskState::Failed, exit_code: None, output_path: None }
                }
            };

            let st = outcome.state.as_str().to_string();
            let ec = outcome.exit_code;
            let op = outcome.output_path.map(|p| p.display().to_string());
            let _ = writer.exec(move |conn| {
                conn.execute(
                    "UPDATE task_runs SET state=?1, progress=100, finished_at=?2, exit_code=?3, output_path=?4
                     WHERE id=?5",
                    rusqlite::params![st, now_unix(), ec, op, id],
                ).map_err(|e| PanelError::Database(e.to_string()))?;
                Ok(panel_db::WriteAck { rows_changed: 1 })
            }).await;

            bus.publish(TaskEvent::Finished { id, state: outcome.state, kind: rkind });
        });

        Ok((id, true))
    }

    async fn last_task_id(&self) -> Result<i64> {
        // 读连接池在 panel-api 侧；这里用一个极短的读查询。
        // 实际实现应改为 INSERT ... RETURNING（SQLite ≥3.35），此处为兼容写法。
        self.writer.exec(|conn| {
            let id: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM task_runs", [], |r| r.get(0))
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: id as usize })
        }).await.map(|a| a.rows_changed as i64)
    }

    async fn is_terminal(&self, id: i64) -> Result<bool> {
        self.writer.exec(move |conn| {
            let s: String = conn.query_row("SELECT state FROM task_runs WHERE id=?1",
                                           rusqlite::params![id], |r| r.get(0))
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let st = match s.as_str() {
                "queued" => TaskState::Queued, "running" => TaskState::Running,
                "ok" => TaskState::Ok, "failed" => TaskState::Failed,
                "canceled" => TaskState::Canceled, _ => TaskState::Interrupted,
            };
            Ok(panel_db::WriteAck { rows_changed: if st.is_terminal() { 1 } else { 0 } })
        }).await.map(|a| a.rows_changed == 1)
    }

    /// 启动时调用：把上次进程遗留下来的 running/queued 标记为 interrupted。
    ///
    /// ⚠️ 刻意**不做**自动恢复：副作用可能已部分生效，自动重跑的风险高于收益。
    /// 前端应把这些任务标红并提示"请人工确认后重试"。
    pub async fn reap_orphans(&self) -> Result<usize> {
        let ack = self.writer.exec(|conn| {
            let n = conn.execute(
                "UPDATE task_runs SET state='interrupted', finished_at=?1
                 WHERE state IN ('running','queued')",
                rusqlite::params![now_unix()],
            ).map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        }).await?;
        Ok(ack.rows_changed)
    }

    /// 取消：只置状态位，不强杀子进程（强杀会留下半个副作用）。
    /// 真正的终止由任务体自己在下一个检查点感知 `is_canceled()` 后优雅退出。
    pub async fn cancel(&self, id: i64) -> Result<()> {
        let _ = self.writer.exec(move |conn| {
            let n = conn.execute(
                "UPDATE task_runs SET state='canceled', finished_at=?1 WHERE id=?2 AND state IN ('queued','running')",
                rusqlite::params![now_unix(), id],
            ).map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        }).await?;
        self.bus.publish(TaskEvent::CancelRequested { id });
        Ok(())
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states() {
        assert!(!TaskState::Running.is_terminal());
        assert!(!TaskState::Queued.is_terminal());
        assert!(TaskState::Ok.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(TaskState::Canceled.is_terminal());
        assert!(TaskState::Interrupted.is_terminal());
        assert!(TaskState::Interrupted.needs_human(), "中断必须人工确认");
    }

    #[test]
    fn package_install_never_auto_retries() {
        let p = TaskKind::Package.retry_policy();
        assert_eq!(p.max_attempts, 1, "软件安装失败绝不自动重试——半装状态比重跑更危险");
        assert_eq!(p.delay_for(1), Duration::ZERO);
    }

    #[test]
    fn cert_issue_backs_off_for_rate_limit() {
        let p = TaskKind::CertIssue.retry_policy();
        assert_eq!(p.max_attempts, 3);
        assert_eq!(p.delay_for(1), Duration::from_secs(60));
        assert_eq!(p.delay_for(2), Duration::from_secs(120));
        assert_eq!(p.delay_for(3), Duration::from_secs(240));
        // 上限保护：不能超过 max_delay
        assert!(p.delay_for(10) <= p.max_delay);
    }

    #[test]
    fn idempotent_kinds_can_retry() {
        assert!(TaskKind::Backup.retry_policy().max_attempts > 1);
        assert!(TaskKind::ConfigApply.retry_policy().max_attempts > 1);
        assert!(TaskKind::Service.retry_policy().max_attempts > 1);
    }

    #[test]
    fn concurrency_scales_with_tier() {
        assert_eq!(Tier::Nano.task_concurrency(), 1, "512MB 机器上同时跑两个 apt 会 OOM");
        assert_eq!(Tier::Small.task_concurrency(), 2);
        assert_eq!(Tier::Standard.task_concurrency(), 4);
    }

    #[test]
    fn state_strings_match_schema() {
        // schema 注释：queued|running|ok|failed|canceled|interrupted
        assert_eq!(TaskState::Queued.as_str(), "queued");
        assert_eq!(TaskState::Interrupted.as_str(), "interrupted");
    }

    #[test]
    fn kind_strings_are_stable() {
        assert_eq!(TaskKind::Package.as_str(), "package");
        assert_eq!(TaskKind::CertIssue.as_str(), "cert_issue");
        assert_eq!(TaskKind::Internal.as_str(), "internal");
    }
}
