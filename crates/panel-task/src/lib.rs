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
//! 2. **输出写文件不写库**：实测把 stdout 塞进 DB 会让库体积失控。
//!    ⚠ 但**当前没有任何代码往 `log_dir()/tasks/` 写文件**：所有
//!    `output_path: Some(..)` 都指向各自任务的**业务产物**（备份 .db/.tar.gz、
//!    证书 .crt、DB dump），全在 data 目录下，与日志目录无关。任务日志走内存
//!    bus 推送 SSE（`Progress::log`），不落盘。
//!    故 `TaskRunner::output_dir` 是个**预留而未接线的字段**（`#[allow(dead_code)]`，
//!    构造签名保留以维持注入契约）——将来真要把 stdout 落盘时用它，别自己另拼路径。
//!    本条曾是"注释声称落了盘、实际没人写"的失真，2026-10-19 核对后改正。
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
    /// 恢复（备份回写 / 数据库导入）：**覆盖当前数据，副作用不可回滚**
    Restore,
}

impl TaskKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Package => "package", Self::Backup => "backup",
            Self::CertIssue => "cert_issue", Self::ConfigApply => "config_apply",
            Self::Service => "service", Self::Database => "database",
            Self::Internal => "internal", Self::Restore => "restore",
        }
    }

    /// 同组互斥：返回 `Some(组名)` 的任务**串行**执行；`None` 只受全局并发额度约束。
    ///
    /// 判据是"底层资源是否全局独占"：
    /// - `Package` → `"package"`：apt/dpkg 有全局独占锁，并发必有一方失败，只能排队。
    /// - 其余类型当前没有全局独占资源（备份 / 证书 / 服务启停可安全并行）。
    ///
    /// 刻意**穷举匹配、不写 `_ =>`**：将来新增 `TaskKind` 时编译器会强制在这里表态，
    /// 而不是默默沿用默认值（默认"可并行"对新增的写操作类型往往就是错的）。
    /// 将来若出现同类约束（例如都写同一个配置目录），给它们同一个组名即可复用，
    /// 不需要在调度器里再加分支。
    pub fn exclusive_group(&self) -> Option<&'static str> {
        match self {
            Self::Package => Some("package"),
            Self::Backup | Self::CertIssue | Self::ConfigApply
            | Self::Service | Self::Database | Self::Internal | Self::Restore => None,
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
            // 恢复会覆盖当前数据：自动重试 = 再覆盖一次，绝不重试（与 Package 同纪律）
            Self::Restore => RetryPolicy { max_attempts: 1, base_delay: Duration::ZERO, max_delay: Duration::ZERO },
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
    /// 同组任务互斥闸门：组名 → 容量恒为 1 的信号量（懒建）。
    ///
    /// 为什么单靠 `slots` 不够：`slots` 只限**总量**。Package 类任务会去抢 apt/dpkg
    /// 的**全局独占锁**（/var/lib/dpkg/lock-frontend），两个同时放出去必然有一方
    /// 拿不到锁而直接失败（实测 1 秒内 exit 1）。这里按组串行：后到者停在
    /// `queued` 排队等锁，而不是撞锁报错。分组判据见 [`TaskKind::exclusive_group`]。
    exclusive: Arc<Mutex<HashMap<&'static str, Arc<Semaphore>>>>,
    /// 输出目录（来自 PathLayout，不由任务中心自己拼）。
    /// 任务输出落盘功能接入前未读取；构造签名保留该参数以维持注入契约。
    #[allow(dead_code)]
    output_dir: PathBuf,
    /// 任务创建专用写库路径。
    ///
    /// ⚠️ 任务创建的 INSERT **不走 writer actor 的攒批事务**：同 key 两个并发
    /// INSERT 一旦被收进同一批，会在一个事务里互相触发唯一约束、整批回滚，
    /// 两个请求都失败且无法回退合并。故 submit 用此路径独立开连接单事务写入，
    /// 确保"先到者提交、后到者唯一冲突后回退复用既有 id"。
    db_path: PathBuf,
}

impl TaskRunner {
    pub fn new(writer: Arc<WriterActor>, tier: Tier, output_dir: PathBuf, db_path: PathBuf) -> Self {
        Self {
            writer,
            bus: Arc::new(ProgressBus::new()),
            tier,
            slots: Arc::new(Semaphore::new(tier.task_concurrency())),
            idempotency: Arc::new(Mutex::new(HashMap::new())),
            exclusive: Arc::new(Mutex::new(HashMap::new())),
            output_dir,
            db_path,
        }
    }

    /// 取（或建）任务组的互斥闸门。容量恒为 1 → 同组串行。
    ///
    /// 懒建：只有真的出现过该组任务才会分配信号量。
    /// 这里用 `std::sync::Mutex` 是刻意的——临界区只有一次 HashMap 读写、无 await；
    /// 且 guard 绝不跨 await（跨 await 持 std guard 会让 future 非 Send，
    /// 所有 await 本函数的 axum handler 都会编译失败）。
    fn group_gate(&self, group: &'static str) -> Arc<Semaphore> {
        let mut m = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(group).or_insert_with(|| Arc::new(Semaphore::new(1))).clone()
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

        // 2) 落库。
        //
        // ⚠️ 任务创建**不走 writer actor 的攒批事务**：writer 会把同一时间窗口内的
        // 多个写 op 收进一个 conn.transaction() 执行，若同 key 的两个并发 INSERT
        // 被收进同一批，第二个触发唯一约束会让**整批回滚**——两个请求都失败，且
        // 回退查询因回滚后库中无 same-key 行而无从合并（实测：回归测试直接 Internal）。
        // 故任务创建用独立连接单事务：先到者 INSERT 提交成功，后到者唯一冲突 →
        // 走下方回退复用既有 id。任务提交频率极低（用户每次操作一次），独立连接的
        // 写锁争用可忽略；且 db 是 WAL 模式，已提交写入对其他连接立即可见。
        //
        // 任务 id 必须**在同一连接内**取回（last_insert_rowid），不能插入后再查
        // MAX(id)：那样会拿到别的任务插入的 id，覆盖其状态行。
        let kind = req.kind.as_str().to_string();
        let label = req.label.clone();
        let ikey = req.idempotency_key.clone();
        let db_path = self.db_path.clone();
        let tier = self.tier;
        let ins = tokio::task::spawn_blocking(move || -> Result<i64> {
            let conn = panel_db::open(&db_path, tier)
                .map_err(|e| PanelError::Internal(format!("open task db: {e}")))?;
            match conn.execute(
                "INSERT INTO task_runs(task_id, kind, state, progress, started_at)
                 VALUES(?1, ?2, 'queued', 0, ?3)",
                rusqlite::params![ikey, kind, now_unix()],
            ) {
                Ok(_) => Ok(conn.last_insert_rowid() as i64),
                // 唯一约束命中：并发同 key 已先插入非终态任务（部分唯一索引保证）。
                // 上层合并到既有任务，绝不重复执行——这是幂等语义的核心。
                Err(e) if is_unique_violation(&e) => {
                    Err(PanelError::Conflict(format!("重复幂等键 {ikey}")))
                }
                Err(e) => Err(PanelError::Database(e.to_string())),
            }
        }).await
            .map_err(|e| PanelError::Internal(format!("submit task panicked: {e}")))?;

        let id = match ins {
            Ok(id) => id,
            Err(PanelError::Conflict(_)) => {
                // 回退：找到既有非终态任务，复用其 id（db 是唯一真相，独立连接已提交）。
                let key = req.idempotency_key.clone();
                let found = self.writer.exec(move |conn| {
                    match conn.query_row(
                        "SELECT id FROM task_runs
                         WHERE task_id=?1 AND state IN ('queued','running')
                         ORDER BY id DESC LIMIT 1",
                        rusqlite::params![key], |r| r.get::<_, i64>(0),
                    ) {
                        Ok(v) => Ok(panel_db::WriteAck { rows_changed: v as usize }),
                        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(panel_db::WriteAck { rows_changed: 0 }),
                        Err(e) => Err(PanelError::Database(e.to_string())),
                    }
                }).await?;
                if found.rows_changed != 0 {
                    let eid = found.rows_changed as i64;
                    // 同步内存 map，避免后续同 key 请求再走一次无谓的 INSERT+回退
                    let mut m = self.idempotency.lock().unwrap_or_else(|e| e.into_inner());
                    m.insert(req.idempotency_key.clone(), (eid, std::time::Instant::now()));
                    return Ok((eid, false));
                }
                // 理论不可达：唯一约束冲突了却查不到活跃行，说明索引与数据不一致
                return Err(PanelError::Internal(format!(
                    "幂等键 {} 冲突但无可合并的活跃任务", req.idempotency_key)));
            }
            Err(e) => return Err(e),
        };
        let _ = label;

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
        let timeout = req.timeout;
        let rkind = req.kind;
        // 组闸门在 spawn **之前**取好：group_gate 用 std Mutex，guard 不能跨 await。
        let gate = rkind.exclusive_group().map(|g| self.group_gate(g));

        tokio::spawn(async move {
            // 先占**组闸门**再占全局 slot，顺序不可反：若反序，一串同组任务会把全局
            // 名额全占满并一起堵在组闸门前，备份等其它类型任务将永远拿不到名额。
            // 排队期间任务在库中仍是 queued —— 前端因此能显示"排队中"而非假装在跑。
            let _group_permit: Option<tokio::sync::OwnedSemaphorePermit> = match gate {
                Some(g) => match g.acquire_owned().await {
                    Ok(p) => Some(p),
                    Err(_) => return,   // 闸门关闭（正在 shutdown）
                },
                None => None,
            };
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

/// 判定是否为 SQLite 唯一约束冲突。
///
/// 部分唯一索引（idx_task_runs_idempotent_active）的冲突也走 `ConstraintViolation`
/// code；此处 INSERT 除该索引外无其他可能触发约束的列，故命中即"幂等键重复"。
fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(e,
        rusqlite::Error::SqliteFailure(ref f, _)
        if f.code == rusqlite::ErrorCode::ConstraintViolation)
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

    /// 不变量：并发提交的两个任务必须拿到**不同** id。
    ///
    /// 钉住 `submit()` 里"INSERT 与取 id 必须在同一个闭包"这件事——
    /// 若退回成"先 INSERT、再单独查 MAX(id)"，两次提交会撞成同一个 id，
    /// 后完成的那个 UPDATE 会覆盖前一个的状态，前端看到的是别人的任务结果。
    struct NoopBody;
    #[async_trait::async_trait]
    impl TaskBody for NoopBody {
        async fn run(&self, _p: Progress) -> Result<TaskOutcome> {
            Ok(TaskOutcome { state: TaskState::Ok, exit_code: Some(0), output_path: None })
        }
    }

    #[tokio::test]
    async fn concurrent_submits_get_distinct_ids() {
        let dir = std::env::temp_dir().join(format!("panel-task-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("panel.db");

        // 建表：writer actor 只负责写，schema 由迁移负责
        {
            let mut c = rusqlite::Connection::open(&db).unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
        }

        let writer = std::sync::Arc::new(panel_db::WriterActor::spawn(db.clone(), Tier::Nano).unwrap());
        let runner = TaskRunner::new(writer, Tier::Nano, dir.clone(), db.clone());

        let req = |k: &str| TaskRequest {
            idempotency_key: k.to_string(),
            kind: TaskKind::Service,
            label: k.to_string(),
            timeout: Duration::from_secs(5),
        };

        // 并发提交：两个 future 同时推进，正是竞态发生的时机
        let (a, b) = tokio::join!(
            runner.submit(req("k-a"), NoopBody),
            runner.submit(req("k-b"), NoopBody),
        );
        let (id_a, _) = a.expect("提交 A 失败");
        let (id_b, _) = b.expect("提交 B 失败");

        assert_ne!(id_a, id_b, "并发提交撞成了同一个任务 id（{id_a}）");
        assert!(id_a > 0 && id_b > 0, "任务 id 必须来自自增主键，不能是 0");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 不变量：并发提交**相同** idempotency_key 必须合并到同一个活跃任务，
    /// 不能各 INSERT 一条（否则防双击 / 防重试风暴失效）。
    ///
    /// 钉住本次修复：submit() 的"查 map → INSERT"之间无原子保护，仅靠内存 map
    /// 会在并发下两个请求都通过检查、各自建出一条任务。修复把原子性下沉到数据库
    /// 部分唯一索引（idx_task_runs_idempotent_active），冲突时回退复用既有 id。
    ///
    /// 负向对照：若撤掉该唯一索引，writer actor 串行执行两个 INSERT 都会成功、
    /// 拿到不同 id，本测试随即转红，故不会是永绿门禁。
    #[tokio::test]
    async fn concurrent_same_key_collapses_to_one() {
        let dir = std::env::temp_dir().join(format!("panel-task-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("panel.db");
        {
            let mut c = rusqlite::Connection::open(&db).unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
        }
        let writer = std::sync::Arc::new(panel_db::WriterActor::spawn(db.clone(), Tier::Nano).unwrap());
        let runner = TaskRunner::new(writer, Tier::Nano, dir.clone(), db.clone());

        let req = |k: &str| TaskRequest {
            idempotency_key: k.to_string(),
            kind: TaskKind::Service,
            label: k.to_string(),
            timeout: Duration::from_secs(5),
        };

        // join! 先 poll A 到首个 await（writer.exec 挂起），再 poll B：
        // B 的 map 检查一定发生在 A 写回 map 之前 → 两个都进 INSERT。
        // writer 串行，第二个 INSERT 落到部分唯一索引冲突 → 回退复用 A 的 id。
        let (a, b) = tokio::join!(
            runner.submit(req("same-key"), NoopBody),
            runner.submit(req("same-key"), NoopBody),
        );
        let (id_a, _) = a.expect("提交 A 失败");
        let (id_b, _) = b.expect("提交 B 失败");
        assert_eq!(id_a, id_b, "并发同 key 应合并到同一任务 id，却得到 {id_a} 与 {id_b}");

        // 数据库侧确认：同 key 的非终态行只能有一条
        let c = rusqlite::Connection::open(dir.join("panel.db")).unwrap();
        let active: i64 = c.query_row(
            "SELECT COUNT(*) FROM task_runs WHERE task_id='same-key' AND state IN ('queued','running')",
            [], |r| r.get(0)).unwrap();
        assert_eq!(active, 1, "同 key 非终态行应为 1，实为 {active}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // ─────────────── 并发闸门 ───────────────

    // `use` 是 item，可出现在模块任意位置；就近声明，免得为新增用例再动文件头部。
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 探针任务体：记录"同时进入执行体"的最大条数，用来观测是否真的串行。
    struct ProbeBody {
        live: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl TaskBody for ProbeBody {
        async fn run(&self, _p: Progress) -> Result<TaskOutcome> {
            let n = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(n, Ordering::SeqCst);
            // 留出足够的交叠窗口：闸门若失效，另一个任务能在这段时间内也进来 → peak=2
            tokio::time::sleep(Duration::from_millis(400)).await;
            self.live.fetch_sub(1, Ordering::SeqCst);
            Ok(TaskOutcome { state: TaskState::Ok, exit_code: Some(0), output_path: None })
        }
    }

    /// 建一个带迁移的临时库 + TaskRunner。返回 (runner, 目录) 供收尾清理。
    fn runner_for(tag: &str, tier: Tier) -> (TaskRunner, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("panel-task-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("panel.db");
        {
            let mut c = rusqlite::Connection::open(&db).unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
        }
        let writer = std::sync::Arc::new(panel_db::WriterActor::spawn(db.clone(), tier).unwrap());
        (TaskRunner::new(writer, tier, dir.clone(), db), dir)
    }

    /// 轮询等所有任务进终态（上限 20s）。不用固定 sleep，避免偶发翻红。
    async fn wait_all(runner: &TaskRunner, ids: &[i64]) {
        for _ in 0..200 {
            let mut all = true;
            for &id in ids {
                if !runner.is_terminal(id).await.unwrap_or(false) { all = false; break; }
            }
            if all { return }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("任务未在 20s 内进入终态：{ids:?}");
    }

    /// 不变量：Package 类任务必须**串行**，即便全局并发额度还有空位。
    ///
    /// 钉住：apt/dpkg 有全局独占锁（/var/lib/dpkg/lock-frontend），两个包任务同时
    /// 放出去必然有一方拿不到锁、1 秒内 exit 1（实测线上 task 14：
    /// `E: Could not get lock ... It is held by process 109738 (apt)`）。
    ///
    /// 刻意用 Standard 档（额度 4）而非 Nano：Nano 档全局额度本来就是 1，串行会被
    /// `slots` 顺带保证，测不出组闸门是否真的生效——那就是一条永绿门禁。
    /// 负向对照：把 `TaskKind::exclusive_group` 里 Package 改回 `None`，本条即转红。
    #[tokio::test]
    async fn package_tasks_are_serialized_despite_free_slots() {
        let (runner, dir) = runner_for("serial", Tier::Standard);
        assert_eq!(runner.tier().task_concurrency(), 4,
                   "前提被破坏：Standard 档全局额度应为 4，否则本用例测不出组闸门");

        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let body = || ProbeBody { live: live.clone(), peak: peak.clone() };
        let req = |k: &str| TaskRequest {
            idempotency_key: k.to_string(),
            kind: TaskKind::Package,
            label: k.to_string(),
            timeout: Duration::from_secs(30),
        };

        let (a, _) = runner.submit(req("pkg.install:a"), body()).await.unwrap();
        let (b, _) = runner.submit(req("pkg.install:b"), body()).await.unwrap();
        wait_all(&runner, &[a, b]).await;

        let p = peak.load(Ordering::SeqCst);
        assert_eq!(p, 1, "两个 Package 任务同时进入了执行体（峰值 {p}）：同组必须串行排队");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 负向对照：串行必须来自**组闸门**，而不是"全局额度恰好被压成 1"。
    /// 两个不属于任何互斥组的任务在 Standard 档下应能并行（峰值 2）。
    /// 若把 `group_gate` 的容量写成 0、或让所有 kind 都落进同一个组，本条转红。
    #[tokio::test]
    async fn non_exclusive_kinds_still_run_in_parallel() {
        let (runner, dir) = runner_for("parallel", Tier::Standard);

        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let body = || ProbeBody { live: live.clone(), peak: peak.clone() };
        let req = |k: &str| TaskRequest {
            idempotency_key: k.to_string(),
            kind: TaskKind::Internal,
            label: k.to_string(),
            timeout: Duration::from_secs(30),
        };

        let (a, _) = runner.submit(req("int-a"), body()).await.unwrap();
        let (b, _) = runner.submit(req("int-b"), body()).await.unwrap();
        wait_all(&runner, &[a, b]).await;

        let p = peak.load(Ordering::SeqCst);
        assert_eq!(p, 2, "无互斥组的任务被意外串行化了（峰值 {p}）：组闸门不该影响它们");

        std::fs::remove_dir_all(&dir).ok();
    }
}
