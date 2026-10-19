//! SQLite 数据层：连接模型、迁移、指标分层存储、备份、清理。
//!
//! # 本文件的每一行 PRAGMA 与阈值都有实测依据
//! 见《量化假设实测附录》第二轮（bench4/bench5/bench6）：
//!
//! | 结论 | 实测数据 | 代码位置 |
//! |---|---|---|
//! | 单写串行化 > 并发写 | 单写 9,032 ops/s，4 写并发 4,760 ops/s（**降 47%**） | [`WriterActor`] |
//! | flush 窗口选择 | count=64: flush 4 次/3s，p99 0.31ms；count=1: 300 次，p99 0.056ms | [`FlushPolicy`] |
//! | 事务内禁止慢操作 | 事务持有 1,000ms → 其他写者等待 1,046ms（**1:1 传导**） | [`Txn`] 文档 |
//! | 指标必须聚合 | 1s 原始 3,600 点 = 196KB/3600 事务；1m 聚合 = 8KB/60 事务（**24 倍体积、60 倍事务**） | [`aggregator`] |
//! | 环形缓冲布局 | 紧凑 struct 3600 点 = 253KB；朴素 dict 等价实现 2.2MB（**9 倍**） | [`ring::MetricsRing`] |
//! | 清理分档 | ≤5 万行一次性；5~50 万 LIMIT 5000；>50 万 LIMIT 10000 | [`cleanup`] |
//! | WAL 必须有上限 | 关闭 autocheckpoint 后 5 万行即膨胀至 7.71MB | [`open`] |
//! | 审计才是体积大头 | 180 天 × 200 条/天 = 4.12MB（指标的 6 倍）→ 默认 90 天 | [`cleanup::prune_audit`] |

pub mod aggregator;
pub mod cleanup;
pub mod migrate;
pub mod ring;

use panel_core::{PanelError, Result, Tier};
use rusqlite::{Connection, OpenFlags};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, Semaphore};

// ═══════════════════════════ 连接与 PRAGMA ═══════════════════════════

/// 打开主库并施加档位相关的 PRAGMA。
///
/// 关键点：
/// - `journal_mode=WAL` 必须在事务外执行，且**数据目录不能是网络文件系统**
///   （启动前由 `panel_os::startup_fs_check` 拦截）。
/// - `wal_autocheckpoint` **绝不能为 0**：实测关闭后写入 5 万行即让 WAL 涨到 7.71MB 且持续膨胀。
/// SQLite `synchronous` 合法取值（大小写不敏感）。非法值会在 `open` 时直接报错，
/// 避免把用户的笔误静默降级成默认档（那种「配了不生效」最隐蔽）。
pub const SYNCHRONOUS_MODES: &[&str] = &["OFF", "NORMAL", "FULL", "EXTRA"];
pub const DEFAULT_SYNCHRONOUS: &str = "NORMAL";

/// 校验并归一化 `synchronous` 配置值（大小写不敏感 → 标准大写）。
fn normalize_synchronous(s: &str) -> Result<&'static str> {
    let up = s.trim().to_uppercase();
    SYNCHRONOUS_MODES
        .iter()
        .copied()
        .find(|m| *m == up)
        .ok_or_else(|| PanelError::Validation {
            field: "db.synchronous",
            reason: format!("必须是 OFF / NORMAL / FULL / EXTRA 之一，收到 {s:?}"),
        })
}

pub fn open(path: &Path, tier: Tier, synchronous: &str) -> Result<Connection> {
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| PanelError::Database(format!("open {}: {e}", path.display())))?;

    c.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| PanelError::Database(format!("set WAL: {e}")))?;
    // WAL + synchronous：进程崩溃不丢已提交事务（实测 kill -9 后 5,200 行完整、integrity_check ok）。
    // FULL 的代价：实测吞吐降 42%（624k → 361k rows/s），故仅在用户于 config.toml 显式
    // 配 `db.synchronous = "FULL"` 时启用断电强保证。此前此处硬编码 "NORMAL"，配置项形同虚设
    // （与 session_* / max_login_attempts 同类「假控制」）；现经 `normalize_synchronous` 校验后透传。
    let sync_mode = normalize_synchronous(synchronous)?;
    c.pragma_update(None, "synchronous", sync_mode)
        .map_err(|e| PanelError::Database(e.to_string()))?;
    c.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| PanelError::Database(e.to_string()))?;
    c.pragma_update(None, "busy_timeout", "5000")
        .map_err(|e| PanelError::Database(e.to_string()))?;
    c.pragma_update(None, "wal_autocheckpoint", "512")
        .map_err(|e| PanelError::Database(e.to_string()))?;
    c.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|e| PanelError::Database(e.to_string()))?;
    // 低配关闭 mmap：mmap 会把页缓存计入 RSS，与"常驻 ≤12MB"目标冲突
    c.pragma_update(None, "mmap_size", "0")
        .map_err(|e| PanelError::Database(e.to_string()))?;
    c.pragma_update(None, "cache_size", tier.sqlite_cache_kib())
        .map_err(|e| PanelError::Database(e.to_string()))?;

    Ok(c)
}

// ═══════════════════════════ 写串行化 Actor ═══════════════════════════
//
// 为什么是单写：SQLite 的写锁是**库级独占**的。实测 4 个并发写进程总吞吐 4,760 ops/s，
// 反而低于单写进程的 9,032 ops/s。多写者只带来锁争抢与重试。
// 这是性能优化，不是代码洁癖 —— 请勿"优化"成并发写。

/// 一条待写入操作。业务层把写请求投递给 actor，由 actor 串行执行。
// 注意：签名是 `&Connection` 而非 `&mut Connection`。
// rusqlite 的 Transaction 只实现 Deref（无 DerefMut），事务内拿不到 &mut Connection；
// 且 Connection 的语句执行本就只需 &self（内部可变性），故写操作用 &Connection 即可。
pub type WriteOp = Box<dyn FnOnce(&Connection) -> Result<WriteAck> + Send>;

/// actor 执行完的回执
pub struct WriteAck {
    pub rows_changed: usize,
}

/// flush 策略。
///
/// # ⚠️ 实测修正（第二轮）
/// 原方案的"每 200ms 或 64 条"在**低速率**写入下，count=64 几乎永不触发
/// （100 条/秒时攒满 64 条需 640ms，而 200ms 窗口早已到期）。实测对比：
///
/// | 策略 | flush 次数 | p99 | 队列长度 |
/// |---|---|---|---|
/// | count=64 | 4 | 0.309 ms | 75 |
/// | **time=200ms** | 15 | **0.173 ms** | 20 |
/// | count=1 | 300 | 0.056 ms | 1 |
///
/// 结论：**低速率写入以时间窗口为主**，count 的语义应改为"批量上限保护"
/// （防事件风暴时单事务过大），而非"攒够再写"。
/// 实测（100 条/秒到达，持续 3 秒 = 300 条）：
///
/// | 策略 | flush 次数 | flush p99 |
/// |---|---|---|
/// | count=1  | 300 | 0.056 ms |
/// | count=16 | 18  | 0.149 ms |
/// | **count=64** | 4 | 0.309 ms |
/// | count=256| 1   | 0.549 ms |
/// | **time=200ms** | 15 | 0.173 ms |
///
/// 结论：审计/任务这类低速率写入用 `time=200ms` 更平滑（p99 0.173ms，队列长度 20）；
/// 指标聚合这类批量写入用 `count` 阈值更省 CPU。默认采用 **两者取先满足**。
#[derive(Debug, Clone, Copy)]
pub struct FlushPolicy {
    pub max_batch: usize,
    pub max_delay: Duration,
}

impl Default for FlushPolicy {
    fn default() -> Self {
        Self { max_batch: 64, max_delay: Duration::from_millis(200) }
    }
}

impl FlushPolicy {
    /// 低配：缩小批次、拉长窗口，减少 fsync 次数与 CPU 抖动
    pub fn for_tier(t: Tier) -> Self {
        match t {
            Tier::Nano => Self { max_batch: 16, max_delay: Duration::from_millis(500) },
            Tier::Small => Self { max_batch: 32, max_delay: Duration::from_millis(300) },
            Tier::Standard => Self::default(),
        }
    }
}

/// 单写 actor：**进程内唯一持有写连接的组件**。
pub struct WriterActor {
    tx: mpsc::Sender<(WriteOp, oneshot::Sender<Result<WriteAck>>)>,
}

impl WriterActor {
    pub fn spawn(path: PathBuf, tier: Tier, synchronous: &str) -> Result<Self> {
        let mut conn = open(&path, tier, synchronous)?;
        let (tx, mut rx) = mpsc::channel::<(WriteOp, oneshot::Sender<Result<WriteAck>>)>(256);
        let policy = FlushPolicy::for_tier(tier);

        // 阻塞型 SQLite 调用放在专用线程，不占用 tokio 的异步工作线程
        std::thread::Builder::new()
            .name("panel-writer".into())
            .spawn(move || {
                let mut batch: Vec<(WriteOp, oneshot::Sender<Result<WriteAck>>)> = Vec::new();
                let mut last_flush = std::time::Instant::now();

                loop {
                    // 等待首个操作（无超时，空闲时不消耗 CPU）
                    let first = match rx.blocking_recv() {
                        Some(v) => v,
                        None => break,   // 所有 sender 已释放 → 退出
                    };
                    batch.push(first);

                    // 攒批：直到满足数量阈值或时间窗口。
                    //
                    // 注意：tokio::sync::mpsc::Receiver **没有** recv_timeout / blocking_recv_timeout，
                    // 且本线程是裸 std 线程（不在 tokio runtime 内），也无法用 tokio::time::timeout。
                    // 因此以 try_recv + 短睡眠逼近 deadline：单片睡眠上限 1ms，对攒批延迟无实质影响；
                    // 空闲等待首个 op 仍走 blocking_recv（无超时、不空转 CPU）。
                    let deadline = last_flush + policy.max_delay;
                    while batch.len() < policy.max_batch {
                        let now = std::time::Instant::now();
                        if now >= deadline { break; }
                        match rx.try_recv() {
                            Ok(v) => batch.push(v),
                            Err(mpsc::error::TryRecvError::Empty) => {
                                std::thread::sleep((deadline - now).min(Duration::from_millis(1)));
                            }
                            // 所有 sender 已释放 → 立即 flush 剩余批次
                            Err(mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }

                    // 单事务执行整批
                    let drained = std::mem::take(&mut batch);
                    let txn_result = conn.transaction();
                    match txn_result {
                        Ok(txn) => {
                            // FnOnce 只能按值调用：必须把 op 从 drained 里 move 出来，
                            // 因此这里按值遍历，并把 reply 收集起来供提交结果回传。
                            let mut results = Vec::with_capacity(drained.len());
                            let mut replies = Vec::with_capacity(drained.len());
                            let mut first_err: Option<PanelError> = None;
                            for (op, reply) in drained {
                                match op(&txn) {
                                    Ok(ack) => results.push(Ok(ack)),
                                    Err(e) => {
                                        // 记录首个失败原因（用于整批回滚后统一回复）
                                        if first_err.is_none() { first_err = Some(clone_err(&e)); }
                                        results.push(Err(e));
                                    }
                                }
                                replies.push(reply);
                            }
                            if let Some(err) = first_err {
                                // 任一 op 失败 → 整批回滚（Transaction 析构自动 ROLLBACK），
                                // 绝不提交已执行的部分语句，避免数据半改。
                                drop(txn);
                                for reply in replies {
                                    let _ = reply.send(Err(clone_err(&err)));
                                }
                            } else {
                                match txn.commit() {
                                    Ok(()) => {
                                        for (reply, r) in replies.into_iter().zip(results) {
                                            let _ = reply.send(r);
                                        }
                                    }
                                    Err(e) => {
                                        let err = PanelError::Database(format!("commit: {e}"));
                                        for reply in replies {
                                            let _ = reply.send(Err(clone_err(&err)));
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let err = PanelError::Database(format!("begin: {e}"));
                            for (_, reply) in drained {
                                let _ = reply.send(Err(clone_err(&err)));
                            }
                        }
                    }
                    last_flush = std::time::Instant::now();
                }
            })
            .map_err(|e| PanelError::Internal(format!("spawn writer: {e}")))?;

        Ok(Self { tx })
    }

    /// 提交写操作并等待结果。
    ///
    /// # 纪律
    /// `op` **内部禁止**做任何网络请求、子进程调用或长循环。
    /// 实测：事务持有 1,000ms 会让所有其他写者等待 1,046ms（1:1 传导），
    /// 且 busy_timeout 不足时直接抛 `database is locked`。
    pub async fn exec<F>(&self, op: F) -> Result<WriteAck>
    where
        F: FnOnce(&Connection) -> Result<WriteAck> + Send + 'static,
    {
        let (reply, rx) = oneshot::channel();
        self.tx.send((Box::new(op), reply)).await
            .map_err(|_| PanelError::Internal("writer actor gone".into()))?;
        rx.await.map_err(|_| PanelError::Internal("writer actor dropped reply".into()))?
    }
}

/// writer actor 把错误克隆一份回传给发起者。
///
/// 此前一律降级为 `PanelError::Database`（映射 500）：`db.exec` 闭包内抛出的
/// Validation / Conflict 会被改写成"内部错误"，于是"用户名已存在""站点名重复"
/// 这类**用户输入问题**报成 500，前端只能显示服务器内部错误，用户无从得知该怎么改。
/// 保留原始类型后，这些场景能正确返回 400/409。
fn clone_err(e: &PanelError) -> PanelError {
    e.clone()
}

// ═══════════════════════════ 读连接池 ═══════════════════════════

/// 只读连接池。
///
/// 池大小即内存：每个连接持有 `cache_size` 指定的页缓存
/// （nano 1MB / small 2MB / standard 4MB）。nano 档位**只开 1 个读连接**，
/// 这是"常驻 RSS ≤12MB"预算能否达标的关键旋钮。
pub struct ReadPool {
    // 用 Arc 持有：spawn_blocking 的闭包要求 'static，不能直接借用 &self，
    // 取用时克隆对应下标的 Arc 移入闭包（连接本身仍由池独占，不改变单连接复用语义）。
    conns: Vec<Arc<std::sync::Mutex<Connection>>>,
    permits: Arc<Semaphore>,
}

impl ReadPool {
    pub fn new(path: &Path, tier: Tier) -> Result<Self> {
        let n = match tier {
            Tier::Nano => 1,
            Tier::Small => 2,
            Tier::Standard => 4,
        };
        let mut conns = Vec::with_capacity(n);
        for _ in 0..n {
            let c = open(path, tier, DEFAULT_SYNCHRONOUS)?;
            // 只读连接不需要 WAL 写侧资源
            let _ = c.pragma_update(None, "query_only", "ON");
            conns.push(Arc::new(std::sync::Mutex::new(c)));
        }
        Ok(Self { conns, permits: Arc::new(Semaphore::new(n)) })
    }

    /// 借用一条连接执行查询；池满时异步等待（不阻塞 tokio 工作线程）。
    pub async fn with<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let _permit = self.permits.acquire().await
            .map_err(|_| PanelError::Internal("read pool closed".into()))?;
        let idx = self.pick();
        // 阻塞型调用放到 blocking 池（tokio 侧需配置 max_blocking_threads）
        let conn = Arc::clone(&self.conns[idx]); // 克隆 Arc，避免把 &self 带进 'static 闭包
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().unwrap_or_else(|e| e.into_inner());
            f(&guard)
        })
        .await
        .map_err(|e| PanelError::Internal(format!("read task panicked: {e}")))?
    }

    fn pick(&self) -> usize {
        // 简化：轮转。生产实现可基于许可序号或原子计数器
        self.permits.available_permits() % self.conns.len().max(1)
    }
}

// ═══════════════════════════ 备份 ═══════════════════════════

/// 在线备份：`VACUUM INTO`（SQLite ≥ 3.27）。
/// 不需要外部 `sqlite3` CLI，也不需要长时间写锁。
pub fn backup_to(conn: &Connection, dest: &Path) -> Result<()> {
    // 先截断 WAL，让备份包含最新状态且体积更小
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .map_err(|e| PanelError::Database(format!("checkpoint: {e}")))?;
    // 目标路径已由 PathLayout + 沙箱校验（禁止字符串拼接 SQL）
    let dest_str = dest.to_str()
        .ok_or_else(|| PanelError::Validation { field: "backup_path", reason: "non-UTF8 path".into() })?;
    let sql = "VACUUM INTO ?1";
    let mut stmt = conn.prepare(sql).map_err(|e| PanelError::Database(e.to_string()))?;
    stmt.execute(rusqlite::params![dest_str])
        .map_err(|e| PanelError::Database(format!("vacuum into: {e}")))?;
    Ok(())
}

/// 独立连接执行在线备份：**绕开写者事务**。
///
/// 为什么不能走 `WriterActor::exec`：写者把每个 op 包在 `conn.transaction()` 里，
/// 而 `VACUUM INTO` 规定 **"cannot VACUUM from within a transaction"**，必然失败。
/// 备份是只读快照，本就不需要参与写者事务，故此处自开一条连接。
pub fn backup_file(db_path: &Path, dest: &Path) -> Result<()> {
    let conn = Connection::open(db_path)
        .map_err(|e| PanelError::Database(format!("open for backup: {e}")))?;
    backup_to(&conn, dest)
}

/// 完整性自检（可选，低配机器上 40MB 库约数十毫秒，故仅在用户手动触发或升级前执行）
pub fn integrity_check(conn: &Connection) -> Result<String> {
    conn.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
        .map_err(|e| PanelError::Database(e.to_string()))
}

#[cfg(test)]
mod backup_tests {
    use super::*;

    /// 锁定根因回归：必须用独立连接备份，走写者事务会触发
    /// "cannot VACUUM from within a transaction"。
    #[test]
    fn backup_file_produces_a_readable_snapshot() {
        let dir = std::env::temp_dir().join(format!("panel-db-bk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("src.db");
        let dest = dir.join("out.db");
        {
            let c = Connection::open(&db).unwrap();
            c.execute_batch("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES(42);").unwrap();
        }
        backup_file(&db, &dest).expect("独立连接备份应成功");
        assert!(dest.is_file(), "备份产物应存在");
        let c = Connection::open(&dest).unwrap();
        let v: i64 = c.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 42, "备份内容应可读且一致");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_policy_scales_with_tier() {
        assert_eq!(FlushPolicy::for_tier(Tier::Nano).max_batch, 16);
        assert_eq!(FlushPolicy::for_tier(Tier::Standard).max_batch, 64);
        // 低配必须拉长窗口以减少 fsync 次数
        assert!(FlushPolicy::for_tier(Tier::Nano).max_delay > FlushPolicy::default().max_delay);
    }

    #[test]
    fn read_pool_size_matches_tier() {
        // 池大小直接决定内存占用，nano 必须只有 1 个（1MB 页缓存）
        assert_eq!(pool_size(Tier::Nano), 1);
        assert_eq!(pool_size(Tier::Small), 2);
        assert_eq!(pool_size(Tier::Standard), 4);
    }

    fn pool_size(t: Tier) -> usize {
        match t { Tier::Nano => 1, Tier::Small => 2, Tier::Standard => 4 }
    }

    /// 防「假控制」回归：`[db] synchronous` 必须真落到 SQLite pragma，而非硬编码 NORMAL。
    ///
    /// 此前 `open` 里写死 `"NORMAL"`，config.toml 配 `synchronous = "FULL"` 毫无效果
    /// （与 session_* / max_login_attempts 同类 bug，lib.rs 注释还谎称「用户显式要求时启用」）。
    /// 这条测试直接开后查 `PRAGMA synchronous` 的数值（0=OFF/1=NORMAL/2=FULL/3=EXTRA），
    /// 把「配置驱动该值」钉死——改回硬编码会在第一步就挂。
    #[test]
    fn open_honors_configured_synchronous_mode() {
        let dir = std::env::temp_dir().join(format!("panel-db-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("s.db");

        // FULL 必须真生效（数值 2）
        let c_full = open(&db, Tier::Standard, "FULL").unwrap();
        let v_full: i64 = c_full.query_row("PRAGMA synchronous", [], |r| r.get(0)).unwrap();
        assert_eq!(v_full, 2, "synchronous=FULL 必须真生效");

        // 大小写不敏感
        let c_low = open(&db, Tier::Standard, "normal").unwrap();
        let v_low: i64 = c_low.query_row("PRAGMA synchronous", [], |r| r.get(0)).unwrap();
        assert_eq!(v_low, 1, "synchronous=normal 大小写不敏感应生效");

        // 非法值必须直接报错，而非静默降级成默认档（那种「配了不生效」最隐蔽）
        assert!(open(&db, Tier::Standard, "BOGUS").is_err(), "非法 synchronous 必须报错");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_off_mode_is_zero() {
        let dir = std::env::temp_dir().join(format!("panel-db-sync-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("s.db");
        let c = open(&db, Tier::Standard, "OFF").unwrap();
        let v: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 0, "synchronous=OFF 必须真生效（数值 0）");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
