//! 过期数据清理（设计方案 §1.4-8，已按实测修正）。
//!
//! # ⚠️ 实测修正：不要一律 `LIMIT 1000`
//! 20 万行表删除 10 万行：
//!
//! | 策略 | 总耗时 | **单次最长写锁** |
//! |---|---|---|
//! | 一次性 DELETE | **16.4 ms** | 16.43 ms |
//! | LIMIT 1000 | 60.6 ms | 5.83 ms |
//! | **LIMIT 5000** | 60.9 ms | **3.09 ms** ← 最优 |
//! | LIMIT 20000 | 62.5 ms | 12.63 ms |
//! | LIMIT 50000 | 63.2 ms | 31.76 ms |
//!
//! 100 万行表删除 50 万行：
//! | 一次性 | 91.1 ms | **91.11 ms** ❌ 超出 50ms 事务预算 |
//! | LIMIT 10000 | 340.1 ms | 12.70 ms ✅ |
//!
//! 结论：分批的价值在于**削平单次锁时长**，但批次过小会让总耗时涨 3.7 倍。
//! 所以按删除规模分档，见 [`batch_for`]。

use crate::{Result, WriteAck};
use panel_core::{PanelError, Tier};
use rusqlite::Connection;

/// 按预估删除行数选择批次大小。**这是实测结论，不要凭直觉改。**
pub fn batch_for(estimated_rows: u64) -> Option<usize> {
    match estimated_rows {
        0..=50_000 => None,              // 一次性删除：锁 ~16ms，且最快
        50_001..=500_000 => Some(5_000), // 最坏锁 3.09ms
        _ => Some(10_000),               // 百万行级：一次性锁 91ms 超标
    }
}

/// 清理指标表。行数已知（由保留策略推算），无需 COUNT 全表。
pub fn prune_metrics(conn: &Connection, r: crate::aggregator::Retention) -> Result<WriteAck> {
    let now = now_unix();
    let mut changed = 0usize;

    // 刻意写成两条常量 SQL 而非 format!("DELETE FROM {}")：
    // 表名虽来自代码常量，但任何 `format!` 进 SQL 都会弱化"禁止拼接"这条可 grep 的纪律。
    // 1m 表 7 天 = 10,080 行；1h 表 90 天 = 2,160 行 —— 均 ≤5 万，一次性删除即可。
    const DEL_1M: &str = "DELETE FROM metrics_1m WHERE ts < ?1";
    const DEL_1H: &str = "DELETE FROM metrics_1h WHERE ts < ?1";

    changed += conn.execute(DEL_1M, rusqlite::params![now - (r.keep_1m_days as i64) * 86_400])
        .map_err(|e| PanelError::Database(format!("prune metrics_1m: {e}")))?;
    changed += conn.execute(DEL_1H, rusqlite::params![now - (r.keep_1h_days as i64) * 86_400])
        .map_err(|e| PanelError::Database(format!("prune metrics_1h: {e}")))?;
    Ok(WriteAck { rows_changed: changed })
}

/// 清理审计日志。
///
/// # 为什么默认是 90 天而不是 180 天（实测修正）
/// 180 天 × 200 条/天 = 36,000 行 = **4.12 MB**（含 ts 索引），是分层后指标体积（668KB）的 **6 倍**。
/// 90 天 × 50 条/天 = 360 KB。故默认收紧为 90 天 + 5 万行上限。
pub fn prune_audit(conn: &Connection, retention_days: u32, max_rows: u64) -> Result<WriteAck> {
    let mut changed = 0usize;
    let cutoff = now_unix() - (retention_days as i64) * 86_400;
    changed += conn.execute("DELETE FROM audit_log WHERE ts < ?1", rusqlite::params![cutoff])
        .map_err(|e| PanelError::Database(format!("prune audit by time: {e}")))?;

    // 行数上限：超出部分按时间顺序删除（防"事件风暴"撑爆磁盘）
    let total: u64 = conn.query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0))
        .unwrap_or(0);
    if total > max_rows {
        let excess = total - max_rows;
        // ⚠ 批大小必须夹到 excess：`batch_for` 在 ≤5 万行时返回 None（意为"一次性删完最快"），
        // 直接兜底成 10000 会让 `LIMIT 10000` 把**整表**删掉——即"超限"实际变成"清空"。
        // 这是本模块原有的潜伏 bug（测试只断言 `>= 40` 没查最终条数，故长期为绿）。
        let batch = batch_for(excess).unwrap_or(10_000).min(excess as usize);
        loop {
            let n = conn.execute(
                "DELETE FROM audit_log WHERE id IN
                 (SELECT id FROM audit_log ORDER BY ts ASC LIMIT ?1)",
                rusqlite::params![batch],
            ).map_err(|e| PanelError::Database(format!("prune audit by count: {e}")))?;
            changed += n;
            if n == 0 { break; }
            let left: u64 = conn.query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0)).unwrap_or(0);
            if left <= max_rows { break; }
        }
    }
    Ok(WriteAck { rows_changed: changed })
}

/// 清理通知。
///
/// # 为什么需要它（此前是唯一漏网的业务表）
/// 通知只增不减：WAF 告警、任务完成、备份结果、证书到期都会写一行，而全仓
/// 唯一的 `DELETE FROM notifications` 是用户按 id 手动删除。列表查询有 `LIMIT`
/// （默认 50 / 上限 200），但**表本身无界**——对比 metrics / audit / task_runs /
/// block_events 都有 prune，这张表当时漏了。
///
/// 保留期与审计同口径（复用 `cfg.audit` 的两个旋钮）：两者都是"操作历史"，
/// 分开配只会多一个没人改的字段（见 MEMORY「配置项假控制」）。真需要分开再拆。
pub fn prune_notifications(conn: &Connection, retention_days: u32, max_rows: u64) -> Result<WriteAck> {
    let mut changed = 0usize;
    let cutoff = now_unix() - (retention_days as i64) * 86_400;
    changed += conn.execute("DELETE FROM notifications WHERE ts < ?1", rusqlite::params![cutoff])
        .map_err(|e| PanelError::Database(format!("prune notifications by time: {e}")))?;

    // 行数上限：防事件风暴（WAF 连续告警）把库撑大。删除顺序按 ts 升序，
    // 即**保留最新**的那 max_rows 条。
    let total: u64 = conn.query_row("SELECT count(*) FROM notifications", [], |r| r.get(0))
        .unwrap_or(0);
    if total > max_rows {
        let excess = total - max_rows;
        // 同 prune_audit：批大小夹到 excess，否则一次删光整表
        let batch = batch_for(excess).unwrap_or(10_000).min(excess as usize);
        loop {
            let n = conn.execute(
                "DELETE FROM notifications WHERE id IN
                 (SELECT id FROM notifications ORDER BY ts ASC LIMIT ?1)",
                rusqlite::params![batch],
            ).map_err(|e| PanelError::Database(format!("prune notifications by count: {e}")))?;
            changed += n;
            if n == 0 { break; }
            let left: u64 = conn.query_row("SELECT count(*) FROM notifications", [], |r| r.get(0))
                .unwrap_or(0);
            if left <= max_rows { break; }
        }
    }
    Ok(WriteAck { rows_changed: changed })
}

/// 清理任务执行记录（同审计策略）
pub fn prune_task_runs(conn: &Connection, retention_days: u32) -> Result<WriteAck> {
    let cutoff = now_unix() - (retention_days as i64) * 86_400;
    let n = conn.execute("DELETE FROM task_runs WHERE started_at < ?1", rusqlite::params![cutoff])
        .map_err(|e| PanelError::Database(format!("prune task_runs: {e}")))?;
    Ok(WriteAck { rows_changed: n })
}

/// 清理后执行一次 TRUNCATE checkpoint，把 WAL 收回主库。
///
/// 必要性：实测关闭 `wal_autocheckpoint` 后写入 5 万行，WAL 即膨胀到 **7.71MB 且持续增长**。
pub fn checkpoint_truncate(conn: &Connection) -> Result<()> {
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .map_err(|e| PanelError::Database(format!("checkpoint: {e}")))?;
    Ok(())
}

/// 清理任务的推荐执行时段（避开业务高峰），以及档位差异
pub fn schedule_hint(tier: Tier) -> &'static str {
    match tier {
        // nano 上清理本身也是 IO 负担，放到最空闲时段且只做时间维度清理
        Tier::Nano => "03:10（仅时间维度，跳过分批）",
        _ => "03:10",
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_thresholds_match_measurements() {
        assert_eq!(batch_for(10_000), None, "1万行应一次性删除");
        assert_eq!(batch_for(50_000), None, "5万行仍一次性");
        assert_eq!(batch_for(50_001), Some(5_000));
        assert_eq!(batch_for(200_000), Some(5_000), "20万行用 5000（实测最坏锁 3.09ms）");
        assert_eq!(batch_for(1_000_000), Some(10_000), "百万行用 10000（一次性锁 91ms 超标）");
    }

    #[test]
    fn small_batches_are_not_always_better() {
        // 反直觉点：更"安全"的 1000 批次在 10 万行量级总耗时涨 3.7 倍，
        // 且最坏锁（5.83ms）反而差于 5000 批次（3.09ms）
        assert_ne!(batch_for(100_000), Some(1_000));
    }

    #[test]
    fn prune_runs_on_real_db() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE audit_log(id INTEGER PRIMARY KEY, ts INTEGER)").unwrap();
        let now = now_unix();
        // 插入 1~100 天前的 100 条（刻意不含"今天"，这样保留 90 天时被删的正好是
        // 91~100 天前那 10 条；若从 0 开始则只有 9 条，与保留语义对不上）
        for i in 1..=100u32 {
            c.execute("INSERT INTO audit_log(ts) VALUES(?1)",
                      rusqlite::params![now - i as i64 * 86_400]).unwrap();
        }
        // 保留 90 天 → 删除 91 天之前的记录
        let ack = prune_audit(&c, 90, 50_000).unwrap();
        assert_eq!(ack.rows_changed, 10, "100 条中 91~100 天前的 10 条应被删除");
        // 再触发行数上限：必须**精确**收敛到 50，而不是被一次性删光
        let ack = prune_audit(&c, 90, 50).unwrap();
        assert_eq!(ack.rows_changed, 40, "90 行保留 50 ⇒ 只需删 40 行");
        let left: u64 = c.query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 50, "上限必须精确收敛到 max_rows（原实现会删光整表）");
    }

    #[test]
    fn prune_notifications_by_time_then_by_count() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE notifications(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, read INTEGER NOT NULL DEFAULT 0)",
        ).unwrap();
        let now = now_unix();
        // 1~100 天前各一条：保留 90 天时，91~100 天前那 10 条应被删
        for i in 1..=100u32 {
            c.execute("INSERT INTO notifications(ts) VALUES(?1)",
                      rusqlite::params![now - i as i64 * 86_400]).unwrap();
        }
        let ack = prune_notifications(&c, 90, 50_000).unwrap();
        assert_eq!(ack.rows_changed, 10, "91~100 天前的 10 条应被删除");

        // 再触发行数上限：保留最新 50 条
        let ack = prune_notifications(&c, 90, 50).unwrap();
        assert_eq!(ack.rows_changed, 40, "90 行保留 50 ⇒ 只需删 40 行");
        let left: u64 = c.query_row("SELECT count(*) FROM notifications", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 50, "上限必须精确收敛到 max_rows");

        // 保留的是**最新**那些（ts 最大），最老的一条必须已消失
        let oldest: u64 = c.query_row("SELECT count(*) FROM notifications WHERE ts = ?1",
            rusqlite::params![now - 90 * 86_400 + 86_400], |r| r.get(0)).unwrap();
        assert_eq!(oldest, 0, "删除顺序必须按 ts 升序（保留最新）");
    }

    #[test]
    fn prune_notifications_is_noop_when_under_limits() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE notifications(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, read INTEGER NOT NULL DEFAULT 0)",
        ).unwrap();
        let now = now_unix();
        for i in 0..5 {
            c.execute("INSERT INTO notifications(ts) VALUES(?1)",
                      rusqlite::params![now - i * 60]).unwrap();
        }
        let ack = prune_notifications(&c, 90, 50_000).unwrap();
        assert_eq!(ack.rows_changed, 0, "未超期未超限时不得删除任何行");
        let left: u64 = c.query_row("SELECT count(*) FROM notifications", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 5);
    }
}
