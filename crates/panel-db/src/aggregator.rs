//! 指标分层聚合器（设计方案 §1.4-3）。
//!
//! # 实测依据（第二轮 bench4）
//! 1 小时 1s 采样（3,600 次）两种落盘方式：
//!
//! | 方式 | 行数 | 事务数 | DB 体积 | 耗时 |
//! |---|---|---|---|---|
//! | 每秒写一行 | 3,600 | 3,600 | 196 KB | 0.055 s |
//! | **聚合为 1 分钟** | 60 | 60 | 8 KB | 0.003 s |
//!
//! **事务数降 60 倍、体积降 24 倍、耗时降 17.7 倍。** 这就是"绝不落 1s 原始点"的量化理由。
//! 外推到 7 天：原始点 31.9 MB vs 分层 668 KB（**48 倍**）。

use crate::{ring::MetricsRing, Result, WriteAck};
use panel_core::{PanelError, Tier};
use rusqlite::Connection;
use std::time::Duration;

/// 三层保留策略
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub keep_1m_days: u32,
    pub keep_1h_days: u32,
}

impl Default for Retention {
    fn default() -> Self { Self { keep_1m_days: 7, keep_1h_days: 90 } }
}

/// 聚合器：驱动内存环形缓冲 → 1m 表 → 1h 表 → 过期清理。
pub struct Aggregator {
    ring: MetricsRing,
    tier: Tier,
    retention: Retention,
}

impl Aggregator {
    pub fn new(tier: Tier) -> Self {
        let cap = match tier {
            // 3600 点 @1s = 1 小时；nano 5s 采样用 720 点覆盖同长，省 200KB
            Tier::Nano => 720,
            _ => 3600,
        };
        Self { ring: MetricsRing::new(cap), tier, retention: Retention::default() }
    }

    pub fn ring(&self) -> &MetricsRing { &self.ring }

    /// 采样任务每 `tier.sampling_interval_ms()` 调用一次，仅写内存。
    pub fn record(&mut self, s: crate::ring::Sample) {
        self.ring.push(s);
    }

    /// 每 60s 调用一次：把环形缓冲中最近 60 点（nano 为 12 点）聚合成一行写入 `metrics_1m`。
    ///
    /// **nano 档位不落盘**（`tier.persist_history() == false`），只保留内存缓冲 ——
    /// 512MB 机器上省掉全部指标写入 IO。
    pub fn flush_1m(&self, conn: &mut Connection) -> Result<WriteAck> {
        if !self.tier.persist_history() {
            return Ok(WriteAck { rows_changed: 0 });
        }
        let n = match self.tier { Tier::Nano => 12, _ => 60 };
        let Some(agg) = self.ring.aggregate(n) else {
            return Ok(WriteAck { rows_changed: 0 });
        };
        conn.execute(
            "INSERT OR REPLACE INTO metrics_1m
             (ts, cpu_pct, mem_used_kib, mem_total_kib, swap_used_kib,
              disk_used_bytes, disk_total_bytes, net_in_bps, net_out_bps, load1)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            rusqlite::params![
                agg.ts - (agg.ts % 60),          // 对齐到分钟
                agg.cpu_pct, agg.mem_used_kib, agg.mem_total_kib, agg.swap_used_kib,
                agg.disk_used_bytes, agg.disk_total_bytes,
                agg.net_in_bps, agg.net_out_bps, agg.load1,
            ],
        ).map_err(|e| PanelError::Database(format!("insert metrics_1m: {e}")))?;
        Ok(WriteAck { rows_changed: 1 })
    }

    /// 每天 03:10 调用：把 1m 聚合为 1h，并清理两级过期数据。
    /// 清理走 `crate::cleanup` 的分档策略（实测：一律 LIMIT 1000 反而更慢）。
    pub fn rollup_1h(&self, conn: &mut Connection) -> Result<WriteAck> {
        let mut stmt = conn.prepare(
            "INSERT OR REPLACE INTO metrics_1h
             (ts, cpu_pct, mem_used_kib, mem_total_kib, swap_used_kib,
              disk_used_bytes, disk_total_bytes, net_in_bps, net_out_bps, load1)
             SELECT ts - (ts % 3600), AVG(cpu_pct), MAX(mem_used_kib), MAX(mem_total_kib),
                    MAX(swap_used_kib), MAX(disk_used_bytes), MAX(disk_total_bytes),
                    MAX(net_in_bps), MAX(net_out_bps), AVG(load1)
             FROM metrics_1m
             WHERE ts < ?1
             GROUP BY ts - (ts % 3600)",
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        let cutoff = now_unix() - 86_400;
        let n = stmt.execute(rusqlite::params![cutoff])
            .map_err(|e| PanelError::Database(format!("rollup: {e}")))?;

        // Statement 持有 &Connection，其借用一直持续到析构；
        // 必须先显式释放，才能把 conn 作为 &mut 交给 prune_metrics。
        drop(stmt);

        crate::cleanup::prune_metrics(conn, self.retention)?;
        Ok(WriteAck { rows_changed: n })
    }

    /// 供 SSE 使用的采样间隔
    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.tier.sampling_interval_ms())
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
    fn nano_uses_smaller_ring() {
        let a = Aggregator::new(Tier::Nano);
        assert_eq!(a.ring().capacity(), 720);
        assert!(a.ring().bytes() < 60 * 1024, "nano 环形缓冲应 < 60KB，实际 {}B", a.ring().bytes());
    }

    #[test]
    fn standard_keeps_one_hour() {
        let a = Aggregator::new(Tier::Standard);
        assert_eq!(a.ring().capacity(), 3600);
        assert_eq!(a.interval(), Duration::from_secs(1));
    }

    #[test]
    fn nano_does_not_persist() {
        // nano 档位 flush_1m 必须是 no-op（512MB 机器上不产生指标写入 IO）
        let a = Aggregator::new(Tier::Nano);
        assert!(!Tier::Nano.persist_history());
        let mut c = Connection::open_in_memory().unwrap();
        let ack = a.flush_1m(&mut c).unwrap();
        assert_eq!(ack.rows_changed, 0);
    }
}
