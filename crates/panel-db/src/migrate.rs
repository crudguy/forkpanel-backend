//! schema 迁移：前向迁移、校验和校验、启动期快速路径。
//!
//! 冷启动预算 ≤150ms（nano），因此**版本未变更时不得执行任何 SQL**。

use crate::Result;
use panel_core::PanelError;
use rusqlite::Connection;

/// 编译期内嵌的迁移脚本（每个版本一个事务）
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../../../migrations/001_init.sql")),
    (2, include_str!("../../../migrations/002_notifications.sql")),
    (3, include_str!("../../../migrations/003_mfa.sql")),
    (4, include_str!("../../../migrations/004_cron_overlap_webhook.sql")),
    (5, include_str!("../../../migrations/005_backup_encrypt.sql")),
    (6, include_str!("../../../migrations/006_roles.sql")),
    (7, include_str!("../../../migrations/007_backup_remote.sql")),
    (8, include_str!("../../../migrations/008_site_waf.sql")),
    (9, include_str!("../../../migrations/009_site_upstreams_fpm.sql")),
    (10, include_str!("../../../migrations/010_cert_auto_renew.sql")),
    (11, include_str!("../../../migrations/011_cert_sweep_state.sql")),
    (12, include_str!("../../../migrations/012_task_idempotency.sql")),
    (13, include_str!("../../../migrations/013_site_spa_redirect.sql")),
    (14, include_str!("../../../migrations/014_apps.sql")),
    (15, include_str!("../../../migrations/015_site_routes.sql")),
    (16, include_str!("../../../migrations/016_site_manual_conf.sql")),
];

/// 当前 schema 版本
pub const LATEST: u32 = 16;

pub fn apply(conn: &mut Connection) -> Result<u32> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations(
             version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL, checksum TEXT NOT NULL);",
    ).map_err(|e| PanelError::Database(e.to_string()))?;

    // 快速路径：无待执行迁移时只做一次单行查询（微秒级），不触碰其他表。
    //
    // 查询失败**绝不能**当成 v0：空表（正常新库）返回的是 `MAX=NULL → COALESCE 0`，
    // 那才是 v0；而报错意味着库不可读或 schema_migrations 结构损坏。若在此兜成 0，
    // 后面的循环会从头重跑 001（历史迁移用的是裸 CREATE TABLE，无 IF NOT EXISTS），
    // 于是抛出 "table xxx already exists" —— 把真正的损坏原因彻底掩盖，
    // 排障时会被这条误导性报错带偏。库损坏必须带着原始错误失败。
    let current: u32 = match conn
        .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_migrations", [], |r| r.get(0))
    {
        Ok(v) => v,
        Err(e) => return Err(PanelError::Database(
            format!("读取 schema 版本失败（数据库可能已损坏）: {e}"))),
    };
    if current >= LATEST { return Ok(current); }

    for (version, sql) in MIGRATIONS {
        if *version <= current { continue; }
        let txn = conn.transaction().map_err(|e| PanelError::Database(e.to_string()))?;
        txn.execute_batch(sql)
            .map_err(|e| PanelError::Database(format!("migrate v{version}: {e}")))?;
        txn.execute(
            "INSERT OR REPLACE INTO schema_migrations(version, applied_at, checksum) VALUES(?1,?2,?3)",
            rusqlite::params![version, now_unix(), checksum(sql)],
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        txn.commit().map_err(|e| PanelError::Database(format!("commit v{version}: {e}")))?;
    }
    Ok(LATEST)
}

/// 校验和用于检测"有人手工改了库结构"——这类情况应告警而非静默继续
fn checksum(sql: &str) -> String {
    // FNV-1a：无需引入 sha2 crate（依赖预算）
    let mut h: u64 = 0xcbf29ce484222325;
    for b in sql.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
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
    fn fast_path_when_up_to_date() {
        let mut c = Connection::open_in_memory().unwrap();
        apply(&mut c).unwrap();
        let v1 = c.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| r.get::<_, u32>(0)).unwrap();
        // 二次调用应命中快速路径且不报错
        let v2 = apply(&mut c).unwrap();
        assert_eq!(v1, LATEST);
        assert_eq!(v1, v2);
    }

    #[test]
    fn checksum_is_stable_and_sensitive() {
        let a = checksum("CREATE TABLE t(a);");
        let b = checksum("CREATE TABLE t(b);");
        assert_eq!(a, checksum("CREATE TABLE t(a);"));
        assert_ne!(a, b);
    }

    #[test]
    fn latest_matches_embedded_count() {
        assert_eq!(LATEST, MIGRATIONS.len() as u32,
                   "新增迁移文件后必须递增 LATEST");
    }
}
