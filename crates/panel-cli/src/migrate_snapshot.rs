//! 升级前自动一致快照：给「旧二进制读新库」提供一条可执行的回退路径。
//!
//! 项目目前只有**前向迁移**（`panel-db/migrate.rs` 的 MIGRATIONS 是纯前向数组），
//! 且 025（`DROP TABLE server_note`）、029（`DROP TABLE api_tokens`）是破坏性变更，
//! 一旦应用，旧二进制无法在同一库上运行，也没有 down migration 可退。
//! 与其为每个历史版本硬写反向 SQL（数据已删的 DROP 无法真正还原），这里在
//! **任何一次真实升级前**用 `VACUUM INTO` 留一份升级前的一致快照；回滚流程是
//! 「停服 → panel restore-db <快照> → 换回旧二进制 → 起服务」，见
//! `docs/deployment.md`「schema 升级与回滚」。
//!
//! 只在 `0 < current < LATEST` 时生成：全新库（current=0）没有可回滚的旧状态，
//! 版本已最新时快速路径不产生任何额外 IO（冷启动预算 ≤150ms 不受影响）。

use panel_core::{PanelError, Result};
use std::path::{Path, PathBuf};

pub const SNAPSHOT_PREFIX: &str = "pre-migrate-";
pub const SNAPSHOT_KEEP: usize = 5;

/// 读当前 schema 版本；`schema_migrations` 不存在（全新库）视为 0。
fn current_version(conn: &rusqlite::Connection) -> Result<u32> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .map_err(|e| PanelError::Database(format!("读取 schema 元信息失败: {e}")))?;
    if !exists {
        return Ok(0);
    }
    conn.query_row("SELECT COALESCE(MAX(version), 0) FROM schema_migrations", [], |r| r.get(0))
        .map_err(|e| PanelError::Database(format!("读取 schema 版本失败: {e}")))
}

/// 在 `migrate::apply` **之前**调用；返回生成的快照路径（无需升级时为 None）。
/// 快照失败按**升级阻断**处理：宁可不起新版本，也不能在没有回退锚点的情况下
/// 把 schema 推到不可回退的位置。
pub fn snapshot_before_migrate(
    conn: &rusqlite::Connection,
    db_path: &Path,
    backup_dir: &Path,
) -> Result<Option<PathBuf>> {
    let current = current_version(conn)?;
    let latest = panel_db::migrate::LATEST;
    if current == 0 || current >= latest {
        return Ok(None);
    }

    std::fs::create_dir_all(backup_dir).map_err(|e| PanelError::Internal(
        format!("创建升级快照目录 {} 失败: {e}", backup_dir.display())))?;

    let base = format!("{SNAPSHOT_PREFIX}v{current}-to-v{latest}-{}.db", panel_core::now_unix() as u64);
    let mut dest = backup_dir.join(&base);
    // 同一秒内多次启动会撞名；VACUUM INTO 拒绝覆盖，顺延序号绝不覆盖旧快照。
    let mut n = 1u32;
    while dest.exists() {
        dest = backup_dir.join(format!(
            "{SNAPSHOT_PREFIX}v{current}-to-v{latest}-{}-{n}.db", panel_core::now_unix() as u64));
        n += 1;
    }
    panel_db::backup_file(db_path, &dest)?;
    let removed = panel_os::prune_keep_newest(backup_dir, SNAPSHOT_PREFIX, SNAPSHOT_KEEP);
    println!("· 升级前一致快照：{}（保留最近 {SNAPSHOT_KEEP} 份，裁掉 {removed} 份）",
             dest.display());
    eprintln!("[panel] schema 将从 v{current} 升到 v{latest}；回滚锚点 {}", dest.display());
    Ok(Some(dest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fp-migrate-snap-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn fresh_db_has_no_rollback_snapshot() {
        let d = tmp("fresh");
        let db = d.join("panel.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        assert_eq!(current_version(&conn).unwrap(), 0);
        assert!(snapshot_before_migrate(&conn, &db, &d.join("backups")).unwrap().is_none());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn older_schema_produces_verifiable_snapshot() {
        let d = tmp("older");
        let db = d.join("panel.db");
        let backups = d.join("backups");
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY);
                 INSERT INTO schema_migrations VALUES(28);
                 CREATE TABLE keep_me(id INTEGER); INSERT INTO keep_me VALUES(42);"
            ).unwrap();
        }
        let conn = rusqlite::Connection::open(&db).unwrap();
        let snap = snapshot_before_migrate(&conn, &db, &backups)
            .unwrap().expect("v28 -> v29 必须留快照");
        assert!(snap.exists());
        let check = rusqlite::Connection::open(&snap).unwrap();
        let n: i64 = check.query_row("SELECT id FROM keep_me LIMIT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 42, "快照必须含升级前的全部数据");
        let v: u32 = check.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 28, "快照必须是升级前的 schema 版本");
        drop(check);
        drop(conn);
        std::fs::remove_dir_all(&d).ok();
    }
}
