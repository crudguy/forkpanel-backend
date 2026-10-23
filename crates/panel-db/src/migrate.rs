//! schema 迁移：前向迁移、校验和核对、启动期快速路径。
//!
//! 冷启动预算 ≤150ms（nano），因此**版本未变更时不得执行任何 SQL**。
//!
//! 校验和核对的语义边界（别夸大成防篡改）：它检测**迁移源漂移**——同一版本
//! 的 SQL 文本在应用到本库之后又被改过（热补丁迁移文件、二进制与库不是同一
//! 构建、迁移文件被回滚）。它**不**检测对库结构的手工修改（那没有可信的比对
//! 基准），后者由 doctor 的 db_integrity 与备份恢复覆盖。发现漂移向 stderr
//! 告警但不阻断启动：面板按库内现状继续运行，静默继续才会让 operator 永远
//! 不知道文件与库已经分家。

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
    (17, include_str!("../../../migrations/017_site_conf_snapshot.sql")),
    (18, include_str!("../../../migrations/018_site_conf_versions.sql")),
    (19, include_str!("../../../migrations/019_site_custom_conf.sql")),
    (20, include_str!("../../../migrations/020_site_advanced.sql")),
    (21, include_str!("../../../migrations/021_site_access_proxy_log.sql")),
    (22, include_str!("../../../migrations/022_remark.sql")),
    (23, include_str!("../../../migrations/023_site_last_applied.sql")),
    // 024（apt-mark hold）无 schema 变更，版本号空置
    (25, include_str!("../../../migrations/025_server_notes.sql")),
    (26, include_str!("../../../migrations/026_waf_templates.sql")),
    (27, include_str!("../../../migrations/027_waf_block_events.sql")),
    (28, include_str!("../../../migrations/028_waf_alert_cfg.sql")),
];

/// 当前 schema 版本
pub const LATEST: u32 = 28;

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
    if current >= LATEST {
        // 版本已最新也要核对：漂移只可能是「旧版本的文件被改过」，与有没有
        // 新迁移要跑无关。快速路径因此多一次 28 行以内的查询（微秒级，冷启动
        // 预算 ≤150ms 不受影响）——省这一下换来的是一辈子静默的漂移。
        warn_on_checksum_drift(conn);
        return Ok(current);
    }

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
    // 新迁移刚写入当期校验和；此处核对的是**旧版本**是否被改过
    warn_on_checksum_drift(conn);
    Ok(LATEST)
}

/// 核对库存校验和；有漂移即向 stderr 打醒目告警。**不返回错误、不阻断启动**
/// ——漂移是「部署被改过」的信号，不是「库不能用」。
///
/// 收敛在 apply() 一处调用：serve / init / migrate / 测试夹具全都经过这里，
/// 不需要每个调用方各自记得查——「配了却忘接线」的假控制由此规避。
fn warn_on_checksum_drift(conn: &Connection) {
    match checksum_drift(conn) {
        Ok(drift) if !drift.is_empty() => {
            let items: Vec<String> = drift
                .iter()
                .map(|d| match &d.embedded {
                    Some(cur) => format!(
                        "v{}（库内 {} → 当前 {}", d.version, short_hash(&d.stored), short_hash(cur)
                    ),
                    None => format!(
                        "v{}（库内 {}，当前二进制无此迁移文件）", d.version, short_hash(&d.stored)
                    ),
                })
                .collect();
            eprintln!("[panel] ⚠ [db] schema 迁移校验和漂移：{}", items.join("；"));
            eprintln!(
                "[panel]    含义：这些迁移文件在应用到本库之后又被修改过（热补丁 / 二进制与库不是同一构建）。"
            );
            eprintln!(
                "[panel]    面板按库内现状继续运行，不会自动改写库存校验和（那会抹掉漂移证据）；"
            );
            eprintln!(
                "[panel]    请核对改动是否有意——有意的 schema 变更应新增迁移版本，详见 panel doctor。"
            );
        }
        Ok(_) => {}
        // 核对本身失败（库可读却查不出校验和）同样值得一声：未知状态不是健康状态
        Err(e) => eprintln!("[panel] ⚠ [db] 迁移校验和核对失败：{e}"),
    }
}

/// 取哈希前 8 位用于告警展示（按字节切，越界/非字符边界整体返回，不 panic）。
fn short_hash(s: &str) -> &str {
    s.get(..8).unwrap_or(s)
}

/// 一条迁移校验和漂移。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumDrift {
    /// 库内 `schema_migrations.version`
    pub version: u32,
    /// 应用时写入库内的校验和
    pub stored: String,
    /// 当前二进制内嵌 SQL 的当期校验和；该版本已无对应迁移文件
    /// （二进制比库旧 / 迁移文件被删）时为 `None`
    pub embedded: Option<String>,
}

/// 核对库存校验和与当前内嵌迁移 SQL 是否一致（迁移源漂移检测）。
///
/// 纯函数、只读：不改库、不迁移，可供 `panel doctor` 与测试直接调用。
/// 无 `schema_migrations` 表（还没迁移过的新库）⇒ 空 Vec——新库不是漂移。
pub fn checksum_drift(conn: &Connection) -> Result<Vec<ChecksumDrift>> {
    let has_table: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| PanelError::Database(e.to_string()))?;
    if !has_table {
        return Ok(Vec::new());
    }
    let mut stmt = conn
        .prepare("SELECT version, checksum FROM schema_migrations")
        .map_err(|e| PanelError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| PanelError::Database(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (version, stored) = row.map_err(|e| PanelError::Database(e.to_string()))?;
        let embedded = MIGRATIONS
            .iter()
            .find(|(v, _)| *v == version)
            .map(|(_, sql)| checksum(sql));
        let drifted = match &embedded {
            Some(cur) => *cur != stored,
            // 二进制里已无此版本的文件：库比二进制新（降级部署 / 文件被删）
            None => true,
        };
        if drifted {
            out.push(ChecksumDrift { version, stored, embedded });
        }
    }
    out.sort_by_key(|d| d.version);
    Ok(out)
}

/// 迁移 SQL 文本的指纹（FNV-1a，零新增依赖）。用于检测**迁移源漂移**：
/// 同一版本的 SQL 在应用到本库之后又被改过。发现漂移应告警而非静默继续
/// （见 `checksum_drift` / `warn_on_checksum_drift`）。
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
    fn checksum_drift_empty_on_fresh_and_consistent_db() {
        let mut c = Connection::open_in_memory().unwrap();
        // 还没建表：新库不是漂移
        assert!(checksum_drift(&c).unwrap().is_empty());
        apply(&mut c).unwrap();
        assert!(
            checksum_drift(&c).unwrap().is_empty(),
            "刚应用的库必须零漂移（否则每次启动都误告）"
        );
    }

    #[test]
    fn checksum_drift_detects_post_apply_edit() {
        let mut c = Connection::open_in_memory().unwrap();
        apply(&mut c).unwrap();
        c.execute(
            "UPDATE schema_migrations SET checksum = 'deadbeefdeadbeef' WHERE version = 3",
            [],
        )
        .unwrap();
        let d = checksum_drift(&c).unwrap();
        assert_eq!(d.len(), 1, "只有 v3 被改过");
        assert_eq!(d[0].version, 3);
        assert_eq!(d[0].stored, "deadbeefdeadbeef");
        let v3_sql = MIGRATIONS.iter().find(|(v, _)| *v == 3).unwrap().1;
        assert_eq!(d[0].embedded, Some(checksum(v3_sql)));
    }

    #[test]
    fn checksum_drift_flags_version_without_embedded_file() {
        let mut c = Connection::open_in_memory().unwrap();
        apply(&mut c).unwrap();
        // 模拟「二进制比库旧」：库里有一个当前构建里没有的迁移版本
        c.execute(
            "INSERT INTO schema_migrations(version, applied_at, checksum) VALUES(999, 0, 'cafecafecafecafe')",
            [],
        )
        .unwrap();
        let d = checksum_drift(&c).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].version, 999);
        assert_eq!(d[0].embedded, None, "当前二进制无此迁移文件");
    }

    #[test]
    fn apply_does_not_fail_on_drift() {
        // 语义钉死：漂移是告警而非阻断——apply 必须照常返回当前版本
        let mut c = Connection::open_in_memory().unwrap();
        apply(&mut c).unwrap();
        c.execute(
            "UPDATE schema_migrations SET checksum = 'tampered00' WHERE version = 1",
            [],
        )
        .unwrap();
        assert_eq!(apply(&mut c).unwrap(), LATEST, "漂移不得让 apply 失败");
    }

    #[test]
    fn latest_matches_embedded_max() {
        // 允许版本号空置（如 024 apt-hold 无 schema 变更、未建迁移文件），
        // 故断言「LATEST == 最大已注册版本」而非数量相等——同样能抓住
        // 「新增迁移文件后忘记递增 LATEST」。
        let max = MIGRATIONS.iter().map(|(v, _)| *v).max().unwrap_or(0);
        assert_eq!(LATEST, max, "新增迁移文件后必须递增 LATEST");
    }
}
