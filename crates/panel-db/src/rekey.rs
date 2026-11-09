//! 主密钥轮换（rekey）：用新主密钥把库里**所有**密文列重加密一遍。
//!
//! # 为什么这件事必须集中在一个文件里
//! 「用主密钥加密后入库」的字段散布在 5 个位置（4 个 BLOB 列 + settings 里的
//! `enc:<hex>`）。轮换时漏掉任何一处，症状都不是启动失败——而是**那个功能在某天
//! 突然报解密错**：旧密钥一销毁，漏掉的那一列就永久解不开。这不是「少做一点」，
//! 是把数据静默烧掉。所以覆盖面本身就是安全性，必须是一张**可被机器核对**的声明表。
//!
//! 声明表 [`BLOB_COLUMNS`] / [`SETTINGS_ENC_KEYS`] 与 `migrations/*.sql` 里实际
//! 存在的 `*_enc` 列、以及 `panel-api` 里 `enc:` 前缀的写入点，由
//! `ci/check_key_hygiene.py` 做**集合相等**校验：新增一个密文列却不更新此表，
//! 守卫直接判红。只写注释说「记得同步」是没用的（本项目已经踩过「配置项假控制」）。
//!
//! # 事务边界
//! 全部重加密在**一个事务**里完成：中途任何一行解不开都整体回滚，
//! 库保持旧密文 + 旧密钥仍然可用。绝不允许「改了一半」——
//! 半新半旧的库既不能被旧密钥打开全部，也不能被新密钥打开全部。
//!
//! # 不变式
//! - 只处理 `IS NOT NULL` 的行；空值不产生密文，也就不需要迁移。
//! - 解密失败一律报错并回滚，**绝不跳过**：跳过等于把坏行留给未来。
//! - 同一个明文重加密后密文必须不同（nonce 随机），故不能靠比较密文判断是否已迁移。

use panel_core::crypto::MasterKey;
use panel_core::{PanelError, Result};
use rusqlite::{Connection, OptionalExtension};

/// BLOB 型密文列：`(表, 列, 人类可读名)`。
///
/// ⚠ 顺序无关，但**内容必须与 schema 完全一致**（守卫会核对）。
/// 加新列时三处一起改：迁移 SQL、写入方 handler、这张表。
pub const BLOB_COLUMNS: &[(&str, &str, &str)] = &[
    ("users", "mfa_secret_enc", "MFA 密钥"),
    ("ssl_certs", "key_enc", "SSL 私钥"),
    ("db_connections", "password_enc", "数据库连接口令"),
    ("backup_jobs", "remote_secret_enc", "远端备份凭据"),
];

/// settings 表里以 `enc:<hex>` 形式存放的密文键。
///
/// 这类值的形态与 BLOB 列不同（JSON 字符串 + 十六进制），不能混进上面那张表。
pub const SETTINGS_ENC_KEYS: &[&str] = &["assistant.llm_api_key"];

/// settings 里密文值的前缀（与 `panel-api::routes::settings` 的写入方一致）。
pub const SETTINGS_ENC_PREFIX: &str = "enc:";

/// 每个作用域各重加密了多少行。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RekeyReport {
    /// `(作用域名, 行数)`，顺序与声明表一致。
    pub per_scope: Vec<(String, usize)>,
}

impl RekeyReport {
    pub fn total(&self) -> usize {
        self.per_scope.iter().map(|(_, n)| *n).sum()
    }
    /// 一行摘要，供 CLI 打印。
    pub fn summary(&self) -> String {
        self.per_scope
            .iter()
            .map(|(name, n)| format!("{name} {n}"))
            .collect::<Vec<_>>()
            .join(" / ")
    }
}

/// 用 `new` 重新加密 `old` 加密过的全部密文。**单事务**，失败整体回滚。
///
/// 成功后**旧密钥立即失效**（库里已无旧密文），调用方必须紧接着把
/// `master.key.bak` 与 `master.key` 原子换掉，否则服务重启会读不到新密钥。
pub fn rekey_all(conn: &mut Connection, old: &MasterKey, new: &MasterKey) -> Result<RekeyReport> {
    let tx = conn
        .transaction()
        .map_err(|e| PanelError::Database(format!("rekey begin: {e}")))?;

    let mut per_scope = Vec::with_capacity(BLOB_COLUMNS.len() + 1);
    for (table, column, label) in BLOB_COLUMNS {
        let n = rekey_blob_column(&tx, table, column, old, new).map_err(|e| {
            PanelError::Internal(format!(
                "重加密 {table}.{column}（{label}）失败，已整体回滚：{e}"
            ))
        })?;
        per_scope.push(((*label).to_string(), n));
    }
    let n = rekey_settings(&tx, old, new)
        .map_err(|e| PanelError::Internal(format!("重加密 settings 密文失败，已整体回滚：{e}")))?;
    per_scope.push(("LLM API Key".to_string(), n));

    tx.commit()
        .map_err(|e| PanelError::Database(format!("rekey commit: {e}")))?;
    Ok(RekeyReport { per_scope })
}

/// 重加密一个 BLOB 列，返回处理行数。
fn rekey_blob_column(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    column: &str,
    old: &MasterKey,
    new: &MasterKey,
) -> Result<usize> {
    // 表名/列名来自本文件的常量表，不是外部输入。仍逐个校验字符集：
    // 将来若有人把这里改成「从配置读」，SQL 拼接会立刻变成注入口子——
    // 让它在改的第一天就 panic，而不是等到被利用。
    for ident in [table, column] {
        if ident.is_empty() || !ident.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(PanelError::Internal(format!("非法标识符：{ident}")));
        }
    }

    let sel = format!("SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL");
    let rows: Vec<(i64, Vec<u8>)> = {
        let mut stmt = tx
            .prepare(&sel)
            .map_err(|e| PanelError::Database(format!("prepare {sel}: {e}")))?;
        let iter = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(|e| PanelError::Database(format!("query {sel}: {e}")))?;
        iter.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| PanelError::Database(format!("read {sel}: {e}")))?
    };

    let upd = format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2");
    let mut n = 0usize;
    for (id, blob) in rows {
        let plain = old.decrypt(&blob).map_err(|e| {
            PanelError::Internal(format!(
                "{table}.{column} id={id} 用旧主密钥解密失败（{e}）——\
                 密钥文件与库不匹配，或该列本就不是主密钥加密"
            ))
        })?;
        let fresh = new.encrypt(&plain)?;
        tx.execute(&upd, rusqlite::params![fresh, id])
            .map_err(|e| PanelError::Database(format!("{upd}: {e}")))?;
        n += 1;
    }
    Ok(n)
}

/// 重加密 settings 表里 `enc:<hex>` 形式的值，返回处理行数。
fn rekey_settings(
    tx: &rusqlite::Transaction<'_>,
    old: &MasterKey,
    new: &MasterKey,
) -> Result<usize> {
    let mut n = 0usize;
    for key in SETTINGS_ENC_KEYS {
        let raw: Option<String> = tx
            .query_row("SELECT value_json FROM settings WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(|e| PanelError::Database(format!("read settings.{key}: {e}")))?;
        let Some(raw) = raw else { continue };

        // value_json 存的是 JSON 字符串（`"enc:<hex>"`），不是裸文本。
        let inner: String = serde_json::from_str(&raw).map_err(|e| {
            PanelError::Internal(format!("settings.{key} 不是 JSON 字符串（{e}）"))
        })?;
        // 没有 `enc:` 前缀 = 明文（历史数据或用户从未设置）⇒ 不含密文，不迁移。
        let Some(hex) = inner.strip_prefix(SETTINGS_ENC_PREFIX) else { continue };

        let blob = hex_decode(hex)
            .ok_or_else(|| PanelError::Internal(format!("settings.{key} 十六进制非法")))?;
        let plain = old.decrypt(&blob).map_err(|e| {
            PanelError::Internal(format!("settings.{key} 用旧主密钥解密失败（{e}）"))
        })?;
        let fresh = new.encrypt(&plain)?;
        let val = serde_json::to_string(&format!("{SETTINGS_ENC_PREFIX}{}", hex_encode(&fresh)))
            .map_err(|e| PanelError::Internal(format!("settings.{key} 序列化失败（{e}）")))?;
        tx.execute("UPDATE settings SET value_json = ?1 WHERE key = ?2", rusqlite::params![val, key])
            .map_err(|e| PanelError::Database(format!("update settings.{key}: {e}")))?;
        n += 1;
    }
    Ok(n)
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate;

    fn key(b: u8) -> MasterKey { MasterKey::from_bytes(&[b; 32]).expect("32 字节") }

    /// 建一份**真 schema**（跑全部迁移），再塞入 5 类密文各一行。
    fn fixture(old: &MasterKey) -> Connection {
        let mut c = Connection::open_in_memory().expect("内存库");
        migrate::apply(&mut c).expect("迁移");
        c.execute(
            "INSERT INTO users(username, pwd_hash, created_at, mfa_secret_enc) \
             VALUES('admin', 'x', 0, ?1)",
            rusqlite::params![old.encrypt(b"JBSWY3DPEHPK3PXP").unwrap()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO ssl_certs(domains, source, key_enc, cert, created_at) \
             VALUES('[\"a.test\"]', 'manual', ?1, 'CERT', 0)",
            rusqlite::params![old.encrypt(b"-----BEGIN PRIVATE KEY-----").unwrap()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO db_connections(name, engine, password_enc) VALUES('db1', 'mysql', ?1)",
            rusqlite::params![old.encrypt(b"db-pass").unwrap()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO backup_jobs(kind, target, dest_dir, remote_secret_enc) \
             VALUES('panel', 'p', '/tmp', ?1)",
            rusqlite::params![old.encrypt(b"remote-secret").unwrap()],
        )
        .unwrap();
        let llm = format!("{SETTINGS_ENC_PREFIX}{}", hex_encode(&old.encrypt(b"sk-real").unwrap()));
        c.execute(
            "INSERT INTO settings(key, value_json) VALUES(?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            rusqlite::params![SETTINGS_ENC_KEYS[0], serde_json::to_string(&llm).unwrap()],
        )
        .unwrap();
        c
    }

    /// 读回某列的密文。
    ///
    /// 用**字面量 SQL 的 match**而不是 `format!("… {table}.{column} …")`：
    /// ① `ci/check-layering.sh` 禁止把拼接串直接喂给查询（哪怕标识符来自常量表）；
    /// ② 顺带多一条护栏——`BLOB_COLUMNS` 里新增一列却没在这里加夹具，会 panic
    ///    而不是静默用一条 `SELECT` 读不到东西然后断言"0 行"通过。
    fn blob_of(c: &Connection, table: &str, column: &str) -> Vec<u8> {
        let sql = match (table, column) {
            ("users", "mfa_secret_enc") => "SELECT mfa_secret_enc FROM users WHERE id = 1",
            ("ssl_certs", "key_enc") => "SELECT key_enc FROM ssl_certs WHERE id = 1",
            ("db_connections", "password_enc") => {
                "SELECT password_enc FROM db_connections WHERE id = 1"
            }
            ("backup_jobs", "remote_secret_enc") => {
                "SELECT remote_secret_enc FROM backup_jobs WHERE id = 1"
            }
            other => panic!("BLOB_COLUMNS 新增了 {other:?}，请在测试里加对应夹具"),
        };
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn llm_of(c: &Connection) -> String {
        let raw: String = c
            .query_row("SELECT value_json FROM settings WHERE key = ?1", [SETTINGS_ENC_KEYS[0]], |r| {
                r.get(0)
            })
            .unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn rekey_makes_every_scope_readable_by_new_key_only() {
        let old = key(1);
        let new = key(2);
        let mut c = fixture(&old);

        let rep = rekey_all(&mut c, &old, &new).expect("rekey 成功");
        // 5 个作用域各命中 1 行——**数量断言**保证没有「声明了但没扫到」
        assert_eq!(rep.per_scope.len(), BLOB_COLUMNS.len() + 1, "作用域数量应与声明表一致");
        assert_eq!(rep.total(), 5, "5 类密文各 1 行：{}", rep.summary());

        for (table, column, label) in BLOB_COLUMNS {
            let blob = blob_of(&c, table, column);
            assert!(new.decrypt(&blob).is_ok(), "{label} 应能被新密钥解开");
            assert!(old.decrypt(&blob).is_err(), "{label} 不该还能被旧密钥解开");
        }
        let hex = llm_of(&c);
        let blob = hex_decode(hex.strip_prefix(SETTINGS_ENC_PREFIX).expect("仍有 enc: 前缀")).unwrap();
        assert_eq!(new.decrypt(&blob).unwrap(), b"sk-real", "LLM key 明文应保持不变");
        assert!(old.decrypt(&blob).is_err());
    }

    #[test]
    fn rekey_is_idempotent_in_shape_and_can_be_repeated() {
        let a = key(3);
        let b = key(4);
        let c2 = key(5);
        let mut c = fixture(&a);
        rekey_all(&mut c, &a, &b).expect("第一次");
        let rep = rekey_all(&mut c, &b, &c2).expect("第二次");
        assert_eq!(rep.total(), 5, "第二次也应命中同样的 5 行");
        let blob = blob_of(&c, "db_connections", "password_enc");
        assert_eq!(c2.decrypt(&blob).unwrap(), b"db-pass");
    }

    #[test]
    fn wrong_old_key_rolls_back_everything() {
        let old = key(6);
        let new = key(7);
        let bad = key(8);
        let mut c = fixture(&old);
        let before = blob_of(&c, "users", "mfa_secret_enc");

        let err = rekey_all(&mut c, &bad, &new).expect_err("密钥不对必须失败");
        let msg = format!("{err}");
        assert!(msg.contains("users.mfa_secret_enc"), "报错要点名哪一列，实际：{msg}");
        assert!(msg.contains("回滚"), "报错要说已回滚，实际：{msg}");

        // ⚠ 回滚的证据必须落在**库**上，不是看函数返回值
        let after = blob_of(&c, "users", "mfa_secret_enc");
        assert_eq!(before, after, "失败后密文必须逐字节不变（整体回滚）");
        assert!(old.decrypt(&after).is_ok(), "旧密钥仍可用");
    }

    #[test]
    fn null_columns_are_skipped() {
        let old = key(9);
        let new = key(10);
        let mut c = Connection::open_in_memory().unwrap();
        migrate::apply(&mut c).unwrap();
        c.execute(
            "INSERT INTO db_connections(name, engine) VALUES('nopw', 'sqlite')",
            [],
        )
        .unwrap();
        let rep = rekey_all(&mut c, &old, &new).expect("无密文也应成功");
        assert_eq!(rep.total(), 0, "全空值时应零行：{}", rep.summary());
    }

    #[test]
    fn settings_without_enc_prefix_is_left_alone() {
        let old = key(11);
        let new = key(12);
        let mut c = Connection::open_in_memory().unwrap();
        migrate::apply(&mut c).unwrap();
        // 明文历史值（不带 enc:）——不是密文，重加密不该动它，也不该报错
        c.execute(
            "INSERT INTO settings(key, value_json) VALUES(?1, '\"plain\"') \
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            [SETTINGS_ENC_KEYS[0]],
        )
        .unwrap();
        let rep = rekey_all(&mut c, &old, &new).expect("明文值不算失败");
        assert_eq!(rep.total(), 0);
        let raw: String = c
            .query_row("SELECT value_json FROM settings WHERE key = ?1", [SETTINGS_ENC_KEYS[0]], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(raw, "\"plain\"", "明文值必须原样保留");
    }

    #[test]
    fn hex_roundtrip() {
        for v in [vec![], vec![0u8], vec![255u8, 0, 16], vec![1, 2, 3, 4, 5]] {
            assert_eq!(hex_decode(&hex_encode(&v)).unwrap(), v);
        }
        assert!(hex_decode("abc").is_none(), "奇数长度必须拒绝");
        assert!(hex_decode("zz").is_none(), "非十六进制必须拒绝");
    }
}
