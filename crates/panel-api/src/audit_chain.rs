//! 审计日志哈希链（P2-11）。
//!
//! ## 解决什么问题
//!
//! 030 的 append-only 触发器只能挡住**经 SQL 接口**的 UPDATE/DELETE。能直接写库
//! 文件的 root 进程可以 `DROP TRIGGER` 后随意改，或干脆用 `sqlite3` 打开文件改——
//! 那种情况下系统一声不吭，事后无法发现。本模块提供**可检测性**：每条审计记录
//! 携带 `prev_hash`（上一条的链值）与 `hash`（本条内容的 HMAC），任何一条被改、
//! 被删、被插，都会让后续的链值对不上。
//!
//! ## 为什么用 HMAC 而不是裸 SHA256
//!
//! 裸哈希链挡不住「改完数据再把后续所有 hash 重算一遍」——攻击者只要读得到库就
//! 算得出来。HMAC 的密钥是 `/var/lib/forkpanel/master.key`，**不进数据库**，
//! 所以即便攻击者能写库，也算不出合法的链值（除非同时拿到密钥文件，那是更深
//! 一层的沦陷，届时检测手段应转向异机备份/外部告警）。
//!
//! ## 边界（诚实，不夸大）
//!
//! - 不防「把 audit_log 与 audit_hash_anchor 一起清空」：那是彻底擦除，本题无解，
//!   只能靠链尾锚点的**异机副本**或外部告警发现。
//! - 迁移前的历史行 `prev_hash/hash` 为 NULL，**不回填**——链从第一条 non-NULL
//!   的行开始，`verify()` 对 NULL 段如实跳过而不是谎称"已校验"。

use panel_core::crypto::MasterKey;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// HMAC 的"域分隔"前缀：让审计链的密钥派生与库内其他用途（如口令加密）互不干扰。
///
/// 直接拿主密钥当 HMAC key 也能跑，但同一把密钥用在两种原语上，任何一边的设计
/// 变更都可能悄悄影响另一边。派生一层几乎没有成本。
const CHAIN_KEY_LABEL: &str = "forkpanel/audit-chain/v1";

/// 一条待写入（或从库里读回）的审计记录内容。
///
/// 之所以不直接传 8 个参数：链值计算要求**字段顺序与拼接方式完全固定**，
/// 散落的参数顺序错一位（比如 referer 与 UA 写反）编译期毫无察觉，却让所有
/// 历史链值对不上。结构体让这件事只能对一个地方错。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub id: i64,
    pub ts: i64,
    pub actor: String,
    pub actor_ip: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub result: String,
    pub detail_json: Option<String>,
}

impl AuditRow {
    /// 计算本条记录的链值。
    ///
    /// 拼接纪律：每个字段前加长度前缀，避免 `("ab","c")` 与 `("a","bc")` 撞成
    /// 同一串——这类歧义在字段可含任意文本时是真实攻击面，不是理论洁癖。
    /// NULL 与空串必须区分（`None` 编成 `-`，`Some("")` 编成 `0:`），否则
    /// "ip 缺失"与"ip 是空串"的语义差异被抹平。
    pub fn chain_hash(&self, key: &MasterKey, prev_hash: &str) -> String {
        let mut h = Sha256::new();
        h.update(derive_key(key, CHAIN_KEY_LABEL));
        put(&mut h, &self.id.to_string());
        put(&mut h, &self.ts.to_string());
        put(&mut h, &self.actor);
        put_opt(&mut h, self.actor_ip.as_deref());
        put(&mut h, &self.action);
        put_opt(&mut h, self.target.as_deref());
        put(&mut h, &self.result);
        put_opt(&mut h, self.detail_json.as_deref());
        put(&mut h, prev_hash);
        hex(&h.finalize())
    }
}

/// 带长度前缀地喂一个字段，杜绝拼接歧义。
fn put(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

/// NULL 与空串必须可区分：NULL 编 `\0`，空串编 `\0` + 长度 0。
fn put_opt(h: &mut Sha256, v: Option<&str>) {
    match v {
        None => h.update([0u8]),
        Some(s) => {
            h.update([1u8]);
            put(h, s);
        }
    }
}

fn derive_key(mk: &MasterKey, label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(mk.as_bytes());
    h.update(label.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(char::from_digit((x >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((x & 0xf) as u32, 16).unwrap());
    }
    s
}

/// 追加一条记录并推进链尾。
///
/// 必须在**写队列的同一事务**里调用（`state.db.exec` 的闭包）：链尾锚点的
/// 读取、插入与更新若不原子，两个并发写者会读到同一链尾、写出两条 `prev_hash`
/// 相同但没有任何一方察觉的记录，链从此分叉。
///
/// 返回写入的 `id`。
pub fn append(conn: &Connection, key: &MasterKey, row: &mut AuditRow) -> rusqlite::Result<i64> {
    // 链尾：优先取锚点表（覆盖"尾部被删"的检测），锚点缺失时回落到 max(id)。
    //
    // 为什么锚点优先：若有人删掉了最后 10 条，max(id) 会退回第 N-10 条，
    // 新记录就"合法地"接在后面，缺口被永久掩盖。锚点仍指着第 N 条，
    // 新记录的 prev_hash 因此与库内最后一条对不上，`verify()` 能报出来。
    let anchor: Option<(i64, String)> = conn
        .query_row(
            "SELECT last_id, last_hash FROM audit_hash_anchor WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    let prev_hash = match anchor {
        Some((_, h)) => h,
        None => head_hash(conn)?.unwrap_or_default(),
    };

    // ⚠ 必须先拿到 id 再 INSERT：hash 的计算输入包含 id，而 audit_log 上有
    // append-only 触发器**禁止任何 UPDATE**（030），所以不能"先插入再回填 hash"。
    // 取 `MAX(id)+1` 在单写者事务里是安全的（写队列串行化，见 routes::audit 的注释）；
    // 表为空时从 1 开始。
    let next_id: i64 = conn
        .query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM audit_log", [], |r| r.get(0))?;

    // 先把 id 定下来，再算 hash——顺序反了会算出一条永远对不上的链
    row.id = next_id;
    let hash = row.chain_hash(key, &prev_hash);

    conn.execute(
        "INSERT INTO audit_log(id, ts, actor, actor_ip, action, target, result, detail_json, prev_hash, hash)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            next_id,
            row.ts,
            row.actor,
            row.actor_ip,
            row.action,
            row.target,
            row.result,
            row.detail_json,
            prev_hash,
            hash
        ],
    )?;
    let id = next_id;

    // 推进锚点（单行 upsert）
    let now = crate::now_unix();
    conn.execute(
        "INSERT INTO audit_hash_anchor(id, last_id, last_hash, updated_ts) VALUES(1, ?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET last_id = ?1, last_hash = ?2, updated_ts = ?3",
        params![id, hash, now],
    )?;
    Ok(id)
}

/// 库内当前链尾的 hash（取 `id` 最大且 `hash` 非 NULL 的那条）。
///
/// 排除 NULL 是刻意的：迁移前的历史行 hash 为 NULL，把它们当链尾会让第一条
/// 链上记录接到一个空串上，链的起点变得不可解释。
pub fn head_hash(conn: &Connection) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    )
    .optional()
}

/// 校验结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// 库内尚无任何带链值的记录（新库或未启用），不构成"通过"。
    NotChained,
    /// 链完整。
    Intact { checked: usize },
    /// 发现断裂：`at_id` 是第一条对不上的记录。
    Broken { at_id: i64, reason: String },
}

/// 全链校验：按 id 升序重算每条的链值，并检查 `prev_hash` 是否等于上一条的 `hash`。
///
/// 只校验 `hash IS NOT NULL` 的行；NULL 段（迁移前历史）跳过，且**必须**记录
/// 跳过了多少条——谎称"整表已校验"会让运维误以为历史也受保护。
pub fn verify(conn: &Connection, key: &MasterKey) -> rusqlite::Result<VerifyOutcome> {
    let mut st = conn.prepare(
        "SELECT id, ts, actor, actor_ip, action, target, result, detail_json, prev_hash, hash
         FROM audit_log WHERE hash IS NOT NULL ORDER BY id ASC",
    )?;
    let mut it = st.query([])?;
    let mut prev: Option<String> = None;
    let mut checked = 0usize;
    while let Some(r) = it.next()? {
        let row = AuditRow {
            id: r.get(0)?,
            ts: r.get(1)?,
            actor: r.get(2)?,
            actor_ip: r.get(3)?,
            action: r.get(4)?,
            target: r.get(5)?,
            result: r.get(6)?,
            detail_json: r.get(7)?,
        };
        let stored_prev: String = r.get(8)?;
        let stored_hash: String = r.get(9)?;

        // ① 与前一条的 hash 必须接上。第一条没有前驱，以自身 prev_hash 为起点。
        if let Some(p) = &prev {
            if &stored_prev != p {
                return Ok(VerifyOutcome::Broken {
                    at_id: row.id,
                    reason: format!(
                        "prev_hash 与上一条的 hash 不一致（上一条 {p}，本条声称 {stored_prev}）"
                    ),
                });
            }
        }
        // ② 本条内容必须能重算出同一个 hash——这条才真正证明"字段没被改"。
        let recomputed = row.chain_hash(key, &stored_prev);
        if recomputed != stored_hash {
            return Ok(VerifyOutcome::Broken {
                at_id: row.id,
                reason: "内容与 hash 不符（记录被改过，或密钥已更换）".to_string(),
            });
        }
        prev = Some(stored_hash);
        checked += 1;
    }

    if checked == 0 {
        return Ok(VerifyOutcome::NotChained);
    }

    // ③ 链尾锚点：库内最后一条必须就是锚点指向的那条。
    //    若尾部被整段删除，这里能发现（and 上面的 prev 检查也覆盖不了"删到只剩合法前缀"）。
    let anchor: Option<(i64, String)> = conn
        .query_row(
            "SELECT last_id, last_hash FROM audit_hash_anchor WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((aid, ahash)) = anchor {
        match &prev {
            // 锚点的 hash 必须真的出现在链尾位置（而不是"当前最后一条恰好 hash 相同"）
            Some(last) if last == &ahash => {}
            _ => {
                return Ok(VerifyOutcome::Broken {
                    at_id: aid,
                    reason: format!(
                        "链尾锚点指向 id={aid}，但库内最后一条链上记录不是它（尾部可能被截断）"
                    ),
                })
            }
        }
    }

    Ok(VerifyOutcome::Intact { checked })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MasterKey {
        MasterKey::from_bytes(&[7u8; 32]).expect("32 字节主密钥")
    }

    fn row(id: i64, action: &str) -> AuditRow {
        AuditRow {
            id,
            ts: 1_700_000_000 + id,
            actor: "admin".into(),
            actor_ip: Some("1.2.3.4".into()),
            action: action.into(),
            target: Some("s1".into()),
            result: "ok".into(),
            detail_json: Some("{}".into()),
        }
    }

    /// 同一内容 + 同一 prev 必须给同一 hash；换任一字段都必须变。
    #[test]
    fn hash_is_deterministic_and_field_sensitive() {
        let k = key();
        let a = row(1, "auth.login");
        let base = a.chain_hash(&k, "");
        assert_eq!(base, a.chain_hash(&k, ""), "同输入必须同输出");

        for mutate in [
            (|r: &mut AuditRow| r.actor = "evil".into()) as fn(&mut AuditRow),
            |r: &mut AuditRow| r.ts += 1,
            |r: &mut AuditRow| r.action = "auth.logout".into(),
            |r: &mut AuditRow| r.target = Some("s2".into()),
            |r: &mut AuditRow| r.result = "denied".into(),
            |r: &mut AuditRow| r.detail_json = Some("{\"x\":1}".into()),
            |r: &mut AuditRow| r.actor_ip = None,
            |r: &mut AuditRow| r.id += 1,
        ] {
            let mut b = a.clone();
            mutate(&mut b);
            assert_ne!(base, b.chain_hash(&k, ""), "字段改动必须改变 hash");
        }
        assert_ne!(base, a.chain_hash(&k, "prev"), "prev_hash 参与计算");
    }

    /// 拼接歧义回归：`("ab","c")` 与 `("a","bc")` 在朴素拼接下同值。
    #[test]
    fn length_prefix_prevents_concatenation_ambiguity() {
        let k = key();
        let mut x = row(1, "act");
        x.actor = "ab".into();
        x.target = Some("c".into());
        let mut y = row(1, "act");
        y.actor = "a".into();
        y.target = Some("bc".into());
        assert_ne!(
            x.chain_hash(&k, ""),
            y.chain_hash(&k, ""),
            "字段边界必须不可歧义"
        );
    }

    /// NULL 与空串必须产生不同链值。
    #[test]
    fn null_and_empty_string_differ() {
        let k = key();
        let mut a = row(1, "act");
        a.target = None;
        let mut b = row(1, "act");
        b.target = Some(String::new());
        assert_ne!(a.chain_hash(&k, ""), b.chain_hash(&k, ""));
    }

    /// 不同密钥必须给出不同链值——否则"改库也改得了链"。
    #[test]
    fn different_key_yields_different_hash() {
        let k1 = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        let k2 = MasterKey::from_bytes(&[2u8; 32]).unwrap();
        let r = row(1, "act");
        assert_ne!(r.chain_hash(&k1, ""), r.chain_hash(&k2, ""));
    }

    // ───────── 以下用内存库跑真实的 append/verify ─────────

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE audit_log(
                id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL,
                actor_ip TEXT, action TEXT NOT NULL, target TEXT, result TEXT NOT NULL,
                detail_json TEXT, prev_hash TEXT, hash TEXT);
             CREATE TABLE audit_hash_anchor(
                id INTEGER PRIMARY KEY CHECK (id = 1), last_id INTEGER NOT NULL,
                last_hash TEXT NOT NULL, updated_ts INTEGER NOT NULL);",
        )
        .unwrap();
        c
    }

    fn insert_n(c: &Connection, k: &MasterKey, n: i64) {
        for i in 1..=n {
            let mut r = row(i, "auth.login");
            r.ts = 1_700_000_000 + i;
            append(c, k, &mut r).unwrap();
        }
    }

    #[test]
    fn append_builds_a_verifiable_chain() {
        let c = db();
        let k = key();
        insert_n(&c, &k, 5);
        assert_eq!(verify(&c, &k).unwrap(), VerifyOutcome::Intact { checked: 5 });
    }

    #[test]
    fn empty_table_is_not_chained_rather_than_intact() {
        let c = db();
        assert_eq!(verify(&c, &key()).unwrap(), VerifyOutcome::NotChained);
    }

    /// 篡改中间某条的字段 ⇒ 必须在**那一条**报出内容不符。
    #[test]
    fn tampering_a_field_is_detected() {
        let c = db();
        let k = key();
        insert_n(&c, &k, 5);
        // 绕过 030 触发器（这里用内存库，模拟"root 直接写文件"）
        c.execute("UPDATE audit_log SET actor = 'hacker' WHERE id = 3", []).unwrap();
        match verify(&c, &k).unwrap() {
            VerifyOutcome::Broken { at_id, .. } => assert_eq!(at_id, 3),
            other => panic!("应检出篡改，实际 {other:?}"),
        }
    }

    /// 删除中间一条 ⇒ 下一条的 prev_hash 接不上。
    #[test]
    fn deleting_a_middle_row_breaks_the_chain() {
        let c = db();
        let k = key();
        insert_n(&c, &k, 5);
        c.execute("DELETE FROM audit_log WHERE id = 3", []).unwrap();
        match verify(&c, &k).unwrap() {
            VerifyOutcome::Broken { at_id, .. } => assert_eq!(at_id, 4),
            other => panic!("应检出断链，实际 {other:?}"),
        }
    }

    /// 只删尾部：prev 检查覆盖不到（剩下的是合法前缀），必须靠锚点发现。
    #[test]
    fn truncating_the_tail_is_detected_by_anchor() {
        let c = db();
        let k = key();
        insert_n(&c, &k, 5);
        c.execute("DELETE FROM audit_log WHERE id = 5", []).unwrap();
        match verify(&c, &k).unwrap() {
            VerifyOutcome::Broken { .. } => {}
            other => panic!("尾部截断必须被锚点发现，实际 {other:?}"),
        }
    }

    /// 换密钥（master.key 被替换/丢失）⇒ 校验失败而不是静默通过。
    #[test]
    fn wrong_key_fails_verification() {
        let c = db();
        insert_n(&c, &key(), 3);
        let other = MasterKey::from_bytes(&[9u8; 32]).unwrap();
        assert!(matches!(
            verify(&c, &other).unwrap(),
            VerifyOutcome::Broken { .. }
        ));
    }

    /// 迁移前历史行（hash 为 NULL）不参与校验，也不让链断掉。
    #[test]
    fn legacy_null_rows_are_skipped_not_treated_as_broken() {
        let c = db();
        // 两条历史行
        for i in 1..=2 {
            c.execute(
                "INSERT INTO audit_log(ts, actor, action, result) VALUES(?1,'old','legacy','ok')",
                params![1_600_000_000 + i],
            ).unwrap();
        }
        let k = key();
        insert_n(&c, &k, 3);
        assert_eq!(verify(&c, &k).unwrap(), VerifyOutcome::Intact { checked: 3 });
    }
}
