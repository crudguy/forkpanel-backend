//! 会话、口令、防暴力、RBAC、CSRF（设计方案 §1.3）。

use crate::error::{ApiError, ApiResult};
use panel_core::{PanelError, Result, Tier};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

// ═══════════════════════════ 口令 ═══════════════════════════

/// argon2id 参数（设计方案 §1.3）。
/// nano 档位降到 8MiB：实测登录时瞬时占用即为该值，512MB 机器上需保守。
pub struct HashParams { pub m_cost: u32, pub t_cost: u32, pub p_cost: u32 }

impl HashParams {
    pub fn for_tier(t: Tier) -> Self {
        match t {
            Tier::Nano => Self { m_cost: 8 * 1024, t_cost: 2, p_cost: 1 },
            Tier::Small => Self { m_cost: 16 * 1024, t_cost: 2, p_cost: 1 },
            Tier::Standard => Self { m_cost: 19 * 1024, t_cost: 2, p_cost: 1 },
        }
    }
}

pub fn hash_password(pwd: &str, p: &HashParams) -> Result<String> {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(p.m_cost, p.t_cost, p.p_cost, None)
            .map_err(|e| PanelError::Internal(format!("argon2 params: {e}")))?,
    );
    argon2.hash_password(pwd.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PanelError::Internal(format!("hash: {e}")))
}

pub fn verify_password(pwd: &str, hash: &str) -> Result<bool> {
    use argon2::{Argon2, PasswordVerifier, PasswordHash};
    let parsed = PasswordHash::new(hash)
        .map_err(|e| PanelError::Internal(format!("bad hash: {e}")))?;
    // 这里刻意不做时序恒等比较：argon2 内部的验证已足够，且验证本身耗时远大于差异
    Ok(Argon2::default().verify_password(pwd.as_bytes(), &parsed).is_ok())
}

/// 弱口令策略：最小长度 10 + 常见弱口令黑名单。
/// 说明：完整字典检查会把字典带进二进制（体积成本），故只做最小集 + 长度 + 字符多样性。
pub fn check_password_policy(pwd: &str) -> Result<()> {
    if pwd.len() < 10 {
        return Err(PanelError::Validation { field: "password", reason: "min length is 10".into() });
    }
    if pwd.len() > 256 {
        return Err(PanelError::Validation { field: "password", reason: "too long".into() });
    }
    let lower = pwd.to_lowercase();
    const WEAK: &[&str] = &["password", "123456789", "qwertyuiop", "admin1234", "iloveyou", "letmein"];
    if WEAK.iter().any(|w| lower.contains(w)) {
        return Err(PanelError::Validation { field: "password", reason: "too common".into() });
    }
    let classes = (pwd.chars().any(|c| c.is_ascii_lowercase()) as u8)
        + (pwd.chars().any(|c| c.is_ascii_uppercase()) as u8)
        + (pwd.chars().any(|c| c.is_ascii_digit()) as u8)
        + (pwd.chars().any(|c| !c.is_ascii_alphanumeric()) as u8);
    if classes < 2 {
        return Err(PanelError::Validation { field: "password", reason: "needs 2 character classes".into() });
    }
    Ok(())
}

// ═══════════════════════════ 引导令牌 ═══════════════════════════

/// 一次性引导令牌（128-bit 随机 → 32 位 hex）。
/// serve 首启发现数据库无 owner 时生成并打印到终端，用户在 Web 首启向导提交。
pub fn generate_bootstrap_token() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}

/// 内存中的一次性引导令牌守卫。
///
/// 安全模型：能创建 owner 的前提 = 看过 serve 首启的终端输出（与 CLI init 等价），
/// 不开放常驻注册接口，避免给同机任意本地进程留后门。
/// - 只存 sha256 哈希（对齐 `SessionCache` 只存 sid 哈希的纪律）
/// - 常数时间比较，防时序侧信道
/// - 正确即焚；错误候选**不**消耗令牌（128-bit 枚举不可行，无需失败计数）
/// - 只存内存：重启即重新生成，不落库
pub struct BootstrapGuard {
    inner: Mutex<Option<BootstrapSecret>>,
}

#[derive(Clone)]
struct BootstrapSecret {
    hash: String,
    expires_at: Instant,
}

impl BootstrapGuard {
    pub fn new() -> Self { Self { inner: Mutex::new(None) } }

    /// 设置（或替换）令牌。每次 serve 启动若仍无 owner 则重新生成，旧令牌作废。
    pub fn set(&self, token: &str, ttl: Duration) {
        let s = BootstrapSecret { hash: sid_hash(token), expires_at: Instant::now() + ttl };
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(s);
    }

    /// 校验并消费。正确且未过期 → 立即作废并返回 true。
    pub fn take_if_valid(&self, candidate: &str) -> bool {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let valid = match m.as_ref() {
            Some(s) => {
                s.expires_at > Instant::now()
                    && constant_time_eq(s.hash.as_bytes(), sid_hash(candidate).as_bytes())
            }
            None => false,
        };
        if valid { *m = None; }
        valid
    }

    /// 令牌是否仍有效（status 接口用于提示"令牌已过期，重启 serve 重新生成"）。
    pub fn active(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
            .map(|s| s.expires_at > Instant::now())
            .unwrap_or(false)
    }
}

impl Default for BootstrapGuard { fn default() -> Self { Self::new() } }

/// 用户名校验（owner 与后续 M5 用户管理共用）：去首尾空白后 1..=64 字节。
/// 返回归一化后的用户名。
pub fn validate_username(name: &str) -> Result<String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 64 {
        return Err(PanelError::Validation {
            field: "username", reason: "length must be 1..=64".into(),
        });
    }
    Ok(n.to_string())
}

// ═══════════════════════════ 会话 ═══════════════════════════

/// 会话只存 sid 的哈希：数据库泄露也不能直接劫持会话
#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
    /// 目录作用域：文件与站点操作被限制在这些根内
    pub allowed_roots: Vec<String>,
    /// 登录时的客户端 IP，写入审计日志的 `actor_ip`。
    ///
    /// 只在登录那一刻采集：审计要回答"这次危险操作从哪来"，而请求中途
    /// 的 HeaderMap 拿不到（`audit()` 只收 Session）。从库里重建会话
    /// （进程重启后）无法还原，置 `unknown` 而非留空——空值会被前端
    /// 渲染成"—"，看起来像"没记录"，实际是"记不了"，两者要能区分。
    pub ip: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub expires_at: i64,
}

pub fn generate_sid() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}

pub fn sid_hash(sid: &str) -> String { hex(&Sha256::digest(sid.as_bytes())) }

fn hex(b: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b { s.push(T[(x >> 4) as usize] as char); s.push(T[(x & 0xf) as usize] as char); }
    s
}

/// 内存会话缓存（避免每请求查库）。DB 是持久化真相，重启后可从库恢复。
pub struct SessionCache {
    inner: Mutex<HashMap<String, Session>>,
    idle_timeout: Duration,
    absolute_timeout: Duration,
    /// 持久化后端：会话落 `sessions` 表（该表 001 即已定义，**此前无人使用**）。
    /// 有它 → 面板重启后会话仍在（不再全员登出）；`None` → 纯内存（测试/无 DB）。
    db: Option<std::sync::Arc<panel_db::WriterActor>>,
}

impl SessionCache {
    /// 纯内存（无持久化）。测试与无 DB 场景使用。
    pub fn new(idle: Duration, absolute: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            idle_timeout: idle,
            absolute_timeout: absolute,
            db: None,
        }
    }

    /// 带持久化：变更同步到 `sessions` 表，启动时可用 [`Self::restore_from_db`] 恢复。
    pub fn new_with_db(
        idle: Duration,
        absolute: Duration,
        db: std::sync::Arc<panel_db::WriterActor>,
    ) -> Self {
        Self { inner: Mutex::new(HashMap::new()), idle_timeout: idle, absolute_timeout: absolute, db: Some(db) }
    }

    /// 把 DB 写入丢给 runtime：**绝不持 MutexGuard 跨 await**（本 crate 已踩过两次）。
    /// 无 runtime（如单测/启动早期）时静默降级为纯内存。
    fn sync_db<F>(&self, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(fut);
        }
    }

    pub fn get(&self, sid: &str) -> Option<Session> {
        let now = now_unix();
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match m.get_mut(sid) {
            Some(s) if s.expires_at > now && now - s.created_at < self.absolute_timeout.as_secs() as i64 => {
                s.last_seen = now;
                s.expires_at = now + self.idle_timeout.as_secs() as i64;
                Some(s.clone())
            }
            Some(_) => { m.remove(sid); None }
            None => None,
        }
    }

    pub fn insert(&self, sid: String, s: Session) {
        let mut s = s;
        let now = now_unix();
        s.created_at = now; s.last_seen = now;
        s.expires_at = now + self.idle_timeout.as_secs() as i64;
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(sid.clone(), s.clone());

        if let Some(db) = self.db.clone() {
            let h = sid_hash(&sid);
            let uid = s.user_id;
            let exp = s.expires_at;
            self.sync_db(async move {
                let _ = db
                    .exec(move |conn| {
                        conn.execute(
                            "INSERT OR REPLACE INTO sessions\
                             (sid_hash, user_id, ip, ua, created_at, last_seen_at, expires_at) \
                             VALUES(?1, ?2, NULL, NULL, ?3, ?3, ?4)",
                            rusqlite::params![h, uid, now, exp],
                        )
                        .map(|_| panel_db::WriteAck { rows_changed: 1 })
                        .map_err(|e| PanelError::Database(e.to_string()))
                    })
                    .await;
            });
        }
    }

    /// 登录成功后轮换 sid（防会话固定）。
    /// 走 `self.remove` 而非直接摘 map —— 让旧 sid 的库记录一并删除。
    pub fn rotate(&self, old: &str) -> Option<(String, Session)> {
        let s = { self.inner.lock().unwrap_or_else(|e| e.into_inner()).get(old).cloned() }?;
        self.remove(old);
        let new = generate_sid();
        self.insert(new.clone(), s.clone());
        Some((new, s))
    }

    /// 吊销指定会话。返回是否存在（供「吊销不存在的会话」→ 404 判定）。
    pub fn remove(&self, sid: &str) -> bool {
        let existed = self.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(sid).is_some();
        if existed {
            if let Some(db) = self.db.clone() {
                let h = sid_hash(sid);
                self.sync_db(async move {
                    let _ = db
                        .exec(move |conn| {
                            conn.execute("DELETE FROM sessions WHERE sid_hash = ?1", [h])
                                .map(|_| panel_db::WriteAck { rows_changed: 1 })
                                .map_err(|e| PanelError::Database(e.to_string()))
                        })
                        .await;
                });
            }
        }
        existed
    }

    /// 在线会话快照（管理员视图）：sid → Session。锁内克隆，绝不外借引用。
    pub fn list(&self) -> Vec<(String, Session)> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(k, s)| (k.clone(), s.clone()))
            .collect()
    }

    /// 按用户 id 清除其所有会话（禁用/删除用户时立即踢下线）
    pub fn remove_by_user(&self, uid: i64) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, s| s.user_id != uid);
        if let Some(db) = self.db.clone() {
            self.sync_db(async move {
                let _ = db
                    .exec(move |conn| {
                        conn.execute("DELETE FROM sessions WHERE user_id = ?1", [uid])
                            .map(|_| panel_db::WriteAck { rows_changed: 1 })
                            .map_err(|e| PanelError::Database(e.to_string()))
                    })
                    .await;
            });
        }
    }

    /// 按用户清除其**除 keep_sid 外**的全部会话（改密强制其他端下线，当前端不踢）。
    /// 返回清除的会话数。
    pub fn remove_by_user_except(&self, uid: i64, keep_sid: &str) -> usize {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = m.len();
        m.retain(|sid, s| s.user_id != uid || sid == keep_sid);
        let n = before - m.len();
        drop(m); // 先放锁，再派发 DB 写入
        if n > 0 {
            if let Some(db) = self.db.clone() {
                let keep = sid_hash(keep_sid);
                self.sync_db(async move {
                    let _ = db
                        .exec(move |conn| {
                            conn.execute(
                                "DELETE FROM sessions WHERE user_id = ?1 AND sid_hash <> ?2",
                                rusqlite::params![uid, keep],
                            )
                            .map(|_| panel_db::WriteAck { rows_changed: 1 })
                            .map_err(|e| PanelError::Database(e.to_string()))
                        })
                        .await;
                });
            }
        }
        n
    }

    /// 定时清理过期会话（合并进统一调度器，避免独立定时器）
    pub fn sweep(&self) -> usize {
        let now = now_unix();
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = m.len();
        m.retain(|_, s| s.expires_at > now);
        let n = before - m.len();
        drop(m);
        if let Some(db) = self.db.clone() {
            self.sync_db(async move {
                let _ = db
                    .exec(move |conn| {
                        conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])
                            .map(|_| panel_db::WriteAck { rows_changed: 1 })
                            .map_err(|e| PanelError::Database(e.to_string()))
                    })
                    .await;
            });
        }
        n
    }

    /// 先查内存；未命中则按 `sid_hash` 查库并**惰性重建**（面板重启后会话仍有效）。
    ///
    /// 库里只有哈希，无法还原 sid 本身——只能"验证并重建"，这正好守住
    /// 「凭据不落库」纪律：库泄露也拿不到可直接使用的 sid。
    /// 用户资料以**当前 `users` 表**为准：重启期间若被改权/禁用，恢复后即生效。
    pub async fn get_or_restore(&self, sid: &str, pool: &crate::ReadPool) -> Option<Session> {
        if let Some(s) = self.get(sid) {
            return Some(s);
        }
        if self.db.is_none() {
            return None;
        }
        let h = sid_hash(sid);
        let now = now_unix();
        // 注：`.ok().flatten()?` 已解包 Option，故类型注解是**元组**本身
        let row: (i64, String, String, String, i64, i64) = pool
            .with(move |conn| {
                let mut st = conn
                    .prepare(
                        "SELECT s.user_id, u.username, u.role, u.allowed_roots, s.created_at, s.expires_at \
                         FROM sessions s JOIN users u ON u.id = s.user_id \
                         WHERE s.sid_hash = ?1 AND s.expires_at > ?2 AND u.disabled = 0",
                    )
                    .map_err(|e| PanelError::Database(e.to_string()))?;
                let mut it = st
                    .query_map(rusqlite::params![h, now], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, i64>(4)?,
                            r.get::<_, i64>(5)?,
                        ))
                    })
                    .map_err(|e| PanelError::Database(e.to_string()))?;
                Ok(it.next().transpose().map_err(|e| PanelError::Database(e.to_string()))?)
            })
            .await
            .ok()
            .flatten()?;

        let (user_id, username, role, roots_json, created_at, expires_at) = row;
        let allowed_roots: Vec<String> = serde_json::from_str(&roots_json).unwrap_or_default();
        let s = Session {
            user_id,
            username,
            permissions: permissions_for_role(&role),
            role,
            allowed_roots,
            // 库不存 IP：进程重启后重建的会话丢失来源，诚实标 unknown
            ip: "unknown".into(),
            created_at,
            last_seen: now,
            expires_at,
        };
        // 直接放回内存走后续快路径；**不用 insert**——那会重置到期时间并重复写库
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sid.to_string(), s.clone());
        Some(s)
    }
}

// ═══════════════════════════ 防暴力 ═══════════════════════════

/// 滑动窗口失败计数 + 指数退避 + 锁定（设计方案 §1.3）。
///
/// ⚠ `attempts` 必须有**键数硬上限**：key 只在登录成功时被 `reset` 移除，若不做淘汰，
/// 未授权请求刷不同用户名即可让这张表无限增长（面板以 root 运行，OOM = 整体不可用）。
/// 上限与淘汰逻辑见 [`LoginGuard::record_failure`]。
pub struct LoginGuard {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    max_attempts: usize,
    lock_after: usize,
    lock_duration: Duration,
    /// 失败 key 数硬上限（`MAX_KEYS`）
    max_keys: usize,
}

/// 失败 key 数硬上限。单 key 在 15 分钟窗口内最多留 15 条记录，1 万个 key 足以覆盖
/// 真实多用户场景（含共享 NAT 出口造成的少量误判），内存占用在 MB 级。
const MAX_KEYS: usize = 10_000;

impl LoginGuard {
    pub fn new(max_attempts: usize) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            lock_after: 15,
            lock_duration: Duration::from_secs(900),
            max_keys: MAX_KEYS,
        }
    }

    /// 返回 None 表示允许尝试；Some(secs) 表示需等待。
    ///
    /// ⚠ **只读，绝不插入**：这里曾经用 `entry(key).or_default()`，任何一次登录尝试
    /// （包括随机编造的用户名）都会在 map 里留下一个 key，而 key 只在登录成功时才被
    /// `reset` 移除 ⇒ 未授权请求就能把 map 撑到 OOM。现在没有记录就直接放行，插入
    /// 只发生在 [`Self::record_failure`]。
    ///
    /// ⚠ **被本函数拦下的尝试同样计入 `attempts`**（P2-11，2026-10-20 决定；计数由
    /// 调用方在 `routes/auth.rs` 的 429 分支里 `record_failure`）。这条改过，历史动因
    /// 值得留档——它决定了防暴力的**实际强度**：
    ///
    /// 旧行为（闸门不计数）：快速连点会冻结在 `max_attempts`，每次都拿
    /// `retry_after=1` 的 429 ⇒ 实际只有「1 次/秒」的软限速，**永远到不了
    /// `lock_after` 的 15 分钟锁定**；真机压测实测攻击者保持 1 req/s 可在 2 小时内
    /// 试约 7200 个口令。而面板以 root 运行，弱口令场景下这个速率偏危险。
    ///
    /// 现行为（闸门也计数），用真实 `LoginGuard` 实测：
    /// - 攻击者连点：第 **11** 次即进 15 分钟锁定，2 小时内最多 10 次有效尝试；
    /// - 正常用户手快连错：第 **16** 次被锁 15 分钟。
    /// 退避仍按 1→2→4→…→64s 递增，只是不再「卡死在下界」。
    ///
    /// 行为由 `blocked_attempts_still_advance_the_counter` 钉住（旧的反向断言
    /// `blocked_attempts_do_not_advance_the_counter` 已随之改写——若它还在且为绿，
    /// 说明计数没接上）。
    pub fn check(&self, key: &str) -> Option<u64> {
        let mut m = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let Some(v) = m.get_mut(key) else { return None };
        // 只保留 15 分钟窗口内的记录
        v.retain(|t| now.duration_since(*t) < Duration::from_secs(900));
        if v.is_empty() {
            // 顺手回收：窗口滑过后这条 key 已无意义，不该永久占位
            m.remove(key);
            return None;
        }
        let n = v.len();
        if n >= self.lock_after {
            // 锁定期从**进入锁定的那一刻**算起，而不是「最后一条失败」。
            //
            // ⚠ 这里踩过一个真实坑（P2-11 启用「429 也计数」后才暴露）：原实现取
            // `v.last()` 当基准，而锁定期内被拦下的请求现在也会写一条新记录 ⇒ 基准
            // 被不断推后 ⇒ `retry_after` 永远接近满额、**锁定被无限续期**。
            // 后果是攻击者持续发请求即可让某个账号**永久无法登录**（拒绝服务），
            // 比「锁 15 分钟」严重得多。真机实测：锁定后每 2 秒打一次，
            // retry_after 稳定停在 898 而不再递减。
            //
            // 正确基准是 `v[lock_after - 1]`：窗口内第 lock_after 条失败的时刻，
            // 即「跨过阈值的那一次」。之后无论再来多少次，到期时间都不再移动。
            let locked_at = v.get(self.lock_after - 1).copied().unwrap_or(now);
            let elapsed = now.duration_since(locked_at).as_secs();
            return Some(self.lock_duration.as_secs().saturating_sub(elapsed));
        } else if n >= self.max_attempts {
            // 指数退避：2^(n - max_attempts) 秒
            let backoff = 1u64 << (n - self.max_attempts).min(6);
            let last = v.last().copied().unwrap_or(now);
            let elapsed = now.duration_since(last).as_secs();
            if elapsed < backoff { return Some(backoff - elapsed); }
        }
        None
    }

    /// 记录一次失败。到达 `max_keys` 时淘汰**最久没有活动**的 key（按该 key 最后一
    /// 条记录的时间取最早者）——宁可错杀一个陈旧 key，也不能让表无限增长。
    pub fn record_failure(&self, key: &str) {
        let mut m = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        if !m.contains_key(key) && m.len() >= self.max_keys {
            let oldest = m
                .iter()
                .min_by_key(|(_, v)| v.last().copied().unwrap_or_else(Instant::now))
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest { m.remove(&k); }
        }
        m.entry(key.to_string()).or_default().push(Instant::now());
    }

    #[cfg(test)]
    pub(crate) fn key_count(&self) -> usize {
        self.attempts.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    #[cfg(test)]
    pub(crate) fn with_max_keys_for_test(n: usize) -> Self {
        Self { max_keys: n, ..Self::new(5) }
    }

    pub fn reset(&self, key: &str) {
        self.attempts.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
    }

    /// 当前生效的最大登录尝试次数（来自 config.toml `[security] max_login_attempts`）。
    /// 曾硬编码 5，配置项形同虚设——与 `session_*` 同一类"假控制"，现已由 `AppState`
    /// 从配置注入。设置页 deployment 段展示此值，证明它是真接线而非死数据。
    pub fn max_attempts(&self) -> usize { self.max_attempts }
}

impl Default for LoginGuard { fn default() -> Self { Self::new(5) } }

// ═══════════════════════════ RBAC ═══════════════════════════

/// 权限点常量。handler 用 `require!(session, SITE_MANAGE)` 声明所需权限。
pub mod perm {
    pub const SYSTEM_VIEW: &str     = "system.view";
    pub const SYSTEM_MANAGE: &str   = "system.manage";
    pub const SERVICE_VIEW: &str    = "service.view";
    pub const SERVICE_MANAGE: &str  = "service.manage";
    pub const PACKAGE_MANAGE: &str  = "package.manage";
    pub const SITE_VIEW: &str       = "site.view";
    pub const SITE_MANAGE: &str     = "site.manage";
    pub const SSL_MANAGE: &str      = "ssl.manage";
    pub const FILE_READ: &str       = "file.read";
    pub const FILE_WRITE: &str      = "file.write";
    pub const DB_VIEW: &str         = "db.view";
    pub const DB_MANAGE: &str       = "db.manage";
    pub const FIREWALL_VIEW: &str   = "firewall.view";
    pub const FIREWALL_MANAGE: &str = "firewall.manage";
    pub const SECURITY_MANAGE: &str = "security.manage";
    pub const CRON_VIEW: &str       = "cron.view";
    pub const CRON_MANAGE: &str     = "cron.manage";
    pub const LOG_VIEW: &str        = "log.view";
    pub const TASK_VIEW: &str       = "task.view";
    pub const TASK_MANAGE: &str      = "task.manage";
    pub const BACKUP_VIEW: &str     = "backup.view";
    pub const BACKUP_MANAGE: &str   = "backup.manage";
    pub const CONTAINER_VIEW: &str  = "container.view";
    pub const CONTAINER_MANAGE: &str= "container.manage";
    pub const USER_MANAGE: &str     = "user.manage";
    pub const SETTINGS_MANAGE: &str = "settings.manage";
    pub const AUDIT_VIEW: &str      = "audit.view";
}

/// 内置角色名。**保留字**：自定义角色不得占用——同名两套权限定义是最难排查的 bug。
pub const BUILTIN_ROLES: &[&str] = &["owner", "admin", "operator", "viewer"];

/// 全部已知权限名。用于校验自定义角色的权限集合"确实有意义"。
///
/// **必须与 [`perm`] 模块保持同步**：新增权限常量时这里也要加，否则新权限
/// 无法授予任何自定义角色。有一条单测钉住两者数量一致。
pub fn all_permissions() -> Vec<&'static str> {
    use perm::*;
    vec![
        SYSTEM_VIEW, SYSTEM_MANAGE, SERVICE_VIEW, SERVICE_MANAGE, PACKAGE_MANAGE,
        SITE_VIEW, SITE_MANAGE, SSL_MANAGE, FILE_READ, FILE_WRITE,
        DB_VIEW, DB_MANAGE, FIREWALL_VIEW, FIREWALL_MANAGE, SECURITY_MANAGE,
        CRON_VIEW, CRON_MANAGE, LOG_VIEW, TASK_VIEW, TASK_MANAGE, BACKUP_VIEW, BACKUP_MANAGE,
        CONTAINER_VIEW, CONTAINER_MANAGE, USER_MANAGE, SETTINGS_MANAGE, AUDIT_VIEW,
    ]
}

/// 解析角色的权限集合：**先查自定义角色表，未命中回退内置**。
///
/// 失败路径刻意选择"回退内置"而不是"返回空权限"：后者会让所有内置角色的用户
/// 在一次 DB 抖动中**集体被锁在门外**。内置定义是代码里的常量，永远可得。
pub async fn permissions_for_role_resolved(state: &crate::AppState, role: &str) -> Vec<String> {
    let role_owned = role.to_string();
    let from_db = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT permissions FROM roles WHERE name = ?1")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let mut it = st
                .query_map([role_owned], |r| r.get::<_, String>(0))
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let row: Option<String> = it
                .next()
                .transpose()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(row)
        })
        .await;
    match from_db {
        // 命中自定义角色：用它的权限集合
        Ok(Some(json_str)) => match serde_json::from_str::<Vec<String>>(&json_str) {
            Ok(v) => v,
            // JSON 损坏：不静默给空（等于锁死），也不放行——回退内置并把问题暴露出来
            Err(e) => {
                eprintln!("[panel] 角色 {role} 的权限 JSON 损坏，已回退内置定义: {e}");
                permissions_for_role(role)
            }
        },
        Ok(None) => permissions_for_role(role),
        Err(e) => {
            eprintln!("[panel] 解析角色 {role} 权限失败，已回退内置定义: {e}");
            permissions_for_role(role)
        }
    }
}

/// 角色 → 权限集合。**默认拒绝**：未列出的权限一律不允许。
pub fn permissions_for_role(role: &str) -> Vec<String> {
    use perm::*;
    let view_only = vec![SYSTEM_VIEW, SERVICE_VIEW, SITE_VIEW, FILE_READ, DB_VIEW,
                         FIREWALL_VIEW, CRON_VIEW, LOG_VIEW, TASK_VIEW, BACKUP_VIEW,
                         CONTAINER_VIEW, AUDIT_VIEW];
    match role {
        "owner" | "admin" => {
            let mut v = view_only.clone();
            v.extend([SYSTEM_MANAGE, SERVICE_MANAGE, PACKAGE_MANAGE, SITE_MANAGE, SSL_MANAGE,
                      FILE_WRITE, DB_MANAGE, FIREWALL_MANAGE, SECURITY_MANAGE, CRON_MANAGE,
                      TASK_MANAGE, BACKUP_MANAGE, CONTAINER_MANAGE, SETTINGS_MANAGE, USER_MANAGE]);
            v
        }
        "operator" => {
            let mut v = view_only.clone();
            v.extend([SERVICE_MANAGE, SITE_MANAGE, SSL_MANAGE, CRON_MANAGE, TASK_MANAGE, BACKUP_MANAGE,
                      CONTAINER_MANAGE, FILE_WRITE]);
            v
        }
        "viewer" => view_only,
        _ => vec![],   // 未知角色 = 零权限（默认拒绝，不给意外放行）
    }
    .into_iter().map(String::from).collect()
}

/// 权限断言。**每个写 handler 都必须显式调用。**
pub fn require(session: &Session, p: &str) -> ApiResult<()> {
    if session.permissions.iter().any(|x| x == p) { Ok(()) }
    else { Err(ApiError::forbidden(leak_static(p))) }
}

// 权限点都是 &'static str 常量；这里只在错误路径上做一次静态回退，避免生命周期扩散
fn leak_static(p: &str) -> &'static str {
    use perm::*;
    for c in [SYSTEM_VIEW, SYSTEM_MANAGE, SERVICE_VIEW, SERVICE_MANAGE, PACKAGE_MANAGE,
              SITE_VIEW, SITE_MANAGE, SSL_MANAGE, FILE_READ, FILE_WRITE, DB_VIEW, DB_MANAGE,
              FIREWALL_VIEW, FIREWALL_MANAGE, SECURITY_MANAGE, CRON_VIEW, CRON_MANAGE,
              LOG_VIEW, TASK_VIEW, TASK_MANAGE, BACKUP_VIEW, BACKUP_MANAGE, USER_MANAGE, SETTINGS_MANAGE, AUDIT_VIEW] {
        if c == p { return c; }
    }
    "unknown"
}

// ═══════════════════════════ CSRF ═══════════════════════════

/// 双提交 token 校验：Cookie 中的可读 token 必须与请求头一致。
/// 配合 `SameSite=Strict` 与 Origin 白名单。
pub fn csrf_ok(cookie_token: Option<&str>, header_token: Option<&str>) -> bool {
    match (cookie_token, header_token) {
        (Some(a), Some(b)) if !a.is_empty() && a.len() == b.len() => constant_time_eq(a.as_bytes(), b.as_bytes()),
        _ => false,
    }
}

/// 时序恒等比较（CSRF token 属于秘密，必须防时序侧信道）
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { acc |= x ^ y; }
    acc == 0
}

pub fn generate_csrf_token() -> String {
    let mut b = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_permissions_stays_in_sync_with_perm_module() {
        // all_permissions 是自定义角色的权限白名单。漏掉一个权限常量，
        // 就意味着该权限**永远无法授予任何自定义角色**——而且不会报错，
        // 只会在用户创建角色时"这个权限怎么选不到"。故钉住数量与无重复。
        let all = all_permissions();
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "all_permissions 存在重复项");
        assert_eq!(all.len(), 27, "权限常量增减时请同步 all_permissions 与其数量断言");

        // 内置角色用到的权限必须都在白名单内，否则自定义角色会出现
        // "内置能用、自定义选不到"的不一致
        for r in BUILTIN_ROLES {
            for p in permissions_for_role(r) {
                assert!(all.contains(&p.as_str()), "内置角色 {r} 使用了白名单外的权限: {p}");
            }
        }
    }

    #[test]
    fn unknown_role_is_deny_by_default() {
        // 默认拒绝：不认识的角色（含被删除的自定义角色）拿到零权限，
        // 而不是意外继承某个内置角色的权限
        assert!(permissions_for_role("no-such-role").is_empty());
        assert!(permissions_for_role("").is_empty());
    }

    #[test]
    fn weak_passwords_rejected() {
        assert!(check_password_policy("short1!A").is_err());
        assert!(check_password_policy("password12345").is_err());
        assert!(check_password_policy("aaaaaaaaaaaa").is_err(), "单一字符类应拒绝");
        assert!(check_password_policy("Tr0ub4dor&3xy").is_ok());
    }

    #[test]
    fn password_roundtrip() {
        let p = HashParams::for_tier(Tier::Nano);
        let h = hash_password("Tr0ub4dor&3xy", &p).unwrap();
        assert!(verify_password("Tr0ub4dor&3xy", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn nano_uses_smaller_argon2() {
        assert_eq!(HashParams::for_tier(Tier::Nano).m_cost, 8 * 1024);
        assert_eq!(HashParams::for_tier(Tier::Standard).m_cost, 19 * 1024);
    }

    #[test]
    fn session_expiry_and_rotation() {
        let c = SessionCache::new(Duration::from_secs(1), Duration::from_secs(3600));
        let s = Session { user_id: 1, username: "a".into(), role: "admin".into(),
                          permissions: vec![], allowed_roots: vec![], ip: "unknown".into(),
                          created_at: 0, last_seen: 0, expires_at: 0 };
        let sid = generate_sid();
        c.insert(sid.clone(), s);
        assert!(c.get(&sid).is_some());
        let (new, _) = c.rotate(&sid).unwrap();
        assert_ne!(new, sid);
        assert!(c.get(&sid).is_none(), "旧 sid 必须立即失效");
        c.remove(&new);
        assert!(c.get(&new).is_none());
    }

    #[test]
    fn unknown_role_gets_zero_permissions() {
        assert!(permissions_for_role("nobody").is_empty());
        assert!(permissions_for_role("").is_empty());
    }

    #[test]
    fn viewer_cannot_manage() {
        let v = permissions_for_role("viewer");
        assert!(v.iter().any(|p| p == "system.view"));
        assert!(!v.iter().any(|p| p == "site.manage"));
        assert!(!v.iter().any(|p| p == "firewall.manage"));
    }

    #[test]
    fn login_guard_locks_after_threshold() {
        let g = LoginGuard::new(5);
        for i in 0..15 { g.record_failure("1.2.3.4"); let _ = i; }
        assert!(g.check("1.2.3.4").is_some(), "15 次后应锁定");
        g.reset("1.2.3.4");
        assert!(g.check("1.2.3.4").is_none());
    }

    #[test]
    fn csrf_is_constant_time_and_strict() {
        let t = generate_csrf_token();
        assert!(csrf_ok(Some(&t), Some(&t)));
        assert!(!csrf_ok(Some(&t), Some("x")));
        assert!(!csrf_ok(None, Some(&t)));
        assert!(!csrf_ok(Some(""), Some("")));
    }

    #[test]
    fn bootstrap_token_is_hex_and_unique() {
        let a = generate_bootstrap_token();
        let b = generate_bootstrap_token();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn bootstrap_token_one_shot_wrong_candidate_keeps_token() {
        let g = BootstrapGuard::new();
        assert!(!g.active(), "未设置前必须无效");
        g.set("abcd1234", Duration::from_secs(60));
        assert!(g.active());
        assert!(!g.take_if_valid("wrong-wrong-wrong"));
        assert!(g.active(), "错误候选不应消耗令牌（128-bit 枚举不可行）");
        assert!(g.take_if_valid("abcd1234"), "正确令牌应通过");
        assert!(!g.active(), "用后即焚");
        assert!(!g.take_if_valid("abcd1234"), "二次使用必须失败");
        assert!(!g.take_if_valid(""), "空候选必须失败");
    }

    #[test]
    fn bootstrap_token_expires() {
        let g = BootstrapGuard::new();
        g.set("abcd1234", Duration::ZERO);
        assert!(!g.active(), "ttl=0 即立即过期");
        assert!(!g.take_if_valid("abcd1234"), "过期令牌必须拒绝");
    }

    #[test]
    fn bootstrap_token_replaced_by_latest() {
        let g = BootstrapGuard::new();
        g.set("aaaa", Duration::from_secs(60));
        g.set("bbbb", Duration::from_secs(60));
        assert!(!g.take_if_valid("aaaa"), "重复 set 应作废旧令牌");
        assert!(g.take_if_valid("bbbb"));
    }

    #[test]
    fn username_validation_bounds() {
        assert_eq!(validate_username("  admin ").unwrap(), "admin");
        assert!(validate_username("").is_err());
        assert!(validate_username("   ").is_err());
        assert!(validate_username(&"x".repeat(65)).is_err());
        assert!(validate_username(&"x".repeat(64)).is_ok());
    }

    // ── LoginGuard：key 无界增长曾是 P0，下面几条把它钉死 ──

    #[test]
    fn check_must_not_insert_key() {
        let g = LoginGuard::new(5);
        // 只读的 check 绝不能留下 key：否则未授权请求刷不同用户名即可把 map 撑到 OOM
        assert!(g.check("10.0.0.1:ghost").is_none());
        assert_eq!(g.key_count(), 0, "check 不得插入 key");
    }

    #[test]
    fn failures_still_back_off_after_fix() {
        let g = LoginGuard::new(5);
        for _ in 0..5 { g.record_failure("admin"); }   // max_attempts = 5
        assert_eq!(g.key_count(), 1, "失败要记账");
        assert!(g.check("admin").is_some(), "达到 max_attempts 必须退避——修无界增长不能把限速修丢");
        g.reset("admin");
        assert!(g.check("admin").is_none(), "登录成功后 reset 应放行");
        assert_eq!(g.key_count(), 0);
    }

    /// **配置值必须真的被消费**（防"假控制"回归）。
    ///
    /// `max_attempts` 曾在 `LoginGuard::new()` 里硬编码 5，config.toml 的
    /// `[security] max_login_attempts` 配了毫无效果（与 `session_*` 同一类 bug）。
    /// 这里用非默认值 3，并断言"不等于硬编码 5 时的行为"——证明有判别力：
    /// 若有人把 `new(max_attempts)` 改回 `new(5)` 硬编码，本测试会红。
    #[test]
    fn max_attempts_comes_from_config_not_hardcoded() {
        let g = LoginGuard::new(3);
        for _ in 0..3 { g.record_failure("admin"); }
        assert!(g.check("admin").is_some(), "max_attempts=3 时第 3 次失败必须退避");
        // 判别力：若仍是硬编码 5，第 3 次失败不应触发退避（要 5 次才触发）
        assert_eq!(g.max_attempts(), 3, "getter 必须回传入值");
    }

    /// **特性测试**：把「被 `check` 拦下的尝试**也**推进计数」这一行为钉住（P2-11）。
    ///
    /// 历史：旧行为是「闸门不计数」，快速连点会冻结在 `retry_after=1` 的软限速上，
    /// **永远进不了 15 分钟锁定**——真机压测实测攻击者 1 req/s 可在 2 小时内试约
    /// 7200 个口令。2026-10-20 决定改为「429 也计数」，本测试随之从
    /// `blocked_attempts_do_not_advance_the_counter` 改写为**反向断言**。
    ///
    /// ⚠ 本测试只驱动 `LoginGuard` 本身。**真正的接线点在 `routes/auth.rs` 的 429
    /// 分支里那次 `record_failure`**——那行才是"拦下也计数"的实现。把它删掉时
    /// 这个测试仍然会绿（因为本测试自己调用 record_failure），所以另有一条
    /// `login_429_branch_records_the_failure` 用源码级断言守住接线（见 routes/tests）。
    #[test]
    fn blocked_attempts_still_advance_the_counter() {
        let g = LoginGuard::new(5);
        for _ in 0..5 { g.record_failure("admin"); }   // n = max_attempts = 5

        // 模拟「每次被拦下也计数」：连点 12 次，退避逐级抬升（不再卡在 1s）
        let mut waits = Vec::new();
        for _ in 0..12 {
            if let Some(w) = g.check("admin") { waits.push(w); }
            g.record_failure("admin");
        }
        // n 从 5 一路涨到 17 ⇒ 前几次退避 1,2,4,8,16,32,64，之后进入 lock_after(15) 的锁定
        assert!(waits.iter().any(|&w| w > 1), "退避必须能抬升，不能恒为 1s：{waits:?}");
        let last = *waits.last().expect("至少被拦下若干次");
        assert!(last >= 900, "连点 12 次后必须进入 15 分钟锁定区间，实际 retry_after={last}");

        // 明确把"旧行为"作为负向对照写下来：不计数就永远到不了锁定。
        let old = LoginGuard::new(5);
        for _ in 0..5 { old.record_failure("admin"); }
        // 不 record_failure（= 旧行为），连点 60 次都只拿 1s
        for _ in 0..60 {
            assert_eq!(old.check("admin"), Some(1), "旧行为下恒为 1s——这正是被修掉的软限速");
        }
        assert!(old.check("admin").unwrap() < 900, "旧行为永远进不了锁定（负向对照）");
    }

    /// ⭐⭐ **锁定到期时间不得被后续尝试续期**（P2-11 引入「429 也计数」后暴露的真 bug）。
    ///
    /// 复现要点：进入锁定后**继续** record_failure（这是「429 也计数」的必然结果），
    /// 然后断言 `retry_after` 只随真实时间**递减**，不会因为又来了几次请求而回涨。
    ///
    /// 旧实现取 `v.last()` 当基准 ⇒ 每来一次请求，基准后移 ⇒ retry_after 永远接近
    /// 满额，攻击者持续发请求即可让账号**永久无法登录**（真机实测：锁定后每 2 秒
    /// 打一次，retry 稳定停在 898 不降）。这是拒绝服务，比「锁 15 分钟」严重。
    #[test]
    fn lock_deadline_is_not_extended_by_further_attempts() {
        use std::thread::sleep;
        let g = LoginGuard::new(5);
        // 攒到 lock_after(15)：前 14 次纯记录，第 15 次跨过阈值
        for _ in 0..15 { g.record_failure("admin"); }
        let first = g.check("admin").expect("已过 lock_after，必须锁定");
        assert!(first >= 895 && first <= 900, "刚进入锁定应接近满额 900s，实际 {first}");

        // 关键：锁定期间"继续尝试"（429 也计数 ⇒ 每次都会 record_failure）
        sleep(Duration::from_millis(1100));
        for _ in 0..5 { g.record_failure("admin"); }
        let after = g.check("admin").expect("仍在锁定中");
        assert!(
            after < first,
            "锁定期间又来了 5 次请求，剩余时间必须**继续递减**而不是被续期满额：\
             首测 {first}s，之后 {after}s"
        );

        // 再等一会儿、再打几次，仍然只能递减
        sleep(Duration::from_millis(1100));
        for _ in 0..3 { g.record_failure("admin"); }
        let later = g.check("admin").expect("仍在锁定中");
        assert!(later < after, "续期判定：应 {later} < {after}");
    }

    #[test]
    fn key_count_is_capped_and_oldest_evicted() {
        let g = LoginGuard::with_max_keys_for_test(3);
        g.record_failure("a");
        std::thread::sleep(Duration::from_millis(2));
        g.record_failure("b");
        std::thread::sleep(Duration::from_millis(2));
        g.record_failure("c");
        assert_eq!(g.key_count(), 3);
        g.record_failure("d");   // 超限 → 淘汰最久没活动的 "a"
        assert_eq!(g.key_count(), 3, "key 数不得超过硬上限");
        assert!(g.check("a").is_none(), "被淘汰的 key 应视为无记录");
        assert!(g.check("d").is_none(), "新 key 正常放行");
    }
}
