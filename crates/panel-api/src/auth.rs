//! 会话、口令、防暴力、RBAC、CSRF（设计方案 §1.3）。

use crate::error::{ApiError, ApiResult};
use panel_core::{PanelError, Result, Tier};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
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
}

impl SessionCache {
    pub fn new(idle: Duration, absolute: Duration) -> Self {
        Self { inner: Mutex::new(HashMap::new()), idle_timeout: idle, absolute_timeout: absolute }
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
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(sid, s);
    }

    /// 登录成功后轮换 sid（防会话固定）
    pub fn rotate(&self, old: &str) -> Option<(String, Session)> {
        let s = { self.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(old)? };
        let new = generate_sid();
        self.insert(new.clone(), s.clone());
        Some((new, s))
    }

    pub fn remove(&self, sid: &str) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
    }

    /// 定时清理过期会话（合并进统一调度器，避免独立定时器）
    pub fn sweep(&self) -> usize {
        let now = now_unix();
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = m.len();
        m.retain(|_, s| s.expires_at > now);
        before - m.len()
    }
}

// ═══════════════════════════ 防暴力 ═══════════════════════════

/// 滑动窗口失败计数 + 指数退避 + 锁定（设计方案 §1.3）
pub struct LoginGuard {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    max_attempts: usize,
    lock_after: usize,
    lock_duration: Duration,
}

impl LoginGuard {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts: 5,
            lock_after: 15,
            lock_duration: Duration::from_secs(900),
        }
    }

    /// 返回 None 表示允许尝试；Some(secs) 表示需等待
    pub fn check(&self, key: &str) -> Option<u64> {
        let mut m = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let v = m.entry(key.to_string()).or_default();
        // 只保留 15 分钟窗口内的记录
        v.retain(|t| now.duration_since(*t) < Duration::from_secs(900));
        let n = v.len();
        if n >= self.lock_after {
            let last = v.last().copied().unwrap_or(now);
            let elapsed = now.duration_since(last);
            return Some(self.lock_duration.as_secs().saturating_sub(elapsed.as_secs()));
        }
        if n >= self.max_attempts {
            // 指数退避：2^(n - max_attempts) 秒
            let backoff = 1u64 << (n - self.max_attempts).min(6);
            let last = v.last().copied().unwrap_or(now);
            let elapsed = now.duration_since(last).as_secs();
            if elapsed < backoff { return Some(backoff - elapsed); }
        }
        None
    }

    pub fn record_failure(&self, key: &str) {
        self.attempts.lock().unwrap_or_else(|e| e.into_inner())
            .entry(key.to_string()).or_default().push(Instant::now());
    }

    pub fn reset(&self, key: &str) {
        self.attempts.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
    }
}

impl Default for LoginGuard { fn default() -> Self { Self::new() } }

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
    pub const USER_MANAGE: &str     = "user.manage";
    pub const SETTINGS_MANAGE: &str = "settings.manage";
    pub const AUDIT_VIEW: &str      = "audit.view";
}

/// 角色 → 权限集合。**默认拒绝**：未列出的权限一律不允许。
pub fn permissions_for_role(role: &str) -> Vec<String> {
    use perm::*;
    let view_only = vec![SYSTEM_VIEW, SERVICE_VIEW, SITE_VIEW, FILE_READ, DB_VIEW,
                         FIREWALL_VIEW, CRON_VIEW, LOG_VIEW, TASK_VIEW, AUDIT_VIEW];
    match role {
        "owner" | "admin" => {
            let mut v = view_only.clone();
            v.extend([SYSTEM_MANAGE, SERVICE_MANAGE, PACKAGE_MANAGE, SITE_MANAGE, SSL_MANAGE,
                      FILE_WRITE, DB_MANAGE, FIREWALL_MANAGE, SECURITY_MANAGE, CRON_MANAGE,
                      SETTINGS_MANAGE, USER_MANAGE]);
            v
        }
        "operator" => {
            let mut v = view_only.clone();
            v.extend([SERVICE_MANAGE, SITE_MANAGE, SSL_MANAGE, CRON_MANAGE, FILE_WRITE]);
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
              LOG_VIEW, TASK_VIEW, USER_MANAGE, SETTINGS_MANAGE, AUDIT_VIEW] {
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
                          permissions: vec![], allowed_roots: vec![],
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
        let g = LoginGuard::new();
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
}
