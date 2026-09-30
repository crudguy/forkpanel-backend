//! panel-core：领域模型、错误类型、能力矩阵、公共类型。
//!
//! 纪律：本 crate **不得依赖任何 IO**（无 std::fs / std::process / 网络 / 数据库），
//! 以便在 Windows/macOS 实现与单元测试中零成本复用。

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod crypto; // 应用层密钥加密（AES-256-GCM，关闭 M0 阻塞项）

// ───────────────────────────── 错误模型 ─────────────────────────────

pub type Result<T> = std::result::Result<T, PanelError>;

#[derive(Debug, thiserror::Error)]
pub enum PanelError {
    /// 输入未通过校验器（携带字段级明细，映射 HTTP 10001）
    #[error("invalid input: {field}: {reason}")]
    Validation { field: &'static str, reason: String },

    /// 路径超出允许根（映射 HTTP 50001），须由 OsAdapter/PathLayout 层抛出
    #[error("path escapes allowed root: {0}")]
    PathEscape(String),

    /// 文件 / 进程 IO 失败（OS 抽象层 std::io::Error 的统一收口，映射 HTTP 50002）
    #[error("io: {0}")]
    Io(String),

    /// 当前平台未实现该能力（对应能力矩阵 supported=false）
    #[error("unsupported on this platform: {0}")]
    Unsupported(&'static str),

    /// 外部命令执行失败：非 0 退出码 / 超时 / 被拒绝
    #[error("command failed [{bin}]: {detail}")]
    Command { bin: String, detail: String },

    #[error("command timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// 资源不存在
    #[error("not found: {0}")]
    NotFound(String),

    /// 冲突（如端口已占用、站点重名）
    #[error("conflict: {0}")]
    Conflict(String),

    /// 权限不足（RBAC 层，映射 10003）
    #[error("permission denied: {0}")]
    PermissionDenied(&'static str),

    /// 数据库层错误
    #[error("database: {0}")]
    Database(String),

    /// 配置生成后校验未通过（如 nginx -t 失败），detail 携带原始输出
    #[error("config validation failed: {detail}")]
    ConfigInvalid { detail: String },

    #[error("internal: {0}")]
    Internal(String),
}

impl PanelError {
    /// 映射为设计方案 §3.4 的错误码分段
    pub fn code(&self) -> u32 {
        use PanelError::*;
        match self {
            Validation { .. } => 10001,
            PermissionDenied(_) => 10003,
            NotFound(_) => 10004,
            Conflict(_) => 10005,
            Unsupported(_) => 10009,
            PathEscape(_) => 50001,
            Io(_) => 50002,
            Timeout(_) => 80003,
            ConfigInvalid { .. } => 40002,
            Command { .. } => 30000,
            Database(_) => 60000,
            Internal(_) => 10999,
        }
    }
}

// ───────────────────────────── 平台与能力矩阵 ─────────────────────────────
//
// 关键设计：前端**禁止**写 `if (isLinux)`，只能读后端下发的 capabilities 位。
// 这是"避免硬编码 Linux 假设"在 UI 侧的对应纪律。

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os { Linux, Windows, Macos }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch { X86_64, Aarch64, Armv7, X86 }

/// init 系统 / 服务管理器类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InitSystem { Systemd, SysV, OpenRc, Launchd, Scm, Unknown }

/// 防火墙后端
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend { Nftables, Iptables, Ufw, Firewalld, Pf, WindowsFirewall, None }

/// 日志后端
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogBackend { Journald, File, EventLog, OsLog }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os: Os,
    pub arch: Arch,
    pub init: InitSystem,
    pub distro: Option<String>,   // 例如 "debian:12"
    pub kernel: Option<String>,
}

/// 单个能力位：是否支持 + 实际后端 + 不支持的原因
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub supported: bool,
    pub backend: Option<String>,
    pub reason: Option<String>,   // "not_implemented" / "binary_missing" / "unsupported_os"
}

impl Capability {
    pub fn yes(backend: &str) -> Self {
        Self { supported: true, backend: Some(backend.into()), reason: None }
    }
    pub fn no(reason: &str) -> Self {
        Self { supported: false, backend: None, reason: Some(reason.into()) }
    }
}

/// 能力键：前端菜单与按钮的唯一开关来源
pub mod cap_keys {
    pub const METRICS_READ: &str   = "metrics.read";
    pub const PROCESS_LIST: &str   = "process.list";
    pub const PROCESS_SIGNAL: &str = "process.signal";
    pub const SERVICE_MANAGE: &str = "service.manage";
    pub const PACKAGE_INSTALL: &str= "package.install";
    pub const FILE_READ: &str      = "file.read";
    pub const FILE_WRITE: &str     = "file.write";
    pub const FIREWALL_MANAGE: &str= "firewall.manage";
    pub const FAIL2BAN: &str = "fail2ban.manage";
    pub const WEBSERVER_MANAGE:&str= "webserver.manage";
    pub const SCHEDULER_MANAGE:&str= "scheduler.manage";
    pub const LOGS_READ: &str      = "logs.read";
    pub const DBMS_MANAGE: &str    = "dbms.manage";
    pub const SSL_ACME: &str       = "ssl.acme";
    /// 面板自签证书：本机有 openssl 即可签发（离线可用），与 ACME 相互独立
    pub const SSL_SELFSIGNED: &str = "ssl.selfsigned";
    /// 备份计划（本地）：面板内建功能，任何平台恒支持
    pub const BACKUP_MANAGE: &str  = "backup.manage";
    /// 容器管理：依赖宿主 docker/podman **守护进程**可达（二进制存在 ≠ 可用，
    /// 常见的是 socket 权限不足或 daemon 未运行）。
    pub const CONTAINER_MANAGE: &str = "container.manage";
    /// 内置 Web 终端：本机存在可用交互 shell（bash/sh）即可。**高危面**——
    /// 能力位只管"能不能开"，真正的准入还叠加 SYSTEM_MANAGE 权限 + 只读拒绝。
    pub const TERMINAL_MANAGE: &str = "terminal.manage";
    /// 用户与角色管理：面板内建功能（非 OS 能力），任何平台恒支持
    pub const USER_MANAGE: &str    = "user.manage";
}

pub type CapabilityMap = std::collections::BTreeMap<String, Capability>;

// ───────────────────────────── 资源档位 ─────────────────────────────

/// 低配降级档位（设计方案 §1.6）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier { Nano, Small, Standard }

impl Tier {
    /// 依据内存与 CPU 探测（可由配置覆盖）
    pub fn detect(total_mem_mb: u64, cpus: u32) -> Self {
        if total_mem_mb <= 512 || cpus <= 1 { Tier::Nano }
        else if total_mem_mb <= 2048 || cpus <= 2 { Tier::Small }
        else { Tier::Standard }
    }

    pub fn sampling_interval_ms(&self) -> u64 {
        match self { Tier::Nano => 5000, Tier::Small => 2000, Tier::Standard => 1000 }
    }
    pub fn max_sse_clients(&self) -> usize {
        match self { Tier::Nano => 3, Tier::Small => 10, Tier::Standard => 50 }
    }
    pub fn task_concurrency(&self) -> usize {
        match self { Tier::Nano => 1, Tier::Small => 2, Tier::Standard => 4 }
    }
    pub fn sqlite_cache_kib(&self) -> i64 {
        match self { Tier::Nano => -1000, Tier::Small => -2000, Tier::Standard => -4000 }
    }
    /// nano 档位不做历史聚合落盘，仅保留内存环形缓冲
    pub fn persist_history(&self) -> bool { !matches!(self, Tier::Nano) }
}

// ───────────────────────────── 强类型标识 ─────────────────────────────
// 目的：杜绝把未校验的字符串直接送进命令或路径。

/// 已通过 UnitName 校验器验证的 systemd/服务单元名
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnitName(String);

/// 已通过域名校验器验证的域名（已 punycode 归一）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain(String);

/// 已通过路径沙箱校验、确认位于允许根之内的绝对路径
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SafePath(std::path::PathBuf);

// `unsafe` 是刻意的：跨 crate 构造这些类型意味着调用方**声明**自己已完成校验。
// CI 门禁会 grep `from_raw` 的全部调用点，确保只出现在校验器内部（见 ci/check-layering.sh）。

macro_rules! impl_validated {
    ($t:ty) => {
        impl $t {
            /// # Safety
            /// 调用方必须已对该字符串执行对应校验器（rules::is_valid_*）。
            pub unsafe fn from_raw(s: impl Into<String>) -> Self { Self(s.into()) }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }
        impl AsRef<str> for $t {
            fn as_ref(&self) -> &str { &self.0 }
        }
    };
}
impl_validated!(UnitName);
impl_validated!(Domain);

impl SafePath {
    /// # Safety
    /// 调用方必须已完成：canonicalize + 允许根前缀断言 + 符号链接检查。
    pub unsafe fn from_raw(p: std::path::PathBuf) -> Self { Self(p) }
    pub fn as_path(&self) -> &std::path::Path { &self.0 }
    pub fn as_os_str(&self) -> &std::ffi::OsStr { self.0.as_os_str() }
}
impl AsRef<std::path::Path> for SafePath {
    fn as_ref(&self) -> &std::path::Path { &self.0 }
}

// ───────────────────────────── 校验器入口 ─────────────────────────────
// 实现位于 panel-os::validate（需与 PathLayout 联动做沙箱判定），
// 这里只暴露构造函数供其他 crate 使用。

pub fn unit_name(raw: &str) -> Result<UnitName> {
    if rules::is_valid_unit_name(raw) {
        // SAFETY: 上一行刚完成校验
        Ok(unsafe { UnitName::from_raw(raw.to_string()) })
    } else {
        Err(PanelError::Validation { field: "unit_name", reason: format!("invalid systemd unit name: {raw:?}") })
    }
}

pub fn domain(raw: &str) -> Result<Domain> {
    if rules::is_valid_domain(raw) {
        // SAFETY: 上一行刚完成校验
        Ok(unsafe { Domain::from_raw(raw.to_lowercase()) })
    } else {
        Err(PanelError::Validation { field: "domain", reason: format!("invalid domain: {raw:?}") })
    }
}

/// 纯字符串规则（无 IO，便于跨平台复用与单测）
pub mod rules {
    pub fn is_valid_unit_name(s: &str) -> bool {
        // 参考 systemd 单元名约束：[a-zA-Z0-9_.@-]{1,256}，不含 ".."，不以 '-' 开头
        if s.is_empty() || s.len() > 256 { return false; }
        if s.starts_with('-') || s.contains("..") { return false; }
        s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-'))
    }

    pub fn is_valid_domain(s: &str) -> bool {
        if s.is_empty() || s.len() > 253 { return false; }
        if s.starts_with('.') || s.ends_with('.') { return false; }
        s.split('.').all(|label| {
            let n = label.len();
            n >= 1 && n <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-') && !label.ends_with('-')
        })
    }

    pub fn is_valid_system_user(s: &str) -> bool {
        if s.is_empty() || s.len() > 32 { return false; }
        let mut cs = s.chars();
        match cs.next() {
            Some(c) if c.is_ascii_lowercase() || c == '_' => {}
            _ => return false,
        }
        cs.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    }

    pub fn is_valid_db_name(s: &str) -> bool {
        // 刻意排除 '-'，避免 MySQL 反引号陷阱
        if s.is_empty() || s.len() > 64 { return false; }
        s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// 路径段（cron 任务名 / 脚本文件名 / 站点名等）合法性。
    ///
    /// **必须白名单，不能黑名单**：该名字会进入文件名、crontab 行与命令行，
    /// 只排除 `\0 / \\` 会放过空格、`;`、`$`、反引号、引号等 ——
    /// 空格会破坏 crontab 的字段切分，`;` 与 `$()` 则可被 shell 解释（注入）。
    pub fn is_valid_container_ref(s: &str) -> bool {
        // 容器 ID（hex）或名称（docker 允许 [a-zA-Z0-9][a-zA-Z0-9_.-]*）。
        // 字符集沿用路径段白名单，但**必须额外禁止首字符 '-'**：
        // 该值会作为 argv 传给 docker CLI，`--force` 之类会被当成选项解析
        // （参数注入，与 shell 注入同源）。绝不接受。
        if s.len() > 255 { return false; }
        if s.starts_with('-') { return false; }
        is_valid_path_segment(s)
    }

    pub fn is_valid_path_segment(s: &str) -> bool {
        if s.is_empty() || s.len() > 255 { return false; }
        if s == "." || s == ".." { return false; }
        s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    }
}

#[cfg(test)]
mod tests {
    use super::rules::*;

    #[test]
    fn unit_name_rejects_injection() {
        assert!(is_valid_unit_name("nginx.service"));
        assert!(is_valid_unit_name("panel@1.service"));
        // 注入类输入必须全部拒绝
        for bad in ["nginx; rm -rf /", "../../etc/passwd", "$(id)", "`id`", "-bad", "a..b", ""] {
            assert!(!is_valid_unit_name(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn domain_rules() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("a.b.c.example.org"));
        for bad in ["-a.com", "a-.com", ".com", "exa mple.com", "a".repeat(254).as_str(), ""] {
            assert!(!is_valid_domain(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn db_name_excludes_dash() {
        assert!(is_valid_db_name("wp_db1"));
        assert!(!is_valid_db_name("wp-db"));   // 反引号陷阱
        assert!(!is_valid_db_name("db;drop"));
    }

    #[test]
    fn path_segment_rejects_traversal() {
        assert!(is_valid_path_segment("site-a"));
        assert!(!is_valid_path_segment(".."));
        assert!(!is_valid_path_segment("a/b"));
        assert!(!is_valid_path_segment("a\0b"));
    }

    #[test]
    fn container_ref_accepts_id_and_name() {
        // 64 位 hex ID 与 docker 命名规则下的名称都应通过
        assert!(is_valid_container_ref("3f2a1b0c9d8e7f6a"));
        assert!(is_valid_container_ref("web-proxy"));
        assert!(is_valid_container_ref("mysql_8.0"));
        assert!(is_valid_container_ref("a"));
    }

    #[test]
    fn container_ref_rejects_flag_injection_and_traversal() {
        // 首字符 '-' 会被 docker CLI 当选项解析（`docker rm --force`）→ 必须拒绝
        assert!(!is_valid_container_ref("-f"));
        assert!(!is_valid_container_ref("--force"));
        assert!(!is_valid_container_ref("--privileged"));
        // 其余注入面
        assert!(!is_valid_container_ref(""));
        assert!(!is_valid_container_ref("a b"));      // 空格会被当第二个 argv
        assert!(!is_valid_container_ref("a;b"));
        assert!(!is_valid_container_ref("a$(id)"));
        assert!(!is_valid_container_ref("a/b"));
        assert!(!is_valid_container_ref(".."));
        assert!(!is_valid_container_ref("a\0b"));
        assert!(!is_valid_container_ref(&"x".repeat(256)));   // 超长
    }
}
