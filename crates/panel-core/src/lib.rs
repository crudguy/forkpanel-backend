//! panel-core：领域模型、错误类型、能力矩阵、公共类型。
//!
//! 纪律：本 crate **不得依赖任何 IO**（无 std::fs / std::process / 网络 / 数据库），
//! 以便在 Windows/macOS 实现与单元测试中零成本复用。

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod crypto; // 应用层密钥加密（AES-256-GCM，关闭 M0 阻塞项）
pub mod sync;   // 互斥锁中毒恢复（禁止裸 lock().unwrap()，见 ci/check_lock_unwrap.py）

// ───────────────────────────── 错误模型 ─────────────────────────────

pub type Result<T> = std::result::Result<T, PanelError>;

// Clone：panel-db 的 writer actor 需要把错误克隆一份回传给发起者（见 panel-db 的
// clone_err）。此前 PanelError 不可 Clone，只能把错误压成 Database 变体，
// 导致错误类型（也就HTTP 状态码）在跨线程回传时丢失。
#[derive(Debug, Clone, thiserror::Error)]
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
    pub const PACKAGE_UPGRADE: &str= "package.upgrade";
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
    /// 容器查看/入口：恒 supported（只要平台支持容器概念）。与 `CONTAINER_MANAGE` 解耦——
    /// 菜单是否点亮只看"功能是否可见"，不卡"daemon 是否可达"。daemon 不可达时进页面
    /// 由 ContainersView 显示诊断/引导，而非把整个菜单置灰（宝塔式常亮体验）。
    pub const CONTAINER_VIEW: &str = "container.view";
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

    /// IANA 根区 TLD 白名单（编译期内嵌，运行时惰性建一次 HashSet）。
    ///
    /// 数据来自 <https://data.iana.org/TLD/tlds-alpha-by-domain.txt>（版本行见
    /// `data/tlds.txt` 头部），**零 crate 依赖、零运行时 IO**。额外并入
    /// RFC 6761/6762 与 ICANN 私有保留后缀——它们语法合法但不在根区委派表内，
    /// 不显式例外就会误伤内网/测试域名（`app.local`、`h.lan`、`x.internal`）。
    fn tld_allowlist() -> &'static std::collections::HashSet<&'static str> {
        static SET: std::sync::OnceLock<std::collections::HashSet<&'static str>> =
            std::sync::OnceLock::new();
        SET.get_or_init(|| {
            let mut set: std::collections::HashSet<&'static str> = include_str!("data/tlds.txt")
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            set.extend([
                "local", "lan", "internal", "home", "test", "example", "invalid",
                "localhost", "onion",
            ]);
            set
        })
    }

    /// 域名校验：**语法 + TLD 真实性**。
    ///
    /// 语法层：非空、≤253、不以 `.` 起止、≥2 个 label、每个 label `[a-zA-Z0-9-]`
    /// 且首尾非 `-`、长度 1~63。单词级串（`random` / `localhost` / `as`）在此被拒。
    ///
    /// 真实性层：
    /// ① 纯数字组合按 **IPv4 字面量**语义校验——必须 4 段且每段 0~255，于是
    ///    `1.2.3.4` 放行、`999.999.999.999` 拒绝；
    /// ② 其余取最后一段作 TLD，必须命中 IANA 根区白名单，于是 `example.com`
    ///    放行、`asdf.qwer`（编造的 TLD）拒绝。
    ///
    /// 此前只做语法校验，用户"随便乱填"一个语法合法的两级串就能落库；TLD 白名单
    /// 把明显不存在的域名挡在写库之前。刻意**不**做 DNS 解析——那是运行时网络 IO，
    /// 且会把「尚未解析的新域名」误拒。
    pub fn is_valid_domain(s: &str) -> bool {
        if s.is_empty() || s.len() > 253 { return false; }
        if s.starts_with('.') || s.ends_with('.') { return false; }
        // 必须至少两级（含 '.'）。nginx 的 server_name 接不住单词级值。
        let labels: Vec<&str> = s.split('.').collect();
        if labels.len() < 2 { return false; }
        // 语法：每个 label 的字符集与首尾约束
        let syntax_ok = labels.iter().all(|label| {
            let n = label.len();
            (1..=63).contains(&n)
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-') && !label.ends_with('-')
        });
        if !syntax_ok { return false; }
        // 纯数字（形似 IPv4）：只接受 4 段且每段 0~255，挡掉 999.999.999.999
        if labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit())) {
            return labels.len() == 4
                && labels.iter().all(|l| l.parse::<u16>().map(|n| n <= 255).unwrap_or(false));
        }
        // TLD 必须真实存在（大小写不敏感）
        let tld = labels.last().unwrap().to_ascii_lowercase();
        tld_allowlist().contains(tld.as_str())
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

    /// 站点名称（即 `sites.name`，用户可见的虚拟主机标识）。
    ///
    /// 它**不进 nginx 配置**（conf 文件名按域名派生、server_name 即 domains），
    /// 但会进入两处敏感面：
    /// ① 落库为 `sites` 表主键（UNIQUE）——空名会让 `INSERT` 直接失败；
    /// ② 作为站点根目录的默认目录名（未指定 root 时 `resolve_site_root` 用它
    ///    在 site_root 下建子目录）——`.`/`..`/含 `/` 会越界或建出隐藏/逃逸目录。
    ///
    /// 故采用白名单而非黑名单：首字符必须字母数字，后续允许字母数字与 `. _ -`，
    /// 长度 1~63。明确拒绝：空、空格、`.`、`..`、首字符 `-`、含 `/`、含 shell
    /// 注入字符（空格 / `;` / `$` / 反引号 / 引号）。返回 400 比"建出一个打不开或
    /// 跨站泄露的站点"安全得多——此前 name 仅判非空，于是 `a b` 之类能进库、
    /// `.` 名会把根目录解析成整个 site_root（跨站泄露）。
    pub fn is_valid_site_name(s: &str) -> bool {
        // 长度 1~63（与 systemd 单元名上限同源，避免某些文件系统对超长目录名支持不稳）
        if s.is_empty() || s.len() > 63 { return false; }
        // 首字符必须字母数字：排除 `-` 被当成 CLI 选项、`.` 建出隐藏/当前目录
        let mut chars = s.chars();
        let first = chars.next().unwrap(); // 非空已判过，unwrap 安全
        if !first.is_ascii_alphanumeric() { return false; }
        // 其余字符白名单：字母数字 + . _ -（排除 / \ 及任何空白或注入字符）
        chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    }
}

#[cfg(test)]
mod tests {
    use super::rules::*;

    #[test]
    fn unit_name_rejects_injection() {
        // 合法：systemd 单元名的真实形态
        for ok in ["nginx.service", "panel@1.service", "sshd", "mysql_1.service", "a.b-c@d"] {
            assert!(is_valid_unit_name(ok), "应放行: {ok}");
        }
        // 注入 / 越界 / 超长 必须全部拒绝
        for bad in [
            "nginx; rm -rf /", "../../etc/passwd", "$(id)", "`id`", "-bad", "a..b", "",
            "nginx|cat /etc/shadow", "nginx\nrm -rf /", "unit&id",  // 管道 / 换行 / `&` 注入
            &"x".repeat(300),                                       // 超长（>256）
        ] {
            assert!(!is_valid_unit_name(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn domain_rules() {
        // 合法：真实 TLD / 多级 / IP 字面量 / punycode TLD / 私有后缀例外 / 大小写
        for ok in [
            "example.com", "a.b.c.example.org", "sub.example.com",
            "host.lan", "app.local", "svc.internal",          // 私有后缀例外
            "1.2.3.4", "0.0.0.0", "255.255.255.255",          // IPv4 字面量
            "example.xn--fiqs8s", "Example.COM",              // punycode TLD / 大小写
        ] {
            assert!(is_valid_domain(ok), "应放行: {ok}");
        }
        // 非法
        for bad in [
            "random", "test123", "localhost", "as", "a",       // 单词级（无 TLD）
            "-a.com", "a-.com", ".com", "exa mple.com",        // label 语法 / 空格
            "a..b",                                            // 空 label
            "asdf.qwer", "host.zzz", "example.notreal",        // TLD 不存在（编造）
            "999.999.999.999", "256.1.1.1", "1.2.3",           // 伪 IP / 段数不足
            "example.com;rm -rf /",                            // 分号注入
            "example.com\nSet-Cookie:x",                       // 换行头注入（CRLF）
            "$(id).com",                                       // 命令替换
            "a".repeat(254).as_str(), "",                      // 超长 / 空
        ] {
            assert!(!is_valid_domain(bad), "必须拒绝: {bad:?}");
        }
    }

    #[test]
    fn db_name_excludes_dash() {
        // 合法：大小写字母 / 数字 / 下划线（`Panel` 验证大写不被误拒）
        for ok in ["wp_db1", "Panel", "a"] {
            assert!(is_valid_db_name(ok), "应放行: {ok}");
        }
        // 非法
        for bad in [
            "wp-db",                       // '-' 会诱出 MySQL 反引号陷阱，刻意排除
            "db;drop table", "db'or 1=1--", // SQL 注入
            "db`x",                        // 反引号（反引号陷阱的元凶字符本身）
            "", &"d".repeat(65),           // 空 / 超长（>64）
        ] {
            assert!(!is_valid_db_name(bad), "必须拒绝: {bad:?}");
        }
    }

    /// 系统用户名（cron / 服务运行身份）：首字符须小写字母或 `_`，其余 `[a-z0-9_-]`。
    ///
    /// 该值会进 crontab 的 `-u` 参数与 systemd 单元，故大写、空格、注入字符全拒。
    /// 单独在 rules 层覆盖——路由层（`routes/cron.rs`）也有一份断言，但那是"cron
    /// 路由顺带校验"，规则的边界（如 `_apps` 走 `c == '_'` 分支）应在此处兜住。
    #[test]
    fn system_user_rules() {
        for ok in ["www-data", "_apps", "nginx1", "root"] {
            assert!(is_valid_system_user(ok), "应放行: {ok}");
        }
        for bad in [
            "-root",       // 首字符 '-'（CLI 选项注入）
            "Root",        // 大写（Linux 用户名惯例全小写）
            "user name",   // 空格
            "root;id", "user$(id)",  // 注入
            "", &"u".repeat(33),     // 空 / 超长（>32）
        ] {
            assert!(!is_valid_system_user(bad), "必须拒绝: {bad:?}");
        }
    }

    #[test]
    fn path_segment_rejects_traversal() {
        for ok in ["site-a", "index.html"] {
            assert!(is_valid_path_segment(ok), "应放行: {ok}");
        }
        for bad in [
            "..", ".",                    // 上级 / 当前目录
            "a/b", "a\\b", "a\0b",        // 路径分隔符与 NUL（反斜杠在 Windows 上也是分隔符）
            "a b", "a;b",                 // 空格破坏 crontab 字段切分；分号可被 shell 解释
            "", &"s".repeat(256),         // 空 / 超长（>255）
        ] {
            assert!(!is_valid_path_segment(bad), "必须拒绝: {bad:?}");
        }
    }

    /// 站点名共享校验（后端 create / patch 共用）：白名单而非黑名单。
    /// 这批用例是此前仅判非空时漏掉的危险输入——`.` 会让根目录解析成整个
    /// site_root（跨站泄露）、空格名会带着注入字符进库。
    #[test]
    fn site_name_rules() {
        // 合法：字母数字开头，后续可含 . _ -
        for ok in ["web", "my-site", "site1", "a.b", "api_v2", "Blog2026", "x"] {
            assert!(is_valid_site_name(ok), "should accept {ok:?}");
        }
        // 非法：空 / 空格 / 点类 / 越界 / 注入
        for bad in [
            "", " ", ".", "..", ".hidden", "-lead", "a/b", "a b",
            "a;b", "a$(id)", "a`id`", "a\"b", "a\\b",
            &"x".repeat(64),
        ] {
            assert!(!is_valid_site_name(bad), "should reject {bad:?}");
        }
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

    // ───────────── 契约层：错误码 / 档位 / 构造器 ─────────────
    //
    // rules 层（上面那批）测的是"输入合法性"；这里测的是**跨 crate 的契约**：
    // 错误码是前端映射的依据、档位决定采样与并发、构造器是唯一的安全入口。
    // 这三类一旦悄悄变了，编译与 rules 测试都不会红，但行为会整体偏移。
    mod contract {
        use crate::{domain, unit_name, Capability, PanelError, Tier};

        /// 错误码是**前后端契约**：前端按 10009 判"能力未实现"、10001 标字段错误、
        /// 50001 提示路径越界。改这些数字等于改 API——必须连同 openapi 与前端
        /// 映射一起动，所以用测试钉死。
        #[test]
        fn error_codes_are_stable() {
            let cases: [(PanelError, u32); 11] = [
                (PanelError::Validation { field: "f", reason: "r".into() }, 10001),
                (PanelError::PermissionDenied("p"), 10003),
                (PanelError::NotFound("x".into()), 10004),
                (PanelError::Conflict("x".into()), 10005),
                (PanelError::Unsupported("u"), 10009),
                (PanelError::PathEscape("p".into()), 50001),
                (PanelError::Io("i".into()), 50002),
                (PanelError::Timeout(std::time::Duration::from_secs(1)), 80003),
                (PanelError::ConfigInvalid { detail: "d".into() }, 40002),
                (PanelError::Command { bin: "b".into(), detail: "d".into() }, 30000),
                (PanelError::Database("d".into()), 60000),
            ];
            for (e, want) in cases {
                assert_eq!(e.code(), want, "错误码变了会破坏前端映射: {e:?}");
            }
            assert_eq!(PanelError::Internal("x".into()).code(), 10999);
        }

        /// 档位边界：**1 核即使内存巨大也按 Nano**——这是刻意的保守取值
        /// （采样、并发、SQLite 缓存都按单核能力给），别"优化"成只看内存。
        #[test]
        fn tier_detection_boundaries() {
            assert_eq!(Tier::detect(512, 8), Tier::Nano, "≤512MB 即 Nano");
            assert_eq!(Tier::detect(65536, 1), Tier::Nano, "单核按 Nano，不看内存");
            assert_eq!(Tier::detect(513, 8), Tier::Small, "513MB 起进 Small");
            assert_eq!(Tier::detect(65536, 2), Tier::Small, "双核按 Small");
            assert_eq!(Tier::detect(2048, 8), Tier::Small, "2048MB 仍属 Small");
            assert_eq!(Tier::detect(2049, 3), Tier::Standard, "2049MB 且 3 核起进 Standard");
            assert_eq!(Tier::detect(8192, 4), Tier::Standard);
        }

        /// 各档位旋钮必须**单调**：低配采样更稀、SSE 更少、并发更低、缓存更小；
        /// 只有 nano 不落历史。写反了不会 panic，只会悄悄压垮低配机器。
        #[test]
        fn tier_knobs_are_monotonic() {
            let (n, s, d) = (Tier::Nano, Tier::Small, Tier::Standard);
            assert!(n.sampling_interval_ms() > s.sampling_interval_ms());
            assert!(s.sampling_interval_ms() > d.sampling_interval_ms());
            assert!(n.max_sse_clients() < s.max_sse_clients());
            assert!(s.max_sse_clients() < d.max_sse_clients());
            assert!(n.task_concurrency() < s.task_concurrency());
            assert!(s.task_concurrency() < d.task_concurrency());
            // SQLite 的 cache_size 用**负值表示 KiB**（-4000 = 4MiB）⇒ 越负缓存越大。
            // 初版这里写反了（以为数值大=缓存大），是这条断言把它抓出来的。
            assert!(n.sqlite_cache_kib() > s.sqlite_cache_kib());
            assert!(s.sqlite_cache_kib() > d.sqlite_cache_kib());
            assert!(!n.persist_history(), "nano 只留内存环形缓冲");
            assert!(s.persist_history() && d.persist_history());
        }

        /// 能力位的两个构造器必须保持"支持⇔有 backend、不支持⇔有 reason"的不变式：
        /// 前端拿 `supported` 判开关、拿 `reason` 显示为什么灰。混填会让 UI 自相矛盾。
        #[test]
        fn capability_constructors_keep_invariants() {
            let yes = Capability::yes("nginx");
            assert!(yes.supported);
            assert_eq!(yes.backend.as_deref(), Some("nginx"));
            assert!(yes.reason.is_none());

            let no = Capability::no("binary_missing");
            assert!(!no.supported);
            assert!(no.backend.is_none());
            assert_eq!(no.reason.as_deref(), Some("binary_missing"));
        }

        /// 域名构造器：**必须小写归一**（落库与 nginx server_name 都按小写比对），
        /// 非法输入必须返回 10001 且字段名可定位。
        #[test]
        fn domain_constructor_normalizes_case_and_reports_field() {
            let d = domain("Example.COM").expect("合法域名");
            assert_eq!(d.as_str(), "example.com");
            let e = domain("asdf.qwer").unwrap_err();
            assert_eq!(e.code(), 10001);
            assert!(format!("{e}").contains("domain"), "错误必须带字段名: {e}");
        }

        #[test]
        fn unit_name_constructor_rejects_injection() {
            assert_eq!(unit_name("nginx.service").unwrap().as_str(), "nginx.service");
            let e = unit_name("nginx; rm -rf /").unwrap_err();
            assert_eq!(e.code(), 10001);
            assert!(format!("{e}").contains("unit_name"), "错误必须带字段名: {e}");
        }
    }
}
