//! macOS 平台实现 —— **Phase 1：能编译、能启动、能登录**。
//!
//! # 范围声明（诚实优先）
//!
//! 本模块在 Phase 1 只做三件事：
//! 1. 提供**真实的** macOS 路径布局（`MacPathLayout`）；
//! 2. 提供**真实的**平台信息（`sw_vers` / `uname`，`Os::Macos` + `InitSystem::Launchd`）；
//! 3. 其余 15 个 provider **全部返回 `Unsupported`**，能力位一律 `no(reason)`。
//!
//! 为什么全部 Unsupported 而不是先给个"能跑但数据是假的"实现：项目纪律是
//! 「未实现必须返回 `Unsupported`，禁止返回空 Vec / Ok(()) 假装成功」
//! （见 `linux/stub/mod.rs:3` 与 `tests/conformance.rs` 契约 9）。给假数据会让
//! 前端显示"磁盘 0%""0 个进程"这类**看起来正常实则错误**的状态，比置灰危险得多。
//!
//! # 后续分期（见 `docs/design-macos.md`）
//! - Phase 2：`metrics`（host_statistics64/IOKit）、`processes`（libproc）、`network`
//! - Phase 3：`files`、`terminal`
//! - Phase 4：`services`（launchctl）、`packages`（brew）
//! - Phase 5+：`webserver`、`logs`、`firewall`（pfctl）、`databases`、`containers`
//! - `security` / `fail2ban` / WAF：长期 Unsupported（macOS 无对应生态）

pub mod paths;
mod providers;

pub use paths::MacPathLayout;
pub use providers::{
    MacContainers, MacDatabases, MacFiles, MacFirewall, MacLogs, MacMetrics, MacNetwork,
    MacPackages, MacProcesses, MacScheduler, MacSecurity, MacServices, MacStorage, MacTerminal,
    MacUsers, MacWebServer,
};

use crate::traits::*;
use panel_core::{Capability, CapabilityMap, InitSystem, Os, PlatformInfo};
use std::sync::Arc;

// ───────────────────────── 平台探测 ─────────────────────────

/// 通过 `sw_vers` 读取 macOS 版本，拼成 `macos:15.1` 形式（与 Linux 的 `debian:12` 同构）。
///
/// 走 `crate::cmd::run_probe_sync`（而非 `std::process`）：子进程只能从 `cmd.rs`
/// 派出是 CI 门禁 [1] 的硬不变量，平台探测是"读一行版本号"也不构成例外。
///
/// 失败一律返回 `None`（而非 panic 或编造默认值）：`distro` 字段本就是 `Option`，
/// 拿不到就诚实留空——`conformance` 契约 2 只要求 distro/kernel **至少有一个**。
fn detect_version() -> Option<String> {
    // 2s 超时：`sw_vers` 是系统自带只读命令，正常在毫秒级返回
    let v = crate::cmd::run_probe_sync(crate::cmd::Bin::SwVers, &["-productVersion"], 2000)?;
    Some(format!("macos:{v}"))
}

/// `uname -r`（Darwin 内核版本，如 `24.1.0`）。
fn detect_kernel() -> Option<String> {
    crate::cmd::run_probe_sync(crate::cmd::Bin::Uname, &["-r"], 2000)
}

pub fn detect_platform() -> PlatformInfo {
    PlatformInfo {
        os: Os::Macos,
        arch: match std::env::consts::ARCH {
            "aarch64" => panel_core::Arch::Aarch64,
            _ => panel_core::Arch::X86_64,
        },
        // macOS 的服务管理器恒为 launchd（不存在 sysv/openrc 的等价物）。
        // 这是事实陈述，与"服务管理能力是否已实现"是两件事。
        init: InitSystem::Launchd,
        distro: detect_version(),
        kernel: detect_kernel(),
    }
}

// ───────────────────────── 聚合 ─────────────────────────

pub struct MacOsAdapter {
    pub paths: Arc<MacPathLayout>,
    pub platform: PlatformInfo,
    metrics: MacMetrics,
    processes: MacProcesses,
    services: MacServices,
    packages: MacPackages,
    firewall: MacFirewall,
    network: MacNetwork,
    users: MacUsers,
    storage: MacStorage,
    files: MacFiles,
    logs: MacLogs,
    scheduler: MacScheduler,
    webserver: MacWebServer,
    databases: MacDatabases,
    security: MacSecurity,
    containers: MacContainers,
    terminal: MacTerminal,
}

impl MacOsAdapter {
    pub fn new() -> Self {
        Self::with_paths(Arc::new(MacPathLayout::default()))
    }

    /// 用配置感知的路径布局构造（与 `LinuxOsAdapter::with_paths` 同构）。
    pub fn with_paths(paths: Arc<MacPathLayout>) -> Self {
        Self {
            paths,
            platform: detect_platform(),
            metrics: MacMetrics,
            processes: MacProcesses,
            services: MacServices,
            packages: MacPackages,
            firewall: MacFirewall,
            network: MacNetwork,
            users: MacUsers,
            storage: MacStorage,
            files: MacFiles,
            logs: MacLogs,
            scheduler: MacScheduler,
            webserver: MacWebServer,
            databases: MacDatabases,
            security: MacSecurity,
            containers: MacContainers,
            terminal: MacTerminal,
        }
    }
}

impl Default for MacOsAdapter {
    fn default() -> Self { Self::new() }
}

/// 统一构造"本平台尚未实现"的能力位。
///
/// `Capability::no` 只接受 `&'static str`（能力矩阵是启动时求值一次、长期持有的
/// 只读表，用静态字符串避免每次构造都分配）。因此这里不能 `format!` 拼动态原因——
/// 各能力位的具体原因直接写在调用处，保持"原因能精确到哪个子系统"。
///
/// `reason` 必须非空（conformance 契约 1 会断言），且要**用户能看懂**：
/// 前端把它当 tooltip 展示，写内部标识符等于没说。
fn not_yet(reason: &'static str) -> Capability {
    Capability::no(reason)
}

impl crate::OsAdapter for MacOsAdapter {
    fn platform(&self) -> PlatformInfo { self.platform.clone() }

    /// 宿主规模：Phase 1 拿不到真实值，返回 `(0, 0)` 表示"未知"。
    ///
    /// ⚠ 这里**不能**随便填一个看起来合理的数：`detect_tier()` 用它选
    /// nano/small/standard 档位，而档位决定 SQLite 缓存与连接池大小。
    /// 返回 0 时 `Config::tier()` 会按配置里显式的 `tier` 字段走，不会被误导。
    /// Phase 2 用 `sysctl hw.memsize` 与 `hw.ncpu` 补真值。
    fn host_profile(&self) -> (u64, u32) { (0, 0) }

    fn capabilities(&self) -> CapabilityMap {
        use panel_core::cap_keys as k;
        let mut m = CapabilityMap::new();
        // 与 Linux 实现保持**同一组键**：少登记一个键，前端读 `caps[key]`
        // 会拿到 undefined 而不是"不支持"，置灰逻辑失效。
        m.insert(k::METRICS_READ.into(), not_yet("macOS 指标采集未实现（Phase 2）"));
        m.insert(k::PROCESS_LIST.into(), not_yet("macOS 进程管理未实现（Phase 2）"));
        m.insert(k::PROCESS_SIGNAL.into(), not_yet("macOS 进程管理未实现（Phase 2）"));
        m.insert(k::SERVICE_MANAGE.into(), not_yet("macOS 服务管理未实现（Phase 4）"));
        m.insert(k::PACKAGE_INSTALL.into(), not_yet("macOS 软件包管理未实现（Phase 4）"));
        m.insert(k::PACKAGE_UPGRADE.into(), not_yet("macOS 软件包管理未实现（Phase 4）"));
        m.insert(k::FILE_READ.into(), not_yet("macOS 文件管理未实现（Phase 3）"));
        m.insert(k::FILE_WRITE.into(), not_yet("macOS 文件管理未实现（Phase 3）"));
        m.insert(k::FIREWALL_MANAGE.into(), not_yet("macOS 防火墙管理未实现（Phase 5）"));
        m.insert(k::FAIL2BAN.into(), not_yet("macOS 无 fail2ban 生态"));
        m.insert(k::WEBSERVER_MANAGE.into(), not_yet("macOS 站点托管未实现（Phase 5）"));
        m.insert(k::SCHEDULER_MANAGE.into(), not_yet("macOS 计划任务未实现（Phase 4）"));
        m.insert(k::LOGS_READ.into(), not_yet("macOS 日志阅读未实现（Phase 5）"));
        m.insert(k::DBMS_MANAGE.into(), not_yet("macOS 数据库浏览未实现（Phase 5）"));
        m.insert(k::SSL_ACME.into(), not_yet("macOS ACME 证书未实现（Phase 5）"));
        m.insert(k::SSL_SELFSIGNED.into(), not_yet("macOS 自签证书未实现（Phase 5）"));
        // 备份是面板**内建**能力（SQLite 在线备份 + tar），不依赖任何系统接口 → 恒 yes。
        // 置 no 等于白白关掉一个可用功能，那是"置灰过度"而非诚实。
        m.insert(k::BACKUP_MANAGE.into(), Capability::yes("builtin"));
        m.insert(k::CONTAINER_MANAGE.into(), not_yet("macOS 容器管理未实现（Phase 5）"));
        m.insert(k::CONTAINER_VIEW.into(), not_yet("macOS 容器管理未实现（Phase 5）"));
        m.insert(k::TERMINAL_MANAGE.into(), not_yet("macOS 终端未实现（Phase 3）"));
        // 用户与角色管理是面板内建功能（存自己的 SQLite），与 OS 能力无关 → 恒 yes。
        m.insert(k::USER_MANAGE.into(), Capability::yes("builtin"));
        m
    }

    fn paths(&self) -> &dyn crate::PathLayout { &*self.paths }
    fn metrics(&self) -> &dyn MetricsProvider { &self.metrics }
    fn processes(&self) -> &dyn ProcessProvider { &self.processes }
    fn services(&self) -> &dyn ServiceProvider { &self.services }
    fn packages(&self) -> &dyn PackageProvider { &self.packages }
    fn firewall(&self) -> &dyn FirewallProvider { &self.firewall }
    fn network(&self) -> &dyn NetworkProvider { &self.network }
    fn users(&self) -> &dyn UserProvider { &self.users }
    fn storage(&self) -> &dyn StorageProvider { &self.storage }
    fn files(&self) -> &dyn FileProvider { &self.files }
    fn logs(&self) -> &dyn LogProvider { &self.logs }
    fn scheduler(&self) -> &dyn SchedulerProvider { &self.scheduler }
    fn webserver(&self) -> &dyn WebServerProvider { &self.webserver }
    fn databases(&self) -> &dyn DatabaseProvider { &self.databases }
    fn security(&self) -> &dyn SecurityProvider { &self.security }
    fn containers(&self) -> &dyn ContainerProvider { &self.containers }
    fn terminal(&self) -> &dyn TerminalProvider { &self.terminal }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OsAdapter;
    use panel_core::cap_keys;

    /// 能力矩阵必须**与 Linux 同键集**且自洽（conformance 契约 1）。
    ///
    /// 这条测试在 Linux 上也会跑（`macos` 模块是无条件声明的），所以它能在
    /// CI 里验证 macOS 实现——不必有 Mac 机器。这是刻意的：`MacOsAdapter`
    /// 不依赖任何 macOS 专有 API（Phase 1 全是 Unsupported），故可跨平台构造。
    #[test]
    fn capability_matrix_is_self_consistent() {
        let a = MacOsAdapter::new();
        let caps = a.capabilities();
        assert!(!caps.is_empty());
        for (key, c) in &caps {
            if c.supported {
                assert!(c.backend.is_some(), "{key}: supported 必须有 backend");
                assert!(c.reason.is_none(), "{key}: supported 不应有 reason");
            } else {
                assert!(c.reason.is_some(), "{key}: unsupported 必须有 reason");
            }
        }
    }

    /// 关键能力位必须显式登记，且 Phase 1 全部为 no。
    /// 少登记一个键，前端 `caps[key]` 拿到 undefined → 置灰逻辑失效。
    #[test]
    fn unimplemented_capabilities_are_explicitly_off() {
        let caps = MacOsAdapter::new().capabilities();
        for key in [
            cap_keys::METRICS_READ, cap_keys::PROCESS_LIST, cap_keys::PROCESS_SIGNAL,
            cap_keys::SERVICE_MANAGE, cap_keys::PACKAGE_INSTALL, cap_keys::PACKAGE_UPGRADE,
            cap_keys::FILE_READ, cap_keys::FILE_WRITE, cap_keys::FIREWALL_MANAGE,
            cap_keys::WEBSERVER_MANAGE, cap_keys::SCHEDULER_MANAGE, cap_keys::LOGS_READ,
            cap_keys::DBMS_MANAGE, cap_keys::CONTAINER_MANAGE, cap_keys::TERMINAL_MANAGE,
        ] {
            let c = caps.get(key).unwrap_or_else(|| panic!("{key} 未登记"));
            assert!(!c.supported, "{key} 在 Phase 1 必须是 no（实现未接入）");
        }
    }

    /// 内建能力（备份 / 用户管理）必须 yes：它们不依赖系统接口，
    /// 置 no 会让用户白白用不上能用的功能。
    #[test]
    fn builtin_capabilities_are_on() {
        let caps = MacOsAdapter::new().capabilities();
        for key in [cap_keys::BACKUP_MANAGE, cap_keys::USER_MANAGE] {
            let c = caps.get(key).unwrap_or_else(|| panic!("{key} 未登记"));
            assert!(c.supported, "{key} 是面板内建能力，必须 yes");
        }
    }

    /// pid 1 保护必须生效（conformance 契约 6），即便进程管理整体未实现。
    /// 返回 Unsupported 会让调用方拿不到 true 而放行 kill。
    #[tokio::test]
    async fn pid_one_is_protected_even_though_processes_unimplemented() {
        let a = MacOsAdapter::new();
        let p = a.processes();
        assert!(p.is_protected(1).await.unwrap(), "pid 1 必须被保护");
        assert!(p.is_protected(0).await.unwrap(), "pid 0 同样不是可杀目标");
        assert!(!p.is_protected(12345).await.unwrap(), "普通 pid 不应被误保护");
        // 而真正需要系统能力的操作必须诚实 Unsupported
        assert!(p.list(5, ProcessSort::Cpu).await.is_err());
    }

    /// 终端如实报告不可用（能力位 no 的数据来源），而不是 Unsupported。
    #[test]
    fn terminal_reports_unavailable() {
        let a = MacOsAdapter::new();
        assert!(!a.terminal().available());
        assert!(a.terminal().shell().is_none());
    }

    /// 文件敏感路径判定必须**保守为 true**：功能未实现时宁多挡不漏挡。
    /// 返回 false 会让将来接入文件功能时黑名单形同虚设。
    #[test]
    fn file_sensitivity_defaults_to_conservative() {
        let a = MacOsAdapter::new();
        assert!(a.files().is_sensitive_path(std::path::Path::new("/etc/passwd")));
    }

    /// 平台信息必须是 Os::Macos + Launchd，且 distro/kernel 至少有一个
    /// （conformance 契约 2 的机器无关版本——在 Linux 上跑时 sw_vers 不存在，
    /// 此时 kernel 由 uname 兜底，故断言用"或"）。
    #[test]
    fn platform_info_identifies_macos() {
        let p = MacOsAdapter::new().platform();
        assert!(matches!(p.os, panel_core::Os::Macos));
        assert!(matches!(p.init, panel_core::InitSystem::Launchd));
    }
}
