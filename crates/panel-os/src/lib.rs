//! OS 抽象层（设计方案 §0.3）。业务层**只**通过本 trait 访问操作系统能力。
//!
//! ```ignore
//! let os: Arc<dyn OsAdapter> = default_adapter();
//! let snap = os.metrics().snapshot().await?;          // 不做任何平台判断
//! if os.capabilities()["firewall.manage"].supported { /* UI 才显示防火墙页 */ }
//! ```

pub mod backup;
pub mod cmd;
pub mod fs;
pub mod linux;
pub mod mock_files;
pub mod mock;
pub mod paths;
pub mod tls;
pub mod traits;

pub use cmd::{run, run_checked, run_shell, spawn_stream, Bin, CmdOpt, CmdOutput};
pub use fs::{ensure_dir, is_root, mode_of, read_password, set_mode, write_private};
pub use paths::{resolve_within, PathLayout};
pub use traits::*;

use panel_core::{Capability, CapabilityMap, PlatformInfo};
use std::sync::Arc;

/// 平台能力聚合入口。**新增平台 = 新增一个 impl，业务层零改动。**
pub trait OsAdapter: Send + Sync + 'static {
    fn platform(&self) -> PlatformInfo;
    /// 能力矩阵：前端菜单/按钮的唯一开关来源（禁止前端写 if (isLinux)）
    fn capabilities(&self) -> CapabilityMap;
    /// 宿主规模：`(总内存 MB, CPU 数)`，用于档位探测。
    /// 必须走 trait —— CLI 里直接读 /proc/meminfo 会让平台知识泄漏到业务层。
    fn host_profile(&self) -> (u64, u32);

    fn paths(&self) -> &dyn PathLayout;
    fn metrics(&self) -> &dyn MetricsProvider;
    fn processes(&self) -> &dyn ProcessProvider;
    fn services(&self) -> &dyn ServiceProvider;
    fn packages(&self) -> &dyn PackageProvider;
    fn firewall(&self) -> &dyn FirewallProvider;
    fn network(&self) -> &dyn NetworkProvider;
    fn users(&self) -> &dyn UserProvider;
    fn storage(&self) -> &dyn StorageProvider;
    fn files(&self) -> &dyn FileProvider;
    fn logs(&self) -> &dyn LogProvider;
    fn scheduler(&self) -> &dyn SchedulerProvider;
    fn webserver(&self) -> &dyn WebServerProvider;
    fn databases(&self) -> &dyn DatabaseProvider;
    fn security(&self) -> &dyn SecurityProvider;
    fn containers(&self) -> &dyn ContainerProvider;
    fn terminal(&self) -> &dyn TerminalProvider;
}

/// 按编译目标选择实现。Windows/macOS 接入时在此追加分支（设计方案 §0.4.2）。
pub fn default_adapter() -> Arc<dyn OsAdapter> {
    #[cfg(all(target_os = "linux", not(feature = "force-mock")))]
    { Arc::new(linux::LinuxOsAdapter::new()) }

    #[cfg(any(not(target_os = "linux"), feature = "force-mock"))]
    { Arc::new(mock::MockOsAdapter::new()) }
}

/// 由配置覆盖构造适配器（**跨平台入口**，供 CLI 的 `serve` 使用）。
///
/// 为什么必须有这个入口，而不是让 CLI 直接 `Arc::new(linux::LinuxOsAdapter::with_paths(..))`：
/// 1. **可移植性**：业务层一旦引用 `panel_os::linux::*` 就绑死在 Linux，
///    非 Linux 目标编译不过（CI 门禁 [4c] 正是拦这个）。
/// 2. **`force-mock` 会失效**：`serve` 绕过 `default_adapter()` 直接起真实平台适配器，
///    于是"无 Linux / 无 root 环境下用 mock 跑逻辑"这一已声明的能力形同虚设。
///
/// 入参是**值**而非平台类型，具体用哪个 `PathLayout` 实现由本函数内部决定。
pub fn adapter_with_overrides(
    config_dir: Option<std::path::PathBuf>,
    site_root: Option<std::path::PathBuf>,
    data_dir: Option<std::path::PathBuf>,
    log_dir: Option<std::path::PathBuf>,
) -> Arc<dyn OsAdapter> {
    #[cfg(all(target_os = "linux", not(feature = "force-mock")))]
    {
        let layout = paths::LinuxPathLayout::default()
            .with_overrides(config_dir, site_root, data_dir, log_dir);
        Arc::new(linux::LinuxOsAdapter::with_paths(Arc::new(layout)))
    }
    #[cfg(any(not(target_os = "linux"), feature = "force-mock"))]
    {
        // mock 布局是内存视图，配置覆盖无意义；显式丢弃以避免"看起来生效了"
        let _ = (config_dir, site_root, data_dir, log_dir);
        Arc::new(mock::MockOsAdapter::new())
    }
}

impl OsAdapter for linux::LinuxOsAdapter {
    fn platform(&self) -> PlatformInfo { self.platform.clone() }

    fn host_profile(&self) -> (u64, u32) { linux::host_profile() }

    fn files(&self) -> &dyn FileProvider { &*self.files }

    fn capabilities(&self) -> CapabilityMap {
        use panel_core::cap_keys as k;
        let mut m = CapabilityMap::new();
        m.insert(k::METRICS_READ.into(), Capability::yes("procfs"));
        m.insert(k::PROCESS_LIST.into(), Capability::yes("procfs"));
        m.insert(k::PROCESS_SIGNAL.into(), Capability::yes("posix"));
        m.insert(k::SERVICE_MANAGE.into(), match self.services.init_system() {
            panel_core::InitSystem::Systemd => Capability::yes("systemd"),
            panel_core::InitSystem::SysV => Capability::yes("sysv"),
            panel_core::InitSystem::OpenRc => Capability::yes("openrc"),
            _ => Capability::no("init_unknown"),
        });
        m.insert(k::PACKAGE_INSTALL.into(), match self.packages.manager() {
            Some(mgr) => Capability::yes(mgr),
            None => Capability::no("no_package_manager"),
        });
        m.insert(k::FILE_READ.into(), Capability::yes("posix"));
        m.insert(k::FILE_WRITE.into(), Capability::yes("posix"));
        m.insert(k::FIREWALL_MANAGE.into(), self.firewall.capability());
        m.insert(k::FAIL2BAN.into(), self.firewall.fail2ban_capability());
        // 仅 nginx 已实装渲染/下发；caddy 已探测但 render 未实现，
        // 不能"探测到就报 yes"——那正是"假装可移植"。诚实置 no 并给出原因。
        m.insert(k::WEBSERVER_MANAGE.into(), match self.webserver.name() {
            "nginx" => Capability::yes("nginx"),
            "caddy" => Capability::no("caddy_render_not_implemented"),
            _ => Capability::no("binary_missing"),
        });
        // scheduler 已随 crontab 落地，能力位必须跟着实现走（不要写死 no）
        m.insert(k::SCHEDULER_MANAGE.into(), self.scheduler.capability());
        // 以下为 M4/M5 待实现：显式 no，UI 自动置灰
        // 日志：有 journald 或站点日志文件即可读（诚实：无任何源则 no）
        m.insert(k::LOGS_READ.into(), if self.logs.available() {
            Capability::yes(match self.logs.backend() {
                panel_core::LogBackend::Journald => "journald",
                panel_core::LogBackend::File => "file",
                panel_core::LogBackend::EventLog => "eventlog",
                panel_core::LogBackend::OsLog => "oslog",
            })
        } else {
            Capability::no("no_log_source")
        });
        // 数据库浏览：SQLite 内建引擎已实装 → yes；mysql/postgres 未实装，逐连接再判
        m.insert(k::DBMS_MANAGE.into(), if self.databases.supports(DbEngine::Sqlite) {
            Capability::yes("sqlite")
        } else {
            Capability::no("no_engine")
        });
        // ACME：按设计 §5.3 的"certbot 回退实现"路线（内置 instant-acme 留作后续，
        // 需评估 DNS-01 与各家 CA 兼容性）。能力位看**二进制存在性**——
        // 没有 certbot 就诚实置灰，绝不给出"能点但必失败"的假按钮。
        m.insert(k::SSL_ACME.into(), if crate::cmd::Bin::Certbot.available() {
            Capability::yes("certbot")
        } else {
            Capability::no("certbot_missing")
        });
        // 面板自签：本机有 openssl 即可（离线可用），与 ACME 相互独立
        m.insert(k::SSL_SELFSIGNED.into(), if tls::available() {
            Capability::yes("openssl")
        } else {
            Capability::no("openssl_missing")
        });
        // 备份计划：面板内建（SQLite 在线备份 + tar），与平台能力无关
        m.insert(k::BACKUP_MANAGE.into(), Capability::yes("builtin"));
        // 容器：**看守护进程可达性，不看二进制存在性**。
        // 装好 docker 但面板身份连不上 socket 是常态（不在 docker 组 / daemon 未跑）；
        // 若按"二进制存在"就报 yes，用户会得到一个点了必报错的假按钮。
        m.insert(k::CONTAINER_MANAGE.into(), match self.containers.unavailable_reason() {
            None => Capability::yes(self.containers.engine().as_str()),
            Some(reason) => Capability::no(reason),
        });
        // 终端：本机有可用交互 shell 即可。**能力位只管"能不能开"**，
        // 真正的准入还叠加 SYSTEM_MANAGE 权限 + 只读模式拒绝（见 routes/terminal.rs）。
        m.insert(k::TERMINAL_MANAGE.into(), match self.terminal.shell() {
            Some(sh) => Capability::yes(sh.as_str()),
            None => Capability::no("binary_missing"),
        });
        // 用户与角色管理是面板内建功能，与操作系统能力无关，任何平台恒支持
        m.insert(k::USER_MANAGE.into(), Capability::yes("builtin"));
        m
    }

    fn paths(&self) -> &dyn PathLayout { &*self.paths }
    fn metrics(&self) -> &dyn MetricsProvider { &*self.metrics }
    fn processes(&self) -> &dyn ProcessProvider { &*self.metrics }
    fn services(&self) -> &dyn ServiceProvider { &*self.services }
    fn packages(&self) -> &dyn PackageProvider { &*self.packages }
    fn firewall(&self) -> &dyn FirewallProvider { &*self.firewall }
    fn network(&self) -> &dyn NetworkProvider { &*self.network }
    fn users(&self) -> &dyn UserProvider { &*self.users }
    fn storage(&self) -> &dyn StorageProvider { &*self.storage }
    fn logs(&self) -> &dyn LogProvider { &*self.logs }
    fn scheduler(&self) -> &dyn SchedulerProvider { &*self.scheduler }
    fn webserver(&self) -> &dyn WebServerProvider { &*self.webserver }
    fn databases(&self) -> &dyn DatabaseProvider { &*self.databases }
    fn security(&self) -> &dyn SecurityProvider { &*self.security }
    fn containers(&self) -> &dyn ContainerProvider { &*self.containers }
    fn terminal(&self) -> &dyn TerminalProvider { &*self.terminal }
}

/// 启动自检：数据目录落在网络文件系统上时必须拒绝启动（WAL 不可用）
pub fn startup_fs_check(paths: &dyn PathLayout) -> panel_core::Result<()> {
    let (fs, is_network) = linux::check_data_dir_fs(&paths.data_dir())?;
    if is_network {
        return Err(panel_core::PanelError::Internal(
            format!("data dir on network filesystem ({fs}): SQLite WAL is unsafe here; \
                     move data_dir to a local filesystem")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::cap_keys;

    #[test]
    fn adapter_exposes_capability_matrix() {
        let os = default_adapter();
        let caps = os.capabilities();
        // 能力矩阵必须包含关键位，且不允许空
        assert!(caps.contains_key(cap_keys::METRICS_READ));
        assert!(caps.contains_key(cap_keys::FIREWALL_MANAGE));
        assert!(!caps.is_empty());
    }

    #[test]
    fn paths_are_never_empty() {
        let os = default_adapter();
        assert!(!os.paths().data_dir().as_os_str().is_empty());
        assert!(!os.paths().site_root().as_os_str().is_empty());
        assert!(!os.paths().default_web_user().is_empty());
    }
}
