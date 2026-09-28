//! OS 抽象层（设计方案 §0.3）。业务层**只**通过本 trait 访问操作系统能力。
//!
//! ```ignore
//! let os: Arc<dyn OsAdapter> = default_adapter();
//! let snap = os.metrics().snapshot().await?;          // 不做任何平台判断
//! if os.capabilities()["firewall.manage"].supported { /* UI 才显示防火墙页 */ }
//! ```

pub mod cmd;
pub mod fs;
pub mod linux;
pub mod mock_files;
pub mod mock;
pub mod paths;
pub mod traits;

pub use cmd::{run, run_checked, spawn_stream, Bin, CmdOpt, CmdOutput};
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
}

/// 按编译目标选择实现。Windows/macOS 接入时在此追加分支（设计方案 §0.4.2）。
pub fn default_adapter() -> Arc<dyn OsAdapter> {
    #[cfg(all(target_os = "linux", not(feature = "force-mock")))]
    { Arc::new(linux::LinuxOsAdapter::new()) }

    #[cfg(any(not(target_os = "linux"), feature = "force-mock"))]
    { Arc::new(mock::MockOsAdapter::new()) }
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
        m.insert(k::WEBSERVER_MANAGE.into(), match self.webserver.name() {
            "none" => Capability::no("binary_missing"),
            n => Capability::yes(n),
        });
        // 以下为 M4/M5 待实现：显式 no，UI 自动置灰
        m.insert(k::SCHEDULER_MANAGE.into(), Capability::no("not_implemented"));
        m.insert(k::LOGS_READ.into(), Capability::no("not_implemented"));
        m.insert(k::DBMS_MANAGE.into(), Capability::no("not_implemented"));
        m.insert(k::SSL_ACME.into(), Capability::no("not_implemented"));
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
