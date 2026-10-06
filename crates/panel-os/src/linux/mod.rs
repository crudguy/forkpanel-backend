//! Linux 平台实现：当前唯一完整实现（设计方案 §0.3.3）。
//!
//! 已实现（骨架内可运行）：metrics、process、storage、services。
//! 其余 provider 为**显式 stub**，返回 `Unsupported` 而非 panic —— 这样
//! 能力矩阵能正确置灰 UI，也给出清晰的接入清单（对应里程碑 M2~M5）。

pub mod containers;
pub mod files;
/// 第三方官方 apt 源注入（方案1：加官方源；含 GPG 指纹校验）。
pub mod repo;
pub mod firewall;
pub mod metrics;
pub mod scheduler;
pub mod security;
pub mod services;
pub mod stub;
pub mod terminal;

use crate::{
    paths::LinuxPathLayout,
    traits::*,
};
use panel_core::{PlatformInfo, Result};
use std::sync::Arc;

/// 平台能力聚合（进程内单例，注入给业务层）
pub struct LinuxOsAdapter {
    pub paths: Arc<LinuxPathLayout>,
    pub metrics: Arc<metrics::LinuxMetrics>,
    pub services: Arc<services::LinuxServices>,
    pub firewall: Arc<firewall::LinuxFirewall>,
    pub packages: Arc<stub::LinuxPackages>,
    pub logs: Arc<stub::LinuxLogs>,
    pub scheduler: Arc<scheduler::LinuxScheduler>,
    pub security: Arc<security::LinuxSecurity>,
    pub webserver: Arc<stub::LinuxWebServer>,
    pub databases: Arc<stub::LinuxDatabases>,
    pub containers: Arc<containers::LinuxContainers>,
    pub terminal: Arc<terminal::LinuxTerminal>,
    pub users: Arc<stub::LinuxUsers>,
    pub network: Arc<stub::LinuxNetwork>,
    pub storage: Arc<stub::LinuxStorage>,
    pub files: Arc<files::LinuxFileProvider>,
    pub platform: PlatformInfo,
}

impl LinuxOsAdapter {
    pub fn new() -> Self {
        let paths = Arc::new(LinuxPathLayout::default());
        Self {
            metrics: Arc::new(metrics::LinuxMetrics::new()),
            services: Arc::new(services::LinuxServices::detect()),
            firewall: Arc::new(firewall::LinuxFirewall::detect()),
            packages: Arc::new(stub::LinuxPackages::detect()),
            logs: Arc::new(stub::LinuxLogs::detect(paths.clone())),
            scheduler: Arc::new(scheduler::LinuxScheduler::default()),
            security: Arc::new(security::LinuxSecurity),
            // webserver 需要路径布局（站点 conf 落盘到 web_conf_dir），故显式注入
            webserver: Arc::new(stub::LinuxWebServer::detect(paths.clone())),
            databases: Arc::new(stub::LinuxDatabases::default()),
            // 容器探测依赖 socket 路径（走 PathLayout，不硬编码），故注入 paths
            containers: Arc::new(containers::LinuxContainers::detect(paths.clone())),
            // 终端只需探测 shell 是否存在（纯文件检查），无需 paths
            terminal: Arc::new(terminal::LinuxTerminal::detect()),
            users: Arc::new(stub::LinuxUsers::default()),
            network: Arc::new(stub::LinuxNetwork::default()),
            storage: Arc::new(stub::LinuxStorage),
            files: Arc::new(files::LinuxFileProvider),
            platform: detect_platform(),
            paths,
        }
    }

    /// 用配置感知的路径布局构造适配器（覆盖 `site_root`/`data`/`log` 等）。
    /// **paths 会被注入 webserver / logs / containers**（均依赖路径布局），
    /// 必须与 `paths` 字段同源。
    /// `serve` 在加载配置后必须用它重建适配器，否则运行期 `site_root()` 等
    /// `[paths]` 覆盖不生效（落入 `LinuxPathLayout::default()` = /var/www）。
    pub fn with_paths(paths: Arc<LinuxPathLayout>) -> Self {
        let mut s = Self::new();
        s.webserver = Arc::new(stub::LinuxWebServer::detect(paths.clone()));
        s.logs = Arc::new(stub::LinuxLogs::detect(paths.clone()));
        s.containers = Arc::new(containers::LinuxContainers::detect(paths.clone()));
        s.paths = paths;
        s
    }
}

impl LinuxOsAdapter {
    pub fn files(&self) -> &Arc<files::LinuxFileProvider> { &self.files }
}

impl Default for LinuxOsAdapter { fn default() -> Self { Self::new() } }

/// 读取 /etc/os-release，避免硬编码发行版分支
pub fn detect_platform() -> PlatformInfo {
    let distro = std::fs::read_to_string("/etc/os-release").ok().and_then(|s| {
        let mut id = None; let mut ver = None;
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("ID=") { id = Some(v.trim_matches('"').to_string()); }
            if let Some(v) = line.strip_prefix("VERSION_ID=") { ver = Some(v.trim_matches('"').to_string()); }
        }
        match (id, ver) { (Some(i), Some(v)) => Some(format!("{i}:{v}")), _ => None }
    });
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|s| s.trim().to_string());
    PlatformInfo {
        os: panel_core::Os::Linux,
        arch: match std::env::consts::ARCH {
            "x86_64" => panel_core::Arch::X86_64,
            "aarch64" => panel_core::Arch::Aarch64,
            "arm" => panel_core::Arch::Armv7,
            _ => panel_core::Arch::X86,
        },
        init: services::LinuxServices::detect().init_system(),
        distro,
        kernel,
    }
}

/// 宿主规模探测（内存 MB / CPU 数）。只读 procfs，零子进程。
pub fn host_profile() -> (u64, u32) {
    let mem_mb = std::fs::read_to_string("/proc/meminfo").ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok()))
        .map(|kb| kb / 1024)
        .unwrap_or(1024);
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u32).unwrap_or(1);
    (mem_mb, cpus)
}

/// 数据目录文件系统检查：网络文件系统上 WAL 不可靠，必须拒绝启动（设计方案 §1.4-7）
pub fn check_data_dir_fs(path: &std::path::Path) -> Result<(String, bool)> {
    use std::ffi::CString;
    let Ok(c) = CString::new(path.to_string_lossy().as_bytes()) else {
        return Err(panel_core::PanelError::Internal("bad path".into()));
    };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(panel_core::PanelError::Internal("statfs failed".into()));
    }
    // 魔数：NFS_SUPER_MAGIC 0x6969 / CIFS 0xFF534D42 / 9P 0x01021997 / OVERLAYFS 0x794c7630
    let is_network = matches!(st.f_type as u64,
        0x6969 | 0xFF534D42 | 0x01021997 | 0x517B | 0xFE534D42);
    let name = match st.f_type as u64 {
        0xEF53 => "ext4/ext3/ext2",
        0x9123683E => "btrfs",
        0x58465342 => "xfs",
        0x794c7630 => "overlayfs",
        0x6969 => "nfs",
        0xFF534D42 => "cifs",
        _ => "unknown",
    };
    Ok((name.to_string(), is_network))
}
pub use files::{LinuxFileProvider, is_sensitive_path};
