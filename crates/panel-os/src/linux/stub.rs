//! 未实现能力的**显式 stub** 与少量轻量实现。
//!
//! 纪律：未实现的能力必须返回 `PanelError::Unsupported`，**禁止**返回空 Vec 或 Ok(())
//! 假装成功——那会让 UI 显示错误状态，是"假装可移植"的典型表现。

use crate::traits::*;
use async_trait::async_trait;
use panel_core::{Capability, FirewallBackend, LogBackend, PanelError, Result, SafePath, UnitName};
use std::path::PathBuf;

macro_rules! unsupported {
    ($what:expr) => { Err(PanelError::Unsupported($what)) };
}

// ───────────────── 进程（复用 metrics 的快照状态） ─────────────────

#[async_trait]
impl ProcessProvider for crate::linux::metrics::LinuxMetrics {
    async fn list(&self, limit: usize, sort: ProcessSort) -> Result<Vec<ProcessInfo>> {
        self.top_processes(limit, sort).await
    }

    async fn signal(&self, pid: i32, sig: ProcessSignal) -> Result<()> {
        if self.is_protected(pid).await? {
            return Err(PanelError::PermissionDenied("process.signal: protected pid"));
        }
        let signo: i32 = match sig {
            ProcessSignal::Terminate => 15,   // SIGTERM（语义由平台解释，不暴露数值给业务层）
            ProcessSignal::Kill => 9,
            ProcessSignal::Reload => 1,
        };
        unsafe {
            if libc::kill(pid, signo) != 0 {
                return Err(PanelError::Command {
                    bin: "kill".into(),
                    detail: format!("kill({pid}, {signo}) failed"),
                });
            }
        }
        Ok(())
    }

    async fn is_protected(&self, pid: i32) -> Result<bool> {
        // pid 1 与面板自身不可终止
        Ok(pid <= 1 || pid == std::process::id() as i32)
    }
}

// ───────────────── 网络 ─────────────────

#[derive(Default)]
pub struct LinuxNetwork;

#[async_trait]
impl NetworkProvider for LinuxNetwork {
    async fn interfaces(&self) -> Result<Vec<NetSample>> {
        let s = tokio::fs::read_to_string("/proc/net/dev").await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        let mut out = Vec::new();
        for line in s.lines().skip(2) {
            let mut it = line.split_whitespace();
            let iface = match it.next() { Some(v) => v.trim_end_matches(':').to_string(), None => continue };
            let f: Vec<u64> = it.filter_map(|v| v.parse().ok()).collect();
            if f.len() < 10 { continue; }
            out.push(NetSample { iface, rx_bytes: f[0], tx_bytes: f[8], rx_rate_bps: 0, tx_rate_bps: 0 });
        }
        Ok(out)
    }

    /// 监听端口：M5 实现（解析 /proc/net/tcp + inode→pid 映射成本较高）
    async fn listening(&self) -> Result<Vec<ListeningPort>> { unsupported!("network.listening (M5)") }
}

// ───────────────── 存储 ─────────────────

pub struct LinuxStorage;

#[async_trait]
impl StorageProvider for LinuxStorage {
    async fn mounts(&self) -> Result<Vec<DiskSample>> {
        crate::linux::metrics::LinuxMetrics::new().snapshot().await.map(|s| s.disks)
    }

    async fn fs_type(&self, path: &std::path::Path) -> Result<(String, bool)> {
        crate::linux::check_data_dir_fs(path)
    }

    async fn set_permissions(&self, path: &SafePath, op: PermissionOp) -> Result<()> {
        match op {
            PermissionOp::Posix { mode, .. } => {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(mode)).await
                    .map_err(|e| PanelError::Internal(e.to_string()))
            }
            PermissionOp::Windows { .. } => unsupported!("storage.permissions: not a POSIX platform"),
            PermissionOp::Noop => Ok(()),
        }
    }

    async fn set_owner_recursive(&self, _path: &SafePath, _user: &str) -> Result<()> {
        // M4：需降权子进程执行 chown -R，且必须先校验路径在允许根内
        unsupported!("storage.set_owner_recursive (M4)")
    }
}

// ───────────────── 防火墙（M5） ─────────────────

pub struct LinuxFirewall { backend: FirewallBackend }

impl LinuxFirewall {
    pub fn detect() -> Self {
        let backend = if which("nft") { FirewallBackend::Nftables }
            else if which("iptables") { FirewallBackend::Iptables }
            else if which("ufw") { FirewallBackend::Ufw }
            else if which("firewall-cmd") { FirewallBackend::Firewalld }
            else { FirewallBackend::None };
        Self { backend }
    }
}

fn which(name: &str) -> bool {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"].iter()
        .any(|d| std::path::Path::new(d).join(name).is_file())
}

#[async_trait]
impl FirewallProvider for LinuxFirewall {
    fn backend(&self) -> FirewallBackend { self.backend }
    async fn is_active(&self) -> Result<bool> { unsupported!("firewall.status (M5)") }
    async fn set_active(&self, _a: bool) -> Result<()> { unsupported!("firewall.set_active (M5)") }
    async fn list_rules(&self) -> Result<Vec<FirewallRule>> { unsupported!("firewall.list (M5)") }
    async fn apply(&self, _plan: RulePlan) -> Result<ApplyReport> { unsupported!("firewall.apply (M5)") }
    async fn snapshot(&self) -> Result<Vec<u8>> { unsupported!("firewall.snapshot (M5)") }
    async fn restore_snapshot(&self, _d: &[u8]) -> Result<()> { unsupported!("firewall.restore (M5)") }
}

impl Capable for LinuxFirewall {
    fn capability(&self) -> Capability {
        match self.backend {
            FirewallBackend::None => Capability::no("binary_missing"),
            b => Capability::yes(&format!("{b:?}").to_lowercase()),
        }
    }
}

// ───────────────── 包管理（M2） ─────────────────

pub struct LinuxPackages { manager: Option<&'static str> }

impl LinuxPackages {
    pub fn detect() -> Self {
        let manager = if which("apt-get") { Some("apt") }
            else if which("dnf") { Some("dnf") }
            else if which("yum") { Some("yum") }
            else if which("apk") { Some("apk") }
            else if which("zypper") { Some("zypper") }
            else { None };
        Self { manager }
    }
}

#[async_trait]
impl PackageProvider for LinuxPackages {
    fn manager(&self) -> Option<&'static str> { self.manager }
    async fn detect_installed(&self, _names: &[&str]) -> Result<Vec<PackageInfo>> { unsupported!("package.detect (M2)") }
    async fn install(&self, _n: &str, _cb: Box<dyn Fn(String) + Send + Sync>) -> Result<()> { unsupported!("package.install (M2)") }
    async fn remove(&self, _n: &str) -> Result<()> { unsupported!("package.remove (M2)") }
}

// ───────────────── 日志（M5） ─────────────────

#[derive(Default)]
pub struct LinuxLogs { backend: Option<LogBackend> }

#[async_trait]
impl LogProvider for LinuxLogs {
    fn backend(&self) -> LogBackend { self.backend.unwrap_or(LogBackend::File) }
    async fn sources(&self) -> Result<Vec<LogSource>> { unsupported!("logs.sources (M5)") }
    async fn read(&self, _s: &LogSource, _q: LogQuery) -> Result<Vec<LogLine>> { unsupported!("logs.read (M5)") }
    async fn follow(&self, _s: &LogSource, _q: LogQuery) -> Result<tokio::sync::mpsc::Receiver<LogLine>> {
        unsupported!("logs.follow (M5)")
    }
}

// ───────────────── 计划任务（M5） ─────────────────

#[derive(Default)]
pub struct LinuxScheduler;

#[async_trait]
impl SchedulerProvider for LinuxScheduler {
    fn validate_expression(&self, _e: &str) -> Result<()> { unsupported!("cron.validate (M5)") }
    fn next_fire_times(&self, _e: &str, _n: usize) -> Result<Vec<i64>> { unsupported!("cron.preview (M5)") }
    async fn list(&self) -> Result<Vec<ScheduledJob>> { unsupported!("cron.list (M5)") }
    async fn upsert(&self, _j: ScheduledJob) -> Result<()> { unsupported!("cron.upsert (M5)") }
    async fn remove(&self, _i: &str) -> Result<()> { unsupported!("cron.remove (M5)") }
    async fn runs(&self, _i: &str, _l: usize) -> Result<Vec<JobRun>> { unsupported!("cron.runs (M5)") }
}

// ───────────────── Web 服务器（M3） ─────────────────

pub struct LinuxWebServer { name: Option<&'static str> }

impl LinuxWebServer {
    pub fn detect() -> Self {
        let name = if which("nginx") { Some("nginx") } else if which("caddy") { Some("caddy") } else { None };
        Self { name }
    }
}

#[async_trait]
impl WebServerProvider for LinuxWebServer {
    fn name(&self) -> &'static str { self.name.unwrap_or("none") }
    fn render(&self, _spec: &SiteSpec) -> Result<(PathBuf, String)> { unsupported!("webserver.render (M3)") }
    async fn validate(&self, _r: &str) -> Result<()> { unsupported!("webserver.validate (M3)") }
    async fn deploy(&self, _t: &std::path::Path, _c: &str) -> Result<()> { unsupported!("webserver.deploy (M3)") }
    async fn reload(&self) -> Result<()> { unsupported!("webserver.reload (M3)") }
}

// ───────────────── 数据库（M4） ─────────────────

#[derive(Default)]
pub struct LinuxDatabases;

#[async_trait]
impl DatabaseProvider for LinuxDatabases {
    fn engine(&self) -> DbEngine { DbEngine::Sqlite }
    async fn available(&self) -> Result<bool> { Ok(true) }   // SQLite 内建，始终可用
    async fn databases(&self, _t: &DbTarget) -> Result<Vec<String>> { unsupported!("dbms.databases (M4)") }
    async fn tables(&self, _t: &DbTarget) -> Result<Vec<String>> { unsupported!("dbms.tables (M4)") }
    async fn backup(&self, _t: &DbTarget, _o: &SafePath, _cb: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        unsupported!("dbms.backup (M4)")
    }
    async fn restore(&self, _t: &DbTarget, _f: &SafePath) -> Result<()> { unsupported!("dbms.restore (M4)") }
}

// ───────────────── 系统用户（M3） ─────────────────

#[derive(Default)]
pub struct LinuxUsers;

#[async_trait]
impl UserProvider for LinuxUsers {
    async fn exists(&self, name: &str) -> Result<bool> {
        // 读 /etc/passwd 而非 spawn getent：零子进程
        let s = tokio::fs::read_to_string("/etc/passwd").await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        Ok(s.lines().any(|l| l.split(':').next() == Some(name)))
    }
    async fn ensure(&self, _n: &str, _s: bool, _l: bool) -> Result<()> { unsupported!("user.ensure (M3)") }
    async fn uid_gid(&self, _n: &str) -> Result<(u32, u32)> { unsupported!("user.uid_gid (M3)") }
}

// 未在 stub 中使用的导入显式标记，避免 dead_code 警告干扰评审
#[allow(dead_code)]
fn _assert_types(_: Option<UnitName>) {}
