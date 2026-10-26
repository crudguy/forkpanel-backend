//! macOS 的 16 个 provider —— **Phase 1 全部返回 `Unsupported`**。
//!
//! # 为什么单独成文件
//!
//! `mod.rs` 只留聚合与平台探测，把"每个 trait 的每个方法都显式返回 Unsupported"
//! 这部分机械代码隔离出来。好处有二：
//! 1. 分期实现时（Phase 2 起）**逐个替换**这里的 struct，不必翻阅聚合代码；
//! 2. 这 400 行是"能力边界清单"——审计时一眼能看出 macOS 上到底哪些还没做。
//!
//! # 诚实性约束
//!
//! 纪律同 `linux/stub/mod.rs:3`：**禁止**返回空 `Vec` / `Ok(())` 假装成功。
//! 返回 `Unsupported` 会让能力位置灰、前端隐藏入口；返回空集合则会让 UI 显示
//! "0 个进程""0 条规则"这类看起来正常实则可疑的状态——后者危险得多。
//!
//! `tests/conformance.rs` 契约 9 专门钉这条，且它对**任何**平台实现生效。

use crate::traits::*;
use async_trait::async_trait;
use panel_core::{PanelError, Result, SafePath, UnitName};

fn unimpl(what: &'static str) -> PanelError {
    PanelError::Unsupported(what)
}

// ═══════════════════════════ 指标 ═══════════════════════════

pub struct MacMetrics;

#[async_trait]
impl MetricsProvider for MacMetrics {
    async fn snapshot(&self) -> Result<SystemSnapshot> { Err(unimpl("macos.metrics.snapshot")) }
    async fn top_processes(&self, _n: usize, _sort: ProcessSort) -> Result<Vec<ProcessInfo>> {
        Err(unimpl("macos.metrics.top_processes"))
    }
}

// ═══════════════════════════ 进程 ═══════════════════════════

pub struct MacProcesses;

#[async_trait]
impl ProcessProvider for MacProcesses {
    async fn list(&self, _limit: usize, _sort: ProcessSort) -> Result<Vec<ProcessInfo>> {
        Err(unimpl("macos.processes.list"))
    }
    async fn signal(&self, _pid: i32, _sig: ProcessSignal) -> Result<()> {
        Err(unimpl("macos.processes.signal"))
    }
    /// ⚠ 与其它方法不同：`is_protected` **不返回 Unsupported**，而是如实判断 pid 1。
    ///
    /// 理由：这是 conformance 契约 6 明确要求的保护语义（"pid 1 必须被保护"），
    /// 且它的答案与平台无关——任何 POSIX 系统上 pid 1 都是 init，杀它等于关机。
    /// 返回 `Unsupported` 会让保护失效：调用方拿不到 true 就可能放行 kill，
    /// 那是一个"未实现"伪装成"可以杀"的危险降级。
    async fn is_protected(&self, pid: i32) -> Result<bool> {
        Ok(pid <= 1)
    }
}

// ═══════════════════════════ 服务 ═══════════════════════════

pub struct MacServices;

#[async_trait]
impl ServiceProvider for MacServices {
    /// init 系统恒为 launchd：这是 macOS 的事实，不是"探测结果"。
    /// 能力位仍报 no（服务管理未实现），前端因此置灰——两者不矛盾。
    fn init_system(&self) -> panel_core::InitSystem { panel_core::InitSystem::Launchd }

    async fn list(&self, _f: ServiceFilter) -> Result<Vec<ServiceUnit>> {
        Err(unimpl("macos.services.list"))
    }
    async fn status(&self, _n: &UnitName) -> Result<ServiceState> {
        Err(unimpl("macos.services.status"))
    }
    async fn statuses(&self, _n: &[UnitName]) -> Result<std::collections::HashMap<String, ServiceState>> {
        Err(unimpl("macos.services.statuses"))
    }
    async fn show(&self, _n: &UnitName) -> Result<Option<ServiceUnit>> {
        Err(unimpl("macos.services.show"))
    }
    async fn start(&self, _n: &UnitName) -> Result<()> { Err(unimpl("macos.services.start")) }
    async fn stop(&self, _n: &UnitName) -> Result<()> { Err(unimpl("macos.services.stop")) }
    async fn restart(&self, _n: &UnitName) -> Result<()> { Err(unimpl("macos.services.restart")) }
    async fn reload(&self, _n: &UnitName) -> Result<()> { Err(unimpl("macos.services.reload")) }
    async fn set_enabled(&self, _n: &UnitName, _e: bool) -> Result<()> {
        Err(unimpl("macos.services.set_enabled"))
    }
    async fn journal(&self, _n: &UnitName, _q: JournalQuery) -> Result<tokio::sync::mpsc::Receiver<String>> {
        Err(unimpl("macos.services.journal"))
    }
    async fn config_read(&self, _n: &UnitName, _t: ConfigTarget) -> Result<ServiceConfig> {
        Err(unimpl("macos.services.config_read"))
    }
    async fn config_write(&self, _n: &UnitName, _c: &str, _r: bool, _t: ConfigTarget) -> Result<()> {
        Err(unimpl("macos.services.config_write"))
    }
    async fn install_unit(&self, _n: &UnitName, _c: &str) -> Result<()> {
        Err(unimpl("macos.services.install_unit"))
    }
    async fn remove_unit(&self, _n: &UnitName) -> Result<()> {
        Err(unimpl("macos.services.remove_unit"))
    }
}

// ═══════════════════════════ 软件包 ═══════════════════════════

pub struct MacPackages;

#[async_trait]
impl PackageProvider for MacPackages {
    /// `None` = 无包管理器。Phase 4 接 Homebrew 后改为按 `brew` 存在性返回 `Some("brew")`。
    /// 现在返回 None 是**诚实**的：能力位据此置灰，前端不显示安装按钮。
    fn manager(&self) -> Option<&'static str> { None }

    async fn detect_installed(&self, _names: &[&str]) -> Result<Vec<PackageInfo>> {
        Err(unimpl("macos.packages.detect_installed"))
    }
    async fn install(&self, _n: &str, _v: Option<&str>, _on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        Err(unimpl("macos.packages.install"))
    }
    async fn remove(&self, _n: &str) -> Result<()> { Err(unimpl("macos.packages.remove")) }
    async fn list_versions(&self, _n: &str) -> Result<PackageVersions> {
        Err(unimpl("macos.packages.list_versions"))
    }
    async fn ensure_repo(&self, _l: &str, _on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        Err(unimpl("macos.packages.ensure_repo"))
    }
    async fn service_unit(&self, _n: &str) -> Result<Option<String>> {
        Err(unimpl("macos.packages.service_unit"))
    }
    async fn upgradable(&self, _names: &[&str]) -> Result<Vec<UpgradablePkg>> {
        Err(unimpl("macos.packages.upgradable"))
    }
    async fn holds(&self) -> Result<Vec<String>> { Err(unimpl("macos.packages.holds")) }
    async fn set_hold(&self, _n: &str, _h: bool) -> Result<()> {
        Err(unimpl("macos.packages.set_hold"))
    }
}

// ═══════════════════════════ 防火墙 ═══════════════════════════

pub struct MacFirewall;

#[async_trait]
impl FirewallProvider for MacFirewall {
    /// 后端声明为 `Pf`：这是 macOS 的事实（pf 是系统自带的包过滤器）。
    /// 但 `capability()` 报 no —— 声明后端 ≠ 已实现管理能力，两者必须分开。
    fn backend(&self) -> panel_core::FirewallBackend { panel_core::FirewallBackend::Pf }

    fn capability(&self) -> panel_core::Capability {
        panel_core::Capability::no("macos_firewall_未实现")
    }
    async fn is_active(&self) -> Result<bool> { Err(unimpl("macos.firewall.is_active")) }
    async fn set_active(&self, _a: bool) -> Result<()> { Err(unimpl("macos.firewall.set_active")) }
    async fn list_rules(&self) -> Result<Vec<FirewallRule>> { Err(unimpl("macos.firewall.list_rules")) }
    async fn apply(&self, _p: RulePlan) -> Result<ApplyReport> { Err(unimpl("macos.firewall.apply")) }
    async fn delete_rule(&self, _id: &str) -> Result<()> { Err(unimpl("macos.firewall.delete_rule")) }
    async fn snapshot(&self) -> Result<Vec<u8>> { Err(unimpl("macos.firewall.snapshot")) }
    async fn restore_snapshot(&self, _d: &[u8]) -> Result<()> { Err(unimpl("macos.firewall.restore_snapshot")) }
    fn fail2ban_capability(&self) -> panel_core::Capability {
        panel_core::Capability::no("fail2ban_无_macos_生态")
    }
    async fn fail2ban_status(&self) -> Result<Fail2banStatus> { Err(unimpl("macos.fail2ban.status")) }
    async fn fail2ban_set_jail(&self, _n: &str, _e: bool) -> Result<()> { Err(unimpl("macos.fail2ban.set_jail")) }
    async fn fail2ban_unban(&self, _j: &str, _ip: &str) -> Result<()> { Err(unimpl("macos.fail2ban.unban")) }
}

// ═══════════════════════════ 网络 ═══════════════════════════

pub struct MacNetwork;

#[async_trait]
impl NetworkProvider for MacNetwork {
    async fn interfaces(&self) -> Result<Vec<NetSample>> { Err(unimpl("macos.network.interfaces")) }
    async fn listening(&self) -> Result<Vec<ListeningPort>> { Err(unimpl("macos.network.listening")) }
}

// ═══════════════════════════ 系统用户 ═══════════════════════════

pub struct MacUsers;

#[async_trait]
impl UserProvider for MacUsers {
    async fn exists(&self, _n: &str) -> Result<bool> { Err(unimpl("macos.users.exists")) }
    async fn ensure(&self, _n: &str, _s: bool, _sh: bool) -> Result<()> { Err(unimpl("macos.users.ensure")) }
    async fn uid_gid(&self, _n: &str) -> Result<(u32, u32)> { Err(unimpl("macos.users.uid_gid")) }
    async fn list(&self) -> Result<Vec<SystemUser>> { Err(unimpl("macos.users.list")) }
}

// ═══════════════════════════ 存储 ═══════════════════════════

pub struct MacStorage;

#[async_trait]
impl StorageProvider for MacStorage {
    async fn mounts(&self) -> Result<Vec<DiskSample>> { Err(unimpl("macos.storage.mounts")) }
    async fn fs_type(&self, _p: &std::path::Path) -> Result<(String, bool)> {
        Err(unimpl("macos.storage.fs_type"))
    }
    async fn set_permissions(&self, _p: &SafePath, _op: PermissionOp) -> Result<()> {
        Err(unimpl("macos.storage.set_permissions"))
    }
    async fn set_owner_recursive(&self, _p: &SafePath, _u: &str) -> Result<()> {
        Err(unimpl("macos.storage.set_owner_recursive"))
    }
}

// ═══════════════════════════ 日志 ═══════════════════════════

pub struct MacLogs;

#[async_trait]
impl LogProvider for MacLogs {
    /// `File`：macOS 的日志主体是文件（`~/Library/Logs`、`/var/log`），
    /// 不是 journald。声明为 File 是为了后续 Phase 5 接文件日志时口径一致。
    fn backend(&self) -> panel_core::LogBackend { panel_core::LogBackend::File }

    async fn sources(&self) -> Result<Vec<LogSource>> { Err(unimpl("macos.logs.sources")) }
    async fn read(&self, _s: &LogSource, _q: LogQuery) -> Result<Vec<LogLine>> {
        Err(unimpl("macos.logs.read"))
    }
    async fn follow(&self, _s: &LogSource, _q: LogQuery) -> Result<tokio::sync::mpsc::Receiver<LogLine>> {
        Err(unimpl("macos.logs.follow"))
    }
}

// ═══════════════════════════ 计划任务 ═══════════════════════════

pub struct MacScheduler;

#[async_trait]
impl SchedulerProvider for MacScheduler {
    fn validate_expression(&self, _e: &str) -> Result<()> { Err(unimpl("macos.scheduler.validate")) }
    fn next_fire_times(&self, _e: &str, _n: usize) -> Result<Vec<i64>> {
        Err(unimpl("macos.scheduler.next_fire"))
    }
    async fn list(&self) -> Result<Vec<ScheduledJob>> { Err(unimpl("macos.scheduler.list")) }
    async fn upsert(&self, _j: ScheduledJob) -> Result<()> { Err(unimpl("macos.scheduler.upsert")) }
    async fn remove(&self, _id: &str) -> Result<()> { Err(unimpl("macos.scheduler.remove")) }
    async fn runs(&self, _id: &str, _l: usize) -> Result<Vec<JobRun>> { Err(unimpl("macos.scheduler.runs")) }
}

// ═══════════════════════════ Web 服务器 ═══════════════════════════

pub struct MacWebServer;

#[async_trait]
impl WebServerProvider for MacWebServer {
    fn name(&self) -> &'static str { "none" }
    fn conf_path(&self, _names: &[String]) -> std::path::PathBuf {
        // 纯路径计算不应失败，返回配置目录下的占位路径。
        // 注意：能力位为 no，此路径不会被真正写入。
        std::path::PathBuf::from("")
    }
    fn render(&self, _spec: &SiteSpec) -> Result<(std::path::PathBuf, String)> {
        Err(unimpl("macos.webserver.render"))
    }
    async fn validate(&self, _r: &str) -> Result<()> { Err(unimpl("macos.webserver.validate")) }
    async fn deploy(&self, _t: &std::path::Path, _c: &str) -> Result<()> {
        Err(unimpl("macos.webserver.deploy"))
    }
    async fn reload(&self) -> Result<()> { Err(unimpl("macos.webserver.reload")) }
}

// ═══════════════════════════ 数据库 ═══════════════════════════

pub struct MacDatabases;

#[async_trait]
impl DatabaseProvider for MacDatabases {
    /// 仍声明 `Sqlite`：SQLite 引擎是**面板内建**的（用 rusqlite，不调外部命令），
    /// 与平台无关。但 `supports()` 返回 false —— 浏览 UI 依赖外部客户端调用，
    /// Phase 5 接入后才亮。两者分开表述，避免"声明了引擎却不能用"的困惑。
    fn engine(&self) -> DbEngine { DbEngine::Sqlite }
    async fn available(&self) -> Result<bool> { Ok(false) }
    fn supports(&self, _e: DbEngine) -> bool { false }

    async fn databases(&self, _t: &DbTarget) -> Result<Vec<String>> { Err(unimpl("macos.databases.list")) }
    async fn tables(&self, _t: &DbTarget) -> Result<Vec<DbTable>> { Err(unimpl("macos.databases.tables")) }
    async fn rows(&self, _t: &DbTarget, _tb: &str, _l: usize, _o: usize) -> Result<DbRows> {
        Err(unimpl("macos.databases.rows"))
    }
    async fn query(&self, _t: &DbTarget, _s: &str, _l: usize) -> Result<DbQueryResult> {
        Err(unimpl("macos.databases.query"))
    }
    async fn backup(&self, _t: &DbTarget, _o: &SafePath, _on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        Err(unimpl("macos.databases.backup"))
    }
    async fn restore(&self, _t: &DbTarget, _f: &SafePath) -> Result<()> {
        Err(unimpl("macos.databases.restore"))
    }
}

// ═══════════════════════════ 安全基线 ═══════════════════════════

pub struct MacSecurity;

#[async_trait]
impl SecurityProvider for MacSecurity {
    async fn baseline(&self) -> Result<Vec<SecurityCheck>> { Err(unimpl("macos.security.baseline")) }
    async fn apply(&self, _key: &str) -> Result<SecurityApplyResult> {
        Err(unimpl("macos.security.apply"))
    }
}

// ═══════════════════════════ 容器 ═══════════════════════════

pub struct MacContainers;

#[async_trait]
impl ContainerProvider for MacContainers {
    fn engine(&self) -> ContainerEngine { ContainerEngine::None }
    fn available(&self) -> bool { false }
    fn unavailable_reason(&self) -> Option<&'static str> { Some("macos_containers_未实现") }

    async fn list(&self) -> Result<Vec<ContainerSummary>> { Err(unimpl("macos.containers.list")) }
    async fn images(&self) -> Result<Vec<ImageSummary>> { Err(unimpl("macos.containers.images")) }
    async fn act(&self, _a: ContainerAction, _id: &str) -> Result<()> { Err(unimpl("macos.containers.act")) }
    async fn create(&self, _r: ContainerCreateReq) -> Result<ContainerSummary> {
        Err(unimpl("macos.containers.create"))
    }
    async fn pull(&self, _i: &str) -> Result<ImageSummary> { Err(unimpl("macos.containers.pull")) }
    async fn logs(&self, _id: &str, _o: ContainerLogsOpts) -> Result<Vec<ContainerLogLine>> {
        Err(unimpl("macos.containers.logs"))
    }
    async fn stats_all(&self) -> Result<Vec<ContainerStatsLine>> { Err(unimpl("macos.containers.stats")) }
    async fn networks_all(&self) -> Result<Vec<ContainerNetworkLine>> { Err(unimpl("macos.containers.networks")) }
    async fn volumes_all(&self) -> Result<Vec<ContainerVolumeLine>> { Err(unimpl("macos.containers.volumes")) }
    async fn compose_projects_all(&self) -> Result<Vec<ContainerComposeProjectLine>> {
        Err(unimpl("macos.containers.compose_projects"))
    }
    async fn compose_act(&self, _a: ComposeAction, _p: &str, _w: Option<&str>) -> Result<()> {
        Err(unimpl("macos.containers.compose_act"))
    }
    async fn compose_stacks(&self) -> Result<Vec<ComposeStack>> { Err(unimpl("macos.containers.stacks")) }
    async fn compose_stack_get(&self, _p: &str) -> Result<ComposeStack> {
        Err(unimpl("macos.containers.stack_get"))
    }
    async fn compose_stack_save(&self, _s: ComposeStackSpec) -> Result<ComposeStack> {
        Err(unimpl("macos.containers.stack_save"))
    }
}

// ═══════════════════════════ 终端 ═══════════════════════════

pub struct MacTerminal;

/// 终端不返回 Unsupported，而是**如实报告不可用**：
/// `available()=false` + `shell()=None` 正是能力位 `no` 的数据来源。
/// 返回 Unsupported 在这里没有意义——这两个方法本身不执行任何操作。
impl TerminalProvider for MacTerminal {
    fn available(&self) -> bool { false }
    fn shell(&self) -> Option<crate::cmd::Bin> { None }
}

// ═══════════════════════════ 文件 ═══════════════════════════

pub struct MacFiles;

#[async_trait]
impl FileProvider for MacFiles {
    async fn list_dir(&self, _d: &SafePath, _o: ListOpt) -> Result<Vec<DirEntry>> {
        Err(unimpl("macos.files.list_dir"))
    }
    async fn stat(&self, _p: &SafePath) -> Result<FileStat> { Err(unimpl("macos.files.stat")) }
    async fn read(&self, _p: &SafePath, _m: usize) -> Result<Vec<u8>> { Err(unimpl("macos.files.read")) }
    async fn read_range(&self, _p: &SafePath, _o: u64, _l: usize) -> Result<Vec<u8>> {
        Err(unimpl("macos.files.read_range"))
    }
    async fn write(&self, _p: &SafePath, _c: &[u8]) -> Result<()> { Err(unimpl("macos.files.write")) }
    async fn append(&self, _p: &SafePath, _c: &[u8]) -> Result<()> { Err(unimpl("macos.files.append")) }
    async fn merge_chunks(&self, _parts: &[std::path::PathBuf], _dst: &SafePath) -> Result<u64> {
        Err(unimpl("macos.files.merge_chunks"))
    }
    async fn create_dir(&self, _p: &SafePath, _r: bool) -> Result<()> {
        Err(unimpl("macos.files.create_dir"))
    }
    async fn remove(&self, _p: &SafePath, _a: bool) -> Result<()> { Err(unimpl("macos.files.remove")) }
    async fn rename(&self, _f: &SafePath, _t: &SafePath) -> Result<()> { Err(unimpl("macos.files.rename")) }
    async fn copy(&self, _f: &SafePath, _t: &SafePath) -> Result<()> { Err(unimpl("macos.files.copy")) }

    /// ⚠ 这两个方法**不返回 Unsupported**：它们是 `bool` 返回值的判定函数，
    /// 且与 conformance 契约 10（路径沙箱）的安全语义直接相关。
    ///
    /// 返回 `true`（"是敏感的"）是**保守方向**：文件功能未实现时，宁可多挡也不漏挡。
    /// 返回 false 会让将来接文件功能时，敏感路径判定形同虚设。
    /// 真正的 macOS 黑名单（`/System`、`/Library/LaunchDaemons`、`/etc/sudoers` 等）
    /// 在 Phase 3 接入时补全。
    fn is_sensitive(&self, _p: &SafePath) -> bool { true }
    fn is_sensitive_path(&self, _p: &std::path::Path) -> bool { true }
}
