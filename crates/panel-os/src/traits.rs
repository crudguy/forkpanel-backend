//! OS 抽象层的**全部对外契约**。
//!
//! 设计原则（设计方案 §0.3）：
//! 1. 定义"能做什么"（能力），而非"怎么做"（命令）—— 业务层禁止出现命令名。
//! 2. 写操作一律**声明式**：提交"期望的最终状态"（如 `RulePlan`），由平台实现翻译成
//!    `nft` / `iptables` / `netsh` / `pfctl` 的具体命令。这是跨平台零改动的根本保证。
//! 3. 所有可能阻塞的操作都是 async；所有返回路径的签名都使用 `SafePath`（已校验）。
//! 4. 不支持的能力返回 `PanelError::Unsupported`，**绝不能 panic 或返回空数据假装成功**。

use async_trait::async_trait;
use panel_core::{
    Capability, FirewallBackend, InitSystem, LogBackend, PlatformInfo, Result, SafePath,
    UnitName,
};
use std::{path::PathBuf, time::Duration};
use tokio::sync::mpsc::Receiver;

// ═══════════════════════════ 指标 ═══════════════════════════

// 注意：含 Option<Vec<f32>>，故不可派生 Copy（Vec 非 Copy）；需要复制时用 .clone()。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CpuSample {
    /// 总体使用率 0.0~100.0
    pub total_pct: f32,
    /// 每核使用率（低配档位可为空以省内存）
    pub per_core_pct: Option<Vec<f32>>,
    pub load1: f32,
    pub load5: f32,
    pub load15: f32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemSample {
    pub total_kib: u64,
    pub used_kib: u64,
    pub available_kib: u64,
    pub buffers_kib: u64,
    pub cached_kib: u64,
    pub swap_total_kib: u64,
    pub swap_used_kib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskSample {
    pub mount_point: PathBuf,
    pub device: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    /// 网络文件系统上 WAL 不可用，需据此告警（设计方案 §1.4-7）
    pub is_network_fs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetSample {
    pub iface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// 上次采样以来的速率（字节/秒），由实现计算
    pub rx_rate_bps: u64,
    pub tx_rate_bps: u64,
}

/// 一次完整采样快照（单点写入 ArcSwap，多 SSE 客户端共享，设计方案 §3.6-7）
#[derive(Debug, Clone, Default)]
pub struct SystemSnapshot {
    pub ts_unix: i64,
    pub uptime_sec: u64,
    pub cpu: CpuSample,
    pub mem: MemSample,
    pub disks: Vec<DiskSample>,
    pub nets: Vec<NetSample>,
    pub proc_count: u32,
    pub tcp_conns: u32,
}

#[async_trait]
pub trait MetricsProvider: Send + Sync {
    async fn snapshot(&self) -> Result<SystemSnapshot>;
    /// 进程列表：按需返回 Top-N，禁止全量扫描（实测 200 进程全扫描 3~10ms）
    async fn top_processes(&self, n: usize, sort: ProcessSort) -> Result<Vec<ProcessInfo>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSort { Cpu, Memory, Pid }

// 注意：cpu_pct 为 f32，不实现 Eq，故只派生 PartialEq。
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub name: String,
    pub cpu_pct: f32,
    pub rss_kib: u64,
    pub cmdline: String,
    pub user: Option<String>,
}

// ═══════════════════════════ 进程 ═══════════════════════════

/// 信号语义按平台解释（POSIX SIGTERM / Windows CTRL_CLOSE 等），业务层不得假设数值
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSignal { Terminate, Kill, Reload }

#[async_trait]
pub trait ProcessProvider: Send + Sync {
    async fn list(&self, limit: usize, sort: ProcessSort) -> Result<Vec<ProcessInfo>>;
    async fn signal(&self, pid: i32, sig: ProcessSignal) -> Result<()>;
    /// 面板必须能自我保护：拒绝信号自身与 pid 1
    async fn is_protected(&self, pid: i32) -> Result<bool>;
}

// ═══════════════════════════ 服务 ═══════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState { Active, Inactive, Failed, Activating, Deactivating, Unknown }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUnit {
    pub name: UnitName,
    pub description: String,
    pub state: ServiceState,
    pub enabled: bool,
    pub pid: Option<i32>,
    pub memory_kib: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceFilter {
    pub name_contains: Option<String>,
    pub state: Option<ServiceState>,
    pub only_panel_managed: bool,
}

#[derive(Debug, Clone)]
pub struct JournalQuery {
    pub lines: usize,
    pub since_secs: Option<u64>,
    pub grep: Option<String>,
    /// 是否跟随（SSE）
    pub follow: bool,
}

impl Default for JournalQuery {
    fn default() -> Self {
        Self { lines: 500, since_secs: None, grep: None, follow: false }
    }
}

#[async_trait]
pub trait ServiceProvider: Send + Sync {
    fn init_system(&self) -> InitSystem;
    async fn list(&self, filter: ServiceFilter) -> Result<Vec<ServiceUnit>>;
    async fn status(&self, name: &UnitName) -> Result<ServiceState>;
    async fn start(&self, name: &UnitName) -> Result<()>;
    async fn stop(&self, name: &UnitName) -> Result<()>;
    async fn restart(&self, name: &UnitName) -> Result<()>;
    async fn reload(&self, name: &UnitName) -> Result<()>;
    async fn set_enabled(&self, name: &UnitName, enabled: bool) -> Result<()>;
    /// 返回日志行接收端；调用方通过 SSE 转发
    async fn journal(&self, name: &UnitName, q: JournalQuery) -> Result<Receiver<String>>;
}

// ═══════════════════════════ 软件包 ═══════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    pub name: String,
    pub version: Option<String>,
    pub manager: String,
    pub binaries: Vec<PathBuf>,
}

#[async_trait]
pub trait PackageProvider: Send + Sync {
    fn manager(&self) -> Option<&'static str>;   // apt / dnf / apk / None
    async fn detect_installed(&self, names: &[&str]) -> Result<Vec<PackageInfo>>;
    /// 安装/卸载必须走任务队列（外部命令，耗时）；输出通过回调流式返回
    async fn install(&self, name: &str, on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()>;
    async fn remove(&self, name: &str) -> Result<()>;
}

// ═══════════════════════════ 防火墙（声明式） ═══════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action { Allow, Deny, Reject }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction { Inbound, Outbound }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol { Tcp, Udp, Icmp, Any }

/// 端口规格：解析自 "80,443,8000-8100"，业务层只传结构化数据
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub id: String,
    pub ports: PortSpec,
    pub protocol: Protocol,
    pub action: Action,
    pub direction: Direction,
    pub source_cidr: Option<String>,
    pub comment: Option<String>,
}

/// 期望的最终状态 —— 实现必须做到**幂等**（一致性测试会验证）
#[derive(Debug, Clone, Default)]
pub struct RulePlan {
    pub rules: Vec<FirewallRule>,
    /// 面板只管理自己写入的规则（以注释/标记识别），不得破坏用户既有规则
    pub replace_panel_managed_only: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ApplyReport {
    pub added: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub warnings: Vec<String>,
}

#[async_trait]
pub trait FirewallProvider: Send + Sync {
    fn backend(&self) -> FirewallBackend;
    async fn is_active(&self) -> Result<bool>;
    async fn set_active(&self, active: bool) -> Result<()>;
    async fn list_rules(&self) -> Result<Vec<FirewallRule>>;
    async fn apply(&self, plan: RulePlan) -> Result<ApplyReport>;
    /// 规则快照用于"误操作应急恢复"（防 SSH 失联，设计方案 §4-M5）
    async fn snapshot(&self) -> Result<Vec<u8>>;
    async fn restore_snapshot(&self, data: &[u8]) -> Result<()>;
}

// ═══════════════════════════ 网络 ═══════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: Protocol,
    pub addr: String,
    pub pid: Option<i32>,
    pub process: Option<String>,
}

#[async_trait]
pub trait NetworkProvider: Send + Sync {
    async fn interfaces(&self) -> Result<Vec<NetSample>>;
    async fn listening(&self) -> Result<Vec<ListeningPort>>;
}

// ═══════════════════════════ 系统用户 ═══════════════════════════

#[async_trait]
pub trait UserProvider: Send + Sync {
    async fn exists(&self, name: &str) -> Result<bool>;
    async fn ensure(&self, name: &str, system: bool, shell_nologin: bool) -> Result<()>;
    async fn uid_gid(&self, name: &str) -> Result<(u32, u32)>;
}

// ═══════════════════════════ 存储与权限 ═══════════════════════════

/// 权限变更的**不透明描述**：POSIX 是 mode+uid/gid，Windows 是 ACL，
/// 业务层不得假设 0o644 或 chown 语义
#[derive(Debug, Clone)]
pub enum PermissionOp {
    Posix { mode: u32, owner: Option<String>, group: Option<String> },
    Windows { inherit: bool, read_only: bool },
    Noop,
}

#[async_trait]
pub trait StorageProvider: Send + Sync {
    async fn mounts(&self) -> Result<Vec<DiskSample>>;
    /// 检测数据目录所在文件系统；网络文件系统上 WAL 不可靠，需拒绝启动
    async fn fs_type(&self, path: &std::path::Path) -> Result<(String, bool)>;
    async fn set_permissions(&self, path: &SafePath, op: PermissionOp) -> Result<()>;
    async fn set_owner_recursive(&self, path: &SafePath, user: &str) -> Result<()>;
}

// ═══════════════════════════ 日志 ═══════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSource {
    pub id: String,                 // "panel" | "system" | "service:nginx" | "site:xyz/access"
    pub label: String,
    pub kind: LogSourceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSourceKind { Panel, System, Service, SiteAccess, SiteError, CustomFile }

#[derive(Debug, Clone)]
pub struct LogQuery {
    pub lines: usize,               // 上限 2000（服务端硬限制）
    pub grep: Option<String>,
    pub level: Option<String>,
    pub follow: bool,
    pub since_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub ts_unix: Option<i64>,
    pub level: Option<String>,
    pub text: String,
}

#[async_trait]
pub trait LogProvider: Send + Sync {
    fn backend(&self) -> LogBackend;
    async fn sources(&self) -> Result<Vec<LogSource>>;
    /// 读历史（分页回溯）
    async fn read(&self, src: &LogSource, q: LogQuery) -> Result<Vec<LogLine>>;
    /// 实时跟随：返回接收端，服务端负责轮转检测与背压
    async fn follow(&self, src: &LogSource, q: LogQuery) -> Result<Receiver<LogLine>>;
}

// ═══════════════════════════ 计划任务 ═══════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJob {
    pub id: String,
    /// 表达式由平台实现校验（cron 5 段 / launchd 字典 / 任务计划 XML）
    pub expression: String,
    pub command: String,
    pub user: String,
    pub enabled: bool,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRun {
    pub started_unix: i64,
    pub finished_unix: i64,
    pub exit_code: Option<i32>,
    pub output_excerpt: String,
}

#[async_trait]
pub trait SchedulerProvider: Send + Sync {
    /// 校验表达式并返回**平台本地语义**的下次执行时间预览（供 UI 展示）
    fn validate_expression(&self, expr: &str) -> Result<()>;
    fn next_fire_times(&self, expr: &str, n: usize) -> Result<Vec<i64>>;
    async fn list(&self) -> Result<Vec<ScheduledJob>>;
    async fn upsert(&self, job: ScheduledJob) -> Result<()>;
    async fn remove(&self, id: &str) -> Result<()>;
    async fn runs(&self, id: &str, limit: usize) -> Result<Vec<JobRun>>;
}

// ═══════════════════════════ Web 服务器 ═══════════════════════════

/// 站点规格（业务层产出，平台实现渲染为具体服务器配置）
#[derive(Debug, Clone)]
pub struct SiteSpec {
    pub server_names: Vec<String>,
    pub root: PathBuf,
    pub listen: Vec<u16>,
    pub kind: SiteKind,
    pub access_log: Option<PathBuf>,
    pub error_log: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub force_https: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteKind { Static, ReverseProxy { upstream: &'static str } }

#[async_trait]
pub trait WebServerProvider: Send + Sync {
    fn name(&self) -> &'static str;                       // nginx / caddy / iis
    /// 渲染配置（纯字符串生成，不落盘）
    fn render(&self, spec: &SiteSpec) -> Result<(PathBuf, String)>;
    /// 写入前必须校验；失败时业务层回滚（设计方案 §2.4-4）
    async fn validate(&self, rendered: &str) -> Result<()>;
    async fn deploy(&self, target: &std::path::Path, content: &str) -> Result<()>;
    async fn reload(&self) -> Result<()>;
}

// ═══════════════════════════ 数据库引擎 ═══════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbEngine { Sqlite, MySql, Postgres }

#[derive(Debug, Clone)]
pub struct DbTarget {
    pub engine: DbEngine,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    /// 加密凭据（由业务层解密后传入）
    pub password: Option<String>,
    pub database: Option<String>,
}

#[async_trait]
pub trait DatabaseProvider: Send + Sync {
    fn engine(&self) -> DbEngine;
    /// 外部客户端缺失时返回 Unsupported，前端据此置灰
    async fn available(&self) -> Result<bool>;
    async fn databases(&self, t: &DbTarget) -> Result<Vec<String>>;
    async fn tables(&self, t: &DbTarget) -> Result<Vec<String>>;
    async fn backup(&self, t: &DbTarget, out: &SafePath,
                    on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()>;
    async fn restore(&self, t: &DbTarget, from: &SafePath) -> Result<()>;
}

// ═══════════════════════════ 能力声明 ═══════════════════════════

/// 每个 provider 都必须能自报能力，供 `OsAdapter::capabilities()` 汇总
pub trait Capable {
    fn capability(&self) -> Capability;
}

/// 平台信息 + 能力探测（进程内单例）
pub trait PlatformProbe: Send + Sync {
    fn platform(&self) -> PlatformInfo;
}

// ═══════════════════════════ 文件管理 ═══════════════════════════
//
// 为什么单独成 trait 而不是并入 StorageProvider：
// 文件树遍历、符号链接语义、大小写敏感性、权限位表达，在不同 OS 上差异极大。
// 若让 handler 直接用 std::fs，平台知识就泄漏进业务层了。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind { File, Dir, Symlink, Other }

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryKind,
    /// 字节（目录为 0）
    pub size: u64,
    /// POSIX 权限位；非 POSIX 平台为 None
    pub mode: Option<u32>,
    pub owner: Option<String>,
    pub modified_unix: i64,
    /// 符号链接指向（仅 Symlink）
    pub link_target: Option<String>,
    /// 是否命中平台敏感路径黑名单。
    /// **由 list_dir 顺带判定**：否则调用方得自己拼子路径再调 is_sensitive，
    /// 那意味着要绕过沙箱构造 SafePath（正是 CI 禁止的形态）。
    pub sensitive: bool,
}

#[derive(Debug, Clone)]
pub struct FileStat {
    pub kind: EntryKind,
    pub size: u64,
    pub mode: Option<u32>,
    pub owner: Option<String>,
    pub modified_unix: i64,
}

/// 目录列表排序
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortBy { #[default] Name, Size, Modified }

#[derive(Debug, Clone)]
pub struct ListOpt {
    /// 是否包含隐藏文件（以 . 开头）
    pub show_hidden: bool,
    pub sort: SortBy,
    /// 目录优先（类 ls / 文件管理器惯例）
    pub dirs_first: bool,
    /// 单次返回上限（防止百万文件目录把内存打爆）
    pub limit: usize,
}

impl Default for ListOpt {
    fn default() -> Self {
        Self { show_hidden: false, sort: SortBy::Name, dirs_first: true, limit: 1000 }
    }
}

#[async_trait]
pub trait FileProvider: Send + Sync {
    async fn list_dir(&self, dir: &SafePath, opt: ListOpt) -> Result<Vec<DirEntry>>;
    async fn stat(&self, path: &SafePath) -> Result<FileStat>;
    /// 读取文件内容。**必须**限制大小（大文件用 read_range 分块）
    async fn read(&self, path: &SafePath, max_bytes: usize) -> Result<Vec<u8>>;
    /// 分块读取（大文件预览 / 下载）
    async fn read_range(&self, path: &SafePath, offset: u64, len: usize) -> Result<Vec<u8>>;
    /// 写入。**必须**先写临时文件再原子替换，避免半写状态
    async fn write(&self, path: &SafePath, content: &[u8]) -> Result<()>;
    async fn append(&self, path: &SafePath, content: &[u8]) -> Result<()>;
    async fn create_dir(&self, path: &SafePath, recursive: bool) -> Result<()>;
    /// 删除。目录需递归；`allow_dir` 为 false 时拒绝删目录（防误删）
    async fn remove(&self, path: &SafePath, allow_dir: bool) -> Result<()>;
    /// 重命名 / 移动。**目标也必须在允许根内**，由调用方保证 SafePath
    async fn rename(&self, from: &SafePath, to: &SafePath) -> Result<()>;
    async fn copy(&self, from: &SafePath, to: &SafePath) -> Result<()>;
    /// 平台敏感路径黑名单判定（如 /etc/shadow）。**由平台实现决定**，业务层不硬编码
    fn is_sensitive(&self, path: &SafePath) -> bool;
    /// 单文件大小上限（上传与写入共用）
    fn max_file_bytes(&self) -> usize { 100 * 1024 * 1024 }
}
