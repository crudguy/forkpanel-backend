//! OS 抽象层的**全部对外契约**。
//!
//! 设计原则（设计方案 §0.3）：
//! 1. 定义"能做什么"（能力），而非"怎么做"（命令）—— 业务层禁止出现命令名。
//! 2. 写操作一律**声明式**：提交"期望的最终状态"（如 `RulePlan`），由平台实现翻译成
//!    `nft` / `iptables` / `netsh` / `pfctl` 的具体命令。这是跨平台零改动的根本保证。
//! 3. 所有可能阻塞的操作都是 async；所有返回路径的签名都使用 `SafePath`（已校验）。
//! 4. 不支持的能力返回 `PanelError::Unsupported`，**绝不能 panic 或返回空数据假装成功**。

use async_trait::async_trait;
use serde::Serialize;
use panel_core::{
    Capability, FirewallBackend, InitSystem, LogBackend, PlatformInfo, Result, SafePath,
    UnitName,
};
use std::{path::PathBuf, time::Duration};
use tokio::sync::mpsc::Receiver;

// ═══════════════════════════ 指标 ═══════════════════════════

// 注意：含 Option<Vec<f32>>，故不可派生 Copy（Vec 非 Copy）；需要复制时用 .clone()。
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CpuSample {
    /// 总体使用率 0.0~100.0
    pub total_pct: f32,
    /// 每核使用率（低配档位可为空以省内存）
    pub per_core_pct: Option<Vec<f32>>,
    pub load1: f32,
    pub load5: f32,
    pub load15: f32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MemSample {
    pub total_kib: u64,
    pub used_kib: u64,
    pub available_kib: u64,
    pub buffers_kib: u64,
    pub cached_kib: u64,
    pub swap_total_kib: u64,
    pub swap_used_kib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskSample {
    pub mount_point: PathBuf,
    pub device: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    /// 网络文件系统上 WAL 不可用，需据此告警（设计方案 §1.4-7）
    pub is_network_fs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetSample {
    pub iface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// 上次采样以来的速率（字节/秒），由实现计算
    pub rx_rate_bps: u64,
    pub tx_rate_bps: u64,
}

/// 温度传感器读数（取自 `/sys/class/hwmon`，内核以**毫摄氏度**暴露）。
///
/// 采集是**尽力而为**的：没有 hwmon 的机器（多数虚拟机、部分云主机）返回空列表，
/// 这属于正常情况而非故障——因此不报错，也不伪造 `0°C`。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TempSample {
    /// 传感器芯片名（hwmon 的 `name`，如 `coretemp` / `k10temp` / `nvme` / `acpitz`）
    pub chip: String,
    /// 通道标签（`tempN_label`；缺失时回退为 `tempN`，绝不凭空命名）
    pub label: String,
    /// 摄氏度（内核值 / 1000）
    pub celsius: f64,
    /// 是否达到 `tempN_crit` 阈值；读不到 crit 时恒 `false`（不臆测告警）
    pub critical: bool,
}

/// 一次完整采样快照（单点写入 ArcSwap，多 SSE 客户端共享，设计方案 §3.6-7）
#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemSnapshot {
    pub ts_unix: i64,
    pub uptime_sec: u64,
    pub cpu: CpuSample,
    pub mem: MemSample,
    pub disks: Vec<DiskSample>,
    pub nets: Vec<NetSample>,
    pub proc_count: u32,
    pub tcp_conns: u32,
    /// 温度传感器（无 hwmon 时为空数组）
    pub temps: Vec<TempSample>,
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
#[derive(Debug, Clone, PartialEq, Serialize)]
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

/// 服务配置的读写目标。
///
/// 为什么有两种：直接改写单元文件（尤其位于 `/lib`、`/usr/lib` 的发行版文件）
/// 会在**软件包升级时被覆盖**；systemd 的 drop-in 机制
/// （`/etc/systemd/system/<unit>.d/override.conf`）与单元文件合并生效、
/// 不被包升级覆盖，是官方推荐做法。
///
/// 用枚举而非布尔（`drop_in: bool`）：与项目"多档操作用显式联合类型"的约定一致——
/// 布尔会让"目标是哪个"散落在读与写两处判断里，将来加第三种目标必漏。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigTarget {
    /// 单元文件本体（`systemctl show -p FragmentPath`）
    Unit,
    /// `/etc/systemd/system/<unit>.d/override.conf`
    DropIn,
}

/// 服务单元文件（配置）快照。
///
/// 对 systemd：来自 `systemctl show -p FragmentPath` 指向的文件，或 drop-in 文件。
/// `writable=false` 表示该文件位于发行版目录（如 `/lib/systemd/system/`、
/// `/usr/lib/systemd/system/`）——可直接改但**包升级时会被覆盖**，
/// 业务层据此提示用户改用 drop-in（`/etc/systemd/system/<unit>.d/`）。
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// 单元文件绝对路径
    pub path: String,
    /// 文件内容（UTF-8；非 UTF-8 文件由底层转换为替换字符）
    pub content: String,
    /// 是否位于用户可覆盖目录（`/etc/systemd/` 下）
    pub writable: bool,
    /// 该文件当前是否存在（drop-in 目标下可为 false＝"保存即新建"）
    pub exists: bool,
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
    /// 读取服务配置（修改配置功能的数据源）。
    /// 非 systemd 或无可编辑配置时返回 Unsupported。
    /// `target=DropIn` 且文件尚不存在时，返回空 `content` + `exists=false`（待新建），
    /// 而非报错——否则用户永远无法通过面板新建 drop-in。
    async fn config_read(&self, name: &UnitName, target: ConfigTarget) -> Result<ServiceConfig>;
    /// 写回配置并经 `daemon-reload` 重新加载；`restart` 为真时随后重启服务。
    /// 写入前自动备份为 `<path>.panel.bak`，并原子替换（先写临时文件再 rename）。
    async fn config_write(&self, name: &UnitName, content: &str, restart: bool, target: ConfigTarget) -> Result<()>;
}

// ═══════════════════════════ 软件包 ═══════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    pub name: String,
    pub version: Option<String>,
    pub manager: String,
    pub binaries: Vec<PathBuf>,
}

/// 某包的可安装版本集合。
///
/// `installed` 由包管理器自己给出（apt policy 的 `Installed:` 行），比前端拿
/// "已安装列表"去反查更可靠——逻辑名与真实包名不一致时（如 php-fpm ↔ php8.4-fpm）
/// 前端反查会漏，而 apt 永远知道本机实际装的是哪一个。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageVersions {
    pub versions: Vec<String>,          // 可供安装的版本（新→旧）
    pub installed: Option<String>,      // 当前已安装版本；未安装为 None
}

/// 某个已安装包存在可用更新的信息（由包管理器的 upgradable 列表派生）。
///
/// 只报**白名单内**的包：探测结果直接驱动 UI 的「有新版」徽标与更新按钮，
/// 若不过滤，用户会看到几百个自己并未在面板里管的系统库冒出来。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradablePkg {
    /// 真实包名（包管理器口径，如 `redis-server`）。
    pub name: String,
    /// 当前已安装版本。
    pub current: String,
    /// 可升级到的版本。
    pub candidate: String,
    /// 是否跨主版本升级（current 与 candidate 首段数字不同）。
    ///
    /// 跨主版本升级（如 PostgreSQL 17→18、Node.js 20→24）可能**不向后兼容**，
    /// 需要数据迁移（`pg_upgrade` / 逻辑备份恢复）或服务重配，升级前必须二次确认；
    /// 而仅次/修订版本变化（如 Redis 8.0.2→8.10.2、Nginx 1.26→1.30、Node 18→18.x）
    /// 是常规维护，可直接升级。后端据此在升级接口强制确认、前端弹窗警告。
    pub major: bool,
}

/// 两个版本号是否跨主版本（首段数字不同）——用于升级前风险判定。
///
/// 规则：先剥 epoch（`N:` 前缀，Debian 版本常见如 `5:8.0.2`），再取开头连续数字段
/// 作主版本号比较：
/// - `17+278` vs `18+293.pgdg13+1` → 17≠18（PostgreSQL 跨主版本，需数据迁移）
/// - `5:8.0.2` vs `5:8.10.2` → 8=8（仅次版本，常规升级）
/// - `1.26.3` vs `1.30.5` → 1=1（仅次版本）
/// - `20.19.0` vs `24.21.0` → 20≠24（Node.js 跨主版本）
///
/// 任一无法解析主版本号时返回 `false`（保守：解析不出就**不**当作跨主版本，
/// 避免把可安全升级的包误判成高风险而阻断）。`stub.rs` 解析与 `services.rs`
/// 升级守卫共用本函数，避免两处各写一份漂移。
pub fn version_major_jump(a: &str, b: &str) -> bool {
    let major = |v: &str| -> Option<u32> {
        // 剥 epoch：取最后一个 ':' 之后的部分（无 ':' 时即原串）
        let v = v.split(':').last().unwrap_or(v);
        // 取开头连续数字段作主版本号（'17+278' → 17，'1.26.3' → 1）
        let digits: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u32>().ok()
    };
    match (major(a), major(b)) {
        (Some(x), Some(y)) => x != y,
        _ => false,
    }
}

#[async_trait]
pub trait PackageProvider: Send + Sync {
    fn manager(&self) -> Option<&'static str>;   // apt / dnf / apk / None
    async fn detect_installed(&self, names: &[&str]) -> Result<Vec<PackageInfo>>;
    /// 安装/卸载必须走任务队列（外部命令，耗时）；输出通过回调流式返回
    async fn install(&self, name: &str, version: Option<&str>, on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()>;
    async fn remove(&self, name: &str) -> Result<()>;
    /// 列出该包在**当前已配置软件源**里可供安装的版本（由新到旧）。
    ///
    /// 用途：安装弹窗把它渲染成下拉选项，用户点选而不必手输——手输版本号极易出错
    /// （Debian 版本号形如 `1.26.3-3+deb13u9`，含 epoch/修订号，凭记忆写几乎必错）。
    /// 返回空列表表示"查不到"，调用方应退回"装最新版"，不应视为错误。
    async fn list_versions(&self, name: &str) -> Result<PackageVersions>;
    /// 安装第三方官方源包前，确保对应的第三方 apt 源已就绪
    /// （下载并校验 GPG 密钥指纹、写隔离 keyring + sources.list.d，再 apt-get update）。
    ///
    /// 仅对 `third_party_repo(logical)` 命中且当前为 apt 的包生效；其它情况
    /// （白名单内普通包、非 apt 发行版、无第三方源的包如 minio）为 no-op，直接返回 Ok，
    /// 不影响既有安装路径。调用方应在 `install` 之前调用，加源失败即中止安装。
    async fn ensure_repo(&self, logical: &str, on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()>;
    /// 列出**已安装且源里有新版**的包（只读探测，不改动系统）。
    ///
    /// 供 UI 显示「有新版」徽标。返回空列表表示"无可升级项"，**不是错误**
    /// （多数机器本来就没有可升级的白名单包）。查不到（无包管理器/命令缺失）同样返回空列表，
    /// 调用方据此隐藏入口而不是报错——探测失败不该让整页软件列表挂掉。
    async fn upgradable(&self) -> Result<Vec<UpgradablePkg>>;
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
    /// 多个端口规格的组合（如 "80,443,8000-8100"）。ufw 接受逗号分隔的端口/区间列表，
    /// 因此渲染为 `80,443,8000:8100` 即可在单条规则内表达混合规格。
    List(Vec<PortSpec>),
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
    /// 是否为面板自身写入的规则（"只删自己写的"守卫依据）
    pub panel_managed: bool,
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

/// fail2ban 监狱（jail）状态——防 SSH 等服务被暴力破解的封禁统计。
#[derive(Debug, Clone, Default, Serialize)]
pub struct Fail2banJail {
    pub name: String,
    pub enabled: bool,
    pub currently_failed: u32,
    pub total_failed: u32,
    pub banned: u32,
    pub banned_ips: Vec<String>,
}

/// fail2ban 总览。
#[derive(Debug, Clone, Default, Serialize)]
pub struct Fail2banStatus {
    /// fail2ban-client 是否存在（二进制缺失则整功能不可用）
    pub available: bool,
    /// fail2ban 服务是否运行中
    pub active: bool,
    pub jails: Vec<Fail2banJail>,
}

#[async_trait]
pub trait FirewallProvider: Send + Sync {
    fn backend(&self) -> FirewallBackend;
    async fn is_active(&self) -> Result<bool>;
    async fn set_active(&self, active: bool) -> Result<()>;
    async fn list_rules(&self) -> Result<Vec<FirewallRule>>;
    async fn apply(&self, plan: RulePlan) -> Result<ApplyReport>;
    /// 删除单条规则。`id` 来自 `list_rules` 返回的 `FirewallRule.id`。
    /// 实现必须只允许删除面板自己创建的（由标记识别），拒绝删除用户既有规则。
    async fn delete_rule(&self, id: &str) -> Result<()>;
    /// 规则快照用于"误操作应急恢复"（防 SSH 失联，设计方案 §4-M5）
    async fn snapshot(&self) -> Result<Vec<u8>>;
    async fn restore_snapshot(&self, data: &[u8]) -> Result<()>;
    /// fail2ban 能力位（独立于防火墙后端，按 fail2ban-client 存在性判定）。
    fn fail2ban_capability(&self) -> Capability;
    /// 总览：可用性与各 jail 状态。
    async fn fail2ban_status(&self) -> Result<Fail2banStatus>;
    /// 启停某 jail（等价 `fail2ban-client set <jail> on/off`）。
    async fn fail2ban_set_jail(&self, name: &str, enabled: bool) -> Result<()>;
    /// 解封某 jail 下的某个 IP（等价 `fail2ban-client set <jail> unbanip <ip>`）。
    async fn fail2ban_unban(&self, jail: &str, ip: &str) -> Result<()>;
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
    /// 并发上限（防重入）。==1 时由 Linux 实现用 flock 互斥包裹命令；
    /// >1 或 0 表示不强制（OS 级 N>1 计数并发未实装，诚实标注）。
    pub max_overlap: u32,
    /// 完成/开始时回调的 Webhook URL（POST JSON）。None = 不发。
    pub webhook_url: Option<String>,
    /// 触发事件子集：`start` / `success` / `failure`，逗号分隔持久化，此处展开。
    pub webhook_events: Vec<String>,
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
    /// WAF 配置；`None` = 不生成任何拦截规则
    pub waf: Option<WafSpec>,
}

/// WAF 规则档位。
///
/// **规则集是编译期常量，用户只能选档位与数值**——刻意不开放"自定义正则"：
/// ① 让用户写原始 nginx 正则等于把配置注入面交出去；② 一条写坏的正则会让
/// `nginx -t` 拒绝**整份**配置，一个站点出错会连带全机站点加载失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafProfile {
    /// 基础：SQLi / XSS / 路径穿越 / 敏感文件探测 / 恶意 UA
    Basic,
    /// 严格：基础 + 空 UA / 非白名单方法 / 更宽的注入与扫描器关键词。
    /// **误杀概率随之上抬**，故不设为默认——安全的默认值应该是"够用且不误伤"。
    Strict,
}

impl WafProfile {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "basic" => Some(Self::Basic),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Strict => "strict",
        }
    }
}

/// 站点 WAF 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafSpec {
    pub profile: WafProfile,
    /// CC 限速：每秒请求数上限；`None` = 不限速
    pub rate_per_sec: Option<u32>,
    /// 突发桶容量（仅在 `rate_per_sec` 有值时生效）
    pub burst: u32,
}

/// 站点类型。
///
/// **刻意不再派生 `Copy`**：负载均衡与 PHP 需要携带动态字符串（后端列表 /
/// socket 路径），而 `&'static str` 只能表达硬编码常量——等于把配置能力
/// 锁死在编译期，用户在界面上永远改不了。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteKind {
    /// 纯静态文件
    Static,
    /// 反向代理 / 负载均衡：一个或多个后端。
    /// 多个后端时由 nginx `upstream` 块轮询（块必须置于 http 级，见 render 实现）。
    ReverseProxy { upstreams: Vec<String> },
    /// PHP：`fastcgi_pass` 到 php-fpm（`unix:/path.sock` 或 `host:port`）
    Php { fpm: String },
}

#[async_trait]
pub trait WebServerProvider: Send + Sync {
    fn name(&self) -> &'static str;                       // nginx / caddy / iis
    /// 渲染配置（纯字符串生成，不落盘）
    fn render(&self, spec: &SiteSpec) -> Result<(PathBuf, String)>;
    /// 写入前必须校验；失败时业务层回滚（设计方案 §2.4-4）
    async fn validate(&self, rendered: &str) -> Result<()>;
    async fn deploy(&self, target: &std::path::Path, content: &str) -> Result<()>;
    async fn reload(&self) -> Result<()>;
    /// 删除单个站点配置（按 apply 写入的 conf_path）。实现负责删除文件并 reload，
    /// 使站点"真正下线"。默认实现直接删文件（nginx 等需 reload 的后端应重载配置）。
    async fn remove(&self, conf_path: &std::path::Path) -> Result<()> {
        if conf_path.exists() {
            std::fs::remove_file(conf_path)
                .map_err(|e| panel_core::PanelError::Io(format!("remove {}: {e}", conf_path.display())))?;
        }
        Ok(())
    }
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

/// 表元信息（浏览用）：表名 + 行数（估算；无法取得时为 -1）
#[derive(Debug, Clone)]
pub struct DbTable {
    pub name: String,
    pub rows: i64,
}

/// 只读数据预览（分页）。值一律**字符串化**（NULL → None），保持引擎无关，
/// 避免在 OS 抽象层引入 JSON 类型；业务层按契约原样透出。
#[derive(Debug, Clone, Default)]
pub struct DbRows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    /// 总行数（用于分页器）
    pub total: i64,
}

/// 只读查询结果。**刻意与 [`DbRows`] 分开**：任意 SQL 的"总行数"无从得知，
/// 硬塞一个 `total` 只会逼实现去伪造数字。这里用 `truncated` 如实表达
/// "是否被行数上限截断"——这是唯一能诚实回答的问题。
#[derive(Debug, Clone)]
pub struct DbQueryResult {
    pub columns: Vec<String>,
    /// 最多 `limit` 行（超出部分已被丢弃）
    pub rows: Vec<Vec<Option<String>>>,
    /// 是否因行数上限被截断
    pub truncated: bool,
}

#[async_trait]
pub trait DatabaseProvider: Send + Sync {
    fn engine(&self) -> DbEngine;
    /// 外部客户端缺失时返回 Unsupported，前端据此置灰
    async fn available(&self) -> Result<bool>;
    /// 该引擎是否**已实装**（用于逐连接可用性判定与能力位；未实装返回 false 而非撒谎）
    fn supports(&self, e: DbEngine) -> bool;
    async fn databases(&self, t: &DbTarget) -> Result<Vec<String>>;
    /// 表列表（含行数）
    async fn tables(&self, t: &DbTarget) -> Result<Vec<DbTable>>;
    /// **只读**数据预览（分页）。`table` 由业务层校验后传入，实现内部仍须安全加引号。
    async fn rows(&self, t: &DbTarget, table: &str, limit: usize, offset: usize) -> Result<DbRows>;
    /// **只读**任意查询（SQL 控制台）。SQL 由业务层白名单校验后传入。
    ///
    /// 实现必须自己兜底只读：SQLite 用**只读连接**打开，即使上层校验被绕过
    /// 也物理写不进去（纵深防御）；没有只读保证的引擎应当直接返回 `Unsupported`，
    /// 而不是"先跑起来再说"——那等于给面板开了一个任意写库的口子。
    async fn query(&self, t: &DbTarget, sql: &str, limit: usize) -> Result<DbQueryResult>;
    async fn backup(&self, t: &DbTarget, out: &SafePath,
                    on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()>;
    async fn restore(&self, t: &DbTarget, from: &SafePath) -> Result<()>;
}

// ═══════════════════════════ 安全基线 ═══════════════════════════

/// 一条基线检查结果。`applicable=false` 表示**该环境不适用**（如未装 sshd），
/// 与"通过"（`ok=true`）语义不同——UI 据此显示为灰色而非绿色。
#[derive(Debug, Clone)]
pub struct SecurityCheck {
    /// 稳定标识（如 `ssh.permit_root_login`），一键修复按此定位
    pub key: String,
    pub title: String,
    /// 是否满足安全期望（`applicable=false` 时此值无意义）
    pub ok: bool,
    /// 当前实际值（人类可读）
    pub current: String,
    /// 期望值（人类可读）
    pub expected: String,
    /// 修复建议
    pub advice: String,
    pub applicable: bool,
}

/// 一键修复的结果。**必须携带备份路径**——修复出事时可回滚。
#[derive(Debug, Clone, Serialize)]
pub struct SecurityApplyResult {
    /// 是否实际改动（已符合预期时为 false，不写盘）
    pub changed: bool,
    /// 修改**前**的备份文件路径，用户可据此回滚
    pub backup: Option<std::path::PathBuf>,
    /// 是否通过了配置语法校验（如 `sshd -t`）
    pub validated: bool,
}

#[async_trait]
pub trait SecurityProvider: Send + Sync {
    /// **只读**安全基线扫描。实现**绝不修改系统**（修复是独立的高危操作）。
    async fn baseline(&self) -> Result<Vec<SecurityCheck>>;

    /// **高危写操作**：一键修复指定基线项。
    ///
    /// 纪律（实现必须遵守）：
    /// 1. **先备份**再写，备份路径回传；
    /// 2. 写完**必须校验**（如 `sshd -t`），校验失败**立刻回滚**；
    /// 3. 校验器不可用时应**拒绝修改**——宁可不修，也不制造"把人锁在门外"的配置；
    /// 4. 只修白名单内的项，未知 key 直接报错。
    async fn apply(&self, key: &str) -> Result<SecurityApplyResult>;
}

// ═══════════════════════════ 容器 ═══════════════════════════
//
// 关键诚实性约束：**CLI 二进制存在 ≠ 容器能力可用**。
// 真实环境里最常见的失败不是"没装 docker"，而是"装了但当前身份连不上 daemon"
// （不在 docker 组 / daemon 没起来）。所以能力判定看的是 **socket 可达性**，
// 而不是二进制存在性——否则 UI 会给用户一个"能点但一点就报错"的假按钮。

/// 容器引擎。只声明**已实装**的引擎：探测到别的（如仅 podman）应诚实置灰。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerEngine {
    Docker,
    None,
}

impl ContainerEngine {
    pub fn as_str(self) -> &'static str {
        match self { ContainerEngine::Docker => "docker", ContainerEngine::None => "none" }
    }
}

/// 容器摘要（等价 `docker ps -a` 的关键列；状态字段直接取 CLI 的人类可读值，
/// 不自行推算——`docker ps` 的 STATUS 已包含退出码与时长信息）。
#[derive(Debug, Clone, Serialize)]
pub struct ContainerSummary {
    /// 完整 ID（短 ID 在 UI 层裁剪展示）
    pub id: String,
    pub name: String,
    pub image: String,
    /// 归一化状态：running / exited / created / paused / restarting / dead
    pub state: String,
    /// 人类可读状态描述（如 `Up 3 hours`、`Exited (0) 2 days ago`）
    pub status: String,
    pub ports: String,
    pub created: String,
}

/// 镜像摘要（等价 `docker images`）。
#[derive(Debug, Clone, Serialize)]
pub struct ImageSummary {
    pub id: String,
    pub repository: String,
    pub tag: String,
    /// 人类可读体积（CLI 已格式化）
    pub size: String,
    pub created: String,
}

/// 容器生命周期动作。声明式——由平台实现翻译成具体 CLI 子命令，
/// 业务层不出现 `start`/`stop` 之类命令字面量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerAction {
    Start,
    Stop,
    Restart,
    Remove,
}

impl ContainerAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ContainerAction::Start => "start",
            ContainerAction::Stop => "stop",
            ContainerAction::Restart => "restart",
            ContainerAction::Remove => "remove",
        }
    }
}

/// 创建容器的请求。**结构化字段**：所有值经 provider 严格校验后翻译成固定 argv，
/// 任何用户原始串都不会直接拼进命令（防参数注入，与 `act` 同纪律）。
///
/// 安全约束（provider 层强制，业务层不得假设上游已校验）：
/// - `privileged` 必须为 false：等价宿主机 root，绝不允许经面板创建特权容器。
/// - `volumes` 不得挂载宿主敏感路径（`/`、`/etc`、`/var/run/docker.sock`、`/proc`、`/sys`）。
/// - `image` 必须命中字符集（不含 shell 元字符），且（若服务端配置了镜像白名单）必须命中。
/// - `cpu_quota` / `mem_limit` 提供资源配额，避免单容器吃满宿主。
#[derive(Debug, Clone, Default)]
pub struct ContainerCreateReq {
    pub name: String,
    pub image: String,
    /// 容器启动命令（覆盖镜像 ENTRYPOINT）；逐元素进 argv，不整体拼串。
    pub cmd: Vec<String>,
    /// 端口映射 `host:container[/proto]`，如 `8080:80/tcp`。
    pub ports: Vec<String>,
    /// 环境变量 `KEY=VALUE`，逐条进 `-e`。
    pub env: Vec<String>,
    /// 卷挂载 `src:dst[:ro]`，src 可为具名卷或宿主路径（宿主敏感路径被拒）。
    pub volumes: Vec<String>,
    /// 重启策略：`no` / `on-failure` / `always` / `unless-stopped`。
    pub restart: Option<String>,
    /// CPU 配额（核数，如 1.5 = 1.5 核）。
    pub cpu_quota: Option<f64>,
    /// 内存上限，CLI 单位串（如 `512m`、`2g`）。
    pub mem_limit: Option<String>,
    /// 必须为 false；为 true 时 provider 直接拒绝（等价宿主 root）。
    pub privileged: bool,
}

#[async_trait]
pub trait ContainerProvider: Send + Sync {
    fn engine(&self) -> ContainerEngine;
    /// 守护进程**真实可达**才为 true（socket 可连接）。
    /// 同步且廉价：能力矩阵在启动时求值一次，此处只做一次 connect 尝试。
    fn available(&self) -> bool;
    /// 不可用原因（`binary_missing` / `daemon_unreachable`），可用时为 None。
    /// UI 据此给出可操作的提示，而不是一句"不支持"。
    fn unavailable_reason(&self) -> Option<&'static str>;
    /// 列出全部容器（含已停止），等价 `docker ps -a`。
    async fn list(&self) -> Result<Vec<ContainerSummary>>;
    /// 列出镜像，等价 `docker images`。
    async fn images(&self) -> Result<Vec<ImageSummary>>;
    /// 执行生命周期动作。`id` 必须是容器 ID/名称，实现**必须**先校验字符集。
    async fn act(&self, action: ContainerAction, id: &str) -> Result<()>;
    /// 创建容器（等价 `docker create`，**不自动运行**）。`privileged`/宿主挂载/镜像
    /// 白名单等安全约束由实现强制；返回新建容器的摘要（含完整 id）。
    async fn create(&self, req: ContainerCreateReq) -> Result<ContainerSummary>;
}

// ═══════════════════════════ 终端 ═══════════════════════════
//
// 刻意**只**暴露"能不能开"与"用哪个 shell"，不暴露 PTY 本身：
// PTY 的创建被收敛在 `cmd::spawn_pty`（全项目唯一子进程出口的不变量），
// 平台实现的职责仅止于回答"这台机器上有没有可用的交互 shell"。

/// 内置 Web 终端的后端能力。
pub trait TerminalProvider: Send + Sync {
    /// 是否具备可用的交互 shell（决定能力位与 UI 置灰）
    fn available(&self) -> bool;
    /// 首选的交互 shell；不可用时为 `None`。
    ///
    /// 返回 `Bin` 而**不是字符串**：保证"探测到的 shell"与"实际 spawn 的 shell"
    /// 同源。若这里给字符串、调用方再按名字挑 `Bin`，两处优先级一旦不一致，
    /// 就会出现"能力位说有 bash，实际用的却是 sh"这类静默漂移。
    fn shell(&self) -> Option<crate::cmd::Bin>;
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
    /// 把若干**分片文件**按顺序流式合并写入 `dst`（先写临时文件、再原子替换）。
    ///
    /// 分片由面板自己产出（位于数据目录的 `uploads/` 下），故以裸 `PathBuf` 传入；
    /// 最终目标对用户可见，走 `SafePath` 以复用沙箱校验。
    /// **必须流式**：分片各自可能几十 MB，整体读进内存再拼会在低配机上直接 OOM。
    /// 返回实际写入字节数，供调用方与声明的总大小核对。
    async fn merge_chunks(&self, parts: &[std::path::PathBuf], dst: &SafePath) -> Result<u64>;
    async fn create_dir(&self, path: &SafePath, recursive: bool) -> Result<()>;
    /// 删除。目录需递归；`allow_dir` 为 false 时拒绝删目录（防误删）
    async fn remove(&self, path: &SafePath, allow_dir: bool) -> Result<()>;
    /// 重命名 / 移动。**目标也必须在允许根内**，由调用方保证 SafePath
    async fn rename(&self, from: &SafePath, to: &SafePath) -> Result<()>;
    async fn copy(&self, from: &SafePath, to: &SafePath) -> Result<()>;
    /// 平台敏感路径黑名单判定（如 /etc/shadow）。**由平台实现决定**，业务层不硬编码
    fn is_sensitive(&self, path: &SafePath) -> bool;
    /// 按**裸路径**判定敏感。
    ///
    /// 给"路径不是用户交互输入、因此拿不到 `SafePath`"的场景用——典型是数据库连接
    /// 配置里填的 sqlite 文件路径。**必须与 `is_sensitive` 共用同一份黑名单**：
    /// 两套判定必然会漂移，而漂移的那一套就是漏网的那一套。
    fn is_sensitive_path(&self, path: &std::path::Path) -> bool;
    /// 单文件大小上限（上传与写入共用）
    fn max_file_bytes(&self) -> usize { 100 * 1024 * 1024 }
}
