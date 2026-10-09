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
use std::{cmp::Ordering, path::PathBuf, time::Duration};
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
    /// 按单元名直接查单个服务，绕开 `list` 的 `list-units --all` 全量枚举。
    ///
    /// 为什么需要：systemd 的 `list-units` 只列出**已加载进运行时**的单元，
    /// 所有 `enabled` 但从未启动（dead）的服务（典型如刚装好还没 start 的 nginx）
    /// 整体不在列表里，于是详情页按列表反查必然"未找到该服务"。
    /// 本方法用 `systemctl show <unit>` 按需加载单元，dead 也能查到；
    /// 单元根本不存在时返回 `None`（路由据此回 404）。
    async fn show(&self, name: &UnitName) -> Result<Option<ServiceUnit>>;
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

    /// **新建**一个单元文件（`/etc/systemd/system/<name>`）并 `daemon-reload`。
    ///
    /// 与 `config_write` 的区别：那个改**已存在**的单元（靠 `FragmentPath` 定位），
    /// 本方法用于**面板自建**的应用单元——文件尚不存在，没有 FragmentPath 可查，
    /// 故路径由单元名直接派生（`/etc/systemd/system/<name>`，`UnitName` 已校验安全）。
    ///
    /// `name` 必须带 `.service` 后缀（如 `panel-app-blog.service`）；实现方需再兜一次
    /// 后缀与路径穿越校验——**绝不信任调用方拼好的字符串直接落盘**。
    /// 写入采用「先写临时文件再 rename」的原子替换，避免半写文件把单元改坏。
    /// 幂等：同名单元已存在时**覆盖**（面板自建的单元以 DB 为真相源，DB 改了就该重写）。
    async fn install_unit(&self, name: &UnitName, content: &str) -> Result<()>;

    /// 删除面板自建的应用单元（`/etc/systemd/system/<name>`）并 `daemon-reload`。
    ///
    /// 与 `install_unit` 对称：删应用时必须把单元文件一并清掉，否则留下**孤儿单元**
    /// （systemd 仍会按残留的 `[Install]` 段尝试拉起它）。文件不存在时不报错（幂等）。
    async fn remove_unit(&self, name: &UnitName) -> Result<()>;
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

/// 某个已安装包存在可用更新的信息（由包管理器的**版本表**派生，见 `upgradable_pair`）。
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

/// Debian 版本号比较（Debian Policy §5.6.12，等价于 `dpkg --compare-versions`）。
///
/// 返回 `a` 相对 `b` 的大小。**不能退化成字符串比较**——版本号按
/// 「[epoch:]upstream[-revision]」比较，段内又按「非数字片段逐字符、数字片段按数值」
/// 交替切分，还有 `~` 排在**一切字符（含串尾）之前**这条反直觉规则。字符串比较会得出
/// `"8.9" > "8.10"` 这种错误结论，而它直接决定「有没有新版」，错了就报错版本。
///
/// 实现逐条对齐本机 `dpkg --compare-versions` 的实测行为（含 `~`、epoch、前导零、
/// 缺省 revision、串尾权重）。安装弹窗默认值与升级守卫都经它判定，故只能有一份。
pub fn deb_version_cmp(a: &str, b: &str) -> Ordering {
    let (ea, ra) = split_epoch(a);
    let (eb, rb) = split_epoch(b);
    match ea.cmp(&eb) {
        Ordering::Equal => {}
        o => return o,
    }
    let (ua, va) = split_revision(ra);
    let (ub, vb) = split_revision(rb);
    match verrevcmp(ua, ub) {
        Ordering::Equal => verrevcmp(va, vb),
        o => o,
    }
}

/// 拆出 `(epoch, 其余)`。epoch 是第一个 `:` 之前**全为数字**的前缀，缺省为 0。
fn split_epoch(v: &str) -> (u64, &str) {
    if let Some((head, rest)) = v.split_once(':') {
        if !head.is_empty() && head.bytes().all(|c| c.is_ascii_digit()) {
            // 超长 epoch 用 MAX 兜底：真实版本号不会触及，且比较仍保持"更大"
            return (head.parse::<u64>().unwrap_or(u64::MAX), rest);
        }
    }
    (0, v)
}

/// 按**最后一个** `-` 拆出 `(upstream, revision)`；无 `-` 时 revision 为空串。
///
/// 空 revision 与 `"0"` 等价（dpkg 实测 `1.0 == 1.0-0`）：`verrevcmp` 会跳过前导零，
/// 于是空串与 `"0"` 自然判等，无需特判。
fn split_revision(v: &str) -> (&str, &str) {
    match v.rfind('-') {
        Some(i) => (&v[..i], &v[i + 1..]),
        None => (v, ""),
    }
}

/// dpkg `verrevcmp` 的等价实现：非数字片段逐字符比 `order()` 权重，
/// 数字片段比数值（忽略前导零；位数不同则位数多者更大）。
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() || j < b.len() {
        let mut first_diff: i32 = 0;
        // 1) 非数字片段：任一非数字即进入（另一方已到串尾则按 None 参与）
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = order(a.get(i).copied());
            let bc = order(b.get(j).copied());
            if ac != bc { return ac.cmp(&bc); }
            i += 1;
            j += 1;
        }
        // 2) 前导零不参与数值比较（"1.001" == "1.1"）
        while i < a.len() && a[i] == b'0' { i += 1; }
        while j < b.len() && b[j] == b'0' { j += 1; }
        // 3) 数字片段：位数相同才用先出现的差异位，位数不同则位数多者更大
        while i < a.len() && j < b.len() && a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            if first_diff == 0 { first_diff = a[i] as i32 - b[j] as i32; }
            i += 1;
            j += 1;
        }
        if i < a.len() && a[i].is_ascii_digit() { return Ordering::Greater; }
        if j < b.len() && b[j].is_ascii_digit() { return Ordering::Less; }
        if first_diff != 0 { return first_diff.cmp(&0); }
    }
    Ordering::Equal
}

/// 非数字字符的排序权重（对齐 dpkg 的 `order()`）：
/// `~`(-1) < 串尾(0) < 大写字母 < 小写字母 < 其它 ASCII 符号。
///
/// 串尾取 0 由实测确定（`1.0 < 1.0a` 而 `1.0 > 1.0~`），即"短串在前"。
/// 数字在非数字片段里不会出现，故 0 与数字权重重合无害。
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}

/// 判定「源里最高版本是否高于已安装版本」，是则返回 `(已安装版本, 目标版本)`。
///
/// 判据**只看版本表**（`apt-cache policy` 的 `Version table:`），与安装弹窗默认选中的
/// 那一项（`versions[0]`）同源。刻意不用 apt 的 `Candidate`／`apt list --upgradable`：
/// Candidate 会被 pin、`NotAutomatic`、源优先级压低，一旦低于已安装版本，apt 就
/// **永远不报告**该项——哪怕版本表里另有更高版本（实测：pin 后 `Candidate: 1.30.2`
/// 而版本表最高仍是 `1.30.5`）。用户侧表现就是"官方源明明有新版，面板却总说已是最新"。
pub fn upgradable_pair(installed: Option<&str>, versions: &[String]) -> Option<(String, String)> {
    let cur = installed.filter(|s| !s.is_empty())?;
    // 显式取最大，不依赖 apt"版本表已按新→旧排好"这一未文档化的保证
    let best = versions.iter().max_by(|x, y| deb_version_cmp(x, y))?;
    (deb_version_cmp(best, cur) == Ordering::Greater).then(|| (cur.to_string(), best.clone()))
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
    /// 返回该已装包 shipping 的**主服务单元名**（含 `.service` 后缀），如 `nginx` → `nginx.service`。
    ///
    /// 用途：软件卡片要渲染「服务管理」入口，但 `systemctl list-units`（服务页枚举命令）
    /// 只列出**已加载进 systemd 运行时**的单元——对 `enabled` 却从未激活过的单元
    /// （典型如装好 nginx 但没 start 过）整体遗漏，导致卡片匹配不到对应单元、不渲染入口。
    /// 这里改为直接问包管理器"这个包装了哪些 `.service` 文件"（Debian 上 `dpkg -L`），
    /// 与运行时加载状态解耦，故 enabled-but-dead 的服务也能被正确关联到。
    ///
    /// 一个包可能 shipping 多个单元（如 postgresql 的 `postgresql.service` + `postgresql@.service`），
    /// 返回第一个**非模板**（不含 `@`）单元；没有任何 `.service` 则 `None`
    /// （certbot/ufw 之类无常驻服务可管，调用方据此不渲染入口）。
    async fn service_unit(&self, name: &str) -> Result<Option<String>>;
    /// 探测**给定包名**中「源里最高版本高于已安装版本」的项（只读，不改动系统）。
    ///
    /// 传名字列表而不做全系统扫描：调用方（软件页）只关心白名单这二十来个包，
    /// 全量扫描既慢、又得再把几百个系统库过滤掉。返回项的 `name` 是**真实包名**
    /// （包管理器口径，如 `redis-server`），由调用方映射回逻辑名对外。
    ///
    /// 判据必须是「版本表最高版本 > 已安装版本」而非 apt 的 Candidate，理由见
    /// `upgradable_pair`——这是"官方源有新版却不提示"的根因所在。
    ///
    /// 返回空列表表示"无可升级项"，**不是错误**（多数机器本来就没有可升级的白名单包）；
    /// 查不到（无包管理器 / 非 apt）同样返回空列表，调用方据此隐藏入口而不是报错
    /// ——探测失败不该让整页软件列表挂掉。
    async fn upgradable(&self, names: &[&str]) -> Result<Vec<UpgradablePkg>>;
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
    /// 该后端的能力位（按二进制存在性等判定）。前端据此置灰，绝不伪造成功。
    ///
    /// 作为 trait 方法而非独立 `Capable` impl：路由层持有 `Arc<dyn FirewallProvider>`，
    /// 只有落在 vtable 里的方法才能经 trait object 调用（单独 `impl Capable` 的方法
    /// 不在 `FirewallProvider` 的 vtable 中，编译期即报 `no method named capability`）。
    fn capability(&self) -> Capability;
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

// ═══════════════════════════ 应用托管（systemd 单元） ═══════════════════════════

/// 受支持的应用运行时。
///
/// **只描述「怎么把进程拉起来」**——运行时不改变 nginx 的接入方式：Node / Go / Rust / Java /
/// Python / .NET 在 nginx 侧一律走 `proxy_pass` 到本机端口，配置逐字节相同。差异只在
/// 「装哪个系统包、用什么命令启动、默认监听哪个端口」，故做成运行时元数据而非 `SiteKind`
/// 变体（加变体＝加一份产出同一份 nginx 配置的 match 分支，纯重复）。
///
/// 与 `SiteKind` 的分工是**正交**的：`SiteKind` 管接入协议（静态/反向代理/FastCGI/重定向），
/// 本枚举管进程怎么起。一个 Go 应用 = `AppRuntime::Go` + `SiteKind::ReverseProxy`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRuntime {
    Node,
    Go,
    Rust,
    Java,
    Python,
    DotNet,
    Php,
    /// 自定义：用户自备启动命令，面板不提供任何默认值或运行时提示。
    Custom,
}

impl AppRuntime {
    /// 全部运行时（前端下拉与 catalog 端点的数据源）。
    pub const ALL: [AppRuntime; 8] = [
        AppRuntime::Node, AppRuntime::Go, AppRuntime::Rust, AppRuntime::Java,
        AppRuntime::Python, AppRuntime::DotNet, AppRuntime::Php, AppRuntime::Custom,
    ];

    /// 稳定标识（落库 / API 传输用）。**不可随意改**——改了会读不出已有数据。
    pub fn key(&self) -> &'static str {
        match self {
            AppRuntime::Node => "node",
            AppRuntime::Go => "go",
            AppRuntime::Rust => "rust",
            AppRuntime::Java => "java",
            AppRuntime::Python => "python",
            AppRuntime::DotNet => "dotnet",
            AppRuntime::Php => "php",
            AppRuntime::Custom => "custom",
        }
    }

    /// 由落库标识反解；未知值返回 `None`（调用方据此回退到 `Custom`，不 panic）。
    pub fn from_key(k: &str) -> Option<AppRuntime> {
        AppRuntime::ALL.into_iter().find(|r| r.key() == k)
    }

    /// 展示名。
    pub fn label(&self) -> &'static str {
        match self {
            AppRuntime::Node => "Node.js",
            AppRuntime::Go => "Go",
            AppRuntime::Rust => "Rust",
            AppRuntime::Java => "Java",
            AppRuntime::Python => "Python",
            AppRuntime::DotNet => ".NET",
            AppRuntime::Php => "PHP",
            AppRuntime::Custom => "自定义",
        }
    }

    /// 默认监听端口（仅作预填，用户可改；`Custom` 无默认故给 0）。
    pub fn default_port(&self) -> u16 {
        match self {
            AppRuntime::Node => 3000,
            AppRuntime::Go => 8080,
            AppRuntime::Rust => 8080,
            AppRuntime::Java => 8081,
            AppRuntime::Python => 8000,
            AppRuntime::DotNet => 5000,
            AppRuntime::Php => 9000,
            AppRuntime::Custom => 0,
        }
    }

    /// 面板包白名单里的系统包名，用于「已装 / 未装」提示。
    ///
    /// `None` = 面板不托管该运行时（如 Python 用系统自带、.NET 需微软源），
    /// 此时前端不显示安装状态——**不做「你没有 X」这种面板无权判断的断言**。
    ///
    /// ⚠ 口径是**包管理器里的系统包**，不等于「这台机器上有没有该语言」：
    /// 用 nvm / 官方安装包装好的 node 不出现在 apt 的已装列表里（本机实测如此）。
    pub fn runtime_pkg(&self) -> Option<&'static str> {
        match self {
            AppRuntime::Node => Some("nodejs"),
            AppRuntime::Go => Some("golang-go"),
            AppRuntime::Rust => Some("cargo"),
            AppRuntime::Java => Some("default-jdk"),
            AppRuntime::Php => Some("php-fpm"),
            AppRuntime::Python | AppRuntime::DotNet | AppRuntime::Custom => None,
        }
    }

    /// 默认启动命令（进 systemd `ExecStart=`）。刻意是**可跑的示例**而非占位符——
    /// 用户改起来比从空白开始快，也顺带示范了该运行时的常见入口形式。
    pub fn default_exec(&self) -> &'static str {
        match self {
            AppRuntime::Node => "node server.js",
            AppRuntime::Go => "app",
            AppRuntime::Rust => "app",
            AppRuntime::Java => "java -jar app.jar",
            AppRuntime::Python => "gunicorn app:app -b 127.0.0.1:8000",
            AppRuntime::DotNet => "dotnet App.dll",
            AppRuntime::Php => "php-fpm -F -y /etc/php/8.4/fpm/php-fpm.conf",
            AppRuntime::Custom => "",
        }
    }

    /// 典型框架（帮用户确认没选错运行时）。
    pub fn typical(&self) -> &'static str {
        match self {
            AppRuntime::Node => "Express / NestJS / Next.js",
            AppRuntime::Go => "net/http / Gin / Echo",
            AppRuntime::Rust => "Axum / Actix Web / Rocket",
            AppRuntime::Java => "Spring Boot（内置 Tomcat）",
            AppRuntime::Python => "Django / Flask / FastAPI",
            AppRuntime::DotNet => "ASP.NET Core（Kestrel）",
            AppRuntime::Php => "Laravel / Symfony（php-fpm 常驻）",
            AppRuntime::Custom => "任意自托管服务",
        }
    }

    /// 构建步骤提示（纯文案，前端展示；面板**不执行**构建——那属于用户自己的 CI/流水线）。
    pub fn build_hint(&self) -> &'static str {
        match self {
            AppRuntime::Node => "先 npm ci && npm run build，再以启动命令拉起",
            AppRuntime::Go => "先 go build -o app .（本机需 Go 工具链或交叉编译产物）",
            AppRuntime::Rust => "先 cargo build --release，产物在 target/release/（拷或链接为工作目录下的 app）",
            AppRuntime::Java => "先 mvn package / gradle build 产出可执行 jar",
            AppRuntime::Python => "先建虚拟环境并 pip install -r requirements.txt",
            // ci-allow-layering[2]: 纯提示文案里的 dotnet publish -c Release；并非 shell 调用（无引号包裹的 -c）
            AppRuntime::DotNet => "先 dotnet publish -c Release 产出可部署目录", // ci-allow-layering[2]: 文案里的 `-c Release` 被正则误判为 shell 参数，非真实 shell 调用
            AppRuntime::Php => "通常无需构建；依赖用 composer install 装到项目目录",
            AppRuntime::Custom => "自行准备可执行文件或解释器命令",
        }
    }
}

/// 一个「面板托管的应用」的规格（渲染成 systemd 单元）。
///
/// 面板的职责边界：**只负责把进程按 systemd 拉起来**，构建/依赖安装仍由用户在项目
/// 目录自行完成（`build_hint` 仅作提示）。这样面板不需要理解语言的包管理器，
/// 也不会因为某语言的构建工具变更而失效。
#[derive(Debug, Clone)]
pub struct AppUnitSpec {
    /// systemd 单元名（`panel-app-<name>.service`，由 `app_unit_name` 派生）
    pub unit: String,
    /// 人读描述（进 `Description=`）
    pub description: String,
    /// 工作目录（`WorkingDirectory=`）；必须是已存在的绝对路径，否则 systemd 以 CHDIR 失败
    pub workdir: PathBuf,
    /// 启动命令（`ExecStart=`）。面板**不解析**它——语义完全交由 systemd
    pub exec_start: String,
    /// 运行用户（`User=` / `Group=`）；`None` = 以 root 运行
    pub run_user: Option<String>,
    /// 追加环境变量（逐条 `Environment=`）
    pub env: Vec<(String, String)>,
    /// 监听端口——**仅供描述与前端展示**，systemd 本身不读它
    pub port: u16,
    /// 崩溃后自动重启（`Restart=always`）；关闭则 `Restart=no`
    pub auto_restart: bool,
}

/// 应用名 → systemd 单元名：统一 `panel-app-<名>.service` 前缀，便于与系统单元区分、
/// 也便于按前缀反查「哪些单元是面板托管的」。
///
/// ⚠ 应用名先经站点名白名单（`rules::is_valid_site_name`）校验，但那条规则**允许 `..`**
/// （如 `a..b`），而 systemd 单元名**禁止** `..`——故此处再折叠一次，保证派生结果一定
/// 能过 `rules::is_valid_unit_name`（否则会出现"校验通过却装不进 systemd"的死角）。
pub fn app_unit_name(app: &str) -> String {
    let safe = app.replace("..", "-");
    format!("panel-app-{safe}.service")
}

/// systemd 配置值里的 `%` 必须写成 `%%`——否则 `%` 后跟字符会被当 **specifier** 展开
/// （`%i` / `%n` / `%H` …），路径里的 `%` 会被静默替换掉。
fn sd_pct(s: &str) -> String {
    s.replace('%', "%%")
}

/// `Environment="K=V"` 的转义：反斜杠与双引号需转义；**换行直接剔除**——
/// 换行会打断单元文件结构（等于把 V 里的内容注入成新的 systemd 指令），是实打实的注入点。
fn env_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], " ")
}


/// 渲染 systemd 单元文本（纯字符串生成，不落盘；与 `render_nginx` 同性质）。
///
/// 刻意**输出最小可用集**：不写 `Type=` 之外的进程管理细节、不加多余 `After=`——
/// 写得越多越容易与用户的实际需求冲突，而 systemd 的默认值对本场景已经够用。
/// systemd 的 `ExecStart` 只接受**纯命令名**（走 PATH）或**绝对路径**——
/// 相对路径（`./app`）会被判`bad unit file setting` 且**单元永不启动**
/// （实测 `systemd-analyze verify`：Neither a valid executable name nor an absolute path）。
/// 这里提前拦下，别让用户建完应用才发现 systemd 拒绝加载。
pub fn exec_start_is_valid(cmd: &str) -> bool {
    let c = cmd.trim();
    if c.is_empty() {
        return false;
    }
    // 首个 token 之前的部分即「程序名」；含空格时按 shell 词法粗切（systemd 语义更严格，
    // 但足以拦住「以 ./ 开头的相对路径」这一实际踩到的坑）。
    let first = c.split_whitespace().next().unwrap_or("");
    if first.starts_with('/') || first.starts_with('~') {
        return true;
    }
    // 相对路径（含 ./ ../）一律不合法
    !first.contains('/')
}

pub fn render_app_unit(spec: &AppUnitSpec) -> String {
    let mut out = String::new();
    out.push_str("# 由 ForkPanel 生成 —— 请勿手工编辑\n");
    out.push_str("# 面板以数据库为真相源，下次保存会整体覆盖本文件。\n");
    out.push_str("# 对应的 nginx 反代站点在「网站」页管理。\n\n");
    out.push_str("[Unit]\n");
    out.push_str(&format!("Description={}\n", sd_pct(&spec.description)));
    out.push_str("After=network-online.target\n");
    out.push_str("Wants=network-online.target\n\n");
    out.push_str("[Service]\n");
    out.push_str("Type=simple\n");
    out.push_str(&format!("WorkingDirectory={}\n", sd_pct(&spec.workdir.display().to_string())));
    out.push_str(&format!("ExecStart={}\n", sd_pct(&spec.exec_start)));
    if let Some(u) = &spec.run_user {
        out.push_str(&format!("User={u}\n"));
        out.push_str(&format!("Group={u}\n"));
    }
    for (k, v) in &spec.env {
        out.push_str(&format!("Environment=\"{}={}\"\n", env_escape(k), env_escape(v)));
    }
    if spec.auto_restart {
        out.push_str("Restart=always\n");
        out.push_str("RestartSec=3\n");
    } else {
        out.push_str("Restart=no\n");
    }
    out.push_str("\n[Install]\nWantedBy=multi-user.target\n");
    out
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
    /// 静态站点 SPA 回退：开启后 `try_files` 末项为 `/index.html`（支持 history 路由的
    /// 单页应用）。只对 `SiteKind::Static` 生效，其余类型忽略。
    pub spa_fallback: bool,
    /// WAF 配置；`None` = 不生成任何拦截规则
    pub waf: Option<WafSpec>,
    /// 路由表。`Some(..)` 时 `kind` 必须是 [`SiteKind::Routed`] 且与之内容一致；
    /// 保留为独立字段是为了让调用方能「构造 spec 时先算好routes、再决定 kind」，
    /// 渲染层以 `kind` 为唯一真相源，本字段只作校验对照（不一致即渲染期报错）。
    pub routes: Option<SiteRoutes>,
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
    /// 整站重定向：访问本站点域名时返回 `<code>` 跳转到 `target`（自动追加
    /// `$request_uri` 保留路径）。`code` 仅限 301 / 302 / 307 / 308，`target` 必须是
    /// 绝对 `http(s)://` URL。`root` / `index` / `location` 一概不输出。
    Redirect { target: String, code: u16 },
    /// 多路由：一个站点内按 URL 前缀分派（`/` 兜底 + 任意条 `/api`、`/admin` …）。
    ///
    /// 与其它变体的关系：**互斥**（一个站点要么是单一形态、要么是路由表），
    /// 这样 `spa_fallback` 等旧字段的语义不会在多路由下产生歧义——
    /// 路由表里每条静态路由自带 `spa`，不受站点级 `spa_fallback` 影响。
    Routed { routes: SiteRoutes },
}

/// 一条路由：把某个 URL 前缀交给特定处理方式。
///
/// 存在的意义：单 `kind` 的站点只有**一个** `location /`，于是「Vue 静态站 +
/// `/api` 交给 Go 后端」这种最常见的混合形态必须拆成两个站点（两个域名、两份
/// 证书、两套 WAF），或者手改 nginx 配置。多路由把它变成站点的一等公民。
///
/// ⚠ **渲染一律用 `location ^~ <prefix>`**（不使用正则）：nginx 的 location
/// 优先级是「精确 `=` > 前缀 `^~` > 正则 > 普通前缀」，**前缀一旦带 `^~`
/// 就永不再走正则**——这正是我们要的确定性（用户写的 prefix 与任何正则规则
/// 谁先命中，不再依赖配置里的书写顺序）。反过来说，**多路由模式下不能再依赖
/// 正则 location**（含本文件自己为单路由 PHP 生成的 `~ \.php$`），故 PHP 路由
/// 改用「固定 front controller」的 FastCGI 形式（见 [`RouteKind::Php`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteRoute {
    /// URL 前缀。必须以 `/` 开头；`/` 表示兜底（只能有一条）。
    /// 归一化由调用方负责（去掉末尾多余的 `/`，除根之外）。
    pub prefix: String,
    pub kind: RouteKind,
}

/// 单条路由的处理方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteKind {
    /// 反向代理（可多后端 → 由 `upstream` 块轮询）。
    Proxy { upstreams: Vec<String> },
    /// 静态文件。`spa` 开启时未命中回退到 `/index.html`（history 路由）。
    Static { spa: bool },
    /// PHP：转发到 php-fpm。
    ///
    /// `front_controller` 是入口脚本（相对 `root`，如 `index.php`）。**必填**：
    /// 多路由下不能用 `location ~ \.php$` 正则（`^~` 会屏蔽它），所以必须
    /// 显式指定入口，把**整个前缀**都交给它——这也正是现代 PHP 框架
    /// （Laravel / ThinkPHP / Slim）的标准 front controller 模式。
    Php { fpm: String, front_controller: String },
}

/// 多路由站点：`routes` 至少一条，其中**恰好一条** `prefix == "/"` 作兜底。
///
/// 渲染时按 prefix 长度**降序**输出（`/api/admin` 先于 `/api` 先于 `/`），
/// 让最长前缀先匹配——即便 nginx 的前缀匹配本身会挑最长，显式降序也让
/// 配置文本读起来与实际生效顺序一致，便于人工核对。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteRoutes {
    pub routes: Vec<SiteRoute>,
}

impl SiteRoutes {
    /// 按 prefix 长度降序（同级保持原序，稳定）——渲染顺序即生效顺序。
    pub fn sorted(&self) -> Vec<&SiteRoute> {
        let mut v: Vec<&SiteRoute> = self.routes.iter().collect();
        v.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));
        v
    }

    /// 找出兜底路由（`prefix == "/"`）。
    pub fn fallback(&self) -> Option<&SiteRoute> {
        self.routes.iter().find(|r| r.prefix == "/")
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::{Equal, Greater, Less};

    /// 期望值全部取自本机 `dpkg --compare-versions` 实测（Debian 版本比较的唯一权威），
    /// 覆盖 `~` / epoch / 前导零 / 缺省 revision / 串尾权重这几条最容易写错的规则。
    #[test]
    fn deb_version_cmp_matches_dpkg_on_real_world_versions() {
        // 数值序而非字典序：字符串比较会得出 "8.9" > "8.10" 的错误结论
        assert_eq!(deb_version_cmp("8.10", "8.9"), Greater);
        assert_eq!(deb_version_cmp("13.2.10", "13.2.3"), Greater);
        // 本机白名单包的真实版本（apt-cache policy 实测）
        assert_eq!(deb_version_cmp("1.30.5-1~trixie", "1.26.3-3+deb13u9"), Greater);
        assert_eq!(deb_version_cmp("18+293.pgdg13+1", "18+291.pgdg13+1"), Greater);
        assert_eq!(deb_version_cmp("5:8.0.2-3", "5:8.10.2-1"), Less);
        assert_eq!(deb_version_cmp("6:8.10.2-1rl1~trixie1", "6:8.10.1-1rl1~trixie1"), Greater);
        assert_eq!(deb_version_cmp("4.0.0-2+deb13u1", "4.0.0-2"), Greater);
        // epoch 优先于其余各段
        assert_eq!(deb_version_cmp("2:1.0", "1:9.9"), Greater);
        assert_eq!(deb_version_cmp("1:1.0", "1.0"), Greater);
        assert_eq!(deb_version_cmp("0:1.0", "1.0"), Equal);
        // 前导零不参与数值比较
        assert_eq!(deb_version_cmp("1.001", "1.1"), Equal);
        assert_eq!(deb_version_cmp("1.0", "1.00"), Equal);
        assert_eq!(deb_version_cmp("1.0-1", "1.0-01"), Equal);
        // 缺省 revision 等价于 "0"（dpkg 实测 1.0 == 1.0-0）
        assert_eq!(deb_version_cmp("1.0", "1.0-0"), Equal);
        assert_eq!(deb_version_cmp("1.0-1", "1.0"), Greater);
        // '~' 排在一切字符（含串尾）之前
        assert_eq!(deb_version_cmp("1.0~rc1", "1.0"), Less);
        assert_eq!(deb_version_cmp("1.0", "1.0~"), Greater);
        assert_eq!(deb_version_cmp("1.2.3~rc1+deb1", "1.2.2+deb1"), Greater);
        // 串尾排在大写字母之前；字母按 ASCII；其它符号排在字母之后
        assert_eq!(deb_version_cmp("1.0", "1.0a"), Less);
        assert_eq!(deb_version_cmp("1.0", "1.0A"), Less);
        assert_eq!(deb_version_cmp("1.0A", "1.0a"), Less);
        assert_eq!(deb_version_cmp("1.0a", "1.0aa"), Less);
        assert_eq!(deb_version_cmp("1.0a", "1.0+"), Less);
        assert_eq!(deb_version_cmp("1.0z", "1.0+"), Less);
        // 数字段与非数字段交替切分
        assert_eq!(deb_version_cmp("1.0a1", "1.01"), Less);
        assert_eq!(deb_version_cmp("1.0a1", "1.0a"), Greater);
        // 自反
        assert_eq!(deb_version_cmp("1.30.5-1~trixie", "1.30.5-1~trixie"), Equal);
    }

    /// 判定「有更新」的口径：只看版本表最高版，与安装弹窗默认选中项同源。
    /// 关键回归点是**无视 apt pin 后的候选版本**——本机实测 pin 后
    /// `Candidate: 1.30.2`，而版本表最高仍是 `1.30.5`，旧口径会因此永远沉默。
    #[test]
    fn upgradable_pair_uses_version_table_top_not_apt_candidate() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // 已装 1.30.4，版本表最高 1.30.5（候选被 pin 压到 1.30.2 也不影响判定）
        assert_eq!(
            upgradable_pair(
                Some("1.30.4-1~trixie"),
                &v(&["1.30.5-1~trixie", "1.30.4-1~trixie", "1.30.2-1~trixie"])
            ),
            Some(("1.30.4-1~trixie".to_string(), "1.30.5-1~trixie".to_string())),
        );
        // 已装即最高版 → 无更新
        assert_eq!(
            upgradable_pair(Some("1.30.5-1~trixie"), &v(&["1.30.5-1~trixie", "1.26.3-3+deb13u9"])),
            None
        );
        // 已装版本比源里所有版本都新（源被移除或回退）→ 无更新，绝不提示"降级"
        assert_eq!(upgradable_pair(Some("1.31.0-1~trixie"), &v(&["1.30.5-1~trixie"])), None);
        // 未安装 → 交给安装路径，不报"有更新"
        assert_eq!(upgradable_pair(None, &v(&["1.0"])), None);
        assert_eq!(upgradable_pair(Some("1.0"), &v(&[])), None);
        // 版本表乱序也要能挑出真正最高的（不依赖 apt 的排序这一未文档化保证）
        assert_eq!(
            upgradable_pair(Some("8.0.2"), &v(&["8.0.1", "8.10.2", "8.0.3"])),
            Some(("8.0.2".to_string(), "8.10.2".to_string())),
        );
    }

    /// 组合后的对外语义：跨主版本标记必须与版本表口径一致。
    #[test]
    fn upgradable_pair_feeds_major_jump_flag() {
        let pg = upgradable_pair(Some("17+278"), &["18+293.pgdg13+1".to_string()]).unwrap();
        assert!(version_major_jump(&pg.0, &pg.1), "PG 17→18 应判跨主版本");
        let redis = upgradable_pair(Some("5:8.0.2"), &["5:8.10.2".to_string()]).unwrap();
        assert!(!version_major_jump(&redis.0, &redis.1), "Redis 8.0.2→8.10.2 仅次版本");
    }

    /// 与 dpkg 的**差分对拍**：把一批刁钻片段做笛卡尔积，逐个与
    /// `dpkg --compare-versions` 的真实结果比对。手写期望值只能覆盖"想得到的规则"，
    /// 对拍才能发现没想到的（`~` 的插入位置、串尾权重、字母与符号的相对次序都极易写反）。
    ///
    /// 本机无 dpkg（非 Debian 系）时自行跳过——此时上面的手写期望值仍然有效。
    #[test]
    fn deb_version_cmp_agrees_with_dpkg_on_a_matrix() {
        if std::process::Command::new("dpkg").arg("--version").output().is_err() {
            eprintln!("跳过差分对拍：本机无 dpkg");
            return;
        }
        // 片段刻意含 ~ / epoch / 前导零 / 大小写字母 / 符号 / 长数字 / 真实项目版本号
        let parts = [
            "1", "0", "2", "10", "9", "001", "0.9", "1.0", "1.10", "1.9", "1.0~rc1", "1.0~",
            "1.0a", "1.0A", "1.0z", "1.0+", "1.0.", "1.0a1", "1.01", "18+293.pgdg13+1",
            "5:8.0.2-3", "1.30.5-1~trixie", "1:1.0", "0:1.0", "2:1.0",
        ];
        let mut checked = 0usize;
        for a in parts {
            for b in parts {
                let Some(want) = dpkg_cmp(a, b) else { continue };
                let got = deb_version_cmp(a, b);
                assert_eq!(got, want, "与 dpkg 不一致：{a} vs {b}");
                checked += 1;
            }
        }
        // 防"恒绿"：样本量异常小说明循环没真正跑起来（而非真的全对）
        assert!(checked > 400, "对拍样本过少（{checked}），测试可能没跑起来");
    }

    /// 取 `dpkg --compare-versions` 的真实结论；版本号非法（dpkg 报语法错误）时返回 None，
    /// 由调用方跳过该样本——绝不能把"解析失败"当成"相等"。
    fn dpkg_cmp(a: &str, b: &str) -> Option<Ordering> {
        let ops = [("gt", Greater), ("lt", Less), ("eq", Equal)];
        ops.iter().find_map(|(op, ord)| {
            let ok = std::process::Command::new("dpkg")
                .args(["--compare-versions", a, op, b])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            ok.then_some(*ord)
        })
    }

    /// 运行时元数据必须自洽——这些字符串**直接进 systemd 单元与前端下拉**，
    /// 任一处漏配都不会编译报错（match 已穷尽），只会在运行时表现为
    /// 「选项点了没反应」或「永远显示未装」，属最难查的一类。
    #[test]
    fn app_runtime_metadata_is_consistent() {
        // key 唯一：落库标识，重复会让 from_key 静默取到第一个
        let mut keys: Vec<&str> = AppRuntime::ALL.iter().map(|r| r.key()).collect();
        let n = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), n, "AppRuntime::ALL 的 key 有重复");

        for r in AppRuntime::ALL {
            // key 必须能反解回**同一个**变体，否则落库后读不出来
            assert_eq!(AppRuntime::from_key(r.key()), Some(r), "round-trip 失败: {}", r.key());
            // 展示项为空会让界面出现空白行
            assert!(!r.label().is_empty(), "{} label 为空", r.key());
            assert!(!r.typical().is_empty(), "{} typical 为空", r.key());
            assert!(!r.build_hint().is_empty(), "{} build_hint 为空", r.key());
        }

        // Custom = 用户自备：无默认端口 / 无默认命令 / 不托管运行时
        assert_eq!(AppRuntime::Custom.default_port(), 0);
        assert!(AppRuntime::Custom.default_exec().is_empty());
        assert_eq!(AppRuntime::Custom.runtime_pkg(), None);

        // 其余变体必须有非零默认端口与可跑示例命令（否则模板预填等于没填）
        for r in AppRuntime::ALL.iter().filter(|r| **r != AppRuntime::Custom) {
            assert!(r.default_port() > 0, "{} 缺默认端口", r.key());
            assert!(!r.default_exec().is_empty(), "{} 缺默认启动命令", r.key());
        }

        // 未知识别符不得 panic，须返回 None 交由调用方回退 Custom
        assert_eq!(AppRuntime::from_key("cobol"), None);
        assert_eq!(AppRuntime::from_key(""), None);
        // ⚠ runtime_pkg 的字符串必须存在于后端 ALLOWED_PACKAGES —— 该约束跨 crate
        //   （panel-os 不依赖 panel-api），故由 ci/check-pkg-whitelist.sh 的 [E] 项把守。
    }
}
