//! 内存实现：用于单元测试、CI（无 root / 非 Linux 环境）以及 Windows/macOS 接入前的开发。
//!
//! **这也是一致性测试的对象**：任何新平台实现都必须能在同一套契约测试上跑通
//! （设计方案 §0.3.5），避免口头声称支持。

use crate::mock_files; // Rust 2018+：兄弟模块必须走 crate:: 前缀，裸 `mock_files::` 解析不到
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{
    cap_keys, Capability, CapabilityMap, FirewallBackend, InitSystem, LogBackend, Os,
    PanelError, PlatformInfo, Result, SafePath, UnitName,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{channel, Receiver};

#[derive(Default)]
pub(crate) struct State {
    service_states: BTreeMap<String, ServiceState>,
    rules: BTreeMap<String, FirewallRule>,
    apply_calls: usize,
}

/// 一个覆盖全部 trait 的内存实现
pub struct MockOsAdapter {
    services: Arc<MockServices>,
    firewall: Arc<MockFirewall>,
    files: Arc<mock_files::MockFiles>,
}

impl MockOsAdapter {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let mut mem = mock_files::MemFs::new();
        mem.seed_dir("/var/www");
        mem.seed("/var/www/index.html", b"<h1>hello</h1>");
        Self {
            services: Arc::new(MockServices::new(state.clone())),
            firewall: Arc::new(MockFirewall::new(state)),
            files: Arc::new(mock_files::MockFiles::new(Arc::new(Mutex::new(mem)))),
        }
    }
}

impl Default for MockOsAdapter { fn default() -> Self { Self::new() } }

// ───────────────────────── 指标 ─────────────────────────

pub struct MockMetrics;

#[async_trait]
impl MetricsProvider for MockMetrics {
    async fn snapshot(&self) -> Result<SystemSnapshot> {
        Ok(SystemSnapshot {
            ts_unix: 1_700_000_000,
            uptime_sec: 3600,
            cpu: CpuSample { total_pct: 12.5, per_core_pct: Some(vec![10.0, 15.0]),
                             load1: 0.42, load5: 0.30, load15: 0.21 },
            mem: MemSample { total_kib: 1_018_000, used_kib: 412_000, available_kib: 606_000,
                             buffers_kib: 12_000, cached_kib: 300_000,
                             swap_total_kib: 204_800, swap_used_kib: 0 },
            disks: vec![DiskSample {
                mount_point: PathBuf::from("/"),
                device: "/dev/vda1".into(),
                fs_type: "ext4".into(),
                total_bytes: 50 * 1024 * 1024 * 1024,
                used_bytes: 20 * 1024 * 1024 * 1024,
                is_network_fs: false,
            }],
            nets: vec![NetSample { iface: "eth0".into(), rx_bytes: 1024, tx_bytes: 2048,
                                    rx_rate_bps: 1024, tx_rate_bps: 2048 }],
            proc_count: 120,
            tcp_conns: 8,
            // 温度是尽力而为的维度：mock 不编造真实传感器读数，如实给空
            temps: Vec::new(),
        })
    }

    async fn top_processes(&self, n: usize, _sort: ProcessSort) -> Result<Vec<ProcessInfo>> {
        Ok((1..=n as i32).map(|i| ProcessInfo {
            pid: i,
            ppid: 1,
            name: format!("proc{i}"),
            cpu_pct: (i as f32) * 0.5,
            rss_kib: (i as u64) * 1024,
            cmdline: format!("/usr/bin/proc{i} --flag"),
            user: Some("root".into()),
        }).collect())
    }
}

// ───────────────────────── 进程 ─────────────────────────

pub struct MockProcesses;

#[async_trait]
impl ProcessProvider for MockProcesses {
    async fn list(&self, limit: usize, sort: ProcessSort) -> Result<Vec<ProcessInfo>> {
        MockMetrics.top_processes(limit, sort).await
    }
    async fn signal(&self, pid: i32, _sig: ProcessSignal) -> Result<()> {
        if pid <= 1 { return Err(PanelError::PermissionDenied("process.signal")); }
        Ok(())
    }
    async fn is_protected(&self, pid: i32) -> Result<bool> { Ok(pid <= 1) }
}

// ───────────────────────── 服务（状态机，可测幂等） ─────────────────────────

pub struct MockServices { state: Arc<Mutex<State>> }

impl MockServices {
    pub(crate) fn new(state: Arc<Mutex<State>>) -> Self { Self { state } }
}

#[async_trait]
impl ServiceProvider for MockServices {
    fn init_system(&self) -> InitSystem { InitSystem::Systemd }

    async fn list(&self, _f: ServiceFilter) -> Result<Vec<ServiceUnit>> {
        let st = self.state.lock().unwrap();
        Ok(st.service_states.iter().map(|(name, s)| ServiceUnit {
            // SAFETY: mock 内部数据，名称取自已校验集合
            name: unsafe { UnitName::from_raw(name.clone()) },
            description: format!("mock {name}"),
            state: *s,
            enabled: true,
            pid: Some(1000),
            memory_kib: Some(2048),
        }).collect())
    }

    async fn status(&self, name: &UnitName) -> Result<ServiceState> {
        let st = self.state.lock().unwrap();
        Ok(st.service_states.get(name.as_str()).copied().unwrap_or(ServiceState::Unknown))
    }

    async fn show(&self, name: &UnitName) -> Result<Option<ServiceUnit>> {
        let st = self.state.lock().unwrap();
        Ok(st.service_states.get(name.as_str()).map(|s| ServiceUnit {
            // SAFETY: mock 内部数据，名称取自已校验集合
            name: unsafe { UnitName::from_raw(name.as_str().to_string()) },
            description: format!("mock {}", name.as_str()),
            state: *s,
            enabled: true,
            pid: Some(1000),
            memory_kib: Some(2048),
        }))
    }

    async fn start(&self, name: &UnitName) -> Result<()> { self.set(name, ServiceState::Active) }
    async fn stop(&self, name: &UnitName) -> Result<()> { self.set(name, ServiceState::Inactive) }
    async fn restart(&self, name: &UnitName) -> Result<()> { self.set(name, ServiceState::Active) }
    async fn reload(&self, _name: &UnitName) -> Result<()> { Ok(()) }
    async fn set_enabled(&self, _n: &UnitName, _e: bool) -> Result<()> { Ok(()) }

    async fn journal(&self, _n: &UnitName, q: JournalQuery) -> Result<Receiver<String>> {
        let (tx, rx) = channel(16);
        for i in 0..q.lines.min(50) {
            if tx.send(format!("mock log line {i}")).await.is_err() { break; }
        }
        Ok(rx)
    }

    async fn config_read(&self, _n: &UnitName, _t: crate::traits::ConfigTarget) -> Result<ServiceConfig> {
        Err(panel_core::PanelError::Unsupported("service.config (mock adapter has no real unit files)"))
    }

    async fn config_write(&self, _n: &UnitName, _content: &str, _restart: bool, _t: crate::traits::ConfigTarget) -> Result<()> {
        Err(panel_core::PanelError::Unsupported("service.config (mock adapter has no real unit files)"))
    }

    // mock 无真实单元文件，但装/删是"声明式写操作"——与 start/stop/set_enabled 一致地
    // 假装成功，让上层业务逻辑（apps → systemd → 站点）在 mock 下也能跑通。
    async fn install_unit(&self, _n: &UnitName, _content: &str) -> Result<()> { Ok(()) }
    async fn remove_unit(&self, _n: &UnitName) -> Result<()> { Ok(()) }
}

impl MockServices {
    fn set(&self, name: &UnitName, s: ServiceState) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        st.service_states.insert(name.as_str().to_string(), s);
        Ok(())
    }
}

// ───────────────────────── 防火墙（幂等可测） ─────────────────────────

pub struct MockFirewall { state: Arc<Mutex<State>> }

impl MockFirewall { pub(crate) fn new(state: Arc<Mutex<State>>) -> Self { Self { state } } }

#[async_trait]
impl FirewallProvider for MockFirewall {
    fn backend(&self) -> FirewallBackend { FirewallBackend::Nftables }
    fn capability(&self) -> Capability { Capability::yes("mock") }
    async fn is_active(&self) -> Result<bool> { Ok(true) }
    async fn set_active(&self, _a: bool) -> Result<()> { Ok(()) }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        Ok(self.state.lock().unwrap().rules.values().cloned().collect())
    }

    /// 幂等契约：同一 plan 连续 apply 两次，第二次 unchanged 计数应等于规则数
    async fn apply(&self, plan: RulePlan) -> Result<ApplyReport> {
        let mut st = self.state.lock().unwrap();
        st.apply_calls += 1;
        let mut rep = ApplyReport::default();
        for r in plan.rules {
            match st.rules.get(&r.id) {
                Some(existing) if existing == &r => rep.unchanged += 1,
                Some(_) => { st.rules.insert(r.id.clone(), r); rep.added += 1; }
                None => { st.rules.insert(r.id.clone(), r); rep.added += 1; }
            }
        }
        Ok(rep)
    }

    async fn snapshot(&self) -> Result<Vec<u8>> {
        Ok(b"mock-firewall-snapshot".to_vec())
    }
    async fn restore_snapshot(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() { return Err(PanelError::Validation { field: "snapshot", reason: "empty".into() }); }
        Ok(())
    }

    async fn delete_rule(&self, id: &str) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if st.rules.remove(id).is_some() { Ok(()) }
        else { Err(PanelError::NotFound(format!("firewall rule `{id}`"))) }
    }

    fn fail2ban_capability(&self) -> Capability { Capability::yes("mock") }
    async fn fail2ban_status(&self) -> Result<Fail2banStatus> {
        Ok(Fail2banStatus {
            available: true,
            active: true,
            jails: vec![Fail2banJail {
                name: "sshd".into(), enabled: true,
                currently_failed: 0, total_failed: 3, banned: 1,
                banned_ips: vec!["192.168.1.5".into()],
            }],
        })
    }
    async fn fail2ban_set_jail(&self, _name: &str, _enabled: bool) -> Result<()> { Ok(()) }
    async fn fail2ban_unban(&self, _jail: &str, _ip: &str) -> Result<()> { Ok(()) }
}

// ───────────────────────── 其余：显式不支持 ─────────────────────────

macro_rules! mock_unsupported {
    ($name:ident, $trait:path) => {
        pub struct $name;
    };
}
mock_unsupported!(MockPackages, PackageProvider);
mock_unsupported!(MockNetwork, NetworkProvider);
mock_unsupported!(MockUsers, UserProvider);
mock_unsupported!(MockStorage, StorageProvider);
mock_unsupported!(MockLogs, LogProvider);
mock_unsupported!(MockScheduler, SchedulerProvider);
mock_unsupported!(MockWebServer, WebServerProvider);
mock_unsupported!(MockDatabases, DatabaseProvider);
mock_unsupported!(MockSecurity, SecurityProvider);

#[async_trait]
impl PackageProvider for MockPackages {
    fn manager(&self) -> Option<&'static str> { Some("mock") }
    async fn detect_installed(&self, names: &[&str]) -> Result<Vec<PackageInfo>> {
        Ok(names.iter().map(|n| PackageInfo {
            name: n.to_string(), version: Some("1.0.0".into()),
            manager: "mock".into(), binaries: vec![PathBuf::from("/usr/bin").join(n)],
        }).collect())
    }
    async fn install(&self, _n: &str, _v: Option<&str>, cb: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        cb("mock: installing".into()); Ok(())
    }
    async fn remove(&self, _n: &str) -> Result<()> { Ok(()) }
    async fn list_versions(&self, _n: &str) -> Result<PackageVersions> {
        // 返回空列表：mock 没有真实软件源，调用方据此退回"装最新版"
        Ok(PackageVersions::default())
    }
    async fn ensure_repo(&self, _logical: &str, _cb: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        // mock 不接真实软件源；第三方源加源在测试里是 no-op
        Ok(())
    }

    async fn service_unit(&self, name: &str) -> Result<Option<String>> {
        // 给已知白名单包一个稳定的单元名，便于前端联调；其余返回 None。
        Ok(match name {
            "nginx" | "nginx-core" => Some("nginx.service".into()),
            "redis-server" | "redis" => Some("redis-server.service".into()),
            "postgresql" | "postgresql-18" | "postgresql-16" => Some("postgresql.service".into()),
            _ => None,
        })
    }

    async fn upgradable(&self, _names: &[&str]) -> Result<Vec<UpgradablePkg>> {
        // mock 不跑 apt；返回空列表=「无可升级项」，调用方应隐藏入口而非报错
        Ok(Vec::new())
    }

    async fn holds(&self) -> Result<Vec<String>> {
        // 进程内状态：mock 没有 apt-mark，用静态集合模拟「钉住全集」，
        // 使预览模式下 UI 的 hold 读写闭环（列徽标 + 切换后回读）可联调。
        let set = mock_holds().lock().unwrap();
        Ok(set.iter().cloned().collect())
    }

    async fn set_hold(&self, name: &str, held: bool) -> Result<()> {
        let mut set = mock_holds().lock().unwrap();
        if held { set.insert(name.to_string()); } else { set.remove(name); }
        Ok(())
    }
}

/// mock 的 hold 全集（进程级）。预览模式无真实包管理器，这组状态就是
/// 「本进程内被钉住的包」——刷新页面不丢（后端进程活着），重启即清空，
/// 与「mock 不改真实系统」的定位一致。
fn mock_holds() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    use std::sync::{Mutex, OnceLock};
    static HOLDS: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    HOLDS.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

#[async_trait]
impl NetworkProvider for MockNetwork {
    async fn interfaces(&self) -> Result<Vec<NetSample>> {
        MockMetrics.snapshot().await.map(|s| s.nets)
    }
    async fn listening(&self) -> Result<Vec<ListeningPort>> {
        Ok(vec![ListeningPort { port: 80, protocol: Protocol::Tcp,
                                addr: "0.0.0.0".into(), pid: Some(1), process: Some("nginx".into()) }])
    }
}

#[async_trait]
impl UserProvider for MockUsers {
    async fn exists(&self, name: &str) -> Result<bool> { Ok(name == "www-data") }
    async fn ensure(&self, _n: &str, _s: bool, _l: bool) -> Result<()> { Ok(()) }
    async fn uid_gid(&self, _n: &str) -> Result<(u32, u32)> { Ok((33, 33)) }
}

#[async_trait]
impl StorageProvider for MockStorage {
    async fn mounts(&self) -> Result<Vec<DiskSample>> { MockMetrics.snapshot().await.map(|s| s.disks) }
    async fn fs_type(&self, _p: &std::path::Path) -> Result<(String, bool)> { Ok(("ext4".into(), false)) }
    async fn set_permissions(&self, _p: &SafePath, _op: PermissionOp) -> Result<()> { Ok(()) }
    async fn set_owner_recursive(&self, _p: &SafePath, _u: &str) -> Result<()> { Ok(()) }
}

#[async_trait]
impl LogProvider for MockLogs {
    fn backend(&self) -> LogBackend { LogBackend::File }
    async fn sources(&self) -> Result<Vec<LogSource>> {
        Ok(vec![LogSource { id: "panel".into(), label: "Panel".into(), kind: LogSourceKind::Panel }])
    }
    async fn read(&self, _s: &LogSource, q: LogQuery) -> Result<Vec<LogLine>> {
        Ok((0..q.lines.min(10)).map(|i| LogLine {
            ts_unix: Some(1_700_000_000 + i as i64),
            level: Some("INFO".into()),
            text: format!("mock log {i}"),
        }).collect())
    }
    async fn follow(&self, _s: &LogSource, _q: LogQuery) -> Result<Receiver<LogLine>> {
        let (_tx, rx) = channel(1);
        Ok(rx)
    }
}

#[async_trait]
impl SchedulerProvider for MockScheduler {
    fn validate_expression(&self, e: &str) -> Result<()> {
        // 仅接受 5 段表达式的粗校验（真实实现见 M5）
        if e.split_whitespace().count() == 5 { Ok(()) }
        else { Err(PanelError::Validation { field: "cron", reason: "expected 5 fields".into() }) }
    }
    fn next_fire_times(&self, _e: &str, n: usize) -> Result<Vec<i64>> { Ok(vec![1_700_003_600; n]) }
    async fn list(&self) -> Result<Vec<ScheduledJob>> { Ok(vec![]) }
    async fn upsert(&self, _j: ScheduledJob) -> Result<()> { Ok(()) }
    async fn remove(&self, _i: &str) -> Result<()> { Ok(()) }
    async fn runs(&self, _i: &str, _l: usize) -> Result<Vec<JobRun>> { Ok(vec![]) }
}

#[async_trait]
impl WebServerProvider for MockWebServer {
    fn name(&self) -> &'static str { "mock" }
    fn conf_path(&self, server_names: &[String]) -> PathBuf {
        PathBuf::from("/etc/mock/conf.d")
            .join(format!("{}.conf", server_names.first().unwrap_or(&"site".into())))
    }
    fn render(&self, spec: &SiteSpec) -> Result<(PathBuf, String)> {
        Ok((self.conf_path(&spec.server_names), "server { listen 80; }".into()))
    }
    async fn validate(&self, _r: &str) -> Result<()> { Ok(()) }
    async fn deploy(&self, _t: &std::path::Path, _c: &str) -> Result<()> { Ok(()) }
    async fn reload(&self) -> Result<()> { Ok(()) }
}

#[async_trait]
impl DatabaseProvider for MockDatabases {
    fn engine(&self) -> DbEngine { DbEngine::Sqlite }
    async fn available(&self) -> Result<bool> { Ok(true) }
    fn supports(&self, e: DbEngine) -> bool { matches!(e, DbEngine::Sqlite) }
    async fn databases(&self, _t: &DbTarget) -> Result<Vec<String>> { Ok(vec!["panel".into()]) }
    async fn tables(&self, _t: &DbTarget) -> Result<Vec<DbTable>> {
        Ok(vec![DbTable { name: "sites".into(), rows: 3 }])
    }
    async fn rows(&self, _t: &DbTarget, _table: &str, _limit: usize, _offset: usize) -> Result<DbRows> {
        Ok(DbRows {
            columns: vec!["id".into(), "name".into()],
            rows: vec![
                vec![Some("1".into()), Some("demo".into())],
                vec![Some("2".into()), None],
            ],
            total: 2,
        })
    }
    async fn query(&self, _t: &DbTarget, _sql: &str, _limit: usize) -> Result<DbQueryResult> {
        Ok(DbQueryResult {
            columns: vec!["answer".into()],
            rows: vec![vec![Some("42".into())]],
            truncated: false,
        })
    }
    async fn backup(&self, _t: &DbTarget, _o: &SafePath, cb: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        cb("mock: dump complete".into()); Ok(())
    }
    async fn restore(&self, _t: &DbTarget, _f: &SafePath) -> Result<()> { Ok(()) }
}

// ═══════════════ 容器（模拟器） ═══════════════
//
// 定位说明：Mock 平台（非 Linux 目标 / `force-mock` 构建）本就以"固定样例数据"
// 驱动前端联调（与 MockDatabases 同性质），不是生产路径上的"假装成功"。

pub struct MockContainers;

#[async_trait]
impl ContainerProvider for MockContainers {
    fn engine(&self) -> ContainerEngine { ContainerEngine::Docker }
    fn available(&self) -> bool { true }
    fn unavailable_reason(&self) -> Option<&'static str> { None }

    async fn list(&self) -> Result<Vec<ContainerSummary>> {
        Ok(vec![ContainerSummary {
            id: "3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a".into(),
            name: "web-proxy".into(),
            image: "nginx:1.27-alpine".into(),
            state: "running".into(),
            status: "Up 9 days".into(),
            ports: "0.0.0.0:80->80/tcp".into(),
            created: "2026-09-20 08:12:33 +0800 CST".into(),
        }])
    }

    async fn images(&self) -> Result<Vec<ImageSummary>> {
        Ok(vec![ImageSummary {
            id: "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            repository: "nginx".into(),
            tag: "1.27-alpine".into(),
            size: "55.3MB".into(),
            created: "2026-07-11 10:00:00 +0800 CST".into(),
        }])
    }

    async fn act(&self, _action: ContainerAction, _id: &str) -> Result<()> { Ok(()) }

    async fn create(&self, req: ContainerCreateReq) -> Result<ContainerSummary> {
        // mock 不真正调用 docker：仅返回结构化摘要（id 用 name 派生，便于回放测试）
        Ok(ContainerSummary {
            id: format!("mock-{:x}", req.name.len()),
            name: req.name,
            image: req.image,
            state: "created".into(),
            status: "Created".into(),
            ports: req.ports.join(","),
            created: String::new(),
        })
    }
}

#[async_trait]
impl SecurityProvider for MockSecurity {
    /// mock 不写盘：一律返回"未改动"。真实校验/回滚逻辑在 `linux/security.rs` 单测覆盖。
    async fn apply(&self, _key: &str) -> Result<crate::traits::SecurityApplyResult> {
        Ok(crate::traits::SecurityApplyResult { changed: false, backup: None, validated: true })
    }

    async fn baseline(&self) -> Result<Vec<SecurityCheck>> {
        Ok(vec![
            SecurityCheck {
                key: "ssh.permit_root_login".into(), title: "SSH 禁止 root 直接登录".into(),
                ok: true, current: "PermitRootLogin no".into(), expected: "no".into(),
                advice: String::new(), applicable: true,
            },
            SecurityCheck {
                key: "service.fail2ban".into(), title: "部署 fail2ban 防暴力破解".into(),
                ok: false, current: "未安装".into(), expected: "已安装并启用 fail2ban".into(),
                advice: "apt install fail2ban".into(), applicable: true,
            },
        ])
    }
}

// ───────────────────────── 路径布局（内存视图） ─────────────────────────

pub struct MockPathLayout;

impl crate::PathLayout for MockPathLayout {
    fn config_dir(&self) -> PathBuf { PathBuf::from("/mock/etc/panel") }
    fn data_dir(&self) -> PathBuf { PathBuf::from("/mock/var/lib/panel") }
    fn log_dir(&self) -> PathBuf { PathBuf::from("/mock/var/log/panel") }
    fn cache_dir(&self) -> PathBuf { self.data_dir().join("cache") }
    fn tmp_dir(&self) -> PathBuf { self.data_dir().join("tmp") }
    fn site_root(&self) -> PathBuf { PathBuf::from("/mock/var/www") }
    fn web_conf_dir(&self) -> PathBuf { self.config_dir().join("nginx/conf.d") }
    fn web_log_dir(&self) -> PathBuf { self.log_dir().join("web") }
    fn service_dir(&self) -> PathBuf { PathBuf::from("/mock/etc/systemd/system") }
    fn cron_dir(&self) -> PathBuf { PathBuf::from("/mock/etc/cron.d") }
    fn script_dir(&self) -> PathBuf { self.data_dir().join("scripts") }
    fn backup_dir(&self) -> PathBuf { self.data_dir().join("backups") }
    fn container_socket(&self) -> PathBuf { PathBuf::from("/mock/var/run/docker.sock") }
    fn default_web_user(&self) -> &'static str { "www-data" }
}

// ═══════════════ 终端（模拟器） ═══════════════

/// Mock 终端：声明可用但不提供真实 PTY。
///
/// 注意：`cmd::spawn_pty` 是 Linux 实现（openpty 是 POSIX 专有），
/// 因此 mock 平台下开启终端会话会在 `spawn_pty` 处失败——这是**真实**的失败，
/// 不会伪装成成功。能力位在此仍报 yes，是为了让前端可以走通页面与置灰逻辑。
#[derive(Debug, Default)]
pub struct MockTerminal;

impl TerminalProvider for MockTerminal {
    fn available(&self) -> bool { true }
    // 测试用：能力位需要"有 shell"才置 yes，这里给一个恒可用的 Bin。
    fn shell(&self) -> Option<crate::cmd::Bin> { Some(crate::cmd::Bin::Sh) }
}

// ───────────────────────── 聚合 ─────────────────────────

impl crate::OsAdapter for MockOsAdapter {
    fn platform(&self) -> PlatformInfo {
        PlatformInfo { os: Os::Linux, arch: panel_core::Arch::X86_64, init: InitSystem::Systemd,
                       distro: Some("mock:1".into()), kernel: Some("mock".into()) }
    }

    fn host_profile(&self) -> (u64, u32) { (2048, 2) }

    fn files(&self) -> &dyn FileProvider { &*self.files }

    fn capabilities(&self) -> CapabilityMap {
        let mut m = CapabilityMap::new();
        for k in [cap_keys::METRICS_READ, cap_keys::PROCESS_LIST, cap_keys::PROCESS_SIGNAL,
                  cap_keys::SERVICE_MANAGE, cap_keys::PACKAGE_INSTALL, cap_keys::FIREWALL_MANAGE,
                  cap_keys::WEBSERVER_MANAGE, cap_keys::SCHEDULER_MANAGE, cap_keys::LOGS_READ,
                  cap_keys::DBMS_MANAGE, cap_keys::SSL_ACME, cap_keys::CONTAINER_VIEW,
                  cap_keys::CONTAINER_MANAGE, cap_keys::TERMINAL_MANAGE] {
            m.insert(k.into(), Capability::yes("mock"));
        }
        m
    }

    fn paths(&self) -> &dyn crate::PathLayout { &MockPathLayout }
    fn metrics(&self) -> &dyn MetricsProvider { &MockMetrics }
    fn processes(&self) -> &dyn ProcessProvider { &MockProcesses }
    fn services(&self) -> &dyn ServiceProvider { &*self.services }
    fn packages(&self) -> &dyn PackageProvider { &MockPackages }
    fn firewall(&self) -> &dyn FirewallProvider { &*self.firewall }
    fn network(&self) -> &dyn NetworkProvider { &MockNetwork }
    fn users(&self) -> &dyn UserProvider { &MockUsers }
    fn storage(&self) -> &dyn StorageProvider { &MockStorage }
    fn logs(&self) -> &dyn LogProvider { &MockLogs }
    fn scheduler(&self) -> &dyn SchedulerProvider { &MockScheduler }
    fn webserver(&self) -> &dyn WebServerProvider { &MockWebServer }
    fn databases(&self) -> &dyn DatabaseProvider { &MockDatabases }
    fn security(&self) -> &dyn SecurityProvider { &MockSecurity }
    fn containers(&self) -> &dyn ContainerProvider { &MockContainers }
    fn terminal(&self) -> &dyn TerminalProvider { &MockTerminal }
}
