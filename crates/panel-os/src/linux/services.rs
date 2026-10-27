//! Linux 服务管理：优先 systemd，回退 SysV / OpenRC（设计方案 §0.3.3）。
//!
//! 关键点：
//! - 单元名必须是校验过的 `UnitName`（强类型），绝不接受原始字符串。
//! - 所有调用经 `cmd::run`，无 shell、无拼接。
//! - 面板自身与被保护进程由业务层二次判定（此处只提供状态查询）。

use crate::{
    cmd::{self, Bin, CmdOpt},
    linux::stub::parse_journal_json,
    traits::{
        JournalQuery, ServiceConfig, ServiceFilter, ServiceProvider, ServiceState, ServiceUnit,
    },
};
use async_trait::async_trait;
use panel_core::{InitSystem, Result, UnitName};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver};

pub struct LinuxServices {
    init: InitSystem,
}

impl LinuxServices {
    /// 探测 init 系统：/run/systemd/system 存在即为 systemd
    pub fn detect() -> Self {
        let init = if std::path::Path::new("/run/systemd/system").exists() {
            InitSystem::Systemd
        } else if std::path::Path::new("/sbin/rc-service").exists()
            || std::path::Path::new("/usr/bin/rc-service").exists() {
            InitSystem::OpenRc
        } else if std::path::Path::new("/etc/init.d").exists() {
            InitSystem::SysV
        } else {
            InitSystem::Unknown
        };
        Self { init }
    }
}

#[async_trait]
impl ServiceProvider for LinuxServices {
    fn init_system(&self) -> InitSystem { self.init }

    async fn list(&self, filter: ServiceFilter) -> Result<Vec<ServiceUnit>> {
        match self.init {
            InitSystem::Systemd => {
                let out = cmd::run(
                    Bin::Systemctl,
                    &["list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"],
                    CmdOpt { timeout: Duration::from_secs(5), ..Default::default() },
                ).await?;
                let mut units = parse_systemd_list(&out.stdout);
                if let Some(q) = &filter.name_contains {
                    let q = q.to_lowercase();
                    units.retain(|u| u.name.as_str().to_lowercase().contains(&q));
                }
                if let Some(st) = filter.state {
                    units.retain(|u| u.state == st);
                }
                Ok(units)
            }
            _ => Err(panel_core::PanelError::Unsupported("service.list requires systemd or a provider implementation")),
        }
    }

    async fn status(&self, name: &UnitName) -> Result<ServiceState> {
        match self.init {
            InitSystem::Systemd => {
                let out = cmd::run(Bin::Systemctl, &["is-active", name.as_str()], CmdOpt::default()).await?;
                Ok(parse_is_active_state(&out.stdout))
            }
            InitSystem::SysV => {
                let out = cmd::run(Bin::Service, &[name.as_str(), "status"], CmdOpt::default()).await?;
                Ok(if out.code == Some(0) { ServiceState::Active } else { ServiceState::Inactive })
            }
            _ => Err(panel_core::PanelError::Unsupported("service.status")),
        }
    }

    async fn statuses(&self, names: &[UnitName]) -> Result<HashMap<String, ServiceState>> {
        if names.is_empty() {
            return Ok(HashMap::new());
        }
        match self.init {
            InitSystem::Systemd => {
                // 一次 `systemctl is-active` 取多个单元，输出按入参顺序逐行（已本机实证）。
                let mut args: Vec<&str> = Vec::with_capacity(names.len() + 1);
                args.push("is-active");
                args.extend(names.iter().map(|n| n.as_str()));
                let out = cmd::run(Bin::Systemctl, &args, CmdOpt::default()).await?;
                let mut lines = out.stdout.lines();
                let mut map = HashMap::with_capacity(names.len());
                for u in names {
                    let line = lines.next().map(str::trim).unwrap_or("");
                    let st = parse_is_active_state(line);
                    map.insert(u.as_str().to_string(), st);
                }
                Ok(map)
            }
            // 非 systemd：无单次批量原语，退化为逐次 status（保持语义，仅为保底路径）。
            _ => {
                let mut map = HashMap::with_capacity(names.len());
                for u in names {
                    if let Ok(s) = self.status(u).await {
                        map.insert(u.as_str().to_string(), s);
                    }
                }
                Ok(map)
            }
        }
    }

    async fn show(&self, name: &UnitName) -> Result<Option<ServiceUnit>> {
        match self.init {
            InitSystem::Systemd => {
                let out = cmd::run(
                    Bin::Systemctl,
                    &[
                        "show", name.as_str(),
                        "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
                        "-p", "UnitFileState", "-p", "Description",
                        "--no-pager",
                    ],
                    CmdOpt { timeout: Duration::from_secs(5), ..Default::default() },
                ).await?;
                // 单元不存在（LoadState=not-found）或输出异常 → None，由路由回 404。
                // 用 `name` 直接构造强类型（show 的入参已校验），无需再次解析。
                Ok(parse_systemd_show(&out.stdout, name))
            }
            _ => Err(panel_core::PanelError::Unsupported("service.show requires systemd")),
        }
    }

    async fn start(&self, name: &UnitName) -> Result<()> { self.act("start", name).await }
    async fn stop(&self, name: &UnitName) -> Result<()> { self.act("stop", name).await }
    async fn restart(&self, name: &UnitName) -> Result<()> { self.act("restart", name).await }
    async fn reload(&self, name: &UnitName) -> Result<()> { self.act("reload", name).await }

    async fn set_enabled(&self, name: &UnitName, enabled: bool) -> Result<()> {
        let verb = if enabled { "enable" } else { "disable" };
        cmd::run_checked(
            Bin::Systemctl,
            &[verb, name.as_str()],
            CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
        ).await.map(|_| ())
    }

    async fn journal(&self, name: &UnitName, q: JournalQuery) -> Result<Receiver<String>> {
        let (tx, rx) = mpsc::channel(64);
        let lines = q.lines.min(2000).to_string();
        let unit = format!("-u{}", name.as_str());

        if !q.follow {
            // 一次性读取（无 journald 时回退：读取 /var/log 下的对应文件由 LogProvider 负责）
            let out = cmd::run(
                Bin::Journalctl,
                // `-o json` 取结构化字段，再统一格式化成 `YYYY-MM-DD HH:MM:SS 消息`
                // （`-o cat` 只有消息、丢时间；`short-iso` 带主机名/单元名前缀太杂）。
                &[&unit, "-n", &lines, "--no-pager", "-o", "json"],
                CmdOpt {
                    timeout: Duration::from_secs(5),
                    // JSON 每行比裸消息大数倍，2000 行可能 >1MB；放大上限避免
                    // collect 从头累积时把**最新**的日志截掉。
                    max_output: 4 * 1024 * 1024,
                    ..Default::default()
                },
            ).await?;
            // ⚠ 绝不能在这里同步 `tx.send`：channel 有界（64），消费者要等本函数
            // 返回拿到 rx 后才开始 recv ⇒ 日志 >64 行时 send 永久阻塞。实测
            // accounts-daemon 139 行、路由的 10s 兜底都轮不到，请求直接挂死。
            // 把灌入放到独立任务：本函数立即返回 rx，边收边灌（仍有背压）。
            let formatted: Vec<String> =
                out.stdout.lines().filter_map(format_journal_line).collect();
            pump_lines(formatted, tx);
            return Ok(rx);
        }

        // follow 模式：走 cmd 唯一出口的流式变体（禁止在此处直接 spawn）。
        // 原始行是 journalctl 的 JSON，逐行转成 `YYYY-MM-DD HH:MM:SS 消息`再推给前端。
        let args = [unit.as_str(), "-n", lines.as_str(), "-f", "--no-pager", "-o", "json"];
        let mut raw = cmd::spawn_stream(Bin::Journalctl, &args, 64)?;
        let (ftx, frx) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(line) = raw.recv().await {
                if let Some(f) = format_journal_line(&line) {
                    if ftx.send(f).await.is_err() { break; }
                }
            }
        });
        return Ok(frx);
    }

    async fn config_read(&self, name: &UnitName, target: crate::traits::ConfigTarget) -> Result<ServiceConfig> {
        match self.init {
            InitSystem::Systemd => {
                let path = match target {
                    crate::traits::ConfigTarget::Unit => fragment_path(name).await?,
                    crate::traits::ConfigTarget::DropIn => drop_in_path(name)?,
                };
                // 仅 /etc/systemd/ 下为可覆盖目录；/lib、/usr/lib 下是发行版文件，
                // 直接改会在包升级时被覆盖，前端据此提示改用 drop-in。
                let writable = path.starts_with("/etc/systemd/");
                // drop-in 允许"文件尚不存在"：返回空内容 + exists=false，
                // 前端据此提示"保存后将新建"，而不是报 404 / 不支持——
                // 否则用户永远无法通过面板新建 drop-in。
                let (content, exists) = match tokio::fs::read_to_string(&path).await {
                    Ok(c) => (c, true),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound
                        && target == crate::traits::ConfigTarget::DropIn => (String::new(), false),
                    Err(e) => return Err(panel_core::PanelError::Io(
                        format!("read {path}: {e}"))),
                };
                Ok(ServiceConfig { path, content, writable, exists })
            }
            _ => Err(panel_core::PanelError::Unsupported("service.config_read requires systemd")),
        }
    }

    async fn config_write(&self, name: &UnitName, content: &str, restart: bool, target: crate::traits::ConfigTarget) -> Result<()> {
        match self.init {
            InitSystem::Systemd => {
                // 先确认真实写入路径，禁止把任意 content 写到任意文件
                let path = match target {
                    crate::traits::ConfigTarget::Unit => fragment_path(name).await?,
                    crate::traits::ConfigTarget::DropIn => {
                        let p = drop_in_path(name)?;
                        let dir = p.rsplit_once('/').map(|(d, _)| d.to_string())
                            .unwrap_or_else(|| "/etc/systemd/system".to_string());
                        // drop-in 目录首次使用时尚不存在，幂等创建
                        tokio::fs::create_dir_all(&dir).await
                            .map_err(|e| panel_core::PanelError::Io(format!("mkdir {dir}: {e}")))?;
                        p
                    }
                };

                // 原子替换：先备份为 .panel.bak（best-effort；文件可能尚不存在），
                // 再写临时文件并 rename。不原地写——半写状态会让 unit 文件损坏、
                // 该服务再也起不来。
                let _ = tokio::fs::copy(&path, format!("{path}.panel.bak")).await;
                let tmp = format!("{path}.panel.tmp");
                tokio::fs::write(&tmp, content.as_bytes()).await
                    .map_err(|e| panel_core::PanelError::Io(format!("write {tmp}: {e}")))?;
                tokio::fs::rename(&tmp, &path).await
                    .map_err(|e| panel_core::PanelError::Io(format!("rename to {path}: {e}")))?;

                // 重新加载 systemd 单元（不重启服务本身，避免误杀在线连接）
                cmd::run_checked(
                    Bin::Systemctl, &["daemon-reload"],
                    CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
                ).await.map_err(|e| panel_core::PanelError::Command {
                    bin: "systemctl".into(), detail: format!("daemon-reload: {e}"),
                })?;

                if restart {
                    self.restart(name).await?;
                }
                Ok(())
            }
            _ => Err(panel_core::PanelError::Unsupported("service.config_write requires systemd")),
        }
    }

    async fn install_unit(&self, name: &UnitName, content: &str) -> Result<()> {
        match self.init {
            InitSystem::Systemd => {
                let path = system_unit_path(name)?;
                // 原子替换：先写临时文件再 rename。不原地写——半写状态会让单元文件损坏，
                // systemd 随后连 `daemon-reload` 都会拒绝整份单元。
                // 刻意**不**备份成 `.panel.bak`：面板自建的单元以 DB 为真相源，
                // 重写就是最新，留着旧备份反而会被误当成"用户的原始配置"。
                let tmp = format!("{path}.panel.tmp");
                tokio::fs::write(&tmp, content.as_bytes()).await
                    .map_err(|e| panel_core::PanelError::Io(format!("write {tmp}: {e}")))?;
                tokio::fs::rename(&tmp, &path).await
                    .map_err(|e| panel_core::PanelError::Io(format!("rename to {path}: {e}")))?;
                daemon_reload().await
            }
            _ => Err(panel_core::PanelError::Unsupported("service.install_unit requires systemd")),
        }
    }

    async fn remove_unit(&self, name: &UnitName) -> Result<()> {
        match self.init {
            InitSystem::Systemd => {
                let path = system_unit_path(name)?;
                // 幂等：文件不存在不算错（可能删过一次，或从未成功安装过）
                match tokio::fs::remove_file(&path).await {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(panel_core::PanelError::Io(format!("remove {path}: {e}"))),
                }
                daemon_reload().await
            }
            _ => Err(panel_core::PanelError::Unsupported("service.remove_unit requires systemd")),
        }
    }
}

/// 面板自建单元的落盘路径：`/etc/systemd/system/<unit>`。
///
/// 与 `fragment_path`（走 `systemctl show` 查已装单元的 FragmentPath）的区别：本函数
/// 用于**尚未安装**的单元——此刻没有任何 FragmentPath 可查。因此安全性完全依赖
/// `UnitName` 的校验 + 本函数再兜的一次后缀与穿越检查：写系统目录前**绝不**信任
/// 调用方拼好的字符串。
fn system_unit_path(name: &UnitName) -> Result<String> {
    let u = name.as_str();
    if !u.ends_with(".service") || u.contains('/') || u.contains("..") || u.starts_with('-') {
        return Err(panel_core::PanelError::Validation {
            field: "unit",
            reason: format!("refuse to install unit with unsafe name: {u:?}"),
        });
    }
    Ok(format!("/etc/systemd/system/{u}"))
}

/// `systemctl daemon-reload`——装/删单元后必须调用，否则 systemd 仍持旧单元表。
async fn daemon_reload() -> Result<()> {
    cmd::run_checked(
        Bin::Systemctl, &["daemon-reload"],
        CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
    ).await.map_err(|e| panel_core::PanelError::Command {
        bin: "systemctl".into(), detail: format!("daemon-reload: {e}"),
    }).map(|_| ())
}

/// 单元文件真实路径（`systemctl show -p FragmentPath`）+ 路径安全校验。
async fn fragment_path(name: &UnitName) -> Result<String> {
    let out = cmd::run(
        Bin::Systemctl,
        &["show", "-p", "FragmentPath", "--value", name.as_str()],
        CmdOpt { timeout: Duration::from_secs(5), ..Default::default() },
    ).await?;
    let path = out.stdout.trim().to_string();
    if path.is_empty() {
        // 生成型单元（如 some.service 由其他 unit 反代）没有独立文件
        return Err(panel_core::PanelError::Unsupported(
            "service has no fragment path (generated unit?)"));
    }
    // 防御：只接受绝对路径且不含路径穿越（FragmentPath 来自 systemctl，
    // 理论上安全，但写操作前必须再校验一次，绝不信任外部字符串拼路径）
    if !path.starts_with('/') || path.contains("..") {
        return Err(panel_core::PanelError::Unsupported(
            "service config path is not a safe absolute path"));
    }
    Ok(path)
}

/// drop-in 路径：`/etc/systemd/system/<unit>.d/override.conf`
fn drop_in_path(name: &UnitName) -> Result<String> {
    let u = name.as_str();
    // 单元名已由 UnitName 校验，但拼路径前再兜一次：绝不允许穿越出目录
    if u.trim().is_empty() || u.contains('/') || u.contains("..") {
        return Err(panel_core::PanelError::Unsupported(
            "invalid unit name for drop-in path"));
    }
    Ok(format!("/etc/systemd/system/{u}.d/override.conf"))
}

impl LinuxServices {
    async fn act(&self, verb: &str, name: &UnitName) -> Result<()> {
        match self.init {
            InitSystem::Systemd => cmd::run_checked(
                Bin::Systemctl, &[verb, name.as_str()],
                CmdOpt { timeout: Duration::from_secs(30), ..Default::default() },
            ).await.map(|_| ()),
            InitSystem::SysV => cmd::run_checked(
                Bin::Service, &[name.as_str(), verb],
                CmdOpt { timeout: Duration::from_secs(30), ..Default::default() },
            ).await.map(|_| ()),
            InitSystem::OpenRc => cmd::run_checked(
                Bin::RcService, &[name.as_str(), verb],
                CmdOpt { timeout: Duration::from_secs(30), ..Default::default() },
            ).await.map(|_| ()),
            _ => Err(panel_core::PanelError::Unsupported("service action")),
        }
    }
}

/// 解析 `systemctl show -p LoadState -p ActiveState -p SubState -p UnitFileState -p Description` 的输出。
///
/// - 单元不存在（`LoadState=not-found`）、被屏蔽或输出为空 → 返回 `None`。
/// - 否则构造 `ServiceUnit`：`enabled` 取自 `UnitFileState`（enabled / enabled-runtime 视为已启用）；
///   `description` 可为空；`pid` / `memory_kib` 该命令取不到，留 `None`（详情页这些数据非必需）。
fn parse_systemd_show(out: &str, name: &UnitName) -> Option<ServiceUnit> {
    let mut load = "";
    let mut active = "";
    let mut unit_file = "";
    let mut desc = String::new();
    for line in out.lines() {
        if let Some(v) = line.strip_prefix("LoadState=") { load = v; }
        else if let Some(v) = line.strip_prefix("ActiveState=") { active = v; }
        else if let Some(v) = line.strip_prefix("UnitFileState=") { unit_file = v; }
        else if let Some(v) = line.strip_prefix("Description=") { desc = v.to_string(); }
    }
    // 只认真正加载成功的单元；not-found / masked / error / generated 等一律视为"查不到"
    if load != "loaded" {
        return None;
    }
    let state = match active {
        "active" => ServiceState::Active,
        "inactive" => ServiceState::Inactive,
        "failed" => ServiceState::Failed,
        "activating" => ServiceState::Activating,
        "deactivating" => ServiceState::Deactivating,
        _ => ServiceState::Unknown,
    };
    let enabled = matches!(unit_file, "enabled" | "enabled-runtime");
    Some(ServiceUnit {
        name: name.clone(),
        description: desc,
        state,
        enabled,
        pid: None,
        memory_kib: None,
    })
}

fn parse_systemd_list(s: &str) -> Vec<ServiceUnit> {
    let mut out = Vec::new();
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 { continue; }
        // 结构校验：第二列必须是 systemd 的 LOAD 状态。
        // 只校验单元名是不够的——畸形行（如 `bad name!!  loaded active running`）的第一个
        // token 可能恰好是合法单元名（"bad"），从而被当成正常服务收进来。
        // LOAD 取值是稳定且封闭的小集合，不认识即判定这行不是 systemctl 的正常输出。
        const LOAD_STATES: &[&str] = &[
            "loaded", "not-found", "bad-setting", "error", "masked", "stub", "alias", "generated",
        ];
        if !LOAD_STATES.contains(&f[1]) { continue; }
        let name = f[0].to_string();
        // 仅接受合法单元名：不合法即跳过，绝不进入后续命令
        let Ok(unit) = panel_core::unit_name(&name) else { continue };
        let state = match f[2] {
            "active" => ServiceState::Active,
            "inactive" => ServiceState::Inactive,
            "failed" => ServiceState::Failed,
            "activating" => ServiceState::Activating,
            "deactivating" => ServiceState::Deactivating,
            _ => ServiceState::Unknown,
        };
        out.push(ServiceUnit {
            name: unit,
            description: f[3..].join(" "),
            state,
            enabled: false,   // 需额外 `is-enabled` 查询；低配下按需获取
            pid: None,
            memory_kib: None,
        });
    }
    out
}

/// 解析 `systemctl is-active` 的单行输出 → 状态。未知/异常/空值一律 `Unknown`。
/// 抽成自由函数：① `status` 与 `statuses` 共用，避免映射漂移；② 可单测、不依赖 systemd。
fn parse_is_active_state(line: &str) -> ServiceState {
    match line.trim() {
        "active" => ServiceState::Active,
        "inactive" => ServiceState::Inactive,
        "failed" => ServiceState::Failed,
        "activating" => ServiceState::Activating,
        "deactivating" => ServiceState::Deactivating,
        _ => ServiceState::Unknown,
    }
}

/// 把已格式化的日志行灌入有界 channel，**在独立任务里**执行，调用方立即返回。
/// 抽成函数是为了可单测「调用方不被阻塞」这一死锁回归（见 tests）。
fn pump_lines(lines: Vec<String>, tx: mpsc::Sender<String>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for line in lines {
            if tx.send(line).await.is_err() { break; }
        }
    })
}

/// `journalctl -o json` 的单行 → `YYYY-MM-DD HH:MM:SS 消息`（本地时区）。
/// 非 JSON 行（`-- Boot ... --` 分隔符）原样保留；解析失败且不像分隔符则丢弃。
fn format_journal_line(raw: &str) -> Option<String> {
    match parse_journal_json(raw) {
        Some(l) => Some(match l.ts_unix {
            Some(secs) => format!("{} {}", format_local_ts(secs), l.text),
            // 极少数缺 __REALTIME_TIMESTAMP 的条目：只给消息，不伪造时间
            None => l.text,
        }),
        None if raw.starts_with("-- ") => Some(raw.to_string()),
        None => None,
    }
}

/// epoch 秒 → 本地时区 `YYYY-MM-DD HH:MM:SS`。
/// 用 libc `localtime_r`（libc 已是本 crate 直接依赖），不引入 chrono/time 新依赖
/// （直接依赖预算上限 38，去重后现约 22）。转换失败给占位符，绝不 panic。
fn format_local_ts(secs: i64) -> String {
    // time_t 在现代 64 位平台（glibc / musl 1.2.0+）恒为 64 位；libc 已弃用
    // `libc::time_t` 类型别名（musl 1.2.0 起改 64 位），直接用 i64 避免弃用警告。
    let t = secs;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r 只写我们提供的 tm；t 为合法 i64（time_t 在目标平台恒 64 位）。
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if !ok {
        return "????-??-?? ??:??:??".to_string();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归：`journal()` 的非 follow 分支必须把灌入放到独立任务，调用方立即返回。
    /// 旧实现同步 `tx.send` 进容量 64 的 channel，消费者要等 `journal()` 返回后才
    /// recv ⇒ 日志 >64 行时死锁（dev 实测 accounts-daemon 139 行，请求挂死 >20s）。
    /// 本测试不依赖 journalctl：直接给 `pump_lines` 200 行，要求立即返回且不丢行。
    /// ⚠ 下面那层 `async move { pump_lines(..) }` 是**故意**的，不是冗余：
    /// `pump_lines` 是**同步**函数（内部 spawn 任务后立刻返回 JoinHandle），这层 async
    /// 块把那次**同步调用**放进 timeout 之内——若它哪天退化成同步灌入，channel 满（64 行）
    /// 处会阻塞，2s 超时直接失败，正是本测试要抓的回归。
    /// ⚠ 而 timeout **不能**直接吃 JoinHandle：那会等到任务**完成**，而任务要等我们抽干
    /// channel 才完成 ⇒ 死锁 + 超时误报。故此处"吐出 awaitable 的 JoinHandle"是有意为之。
    #[allow(clippy::async_yields_async)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_lines_returns_immediately_and_delivers_all() {
        let (tx, mut rx) = mpsc::channel::<String>(64);
        let lines: Vec<String> = (0..200).map(|i| format!("line-{i}")).collect();
        // 若 pump_lines 同步灌入，这里会在 64 行处阻塞，2s 超时直接失败。
        let handle = tokio::time::timeout(Duration::from_secs(2), async move {
            pump_lines(lines, tx)
        }).await.expect("pump_lines 不得阻塞调用方（否则 channel 满即死锁）");

        let mut n = 0;
        while rx.recv().await.is_some() { n += 1; }
        handle.await.expect("pump 任务不应 panic");
        assert_eq!(n, 200, "200 行必须全部送达");
    }

    /// `-o json` → `YYYY-MM-DD HH:MM:SS 消息`（时间部分只验形状，具体值依赖本地时区）。
    #[test]
    fn journal_json_is_formatted_with_local_timestamp() {
        let raw = r#"{"__REALTIME_TIMESTAMP":"1700000000000000","MESSAGE":"hello world"}"#;
        let got = format_journal_line(raw).expect("应能格式化");
        let b = got.as_bytes();
        assert!(b.len() > 20, "过短：{got}");
        assert_eq!(&got[4..5], "-"); assert_eq!(&got[7..8], "-");
        assert_eq!(&got[10..11], " ");
        assert_eq!(&got[13..14], ":"); assert_eq!(&got[16..17], ":");
        assert_eq!(&got[19..20], " ", "时间与消息之间应有空格：{got}");
        assert_eq!(&got[20..], "hello world");
        assert!(got.starts_with("20"), "年份应合理：{got}");

        // 缺时间戳：只给消息，不伪造时间
        let raw = r#"{"MESSAGE":"no ts"}"#;
        assert_eq!(format_journal_line(raw).as_deref(), Some("no ts"));

        // boot 分隔符原样保留；坏 JSON 丢弃
        assert_eq!(format_journal_line("-- Boot abc --").as_deref(), Some("-- Boot abc --"));
        assert!(format_journal_line("{not json").is_none());
    }

    #[test]
    fn parser_skips_malformed() {
        let s = "nginx.service  loaded active running  nginx\nbad name!!  loaded active running\n";
        let v = parse_systemd_list(s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name.as_str(), "nginx.service");
        assert_eq!(v[0].state, ServiceState::Active);
    }

    #[test]
    fn parser_rejects_injection_shaped_names() {
        // 即便 systemctl 输出被污染，非法单元名也不会进入强类型
        let s = "evil;rm -rf /  loaded active running\n";
        assert!(parse_systemd_list(s).is_empty());
    }

    #[test]
    fn parse_systemd_show_handles_dead_and_missing() {
        // 刚装好、enabled 但 dead（从未 start）的服务：LoadState=loaded、ActiveState=inactive
        let dead = "LoadState=loaded\nActiveState=inactive\nSubState=dead\n\
                    UnitFileState=enabled\nDescription=A high performance web server\n";
        let un = panel_core::unit_name("nginx.service").unwrap();
        let u = parse_systemd_show(dead, &un).expect("dead 服务应可被查到");
        assert_eq!(u.state, ServiceState::Inactive);
        assert!(u.enabled);
        assert_eq!(u.description, "A high performance web server");

        // 单元根本不存在 → None（路由据此回 404）
        assert!(parse_systemd_show("LoadState=not-found\n", &un).is_none());
        // 输出为空（异常）也应 None
        assert!(parse_systemd_show("", &un).is_none());
    }

    #[test]
    fn parse_is_active_state_maps_each_line_and_defaults_unknown() {
        // 与 `systemctl is-active` 真实输出逐行映射一致（已在本机实证：输出顺序 = 入参顺序）
        assert_eq!(parse_is_active_state("active\n"), ServiceState::Active);
        assert_eq!(parse_is_active_state("inactive"), ServiceState::Inactive);
        assert_eq!(parse_is_active_state("failed"), ServiceState::Failed);
        assert_eq!(parse_is_active_state("activating"), ServiceState::Activating);
        assert_eq!(parse_is_active_state("deactivating"), ServiceState::Deactivating);
        // 空行 / 未知值（如不存在单元返回 "unknown"、或异常输出）一律 Unknown
        assert_eq!(parse_is_active_state(""), ServiceState::Unknown);
        assert_eq!(parse_is_active_state("unknown"), ServiceState::Unknown);
        assert_eq!(parse_is_active_state("weird\noutput"), ServiceState::Unknown);
    }
}
