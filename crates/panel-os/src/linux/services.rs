//! Linux 服务管理：优先 systemd，回退 SysV / OpenRC（设计方案 §0.3.3）。
//!
//! 关键点：
//! - 单元名必须是校验过的 `UnitName`（强类型），绝不接受原始字符串。
//! - 所有调用经 `cmd::run`，无 shell、无拼接。
//! - 面板自身与被保护进程由业务层二次判定（此处只提供状态查询）。

use crate::{
    cmd::{self, Bin, CmdOpt},
    traits::{
        JournalQuery, ServiceConfig, ServiceFilter, ServiceProvider, ServiceState, ServiceUnit,
    },
};
use async_trait::async_trait;
use panel_core::{InitSystem, Result, UnitName};
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
                Ok(match out.stdout.trim() {
                    "active" => ServiceState::Active,
                    "inactive" => ServiceState::Inactive,
                    "failed" => ServiceState::Failed,
                    "activating" => ServiceState::Activating,
                    "deactivating" => ServiceState::Deactivating,
                    _ => ServiceState::Unknown,
                })
            }
            InitSystem::SysV => {
                let out = cmd::run(Bin::Service, &[name.as_str(), "status"], CmdOpt::default()).await?;
                Ok(if out.code == Some(0) { ServiceState::Active } else { ServiceState::Inactive })
            }
            _ => Err(panel_core::PanelError::Unsupported("service.status")),
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
        let _ = &tx;
        let lines = q.lines.min(2000).to_string();
        let unit = format!("-u{}", name.as_str());

        if !q.follow {
            // 一次性读取（无 journald 时回退：读取 /var/log 下的对应文件由 LogProvider 负责）
            let out = cmd::run(
                Bin::Journalctl,
                &[&unit, "-n", &lines, "--no-pager", "-o", "cat"],
                CmdOpt { timeout: Duration::from_secs(5), ..Default::default() },
            ).await?;
            for line in out.stdout.lines() {
                if tx.send(line.to_string()).await.is_err() { break; }
            }
            return Ok(rx);
        }

        // follow 模式：走 cmd 唯一出口的流式变体（禁止在此处直接 spawn）
        let args = [unit.as_str(), "-n", lines.as_str(), "-f", "--no-pager", "-o", "cat"];
        return cmd::spawn_stream(Bin::Journalctl, &args, 64);
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
