//! Linux 服务管理：优先 systemd，回退 SysV / OpenRC（设计方案 §0.3.3）。
//!
//! 关键点：
//! - 单元名必须是校验过的 `UnitName`（强类型），绝不接受原始字符串。
//! - 所有调用经 `cmd::run`，无 shell、无拼接。
//! - 面板自身与被保护进程由业务层二次判定（此处只提供状态查询）。

use crate::{
    cmd::{self, Bin, CmdOpt},
    traits::{
        JournalQuery, ServiceFilter, ServiceProvider, ServiceState, ServiceUnit,
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

fn parse_systemd_list(s: &str) -> Vec<ServiceUnit> {
    let mut out = Vec::new();
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 { continue; }
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
}
