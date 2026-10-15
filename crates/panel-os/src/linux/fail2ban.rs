//! fail2ban 入侵防御 jail 管理（`fail2ban-client` 封装）。
//!
//! **与防火墙后端正交**：fail2ban 是独立服务，经 `fail2ban-client` 交互；它用什么
//! banaction（iptables/nftables/firewalld…）执行封禁，与面板选用的防火墙 provider
//! 无关。因此本实现被 ufw 与 nftables 两个防火墙后端**共用**。
//!
//! 能力位只按 `fail2ban-client` 二进制存在性判定——「装没装 fail2ban-client」是事实，
//! 与「宿主用 ufw 还是 nft」没有因果关系。（历史教训：fail2ban 实现曾被绑死在 ufw 后端里，
//! nftables 后端把 fail2ban 硬编码为 `Unsupported`，导致只装 nft 的机器上即便
//! fail2ban-client 齐全且工作正常，功能也被武断判死——故抽成此处共享。）
//!
//! **护栏**：
//! - 能力位诚实：二进制缺失即报不支持，前端据此置灰，绝不伪造成功。
//! - jail 名 / IP 参数严格校验（`is_safe_jail_name` + `IpAddr` 解析），防参数注入 argv。
//! - 只调用 `fail2ban-client` 标准子命令（`ping`/`status`/`set … on|off|unbanip`），
//!   不触碰防火墙底层规则，与面板自有 `panel-managed` 规则体系互不干扰。

use crate::cmd::{Bin, CmdOpt};
use crate::traits::{Fail2banJail, Fail2banStatus};
use panel_core::{Capability, PanelError, Result};
use std::time::Duration;

/// fail2ban-client 管理器（无状态，ufw / nftables 两个防火墙后端共用）。
pub struct Fail2ban;

impl Fail2ban {
    /// 能力位：只看 `fail2ban-client` 二进制是否存在，与防火墙后端无关。
    pub fn capability() -> Capability {
        if Bin::Fail2banClient.available() {
            Capability::yes("fail2ban-client")
        } else {
            Capability::no("binary_missing")
        }
    }

    /// 总览：可用性与各 jail 状态。fail2ban-client 缺失 → `available:false`（不是错误）。
    pub async fn status() -> Result<Fail2banStatus> {
        if !Bin::Fail2banClient.available() {
            return Ok(Fail2banStatus { available: false, active: false, jails: vec![] });
        }
        // `fail2ban-client ping` 成功（回 "Server replied: pong"）表示服务在运行
        let ping = crate::cmd::run(
            Bin::Fail2banClient, &["ping"],
            CmdOpt { timeout: Duration::from_secs(10), ..Default::default() },
        ).await?;
        let active = ping.code == Some(0) && ping.stdout.contains("pong");

        let mut status = Fail2banStatus { available: true, active, jails: vec![] };
        if !active {
            return Ok(status);
        }
        let out = crate::cmd::run(
            Bin::Fail2banClient, &["status"],
            CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
        ).await?;
        for name in parse_jail_list(&out.stdout) {
            let jo = crate::cmd::run(
                Bin::Fail2banClient, &["status", &name],
                CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
            ).await?;
            status.jails.push(parse_jail_detail(&name, &jo.stdout));
        }
        Ok(status)
    }

    /// 启停某 jail（等价 `fail2ban-client set <jail> on/off`）。
    pub async fn set_jail(name: &str, enabled: bool) -> Result<()> {
        if !is_safe_jail_name(name) {
            return Err(PanelError::Validation { field: "name", reason: "jail 名非法（仅字母数字与 _ -）".into() });
        }
        let out = crate::cmd::run(
            Bin::Fail2banClient, &["set", name, if enabled { "on" } else { "off" }],
            CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
        ).await?;
        if out.code != Some(0) {
            return Err(PanelError::Command { bin: "fail2ban-client".into(), detail: out.stderr.trim().to_string() });
        }
        Ok(())
    }

    /// 解封某 jail 下的某个 IP（等价 `fail2ban-client set <jail> unbanip <ip>`）。
    pub async fn unban(jail: &str, ip: &str) -> Result<()> {
        if !is_safe_jail_name(jail) || ip.parse::<std::net::IpAddr>().is_err() {
            return Err(PanelError::Validation { field: "jail/ip", reason: "jail 名或 IP 非法".into() });
        }
        let out = crate::cmd::run(
            Bin::Fail2banClient, &["set", jail, "unbanip", ip],
            CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
        ).await?;
        if out.code != Some(0) {
            return Err(PanelError::Validation { field: "ip", reason: format!("解封失败：{}", out.stderr.trim()) });
        }
        Ok(())
    }
}

/// jail 名只允许字母数字与 _ -（防参数注入进 fail2ban-client argv）。
fn is_safe_jail_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// 解析 `fail2ban-client status` 的 "Jail list: a, b"（行带 `|-` / `-` 前缀，故用 find）。
fn parse_jail_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(idx) = l.find("Jail list:") {
            let rest = &l[idx + "Jail list:".len()..];
            for part in rest.split(',') {
                let p = part.trim();
                if !p.is_empty() { out.push(p.to_string()); }
            }
        }
    }
    out
}

/// 解析单 jail 详情（currently/total failed、currently banned、banned IP 列表）。
/// 行带 `|-` / `-` 前缀，用 find 定位 key 而非 strip_prefix。
fn parse_jail_detail(name: &str, text: &str) -> Fail2banJail {
    let mut j = Fail2banJail { name: name.to_string(), enabled: true, ..Default::default() };
    for line in text.lines() {
        let l = line.trim();
        if let Some(idx) = l.find("Currently failed:") {
            j.currently_failed = l[idx + "Currently failed:".len()..].trim().parse().unwrap_or(0);
        } else if let Some(idx) = l.find("Total failed:") {
            j.total_failed = l[idx + "Total failed:".len()..].trim().parse().unwrap_or(0);
        } else if let Some(idx) = l.find("Currently banned:") {
            j.banned = l[idx + "Currently banned:".len()..].trim().parse().unwrap_or(0);
        } else if l.contains("Banned IP list:") {
            let rest = l.split_once(':').map(|(_, r)| r).unwrap_or("").trim();
            if !rest.is_empty() {
                j.banned_ips = rest.split_whitespace().map(|s| s.to_string()).collect();
            }
        }
    }
    j
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jail_list_parsing() {
        let out = "Status\n|- Number of jail:\t2\n`- Jail list:   sshd, nginx\n";
        assert_eq!(parse_jail_list(out), vec!["sshd", "nginx"]);
        assert!(parse_jail_list("nothing here").is_empty());
    }

    #[test]
    fn jail_detail_parsing() {
        let out = "\
Status for the jail: sshd
|- Filter
|  |- Currently failed: 3
|  `- Total failed:     12
`- Actions
   |- Currently banned: 1
   |- Total banned:     2
   `- Banned IP list:   192.168.1.5 10.0.0.2
";
        let j = parse_jail_detail("sshd", out);
        assert_eq!(j.name, "sshd");
        assert_eq!(j.currently_failed, 3);
        assert_eq!(j.total_failed, 12);
        assert_eq!(j.banned, 1);
        assert_eq!(j.banned_ips, vec!["192.168.1.5", "10.0.0.2"]);
    }

    #[test]
    fn jail_name_guard() {
        // 防参数注入：jail 名只允许字母数字与 _ -
        assert!(is_safe_jail_name("sshd"));
        assert!(is_safe_jail_name("nginx-badbot"));
        assert!(!is_safe_jail_name(""));
        assert!(!is_safe_jail_name("ssh; rm -rf /"));
        assert!(!is_safe_jail_name("../etc"));
    }

    /// 能力位不能撒谎：必须与 fail2ban-client 二进制实际可用性一致。
    #[test]
    fn capability_is_honest() {
        assert_eq!(Fail2ban::capability().supported, Bin::Fail2banClient.available(),
                   "能力位必须与二进制实际可用性一致，否则前端会伪造成功");
    }
}
