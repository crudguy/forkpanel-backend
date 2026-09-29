//! 安全基线扫描（**只读**）。
//!
//! 纪律：本模块**绝不修改系统**——只读取配置文件与既有事实，产出分级发现项。
//! 任何"修复"（写回 sshd_config 等）都是独立的高危操作，需 root + 二次确认，
//! 且必须先备份，避免把 SSH 锁死（详见设计方案 §2.10）。

use crate::traits::*;
use async_trait::async_trait;
use panel_core::Result;
use std::path::{Path, PathBuf};

/// Linux 安全基线：读配置/探测既有事实，产出发现项。
#[derive(Default)]
pub struct LinuxSecurity;

impl LinuxSecurity {
    /// sshd 主配置路径。`PANEL_SSHD_CONFIG` 可覆盖（测试 / 非标准部署）。
    fn sshd_config_path() -> PathBuf {
        std::env::var("PANEL_SSHD_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/ssh/sshd_config"))
    }
}

/// 解析 sshd 配置某指令的**有效值**（OpenSSH 语义：先出现者生效）。
/// 顺序：`sshd_config.d/*.conf`（按文件名排序；Debian 在主配置顶部 include）→ 主配置。
fn ssh_effective(cfg: &Path, key: &str) -> Option<String> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(dir) = cfg.parent().map(|p| p.join("sshd_config.d")) {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let mut v: Vec<PathBuf> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
                .collect();
            v.sort();
            files.extend(v);
        }
    }
    files.push(cfg.to_path_buf());
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() { continue; }
            let mut it = line.split_whitespace();
            if let (Some(k), Some(v)) = (it.next(), it.next()) {
                if k.eq_ignore_ascii_case(key) { return Some(v.to_string()); }
            }
        }
    }
    None
}

fn check(
    key: &str, title: &str, ok: bool,
    current: impl Into<String>, expected: &str, advice: &str,
) -> SecurityCheck {
    SecurityCheck {
        key: key.into(), title: title.into(), ok,
        current: current.into(), expected: expected.into(), advice: advice.into(),
        applicable: true,
    }
}

fn na(key: &str, title: &str, advice: &str) -> SecurityCheck {
    SecurityCheck {
        key: key.into(), title: title.into(), ok: true,
        current: "不适用".into(), expected: "—".into(), advice: advice.into(),
        applicable: false,
    }
}

fn any_file(paths: &[&str]) -> bool {
    paths.iter().any(|p| Path::new(p).is_file())
}

/// 当前值展示：显式设置则显示 `Key value`，否则标注 OpenSSH 编译默认值。
fn disp(key: &str, raw: Option<&str>, default: &str) -> String {
    match raw {
        Some(v) => format!("{key} {v}"),
        None => format!("未显式设置（默认 {default}）"),
    }
}

/// SSH 加固检查（纯函数，便于单测）。未显式设置时按 **OpenSSH 编译默认值**判定，
/// 不拿标注串去比较：`PermitRootLogin` 默认 prohibit-password（安全）、
/// `PasswordAuthentication` 默认 yes（不安全）、`PubkeyAuthentication` 默认 yes（安全）。
fn ssh_checks(cfg: &Path) -> Vec<SecurityCheck> {
    if !cfg.is_file() {
        return vec![
            na("ssh.permit_root_login", "SSH 禁止 root 直接登录", "未检测到 sshd 配置（未安装 SSH 服务？）"),
            na("ssh.password_auth", "SSH 禁口令登录（仅密钥）", "未检测到 sshd 配置"),
            na("ssh.pubkey_auth", "SSH 启用公钥认证", "未检测到 sshd 配置"),
        ];
    }

    let raw = ssh_effective(cfg, "PermitRootLogin");
    let eff = raw.clone().unwrap_or_else(|| "prohibit-password".into());
    let prl = check("ssh.permit_root_login", "SSH 禁止 root 直接登录",
        matches!(eff.as_str(), "no" | "prohibit-password" | "without-password"),
        disp("PermitRootLogin", raw.as_deref(), "prohibit-password"),
        "no / prohibit-password",
        "在 sshd_config 设 `PermitRootLogin no`（或 prohibit-password）");

    let raw = ssh_effective(cfg, "PasswordAuthentication");
    let eff = raw.clone().unwrap_or_else(|| "yes".into());
    let pa = check("ssh.password_auth", "SSH 禁口令登录（仅密钥）",
        eff.eq_ignore_ascii_case("no"),
        disp("PasswordAuthentication", raw.as_deref(), "yes"), "no",
        "配置好密钥登录后设 `PasswordAuthentication no`");

    let raw = ssh_effective(cfg, "PubkeyAuthentication");
    let eff = raw.clone().unwrap_or_else(|| "yes".into());
    let pka = check("ssh.pubkey_auth", "SSH 启用公钥认证",
        eff.eq_ignore_ascii_case("yes"),
        disp("PubkeyAuthentication", raw.as_deref(), "yes"), "yes",
        "设 `PubkeyAuthentication yes`");

    vec![prl, pa, pka]
}

#[async_trait]
impl SecurityProvider for LinuxSecurity {
    async fn baseline(&self) -> Result<Vec<SecurityCheck>> {
        let mut out = Vec::new();
        let cfg = Self::sshd_config_path();

        // ── SSH 加固（配置不存在 → 不适用，而非"通过"）──
        out.extend(ssh_checks(&cfg));

        // ── 自动安全更新（apt 系）──
        if Path::new("/etc/apt").is_dir() {
            let ok = any_file(&["/etc/apt/apt.conf.d/20auto-upgrades", "/usr/bin/unattended-upgrade"]);
            out.push(check("system.auto_updates", "启用自动安全更新", ok,
                if ok { "已配置" } else { "未配置" }, "已启用 unattended-upgrades",
                "安装并启用自动更新：apt install unattended-upgrades"));
        } else {
            out.push(na("system.auto_updates", "启用自动安全更新", "非 apt 系发行版，请用对应包管理器"));
        }

        // ── fail2ban ──
        if Path::new("/run/systemd/system").is_dir() {
            let ok = any_file(&[
                "/lib/systemd/system/fail2ban.service",
                "/usr/lib/systemd/system/fail2ban.service",
                "/usr/bin/fail2ban-server",
                "/usr/sbin/fail2ban-server",
            ]);
            out.push(check("service.fail2ban", "部署 fail2ban 防暴力破解", ok,
                if ok { "已安装" } else { "未安装" }, "已安装并启用 fail2ban",
                "安装 fail2ban：apt install fail2ban"));
        } else {
            out.push(na("service.fail2ban", "部署 fail2ban 防暴力破解", "无 systemd，跳过服务检查"));
        }

        // ── 空口令账户（读 /etc/shadow 需 root）──
        match std::fs::read_to_string("/etc/shadow") {
            Ok(txt) => {
                let empties: Vec<String> = txt
                    .lines()
                    .filter_map(|l| {
                        let mut it = l.split(':');
                        let name = it.next()?;
                        let pw = it.next()?;
                        if pw.is_empty() { Some(name.to_string()) } else { None }
                    })
                    .collect();
                let ok = empties.is_empty();
                out.push(check("accounts.empty_password", "无空口令账户", ok,
                    if ok { "无".to_string() } else { format!("{} 个：{}", empties.len(), empties.join(", ")) },
                    "无空口令账户",
                    "为相关账户设口令或锁定：passwd -l <user>"));
            }
            Err(_) => out.push(na("accounts.empty_password", "无空口令账户", "读取 /etc/shadow 需 root 权限")),
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("panel-sec-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ssh_effective_first_wins_and_dropins() {
        let d = tmp_dir("ssh");
        std::fs::create_dir_all(d.join("sshd_config.d")).unwrap();
        std::fs::write(d.join("sshd_config.d/10-hard.conf"), "PermitRootLogin no\n").unwrap();
        std::fs::write(d.join("sshd_config"), "PermitRootLogin yes\nPasswordAuthentication no\n").unwrap();
        let cfg = d.join("sshd_config");
        // drop-in 先于主配置 → 生效值为 no
        assert_eq!(ssh_effective(&cfg, "PermitRootLogin").as_deref(), Some("no"));
        assert_eq!(ssh_effective(&cfg, "PasswordAuthentication").as_deref(), Some("no"));
        // 注释与大小写
        assert_eq!(ssh_effective(&cfg, "nothere"), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn baseline_runs_and_is_readonly() {
        let items = LinuxSecurity.baseline().await.expect("baseline 不应报错");
        assert!(!items.is_empty(), "至少应有若干检查项");
        // 每项都有稳定 key，且 key 不重复
        let mut keys: Vec<&str> = items.iter().map(|c| c.key.as_str()).collect();
        keys.sort();
        let n = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), n, "检查项 key 不应重复");
    }

    /// 未显式设置时必须按 OpenSSH **编译默认值**判定（曾因拿标注串比较而误判）。
    #[test]
    fn ssh_defaults_follow_openssh_semantics() {
        let d = tmp_dir("sshdef");
        let cfg = d.join("sshd_config");
        std::fs::write(&cfg, "# 空配置\n").unwrap();
        let items = ssh_checks(&cfg);
        let get = |k: &str| items.iter().find(|c| c.key == k).expect("check 存在");
        assert!(get("ssh.permit_root_login").ok, "默认 prohibit-password 应判安全");
        assert!(get("ssh.pubkey_auth").ok, "默认 yes 应判安全");
        assert!(!get("ssh.password_auth").ok, "默认 yes 应判不安全");
        assert!(get("ssh.password_auth").current.contains("默认 yes"), "应标注默认值");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ssh_bad_config_flags_risky_directives() {
        let d = tmp_dir("sshbad");
        let cfg = d.join("sshd_config");
        // 显式写坏的 root/口令登录；PubkeyAuthentication 未设 → 默认 yes（安全）
        std::fs::write(&cfg, "PermitRootLogin yes\nPasswordAuthentication yes\n").unwrap();
        let items = ssh_checks(&cfg);
        let get = |k: &str| items.iter().find(|c| c.key == k).unwrap();
        assert_eq!(items.len(), 3);
        assert!(!get("ssh.permit_root_login").ok);
        assert!(!get("ssh.password_auth").ok);
        assert!(get("ssh.pubkey_auth").ok, "未设 PubkeyAuthentication 默认 yes → 安全");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ssh_missing_config_is_not_applicable() {
        let items = ssh_checks(Path::new("/nonexistent/sshd_config"));
        assert!(items.iter().all(|c| !c.applicable), "缺配置应标不适用（而非通过）");
    }
}
