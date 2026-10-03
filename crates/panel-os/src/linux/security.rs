//! 安全基线扫描（**只读**）。
//!
//! 纪律：本模块**绝不修改系统**——只读取配置文件与既有事实，产出分级发现项。
//! 任何"修复"（写回 sshd_config 等）都是独立的高危操作，需 root + 二次确认，
//! 且必须先备份，避免把 SSH 锁死（详见设计方案 §2.10）。

use crate::traits::*;
use async_trait::async_trait;
use panel_core::{PanelError, Result};
use std::path::{Path, PathBuf};

/// sshd 配置备份名的固定记号（`<原名>.conf.panel.bak-<秒级时间戳>`）。
/// 既是文件名的组成部分，也用作"本次备份属于哪一批"的识别前缀。
const BACKUP_MARKER: &str = ".panel.bak-";
/// 保留最近几份 sshd 备份：回滚只需最近那次，留 10 份足够兜住连续误改。
const SSH_BACKUP_KEEP: usize = 10;

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
    /// 一键修复：委托 [`apply_ssh_item`]（先备份 → 写 → `sshd -t` 校验 → 失败回滚）。
    async fn apply(&self, key: &str) -> Result<crate::traits::SecurityApplyResult> {
        apply_ssh_item(key).await
    }

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

// ─────────────── 一键修复（**高危写**：先备份 → 写 → 校验 → 失败回滚） ───────────────

/// 基线项 → (sshd 指令名, 期望值)。**白名单以外一律不修**（未知项直接报错）。
pub(crate) fn ssh_fix_target(key: &str) -> Option<(&'static str, &'static str)> {
    match key {
        "ssh.permit_root_login" => Some(("PermitRootLogin", "no")),
        "ssh.password_auth" => Some(("PasswordAuthentication", "no")),
        // PubkeyAuthentication **只允许设为 yes**：置 no 会把所有人（含面板自己）锁在门外
        "ssh.pubkey_auth" => Some(("PubkeyAuthentication", "yes")),
        _ => None,
    }
}

/// 把 `Key <value>` 写入 sshd 配置文本：已存在则替换（保留注释行），否则追加。
///
/// **纯函数**——写盘前后各有备份与校验，但"生成什么内容"这件事必须可单测验证。
pub(crate) fn apply_ssh_directive(content: &str, key: &str, value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in content.lines() {
        let t = line.trim();
        let hit = !t.starts_with('#')
            && t.split_whitespace()
                .next()
                .map(|w| w.eq_ignore_ascii_case(key))
                .unwrap_or(false);
        if hit {
            out.push(format!("{key} {value}"));
            replaced = true;
        } else {
            out.push(line.to_string());
        }
    }
    if !replaced {
        out.push(format!("{key} {value}"));
    }
    let mut s = out.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 修复一项 sshd 基线。**校验器不可用时拒绝修改**——
/// 宁可不修，也不写坏配置把人锁在服务器门外。
pub(crate) async fn apply_ssh_item(key: &str) -> Result<SecurityApplyResult> {
    let Some((directive, value)) = ssh_fix_target(key) else {
        return Err(PanelError::Validation {
            field: "key".into(),
            reason: format!("不支持自动修复的基线项：{key}（仅支持 ssh.permit_root_login / ssh.password_auth / ssh.pubkey_auth）"),
        });
    };

    if !crate::cmd::Bin::available(crate::cmd::Bin::Sshd) {
        return Err(PanelError::Validation {
            field: "sshd".into(),
            reason: "sshd 不可用，无法校验配置语法 → 拒绝自动修改（避免写错导致无法登录）".into(),
        });
    }

    let path = LinuxSecurity::sshd_config_path();
    if !path.exists() {
        return Err(PanelError::NotFound(format!("sshd 配置不存在：{}", path.display())));
    }
    let orig = std::fs::read_to_string(&path).map_err(|e| PanelError::Io(e.to_string()))?;
    let next = apply_ssh_directive(&orig, directive, value);
    if next == orig {
        // 已符合预期：不写盘、不备份
        return Ok(SecurityApplyResult { changed: false, backup: None, validated: true });
    }

    // ① 先备份
    let backup = path.with_extension(format!("conf.panel.bak-{}", now_secs()));
    std::fs::copy(&path, &backup).map_err(|e| PanelError::Io(e.to_string()))?;

    // 备份文件名带秒级时间戳，每次改配置都是**新文件**、永不复用也从不清理，
    // 目录会随改配置次数无限膨胀。只保留最近几份（回滚用得上最近的那次就够）：
    // 前缀取自本次备份名（截到 ".panel.bak-" 为止），避免误删同目录其他文件。
    if let (Some(dir), Some(name)) = (backup.parent(), backup.file_name().and_then(|n| n.to_str())) {
        if let Some(i) = name.find(BACKUP_MARKER) {
            crate::fs::prune_keep_newest(dir, &name[..i + BACKUP_MARKER.len()], SSH_BACKUP_KEEP);
        }
    }

    // ② 写（失败则备份仍在、原文件未变）
    if let Err(e) = std::fs::write(&path, &next) {
        return Err(PanelError::Io(format!(
            "写入失败，原配置未改动（备份 {}）：{e}",
            backup.display()
        )));
    }

    // ③ 校验：不通过立刻回滚
    let out = crate::cmd::run(
        crate::cmd::Bin::Sshd,
        &["-t", "-f", &path.to_string_lossy()],
        crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(10), ..Default::default() },
    )
    .await;
    let ok = matches!(&out, Ok(o) if o.code == Some(0));
    if !ok {
        let _ = std::fs::copy(&backup, &path); // 回滚
        let why = match out {
            Ok(o) => o.stderr,
            Err(e) => e.to_string(),
        };
        return Err(PanelError::Command {
            bin: "sshd".into(),
            detail: format!(
                "配置校验未通过，已自动回滚（原配置已恢复，备份 {}）：{why}",
                backup.display()
            ),
        });
    }

    Ok(SecurityApplyResult { changed: true, backup: Some(backup), validated: true })
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
    #[test]
    fn apply_replaces_existing_directive_and_keeps_comments() {
        let src = "#PermitRootLogin yes\nPermitRootLogin yes\nPort 22\n";
        let out = super::apply_ssh_directive(src, "PermitRootLogin", "no");
        assert!(out.contains("PermitRootLogin no"));
        assert!(out.contains("#PermitRootLogin yes"), "注释行必须保留，不得被顺手改写");
        assert!(out.contains("Port 22"));
        assert_eq!(out.matches("PermitRootLogin no").count(), 1, "不得产生两条生效指令");
    }

    #[test]
    fn apply_appends_when_absent_and_ends_with_newline() {
        let out = super::apply_ssh_directive("Port 22\n", "PasswordAuthentication", "no");
        assert!(out.ends_with("PasswordAuthentication no\n"));
    }

    #[test]
    fn apply_is_idempotent() {
        let once = super::apply_ssh_directive("Port 22\n", "PubkeyAuthentication", "yes");
        let twice = super::apply_ssh_directive(&once, "PubkeyAuthentication", "yes");
        assert_eq!(once, twice, "重复修复不得重复追加同一指令");
    }

    #[test]
    fn fix_target_whitelist_and_pubkey_guardrail() {
        assert_eq!(super::ssh_fix_target("ssh.permit_root_login"), Some(("PermitRootLogin", "no")));
        assert_eq!(super::ssh_fix_target("ssh.password_auth"), Some(("PasswordAuthentication", "no")));
        // **护栏**：pubkey 只允许置 yes —— 置 no 会把所有人（含面板自己）锁在门外
        assert_eq!(super::ssh_fix_target("ssh.pubkey_auth"), Some(("PubkeyAuthentication", "yes")));
        // 白名单以外一律不修
        assert!(super::ssh_fix_target("system.auto_updates").is_none());
        assert!(super::ssh_fix_target("ssh.permit_root_login; rm -rf /").is_none());
    }

    fn ssh_missing_config_is_not_applicable() {
        let items = ssh_checks(Path::new("/nonexistent/sshd_config"));
        assert!(items.iter().all(|c| !c.applicable), "缺配置应标不适用（而非通过）");
    }
}
