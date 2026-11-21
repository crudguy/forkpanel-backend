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
/// 基线修复写入的 drop-in 文件名。`00-` 前缀保证排在既有 drop-in 之前——
/// 与 SSH 端口的 `00-panel-port.conf` 同一套 OpenSSH「先出现者生效」纪律。
/// ⚠ 绝不写主配置：drop-in 里的同名指令会遮蔽主配置，写了也不生效（假绿）。
pub(crate) const BASELINE_DROPIN: &str = "00-panel-baseline.conf";

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

/// 读 apt 配置（主文件 + `apt.conf.d/*.conf` 按文件名排序）。apt 按此顺序加载，
/// 同名项**后出现者覆盖先出现者**，与 sshd 的「先出现者生效」相反。
fn load_apt_configs() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let main = Path::new("/etc/apt/apt.conf");
    if let Ok(text) = std::fs::read_to_string(main) {
        out.push((main.to_path_buf(), text));
    }
    if let Ok(rd) = std::fs::read_dir("/etc/apt/apt.conf.d") {
        let mut v: Vec<PathBuf> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
            .collect();
        v.sort();
        for p in v {
            if let Ok(text) = std::fs::read_to_string(&p) {
                out.push((p, text));
            }
        }
    }
    out
}

/// 解析 `APT::Periodic::<key> "<n>";`。apt 配置注释是 `//`（不是 `#`）。
pub(crate) fn apt_periodic_value(configs: &[(PathBuf, String)], key: &str) -> Option<i64> {
    let mut found = None;
    for (_, text) in configs {
        for line in text.lines() {
            let t = line.split("//").next().unwrap_or("").trim();
            let mut it = t.split_whitespace();
            let Some(k) = it.next().and_then(|s| s.strip_prefix("APT::Periodic::")) else { continue };
            if k != key { continue; }
            // apt 语法是 `Key "1";`（空格分隔，不是 =）
            let Some(v) = it.next() else { continue };
            let v = v.trim_end_matches(';').trim_matches('"').trim();
            if let Ok(n) = v.parse::<i64>() { found = Some(n); }
        }
    }
    found
}

/// "自动安全更新已启用"必须看**周期配置值**，装了包不算——这是原来的假绿根因：
/// `any_file(["/etc/apt/apt.conf.d/20auto-upgrades", "/usr/bin/unattended-upgrade"])`
/// 只要文件在就报绿，而两个周期值都写 0 时 apt 根本不会更新。
pub(crate) fn auto_updates_state(
    configs: &[(PathBuf, String)], binary_present: bool,
) -> (bool, String) {
    let update = apt_periodic_value(configs, "Update-Package-Lists");
    let upgrade = apt_periodic_value(configs, "Unattended-Upgrade");
    let show = |v: Option<i64>| v.map(|n| n.to_string()).unwrap_or_else(|| "未设置".into());
    let enabled = matches!(update, Some(v) if v >= 1) && matches!(upgrade, Some(v) if v >= 1);
    let current = if enabled {
        format!("Update-Package-Lists={}, Unattended-Upgrade={}", show(update), show(upgrade))
    } else {
        format!(
            "Update-Package-Lists={}, Unattended-Upgrade={}{}",
            show(update), show(upgrade),
            if binary_present { "（已安装但未启用）" } else { "" }
        )
    };
    (enabled, current)
}

/// fail2ban 的 systemd `wants` 符号链接位置（enable 后由 systemctl 建立）。
pub(crate) const FAIL2BAN_WANTS: &[&str] = &[
    "/etc/systemd/system/multi-user.target.wants/fail2ban.service",
    "/lib/systemd/system/multi-user.target.wants/fail2ban.service",
    "/usr/lib/systemd/system/multi-user.target.wants/fail2ban.service",
];

/// "已启用且在运行"= wants 链接存在 **且** 命令探测到 active。
/// 原来的 `any_file(服务单元/二进制路径)` 只能证明"装了"，未 enable/未运行也报绿。
pub(crate) fn fail2ban_state(wants: &[&str], active: bool, installed: bool) -> (bool, String) {
    let enabled = wants.iter().any(|p| std::fs::symlink_metadata(p).is_ok());
    let ok = enabled && active;
    let current = if ok { "已启用且运行中".into() }
        else if !installed { "未安装".into() }
        else if !enabled { "已安装但未设置开机自启".into() }
        else { "已启用但未运行".into() };
    (ok, current)
}

/// 实际探测 fail2ban 是否在跑：只取 `fail2ban-client status` 的返回码，
/// 不回显输出（外部命令输出可能含 jail/IP 等运行信息）。
async fn fail2ban_active() -> bool {
    if !crate::cmd::Bin::available(crate::cmd::Bin::Fail2banClient) {
        return false;
    }
    matches!(
        crate::cmd::run(
            crate::cmd::Bin::Fail2banClient,
            &["status"],
            crate::cmd::CmdOpt {
                timeout: std::time::Duration::from_secs(5),
                ..Default::default()
            },
        ).await,
        Ok(o) if o.code == Some(0)
    )
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

    /// SSH 端口现状（只读）。
    async fn ssh_port(&self) -> Result<crate::traits::SshPortState> {
        crate::linux::ssh_port::current(Self::sshd_config_path()).await
    }

    /// 改 SSH 端口：写 `00-panel-port.conf` drop-in（优先级高于既有 drop-in），
    /// 端口占用预检 → 备份 → 写 → `sshd -t` → 失败回滚。见 `linux/ssh_port.rs`。
    async fn set_ssh_port(&self, port: u16, keep_old: bool) -> Result<crate::traits::SshPortChange> {
        crate::linux::ssh_port::set_port(Self::sshd_config_path(), port, keep_old).await
    }

    async fn baseline(&self) -> Result<Vec<SecurityCheck>> {
        let mut out = Vec::new();
        let cfg = Self::sshd_config_path();

        // ── SSH 加固（配置不存在 → 不适用，而非"通过"）──
        out.extend(ssh_checks(&cfg));

        // ── 自动安全更新（apt 系）：看周期值，不看"包装没装" ──
        if Path::new("/etc/apt").is_dir() {
            let configs = load_apt_configs();
            let binary_present = Path::new("/usr/bin/unattended-upgrade").is_file();
            let (ok, current) = auto_updates_state(&configs, binary_present);
            out.push(check("system.auto_updates", "启用自动安全更新", ok, current,
                "Update-Package-Lists >= 1 且 Unattended-Upgrade >= 1",
                "在 /etc/apt/apt.conf.d/20auto-upgrades 把 APT::Periodic 两项都设为 1"));
        } else {
            out.push(na("system.auto_updates", "启用自动安全更新", "非 apt 系发行版，请用对应包管理器"));
        }

        // ── fail2ban：enable（wants 链接）+ 实际在跑，装了不算 ──
        if Path::new("/run/systemd/system").is_dir() {
            let installed = any_file(&[
                "/lib/systemd/system/fail2ban.service",
                "/usr/lib/systemd/system/fail2ban.service",
                "/usr/bin/fail2ban-server",
                "/usr/sbin/fail2ban-server",
            ]);
            let active = fail2ban_active().await;
            let (ok, current) = fail2ban_state(FAIL2BAN_WANTS, active, installed);
            out.push(check("service.fail2ban", "部署 fail2ban 防暴力破解", ok, current,
                "已设置开机自启且运行中",
                "安装并启用：apt install fail2ban && systemctl enable --now fail2ban"));
        } else {
            out.push(na("service.fail2ban", "部署 fail2ban 防暴力破解", "无 systemd，跳过服务检查"));
        }

        // ── 空口令账户（读 /etc/shadow 需 root）──
        let shadow = crate::fs::blocking(|| std::fs::read_to_string("/etc/shadow")).await?;
        match shadow {
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

/// 从 sshd 主配置路径推导基线 drop-in 路径（与 SSH 端口的 `00-panel-port.conf` 同目录）。
pub(crate) fn baseline_dropin_path(cfg: &Path) -> Option<PathBuf> {
    cfg.parent().map(|p| p.join("sshd_config.d").join(BASELINE_DROPIN))
}

/// 生效值是否已满足基线要求。`PermitRootLogin` 的三种安全等价值都算满足
/// （与 `ssh_checks` 的判定保持一致，否则修完了 check 仍报风险）。
pub(crate) fn baseline_satisfied(directive: &str, effective: Option<&str>, expected: &str) -> bool {
    let Some(v) = effective else { return false };
    if directive.eq_ignore_ascii_case("PermitRootLogin") {
        return matches!(v, "no" | "prohibit-password" | "without-password");
    }
    v.eq_ignore_ascii_case(expected)
}

/// 解析 `sshd -T` 输出里的生效值（输出形如 `permitrootlogin no`，key 全小写）。
/// 用它做**写后复核**：光看我们写了什么不算，得让 sshd 自己说生效值是什么。
pub(crate) fn sshd_t_value(output: &str, directive: &str) -> Option<String> {
    let want = directive.to_ascii_lowercase();
    for line in output.lines() {
        let mut it = line.split_whitespace();
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            if k.eq_ignore_ascii_case(&want) {
                return Some(v.to_string());
            }
        }
    }
    None
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
///
/// ⚠ 写 **drop-in**（`00-panel-baseline.conf`）而非主配置：OpenSSH 对同一指令
/// 「先出现者生效」，drop-in 里的同名指令会遮蔽主配置。此前写主配置的修复在
/// Debian 默认布局（主配置顶部 `Include sshd_config.d/*.conf`）下完全无效，
/// 却返回 `changed:true`——典型的假绿。与 SSH 端口 P1-7 是同一类坑。
pub(crate) async fn apply_ssh_item(key: &str) -> Result<SecurityApplyResult> {
    let Some((directive, value)) = ssh_fix_target(key) else {
        return Err(PanelError::Validation {
            field: "key",
            reason: format!("不支持自动修复的基线项：{key}（仅支持 ssh.permit_root_login / ssh.password_auth / ssh.pubkey_auth）"),
        });
    };

    if !crate::cmd::Bin::available(crate::cmd::Bin::Sshd) {
        return Err(PanelError::Validation {
            field: "sshd",
            reason: "sshd 不可用，无法校验配置语法 → 拒绝自动修改（避免写错导致无法登录）".into(),
        });
    }

    let cfg = LinuxSecurity::sshd_config_path();
    if !cfg.exists() {
        return Err(PanelError::NotFound(format!("sshd 配置不存在：{}", cfg.display())));
    }

    // ① 看**生效值**判定是否已符合，不能看主配置文本——主配置写着正确值而
    //    被 drop-in 遮蔽，正是这次要修的假绿。
    let effective = ssh_effective(&cfg, directive);
    if baseline_satisfied(directive, effective.as_deref(), value) {
        return Ok(SecurityApplyResult { changed: false, backup: None, validated: true });
    }

    let target = baseline_dropin_path(&cfg).ok_or_else(|| PanelError::Validation {
        field: "path",
        reason: "sshd 配置无父目录，无法定位 drop-in 目录".into(),
    })?;
    if let Some(dir) = target.parent() {
        let d = dir.to_path_buf();
        crate::fs::blocking(move || std::fs::create_dir_all(&d))
            .await?
            .map_err(|e| PanelError::Io(format!("创建 drop-in 目录失败：{e}")))?;
    }

    let prev = crate::fs::blocking({
        let p = target.clone();
        move || std::fs::read_to_string(&p).ok()
    }).await.ok().flatten();
    let next = apply_ssh_directive(prev.as_deref().unwrap_or(""), directive, value);
    if prev.as_deref() == Some(next.as_str()) {
        // drop-in 已写好但生效值仍不对：存在我们覆盖不了的遮蔽源（Match 块 /
        // 更早的 Include）。绝不返回"成功"——那比不修更危险。
        return Err(PanelError::Validation {
            field: "sshd",
            reason: format!(
                "已在 {} 写入 {directive} {value}，但 sshd 生效值仍为 {}；存在其它遮蔽配置（Match 块 / 更早的 Include），请手工排查后再修复",
                target.display(),
                effective.as_deref().unwrap_or("未设置"),
            ),
        });
    }

    // ② 备份（原文件不存在则无备份；回滚 = 删除本文件）
    let backup = if prev.is_some() {
        let b = target.with_extension(format!("conf.panel.bak-{}", now_secs()));
        let (a, c) = (target.clone(), b.clone());
        crate::fs::blocking(move || std::fs::copy(&a, &c))
            .await?
            .map_err(|e| PanelError::Io(e.to_string()))?;
        if let (Some(dir), Some(name)) = (b.parent(), b.file_name().and_then(|n| n.to_str())) {
            if let Some(i) = name.find(BACKUP_MARKER) {
                crate::fs::prune_keep_newest(dir, &name[..i + BACKUP_MARKER.len()], SSH_BACKUP_KEEP);
            }
        }
        Some(b)
    } else {
        None
    };
    let backup_desc = backup.as_ref().map(|b| b.display().to_string())
        .unwrap_or_else(|| "无（本次为新建 drop-in，回滚即删除）".into());

    // ③ 写 drop-in（不是主配置！）
    let write_res = crate::fs::blocking({
        let (p, n) = (target.clone(), next.clone());
        move || std::fs::write(&p, &n)
    }).await?;
    if let Err(e) = write_res {
        return Err(PanelError::Io(format!(
            "写入失败，原配置未改动（备份 {backup_desc}）：{e}"
        )));
    }

    // ④ 语法校验：`sshd -t -f <cfg>` 走整机配置（含 Include），能抓到 drop-in 写坏。
    let out = crate::cmd::run(
        crate::cmd::Bin::Sshd,
        &["-t", "-f", &cfg.to_string_lossy()],
        crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(10), ..Default::default() },
    )
    .await;
    let syntax_ok = matches!(&out, Ok(o) if o.code == Some(0));
    if !syntax_ok {
        // ⚠ 回滚**可能失败**（备份被删、权限变化、磁盘满）。失败必须如实报出，
        // 用户据此重启 sshd 会在磁盘上仍是坏配置时把自己锁在门外（二轮审计 P0-9）。
        let rolled_back = rollback_dropin(&target, backup.as_ref()).await;
        if !rolled_back {
            eprintln!(
                "[panel] ⚠ [security] sshd 配置校验未通过且**回滚失败**：目标 {} 上仍是未通过校验的配置（备份 {backup_desc}）",
                target.display()
            );
        }
        let why = match out {
            Ok(o) => panel_core::sanitize::stderr(&o.stderr),
            Err(e) => e.to_string(),
        };
        return Err(PanelError::Command {
            bin: "sshd".into(),
            detail: sshd_validate_failure_detail(rolled_back, &target.display().to_string(), &why),
        });
    }

    // ⑤ 生效值复核：写了 ≠ 生效。让 sshd 自己报生效值，任何遮蔽源都在这里被抓到。
    let dump = crate::cmd::run(
        crate::cmd::Bin::Sshd,
        &["-T", "-f", &cfg.to_string_lossy()],
        crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(10), ..Default::default() },
    )
    .await;
    let actual = match &dump {
        Ok(o) if o.code == Some(0) => sshd_t_value(&o.stdout, directive),
        _ => None,
    };
    if !baseline_satisfied(directive, actual.as_deref(), value) {
        let rolled_back = rollback_dropin(&target, backup.as_ref()).await;
        let why = match &dump {
            Ok(o) => panel_core::sanitize::stderr(&o.stderr),
            Err(e) => e.to_string(),
        };
        return Err(PanelError::Command {
            bin: "sshd".into(),
            detail: format!(
                "写入 {directive} {value} 后 sshd 生效值仍为 {}（存在遮蔽配置），已{}。请手工排查 Include / Match 块：{why}",
                actual.as_deref().unwrap_or("未取到"),
                if rolled_back { "回滚" } else { "**回滚失败（请勿重启 sshd）**" },
            ),
        });
    }

    Ok(SecurityApplyResult { changed: true, backup, validated: true })
}

/// 回滚 drop-in：有备份拷回，无备份（本次新建）则删除。返回是否成功。
async fn rollback_dropin(target: &Path, backup: Option<&PathBuf>) -> bool {
    match backup {
        Some(b) => {
            let (a, c) = (b.clone(), target.to_path_buf());
            crate::fs::blocking(move || std::fs::copy(&a, &c))
                .await.ok().and_then(|r| r.ok()).is_some()
        }
        None => {
            let t = target.to_path_buf();
            crate::fs::blocking(move || std::fs::remove_file(&t))
                .await.ok().and_then(|r| r.ok()).is_some()
        }
    }
}

/// sshd 配置校验失败时的错误文案。
///
/// ⚠ 文案必须**如实反映回滚是否成功**：无条件宣称「已自动回滚」是最危险的谎报——
/// 用户会在磁盘上仍是坏配置时重启 sshd。抽成纯函数才能被断言。
pub(crate) fn sshd_validate_failure_detail(rolled_back: bool, backup: &str, why: &str) -> String {
    if rolled_back {
        format!("配置校验未通过，已自动回滚（原配置已恢复，备份 {backup}）：{why}")
    } else {
        format!(
            "配置校验未通过，且**自动回滚失败**：磁盘上仍是这份未通过校验的配置（备份留存在 {backup}）。请勿重启 sshd——先手工恢复备份或修正配置，否则可能锁死 SSH 登录：{why}"
        )
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

    #[test]
    fn ssh_missing_config_is_not_applicable() {
        let items = ssh_checks(Path::new("/nonexistent/sshd_config"));
        assert!(items.iter().all(|c| !c.applicable), "缺配置应标不适用（而非通过）");
    }

    /// 二轮审计 P0-9：回滚失败时**不得**宣称「已自动回滚」——用户据此重启 sshd
    /// 会在磁盘上仍是坏配置的情况下把自己锁在门外。
    #[test]
    fn sshd_failure_detail_tells_whether_rollback_worked() {
        let ok_detail = sshd_validate_failure_detail(true, "/tmp/sshd.bak", "syntax error");
        assert!(ok_detail.contains("已自动回滚"), "回滚成功应如实说明：{ok_detail}");
        assert!(!ok_detail.contains("回滚失败"), "回滚成功不该出现失败字样：{ok_detail}");

        let bad_detail = sshd_validate_failure_detail(false, "/tmp/sshd.bak", "syntax error");
        assert!(bad_detail.contains("回滚失败"), "回滚失败必须说出来：{bad_detail}");
        assert!(
            !bad_detail.contains("已自动回滚"),
            "回滚失败却宣称「已自动回滚」= 谎报，用户会重启 sshd 被锁在门外：{bad_detail}"
        );
        assert!(bad_detail.contains("请勿重启"), "必须给出行动指引：{bad_detail}");
        assert!(bad_detail.contains("/tmp/sshd.bak"), "要告诉用户备份在哪：{bad_detail}");
    }

    /// `00-` 前缀是修复生效的前提：必须排在既有 drop-in 之前。
    #[test]
    fn baseline_dropin_sorts_before_existing_dropins() {
        assert!(BASELINE_DROPIN < "10-hardening.conf");
        assert!(BASELINE_DROPIN < "20-systemd-userdb.conf");
        assert!(BASELINE_DROPIN < "50-cloud-init.conf");
        let cfg = Path::new("/etc/ssh/sshd_config");
        assert_eq!(
            baseline_dropin_path(cfg),
            Some(PathBuf::from("/etc/ssh/sshd_config.d/00-panel-baseline.conf"))
        );
    }

    /// `ssh_checks` 接受三种 root 登录安全值，"已符合"判定必须与之一致，
    /// 否则修完仍报风险（或把本来就安全的配置重复写一遍）。
    #[test]
    fn baseline_satisfied_matches_ssh_checks_semantics() {
        for v in ["no", "prohibit-password", "without-password"] {
            assert!(baseline_satisfied("PermitRootLogin", Some(v), "no"), "{v} 应算安全");
        }
        assert!(!baseline_satisfied("PermitRootLogin", Some("yes"), "no"));
        assert!(!baseline_satisfied("PermitRootLogin", None, "no"));
        assert!(baseline_satisfied("PasswordAuthentication", Some("NO"), "no"));
        assert!(!baseline_satisfied("PasswordAuthentication", Some("yes"), "no"));
    }

    /// `sshd -T` 输出 key 全小写，解析必须大小写无关且不把注释当配置。
    #[test]
    fn sshd_t_value_parses_lowercase_output() {
        let dump = "permitrootlogin prohibit-password\npasswordauthentication no\n\
                    # pubkeyauthentication no\npubkeyauthentication yes\n";
        assert_eq!(sshd_t_value(dump, "PermitRootLogin").as_deref(), Some("prohibit-password"));
        assert_eq!(sshd_t_value(dump, "PasswordAuthentication").as_deref(), Some("no"));
        assert_eq!(sshd_t_value(dump, "PubkeyAuthentication").as_deref(), Some("yes"));
        assert_eq!(sshd_t_value(dump, "ChallengeResponseAuthentication"), None);
    }

    /// ⭐ 钉住这次修的假绿根因：主配置写着正确值、drop-in 里有冲突值时，
    /// 判定必须按**生效值**走，不能按主配置文本走。
    #[test]
    fn baseline_satisfied_uses_effective_value_not_main_config() {
        let d = tmp_dir("baseff");
        std::fs::create_dir_all(d.join("sshd_config.d")).unwrap();
        std::fs::write(d.join("sshd_config.d/10-hard.conf"), "PermitRootLogin yes\n").unwrap();
        let cfg = d.join("sshd_config");
        std::fs::write(&cfg, "PermitRootLogin no\n").unwrap();

        let eff = ssh_effective(&cfg, "PermitRootLogin");
        assert_eq!(eff.as_deref(), Some("yes"), "drop-in 必须先于主配置生效");
        assert!(
            !baseline_satisfied("PermitRootLogin", eff.as_deref(), "no"),
            "主配置写着 no 但生效值是 yes，必须判定为未满足（否则又是假绿）"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// ⭐ 源码守卫：`apply_ssh_item` 必须写 drop-in + `sshd -T` 复核。
    /// 只靠上面的纯函数单测挡不住有人把写盘目标改回主配置——那会让纯函数
    /// 全绿而修复再次失效。取生产段（剔注释/测试）后再断言，避免注释里
    /// 提到旧路径就假绿。
    #[test]
    fn baseline_apply_writes_dropin_and_verifies_effective_value() {
        let src = panel_testutil::production_source(include_str!("security.rs"));
        let start = src.find("pub(crate) async fn apply_ssh_item")
            .expect("apply_ssh_item 必须在生产段里");
        let rest = &src[start..];
        let end = rest.find("pub(crate) fn sshd_validate_failure_detail")
            .expect("apply_ssh_item 之后应有错误文案函数");
        let body = &rest[..end];

        assert!(body.contains("ssh_effective(&cfg, directive)"),
            "必须先按生效值判定是否已符合，不能看主配置文本");
        assert!(body.contains("baseline_dropin_path(&cfg)"),
            "修复目标必须是 drop-in，不能写主配置（会被 drop-in 遮蔽）");
        assert!(body.contains("let (p, n) = (target.clone(), next.clone())"),
            "写盘闭包必须拿 drop-in 的 target，不是主配置 cfg");
        assert!(!body.contains("let (p, n) = (cfg.clone()"),
            "绝不能写回主配置——那是这次假绿的根因");
        assert!(body.contains("\"-T\""), "写后必须用 sshd -T 复核生效值");
    }

    /// apt 按文件名排序加载，同名项后出现覆盖先出现；`//` 注释不得当成配置。
    #[test]
    fn apt_periodic_value_last_file_wins_and_comments_ignored() {
        let configs = vec![
            (PathBuf::from("10-early.conf"), "APT::Periodic::Update-Package-Lists \"0\";\n".into()),
            (PathBuf::from("20-late.conf"),
             "// APT::Periodic::Update-Package-Lists \"0\";\nAPT::Periodic::Update-Package-Lists \"1\";\n".into()),
        ];
        assert_eq!(apt_periodic_value(&configs, "Update-Package-Lists"), Some(1));
        assert_eq!(apt_periodic_value(&configs, "Unattended-Upgrade"), None);
    }

    /// ⭐ 装了包但两个周期值为 0 → 必须报不通过（这正是原来的假绿）。
    #[test]
    fn auto_updates_requires_enabled_periodic_not_just_installed() {
        let off = vec![(PathBuf::from("20auto-upgrades"),
            "APT::Periodic::Update-Package-Lists \"0\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n".into())];
        let (ok, current) = auto_updates_state(&off, true);
        assert!(!ok, "已安装但周期值为 0 不得报绿");
        assert!(current.contains("已安装但未启用"), "文案要说清差在哪：{current}");

        let half = vec![(PathBuf::from("20auto-upgrades"),
            "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n".into())];
        assert!(!auto_updates_state(&half, true).0, "只启用一半不算");

        let on = vec![(PathBuf::from("20auto-upgrades"),
            "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n".into())];
        assert!(auto_updates_state(&on, true).0, "两项都为 1 才通过");
    }

    /// ⭐ enable（wants 链接）与 active 必须同时成立，装了/只启一个都不算。
    #[test]
    fn fail2ban_requires_enabled_and_active() {
        let d = tmp_dir("f2b");
        let wants = d.join("fail2ban.service");
        std::os::unix::fs::symlink("/lib/systemd/system/fail2ban.service", &wants).unwrap();
        let path = wants.to_string_lossy().to_string();
        let linked: &[&str] = &[&path];

        assert!(!fail2ban_state(&[], true, true).0, "没有 wants 链接不得报绿");
        let (ok, current) = fail2ban_state(linked, true, true);
        assert!(ok, "enable + active 应通过：{current}");
        assert!(!fail2ban_state(linked, false, true).0, "已启用但未运行不得报绿");
        let (_, current) = fail2ban_state(linked, false, true);
        assert!(current.contains("未运行"), "要指出具体差在哪：{current}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 源码守卫：两项判定必须走新纯函数，不能退回 any_file 的"存在即绿"。
    #[test]
    fn baseline_checks_use_real_state_not_file_existence() {
        let src = panel_testutil::production_source(include_str!("security.rs"));
        let start = src.find("async fn baseline(&self)").expect("baseline 必须存在");
        let rest = &src[start..];
        let end = rest.find("pub(crate) fn ssh_fix_target").expect("baseline 之后应有一键修复白名单");
        let body = &rest[..end];
        assert!(body.contains("auto_updates_state(&configs, binary_present)"),
            "自动更新必须看 APT::Periodic 周期值");
        assert!(body.contains("fail2ban_state(FAIL2BAN_WANTS, active, installed)"),
            "fail2ban 必须看 enable + active");
        assert!(body.contains("fail2ban_active().await"), "必须实际探测服务在跑");
        assert!(!body.contains("let ok = any_file("), "不得退回文件存在即通过");
    }
}
