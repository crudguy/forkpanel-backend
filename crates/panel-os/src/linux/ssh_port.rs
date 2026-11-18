//! SSH 端口可配置（P1-7）。
//!
//! ## 为什么不能"直接把 Port 写进 sshd_config"
//!
//! Debian/Ubuntu 的 `/etc/ssh/sshd_config` **第 12 行**就是
//! `Include /etc/ssh/sshd_config.d/*.conf`，而 OpenSSH 对同一指令取
//! **先出现者生效**。也就是说 drop-in 里若已有 `Port 22`，往主配置追加
//! `Port 2222` **不会生效**——配置写了、重启了、端口还是 22。用户看到的
//! 是"我明明改了"，实际是假控制（本项目已多次踩过这类坑）。
//!
//! 所以这里一律写 **drop-in 目录里文件名最靠前**的文件（`00-panel-port.conf`），
//! 让它的优先级高于任何 `10-*` / `20-*` 之类的既有 drop-in。
//!
//! ## 为什么"改完就完事"是错的
//!
//! 改端口的真实风险不是配置语法（`sshd -t` 能查），而是**改完连不上**：
//! ① 新端口被别的进程占着 → 重启 sshd bind 失败 → 服务起不来；
//! ② 防火墙没放行新端口 → ssh 连过去被丢包；
//! ③ 旧端口被立刻关掉 → 新端口又不通时**没有任何回退通道**。
//!
//! 因此本模块的产出必须带 `next_steps` 把"还要做什么"明说，
//! 并且默认保留旧端口（两个 Port 同时监听），把"立刻失联"变成可逆操作。

use crate::traits::SshPortChange;
use panel_core::{PanelError, Result};
use std::path::{Path, PathBuf};

/// 本模块写入的 drop-in 文件名。**`00-` 前缀是刻意的**：sshd 按文件名
/// 字典序展开 `Include`，`00-` 保证排在 `10-*`/`20-*`/`50-*` 之前，
/// 从而在任何已有 drop-in 之前生效。
pub(crate) const PORT_DROPIN: &str = "00-panel-port.conf";

/// SSH 默认端口（OpenSSH 编译默认）。
pub(crate) const DEFAULT_SSH_PORT: u16 = 22;

/// 端口合法性：1..=65535。**不接受 0**（0 在 bind 语义里是"随便挑一个"，
/// 对 sshd 毫无意义，只会让人以为配好了）。
pub(crate) fn validate_port(port: u16) -> Result<u16> {
    if port == 0 {
        return Err(PanelError::Validation {
            field: "port",
            reason: "端口必须为 1-65535（0 表示由系统随机分配，不适用于 SSH）".into(),
        });
    }
    Ok(port)
}

/// 从一段 `sshd_config` 文本里收集所有 `Port` 指令值（**保留重复与顺序**）。
///
/// 与 `ssh_effective` 的「取第一个」不同：这里要如实列出全部，因为 sshd
/// 会监听**每一个** Port。只报生效值会让用户以为"22 已经关了"，实际还在听。
pub(crate) fn ports_in_text(content: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for line in content.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        let mut it = t.split_whitespace();
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            if k.eq_ignore_ascii_case("Port") {
                if let Ok(p) = v.parse::<u16>() {
                    // 与 sshd 一致：非法值 sshd 会自己报错，这里跳过、不臆造
                    if p != 0 {
                        out.push(p);
                    }
                }
            }
        }
    }
    out
}

/// 按 OpenSSH 语义解析**生效端口**：drop-in（文件名排序）→ 主配置，先出现者胜。
///
/// 返回 `(port, 来源文件, 是否显式配置)`。都没显式设置时返回
/// (`DEFAULT_SSH_PORT`, 主配置路径, false)——**这是"默认"而非"配置值"**，
/// 前端据此区分"用户设过"和"一直没动"。
pub(crate) fn effective_port(cfg: &Path, dropins: &[(PathBuf, String)]) -> (u16, PathBuf, bool) {
    for (path, text) in dropins {
        if let Some(p) = ports_in_text(text).first() {
            return (*p, path.clone(), true);
        }
    }
    if let Ok(text) = std::fs::read_to_string(cfg) {
        if let Some(p) = ports_in_text(&text).first() {
            return (*p, cfg.to_path_buf(), true);
        }
    }
    (DEFAULT_SSH_PORT, cfg.to_path_buf(), false)
}

/// 生成 drop-in 内容。
///
/// `keep_old=true` 时保留**改动前所有在听的端口**（不只是 "生效的那个"），
/// sshd 会同时监听它们——这是刻意保留的回退通道：新端口若因防火墙/网络不通，
/// 旧端口仍能进去改回来。用户确认新端口可用后，再跑一次 `keep_old=false` 收敛。
///
/// ⚠ 为什么传**列表**而不是单个 `old_port`：改端口是幂等重试的热点。第一次调用后
/// 生效端口已变成新端口，若"旧端口"只取生效值，用户**再点一次**就会看到
/// `old == new` ⇒ 旧端口被静默丢弃 ⇒ 回退通道没了。这里改为从"配置里现有的
/// 全部端口"取值，重复提交不会吃掉过渡期端口（实测踩过）。
///
/// 新端口在列表中时会被排除，避免出现两行相同的 `Port`。
pub(crate) fn render_dropin(new_port: u16, old_ports: &[u16], keep_old: bool) -> String {
    let mut s = String::new();
    s.push_str("# 由 ForkPanel 生成（P1-7 SSH 端口）。此文件优先级高于其它 drop-in，\n");
    s.push_str("# 请勿手工编辑：面板会整体覆盖。要改端口请在面板里操作。\n");
    s.push_str(&format!("Port {new_port}\n"));
    if keep_old {
        let mut kept: Vec<u16> = Vec::new();
        for p in old_ports {
            if *p != new_port && !kept.contains(p) {
                kept.push(*p);
            }
        }
        if !kept.is_empty() {
            s.push_str("# 过渡期保留旧端口（确认新端口可用后再收敛）\n");
            for p in kept {
                s.push_str(&format!("Port {p}\n"));
            }
        }
    }
    s
}

/// 解析 `ss -H -ltn` 输出里所有**处于 LISTEN 状态**的本地端口。
///
/// 典型一行：`LISTEN 0 128 0.0.0.0:22 0.0.0.0:*`
/// IPv6：`LISTEN 0 128 [::]:22 [::]:*`
///
/// **判据只看最后一个 `:` 之后的部分**（IPv6 地址里含冒号，`[::]:22`
/// 用 `rsplit_once(':')` 才对；用 `split(':')` 会把 `[::]` 切碎取到空串）。
pub(crate) fn listening_ports(ss_output: &str) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for line in ss_output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // 列：State Recv-Q Send-Q Local:Port Peer:Port（-H 去掉了表头）
        let Some(local) = cols.get(3) else { continue };
        let Some((_, port)) = local.rsplit_once(':') else { continue };
        if let Ok(p) = port.parse::<u16>() {
            if p != 0 && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.sort_unstable();
    out
}

/// 检查新端口是否可用（未被其它进程监听）。
///
/// `old_port` 例外：sshd 自己正在监听旧端口，切到自己身上不算冲突。
pub(crate) fn check_port_available(new_port: u16, old_port: Option<u16>, listening: &[u16]) -> Result<()> {
    if Some(new_port) == old_port {
        // 就是要当前这个端口：无改动，由调用方短路
        return Ok(());
    }
    if listening.contains(&new_port) {
        return Err(PanelError::Validation {
            field: "port",
            reason: format!(
                "端口 {new_port} 已被其它进程占用，改用它会导致 sshd 重启后 bind 失败、SSH 连不上。请换一个端口"
            ),
        });
    }
    Ok(())
}

/// drop-in 目录里的现有文件（按文件名排序，只收 `.conf`），用于解析生效值。
pub(crate) fn load_dropins(cfg: &Path) -> Vec<(PathBuf, String)> {
    let Some(dir) = cfg.parent().map(|p| p.join("sshd_config.d")) else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
        .collect();
    files.sort();
    files
        .into_iter()
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|t| (p, t)))
        .collect()
}

/// 改动后应提示用户做的事。**空数组 = 无需额外动作**。
///
/// 分开列是为了前端能逐条渲染 checklist，而不是塞一句"请注意防火墙"
/// 让用户自己去猜。
pub(crate) fn next_steps(new_port: u16, keep_old: bool, old_ports: &[u16]) -> Vec<String> {
    let mut v = Vec::new();
    v.push(format!("防火墙/安全组放行 TCP {new_port}（未放行则新端口连不上）"));
    let kept: Vec<String> = old_ports
        .iter()
        .filter(|p| **p != new_port)
        .map(|p| p.to_string())
        .collect();
    if keep_old && !kept.is_empty() {
        v.push(format!(
            "先保持旧端口 {} 可用，用 `ssh -p {new_port}` 确认能登录；确认后再回来把「保留旧端口」关掉",
            kept.join("、")
        ));
    }
    v.push("重启 SSH 服务后新端口才生效（重启命令：systemctl restart ssh）".into());
    v
}

/// 改动**前**配置里出现的全部端口（drop-in + 主配置，去重保序）。
///
/// 这是 `keep_old` 与 `next_steps` 的唯一取值来源：用"全部"而非"生效的那个"，
/// 重复提交才不会把过渡期保留的旧端口吃掉（见 [`render_dropin`] 的说明）。
///
/// ⚠ **一条端口都没显式配置时，必须返回编译默认 [`DEFAULT_SSH_PORT`]**，不能返回空。
/// Debian 开箱的 `sshd_config` 里 `Port` 是注释掉的（走编译默认 22），此时返回空
/// ⇒ `keep_old` 什么都不保留 ⇒ 用户改完就永久失去 22 这个回退通道，
/// 而这恰恰是最需要回退通道的场景（真机实测踩到：默认配置下改 2222，
/// 落盘只有 `Port 2222`，22 直接没了）。
pub(crate) fn current_ports(cfg: &Path, dropins: &[(PathBuf, String)]) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for (_, text) in dropins {
        for p in ports_in_text(text) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(cfg) {
        for p in ports_in_text(&text) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    // 一条都没显式配置 ⇒ 实际在听的是编译默认端口，它同样需要被保留
    if out.is_empty() {
        out.push(DEFAULT_SSH_PORT);
    }
    out
}

/// 改动后应处于监听状态的端口集合（去重、升序）。用于回执里如实告知。
pub(crate) fn resulting_ports(new_port: u16, old_ports: &[u16], keep_old: bool) -> Vec<u16> {
    let mut v = vec![new_port];
    if keep_old {
        for p in old_ports {
            if *p != new_port && !v.contains(p) {
                v.push(*p);
            }
        }
    }
    v.sort_unstable();
    v
}

/// 修改 SSH 端口的主流程（写盘 + 校验 + 失败回滚）。
///
/// 参数全部由 provider 传入，本函数只负责"读→改→备份→写→校验→必要时回滚"。
pub(crate) async fn set_port(
    cfg: PathBuf,
    new_port: u16,
    keep_old: bool,
) -> Result<SshPortChange> {
    validate_port(new_port)?;

    if !crate::cmd::Bin::available(crate::cmd::Bin::Sshd) {
        return Err(PanelError::Validation {
            field: "sshd",
            reason: "sshd 不可用，无法校验配置语法 → 拒绝修改（避免写错导致无法登录）".into(),
        });
    }
    if !cfg.exists() {
        return Err(PanelError::NotFound(format!("sshd 配置不存在：{}", cfg.display())));
    }

    let dropins = load_dropins(&cfg);
    let (old_port, _src, _explicit) = effective_port(&cfg, &dropins);
    // "旧端口"取**配置里全部端口**而非仅生效值：重复提交时不至于把过渡期
    // 保留的端口吃掉（实测：第一次写 Port 2222 + Port 22，再点一次若只取
    // 生效值则 old==new，22 被静默丢弃）。
    let old_ports = current_ports(&cfg, &dropins);

    // 端口占用预检：**在写盘之前**。写完了才发现端口被占用是最坏顺序——
    // 配置已改、sshd 重启会失败、旧端口也进入不确定状态。
    let listening = probe_listening().await?;
    check_port_available(new_port, Some(old_port), &listening)?;

    let target = cfg
        .parent()
        .map(|p| p.join("sshd_config.d").join(PORT_DROPIN))
        .ok_or_else(|| PanelError::Validation {
            field: "path",
            reason: "sshd 配置无父目录，无法定位 drop-in 目录".into(),
        })?;
    if let Some(dir) = target.parent() {
        let d = dir.to_path_buf();
        crate::fs::blocking(move || std::fs::create_dir_all(&d))
            .await?
            .map_err(|e| PanelError::Io(format!("创建 drop-in 目录失败：{e}")))?;
    }

    let next = render_dropin(new_port, &old_ports, keep_old);

    // 已符合预期：不写盘、不备份（keep_old 与否会影响内容，故按内容比较而非按端口）
    let prev = crate::fs::blocking({
        let p = target.clone();
        move || std::fs::read_to_string(&p).ok()
    })
    .await
    .ok()
    .flatten();
    if prev.as_deref() == Some(next.as_str()) {
        return Ok(SshPortChange {
            changed: false,
            effective: new_port,
            target_file: target.display().to_string(),
            backup: None,
            validated: true,
            listening_ports: resulting_ports(new_port, &old_ports, keep_old),
            next_steps: next_steps(new_port, keep_old, &old_ports),
        });
    }

    // ① 备份（原文件不存在则无备份；回滚 = 删除本文件）
    let backup = if prev.is_some() {
        let b = target.with_extension(format!("conf.panel.bak-{}", now_secs()));
        let (a, c) = (target.clone(), b.clone());
        crate::fs::blocking(move || std::fs::copy(&a, &c))
            .await?
            .map_err(|e| PanelError::Io(e.to_string()))?;
        if let (Some(dir), Some(name)) = (b.parent(), b.file_name().and_then(|n| n.to_str())) {
            if let Some(i) = name.find(".panel.bak-") {
                crate::fs::prune_keep_newest(dir, &name[..i + ".panel.bak-".len()], 10);
            }
        }
        Some(b)
    } else {
        None
    };

    // ② 写
    let write_res = crate::fs::blocking({
        let (p, n) = (target.clone(), next.clone());
        move || std::fs::write(&p, &n)
    })
    .await?;
    if let Err(e) = write_res {
        return Err(PanelError::Io(format!(
            "写入失败，原配置未改动（备份 {}）：{e}",
            backup.as_ref().map(|b| b.display().to_string()).unwrap_or_else(|| "无".into())
        )));
    }

    // ③ 校验：`sshd -t` 走的是**整机配置**（含 Include），所以它能抓到
    //    "drop-in 里写坏了"这件事——这正是我们要的，而不是只校验这个文件。
    let out = crate::cmd::run(
        crate::cmd::Bin::Sshd,
        &["-t"],
        crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(10), ..Default::default() },
    )
    .await;
    let ok = matches!(&out, Ok(o) if o.code == Some(0));
    if !ok {
        // 回滚：原先没有文件就删掉（否则"回滚"会留下一个我们自己造的坏文件）
        let rolled_back = rollback(&target, backup.as_ref()).await;
        if !rolled_back {
            eprintln!(
                "[panel] ⚠ [security] SSH 端口校验未通过且**回滚失败**：{} 上仍是未通过校验的配置",
                target.display()
            );
        }
        let why = match out {
            Ok(o) => panel_core::sanitize::stderr(&o.stderr),
            Err(e) => e.to_string(),
        };
        return Err(PanelError::Command {
            bin: "sshd".into(),
            detail: if rolled_back {
                format!("SSH 端口配置校验未通过，已回滚：{why}")
            } else {
                format!(
                    "SSH 端口配置校验未通过，且**回滚失败**：{} 上仍是未通过校验的配置，请勿重启 sshd，先手工修正或删除该文件：{why}",
                    target.display()
                )
            },
        });
    }

    Ok(SshPortChange {
        changed: true,
        effective: new_port,
        target_file: target.display().to_string(),
        backup,
        validated: true,
        listening_ports: resulting_ports(new_port, &old_ports, keep_old),
        next_steps: next_steps(new_port, keep_old, &old_ports),
    })
}

/// 回滚：有备份则拷回，无备份（原文件本不存在）则删除。返回是否成功。
async fn rollback(target: &Path, backup: Option<&PathBuf>) -> bool {
    match backup {
        Some(b) => {
            let (a, c) = (b.clone(), target.to_path_buf());
            crate::fs::blocking(move || std::fs::copy(&a, &c))
                .await
                .ok()
                .and_then(|r| r.ok())
                .is_some()
        }
        None => {
            let t = target.to_path_buf();
            crate::fs::blocking(move || std::fs::remove_file(&t))
                .await
                .ok()
                .and_then(|r| r.ok())
                .is_some()
        }
    }
}

/// `ss -H -ltn` 探测当前 LISTEN 端口。`ss` 不可用时返回**空集**——
/// 宁可不做占用检查（并让 enabled 能力位如实置灰），也不谎称"端口可用"。
pub(crate) async fn probe_listening() -> Result<Vec<u16>> {
    if !crate::cmd::Bin::available(crate::cmd::Bin::Ss) {
        return Ok(Vec::new());
    }
    let out = crate::cmd::run(
        crate::cmd::Bin::Ss,
        &["-H", "-ltn"],
        crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(10), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Ok(Vec::new());
    }
    Ok(listening_ports(&out.stdout))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 只读：读取当前 SSH 端口状态。
pub(crate) async fn current(cfg: PathBuf) -> Result<crate::traits::SshPortState> {
    let present = cfg.exists();
    if !present {
        return Ok(crate::traits::SshPortState {
            effective: DEFAULT_SSH_PORT,
            explicit: false,
            source_file: cfg.display().to_string(),
            configured: Vec::new(),
            sshd_present: false,
        });
    }
    let dropins = load_dropins(&cfg);
    let (eff, src, explicit) = effective_port(&cfg, &dropins);
    // 全部已配置端口 = drop-in 里的 + 主配置里的（去重保序）
    let mut configured: Vec<u16> = Vec::new();
    for (_, text) in &dropins {
        for p in ports_in_text(text) {
            if !configured.contains(&p) {
                configured.push(p);
            }
        }
    }
    // 主配置也要读——drop-in 只覆盖它 Include 之后的部分，主配置里可能还有 Port。
    // 读失败（文件不存在/无权限）等同于「主配置没贡献端口」，不是错误。
    if let Some(text) = crate::fs::blocking({
        let c = cfg.clone();
        move || std::fs::read_to_string(&c).ok()
    })
    .await
    .ok()
    .flatten()
    {
        for p in ports_in_text(&text) {
            if !configured.contains(&p) {
                configured.push(p);
            }
        }
    }
    Ok(crate::traits::SshPortState {
        effective: eff,
        explicit,
        source_file: src.display().to_string(),
        configured,
        sshd_present: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("panel-sshport-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn port_zero_is_rejected() {
        // 0 在 bind 语义里是"随便挑"，对 sshd 无意义：必须拒绝而不是静默接受
        assert!(validate_port(0).is_err());
        assert!(validate_port(1).is_ok());
        assert!(validate_port(65535).is_ok());
    }

    #[test]
    fn collects_all_port_directives_in_order() {
        let t = "Port 22\n#Port 99\nPort 2222\n  port 2022  # 注释\n";
        assert_eq!(ports_in_text(t), vec![22, 2222, 2022]);
    }

    #[test]
    fn commented_port_is_ignored() {
        let t = "#Port 2222\nPort 22\n";
        assert_eq!(ports_in_text(t), vec![22], "注释掉的 Port 不生效，不能被当成配置值");
    }

    #[test]
    fn dropin_wins_over_main_config() {
        // 关键回归：主配置第 12 行就 Include 了 drop-in，所以 drop-in 优先。
        // 若把 Port 写进主配置而 drop-in 里已有旧值，改动会**静默不生效**。
        let d = tmp_dir("eff");
        let cfg = d.join("sshd_config");
        std::fs::write(&cfg, "Include /etc/ssh/sshd_config.d/*.conf\nPort 2222\n").unwrap();
        let dropin = d.join("sshd_config.d/10-old.conf");
        std::fs::create_dir_all(dropin.parent().unwrap()).unwrap();
        std::fs::write(&dropin, "Port 22\n").unwrap();
        let dropins = vec![(dropin.clone(), "Port 22\n".to_string())];
        let (p, src, explicit) = effective_port(&cfg, &dropins);
        assert_eq!(p, 22, "drop-in 里的值必须赢");
        assert_eq!(src, dropin);
        assert!(explicit);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn default_port_when_nothing_configured() {
        let d = tmp_dir("def");
        let cfg = d.join("sshd_config");
        std::fs::write(&cfg, "#Port 22\n").unwrap();
        let (p, _, explicit) = effective_port(&cfg, &[]);
        assert_eq!(p, DEFAULT_SSH_PORT);
        assert!(!explicit, "走编译默认时必须如实标 explicit=false");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dropin_name_sorts_before_existing_ones() {
        // 00- 前缀必须排在 10-/20-/50- 之前；这条断言防止有人"顺手"改个更友好的名字
        assert!(PORT_DROPIN < "10-hardening.conf");
        assert!(PORT_DROPIN < "20-systemd-userdb.conf");
        assert!(PORT_DROPIN < "50-cloud-init.conf");
    }

    #[test]
    fn keep_old_renders_both_ports() {
        let s = render_dropin(2222, &[22], true);
        assert_eq!(ports_in_text(&s), vec![2222, 22], "过渡期必须两个端口都在");
        let s2 = render_dropin(2222, &[22], false);
        assert_eq!(ports_in_text(&s2), vec![2222], "收敛后只剩新端口");
    }

    #[test]
    fn keep_old_does_not_duplicate_when_same_port() {
        let s = render_dropin(2222, &[2222], true);
        assert_eq!(ports_in_text(&s), vec![2222]);
    }

    /// 关键回归（真机踩到）：改端口是幂等重试的热点。
    /// 第一次写 `Port 2222 + Port 22` 后，生效值已是 2222；用户若**再点一次**，
    /// 只要"旧端口"取的是生效值（而不是配置里的全部端口），就会 old==new
    /// ⇒ 22 被静默丢弃 ⇒ 回退通道没了。这条测试钉住"整份配置里的端口都要留下"。
    #[test]
    fn repeated_submit_keeps_transitional_old_port() {
        // 模拟第一次写入后的状态：配置里同时有 2222 与 22
        let current = vec![2222, 22];
        let s = render_dropin(2222, &current, true);
        assert_eq!(
            ports_in_text(&s), vec![2222, 22],
            "重复提交同一端口时，过渡期保留的旧端口不能被吃掉"
        );
    }

    /// 去重：old_ports 里若含新端口（无论重复几次），成品中不能出现两行相同 Port。
    #[test]
    fn render_dedups_against_new_port() {
        let s = render_dropin(2222, &[2222, 2222, 22, 22], true);
        assert_eq!(ports_in_text(&s), vec![2222, 22]);
    }

    /// ⚠ 真机踩到的关键回归：Debian 开箱 `sshd_config` 里 `Port` 是**注释掉的**
    /// （走编译默认 22）。若此时 `current_ports` 返回空列表，`keep_old` 就什么都
    /// 不保留 ⇒ 用户改成 2222 后 22 永久消失 ⇒ 新端口不通时没有任何回退通道。
    /// 必须返回 `[22]`。
    #[test]
    fn current_ports_falls_back_to_default_when_nothing_configured() {
        let d = tmp_dir("curports-empty");
        let cfg = d.join("sshd_config");
        std::fs::write(
            &cfg,
            "#Port 22\n#AddressFamily any\nInclude /etc/ssh/sshd_config.d/*.conf\n",
        )
        .unwrap();
        assert_eq!(
            current_ports(&cfg, &[]), vec![DEFAULT_SSH_PORT],
            "默认配置下必须把编译默认端口当作\"正在听\"的端口，否则改完丢掉回退通道"
        );
        // 落盘效果：必须同时有 Port 2222 与 Port 22
        let s = render_dropin(2222, &current_ports(&cfg, &[]), true);
        assert_eq!(ports_in_text(&s), vec![2222, 22], "默认配置下改端口也要保留 22");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `current_ports` 必须把 drop-in 与主配置的端口合并去重；
    /// 它是 `keep_old` 的唯一取值来源，取漏了旧端口就没了。
    #[test]
    fn current_ports_merges_dropins_and_main_config() {
        let d = tmp_dir("curports");
        let cfg = d.join("sshd_config");
        std::fs::write(&cfg, "Port 2022\n#Port 9999\n").unwrap();
        let dropins = vec![
            (PathBuf::from("a.conf"), "Port 2222\nPort 22\n".to_string()),
            (PathBuf::from("b.conf"), "Port 22\n".to_string()),
        ];
        assert_eq!(current_ports(&cfg, &dropins), vec![2222, 22, 2022]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 接线守卫：`set_port` 必须用 `current_ports(...)` 取旧端口。
    ///
    /// ⚠ 为什么必须单独守这一条而不是靠纯函数单测：`render_dropin` /
    /// `resulting_ports` 的单测**全绿**也挡不住 `set_port` 里退回
    /// `vec![old_port]`——那正是真机踩到的 bug（重复提交把过渡期旧端口吃掉），
    /// 而它只在 `set_port` 这一层。实测过：只靠纯函数单测时，把这一行改回
    /// `vec![old_port]`，18 条测试**一条都不红**（"判据指向错"的标准案例）。
    ///
    /// 判据扫 `set_port` 的函数体（不扫整个文件），并且断言"定义处恰好 1 处 +
    /// 该函数体内 1 处"，避免正则写错时静默空转。
    #[test]
    fn set_port_uses_all_configured_ports_not_just_effective() {
        let src = panel_testutil::production_source(include_str!("ssh_port.rs"));
        // ① 先确认 `current_ports` 在源码里确实被定义了（防止改名后本守卫空转）
        let defs = src.matches("pub(crate) fn current_ports").count();
        assert_eq!(defs, 1, "current_ports 定义处应恰好 1 处，实际 {defs}");
        // ② 只取 set_port 的函数体。`production_source` 已剔注释，所以锚点
        //    只能用代码本身（不能用 `/// 回滚：` 这类注释文本）。
        let start = src.find("pub(crate) async fn set_port").expect("set_port 必须存在");
        let rest = &src[start..];
        let end = rest.find("async fn rollback").expect("set_port 之后应有 rollback 定义");
        let body = &rest[..end];
        assert!(
            body.contains("current_ports(&cfg, &dropins)"),
            "set_port 必须从配置里取全部端口（current_ports），不能只取生效值——\
             否则重复提交会静默丢掉过渡期保留的旧端口"
        );
        // ③ 反证：不能退回只取生效值的写法
        assert!(
            !body.contains("vec![old_port]"),
            "set_port 不得退回 `vec![old_port]`（真机踩过的 bug）"
        );
    }

    /// `resulting_ports` 必须去重且升序：回执里出现 `[2222, 2222]` 会让用户
    /// 以为面板算错了端口。
    #[test]
    fn resulting_ports_is_deduped_and_sorted() {
        assert_eq!(resulting_ports(2222, &[22], true), vec![22, 2222]);
        assert_eq!(resulting_ports(2222, &[2222, 22], true), vec![22, 2222]);
        assert_eq!(resulting_ports(2222, &[2222], true), vec![2222]);
        assert_eq!(resulting_ports(2222, &[22], false), vec![2222]);
    }

    #[test]
    fn parses_ipv4_and_ipv6_listeners() {
        let out = "\
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 [::]:22 [::]:*
LISTEN 0 128 127.0.0.1:2222 0.0.0.0:*
LISTEN 0 128 [::1]:8080 [::]:*
";
        // IPv6 地址里含冒号，必须按最后一个 ':' 切；22 去重后只出现一次
        assert_eq!(listening_ports(out), vec![22, 2222, 8080]);
    }

    #[test]
    fn empty_ss_output_yields_empty() {
        assert!(listening_ports("").is_empty());
    }

    #[test]
    fn port_conflict_with_other_process_is_rejected() {
        // 关键：端口被别人占着时必须拒绝，否则重启 sshd 直接失败
        let e = check_port_available(2222, Some(22), &[22, 2222]).unwrap_err();
        assert!(matches!(e, PanelError::Validation { field: "port", .. }));
        // 旧端口本身不算冲突（sshd 正在监听它）
        assert!(check_port_available(22, Some(22), &[22]).is_ok());
        // 空闲端口通过
        assert!(check_port_available(2200, Some(22), &[22, 2222]).is_ok());
    }

    #[test]
    fn next_steps_always_mentions_firewall_and_restart() {
        let v = next_steps(2222, true, &[22]);
        let all = v.join(" | ");
        assert!(all.contains("2222"), "必须明确要放行的端口号：{all}");
        assert!(all.contains("防火墙"), "不放行防火墙就会被锁在门外：{all}");
        assert!(all.contains("重启"), "不重启不生效：{all}");
        // 保留旧端口时必须给出回退指引
        assert!(all.contains("ssh -p 2222"), "必须给出验证新端口的命令：{all}");
    }

    #[test]
    fn next_steps_without_keep_old_has_no_fallback_line() {
        let v = next_steps(2222, false, &[22]);
        assert!(!v.join(" ").contains("ssh -p"), "关了过渡期就不该再提回退");
    }

    #[test]
    fn render_includes_warning_header() {
        let s = render_dropin(2222, &[22], true);
        assert!(s.contains("ForkPanel"), "生成物要标明来源，否则运维不知道能不能手改");
        assert!(s.starts_with('#'), "首行必须是注释，不能是有效指令");
    }
}
