//! 面板自身的运维命令：systemd 单元、探活、能力矩阵、卸载、升级。
//!
//! 为什么归一域：它们操作的是**这台机器上的面板安装**（单元文件、探活脚本、
//! 二进制、可执行入口），而不是数据库或站点。危险等级也同档——`uninstall` 会删
//! 二进制与单元、`upgrade` 会替换二进制，二者都要求 root 且失败时都可能留下
//! 「服务指向不存在的文件」的残态，所以放在一起审。
//!
//! ⚠ 四条容易改坏的约定：
//! 1. `systemd-unit` / `healthcheck` **缺省只打印不安装**：不装 root 也能审阅要写入
//!    什么，也便于把单元/脚本内容抽出来单测。改成"默认就装"会破坏这条。
//! 2. `healthcheck --uninstall` 先 `systemctl disable --now <timer>` 再删文件。
//!    只删单元不停 timer 会留下「每分钟触发、ExecStart 指向不存在脚本」的残态。
//! 3. `uninstall` 在开头就判 root 并**提前失败**：绝不半途留下"服务还在指着一个
//!    已被删掉的二进制"。同样地，探活 service/timer 必须与 panel.service 一起删。
//! 4. `capabilities --json` 是本项目唯一实现了 JSON 输出的子命令（见
//!    `cli_flags_tests`）——其余命令的 `--json` 由 clap 直接拒绝，宁可响亮失败，
//!    也不"收下参数却不生效"。
use std::sync::Arc;

use panel_core::{PanelError, Result};

use crate::config::Config;
use crate::{bootstrap, build_layout, detect_tier, load_cfg, upgrade, Cli};


/// 生成（或 `--install` 写入）`panel.service`。
///
/// 必须用**配置感知**的 layout 构造 `writable`：否则用户覆盖 `[paths]` 后单元里的
/// `ReadWritePaths` 仍是默认值，而 `ExecStart` 指向自定义 `--config`，在
/// `ProtectSystem=strict` 下面板写不进真实数据/日志/站点目录。
pub(crate) fn systemd_unit(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>, install: bool) -> Result<()> {
    // 关键修复：必须用配置感知的布局构造 `writable`。否则用户在 config.toml
    // 覆盖 [paths] 后，生成的单元 ReadWritePaths 仍是默认值，而 ExecStart
    // 指向自定义 --config ⇒ ProtectSystem=strict 下面板写不进真实
    // 数据/日志/站点目录 ⇒ 起不来或丢数据。逻辑与 Cmd::Serve 对齐。
    // 容错：config 尚未写入（仅打印单元预览）时回退默认布局。
    let layout0 = build_layout(&os, None);
    let cfgp = cli.config.clone().unwrap_or_else(|| layout0.config_dir().join("config.toml"));
    let mut cfg = Config::load(&cfgp).unwrap_or_default();
    if let Some(t) = &cli.tier { cfg.tier = t.clone(); }
    let layout = build_layout(&os, Some(&cfg));
    let tier = detect_tier(&*os, &cfg);
    let bin = std::env::current_exe()
        .map(|p| p.display().to_string())
        .map_err(|e| PanelError::Internal(format!("无法确定自身路径：{e}")))?;
    // 放行目录两档（必填四目录 / 可选 web conf drop-in）由 bootstrap 收敛，
    // 与单测同源：可选档漏了 web conf 目录，官方单元部署后建站必然 EROFS
    // （LinuxWebServer::deploy 直写 /etc/nginx/conf.d 等）。
    let (writable, optional_writable) = bootstrap::writable_dirs(&layout);
    let unit = bootstrap::systemd_unit(&bin, &cfgp.display().to_string(), tier,
                                       &writable, &optional_writable);
    if install {
        let dir = os.paths().service_dir();
        if dir.as_os_str().is_empty() {
            return Err(PanelError::Unsupported("service_dir: 该平台无单元文件目录"));
        }
        std::fs::create_dir_all(&dir).ok();
        let p = dir.join("panel.service");
        std::fs::write(&p, &unit)
            .map_err(|e| PanelError::Internal(format!("write unit: {e}")))?;
        println!("已写入 {}（执行 systemctl daemon-reload && systemctl enable --now panel）", p.display());
    } else {
        println!("{unit}");
    }
    Ok(())
}

/// 生成/安装/卸载外部探活（覆盖 `Restart=on-failure` 管不了的"活着但不服务"）。
pub(crate) fn healthcheck(
    cli: &Cli,
    os: Arc<dyn panel_os::OsAdapter>,
    install: bool,
    uninstall: bool,
) -> Result<()> {
    let cfgp = cli.config.clone().unwrap_or_else(|| os.paths().config_dir().join("config.toml"));
    let cfg = Config::load(&cfgp).unwrap_or_default();
    let port = cfg.server.port;
    let dir = os.paths().service_dir();
    if dir.as_os_str().is_empty() {
        return Err(PanelError::Unsupported("service_dir: 该平台无单元文件目录"));
    }
    let script = os.paths().script_dir().join("healthcheck.sh");
    let (svc, timer) = bootstrap::healthcheck_units("panel", &script);

    if uninstall {
        let mut removed = 0;
        for p in [dir.join("panel-healthcheck.service"), dir.join("panel-healthcheck.timer")] {
            if p.exists() { std::fs::remove_file(&p).ok(); removed += 1; }
        }
        let _ = std::fs::remove_file(&script);
        println!("已移除探活（{removed} 个单元文件 + 脚本）；执行 systemctl daemon-reload");
        return Ok(());
    }

    let sh = bootstrap::healthcheck_script("panel", port);
    if !install && !uninstall {
        // 与 `systemd-unit` 同纪律：缺省打印而非安装，便于不装 root 也能
        // 审阅内容 / 抽出来单测行为（探活脚本的逻辑必须真机跑过才算数）。
        print!("{sh}\n--- unit: panel-healthcheck.service ---\n{svc}\n--- unit: panel-healthcheck.timer ---\n{timer}");
        return Ok(());
    }
    if install {
        std::fs::create_dir_all(os.paths().script_dir())
            .map_err(|e| PanelError::Internal(format!("create script_dir: {e}")))?;
        std::fs::write(&script, &sh)
            .map_err(|e| PanelError::Internal(format!("write script: {e}")))?;
        // chmod 是平台专有能力，走 OS 抽象层（分层门禁第 4 条：业务层
        // 不得出现平台条件编译）。0750 = 属主可写、组可读执行。
        panel_os::fs::set_mode(&script, 0o750)?;
        std::fs::create_dir_all(&dir).ok();
        std::fs::write(dir.join("panel-healthcheck.service"), &svc)
            .map_err(|e| PanelError::Internal(format!("write unit: {e}")))?;
        std::fs::write(dir.join("panel-healthcheck.timer"), &timer)
            .map_err(|e| PanelError::Internal(format!("write unit: {e}")))?;
        println!("已安装探活：");
        println!("  脚本  {}", script.display());
        println!("  单元  {}/panel-healthcheck.{{service,timer}}", dir.display());
        println!("下一步：systemctl daemon-reload && systemctl enable --now panel-healthcheck.timer");
    } else {
        print!("{svc}\n--- timer ---\n{timer}");
    }
    Ok(())
}

/// 打印能力矩阵（供脚本判断环境）；`json` 时输出机器可读格式。
pub(crate) fn capabilities(os: Arc<dyn panel_os::OsAdapter>, json: bool) -> Result<()> {
    let caps = os.capabilities();
    if json {
        println!("{}", serde_json::to_string_pretty(&caps).unwrap_or_default());
    } else {
        for (k, c) in &caps {
            let mark = if c.supported { "✓" } else { "✗" };
            let backend = c.backend.as_deref().unwrap_or("-");
            let reason = c.reason.as_deref().map(|r| format!(" ({r})")).unwrap_or_default();
            println!("{} {:<20} {}{}", mark, k, backend, reason);
        }
    }
    Ok(())
}

/// 卸载面板本体：停服务 → 移除单元（含探活）→ 移除二进制与暴露脚本。
///
/// **保留** `/var/lib|/etc|/var/log/forkpanel` 与 `/var/www`（账号与数据不自动删）。
/// 注意这只卸面板本体；撤销公网访问是 `panel expose --uninstall`，不是这里。
pub(crate) fn uninstall(os: Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    // 删单元 / 删二进制都需要 root；非 root 一律提前报错，绝不半途留下
    // 「服务还指着已删二进制」的残态（与 uninstall.sh 同纪律）。
    if !panel_os::fs::is_root() {
        return Err(PanelError::Internal(
            "uninstall: 需要 root 权限（停止/禁用 systemd 服务、移除单元、删除面板二进制都需 root）".into(),
        ));
    }

    // 容错：这些命令在容器 / 非 systemd 环境可能不存在或报错，卸载仍要继续。
    // 子进程出口唯一收敛在 panel-os（cmd.rs）——业务层不得直接 spawn。
    let _ = panel_os::run_sync(panel_os::Bin::Systemctl, &["stop", "panel"]);
    let _ = panel_os::run_sync(panel_os::Bin::Systemctl, &["disable", "panel"]);
    // 探活 timer 必须先 `disable --now`：只删单元不停 timer，会留下
    // 「每分钟触发一次、ExecStart 指向不存在的脚本」的残态，journal 持续刷错误。
    let _ = panel_os::run_sync(
        panel_os::Bin::Systemctl,
        &["disable", "--now", "panel-healthcheck.timer"],
    );

    // 移除面板自建单元：路径经 PathLayout（service_dir），业务层不硬编码 /etc。
    // 三件套必须一起删——历史上只删了 panel.service，探活 service/timer 留在
    // 机器上继续跑，卸载后 journal 每分钟报一次 Failed to start。
    let service_dir = os.paths().service_dir();
    let units = [
        service_dir.join("panel.service"),
        service_dir.join("panel-healthcheck.service"),
        service_dir.join("panel-healthcheck.timer"),
    ];
    let mut removed_units = 0;
    for unit in &units {
        if unit.exists() && std::fs::remove_file(unit).is_ok() {
            removed_units += 1;
        }
    }
    // 探活脚本与单元同源（`panel healthcheck --install` 落盘）；数据目录保留，
    // 但这条脚本属于「安装产物」而非用户数据，一并清掉。
    let _ = std::fs::remove_file(os.paths().script_dir().join("healthcheck.sh"));
    let _ = panel_os::run_sync(panel_os::Bin::Systemctl, &["daemon-reload"]);
    println!("· 已移除 systemd 单元 {removed_units} 个（含探活 service/timer）");

    // 移除命令入口：只有 panel 一个（交互式配置已并入 panel 二进制，
    // 不再单独安装 forkpanel / fp 壳）。只删固定安装路径——不删 current_exe()，
    // 避免 E2E namespace 里误删宿主构建产物。
    let bin = panel_os::paths::panel_bin_install_path();
    let bin_dir = bin.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| bin.clone());
    for name in ["panel"] {
        let p = bin_dir.join(name);
        if !p.exists() {
            continue;
        }
        if std::fs::remove_file(&p).is_ok() {
            println!("· 已移除 {}", p.display());
        } else {
            eprintln!("  警告：无法移除 {}（权限？）", p.display());
        }
    }

    // 公网暴露脚本（`panel expose` 的依赖）与它的空目录。与 install.sh 的
    // EXPOSE_DST 同源（panel-os 提供路径），避免「删了单元却留下脚本」。
    let expose = panel_os::paths::panel_expose_script_path();
    if expose.exists() {
        let _ = std::fs::remove_file(&expose);
        if let Some(dir) = expose.parent() {
            let _ = std::fs::remove_dir(dir); // 仅当空目录，非空则失败无副作用
        }
        println!("· 已移除公网暴露脚本 {}", expose.display());
    }

    println!();
    println!("已卸载 ForkPanel。以下目录被保留（含账号与数据，未自动删除）：");
    println!("  /var/lib/forkpanel    数据库、主密钥、备份");
    println!("  /etc/forkpanel        配置");
    println!("  /var/log/forkpanel    日志");
    println!("  /var/www              站点根目录");
    println!();
    println!("确认不再需要后自行删除：");
    println!("  rm -rf /var/lib/forkpanel /etc/forkpanel /var/log/forkpanel");
    Ok(())
}

/// 升级面板二进制（`--check` 只查、`--dry-run` 只演练）。
pub(crate) fn upgrade(
    cli: &Cli,
    os: Arc<dyn panel_os::OsAdapter>,
    check: bool,
    dry_run: bool,
    version: &Option<String>,
    base_url: &Option<String>,
    pubkey_file: &Option<std::path::PathBuf>,
) -> Result<()> {
    // 与其它需要 [paths] 的命令同款：先按默认布局读配置，再用配置重建布局。
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    let layout = build_layout(&os, Some(&cfg));
    upgrade::run(upgrade::Opts {
        check,
        dry_run,
        version: version.clone(),
        base_url: base_url.clone(),
        pubkey: pubkey_file.clone(),
        data_dir: layout.data_dir(),
    })
}
