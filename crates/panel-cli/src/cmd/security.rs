//! 安全相关的 CLI 命令：改口令、撤销保护地开通公网访问。
//!
//! 为什么这两条归一域：它们都直接改变**谁能访问面板**——`passwd` 改的是账号凭据，
//! `expose` 改的是网络暴露面（nginx 反代 + 防火墙放行）。危险等级也同档，都要求
//! root 并在开头就失败，绝不半途留下「服务指着未生效配置」的残态。
//!
//! ⚠ 三条不许放松的约定：
//! 1. `passwd` **只能改已存在用户**：不得具备建号能力。否则同机任意能执行 CLI 的
//!    进程都能给自己开账号，等于绕过首启引导令牌。
//! 2. `expose` 拒绝开「无来源限制」的反代：`-a/--allow` 为空直接报错。脚本侧还有
//!    一次 fail-closed 校验，两层都保留（纵深防御，别因为"脚本也会拦"就删前端这层）。
//! 3. 调脚本一律经 `crate::invoke_expose`（它走 `panel_os::paths` 定位脚本、
//!    用 `panel_os::run_sync(Bin::Bash, &argv)` 直传 argv）。**不得**在这里拼
//!    shell 字符串或硬编码 `/usr/local/bin/expose-public.sh`——分层门禁会红。
use std::io::IsTerminal;
use std::sync::Arc;

use panel_os::PathLayout;

use panel_core::{now_unix, PanelError, Result};

use crate::{
    bootstrap, build_layout, detect_tier, invoke_expose, load_cfg, prompt_line,
    validate_expose_cidr, validate_expose_domain, Cli,
};


/// 修改已存在用户的口令。口令来源：`--pass` > 交互关回显。
///
/// `--pass` 会进 shell history 与 `ps`，只给脚本场景用；因此非 TTY 且没给
/// `--pass` 时直接报错，不静默用空口令。
pub(crate) fn passwd(
    cli: &Cli,
    os: Arc<dyn panel_os::OsAdapter>,
    user: &str,
    pass: &Option<String>,
) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    let layout = build_layout(&os, Some(&cfg));
    let tier = detect_tier(&*os, &cfg);
    let mut conn = panel_db::open(&layout.sqlite_path(), tier, &cfg.db.synchronous)?;

    // 只改**已存在**用户的口令：passwd 不得具备建号能力，
    // 否则同机任意能执行 CLI 的进程都能给自己开账号（等于绕过引导令牌）。
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM users WHERE username = ?1",
            rusqlite::params![user],
            |r| r.get(0),
        )
        .map_err(|e| PanelError::Database(e.to_string()))?;
    if exists == 0 {
        return Err(PanelError::Validation {
            field: "user",
            reason: format!("用户 {user} 不存在"),
        });
    }

    // 口令：命令行 > 交互关回显（--pass 会进 shell history / ps，仅脚本场景使用）
    let password = match pass.clone() {
        Some(p) => p,
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(PanelError::Validation {
                    field: "pass",
                    reason: "非交互环境请提供 --pass".into(),
                });
            }
            bootstrap::read_password("请输入新口令（≥10 位，含两类字符）：")?
        }
    };
    panel_api::auth::check_password_policy(&password)?;
    let hash =
        panel_api::auth::hash_password(&password, &panel_api::auth::HashParams::for_tier(tier))?;
    let now = now_unix();

    // 单写事务：更新口令 + 审计要么都成，要么都不成
    let tx = conn.transaction().map_err(|e| PanelError::Database(e.to_string()))?;
    tx.execute(
        "UPDATE users SET pwd_hash = ?1 WHERE username = ?2",
        rusqlite::params![hash, user],
    )
    .map_err(|e| PanelError::Database(e.to_string()))?;
    tx.execute(
        "INSERT INTO audit_log(ts, actor, actor_ip, action, target, result, detail_json)
         VALUES (?1, ?2, 'cli', 'auth.passwd', ?2, 'ok', '{}')",
        rusqlite::params![now, user],
    )
    .map_err(|e| PanelError::Database(e.to_string()))?;
    tx.commit().map_err(|e| PanelError::Database(e.to_string()))?;

    println!("用户 {user} 的口令已更新");
    Ok(())
}

/// 开通公网访问：校验域名/来源网段后透传给 `expose-public.sh`。
///
/// `--uninstall` 时直接透传，不需要域名与网段（撤销不该被参数校验挡住）。
/// 注意这只撤反代、面板仍绑回环；卸载面板本体是 `panel uninstall`。
pub(crate) fn expose(
    domain: Option<String>,
    allow: Vec<String>,
    self_signed: bool,
    fullchain: Option<String>,
    key: Option<String>,
    no_firewall: bool,
    uninstall: bool,
) -> Result<()> {
    // 写 /etc/nginx 反代、systemd 单元与防火墙规则都需要 root；非 root 提前报错，
    // 绝不半途留下「服务还指着未生效配置」的残态（与 uninstall 同纪律）。
    if !panel_os::fs::is_root() {
        return Err(PanelError::Internal(
            "expose: 需要 root 权限（要写 /etc/nginx 反代、systemd 单元与防火墙规则）".into(),
        ));
    }

    // 卸载模式：直接透传 --uninstall，无需域名/网段。
    if uninstall {
        return invoke_expose(&["--uninstall".to_string()]);
    }

    // 证书二选一：给了 fullchain 就必须给 key（反之亦然）；都不给则脚本默认自签。
    if fullchain.is_some() != key.is_some() {
        return Err(PanelError::Validation {
            field: "cert",
            reason: "--fullchain 与 --key 必须成对提供（要么都给，要么都不给用自签）".into(),
        });
    }

    // 收集域名：命令行优先，省略则交互询问（非 TTY 直接报错，不放过）。
    let domain = match domain {
        Some(d) => d,
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(PanelError::Validation {
                    field: "domain",
                    reason: "非交互环境请提供 --domain".into(),
                });
            }
            prompt_line("对外域名（如 panel.example.com）: ")?
        }
    };
    validate_expose_domain(&domain)
        .map_err(|e| PanelError::Validation { field: "domain", reason: e })?;

    // 收集来源网段（可重复）：命令行优先，省略则交互询问，至少要有一个。
    let mut allow = allow;
    if allow.is_empty() {
        if !std::io::stdin().is_terminal() {
            return Err(PanelError::Validation {
                field: "allow",
                reason: "非交互环境请提供 -a/--allow <CIDR>（可重复）".into(),
            });
        }
        let raw = prompt_line("允许访问的来源网段（IPv4 CIDR，可多个，逗号/空格分隔，如 1.2.3.4/32）: ")?;
        for part in raw.split(|c| [',', ' '].contains(&c)).filter(|s| !s.is_empty()) {
            allow.push(part.to_string());
        }
    }
    if allow.is_empty() {
        return Err(PanelError::Validation {
            field: "allow",
            reason: "必须至少指定一个来源网段（-a/--allow）；拒绝开无来源限制的反代".into(),
        });
    }
    for c in &allow {
        validate_expose_cidr(c)
            .map_err(|e| PanelError::Validation { field: "allow", reason: e })?;
    }

    // 组装透传给脚本的参数（脚本再做一次 fail-closed 校验，纵深防御）。
    let mut args: Vec<String> = Vec::new();
    args.push("-d".into());
    args.push(domain);
    for c in &allow {
        args.push("-a".into());
        args.push(c.clone());
    }
    if self_signed { args.push("--self-signed".into()); }
    if let Some(f) = fullchain { args.push("--fullchain".into()); args.push(f); }
    if let Some(k) = key { args.push("--key".into()); args.push(k); }
    if no_firewall { args.push("--no-firewall".into()); }
    invoke_expose(&args)?;
    println!("（已通过 `panel expose` 调用 expose-public.sh 完成。若需撤销：sudo panel expose --uninstall）");
    Ok(())
}
