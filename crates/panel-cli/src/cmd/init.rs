//! `panel init` / `panel doctor`：首次初始化与自检，一对"装完立刻用"的命令。
//!
//! 为什么这两条归一域：`init` 建出来的东西（目录、主密钥、配置、库、owner）
//! 恰好就是 `doctor` 逐项体检的对象。两者共用同一套前置（定位配置 → 建 layout →
//! 按档位开库），改其中一边的路径推导而忘了另一边，就会重现"`doctor` 报全绿、
//! `serve` 却起不来"这类自相矛盾。
//!
//! ⚠ 两处别顺手"优化"掉：
//! 1. `init` 在配置文件**已存在**时默认复用而不覆盖（只打印一行提示）。覆盖会
//!    抹掉用户手写的 `[paths]`，把数据目录悄悄指回默认位置——库还在旧路径、
//!    面板却去新路径找，症状是"初始化完是空面板"。`--force` 才是破坏性重建。
//! 2. `doctor` 必须先跑 `validate_implemented()`，与 `serve` 同一套启动前校验。
//!    少了这行，`doctor` 会对 `[server].tls`（或 0 秒会话时长）报全绿，而模板
//!    恰恰是叫用户"改完配置跑 `panel doctor`"——等于把人往坑里带。
//!
//! ⚠ `main.rs::wiring_guard_tests::tls_fake_control_is_wired_into_serve` 断言的
//! 是 `cmd/serve.rs` 里 `validate_implemented()` **恰好一次**。本文件也有一次，
//! 但那条守卫的 `include_str!` 只指向 serve.rs，所以两者互不干扰——别把它改成
//! "全仓计数"，否则真值是 2，守卫会以"太严"为由被改成 `>= 1`（然后恒绿）。
use std::sync::Arc;

use panel_core::{PanelError, Result};

use crate::{bootstrap, build_layout, config, create_owner, detect_tier, doctor, load_cfg, Cli};

/// 初始化面板：目录 / 主密钥 / 配置 / 库结构 / 首个 owner 账号。
///
/// 幂等：配置已存在则复用（除非 `--force`），owner 已存在则跳过创建。
pub(crate) fn init(
    cli: &Cli,
    os: Arc<dyn panel_os::OsAdapter>,
    force: bool,
    owner: &Option<String>,
    owner_pass: &Option<String>,
) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg_path = cli.config.clone().unwrap_or_else(|| layout0.config_dir().join("config.toml"));
    // 配置不存在 → 全新初始化（写模板）；存在 → 复用既有配置（不覆盖，避免改掉 [paths] 等设置）
    let cfg = if !cfg_path.exists() {
        bootstrap::ensure_dirs(&layout0)?;
        let _key = bootstrap::ensure_master_key(&layout0.data_dir())?;
        if let Some(p) = cfg_path.parent() { std::fs::create_dir_all(p).ok(); }
        std::fs::write(&cfg_path, config::template(
            &layout0.config_dir(), &layout0.data_dir(), &layout0.site_root())).ok();
        load_cfg(cli, &layout0)?
    } else {
        if force {
            // --force 按平台默认路径重建配置（会清掉既有 [paths] 覆盖，属破坏性操作）
            bootstrap::ensure_dirs(&layout0)?;
            let _key = bootstrap::ensure_master_key(&layout0.data_dir())?;
            std::fs::write(&cfg_path, config::template(
                &layout0.config_dir(), &layout0.data_dir(), &layout0.site_root())).ok();
        } else {
            println!("（配置已存在，复用 {}，不覆盖）", cfg_path.display());
        }
        load_cfg(cli, &layout0)?
    };
    // 目录与主密钥以最终 layout（含配置中的 [paths] 覆盖）为准
    let layout = build_layout(&os, Some(&cfg));
    bootstrap::ensure_dirs(&layout)?;
    // 与 serve / panel migrate 共用实例锁，避免 init 与正在跑的实例并发改库。
    let _instance_lock = panel_os::instance_lock::acquire(&layout.data_dir())?;
    let _key = bootstrap::ensure_master_key(&layout.data_dir())?;
    let tier = detect_tier(&*os, &cfg);
    let db_path = layout.sqlite_path();
    let mut conn = panel_db::open(&db_path, tier, &cfg.db.synchronous)?;
    crate::migrate_snapshot::snapshot_before_migrate(&conn, &db_path, &layout.backup_dir())?;
    panel_db::migrate::apply(&mut conn)?;
    // 幂等：已有 owner 则跳过
    let owner_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM users WHERE role = 'owner'",
        [],
        |r| r.get(0),
    ).map_err(|e| PanelError::Database(e.to_string()))?;
    if owner_count == 0 {
        create_owner(&mut conn, tier, owner.clone(), owner_pass.clone())?;
    } else {
        println!("（已有 owner 账号，跳过创建）");
    }
    drop(conn);
    println!("初始化完成");
    println!("  配置文件：{}", cfg_path.display());
    println!("  数据目录：{}", layout.data_dir().display());
    println!();
    println!("可用 owner 账号登录面板（生产 http://127.0.0.1:{}；开发模式前端 http://127.0.0.1:5173）。", cfg.server.port);
    Ok(())
}

/// 逐项体检：配置合法性 / 目录权限 / 主密钥 / 库结构 / 能力位，任一 FAIL 退出码 1。
pub(crate) fn doctor(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    // 与 serve 同一套启动前校验（TLS 假控制 / 0 秒会话时长）：否则
    // `panel doctor` 报全绿、serve 却起不来，而模板恰恰叫用户"改完跑 doctor"。
    cfg.validate_implemented()?;
    let layout = build_layout(&os, Some(&cfg));
    let tier = detect_tier(&*os, &cfg);
    let checks = doctor::run(&*os, &layout, &layout.sqlite_path(), tier, &cfg.db.synchronous);
    print!("{}", doctor::render(&checks));
    if doctor::has_fail(&checks) { std::process::exit(1); }
    Ok(())
}
