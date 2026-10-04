//! 可执行入口：`panel {init|doctor|migrate|serve|backup|passwd|systemd-unit|vacuum}`

mod bootstrap;
mod config;
mod doctor;
mod embed;

use clap::{Parser, Subcommand};
use config::Config;
use panel_core::{crypto::MasterKey, PanelError, Result, Tier};
// PathLayout 是 trait：只有引入作用域后，LinuxPathLayout 才能调用 data_dir()/log_dir()/
// sqlite_path()/backup_dir() 等方法（否则会被误认为访问私有字段而报 E0599）。
use panel_os::PathLayout;
use std::{
    io::{IsTerminal, Write},
    path::PathBuf,
    sync::Arc,
};

/// 加载主密钥：优先读已有 `master.key`（0600）；不存在则生成。
/// 任意一步失败都返回 `None`（密钥加密存储降级关闭，绝不明文存秘密）。
fn load_master_key(data_dir: &std::path::Path) -> Option<MasterKey> {
    let p = bootstrap::master_key_path(data_dir);
    let bytes = if p.exists() {
        match std::fs::read(&p) {
            Ok(b) => b,
            Err(e) => { tracing::warn!("读取主密钥失败: {e}"); return None; }
        }
    } else {
        match bootstrap::ensure_master_key(data_dir) {
            Ok(b) => b,
            Err(e) => { tracing::warn!("生成主密钥失败: {e}"); return None; }
        }
    };
    match MasterKey::from_bytes(&bytes) {
        Ok(k) => Some(k),
        Err(e) => { tracing::warn!("主密钥长度非法: {e}"); None }
    }
}

#[derive(Parser)]
#[command(name = "panel", version, about = "轻量 Linux 服务器管理面板")]
struct Cli {
    /// 配置文件路径；省略时使用平台默认（由 PathLayout 决定）
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// 覆盖档位：nano | small | standard | auto
    #[arg(long, global = true)]
    tier: Option<String>,

    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 首次初始化：目录、主密钥、owner、配置模板
    Init {
        #[arg(long)] force: bool,
        /// 非交互创建 owner 的用户名（缺省交互提示，默认 admin）
        #[arg(long)] owner: Option<String>,
        /// 非交互创建 owner 的口令（缺省交互关回显读取）
        #[arg(long)] owner_pass: Option<String>,
    },
    /// 启动自检（部署前必跑）
    Doctor,
    /// 执行数据库迁移（幂等）
    Migrate,
    /// 启动服务
    Serve,
    /// 在线备份数据库
    Backup { #[arg(long)] out: Option<PathBuf> },
    /// 重建数据库（回收空间）
    Vacuum,
    /// 修改用户口令（仅改已存在用户；建号只能走 init / 首启引导令牌）
    Passwd {
        user: String,
        /// 非交互指定新口令（缺省交互关回显读取）
        #[arg(long)] pass: Option<String>,
    },
    /// 输出 systemd 单元文件
    SystemdUnit { #[arg(long)] install: bool },
    /// 打印能力矩阵（供脚本判断环境）
    Capabilities,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("panel: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    init_tracing();
    let os: Arc<dyn panel_os::OsAdapter> = panel_os::default_adapter();

    match cli.cmd {
        Cmd::Init { force, ref owner, ref owner_pass } => {
            let layout0 = build_layout(&os, None);
            let cfg_path = cli.config.clone().unwrap_or_else(|| layout0.config_dir().join("config.toml"));

            // 配置不存在 → 全新初始化（写模板）；存在 → 复用既有配置（不覆盖，避免改掉 [paths] 等设置）
            let cfg = if !cfg_path.exists() {
                bootstrap::ensure_dirs(&layout0)?;
                let _key = bootstrap::ensure_master_key(&layout0.data_dir())?;
                if let Some(p) = cfg_path.parent() { std::fs::create_dir_all(p).ok(); }
                std::fs::write(&cfg_path, config::template(
                    &layout0.config_dir(), &layout0.data_dir(), &layout0.site_root())).ok();
                load_cfg(&cli, &layout0)?
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
                load_cfg(&cli, &layout0)?
            };

            // 目录与主密钥以最终 layout（含配置中的 [paths] 覆盖）为准
            let layout = build_layout(&os, Some(&cfg));
            bootstrap::ensure_dirs(&layout)?;
            let _key = bootstrap::ensure_master_key(&layout.data_dir())?;

            let tier = detect_tier(&*os, &cfg);
            let db_path = layout.sqlite_path();
            let mut conn = panel_db::open(&db_path, tier)?;
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
            println!("可用 owner 账号登录面板（前端 http://127.0.0.1:5173，后端 127.0.0.1:2083）。");
            Ok(())
        }

        Cmd::Doctor => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let tier = detect_tier(&*os, &cfg);
            let checks = doctor::run(&*os, &layout, &layout.sqlite_path(), tier);
            print!("{}", doctor::render(&checks));
            if doctor::has_fail(&checks) { std::process::exit(1); }
            Ok(())
        }

        Cmd::Migrate => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let mut conn = panel_db::open(&layout.sqlite_path(), detect_tier(&*os, &cfg))?;
            let v = panel_db::migrate::apply(&mut conn)?;
            println!("schema 版本 {v}");
            Ok(())
        }

        Cmd::Serve => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            // 关键修复：把配置感知的路径布局注入适配器。否则运行期
            // `site_root()` 等 [paths] 覆盖不生效（adapter 仍用默认 /var/www），
            // 导致建站等依赖 site_root 的能力在非 root 环境下必然失败。
            //
            // 必须走 `panel_os::adapter_with_overrides`（跨平台入口）而非直接
            // 构造 `linux::LinuxOsAdapter`：后者会让本 crate 绑死 Linux
            // （CI 门禁 [4c]），并让 `force-mock` 构建在 `serve` 路径上失效。
            let os = panel_os::adapter_with_overrides(
                cfg.paths.config.clone(),
                cfg.paths.site_root.clone(),
                cfg.paths.data.clone(),
                cfg.paths.log.clone(),
            );
            let tier = detect_tier(&*os, &cfg);

            // 启动前硬校验：WAL 在网络文件系统上不可靠，直接拒绝启动
            let (fs, is_network) = panel_os::fs::check_data_dir(&layout.data_dir())?;
            if is_network {
                return Err(PanelError::Internal(format!(
                    "数据目录位于网络文件系统（{fs}），SQLite WAL 不可靠，拒绝启动")));
            }

            let db_path = layout.sqlite_path();
            let mut conn = panel_db::open(&db_path, tier)?;
            panel_db::migrate::apply(&mut conn)?;
            drop(conn);

            let writer = Arc::new(panel_db::WriterActor::spawn(db_path.clone(), tier)?);
            let pool = Arc::new(panel_db::ReadPool::new(&db_path, tier)?);

            // 任务中心：输出落文件而非入库（实测：stdout 塞进 DB 会让体积失控）
            let task_out = layout.log_dir().join("tasks");
            std::fs::create_dir_all(&task_out).ok();
            let tasks = Arc::new(panel_task::TaskRunner::new(writer.clone(), tier, task_out, db_path.clone()));

            // run() 是同步函数，所有 .await 都必须发生在 runtime 的 block_on 之内，
            // 因此 runtime 要在异步初始化之前就构建好。
            let rt = tokio::runtime::Builder::new_multi_thread()
                // 低配机器上异步线程数也要收窄：每线程默认栈 2MB
                .worker_threads(match tier { Tier::Nano => 2, Tier::Small => 3, _ => 4 })
                .max_blocking_threads(match tier { Tier::Nano => 8, _ => 32 })
                .enable_all()
                .build()
                .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;

            let sched = Arc::new(panel_task::InternalScheduler::new());
            let sched_in = Arc::clone(&sched);

            let r = rt.block_on(async move {
                // 上次进程遗留的 running/queued 一律标记 interrupted，**不自动恢复**
                let orphans = tasks.reap_orphans().await?;
                if orphans > 0 {
                    tracing::warn!("发现 {orphans} 个中断任务，需在界面上人工确认后重试");
                }

                let metrics = Arc::new(std::sync::Mutex::new(panel_db::aggregator::Aggregator::new(tier)));

                // ── 主密钥：SSL 私钥 / 数据库口令的 AES-256-GCM 加密密钥（M0 阻塞项已关闭）──
                // 内存常驻、不落库；缺失则密钥加密存储不可用（对应操作被拒绝，而非明文入库）。
                let master_key = load_master_key(&layout.data_dir());

                let state = Arc::new(panel_api::AppState::new(
                    os.clone(), writer.clone(), pool, tasks.clone(), metrics.clone(), tier, master_key));

                // ── 内部周期任务 ──
                register_internal_jobs(&sched_in, &os, writer.clone(), metrics.clone(), &layout, &cfg, tier, state.clone()).await;
                let schedules = panel_task::builtin_schedules(tier);
                let n_sched = schedules.len();
                sched_in.start(schedules).await;
                tracing::info!("内部调度器已启动（{} 个周期任务）", n_sched);

                let app = panel_api::routes::build_router(state.clone())
                    .route("/healthz", axum::routing::get(embed::healthz))
                    .fallback(embed::static_handler);

                let addr = cfg.addr()?;

                // ── 首启引导：数据库尚无 owner 时生成一次性令牌，打印到终端 ──
                // 查询失败按"有 owner"处理（不打印横幅，避免误导；登录时会自然报错）
                let has_owner = state.pool.with(|conn| {
                    conn.query_row("SELECT COUNT(*) FROM users WHERE role = 'owner'", [], |r| r.get::<_, i64>(0))
                        .map_err(|e| panel_core::PanelError::Database(e.to_string()))
                }).await.unwrap_or(1);
                if has_owner == 0 {
                    let tok = panel_api::auth::generate_bootstrap_token();
                    state.bootstrap.set(&tok, std::time::Duration::from_secs(30 * 60));
                    eprintln!();
                    eprintln!("════════════════════════════════════════════════════════");
                    eprintln!(" 首次启动：尚无 owner 账号");
                    eprintln!(" 打开面板完成初始设置，引导令牌（一次性，30 分钟内有效）：");
                    eprintln!();
                    eprintln!("     {tok}");
                    eprintln!();
                    eprintln!(" 面板地址：http://{addr}");
                    eprintln!(" 远程访问：ssh -L 2083:127.0.0.1:2083 <user>@<server>");
                    eprintln!(" 令牌过期/丢失：重启 panel serve 重新生成");
                    eprintln!("════════════════════════════════════════════════════════");
                }

                println!("监听 {addr}（档位 {tier:?}）");

                let listener = tokio::net::TcpListener::bind(addr).await
                    .map_err(|e| PanelError::Internal(format!("bind {addr}: {e}")))?;
                axum::serve(listener, app).await
                    .map_err(|e| PanelError::Internal(format!("serve: {e}")))
            });
            sched.shutdown();
            r
        }

        // 用 ref 绑定：若写成 `Cmd::Backup { out }` 会按值移出 cli 的字段，
        // 之后再 `load_cfg(&cli, ...)` 就变成"部分移动后借用"（E0382）。
        Cmd::Backup { ref out } => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let dest = out.clone().unwrap_or_else(|| {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                std::fs::create_dir_all(layout.backup_dir()).ok();
                layout.backup_dir().join(format!("panel-{ts}.db"))
            });
            let conn = panel_db::open(&layout.sqlite_path(), detect_tier(&*os, &cfg))?;
            panel_db::backup_to(&conn, &dest)?;
            println!("备份完成：{}", dest.display());
            Ok(())
        }

        Cmd::Vacuum => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let conn = panel_db::open(&layout.sqlite_path(), detect_tier(&*os, &cfg))?;
            panel_db::cleanup::checkpoint_truncate(&conn)?;
            println!("WAL 已回收");
            Ok(())
        }

        Cmd::Passwd { ref user, ref pass } => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let tier = detect_tier(&*os, &cfg);
            let mut conn = panel_db::open(&layout.sqlite_path(), tier)?;

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
                    field: "user".into(),
                    reason: format!("用户 {user} 不存在"),
                });
            }

            // 口令：命令行 > 交互关回显（--pass 会进 shell history / ps，仅脚本场景使用）
            let password = match pass.clone() {
                Some(p) => p,
                None => {
                    if !std::io::stdin().is_terminal() {
                        return Err(PanelError::Validation {
                            field: "pass".into(),
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

        Cmd::SystemdUnit { install } => {
            let tier = detect_tier(&*os, &Config::default());
            let bin = std::env::current_exe()
                .map(|p| p.display().to_string())
                .map_err(|e| PanelError::Internal(format!("无法确定自身路径：{e}")))?;
            let layout_data = os.paths().data_dir();
            let layout_log = os.paths().log_dir();
            let layout_site = os.paths().site_root();
            let cfgp = cli.config.clone().unwrap_or_else(|| os.paths().config_dir().join("config.toml"));
            let writable = vec![layout_data.clone(), layout_log.clone(), layout_site.clone(), os.paths().config_dir()];
            let unit = bootstrap::systemd_unit(&bin, &cfgp.display().to_string(), tier, &writable);
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

        Cmd::Capabilities => {
            let caps = os.capabilities();
            if cli.json {
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
    }
}

/// 注册内部周期任务的实现。
///
/// 刻意集中在一处：`builtin_schedules` 里加了名字，这里就必须有对应实现，
/// 否则调度器会静默跳过（代码里已用 warn 记录这种漏配）。
async fn register_internal_jobs(
    sched: &panel_task::InternalScheduler,
    os: &Arc<dyn panel_os::OsAdapter>,
    writer: Arc<panel_db::WriterActor>,
    metrics: Arc<std::sync::Mutex<panel_db::aggregator::Aggregator>>,
    layout: &panel_os::paths::LinuxPathLayout,
    cfg: &Config,
    tier: Tier,
    // 供证书自动续期使用（需要任务队列、读连接池与主密钥）
    state: std::sync::Arc<panel_api::AppState>,
) {
    // ── 指标采样：只写内存环形缓冲，不落库 ──
    {
        let os = os.clone();
        let metrics = metrics.clone();
        sched.register("metrics.sample", move || {
            let os = os.clone();
            let metrics = metrics.clone();
            async move {
                let snap = os.metrics().snapshot().await?;
                let mut g = metrics.lock().unwrap_or_else(|e| e.into_inner());
                g.record(panel_db::ring::Sample {
                    ts: snap.ts_unix,
                    cpu_pct: snap.cpu.total_pct,
                    mem_used_kib: snap.mem.used_kib,
                    mem_total_kib: snap.mem.total_kib,
                    swap_used_kib: snap.mem.swap_used_kib,
                    // 与 /system/overview 保持同一口径：所有本地盘求和、排除网络文件系统；
                    // 网络速率排除回环接口 lo。否则概览首屏（求和）与实时跳动（首个盘）会口径跳变。
                    disk_used_bytes: snap.disks.iter().filter(|d| !d.is_network_fs).map(|d| d.used_bytes).sum(),
                    disk_total_bytes: snap.disks.iter().filter(|d| !d.is_network_fs).map(|d| d.total_bytes).sum(),
                    // SystemSnapshot 字段是 nets（复数）；NetSample 速率字段是 rx/tx_rate_bps
                    net_in_bps: snap.nets.iter().filter(|n| n.iface != "lo").map(|n| n.rx_rate_bps).sum(),
                    net_out_bps: snap.nets.iter().filter(|n| n.iface != "lo").map(|n| n.tx_rate_bps).sum(),
                    load1: snap.cpu.load1,
                });
                Ok(())
            }
        }).await;
    }

    // ── 1m 聚合：nano 档位是 no-op（不落盘）──
    {
        let writer = writer.clone();
        let metrics = metrics.clone();
        sched.register("metrics.aggregate_1m", move || {
            let writer = writer.clone();
            let metrics = metrics.clone();
            async move {
                let n = match tier { Tier::Nano => 12, _ => 60 };
                let agg = {
                    let g = metrics.lock().unwrap_or_else(|e| e.into_inner());
                    g.ring().aggregate(n)
                };
                let Some(a) = agg else { return Ok(()) };
                writer.exec(move |conn| {
                    conn.execute(
                        "INSERT OR REPLACE INTO metrics_1m
                         (ts, cpu_pct, mem_used_kib, mem_total_kib, swap_used_kib,
                          disk_used_bytes, disk_total_bytes, net_in_bps, net_out_bps, load1)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                        rusqlite::params![
                            a.ts - (a.ts % 60), a.cpu_pct, a.mem_used_kib, a.mem_total_kib,
                            a.swap_used_kib, a.disk_used_bytes, a.disk_total_bytes,
                            a.net_in_bps, a.net_out_bps, a.load1,
                        ],
                    ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
                    Ok(panel_db::WriteAck { rows_changed: 1 })
                }).await?;
                Ok(())
            }
        }).await;
    }

    // ── 1h rollup：聚合后再清理过期指标 ──
    {
        let writer = writer.clone();
        sched.register("metrics.rollup_1h", move || {
            let writer = writer.clone();
            async move {
                writer.exec(|conn| {
                    let mut st = conn.prepare(
                        "INSERT OR REPLACE INTO metrics_1h
                         (ts, cpu_pct, mem_used_kib, mem_total_kib, swap_used_kib,
                          disk_used_bytes, disk_total_bytes, net_in_bps, net_out_bps, load1)
                         SELECT ts - (ts % 3600), AVG(cpu_pct), MAX(mem_used_kib), MAX(mem_total_kib),
                                MAX(swap_used_kib), MAX(disk_used_bytes), MAX(disk_total_bytes),
                                MAX(net_in_bps), MAX(net_out_bps), AVG(load1)
                         FROM metrics_1m WHERE ts < ?1 GROUP BY ts - (ts % 3600)",
                    ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
                    let cutoff = now_unix() - 86_400;
                    let n = st.execute(rusqlite::params![cutoff])
                        .map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
                    Ok(panel_db::WriteAck { rows_changed: n })
                }).await?;
                Ok(())
            }
        }).await;
    }

    // ── 清理：指标 + 审计 + 任务记录 ──
    {
        let writer = writer.clone();
        let retention = cfg.audit.retention_days;
        let max_rows = cfg.audit.max_rows;
        sched.register("db.cleanup", move || {
            let writer = writer.clone();
            async move {
                writer.exec(move |conn| {
                    // 指标：7 天 1m + 90 天 1h（均 ≤5 万行，一次性删除最快）
                    panel_db::cleanup::prune_metrics(conn, panel_db::aggregator::Retention::default())?;
                    // 审计：默认 90 天 + 5 万行上限（实测 180 天 = 4.12MB）
                    panel_db::cleanup::prune_audit(conn, retention, max_rows)?;
                    panel_db::cleanup::prune_task_runs(conn, retention)?;
                    Ok(panel_db::WriteAck { rows_changed: 0 })
                }).await?;
                // 清理后回收 WAL（实测：无界时 5 万行即 7.71MB）
                writer.exec(|conn| {
                    panel_db::cleanup::checkpoint_truncate(conn)?;
                    Ok(panel_db::WriteAck { rows_changed: 0 })
                }).await?;
                Ok(())
            }
        }).await;
    }

    // ── 每日备份（nano 档位未注册该任务）──
    if cfg.db.daily_backup && !matches!(tier, Tier::Nano) {
        let backup_dir = layout.backup_dir();
        let db_path = layout.sqlite_path();
        sched.register("db.backup", move || {
            let backup_dir = backup_dir.clone();
            let db_path = db_path.clone();
            async move {
                std::fs::create_dir_all(&backup_dir).ok();
                let ts = now_unix();
                let dest = backup_dir.join(format!("panel-{ts}.db"));
                // 独立连接备份：写者把 op 包在事务里，事务内不能 VACUUM INTO
                panel_db::backup_file(&db_path, &dest)?;
                Ok(())
            }
        }).await;
    }

    // ── 证书自动续期扫描 ──
    // 扫描 ssl_certs 中「30 天内到期 + auto_renew=1 + source=acme」的证书，
    // 逐个提交 AcmeTask{Renew}。能力位缺失（certbot 不在）时内部自行跳过返回 0。
    {
        let state = state.clone();
        sched.register("cert.renew_check", move || {
            let state = state.clone();
            async move {
                match panel_api::routes::sites::auto_renew_sweep(state).await {
                    Ok(n) => {
                        if n > 0 {
                            tracing::info!("证书自动续期扫描：已入队 {n} 张到期证书");
                        }
                        Ok(())
                    }
                    Err(e) => {
                        tracing::warn!("证书自动续期扫描失败: {e}");
                        Err(e)
                    }
                }
            }
        }).await;
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 交互式（或经 `--owner`/`--owner-pass` 非交互）创建首个 owner 账号。
///
/// 设计取舍：原方案是 `init` 打印一次性引导令牌、登录页用令牌建 owner，
/// 但后端消费令牌的接口与前端令牌 UI 均未实现（M0/M5 未完工），导致首个账号
/// 无从创建、面板无法登录。此处改为 `init` 阶段直接落库 owner，本地可立即登录，
/// 且同样要求有终端/CLI 权限（同机任意本地进程拿不到你的口令），安全等效。
fn create_owner(
    conn: &mut rusqlite::Connection,
    tier: Tier,
    owner: Option<String>,
    owner_pass: Option<String>,
) -> Result<()> {
    let interactive = std::io::stdin().is_terminal();

    // 用户名：命令行 > 交互提示（默认 admin）> 非交互报错
    let username = match owner {
        Some(u) => u.trim().to_string(),
        None => {
            if !interactive {
                return Err(PanelError::Validation {
                    field: "owner".into(),
                    reason: "非交互环境请提供 --owner".into(),
                });
            }
            print!("请输入 owner 用户名（默认 admin）：");
            let _ = std::io::stdout().flush();
            let mut s = String::new();
            std::io::stdin().read_line(&mut s).map_err(|e| PanelError::Internal(format!("读用户名: {e}")))?;
            let s = s.trim().to_string();
            if s.is_empty() { "admin".to_string() } else { s }
        }
    };
    if username.is_empty() || username.len() > 64 {
        return Err(PanelError::Validation {
            field: "username".into(),
            reason: "用户名长度需在 1..=64".into(),
        });
    }

    // 口令：命令行 > 交互关回显
    let password = match owner_pass {
        Some(p) => p,
        None => {
            if !interactive {
                return Err(PanelError::Validation {
                    field: "owner-pass".into(),
                    reason: "非交互环境请提供 --owner-pass".into(),
                });
            }
            bootstrap::read_password("请输入 owner 口令（≥10 位，含两类字符）：")?
        }
    };
    panel_api::auth::check_password_policy(&password)?;

    let hash = panel_api::auth::hash_password(&password, &panel_api::auth::HashParams::for_tier(tier))?;
    let now = now_unix();
    conn.execute(
        "INSERT INTO users(username, pwd_hash, role, allowed_roots, created_at)
         VALUES (?1, ?2, 'owner', '[]', ?3)",
        rusqlite::params![username, hash, now],
    ).map_err(|e| PanelError::Database(e.to_string()))?;

    println!("owner 账号已创建：{username}");
    Ok(())
}

fn load_cfg(cli: &Cli, layout: &dyn panel_os::PathLayout) -> Result<Config> {
    let p = cli.config.clone().unwrap_or_else(|| layout.config_dir().join("config.toml"));
    let mut c = Config::load(&p)?;
    // CLI --tier 覆盖配置文件（不穿透所有函数，集中在入口处理一次）
    if let Some(t) = &cli.tier { c.tier = t.clone(); }
    Ok(c)
}

/// 用配置文件中的覆盖值构造路径布局。
/// 关键：覆盖之后仍然只通过 `PathLayout` 访问，业务层不出现路径字面量。
/// `os` 参数暂未使用（LinuxPathLayout 尚不依赖运行时探测），保留以维持
/// 「布局由平台适配器注入」的签名契约，多平台接入时启用。
fn build_layout(_os: &Arc<dyn panel_os::OsAdapter>, cfg: Option<&Config>) -> panel_os::paths::LinuxPathLayout {
    let base = panel_os::paths::LinuxPathLayout::default();
    match cfg {
        None => base,
        Some(c) => base.with_overrides(
            c.paths.config.clone(),
            c.paths.site_root.clone(),
            c.paths.data.clone(),
            c.paths.log.clone(),
        ),
    }
}

/// 档位探测：宿主规模**必须**来自 OsAdapter，CLI 不得自行读 procfs
fn detect_tier(os: &dyn panel_os::OsAdapter, cfg: &Config) -> Tier {
    let (mem_mb, cpus) = os.host_profile();
    cfg.tier(mem_mb, cpus)
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
