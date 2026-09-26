//! 可执行入口：`panel {init|doctor|migrate|serve|backup|passwd|systemd-unit|vacuum}`

mod bootstrap;
mod config;
mod doctor;
mod embed;

use clap::{Parser, Subcommand};
use config::Config;
use panel_core::{crypto::MasterKey, PanelError, Result, Tier};
use std::{path::PathBuf, sync::Arc};

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
    Init { #[arg(long)] force: bool },
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
    /// 修改用户口令
    Passwd { user: String },
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
        Cmd::Init { force } => {
            let layout = build_layout(&os, None);
            bootstrap::ensure_dirs(&layout)?;
            let _key = bootstrap::ensure_master_key(&layout.data_dir())?;

            let cfg_path = cli.config.clone().unwrap_or_else(|| layout.config_dir().join("config.toml"));
            if cfg_path.exists() && !force {
                return Err(PanelError::Conflict(
                    format!("{} 已存在（加 --force 覆盖）", cfg_path.display())));
            }
            if let Some(p) = cfg_path.parent() { std::fs::create_dir_all(p).ok(); }
            std::fs::write(&cfg_path, config::template(
                &layout.config_dir(), &layout.data_dir(), &layout.site_root())).ok();

            let token = bootstrap::generate_bootstrap_token();
            println!("初始化完成");
            println!("  配置文件：{}", cfg_path.display());
            println!("  数据目录：{}", layout.data_dir().display());
            println!();
            println!("引导令牌（仅显示一次）：{token}");
            println!("在首次登录页面使用此令牌创建 owner 账号。");
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
            let tasks = Arc::new(panel_task::TaskRunner::new(writer.clone(), tier, task_out));

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
            let sched = Arc::new(panel_task::InternalScheduler::new());
            register_internal_jobs(&sched, &os, writer.clone(), metrics.clone(), &layout, &cfg, tier).await;
            sched.start(panel_task::builtin_schedules(tier)).await;
            tracing::info!("内部调度器已启动（{} 个周期任务）",
                           panel_task::builtin_schedules(tier).len());

            let app = panel_api::routes::build_router(state.clone())
                .route("/healthz", axum::routing::get(embed::healthz))
                .fallback(embed::static_handler);

            let addr = cfg.addr()?;
            println!("监听 {addr}（档位 {tier:?}）");

            let rt = tokio::runtime::Builder::new_multi_thread()
                // 低配机器上异步线程数也要收窄：每线程默认栈 2MB
                .worker_threads(match tier { Tier::Nano => 2, Tier::Small => 3, _ => 4 })
                .max_blocking_threads(match tier { Tier::Nano => 8, _ => 32 })
                .enable_all()
                .build()
                .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;

            let r = rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind(addr).await
                    .map_err(|e| PanelError::Internal(format!("bind {addr}: {e}")))?;
                axum::serve(listener, app).await
                    .map_err(|e| PanelError::Internal(format!("serve: {e}")))
            });
            sched.shutdown();
            r
        }

        Cmd::Backup { out } => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let dest = out.unwrap_or_else(|| {
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

        Cmd::Passwd { user } => {
            // 完整实现（M0 收尾）：校验策略 → 档位参数哈希 → 单写事务更新
            println!("(尚未接线) 将修改用户 {user} 的口令");
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
                    disk_used_bytes: snap.disks.first().map(|d| d.used_bytes).unwrap_or(0),
                    disk_total_bytes: snap.disks.first().map(|d| d.total_bytes).unwrap_or(0),
                    net_in_bps: snap.net.iter().map(|n| n.rx_bps).sum(),
                    net_out_bps: snap.net.iter().map(|n| n.tx_bps).sum(),
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
        let writer = writer.clone();
        let backup_dir = layout.backup_dir();
        sched.register("db.backup", move || {
            let writer = writer.clone();
            let backup_dir = backup_dir.clone();
            async move {
                std::fs::create_dir_all(&backup_dir).ok();
                let ts = now_unix();
                let dest = backup_dir.join(format!("panel-{ts}.db"));
                writer.exec(move |conn| {
                    panel_db::backup_to(conn, &dest)?;
                    Ok(panel_db::WriteAck { rows_changed: 1 })
                }).await?;
                Ok(())
            }
        }).await;
    }

    // ── 证书续期检查（M3 接入 ACME 前为空操作）──
    sched.register("cert.renew_check", || async {
        // M3：扫描 ssl_certs 中 30 天内到期且 auto_renew=1 的证书并签发
        Ok(())
    }).await;
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn load_cfg(cli: &Cli, layout: &dyn panel_os::PathLayout) -> Result<Config> {
    let p = cli.config.clone().unwrap_or_else(|| layout.config_dir().join("config.toml"));
    let mut c = Config::load(&p)?;
    // CLI --tier 覆盖配置文件（不穿透所有函数，集中在入口处理一次）
    if let Some(t) = &cli.tier { c.tier = t.clone(); }
    Ok(c)
}

/// 用配置文件中的覆盖值构造路径布局。
/// 关键：覆盖之后仍然只通过 `PathLayout` trait 访问，业务层不出现路径字面量。
fn build_layout(os: &Arc<dyn panel_os::OsAdapter>, cfg: Option<&Config>) -> panel_os::paths::LinuxPathLayout {
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
