//! `panel serve`：前台常驻服务（面板本体）。
//!
//! 为什么单独成文件：它原本是 `run()` 里 `match cmd` 的一条 arm，占掉那个函数
//! 818 行中的 187 行。`run()` 是 17 条子命令的分派表，arm 里塞进完整启动流程后，
//! 分派表本身再也看不清——想知道"有哪 17 个命令"要翻过一整段启动代码。
//!
//! ⚠️ 本文件与 `main.rs` 之间有一层**不易察觉的耦合**：`main.rs` 的
//! `wiring_guard_tests` 里有几条守卫靠 `include_str!` 扫"serve 的启动链"，
//! 分别钉住 `validate_implemented()`、`warn_if_exposed(&addr)`、以及
//! `request_log` 必须是 `.fallback()` 之后的最外层且全链唯一。
//! 那些守卫读的是**本文件**（`include_str!("cmd/serve.rs")`），不是在 `main.rs` 里
//! 全文 grep——因为"全仓都能搜到"证明不了它挂在 serve 链上。
//! 所以：把这里的装配代码往别处搬时，必须同步改那几条守卫的 `include_str!` 目标，
//! 否则它们会指向一个不再含有被检查代码的文件，从而**恒绿**。
//!
//! 另一条不动的东西：`.fallback()` 之后再加 `.layer()` 的次序不是风格问题。
//! axum 的 `.fallback()` 会整体替换既有 fallback 路由，且新 fallback 不被此前任何
//! `.layer()` 包裹；日志层若加在它之前（或退回 `build_router` 内），未匹配请求
//! （404 / SPA miss）会整条绕过日志层——冒烟实测过：每个 404 都无日志行、其余全有。
use std::sync::Arc;

use panel_core::{now_unix, PanelError, Result, Tier};
use panel_os::PathLayout;

use crate::config::Config;
use crate::{
    build_layout, detect_tier, embed, load_cfg, load_master_key, warn_if_exposed,
    write_bootstrap_token_file, Cli,
};

/// 启动并阻塞在 HTTP 服务上，直到进程被信号终止或 serve 出错。
///
/// 参数 `os` 按值传入：本函数随后用 `adapter_with_overrides` 以配置里的
/// `[paths]` 覆盖重建适配器（否则 `site_root()` 等覆盖不生效），原先那个只用于
/// 在读到配置前定位配置文件。
pub(crate) fn run(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    // 配置项假控制闸门：`[server] tls` 无实现，配了必须拒绝启动而不是静默明文。
    // 放在任何副作用（建库 / 起调度器 / bind）之前——失败时机器状态零改动。
    cfg.validate_implemented()?;
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
    let mut conn = panel_db::open(&db_path, tier, &cfg.db.synchronous)?;
    panel_db::migrate::apply(&mut conn)?;
    drop(conn);

    let writer = Arc::new(panel_db::WriterActor::spawn(db_path.clone(), tier, &cfg.db.synchronous)?);
    let pool = Arc::new(panel_db::ReadPool::new(&db_path, tier)?);

    // 任务中心：输出落文件而非入库（实测：stdout 塞进 DB 会让体积失控）
    let task_out = layout.log_dir().join("tasks");
    std::fs::create_dir_all(&task_out).ok();
    let tasks = Arc::new(panel_task::TaskRunner::new(writer.clone(), tier, task_out, db_path.clone(), cfg.db.synchronous.clone()));

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

        // 只读模式：config 基线 **或** 环境变量（`read_only_from` 把两条路径合成
        // 一个 bool，之后 guard / 设置页 / 终端入口都只认 AppState.read_only）。
        let read_only = panel_api::read_only_from(cfg.security.read_only);
        // 会话超时：config.toml 的 `[security]` session_idle / session_absolute。
        // 解析失败（配了 "30分钟" 这种）**不让服务起不来**——回落到默认值并
        // 打一条醒目的警告，而不是静默用默认值（静默 = 用户以为配生效了）。
        let dur_or = |v: &str, dflt: u64| match crate::config::parse_duration(v) {
            Ok(d) => d.as_secs(),
            Err(e) => {
                eprintln!("[panel] ⚠ [security] {v:?} 解析失败（{e}），回落到 {dflt}s");
                dflt
            }
        };
        let session_idle = std::time::Duration::from_secs(
            dur_or(&cfg.security.session_idle, 30 * 60));
        let session_absolute = std::time::Duration::from_secs(
            dur_or(&cfg.security.session_absolute, 12 * 3600));
        // 登录最大尝试次数：config.toml 的 `[security] max_login_attempts`。
        // 曾硬编码 5 于 LoginGuard::new()——配置项形同虚设（与 session_* 同类）。
        let max_login_attempts = cfg.security.max_login_attempts;
        // 审计保留：config.toml `[audit]`（部署级，强制清理见下方周期任务）。
        // 这里读一次注入 AppState，设置页 deployment 段据此只读展示真实生效值，
        // 避免页面只显示 reserved 段的死占位而让用户误以为保留策略「未实现」。
        let audit_retention_days = cfg.audit.retention_days;
        let audit_max_rows = cfg.audit.max_rows;
        // 暴露面 / 备份：`[server] localhost_only`（`Config::addr()` 强制覆盖
        // bind）与 `[db] daily_backup`（调度器据此注册每日备份）均已真实生效，
        // 注入 AppState 供设置页 deployment 段只读展示。
        let localhost_only = cfg.server.localhost_only;
        let daily_backup = cfg.db.daily_backup;
        let db_synchronous = cfg.db.synchronous.clone();
        // 保留份数：`[db] backup_keep`。与 daily_backup 同一条链——调度器
        // 注册 `db.backup` 时就取它做裁剪阈值（见下方 register_internal_jobs），
        // 这里同时注入 AppState 供备份页显示"实际保留几份"。
        let backup_keep = cfg.db.backup_keep;
        let state = Arc::new(panel_api::AppState::new(
            os.clone(), writer.clone(), pool, tasks.clone(), metrics.clone(), tier,
            master_key, read_only, max_login_attempts, session_idle, session_absolute,
            audit_retention_days, audit_max_rows, localhost_only, daily_backup,
            db_synchronous, backup_keep, cfg.danger.allow_web_upgrade));

        // ── 内部周期任务 ──
        register_internal_jobs(&sched_in, &os, writer.clone(), metrics.clone(), &layout, &cfg, tier, state.clone()).await;
        let schedules = panel_task::builtin_schedules(tier);
        let n_sched = schedules.len();
        sched_in.start(schedules).await;
        tracing::info!("内部调度器已启动（{} 个周期任务）", n_sched);

        let app = panel_api::routes::build_router(state.clone())
            .route("/healthz", axum::routing::get(embed::healthz))
            .fallback(embed::static_handler)
            // 请求级结构化日志：**最后加 = 最外层**。必须加在 `.fallback()`
            // 之后——axum 的 `.fallback()` 会整体替换既有 fallback 路由，且
            // 新 fallback 不被此前任何 `.layer()` 包裹；本层若加在它之前
            // （或退回 build_router 内），未匹配请求（404 / SPA miss）会整条
            // 绕过日志层（冒烟实测：每个 404 都无行、其余全有行）。/healthz
            // 也由此一并覆盖；panic 被内层 CatchPanic 转成 500 后回流经过
            // 本层，`status=500` 同样有行。全链只此一个挂点，双挂会每请求
            // 两行——次序与唯一性由 `main.rs` 的 `wiring_guard_tests` 钉住，
            // 那几条守卫读的就是本文件。
            .layer(axum::middleware::from_fn_with_state(
                state.sessions.clone(),
                panel_api::middleware::request_log,
            ));

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
            // 落盘：让看不到终端的本地用户也能初始化（首启页「从文件读取令牌」按钮）。
            // 文件 0600、属 root；bootstrap 成功后删除。落盘失败不阻断 serve（终端打印仍可用）。
            let tok_path = layout.data_dir().join("bootstrap.token");
            if let Err(e) = write_bootstrap_token_file(&tok_path, &tok) {
                eprintln!("[panel] ⚠ 引导令牌落盘失败（终端打印仍可用）：{e}");
            }
            eprintln!();
            eprintln!("════════════════════════════════════════════════════════");
            eprintln!(" 首次启动：尚无 owner 账号");
            eprintln!(" 打开面板完成初始设置，引导令牌（一次性，30 分钟内有效）：");
            eprintln!();
            eprintln!("     {tok}");
            eprintln!();
            eprintln!(" 面板地址：http://{addr}");
            eprintln!(" 远程访问：ssh -L {}:127.0.0.1:{} <user>@<server>", addr.port(), addr.port());
            eprintln!(" 令牌过期/丢失：重启 panel serve 重新生成");
            eprintln!("════════════════════════════════════════════════════════");
        } else {
            // 防御：owner 已存在却残留令牌文件（上一轮 bootstrap 后崩溃未删干净）。
            let _ = std::fs::remove_file(layout.data_dir().join("bootstrap.token"));
        }

        // 非回环监听必须当场说清楚：面板 root 运行 + 明文 HTTP，
        // 暴露面是安全边界而不是配置细节（见 warn_if_exposed 的注释）。
        warn_if_exposed(&addr);
        if localhost_only {
            // 一行足够：安装提示与文档已把三条访问方式说过一遍，这里每次重启
            // 再抄一遍只会把真正要看的东西（令牌 / 启动错误）挤出 journal。
            // 安全默认仍然明确说出来，不靠用户自己猜。
            eprintln!(
                "[panel] 仅本机访问（安全默认）：远程用 ssh -L {}:127.0.0.1:{}，长期对外用 sudo panel expose",
                addr.port(), addr.port()
            );
        }
        println!("监听 {addr}（档位 {tier:?}）");

        let listener = tokio::net::TcpListener::bind(addr).await
            .map_err(|e| PanelError::Internal(format!("bind {addr}: {e}")))?;
        // 接线 ConnectInfo：引导令牌端点据此判定请求是否来自回环地址，
        // 拒绝非 localhost 取令牌（远程攻击者即使能访问端口也拿不到）。
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await
            .map_err(|e| PanelError::Internal(format!("serve: {e}")))
    });
    sched.shutdown();
    r
}

/// 注册内部周期任务的实现。
///
/// **为什么住在 serve.rs**：全站只有 `run()` 一处调用它，它注册的每个任务都是
/// 服务启动后才有意义的后台循环。放在 `main.rs` 时，17 条子命令的分派表下面直接
/// 挂着 270 行装配代码，想知道"面板有哪几个命令"要翻过整段任务注册。
///
/// ⚠️ 本函数被 `main.rs::wiring_guard_tests` 的两条守卫盯着——`backup_sweep` 与
/// `session_sweep` 必须在 `builtin_schedules` 声明之后**真的被注册**。漏注册时
/// 调度器每轮 `jobs.get(name)` 取到 None 就静默跳过：定时备份永远不跑、会话 map
/// 单调增长，而且没有任何报错。那些守卫的 `include_str!` 指向本文件，搬动本函数
/// 必须同步改目标，别改成"全仓 grep 到就算过"。
#[allow(clippy::too_many_arguments)]
async fn register_internal_jobs(
    sched: &panel_task::InternalScheduler,
    os: &Arc<dyn panel_os::OsAdapter>,
    writer: Arc<panel_db::WriterActor>,
    metrics: Arc<std::sync::Mutex<panel_db::aggregator::Aggregator>>,
    layout: &Arc<dyn panel_os::PathLayout>,
    cfg: &Config,
    tier: Tier,
    // 供证书自动续期使用（需要任务队列、读连接池与主密钥）
    state: std::sync::Arc<panel_api::AppState>,
) {
    // ── 指标采样：只写内存环形缓冲，不落库 ──
    {
        let os = os.clone();
        let metrics = metrics.clone();
        // 闭包是 move 且会被周期反复调用，故在这里 clone 一份，进 async 块前再 clone，
        // 否则外层 state 会被移走（E0382）/ 闭包第二次调用时无值可用。
        let state_for_sample = state.clone();
        sched.register("metrics.sample", move || {
            let os = os.clone();
            let metrics = metrics.clone();
            let state_for_sample = state_for_sample.clone();
            async move {
                let snap = os.metrics().snapshot().await?;
                // 采集循环是**唯一**的采样者：把结果缓存起来供 HTTP 接口读。
                // 否则每个调 snapshot() 的请求都会重置 panel-os 的共享采样基准，
                // 既拿到抖动值、又截短下一次采样窗口（见 AppState::cached_snapshot）。
                let snap = Arc::new(snap);
                state_for_sample.record_snapshot(snap.clone()).await;
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

    // ── 分片上传残包清理（P2-1）：1h 一次，让闲置面板也能回收 ──
    {
        let state = state.clone();
        sched.register("uploads.sweep", move || {
            let state = state.clone();
            async move {
                panel_api::routes::multipart::sweep_expired(&state).await;
                Ok(())
            }
        }).await;
    }

    // ── 会话过期回收（P1-9）：sessions 内存 map 与 sessions 表此前单调增长——
    // `SessionCache::sweep()` 已实现却从未被调用。挂上唯一消费者：每 5 分钟清理
    // 一次过期会话（按 expires_at 判，与登录/访问续期口径一致）。
    {
        let state = state.clone();
        sched.register("session.sweep", move || {
            let state = state.clone();
            async move {
                // sweep 同步、内部自行向 DB 派发清理；返回清理条数仅用于日志
                let n = state.sessions.sweep();
                if n > 0 {
                    tracing::info!("会话过期回收：清理 {n} 个过期会话");
                }
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

    // ── 清理：指标 + 审计 + 任务记录 + 通知 ──
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
                    // 通知此前是唯一没有 prune 的业务表（只增不减：WAF 告警 /
                    // 任务完成 / 备份结果都会写一行）。保留期与审计同口径。
                    panel_db::cleanup::prune_notifications(conn, retention, max_rows)?;
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
        // 保留份数必须在**注册时**取出：闭包里再读 cfg 会活不过 'static。
        // 这个值是真消费者——写完后立刻按它裁剪，否则 `panel-*.db` 只增不减，
        // 一年堆 365 份把磁盘慢慢吃满（且此前页面完全看不到这些文件）。
        let keep = cfg.db.backup_keep;
        sched.register("db.backup", move || {
            let backup_dir = backup_dir.clone();
            let db_path = db_path.clone();
            async move {
                std::fs::create_dir_all(&backup_dir).ok();
                let ts = now_unix();
                let dest = backup_dir.join(format!("panel-{ts}.db"));
                // 独立连接备份：写者把 op 包在事务里，事务内不能 VACUUM INTO。
                // VACUUM INTO 是同步阻塞调用（实测占死 2~3 个 worker 线程数秒），
                // 用 spawn_blocking 丢到阻塞线程池，避免卡住 tokio 的异步 worker
                // 导致同进程内其它周期任务一起停摆（P1-11）。
                let db_path_bk = db_path.clone();
                let dest_bk = dest.clone();
                let bak = tokio::task::spawn_blocking(move || panel_db::backup_file(&db_path_bk, &dest_bk))
                    .await
                    .map_err(|e| panel_core::PanelError::Internal(format!("每日备份线程崩溃（join 失败）: {e}")))?;
                bak.map_err(|e| panel_core::PanelError::Internal(format!("每日备份失败: {e}")))?;
                let pruned = panel_api::routes::backups::prune_daily_db(&backup_dir, keep);
                if !pruned.is_empty() {
                    tracing::info!("每日备份已裁剪 {} 份旧文件（保留 {keep}）", pruned.len());
                }
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

    // ── 备份计划的 cron 扫描（每分钟）──
    //
    // `backup_jobs.cron_expr` / `enabled` 此前**只存不读**：页面上配了"每天 3 点"，
    // 实际永远只有手动执行（典型「配置项假控制」）。这里挂上唯一消费者——
    // 定时表在 `panel-task::builtin_schedules`，注册在这里，两处名字必须一致。
    {
        let state = state.clone();
        sched.register("backup.sweep", move || {
            let state = state.clone();
            async move {
                match panel_api::routes::backups::sweep_due(&state).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!("定时备份：本轮提交 {n} 个计划"),
                    Err(e) => tracing::warn!("定时备份扫描失败: {e}"),
                }
                Ok(())
            }
        }).await;
    }

    // ── 拦截事件采集（027）：读开日志站点的 access log 增量，落 403/405/429 事件 ──
    {
        let state = state.clone();
        sched.register("waf.collect", move || {
            let state = state.clone();
            async move {
                match panel_api::routes::waf_events::collect_block_events(&state).await {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        tracing::warn!("拦截事件采集失败: {e}");
                        Err(e)
                    }
                }
            }
        }).await;
    }
}

