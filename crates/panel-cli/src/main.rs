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
/// 只接受面板库产物：`.db` / `.db.enc`。
///
/// `.tar.gz` 也能通过 `verify_artifact`（它是合法的站点归档），但把它盖到
/// `panel.db` 上只会得到一个打不开的库——所以必须在扩展名这一层先挡掉。
fn is_db_artifact_name(name: &str) -> bool {
    name.trim_end_matches(".enc").ends_with(".db")
}

/// 原子替换数据库：先写同目录临时文件再 `rename`，并清掉属于**旧库**的 -wal/-shm。
///
/// 为什么必须删 WAL/SHM：它们记录的是被替换掉那个库的事务帧。留着会让 SQLite
/// 把旧帧回放到新库上——库能打开但数据错乱，比打不开更难查。
fn atomic_replace_db(plain: &std::path::Path, db: &std::path::Path) -> Result<()> {
    let tmp = db.with_extension("db.restore-tmp");
    std::fs::copy(plain, &tmp)
        .map_err(|e| PanelError::Io(format!("写入临时库失败: {e}")))?;
    std::fs::rename(&tmp, db)
        .map_err(|e| PanelError::Io(format!("替换数据库失败: {e}")))?;
    for suffix in ["-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{suffix}", db.display()));
        if p.exists() {
            let _ = std::fs::remove_file(&p);
        }
    }
    Ok(())
}

/// 把一次性引导令牌明文落盘（权限 0600、进程用户即属主）。
///
/// 目的：让**看不到终端输出**的本地用户也能初始化——首启页「从文件读取令牌」按钮
/// 经 `GET /api/v1/auth/bootstrap-token`（仅 localhost）取到这里的明文。
/// 与内存守卫不同，这是磁盘上的明文，故权限必须 0600；面板以 root 运行、进程用户即
/// 文件属主，同机非 root 进程读不到。文件在 bootstrap 成功后由端点删除。
fn write_bootstrap_token_file(path: &std::path::Path, tok: &str) -> std::io::Result<()> {
    std::fs::write(path, tok)?;
    // 权限收紧走 `panel_os::fs::set_mode`，平台条件编译只允许出现在 OS 抽象层内
    // （CI 门禁 [4]），CLI 层出现即绑死平台。
    // set_mode 内部已按 unix / 非 unix 分流（后者为 no-op），失败不致命——
    // 文件内容已写入，权限收紧失败最多是"比预期宽松"，不应让 serve 起不来。
    if let Err(e) = panel_os::fs::set_mode(path, 0o600) {
        eprintln!("[panel] ⚠ 引导令牌文件权限收紧失败（内容已写入）：{e}");
    }
    Ok(())
}

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

    // ⚠ `--json` **不能**声明为 global：global 意味着每个子命令都收下它，
    // 而真正输出 JSON 的只有 `capabilities`——`panel doctor --json` 会静默打印
    // 人类可读文本（用户以为拿到了机器可读结果）。宁可让 clap 直接报错，
    // 也不要"收下参数却不生效"（配置项假控制那类 bug 的命令行版本）。
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
    /// 校验备份产物**真的能恢复**（解密 + 解压 +  integrity_check）
    VerifyBackup {
        /// 产物路径（.db / .tar.gz 及其 .enc 变体）
        path: std::path::PathBuf,
    },
    /// 离线恢复面板数据库（**必须先停服务**：在线覆盖会损坏 SQLite WAL）
    RestoreDb {
        /// 产物路径（`.db` 或 `.db.enc`；站点 `.tar.gz` 会拒绝）
        ///
        /// 与 `--remote` 二选一：本地盘还在就直接用它；盘没了用 `--remote`。
        path: Option<PathBuf>,
        /// 从远端副本取产物：指定备份计划 id（**本地盘没了**时用）。
        /// 计划必须配置为 `kind=panel` 且配了远端副本。
        #[arg(long, value_name = "PLAN_ID")]
        remote: Option<i64>,
        /// `--remote` 时指定产物名；缺省取该计划**最新**的面板库产物
        #[arg(long, value_name = "NAME")]
        artifact: Option<String>,
        /// 跳过"服务仍在监听"的检查（容器里进程名不同 / 已确认停机时用）
        #[arg(long)]
        force: bool,
    },
    /// 安装/卸载外部探活（覆盖 Restart=on-failure 管不了的"活着但不服务"）
    Healthcheck {
        /// 安装探活脚本与 systemd service/timer
        #[arg(long)] install: bool,
        /// 卸载（删除脚本与两个单元文件）
        #[arg(long)] uninstall: bool,
    },
    /// 打印能力矩阵（供脚本判断环境）
    /// 输出本机能力位清单（唯一实现 `--json` 的子命令）
    Capabilities {
        /// 以 JSON 输出（供脚本消费）
        #[arg(long)]
        json: bool,
    },
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
            let mut conn = panel_db::open(&db_path, tier, &cfg.db.synchronous)?;
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

        Cmd::Doctor => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
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

        Cmd::Migrate => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let mut conn = panel_db::open(&layout.sqlite_path(), detect_tier(&*os, &cfg), &cfg.db.synchronous)?;
            let v = panel_db::migrate::apply(&mut conn)?;
            println!("schema 版本 {v}");
            Ok(())
        }

        Cmd::Serve => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
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
                    db_synchronous, backup_keep));

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
                    // 两行——次序与唯一性由下方 `wiring_guard_tests` 钉住。
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
            // `VACUUM INTO` 拒绝覆盖已存在的文件，报的是 "output file already
            // exists"——用户看不出是该删还是该改名。显式说清楚。
            if dest.exists() {
                return Err(PanelError::Validation {
                    field: "out",
                    reason: format!("目标已存在：{}（VACUUM INTO 不覆盖，请先删除或换个路径）", dest.display()),
                });
            }
            let conn = panel_db::open(&layout.sqlite_path(), detect_tier(&*os, &cfg), &cfg.db.synchronous)?;
            panel_db::backup_to(&conn, &dest)?;
            println!("备份完成：{}", dest.display());
            Ok(())
        }

        Cmd::Vacuum => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let conn = panel_db::open(&layout.sqlite_path(), detect_tier(&*os, &cfg), &cfg.db.synchronous)?;
            panel_db::cleanup::checkpoint_truncate(&conn)?;
            println!("WAL 已回收");
            Ok(())
        }

        Cmd::Passwd { ref user, ref pass } => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
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

        Cmd::SystemdUnit { install } => {
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

        Cmd::VerifyBackup { ref path } => {
            // 产物校验是 panel-api 的能力（要同时用 panel-db 的 integrity_check 与
            // panel-os 的解压/解密），CLI 侧只做参数与主密钥装配。
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));
            let key = load_master_key(&layout.data_dir());
            if panel_os::backup::is_encrypted_file(path) && key.is_none() {
                return Err(PanelError::Internal(
                    "产物已加密但读不到主密钥（data_dir/master.key）——没有它无法校验".into(),
                ));
            }
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;
            let note = rt.block_on(panel_api::routes::backups::verify_artifact_cli(
                path, key.as_ref(), &layout.tmp_dir(),
            ))?;
            println!("✅ 产物可恢复：{note}");
            Ok(())
        }

        // 面板自身的库是**运行中的库**：API 侧一直拒绝在线恢复（会损坏 WAL）。
        // 但"拒绝"只解决了一半问题——出事时用户仍要手抄一份 mv 命令，而且
        // 没人先验一遍产物是不是好的。这个子命令把那段手工流程收敛成一条：
        // 先验产物 → 留当前态快照 → 原子替换 → 清掉旧 -wal/-shm。
        Cmd::RestoreDb { ref path, remote, ref artifact, force } => {
            let layout0 = build_layout(&os, None);
            let cfg = load_cfg(&cli, &layout0)?;
            let layout = build_layout(&os, Some(&cfg));

            // ① 服务在跑就不能动库：在线覆盖会让 WAL 与主库不一致
            if !force {
                let host = match cfg.server.bind.as_str() {
                    "0.0.0.0" | "::" => "127.0.0.1",
                    other => other,
                };
                let addr = format!("{host}:{}", cfg.server.port);
                if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
                    if std::net::TcpStream::connect_timeout(
                        &sa, std::time::Duration::from_millis(300),
                    ).is_ok() {
                        return Err(PanelError::Validation {
                            field: "service",
                            reason: format!(
                                "服务仍在运行（{addr} 可连接）。请先停止 panel 再恢复；\n                                 确认已停机（例如容器内进程名不同）可加 --force"
                            ),
                        });
                    }
                }
            }

            // ② 二选一：本地产物路径，或从远端副本拉回来。
            //    `--remote` 拉下来的文件落在临时目录，**用完必须删**（它不是备份，
            //    留在那里只会让人误以为本地还有一份副本）。
            let mut downloaded: Option<PathBuf> = None;
            let path: PathBuf = match (path.clone(), remote) {
                (Some(p), None) => p,
                (None, Some(plan_id)) => {
                    let db_path = layout.sqlite_path();
                    let key = load_master_key(&layout.data_dir());
                    let rt = tokio::runtime::Runtime::new()
                        .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;
                    let p = rt.block_on(panel_api::routes::backups::fetch_remote_artifact_cli(
                        &db_path, plan_id, artifact.as_deref(), &layout.tmp_dir(), key.as_ref(),
                    ))?;
                    println!("已从远端取回产物：{}", p.display());
                    downloaded = Some(p.clone());
                    p
                }
                (Some(_), Some(_)) => return Err(PanelError::Validation {
                    field: "path",
                    reason: "产物路径与 --remote 只能给一个".into(),
                }),
                (None, None) => return Err(PanelError::Validation {
                    field: "path",
                    reason: "请给产物路径，或用 --remote <计划 id> 从远端副本取回".into(),
                }),
            };

            // ③ 只接受面板库产物。verify 对 .tar.gz 也会通过——但把站点归档
            //    盖到 panel.db 上会得到一个打不开的库，必须先按扩展名挡掉。
            let fname = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if !is_db_artifact_name(&fname) {
                return Err(PanelError::Validation {
                    field: "path",
                    reason: format!("只接受面板库产物（.db / .db.enc），收到：{fname}"),
                });
            }
            if !path.is_file() {
                return Err(PanelError::NotFound(format!("产物 {}", path.display())));
            }

            // ④ 产物先验：坏产物绝不能覆盖正在用的库
            let key = load_master_key(&layout.data_dir());
            if panel_os::backup::is_encrypted_file(path.as_path()) && key.is_none() {
                return Err(PanelError::Internal(
                    "产物已加密但读不到主密钥（data_dir/master.key）——没有它无法恢复".into(),
                ));
            }
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;
            let note = rt.block_on(panel_api::routes::backups::verify_artifact_cli(
                path.as_path(), key.as_ref(), &layout.tmp_dir(),
            ))?;
            println!("✅ 产物可恢复：{note}");

            // ⑤ 加密产物先解密到临时文件（不原地解密）
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let plain: PathBuf = if panel_os::backup::is_encrypted_file(path.as_path()) {
                std::fs::create_dir_all(layout.tmp_dir()).ok();
                let p = layout.tmp_dir().join(format!("restore-db-{ts}.db"));
                rt.block_on(panel_os::backup::decrypt_file(path.as_path(), &p, key.as_ref().unwrap()))?;
                p
            } else {
                path.clone()
            };

            // ⑥ 当前库先留快照：这是回滚的唯一依据
            let db = layout.sqlite_path();
            if db.exists() {
                std::fs::create_dir_all(layout.backup_dir()).ok();
                let snap = layout.backup_dir().join(format!("pre-restore-{ts}.db"));
                panel_db::backup_file(&db, &snap)?;
                println!("当前库已留快照：{}", snap.display());
            }

            // ⑦ 原子替换 + 清掉旧库的 -wal/-shm（见 `atomic_replace_db` 的说明）
            atomic_replace_db(&plain, &db)?;
            if plain.as_path() != path.as_path() {
                let _ = std::fs::remove_file(&plain);
            }
            // 从远端拉下来的临时副本用完即删：留着会让人误以为本地另有一份备份
            if let Some(d) = downloaded {
                let _ = std::fs::remove_file(&d);
            }
            println!("✅ 已恢复：{}", db.display());
            println!("现在可以启动服务（如 systemctl start panel）。");
            Ok(())
        }

        Cmd::Healthcheck { install, uninstall } => {
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

        Cmd::Capabilities { json } => {
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
    }
}

/// 注册内部周期任务的实现。
///
/// 刻意集中在一处：`builtin_schedules` 里加了名字，这里就必须有对应实现，
/// 否则调度器会静默跳过（代码里已用 warn 记录这种漏配）。
// 参数多是有意的：内部任务的注册入口要把调度器/存储/路径/配置/状态一次性交齐，
// 拆成 builder 只会让调用点更难核对（漏一个依赖＝该任务静默不注册）。
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
                    field: "owner",
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
            field: "username",
            reason: "用户名长度需在 1..=64".into(),
        });
    }

    // 口令：命令行 > 交互关回显
    let password = match owner_pass {
        Some(p) => p,
        None => {
            if !interactive {
                return Err(PanelError::Validation {
                    field: "owner-pass",
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
///
/// 返回 `Arc<dyn PathLayout>` 而**不是** `LinuxPathLayout`：后者会让 CLI 绑死具体
/// 实现（业务层其余部分早已只认 trait）。持有具体类型时，布局的构造点就多了一处，
/// 与适配器内部的布局静默分叉，且编译期毫无提示。
///
/// 构造必须经 `panel_os::layout_with_overrides()`：`adapter_with()` 内部用的是
/// **同一个工厂**，从而保证"适配器持有的布局"与"CLI 建目录/打印的布局"永远同源。
/// 此前两处各建一份 `LinuxPathLayout`、靠参数巧合保持一致，任一处改动都会静默分叉。
///
/// `_os` 参数保留但不用：布局不依赖运行时探测（纯配置 + 平台默认值）。
/// 若将来需要探测（如挂载点），在工厂内部实现，**不要**在这里加分支
/// ——否则平台知识又漏回 CLI 层（CI 门禁 [4] 会拦）。
fn build_layout(_os: &Arc<dyn panel_os::OsAdapter>, cfg: Option<&Config>) -> Arc<dyn panel_os::PathLayout> {
    let ov = match cfg {
        None => panel_os::PathOverrides::none(),
        Some(c) => panel_os::PathOverrides {
            config_dir: c.paths.config.clone(),
            site_root: c.paths.site_root.clone(),
            data_dir: c.paths.data.clone(),
            log_dir: c.paths.log.clone(),
        },
    };
    panel_os::layout_with_overrides(&ov)
}

/// 档位探测：宿主规模**必须**来自 OsAdapter，CLI 不得自行读 procfs
fn detect_tier(os: &dyn panel_os::OsAdapter, cfg: &Config) -> Tier {
    let (mem_mb, cpus) = os.host_profile();
    cfg.tier(mem_mb, cpus)
}

/// 该监听地址是否**非回环**（即暴露到本机之外）。
///
/// 抽成纯函数是为了让"该不该警告"可断言——直接写在启动流程里就成了不可测的副作用，
/// 而这类"看起来有防护其实没触发"的检查正是最容易静默失效的地方。
fn is_non_loopback_bind(addr: &std::net::SocketAddr) -> bool {
    !addr.ip().is_loopback()
}

/// 非回环监听的启动横幅。
///
/// 为什么必须说：面板**以 root 运行**，且本构建**不提供 HTTPS 监听**（serve 永远是
/// 明文 `axum::serve`）。把它绑到 0.0.0.0 或局域网地址，等于把 root 权限的操作入口
/// 直接放到网上——凭据会明文过网。此前启动只打印一行"监听 {addr}"，与监听回环时
/// 完全一样，用户无从察觉。
fn warn_if_exposed(addr: &std::net::SocketAddr) {
    if !is_non_loopback_bind(addr) {
        return;
    }
    eprintln!("════════════════════════════════════════════════════════");
    eprintln!("[panel] ⚠ [security] 监听非回环地址 {addr}");
    eprintln!("  面板以 root 运行，且本构建不提供 HTTPS：此处监听是明文 HTTP。");
    eprintln!("  若这台机器能被局域网/公网访问，root 权限的操作入口即已暴露。");
    eprintln!("  · 需要远程访问：优先 ssh -L {}:127.0.0.1:{} 端口转发；", addr.port(), addr.port());
    eprintln!("  · 确需直接监听：务必前置反向代理终结 TLS，并用防火墙限制来源 IP；");
    eprintln!("  · 只想本机访问：把 [server] localhost_only 设为 true（它会强制覆盖 bind）。");
    eprintln!("════════════════════════════════════════════════════════");
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod wiring_guard_tests {
    /// **判据必须指向生产代码那一份**：调度表在 `panel-task`、注册在 `panel-cli`，
    /// 只靠名字约定对齐。漏注册时调度器每轮 `jobs.get(name)` 取到 None 就静默跳过
    /// ——页面上配了定时备份却永远不跑，且没有任何报错。
    ///
    /// 取生产段必须走 `panel_testutil::production_source`：本模块自身的断言字符串
    /// 里就含有 `sched.register("backup.sweep"`（判据自引用）—— 不剔测试段，把注册
    /// 删了照样绿。它**还剔注释行**：实测过把注册整块注释掉、注释里留同名 needle，
    /// 只 `split("#[cfg(test)]")` 的版本依然全绿（定时备份静默不跑，门禁一声不吭）。
    #[test]
    fn backup_sweep_is_registered_in_serve() {
        let src = include_str!("main.rs");
        let prod = panel_testutil::production_source(src);
        assert!(
            prod.contains("sched.register(\"backup.sweep\", move ||"),
            "builtin_schedules 声明了 backup.sweep，serve 必须注册同名实现，否则定时备份静默不跑"
        );
        assert!(
            prod.contains("backups::sweep_due(&state)"),
            "注册的实现必须真的调用 sweep_due"
        );
    }

    /// **判据必须指向生产代码那一份**：会话回收在 `panel-task` 声明、在 `panel-cli`
    /// 注册，只靠名字约定对齐。漏注册时调度器每轮 `jobs.get(name)` 取到 None 就静默
    /// 跳过——`SessionCache::sweep()` 已实现却永不被调用，会话内存 map 与 sessions
    /// 表单调增长（P1-9）。同样走 `production_source`（剔测试段 + 剔注释）。
    #[test]
    fn session_sweep_is_registered_in_serve() {
        let src = include_str!("main.rs");
        let prod = panel_testutil::production_source(src);
        assert!(
            prod.contains("sched.register(\"session.sweep\", move ||"),
            "builtin_schedules 声明了 session.sweep，serve 必须注册同名实现，否则会话回收静默不跑"
        );
        assert!(
            prod.contains("state.sessions.sweep()"),
            "注册的实现必须真的调用 SessionCache::sweep()"
        );
    }

    /// `[server].tls` 的拒绝必须**接在 serve 启动路径上**，而不只是"有个函数"。
    /// 只测 `validate_implemented()` 的纯逻辑不够——把 serve 里那行调用删掉，单测
    /// 照样全绿，运行时又回到"配了 TLS 却静默明文"（配置项假控制）。
    #[test]
    fn tls_fake_control_is_wired_into_serve() {
        let src = include_str!("main.rs");
        let prod = panel_testutil::production_source(src);
        assert!(
            prod.contains("cfg.validate_implemented()?;"),
            "serve 启动路径必须调用 validate_implemented()，否则 [server].tls 会被静默忽略"
        );
    }

    /// **生产 serve 链的最外层必须是 request_log**。axum 语义：`.fallback()` 会
    /// 整体替换既有 fallback 路由，且新 fallback 不被此前任何 `.layer()` 包裹——
    /// 生产链在 build_router 之后还要 `.fallback(embed::static_handler)` 兜 SPA，
    /// 日志层若加在它之前（或退回 build_router 内），未匹配请求（404 / SPA miss）
    /// 会整条绕过日志层。冒烟实测过这个形态：每个 404 都无日志行、其余全有行。
    /// 判据用 `find` 下标比较——源码出现顺序即 builder 调用顺序，层序即包裹关系。
    /// 判据真机回归：回环不告警、非回环必须告警。
    /// `0.0.0.0` 是最容易踩的一种——很多人以为它"只是本机"，实际是全网可达。
    #[test]
    fn non_loopback_bind_is_detected() {
        let a = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        assert!(!super::is_non_loopback_bind(&a("127.0.0.1:2083")), "回环不得告警");
        assert!(!super::is_non_loopback_bind(&a("[::1]:2083")), "IPv6 回环不得告警");
        assert!(super::is_non_loopback_bind(&a("0.0.0.0:2083")), "0.0.0.0 是全网可达，必须告警");
        assert!(super::is_non_loopback_bind(&a("192.168.1.5:2083")), "局域网地址必须告警");
        assert!(super::is_non_loopback_bind(&a("[::]:2083")), "IPv6 未指定地址必须告警");
    }

    /// ⭐⭐ 接线守卫：`warn_if_exposed` 掉调用后，启动流程照常工作、所有行为测试
    /// 全绿，只是"暴露到网上的提醒"从此消失——只能源码级钉住。
    #[test]
    fn serve_warns_when_listening_outside_loopback() {
        let src = include_str!("main.rs");
        let code = panel_testutil::production_source(src);
        assert!(
            code.contains("warn_if_exposed(&addr)"),
            "serve 启动必须调用 warn_if_exposed(&addr)：面板 root 运行且无 HTTPS，\
             非回环监听必须在启动日志里说清楚"
        );
    }

    #[test]
    fn request_log_is_the_outermost_layer_of_the_serve_chain() {
        let src = include_str!("main.rs");
        let prod = panel_testutil::production_source(src);
        let mount = "axum::middleware::from_fn_with_state(";
        let at = prod
            .find(mount)
            .unwrap_or_else(|| panic!("serve 链必须挂 request_log 层（请求级结构化日志）: {mount}"));
        let fb_at = prod
            .find(".fallback(embed::static_handler)")
            .expect("serve 链必须设 static_handler 兜底（SPA 回退）");
        let hz_at = prod
            .find(".route(\"/healthz\"")
            .expect("serve 链必须挂 /healthz");
        assert!(
            fb_at < at,
            "request_log 必须加在 `.fallback(embed::static_handler)` 之后：否则未匹配请求（404 / SPA miss）绕过日志层，不留日志行"
        );
        assert!(
            hz_at < at,
            "request_log 必须加在 `/healthz` 之后：否则健康检查请求不留日志行"
        );
    }

    /// **全链只许一个挂点**。build_router 内若也挂 request_log，同一请求会落两行
    /// 日志（外层一次 + 内层一次）——行数翻倍，对账与排障反而更难。挂点唯一化后
    /// 由 main.rs 一处装配；routes.rs 的生产段（剔注释行后）不允许再出现。
    /// 剔注释是必须的：routes.rs 接线段有大段注释解释"为什么不挂这里"，
    /// 不剔就会把解释性文字当成挂点（判据指向错 ⇒ 恒绿）。
    #[test]
    fn request_log_is_mounted_exactly_once() {
        let src = include_str!("main.rs");
        let prod = panel_testutil::production_source(src);
        assert_eq!(
            prod.matches("panel_api::middleware::request_log").count(),
            1,
            "serve 链里 request_log 必须恰好一个挂点（双挂 = 每请求两行日志）"
        );
        let routes = include_str!("../../panel-api/src/routes.rs");
        let code = panel_testutil::production_source(routes);
        assert!(
            !code.contains("request_log"),
            "build_router 不得再挂 request_log：生产链已在 main.rs 最外层挂载，双挂 = 每请求两行日志"
        );
    }
}

#[cfg(test)]
mod cli_flags_tests {
    use super::*;

    /// ⭐⭐ `--json` 曾是 `#[arg(long, global = true)]`：任何子命令都收下它，但只有
    /// `capabilities` 真的输出 JSON ⇒ `panel doctor --json` 静默打印人类可读文本，
    /// 脚本拿到一堆散文还以为解析成功了（命令行版「配置项假控制」）。
    /// 现在它只在实现了的子命令上声明，未实现处 clap 直接报错——宁可响亮失败，
    /// 不要"收下参数却不生效"。
    #[test]
    fn json_flag_is_only_accepted_where_it_is_implemented() {
        let ok = Cli::try_parse_from(["panel", "capabilities", "--json"]);
        assert!(ok.is_ok(), "capabilities 必须接受 --json（唯一实现了的子命令）");
        let ok_plain = Cli::try_parse_from(["panel", "capabilities"]);
        assert!(ok_plain.is_ok(), "不带 --json 也要能跑");

        for cmd in ["doctor", "migrate", "vacuum", "serve"] {
            let r = Cli::try_parse_from(["panel", cmd, "--json"]);
            assert!(
                r.is_err(),
                "`panel {cmd} --json` 必须被 clap 拒绝：该子命令没实现 JSON 输出，\
                 收下参数却不生效比直接报错更危险"
            );
        }
    }
}

#[cfg(test)]
mod restore_cli_tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("panel-rstdb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn only_db_artifacts_pass_the_gate() {
        assert!(is_db_artifact_name("plan1-1700000000.db"));
        assert!(is_db_artifact_name("plan1-1700000000.db.enc"));
        assert!(!is_db_artifact_name("plan1-1700000000.tar.gz"), "站点归档不能盖到 panel.db");
        assert!(!is_db_artifact_name("plan1-1700000000.tar.gz.enc"));
        assert!(!is_db_artifact_name("panel.db.bak"));
    }

    #[test]
    fn atomic_replace_swaps_content_and_clears_wal_and_shm() {
        let d = tmp("swap");
        let db = d.join("panel.db");
        let src = d.join("art.db");
        std::fs::write(&db, b"OLD-DB").unwrap();
        std::fs::write(d.join("panel.db-wal"), b"STALE-WAL").unwrap();
        std::fs::write(d.join("panel.db-shm"), b"STALE-SHM").unwrap();
        std::fs::write(&src, b"NEW-DB").unwrap();

        atomic_replace_db(&src, &db).unwrap();

        assert_eq!(std::fs::read(&db).unwrap(), b"NEW-DB", "主库必须被替换");
        assert!(!d.join("panel.db-wal").exists(), "旧 WAL 必须删掉，否则会回放到新库");
        assert!(!d.join("panel.db-shm").exists(), "旧 SHM 必须删掉");
        assert!(!d.join("panel.db.restore-tmp").exists(), "临时文件不能留下");
        let _ = std::fs::remove_dir_all(&d);
    }
}
