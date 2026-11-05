//! 可执行入口：`panel {init|doctor|migrate|serve|backup|passwd|systemd-unit|vacuum}`

mod bootstrap;
mod cmd;
mod config;
mod doctor;
mod embed;
mod upgrade;

use clap::{CommandFactory, Parser, Subcommand};
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
    cmd: Option<Cmd>,
}

#[derive(Clone, Subcommand)]
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
    /// 卸载 ForkPanel：停服务 → 移除 systemd 单元 → 移除二进制（保留数据与配置）
    ///
    /// 与 `deploy/uninstall.sh` 等价，给「已经装好的面板自己卸载自己」一个 CLI 入口，
    /// 不必再单独取安装脚本。安全边界与 uninstall.sh 一致：**只删程序与单元，
    /// 绝不删数据/配置**（账号、站点、审计、备份都在里面）。彻底清除数据请手动 `rm -rf`。
    Uninstall,
    /// 交互式公网暴露（薄壳包 `deploy/expose-public.sh`）：引导用户填域名 +
    /// 来源网段，校验后透传脚本（面板仍绑回环，由 nginx 反代终结 TLS）。
    ///
    /// 这是「引导式安全暴露」的 CLI 入口：默认零暴露不变，用户想对外才显式跑。
    /// 拒绝 0.0.0.0/0（掩码 0）；域名/CIDR 先过 Rust 同款校验，脚本再 fail-closed 复核。
    /// 卸载模式 `--uninstall` 撤下反代、面板恢复只绑回环。
    Expose {
        /// 对外域名（如 panel.example.com）。省略则在终端交互询问。
        #[arg(long, short)]
        domain: Option<String>,
        /// 允许访问的来源 IPv4 CIDR（可重复，如 -a 1.2.3.4/32）。省略则交互询问。
        #[arg(long = "allow", short = 'a')]
        allow: Vec<String>,
        /// 使用自签名证书（脚本现场生成），不需自带证书。
        ///
        /// ⚠ 与 `--fullchain` / `--key` 是**互斥**的，且这里必须显式声明：
        ///   脚本侧在 `SELF_SIGNED=1` 时会把 FULLCHAIN/KEY 变量重赋为自签路径，
        ///   于是"同时给了受信任证书 + --self-signed"会被**静默降级成自签**
        ///   （全程退出码 0、不打任何说明）。不拦就等于埋一个静默 TLS 降级。
        #[arg(long, conflicts_with_all = ["fullchain", "key"])]
        self_signed: bool,
        /// 自带证书：证书链文件（PEM）。与 --self-signed 二选一。
        #[arg(long)]
        fullchain: Option<String>,
        /// 自带证书：私钥文件（PEM）。
        #[arg(long)]
        key: Option<String>,
        /// 不写防火墙规则（仅反代）。仅在已有独立防火墙策略时使用。
        #[arg(long)]
        no_firewall: bool,
        /// 撤销暴露：撤下反代，面板恢复只绑回环。
        #[arg(long)]
        uninstall: bool,
    },
        /// 升级面板：下载签名发行包 → 验签 → 解包 → 调用包内 install.sh → 失败回滚
        ///
        /// 验签公钥与 `deploy/get-panel.sh` 内嵌的是同一把（`deploy/release-pubkey.pub`，
        /// 由 `ci/check-docs-consistency.sh` 钉住两处一致）。验不过立即中止，绝不执行
        /// 包内文件。安装前备份旧二进制为 `panel.bak`，install.sh 失败或装完服务不是
        /// active 都会回滚。配置与数据不删。
        Upgrade {
            /// 只检查是否有新版本（不下载）
            #[arg(long)]
            check: bool,
            /// 下载并验签后停止，不安装
            #[arg(long)]
            dry_run: bool,
            /// 指定版本（带不带 v 均可）；省略则取 GitHub 最新
            #[arg(long)]
            version: Option<String>,
            /// 覆盖下载基址（自建镜像；签名仍用内嵌公钥校验）
            #[arg(long)]
            base_url: Option<String>,
            /// 覆盖验签公钥（仅自建分发 / E2E；官方安装不要用）
            #[arg(long)]
            pubkey_file: Option<PathBuf>,
        },

        /// 查看 / 修改面板网络配置（端口、监听地址）
        ///
        /// 替代原 `forkpanel` / `fp` 壳的 `status` / `set-port` / `set-bind`：由 Rust 端
        /// 原子、带校验地改 `config.toml` 的 `[server]` 段（保留注释、沿用权限），杜绝
        /// 原 awk 文本编辑写坏后 serve 因 `deny_unknown_fields` 起不来的情况。
        Config {
            /// 查看 / 修改面板网络配置（status / set port / set bind）
            #[command(subcommand)]
            action: Option<ConfigAction>,
        },
        /// 进入交互式面板配置菜单（TTY 下直接运行 `panel` 即进入，替代原 `forkpanel` / `fp`）
        Menu,
    }

    /// `panel config` 的子命令。
    #[derive(Clone, Subcommand)]
    enum ConfigAction {
        /// 打印当前配置与服务状态（不需要 root）
        Status,
        /// 修改 `[server]` 段字段（set port / set bind）
        Set {
            #[command(subcommand)]
            target: ConfigSet,
        },
    }

    /// `panel config set` 的子命令：修改 `[server]` 段的具体字段。
    #[derive(Clone, Subcommand)]
    enum ConfigSet {
        /// 修改监听端口（1-65535）
        Port {
            /// 监听端口
            port: u16,
        },
        /// 修改监听地址；非回环地址默认拒绝，需显式 --yes
        Bind {
            /// 监听地址（IPv4 / IPv6 / 主机名）
            addr: String,
            /// 非回环地址会暴露 root 面板到网络，默认拒绝，需显式确认
            #[arg(long)]
            yes: bool,
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

    // 裸跑（无子命令）：
    //  - TTY：进入交互式面板配置菜单（替代原 forkpanel / fp 壳）
    //  - 非 TTY（脚本 / 管道）：打印帮助并以非零退出，等价于 clap 缺子命令
    if cli.cmd.is_none() {
        if std::io::stdin().is_terminal() {
            return run_menu(&cli, &os);
        }
        let _ = Cli::command().print_help();
        println!();
        return Err(PanelError::Validation {
            field: "command",
            reason: "缺少子命令：脚本环境请显式指定子命令（如 `panel config --status`），交互终端直接运行 `panel` 即进入配置菜单".into(),
        });
    }
    let cmd = cli.cmd.clone().unwrap();
    match cmd {
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

        Cmd::Migrate => cmd::db::migrate(&cli, os.clone()),

        // 启动流程整体搬进 `cmd/serve.rs`：它原本占掉本函数 187 行，
        // 让 17 条子命令的分派表彻底看不清。`os` 按值移交——serve 会用配置里的
        // `[paths]` 覆盖重建适配器，原先那个只在读到配置前用于定位配置文件。
        Cmd::Serve => cmd::serve::run(&cli, os),

        Cmd::Backup { ref out } => cmd::db::backup(&cli, os.clone(), out.as_deref()),

        Cmd::Vacuum => cmd::db::vacuum(&cli, os.clone()),

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

        Cmd::SystemdUnit { install } => cmd::system::systemd_unit(&cli, os.clone(), install),

        Cmd::VerifyBackup { ref path } => cmd::db::verify(&cli, os.clone(), path),

        // 面板自身库的五条运维命令搬进 `cmd/db.rs`（同域：都动同一份 panel.db）。
        Cmd::RestoreDb { ref path, remote, ref artifact, force } => cmd::db::restore(
            &cli, os.clone(), path.as_deref(), remote, artifact.as_deref(), force),

        Cmd::Healthcheck { install, uninstall } =>
            cmd::system::healthcheck(&cli, os.clone(), install, uninstall),

        Cmd::Capabilities { json } => cmd::system::capabilities(os.clone(), json),

        Cmd::Uninstall => cmd::system::uninstall(os.clone()),

        Cmd::Upgrade { check, dry_run, ref version, ref base_url, ref pubkey_file } =>
            cmd::system::upgrade(&cli, os.clone(), check, dry_run, version, base_url, pubkey_file),

        Cmd::Expose { domain, allow, self_signed, fullchain, key, no_firewall, uninstall } => {
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

        Cmd::Config { action } => run_config(&cli, &os, action),
        Cmd::Menu => run_menu(&cli, &os),
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

use panel_core::now_unix;
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

/// 域名校验：**规则在 `panel_core::expose`（唯一事实源）**，此处只做转发。
///
/// 为什么不就地实现：面板内的 Web 向导（`POST /api/v1/system/expose/apply`）要用
/// 同一套规则，两处各写一份迟早漂移出一个放行、另一个拒绝。保留本函数名是为了
/// 不动既有 `expose_tests` 的断言面（它们按名调这里，等于顺带钉住"仍走共享层"）。
fn validate_expose_domain(d: &str) -> std::result::Result<(), String> {
    panel_core::expose::validate_domain(d)
}

/// CIDR 校验：同理由 `panel_core::expose::validate_cidr` 提供（掩码 0 被拒等 fail-closed
/// 语义都在那边，脚本侧另有同名校验做纵深防御）。
fn validate_expose_cidr(c: &str) -> std::result::Result<(), String> {
    panel_core::expose::validate_cidr(c)
}

/// 交互读取一行（去掉行尾换行）。仅在确认 `is_terminal()` 后调用。
fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| PanelError::Internal(format!("读取输入失败：{e}")))?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// 调用 `deploy/expose-public.sh`（路径经 `panel_os::paths` 抽象，业务层不硬编码）。
///
/// 薄壳：Rust 只负责收输入 + 同款校验 + 透传，绝不重写脚本的 fail-closed 逻辑
/// （绝不绑 0.0.0.0、防火墙白名单掩码 0 即 0.0.0.0/0 被拒）。脚本不存在时给明确提示，
/// 而不是让 `bash` 去 exec 一个不存在的路径（那会落到 127 + 难懂报错）。
fn invoke_expose(script_args: &[String]) -> Result<()> {
    let script = panel_os::paths::panel_expose_script_path();
    let script_s = script.to_str().ok_or_else(|| {
        PanelError::Internal(format!("expose 脚本路径非 UTF-8：{}", script.display()))
    })?;
    if !script.exists() {
        return Err(PanelError::Internal(format!(
            "找不到 expose 脚本 {}（是否漏装？重新跑 install.sh 或手动部署 deploy/expose-public.sh）",
            script.display(),
        )));
    }
    let mut argv: Vec<&str> = Vec::with_capacity(script_args.len() + 1);
    argv.push(script_s);
    for a in script_args {
        argv.push(a.as_str());
    }
    let out = panel_os::run_sync(panel_os::Bin::Bash, &argv)?;
    // 脚本约定：非零退出 = 失败（fail-closed）。把它的输出原样透传给用户。
    if out.code != Some(0) {
        return Err(PanelError::Internal(format!(
            "expose-public.sh 失败（退出码 {:?}）：\n{}{}",
            out.code, out.stdout, out.stderr,
        )));
    }
    // ⚠ 成功分支**同样**要回显脚本输出：脚本把「nginx -t 已通过但重载失败」
    //   「云厂商安全组脚本碰不到」「无 systemd，请自行重启面板」等警告写在 stderr
    //   上且**仍以 0 退出**。此前成功时一律丢弃，用户只看到"完成"而实际并未生效。
    //   与 Web 向导同口径：后者把脚本 stdout 原样回给前端展示（见 panel-api
    //   routes/expose.rs 的 apply/remove）。
    if !out.stdout.trim().is_empty() {
        println!("{}", out.stdout.trim_end());
    }
    if !out.stderr.trim().is_empty() {
        eprintln!("{}", out.stderr.trim_end());
    }
    Ok(())
}

/// 配置子命令：`panel config [status | set port N | set bind ADDR [--yes]]`。
fn run_config(
    cli: &Cli,
    os: &Arc<dyn panel_os::OsAdapter>,
    action: Option<ConfigAction>,
) -> Result<()> {
    match action {
        Some(ConfigAction::Set { target: ConfigSet::Port { port } }) => do_set_port(cli, os, port),
        Some(ConfigAction::Set { target: ConfigSet::Bind { addr, yes } }) => do_set_bind(cli, os, &addr, yes),
        None | Some(ConfigAction::Status) => show_panel_status(cli, os),
    }
}

/// 打印面板配置与运行状态（不需要 root）。
fn show_panel_status(cli: &Cli, os: &Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    let layout0 = build_layout(os, None);
    let cfgp = cli.config.clone().unwrap_or_else(|| layout0.config_dir().join("config.toml"));
    println!("ForkPanel 状态");
    println!("  配置文件   {}", cfgp.display());
    if !cfgp.exists() {
        println!("  （配置文件不存在：面板可能尚未安装）");
    } else {
        let cfg = Config::load(&cfgp).map_err(|e| {
            PanelError::Validation { field: "config", reason: format!("读取配置失败：{e}") }
        })?;
        println!("  监听       {}:{}", cfg.server.bind, cfg.server.port);
        println!("  仅本机     {}  （true 时覆盖 bind）", cfg.server.localhost_only);
        println!(
            "  数据目录   {}",
            cfg.paths.data.clone().unwrap_or_else(|| layout0.data_dir()).display()
        );
    }
    // 服务状态（不依赖 root）。进程调用一律走 panel-os 的唯一出口
    // （ci/check-layering.sh 规则[1]：cmd.rs 之外不得直接 spawn）。
    let active = panel_os::run_sync(panel_os::Bin::Systemctl, &["is-active", "--quiet", "panel"])
        .map(|o| o.code == Some(0))
        .unwrap_or(false);
    println!("  服务       {}", if active { "active" } else { "inactive / 未安装" });
    // 版本：直接让 clap 渲染，不必再 spawn 自身二进制去问一次 `--version`
    let v = Cli::command().render_version();
    let v = v.trim();
    if !v.is_empty() {
        println!("  版本       {v}");
    }
    Ok(())
}

/// 修改监听端口（root 权限；写 config.toml 的 `[server].port` 并重启服务）。
fn do_set_port(cli: &Cli, os: &Arc<dyn panel_os::OsAdapter>, port: u16) -> Result<()> {
    if !panel_os::fs::is_root() {
        return Err(PanelError::Internal(
            "set-port: 需要 root 权限（写 /etc/forkpanel/config.toml 并重启服务）".into(),
        ));
    }
    if port == 0 {
        return Err(PanelError::Validation { field: "port", reason: "端口必须是 1-65535".into() });
    }
    let layout0 = build_layout(os, None);
    let cfgp = cli.config.clone().unwrap_or_else(|| layout0.config_dir().join("config.toml"));
    if !cfgp.exists() {
        return Err(PanelError::Validation {
            field: "config",
            reason: format!("找不到配置文件 {}", cfgp.display()),
        });
    }
    config::write_server_key(&cfgp, "port", &port.to_string())?;
    println!("· 端口已改为 {port}");
    restart_panel_service()
}

/// 修改监听地址（root 权限）。回环地址设 `localhost_only=true`；非回环默认拒绝，需 `--yes`
/// 并显式设 `localhost_only=false`（否则 bind 不生效，且会暴露 root 面板到网络）。
fn do_set_bind(cli: &Cli, os: &Arc<dyn panel_os::OsAdapter>, addr: &str, yes: bool) -> Result<()> {
    if !panel_os::fs::is_root() {
        return Err(PanelError::Internal(
            "set-bind: 需要 root 权限（写 /etc/forkpanel/config.toml 并重启服务）".into(),
        ));
    }
    let layout0 = build_layout(os, None);
    let cfgp = cli.config.clone().unwrap_or_else(|| layout0.config_dir().join("config.toml"));
    if !cfgp.exists() {
        return Err(PanelError::Validation {
            field: "config",
            reason: format!("找不到配置文件 {}", cfgp.display()),
        });
    }
    let loopback = matches!(addr, "127.0.0.1" | "::1");
    if !loopback && !yes {
        return Err(PanelError::Validation {
            field: "bind",
            reason: format!(
                "拒绝直接改到非回环地址：{addr}\n  面板以 root 运行且无内置 HTTPS，直接绑出去等于把 root 面板暴露到网络。\n  确需公网访问，优先用：sudo panel expose -d <域名> -a <出口IP>/32\n  仍要直接改，请显式加 --yes（会同时设置 localhost_only=false，否则 bind 不生效）。",
            ),
        });
    }
    config::write_server_key(&cfgp, "bind", &format!("\"{addr}\""))?;
    config::write_server_key(&cfgp, "localhost_only", &loopback.to_string())?;
    if loopback {
        println!("· 监听地址已改为 {addr}（localhost_only=true）");
    } else {
        println!("· 监听地址已改为 {addr}，并设置 localhost_only=false");
        println!("  ⚠ 已把 root 面板暴露到网络；强烈建议改用 panel expose 接 TLS。");
    }
    restart_panel_service()
}

/// 写配置后按需重启 panel 服务（systemd 已 enable 才 restart；否则提示下次启动生效）。
fn restart_panel_service() -> Result<()> {
    // 三处进程调用都走 panel-os 唯一出口（ci/check-layering.sh 规则[1]）。
    let has_systemctl = panel_os::run_sync(panel_os::Bin::Systemctl, &["--version"])
        .map(|o| o.code == Some(0))
        .unwrap_or(false);
    if !has_systemctl {
        println!("· 未检测到 systemd，改动将在下次手动启动生效");
        return Ok(());
    }
    let enabled = panel_os::run_sync(panel_os::Bin::Systemctl, &["is-enabled", "--quiet", "panel"])
        .map(|o| o.code == Some(0))
        .unwrap_or(false);
    if !enabled {
        println!("· 未检测到 panel 的 systemd 单元，改动将在下次启动生效");
        return Ok(());
    }
    match panel_os::run_sync(panel_os::Bin::Systemctl, &["restart", "panel"]) {
        Ok(o) if o.code == Some(0) => println!("· 已重启 panel"),
        Ok(o) => eprintln!(
            "· ⚠ 重启失败（退出码 {:?}）：journalctl -u panel -n 50 --no-pager",
            o.code
        ),
        Err(e) => eprintln!("· ⚠ 重启命令执行失败：{e}"),
    }
    Ok(())
}

/// 交互式面板配置菜单（替代原 forkpanel / fp 壳）。仅在 TTY 下可用。
fn run_menu(cli: &Cli, os: &Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(PanelError::Validation {
            field: "menu",
            reason: "非交互环境请用 `panel config --status` / `panel config set port N` / `panel config set bind ADDR`".into(),
        });
    }
    loop {
        println!();
        println!("==== ForkPanel 配置 ====");
        println!("  1) 查看状态");
        println!("  2) 修改监听端口");
        println!("  3) 修改监听地址（含公网风险确认）");
        println!("  4) 重置用户口令");
        println!("  5) 公网暴露（引导命令）");
        println!("  6) 升级面板");
        println!("  7) 卸载面板");
        println!("  8) 查看全部命令");
        println!("  0) 退出");
        let choice = prompt_line("选择 [0-8]：")?;
        match choice.as_str() {
            "1" => {
                let _ = show_panel_status(cli, os);
            }
            "2" => {
                let p = prompt_line("新端口 [1-65535]：")?;
                match p.parse::<u16>() {
                    Ok(port) => {
                        if let Err(e) = do_set_port(cli, os, port) {
                            eprintln!("panel: {e}");
                        }
                    }
                    Err(_) => eprintln!("端口必须是数字：{p}"),
                }
            }
            "3" => {
                let cfgp = cli.config.clone().unwrap_or_else(|| {
                    build_layout(os, None).config_dir().join("config.toml")
                });
                println!("当前配置：{}", cfgp.display());
                println!("  1) 127.0.0.1（推荐：仅本机）");
                println!("  2) 自定义地址");
                let c = prompt_line("选择 [1-2]：")?;
                match c.as_str() {
                    "1" => {
                        if let Err(e) = do_set_bind(cli, os, "127.0.0.1", false) {
                            eprintln!("panel: {e}");
                        }
                    }
                    "2" => {
                        let b = prompt_line("地址：")?;
                        if let Err(e) = do_set_bind(cli, os, &b, false) {
                            eprintln!("panel: {e}");
                        }
                    }
                    _ => eprintln!("无效选择"),
                }
            }
            "4" => {
                let u = prompt_line("用户名：")?;
                if let Err(e) = run_subcommand(cli, Cmd::Passwd { user: u, pass: None }) {
                    eprintln!("panel: {e}");
                }
            }
            "5" => print_expose_help(),
            "6" => print_upgrade_help(),
            "7" => {
                if let Err(e) = run_subcommand(cli, Cmd::Uninstall) {
                    eprintln!("panel: {e}");
                } else {
                    // 卸载已删磁盘二进制，但本菜单进程仍驻内存（删文件不影响在跑的进程）。
                    // 若不清退，loop 会回显菜单让人误以为「没卸干净」。卸载成功即退出菜单。
                    println!("面板已卸载，正在退出菜单。");
                    break;
                }
            }
            "8" => {
                let _ = Cli::command().print_help();
                println!();
            }
            "0" | "q" | "Q" => break,
            _ => eprintln!("无效选择：{choice}"),
        }
    }
    Ok(())
}

/// 菜单里那些本就由其它子命令实现的项（口令 / 卸载）：**进程内**委派给 `run()`。
///
/// 为什么不再 spawn 自身二进制（原 `reexec_panel` 的做法）：
/// ① 架构上子进程只允许从 `panel-os/src/cmd.rs` 这一个出口出去，
///    `ci/check-layering.sh` 规则[1] 会拦住 cmd.rs 之外的进程调用
/// ② 进程内委派还省掉一次「重新解析配置 / 重建 adapter」，且天然继承菜单
///    已拿到的 `--config` / `--tier`，不存在漏传参数的可能。
fn run_subcommand(cli: &Cli, cmd: Cmd) -> Result<()> {
    run(Cli {
        config: cli.config.clone(),
        tier: cli.tier.clone(),
        cmd: Some(cmd),
    })
}

fn print_expose_help() {
    println!("公网暴露（脚本做 nginx 反代 + 防火墙白名单，面板本身仍只绑回环）：");
    println!("  sudo panel expose -d <域名> -a <出口IP>/32");
    println!("撤销：");
    println!("  sudo panel expose --uninstall");
}

fn print_upgrade_help() {
    println!("升级（下载签名二进制 → 验签 → 替换并重启；配置与数据保留）：");
    println!("  wget -O get-panel.sh https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh");
    println!("  sudo sh get-panel.sh");
    println!("注：PANEL_VERSION 不带 v 前缀（脚本自己拼 /v<版本>）。");
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
        // 判据跟着被检查的那份文件走：serve 的启动链已搬进 cmd/serve.rs。
        // ⚠ 这里必须用**计数**而不是 contains。`panel doctor` 也调同一个函数，
        //   而当初 serve 那条与 doctor 那条同在 main.rs：把 serve 里那行删掉，
        //   contains 版本会被 doctor 的副本满足，照样绿。实测印证——本轮拆
        //   serve 时同批三条守卫都红了，唯独这条没红（它的判据指向不唯一）。
        let src = include_str!("cmd/serve.rs");
        let prod = panel_testutil::production_source(src);
        assert_eq!(
            prod.matches("cfg.validate_implemented()?;").count(),
            1,
            "serve 启动路径必须调用且只调用一次 validate_implemented()，否则 [server].tls 会被静默忽略"
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
        // 判据跟着被检查的那份文件走：serve 的启动链已搬进 cmd/serve.rs
        let src = include_str!("cmd/serve.rs");
        let code = panel_testutil::production_source(src);
        assert!(
            code.contains("warn_if_exposed(&addr)"),
            "serve 启动必须调用 warn_if_exposed(&addr)：面板 root 运行且无 HTTPS，\
             非回环监听必须在启动日志里说清楚"
        );
    }

    #[test]
    fn request_log_is_the_outermost_layer_of_the_serve_chain() {
        // 判据跟着被检查的那份文件走：builder 调用顺序即层序，而这条链在 cmd/serve.rs
        let src = include_str!("cmd/serve.rs");
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
        // 全链 = main.rs（分派）+ cmd/serve.rs（装配）+ routes.rs（build_router），
        // 三处都要扫：只扫 serve.rs 会漏掉"有人又在 main.rs 里挂一层"，
        // 只扫 main.rs 则会漏掉本函数真正要守的那一处（装配已搬走）。
        let serve = panel_testutil::production_source(include_str!("cmd/serve.rs"));
        assert_eq!(
            serve.matches("panel_api::middleware::request_log").count(),
            1,
            "serve 链里 request_log 必须恰好一个挂点（双挂 = 每请求两行日志）"
        );
        let main = panel_testutil::production_source(include_str!("main.rs"));
        assert!(
            !main.contains("panel_api::middleware::request_log"),
            "main.rs 不得再挂 request_log：装配已收敛到 cmd/serve.rs 一处"
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

    /// `panel expose` 子命令必须能被 clap 正常解析（域名 + 至少一个来源网段）。
    #[test]
    fn expose_subcommand_parses() {
        let ok = Cli::try_parse_from([
            "panel", "expose", "-d", "panel.example.com", "-a", "203.0.113.0/24",
        ]);
        assert!(ok.is_ok(), "expose 必须接受 -d 与 -a");
        let un = Cli::try_parse_from(["panel", "expose", "--uninstall"]);
        assert!(un.is_ok(), "expose 必须接受 --uninstall");
        // 来源网段可重复给定
        let multi = Cli::try_parse_from([
            "panel", "expose", "-d", "panel.example.com",
            "-a", "203.0.113.0/24", "-a", "198.51.100.0/24",
        ]);
        assert!(multi.is_ok(), "expose 必须允许重复 -a");
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

#[cfg(test)]
mod expose_tests {
    /// 域名校验与脚本 `validate_domain` 同款规则，必须拒绝非法输入。
    #[test]
    fn domain_validation_rejects_bad_input() {
        assert!(super::validate_expose_domain("panel.example.com").is_ok());
        assert!(super::validate_expose_domain("example.com").is_ok());
        assert!(super::validate_expose_domain("a.b").is_ok());
        assert!(super::validate_expose_domain("example").is_err(), "单级域名必须拒");
        assert!(super::validate_expose_domain("1.2.3.4").is_err(), "纯 IP 当域名必须拒（顶级域含数字）");
        assert!(super::validate_expose_domain("-x.example.com").is_err(), "段首连字符必须拒");
        assert!(super::validate_expose_domain("x-.example.com").is_err(), "段尾连字符必须拒");
        assert!(super::validate_expose_domain("a..b").is_err(), "空段必须拒");
    }

    /// CIDR 校验：IPv4 正常放行；掩码 0（0.0.0.0/0）与 IPv6 必须拒。
    #[test]
    fn cidr_validation_rejects_open_and_ipv6() {
        assert!(super::validate_expose_cidr("203.0.113.0/24").is_ok());
        assert!(super::validate_expose_cidr("1.2.3.4/32").is_ok());
        assert!(super::validate_expose_cidr("192.168.1.5").is_ok(), "缺省掩码当 /32");
        assert!(super::validate_expose_cidr("0.0.0.0/0").is_err(), "掩码 0 = 不设限制，必须拒");
        assert!(super::validate_expose_cidr("2001:db8::/32").is_err(), "IPv6 必须拒");
        assert!(super::validate_expose_cidr("1.2.3.256/32").is_err(), "段超 255 必须拒");
        assert!(super::validate_expose_cidr("1.2.3/24").is_err(), "IPv4 必须四段");
        assert!(super::validate_expose_cidr("abc").is_err(), "非数字 IP 必须拒");
    }

    /// 接线守卫：`panel expose` 必须真的调到 expose 脚本（路径经 paths 抽象）、
    /// 且经 `Bin::Bash` argv 直传——删掉这条调用，子命令就成了"收下参数却不做事"
    /// 的命令行版假控制。判据指向生产段（剔测试与注释）。
    #[test]
    fn expose_arm_invokes_script_via_bash() {
        let src = include_str!("main.rs");
        let prod = panel_testutil::production_source(src);
        assert!(prod.contains("Cmd::Expose"), "Cmd 枚举必须声明 Expose 变体");
        assert!(
            prod.contains("panel_os::paths::panel_expose_script_path()"),
            "expose 必须经由 paths 抽象定位脚本（业务层不得硬编码安装路径，门禁 [3]）"
        );
        assert!(
            prod.contains("panel_os::run_sync(panel_os::Bin::Bash"),
            "expose 必须经 Bin::Bash argv 直传调脚本（不得 shell 拼字符串）"
        );
    }

    /// 接线守卫：serve 在 `localhost_only` 时必须打印"仅本机访问"横幅并提示
    /// `sudo panel expose`——这是小白困惑的根因修复（装完以为能 IP:端口 访问）。
    /// 判据指向生产段，避免重复实现时把横幅删了还全绿。
    #[test]
    fn serve_prints_localhost_only_banner() {
        // 判据跟着被检查的那份文件走：横幅在 cmd/serve.rs。
        // ⚠ 必须计数而不是 contains：`sudo panel expose` 在 main.rs 另有 4 处
        //   （Expose arm 的 println、改 bind 的拒绝文案、帮助文本两行），
        //   所以旧版在 main.rs 上做 contains **从来没检查过 serve**——把 serve 里
        //   的横幅整段删掉它照样绿。这是拆分时「没红的守卫」暴露出来的存量假绿。
        let src = include_str!("cmd/serve.rs");
        let prod = panel_testutil::production_source(src);
        assert_eq!(
            prod.matches("sudo panel expose").count(),
            1,
            "serve 在 localhost_only 时必须且只提示一次 `sudo panel expose`，否则小白仍以为能 IP:端口 访问"
        );
    }
}
