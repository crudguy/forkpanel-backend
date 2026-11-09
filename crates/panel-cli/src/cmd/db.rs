//! 面板数据库自身的运维命令：迁移、在线备份、回收、产物校验、离线恢复。
//!
//! 为什么这 5 条归一域：它们操作的都是**同一份 `panel.db`**，前置完全相同
//! （读配置 → 建 layout → 按档位开库），危险等级也同为「动到面板的库」。
//! 拆到同一个文件后，"哪些命令会碰库"一眼可见——这比按字母序散在 `run()` 里安全。
//!
//! ⚠ 三处容易改坏的语义，改动前先读完：
//! 1. `backup` 用 `VACUUM INTO` 写目标文件，它**拒绝覆盖已存在文件**（报
//!    "output file already exists"）。所以先判存在并给出「删掉或换路径」的提示，
//!    而不是把 SQLite 的原文抛给用户。
//! 2. `verify` 与 `restore` 都先验产物再动库。加密产物还要求主密钥在位——
//!    没有主密钥时**拒绝**而不是"尽量试试"，因为解不开的产物盖上去就是废库。
//! 3. `restore` 的步骤顺序是安全性的一部分：查服务是否在跑 → 取产物 →
//!    按扩展名挡掉站点归档 → 验产物 → 解密到临时文件 → 给当前库留快照 →
//!    原子替换并清 -wal/-shm。任何一步调换都可能让"坏产物覆盖好库"变成可能。
use std::path::{Path, PathBuf};
use std::sync::Arc;

use panel_core::{PanelError, Result};

use crate::{
    atomic_replace_db, build_layout, detect_tier, is_db_artifact_name, load_cfg,
    load_existing_master_key, Cli, Config,
};


/// 服务在跑就不能动库 / 换主密钥：在线覆盖会让 WAL 与主库不一致。
///
/// 抽成公共函数是因为 `restore` 与 `key rotate` 都要这道闸门。两处各写一份的话，
/// 改一处漏一处会让「换钥时服务还在跑」变成**静默数据损坏**——运行中的进程内存里
/// 还是旧密钥，换完它会继续用旧密钥加密新秘密，于是库里新旧混装、谁都打不开全部。
pub(crate) fn ensure_service_stopped(cfg: &Config, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    let host = match cfg.server.bind.as_str() {
        "0.0.0.0" | "::" => "127.0.0.1",
        other => other,
    };
    let addr = format!("{host}:{}", cfg.server.port);
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        if std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_millis(300)).is_ok() {
            return Err(PanelError::Validation {
                field: "service",
                reason: format!(
                    "服务仍在运行（{addr} 可连接）。请先停止 panel 再继续；\
                     确认已停机（例如容器内进程名不同）可加 --force"
                ),
            });
        }
    }
    Ok(())
}

/// 执行数据库迁移（幂等）；打印迁移后的 schema 版本。
pub(crate) fn migrate(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    let layout = build_layout(&os, Some(&cfg));
    let _instance_lock = panel_os::instance_lock::acquire(&layout.data_dir())?;
    let db_path = layout.sqlite_path();
    let mut conn = panel_db::open(&db_path, detect_tier(&*os, &cfg), &cfg.db.synchronous)?;
    crate::migrate_snapshot::snapshot_before_migrate(&conn, &db_path, &layout.backup_dir())?;
    let v = panel_db::migrate::apply(&mut conn)?;
    println!("schema 版本 {v}");
    Ok(())
}

/// 在线备份：`VACUUM INTO` 出一份一致快照（不停服）。
///
/// `out` 为空时落到 `<backup_dir>/panel-<ts>.db`。**默认加密**（G12）：
/// 产物名多一个 `.enc` 后缀，形如 `panel-<ts>.db.enc`；`--no-encrypt` 才出明文 `.db`。
///
/// 为什么默认加密：`panel.db` 里有数据库口令、SSL 私钥的密文，以及**明文**的
/// 站点配置与审计明细。产物一旦被拷到别的地方（U 盘、对象存储、同事的机器），
/// 未加密就等于把整台服务器的底牌交出去。加密的代价是「主密钥丢失 = 备份全废」，
/// 这一半由 `docs/deployment.md` §4.1 的异地离线副本 + `panel key check` 兜住。
pub(crate) fn backup(
    cli: &Cli,
    os: Arc<dyn panel_os::OsAdapter>,
    out: Option<&Path>,
    encrypt: bool,
) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    let layout = build_layout(&os, Some(&cfg));
    let base = out.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        std::fs::create_dir_all(layout.backup_dir()).ok();
        layout.backup_dir().join(format!("panel-{ts}.db"))
    });
    let dest = if encrypt { encrypted_path(&base) } else { base.clone() };
    // `VACUUM INTO` 拒绝覆盖已存在的文件，报的是 "output file already
    // exists"——用户看不出是该删还是该改名。显式说清楚。
    if dest.exists() {
        return Err(PanelError::Validation {
            field: "out",
            reason: format!("目标已存在：{}（VACUUM INTO 不覆盖，请先删除或换个路径）", dest.display()),
        });
    }

    // 加密时明文只落在一个临时路径上，且**加密后立即删除**：
    // 否则「加了密的备份」旁边躺着一份同名明文，等于没加密。
    //
    // ⚠ 临时名不能写成 `<dest>.part`：`encrypt_file` 自己的临时文件正是
    //   `dst.with_extension("enc.part")`，两者会撞成同一个路径 —— 于是它一边读
    //   src 一边 truncate 同一个文件，永远读不到 EOF、产物无限增长。
    //   放到 tmp_dir 并带上 pid+纳秒，既避开撞名也不把明文留在产物旁边。
    let plain = if encrypt {
        std::fs::create_dir_all(layout.tmp_dir()).ok();
        let nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let p = layout.tmp_dir().join(format!("panel-backup-{}-{nano}.db", std::process::id()));
        let _ = std::fs::remove_file(&p); // 理论上不会是自己的残留，但删了更安全
        p
    } else {
        dest.clone()
    };

    let conn = panel_db::open(&layout.sqlite_path(), detect_tier(&*os, &cfg), &cfg.db.synchronous)?;
    let made = panel_db::backup_to(&conn, &plain);
    drop(conn); // 先关连接再加密：产物已落盘，握着库句柄没必要
    if let Err(e) = made {
        if encrypt {
            let _ = std::fs::remove_file(&plain); // 失败也别把明文留在 tmp 里
        }
        return Err(e);
    }

    if !encrypt {
        println!("备份完成：{}", dest.display());
        println!("⚠ 未加密产物：库里的口令/私钥仍是密文，但站点配置与审计明细是明文。");
        println!("  要交给外部介质，请去掉 --no-encrypt 重新备份。");
        return Ok(());
    }

    // 严格加载：密钥缺失时**不生成**。用一把刚生成的新钥匙加密备份，产物看起来
    // 没问题，但它解不开库里任何一条既有密文——等于交出一份"恢复不了秘密"的备份。
    let key = load_existing_master_key(&layout.data_dir()).ok_or_else(|| {
        PanelError::Internal(
            "读不到主密钥（data_dir/master.key），无法加密备份产物。\
             先 `panel key show` 确认密钥在不在；确实丢了就走 docs/deployment.md §4.1 \
             的丢密钥流程（加密产物无救，但明文备份仍可用 --no-encrypt）"
                .into(),
        )
    })?;
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;
    let res = rt.block_on(panel_os::backup::encrypt_file(&plain, &dest, &key));
    // 无论成败都必须删掉明文：失败时更不能留
    let _ = std::fs::remove_file(&plain);
    res?;
    println!("备份完成：{}（已加密，0600）", dest.display());
    println!("⚠ 这份产物离不开主密钥：恢复前先确认 master.key 的离线副本可用（panel key check <副本>）。");
    Ok(())
}

/// 加密产物的文件名：`x.db` → `x.db.enc`；已经是 `.enc` 则原样返回。
pub(crate) fn encrypted_path(base: &Path) -> PathBuf {
    if base.extension().and_then(|e| e.to_str()) == Some("enc") {
        return base.to_path_buf();
    }
    PathBuf::from(format!("{}.enc", base.display()))
}

/// 加密产物必须有主密钥才能继续；缺失时给出**三条可执行**的出路。
///
/// 这条闸门存在的意义就是「丢密钥」那一步：没有它，调用方会拿着 `None` 去解密，
/// 报错变成 `aes-gcm decrypt` 失败——用户会以为是产物损坏，然后去重做备份。
fn require_key_for_encrypted(
    path: &Path,
    key: Option<&panel_core::crypto::MasterKey>,
    data_dir: &Path,
    action: &str,
) -> Result<()> {
    if !panel_os::backup::is_encrypted_file(path) || key.is_some() {
        return Ok(());
    }
    let want = crate::bootstrap::master_key_path(data_dir);
    Err(PanelError::Internal(format!(
        "产物已加密，但 {} 不存在——没有它无法{action}。\n\
         出路：\n  \
         ① 找回 master.key 的异地离线副本（`panel key export` 导出的那份），放回该路径\
         （chmod 600），先 `panel key check <副本>` 确认真能开锁；\n  \
         ② 若目录里有 `master.key.bak-<ts>`（换过密钥），用加密该产物那一代的密钥；\n  \
         ③ 确实全丢了：加密产物无救（AES-256-GCM 无密钥即无解），只能改用未加密的 \
         `.db` 产物，并接受库里所有密文失效。\n\
         ⚠ 不要在这里新建一把密钥顶替：新密钥解不开旧产物，只会让现场看起来像「产物损坏」。",
        want.display()
    )))
}

/// 把「加密容器解不开」翻译成运维能照着做的事。
///
/// 原始报错是 `aes-gcm decrypt: aead::Error`——它同时覆盖两种完全不同的处境：
/// ①产物是**上一代密钥**加密的（换过密钥 / 拿错了副本）；②文件真的损坏了。
/// 不翻译的话，用户唯一能想到的动作是「再恢复一次试试」，而恢复会覆盖现有库。
fn explain_decrypt_error(path: &Path, e: PanelError) -> PanelError {
    if !panel_os::backup::is_encrypted_file(path) {
        return e;
    }
    // `PanelError::Internal` 的 Display 自带 "internal: " 前缀；这里再包一层会把
    // 前缀重复成 "internal: internal: ..."。剥一次，只留原始错误文本。
    let raw = format!("{e}");
    let raw = raw.strip_prefix("internal: ").unwrap_or(&raw).to_string();
    PanelError::Internal(format!(
        "{raw}\n\
         （产物是加密容器，这句只说明「当前主密钥解不开它」，有两种可能：\n  \
         ① 它是用**上一代主密钥**加密的——`panel key show` 看当前指纹，\
         找出加密它那一代的 master.key（`master.key.bak-<ts>`）再试；\n  \
         ② 文件已损坏（拷贝中断 / 磁盘坏块）。\n  \
         两种情况都**不要**拿它去覆盖现有库。）"
    ))
}

/// 回收 WAL：checkpoint(TRUNCATE)，把 `-wal` 文件缩回 0。
pub(crate) fn vacuum(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    let layout = build_layout(&os, Some(&cfg));
    let conn = panel_db::open(&layout.sqlite_path(), detect_tier(&*os, &cfg), &cfg.db.synchronous)?;
    panel_db::cleanup::checkpoint_truncate(&conn)?;
    println!("WAL 已回收");
    Ok(())
}

/// 校验备份产物**真的能恢复**（解密 + 解压 + integrity_check），不改动任何库。
pub(crate) fn verify(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>, path: &Path) -> Result<()> {
    // 产物校验是 panel-api 的能力（要同时用 panel-db 的 integrity_check 与
    // panel-os 的解压/解密），CLI 侧只做参数与主密钥装配。
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    let layout = build_layout(&os, Some(&cfg));
    // 「读既有数据」一律用严格加载：密钥缺失时**不能**顺手生成一把新的
    let key = load_existing_master_key(&layout.data_dir());
    require_key_for_encrypted(path, key.as_ref(), &layout.data_dir(), "校验")?;
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;
    let note = rt.block_on(panel_api::routes::backups::verify_artifact_cli(
        path, key.as_ref(), &layout.tmp_dir(),
    )).map_err(|e| explain_decrypt_error(path, e))?;
    println!("✅ 产物可恢复：{note}");
    Ok(())
}

/// 离线恢复面板数据库。**必须先停服务**：在线覆盖会损坏 SQLite WAL。
///
/// 面板自身的库是**运行中的库**：API 侧一直拒绝在线恢复（会损坏 WAL）。但"拒绝"
/// 只解决了一半问题——出事时用户仍要手抄一份 mv 命令，而且没人先验一遍产物是不是
/// 好的。这个子命令把那段手工流程收敛成一条：先验产物 → 留当前态快照 → 原子替换
/// → 清掉旧 -wal/-shm。
///
/// `path` 与 `remote` 二选一：本地盘还在就直接给路径；盘没了用 `--remote`。
pub(crate) fn restore(
    cli: &Cli,
    os: Arc<dyn panel_os::OsAdapter>,
    path: Option<&Path>,
    remote: Option<i64>,
    artifact: Option<&str>,
    force: bool,
) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    let layout = build_layout(&os, Some(&cfg));

    // ① 服务在跑就不能动库：在线覆盖会让 WAL 与主库不一致
    ensure_service_stopped(&cfg, force)?;

    // ② 二选一：本地产物路径，或从远端副本拉回来。
    //    `--remote` 拉下来的文件落在临时目录，**用完必须删**（它不是备份，
    //    留在那里只会让人误以为本地还有一份副本）。
    let mut downloaded: Option<PathBuf> = None;
    let path: PathBuf = match (path, remote) {
        (Some(p), None) => p.to_path_buf(),
        (None, Some(plan_id)) => {
            let db_path = layout.sqlite_path();
            let key = load_existing_master_key(&layout.data_dir());
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;
            let p = rt.block_on(panel_api::routes::backups::fetch_remote_artifact_cli(
                &db_path, plan_id, artifact, &layout.tmp_dir(), key.as_ref(),
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
    let key = load_existing_master_key(&layout.data_dir());
    require_key_for_encrypted(path.as_path(), key.as_ref(), &layout.data_dir(), "恢复")?;
    // 明文产物 + 没有主密钥：能恢复，但要知道自己恢复出来的是什么。
    // 不说这一句的话，用户看到「已恢复」会以为万事大吉，直到某天要读 SSL 私钥。
    if key.is_none() {
        eprintln!(
            "⚠ 本机没有主密钥（data_dir/master.key）：库可以恢复，但库里的密文\
             （SSL 私钥 / 数据库口令 / MFA 密钥 / 远端备份凭据 / LLM API Key）\
             将永久解不开。恢复后请立刻补回离线副本，再 `panel key check <副本>` 验证。"
        );
    }
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;
    let note = rt.block_on(panel_api::routes::backups::verify_artifact_cli(
        path.as_path(), key.as_ref(), &layout.tmp_dir(),
    )).map_err(|e| explain_decrypt_error(path.as_path(), e))?;
    println!("✅ 产物可恢复：{note}");

    // ⑤ 加密产物先解密到临时文件（不原地解密）
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let plain: PathBuf = if panel_os::backup::is_encrypted_file(path.as_path()) {
        std::fs::create_dir_all(layout.tmp_dir()).ok();
        let p = layout.tmp_dir().join(format!("restore-db-{ts}.db"));
        rt.block_on(panel_os::backup::decrypt_file(path.as_path(), &p, key.as_ref().unwrap()))
            .map_err(|e| explain_decrypt_error(path.as_path(), e))?;
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
