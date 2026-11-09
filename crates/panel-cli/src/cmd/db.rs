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
    atomic_replace_db, build_layout, detect_tier, is_db_artifact_name, load_cfg, load_master_key, Cli,
};


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
/// `out` 为空时落到 `<backup_dir>/panel-<ts>.db`。
pub(crate) fn backup(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>, out: Option<&Path>) -> Result<()> {
    let layout0 = build_layout(&os, None);
    let cfg = load_cfg(cli, &layout0)?;
    let layout = build_layout(&os, Some(&cfg));
    let dest = out.map(|p| p.to_path_buf()).unwrap_or_else(|| {
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
    let path: PathBuf = match (path, remote) {
        (Some(p), None) => p.to_path_buf(),
        (None, Some(plan_id)) => {
            let db_path = layout.sqlite_path();
            let key = load_master_key(&layout.data_dir());
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
