//! 主密钥运维：查看指纹、导出离线副本、校验副本可用性、轮换密钥。
//!
//! # 为什么这四条归一域
//! 它们操作的都是**同一份 `master.key`**（或它的副本），前置相同、危险等级同为
//! 「动到唯一能解开全库密文的钥匙」。放在一起之后，"哪些命令会碰主密钥"一眼可见。
//!
//! # 为什么需要 `check` 而不只是比对指纹
//! 指纹只证明「两个文件字节一致」，不证明「这份钥匙真能开这把锁」——
//! 用户完全可能导出了正确的副本，但之后轮换过密钥、或把副本留在了旧版本上。
//! `check` 会真拿副本去解库里的第一条密文，把「看起来对」变成「解得开」。
//! 这正是 `docs/deployment.md` §4.1 里那句「异地副本要定期验证」的可执行版本。
//!
//! # `rotate` 的两条硬前提
//! 1. **服务必须停**：运行中的进程内存里还是旧密钥，换完它会继续用旧密钥加密新
//!    秘密，库里新旧混装 ⇒ 两份密钥都打不开全部。这道闸门与 `restore-db` 共用
//!    [`crate::cmd::db::ensure_service_stopped`]。
//! 2. **不能有旧密钥加密的产物**：备份产物换钥后永久不可解（容器是 AES-GCM，
//!    没有密钥就没救）。故默认拒绝，`--force` 才继续——让用户明确承担这件事。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use panel_core::crypto::MasterKey;
use panel_core::{PanelError, Result};
use sha2::{Digest, Sha256};

use crate::{bootstrap, build_layout, load_cfg, Cli};

/// 指纹长度（字节）；转十六进制后 16 个字符，够人工比对且短到能贴进工单。
const FP_BYTES: usize = 8;

/// 主密钥指纹：`SHA-256(key)` 的前 8 字节十六进制。
///
/// 用哈希而不是密钥本身：指纹可以贴到工单、聊天、监控里做比对，
/// 泄露它不会泄露密钥。**它不是密钥的替代品**，只说「是不是同一把」。
fn fingerprint(k: &MasterKey) -> String {
    let d = Sha256::digest(k.as_bytes());
    d.iter().take(FP_BYTES).map(|b| format!("{b:02x}")).collect()
}

/// 读一个 32 字节主密钥文件（副本或正本）。
///
/// 长度不对时**点名实际字节数**：用户最常见的错是把 `master.key` 和
/// `bootstrap.token`、`.pub` 弄混，只报「格式错误」等于让他自己猜。
fn read_key_file(p: &Path) -> Result<MasterKey> {
    let bytes = std::fs::read(p).map_err(|e| PanelError::Validation {
        field: "path",
        reason: format!("读不到 {}：{e}", p.display()),
    })?;
    MasterKey::from_bytes(&bytes).map_err(|_| PanelError::Validation {
        field: "path",
        reason: format!(
            "{} 不是主密钥：期望 32 字节原始密钥，实际 {} 字节",
            p.display(),
            bytes.len()
        ),
    })
}

/// 取「在用」的主密钥文件路径；不存在时直接报错。
///
/// **不走 `load_master_key`**：那个函数在密钥缺失时会**顺手生成一把新的**。
/// 对备份 / 导出 / 换钥来说，「密钥不见了」必须是一次显式失败——静默生成新钥匙
/// 会让库里所有密文变成永久无法解开的垃圾，而且症状要到下次读秘密才出现。
fn live_key_path(data_dir: &Path) -> Result<PathBuf> {
    let p = bootstrap::master_key_path(data_dir);
    if !p.is_file() {
        return Err(PanelError::Validation {
            field: "master.key",
            reason: format!(
                "{} 不存在。先 `panel init` 或启动一次服务生成主密钥；\
                 若是**丢了**密钥，走 docs/deployment.md §4.1 的丢密钥处置流程",
                p.display()
            ),
        });
    }
    Ok(p)
}

/// 把路径尽量变成绝对路径（目标可以尚不存在）。
fn absolute(p: &Path) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => match parent.canonicalize() {
            Ok(c) => c.join(name),
            Err(_) => p.to_path_buf(),
        },
        _ => p.to_path_buf(),
    }
}

/// `panel key show`：打印路径、权限、指纹。
pub(crate) fn show(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    let cfg = load_cfg(cli, &build_layout(&os, None))?;
    let layout = build_layout(&os, Some(&cfg));
    let p = live_key_path(&layout.data_dir())?;
    let key = read_key_file(&p)?;

    println!("主密钥：{}", p.display());
    match panel_os::fs::mode_of(&p) {
        Some(m) => {
            let perm = m & 0o777;
            println!("权限：{perm:04o}");
            if perm & 0o077 != 0 {
                println!("  ⚠ 权限过宽（组/其他用户可读）。应收紧为 0600：chmod 600 {}", p.display());
            }
        }
        None => println!("权限：读不到"),
    }
    println!("大小：{} 字节", key.as_bytes().len());
    println!("指纹：{}", fingerprint(&key));
    println!();
    println!("指纹不是密钥本身：可以贴进工单/聊天做比对，泄露它不会泄露密钥。");
    println!("异地离线副本：panel key export --out /media/离线介质/master.key");
    println!("副本是否真能开这把锁：panel key check /media/离线介质/master.key");
    Ok(())
}

/// `panel key export --out <路径>`：导出一份 0600 的离线副本。
pub(crate) fn export(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>, out: &Path) -> Result<()> {
    let cfg = load_cfg(cli, &build_layout(&os, None))?;
    let layout = build_layout(&os, Some(&cfg));
    let src = live_key_path(&layout.data_dir())?;
    let key = read_key_file(&src)?;

    // 拒绝写回数据目录：同盘 = 同丢。这条不是形式主义——最常见的"备份"就是把
    // 密钥 cp 到 /var/lib/forkpanel/ 下再改名，机器一炸两份一起没。
    let data_dir = absolute(&layout.data_dir());
    let target = absolute(out);
    if target.starts_with(&data_dir) {
        return Err(PanelError::Validation {
            field: "out",
            reason: format!(
                "目标 {} 在数据目录 {} 内——同盘等于没备份（磁盘/实例一起丢）。\
                 请给异地介质上的路径，例如挂载后的 /mnt/usb/master.key",
                target.display(),
                data_dir.display()
            ),
        });
    }
    if target == absolute(&src) {
        return Err(PanelError::Validation {
            field: "out",
            reason: "目标就是正在用的 master.key，拒绝覆盖".into(),
        });
    }
    if target.exists() {
        return Err(PanelError::Validation {
            field: "out",
            reason: format!("目标已存在：{}（避免误覆盖一份有效的旧副本，请先确认或换路径）", target.display()),
        });
    }

    panel_os::fs::write_private(&target, key.as_bytes(), 0o600)?;
    println!("已导出：{}（0600，指纹 {}）", target.display(), fingerprint(&key));
    println!();
    println!("下一步（必须做完，否则这份副本只是「看着像备份」）：");
    println!("  1. 立刻验证它真能开锁：panel key check {}", target.display());
    println!("  2. 存到与备份**不同**的介质，并记下指纹 {}", fingerprint(&key));
    println!("  3. 换机器/换密钥前，先跑一次 docs/deployment.md §4.1 的三方恢复演练");
    Ok(())
}

/// `panel key check <副本路径>`：比对指纹 + 真拿它解一条密文。
pub(crate) fn check(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>, path: &Path) -> Result<()> {
    let cfg = load_cfg(cli, &build_layout(&os, None))?;
    let layout = build_layout(&os, Some(&cfg));
    let copy = read_key_file(path)?;
    println!("副本：{}（{} 字节，指纹 {}）", path.display(), copy.as_bytes().len(), fingerprint(&copy));

    let live_path = bootstrap::master_key_path(&layout.data_dir());
    if !live_path.is_file() {
        println!("本机没有在用的主密钥（{} 不存在）——只能报告副本指纹，无法比对。", live_path.display());
        return Ok(());
    }
    let live = read_key_file(&live_path)?;
    let fp_live = fingerprint(&live);
    let fp_copy = fingerprint(&copy);
    if fp_copy != fp_live {
        println!("在用：指纹 {fp_live}（{}）", live_path.display());
        return Err(PanelError::Validation {
            field: "path",
            reason: format!(
                "指纹不一致：副本 {fp_copy} ≠ 在用 {fp_live}。这份副本开不了当前的库——\
                 要么是旧密钥（轮换过？），要么根本不是这台机器的密钥。"
            ),
        });
    }
    println!("在用：指纹 {fp_live}（{}）—— 与本副本一致", live_path.display());

    // 真开锁：解库里第一条密文。指纹一致 + 解得开，才算「这份副本可用」。
    match probe_ciphertext(&layout.sqlite_path(), &copy)? {
        Some(where_) => println!("✅ 已用副本解开一条真实密文（{where_}）——这份副本确实能开这把锁"),
        None => println!(
            "⚠ 库里当前没有任何密文（没配 MFA / SSL / 数据库连接 / 远端备份凭据），\
             无法做开锁验证；指纹一致是此刻能给出的最强结论"
        ),
    }
    Ok(())
}

/// 打开库（只读）取一条非空密文，用 `key` 试解。返回命中的位置描述。
///
/// 只读打开：`check` 是诊断命令，绝不能顺带创建 WAL 或改库。
fn probe_ciphertext(db: &Path, key: &MasterKey) -> Result<Option<String>> {
    if !db.is_file() {
        return Ok(None);
    }
    let conn = rusqlite::Connection::open_with_flags(
        db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| PanelError::Database(format!("只读打开 {} 失败：{e}", db.display())))?;

    for (table, column, label) in panel_db::rekey::BLOB_COLUMNS {
        let sql = format!("SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL LIMIT 1");
        let row: Option<(i64, Vec<u8>)> = conn
            .query_row(&sql, [], |r| Ok((r.get(0)?, r.get(1)?)))
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                // 表不存在（老库还没迁移到这一版）⇒ 跳过，不算失败
                rusqlite::Error::SqliteFailure(_, Some(ref m)) if m.contains("no such table") => {
                    Ok(None)
                }
                other => Err(PanelError::Database(format!("{sql}: {other}"))),
            })?;
        if let Some((id, blob)) = row {
            return match key.decrypt(&blob) {
                Ok(_) => Ok(Some(format!("{table}.{column} id={id}（{label}）"))),
                Err(e) => Err(PanelError::Validation {
                    field: "path",
                    reason: format!(
                        "指纹一致但解不开 {table}.{column} id={id}（{label}）：{e}\
                         ——这把钥匙不是这批密文的那把（库里可能混装了多代密钥）"
                    ),
                }),
            };
        }
    }
    Ok(None)
}

/// `panel key rotate [--force] [--yes]`：用新主密钥重加密全库密文并原子换钥。
pub(crate) fn rotate(
    cli: &Cli,
    os: Arc<dyn panel_os::OsAdapter>,
    force: bool,
    yes: bool,
) -> Result<()> {
    let cfg = load_cfg(cli, &build_layout(&os, None))?;
    let layout = build_layout(&os, Some(&cfg));
    let old_path = live_key_path(&layout.data_dir())?;
    let old = read_key_file(&old_path)?;

    // ① 服务在跑就不能换：运行中的进程会继续用旧密钥写新秘密
    super::db::ensure_service_stopped(&cfg, force)?;

    // ② 旧密钥加密的产物在换钥后永久不可解 —— 必须先让人处理掉
    let stale = list_encrypted_artifacts(&layout.backup_dir());
    if !stale.is_empty() && !force {
        let list = stale
            .iter()
            .take(5)
            .map(|p| format!("\n  - {}", p.display()))
            .collect::<String>();
        return Err(PanelError::Validation {
            field: "backup_dir",
            reason: format!(
                "{} 里还有 {} 份**旧密钥加密**的备份产物：{list}\n\
                 换钥后它们将永久无法解密（AES-GCM 无密钥即无解）。\n\
                 先处理掉：`panel restore-db` 恢复到新库 / 用旧密钥解出一份明文 `--no-encrypt` 备份，\
                 或确认可弃后加 --force。",
                layout.backup_dir().display(),
                stale.len()
            ),
        });
    }

    if !yes {
        return Err(PanelError::Validation {
            field: "yes",
            reason: format!(
                "即将用一把**全新的主密钥**重加密库里全部密文（MFA 密钥 / SSL 私钥 / \
                 数据库口令 / 远端备份凭据 / LLM API Key），并把当前密钥改名为 \
                 {}.bak-<时间戳>。换完旧密钥立即作废。\n\
                 确认要换请加 --yes 重跑。",
                old_path.display()
            ),
        });
    }

    // ③ 新密钥**先落盘**再改库：反过来的话，一旦写新密钥失败，库里已是新密文而
    //    磁盘上没有对应钥匙 = 数据当场全废。先落盘最多留一个「多余的新钥匙」。
    let mut bytes = vec![0u8; crate::bootstrap::MASTER_KEY_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let new = MasterKey::from_bytes(&bytes)?;
    let new_path = PathBuf::from(format!("{}.new", old_path.display()));
    panel_os::fs::write_private(&new_path, new.as_bytes(), 0o600)?;
    println!("新密钥已落到 {}（0600，指纹 {}）", new_path.display(), fingerprint(&new));

    // ④ 单事务重加密
    let mut conn = panel_db::open(
        &layout.sqlite_path(),
        crate::detect_tier(&*os, &cfg),
        &cfg.db.synchronous,
    )?;
    let report = match panel_db::rekey::rekey_all(&mut conn, &old, &new) {
        Ok(r) => r,
        Err(e) => {
            // 库已整体回滚，旧密钥仍然有效 ⇒ 删掉多余的新钥匙，原样退出
            let _ = std::fs::remove_file(&new_path);
            return Err(e);
        }
    };
    drop(conn);
    println!("重加密完成：{}（共 {} 行）", report.summary(), report.total());

    // ⑤ 原子换钥：旧 → .bak-<ts>，新 → master.key
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let bak = PathBuf::from(format!("{}.bak-{ts}", old_path.display()));
    if let Err(e) = std::fs::rename(&old_path, &bak) {
        return Err(swap_failed(&old_path, &bak, &new_path, format!("旧密钥改名失败：{e}")));
    }
    if let Err(e) = std::fs::rename(&new_path, &old_path) {
        return Err(swap_failed(&old_path, &bak, &new_path, format!("新密钥改名失败：{e}")));
    }
    panel_os::fs::set_mode(&old_path, 0o600)?;

    println!();
    println!("✅ 换钥完成。新指纹 {}", fingerprint(&new));
    println!("旧密钥留在：{}（0600）", bak.display());
    println!("  确认服务能正常启动、各功能无解密报错后，再删除它。");
    println!("⚠ 换钥前用旧密钥加密的备份产物已经不可解；异地离线副本必须同步更新：");
    println!("   panel key export --out <离线介质>/master.key");
    Ok(())
}

/// 换钥过程中「库已提交、密钥文件没换完」的补救指引。
///
/// 这是唯一会让人当场懵的状态：库里的密文已是新密钥，而 `master.key` 还是旧的。
/// 新密钥**一定还在**磁盘上（第 ③ 步强制先落盘），所以把它写清楚就能救回来。
fn swap_failed(old_path: &Path, bak: &Path, new_path: &Path, what: String) -> PanelError {
    PanelError::Internal(format!(
        "{what}\n\
         ⚠ 库里的密文**已经**用新密钥重加密，而 {} 还是旧密钥——服务此刻起不来是正常的。\n\
         立即执行（新密钥就在盘上，别慌）：\n  \
         mv {} {} 2>/dev/null; mv {} {}\n\
         完成后 panel doctor 确认，再启动服务。",
        old_path.display(),
        old_path.display(),
        bak.display(),
        new_path.display(),
        old_path.display()
    ))
}

/// 列出备份目录里由主密钥加密的产物（`.enc` 结尾），**递归**。
///
/// 必须递归：定时备份计划把产物写进 `dest_dir`（`backup_dir` 下的子目录），
/// 只看顶层会漏掉绝大多数产物——于是「换钥前拦一道」变成了只在手工备份上生效，
/// 而这正是最容易被忽略的假安全。
fn list_encrypted_artifacts(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        if depth > 4 {
            continue; // 防目录环 / 深井：备份目录结构最多两层
        }
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push((p, depth + 1));
            } else if p.extension().and_then(|e| e.to_str()) == Some("enc") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> MasterKey { MasterKey::from_bytes(&[b; 32]).unwrap() }

    #[test]
    fn fingerprint_is_stable_short_and_different_per_key() {
        let a = fingerprint(&key(1));
        assert_eq!(a.len(), FP_BYTES * 2, "8 字节 ⇒ 16 个十六进制字符");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, fingerprint(&key(1)), "同一把密钥指纹必须稳定");
        assert_ne!(a, fingerprint(&key(2)), "不同密钥指纹必须不同");
        // 指纹不能是密钥本身的子串（否则等于泄露）
        let raw = key(1);
        let hex: String = raw.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!hex.contains(&a), "指纹不能是密钥十六进制的片段");
    }

    #[test]
    fn read_key_file_reports_actual_length() {
        let dir = std::env::temp_dir().join(format!("panel-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("short.key");
        std::fs::write(&p, b"tooshort").unwrap();
        // `MasterKey` 刻意不实现 Debug（防止被 `{:?}` 打进日志），所以这里不能用
        // `expect_err`——它要求 Ok 侧的类型可 Debug。手写 match 反而更清楚。
        let err = match read_key_file(&p) {
            Ok(_) => panic!("长度不对必须拒绝"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("8 字节"), "要点名实际字节数，实际：{msg}");
        std::fs::remove_file(&p).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn encrypted_path_appends_once() {
        assert_eq!(super::super::db::encrypted_path(Path::new("/x/a.db")), PathBuf::from("/x/a.db.enc"));
        assert_eq!(super::super::db::encrypted_path(Path::new("/x/a.db.enc")), PathBuf::from("/x/a.db.enc"));
    }
}
