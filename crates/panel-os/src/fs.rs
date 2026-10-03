//! 同步文件系统 / 权限 / 终端原语。
//!
//! # 为什么这些看似琐碎的函数要在 OS 层
//! `chmod`、`getuid`、关闭终端回显都是**平台专有**的。若散落在 CLI 里，
//! 就会出现 `#[cfg(unix)]` 长在业务层的情况 —— 这正是 CI 门禁禁止的形态。
//! 集中到这里之后，Windows 接入只需在本文件补 `#[cfg(windows)]` 分支。

use panel_core::{PanelError, Result};
use std::path::Path;

/// 是否以特权用户运行（POSIX: uid 0；Windows: 管理员令牌）
pub fn is_root() -> bool {
    #[cfg(unix)]
    { unsafe { libc::geteuid() == 0 } }
    #[cfg(windows)]
    { false }   // 接入 Windows 时需改为 CheckTokenMembership 判断
    #[cfg(not(any(unix, windows)))]
    { false }
}

/// 设置文件/目录权限位。非 POSIX 平台降级为"只读标志"语义。
pub fn set_mode(p: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
            .map_err(|e| PanelError::Internal(format!("chmod {}: {e}", p.display())))
    }
    #[cfg(not(unix))]
    {
        // Windows：0o600 语义 → 去除只读标志由调用方决定；此处仅记录
        let _ = (p, mode);
        Ok(())
    }
}

/// 读取权限位（POSIX）。非 POSIX 返回 None，调用方据此跳过该项检查。
pub fn mode_of(p: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).ok().map(|m| m.permissions().mode())
    }
    #[cfg(not(unix))]
    { let _ = p; None }
}

/// 创建目录（递归）并设置权限
pub fn ensure_dir(p: &Path, mode: u32) -> Result<()> {
    std::fs::create_dir_all(p)
        .map_err(|e| PanelError::Internal(format!("mkdir {}: {e}", p.display())))?;
    set_mode(p, mode)
}

/// 写入文件并设置权限（主密钥等敏感文件用 0600）
pub fn write_private(p: &Path, data: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = p.parent() { std::fs::create_dir_all(parent).ok(); }
    std::fs::write(p, data)
        .map_err(|e| PanelError::Internal(format!("write {}: {e}", p.display())))?;
    set_mode(p, mode)
}

/// 检查数据目录所在文件系统，返回 `(文件系统名, 是否为网络文件系统)`。
///
/// 为什么必须走这里：SQLite 的 WAL 依赖共享内存与可靠的 fsync 语义，
/// 在 NFS / SMB / 9p 上会静默损坏。启动期必须**拒绝**而非警告。
/// 平台差异（statfs 魔数 / GetVolumeInformation）在各自实现内，业务层只看到布尔值。
pub fn check_data_dir(dir: &Path) -> Result<(String, bool)> {
    #[cfg(target_os = "linux")]
    { crate::linux::check_data_dir_fs(dir) }
    #[cfg(target_os = "macos")]
    { crate::linux::check_data_dir_fs(dir) }   // BSD 系 statfs 语义相同
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Windows：检测网络驱动器（GetDriveType == DRIVE_REMOTE）
        let _ = dir;
        Ok(("unknown".into(), false))
    }
}

/// 从终端读取一行且**不回显**（口令输入）。
/// 无论读取成功与否都恢复终端回显，避免失败后终端"卡住"。
/// 保留目录里**最近** `keep` 个文件名以 `prefix` 开头的普通文件，删除更旧的。
///
/// 用途：带时间戳/自增 id 的备份与日志（如 `sshd.conf.panel.bak-<ts>`、
/// `panel-task-<id>.log`）每次生成新文件、从不复用，不清理会无限增长。
///
/// 排序依据**修改时间而非文件名**——文件名里的时间戳格式可能变，mtime 才可靠。
///
/// 失败一律静默（返回已删除个数）：清理是附带的收尾动作，
/// 不该因为它失败就让"保存配置""写任务日志"这类主操作报错。
pub fn prune_keep_newest(dir: &Path, prefix: &str, keep: usize) -> usize {
    if keep == 0 { return 0; }
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf)> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(prefix))
                    .unwrap_or(false)
        })
        .filter_map(|p| {
            std::fs::metadata(&p).ok().and_then(|m| m.modified().ok()).map(|t| (t, p))
        })
        .collect();
    // 新的在前：mtime 降序
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    let mut removed = 0;
    for (_, p) in entries.iter().skip(keep) {
        if std::fs::remove_file(p).is_ok() { removed += 1; }
    }
    removed
}

pub fn read_password(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    #[cfg(unix)]
    { read_hidden_unix() }
    #[cfg(not(unix))]
    { read_plain() }
}

#[cfg(unix)]
fn read_hidden_unix() -> Result<String> {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            return read_plain();
        }
        let original = term;
        term.c_lflag &= !libc::ECHO;
        if libc::tcsetattr(fd, libc::TCSANOW, &term) != 0 {
            return read_plain();
        }
        let mut s = String::new();
        let r = std::io::stdin().read_line(&mut s);
        libc::tcsetattr(fd, libc::TCSANOW, &original);   // 必须恢复
        eprintln!();
        match r {
            Ok(_) => Ok(s.trim().to_string()),
            Err(e) => Err(PanelError::Internal(e.to_string())),
        }
    }
}

fn read_plain() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)
        .map_err(|e| PanelError::Internal(format!("read stdin: {e}")))?;
    Ok(s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_file_is_0600() {
        let d = std::env::temp_dir().join(format!("panel-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_dir(&d, 0o700).unwrap();
        let f = d.join("k.bin");
        write_private(&f, b"secret", 0o600).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"secret");
        #[cfg(unix)]
        assert_eq!(mode_of(&f).unwrap() & 0o777, 0o600);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn mode_of_missing_file_is_none() {
        assert!(mode_of(Path::new("/definitely/not/here")).is_none());
    }

    #[test]
    fn prune_keeps_newest_and_only_touches_matching_prefix() {
        let d = std::env::temp_dir().join(format!("panel-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_dir(&d, 0o700).unwrap();

        // 三份同名前缀的备份，mtime 依次变旧（0 最新、2 最旧）
        let base = std::time::SystemTime::now();
        for i in 0..3 {
            let f = d.join(format!("sshd.conf.panel.bak-{i}"));
            std::fs::write(&f, b"x").unwrap();
            std::fs::File::options().write(true).open(&f).unwrap()
                .set_modified(base - std::time::Duration::from_secs(i * 10)).unwrap();
        }
        // 同目录但**前缀不同**的文件：绝不能被误删
        let other = d.join("sshd.conf.keepme");
        std::fs::write(&other, b"x").unwrap();

        assert_eq!(prune_keep_newest(&d, "sshd.conf.panel.bak-", 1), 2,
            "保留 1 份 → 应删掉其余 2 份");
        assert!(d.join("sshd.conf.panel.bak-0").exists(), "最新的一份必须留下");
        assert!(!d.join("sshd.conf.panel.bak-1").exists());
        assert!(!d.join("sshd.conf.panel.bak-2").exists());
        assert!(other.exists(), "非本前缀的文件被误删了（前缀匹配失效）");

        // 边界：目录不存在、前缀无匹配，都静默返回 0（清理失败不该打断主操作）
        assert_eq!(prune_keep_newest(Path::new("/definitely/not/here"), "x-", 1), 0);
        assert_eq!(prune_keep_newest(&d, "no-such-prefix-", 1), 0);
        // keep=0 表示"不保留"应视为无效参数，直接不动任何文件
        assert_eq!(prune_keep_newest(&d, "sshd.conf.panel.bak-", 0), 0);

        std::fs::remove_dir_all(&d).ok();
    }
}
