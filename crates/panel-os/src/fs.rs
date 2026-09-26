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
}
