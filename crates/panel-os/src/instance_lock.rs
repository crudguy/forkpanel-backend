//! 单实例排他锁：一个 `panel serve` 进程对应一个 `<data_dir>/panel.lock`。
//!
//! 为什么需要（生产就绪度 §3.6 / G9）：
//! ① 启动期 `migrate::apply` 发生在端口 bind **之前**，两个进程同时启动会读到同一个
//!    schema_migrations 版本并各自执行 DDL，出现 `table already exists` /
//!    `database is locked`；② 后台 10 个周期任务是进程内 tokio 定时器，双实例会
//!    各跑一遍备份 / 证书续期 / 清理，且 `last_snapshot` 各持一份；③ WriterActor
//!    只做进程内串行化，跨进程仍是 SQLite 库级独占写锁，实测并发写吞吐降 47%。
//!
//! 用 `flock(LOCK_EX | LOCK_NB)` 而非「检查 pid 文件」：后者在进程被 SIGKILL 后
//! 会留下陈旧 pid 文件，导致永远起不来；flock 由内核持有，fd 关闭（含进程崩溃）
//! 自动释放。锁文件里的 PID 只用于诊断，不参与判定。
//!
//! 项目只支持 Linux，故直接用 libc::flock，不做 cfg 分支。

use panel_core::{PanelError, Result};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::Path;

/// 持有期间独占；drop（或进程退出）时释放。
#[derive(Debug)]
pub struct InstanceLock {
    file: File,
}

/// 尝试获取实例锁。已被占用时返回带持有者 PID 的明确错误，**不等待**。
/// 调用方应把返回值保存在整个进程生命周期内（如 `let _lock = ...`）。
pub fn acquire(data_dir: &Path) -> Result<InstanceLock> {
    std::fs::create_dir_all(data_dir).map_err(|e| PanelError::Internal(
        format!("创建数据目录 {} 失败: {e}", data_dir.display())))?;
    let path = data_dir.join("panel.lock");
    let mut file = OpenOptions::new()
        .create(true)
        // 锁文件内容只是诊断用的 PID，不因 open 就截断；拿到锁后自己 set_len(0)。
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| PanelError::Internal(format!("打开实例锁 {} 失败: {e}", path.display())))?;

    // SAFETY: fd 来自上面的 File，在作用域内有效；flock 只操作内核锁表。
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            let holder = std::fs::read_to_string(&path).unwrap_or_default();
            return Err(PanelError::Internal(format!(
                "已有 panel 实例持有 {}（锁文件记录 pid={}）。\
                 同一数据目录只允许一个 serve / migrate / init 进程；\
                 请确认已有实例在正常服务，或停掉它后再启动。",
                path.display(), holder.trim()
            )));
        }
        return Err(PanelError::Internal(format!(
            "获取实例锁 {} 失败: {e}", path.display())));
    }

    // PID 只用于诊断；写失败不影响锁本身（锁由 fd 持有）。
    let _ = file.set_len(0);
    let _ = writeln!(file, "{}", std::process::id());
    let _ = file.flush();
    Ok(InstanceLock { file })
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // 进程正常退出时显式解锁；SIGKILL 下 fd 由内核关闭，锁同样释放。
        // SAFETY: fd 在本结构体存活期间有效。
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fp-instance-lock-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn second_acquire_is_rejected_with_diagnostic() {
        let d = dir("exclusive");
        let a = acquire(&d).expect("首个实例应拿到锁");
        let pid = std::process::id().to_string();
        assert_eq!(std::fs::read_to_string(d.join("panel.lock")).unwrap().trim(), pid);
        let err = acquire(&d).expect_err("第二个实例必须被硬拒绝");
        let msg = err.to_string();
        assert!(msg.contains("已有 panel 实例"), "诊断应点明是实例冲突: {msg}");
        assert!(msg.contains(&pid), "诊断应带持有者 pid: {msg}");
        drop(a);
        assert!(acquire(&d).is_ok(), "锁释放后应可再次获取");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn different_data_dirs_do_not_conflict() {
        let a = dir("a");
        let b = dir("b");
        let la = acquire(&a).unwrap();
        let lb = acquire(&b).unwrap();
        drop(la);
        drop(lb);
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }
}
