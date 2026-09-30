//! Linux 文件管理实现。
//!
//! # 安全要点（每一条都对应一个真实事故模式）
//!
//! 1. **写入先临时后原子替换**：直接 `fs::write` 在进程被杀/磁盘满时会留下截断的文件。
//!    做法是写 `xxx.tmp-<pid>` 再 `rename`（同分区 rename 是原子的）。
//! 2. **符号链接**：`list_dir` 用 `symlink_metadata` 而非 `metadata`，
//!    否则会把链外的目标当作链内条目，绕过沙箱（经典 TOCTOU）。
//! 3. **敏感路径黑名单**：`/etc/shadow`、`authorized_keys`、面板自身密钥等。
//!    注意：黑名单**不能**替代沙箱——沙箱是主防线，黑名单是"即使沙箱配错也别把密钥读出去"。
//! 4. **递归删除上限**：防止 `rm -rf` 一个深目录把 IO 打满。

use panel_core::{PanelError, Result, SafePath};
use super::{
    DirEntry, EntryKind, FileProvider, FileStat, ListOpt, SortBy,
};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

pub struct LinuxFileProvider;

/// 递归删除的条目上限。超过即拒绝——要么是误操作，要么该交给专门工具处理。
const MAX_REMOVE_ENTRIES: usize = 50_000;

/// 敏感路径判定。**刻意只做前缀/精确匹配**，不做模糊匹配（模糊匹配容易误伤且难审计）。
pub fn is_sensitive_path(p: &Path) -> bool {
    let s = match p.to_str() { Some(s) => s, None => return false };
    const DENY_EXACT: &[&str] = &[
        "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
    ];
    const DENY_PREFIX: &[&str] = &[
        "/etc/ssh/", "/etc/ssl/private/", "/etc/panel/",
        "/root/.ssh/", "/proc/", "/sys/", "/dev/",
    ];
    if DENY_EXACT.contains(&s) { return true; }
    if DENY_PREFIX.iter().any(|x| s.starts_with(x)) { return true; }
    // 任何用户的 authorized_keys（面板绝不该通过 Web 改它）
    if s.ends_with("/authorized_keys") || s.ends_with("/.ssh/id_rsa") { return true; }
    false
}

#[async_trait::async_trait]
impl FileProvider for LinuxFileProvider {
    async fn list_dir(&self, dir: &SafePath, opt: ListOpt) -> Result<Vec<DirEntry>> {
        let dir = dir.as_path().to_path_buf();
        // 阻塞型 IO 放到 blocking 池；列表可能很大
        tokio::task::spawn_blocking(move || -> Result<Vec<DirEntry>> {
            let mut v = Vec::new();
            let rd = std::fs::read_dir(&dir)
                .map_err(|e| PanelError::Io(format!("read_dir {}: {e}", dir.display())))?;
            for entry in rd {
                let e = entry.map_err(|e| PanelError::Io(e.to_string()))?;
                let name = e.file_name().to_string_lossy().to_string();
                if !opt.show_hidden && name.starts_with('.') { continue; }
                // 关键：symlink_metadata，不跟随链接（防沙箱绕过）。
                // 注意：DirEntry 上没有 symlink_metadata 方法，需对 path 调用 std::fs 版本。
                let md = match std::fs::symlink_metadata(e.path()) {
                    Ok(m) => m,
                    Err(_) => continue,   // 断裂链接等，跳过而非报错
                };
                let kind = if md.file_type().is_symlink() {
                    EntryKind::Symlink
                } else if md.file_type().is_dir() {
                    EntryKind::Dir
                } else if md.file_type().is_file() {
                    EntryKind::File
                } else {
                    EntryKind::Other
                };
                if v.len() >= opt.limit { break; }
                let sensitive = is_sensitive_path(&e.path());
                v.push(DirEntry {
                    name,
                    kind,
                    size: if kind == EntryKind::Dir { 0 } else { md.len() },
                    mode: Some(md.permissions().mode()),
                    owner: uid_to_name(md.uid()),
                    modified_unix: md.mtime(),
                    link_target: if kind == EntryKind::Symlink {
                        std::fs::read_link(e.path()).ok()
                            .map(|p| p.to_string_lossy().to_string())
                    } else { None },
                    sensitive,
                });
            }

            if opt.dirs_first {
                v.sort_by(|a, b| {
                    let ad = a.kind == EntryKind::Dir;
                    let bd = b.kind == EntryKind::Dir;
                    bd.cmp(&ad).then_with(|| a.name.cmp(&b.name))
                });
            } else {
                match opt.sort {
                    SortBy::Name => v.sort_by(|a, b| a.name.cmp(&b.name)),
                    SortBy::Size => v.sort_by(|a, b| b.size.cmp(&a.size)),
                    SortBy::Modified => v.sort_by(|a, b| b.modified_unix.cmp(&a.modified_unix)),
                }
            }
            Ok(v)
        })
        .await
        .map_err(|e| PanelError::Internal(format!("list task: {e}")))?
    }

    async fn stat(&self, path: &SafePath) -> Result<FileStat> {
        let p = path.as_path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let md = std::fs::symlink_metadata(&p)
                .map_err(|e| PanelError::Io(format!("stat {}: {e}", p.display())))?;
            let kind = if md.file_type().is_symlink() { EntryKind::Symlink }
                else if md.file_type().is_dir() { EntryKind::Dir }
                else if md.file_type().is_file() { EntryKind::File }
                else { EntryKind::Other };
            Ok(FileStat {
                kind, size: md.len(),
                mode: Some(md.permissions().mode()),
                owner: uid_to_name(md.uid()),
                modified_unix: md.mtime(),
            })
        }).await.map_err(|e| PanelError::Internal(e.to_string()))?
    }

    async fn read(&self, path: &SafePath, max_bytes: usize) -> Result<Vec<u8>> {
        self.read_range(path, 0, max_bytes).await
    }

    async fn read_range(&self, path: &SafePath, offset: u64, len: usize) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let p = path.as_path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            // 拒绝读目录
            let md = std::fs::symlink_metadata(&p)
                .map_err(|e| PanelError::Io(e.to_string()))?;
            if md.file_type().is_dir() {
                return Err(PanelError::Validation { field: "path", reason: "is a directory".into() });
            }
            let mut f = std::fs::File::open(&p)
                .map_err(|e| PanelError::Io(format!("open {}: {e}", p.display())))?;
            if offset > 0 {
                f.seek(SeekFrom::Start(offset))
                    .map_err(|e| PanelError::Io(format!("seek {}: {e}", p.display())))?;
            }
            let mut buf = vec![0u8; len];
            let n = f.read(&mut buf).map_err(|e| PanelError::Io(e.to_string()))?;
            buf.truncate(n);
            Ok(buf)
        }).await.map_err(|e| PanelError::Internal(e.to_string()))?
    }

    async fn write(&self, path: &SafePath, content: &[u8]) -> Result<()> {
        let p = path.as_path().to_path_buf();
        let data = content.to_vec();
        tokio::task::spawn_blocking(move || {
            // 原子写入：临时文件 + rename。直接 write 会在崩溃时留下截断文件。
            let dir = p.parent()
                .ok_or_else(|| PanelError::Validation { field: "path", reason: "no parent dir".into() })?;
            let tmp = dir.join(format!(".panel-tmp-{}.{}", std::process::id(),
                p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "f".into())));
            std::fs::write(&tmp, &data)
                .map_err(|e| PanelError::Io(format!("write tmp: {e}")))?;
            // 同步落盘，避免 rename 后数据仍在页缓存（断电丢失）
            if let Ok(f) = std::fs::File::open(&tmp) { let _ = f.sync_all(); }
            std::fs::rename(&tmp, &p).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                PanelError::Io(format!("rename: {e}"))
            })?;
            Ok(())
        }).await.map_err(|e| PanelError::Internal(e.to_string()))?
    }

    async fn append(&self, path: &SafePath, content: &[u8]) -> Result<()> {
        use std::io::Write;
        let p = path.as_path().to_path_buf();
        let data = content.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&p)
                .map_err(|e| PanelError::Io(e.to_string()))?;
            f.write_all(&data).map_err(|e| PanelError::Io(e.to_string()))?;
            Ok(())
        }).await.map_err(|e| PanelError::Internal(e.to_string()))?
    }

    async fn create_dir(&self, path: &SafePath, recursive: bool) -> Result<()> {
        let p = path.as_path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            if recursive { std::fs::create_dir_all(&p) } else { std::fs::create_dir(&p) }
                .map_err(|e| PanelError::Io(format!("mkdir {}: {e}", p.display())))
        }).await.map_err(|e| PanelError::Internal(e.to_string()))?
    }

    async fn remove(&self, path: &SafePath, allow_dir: bool) -> Result<()> {
        let p = path.as_path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let md = std::fs::symlink_metadata(&p)
                .map_err(|e| PanelError::Io(e.to_string()))?;
            if md.file_type().is_dir() {
                if !allow_dir {
                    return Err(PanelError::Validation {
                        field: "path", reason: "refusing to remove a directory without allow_dir".into() });
                }
                // 规模检查：超过上限拒绝，避免误删巨型目录把 IO 打满
                let n = count_entries(&p, MAX_REMOVE_ENTRIES)?;
                if n > MAX_REMOVE_ENTRIES {
                    return Err(PanelError::Validation {
                        field: "path", reason: format!("directory has >{MAX_REMOVE_ENTRIES} entries, refused") });
                }
                std::fs::remove_dir_all(&p)
            } else {
                std::fs::remove_file(&p)
            }.map_err(|e| PanelError::Io(format!("remove {}: {e}", p.display())))
        }).await.map_err(|e| PanelError::Internal(e.to_string()))?
    }

    async fn rename(&self, from: &SafePath, to: &SafePath) -> Result<()> {
        let (a, b) = (from.as_path().to_path_buf(), to.as_path().to_path_buf());
        tokio::task::spawn_blocking(move || {
            std::fs::rename(&a, &b).map_err(|e| PanelError::Io(format!("rename: {e}")))
        }).await.map_err(|e| PanelError::Internal(e.to_string()))?
    }

    async fn copy(&self, from: &SafePath, to: &SafePath) -> Result<()> {
        let (a, b) = (from.as_path().to_path_buf(), to.as_path().to_path_buf());
        tokio::task::spawn_blocking(move || {
            let md = std::fs::symlink_metadata(&a)
                .map_err(|e| PanelError::Io(e.to_string()))?;
            if md.file_type().is_dir() {
                copy_dir_recursive(&a, &b)
            } else {
                std::fs::copy(&a, &b).map(|_| ())
                    .map_err(|e| PanelError::Io(format!("copy: {e}")))
            }
        }).await.map_err(|e| PanelError::Internal(e.to_string()))?
    }

    fn is_sensitive(&self, path: &SafePath) -> bool { is_sensitive_path(path.as_path()) }

    // 裸路径版本：与上一行共用同一个自由函数，两处判定不会分叉
    fn is_sensitive_path(&self, path: &Path) -> bool { is_sensitive_path(path) }

    async fn merge_chunks(&self, parts: &[std::path::PathBuf], dst: &SafePath) -> Result<u64> {
        let parts = parts.to_vec();
        let dst = dst.as_path().to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            use std::io::{Read, Write};
            // 与 write 同纪律：先写临时文件、再原子替换。
            // 否则中途失败会留下一个"看起来完整"的截断文件——那比没有更危险。
            let tmp = dst.with_extension(format!(
                "merging-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let merged = (|| -> Result<u64> {
                let mut w = std::fs::File::create(&tmp)
                    .map_err(|e| PanelError::Io(format!("create {}: {e}", tmp.display())))?;
                let mut total = 0u64;
                let mut buf = vec![0u8; 1024 * 1024];
                for p in &parts {
                    let mut r = std::fs::File::open(p)
                        .map_err(|e| PanelError::Io(format!("open {}: {e}", p.display())))?;
                    loop {
                        // 短读是正常的：读多少写多少，不做"必须读满"的假设
                        let n = r.read(&mut buf).map_err(|e| PanelError::Io(e.to_string()))?;
                        if n == 0 { break; }
                        w.write_all(&buf[..n]).map_err(|e| PanelError::Io(e.to_string()))?;
                        total += n as u64;
                    }
                }
                w.sync_all().map_err(|e| PanelError::Io(e.to_string()))?;
                drop(w);
                Ok(total)
            })();
            match merged {
                Ok(total) => {
                    std::fs::rename(&tmp, &dst).map_err(|e| {
                        PanelError::Io(format!("rename to {}: {e}", dst.display()))
                    })?;
                    Ok(total)
                }
                Err(e) => {
                    // 失败即清掉半成品，不给下一次留垃圾
                    let _ = std::fs::remove_file(&tmp);
                    Err(e)
                }
            }
        })
        .await
        .map_err(|e| PanelError::Internal(format!("merge join: {e}")))?
    }

    fn max_file_bytes(&self) -> usize { 100 * 1024 * 1024 }
}

fn count_entries(dir: &Path, cap: usize) -> Result<usize> {
    let mut n = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| PanelError::Io(e.to_string()))? {
            let e = e.map_err(|e| PanelError::Io(e.to_string()))?;
            n += 1;
            if n > cap { return Ok(n); }
            let md = e.metadata().map_err(|e| PanelError::Io(e.to_string()))?;
            if md.is_dir() { stack.push(e.path()); }
        }
    }
    Ok(n)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| PanelError::Io(e.to_string()))?;
    for e in std::fs::read_dir(src).map_err(|e| PanelError::Io(e.to_string()))? {
        let e = e.map_err(|e| PanelError::Io(e.to_string()))?;
        let t = dst.join(e.file_name());
        let md = e.metadata().map_err(|e| PanelError::Io(e.to_string()))?;
        if md.is_dir() { copy_dir_recursive(&e.path(), &t)?; }
        else { std::fs::copy(e.path(), &t).map_err(|e| PanelError::Io(e.to_string()))?; }
    }
    Ok(())
}

/// uid → 用户名。**绝不用子进程**（`id -un` 会引入命令注入面），只读 /etc/passwd。
fn uid_to_name(uid: u32) -> Option<String> {
    let s = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in s.lines() {
        let mut f = line.split(':');
        let name = f.next()?;
        if f.next() != Some("x") { continue; }
        let u = f.next()?.parse::<u32>().ok()?;
        if u == uid { return Some(name.to_string()); }
    }
    Some(uid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_paths_are_blocked() {
        assert!(is_sensitive_path(Path::new("/etc/shadow")));
        assert!(is_sensitive_path(Path::new("/etc/sudoers")));
        assert!(is_sensitive_path(Path::new("/etc/ssh/sshd_config")));
        assert!(is_sensitive_path(Path::new("/root/.ssh/authorized_keys")));
        assert!(is_sensitive_path(Path::new("/proc/1/mem")));
        assert!(is_sensitive_path(Path::new("/etc/panel/config.toml")));
    }

    #[test]
    fn normal_paths_are_not_blocked() {
        // 黑名单不能误伤正常站点文件，否则面板没法用
        assert!(!is_sensitive_path(Path::new("/var/www/index.html")));
        assert!(!is_sensitive_path(Path::new("/var/www/.htaccess")));
        assert!(!is_sensitive_path(Path::new("/etc/nginx/nginx.conf")));
        assert!(!is_sensitive_path(Path::new("/var/log/panel/panel.log")));
    }

    #[test]
    fn remove_cap_is_conservative() {
        assert!(MAX_REMOVE_ENTRIES >= 10_000, "上限太低会阻碍正常删除");
        assert!(MAX_REMOVE_ENTRIES <= 200_000, "上限太高起不到保护 IO 的作用");
    }

    #[tokio::test]
    async fn write_is_atomic_and_readable() {
        let d = std::env::temp_dir().join(format!("panel-fs-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("a.txt");
        let sp = unsafe { SafePath::from_raw(f.clone()) };
        let p = LinuxFileProvider;
        p.write(&sp, b"hello").await.unwrap();
        assert_eq!(p.read(&sp, 1024).await.unwrap(), b"hello");
        // 不应残留临时文件
        let leftover: Vec<_> = std::fs::read_dir(&d).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".panel-tmp"))
            .collect();
        assert!(leftover.is_empty(), "原子写入后不应残留临时文件");
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn read_range_respects_offset() {
        let d = std::env::temp_dir().join(format!("panel-rr-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("b.bin");
        std::fs::write(&f, b"0123456789").unwrap();
        let sp = unsafe { SafePath::from_raw(f) };
        let p = LinuxFileProvider;
        assert_eq!(p.read_range(&sp, 3, 4).await.unwrap(), b"3456");
        assert_eq!(p.read(&sp, 3).await.unwrap(), b"012");
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn remove_dir_requires_explicit_opt_in() {
        let d = std::env::temp_dir().join(format!("panel-rm-{}", std::process::id()));
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let sp = unsafe { SafePath::from_raw(sub) };
        let p = LinuxFileProvider;
        assert!(p.remove(&sp, false).await.is_err(), "未显式允许时不得删目录");
        assert!(p.remove(&sp, true).await.is_ok());
        std::fs::remove_dir_all(&d).ok();
    }
}
