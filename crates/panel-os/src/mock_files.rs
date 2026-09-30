//! 内存文件系统 mock：让文件管理在无 root / 非 Linux 环境下也能跑完整流程，
//! 同时给一致性测试提供一个"平台无关的参考实现"。

use crate::traits::{
    DirEntry, EntryKind, FileProvider, FileStat, ListOpt, SortBy,
};
use panel_core::{PanelError, Result, SafePath};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone)]
enum Node { File(Vec<u8>), Dir }

#[derive(Default)]
pub struct MemFs {
    nodes: BTreeMap<PathBuf, Node>,
}

impl MemFs {
    pub fn new() -> Self {
        let mut m = BTreeMap::new();
        m.insert(PathBuf::from("/"), Node::Dir);
        Self { nodes: m }
    }
    /// 预置一个文件（测试用）
    pub fn seed(&mut self, p: &str, content: &[u8]) {
        self.nodes.insert(PathBuf::from(p), Node::File(content.to_vec()));
    }
    pub fn seed_dir(&mut self, p: &str) {
        self.nodes.insert(PathBuf::from(p), Node::Dir);
    }
}

pub struct MockFiles {
    inner: Arc<Mutex<MemFs>>,
    /// 模拟 Windows：路径大小写不敏感（用于验证"业务层不做大小写假设"）
    pub case_insensitive: bool,
}

impl MockFiles {
    pub fn new(inner: Arc<Mutex<MemFs>>) -> Self { Self { inner, case_insensitive: false } }

    fn sensitive_of(p: &Path) -> bool {
        let s = p.to_string_lossy().to_string();
        const DENY_EXACT: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/sudoers"];
        const DENY_PREFIX: &[&str] = &["/etc/ssh/", "/etc/ssl/private/", "/etc/panel/",
                                       "/root/.ssh/", "/proc/", "/sys/", "/dev/"];
        DENY_EXACT.contains(&s.as_str())
            || DENY_PREFIX.iter().any(|x| s.starts_with(x))
            || s.ends_with("/authorized_keys")
    }

    fn key(&self, p: &Path) -> PathBuf {
        if self.case_insensitive {
            PathBuf::from(p.to_string_lossy().to_lowercase())
        } else { p.to_path_buf() }
    }
}

#[async_trait::async_trait]
impl FileProvider for MockFiles {
    async fn list_dir(&self, dir: &SafePath, opt: ListOpt) -> Result<Vec<DirEntry>> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let base = self.key(dir.as_path());
        let prefix = base.to_string_lossy().to_string();
        let prefix = if prefix.ends_with('/') { prefix } else { format!("{prefix}/") };

        let mut v: Vec<DirEntry> = Vec::new();
        for (p, node) in g.nodes.iter() {
            let ps = p.to_string_lossy().to_string();
            if !ps.starts_with(&prefix) || ps == base.to_string_lossy().as_ref() { continue; }
            let rest = &ps[prefix.len()..];
            if rest.contains('/') { continue; }   // 只列直接子项
            if !opt.show_hidden && rest.starts_with('.') { continue; }
            let (kind, size) = match node {
                Node::File(b) => (EntryKind::File, b.len() as u64),
                Node::Dir => (EntryKind::Dir, 0),
            };
            let child = PathBuf::from(&ps);
            v.push(DirEntry {
                name: rest.to_string(), kind, size,
                mode: Some(if kind == EntryKind::Dir { 0o755 } else { 0o644 }),
                owner: Some("mock".into()),
                modified_unix: 0,
                link_target: None,
                sensitive: Self::sensitive_of(&child),
            });
            if v.len() >= opt.limit { break; }
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
    }

    async fn stat(&self, path: &SafePath) -> Result<FileStat> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let k = self.key(path.as_path());
        match g.nodes.get(&k) {
            Some(Node::File(b)) => Ok(FileStat { kind: EntryKind::File, size: b.len() as u64,
                mode: Some(0o644), owner: Some("mock".into()), modified_unix: 0 }),
            Some(Node::Dir) => Ok(FileStat { kind: EntryKind::Dir, size: 0,
                mode: Some(0o755), owner: Some("mock".into()), modified_unix: 0 }),
            None => Err(PanelError::NotFound(format!("{:?}", path.as_path()))),
        }
    }

    async fn read(&self, path: &SafePath, max_bytes: usize) -> Result<Vec<u8>> {
        self.read_range(path, 0, max_bytes).await
    }

    async fn read_range(&self, path: &SafePath, offset: u64, len: usize) -> Result<Vec<u8>> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let k = self.key(path.as_path());
        match g.nodes.get(&k) {
            Some(Node::File(b)) => {
                let s = offset as usize;
                if s >= b.len() { return Ok(Vec::new()); }
                let e = (s + len).min(b.len());
                Ok(b[s..e].to_vec())
            }
            Some(Node::Dir) => Err(PanelError::Validation { field: "path", reason: "is a directory".into() }),
            None => Err(PanelError::NotFound(format!("{:?}", path.as_path()))),
        }
    }

    /// 同样是"先临时后替换"的语义：先写 tmp 键再改名，失败时不留半写
    async fn write(&self, path: &SafePath, content: &[u8]) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let k = self.key(path.as_path());
        let tmp = PathBuf::from(format!("{}.panel-tmp", k.display()));
        g.nodes.insert(tmp.clone(), Node::File(content.to_vec()));
        g.nodes.remove(&tmp);
        g.nodes.insert(k, Node::File(content.to_vec()));
        Ok(())
    }

    async fn append(&self, path: &SafePath, content: &[u8]) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let k = self.key(path.as_path());
        match g.nodes.get_mut(&k) {
            Some(Node::File(b)) => { b.extend_from_slice(content); Ok(()) }
            Some(Node::Dir) => Err(PanelError::Validation { field: "path", reason: "is a directory".into() }),
            None => { g.nodes.insert(k, Node::File(content.to_vec())); Ok(()) }
        }
    }

    async fn create_dir(&self, path: &SafePath, _recursive: bool) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.nodes.insert(self.key(path.as_path()), Node::Dir);
        Ok(())
    }

    async fn remove(&self, path: &SafePath, allow_dir: bool) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let k = self.key(path.as_path());
        match g.nodes.get(&k) {
            Some(Node::Dir) if !allow_dir => Err(PanelError::Validation {
                field: "path", reason: "refusing to remove a directory without allow_dir".into() }),
            Some(_) => {
                // 递归删除子项（模拟 remove_dir_all）
                let prefix = format!("{}/", k.display());
                let children: Vec<_> = g.nodes.keys()
                    .filter(|p| p.to_string_lossy().starts_with(&prefix))
                    .cloned().collect();
                for c in children { g.nodes.remove(&c); }
                g.nodes.remove(&k);
                Ok(())
            }
            None => Err(PanelError::NotFound(format!("{:?}", path.as_path()))),
        }
    }

    async fn rename(&self, from: &SafePath, to: &SafePath) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let a = self.key(from.as_path());
        let b = self.key(to.as_path());
        match g.nodes.remove(&a) {
            Some(n) => { g.nodes.insert(b, n); Ok(()) }
            None => Err(PanelError::NotFound(format!("{:?}", from.as_path()))),
        }
    }

    async fn copy(&self, from: &SafePath, to: &SafePath) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let a = self.key(from.as_path());
        let b = self.key(to.as_path());
        match g.nodes.get(&a).cloned() {
            Some(n) => { g.nodes.insert(b, n); Ok(()) }
            None => Err(PanelError::NotFound(format!("{:?}", from.as_path()))),
        }
    }

    fn is_sensitive(&self, path: &SafePath) -> bool {
        is_sensitive_str(&path.as_path().to_string_lossy())
    }

    fn is_sensitive_path(&self, path: &std::path::Path) -> bool {
        is_sensitive_str(&path.to_string_lossy())
    }

    fn max_file_bytes(&self) -> usize { 100 * 1024 * 1024 }
}

/// mock 的敏感路径判定，供 `is_sensitive` 与 `is_sensitive_path` **共用**——
/// 两套判定迟早会漂移，而漂移的那一套就是漏网的那一套。
fn is_sensitive_str(s: &str) -> bool {
    // mock 复用与 Linux 相同的判定，保证一致性测试有意义
    const DENY_EXACT: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/sudoers"];
    const DENY_PREFIX: &[&str] = &["/etc/ssh/", "/etc/ssl/private/", "/etc/panel/", "/root/.ssh/",
                                   "/proc/", "/sys/", "/dev/"];
    DENY_EXACT.contains(&s) || DENY_PREFIX.iter().any(|x| s.starts_with(x)) || s.ends_with("/authorized_keys")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(p: &str) -> SafePath { unsafe { SafePath::from_raw(PathBuf::from(p)) } }

    #[tokio::test]
    async fn list_and_read_roundtrip() {
        let mut fs = MemFs::new();
        fs.seed_dir("/www");
        fs.seed("/www/a.txt", b"hello");
        fs.seed("/www/b.txt", b"world");
        let p = MockFiles::new(Arc::new(Mutex::new(fs)));
        let d = sp("/www");
        let list = p.list_dir(&d, ListOpt::default()).await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "a.txt");
        assert_eq!(p.read(&sp("/www/a.txt"), 100).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn hidden_files_respect_opt() {
        let mut fs = MemFs::new();
        fs.seed_dir("/w");
        fs.seed("/w/.env", b"secret");
        fs.seed("/w/index.html", b"x");
        let p = MockFiles::new(Arc::new(Mutex::new(fs)));
        let d = sp("/w");
        let hidden_off = p.list_dir(&d, ListOpt { show_hidden: false, ..Default::default() }).await.unwrap();
        assert_eq!(hidden_off.len(), 1, "默认应隐藏 .env");
        let hidden_on = p.list_dir(&d, ListOpt { show_hidden: true, ..Default::default() }).await.unwrap();
        assert_eq!(hidden_on.len(), 2);
    }

    #[tokio::test]
    async fn dirs_first_is_default() {
        let mut fs = MemFs::new();
        fs.seed_dir("/w");
        fs.seed("/w/z.txt", b"");
        fs.seed_dir("/w/adir");
        let p = MockFiles::new(Arc::new(Mutex::new(fs)));
        let list = p.list_dir(&sp("/w"), ListOpt::default()).await.unwrap();
        assert_eq!(list[0].kind, EntryKind::Dir, "目录应排在前面");
    }

    #[tokio::test]
    async fn remove_dir_requires_opt_in() {
        let mut fs = MemFs::new();
        fs.seed_dir("/w/d");
        let p = MockFiles::new(Arc::new(Mutex::new(fs)));
        assert!(p.remove(&sp("/w/d"), false).await.is_err());
        assert!(p.remove(&sp("/w/d"), true).await.is_ok());
    }

    #[tokio::test]
    async fn sensitive_paths_blocked_in_mock() {
        let p = MockFiles::new(Arc::new(Mutex::new(MemFs::new())));
        assert!(p.is_sensitive(&sp("/etc/shadow")));
        assert!(p.is_sensitive(&sp("/root/.ssh/authorized_keys")));
        assert!(!p.is_sensitive(&sp("/var/www/index.html")));
    }

    #[tokio::test]
    async fn limit_caps_result_size() {
        let mut fs = MemFs::new();
        fs.seed_dir("/w");
        for i in 0..50 { fs.seed(&format!("/w/f{i}.txt"), b""); }
        let p = MockFiles::new(Arc::new(Mutex::new(fs)));
        let list = p.list_dir(&sp("/w"), ListOpt { limit: 10, ..Default::default() }).await.unwrap();
        assert!(list.len() <= 10, "必须受 limit 约束，防止大目录打爆内存");
    }

    #[tokio::test]
    async fn rename_and_copy() {
        let mut fs = MemFs::new();
        fs.seed("/w/a.txt", b"data");
        let p = MockFiles::new(Arc::new(Mutex::new(fs)));
        p.rename(&sp("/w/a.txt"), &sp("/w/b.txt")).await.unwrap();
        assert_eq!(p.read(&sp("/w/b.txt"), 10).await.unwrap(), b"data");
        p.copy(&sp("/w/b.txt"), &sp("/w/c.txt")).await.unwrap();
        assert_eq!(p.read(&sp("/w/c.txt"), 10).await.unwrap(), b"data");
    }
}
