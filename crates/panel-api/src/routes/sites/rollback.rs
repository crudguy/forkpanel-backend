//! 站点配置下发的回滚快照（生产就绪度 §3.3 S4 / G7）。
//!
//! 旧链路是「deploy（已落盘）→ prune 旧配置 → reload → 落库」。reload 失败或
//! 落库失败时直接返回，磁盘上是新配置、nginx 内存里仍是旧配置（或旧文件已被删）、
//! SQLite 里还是旧记录 —— 三方分叉，下次重启 nginx 才突然加载那份「失败」的配置。
//! 这里在 deploy 之前抓一份文件快照，任一后续步骤失败就恢复，并 best-effort
//! reload 让服务重新加载旧配置。
//!
//! 与 `firewall.rs` 的 `restore_snapshot` 同款模式；防火墙已验证「失败自动回滚」
//! 在本仓可行，这里是把它复用到 Web 服务器下发链路。

use super::Shared;
use std::path::{Path, PathBuf};

/// 下发前的文件状态。`target_before = None` 表示文件原本不存在（新建站点），
/// 此时回滚 = 删掉刚写的文件，而不是写一个空文件。
#[derive(Debug, Clone)]
pub struct DeploySnapshot {
    pub target: PathBuf,
    pub target_before: Option<String>,
    pub stale: Option<PathBuf>,
    pub stale_before: Option<String>,
}

impl DeploySnapshot {
    /// 在 deploy **之前**调用。`stale` 是域名改动时将被 `prune_stale_conf` 删掉的旧配置路径。
    pub async fn capture(target: &Path, stale: Option<&Path>) -> Self {
        let target_before = tokio::fs::read_to_string(target).await.ok();
        // 路径相同不算 stale（prune_stale_conf 自己会跳过），别把目标文件读两遍
        let stale = stale.filter(|p| *p != target).map(Path::to_path_buf);
        let stale_before = match stale.as_deref() {
            Some(p) => tokio::fs::read_to_string(p).await.ok(),
            None => None,
        };
        Self { target: target.to_path_buf(), target_before, stale, stale_before }
    }

    /// 恢复文件到下发前状态；返回失败项（空 = 完全恢复）。
    /// 只做文件恢复，不 reload —— reload 由 [`rollback_after_failure`] 统一 best-effort 执行。
    pub async fn restore(&self) -> Vec<String> {
        let mut errs = Vec::new();
        match &self.target_before {
            Some(old) => {
                if let Err(e) = tokio::fs::write(&self.target, old).await {
                    errs.push(format!("恢复 {} 失败: {e}", self.target.display()));
                }
            }
            None => match tokio::fs::remove_file(&self.target).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => errs.push(format!("清理 {} 失败: {e}", self.target.display())),
            },
        }
        if let (Some(p), Some(content)) = (&self.stale, &self.stale_before) {
            if let Err(e) = tokio::fs::write(p, content).await {
                errs.push(format!("恢复旧配置 {} 失败: {e}", p.display()));
            }
        }
        errs
    }
}

/// 失败路径统一收尾：恢复文件 → best-effort reload → 只记警告，不覆盖原始错误。
/// reload 再失败时磁盘已恢复但服务可能仍加载新配置，必须留一条显式警告供人工核对。
pub async fn rollback_after_failure(state: &Shared, snap: &DeploySnapshot) {
    for e in snap.restore().await {
        eprintln!("[warn] 站点配置回滚失败：{e}（需人工核对 {}）", snap.target.display());
    }
    if let Err(e) = state.os.webserver().reload().await {
        eprintln!("[warn] 站点配置回滚后 reload 失败（磁盘已恢复，服务仍可能加载新配置）: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fp-rollback-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn restore_brings_back_previous_content() {
        let d = dir("prev");
        let p = d.join("site.conf");
        std::fs::write(&p, "old config").unwrap();
        let snap = DeploySnapshot::capture(&p, None).await;
        std::fs::write(&p, "new config").unwrap();
        assert!(snap.restore().await.is_empty());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "old config");
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn restore_removes_newly_created_file() {
        let d = dir("new");
        let p = d.join("brand-new.conf");
        let snap = DeploySnapshot::capture(&p, None).await;
        assert!(snap.target_before.is_none());
        std::fs::write(&p, "new config").unwrap();
        assert!(snap.restore().await.is_empty());
        assert!(!p.exists(), "新建站点下发失败后应删掉刚写入的文件");
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn restore_brings_back_pruned_stale_conf() {
        let d = dir("stale");
        let target = d.join("new-domain.conf");
        let stale = d.join("old-domain.conf");
        std::fs::write(&stale, "stale config").unwrap();
        let snap = DeploySnapshot::capture(&target, Some(&stale)).await;
        std::fs::write(&target, "new config").unwrap();
        std::fs::remove_file(&stale).unwrap();
        assert!(snap.restore().await.is_empty());
        assert!(!target.exists());
        assert_eq!(std::fs::read_to_string(&stale).unwrap(), "stale config");
        std::fs::remove_dir_all(&d).ok();
    }
}
