//! 本地备份原语。**经 `cmd.rs` 唯一子进程出口**调用 `tar`，不做 shell 拼接。

use crate::cmd::{Bin, CmdOpt};
use panel_core::{PanelError, Result};
use std::path::Path;
use std::time::Duration;

/// 把 `src_dir` 打包为 `dest`（`.tar.gz`）。`dest` 的父目录必须已存在。
///
/// 用法：`tar -czf <dest> -C <parent> <dirname>` —— 归档内保留目录名，恢复时可直接解包。
pub async fn tar_gz(src_dir: &Path, dest: &Path) -> Result<()> {
    let parent = src_dir
        .parent()
        .ok_or_else(|| PanelError::Internal("备份源目录无父目录".into()))?;
    let name = src_dir
        .file_name()
        .ok_or_else(|| PanelError::Internal("备份源目录无名称".into()))?
        .to_string_lossy()
        .to_string();
    let dest_s = dest.to_str().ok_or_else(|| PanelError::Internal("备份目标非 UTF-8".into()))?;
    let parent_s = parent.to_str().ok_or_else(|| PanelError::Internal("备份父目录非 UTF-8".into()))?;

    let out = crate::cmd::run(
        Bin::Tar,
        &["-czf", dest_s, "-C", parent_s, name.as_str()],
        CmdOpt { timeout: Duration::from_secs(3600), ..Default::default() },
    )
    .await?;
    if out.code == Some(0) {
        Ok(())
    } else {
        Err(PanelError::Command { bin: "tar".into(), detail: out.stderr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_parent_is_rejected() {
        // `/` 无父目录 → 构造期即拒绝，不 spawn
        let r = tar_gz(Path::new("/"), Path::new("/tmp/x.tar.gz")).await;
        assert!(r.is_err());
    }
}
