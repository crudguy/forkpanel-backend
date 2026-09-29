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

/// 列出归档内条目名（`tar -tzf`）——**解压前**据此做路径逃逸校验。
pub async fn list_tar_entries(archive: &Path) -> Result<Vec<String>> {
    let s = archive.to_str().ok_or_else(|| PanelError::Internal("归档路径非 UTF-8".into()))?;
    let out = crate::cmd::run(
        Bin::Tar,
        &["-tzf", s],
        CmdOpt { timeout: Duration::from_secs(60), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Err(PanelError::Command { bin: "tar".into(), detail: out.stderr });
    }
    Ok(out
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// 归档条目是否安全：**禁止绝对路径与 `..` 逃逸**。
///
/// tar 会剥离前导 `/`，但 `../` 仍可能把文件写到目标目录之外——
/// 恢复的归档虽由本面板产出，仍按不可信输入校验（纵深防御）。
pub fn is_safe_entry(name: &str) -> bool {
    if name.starts_with('/') {
        return false;
    }
    !name.split('/').any(|seg| seg == "..")
}

/// 解包 `archive` 到 `dest_parent`。
///
/// 归档内保留顶层目录名（与 `tar_gz` 对称），故解压目标是**父目录**：
/// 恢复到 `<parent>/<dirname>`，与打包时的布局一致。
pub async fn untar_gz(archive: &Path, dest_parent: &Path) -> Result<()> {
    let arch_s = archive.to_str().ok_or_else(|| PanelError::Internal("归档路径非 UTF-8".into()))?;
    let dest_s =
        dest_parent.to_str().ok_or_else(|| PanelError::Internal("解压目标非 UTF-8".into()))?;
    let out = crate::cmd::run(
        Bin::Tar,
        &["-xzf", arch_s, "-C", dest_s],
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

    #[test]
    fn entry_safety_rejects_escape_and_absolute_paths() {
        assert!(is_safe_entry("site/index.html"));
        assert!(is_safe_entry("site/"));
        // 逃逸：任一路径段为 .. 即拒绝
        assert!(!is_safe_entry("../etc/passwd"));
        assert!(!is_safe_entry("site/../../etc/passwd"));
        assert!(!is_safe_entry("site/../shadow"));
        // 绝对路径
        assert!(!is_safe_entry("/etc/passwd"));
    }
}
