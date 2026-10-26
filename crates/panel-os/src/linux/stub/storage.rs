use super::*;


pub struct LinuxStorage;

#[async_trait]
impl StorageProvider for LinuxStorage {
    async fn mounts(&self) -> Result<Vec<DiskSample>> {
        crate::linux::metrics::LinuxMetrics::new().snapshot().await.map(|s| s.disks)
    }

    async fn fs_type(&self, path: &std::path::Path) -> Result<(String, bool)> {
        crate::linux::check_data_dir_fs(path)
    }

    async fn set_permissions(&self, path: &SafePath, op: PermissionOp) -> Result<()> {
        match op {
            PermissionOp::Posix { mode, .. } => {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(mode)).await
                    .map_err(|e| PanelError::Internal(e.to_string()))
            }
            PermissionOp::Noop => Ok(()),
        }
    }

    async fn set_owner_recursive(&self, _path: &SafePath, _user: &str) -> Result<()> {
        // M4：需降权子进程执行 chown -R，且必须先校验路径在允许根内
        unsupported!("storage.set_owner_recursive (M4)")
    }
}

