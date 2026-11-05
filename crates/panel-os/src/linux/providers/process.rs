use super::*;


#[async_trait]
impl ProcessProvider for crate::linux::metrics::LinuxMetrics {
    async fn list(&self, limit: usize, sort: ProcessSort) -> Result<Vec<ProcessInfo>> {
        self.top_processes(limit, sort).await
    }

    async fn signal(&self, pid: i32, sig: ProcessSignal) -> Result<()> {
        if self.is_protected(pid).await? {
            return Err(PanelError::PermissionDenied("process.signal: protected pid"));
        }
        let signo: i32 = match sig {
            ProcessSignal::Terminate => 15,   // SIGTERM（语义由平台解释，不暴露数值给业务层）
            ProcessSignal::Kill => 9,
            ProcessSignal::Reload => 1,
        };
        unsafe {
            if libc::kill(pid, signo) != 0 {
                return Err(PanelError::Command {
                    bin: "kill".into(),
                    detail: format!("kill({pid}, {signo}) failed"),
                });
            }
        }
        Ok(())
    }

    async fn is_protected(&self, pid: i32) -> Result<bool> {
        // pid 1 与面板自身不可终止
        Ok(pid <= 1 || pid == std::process::id() as i32)
    }
}

