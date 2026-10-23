//! 交互式终端（Web 终端）的能力探测。
//!
//! 只回答"有没有可用的交互 shell"。**不在这里创建 PTY** —— PTY 创建属
//! 子进程出口，统一收敛在 `crate::cmd::spawn_pty`（CI 门禁 [1] 的不变量）。

use crate::cmd::Bin;
use crate::traits::TerminalProvider;

/// Linux：交互 shell 优先 `bash`，回退 `sh`。
///
/// `Bin::available()` 是**纯文件存在性检查**，不执行任何命令——能力位在进程
/// 启动时求值，绝不能有副作用或阻塞。
#[derive(Debug, Default)]
pub struct LinuxTerminal;

impl LinuxTerminal {
    pub fn detect() -> Self { Self }
}

impl TerminalProvider for LinuxTerminal {
    fn available(&self) -> bool { self.shell().is_some() }

    fn shell(&self) -> Option<Bin> {
        // 顺序即优先级：bash 的补全、历史、job control 更完整，
        // 回退 sh 只为兼容极简容器镜像。
        [Bin::Bash, Bin::Sh].into_iter().find(|&b| b.available())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_detection_is_consistent_with_availability() {
        let t = LinuxTerminal::detect();
        assert_eq!(t.available(), t.shell().is_some(),
            "available() 必须与 shell() 同源，否则 UI 会出现「能用但没 shell」");
    }

    #[test]
    fn prefers_bash_then_falls_back_to_sh() {
        let t = LinuxTerminal::detect();
        // 本机 bash 必然存在（面板自身就要靠它跑运维命令）；
        // 若环境极端到只有 sh，也不能判成不可用。
        if Bin::Bash.available() {
            assert_eq!(t.shell(), Some(Bin::Bash));
        } else if Bin::Sh.available() {
            assert_eq!(t.shell(), Some(Bin::Sh));
        } else {
            assert!(!t.available());
        }
    }
}
