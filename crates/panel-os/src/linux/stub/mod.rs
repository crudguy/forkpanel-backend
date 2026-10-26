//! 未实现能力的**显式 stub** 与少量轻量实现。
//!
//! 纪律：未实现的能力必须返回 `PanelError::Unsupported`，**禁止**返回空 Vec 或 Ok(())
//! 假装成功——那会让 UI 显示错误状态，是"假装可移植"的典型表现。

use crate::paths::{slug, LinuxPathLayout, PathLayout};
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{LogBackend, PanelError, Result, SafePath, UnitName};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::cmd::{Bin, CmdOpt};

/// apt 写操作的**等锁**参数：`-o DPkg::Lock::Timeout=<秒>`。
///
/// 为什么需要：apt/dpkg 的锁是**全局独占**的。外部 apt（终端里手敲的、
/// unattended-upgrades）持锁时，apt 默认**立刻**以退出码 100 失败。
/// 本机 `/var/log/apt/history.log` 实证：面板的 task 12/14 都是撞上用户终端里的
/// `apt purge libreoffice …`(22:39) / `apt upgrade`(22:44) 而失败的——
/// 面板内部排队救不了这种情况，只能让 apt 自己等。
///
/// 实测（Debian 13 / apt 3.x，两次并发 no-op install）：
/// - 不带该选项 → 立即 exit 100《E: 无法获得锁 … 锁正由进程 N（apt-get）持有》
/// - 带 `=8` → 打印《正在等待缓存锁》→ 等 2s → exit 0
///
/// 取 300s：覆盖常见的外部 apt 事务，又远小于任务超时（1800s），不会把任务卡死。
/// 等待期间 apt 的《正在等待缓存锁》会作为日志行推到前端，用户看得见"在等什么"。
///
/// ⚠️ **刻意不用于只读页面路径**（`repo.rs` 的 ensure_repo → apt-get update）：
/// 那条路径由 `GET /packages/*` 触发，必须快速失败；让它等锁会把一次普通页面
/// 请求阻塞数分钟，比失败更糟。
const APT_LOCK_TIMEOUT: &str = "DPkg::Lock::Timeout=300";

macro_rules! unsupported {
    ($what:expr) => { Err(PanelError::Unsupported($what)) };
}

/// 安全 PATH 内查找二进制是否**可执行**（与 cmd.rs 的解析目录、判据都保持一致）。
///
/// ⚠️ 判据是「普通文件 + 有执行位」，不是裸 `is_file()`。原因见
/// `crate::cmd::is_executable_file` 的注释：只查存在性时，一个 0 字节普通文件
/// 顶掉 `/usr/bin/journalctl` 也会被判成"可用"，能力位 supported=true 而真
/// spawn 时 EACCES——「说能用、一用就炸」比直接置 false 更坑用户。
///
/// 保留 `&str` 签名是为了不动各 provider 的调用点；判据本身由 `cmd` 单点提供，
/// 不存在两份实现漂移的可能。
fn which(name: &str) -> bool {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"]
        .iter()
        .any(|d| crate::cmd::is_executable_file(&std::path::Path::new(d).join(name)))
}

// ─── 按 provider 拆分为子模块 ───
// 各子模块文件顶部 `use super::*;` 取共享 imports / `which()`；`unsupported!` 宏经
// 文本作用域（macro_rules 定义于本模块、子模块在其后声明）对子模块可见。
// linux/mod.rs 里的 `stub::LinuxXxx` 经下方 `pub use` 重导出保持不变。
// 防火墙 / 计划任务的真实实现已在 linux/firewall.rs / scheduler.rs，此处不再占位。

mod process;
mod network;
mod storage;
mod packages;
mod logs;
mod webserver;
mod databases;
mod users;

pub use network::*;
pub use storage::*;
pub use packages::*;
pub use logs::*;
pub use webserver::*;
pub use databases::*;
pub use users::*;

// 跨 provider 白盒测试集中在独立文件（cfg(test) 挂在父模块的 `mod tests;` 声明上，
// 故 strip_tests.py 按 `tests.rs` 命名约定豁免整个文件，见该脚本 prod_files）。
#[cfg(test)]
mod tests;
