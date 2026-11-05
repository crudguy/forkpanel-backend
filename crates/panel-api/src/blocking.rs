//! 阻塞子进程调用的**唯一出口**（Q-01）。
//!
//! `panel_os::run_sync` 是**同步**的：内部真的 fork/exec 一个子进程并 `wait()` 它。
//! 在 async handler 里直接调它会把 tokio worker 线程钉住到子进程结束——systemd /
//! D-Bus 卡顿时，一次 `systemctl is-active` 就能让整个 API 短时无响应，而这类
//! 查询还会被前端轮询放大。
//!
//! 所以本 crate 里 `panel_os::run_sync` 只允许出现在**这个文件**，由
//! `ci/check-blocking-calls.sh` 钉住。
//!
//! 为什么不写「逐点检查有没有包 spawn_blocking」的守卫：静态判断闭包包裹关系
//! 要么写半个 Rust 解析器，要么退化成靠字符距离的启发式（同样会误判，且误判
//! 方向是**放行**）。把出口收成一处后，判据变成「其它文件里 0 次出现」——
//! 简单、精确、不可能误绿。

use panel_core::Result;

/// 转发到同步的 `panel_os::run_sync`。
///
/// ⚠ **只允许两种调用场景**：
/// 1. 已经在 `tokio::task::spawn_blocking` 的闭包里（async handler 的正确写法）；
/// 2. 一个专门被 `spawn_blocking` 调用的 sync 辅助函数内部
///    （如 `routes/expose.rs` 的 `run_script`）。
///
/// 在 async fn 里裸调本函数 = 把 tokio worker 钉住到子进程结束，正是 Q-01 要防的。
pub fn run_sync_in_blocking(bin: panel_os::Bin, args: &[&str]) -> Result<panel_os::CmdOutput> {
    panel_os::run_sync(bin, args)
}

#[cfg(test)]
mod tests {
    /// 出口必须真的转发（而不是被改成空实现后让「其它文件 0 处」恒绿）。
    /// CI 侧的同名判据在 `ci/check-blocking-calls.sh`，这里再钉一次是因为
    /// `make check` 与 `make guards` 是两条独立入口，任一条单独跑都不该失去保护。
    #[test]
    fn outlet_really_forwards_to_run_sync() {
        let prod = panel_testutil::production_source(include_str!("blocking.rs"));
        assert!(
            prod.contains("panel_os::run_sync(bin, args)"),
            "唯一出口没有真的转发 run_sync（改成空实现后，全仓「0 处裸调」会变成恒绿）"
        );
        assert!(
            !prod.contains("std::process::Command"),
            "唯一出口不得自己 spawn 子进程：进程出口只有 panel-os/src/cmd.rs"
        );
    }
}
