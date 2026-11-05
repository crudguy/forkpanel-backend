//! 统一时钟读数（`now_unix`）。
//!
//! 为什么单独成模块：`now_unix()` 曾在本仓**复制了 15 份**（db / api / task / cli / os
//! 各写各的）。同一份实现散成 15 处，任一处要改（改成毫秒、处理时钟回拨、加测试钩子）
//! 都得同步 15 处，漏改即行为分叉——而这类分叉只在"保留期边界"这种地方偶发暴露，
//! 排查成本极高（cleanup 的边界等值偶发红就是这么来的）。
//!
//! ⚠ 语义刻意保持 `unwrap_or(0)`：系统时钟早于 1970 时返回 0，**不 panic**。
//! 改成 `expect` 会让这类环境（容器快照恢复、时钟未同步的设备）直接崩，
//! 而返回 0 的后果只是"算出来很旧"，由调用方按业务处理。

use std::time::{SystemTime, UNIX_EPOCH};

/// 当前 Unix 时间戳（秒）。系统时钟早于 1970 时返回 0。
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_unix_is_plausible_epoch_seconds() {
        let t = now_unix();
        // 2020-01-01 之后、2100 之前：既排除"单位写成毫秒"，也排除返回 0 的失效路径。
        assert!(t > 1_577_836_800, "now_unix 太小：{t}（疑似退回 0 或单位错）");
        assert!(t < 4_102_444_800, "now_unix 太大：{t}（疑似毫秒当秒）");
    }
}
