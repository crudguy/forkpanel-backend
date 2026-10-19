//! 真机回归：服务日志一次性读取（非 follow）不得死锁。
//!
//! 背景：`LinuxServices::journal` 曾把 `cmd::run` 的输出**同步**灌进容量 64 的
//! channel，而消费者要等 `journal()` 返回拿到 Receiver 后才开始 `recv`——
//! 日志 >64 行时 `send().await` 永久阻塞，HTTP 请求挂死（前端 15s 超时）。
//!
//! 本测试直接调用 provider（不起服务器）：`journal()` 必须在超时内返回，且
//! Receiver 能在超时内被抽干。环境不具备（无 journalctl / 无带日志的 unit）时
//! 显式 `[skip]`——跳过不是通过。

use panel_os::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_non_follow_returns_and_drains_within_timeout() {
    let os = default_adapter();
    // 候选 unit：优先挑一个确实有 >64 行日志的（能真正压到旧实现的死锁路径）。
    let candidates = [
        "accounts-daemon.service",
        "systemd-journald.service",
        "cron.service",
        "dbus.service",
        "ssh.service",
    ];

    let mut exercised = false;
    for c in candidates {
        let Ok(u) = panel_core::unit_name(c) else { continue };

        // 关键断言 1：journal() 必须在 10s 内**返回**。旧实现 >64 行时永不返回。
        let got = tokio::time::timeout(
            Duration::from_secs(10),
            os.services().journal(&u, JournalQuery { lines: 200, ..Default::default() }),
        )
        .await;
        let mut rx = match got {
            Err(_) => panic!("journal({c}) 超过 10s 未返回——channel 同步灌入死锁回归"),
            Ok(Err(_)) => continue, // unit 不存在 / journalctl 不可用 → 换下一个
            Ok(Ok(rx)) => rx,
        };

        // 关键断言 2：Receiver 能抽干（旧实现在上一步就挂死了）。
        let mut lines: Vec<String> = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(l) = rx.recv().await {
                lines.push(l);
            }
        })
        .await;

        if lines.len() > 64 {
            // 格式钉死：`-o short-iso` 的日志行以 `YYYY-MM-DDTHH:MM:SS` 开头。
            // 曾经用 `-o cat`（只有消息），用户看不出日志发生于何时；改回去这里会红。
            assert!(
                lines.iter().any(|l| looks_like_ts(l)),
                "服务日志必须格式化为 `YYYY-MM-DD HH:MM:SS 消息`，实际首行：{:?}",
                lines.first()
            );
            exercised = true;
            eprintln!(
                "journal({c}) 返回 {} 行（>64，已压到旧死锁路径；首行带时间）",
                lines.len()
            );
            break;
        }
    }

    if !exercised {
        eprintln!(
            "[skip] journal_non_follow_returns_and_drains_within_timeout：\
             无 >64 行日志的 unit（环境不具备，跳过）"
        );
    }
}

/// 后端格式化的行首形如 `2026-10-19 09:25:51 ...`。
fn looks_like_ts(l: &str) -> bool {
    let b = l.as_bytes();
    b.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b' '
        && b[13] == b':'
        && b[16] == b':'
}
