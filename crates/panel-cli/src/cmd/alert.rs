//! 外部告警通道运维：查看接线状态、发一条测试告警。
//!
//! # 为什么必须有 `test`
//! 告警通道是「配了但从不验证」的典型：URL 少一位、对方只收 GET、出站被防火墙
//! 挡住、curl 根本没装 —— 每一种都要等真出事才发现，而那时告警恰恰是唯一的信号。
//! `test` 故意走**与业务告警完全相同**的发送路径（同一个 `AlertSink::fire`、
//! 同一份节流记账、同一个 curl 出口），不搞"测试专用旁路"——旁路通只能证明旁路通。
//!
//! # 为什么不回显 URL
//! webhook URL 通常自带 token（`https://hooks.example.com/T000/B000/xxxx`），
//! 回显等于把它写进 shell 历史、工单截图与 `journalctl`。`status` 只报
//! 「已配置 / 未配置」与**文件路径**，要看内容让运维自己 `sudo cat`。

use panel_core::{PanelError, Result};
use std::sync::Arc;

use crate::{build_layout, load_cfg, Cli};

/// 取 (cfg, layout)：两条命令的前置完全一样。
fn layout_of(cli: &Cli, os: &Arc<dyn panel_os::OsAdapter>)
    -> Result<(crate::Config, Arc<dyn panel_os::PathLayout>)>
{
    let cfg = load_cfg(cli, &build_layout(os, None))?;
    let layout = build_layout(os, Some(&cfg));
    Ok((cfg, layout))
}

/// `panel alert status`：这个部署到底会不会发外部告警。
pub(crate) fn status(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    let (_cfg, layout) = layout_of(cli, &os)?;
    let dir = layout.config_dir();
    let path = dir.join(panel_api::alert::WEBHOOK_FILE);
    match panel_api::alert::AlertSink::load(&dir) {
        Some(_) => {
            println!("外部告警：已配置 → {}", path.display());
            println!(
                "节流：同一事件 {} 秒内一条，上限 {} 条/小时",
                panel_api::alert::DEFAULT_MIN_INTERVAL_SECS,
                panel_api::alert::MAX_PER_HOUR
            );
            println!("同文件也供崩溃告警使用（systemd OnFailure → notify-failure.sh）");
            println!("验证投递：sudo panel alert test");
        }
        None => {
            println!("外部告警：未配置（失败只会留在 journald 与站内通知里）");
            println!("{}", panel_api::alert::describe_missing(&dir));
        }
    }
    Ok(())
}

/// `panel alert test`：真发一条，把「配了」变成「通了」。
pub(crate) fn test(cli: &Cli, os: Arc<dyn panel_os::OsAdapter>) -> Result<()> {
    let (_cfg, layout) = layout_of(cli, &os)?;
    let dir = layout.config_dir();
    let sink = panel_api::alert::AlertSink::load(&dir).ok_or_else(|| {
        // 未配置是**用户可修的错误**，不是内部故障：给可复制的命令，别让人猜。
        PanelError::Validation {
            field: "alert-webhook",
            reason: panel_api::alert::describe_missing(&dir),
        }
    })?;
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PanelError::Internal(format!("runtime: {e}")))?;
    // event 用独立的 "test"：它不会占掉任何业务事件的节流窗口，
    // 也就不会让「刚测过」变成「真故障没报出来」。
    let r = rt.block_on(sink.fire("test", "panel alert test：这是一条测试告警，收到即表示通道可用"));
    match r {
        Ok(true) => {
            println!("已投递测试告警（对端应收到 {{\"event\":\"test\",…}}）");
            println!("⚠ 记得确认对端**真的显示了**这条：curl 返回 0 只代表 HTTP 200/2xx。");
            Ok(())
        }
        Ok(false) => {
            println!("被节流：{} 秒内已发过同类告警，稍后重试",
                panel_api::alert::DEFAULT_MIN_INTERVAL_SECS);
            Ok(())
        }
        // 这里必须响亮失败：`panel alert test` 的唯一用途就是暴露"发不出去"。
        Err(e) => Err(PanelError::Internal(format!(
            "测试告警投递失败：{e}\n\
             排查顺序：① `curl -v -X POST -d '{{}}' <URL>` 看对端是否接受 POST；\
             ② 出站防火墙/nft 是否放行；③ `which curl`（本面板经 curl 投递，未装则必然失败）"
        ))),
    }
}

#[cfg(test)]
mod tests {
    /// 未配置时 `test` 必须**明确报错**而不是静默成功——
    /// 静默成功会让运维以为通道可用，直到真出事。
    #[test]
    fn missing_webhook_is_reported_by_describe_missing() {
        let dir = std::path::Path::new("/nonexistent-forkpanel-config");
        let msg = panel_api::alert::describe_missing(dir);
        assert!(msg.contains("未配置"), "必须明说未配置：{msg}");
        // 给出的修复动作必须可复制执行（含完整路径）
        assert!(msg.contains("alert-webhook"), "必须指出文件名：{msg}");
    }
}
