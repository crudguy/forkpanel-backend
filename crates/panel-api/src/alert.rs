//! 外部告警通道（G8）：把「进程活着但事情坏了」转发给运维配置的 webhook。
//!
//! # 与崩溃告警共用同一个出口（重要）
//!
//! 安装器已生成两样东西（`deploy/install.sh`）：
//! - `/etc/forkpanel/alert-webhook` —— **单行 URL** 的配置文件；
//! - systemd 单元 `panel-failure-notify.service`（由 `panel.service` 的 `OnFailure=` 拉
//!   起）—— 进程崩溃时由 `/usr/share/forkpanel/notify-failure.sh` 读该文件并 POST
//!   `{"panel":"forkpanel","event":"crash",…}`。
//!
//! 本模块**读同一个文件、发同一形状的包**，只把覆盖面从「进程死了」扩到
//! 「进程活着但事情坏了」：备份失败、证书续期失败、内部周期任务失败。
//! 运维只需要维护一个 webhook 地址，不需要在设置页再配第二个。
//!
//! # 为什么 URL 不存 settings 表
//!
//! 告警通道**不能依赖它要监控的组件**。库挂了（损坏 / 磁盘满 / 迁移卡死）恰恰是最该
//! 告警的时刻，而 settings 表就在那个库里 —— 存进去等于「最需要它的时候它读不出来」。
//! 配置文件是纯文件读取，库不可用也能工作。崩溃告警走 shell 也是同一个理由。
//!
//! # 节流
//!
//! 内部任务失败可能是每分钟一次（`backup.sweep` 每分钟扫），逐条外发会把运维的手机
//! 打爆，然后运维就会把告警关掉 —— 那比没有告警更糟。同一 `event` 在
//! `DEFAULT_MIN_INTERVAL_SECS` 内只外发一条；**被节流不影响日志**，journald 里每次都有。
//!
//! # 诚实的降级
//!
//! 未配置（文件不存在 / 空）→ `load` 返回 `None`，调用方据此认为「没有告警通道」，
//! 静默跳过，**不报错也不假装发出**。配了但发送失败 → 返回 `Err` 由调用方记 warn，
//! **绝不因此中断业务**（备份失败的原因不该被「告警发不出去」覆盖掉）。

use crate::webhook;
use panel_core::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// 配置文件名。与 `deploy/notify-failure.sh` 里的 `WH=/etc/forkpanel/alert-webhook`
/// 及 `ci/check_logging.py` 的清单**必须一致**——改这里就要同步改那两处。
pub const WEBHOOK_FILE: &str = "alert-webhook";

/// 默认节流窗口：同一事件 5 分钟内只外发一次。
///
/// 取值理由：备份/证书是**每天**级别的任务，5 分钟窗口对它们等于「不节流」；
/// 而 `backup.sweep` 这类每分钟任务在持续故障时正好压到每 5 分钟一条——
/// 足够让运维看到「一直在坏」，又不至于变成短信轰炸。
pub const DEFAULT_MIN_INTERVAL_SECS: u64 = 300;

/// 一小时内最多外发多少条（跨事件的兜底闸门）。
///
/// 节流是按事件的，事件种类涨到十几个时（每个都被触发）仍可能一分钟十几条。
/// 这个上限只防「告警风暴」，正常运维根本碰不到。
pub const MAX_PER_HOUR: usize = 30;

/// 已配置的外部告警通道。
///
/// 生命周期与进程一致：`serve` 启动时 `load` 一次，之后只读（除节流用的内部计数）。
pub struct AlertSink {
    url: String,
    min_interval: Duration,
    /// 每个 event 上次外发的时间（Unix 秒）。只用于节流，丢了也不影响正确性
    /// ⇒ 中毒可恢复，符合 `sync::lock_recover` 的适用前提。
    last: Mutex<HashMap<String, i64>>,
}

impl AlertSink {
    /// 用显式 URL 构造（`panel alert test` 与单测用）。
    pub fn new(url: &str) -> Result<Self> {
        let url = url.trim();
        // 复用 webhook 的校验（仅 http(s)、限长、挡控制字符）。**不另写一份**：
        // 两套校验必然漂移，而这里正是 SSRF 的入口。
        webhook::validate_url(url)?;
        Ok(Self {
            url: url.to_string(),
            min_interval: Duration::from_secs(DEFAULT_MIN_INTERVAL_SECS),
            last: Mutex::new(HashMap::new()),
        })
    }

    /// 从 `<config_dir>/alert-webhook` 读取。文件不存在 / 空 / 内容非法 → `None`。
    ///
    /// 「非法 → None」而不是 panic：这是可选功能，配错了不该让面板起不来；
    /// 但会往 stderr 打一行**指名文件路径与原因**，否则运维会以为配好了。
    pub fn load(config_dir: &Path) -> Option<Self> {
        let path = config_dir.join(WEBHOOK_FILE);
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                eprintln!("[panel] 告警配置读取失败 {}: {e}", path.display());
                return None;
            }
        };
        // 与 shell 侧 `head -1 | tr -d '\r\n'` 同口径：只认第一行，容忍 CRLF
        let url = raw.lines().next().unwrap_or("").trim();
        if url.is_empty() {
            return None;
        }
        match Self::new(url) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "[panel] 告警配置被忽略 {}: {e}（只接受 http(s) 绝对 URL）",
                    path.display()
                );
                None
            }
        }
    }

    /// 外发一条告警。返回 `Ok(true)` = 真的发出去了；`Ok(false)` = 被节流拦下。
    ///
    /// 调用方纪律：**永远不要 `?` 到业务流程上**——告警失败不能改变业务结果。
    pub async fn fire(&self, event: &str, detail: &str) -> Result<bool> {
        let now = panel_core::now_unix();
        if !self.claim(event, now) {
            // 节流是常态（每分钟任务持续失败），不刷 journald
            eprintln!("[panel] 告警被节流：{event}");
            return Ok(false);
        }
        let payload = payload(event, detail, now);
        match webhook::fire(&self.url, &payload).await {
            Ok(()) => {
                eprintln!("[panel] 外部告警已投递：{event}");
                Ok(true)
            }
            Err(e) => {
                // 投递失败要**回滚节流记录**：否则「本次没送到」会占掉整个窗口，
                // 之后 5 分钟内的真实故障全被静默吞掉。
                panel_core::sync::lock_recover(&self.last).remove(event);
                Err(e)
            }
        }
    }

    /// 抢占节流名额：允许则记账并返回 true。抽成独立函数以便单测覆盖
    /// 「窗口内拒绝 / 窗口外放行 / 时钟回拨」三种情况。
    fn claim(&self, event: &str, now: i64) -> bool {
        let mut last = panel_core::sync::lock_recover(&self.last);
        let window = self.min_interval.as_secs();
        if !throttle_allows(last.get(event).copied(), now, window) {
            return false;
        }
        // 跨事件的总量闸门：只留最近一小时内的记录，顺带把 map 限制在
        // 「一小时内有活动的 event」这个规模（不会随事件种类无限增长）。
        last.retain(|_, t| now.saturating_sub(*t) < 3600);
        if last.len() >= MAX_PER_HOUR {
            eprintln!("[panel] ⚠ 告警一小时上限（{MAX_PER_HOUR} 条）已到，本条只记日志不外发");
            return false;
        }
        last.insert(event.to_string(), now);
        true
    }
}

/// 节流判定（纯函数）。
///
/// - 没发过 → 放行；
/// - 时钟回拨（`now < last`）→ **拒绝**：宁可少发，也不要在时间线错乱时补发一串；
/// - 距上次 ≥ window → 放行。
fn throttle_allows(last: Option<i64>, now: i64, window_secs: u64) -> bool {
    match last {
        None => true,
        Some(t) => match now.checked_sub(t) {
            Some(d) if d >= 0 => (d as u64) >= window_secs,
            // now < t：时钟回拨
            _ => false,
        },
    }
}

/// 告警包。字段与 `notify-failure.sh` 的崩溃包对齐（`panel` / `event` / `host` /
/// `ts` / `unit`），另加 `detail` 给业务失败用。
fn payload(event: &str, detail: &str, now: i64) -> Value {
    json!({
        "panel": "forkpanel",
        "event": event,
        // 读 OS 路径的活归 panel-os（业务层硬编码 `/etc/hostname` 会被分层守卫判红）
        "host": panel_os::hostname(),
        "ts": now,
        "unit": "panel.service",
        "detail": detail,
    })
}

/// 事件名常量。**集中在这里**，调用方不要各写字符串字面量——
/// 拼错了不会报错，只会让运维在告警里看到一个陌生的 event。
///
/// 三个常量各自都有消费者（`serve.rs` 的 TaskRunner 钩子按任务 kind 映射），
/// 不是"先定义着备用"——那种常量最后一定没人用。
pub mod events {
    /// 备份任务失败（`kind=backup` 的任意一步失败）
    pub const BACKUP_FAILED: &str = "backup.failed";
    /// 证书签发/续期失败（`kind=cert_issue`）
    pub const CERT_FAILED: &str = "cert.failed";
    /// 其它任务失败与内部周期任务失败（含超时）
    pub const JOB_FAILED: &str = "job.failed";
}

impl AlertSink {
    /// 业务失败告警：**吞掉**发送错误只记日志，供业务分支直接调用。
    ///
    /// 为什么要有这个包装：`fire` 返回 `Result` 是为了让 CLI / 测试能感知失败；
    /// 而业务分支里（备份失败后）如果写成 `if let Err(e) = sink.fire(..).await {…}`，
    /// 每处都要重复一遍日志格式。更重要的是**没人会不小心 `?` 上去**。
    pub async fn notify_failure(&self, event: &str, detail: impl AsRef<str>) {
        if let Err(e) = self.fire(event, detail.as_ref()).await {
            eprintln!("[panel] 外部告警投递失败（{event}）: {e}");
        }
    }
}

/// 便捷入口：`None`（未配置）时静默跳过。调用方写法：
/// `alert::fire_opt(state.alert.as_deref(), events::BACKUP_FAILED, &msg).await;`
pub async fn fire_opt(sink: Option<&AlertSink>, event: &str, detail: impl AsRef<str>) {
    if let Some(s) = sink {
        s.notify_failure(event, detail).await;
    }
}

/// 「配置了但 URL 非法」这类错误也要能被 CLI 展示（`panel alert test`）。
pub fn describe_missing(config_dir: &Path) -> String {
    format!(
        "未配置外部告警：{} 不存在或为空。\
         写入一行 webhook URL（仅 http/https）即可，与崩溃告警共用同一个文件：\
         `echo 'https://example.com/hook' | sudo tee {}`",
        config_dir.join(WEBHOOK_FILE).display(),
        config_dir.join(WEBHOOK_FILE).display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_blocks_within_window_and_allows_after() {
        assert!(throttle_allows(None, 1_000, 300), "首次必须放行");
        assert!(!throttle_allows(Some(1_000), 1_000, 300), "同一秒重复必须拦");
        assert!(!throttle_allows(Some(1_000), 1_299, 300), "窗口内必须拦");
        assert!(throttle_allows(Some(1_000), 1_300, 300), "正好到窗口应放行");
        assert!(throttle_allows(Some(1_000), 9_999, 300), "窗口外放行");
    }

    #[test]
    fn throttle_rejects_when_clock_goes_backwards() {
        // 时钟回拨时 now < last：宁可静默，也不要补发一串时间戳错乱的告警
        assert!(!throttle_allows(Some(2_000), 1_000, 1));
        assert!(!throttle_allows(Some(i64::MAX), 0, 0));
    }

    #[test]
    fn payload_carries_the_fields_the_shell_script_sends() {
        let p = payload(events::BACKUP_FAILED, "disk full", 1_700_000_000);
        // 与 notify-failure.sh 同形：panel / event / host / ts / unit
        assert_eq!(p["panel"], "forkpanel");
        assert_eq!(p["event"], "backup.failed");
        assert_eq!(p["ts"], 1_700_000_000i64);
        assert_eq!(p["unit"], "panel.service");
        assert_eq!(p["detail"], "disk full");
        assert!(p["host"].is_string(), "host 必须始终存在（读不到给 unknown）");
    }

    #[test]
    fn new_rejects_non_http_and_relative_urls() {
        assert!(AlertSink::new("https://example.com/hook").is_ok());
        assert!(AlertSink::new("http://10.0.0.2:9000/x").is_ok());
        // 与 webhook 校验同源：file:// 等必须拒绝（否则成了本地文件读取通道）
        assert!(AlertSink::new("file:///etc/passwd").is_err());
        assert!(AlertSink::new("/relative/path").is_err());
        assert!(AlertSink::new("").is_err());
    }

    #[test]
    fn new_trims_surrounding_whitespace() {
        // 运维 `echo " url " > alert-webhook` 不该导致校验失败
        let s = AlertSink::new("  https://example.com/h  \n").unwrap();
        assert_eq!(s.url, "https://example.com/h");
    }

    #[test]
    fn load_returns_none_for_missing_or_empty_file() {
        let dir = std::env::temp_dir().join(format!("fp-alert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 不存在
        assert!(AlertSink::load(&dir).is_none());
        // 空文件
        let p = dir.join(WEBHOOK_FILE);
        std::fs::write(&p, "   \n\n").unwrap();
        assert!(AlertSink::load(&dir).is_none(), "空白内容等同未配置");
        // 非法 URL：返回 None 而不是 panic（可选功能不该让进程起不来）
        std::fs::write(&p, "ftp://x/y\n").unwrap();
        assert!(AlertSink::load(&dir).is_none());
        // 合法：只认第一行（与 shell 的 head -1 同口径）
        std::fs::write(&p, "https://example.com/h\nignored-second-line\n").unwrap();
        let s = AlertSink::load(&dir).expect("合法 URL 应被接受");
        assert_eq!(s.url, "https://example.com/h");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 节流记账必须真的拦住第二次调用（而不是只让纯函数返回 false）。
    #[tokio::test]
    async fn fire_throttles_second_call_in_same_window() {
        // 用不可达但合法的地址：第一次会尝试投递并失败，失败后节流记录被回滚，
        // 故这里只验证 claim 的记账行为，不真发网络请求。
        let s = AlertSink::new("http://127.0.0.1:1/never").unwrap();
        let now = panel_core::now_unix();
        assert!(s.claim(events::JOB_FAILED, now), "首次应抢到名额");
        assert!(!s.claim(events::JOB_FAILED, now), "同窗口第二次必须被拦");
        // 不同事件互不影响
        assert!(s.claim(events::CERT_FAILED, now), "不同 event 各自记账");
    }
}
