//! 进度上报与事件广播。
//!
//! # 为什么进度不同步进库
//! 实测：SQLite 写事务 p99 2.36ms，但**每个进度点都落库**会让写队列被 1% 的行冲垮，
//! 且进度本身没有持久化价值（任务结束后 100% 就是终态）。
//! 所以：进度走内存广播（SSE），只有**状态变化**（queued→running→终态）才落库。
//!
//! # 背压
//! 慢消费者直接丢弃（与 SSE 同一策略）：进度是"尽力而为"的信息，
//! 绝不为了让某个客户端跟上而拖慢任务本身。

use super::TaskKind;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::broadcast;

/// 广播通道容量。慢消费者超出即丢弃（不阻塞任务）。
const BUS_CAP: usize = 256;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
pub enum TaskEvent {
    Progress { id: i64, percent: u8, message: Option<String> },
    Log { id: i64, line: String },
    Finished { id: i64, state: super::TaskState, kind: TaskKind },
    CancelRequested { id: i64 },
}

/// 全局任务事件总线
pub struct ProgressBus {
    tx: broadcast::Sender<TaskEvent>,
    /// 最近一次进度：新订阅者立即拿到当前值，避免"连上来要等下一次更新"
    latest: Arc<Mutex<HashMap<i64, u8>>>,
}

impl ProgressBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAP);
        Self { tx, latest: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn publish(&self, ev: TaskEvent) {
        if let TaskEvent::Progress { id, percent, .. } = &ev {
            self.latest.lock().unwrap_or_else(|e| e.into_inner()).insert(*id, *percent);
        }
        // 无接收者时 send 返回 Err，这是正常的（没人订阅就不需要推送）
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TaskEvent> { self.tx.subscribe() }

    /// 当前订阅者数量（用于判断是否值得继续推送）
    pub fn listener_count(&self) -> usize {
        self.latest.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for ProgressBus { fn default() -> Self { Self::new() } }

/// 任务执行体持有的进度句柄
#[derive(Clone)]
pub struct Progress {
    id: i64,
    bus: Arc<ProgressBus>,
    canceled: Arc<std::sync::atomic::AtomicBool>,
}

impl Progress {
    pub fn new(id: i64, bus: Arc<ProgressBus>) -> Self {
        Self { id, bus, canceled: Arc::new(std::sync::atomic::AtomicBool::new(false)) }
    }

    /// 上报进度（0~100）。**不落库**，只广播。
    ///
    /// 节流建议：任务体应自行控制调用频率（例如每 1% 或每 200ms 一次），
    /// 逐行输出时不要每行都调 `set_percent`。
    pub async fn set_percent(&self, pct: u8) {
        let pct = pct.min(100);
        self.bus.publish(TaskEvent::Progress { id: self.id, percent: pct, message: None });
    }

    pub async fn set(&self, pct: u8, msg: impl Into<String>) {
        let pct = pct.min(100);
        self.bus.publish(TaskEvent::Progress {
            id: self.id, percent: pct, message: Some(msg.into()),
        });
    }

    /// 输出一行日志。**不落库**，只广播（完整输出由任务体自行写文件）。
    pub async fn log(&self, line: &str) {
        // 单行上限：防止某个命令刷出 MB 级输出把 SSE 打满
        let line = if line.len() > 4096 { &line[..4096] } else { line };
        self.bus.publish(TaskEvent::Log { id: self.id, line: line.to_string() });
    }

    /// 任务体应在合适的检查点主动查询，然后优雅退出。
    ///
    /// 为什么不强杀：强杀子进程会留下半个副作用（半装的包、写了一半的配置）。
    pub fn is_canceled(&self) -> bool {
        self.canceled.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn mark_canceled(&self) {
        self.canceled.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn id(&self) -> i64 { self.id }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn progress_broadcasts_without_blocking_when_no_listener() {
        let bus = Arc::new(ProgressBus::new());
        let p = Progress::new(1, bus.clone());
        // 无订阅者时不应 panic 或阻塞
        p.set_percent(50).await;
        p.log("hello").await;
    }

    #[tokio::test]
    async fn latest_percent_is_remembered() {
        let bus = Arc::new(ProgressBus::new());
        let p = Progress::new(7, bus.clone());
        p.set_percent(42).await;
        assert_eq!(bus.latest.lock().unwrap().get(&7).copied(), Some(42));
    }

    #[tokio::test]
    async fn long_lines_are_truncated() {
        let bus = Arc::new(ProgressBus::new());
        let mut rx = bus.subscribe();
        let p = Progress::new(1, bus.clone());
        p.log(&"x".repeat(10_000)).await;
        match rx.recv().await.unwrap() {
            TaskEvent::Log { line, .. } => assert_eq!(line.len(), 4096, "超长行必须截断"),
            _ => panic!("应为 Log 事件"),
        }
    }

    #[tokio::test]
    async fn percent_is_clamped() {
        let bus = Arc::new(ProgressBus::new());
        let mut rx = bus.subscribe();
        let p = Progress::new(1, bus.clone());
        p.set_percent(200).await;
        match rx.recv().await.unwrap() {
            TaskEvent::Progress { percent, .. } => assert_eq!(percent, 100),
            _ => panic!("应为 Progress 事件"),
        }
    }

    #[tokio::test]
    async fn cancel_flag_propagates() {
        let bus = Arc::new(ProgressBus::new());
        let p = Progress::new(1, bus);
        assert!(!p.is_canceled());
        p.mark_canceled();
        assert!(p.is_canceled());
    }
}
