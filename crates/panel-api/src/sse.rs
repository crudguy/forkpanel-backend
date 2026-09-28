//! SSE 推送（设计方案 §3.4 / §3.6-8）。
//!
//! 关键约束（低配机器上的生死线）：
//! 1. **共享快照**：所有客户端读同一份 `ArcSwap`，不做"每客户端一份采集"。
//! 2. **背压与丢弃**：慢消费者（写满 channel）直接断开，**绝不**让缓冲区无限增长。
//! 3. **客户端上限**：nano 3 / small 10 / standard 50（超出返回 503 + 明确提示）。
//! 4. 订阅频道按权限过滤：无 `log.read` 则拒绝订阅日志频道。

use crate::{error::ApiError, routes::MaybeAuth, AppState};
use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use futures_util::stream::StreamExt;
use panel_core::Tier;
use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc;

/// 当前 SSE 连接数（进程内原子计数，用于档位上限判定）
pub static SSE_CONNS: AtomicUsize = AtomicUsize::new(0);

pub fn max_clients(t: Tier) -> usize {
    match t { Tier::Nano => 3, Tier::Small => 10, Tier::Standard => 50 }
}

/// 慢消费者丢弃阈值：channel 容量。超出即断开（背压策略）。
const BACKLOG: usize = 64;

pub async fn metrics_stream(
    State(state): State<Arc<AppState>>,
    // Session 未实现 FromRequestParts，不能直接用 Option<Session> 作提取器；
    // MaybeAuth 即为此设计（Rejection 为 Infallible）。
    MaybeAuth(session): MaybeAuth,
) -> axum::response::Response {
    // 指标属于敏感信息（可推断负载与业务量），必须登录后按权限订阅
    match &session {
        Some(s) => {
            if crate::auth::require(s, crate::auth::perm::SYSTEM_VIEW).is_err() {
                return ApiError::forbidden(crate::auth::perm::SYSTEM_VIEW).into_response();
            }
        }
        None => return ApiError::unauthorized().into_response(),
    }
    let limit = max_clients(state.tier);
    if SSE_CONNS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
        if n >= limit { None } else { Some(n + 1) }
    }).is_err() {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE,
                format!("sse client limit reached ({limit})")).into_response();
    }

    let (tx, mut rx) = mpsc::channel::<Event>(BACKLOG);
    let interval = Duration::from_millis(state.tier.sampling_interval_ms());
    let metrics = state.metrics.clone();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // 第一次立即推送，之后按档位间隔
        ticker.tick().await;
        loop {
            ticker.tick().await;
            // 读共享环形缓冲的最新点：**不触发采集**（采集由内部调度器统一做）
            let payload = {
                let g = metrics.lock().unwrap_or_else(|e| e.into_inner());
                // 必须先绑定到局部变量再作为块尾：块尾表达式里的临时迭代器
                // 会在局部变量 g 之后才析构，导致 "g does not live long enough"。
                let x = match g.ring().iter().next_back() {
                    Some(s) => serde_json::json!({
                        "ts": s.ts,
                        "cpu": s.cpu_pct,
                        "mem_used_kib": s.mem_used_kib,
                        "mem_total_kib": s.mem_total_kib,
                        "load1": s.load1,
                    }),
                    None => serde_json::json!({ "ts": now_unix(), "cpu": 0.0,
                                                "mem_used_kib": 0, "mem_total_kib": 0, "load1": 0.0 }),
                };
                x
            };
            let ev = Event::default().event("metrics").data(payload.to_string());
            // try_send：满即丢弃（慢消费者），这是刻意的背压策略
            if tx.try_send(ev).is_err() { break; }
        }
    });

    let stream = async_stream::stream! {
        while let Some(ev) = rx.recv().await { yield Ok::<_, Infallible>(ev); }
    };
    let stream = async_stream::stream! {
        tokio::pin!(stream);
        while let Some(ev) = StreamExt::next(&mut stream).await {
            yield ev;
        }
        SSE_CONNS.fetch_sub(1, Ordering::SeqCst);
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("ping"))
        .into_response()
}

/// 任务进度频道：订阅需 `task.view`
pub async fn task_stream(
    State(state): State<Arc<AppState>>,
    // Session 未实现 FromRequestParts，不能直接用 Option<Session> 作提取器；
    // MaybeAuth 即为此设计（Rejection 为 Infallible）。
    MaybeAuth(session): MaybeAuth,
) -> axum::response::Response {
    if let Some(s) = &session {
        if crate::auth::require(s, crate::auth::perm::TASK_VIEW).is_err() {
            return ApiError::forbidden(crate::auth::perm::TASK_VIEW).into_response();
        }
    } else {
        return ApiError::unauthorized().into_response();
    }
    let limit = max_clients(state.tier);
    if SSE_CONNS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
        if n >= limit { None } else { Some(n + 1) }
    }).is_err() {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE,
                format!("sse client limit reached ({limit})")).into_response();
    }

    // 订阅全局任务总线：所有任务事件都从这里广播
    let mut bus_rx = state.tasks.bus().subscribe();
    let stream = async_stream::stream! {
        while let Ok(ev) = bus_rx.recv().await {
            let (name, data) = match ev {
                panel_task::TaskEvent::Progress { id, percent, message } => (
                    "progress",
                    serde_json::json!({ "id": id, "percent": percent, "message": message }),
                ),
                panel_task::TaskEvent::Log { id, line } => (
                    "log", serde_json::json!({ "id": id, "line": line }),
                ),
                panel_task::TaskEvent::Finished { id, state, kind } => (
                    "finished",
                    serde_json::json!({ "id": id, "state": state.as_str(), "kind": kind.as_str() }),
                ),
                panel_task::TaskEvent::CancelRequested { id } => (
                    "cancel", serde_json::json!({ "id": id }),
                ),
            };
            yield Ok::<_, Infallible>(Event::default().event(name).data(data.to_string()));
        }
        SSE_CONNS.fetch_sub(1, Ordering::SeqCst);
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("ping"))
        .into_response()
}

/// 日志跟随频道：订阅需 `log.view`（权限过滤示例）
pub async fn log_stream(
    State(state): State<Arc<AppState>>,
    // Session 未实现 FromRequestParts，不能直接用 Option<Session> 作提取器；
    // MaybeAuth 即为此设计（Rejection 为 Infallible）。
    MaybeAuth(session): MaybeAuth,
) -> axum::response::Response {
    match &session {
        Some(s) => {
            if crate::auth::require(s, crate::auth::perm::LOG_VIEW).is_err() {
                return ApiError::forbidden(crate::auth::perm::LOG_VIEW).into_response();
            }
        }
        None => return ApiError::unauthorized().into_response(),
    }
    // 能力矩阵未开启日志能力时，直接 501 而非建立空连接
    if !state.capabilities.get("logs.read").map(|c| c.supported).unwrap_or(false) {
        return ApiError::unsupported("logs.read").into_response();
    }
    let (tx, mut rx) = mpsc::channel::<Event>(BACKLOG);
    drop(tx);
    // 注意：不能写成 `let s: Sse<impl Stream<...>> = ...`
    // —— `impl Trait` 不允许出现在 let 绑定的类型标注上（E0562）。直接构造并转换即可。
    Sse::new(async_stream::stream! {
        while let Some(ev) = rx.recv().await { yield Ok::<_, Infallible>(ev); }
    }).into_response()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_limits_match_tier() {
        assert_eq!(max_clients(Tier::Nano), 3);
        assert_eq!(max_clients(Tier::Small), 10);
        assert_eq!(max_clients(Tier::Standard), 50);
    }

    #[test]
    fn backlog_is_small() {
        // 低配机器上缓冲区必须小：64 条 × 事件大小，避免慢客户端拖垮内存
        assert!(BACKLOG <= 128);
    }
}
