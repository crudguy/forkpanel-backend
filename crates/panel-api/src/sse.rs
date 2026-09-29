//! SSE 推送（设计方案 §3.4 / §3.6-8）。
//!
//! 关键约束（低配机器上的生死线）：
//! 1. **共享快照**：所有客户端读同一份 `ArcSwap`，不做"每客户端一份采集"。
//! 2. **背压与丢弃**：慢消费者（写满 channel）直接断开，**绝不**让缓冲区无限增长。
//! 3. **客户端上限**：nano 3 / small 10 / standard 50（超出返回 503 + 明确提示）。
//! 4. 订阅频道按权限过滤：无 `log.read` 则拒绝订阅日志频道。

use crate::{error::ApiError, routes::MaybeAuth, AppState};
use axum::{
    extract::{Query, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use futures_util::stream::StreamExt;
use serde::Deserialize;
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
                        "cpu_pct": s.cpu_pct,
                        "mem_used_kib": s.mem_used_kib,
                        "mem_total_kib": s.mem_total_kib,
                        "disk_used_bytes": s.disk_used_bytes,
                        "disk_total_bytes": s.disk_total_bytes,
                        "net_in_bps": s.net_in_bps,
                        "net_out_bps": s.net_out_bps,
                        "load1": s.load1,
                    }),
                    None => serde_json::json!({ "ts": now_unix(), "cpu_pct": 0.0,
                                                "mem_used_kib": 0, "mem_total_kib": 0,
                                                "disk_used_bytes": 0, "disk_total_bytes": 0,
                                                "net_in_bps": 0, "net_out_bps": 0, "load1": 0.0 }),
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

/// 日志跟随 SSE 的查询参数（契约 `/api/v1/logs/stream`）。
#[derive(Debug, Deserialize)]
pub struct LogStreamQ {
    /// 日志源 id（见 `/api/v1/logs/sources`）；缺省 `system`
    pub source: Option<String>,
    /// 服务端**字面量**子串过滤（刻意不支持正则，防 ReDoS）
    pub filter: Option<String>,
    pub level: Option<String>,
    /// 预读历史行数（服务端硬上限 2000）
    pub limit: Option<usize>,
    #[serde(default)]
    pub follow: Option<bool>,
}

fn line_json(l: &panel_os::LogLine) -> String {
    serde_json::json!({ "ts": l.ts_unix, "level": l.level, "text": l.text }).to_string()
}

/// 通用的「日志源 → SSE」：先补历史（预读），再持续推送增量。
/// 站点日志（`sites::logs`）与统一日志浏览器（`log_stream`）共用此实现。
pub async fn follow_source(
    state: Arc<AppState>,
    src: panel_os::LogSource,
    filter: Option<String>,
    limit: usize,
) -> axum::response::Response {
    let n = limit.clamp(1, 2000);
    let cap = max_clients(state.tier);
    if SSE_CONNS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |k| {
        if k >= cap { None } else { Some(k + 1) }
    }).is_err() {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE,
                format!("sse client limit reached ({cap})")).into_response();
    }

    let history = state.os.logs().read(&src, panel_os::LogQuery {
        lines: n, grep: filter.clone(), level: None, follow: false, since_unix: None,
    }).await.unwrap_or_default();

    let rx = match state.os.logs().follow(&src, panel_os::LogQuery {
        lines: n, grep: filter, level: None, follow: true, since_unix: None,
    }).await {
        Ok(rx) => rx,
        Err(e) => {
            SSE_CONNS.fetch_sub(1, Ordering::SeqCst);
            return ApiError::from(e).into_response();
        }
    };

    let stream = async_stream::stream! {
        for l in history { yield Ok::<_, Infallible>(Event::default().event("log").data(line_json(&l))); }
        let mut rx = rx;
        while let Some(l) = rx.recv().await {
            yield Ok(Event::default().event("log").data(line_json(&l)));
        }
        SSE_CONNS.fetch_sub(1, Ordering::SeqCst);
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("ping"))
        .into_response()
}

/// 日志跟随频道（契约：`/api/v1/logs/stream` 与 `/api/v1/events/logs`）。
pub async fn log_stream(
    State(state): State<Arc<AppState>>,
    // Session 未实现 FromRequestParts，不能直接用 Option<Session> 作提取器；
    // MaybeAuth 即为此设计（Rejection 为 Infallible）。
    MaybeAuth(session): MaybeAuth,
    Query(q): Query<LogStreamQ>,
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
    let want = q.source.clone().unwrap_or_else(|| "system".into());
    let srcs = match state.os.logs().sources().await {
        Ok(v) => v,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let Some(src) = srcs.into_iter().find(|s| s.id == want) else {
        return ApiError::not_found("log source").into_response();
    };
    follow_source(state.clone(), src, q.filter, q.limit.unwrap_or(200)).await
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
