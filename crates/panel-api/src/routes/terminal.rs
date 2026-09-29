//! 内置 Web 终端（#51 / 设计方案 §3.4 终端）。
//!
//! 协议（WebSocket `GET /api/v1/terminal`，101 升级）：
//! - **服务端 → 客户端**：
//!   - 二进制帧 = PTY 原始输出字节（直接喂给 xterm）。
//!   - 文本帧 = 控制 JSON：`{"t":"ready","shell":"bash"}` / `{"t":"exit","code":N}` /
//!     `{"t":"notice","msg":"..."}`。
//! - **客户端 → 服务端**：
//!   - 二进制帧 = 用户输入原始字节（写进 PTY master，**不经任何 shell 解释**）。
//!   - 文本帧 = 控制 JSON：`{"t":"resize","cols":N,"rows":N}`。
//!
//! **卫士（会话建立的瞬间全部生效，而非逐条命令审计）**：
//! 1. 登录（`panel_sid` HttpOnly Cookie，由 `require_auth` 中间件注入 Session）。
//! 2. `perm::SYSTEM_MANAGE`：终端 = 宿主级代码执行，必须最高管理权限。
//! 3. 能力位 `terminal.manage`：本机必须有可用交互 shell（与 `spawn_pty` 同源探测）。
//! 4. 只读模式拒绝（`PANEL_READ_ONLY=1` 时返回 403，终端可改写宿主状态）。
//! 5. 同源校验：WebSocket 升级无法携带 `X-CSRF-Token` 头，**改用 Origin == scheme://Host**
//!    替代 CSRF（与 `guard_write` 的同源逻辑一致，但 WS 是 GET 不过 guard_write）。
//! 6. 并发上限（`TERMINAL_SEM`，全局固定小容量，避免单个活跃终端拖垮低配机器）。
//! 7. 空闲超时（默认 15min 无客户端输入即 SIGHUP，回收进程组）。
//! 8. 审计（`terminal.open` 落库，含操作者）。

use crate::auth::perm;
use crate::error::ApiError;
use crate::routes::{audit, Auth, Shared};
use axum::{
    extract::{FromRequestParts, State, WebSocketUpgrade},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use panel_core::cap_keys;
use panel_os::cmd::{spawn_pty, Bin, PtyReader};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore, SemaphorePermit};
use axum::extract::ws::{Message, WebSocket};

/// 全局并发上限：Web 终端是高危、低频操作，固定小容量即可（无需按档位配置）。
static TERMINAL_SEM: Semaphore = Semaphore::const_new(4);

/// WS 升级初始终端尺寸（前端 fit 后会立即发 resize）。
const DEFAULT_COLS: u16 = 80;
const DEFAULT_ROWS: u16 = 24;
/// 空闲超时：无客户端输入达到此时长即断开（防终端会话被遗忘常驻）。
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// PTY→WS 桥接通道容量（背压：慢客户端会反向阻塞 PTY 读取，不无限缓冲）。
const PTY_CHANNEL_CAP: usize = 64;

/// 从请求头提取同源校验所需的 Origin / Host（提取器只做读取，不阻断请求）。
pub struct ConnMeta {
    pub origin: Option<String>,
    pub host: Option<String>,
}

impl FromRequestParts<Shared> for ConnMeta {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &Shared) -> Result<Self, Self::Rejection> {
        let origin = parts.headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()).map(str::to_string);
        let host = parts.headers.get(header::HOST).and_then(|v| v.to_str().ok()).map(str::to_string);
        Ok(ConnMeta { origin, host })
    }
}

/// 同源校验：Origin 必须严格等于 `https://{host}` 或 `http://{host}`。
/// 缺失 Origin（非浏览器/非跨站场景）一律拒绝，等价于 `guard_write` 的同源策略，
/// 只是 WS 升级走 GET 不经 guard_write，故在此显式补上。
fn origin_ok(origin: &Option<String>, host: &Option<String>) -> bool {
    let (Some(origin), Some(host)) = (origin, host) else { return false; };
    *origin == format!("https://{host}") || *origin == format!("http://{host}")
}

/// 升级入口 handler。**所有卫士在升级前判定**；升级后只剩桥接与收尾。
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    auth: Auth,
    meta: ConnMeta,
) -> Response {
    // 1) 权限：仅 SYSTEM_MANAGE 可开终端（等价宿主 root shell）
    if crate::auth::require(&auth.0, perm::SYSTEM_MANAGE).is_err() {
        return ApiError::forbidden(perm::SYSTEM_MANAGE).into_response();
    }
    // 2) 能力位：本机必须有可用交互 shell
    if !state.capabilities.get(cap_keys::TERMINAL_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return ApiError::unsupported(cap_keys::TERMINAL_MANAGE).into_response();
    }
    // 3) 只读模式：终端可改写宿主状态，一律拒绝
    if std::env::var("PANEL_READ_ONLY").map(|v| v == "1").unwrap_or(false) {
        return ApiError::read_only().into_response();
    }
    // 4) 同源校验（替代 CSRF：WS 升级无法带 x-csrf-token）
    if !origin_ok(&meta.origin, &meta.host) {
        return ApiError::csrf().into_response();
    }
    // 5) 并发上限
    let permit = match TERMINAL_SEM.try_acquire() {
        Ok(p) => p,
        Err(_) => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "code": 10006, "message": "terminal concurrency limit reached" })),
        ).into_response(),
    };
    // 6) 取 shell（与能力位同源，避免"能力位说有 bash、实际用的却是 sh"漂移）
    let Some(shell) = state.os.terminal().shell() else {
        return ApiError::unsupported(cap_keys::TERMINAL_MANAGE).into_response();
    };
    // 7) 审计：开终端是高危动作，必须留痕
    audit(&state, &auth.0, "terminal.open", shell.as_str(), "ok").await;

    // 升级：101 之后进入桥接循环
    ws.on_upgrade(move |socket| terminal_session(socket, shell, permit))
}

/// 升级后的双向桥接循环。
async fn terminal_session(socket: WebSocket, shell: Bin, _permit: SemaphorePermit<'static>) {
    let (mut sink, mut ws_recv) = socket.split();

    // 终端起始目录取面板进程 HOME（交互体验更自然；spawn_pty 已注入 HOME 环境变量）。
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

    let session = match spawn_pty(shell, DEFAULT_COLS, DEFAULT_ROWS, Some(Path::new(&home))) {
        Ok(s) => s,
        Err(e) => {
            let _ = send_json(&mut sink, &json!({ "t": "notice", "msg": format!("无法启动终端: {e}") })).await;
            let _ = send_json(&mut sink, &json!({ "t": "exit", "code": 1 })).await;
            return;
        }
    };
    let (reader, mut tx) = session.split();

    // 通知前端：终端已就绪（前端据此隐藏"连接中"并聚焦输入框）
    if !send_json(&mut sink, &json!({ "t": "ready", "shell": shell.as_str() })).await {
        return;
    }

    // PTY 读 → channel（背压由通道容量控制，不无限缓冲）
    let (pty_tx, mut pty_rx) = mpsc::channel::<Vec<u8>>(PTY_CHANNEL_CAP);
    let pty_task = tokio::spawn(pty_reader(reader, pty_tx));

    let mut idle_deadline = tokio::time::Instant::now() + IDLE_TIMEOUT;
    loop {
        if tokio::time::Instant::now() >= idle_deadline {
            let _ = send_json(&mut sink, &json!({ "t": "notice", "msg": "空闲超时，连接已关闭" })).await;
            break;
        }
        let remaining = idle_deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::select! {
            // 空闲超时（无客户端输入）→ 断开
            _ = tokio::time::sleep(remaining), if tokio::time::Instant::now() < idle_deadline => {
                let _ = send_json(&mut sink, &json!({ "t": "notice", "msg": "空闲超时，连接已关闭" })).await;
                break;
            }
            // PTY 输出 → WS 二进制帧
            maybe = pty_rx.recv() => {
                match maybe {
                    Some(bytes) => {
                        if sink.send(Message::Binary(bytes.into())).await.is_err() { break; }
                    }
                    None => {
                        // PTY EOF：shell 退出，通知前端并收尾
                        let _ = send_json(&mut sink, &json!({ "t": "exit", "code": 0 })).await;
                        break;
                    }
                }
            }
            // WS 输入 → PTY（二进制=输入，文本=控制）
            msg = ws_recv.next() => {
                match msg {
                    Some(Ok(Message::Binary(b))) => {
                        if tx.write(&b).await.is_err() { break; }
                        idle_deadline = tokio::time::Instant::now() + IDLE_TIMEOUT;
                    }
                    Some(Ok(Message::Text(t))) => {
                        if let Some((cols, rows)) = parse_resize(&t.to_string()) {
                            if tx.resize(cols, rows).is_err() { break; }
                        }
                        idle_deadline = tokio::time::Instant::now() + IDLE_TIMEOUT;
                    }
                    Some(Ok(Message::Ping(p))) => {
                        if sink.send(Message::Pong(p)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                }
            }
        }
    }

    // 收尾：先给整个进程组发 SIGHUP（清掉 shell 启动的前台程序），再回收
    tx.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), pty_task).await;
}

/// PTY 读任务：把 master 输出持续推入 channel，EOF/错误即结束。
async fn pty_reader(mut reader: PtyReader, pty_tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 8192];
    loop {
        match reader.0.read(&mut buf).await {
            Ok(0) => break,                       // EOF：shell 退出
            Ok(n) => { if pty_tx.send(buf[..n].to_vec()).await.is_err() { break; } }
            Err(_) => break,
        }
    }
}

/// 文本控制帧发送（就绪/退出/通知）。
async fn send_json(sink: &mut SplitSink<WebSocket, Message>, v: &Value) -> bool {
    sink.send(Message::Text(v.to_string().into())).await.is_ok()
}

/// 解析客户端 resize 控制帧。`{"t":"resize","cols":N,"rows":N}`。
/// 纯函数，便于单测；非法字段一律回退到默认值而非报错（前端偶发脏帧不应断连）。
fn parse_resize(text: &str) -> Option<(u16, u16)> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("t").and_then(|x| x.as_str()) != Some("resize") { return None; }
    let cols = v.get("cols").and_then(|x| x.as_u64()).unwrap_or(DEFAULT_COLS as u64) as u16;
    let rows = v.get("rows").and_then(|x| x.as_u64()).unwrap_or(DEFAULT_ROWS as u64) as u16;
    Some((cols, rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_must_be_same_site() {
        assert!(origin_ok(&Some("https://h".into()), &Some("h".into())));
        assert!(origin_ok(&Some("http://h".into()), &Some("h".into())));
        assert!(!origin_ok(&Some("https://evil".into()), &Some("h".into())), "跨站必须拒绝");
        assert!(!origin_ok(&None, &Some("h".into())), "缺 Origin 必须拒绝");
        assert!(!origin_ok(&Some("https://h".into()), &None), "缺 Host 必须拒绝");
    }

    #[test]
    fn resize_parsing_is_lenient() {
        assert_eq!(parse_resize(r#"{"t":"resize","cols":120,"rows":40}"#), Some((120, 40)));
        // 缺字段回退默认，不报错
        assert_eq!(parse_resize(r#"{"t":"resize"}"#), Some((DEFAULT_COLS, DEFAULT_ROWS)));
        // 非 resize 控制帧忽略
        assert_eq!(parse_resize(r#"{"t":"ping"}"#), None);
        // 脏帧（非 JSON）忽略
        assert_eq!(parse_resize("not-json"), None);
    }
}
