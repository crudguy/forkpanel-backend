//! 进程管理（设计方案 §2.2）。
//!
//! 列表来自 `OsAdapter` 进程快照；kill 走 `ProcessProvider::signal`（Linux 为 `libc::kill`）。
//!
//! 两条防失联设计：
//! - provider 内部拒绝 pid<=1 与面板自身进程（PermissionDenied → 403）；
//! - 默认发 SIGTERM，只有用户显式要求才升到 SIGKILL，且 UI 需二次确认。
//!
//! 面板纪律仍然成立：能力缺失 = 明确告知（501），绝不以假数据填充。

use crate::{auth::perm, error::{ok, ApiError, ApiResult}, routes::{audit, Auth, Shared}};
use axum::extract::{Path as AxPath, Query, State};
use axum::Json;
use panel_os::{ProcessSignal, ProcessSort};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ProcQ { pub sort: Option<String>, pub limit: Option<usize> }

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<ProcQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let sort = match q.sort.as_deref() {
        Some("mem") => ProcessSort::Memory,
        Some("pid") => ProcessSort::Pid,
        _ => ProcessSort::Cpu,
    };
    let n = q.limit.unwrap_or(20).clamp(1, 200);
    let list = state.os.metrics().top_processes(n, sort).await?;
    Ok(ok(list))
}

#[derive(Debug, Deserialize)]
pub struct KillReq {
    /// `term`（默认，SIGTERM）或 `kill`（SIGKILL，强制）
    pub signal: Option<String>,
}

pub async fn kill(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(pid): AxPath<String>,
    body: Option<Json<KillReq>>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    let pid: i32 = pid.parse()
        .map_err(|_| ApiError::bad_request("pid", "pid 必须是数字"))?;

    // 默认 SIGTERM：给进程清理现场的机会（刷盘、关连接）。
    // 进程不响应时用户才显式升级到 SIGKILL —— 后者不给任何收尾机会，不能当默认值。
    let name = body.as_ref().and_then(|b| b.signal.as_deref());
    let (sig, label) = match name {
        Some("kill") | Some("sigkill") | Some("force") => (ProcessSignal::Kill, "kill"),
        Some("hup") | Some("sighup") | Some("reload") => (ProcessSignal::Reload, "hup"),
        Some("term") | Some("sigterm") | None => (ProcessSignal::Terminate, "term"),
        Some(other) => return Err(ApiError::bad_request(
            "signal", format!("unknown signal `{other}`；可选 term | hup | kill"))),
    };

    // provider 内部已拒绝 pid<=1 与面板自身，
    // 返回 PermissionDenied → 403（防失联）。再上层（如 SSH 父进程）由 UI 二次确认兜底。
    state.os.processes().signal(pid, sig).await?;
    audit(&state, &s, "process.kill", &format!("{pid}:{label}"), "ok").await;
    Ok(ok(serde_json::json!({ "killed": pid, "signal": label })))
}
