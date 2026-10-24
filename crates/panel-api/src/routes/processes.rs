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
use panel_core::cap_keys;
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
    // 能力门：前端 ProcessesView 整页置灰读的就是这一位（auth.supported(PROCESS_LIST)）。
    // 模块 doc 承诺的「能力缺失 = 明确告知（501）」此前没有代码兑现——不支持时
    // provider 直接报错，前端拿到的是 500 语义的失败而非可预期的 501，
    // 用户看到「加载失败」而不是「当前环境不支持进程管理」。
    if !state.capabilities.get(cap_keys::PROCESS_LIST).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("process.list"));
    }
    let sort = match q.sort.as_deref() {
        Some("mem") => ProcessSort::Memory,
        Some("pid") => ProcessSort::Pid,
        _ => ProcessSort::Cpu,
    };
    // limit=0（或省略）= 展示全部进程；非零则截断并兜底上限 8192。
    let n = q.limit.unwrap_or(0);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sess(permissions: &[&str]) -> crate::auth::Session {
        crate::auth::Session {
            user_id: 1, username: "tester".into(), role: "admin".into(),
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
            allowed_roots: vec![], ip: "unknown".into(),
            created_at: 0, last_seen: 0, expires_at: 0,
        }
    }

    /// 强制 PROCESS_LIST 为指定能力位的 mock 态（其余照 mock 默认）。
    fn state_with(cap: panel_core::Capability) -> std::sync::Arc<crate::AppState> {
        let mut st = crate::test_support::mock_app_state();
        st.capabilities.insert(cap_keys::PROCESS_LIST.into(), cap);
        std::sync::Arc::new(st)
    }

    /// 二轮审计 P1-22：前端 ProcessesView 整页置灰读的就是
    /// `auth.supported(PROCESS_LIST)`（"当前环境不支持进程管理"），后端必须同口径。
    ///
    /// 修复前 `list` **没有能力门**——模块 doc 承诺「能力缺失 = 明确告知（501）」
    /// 却没有代码兑现：不支持时 provider 直接报错，用户看到的是「加载失败」
    /// （500 语义）而非可预期的 501，置灰与后端双双落空。
    #[tokio::test]
    async fn list_returns_501_when_process_list_unsupported() {
        let state = state_with(panel_core::Capability::no("forced_no"));
        let err = list(
            State(state),
            Auth(sess(&[perm::SYSTEM_VIEW])),
            Query(ProcQ { sort: None, limit: None }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::NOT_IMPLEMENTED,
            "必须是 501，不能是 provider 深处报错的 500");
        assert_eq!(err.code, 10009, "必须走 unsupported 错误码");
    }

    /// **阳性对照**（防恒绿/恒红）：能力位 yes 时门必须放行。
    /// 若把条件写反（`if supported { return 501 }`），上面那条照样绿、这条红。
    #[tokio::test]
    async fn list_serves_when_process_list_supported() {
        let state = state_with(panel_core::Capability::yes("procfs"));
        let res = list(
            State(state),
            Auth(sess(&[perm::SYSTEM_VIEW])),
            Query(ProcQ { sort: Some("mem".into()), limit: Some(3) }),
        )
        .await;
        assert!(res.is_ok(), "能力位 yes 时 list 应正常服务: {:?}",
            res.err().map(|e| e.message));
    }

    /// 能力位**缺键**（map 里根本没有 PROCESS_LIST）同样必须 501：
    /// `unwrap_or(false)` 不容许「查不到就当支持」——那正是静默失同步的入口。
    #[tokio::test]
    async fn list_returns_501_when_capability_key_absent() {
        let mut st = crate::test_support::mock_app_state();
        st.capabilities.remove(cap_keys::PROCESS_LIST);
        let state = std::sync::Arc::new(st);
        let err = list(
            State(state),
            Auth(sess(&[perm::SYSTEM_VIEW])),
            Query(ProcQ { sort: None, limit: None }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, 10009, "缺键必须按不支持处理");
    }
}
