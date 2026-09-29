//! 安全中心（设计方案 §2.10）：基线检查、在线会话管理。
//!
//! `baseline` 为**只读**扫描，输出契约 `SecurityBaselineItem[]`（分级发现项）。
//! 一键修复（`baseline_apply`）属高危写操作，未实装前诚实 501。
//! 会话管理：数据源是**内存 SessionCache**（非 DB）——重启后面板会话自然清零，
//! 列表与吊销都只对当前存活会话生效，这是如实行为而非缺陷。

use crate::{auth::perm, error::{ok, ApiError, ApiResult}, routes::{audit, Auth, CurrentSid, Shared}};
use axum::extract::{Path as AxPath, State};
use axum::{Json, http::StatusCode};
use serde_json::json;

/// 只读安全基线扫描。
pub async fn baseline(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    let items = state.os.security().baseline().await?;
    let out: Vec<serde_json::Value> = items
        .into_iter()
        .map(|c| serde_json::json!({
            "key": c.key,
            "title": c.title,
            "ok": c.ok,
            "current": c.current,
            "expected": c.expected,
            "advice": c.advice,
            "applicable": c.applicable,
        }))
        .collect();
    Ok(ok(out))
}

/// 一键修复：**高危**（写回系统安全配置，需 root + 二次确认 + 先备份）。
/// 未实装前诚实 501 —— 绝不静默半吊子写入把系统/SSH 锁死。
pub async fn baseline_apply(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    Err(ApiError::unsupported(
        "security.baseline.apply：一键修复会写回系统安全配置（需 root + 二次确认 + 先备份），尚未接入"))
}

/// 在线会话列表（管理员视图，数据源=内存 SessionCache）。
/// **ip 刻意不采集**（会话层没有对端地址管道）——不伪造数据，前端不展示该列。
pub async fn sessions(
    State(state): State<Shared>,
    Auth(s): Auth,
    CurrentSid(cur): CurrentSid,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    let now = crate::now_unix();
    let rows: Vec<serde_json::Value> = state
        .sessions
        .list()
        .into_iter()
        .map(|(sid, sess)| {
            json!({
                "id": sid,
                "user": sess.username,
                "role": sess.role,
                // 诚实占位：会话层无对端 IP，返回 null（前端不渲染该信息）
                "ip": Option::<String>::None,
                "created_at": sess.created_at,
                "last_seen": sess.last_seen,
                "expires_at": sess.expires_at,
                "idle_secs": (now - sess.last_seen).max(0),
                "current": sid == cur,
            })
        })
        .collect();
    let total = rows.len();
    Ok(ok(json!({ "sessions": rows, "total": total })))
}

/// 吊销指定会话。允许吊销自己的当前会话（= 自我登出，前端下个请求 401 跳登录）。
pub async fn revoke_session(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    let gone = state.sessions.remove(&id);
    if !gone {
        return Err(ApiError::not_found("session"));
    }
    // 审计不落完整 sid（sid=凭据，落库等于泄密），截断前 8 位
    audit(&state, &s, "session.revoke", &format!("{}…", &id[..id.len().min(8)]), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}
