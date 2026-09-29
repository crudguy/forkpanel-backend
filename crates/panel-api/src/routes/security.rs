//! 安全中心（设计方案 §2.10）：基线检查、在线会话管理。
//!
//! `baseline` 为**只读**扫描，输出契约 `SecurityBaselineItem[]`（分级发现项）。
//! 一键修复（`baseline_apply`）已实装但**仅限 sshd 三项白名单**：
//! 先备份 → 写 → `sshd -t` 校验 → 不通过回滚；校验器不可用则拒绝修改（绝不把人锁在门外）。
//! 会话管理：SessionCache 以内存为快路径，同时落 `sessions` 表 **（只存 sid 哈希）**；
//! 面板重启后按哈希惰性重建，会话**不再**全员登出。

use crate::{auth::perm, error::{ok, ApiError, ApiResult}, routes::{audit, Auth, CurrentSid, Shared}};
use axum::extract::{Path as AxPath, State};
use axum::{Json, http::StatusCode};
use serde::Deserialize;
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
/// 一键修复的二次确认词（写回系统配置属高危，必须手输确认）
pub const APPLY_CONFIRM_WORD: &str = "确认修复";

#[derive(Debug, Deserialize)]
pub struct BaselineApplyReq {
    /// 基线项 key；**白名单**由 provider 层判定（ssh.permit_root_login / ssh.password_auth / ssh.pubkey_auth）
    pub key: String,
    /// 二次确认词，须等于 [`APPLY_CONFIRM_WORD`]
    pub confirm_token: String,
}

/// 一键修复指定基线项（**高危写**）。
///
/// 安全网全部在 provider 层（`panel-os/linux/security.rs`）：
/// 先备份 → 写 → `sshd -t` 校验 → 不通过立刻回滚；**校验器不可用时拒绝修改**。
/// 这里只做权限、确认词与审计。
pub async fn baseline_apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<BaselineApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    if req.confirm_token.trim() != APPLY_CONFIRM_WORD {
        return Err(ApiError::bad_request(
            "confirm_token",
            format!("请输入确认词「{APPLY_CONFIRM_WORD}」以继续"),
        ));
    }

    let r = state.os.security().apply(&req.key).await.map_err(ApiError::from)?;
    audit(
        &state,
        &s,
        "security.baseline.apply",
        &req.key,
        if r.changed { "changed" } else { "unchanged" },
    )
    .await;
    Ok(ok(r))
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
