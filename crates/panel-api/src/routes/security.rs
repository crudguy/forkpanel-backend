//! 安全中心（设计方案 §2.10）：基线检查、在线会话管理。
//!
//! `baseline` 为**只读**扫描，输出契约 `SecurityBaselineItem[]`（分级发现项）。
//! 一键修复（`baseline_apply`）属高危写操作，未实装前诚实 501。
//! 在线会话（`sessions`/`revoke_session`）为另一 feature，本期仍占位。

use crate::{auth::perm, error::{ok, ApiError, ApiResult}, routes::{Auth, Shared}};
use axum::extract::{Path as AxPath, State};
use axum::Json;

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

pub async fn sessions(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    Err(ApiError::unsupported("security.sessions (M5: 在线会话管理尚未接入)"))
}

pub async fn revoke_session(
    State(_): State<Shared>,
    Auth(s): Auth,
    AxPath(_id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    Err(ApiError::unsupported("security.session.revoke (M5)"))
}
