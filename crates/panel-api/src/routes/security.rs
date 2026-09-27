//! 安全中心（设计方案 §2.10）：基线检查、在线会话管理。
//!
//! 本期均为 M5 占位端点：返回结构化 501，待安全基线引擎接入。

use crate::{auth::perm, error::{ApiError, ApiResult}, routes::{Auth, Shared}};
use axum::extract::{Path as AxPath, State};
use axum::Json;

pub async fn baseline(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    Err(ApiError::unsupported("security.baseline (M5: 基线检查尚未接入)"))
}

pub async fn baseline_apply(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    Err(ApiError::unsupported("security.baseline.apply (M5)"))
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
