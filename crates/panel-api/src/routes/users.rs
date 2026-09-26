//! 用户管理（设计方案 §2.12）。M5 接入：管理员 CRUD、角色/权限分配、强制下线。
//! 本期为占位端点，返回结构化 501。登录鉴权链路已在 `auth.rs` 实现。

use crate::{auth::perm, error::ApiError, routes::{Auth, Shared}};
use axum::extract::{Path as AxPath, State};
use axum::Json;

pub async fn list(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    Err(ApiError::unsupported("user.list (M5: 用户管理尚未接入)"))
}

pub async fn create(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    Err(ApiError::unsupported("user.create (M5)"))
}

pub async fn patch(
    State(_): State<Shared>,
    Auth(s): Auth,
    AxPath(_id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    Err(ApiError::unsupported("user.patch (M5)"))
}

pub async fn delete(
    State(_): State<Shared>,
    Auth(s): Auth,
    AxPath(_id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    Err(ApiError::unsupported("user.delete (M5)"))
}
