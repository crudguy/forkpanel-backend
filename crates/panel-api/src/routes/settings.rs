//! 面板设置（设计方案 §2.11）。M5 接入：读写面板级配置（时区、语言、通知等）。
//! 本期为占位端点，返回结构化 501。

use crate::{auth::perm, error::{ApiError, ApiResult}, routes::{Auth, Shared}};
use axum::extract::State;
use axum::Json;

pub async fn get(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SETTINGS_MANAGE)?;
    Err(ApiError::unsupported("settings.get (M5: 面板设置尚未接入)"))
}

pub async fn patch(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SETTINGS_MANAGE)?;
    Err(ApiError::unsupported("settings.patch (M5)"))
}
