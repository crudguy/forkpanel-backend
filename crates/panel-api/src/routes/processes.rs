//! 进程管理（设计方案 §2.2）。
//!
//! M2 接入目标：列表来自 `OsAdapter` 进程快照，kill 走任务队列且需二次确认
//! （终止 SSH/关键进程需 UI 二次确认，防失联）。本期返回结构化 501，
//! 绝不以假数据填充（面板纪律：能力缺失 = 明确告知，而非伪装成功）。

use crate::{auth::perm, error::ApiError, routes::{Auth, Shared}};
use axum::extract::{Path as AxPath, State};
use axum::Json;

pub async fn list(
    State(_): State<Shared>,
    Auth(s): Auth,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    Err(ApiError::unsupported("process.list (M2: 进程快照尚未接入)"))
}

pub async fn kill(
    State(_): State<Shared>,
    Auth(s): Auth,
    AxPath(_pid): AxPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    Err(ApiError::unsupported(
        "process.kill (M2: 终止进程走任务队列且需二次确认，尚未接入)"))
}
