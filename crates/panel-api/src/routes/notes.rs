//! 本机说明（server note）。
//!
//! 单机面板没有 `hosts` 表，机器即本机。把「这台机器是干嘛的」存成单例
//! `server_note`（id 恒为 1）。读对全部登录用户开放；写需 `system.manage`
//! （与「本机说明」属系统级描述的语义一致）。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{State},
    http::StatusCode,
    Json,
};
use panel_core::PanelError;
use serde::Deserialize;

/// 备注内容上限（与设计文档一致：长说明应写成文档而非备注）。
const REMARK_MAX: usize = 500;

/// 更新本机说明请求体。
#[derive(Debug, Deserialize)]
pub struct RemarkReq {
    pub content: String,
}

/// 读取本机说明（全部登录用户可读）。
pub async fn get_note(
    State(state): State<Shared>,
    Auth(_s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    let content: String = state
        .pool
        .with(|conn| {
            conn.query_row("SELECT content FROM server_note WHERE id = 1", [], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
        .unwrap_or_default();
    Ok(ok(serde_json::json!({ "content": content })))
}

/// 更新本机说明（写需 `system.manage`）。
pub async fn update_note(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<RemarkReq>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    let content = req.content.trim().to_string();
    if content.chars().count() > REMARK_MAX {
        return Err(ApiError::bad_request("content", "备注最多 500 字"));
    }
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE server_note SET content = ?1 WHERE id = 1",
                rusqlite::params![content],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    audit(&state, &s, "server.note", "self", "ok").await;
    Ok(StatusCode::NO_CONTENT)
}
