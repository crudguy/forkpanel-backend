//! 站内通知（in-app notifications）。
//!
//! **为什么先做站内、不做邮件/Webhook**：外部通道需要 `reqwest`（HTTP）与
//! `lettre`（SMTP），各占一个直接依赖位；依赖预算门禁 [8] 上限 38、当前 36，
//! 须留给更高价值模块。站内通知零新增依赖，且对单机面板已覆盖主要诉求——
//! **用户打开面板就能看见**，而不是依赖外部可达性。
//!
//! **去重**：`dedup_key` 唯一约束 + `INSERT OR IGNORE`。是否去重由调用方决定：
//! 把时间粒度编进键（如按天 `backup:3:fail:20260929`）即可实现"同类问题每天最多一条"，
//! 避免每次失败都刷屏。键为 `NULL` 表示不去重。
//!
//! **落点纪律**：只报**需要人处置**的事。成功不通知（避免噪音），
//! 失败/风险才通知——通知一旦变成噪音，用户会整体忽略它。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    Json,
};
use panel_core::PanelError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// SQL 全部写成编译期常量（分层门禁 [5] 禁止 format! 拼 SQL，与 sites.rs 同一纪律）
const SQL_LIST_ALL: &str =
    "SELECT id, ts, level, source, title, body, read FROM notifications ORDER BY ts DESC LIMIT ?1";
const SQL_LIST_UNREAD: &str =
    "SELECT id, ts, level, source, title, body, read FROM notifications WHERE read = 0 ORDER BY ts DESC LIMIT ?1";
const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;

#[derive(Debug, Serialize)]
pub struct NotificationDto {
    pub id: i64,
    pub ts: i64,
    pub level: String,
    pub source: String,
    pub title: String,
    pub body: Option<String>,
    pub read: bool,
}

fn row_dto(r: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationDto> {
    Ok(NotificationDto {
        id: r.get(0)?,
        ts: r.get(1)?,
        level: r.get(2)?,
        source: r.get(3)?,
        title: r.get(4)?,
        body: r.get(5)?,
        read: r.get::<_, i64>(6)? != 0,
    })
}

/// 新通知。**level/source 为受控枚举**，非法值归为 `warn`/`system` 而非报错——
/// 通知失败不该让业务操作失败。
pub struct NewNotification {
    pub level: &'static str,
    pub source: &'static str,
    pub title: String,
    pub body: Option<String>,
    /// 去重键；`None` = 不去重
    pub dedup_key: Option<String>,
}

/// 落一条通知。**永不因通知失败而中断调用方**：结果仅记日志。
///
/// 各模块（备份/恢复/证书/任务）在失败或风险分支调用本函数。
pub async fn push(db: &Arc<panel_db::WriterActor>, n: NewNotification) {
    let level = match n.level {
        "info" | "warn" | "crit" => n.level,
        other => {
            eprintln!("[panel] 通知 level 非法（{other}），已降级为 warn");
            "warn"
        }
    };
    let source = if n.source.is_empty() { "system" } else { n.source };
    let ts = crate::now_unix();
    let res = db
        .exec(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO notifications(ts, level, source, title, body, dedup_key) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![ts, level, source, n.title, n.body, n.dedup_key],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await;
    if let Err(e) = res {
        eprintln!("[panel] 写入通知失败：{e}");
    }
}

// ─────────────── 端点 ───────────────

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u32>,
    /// true = 只要未读
    pub unread_only: Option<bool>,
}

/// GET /api/v1/notifications
pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let unread_only = q.unread_only.unwrap_or(false);

    let items = state
        .pool
        .with(move |conn| {
            // WHERE 分支在 Rust 侧选定后各自 prepare（参数化，值不进 SQL 文本）
            let sql = if unread_only { SQL_LIST_UNREAD } else { SQL_LIST_ALL };
            let mut st = conn
                .prepare(sql)
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let it = st
                .query_map([limit], row_dto)
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(it.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| PanelError::Database(e.to_string()))?)
        })
        .await?;
    Ok(ok(items))
}

/// GET /api/v1/notifications/unread-count —— 前端徽章用（轻量，单行聚合）
pub async fn unread_count(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let count: i64 = state
        .pool
        .with(|conn| {
            conn.query_row("SELECT COUNT(*) FROM notifications WHERE read = 0", [], |r| r.get(0))
                .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    Ok(ok(serde_json::json!({ "count": count })))
}

/// POST /api/v1/notifications/{id}/read
pub async fn mark_read(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let changed = set_read(&state, Some(id)).await?;
    if changed == 0 {
        return Err(ApiError::not_found("notification"));
    }
    Ok(ok(true))
}

/// POST /api/v1/notifications/read-all
pub async fn read_all(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let changed = set_read(&state, None).await?;
    Ok(ok(serde_json::json!({ "updated": changed })))
}

/// `id=None` 表示全部标记已读。返回受影响行数。
async fn set_read(state: &Shared, id: Option<i64>) -> ApiResult<i64> {
    let n = state
        .db
        .exec(move |conn| {
            let rows = match id {
                Some(i) => conn.execute("UPDATE notifications SET read = 1 WHERE id = ?1", [i]),
                None => conn.execute("UPDATE notifications SET read = 1 WHERE read = 0", []),
            }
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: rows })
        })
        .await?;
    Ok(n.rows_changed as i64)
}

/// DELETE /api/v1/notifications/{id}
pub async fn remove(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    let n = state
        .db
        .exec(move |conn| {
            let rows = conn
                .execute("DELETE FROM notifications WHERE id = ?1", [id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: rows })
        })
        .await?;
    if n.rows_changed == 0 {
        return Err(ApiError::not_found("notification"));
    }
    audit(&*state, &s, "notification.delete", &id.to_string(), "ok").await;
    Ok(ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_is_clamped() {
        // 上溢与下溢都必须落在 [1, MAX_LIMIT]
        assert_eq!(0u32.clamp(1, MAX_LIMIT), 1);
        assert_eq!(9999u32.clamp(1, MAX_LIMIT), MAX_LIMIT);
        assert_eq!(DEFAULT_LIMIT, 50);
    }
}
