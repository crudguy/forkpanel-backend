//! 本机便签（server notes）。
//!
//! 025 起由单例 `server_note` 改为多条 `server_notes`：单机面板没有 hosts 表、
//! 机器即本机，但「这台机器的事」不止一条（运维禁忌 / 网络变更 / 待办），
//! 单例便签逼用户把所有信息混进一段 500 字里。旧单例内容已由迁移 025
//! 整体迁入为第一条（id 固定 1）。
//!
//! 读对全部登录用户开放；写需 `system.manage`（与「本机说明」属系统级
//! 描述的语义一致）。
//!
//! create **不返回 id**：前端保存后 reload 列表取全量，而编辑/删除用的 id
//! 全部来自列表——自增 id 拿不出 writer actor 闭包（`db.exec` 只回传
//! `WriteAck`），刻意不为此扩展 db 层。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    Json,
};
use panel_core::PanelError;
use serde::Deserialize;
use crate::extract::PanelJson;

/// 单条内容上限（与设计文档一致：长说明应写成文档而非备注）
const REMARK_MAX: usize = 500;
/// 条数上限：防误操作把仪表盘变成博客
const MAX_NOTES: usize = 50;

/// 写请求体（新建 / 更新共用）。
#[derive(Debug, Deserialize)]
pub struct NoteReq {
    pub content: String,
}

/// 内容校验：trim 后非空 + 码点上限于 REMARK_MAX（与前端 `[...draft].length` 对齐）。
fn check_content(raw: &str) -> Result<String, ApiError> {
    let content = raw.trim().to_string();
    if content.is_empty() {
        return Err(ApiError::bad_request("content", "内容不能为空"));
    }
    if content.chars().count() > REMARK_MAX {
        return Err(ApiError::bad_request("content", "备注最多 500 字"));
    }
    Ok(content)
}

/// 列表（读对全员开放）。
///
/// 查询失败**不**静默成空列表——库错误伪装成「没有便签」会让用户以为数据
/// 丢了，违背「状态不撒谎」纪律；前端 load() 自带 catch 降级。
pub async fn list(State(state): State<Shared>, Auth(_s): Auth) -> ApiResult<Json<serde_json::Value>> {
    let items: Vec<serde_json::Value> = state
        .pool
        .with(|conn| {
            let mut stmt = conn
                .prepare("SELECT id, content, updated_at FROM server_notes ORDER BY id ASC")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(serde_json::json!({
                        "id": r.get::<_, i64>(0)?,
                        "content": r.get::<_, String>(1)?,
                        "updated_at": r.get::<_, i64>(2)?,
                    }))
                })
                .map_err(|e| PanelError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await?;
    Ok(ok(serde_json::Value::Array(items)))
}

/// 新建便签（写需 `system.manage`）。
pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<NoteReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    let content = check_content(&req.content)?;
    // 先读后写：条数校验走读池，零写锁占用
    let count: i64 = state
        .pool
        .with(|conn| {
            conn.query_row("SELECT COUNT(*) FROM server_notes", [], |r| r.get(0))
                .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    if count as usize >= MAX_NOTES {
        return Err(ApiError::bad_request(
            "content",
            format!("便签最多 {MAX_NOTES} 条，请先删除再添加"),
        ));
    }
    let now = now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO server_notes(content, created_at, updated_at) VALUES(?1, ?2, ?2)",
                rusqlite::params![content, now],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "server.note.create", "self", "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 更新便签（写需 `system.manage`；id 不存在 → 404）。
pub async fn update(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<NoteReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    let content = check_content(&req.content)?;
    ensure_exists(&state, id).await?;
    let now = now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE server_notes SET content = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![content, now, id],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "server.note.update", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 删除便签（写需 `system.manage`；id 不存在 → 404）。
pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    ensure_exists(&state, id).await?;
    state
        .db
        .exec(move |conn| {
            conn.execute("DELETE FROM server_notes WHERE id = ?1", rusqlite::params![id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "server.note.delete", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 先读后写：id 不存在 → 404（「缺失即 404、非法即 400」的既定分层）。
async fn ensure_exists(state: &Shared, id: i64) -> Result<(), ApiError> {
    let found: bool = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM server_notes WHERE id = ?1)",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    if !found {
        return Err(ApiError::not_found("便签不存在"));
    }
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn mem_db() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        panel_db::migrate::apply(&mut c).unwrap();
        c
    }

    /// 025 迁移后的 schema 形状：新表就绪、旧单例表已 DROP
    /// （数据保迁——旧内容迁入为第一条——由 dev 库实机升级覆盖：
    ///  现网 server_note 正带着 8 行真实内容）
    #[test]
    fn schema_after_migration_025() {
        let c = mem_db();
        // 新表四列可读（空库无行 → QueryReturnedNoRows，但列解析已通过）
        let e = c
            .query_row(
                "SELECT id, content, created_at, updated_at FROM server_notes WHERE id = 1",
                [],
                |_| Ok(()),
            )
            .unwrap_err();
        assert!(
            matches!(e, rusqlite::Error::QueryReturnedNoRows),
            "空库应无行而非结构错: {e:?}"
        );
        // 旧单例表已不存在
        let old: std::result::Result<i64, _> =
            c.query_row("SELECT COUNT(*) FROM server_note", [], |r| r.get(0));
        assert!(old.is_err(), "server_note 应已在 025 中 DROP");
    }

    /// CRUD 往返 + updated_at 刷新 + 只动目标行
    #[test]
    fn create_update_delete_roundtrip() {
        let c = mem_db();
        c.execute(
            "INSERT INTO server_notes(content, created_at, updated_at) VALUES('甲', 100, 100)",
            [],
        )
        .unwrap();
        let id1 = c.last_insert_rowid();
        c.execute(
            "INSERT INTO server_notes(content, created_at, updated_at) VALUES('乙', 100, 100)",
            [],
        )
        .unwrap();
        let id2 = c.last_insert_rowid();
        assert_ne!(id1, id2);

        // update 只动目标行，且刷新 updated_at
        c.execute(
            "UPDATE server_notes SET content = '甲改', updated_at = 200 WHERE id = ?1",
            [id1],
        )
        .unwrap();
        let (c1, u1): (String, i64) = c
            .query_row(
                "SELECT content, updated_at FROM server_notes WHERE id = ?1",
                [id1],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((c1.as_str(), u1), ("甲改", 200));
        let u2: i64 = c
            .query_row(
                "SELECT updated_at FROM server_notes WHERE id = ?1",
                [id2],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(u2, 100, "update 不得波及邻行");

        // delete 只删目标行
        c.execute("DELETE FROM server_notes WHERE id = ?1", [id1]).unwrap();
        let left: i64 = c
            .query_row("SELECT COUNT(*) FROM server_notes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1);
        let gone: std::result::Result<i64, _> =
            c.query_row("SELECT id FROM server_notes WHERE id = ?1", [id1], |r| r.get(0));
        assert!(gone.is_err());
    }

    #[test]
    fn content_validation_rejects_empty_and_overlong() {
        assert!(check_content("").is_err());
        assert!(check_content("   \n\t ").is_err());
        assert!(check_content(&"x".repeat(REMARK_MAX)).is_ok());
        assert!(check_content(&"x".repeat(REMARK_MAX + 1)).is_err());
        // 码点计数而非 UTF-16 length：emoji 只算 1
        assert!(check_content(&"😀".repeat(REMARK_MAX)).is_ok());
        assert!(check_content(&"😀".repeat(REMARK_MAX + 1)).is_err());
    }
}
