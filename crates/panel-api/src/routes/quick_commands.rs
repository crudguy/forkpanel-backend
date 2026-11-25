//! 用户级终端快捷命令（039）。
//!
//! 按 `user_id` 隔离：**所有**读写都带 `user_id` 条件，更新/删除时「不存在」与
//! 「不属于你」统一回 404（不暴露他人资源是否存在，与 multipart.rs 同一口径）。
//! 预置命令不入库——它们是前端常量，服务端只存用户自建项。
//!
//! 读对全部登录用户开放，写只需登录（改自己的偏好，不要求 system.manage）。
//! create 不返回 id（`db.exec` 只回传 WriteAck），前端保存后 reload 列表取 id。

use crate::{
    error::{ok, ApiError, ApiResult},
    extract::PanelJson,
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    Json,
};
use panel_core::{now_unix, PanelError};
use serde::Deserialize;
use serde_json::{json, Value};

const MAX_LABEL: usize = 40;
const MAX_CMD: usize = 500;
const MAX_DESC: usize = 80;
const MAX_ITEMS: i64 = 50;

/// 新建 / 更新共用请求体。
#[derive(Debug, Deserialize)]
pub struct QuickCommandReq {
    pub label: String,
    pub cmd: String,
    #[serde(default)]
    pub desc: String,
}

/// 校验：trim 后非空 + 码点上限；命令必须单行（多行交 PTY 会被逐行执行）。
/// 与前端 `validateQuickCommand` 同规则，一处改了另一处必须跟着改。
fn check_input(req: &QuickCommandReq) -> Result<(String, String, String), ApiError> {
    let label = req.label.trim().to_string();
    let cmd = req.cmd.trim().to_string();
    let desc = req.desc.trim().to_string();
    if label.is_empty() {
        return Err(ApiError::bad_request("label", "名称不能为空"));
    }
    if label.chars().count() > MAX_LABEL {
        return Err(ApiError::bad_request("label", format!("名称最多 {MAX_LABEL} 个字符")));
    }
    if cmd.is_empty() {
        return Err(ApiError::bad_request("cmd", "命令不能为空"));
    }
    if cmd.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(ApiError::bad_request("cmd", "命令必须是单行，不能包含换行"));
    }
    if cmd.chars().count() > MAX_CMD {
        return Err(ApiError::bad_request("cmd", format!("命令最多 {MAX_CMD} 个字符")));
    }
    if desc.chars().count() > MAX_DESC {
        return Err(ApiError::bad_request("desc", format!("说明最多 {MAX_DESC} 个字符")));
    }
    Ok((label, cmd, desc))
}

/// 列表：只返回当前用户的自建命令。
pub async fn list(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<Value>> {
    let uid = s.user_id;
    let items: Vec<Value> = state
        .pool
        .with(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, label, cmd, description FROM user_quick_commands \
                     WHERE user_id = ?1 ORDER BY id ASC",
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([uid], |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?,
                        "label": r.get::<_, String>(1)?,
                        "cmd": r.get::<_, String>(2)?,
                        "desc": r.get::<_, String>(3)?,
                    }))
                })
                .map_err(|e| PanelError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await?;
    Ok(ok(Value::Array(items)))
}

/// 新建：绑定当前用户，超限 400。
pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<QuickCommandReq>,
) -> ApiResult<Json<Value>> {
    let (label, cmd, desc) = check_input(&req)?;
    let uid = s.user_id;
    let count: i64 = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM user_quick_commands WHERE user_id = ?1",
                [uid],
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    if count >= MAX_ITEMS {
        return Err(ApiError::bad_request(
            "cmd",
            format!("快捷命令最多 {MAX_ITEMS} 条，请先删除再添加"),
        ));
    }
    let now = now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO user_quick_commands(user_id, label, cmd, description, created_at, updated_at) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?5)",
                rusqlite::params![uid, label, cmd, desc, now],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "quick_command.create", "self", "ok").await;
    Ok(ok(json!({ "ok": true })))
}

/// 更新：只改当前用户自己的那一行；他人/不存在的 id 一律 404。
pub async fn update(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<QuickCommandReq>,
) -> ApiResult<Json<Value>> {
    let (label, cmd, desc) = check_input(&req)?;
    let uid = s.user_id;
    ensure_owned(&state, id, uid).await?;
    let now = now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE user_quick_commands SET label = ?1, cmd = ?2, description = ?3, updated_at = ?4 \
                 WHERE id = ?5 AND user_id = ?6",
                rusqlite::params![label, cmd, desc, now, id, uid],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "quick_command.update", &id.to_string(), "ok").await;
    Ok(ok(json!({ "ok": true })))
}

/// 删除：同样带 user_id 条件，避免越权删掉他人命令。
pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<Value>> {
    let uid = s.user_id;
    ensure_owned(&state, id, uid).await?;
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "DELETE FROM user_quick_commands WHERE id = ?1 AND user_id = ?2",
                rusqlite::params![id, uid],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "quick_command.delete", &id.to_string(), "ok").await;
    Ok(ok(json!({ "ok": true })))
}

/// 所有权判定：带 user_id 的 EXISTS，「不属于你」与「不存在」同回 404。
async fn ensure_owned(state: &Shared, id: i64, uid: i64) -> Result<(), ApiError> {
    let found: bool = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM user_quick_commands WHERE id = ?1 AND user_id = ?2)",
                rusqlite::params![id, uid],
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    if !found {
        return Err(ApiError::not_found("快捷命令不存在"));
    }
    Ok(())
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

    fn req(label: &str, cmd: &str, desc: &str) -> QuickCommandReq {
        QuickCommandReq { label: label.into(), cmd: cmd.into(), desc: desc.into() }
    }

    #[test]
    fn validation_matches_frontend_rules() {
        assert!(check_input(&req("", "ls", "")).is_err());
        assert!(check_input(&req("x", "", "")).is_err());
        assert!(check_input(&req("x", "ls\nwhoami", "")).is_err());
        assert!(check_input(&req("x", "ls\0", "")).is_err());
        assert!(check_input(&req(&"x".repeat(MAX_LABEL + 1), "ls", "")).is_err());
        assert!(check_input(&req("x", &"a".repeat(MAX_CMD + 1), "")).is_err());
        assert!(check_input(&req("x", "ls", &"d".repeat(MAX_DESC + 1))).is_err());
        let (l, c, d) = check_input(&req(" 状态 ", " git status ", " 说明 ")).unwrap();
        assert_eq!((l.as_str(), c.as_str(), d.as_str()), ("状态", "git status", "说明"));
    }

    /// 用户隔离：list 只返回本人；update/delete 带 user_id 后不会波及他人行。
    #[test]
    fn rows_are_isolated_by_user() {
        let c = mem_db();
        // user_quick_commands.user_id 有外键指向 users(id)；先建两名用户再插命令。
        for uid in [1, 2] {
            c.execute(
                "INSERT INTO users(id, username, pwd_hash, role, allowed_roots, created_at) \
                 VALUES(?1, ?2, 'x', 'operator', '[]', 100)",
                rusqlite::params![uid, format!("u{uid}")],
            )
            .unwrap();
        }
        for (uid, label) in [(1, "甲的"), (2, "乙的")] {
            c.execute(
                "INSERT INTO user_quick_commands(user_id, label, cmd, description, created_at, updated_at) \
                 VALUES(?1, ?2, 'ls', '', 100, 100)",
                rusqlite::params![uid, label],
            )
            .unwrap();
        }
        let id_a: i64 = c.query_row(
            "SELECT id FROM user_quick_commands WHERE user_id = 1", [], |r| r.get(0),
        ).unwrap();
        let id_b: i64 = c.query_row(
            "SELECT id FROM user_quick_commands WHERE user_id = 2", [], |r| r.get(0),
        ).unwrap();

        let mine: String = c.query_row(
            "SELECT label FROM user_quick_commands WHERE user_id = ?1 ORDER BY id ASC LIMIT 1",
            [1], |r| r.get(0),
        ).unwrap();
        assert_eq!(mine, "甲的");

        c.execute(
            "UPDATE user_quick_commands SET label = '改' WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![id_a, 2],
        ).unwrap();
        let a_after: String = c.query_row(
            "SELECT label FROM user_quick_commands WHERE id = ?1", [id_a], |r| r.get(0),
        ).unwrap();
        assert_eq!(a_after, "甲的", "用别人的 user_id 不得改到甲的行");

        c.execute(
            "DELETE FROM user_quick_commands WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![id_a, 2],
        ).unwrap();
        let left: i64 = c.query_row("SELECT COUNT(*) FROM user_quick_commands", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 2, "越权删除应影响 0 行");
        assert_ne!(id_a, id_b);
    }
}
