//! 用户级终端快捷命令（039 / 040）。
//!
//! 按 `user_id` 隔离：**所有**读写都带 `user_id` 条件，更新/删除时「不存在」与
//! 「不属于你」统一回 404（不暴露他人资源是否存在，与 multipart.rs 同一口径）。
//! 预置命令不入库——它们是前端常量，服务端只存用户自建项。
//!
//! 读对全部登录用户开放，写只需登录（改自己的偏好，不要求 system.manage）。
//! create 不返回 id（`db.exec` 只回传 WriteAck），前端保存后 reload 列表取 id。
//!
//! 040 起取消「名称」字段：浮层里展示的是命令文本本身，名称从未出现在界面上，
//! 凭它既认不出也点不准。唯一性改锚定 **命令内容**——同一条命令配两条记录才是
//! 真正会让用户误点的重复。

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

const MAX_CMD: usize = 500;
const MAX_DESC: usize = 80;
const MAX_ITEMS: i64 = 50;

/// 新建 / 更新共用请求体。
#[derive(Debug, Deserialize)]
pub struct QuickCommandReq {
    pub cmd: String,
    #[serde(default)]
    pub desc: String,
}

/// 校验：trim 后非空 + 码点上限；命令必须单行（多行交 PTY 会被逐行执行）。
/// 与前端 `quickFieldError` 同规则，一处改了另一处必须跟着改。
fn check_input(req: &QuickCommandReq) -> Result<(String, String), ApiError> {
    let cmd = req.cmd.trim().to_string();
    let desc = req.desc.trim().to_string();
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
    Ok((cmd, desc))
}

/// 命令查重（按 user_id）：编辑态传 `exclude_id` 排除自身，否则「只改说明」
/// 会被自己的旧命令挡住。抽成可单测函数，让「新增冲突 / 编辑冲突 / 编辑自身」
/// 三条路径都能用内存库钉住，而不是只靠 handler 的端到端测试。
///
/// 库上另有 `(user_id, cmd)` 唯一索引兜底并发：应用层查重与 INSERT 之间仍有
/// 窗口，两条并发请求可能双双通过此处。
fn cmd_taken(
    conn: &rusqlite::Connection,
    uid: i64,
    cmd: &str,
    exclude_id: Option<i64>,
) -> Result<bool, PanelError> {
    let found = if let Some(id) = exclude_id {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_quick_commands \
             WHERE user_id = ?1 AND cmd = ?2 AND id <> ?3)",
            rusqlite::params![uid, cmd, id],
            |r| r.get::<_, bool>(0),
        )
    } else {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_quick_commands WHERE user_id = ?1 AND cmd = ?2)",
            rusqlite::params![uid, cmd],
            |r| r.get::<_, bool>(0),
        )
    }
    .map_err(|e| PanelError::Database(e.to_string()))?;
    Ok(found)
}

/// 列表：只返回当前用户的自建命令。
pub async fn list(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<Value>> {
    let uid = s.user_id;
    let items: Vec<Value> = state
        .pool
        .with(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, cmd, description FROM user_quick_commands \
                     WHERE user_id = ?1 ORDER BY id ASC",
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([uid], |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?,
                        "cmd": r.get::<_, String>(1)?,
                        "desc": r.get::<_, String>(2)?,
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
    let (cmd, desc) = check_input(&req)?;
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
    // 同一条命令存两条，浮层里并排两行一模一样，用户点哪个都一样——写入前按
    // 当前用户查重（前端也拦，这里是服务端兜底）。
    let c = cmd.clone();
    let taken = state
        .pool
        .with(move |conn| cmd_taken(conn, uid, &c, None))
        .await?;
    if taken {
        return Err(ApiError::bad_request("cmd", "该命令已存在，请勿重复添加"));
    }
    let now = now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO user_quick_commands(user_id, cmd, description, created_at, updated_at) \
                 VALUES(?1, ?2, ?3, ?4, ?4)",
                rusqlite::params![uid, cmd, desc, now],
            )
            // 唯一索引兜住 race：并发两次同命令，后到的那次在这里失败。
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(err, _)
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    PanelError::Validation { field: "cmd", reason: "该命令已存在，请勿重复添加".into() }
                }
                other => PanelError::Database(other.to_string()),
            })?;
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
    let (cmd, desc) = check_input(&req)?;
    let uid = s.user_id;
    ensure_owned(&state, id, uid).await?;
    // 编辑时排除自身：只改说明、沿用原命令不算冲突。
    let c = cmd.clone();
    let taken = state
        .pool
        .with(move |conn| cmd_taken(conn, uid, &c, Some(id)))
        .await?;
    if taken {
        return Err(ApiError::bad_request("cmd", "该命令已存在，请勿重复添加"));
    }
    let now = now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE user_quick_commands SET cmd = ?1, description = ?2, updated_at = ?3 \
                 WHERE id = ?4 AND user_id = ?5",
                rusqlite::params![cmd, desc, now, id, uid],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(err, _)
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    PanelError::Validation { field: "cmd", reason: "该命令已存在，请勿重复添加".into() }
                }
                other => PanelError::Database(other.to_string()),
            })?;
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

    fn req(cmd: &str, desc: &str) -> QuickCommandReq {
        QuickCommandReq { cmd: cmd.into(), desc: desc.into() }
    }

    fn mk_user(c: &Connection, uid: i64) {
        c.execute(
            "INSERT INTO users(id, username, pwd_hash, role, allowed_roots, created_at) \
             VALUES(?1, ?2, 'x', 'operator', '[]', 100)",
            rusqlite::params![uid, format!("u{uid}")],
        )
        .unwrap();
    }

    fn mk_cmd(c: &Connection, uid: i64, cmd: &str) {
        c.execute(
            "INSERT INTO user_quick_commands(user_id, cmd, description, created_at, updated_at) \
             VALUES(?1, ?2, '', 100, 100)",
            rusqlite::params![uid, cmd],
        )
        .unwrap();
    }

    #[test]
    fn validation_matches_frontend_rules() {
        assert!(check_input(&req("", "")).is_err());
        assert!(check_input(&req("ls\nwhoami", "")).is_err());
        assert!(check_input(&req("ls\0", "")).is_err());
        assert!(check_input(&req(&"a".repeat(MAX_CMD + 1), "")).is_err());
        assert!(check_input(&req("ls", &"d".repeat(MAX_DESC + 1))).is_err());
        let (c, d) = check_input(&req(" git status ", " 说明 ")).unwrap();
        assert_eq!((c.as_str(), d.as_str()), ("git status", "说明"));
    }

    /// 040 去掉了「名称」：请求体里不再有 label，多传也必须被静默忽略。
    #[test]
    fn label_is_gone_from_request_body() {
        let parsed: QuickCommandReq =
            serde_json::from_str(r#"{ "cmd": "ls", "desc": "列表", "label": "旧客户端传的名称" }"#).unwrap();
        assert_eq!(parsed.cmd, "ls");
        assert_eq!(parsed.desc, "列表");
    }

    /// 用户隔离：list 只返回本人；update/delete 带 user_id 后不会波及他人行。
    #[test]
    fn rows_are_isolated_by_user() {
        let c = mem_db();
        // user_quick_commands.user_id 有外键指向 users(id)；先建两名用户再插命令。
        mk_user(&c, 1);
        mk_user(&c, 2);
        mk_cmd(&c, 1, "ls");
        mk_cmd(&c, 2, "pwd");

        let id_a: i64 = c.query_row(
            "SELECT id FROM user_quick_commands WHERE user_id = 1", [], |r| r.get(0),
        ).unwrap();
        let id_b: i64 = c.query_row(
            "SELECT id FROM user_quick_commands WHERE user_id = 2", [], |r| r.get(0),
        ).unwrap();

        let mine: String = c.query_row(
            "SELECT cmd FROM user_quick_commands WHERE user_id = ?1 ORDER BY id ASC LIMIT 1",
            [1], |r| r.get(0),
        ).unwrap();
        assert_eq!(mine, "ls");

        c.execute(
            "UPDATE user_quick_commands SET cmd = 'id' WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![id_a, 2],
        ).unwrap();
        let a_after: String = c.query_row(
            "SELECT cmd FROM user_quick_commands WHERE id = ?1", [id_a], |r| r.get(0),
        ).unwrap();
        assert_eq!(a_after, "ls", "用别人的 user_id 不得改到甲的行");

        c.execute(
            "DELETE FROM user_quick_commands WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![id_a, 2],
        ).unwrap();
        let left: i64 = c.query_row("SELECT COUNT(*) FROM user_quick_commands", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 2, "越权删除应影响 0 行");
        assert_ne!(id_a, id_b);
    }

    /// 命令唯一：新增同命令拦截；编辑自身沿用旧命令放行；改成同用户已有命令拦截；
    /// 跨用户同命令互不干扰。
    #[test]
    fn cmd_is_unique_per_user() {
        let c = mem_db();
        mk_user(&c, 1);
        mk_user(&c, 2);
        mk_cmd(&c, 1, "git status");
        mk_cmd(&c, 1, "ls -la");
        mk_cmd(&c, 2, "git status");

        let id_a: i64 = c.query_row(
            "SELECT id FROM user_quick_commands WHERE user_id = 1 AND cmd = 'git status'", [], |r| r.get(0),
        ).unwrap();
        let id_other: i64 = c.query_row(
            "SELECT id FROM user_quick_commands WHERE user_id = 1 AND cmd = 'ls -la'", [], |r| r.get(0),
        ).unwrap();
        let id_b: i64 = c.query_row(
            "SELECT id FROM user_quick_commands WHERE user_id = 2 AND cmd = 'git status'", [], |r| r.get(0),
        ).unwrap();

        assert!(cmd_taken(&c, 1, "git status", None).unwrap(), "同用户新增同命令必须拦");
        assert!(!cmd_taken(&c, 1, "git status", Some(id_a)).unwrap(), "编辑自身沿用旧命令应放行");
        assert!(cmd_taken(&c, 1, "ls -la", Some(id_a)).unwrap(), "改成同用户已有命令必须拦");
        assert!(!cmd_taken(&c, 2, "git status", Some(id_b)).unwrap(), "他人编辑自身不应被本用户同命令影响");
        assert!(!cmd_taken(&c, 1, "htop", None).unwrap(), "未使用的命令应放行");
        assert_ne!(id_a, id_other);
    }

    /// (user_id, cmd) 唯一索引必须真生效：应用层存在性与 INSERT 之间仍有并发
    /// 窗口，只靠 cmd_taken 兜不住两条并发请求。
    #[test]
    fn unique_index_blocks_duplicate_cmd() {
        let c = mem_db();
        mk_user(&c, 1);
        mk_cmd(&c, 1, "ls");
        let dup = c.execute(
            "INSERT INTO user_quick_commands(user_id, cmd, description, created_at, updated_at) \
             VALUES(1, 'ls', '', 100, 100)",
            [],
        );
        assert!(dup.is_err(), "同一用户重复插入同一条命令必须被唯一索引挡住");
    }
}
