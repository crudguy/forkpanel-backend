//! 数据库管理（设计方案 §2.6）。
//!
//! # 范围：备份/恢复 + 只读浏览 + **只读 SQL 控制台**
//! Web SQL 终端曾因"怕变成任意写库入口"而整体不做。现在提供的版本把这个顾虑
//! 拆开了：**写**依然完全不提供，**读**则靠服务端物理只读护栏兜底
//! （SQLite 只读连接 / PG `default_transaction_read_only=on` 会话），
//! 白名单只负责尽早给出可读错误。没有护栏的引擎（MySQL）诚实 501。
//!
//! # ⚠️ 安全说明
//! 连接口令一律经 AES-256-GCM（主密钥来自 `master.key`）加密后写入 `password_enc`，
//! 列表接口仅返回 `has_password` 布尔，绝不回显明文/密文。无主密钥时创建带口令的连接被拒绝。
//! 外部客户端（psql/mysql/mysqldump）的口令经环境变量传递，**绝不进 argv**——
//! argv 会被同机任意用户的 `ps` 看到，等于直接泄露数据库口令。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
// Path 与 std::path::PathBuf 同名，按全仓约定别名成 AxPath
use axum::{
    extract::{Path as AxPath, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use panel_core::{PanelError, Result, SafePath};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::extract::PanelJson;

#[derive(Debug, Serialize)]
pub struct ConnDto {
    pub id: i64,
    pub name: String,
    pub engine: &'static str,
    pub host: Option<String>,
    pub port: Option<i64>,
    /// 连接默认库（schema 列名 `default_db`，与 OpenAPI `DbConnection.default_db` 同名）
    pub default_db: Option<String>,
    /// 该引擎所需的**外部客户端**是否可用（UI 据此置灰）。
    ///
    /// ⚠️ 语义边界：**不代表这个连接能连通**。它只回答「这台机器有没有装
    /// psql / mysqldump」，不碰网络也不做认证——真正的连通性要在操作时才知道。
    /// 旧名 `available` 让人误读为「连接可用」，UI 据此渲染成绿色「可用」徽标，
    /// 用户点了「备份」却失败且无从归因（实证过一次）。命名必须诚实。
    pub client_ready: bool,
    /// 该连接能否打开**只读 SQL 控制台**（UI 按钮门控的唯一依据）。
    ///
    /// ⚠️ 与 `client_ready` 不是同一个问题，也不能互相推导：
    /// - `client_ready` 说「浏览/备份的客户端在不在」；
    /// - 这个说「用户自己写 SQL 能不能跑」，判据是**有没有服务端物理只读护栏**
    ///   （SQLite 只读连接 / PG `default_transaction_read_only` 会话）。
    /// MySQL 装了客户端也依然是 false——没有护栏，开了就是任意写库入口。
    /// 前端**不得**用 `engine === 'sqlite'` 自己猜这个值：后端加了护栏而前端
    /// 没跟上，用户就白白用不上已能用的功能（置灰是前端单方面的承诺）。
    pub readonly_sql: bool,
    /// 是否有口令（**绝不返回口令本身**）
    pub has_password: bool,
    /// 对象说明（备注，022）：这个库干嘛的、为何这样配置——手写意图
    pub remark: String,
}

/// 列表端点的目标列。**列序即 `conn_row` 的索引**——加列必须同步改这两处。
const CONN_SELECT: &str =
    "SELECT id, name, engine, host, port, default_db, password_enc, remark FROM db_connections";

/// 一行 `db_connections` 的原始形态（与 `CONN_SELECT` 列序严格对应）。
type ConnRow = (i64, String, String, Option<String>, Option<i64>, Option<String>, Option<Vec<u8>>, String);

/// 行 → 元组。
///
/// **刻意抽成独立函数**：回归测试要能直接拿它跑一次真查询。若把映射留在闭包里，
/// 测试只能另抄一份逻辑——抄的那份必然与原实现漂移，等于没测。
fn conn_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ConnRow> {
    Ok((
        r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?,
        // ⚠ 第 7 列 `password_enc` 是 **BLOB**（migration 001 · `password_enc BLOB`；create
        // 处按 `Option<Vec<u8>>` 写入）。这里曾误读成 `Option<String>` → rusqlite 类型
        // 不匹配，**列表端点直接 500**（`Invalid column type Blob at index: 6`）。
        // 下游只用 `pwd.is_some()`，取字节即可，无需解密。
        r.get(6)?,
        // 第 8 列 `remark`（022）是 TEXT，顺序追加，不影响上面 BLOB 列索引。
        r.get(7)?,
    ))
}

pub async fn list(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;

    let rows = state.pool.with(|conn| {
        let mut st = conn.prepare(CONN_SELECT)
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map([], conn_row)
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;

    let mut dtos = Vec::new();
    for (id, name, engine, host, port, default_db, pwd, remark) in rows {
        let eng = match engine.as_str() {
            "mysql" => panel_os::DbEngine::MySql,
            "postgres" => panel_os::DbEngine::Postgres,
            _ => panel_os::DbEngine::Sqlite,
        };
        // 逐连接按引擎判定「是否已实装」：未实装的引擎（mysql/postgres）诚实置灰，不撒谎
        let available = state.os.databases().supports(eng);
        // 只读 SQL 控制台的能力位同样逐引擎判定，但判据不同（见 ConnDto::readonly_sql）。
        // 与 available 分开算而不是复用：两者回答的不是同一个问题，复用会让
        // 「装了客户端」被误当成「能自己写 SQL」。
        let readonly_sql = state.os.databases().readonly_sql(eng);
        dtos.push(ConnDto {
            id, name,
            engine: match eng { panel_os::DbEngine::MySql => "mysql",
                                panel_os::DbEngine::Postgres => "postgres",
                                panel_os::DbEngine::Sqlite => "sqlite" },
            host, port, default_db,
            client_ready: available,
            readonly_sql,
            has_password: pwd.is_some(),
            remark,
        });
    }
    Ok(ok(dtos))
}

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub name: String,
    pub engine: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    /// 连接默认库；sqlite 引擎下填 `.db` 文件路径
    pub default_db: Option<String>,
}

pub async fn create(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_MANAGE)?;

    // 库名校验（强类型构造点，防 `db; DROP`）
    if !panel_core::rules::is_valid_db_name(&req.name) {
        return Err(ApiError::bad_request("name", "invalid database name"));
    }
    if let Some(db) = &req.default_db {
        if req.engine == "sqlite" {
            // SQLite：「库名」实为 .db **文件路径**（浏览目标就是该文件）
            validate_sqlite_path(&state, db)?;
        } else if !panel_core::rules::is_valid_db_name(db) {
            return Err(ApiError::bad_request("default_db", "invalid database name"));
        }
    }
    let engine = match req.engine.as_str() {
        "mysql" | "postgres" | "sqlite" => req.engine.clone(),
        other => return Err(ApiError::bad_request("engine", format!("unsupported: {other}"))),
    };
    // mysql/postgres 必填 user（见 validate_connection_create）。放在口令加密前先拦，
    // 避免无账号的连接落库后才在备份/还原时炸出不可归因的认证失败。
    validate_connection_create(&engine, &req.user)?;

    // 口令加密存储（AES-256-GCM，主密钥来自 master.key）。
    // 无主密钥时拒绝写入任何真实口令（降级关闭，绝不明文入库）。
    let password_enc: Option<Vec<u8>> = match req.password {
        Some(ref pw) if !pw.is_empty() => {
            let key = state.require_secret_key()?;
            Some(key.encrypt(pw.as_bytes()).map_err(ApiError::from)?)
        }
        _ => None,
    };
    let user = req.user.clone();

    let name = req.name.clone();
    let db = req.default_db.clone();
    let host = req.host.clone();
    let port = req.port.map(|p| p as i64);
    state.db.exec(move |conn| {
        // 注意：列名是 `default_db`（schema/契约口径）；`db_connections` 无 `created_at` 列
        conn.execute(
            "INSERT INTO db_connections(name, engine, host, port, username, password_enc, default_db)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![name, engine, host, port, user, password_enc, db],
        ).map_err(|e| if e.to_string().contains("UNIQUE") {
            PanelError::Conflict("connection name exists".into())
        } else {
            PanelError::Database(e.to_string())
        })?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await?;

    audit(&state, &s, "db.create", &req.name, "ok").await;
    Ok(ok(serde_json::json!({ "name": req.name })))
}

// ─────────────── 备份 / 恢复（走任务队列） ───────────────

/// 更新连接（写需 `db.manage`）。字段缺省保留现值；口令**留空 = 不修改**（不必每次
/// 保存都重输口令，密文原样回写）。改名前查重（排除自身）→ 409。校验与 create 完全同源。
pub async fn update(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<UpdateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_MANAGE)?;
    let cur = fetch_conn(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("连接不存在"))?;
    let orig_name = cur.name.clone();

    // 合并：缺省保留现值（前端编辑弹窗送全字段；此处兼顾部分更新）
    let name = req.name.clone().unwrap_or(cur.name);
    let engine = req.engine.clone().unwrap_or(cur.engine);
    let host = req.host.clone().or(cur.host);
    let port = req.port.map(|p| p as i64).or(cur.port);
    let user = req.user.clone().or(cur.username);
    let default_db = req.default_db.clone().or(cur.default_db);

    // 校验（与 create 同源：库名 / 默认库 / 引擎白名单 / mysql·pg 必填 user）
    if !panel_core::rules::is_valid_db_name(&name) {
        return Err(ApiError::bad_request("name", "invalid database name"));
    }
    if let Some(db) = &default_db {
        if engine == "sqlite" {
            validate_sqlite_path(&state, db)?;
        } else if !panel_core::rules::is_valid_db_name(db) {
            return Err(ApiError::bad_request("default_db", "invalid database name"));
        }
    }
    if !matches!(engine.as_str(), "mysql" | "postgres" | "sqlite") {
        return Err(ApiError::bad_request("engine", format!("unsupported: {engine}")));
    }
    validate_connection_create(&engine, &user)?;

    // 口令：提供且非空 → 重新加密；否则保留现值（密文原样回写，不触碰主密钥）
    let password_enc: Option<Vec<u8>> = match &req.password {
        Some(pw) if !pw.is_empty() => {
            let key = state.require_secret_key()?;
            Some(key.encrypt(pw.as_bytes()).map_err(ApiError::from)?)
        }
        _ => cur.password_enc,
    };

    // 改名前查重（排除自身）；唯一冲突不能依赖 UNIQUE 兜底误报 500
    if name != orig_name && name_taken(&state, &name, Some(id)).await? {
        return Err(ApiError::conflict("connection name exists"));
    }

    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE db_connections SET name = ?1, engine = ?2, host = ?3, port = ?4, username = ?5, password_enc = ?6, default_db = ?7 WHERE id = ?8",
                rusqlite::params![name, engine, host, port, user, password_enc, default_db, id],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "db.update", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 删除连接（写需 `db.manage`；id 不存在 → 404）。仅删面板登记，不动真实库 / 文件。
pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_MANAGE)?;
    let exists: bool = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM db_connections WHERE id = ?1)",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    if !exists {
        return Err(ApiError::not_found("连接不存在"));
    }
    state
        .db
        .exec(move |conn| {
            conn.execute("DELETE FROM db_connections WHERE id = ?1", rusqlite::params![id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "db.delete", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 读连接当前行（更新用：缺省保留 + 口令保留 + 改名查重排除自身）。
struct CurConn {
    name: String,
    engine: String,
    host: Option<String>,
    port: Option<i64>,
    username: Option<String>,
    password_enc: Option<Vec<u8>>,
    default_db: Option<String>,
}

async fn fetch_conn(state: &Shared, id: i64) -> std::result::Result<Option<CurConn>, ApiError> {
    state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT name, engine, host, port, username, password_enc, default_db FROM db_connections WHERE id = ?1",
                rusqlite::params![id],
                |r| Ok(CurConn {
                    name: r.get(0)?,
                    engine: r.get(1)?,
                    host: r.get(2)?,
                    port: r.get(3)?,
                    username: r.get(4)?,
                    password_enc: r.get(5)?,
                    default_db: r.get(6)?,
                }),
            )
            .optional()
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
        .map_err(Into::into)
}

/// 连接名是否被占用（exclude 用于更新时排除自身）。
async fn name_taken(state: &Shared, name: &str, exclude_id: Option<i64>) -> std::result::Result<bool, ApiError> {
    let name = name.to_string();
    state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM db_connections WHERE name = ?1 AND (?2 IS NULL OR id != ?2))",
                rusqlite::params![name, exclude_id],
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
        .map_err(Into::into)
}

/// 更新请求体：字段缺省保留现值；口令留空 = 不修改。
#[derive(Debug, Deserialize)]
pub struct UpdateReq {
    pub name: Option<String>,
    pub engine: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub default_db: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BackupReq { pub id: i64, pub out: String }

/// 备注更新请求体（022）。
#[derive(Debug, Deserialize)]
pub struct ConnRemarkReq {
    pub remark: String,
}

/// 更新数据库连接说明（对象备注，022）。仅 `db.manage`。
///
/// 连接按 `id` 或 `name` 解析（路由段为字符串）：先读后写，不存在返回 404。
pub async fn update_remark(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(conn): AxPath<String>,
    PanelJson(req): PanelJson<ConnRemarkReq>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::DB_MANAGE)?;
    let id: i64 = state
        .pool
        .with(move |c| {
            c.query_row(
                // 注意：`?1` 在同一语句中可重复引用，params 只需给**一个**值——
                // 给两个会触发 InvalidParameterCount，被下方 map_err 吞成 404。
                "SELECT id FROM db_connections WHERE id = ?1 OR name = ?1",
                rusqlite::params![conn],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
        .map_err(|_| ApiError::not_found("connection"))?;
    let remark = req.remark.trim().to_string();
    if remark.chars().count() > 500 {
        return Err(ApiError::bad_request("remark", "备注最多 500 字"));
    }
    state
        .db
        .exec(move |c| {
            c.execute(
                "UPDATE db_connections SET remark = ?1 WHERE id = ?2",
                rusqlite::params![remark, id],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    audit(&state, &s, "db.remark", &id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn backup(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<BackupReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_MANAGE)?;

    // 输出路径必须在允许根内（防把备份写到 /etc 覆盖配置）。
    // create=true：产物此刻尚不存在。`..` 逃逸由沙箱兜底，允许输出到允许根下的子目录。
    let out = resolve_out(&s, &req.out, true)?;

    let os = state.os.clone();
    let target = load_target(&state, req.id, None).await?;
    let (id, _) = state.tasks.submit(
        panel_task::TaskRequest {
            idempotency_key: format!("db.backup:{}", req.id),
            kind: panel_task::TaskKind::Database,
            label: format!("备份数据库 #{}", req.id),
            timeout: std::time::Duration::from_secs(3600),
        },
        DbBackupTask { conn_id: req.id, target, out, os },
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "db.backup", &req.id.to_string(), "queued").await;
    Ok(ok(serde_json::json!({ "task_id": id })))
}

/// 备份产物 / 还原源文件的路径沙箱。纪律与 [`super::files::resolve`] 完全一致。
///
/// `create`：备份输出文件**尚不存在**（用 `resolve_within_for_create`）；
/// 还原源文件**必须已存在**（用 `resolve_within`）。两者的沙箱约束相同，
/// 差别只在目标是否允许不存在。
///
/// ## 此前 bug（owner 完全用不了数据库备份）
/// 原实现只有 `for r in &s.allowed_roots` 循环，没有 owner 特判。而 bootstrap 建的
/// owner 是 `allowed_roots=[]`，循环一次都不执行 → `last=None` → 必返回 PathEscape。
/// 实证：`POST /api/v1/db/1/backup` 返回 400 `path escapes allowed root`——
/// 一个**完全无法使用**的功能，且错误信息把「owner 无允许根」误导成「你传了非法路径」。
/// `_state` 此前是参数但实际未使用——保留它会让本函数无法脱离 AppState 做单测，
/// 而下面的回归测试恰恰必须存在（这个 bug 就是 provider 层全绿、端点层全红）。
fn resolve_out(s: &crate::auth::Session, input: &str, create: bool) -> Result<SafePath> {
    let pick = |root: &PathBuf, rel: String| {
        if create {
            panel_os::paths::resolve_within_for_create(root, &rel)
        } else {
            panel_os::paths::resolve_within(root, &rel)
        }
    };
    // owner 等价宿主管理员：bootstrap 时 allowed_roots 为空，按「空=全拒」会让
    // owner 连面板自身的备份都做不了。
    if s.role == "owner" && s.allowed_roots.is_empty() {
        let rel = super::files::relativize(std::path::Path::new("/"), input)?;
        return pick(&PathBuf::from("/"), rel);
    }
    let mut last = None;
    for r in &s.allowed_roots {
        let rel = match super::files::relativize(std::path::Path::new(r), input) {
            Ok(p) => p,
            Err(e) => { last = Some(e); continue }
        };
        match pick(&PathBuf::from(r), rel) {
            Ok(p) => return Ok(p),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| PanelError::PathEscape(input.to_string())))
}

struct DbBackupTask {
    conn_id: i64,
    /// 真实连接凭据（load_target 已解密口令）。此前用本地默认 Sqlite 凭据，
    /// 会导致无论选哪个连接都备份成面板自身库——静默错误，必须传真实 target。
    target: panel_os::DbTarget,
    out: SafePath,
    os: std::sync::Arc<dyn panel_os::OsAdapter>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for DbBackupTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(5, "准备备份").await;
        let p = progress.clone();
        // on_line 是同步 Fn，不能 await；进度由备份完成后的 set(100) 收尾，
        // 这里只把 Provider 的逐行输出透传给进度通道（不阻塞备份本身）。
        self.os.databases().backup(&self.target, &self.out, Box::new(move |line| {
            let _ = &p; let _ = line;
        })).await?;
        progress.set(100, "备份完成").await;
        let _ = self.conn_id;
        Ok(panel_task::TaskOutcome {
            state: panel_task::TaskState::Ok,
            exit_code: Some(0),
            output_path: Some(self.out.as_path().to_path_buf()),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct RestoreReq {
    /// 备份文件路径（必须在当前用户 allowed_roots 之内）
    pub file: String,
    /// 二次确认词（与备份恢复同源）
    pub confirm_token: String,
}

/// 库还原：**高危**（覆盖当前库）。
///
/// 闸门：①确认词 ②源文件沙箱（`resolve_out`，与备份出口同一纪律）③自动先备份当前库。
/// SQLite 可立即恢复；mysql/pg 需 `mysql`/`psql` 外部客户端，缺失时诚实 501。
pub async fn restore(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(conn): AxPath<i64>,
    PanelJson(req): PanelJson<RestoreReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_MANAGE)?;

    let word = crate::routes::backups::RESTORE_CONFIRM_WORD;
    if req.confirm_token.trim() != word {
        return Err(ApiError::bad_request(
            "confirm_token",
            format!("请输入确认词「{word}」以继续"),
        ));
    }

    // 源文件必须落在允许根内 —— 否则可指定任意路径造成越权读取
    // create=false：还原源文件必须已存在（下面还有 is_file 复核）
    let src = resolve_out(&s, &req.file, false)?;
    if !src.as_path().is_file() {
        return Err(ApiError::not_found("backup file"));
    }

    let target = load_target(&state, conn, None).await?;
    let os = state.os.clone();
    // 快照与产物同目录：用户找得到，且仍在备份允许根内（src 已过沙箱）
    let safety_dir = src.as_path().parent().map(|p| p.to_path_buf());
    let job = DbRestoreTask { target, src: src.clone(), os, safety_dir };
    let (tid, _) = state
        .tasks
        .submit(
            panel_task::TaskRequest {
                idempotency_key: format!("restore:db:{conn}:{}", req.file),
                kind: panel_task::TaskKind::Restore,
                label: format!("还原连接 #{conn}"),
                timeout: std::time::Duration::from_secs(1800),
            },
            job,
        )
        .await
        .map_err(ApiError::from)?;
    // 还原是**覆盖当前库**的破坏性操作，必须留痕（与 db.backup 一致：入队即记 queued）。
    // 此前唯独本端点漏了审计：其余 db.create / db.backup / db.query 均已记录。
    audit(&state, &s, "db.restore", &format!("conn={conn}:{}", req.file), "queued").await;
    Ok(ok(serde_json::json!({ "task_id": tid })))
}

/// 库还原任务体：覆盖前快照与具体导入逻辑都下沉到 provider（见 stub.rs）。
/// 此处只驱动任务进度与结果——不重复实现引擎差异（sqlite 先备份再复制、
/// mysql/pg 走外部客户端导入）。
pub(crate) struct DbRestoreTask {
    pub(crate) target: panel_os::DbTarget,
    pub(crate) src: SafePath,
    pub(crate) os: std::sync::Arc<dyn panel_os::OsAdapter>,
    /// 恢复前快照的落点目录（`None` = 不快照）。
    ///
    /// mysql/pg 的恢复是**覆盖当前库**：导进来的 dump 会先 DROP 再建，原数据随即消失。
    /// provider 里只有 sqlite 分支自带 `.bak-<ts>` 快照，mysql/pg 什么都没留——
    /// 于是「覆盖恢复」这个按钮点下去是不可逆的。这里先导出当前态再动手，
    /// 且**导出失败即中止**：宁可什么都不做，也不裸覆盖。
    pub(crate) safety_dir: Option<std::path::PathBuf>,
}

/// 恢复前快照的文件名前缀与保留份数。
///
/// 保留 3 份而不是无限留：快照的意义是"刚恢复完发现不对能立刻退回"，
/// 再老的没有回滚价值，却会把备份目录撑满（与每日备份踩过的坑同源）。
const PRE_RESTORE_KEEP: usize = 3;

/// 对 mysql/pg 导出一份"当前态"快照，失败即返回 Err（调用方据此中止恢复）。
async fn snapshot_before_restore(
    os: &std::sync::Arc<dyn panel_os::OsAdapter>,
    target: &panel_os::DbTarget,
    dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let tag = match target.engine {
        panel_os::DbEngine::MySql => "mysql",
        panel_os::DbEngine::Postgres => "pg",
        // sqlite 由 provider 内 `.bak-<ts>` 承担，不应走到这里
        panel_os::DbEngine::Sqlite => return Err(PanelError::Internal("sqlite 不需要 pg/mysql 快照".into())),
    };
    std::fs::create_dir_all(dir).map_err(|e| PanelError::Io(format!("create safety dir: {e}")))?;
    let name = format!("pre-restore-{tag}-{}.sql", crate::now_unix());
    let snap = panel_os::paths::resolve_within_for_create(dir, &name)?;
    os.databases().backup(target, &snap, Box::new(|_line| {})).await?;
    prune_pre_restore(dir, tag, PRE_RESTORE_KEEP);
    Ok(snap.as_path().to_path_buf())
}

/// 只留最近 `keep` 份恢复前快照，删掉更老的（按名字排序）。
///
/// 名字形如 `pre-restore-pg-<unix秒>.sql`：同类前缀 + 定长时间戳 ⇒ 字典序即时间序，
/// 不需要读 mtime（也避免了"touch 一下就永远不会被删"的偏差）。
///
/// ⚠ 删除条数必须夹到**实际待删量**：`olds.len() - keep`，不能是固定批量，
/// 否则"超出一点"会被放大成"清空"（`prune_audit` 踩过同款坑）。
fn prune_pre_restore(dir: &std::path::Path, tag: &str, keep: usize) {
    let prefix = format!("pre-restore-{tag}-");
    let mut olds: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(&prefix)))
                .collect()
        })
        .unwrap_or_default();
    olds.sort();
    if olds.len() > keep {
        for p in olds.iter().take(olds.len() - keep) {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// 按**连接名**查 id（备份计划的 `target` 存名字：页面展示友好，改名后计划会
/// 明确报"连接不存在"，而不是悄悄备份到别的库上）。
pub(crate) async fn conn_id_by_name(state: &Shared, name: &str) -> Result<Option<i64>> {
    let name = name.to_string();
    state
        .pool
        .with(move |c| {
            let mut st = c
                .prepare("SELECT id FROM db_connections WHERE name = ?1")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let mut it = st
                .query_map([name], |r| r.get::<_, i64>(0))
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(it.next().transpose().map_err(|e| PanelError::Database(e.to_string()))?)
        })
        .await
}

#[async_trait::async_trait]
impl panel_task::TaskBody for DbRestoreTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(10, "准备还原").await;
        // 覆盖恢复前先把当前态导出来（sqlite 已在 provider 内留 `.bak-`，跳过）
        if let (Some(dir), false) = (&self.safety_dir, matches!(self.target.engine, panel_os::DbEngine::Sqlite))
        {
            progress.set(15, "导出当前态快照").await;
            snapshot_before_restore(&self.os, &self.target, dir).await?;
        }
        self.os.databases().restore(&self.target, &self.src).await?;
        progress.set(100, "完成").await;
        Ok(panel_task::TaskOutcome {
            state: panel_task::TaskState::Ok,
            exit_code: Some(0),
            output_path: Some(self.src.as_path().to_path_buf()),
        })
    }
}

// ─────────────── 浏览（连接 → 库 → 表 → 行预览，**只读**） ───────────────

#[derive(Debug, Deserialize)]
pub struct RowsQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

/// 标识符（库名/表名）业务层校验。provider 内部仍安全加引号，这里是纵深防御。
fn validate_ident(v: &str, field: &'static str) -> ApiResult<()> {
    if v.is_empty() || v.len() > 128 {
        return Err(ApiError::bad_request(field, "empty or too long (>128)"));
    }
    if v.chars().any(|c| c.is_control() || c == '\0') {
        return Err(ApiError::bad_request(field, "control characters not allowed"));
    }
    Ok(())
}

/// SQLite 的「库名」实为 `.db` 文件路径：必须存在且非敏感路径。
fn validate_sqlite_path(state: &Shared, db: &str) -> ApiResult<()> {
    if db.is_empty() || db.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request("database", "invalid path"));
    }
    let p = std::path::Path::new(db);
    if !p.is_file() {
        return Err(ApiError::bad_request("database", format!("sqlite 文件不存在: {db}")));
    }
    // 经跨平台入口判定：业务层不得直接引用 panel_os::linux::*（那会让非 Linux 目标编译不过）
    if state.os.files().is_sensitive_path(p) {
        return Err(ApiError::bad_request("database", "path not allowed"));
    }
    Ok(())
}

/// 创建连接时的业务校验（不碰 DB、不依赖 AppState，可单测）。
///
/// mysql/postgres 是「远端服务器」模型：连主机账号必填。
/// 缺 user 的连接在备份/还原时 `pg_dump`/`mysqldump`/`mysql` 不带 `-U`/`-u`
/// 会走 OS 当前用户认证 → 几乎必然失败，且错误信息对终端用户不可归因。
/// 与其留一个「建出来必失败」的连接，不如创建时就拦下（负向对照见测试）。
/// sqlite 是本地文件、无账号概念，user 可不填。
fn validate_connection_create(engine: &str, user: &Option<String>) -> ApiResult<()> {
    if (engine == "mysql" || engine == "postgres")
        && user.as_ref().map_or(true, |u| u.trim().is_empty())
    {
        return Err(ApiError::bad_request("user", "mysql/postgres 连接必须指定账号（user 必填）"));
    }
    Ok(())
}

/// 读连接行 → 解密口令 → 构造 `DbTarget`（浏览各端点的统一入口）。
pub(crate) async fn load_target(state: &Shared, conn: i64, db_override: Option<&str>) -> ApiResult<panel_os::DbTarget> {
    let row = state.pool.with(move |c| {
        let mut st = c.prepare(
            "SELECT engine, host, port, username, password_enc, default_db \
             FROM db_connections WHERE id = ?1")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let mut it = st.query_map([conn], |r| Ok((
            r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<String>>(3)?, r.get::<_, Option<Vec<u8>>>(4)?, r.get::<_, Option<String>>(5)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(it.next().transpose().map_err(|e| PanelError::Database(e.to_string()))?)
    }).await?
        .ok_or_else(|| ApiError::not_found("connection"))?;
    let (engine_s, host, port, user, pwd_enc, database) = row;

    let engine = match engine_s.as_str() {
        "mysql" => panel_os::DbEngine::MySql,
        "postgres" => panel_os::DbEngine::Postgres,
        _ => panel_os::DbEngine::Sqlite,
    };
    // 口令解密：有密文则必须有主密钥（对齐 create 的纪律）
    let password = match pwd_enc {
        Some(blob) => {
            let key = state.require_secret_key()?;
            let plain = key.decrypt(&blob).map_err(ApiError::from)?;
            Some(String::from_utf8(plain)
                .map_err(|_| ApiError::from(PanelError::Internal("password not utf8".into())))?)
        }
        None => None,
    };
    // SQLite 的 `database` 是文件路径（不可被 URL 的 {db} 覆盖）；
    // 其它引擎的 {db} 才是库名，需覆盖连接默认库。
    let database = if matches!(engine, panel_os::DbEngine::Sqlite) {
        database
    } else {
        db_override.map(|s| s.to_string()).or(database)
    };
    Ok(panel_os::DbTarget { engine, host, port: port.map(|p| p as u16), user, password, database })
}

/// 把 provider 的 DB 错误优雅归一到 ApiError：表不存在属客户端问题 → 404，
/// 其余（连接失败、权限等）保持 500 语义。
fn map_db_err(e: PanelError) -> ApiError {
    if let PanelError::Database(ref m) = e {
        if m.contains("no such table") {
            return ApiError::not_found("table");
        }
    }
    ApiError::from(e)
}

fn engine_str(e: panel_os::DbEngine) -> &'static str {
    match e { panel_os::DbEngine::MySql => "mysql",
              panel_os::DbEngine::Postgres => "postgres",
              panel_os::DbEngine::Sqlite => "sqlite" }
}

pub async fn databases_of(
    State(state): State<Shared>, Auth(s): Auth, AxPath(conn): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    let t = load_target(&state, conn, None).await?;
    let dbs = state.os.databases().databases(&t).await?;
    Ok(ok(dbs))
}

pub async fn tables(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath((conn, db)): AxPath<(i64, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    validate_ident(&db, "db")?;
    let t = load_target(&state, conn, Some(&db)).await?;
    let engine = engine_str(t.engine);
    let list = state.os.databases().tables(&t).await?;
    let out: Vec<serde_json::Value> = list.into_iter()
        .map(|x| serde_json::json!({
            "name": x.name,
            "rows": x.rows,
            "engine": engine,
            // 种类（table/view）。前端据此把「这一层没有可预览对象」与
            // 「只有视图、当前未列入」分开说——两者的用户动作完全不同。
            "kind": x.kind.as_str(),
        }))
        .collect();
    Ok(ok(out))
}

/// 「库」的下一级（PG 是 schema；MySQL/SQLite 没有这一层 → 空数组）。
///
/// 为什么单独一个端点而不是塞进 databases 响应里：
/// 每选一个库都要重查，塞进列表意味着切换库时不刷新——那正是本次要修的病
/// （点不同的库都显示同一句「无表」）。独立端点让「选了哪个库」与
/// 「这一层有什么」严格一一对应。
pub async fn schemas(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath((conn, db)): AxPath<(i64, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    validate_ident(&db, "db")?;
    let t = load_target(&state, conn, Some(&db)).await?;
    let list = state.os.databases().schemas(&t, &db).await?;
    let out: Vec<serde_json::Value> = list.into_iter()
        .map(|x| serde_json::json!({ "name": x.name, "previewable": x.previewable }))
        .collect();
    Ok(ok(out))
}

pub async fn rows(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath((conn, db, table)): AxPath<(i64, String, String)>,
    Query(q): Query<RowsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    validate_ident(&db, "db")?;
    validate_ident(&table, "table")?;
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(50).clamp(1, 200);
    let offset = (page as usize - 1) * page_size as usize;
    let t = load_target(&state, conn, Some(&db)).await?;
    let data = state.os.databases().rows(&t, &table, page_size as usize, offset).await.map_err(map_db_err)?;
    Ok(ok(serde_json::json!({
        "columns": data.columns,
        "rows": data.rows,   // Vec<Vec<Option<String>>>：NULL 序列化为 null
        "page": page,
        "total": data.total,
    })))
}

// ─────────────── CSV 导出（只读） ───────────────

/// 单次导出上限。**刻意不提供"更大"的选项**：导出要把整个结果集拼成一个
/// 字符串再交给 axum，行数无上限就等于让一个请求决定面板吃掉多少内存
/// （与 `QUERY_MAX_LIMIT` 同一个理由，量级更大只因导出是一次性交付、
/// 不是交互式翻页）。
const EXPORT_MAX_ROWS: usize = 20_000;

/// GET /api/v1/db/{conn}/{db}/{table}/export —— 全量表数据导出为 CSV（只读）。
///
/// **为什么由后端生成、不是前端拿当前页拼**：前端只拿得到一页（≤200 行），
/// 而"导出这张表"在用户语义里是全量；且转义规则必须全仓只有一份实现——
/// 放前端就意味着每个视图各写一遍，必然漂移。
///
/// **为什么超限时拒绝而不是截断**：多取一行作哨兵，真有第 N+1 行就整体报错。
/// 静默给一个"看起来完整"的前 N 行文件，比明确失败危险得多——用户会拿它对账、
/// 导入，而缺了哪几行无从得知。拒绝时给出可执行的下一步（SQL 控制台加 WHERE）。
pub async fn export_csv(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath((conn, db, table)): AxPath<(i64, String, String)>,
) -> ApiResult<Response> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    validate_ident(&db, "db")?;
    validate_ident(&table, "table")?;
    let t = load_target(&state, conn, Some(&db)).await?;
    // +1 是哨兵行：真有第 N+1 行才说明"还有更多"
    let d = state.os.databases()
        .rows(&t, &table, EXPORT_MAX_ROWS + 1, 0)
        .await
        .map_err(map_db_err)?;
    if d.rows.len() > EXPORT_MAX_ROWS {
        return Err(ApiError::bad_request(
            "table",
            format!(
                "「{table}」超过 {EXPORT_MAX_ROWS} 行，已拒绝导出：宁可明确失败，\
                 也不给一个看似完整的前 {EXPORT_MAX_ROWS} 行文件。\
                 请用 SQL 控制台加 WHERE 条件收窄后重试，或用数据库客户端导出。"
            ),
        ));
    }
    let body = to_csv(&d.columns, &d.rows);
    audit(
        &state,
        &s,
        "db.export",
        &format!("conn={conn} db={db} table={table} rows={}", d.rows.len()),
        "ok",
    )
    .await;

    // 文件名沿用日志下载同一套净化：`table` 虽过 validate_ident（它不禁非 ASCII），
    // 而 SQLite 的表名可能来自文件路径，仍可能含引号/反斜杠/换行。
    // 非 [A-Za-z0-9._-] 一律换 _，从源头掐掉 Content-Disposition 注入。
    let safe: String = table
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    let safe = if safe.is_empty() { "export".to_string() } else { safe };
    let headers = [
        (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{safe}.csv\""),
        ),
    ];
    Ok((headers, body).into_response())
}

/// 结果集 → CSV 文本。**纯函数**：不碰 IO，可喂任意列名/取值组合单测。
///
/// 三个刻意的决定，都与"用户会拿什么软件打开这个文件"有关：
/// 1. **带 UTF-8 BOM**（`\u{feff}`）：Excel / WPS 在 Windows 上按本地代码页
///    猜编码，无 BOM 的 UTF-8 中文会变乱码。这是本面板用户的实际打开方式，
///    不是理论洁癖。
/// 2. **CRLF 行尾**（RFC 4180）：Excel 对裸 LF 的兼容历来不稳定。
/// 3. **公式注入防护**：以 `=` `+` `@` 或制表符开头的字段加 `'` 前缀，
///    否则表格软件会把单元格内容当公式执行（CSV 注入，OWASP 有专条）。
///
/// ⚠️ `-` **刻意不防**：`-12.5` 这类负数远比 `-1+1` 这类公式常见，一刀切
/// 前缀会把正常负数全变成文本。这个取舍如实记录，不装作完备——真被
/// `-` 开头的公式打到，前提是攻击者能往这个库里写数据。
///
/// NULL 渲染为空串：客户端模式下 NULL 与空串本就无法区分（见 `rows` 的注释），
/// 这里不伪造第三种表示。
pub(super) fn to_csv(columns: &[String], rows: &[Vec<Option<String>>]) -> String {
    let mut out = String::from("\u{feff}");
    out.push_str(&csv_row(columns.iter().map(String::as_str)));
    for r in rows {
        out.push_str(&csv_row(r.iter().map(|c| c.as_deref().unwrap_or(""))));
    }
    out
}

/// 一行 CSV（含结尾 CRLF）。
fn csv_row<'a>(fields: impl Iterator<Item = &'a str>) -> String {
    let mut line = String::new();
    for (i, f) in fields.enumerate() {
        if i > 0 {
            line.push(',');
        }
        line.push_str(&csv_field(f));
    }
    line.push_str("\r\n");
    line
}

/// 单个字段：先按 RFC 4180 加引号，再按需加公式注入前缀。
///
/// 顺序有意义：`'` 前缀放在引号**外**（字段首字符），Excel 解析带引号字段时
/// 仍会把开头的 `'` 当"按文本处理"标记；放引号里面则变成数据的一部分。
fn csv_field(s: &str) -> String {
    let quoted = if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    };
    match s.as_bytes().first() {
        Some(b'=') | Some(b'+') | Some(b'@') | Some(b'\t') | Some(b'\r') => format!("'{quoted}"),
        _ => quoted,
    }
}

// ─────────────── 只读 SQL 控制台 ───────────────

/// 默认返回行数 / 硬上限。**上限不是"建议"**：任意 SQL 可能扫全表，
/// 不限行数等于让一个请求决定面板吃掉多少内存。
const QUERY_DEFAULT_LIMIT: usize = 200;
const QUERY_MAX_LIMIT: usize = 2000;
/// SQL 文本长度上限：正常查询不该有几十 KB
const SQL_MAX_BYTES: usize = 8192;

#[derive(Debug, Deserialize)]
pub struct QueryReq {
    pub sql: String,
    pub limit: Option<usize>,
}

/// SQL 控制台的引擎相关文案：默认语句 + 示例 + 边界提示。
///
/// **为什么放在后端**：这些文本是引擎知识（`sqlite_master` vs
/// `information_schema` vs 只读护栏的残余风险）。放前端就等于把"哪个引擎长什么样"
/// 复制一份到 UI 层，后端改口径时前端静默过期——正是单一事实源纪律要避免的漂移。
/// 前端只负责渲染，不判断引擎（连 `engine === 'postgres'` 都不该出现）。
///
/// MySQL 返回空示例：控制台对它不开放（无服务端只读护栏），给了也点不开。
fn sql_console_meta(engine: &str) -> (&'static str, Vec<(&'static str, &'static str)>, &'static str) {
    // 边界提示按引擎给：**写的是这个引擎真实存在的边界**，不是通用免责声明。
    // PG 那条尤其不能省——只读护栏拦不住 pg_reload_conf 这类配置函数，
    // 如实写出来，用户才不会以为"面板说只读就绝对只读"。
    let (default_sql, samples, note) = match engine {
        "postgres" => (
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' ORDER BY table_name",
            vec![
                ("表清单", "SELECT table_name FROM information_schema.tables \
                            WHERE table_schema = 'public' ORDER BY table_name"),
                ("列结构", "SELECT column_name, data_type, is_nullable FROM information_schema.columns \
                            WHERE table_schema = 'public' AND table_name = 'sites' ORDER BY ordinal_position"),
                ("库信息", "SELECT current_database() AS db, current_user AS usr, version() AS ver"),
                ("活动连接", "SELECT count(*) AS conns FROM pg_stat_activity"),
                ("表体积", "SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) AS size \
                            FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 20"),
            ],
            "会话以只读模式执行，写语句会被数据库拒绝；个别配置类函数（如 pg_reload_conf）不受此约束。",
        ),
        // SQLite：sqlite_master 是它的目录表；PRAGMA 是它的元数据入口
        _ => (
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
            vec![
                ("表清单", "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"),
                ("表结构", "SELECT sql FROM sqlite_master WHERE type = 'table' ORDER BY name"),
                ("索引", "SELECT name, tbl_name FROM sqlite_master WHERE type = 'index' ORDER BY tbl_name"),
                ("库信息", "PRAGMA database_list"),
                ("完整性", "PRAGMA integrity_check"),
            ],
            "连接以只读模式打开，写语句会直接失败。",
        ),
    };
    (default_sql, samples, note)
}

/// 控制台元数据：能力位 + 默认语句 + 示例。
///
/// 单独一个端点而不是塞进 `ConnDto`：列表接口会被轮询/刷新，没必要每次都
/// 带上五六条示例 SQL；控制台是**按需打开**的，一次请求正好。
#[derive(Debug, Serialize)]
pub struct SqlMetaDto {
    pub engine: &'static str,
    /// 与 `ConnDto.readonly_sql` 同源同值——打开控制台前再确认一次，
    /// 避免列表数据过期导致"按钮亮着、内容说不能跑"。
    pub readonly_sql: bool,
    pub default_sql: String,
    pub samples: Vec<SqlSample>,
    /// 只读护栏的**诚实边界**（按引擎给）。前端原样展示，不自行判断引擎。
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SqlSample {
    pub label: &'static str,
    pub sql: &'static str,
}

pub async fn sql_meta(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(conn): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    let t = load_target(&state, conn, None).await?;
    let eng = match t.engine {
        panel_os::DbEngine::MySql => "mysql",
        panel_os::DbEngine::Postgres => "postgres",
        panel_os::DbEngine::Sqlite => "sqlite",
    };
    let (default_sql, samples, note) = sql_console_meta(eng);
    Ok(ok(serde_json::json!(SqlMetaDto {
        engine: eng,
        readonly_sql: state.os.databases().readonly_sql(t.engine),
        default_sql: default_sql.to_string(),
        samples: samples.into_iter().map(|(label, sql)| SqlSample { label, sql }).collect(),
        note,
    })))
}

/// 只读 SQL 控制台。
///
/// **开放范围**：SQLite 与 PostgreSQL。两者的"只读"都不靠本层的白名单兜底——
/// SQLite 是只读连接（`SQLITE_OPEN_READ_ONLY`），PG 是只读会话
/// （`default_transaction_read_only=on`），写语句在服务端**物理失败**。
/// 白名单只是第一层：尽早给出可读的错误。MySQL 仍不开放（无护栏），
/// provider 层会诚实 501。
pub async fn query(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(conn): AxPath<i64>, PanelJson(req): PanelJson<QueryReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    validate_read_only_sql(&req.sql)?;
    // 不额外要求 db 参数：SQL 自带库/表限定，再传一个库名只会让语义含糊
    let t = load_target(&state, conn, None).await?;
    let limit = req.limit.unwrap_or(QUERY_DEFAULT_LIMIT).clamp(1, QUERY_MAX_LIMIT);
    let r = state.os.databases().query(&t, &req.sql, limit).await.map_err(map_db_err)?;
    audit(&state, &s, "db.query", &format!("conn={conn}"), "ok").await;
    Ok(ok(serde_json::json!({
        "columns": r.columns,
        "rows": r.rows,
        "truncated": r.truncated,
        "limit": limit,
    })))
}

/// 写操作关键词。**必须是完整词匹配**（`delete_log` 不算 `delete`）。
///
/// 注意这里**刻意不含 `replace`**：`SELECT replace(name,'a','b')` 是常用字符串函数，
/// 放进来会大面积误伤；而 `REPLACE INTO` 由 SQLite 的只读连接兜底拒绝。
const WRITE_KEYWORDS: &[&str] = &[
    "insert", "update", "delete", "drop", "alter", "create", "truncate",
    "attach", "detach", "grant", "revoke", "vacuum", "reindex",
    "commit", "rollback", "savepoint", "load_extension", "into", "outfile",
];

/// 只读 SQL 校验。
///
/// **这不是唯一防线，也不是最强的那道**：真正的兜底在 provider 层——
/// SQLite 只读连接、PG 只读会话，写语句物理失败。这里做两件事：
///   1. 尽早给出可读的错误（比引擎的 "cannot execute CREATE TABLE in a read-only transaction" 好懂）；
///   2. 挡掉明显的越界，省掉一次无谓的进程启动。
///
/// 判定不能只看首关键词——`WITH x AS (…) DELETE …` 的首词完全合法，
/// 因此必须叠加写关键词黑名单。
///
/// ⚠️ 已知边界（诚实记录）：PG 的美元引用 `$$…$$` 里的分号会被当多语句计，
/// 于是 `SELECT $$a;b$$` 会被误判成"一次只允许一条语句"。PG 的函数体
/// （`CREATE FUNCTION … $$`）本来就该被黑名单拦下，故实际影响面很小；
/// 后果是**可见的报错**而非静默放行，故记为已知边界而非缺陷。
fn validate_read_only_sql(sql: &str) -> ApiResult<()> {
    if sql.len() > SQL_MAX_BYTES {
        return Err(ApiError::bad_request("sql", format!("语句过长（上限 {SQL_MAX_BYTES} 字节）")));
    }
    let (scrubbed, semis) = scrub_sql(sql);
    let body = scrubbed.trim();
    let trailing_semi = body.ends_with(';');
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    if body.is_empty() {
        return Err(ApiError::bad_request("sql", "空语句"));
    }
    // 去掉结尾分号后仍出现分号 → 多语句（注释与字符串里的分号已被 scrub 排除）
    let inner = if trailing_semi { semis.saturating_sub(1) } else { semis };
    if inner > 0 {
        return Err(ApiError::bad_request("sql", "一次只允许一条语句"));
    }
    let kw = body.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    const ALLOWED: &[&str] = &["select", "with", "explain", "pragma", "values"];
    if !ALLOWED.contains(&kw.as_str()) {
        return Err(ApiError::bad_request(
            "sql",
            format!("只允许只读查询（SELECT / WITH / EXPLAIN / PRAGMA / VALUES），当前以 `{kw}` 开头"),
        ));
    }
    for w in WRITE_KEYWORDS {
        if has_keyword(body, w) {
            return Err(ApiError::bad_request(
                "sql",
                format!("语句包含写操作关键字 `{w}`，只读控制台拒绝执行"),
            ));
        }
    }
    Ok(())
}

/// 完整词匹配：左右边界都必须是非词字符。
/// 这样 `deleted_at` / `create_time` 这类**列名**不会被误判成写操作。
fn has_keyword(haystack: &str, kw: &str) -> bool {
    let hay = haystack.to_ascii_lowercase();
    let mut from = 0usize;
    while from < hay.len() {
        let Some(pos) = hay[from..].find(kw) else { return false };
        let start = from + pos;
        let end = start + kw.len();
        // 索引始终落在字符边界上：kw 是 ASCII，start 来自 find
        let ok_left = start == 0 || !is_word_byte(hay.as_bytes()[start - 1]);
        let ok_right = end >= hay.len() || !is_word_byte(hay.as_bytes()[end]);
        if ok_left && ok_right {
            return true;
        }
        from = end;
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// 扫描 SQL：**去掉注释**、把引号串内容抹成占位（不参与关键词判定），
/// 并统计顶层分号数。返回 `(可判定的正文, 顶层分号数)`。
///
/// 自己扫而不用正则的原因：注释/引号状态只有真正走一遍才判得准，
/// 正则很容易在 `'a--b'`、`SELECT 'a;b'` 这类输入上给出错误结论。
fn scrub_sql(sql: &str) -> (String, usize) {
    let cs: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut semis = 0usize;
    let mut i = 0usize;
    while i < cs.len() {
        let c = cs[i];
        // 引号串：整段跳过，只留一个空引号对
        if c == '\'' || c == '"' || c == '`' {
            let q = c;
            i += 1;
            while i < cs.len() {
                if cs[i] == q {
                    // SQL 用重复引号转义（'' / ""）
                    if i + 1 < cs.len() && cs[i + 1] == q {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push_str("''");
            continue;
        }
        // 行注释 --
        if c == '-' && i + 1 < cs.len() && cs[i + 1] == '-' {
            while i < cs.len() && cs[i] != '\n' {
                i += 1;
            }
            out.push(' '); // 用空格替位，避免前后 token 粘连成新词
            continue;
        }
        // 块注释 /* */（未闭合则吞到结尾——未闭合的注释本就不合法）
        if c == '/' && i + 1 < cs.len() && cs[i + 1] == '*' {
            i += 2;
            while i + 1 < cs.len() && !(cs[i] == '*' && cs[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(cs.len());
            out.push(' ');
            continue;
        }
        if c == ';' {
            semis += 1;
        }
        out.push(c);
        i += 1;
    }
    (out, semis)
}

#[cfg(test)]
mod restore_snapshot_tests {
    use super::*;

    /// 临时目录 + 造 n 份"快照"，跑完自删。
    fn with_snapshots(n: usize) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("prune-pre-restore-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        for i in 0..n {
            // 时间戳定长 10 位：字典序必须等于时间序，否则裁剪会删错
            let name = format!("pre-restore-pg-17926800{:02}.sql", i);
            std::fs::write(dir.join(&name), "x").expect("write snapshot");
        }
        dir
    }

    #[test]
    fn only_the_newest_snapshots_survive() {
        let dir = with_snapshots(5);
        prune_pre_restore(&dir, "pg", PRE_RESTORE_KEEP);
        let left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        let mut left = left;
        left.sort();
        assert_eq!(
            left,
            vec![
                "pre-restore-pg-1792680002.sql".to_string(),
                "pre-restore-pg-1792680003.sql".to_string(),
                "pre-restore-pg-1792680004.sql".to_string(),
            ],
            "必须只删超出的那几份，不能把整个目录清空"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 边界：待删条数少于 keep 时一份都不许删（防"固定批量"把快照清空）。
    #[test]
    fn nothing_is_deleted_when_under_the_limit() {
        let dir = with_snapshots(2);
        prune_pre_restore(&dir, "pg", PRE_RESTORE_KEEP);
        let n = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(n, 2, "未超上限却删了快照——删除条数没夹到实际待删量");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 别的引擎/别的前缀的文件不能被顺手删掉。
    #[test]
    fn other_files_are_untouched() {
        let dir = with_snapshots(4);
        std::fs::write(dir.join("plan1-1792680000.sql"), "x").unwrap();
        std::fs::write(dir.join("pre-restore-mysql-1792680000.sql"), "x").unwrap();
        prune_pre_restore(&dir, "pg", PRE_RESTORE_KEEP);
        assert!(dir.join("plan1-1792680000.sql").exists(), "产物被快照裁剪误删");
        assert!(dir.join("pre-restore-mysql-1792680000.sql").exists(), "mysql 快照被 pg 的裁剪误删");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 接线守卫：非 sqlite 的恢复**必须**先导出当前态。
    ///
    /// 用源码断言而非行为测试：`DbRestoreTask::run` 需要一个真能导出的 OsAdapter，
    /// 单测里造不出；而"注释里写了有快照、代码里其实没有"正是最难发现的一类。
    /// ⚠ 断言前剔除注释行——本块注释里逐字写着 `snapshot_before_restore`。
    #[test]
    fn non_sqlite_restore_snapshots_first() {
        let src = include_str!("databases.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: Vec<&str> = prod.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
        let joined = code.join("\n");
        let start = joined
            .find("impl panel_task::TaskBody for DbRestoreTask")
            .expect("DbRestoreTask 必须存在");
        let after = &joined[start..];
        let end = after
            .find("self.os.databases().restore(")
            .expect("DbRestoreTask 必须调用 restore");
        let block = &after[..end];
        assert!(block.contains("snapshot_before_restore("), "恢复前没有导出当前态快照：覆盖恢复不可逆");
        assert!(block.contains("safety_dir"), "快照目录没接进任务体");
        assert!(block.contains("Sqlite"), "必须显式排除 sqlite（它已在 provider 内留 .bak-，重复快照是浪费）");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────── CSV 导出 ───────────────
    //
    // 这一组盯的是"用户拿 Excel/WPS 打开时看到什么"。转义写错的后果不是
    // 报错，是**静默错位**（整列漂移、数字变文本、中文乱码），所以每条都
    // 断言到字符级，而不是"包含某字段"就完。

    #[test]
    fn to_csv_writes_bom_header_and_crlf() {
        let cols = vec!["id".to_string(), "name".to_string()];
        let rows = vec![vec![Some("1".to_string()), Some("张三".to_string())]];
        let out = to_csv(&cols, &rows);
        // BOM：无它 Excel 按本地代码页猜，中文直接乱码
        assert!(out.starts_with('\u{feff}'), "必须带 UTF-8 BOM");
        // CRLF：RFC 4180，且 Excel 对裸 LF 兼容不稳定
        assert!(out.contains("id,name\r\n"), "表头行");
        assert!(out.contains("1,张三\r\n"), "数据行");
        assert!(out.ends_with("\r\n"), "末行也要有行尾");
        // 只有两行：表头 + 一条数据，不多不少
        assert_eq!(out.matches("\r\n").count(), 2);
    }

    #[test]
    fn to_csv_quotes_fields_with_comma_quote_or_newline() {
        let cols = vec!["a".to_string()];
        let rows = vec![
            vec![Some("x,y".to_string())],
            vec![Some("he said \"hi\"".to_string())],
            vec![Some("line1\nline2".to_string())],
        ];
        let out = to_csv(&cols, &rows);
        assert!(out.contains("\"x,y\""), "含逗号必须加引号");
        // 内部引号按 RFC 4180  doubling
        assert!(out.contains("\"he said \"\"hi\"\"\""), "内部引号必须双写");
        assert!(out.contains("\"line1\nline2\""), "含换行必须加引号");
    }

    #[test]
    fn to_csv_renders_null_as_empty_field() {
        // NULL → 空串，不伪造引号或字面量 "NULL"（客户端模式本就无法区分两者）
        let out = to_csv(
            &["a".to_string(), "b".to_string()],
            &[vec![None, Some("v".to_string())]],
        );
        assert!(out.contains(",v\r\n"));
        assert!(!out.contains("NULL"), "不得把 NULL 写成字面量");
    }

    #[test]
    fn to_csv_prefixes_formula_leading_fields() {
        // = + @ 与制表符开头的字段会被表格软件当公式执行（CSV 注入）
        let rows = vec![
            vec![Some("=SUM(A1:A9)".to_string())],
            vec![Some("+1234".to_string())],
            vec![Some("@channel".to_string())],
            vec![Some("\tx".to_string())],
        ];
        let out = to_csv(&["c".to_string()], &rows);
        for pat in ["'=SUM(A1:A9)", "'+1234", "'@channel", "'\tx"] {
            assert!(out.contains(pat), "缺少公式注入前缀：{pat:?}");
        }
    }

    #[test]
    fn to_csv_guard_prefix_sits_outside_the_quotes() {
        // 既需要引号又需要前缀：' 必须在引号外，否则变成数据的一部分，
        // Excel 不再把它当"按文本处理"的标记。
        let out = to_csv(&["c".to_string()], &[vec![Some("=a,b".to_string())]]);
        assert!(out.contains("'\"=a,b\""), "前缀必须包在引号外面，实际：{out:?}");
    }

    #[test]
    fn to_csv_leaves_negative_numbers_alone() {
        // 把取舍钉住：- 刻意不防（见 csv_field 注释）。
        // 将来若改成连 - 一起防，这条会红——那是有意变更，
        // 需连同注释与契约里的说明一起改，不要单独让测试"迁就"。
        let out = to_csv(&["n".to_string()], &[vec![Some("-12.5".to_string())]]);
        assert!(out.contains("-12.5"), "负数必须原样导出");
        assert!(!out.contains("'-12.5"), "负数不得被加公式注入前缀");
    }

    #[test]
    fn to_csv_of_empty_result_is_header_only() {
        let out = to_csv(&["a".to_string(), "b".to_string()], &[]);
        assert_eq!(out, "\u{feff}a,b\r\n");
    }

    /// 构造会话：只填 resolve_out 会读到的字段。
    fn sess(role: &str, roots: &[&str]) -> crate::auth::Session {
        crate::auth::Session {
            user_id: 1,
            username: "u".into(),
            role: role.into(),
            permissions: vec![],
            allowed_roots: roots.iter().map(|r| r.to_string()).collect(),
            ip: "unknown".into(),
            created_at: 0,
            last_seen: 0,
            expires_at: 0,
        }
    }

    /// 回归：owner（bootstrap 建号时 allowed_roots 为空）必须能产出备份路径。
    ///
    /// 实证过的失败：`POST /api/v1/db/1/backup` → 400 `path escapes allowed root`。
    /// 一个**完全不可用**的功能，且错误信息把「owner 无允许根」误导成「你传了非法路径」。
    #[test]
    fn owner_without_allowed_roots_can_write_backup_outside_roots() {
        let dir = std::env::temp_dir()
            .join(format!("panel-db-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = sess("owner", &[]); // ← bootstrap 出来的 owner 正是这个形态

        // create=true：备份产物此刻还不存在，必须用 *_for_create 语义
        let abs = dir.join("p.sql").to_string_lossy().to_string();
        let got = resolve_out(&s, &abs, true)
            .unwrap_or_else(|e| panic!("owner 应能备份到 {abs}，实际: {e}"));
        assert_eq!(got.as_path(), dir.join("p.sql"), "应解析到目标绝对路径");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 回归：非 owner 也要能把恢复源文件（绝对路径）解析进自己的允许根。
    #[test]
    fn operator_resolves_absolute_source_within_allowed_root() {
        let root = std::env::temp_dir()
            .join(format!("panel-db-src-{}", std::process::id()));
        std::fs::create_dir_all(root.join("dumps")).unwrap();
        let f = root.join("dumps").join("x.sql");
        std::fs::write(&f, b"x").unwrap();

        let s = sess("operator", &[&root.to_string_lossy().to_string()]);
        // create=false：还原源文件必须已存在
        let got = resolve_out(&s, &f.to_string_lossy(), false)
            .unwrap_or_else(|e| panic!("允许根内的源应可解析: {e}"));
        assert_eq!(got.as_path(), std::fs::canonicalize(&f).unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_source_outside_allowed_root_is_rejected() {
        let root = std::env::temp_dir()
            .join(format!("panel-db-deny-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let s = sess("operator", &[&root.to_string_lossy().to_string()]);

        // /etc/passwd 不落在允许根内 —— 绝不能因为绝对路径就放行
        let e = resolve_out(&s, "/etc/passwd", false).unwrap_err();
        assert!(matches!(e, PanelError::PathEscape(_)),
            "根外路径必须拒绝，实际得到: {e:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// create=true / create=false 的语义差别不能被抹平：
    /// 还原一个**不存在的**文件必须失败（否则等于把空 promise 当输入）。
    #[test]
    fn restore_source_must_already_exist() {
        let root = std::env::temp_dir()
            .join(format!("panel-db-missing-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let s = sess("operator", &[&root.to_string_lossy().to_string()]);
        assert!(resolve_out(&s, "nope/ghost.sql", false).is_err(),
            "不存在的源文件必须拒绝解析");
        // 同一路径若作为「待创建产物」则合法
        assert!(resolve_out(&s, "nope/ghost.sql", true).is_ok(),
            "作为备份产物（尚待创建）应放行");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_only_sql_accepts_plain_selects() {
        for ok_sql in [
            "SELECT 1",
            "select * from sites limit 5",
            "  \n SELECT name FROM users ;  ",
            "WITH t AS (SELECT 1 AS a) SELECT a FROM t",
            "EXPLAIN SELECT 1",
            "PRAGMA table_info(sites)",
            // 引号里的关键字不算写操作——这是最常见的误伤来源
            "SELECT * FROM audit WHERE action = 'delete'",
        ] {
            assert!(validate_read_only_sql(ok_sql).is_ok(), "应放行: {ok_sql}");
        }
    }

    #[test]
    fn read_only_sql_rejects_writes_and_multi_statements() {
        for bad in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "DROP TABLE t",
            // 首词合法、后面在写：只看首关键词会漏掉
            "WITH x AS (SELECT 1) DELETE FROM t",
            "SELECT 1; SELECT 2",
            "SELECT 1; DROP TABLE t",
            "ATTACH DATABASE '/tmp/x' AS y",
            "SELECT * FROM t INTO OUTFILE '/tmp/x'",
        ] {
            assert!(validate_read_only_sql(bad).is_err(), "应拒绝: {bad}");
        }
    }

    #[test]
    fn comments_cannot_hide_writes() {
        assert!(validate_read_only_sql("/* hi */ DELETE FROM t").is_err());
        assert!(validate_read_only_sql("-- x\nDELETE FROM t").is_err());
        // 反向：注释里的分号/写词不该误伤合法查询
        assert!(validate_read_only_sql("SELECT 1 /* ; DROP TABLE t */").is_ok());
    }

    #[test]
    fn column_names_containing_keywords_are_not_writes() {
        // 完整词匹配的意义：`deleted_at` 不是 `delete`
        assert!(validate_read_only_sql("SELECT deleted_at, create_time, updated_at FROM sites").is_ok());
    }

    #[test]
    fn empty_and_oversized_sql_rejected() {
        assert!(validate_read_only_sql("").is_err());
        assert!(validate_read_only_sql("   ;; ").is_err());
        assert!(validate_read_only_sql(&"SELECT ".repeat(2000)).is_err());
    }

    #[test]
    fn db_name_validation() {
        assert!(panel_core::rules::is_valid_db_name("myapp"));
        assert!(panel_core::rules::is_valid_db_name("my_app_2"));
        // 这些会破坏 SQL 或 shell
        assert!(!panel_core::rules::is_valid_db_name("db; DROP TABLE x"));
        assert!(!panel_core::rules::is_valid_db_name("a b"));
        assert!(!panel_core::rules::is_valid_db_name(""));
    }

    #[test]
    fn mysql_connection_requires_user() {
        // 空 user / 纯空白 / 缺失 三种形态都必须拦下
        assert!(validate_connection_create("mysql", &None).is_err());
        assert!(validate_connection_create("mysql", &Some("".into())).is_err());
        assert!(validate_connection_create("mysql", &Some("  ".into())).is_err());
        assert!(validate_connection_create("mysql", &Some("root".into())).is_ok());
    }

    #[test]
    fn postgres_connection_requires_user() {
        assert!(validate_connection_create("postgres", &None).is_err());
        assert!(validate_connection_create("postgres", &Some("postgres".into())).is_ok());
    }

    #[test]
    fn sqlite_connection_does_not_require_user() {
        // sqlite 是本地文件、无账号概念，user 可空、也可任意
        assert!(validate_connection_create("sqlite", &None).is_ok());
        assert!(validate_connection_create("sqlite", &Some("ignored".into())).is_ok());
    }

    #[test]
    fn engines_are_closed_set() {
        for ok in ["mysql", "postgres", "sqlite"] {
            assert!(matches!(ok, "mysql" | "postgres" | "sqlite"));
        }
        assert!(!matches!("oracle", "mysql" | "postgres" | "sqlite"));
        assert!(!matches!("redis", "mysql" | "postgres" | "sqlite"));
    }

    #[test]
    fn password_is_never_returned() {
        // 列表接口只返回 has_password 布尔，不返回口令
        let dto = ConnDto { id: 1, name: "x".into(), engine: "mysql", host: None,
            port: None, default_db: None, client_ready: true, readonly_sql: false, has_password: true,
            remark: String::new() };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(!v.as_object().unwrap().contains_key("password"));
        assert_eq!(v["has_password"], true);
    }

    /// 回归：`password_enc` 是 **BLOB** 列，按 `String` 读会让列表端点直接 500。
    ///
    /// 实证过的失败：`GET /api/v1/db/connections` → 500
    /// `database: Invalid column type Blob at index: 6, name: password_enc`。
    /// 这类错误**编译期看不见、纯函数单测也抓不到**——必须真跑一次带 BLOB 的查询。
    /// 故本测试建真表、插真数据，并直接调用生产用的 `conn_row`（不另抄一份映射）。
    #[test]
    fn conn_row_reads_blob_password_and_null() {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        panel_db::migrate::apply(&mut c).unwrap();

        // 两种形态都要能读：有口令（BLOB 密文）/ 无口令（NULL）
        c.execute(
            "INSERT INTO db_connections(name, engine, host, port, password_enc) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "with-pwd", "mysql", "127.0.0.1", 3306, Some(vec![0xDEu8, 0xAD, 0xBE, 0xEF])
            ],
        ).unwrap();
        c.execute(
            "INSERT INTO db_connections(name, engine) VALUES (?1, ?2)",
            rusqlite::params!["no-pwd", "sqlite"],
        ).unwrap();

        let mut st = c.prepare(CONN_SELECT).unwrap();
        let rows: Vec<ConnRow> = st
            .query_map([], conn_row)
            .unwrap()
            .map(|x| x.expect("含 BLOB 的行必须能被 conn_row 读出（此前正是在此 500）"))
            .collect();

        assert_eq!(rows.len(), 2);
        let pick = |n: &str| rows.iter().find(|r| r.1 == n).expect("缺行").clone();
        // 有口令：密文原样取回（下游只用 is_some，不解密）
        assert_eq!(pick("with-pwd").6.as_deref(), Some(&[0xDEu8, 0xAD, 0xBE, 0xEF][..]));
        // 无口令：NULL 必须映射成 None，而不是报类型错
        assert!(pick("no-pwd").6.is_none(), "NULL 口令应映射为 None");
    }

    // ── SQL 控制台元数据：引擎文案不得串味 ──

    /// PG 的默认语句与示例**一条 `sqlite_master` 都不能有**。
    ///
    /// 这条守的是这次改造最容易犯的错：控制台从"只对 SQLite 开放"扩到 PG，
    /// 示例 SQL 却还是原来那五条 SQLite 专用句子。用户点开 PG 连接的控制台，
    /// 第一眼看到的是 `SELECT name FROM sqlite_master …`，一执行就是
    /// 「relation "sqlite_master" does not exist」——按钮是亮的、功能是废的。
    /// 判据必须是**内容**，不是"示例列表非空"（非空对串味恒真）。
    #[test]
    fn pg_console_samples_contain_no_sqlite_artifacts() {
        let (default_sql, samples, note) = sql_console_meta("postgres");
        assert!(!default_sql.is_empty(), "默认语句不能空");
        assert_eq!(samples.len(), 5, "示例条数应与 SQLite 对齐（5 条）");
        for (label, sql) in &samples {
            let low = sql.to_ascii_lowercase();
            assert!(!low.contains("sqlite_master"),
                "PG 示例不得出现 sqlite_master：{label} → {sql}");
            assert!(!low.contains("pragma"),
                "PG 没有 PRAGMA，示例不得出现：{label} → {sql}");
        }
        let low = default_sql.to_ascii_lowercase();
        assert!(!low.contains("sqlite_master"), "默认语句不得出现 sqlite_master：{default_sql}");
        assert!(low.contains("information_schema") || low.contains("pg_catalog"),
            "PG 默认语句应指向它自己的目录表：{default_sql}");
        // 边界提示必须讲 PG **真实存在**的残余风险，不能是空话
        assert!(note.contains("pg_reload_conf"),
            "PG 提示必须点出只读护栏拦不住的配置类函数：{note}");
    }

    /// SQLite 侧保持原样（这五条是既有行为，改造不得顺手改掉）。
    /// 反向判据：PG 分支若漏写、落到 `_ =>` 分支上，这条不会红，
    /// 所以真正确认"没串味"的是上一条；这条确认的是"没把 SQLite 弄丢"。
    #[test]
    fn sqlite_console_samples_stay_sqlite_native() {
        let (default_sql, samples, note) = sql_console_meta("sqlite");
        assert!(default_sql.to_ascii_lowercase().contains("sqlite_master"));
        assert_eq!(samples.len(), 5);
        // 表结构走 sqlite_master，而不是 PG 的 information_schema
        let structure = samples.iter().find(|(l, _)| *l == "表结构").expect("缺表结构示例");
        assert!(structure.1.to_ascii_lowercase().contains("sqlite_master"));
        assert!(!note.is_empty(), "SQLite 的边界提示不能空");
    }

    /// 未知引擎走 SQLite 分支：前端只会传后端自己下发的 engine 串，
    /// 但 `_ =>` 兜底必须是"能用的那一套"，而不是空列表让控制台开天窗。
    #[test]
    fn unknown_engine_falls_back_to_sqlite_samples_not_empty() {
        let (default_sql, samples, note) = sql_console_meta("oracle");
        assert!(!default_sql.is_empty());
        assert!(!samples.is_empty(), "兜底分支不能给空示例");
        assert!(!note.is_empty(), "兜底分支的边界提示不能空");
    }

    /// 控制台对 MySQL 不开放，但 `sql_console_meta` 仍返回兜底文案——
    /// **这不矛盾**：门控在 `readonly_sql` 能力位上，meta 只提供内容。
    /// 把两者混在一个判断里，就会出现"能力位说不能跑、示例却说能跑"的自相矛盾。
    #[test]
    fn mysql_meta_content_is_decoupled_from_the_capability_bit() {
        // 内容：有兜底（不会被能力位卡住后开天窗）
        let (default_sql, _, note) = sql_console_meta("mysql");
        assert!(!default_sql.is_empty());
        assert!(!note.is_empty());
        // 能力：矩阵里恒 false（这才是真正的门控）
        assert!(!panel_os::db_console_open(panel_os::DbEngine::MySql, true));
    }
}
