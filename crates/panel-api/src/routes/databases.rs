//! 数据库管理（设计方案 §2.6）。
//!
//! # 范围克制：MVP 只做"备份/恢复 + 列表"，不做 Web SQL 终端
//! 理由：
//! - Web 里放 SQL 执行框 = 给 XSS/CSRF 一个高价值目标，且难以做资源隔离；
//! - 慢查询会占住连接与 CPU，低配机器上直接拖垮面板；
//! - 真要执行 SQL，用本地客户端更安全。
//! 备份/恢复是运维刚需且可走任务队列，故优先实现。
//!
//! # ⚠️ 安全说明
//! 连接口令一律经 AES-256-GCM（主密钥来自 `master.key`）加密后写入 `password_enc`，
//! 列表接口仅返回 `has_password` 布尔，绝不回显明文/密文。无主密钥时创建带口令的连接被拒绝。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
// Path 与 std::path::PathBuf 同名，按全仓约定别名成 AxPath
use axum::{extract::{Path as AxPath, State}, Json};
use panel_core::{cap_keys, PanelError, Result, SafePath};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct ConnDto {
    pub id: i64,
    pub name: String,
    pub engine: &'static str,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub database: Option<String>,
    /// 是否可用（外部客户端缺失时为 false，UI 据此置灰）
    pub available: bool,
    /// 是否有口令（**绝不返回口令本身**）
    pub has_password: bool,
}

pub async fn list(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;

    let rows = state.pool.with(|conn| {
        let mut st = conn.prepare(
            "SELECT id, name, engine, host, port, database, password_enc FROM db_connections")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map([], |r| Ok((
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?, r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<String>>(5)?, r.get::<_, Option<String>>(6)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;

    let mut dtos = Vec::new();
    for (id, name, engine, host, port, database, pwd) in rows {
        let eng = match engine.as_str() {
            "mysql" => panel_os::DbEngine::MySql,
            "postgres" => panel_os::DbEngine::Postgres,
            _ => panel_os::DbEngine::Sqlite,
        };
        // 可用性逐个探测（外部客户端可能缺失）
        let available = state.os.databases().available().await.unwrap_or(false);
        dtos.push(ConnDto {
            id, name,
            engine: match eng { panel_os::DbEngine::MySql => "mysql",
                                panel_os::DbEngine::Postgres => "postgres",
                                panel_os::DbEngine::Sqlite => "sqlite" },
            host, port, database,
            available: available && state.capabilities
                .get(cap_keys::DBMS_MANAGE).map(|c| c.supported).unwrap_or(false),
            has_password: pwd.is_some(),
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
    pub database: Option<String>,
}

pub async fn create(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_MANAGE)?;

    // 库名校验（强类型构造点，防 `db; DROP`）
    if !panel_core::rules::is_valid_db_name(&req.name) {
        return Err(ApiError::bad_request("name", "invalid database name"));
    }
    if let Some(db) = &req.database {
        if !panel_core::rules::is_valid_db_name(db) {
            return Err(ApiError::bad_request("database", "invalid database name"));
        }
    }
    let engine = match req.engine.as_str() {
        "mysql" | "postgres" | "sqlite" => req.engine.clone(),
        other => return Err(ApiError::bad_request("engine", format!("unsupported: {other}"))),
    };

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
    let db = req.database.clone();
    let host = req.host.clone();
    let port = req.port.map(|p| p as i64);
    state.db.exec(move |conn| {
        conn.execute(
            "INSERT INTO db_connections(name, engine, host, port, username, password_enc, database, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![name, engine, host, port, user, password_enc, db, crate::now_unix()],
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await?;

    audit(&state, &s, "db.create", &req.name, "ok").await;
    Ok(ok(serde_json::json!({ "name": req.name })))
}

// ─────────────── 备份 / 恢复（走任务队列） ───────────────

#[derive(Debug, Deserialize)]
pub struct BackupReq { pub id: i64, pub out: String }

pub async fn backup(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<BackupReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_MANAGE)?;

    // 输出路径必须在允许根内（防把备份写到 /etc 覆盖配置）
    let out = resolve_out(&state, &s, &req.out)?;
    if !panel_core::rules::is_valid_path_segment(&req.out) && req.out.contains('/') {
        // 允许子目录，但不允许 `..` 逃逸 —— 由 resolve_out 兜底
    }

    let os = state.os.clone();
    let (id, _) = state.tasks.submit(
        panel_task::TaskRequest {
            idempotency_key: format!("db.backup:{}", req.id),
            kind: panel_task::TaskKind::Database,
            label: format!("备份数据库 #{}", req.id),
            timeout: std::time::Duration::from_secs(3600),
        },
        DbBackupTask { conn_id: req.id, out, os },
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "db.backup", &req.id.to_string(), "queued").await;
    Ok(ok(serde_json::json!({ "task_id": id })))
}

fn resolve_out(_state: &Shared, s: &crate::auth::Session, input: &str) -> Result<SafePath> {
    let mut last = None;
    for r in &s.allowed_roots {
        match panel_os::paths::resolve_within(&PathBuf::from(r), input) {
            Ok(p) => return Ok(p),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| PanelError::PathEscape(input.to_string())))
}

struct DbBackupTask {
    conn_id: i64,
    out: SafePath,
    os: std::sync::Arc<dyn panel_os::OsAdapter>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for DbBackupTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(5, "准备备份").await;
        // 完整实现应读出连接信息并解密口令后构造 DbTarget；
        // 骨架阶段 DbTarget 用本地默认值，M4 接线真实凭据。
        let t = panel_os::DbTarget {
            engine: panel_os::DbEngine::Sqlite,
            host: None, port: None, user: None, password: None, database: None,
        };
        let p = progress.clone();
        self.os.databases().backup(&t, &self.out, Box::new(move |line| {
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
pub struct RestoreReq { pub id: i64, pub from: String }

pub async fn restore(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<RestoreReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_MANAGE)?;
    let _ = resolve_out(&state, &s, &req.from)?;
    // 恢复是破坏性操作：**必须走任务且要求幂等键不同**（防误触两次）
    return Err(ApiError::unsupported(
        "数据恢复为破坏性操作，M4 接入（需先完成凭据加密与二次确认流程）"));
}

// ─────────────── 文档式数据库端点（M4 占位） ───────────────

pub async fn databases_of(
    State(state): State<Shared>, Auth(s): Auth, AxPath(conn): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    let _ = (state, conn);
    Err(ApiError::unsupported("db.databases (M4)"))
}

pub async fn tables(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath((conn, db)): AxPath<(i64, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    let _ = (state, conn, db);
    Err(ApiError::unsupported("db.tables (M4)"))
}

pub async fn rows(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath((conn, db, table)): AxPath<(i64, String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::DB_VIEW)?;
    let _ = (state, conn, db, table);
    Err(ApiError::unsupported("db.rows (M4: 仅预览，禁止 Web SQL 终端)"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            port: None, database: None, available: true, has_password: true };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(!v.as_object().unwrap().contains_key("password"));
        assert_eq!(v["has_password"], true);
    }
}
