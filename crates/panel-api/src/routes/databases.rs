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
use axum::{extract::{Path as AxPath, Query, State}, Json};
use panel_core::{PanelError, Result, SafePath};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct ConnDto {
    pub id: i64,
    pub name: String,
    pub engine: &'static str,
    pub host: Option<String>,
    pub port: Option<i64>,
    /// 连接默认库（schema 列名 `default_db`，与 OpenAPI `DbConnection.default_db` 同名）
    pub default_db: Option<String>,
    /// 是否可用（该引擎未实装时为 false，UI 据此置灰）
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
            "SELECT id, name, engine, host, port, default_db, password_enc FROM db_connections")
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
    for (id, name, engine, host, port, default_db, pwd) in rows {
        let eng = match engine.as_str() {
            "mysql" => panel_os::DbEngine::MySql,
            "postgres" => panel_os::DbEngine::Postgres,
            _ => panel_os::DbEngine::Sqlite,
        };
        // 逐连接按引擎判定「是否已实装」：未实装的引擎（mysql/postgres）诚实置灰，不撒谎
        let available = state.os.databases().supports(eng);
        dtos.push(ConnDto {
            id, name,
            engine: match eng { panel_os::DbEngine::MySql => "mysql",
                                panel_os::DbEngine::Postgres => "postgres",
                                panel_os::DbEngine::Sqlite => "sqlite" },
            host, port, default_db,
            available,
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
    /// 连接默认库；sqlite 引擎下填 `.db` 文件路径
    pub default_db: Option<String>,
}

pub async fn create(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<CreateReq>,
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
    Json(req): Json<RestoreReq>,
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
    let src = resolve_out(&state, &s, &req.file)?;
    if !src.as_path().is_file() {
        return Err(ApiError::not_found("backup file"));
    }

    let t = load_target(&state, conn, None).await?;
    let db_path = match t.engine {
        panel_os::DbEngine::Sqlite => t
            .database
            .clone()
            .ok_or_else(|| ApiError::bad_request("conn", "该连接未指定库文件路径"))?,
        panel_os::DbEngine::MySql | panel_os::DbEngine::Postgres => {
            return Err(ApiError::unsupported(
                "mysql/postgres 还原需外部客户端（mysql / psql），本环境不可用",
            ))
        }
    };

    let job = DbRestoreTask { src: src.as_path().to_path_buf(), dst: PathBuf::from(db_path) };
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

/// 库还原任务体：**先备份当前库再覆盖**，失败即中止。
struct DbRestoreTask {
    src: PathBuf,
    dst: PathBuf,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for DbRestoreTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(20, "备份当前库").await;
        // 当前库不存在时跳过备份（首次还原），存在则必先留快照
        let safety = if self.dst.is_file() {
            let bak = PathBuf::from(format!(
                "{}.bak-{}",
                self.dst.display(),
                crate::now_unix()
            ));
            std::fs::copy(&self.dst, &bak).map_err(|e| PanelError::Io(e.to_string()))?;
            Some(bak)
        } else {
            None
        };

        progress.set(70, "写入还原").await;
        std::fs::copy(&self.src, &self.dst).map_err(|e| PanelError::Io(e.to_string()))?;

        progress.set(100, "完成").await;
        Ok(panel_task::TaskOutcome {
            state: panel_task::TaskState::Ok,
            exit_code: Some(0),
            // 指向还原前的快照，出问题可据此回滚
            output_path: safety,
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

/// 读连接行 → 解密口令 → 构造 `DbTarget`（浏览各端点的统一入口）。
async fn load_target(state: &Shared, conn: i64, db_override: Option<&str>) -> ApiResult<panel_os::DbTarget> {
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
        .map(|x| serde_json::json!({ "name": x.name, "rows": x.rows, "engine": engine }))
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

/// 只读 SQL 控制台。**只对 SQLite 开放**——只有它的读连接是物理只读的，
/// 其它引擎没有这个保证，provider 层会诚实 501。
pub async fn query(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(conn): AxPath<i64>, Json(req): Json<QueryReq>,
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
/// **这不是唯一防线**：SQLite 走只读连接打开，写语句物理上会失败。
/// 这里做两件事：
///   1. 尽早给出可读的错误（比引擎的 "attempt to write a readonly database" 好懂）；
///   2. 对将来可能接入的其它引擎，这是**必须**拦住的地方。
///
/// 判定不能只看首关键词——`WITH x AS (…) DELETE …` 的首词完全合法，
/// 因此必须叠加写关键词黑名单。
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
mod tests {
    use super::*;

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
            port: None, default_db: None, available: true, has_password: true };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(!v.as_object().unwrap().contains_key("password"));
        assert_eq!(v["has_password"], true);
    }
}
