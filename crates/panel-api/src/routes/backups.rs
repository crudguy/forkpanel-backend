//! 备份计划与产物（**本地**）。
//!
//! 数据模型：`backup_jobs`（schema 早已定义，此前无人使用）。
//! - `kind=panel`：用 SQLite 在线备份（`panel_db::backup_to`）导出面板自身数据；
//! - `kind=site`：用 `tar -czf` 打包站点根目录（经 `panel_os::backup::tar_gz`）。
//!
//! **产物命名**：`plan<id>-<unix>.<ext>`，因此「某计划的产物」= 目录内前缀匹配。
//! **沙箱**：产物目录必须落在面板 `backup_dir()` 之内（`resolve_within` 校验）。
//! **恢复**是高危写操作（覆盖当前数据），未实装前诚实 501 —— 需二次确认 + 先备份当前态。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    Json,
};
use panel_core::{cap_keys, PanelError, Result, SafePath};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// 当前只实装这两类；`db` 见 `/api/v1/db/{conn}/backup`（另一条线）。
const KINDS: &[&str] = &["panel", "site"];

#[derive(Debug, Serialize)]
pub struct PlanDto {
    pub id: i64,
    pub kind: String,
    pub target: String,
    pub cron_expr: Option<String>,
    pub keep_count: i64,
    pub dest_dir: String,
    pub enabled: bool,
    pub last_run_at: Option<i64>,
    pub last_result: Option<String>,
}

const COLS: &str = "id, kind, target, cron_expr, keep_count, dest_dir, enabled, last_run_at, last_result";

fn db_err(e: rusqlite::Error) -> PanelError { PanelError::Database(e.to_string()) }

fn row_dto(r: &rusqlite::Row<'_>) -> rusqlite::Result<PlanDto> {
    Ok(PlanDto {
        id: r.get(0)?,
        kind: r.get(1)?,
        target: r.get(2)?,
        cron_expr: r.get(3)?,
        keep_count: r.get(4)?,
        dest_dir: r.get(5)?,
        enabled: r.get::<_, i64>(6)? != 0,
        last_run_at: r.get(7)?,
        last_result: r.get(8)?,
    })
}

/// 产物目录必须在 `backup_dir()` 之内（`input` 为相对该目录的子路径）。
/// 用 `resolve_within_for_create`：目标目录**允许尚不存在**（首次备份时会创建）；
/// 不掩盖底层错误（NotFound/Validation/PathEscape 各自如实上抛）。
fn resolve_dest(state: &Shared, input: &str) -> Result<SafePath> {
    let base = state.os.paths().backup_dir();
    let _ = std::fs::create_dir_all(&base);   // 自愈：备份根缺失时先建
    panel_os::paths::resolve_within_for_create(&base, input.trim())
}

async fn fetch_plan(state: &Shared, id: i64) -> Result<Option<PlanDto>> {
    state
        .pool
        .with(move |conn| {
            let sql = format!("SELECT {COLS} FROM backup_jobs WHERE id = ?1");
            let mut st = conn.prepare(&sql).map_err(db_err)?;
            let mut it = st.query_map([id], row_dto).map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await
}

async fn site_root_by_name(state: &Shared, name: &str) -> Result<Option<String>> {
    let name = name.to_string();
    state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT root FROM sites WHERE name = ?1")
                .map_err(db_err)?;
            let mut it = st.query_map([name], |r| r.get::<_, String>(0)).map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await
}

// ─────────────── CRUD ───────────────

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_VIEW)?;
    let rows = state
        .pool
        .with(|conn| {
            let sql = format!("SELECT {COLS} FROM backup_jobs ORDER BY id");
            let mut st = conn.prepare(&sql).map_err(db_err)?;
            let it = st.query_map([], row_dto).map_err(db_err)?;
            let mut v = Vec::new();
            for x in it { v.push(x.map_err(db_err)?); }
            Ok(v)
        })
        .await?;
    Ok(ok(rows))
}

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub kind: String,
    pub target: String,
    #[serde(default)]
    pub cron_expr: Option<String>,
    #[serde(default)]
    pub keep_count: Option<i64>,
    pub dest_dir: String,
    #[serde(default)]
    pub enabled: Option<bool>,
}

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    let (kind, target, dest) = validate_target(&state, &req.kind, &req.target, &req.dest_dir).await?;
    let keep = req.keep_count.unwrap_or(7).clamp(1, 365);
    let enabled = req.enabled.unwrap_or(true) as i32;
    let cron = req.cron_expr.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO backup_jobs(kind, target, cron_expr, keep_count, dest_dir, enabled)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![kind, target, cron, keep, dest, enabled],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    audit(&state, &s, "backup.create", &req.target, "ok").await;
    Ok(ok(serde_json::json!({ "created": true })))
}

#[derive(Debug, Deserialize)]
pub struct PatchReq {
    #[serde(default)]
    pub cron_expr: Option<String>,
    #[serde(default)]
    pub keep_count: Option<i64>,
    #[serde(default)]
    pub dest_dir: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

pub async fn patch(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<PatchReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    let cur = fetch_plan(&state, id).await?.ok_or_else(|| ApiError::not_found("backup plan"))?;

    // 校验 dest_dir（若变更）：仍必须落在 backup_dir 之内
    let dest = match &req.dest_dir {
        Some(d) => { let _ = resolve_dest(&state, d)?; d.trim().to_string() }
        None => cur.dest_dir.clone(),
    };
    let keep = req.keep_count.unwrap_or(cur.keep_count).clamp(1, 365);
    let enabled = req.enabled.unwrap_or(cur.enabled) as i32;
    let cron = req.cron_expr.clone().or(cur.cron_expr.clone());

    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE backup_jobs SET cron_expr = ?1, keep_count = ?2, dest_dir = ?3, enabled = ?4 WHERE id = ?5",
                rusqlite::params![cron, keep, dest, enabled, id],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    audit(&state, &s, "backup.patch", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "updated": true })))
}

pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<axum::http::StatusCode> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    let n = state
        .db
        .exec(move |conn| {
            let n = conn
                .execute("DELETE FROM backup_jobs WHERE id = ?1", [id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;
    if n.rows_changed == 0 {
        return Err(ApiError::not_found("backup plan"));
    }
    audit(&state, &s, "backup.delete", &id.to_string(), "ok").await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// 校验 kind/target/dest_dir，返回规范化后的 (kind, target, dest_dir_str)。
async fn validate_target(
    state: &Shared,
    kind: &str,
    target: &str,
    dest: &str,
) -> Result<(String, String, String)> {
    if !KINDS.contains(&kind) {
        return Err(PanelError::Validation { field: "kind".into(), reason: format!("仅支持 {KINDS:?}") });
    }
    let target = target.trim().to_string();
    if target.is_empty() {
        return Err(PanelError::Validation { field: "target".into(), reason: "target required".into() });
    }
    // panel 的 target 固定；site 的 target 必须是真实存在的站点（避免备份空目录）
    if kind == "panel" {
        if target != "panel" {
            return Err(PanelError::Validation { field: "target".into(), reason: "panel 计划的 target 必须为 panel".into() });
        }
    } else if site_root_by_name(state, &target).await?.is_none() {
        return Err(PanelError::NotFound(format!("site {target}")));
    }
    // 只**校验** dest 落在 backup_dir 之内；落库存**相对输入**（后续按相对解析才一致）
    let _ = resolve_dest(state, dest)?;
    Ok((kind.to_string(), target, dest.trim().to_string()))
}

// ─────────────── 执行（任务化） ───────────────

struct BackupJob {
    id: i64,
    kind: String,
    root: Option<PathBuf>,
    dest: PathBuf,
    /// 面板 SQLite 路径（panel 备份用；独立连接，绕开写者事务）
    db_path: PathBuf,
    writer: std::sync::Arc<panel_db::WriterActor>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for BackupJob {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        match self.execute(progress).await {
            Ok(o) => Ok(o),
            Err(e) => {
                eprintln!("[panel] 备份计划 #{} 失败: {e}", self.id);
                Err(e)
            }
        }
    }
}

impl BackupJob {
    async fn execute(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(5, "准备备份").await;
        std::fs::create_dir_all(&self.dest).map_err(|e| PanelError::Internal(e.to_string()))?;
        let ts = crate::now_unix();

        let out_path = match self.kind.as_str() {
            "panel" => {
                let dest = self.dest.join(format!("plan{}-{}.db", self.id, ts));
                // 独立连接备份：写者把 op 包在事务里，事务内不能 VACUUM INTO
                panel_db::backup_file(&self.db_path, &dest)?;
                dest
            }
            "site" => {
                let root = self.root.clone().ok_or_else(|| PanelError::Internal("site root 缺失".into()))?;
                let dest = self.dest.join(format!("plan{}-{}.tar.gz", self.id, ts));
                panel_os::backup::tar_gz(&root, &dest).await?;
                dest
            }
            other => {
                return Err(PanelError::Validation {
                    field: "kind".into(),
                    reason: format!("unsupported backup kind: {other}"),
                })
            }
        };

        progress.set(95, "记录结果").await;
        let id = self.id;
        self.writer
            .exec(move |conn| {
                conn.execute(
                    "UPDATE backup_jobs SET last_run_at = ?1, last_result = 'ok' WHERE id = ?2",
                    rusqlite::params![crate::now_unix(), id],
                )
                .map(|_| panel_db::WriteAck { rows_changed: 1 })
                .map_err(|e| PanelError::Database(e.to_string()))
            })
            .await?;
        progress.set(100, "完成").await;
        Ok(panel_task::TaskOutcome {
            state: panel_task::TaskState::Ok,
            exit_code: Some(0),
            output_path: Some(out_path),
        })
    }
}

pub async fn run(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    if !state.capabilities.get(cap_keys::BACKUP_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("backup.manage"));
    }
    let plan = fetch_plan(&state, id).await?.ok_or_else(|| ApiError::not_found("backup plan"))?;
    let dest = resolve_dest(&state, &plan.dest_dir)?.as_path().to_path_buf();
    let root = match plan.kind.as_str() {
        "site" => Some(PathBuf::from(
            site_root_by_name(&state, &plan.target).await?
                .ok_or_else(|| ApiError::bad_request("target", "site not found"))?,
        )),
        _ => None,
    };

    let job = BackupJob {
        id,
        kind: plan.kind.clone(),
        root,
        dest,
        db_path: state.os.paths().sqlite_path(),
        writer: state.db.clone(),
    };
    let (tid, _) = state
        .tasks
        .submit(
            panel_task::TaskRequest {
                idempotency_key: format!("backup:{id}"),
                kind: panel_task::TaskKind::Backup,
                label: format!("备份计划 #{id}（{}）", plan.target),
                timeout: Duration::from_secs(3600),
            },
            job,
        )
        .await
        .map_err(ApiError::from)?;
    audit(&state, &s, "backup.run", &id.to_string(), "queued").await;
    Ok(ok(serde_json::json!({ "task_id": tid })))
}

/// 产物列表（目录内 `plan<id>-` 前缀文件）。
pub async fn artifacts(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_VIEW)?;
    let plan = fetch_plan(&state, id).await?.ok_or_else(|| ApiError::not_found("backup plan"))?;
    let dest = resolve_dest(&state, &plan.dest_dir)?;

    let prefix = format!("plan{id}-");
    let mut items: Vec<serde_json::Value> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dest.as_path()) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with(&prefix) { continue; }
            let md = e.metadata().ok();
            let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
            let mtime = md
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            items.push(serde_json::json!({ "name": name, "size": size, "mtime": mtime }));
        }
    }
    items.sort_by(|a, b| b["name"].as_str().cmp(&a["name"].as_str()));
    Ok(ok(items))
}

/// 从产物恢复：**高危**（覆盖当前数据），未实装前诚实 501。
pub async fn restore(
    State(_): State<Shared>,
    Auth(s): Auth,
    AxPath(_id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    Err(ApiError::unsupported(
        "backup.restore：恢复会覆盖当前数据（高危），需二次确认 + 自动先备份当前态，尚未接入"))
}
