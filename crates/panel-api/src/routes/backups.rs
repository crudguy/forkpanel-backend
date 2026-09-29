//! 备份计划与产物（**本地**）。
//!
//! 数据模型：`backup_jobs`（schema 早已定义，此前无人使用）。
//! - `kind=panel`：用 SQLite 在线备份（`panel_db::backup_to`）导出面板自身数据；
//! - `kind=site`：用 `tar -czf` 打包站点根目录（经 `panel_os::backup::tar_gz`）。
//!
//! **产物命名**：`plan<id>-<unix>.<ext>`，因此「某计划的产物」= 目录内前缀匹配。
//! **沙箱**：产物目录必须落在面板 `backup_dir()` 之内（`resolve_within` 校验）。
//! **恢复**（`kind=site`）已实装：确认词 + 产物名白名单 + **自动先备份当前态** + 归档逃逸校验，
//! 全程走任务中心（`TaskKind::Restore`，破坏性操作不自动重试）。
//! `kind=panel` 保持诚实 501：面板库是自身运行中的库，在线覆盖会损坏 SQLite WAL。

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
    /// 保留份数：成功后按此裁剪最旧产物（防止低配盘被备份撑爆）
    keep_count: i64,
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
                // 备份**静默失败等于没有备份** —— 必须让人知道，否则出事才发现无退路。
                // 按天去重：同一计划当天只报一条，避免每次调度都刷屏。
                let msg = e.to_string();
                crate::routes::notifications::push(
                    &self.writer,
                    crate::routes::notifications::NewNotification {
                        level: "crit",
                        source: "backup",
                        title: format!("备份计划 #{} 执行失败", self.id),
                        body: Some(msg),
                        dedup_key: Some(format!(
                            "backup:{}:fail:{}",
                            self.id,
                            crate::now_unix() / 86_400
                        )),
                    },
                )
                .await;
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

        // 成功后按 keep_count 裁剪最旧产物（保留含本次在内的最新 keep 份）。
        // 不清理会让备份产物无限累加，最终撑爆低配盘——备份反而成了故障源。
        let pruned = prune_old_artifacts(&self.dest, self.id, self.keep_count);
        if pruned > 0 {
            eprintln!("[panel] 备份计划 #{} 按 keep_count={} 清理了 {pruned} 份旧产物",
                self.id, self.keep_count);
        }

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
        keep_count: plan.keep_count,
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

/// 恢复的二次确认词。前端 ConfirmDialog 必须让用户手输该词才能提交。
pub const RESTORE_CONFIRM_WORD: &str = "覆盖恢复";

#[derive(Debug, Deserialize)]
pub struct RestoreReq {
    /// 产物文件名（取自 `artifacts` 列表），**不接受路径**
    pub artifact: String,
    /// 二次确认词，必须等于 [`RESTORE_CONFIRM_WORD`]
    pub confirm_token: String,
}

/// 从产物恢复：**高危**（覆盖当前数据）。
///
/// 三道闸门（缺一不可）：
/// 1. **二次确认词** `confirm_token` —— 防误点；
/// 2. **产物名白名单** —— 必须属本计划前缀且真实存在，不接受 `/` 与 `..`；
/// 3. **自动先备份当前态** —— 任务内第一步（见 `RestoreJob`），失败即中止、绝不裸覆盖。
///
/// `kind=panel` 例外：面板库是面板自身运行的库，在线覆盖会让 SQLite WAL 损坏，
/// 诚实 501 并给出停服后手动替换的指引——不提供"看起来能点"的危险按钮。
pub async fn restore(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<RestoreReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    if !state.capabilities.get(cap_keys::BACKUP_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("backup.manage"));
    }

    // 闸门 1：确认词
    if req.confirm_token.trim() != RESTORE_CONFIRM_WORD {
        return Err(ApiError::bad_request(
            "confirm_token",
            format!("请输入确认词「{RESTORE_CONFIRM_WORD}」以继续"),
        ));
    }

    let plan = fetch_plan(&state, id).await?.ok_or_else(|| ApiError::not_found("backup plan"))?;
    if plan.kind == "panel" {
        return Err(ApiError::unsupported(
            "面板数据库为面板自身运行中的库：在线覆盖会损坏 SQLite WAL。请先停止 panel 服务，再用产物文件手动替换数据目录内的库文件。",
        ));
    }

    // 闸门 2：产物名白名单（目录内前缀匹配 + 禁止路径成分）
    let prefix = format!("plan{id}-");
    let name = req.artifact.trim();
    if !name.starts_with(&prefix) || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(ApiError::bad_request("artifact", "产物名不属于本计划或含非法路径成分"));
    }
    let dest = resolve_dest(&state, &plan.dest_dir)?;
    let archive = dest.as_path().join(name);
    if !archive.is_file() {
        return Err(ApiError::not_found("artifact"));
    }

    let root = PathBuf::from(
        site_root_by_name(&state, &plan.target)
            .await?
            .ok_or_else(|| ApiError::bad_request("target", "site not found"))?,
    );

    let job = RestoreJob {
        id,
        root,
        archive: archive.as_path().to_path_buf(),
        safety_dir: dest.as_path().to_path_buf(),
        writer: state.db.clone(),
    };
    // 幂等键含产物名：同一产物重复提交返回同一任务，天然防误触两次
    let (tid, _) = state
        .tasks
        .submit(
            panel_task::TaskRequest {
                idempotency_key: format!("restore:{id}:{name}"),
                kind: panel_task::TaskKind::Restore,
                label: format!("恢复计划 #{id}（{name}）"),
                timeout: Duration::from_secs(3600),
            },
            job,
        )
        .await
        .map_err(ApiError::from)?;
    // 注：audit 的 result 形参是 &'static str，故产物名走 target（动态），result 用字面量
    audit(&state, &s, "backup.restore", &format!("{id}:{name}"), "queued").await;
    Ok(ok(serde_json::json!({ "task_id": tid })))
}

// ─────────────── 恢复任务体 ───────────────

struct RestoreJob {
    id: i64,
    /// 站点根目录（恢复目标）
    root: PathBuf,
    /// 归档产物绝对路径
    archive: PathBuf,
    /// 安全快照落点（= 产物目录）
    safety_dir: PathBuf,
    /// 写者：失败时落站内通知
    writer: std::sync::Arc<panel_db::WriterActor>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for RestoreJob {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        match self.execute(progress).await {
            Ok(o) => Ok(o),
            Err(e) => {
                eprintln!("[panel] 恢复计划 #{} 失败: {e}", self.id);
                // 恢复失败意味着现场可能处于"已备份未覆盖"或"部分覆盖"的中间态，
                // 必须立即告知人工确认——不去重（每次失败都是独立事件）。
                let msg = e.to_string();
                crate::routes::notifications::push(
                    &self.writer,
                    crate::routes::notifications::NewNotification {
                        level: "crit",
                        source: "restore",
                        title: format!("恢复计划 #{} 失败，请人工确认现场状态", self.id),
                        body: Some(msg),
                        dedup_key: None,
                    },
                )
                .await;
                Err(e)
            }
        }
    }
}

impl RestoreJob {
    async fn execute(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        // ① 解压前校验归档条目：拒绝 `../` 逃逸与绝对路径
        progress.set(10, "校验归档").await;
        let entries = panel_os::backup::list_tar_entries(&self.archive).await?;
        if let Some(bad) = entries.iter().find(|e| !panel_os::backup::is_safe_entry(e)) {
            return Err(PanelError::Validation {
                field: "archive".into(),
                reason: format!("归档含不安全条目，已中止：{bad}"),
            });
        }

        // ② 自动先备份当前态：这是"恢复"唯一的安全网，失败即中止、绝不裸覆盖
        progress.set(30, "先备份当前态").await;
        std::fs::create_dir_all(&self.safety_dir)
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        let ts = crate::now_unix();
        let safety = self.safety_dir.join(format!("safety-plan{}-{}.tar.gz", self.id, ts));
        panel_os::backup::tar_gz(&self.root, &safety).await?;

        // ③ 解包覆盖（归档内含顶层目录名，故解压到父目录）
        progress.set(70, "解压覆盖").await;
        let parent = self
            .root
            .parent()
            .ok_or_else(|| PanelError::Internal("站点目录无父目录".into()))?
            .to_path_buf();
        panel_os::backup::untar_gz(&self.archive, &parent).await?;

        progress.set(100, "完成").await;
        // output_path 指向**恢复前的快照**：出问题可据此回滚
        Ok(panel_task::TaskOutcome {
            state: panel_task::TaskState::Ok,
            exit_code: Some(0),
            output_path: Some(safety),
        })
    }
}

// ─────────────── 保留份数裁剪 ───────────────

/// 按 `keep_count` 裁剪本计划的旧产物：保留**最新** keep 份，删除更旧的。
///
/// 只认 `plan<id>-` 前缀（不误伤其他计划与其他文件）；按文件名排序——
/// 文件名形如 `plan1-1700000000.db`，时间戳为定长 unix 秒，字典序即时间序。
///
/// **返回被删除的数量**。单点删除失败只记日志、不向上抛错：
/// 产物清理失败不该把一次「备份已成功」翻转为失败。
fn prune_old_artifacts(dest: &std::path::Path, plan_id: i64, keep: i64) -> usize {
    let keep = keep.max(1) as usize;
    let prefix = format!("plan{plan_id}-");
    let mut names: Vec<String> = match std::fs::read_dir(dest) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(&prefix))
            .collect(),
        Err(_) => return 0,
    };
    if names.len() <= keep {
        return 0;
    }
    names.sort(); // 升序 → 前面是最旧的
    let drop_n = names.len() - keep;
    let mut removed = 0usize;
    for n in names.into_iter().take(drop_n) {
        match std::fs::remove_file(dest.join(&n)) {
            Ok(()) => removed += 1,
            Err(e) => eprintln!("[panel] 清理旧备份产物失败 {}: {e}", dest.join(&n).display()),
        }
    }
    removed
}

#[cfg(test)]
mod prune_tests {
    use super::prune_old_artifacts;
    use std::fs;

    fn mk(dir: &std::path::Path, name: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), b"x").unwrap();
    }

    fn ls(dir: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn keeps_only_the_newest_n_artifacts() {
        let d = std::env::temp_dir().join(format!("panel-prune-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for i in 1..=5 {
            mk(&d, &format!("plan7-100000000{i}.db"));
        }
        let removed = prune_old_artifacts(&d, 7, 2);
        assert_eq!(removed, 3, "5 份保留 2 → 应删 3");
        assert_eq!(
            ls(&d),
            vec!["plan7-1000000004.db".to_string(), "plan7-1000000005.db".to_string()],
            "应只保留最新的两份"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn does_not_touch_other_plans_or_unrelated_files() {
        let d = std::env::temp_dir().join(format!("panel-prune2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mk(&d, "plan7-1.db");
        mk(&d, "plan7-2.db");
        mk(&d, "plan7-3.db");
        mk(&d, "plan8-1.db"); // 别的计划
        mk(&d, "unrelated.txt");
        let removed = prune_old_artifacts(&d, 7, 1);
        assert_eq!(removed, 2, "只应删 plan7- 的旧产物");
        assert_eq!(ls(&d), vec!["plan7-3.db".to_string(), "plan8-1.db".to_string(), "unrelated.txt".to_string()]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn noop_when_under_budget() {
        let d = std::env::temp_dir().join(format!("panel-prune3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mk(&d, "plan9-1.db");
        assert_eq!(prune_old_artifacts(&d, 9, 7), 0, "份数未超不应删");
        assert_eq!(ls(&d).len(), 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn missing_dir_is_not_an_error() {
        let d = std::env::temp_dir().join(format!("panel-prune4-nope-{}", std::process::id()));
        assert_eq!(prune_old_artifacts(&d, 1, 3), 0, "目录不存在应静默返回 0");
    }
}
