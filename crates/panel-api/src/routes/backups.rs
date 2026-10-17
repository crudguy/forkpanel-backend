//! 备份计划与产物（本地 + 可选远端副本）。
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
//!
//! **远端副本**（`remote_*` 列，schema v7，见 `crate::remote_store`）：本地备份挡不住
//! "整机没了"——磁盘故障、误删、机房事故会把备份一起带走。三条纪律：
//! 1. 凭据加密存储（主密钥 AES-256-GCM），且**绝不下发**——列表只回 `remote_has_secret`；
//! 2. 远端失败**不把本地备份翻转为失败**（本地那份是真的），但也**不谎报 ok**：
//!    `last_result=partial` + 一条 warn 通知，让"异地那份没成"一眼可见；
//! 3. 远端不做独立裁剪：本地按 `keep_count` 裁掉哪份，就同步 DELETE 远端同名对象
//!    （远端清单 == 本地清单，因此不需要 LIST 能力，也不会悄悄堆垃圾）。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    Json,
};
use crate::remote_store::{RemoteKind, RemoteTarget};
use panel_core::{cap_keys, PanelError, Result, SafePath};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// 当前只实装这两类；`db` 见 `/api/v1/db/{conn}/backup`（另一条线）。
const KINDS: &[&str] = &["panel", "site"];

#[derive(Debug, Clone, Serialize)]
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
    /// 产物是否静态加密（AES-256-GCM，主密钥来自 /etc/panel/master.key）
    pub encrypt: bool,
    /// 远端类型：`None` = 仅本地；`webdav` / `s3`
    pub remote_kind: Option<String>,
    pub remote_url: Option<String>,
    pub remote_bucket: Option<String>,
    pub remote_prefix: Option<String>,
    pub remote_region: Option<String>,
    pub remote_user: Option<String>,
    /// 是否已存凭据。**只回这一个布尔**——凭据是打开备份仓库的钥匙，
    /// 没有任何正当理由把它下发到浏览器（哪怕只是"回显"）。
    pub remote_has_secret: bool,
}

const COLS: &str = "id, kind, target, cron_expr, keep_count, dest_dir, enabled, last_run_at, \
                    last_result, encrypt, remote_kind, remote_url, remote_bucket, remote_prefix, \
                    remote_region, remote_user, remote_secret_enc";

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
        encrypt: r.get::<_, i64>(9)? != 0,
        remote_kind: r.get(10)?,
        remote_url: r.get(11)?,
        remote_bucket: r.get(12)?,
        remote_prefix: r.get(13)?,
        remote_region: r.get(14)?,
        remote_user: r.get(15)?,
        remote_has_secret: r.get::<_, Option<Vec<u8>>>(16)?.is_some(),
    })
}

/// 含**加密凭据**的完整行。只有执行路径与连接自检需要它——
/// `PlanDto` 是下发给浏览器的形状，绝不携带密文。
struct PlanFull {
    dto: PlanDto,
    secret_enc: Option<Vec<u8>>,
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
    Ok(fetch_plan_full(state, id).await?.map(|p| p.dto))
}

async fn fetch_plan_full(state: &Shared, id: i64) -> Result<Option<PlanFull>> {
    state
        .pool
        .with(move |conn| {
            let sql = format!("SELECT {COLS} FROM backup_jobs WHERE id = ?1");
            let mut st = conn.prepare(&sql).map_err(db_err)?;
            let mut it = st
                .query_map([id], |r| Ok(PlanFull { dto: row_dto(r)?, secret_enc: r.get(16)? }))
                .map_err(db_err)?;
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

// ─────────────── 远端配置：请求片段 → 落库形态 ───────────────

/// 远端配置的请求片段（create / patch / 连接自检共用）。
///
/// **字段级三态语义**——这是本模块最容易搞错的地方（前端不回显密文）：
/// - `remote_kind`：`None` = 保持现状；`""`/`"none"`/`"off"` = 关闭远端；`webdav`/`s3` = 启用；
/// - 非密字段（url/bucket/prefix/region/user）：`None` = 保持现状；空串 = 清空该项；
/// - `remote_secret`：`None` 或空串 = **保留已存凭据**（不能解释成"清空"，否则每次
///   改 cron 都会顺手把凭据抹掉，而用户根本无从发现）；非空 = 加密后替换。
#[derive(Debug, Default, Deserialize)]
pub struct RemoteReq {
    #[serde(default)] pub remote_kind: Option<String>,
    #[serde(default)] pub remote_url: Option<String>,
    #[serde(default)] pub remote_bucket: Option<String>,
    #[serde(default)] pub remote_prefix: Option<String>,
    #[serde(default)] pub remote_region: Option<String>,
    #[serde(default)] pub remote_user: Option<String>,
    #[serde(default)] pub remote_secret: Option<String>,
}

/// 远端配置的落库形态：6 个非密列 + 1 个密文列。
#[derive(Debug, Clone)]
struct RemoteColumns {
    kind: Option<String>,
    url: Option<String>,
    bucket: Option<String>,
    prefix: Option<String>,
    region: Option<String>,
    user: Option<String>,
    secret_enc: Option<Vec<u8>>,
}

impl RemoteColumns {
    /// 关闭远端：连同凭据一起清空。留着密文没有任何用处，只扩大密钥的暴露面。
    fn cleared() -> Self {
        Self { kind: None, url: None, bucket: None, prefix: None, region: None,
               user: None, secret_enc: None }
    }
}

/// 合并请求片段与现值，并在**落库前**做完整校验。
fn merge_remote(
    state: &Shared,
    req: &RemoteReq,
    cur: Option<&PlanDto>,
    cur_secret: Option<&Vec<u8>>,
) -> ApiResult<RemoteColumns> {
    // ① kind
    let kind: Option<String> = match req.remote_kind.as_deref().map(str::trim) {
        None => cur.and_then(|p| p.remote_kind.clone()),
        Some("") | Some("none") | Some("off") => None,
        Some(k) => {
            if RemoteKind::parse(k).is_none() {
                return Err(ApiError::bad_request(
                    "remote_kind", "remote_kind 必须是 webdav / s3 / none"));
            }
            Some(k.to_string())
        }
    };
    let Some(kind) = kind else { return Ok(RemoteColumns::cleared()) };

    // ② 非密字段：给了就替换（空串 = 清空该项），没给就沿用现值
    fn pick(new: &Option<String>, old: Option<&String>) -> Option<String> {
        match new {
            Some(s) => {
                let t = s.trim();
                if t.is_empty() { None } else { Some(t.to_string()) }
            }
            None => old.cloned(),
        }
    }
    let url = pick(&req.remote_url, cur.and_then(|p| p.remote_url.as_ref()));
    let bucket = pick(&req.remote_bucket, cur.and_then(|p| p.remote_bucket.as_ref()));
    let prefix = pick(&req.remote_prefix, cur.and_then(|p| p.remote_prefix.as_ref()));
    let region = pick(&req.remote_region, cur.and_then(|p| p.remote_region.as_ref()));
    let user = pick(&req.remote_user, cur.and_then(|p| p.remote_user.as_ref()));

    // ③ 凭据
    let typed = req.remote_secret.as_deref().map(str::trim).unwrap_or("");
    let secret_enc = if typed.is_empty() {
        cur_secret.cloned()
    } else {
        let key = state.require_secret_key()?;
        Some(key.encrypt(typed.as_bytes()).map_err(ApiError::from)?)
    };

    // ④ 配对与完整性。用户名与凭据必须同进同退：`--user "ak:"` 这类半截配置在远端
    //    一定认证失败，与其等第一次执行才炸，不如保存时就说清楚。
    if user.is_some() && secret_enc.is_none() {
        return Err(ApiError::bad_request(
            "remote_secret",
            "填了远端用户名就必须提供凭据（改为匿名访问请清空用户名）",
        ));
    }
    if user.is_none() && secret_enc.is_some() {
        return Err(ApiError::bad_request("remote_user", "提供了凭据但缺少用户名"));
    }
    let Some(url_v) = url.clone().filter(|u| !u.is_empty()) else {
        return Err(ApiError::bad_request("remote_url", "启用远端存储必须填写地址"));
    };

    // ⑤ 自检**拼好的对象 URL**（与执行路径同一份逻辑）：
    //    避免"保存得进去、跑起来才失败"这种最难排查的不一致。
    RemoteTarget {
        kind: RemoteKind::parse(&kind).expect("上面已校验"),
        url: url_v,
        bucket: bucket.clone(),
        prefix: prefix.clone(),
        region: region.clone(),
        user: user.clone(),
        // 这里只为过 URL / bucket 校验，凭据内容不参与
        secret: user.as_ref().map(|_| String::new()),
    }
    .validate()
    .map_err(ApiError::from)?;

    Ok(RemoteColumns { kind: Some(kind), url, bucket, prefix, region, user, secret_enc })
}

/// 解密已存凭据。仅执行路径与连接自检使用。
fn decrypt_secret(state: &Shared, blob: Option<&Vec<u8>>) -> ApiResult<Option<String>> {
    let Some(blob) = blob else { return Ok(None) };
    let key = state.require_secret_key()?;
    let bytes = key.decrypt(blob).map_err(ApiError::from)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ApiError::from(PanelError::Internal("远端凭据不是合法 UTF-8".into())))
}

/// 由计划行组装可直接使用的 [`RemoteTarget`]（含解密后的凭据）。
///
/// 未配置远端 → `None`；配置了但主密钥不可用 → **当场报错**：
/// 让"配置看着好好的、每次执行都静默不上传"成为不可能。
fn remote_target_from(
    state: &Shared,
    plan: &PlanDto,
    secret_enc: Option<&Vec<u8>>,
) -> ApiResult<Option<RemoteTarget>> {
    let Some(kind_s) = plan.remote_kind.as_deref().map(str::trim).filter(|k| !k.is_empty()) else {
        return Ok(None);
    };
    let kind = RemoteKind::parse(kind_s)
        .ok_or_else(|| ApiError::bad_request("remote_kind", format!("未知的远端类型：{kind_s}")))?;
    let target = RemoteTarget {
        kind,
        url: plan.remote_url.clone().unwrap_or_default(),
        bucket: plan.remote_bucket.clone(),
        prefix: plan.remote_prefix.clone(),
        region: plan.remote_region.clone(),
        user: plan.remote_user.clone(),
        secret: decrypt_secret(state, secret_enc)?,
    };
    target.validate().map_err(ApiError::from)?;
    Ok(Some(target))
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
    /// 产物是否静态加密；默认 false——加密会抬高恢复门槛，取舍必须由用户显式决定
    #[serde(default)]
    pub encrypt: Option<bool>,
    /// 远端副本（可选）。缺省 = 仅本地。语义见 [`RemoteReq`]。
    #[serde(default)]
    pub remote: RemoteReq,
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
    let encrypt = req.encrypt.unwrap_or(false) as i32;
    // 开启加密前先确认主密钥可用：否则计划创建成功、**执行时**才失败，
    // 用户会以为"已经在备份了"，实际每天在报错——这是最坏的失败方式。
    if encrypt != 0 {
        let _ = state.require_secret_key()?;
    }
    // 远端配置同样在**创建时**就完整校验：地址、协议、bucket、凭据配对，
    // 任何一处不对都当场 400，而不是等第一次执行时才在后台报错。
    let remote = merge_remote(&state, &req.remote, None, None)?;
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO backup_jobs(kind, target, cron_expr, keep_count, dest_dir, enabled, encrypt,
                                         remote_kind, remote_url, remote_bucket, remote_prefix,
                                         remote_region, remote_user, remote_secret_enc)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                rusqlite::params![kind, target, cron, keep, dest, enabled, encrypt,
                                  remote.kind, remote.url, remote.bucket, remote.prefix,
                                  remote.region, remote.user, remote.secret_enc],
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
    #[serde(default)]
    pub encrypt: Option<bool>,
    /// 远端副本。字段级语义见 [`RemoteReq`]：`remote_kind` 缺省 = 不改动，
    /// `"none"` = 关闭；`remote_secret` 留空 = 保留已存凭据。
    #[serde(default)]
    pub remote: RemoteReq,
}

pub async fn patch(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<PatchReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    let full = fetch_plan_full(&state, id).await?
        .ok_or_else(|| ApiError::not_found("backup plan"))?;
    let cur = full.dto.clone();

    // 校验 dest_dir（若变更）：仍必须落在 backup_dir 之内
    let dest = match &req.dest_dir {
        Some(d) => { let _ = resolve_dest(&state, d)?; d.trim().to_string() }
        None => cur.dest_dir.clone(),
    };
    let keep = req.keep_count.unwrap_or(cur.keep_count).clamp(1, 365);
    let enabled = req.enabled.unwrap_or(cur.enabled) as i32;
    let cron = req.cron_expr.clone().or(cur.cron_expr.clone());
    let encrypt = req.encrypt.unwrap_or(cur.encrypt) as i32;
    // 与 create 同理：主密钥不可用时**立刻**拒绝，而不是等到下次执行才失败
    if encrypt != 0 {
        let _ = state.require_secret_key()?;
    }

    // 远端：与现值合并后再落库（凭据三态语义见 `merge_remote`），同样**保存前**校验
    let remote = merge_remote(&state, &req.remote, Some(&cur), full.secret_enc.as_ref())?;

    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE backup_jobs SET cron_expr = ?1, keep_count = ?2, dest_dir = ?3, enabled = ?4, encrypt = ?5,
                     remote_kind = ?7, remote_url = ?8, remote_bucket = ?9, remote_prefix = ?10,
                     remote_region = ?11, remote_user = ?12, remote_secret_enc = ?13
                 WHERE id = ?6",
                rusqlite::params![cron, keep, dest, enabled, encrypt, id,
                                  remote.kind, remote.url, remote.bucket, remote.prefix,
                                  remote.region, remote.user, remote.secret_enc],
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
    /// 是否对产物做静态加密
    encrypt: bool,
    /// 远端副本目标（`None` = 仅本地）。凭据已解密——本结构是执行期形态。
    remote: Option<RemoteTarget>,
    /// 主密钥。`encrypt=false` 时为 `None` —— **不为不加密的计划持有密钥**，
    /// 减少密钥在内存里的驻留面。
    master: Option<panel_core::crypto::MasterKey>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for BackupJob {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        match self.execute(progress).await {
            Ok(o) => Ok(o),
            Err(e) => {
                eprintln!("[panel] 备份计划 #{} 失败: {e}", self.id);
                // 失败必须落库。否则 `last_result` 会**停在上一轮成功的 'ok'**——
                // 界面显示"最近一次成功"、实际已连续失败多天，又是一个静默失败。
                let id = self.id;
                let _ = self
                    .writer
                    .exec(move |conn| {
                        conn.execute(
                            "UPDATE backup_jobs SET last_run_at = ?1, last_result = 'fail' WHERE id = ?2",
                            rusqlite::params![crate::now_unix(), id],
                        )
                        .map(|_| panel_db::WriteAck { rows_changed: 1 })
                        .map_err(|e| PanelError::Database(e.to_string()))
                    })
                    .await;
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
                // 独立连接备份：写者把 op 包在事务里，事务内不能 VACUUM INTO。
                //
                // ⚠ backup_file 是**同步**阻塞调用（开连接 + VACUUM INTO 整个库），
                // 必须放 blocking 池：若在 async fn 里直接调用，大库备份会占住一个
                // tokio worker，期间该 worker 无法服务其他请求。同函数的 tar_gz
                // （异步子进程）与 encrypt_file（spawn_blocking）都已正确处理，
                // 此处是漏改。
                let db = self.db_path.clone();
                let out = dest.clone();
                tokio::task::spawn_blocking(move || panel_db::backup_file(&db, &out))
                    .await
                    .map_err(|e| PanelError::Internal(format!("备份线程异常: {e}")))??;
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

        // 静态加密：加密成功后才删除明文产物——**不留双份**，
        // 否则「我加密了」只是错觉，明文仍躺在盘上。
        let out_path = if self.encrypt {
            let key = self.master.as_ref().ok_or_else(|| {
                PanelError::Internal("encrypt=true 但主密钥缺失（该任务本不该被提交）".into())
            })?;
            // plan1-123.db → plan1-123.db.enc；plan1-123.tar.gz → plan1-123.tar.gz.enc
            let ext = out_path
                .extension()
                .map(|e| format!("{}.enc", e.to_string_lossy()))
                .unwrap_or_else(|| "enc".to_string());
            let enc = out_path.with_extension(ext);
            progress.set(80, "加密产物").await;
            panel_os::backup::encrypt_file(&out_path, &enc, key).await?;
            std::fs::remove_file(&out_path).map_err(|e| {
                PanelError::Io(format!(
                    "加密已完成，但删除明文失败（明文仍在 {}）：{e}",
                    out_path.display()
                ))
            })?;
            enc
        } else {
            out_path
        };

        // 远端副本。**本地已成功，远端失败不把任务翻转为失败**——本地那份是真的；
        // 但也**不谎报 ok**：`partial` + warn 通知，否则"异地没有备份"会一直没人发现。
        let mut remote_err: Option<String> = None;
        if let Some(rt) = &self.remote {
            progress.set(92, "上传远端").await;
            let name = out_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if let Err(e) = rt.upload(&out_path, &name).await {
                remote_err = Some(e.to_string());
            }
        }

        progress.set(95, "记录结果").await;
        let result: &'static str = if remote_err.is_some() { "partial" } else { "ok" };
        let id = self.id;
        self.writer
            .exec(move |conn| {
                conn.execute(
                    "UPDATE backup_jobs SET last_run_at = ?1, last_result = ?2 WHERE id = ?3",
                    rusqlite::params![crate::now_unix(), result, id],
                )
                .map(|_| panel_db::WriteAck { rows_changed: 1 })
                .map_err(|e| PanelError::Database(e.to_string()))
            })
            .await?;

        if let Some(detail) = &remote_err {
            crate::routes::notifications::push(
                &self.writer,
                crate::routes::notifications::NewNotification {
                    level: "warn",
                    source: "backup",
                    title: format!("备份计划 #{} 本地成功，但远端上传失败", self.id),
                    body: Some(format!(
                        "本地产物已生成，**异地副本缺失**，请检查远端配置。\n\n{detail}"
                    )),
                    // 按天去重：同一个坏配置不该每次调度都刷一条
                    dedup_key: Some(format!(
                        "backup:{}:remote:{}",
                        self.id,
                        crate::now_unix() / 86_400
                    )),
                },
            )
            .await;
        }

        // 成功后按 keep_count 裁剪最旧产物（保留含本次在内的最新 keep 份）。
        // 不清理会让备份产物无限累加，最终撑爆低配盘——备份反而成了故障源。
        let pruned = prune_old_artifacts(&self.dest, self.id, self.keep_count);
        if !pruned.is_empty() {
            eprintln!("[panel] 备份计划 #{} 按 keep_count={} 清理了 {} 份旧产物",
                self.id, self.keep_count, pruned.len());
        }
        // 本地裁掉哪份，远端就同步删同名对象 —— 于是"远端清单 == 本地清单"，
        // 既不需要 LIST 能力，也不会出现"远端悄悄堆了几百个旧备份"。
        if let Some(rt) = &self.remote {
            let mut fails = 0usize;
            for n in &pruned {
                if let Err(e) = rt.delete(n).await {
                    eprintln!("[panel] 远端旧产物清理失败 {n}: {e}");
                    fails += 1;
                }
            }
            if fails > 0 {
                crate::routes::notifications::push(
                    &self.writer,
                    crate::routes::notifications::NewNotification {
                        level: "warn",
                        source: "backup",
                        title: format!("备份计划 #{} 远端旧产物清理失败", self.id),
                        body: Some(format!(
                            "{fails} 个已被本地裁剪的旧备份没能从远端删除，远端会比本地多留这些对象。"
                        )),
                        dedup_key: Some(format!(
                            "backup:{}:remote-prune:{}",
                            self.id,
                            crate::now_unix() / 86_400
                        )),
                    },
                )
                .await;
            }
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
    let full = fetch_plan_full(&state, id).await?
        .ok_or_else(|| ApiError::not_found("backup plan"))?;
    let plan = full.dto.clone();
    let dest = resolve_dest(&state, &plan.dest_dir)?.as_path().to_path_buf();
    let root = match plan.kind.as_str() {
        "site" => Some(PathBuf::from(
            site_root_by_name(&state, &plan.target).await?
                .ok_or_else(|| ApiError::bad_request("target", "site not found"))?,
        )),
        _ => None,
    };

    // 加密计划的密钥在**提交任务前**取：取不到就当场 501，
    // 不让任务进队列后在后台反复失败（用户会以为备份在跑）
    let master = if plan.encrypt { Some(state.require_secret_key()?) } else { None };
    // 远端目标也在**提交任务前**组装：凭据解不开就当场报错，
    // 而不是让任务进队列后在后台反复失败（用户会以为备份在跑）。
    let remote = remote_target_from(&state, &plan, full.secret_enc.as_ref())?;
    let job = BackupJob {
        id,
        kind: plan.kind.clone(),
        root,
        dest,
        keep_count: plan.keep_count,
        db_path: state.os.paths().sqlite_path(),
        writer: state.db.clone(),
        encrypt: plan.encrypt,
        master,
        remote,
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

    // 加密产物恢复前需要主密钥。**在这里就取**——取不到则当场 501，
    // 不让一个注定失败的任务进队列（用户会以为恢复正在跑）。
    let master = if panel_os::backup::is_encrypted_file(archive.as_path()) {
        Some(state.require_secret_key()?)
    } else {
        None
    };
    let job = RestoreJob {
        id,
        root,
        archive: archive.as_path().to_path_buf(),
        safety_dir: dest.as_path().to_path_buf(),
        writer: state.db.clone(),
        master,
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
    /// 归档产物绝对路径（可能是一个加密容器）
    archive: PathBuf,
    /// 安全快照落点（= 产物目录）
    safety_dir: PathBuf,
    /// 写者：失败时落站内通知
    writer: std::sync::Arc<panel_db::WriterActor>,
    /// 产物为加密容器时的主密钥；明文产物为 `None`
    master: Option<panel_core::crypto::MasterKey>,
}

/// 临时解密文件的清理守卫。
///
/// 用 `Drop` 而不是在函数尾部手动删：`execute` 里有多个 `?` 提前返回，
/// 靠人工逐个补清理迟早会漏一条路径，把**解密后的明文**留在 /tmp。
struct TempGuard(Option<PathBuf>);

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
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
        // ⓪ 加密产物：先解密到临时文件。**绝不原地解密**——
        //    中途失败会把唯一的那份备份毁掉；解密失败也不该动原产物分毫。
        let decrypted: Option<PathBuf> = if let Some(key) = &self.master {
            progress.set(5, "解密产物").await;
            let tmp = std::env::temp_dir()
                .join(format!("panel-restore-{}-{}.tar.gz", self.id, crate::now_unix()));
            panel_os::backup::decrypt_file(&self.archive, &tmp, key).await?;
            Some(tmp)
        } else {
            None
        };
        // 守卫负责在任意返回路径上删除临时明文
        let _guard = TempGuard(decrypted.clone());
        let archive: &std::path::Path = decrypted.as_deref().unwrap_or(self.archive.as_path());

        // ① 解压前校验归档条目：拒绝 `../` 逃逸与绝对路径
        progress.set(10, "校验归档").await;
        let entries = panel_os::backup::list_tar_entries(archive).await?;
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
        panel_os::backup::untar_gz(archive, &parent).await?;

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
/// **返回被删除的产物名**（不只是数量）——远端要按名字同步 DELETE 同名对象。
/// 单点删除失败只记日志、不向上抛错：产物清理失败不该把一次「备份已成功」翻转为失败。
fn prune_old_artifacts(dest: &std::path::Path, plan_id: i64, keep: i64) -> Vec<String> {
    let keep = keep.max(1) as usize;
    let prefix = format!("plan{plan_id}-");
    let mut names: Vec<String> = match std::fs::read_dir(dest) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(&prefix))
            .collect(),
        Err(_) => return Vec::new(),
    };
    if names.len() <= keep {
        return Vec::new();
    }
    names.sort(); // 升序 → 前面是最旧的
    let drop_n = names.len() - keep;
    let mut removed = Vec::new();
    for n in names.into_iter().take(drop_n) {
        match std::fs::remove_file(dest.join(&n)) {
            Ok(()) => removed.push(n),
            Err(e) => eprintln!("[panel] 清理旧备份产物失败 {}: {e}", dest.join(&n).display()),
        }
    }
    removed
}

/// 远端连接自检请求。
#[derive(Debug, Deserialize)]
pub struct TestRemoteReq {
    /// 复用某个已存计划的凭据（前端不回显密文，否则只能逼用户重输一遍）。
    #[serde(default)]
    pub plan_id: Option<i64>,
    #[serde(default)]
    pub remote: RemoteReq,
}

/// 远端连接自检：**用备份真正要用的操作**（PUT 探针对象 → DELETE）验证配置与凭据。
///
/// 为什么值得单独一个端点：远端配置写错是最典型的静默失败——本地备份照常成功、
/// 远端一直 401，用户要等到真出事才发现异地根本没有副本。让配置**当场可验证**。
pub async fn test_remote(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<TestRemoteReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    let (cur, cur_secret) = match req.plan_id {
        Some(id) => {
            let full = fetch_plan_full(&state, id)
                .await?
                .ok_or_else(|| ApiError::not_found("backup plan"))?;
            (Some(full.dto), full.secret_enc)
        }
        None => (None, None),
    };
    // 复用与落库**同一份**装配/校验：测试通过但保存失败（或反之）是最恼人的不一致
    let cols = merge_remote(&state, &req.remote, cur.as_ref(), cur_secret.as_ref())?;
    let Some(kind_s) = cols.kind.clone() else {
        return Err(ApiError::bad_request("remote_kind", "请先选择远端类型（webdav / s3）"));
    };
    let provided = req
        .remote
        .remote_secret
        .as_deref()
        .map(str::trim)
        .filter(|x| !x.is_empty());
    let secret = match provided {
        Some(p) => Some(p.to_string()),
        None => decrypt_secret(&state, cols.secret_enc.as_ref())?,
    };
    let target = RemoteTarget {
        kind: RemoteKind::parse(&kind_s).expect("merge_remote 已校验 kind"),
        url: cols.url.clone().unwrap_or_default(),
        bucket: cols.bucket.clone(),
        prefix: cols.prefix.clone(),
        region: cols.region.clone(),
        user: cols.user.clone(),
        secret,
    };
    let probe_url = target.probe().await.map_err(ApiError::from)?;
    audit(&state, &s, "backup.test_remote", &probe_url, "ok").await;
    Ok(ok(serde_json::json!({ "ok": true, "probe_url": probe_url })))
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
        assert_eq!(removed.len(), 3, "5 份保留 2 → 应删 3");
        assert_eq!(
            removed,
            vec!["plan7-1000000001.db".to_string(),
                 "plan7-1000000002.db".to_string(),
                 "plan7-1000000003.db".to_string()],
            "返回的必须是**被删掉的那些名字**——远端要按名字同步删同名对象，\
             只回数量没法删"
        );
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
        assert_eq!(removed, vec!["plan7-1.db".to_string(), "plan7-2.db".to_string()],
                   "只应删 plan7- 的旧产物，且不得波及 plans/其它计划/无关文件");
        assert_eq!(ls(&d), vec!["plan7-3.db".to_string(), "plan8-1.db".to_string(), "unrelated.txt".to_string()]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn noop_when_under_budget() {
        let d = std::env::temp_dir().join(format!("panel-prune3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mk(&d, "plan9-1.db");
        assert!(prune_old_artifacts(&d, 9, 7).is_empty(), "份数未超不应删");
        assert_eq!(ls(&d).len(), 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn missing_dir_is_not_an_error() {
        let d = std::env::temp_dir().join(format!("panel-prune4-nope-{}", std::process::id()));
        assert!(prune_old_artifacts(&d, 1, 3).is_empty(), "目录不存在应静默返回空");
    }
}


#[cfg(test)]
mod exec_tests {
    use super::*;
    use panel_task::{Progress, ProgressBus, TaskBody};

    /// `panel` 备份必须真的产出一个能被独立打开、schema 齐全的库文件。
    ///
    /// 这条钉住 `BackupJob` 的整条执行路径——包括 `panel_db::backup_file` 由
    /// 「直接占住 async worker」改为 `spawn_blocking` 后的卸载是否正确：
    /// 「不阻塞」测不出「跑不出文件」，必须落到产物本身。
    #[tokio::test]
    async fn panel_backup_produces_a_readable_db() {
        let base = std::env::temp_dir().join(format!("panel-bkexec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src_db = base.join("src/panel.db");
        let dest = base.join("out");
        std::fs::create_dir_all(src_db.parent().unwrap()).unwrap();

        // 源库先跑迁移：备份的意义就在于"把 schema 和数据一起带走"
        {
            let mut c = rusqlite::Connection::open(&src_db).unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
        }
        let writer = std::sync::Arc::new(
            panel_db::WriterActor::spawn(src_db.clone(), panel_core::Tier::Nano).unwrap(),
        );

        let job = BackupJob {
            id: 1,
            kind: "panel".into(),
            root: None,
            dest: dest.clone(),
            keep_count: 3,
            db_path: src_db.clone(),
            writer,
            encrypt: false,
            remote: None,
            master: None,
        };
        let bus = std::sync::Arc::new(ProgressBus::new());
        job.run(Progress::new(1, bus)).await.expect("备份任务应成功");

        // 产物：目录里那个 .db，且能被独立连接打开、schema 齐全
        let produced = std::fs::read_dir(&dest)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().map(|x| x == "db").unwrap_or(false))
            .expect("应产出 .db 备份产物");
        let c = rusqlite::Connection::open(&produced).unwrap();
        let objs: i64 = c
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .unwrap();
        assert!(objs > 0, "备份库应含 schema 对象（迁移后的表/索引）");
        let users: i64 = c.query_row("SELECT count(*) FROM users", [], |r| r.get(0)).unwrap();
        assert_eq!(users, 0, "备份库内容应与源库一致（刚迁移完 users 为空）");

        std::fs::remove_dir_all(&base).unwrap();
    }
}
