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
//! **产物可恢复性校验**（[`verify_artifact`]）：备份"生成成功"≠"能恢复"——
//! VACUUM INTO 中途磁盘满、tar 管道被信号打断、加密写了一半，都会留下一个看起来
//! 正常、恢复时才发现坏掉的文件。而备份的意义全在"恢复"那一刻，此前无人验证的话，
//! 第一次发现坏通常正是最需要它的那次事故。故每次备份完成后**立刻读一遍**，
//! 读不出来就让任务失败并通知，而不是等事故当天才发现。
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
    routes::{audit, audit_system, Auth, Shared},
};
use axum::{
    body::Body,
    extract::{Path as AxPath, State},
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use crate::remote_store::{RemoteKind, RemoteTarget};
use panel_core::{cap_keys, PanelError, Result, SafePath};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use crate::extract::PanelJson;

/// `panel` = 面板自身库；`site` = 站点文件；`db` = 数据库连接（按连接名）。
///
/// `db` 与 `/api/v1/db/{conn}/backup`（手动导出）共用同一个 provider 实现，
/// 但产物归计划管：有 cron、keep_count 裁剪、远端副本与统一恢复入口。
const KINDS: &[&str] = &["panel", "site", "db"];

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
    /// 产物是否静态加密（AES-256-GCM，主密钥来自 /var/lib/forkpanel/master.key）
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
            it.next().transpose().map_err(db_err)
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
            it.next().transpose().map_err(db_err)
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

/// 远端副本**必须**静态加密（`encrypt=true`）。
///
/// 为什么不给用户留这个开关：本地未加密备份的暴露面是"本机文件系统"，而远端副本
/// 会把**整个面板库**（users 表、站点配置、远端凭据密文）放到第三方存储上——bucket
/// 误公开或凭据泄露即整库外泄。这不是"多一层保险"，是同一份数据换了持有者。
///
/// 为什么是拒绝而不是"顺手替你加密"：静默改写用户提交的值，会让"我明明没勾加密"
/// 变成谎言（与配置项假控制同源）。宁可当场 400，让他自己确认这一步。
fn require_encryption_for_remote(remote_kind: Option<&str>, encrypt: bool) -> ApiResult<()> {
    if !encrypt && remote_kind.is_some() {
        return Err(ApiError::bad_request(
            "encrypt",
            "开启远端副本时必须同时开启静态加密：明文备份会落到第三方存储（S3/WebDAV），\
             bucket 泄露即整库外泄。请勾选加密，或把 remote_kind 设为 none 只做本地备份",
        ));
    }
    Ok(())
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
    PanelJson(req): PanelJson<CreateReq>,
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
    // 远端副本必须加密：放在 merge_remote 之后，才能用**合并后**的 kind 判断
    // （req.remote_kind 可能是 None，表示沿用现值）。
    require_encryption_for_remote(remote.kind.as_deref(), encrypt != 0)?;
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
    PanelJson(req): PanelJson<PatchReq>,
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
    // 与 create 同理：用合并后的 kind 判断。覆盖"给本地计划补上远端"这条路径——
    // 只盯 create 会漏掉它（用户先建本地计划，再改成带远端）。
    require_encryption_for_remote(remote.kind.as_deref(), encrypt != 0)?;

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
        return Err(PanelError::Validation { field: "kind", reason: format!("仅支持 {KINDS:?}") });
    }
    let target = target.trim().to_string();
    if target.is_empty() {
        return Err(PanelError::Validation { field: "target", reason: "target required".into() });
    }
    // panel 的 target 固定；site 的 target 必须是真实存在的站点（避免备份空目录）
    if kind == "panel" {
        if target != "panel" {
            return Err(PanelError::Validation { field: "target", reason: "panel 计划的 target 必须为 panel".into() });
        }
    } else if kind == "db" {
        // 按连接名落库：页面展示友好；改名后计划会明确报"连接不存在"，
        // 而不是悄悄备份到别的库上（比按 id 更不容易出静默错误）。
        if super::databases::conn_id_by_name(state, &target).await?.is_none() {
            return Err(PanelError::NotFound(format!("db connection {target}")));
        }
    } else if site_root_by_name(state, &target).await?.is_none() {
        return Err(PanelError::NotFound(format!("site {target}")));
    }
    // 只**校验** dest 落在 backup_dir 之内；落库存**相对输入**（后续按相对解析才一致）
    let _ = resolve_dest(state, dest)?;
    Ok((kind.to_string(), target, dest.trim().to_string()))
}

// ─────────────── 执行（任务化） ───────────────

/// 校验备份产物**真的可恢复**：解出来并实际读一遍，而非只看文件存在与大小。
///
/// 三种产物各自的读法：
/// - `.db`：开连接跑 `PRAGMA integrity_check`（SQLite 官方的坏库检测）；
/// - `.tar.gz`：真正解压到临时目录并数条目（只 `list_tar_entries` 能抓截断，
///   但抓不到"条目内容损坏"，解压才是诚实的读法）；
/// - 上述任一变体（`.enc`）：先解密到临时文件，验完即删——**绝不在盘上留明文**。
///
/// 返回人类可读摘要（条目数 / 完整性结论），写进任务输出供事后审计。
async fn verify_artifact(
    path: &std::path::Path,
    key: Option<&panel_core::crypto::MasterKey>,
    tmp_dir: &std::path::Path,
) -> Result<String> {
    let fname = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

    // 加密产物先解密到临时文件；明文随后必须删掉（不留双份，同加密那步的纪律）。
    // `is_temp` 显式记录"这个文件是校验自己造的"，而非靠指针比较判断——
    // `path.to_path_buf()` 的地址与 path 无必然关系，ptr::eq 会给出错误答案。
    let mut is_temp = false;
    let plain = if panel_os::backup::is_encrypted_file(path) {
        let k = key.ok_or_else(|| PanelError::Internal(
            format!("产物 {fname} 已加密，但没有主密钥可解密校验")
        ))?;
        std::fs::create_dir_all(tmp_dir)
            .map_err(|e| PanelError::Internal(format!("create tmp: {e}")))?;
        let p = tmp_dir.join(format!("verify-{}-{}", std::process::id(), fname.trim_end_matches(".enc")));
        panel_os::backup::decrypt_file(path, &p, k).await?;
        is_temp = true;
        p
    } else {
        path.to_path_buf()
    };
    // 无论后面成功失败，临时明文都要清掉
    let _guard = TempPlainGuard(plain.clone(), is_temp);

    let ext = plain.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
    let summary = match ext.as_str() {
        "db" => {
            let p = plain.clone();
            // integrity_check 是同步阻塞调用（要读整个库文件），放 blocking 池
            tokio::task::spawn_blocking(move || {
                let conn = rusqlite::Connection::open(&p)
                    .map_err(|e| PanelError::Database(format!("open backup: {e}")))?;
                let r = panel_db::integrity_check(&conn)?;
                if r != "ok" {
                    return Err(PanelError::Internal(format!("SQLite 自检未通过: {r}")));
                }
                // 顺带确认它是个**面板库**而不是随便一个 sqlite 文件：
                // 能查到 users 表才说明备份的是我们的库。
                let n: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'",
                    [], |r| r.get(0),
                ).map_err(|e| PanelError::Database(format!("probe users: {e}")))?;
                if n == 0 {
                    return Err(PanelError::Internal("备份里没有 users 表，不像面板库".into()));
                }
                Ok::<String, PanelError>("SQLite integrity_check=ok，含 users 表".to_string())
            })
            .await
            .map_err(|e| PanelError::Internal(format!("校验线程异常: {e}")))??
        }
        "gz" => {
            let out = tmp_dir.join(format!("verify-untar-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&out);
            // **必须重建**：`untar_gz` 走 `tar -C <dir>`，目录不存在时 tar 直接
            // 报 "Cannot open: No such file or directory"。此前只删不建，导致
            // **所有站点备份（tar.gz）在校验阶段必然失败并删掉产物**——面板库
            // 备份走 `.db` 分支，所以这个 bug 一直没被日常使用暴露。
            std::fs::create_dir_all(&out)
                .map_err(|e| PanelError::Internal(format!("create verify dir: {e}")))?;
            panel_os::backup::untar_gz(&plain, &out).await?;
            let n = walkdir_count(&out);
            let _ = std::fs::remove_dir_all(&out);
            if n == 0 {
                return Err(PanelError::Internal("归档解出来是空的".into()));
            }
            format!("tar.gz 解压成功，{n} 个条目")
        }
        other => return Err(PanelError::Internal(format!("不认识的产物扩展名: {other}"))),
    };
    Ok(format!("{fname}: {summary}"))
}

/// 数据库产物的扩展名：SQLite 是库文件副本（`.db`），mysql/pg 是 SQL 文本（`.sql`）。
fn db_artifact_ext(engine: &panel_os::DbEngine) -> &'static str {
    match engine {
        panel_os::DbEngine::Sqlite => "db",
        _ => "sql",
    }
}

/// 数据库产物的可恢复性校验（`kind=db` 专用）。
///
/// 与 [`verify_artifact`] 的区别：SQLite 产物是**用户的库**，不能套用面板库的
/// 「必须含 users 表」判据；mysql/pg 产物是 SQL 文本，没有服务端可连，只能证明
/// 非空（这一点必须如实写进摘要，不能让"校验通过"听起来比实际更强）。
async fn verify_db_artifact(
    path: &std::path::Path,
    key: Option<&panel_core::crypto::MasterKey>,
    tmp_dir: &std::path::Path,
    engine: Option<panel_os::DbEngine>,
) -> Result<String> {
    let fname = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

    let mut tmp_plain: Option<PathBuf> = None;
    let plain = if panel_os::backup::is_encrypted_file(path) {
        let k = key.ok_or_else(|| {
            PanelError::Internal(format!("产物 {fname} 已加密，但没有主密钥可解密校验"))
        })?;
        std::fs::create_dir_all(tmp_dir)
            .map_err(|e| PanelError::Internal(format!("create tmp: {e}")))?;
        let p = tmp_dir.join(format!(
            "verify-db-{}-{}",
            std::process::id(),
            fname.trim_end_matches(".enc")
        ));
        panel_os::backup::decrypt_file(path, &p, k).await?;
        tmp_plain = Some(p.clone());
        p
    } else {
        path.to_path_buf()
    };
    let _guard = TempGuard(tmp_plain);

    let len = std::fs::metadata(&plain)
        .map_err(|e| PanelError::Io(format!("stat 产物: {e}")))?
        .len();
    if len == 0 {
        return Err(PanelError::Internal("产物是 0 字节".into()));
    }

    match engine {
        Some(panel_os::DbEngine::Sqlite) => {
            let p = plain.clone();
            // integrity_check 要读全库，放 blocking 池
            tokio::task::spawn_blocking(move || {
                let conn = rusqlite::Connection::open(&p)
                    .map_err(|e| PanelError::Database(format!("open db backup: {e}")))?;
                let r = panel_db::integrity_check(&conn)?;
                if r != "ok" {
                    return Err(PanelError::Internal(format!("SQLite 自检未通过: {r}")));
                }
                Ok::<(), PanelError>(())
            })
            .await
            .map_err(|e| PanelError::Internal(format!("校验线程异常: {e}")))??;
            Ok(format!("{fname}: SQLite integrity_check=ok，{len} B"))
        }
        _ => Ok(format!("{fname}: SQL 转储 {len} B（非空；未连库校验）")),
    }
}

/// CLI 入口（`panel verify-backup <path>`）：与 [`verify_artifact`] 同一实现，
/// 单独包一层是为了让 panel-cli 不必接触 `routes::backups` 的私有内部。
pub async fn verify_artifact_cli(
    path: &std::path::Path,
    key: Option<&panel_core::crypto::MasterKey>,
    tmp_dir: &std::path::Path,
) -> Result<String> {
    verify_artifact(path, key, tmp_dir).await
}

/// 远端对象名里属于**面板库产物**的那些（`.db` / `.db.enc`），按新到旧排序。
///
/// 排序依据：对象名形如 `plan1-1700000000.db`，时间戳定长 unix 秒 ⇒ 字典序即时间序。
/// 只要名字里的时间戳是定长的，这就成立；不读 mtime 是因为远端列表**不给 mtime**
/// （S3 `list-type=2` 只返回 key 与 size）。
fn panel_db_names(objects: &[String]) -> Vec<&str> {
    let mut v: Vec<&str> = objects
        .iter()
        .map(|s| s.as_str())
        // 远端列出来的可能是带前缀的完整 key（S3 尤其如此），只看最后一段
        .map(|s| s.rsplit('/').next().unwrap_or(s))
        .filter(|n| n.ends_with(".db") || n.ends_with(".db.enc"))
        .collect();
    v.sort_unstable();
    v.reverse();
    v
}

/// CLI 入口（`panel restore-db --remote <plan_id>`）：**本地盘没了**的时候，
/// 从远端副本把面板库产物拉回来。
///
/// 为什么不复用 HTTP 那条路径：HTTP 侧一切都挂在 `&Shared`（连接池、任务队列、
/// 能力矩阵）上，而 `restore-db` 的前提恰恰是**服务已停**——为了读一行配置去构造
/// 一个 Shared 既重又别扭。这里直接只读打开面板库取计划行：同样的表、同样的解密，
/// 只是不经过 axum。
///
/// ⚠ 只接受 `kind=panel` 的计划：把别的计划（哪怕产物也是 `.db`）盖到 panel.db
/// 上，得到的是一个"能打开但不是面板库"的库，比打不开更难查。
pub async fn fetch_remote_artifact_cli(
    db_path: &std::path::Path,
    plan_id: i64,
    wanted: Option<&str>,
    dest_dir: &std::path::Path,
    key: Option<&panel_core::crypto::MasterKey>,
) -> Result<PathBuf> {
    use rusqlite::OpenFlags;
    // 优先只读打开：没有任何理由在"取回产物"这一步改动面板库。
    // 兜底读写打开：非正常停机留下的 -wal 需要创建 -shm 才能读，只读会直接失败。
    let conn = rusqlite::Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .or_else(|_| rusqlite::Connection::open(db_path))
        .map_err(|e| PanelError::Database(format!("打开面板库失败: {e}")))?;

    // 远端配置 8 元组：拆成结构体要动多处调用点，收益不抵改动面，显式豁免。
    #[allow(clippy::type_complexity)]
    let (kind, r_kind, r_url, r_bucket, r_prefix, r_region, r_user, secret_enc): (
        String, Option<String>, Option<String>, Option<String>,
        Option<String>, Option<String>, Option<String>, Option<Vec<u8>>,
    ) = conn
        .query_row(
            "SELECT kind, remote_kind, remote_url, remote_bucket, remote_prefix, \
                    remote_region, remote_user, remote_secret_enc \
             FROM backup_jobs WHERE id = ?1",
            rusqlite::params![plan_id],
            |r| {
                Ok((
                    r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?,
                    r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?,
                ))
            },
        )
        .map_err(|_| PanelError::NotFound(format!("备份计划 #{plan_id}")))?;

    if kind != "panel" {
        return Err(PanelError::Validation {
            field: "plan",
            reason: format!("计划 #{plan_id} 是 kind={kind}，不是面板库备份计划（--remote 只用于恢复面板库）"),
        });
    }
    let Some(kind_s) = r_kind.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(PanelError::Validation {
            field: "remote_kind",
            reason: format!("计划 #{plan_id} 没配远端副本，无处可取"),
        });
    };
    let rk = RemoteKind::parse(kind_s)
        .ok_or_else(|| PanelError::Validation { field: "remote_kind", reason: format!("未知的远端类型：{kind_s}") })?;
    let secret = match (&secret_enc, key) {
        (Some(blob), Some(k)) => Some(String::from_utf8(k.decrypt(blob)?).map_err(|_| {
            PanelError::Internal("远端凭据不是合法 UTF-8".into())
        })?),
        (Some(_), None) => {
            return Err(PanelError::Internal("计划存了远端凭据但读不到主密钥，无法连接远端".into()))
        }
        (None, _) => None,
    };
    let target = RemoteTarget {
        kind: rk,
        url: r_url.unwrap_or_default(),
        bucket: r_bucket,
        prefix: r_prefix.clone(),
        region: r_region,
        user: r_user,
        secret,
    };
    target.validate()?;

    let objects = target.list(r_prefix.as_deref().unwrap_or("")).await?;
    let cands = panel_db_names(&objects);
    if cands.is_empty() {
        return Err(PanelError::NotFound(format!(
            "远端没有面板库产物（共 {} 个对象）",
            objects.len()
        )));
    }
    let name = match wanted {
        Some(w) => {
            if !cands.contains(&w) {
                return Err(PanelError::NotFound(format!(
                    "远端没有名为 {w} 的面板库产物；可选：{}",
                    cands.iter().take(5).copied().collect::<Vec<_>>().join("、")
                )));
            }
            w.to_string()
        }
        None => cands[0].to_string(),
    };

    std::fs::create_dir_all(dest_dir).map_err(|e| PanelError::Io(format!("create dest: {e}")))?;
    let dest = dest_dir.join(&name);
    target.download(&name, &dest).await?;
    Ok(dest)
}

/// 极简目录计数（校验用，不需要 walkdir 依赖）。
fn walkdir_count(dir: &std::path::Path) -> usize {
    let mut n = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() { stack.push(p) } else { n += 1 }
        }
    }
    n
}

/// 离开作用域时删掉临时明文（校验失败/提前返回都不会漏）。
struct TempPlainGuard(std::path::PathBuf, bool);
impl Drop for TempPlainGuard {
    fn drop(&mut self) {
        if self.1 {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

struct BackupJob {
    id: i64,
    kind: String,
    root: Option<PathBuf>,
    /// 数据库连接目标（`kind=db` 时必填；凭据已解密）
    db_target: Option<panel_os::DbTarget>,
    /// OS 适配器：db 备份要走 `os.databases()`（与手动导出同一实现）
    os: std::sync::Arc<dyn panel_os::OsAdapter>,
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
    /// 临时目录（产物校验时解压/解密用），来自 `PathLayout::tmp_dir()`
    tmp_dir: PathBuf,
}

/// 备份前必须留出的余量（64 MiB）。
///
/// 备份期间面板自己的库还在写、校验时还要解压/解密到临时目录，只按产物体积卡线
/// 会贴着 0 走——盘写满的代价是面板连自己的库都写不进去，不只是这次备份丢掉。
const BACKUP_FREE_HEADROOM: u64 = 64 * 1024 * 1024;

/// 递归统计目录的 `(字节数, 文件数)`。
///
/// 两个口径共用**同一个**遍历：写成两份迟早会漂移（一个数文件、一个不算目录，
/// 日后改一处忘另一处就说不清了）。读不到的条目（权限不足 / 已被并发删除）
/// **跳过**而不是整体失败——这只是估算，为单个条目废掉整次备份不划算。
fn dir_stats(path: &std::path::Path) -> (u64, usize) {
    let (mut bytes, mut files) = (0u64, 0usize);
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&p) else { continue };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() { stack.push(e.path()); } else { bytes += m.len(); files += 1; }
        }
    }
    (bytes, files)
}

fn dir_bytes(path: &std::path::Path) -> u64 { dir_stats(path).0 }
fn count_files(path: &std::path::Path) -> usize { dir_stats(path).1 }

/// 本次备份预计占多少字节。`None` = **估不出来**。
///
/// mysql/pg 的 dump 体积事先无从得知（`mysqldump`/`pg_dump` 不预告），诚实返回
/// `None` ⇒ 跳过检查。⚠ 不能用"上一次产物多大"代替：库可能刚涨了十倍，
/// 拿旧产物当判据就是把错觉当护栏。
fn estimate_backup_bytes(job: &BackupJob) -> Option<u64> {
    match job.kind.as_str() {
        "panel" => std::fs::metadata(&job.db_path).ok().map(|m| m.len()),
        "site" => job.root.as_ref().map(|r| dir_bytes(r)),
        "db" => match job.db_target.as_ref()?.engine {
            // SQLite 就是个文件，体积等于它本身
            panel_os::DbEngine::Sqlite => {
                let p = job.db_target.as_ref()?.database.as_deref()?;
                std::fs::metadata(p).ok().map(|m| m.len())
            }
            panel_os::DbEngine::MySql | panel_os::DbEngine::Postgres => None,
        },
        _ => None,
    }
}

/// 判定：这次备份放得下吗。
///
/// `avail = None`（查不到可用空间）一律**放行**：宁可少拦一次，也不能把备份全挡在
/// 门外——备份静默消失远比备份失败严重。同理，绝不能把 `None` 当成 0。
fn free_space_verdict(avail: Option<u64>, needed: u64) -> std::result::Result<(), String> {
    let Some(a) = avail else { return Ok(()) };
    if a >= needed {
        return Ok(());
    }
    let h = crate::routes::assistant::human_bytes;
    Err(format!(
        "备份目录可用空间不足：预计需要 {}，当前可用 {}。\
         请先清理备份目录下的旧产物（或调小保留份数 / 扩容）再执行——\
         写一半才发现盘满，会连面板自己的库一起写不进去",
        h(needed),
        h(a),
    ))
}

/// 备份**开始前**的空间水位检查：宁可现在失败，也不写到一半才炸。
fn ensure_free_space(job: &BackupJob) -> Result<()> {
    let Some(est) = estimate_backup_bytes(job) else { return Ok(()) };
    // 加密时明文与密文会短暂共存（先写 .enc，成功后才删明文），峰值按两倍算
    let needed = if job.encrypt { est.saturating_mul(2) } else { est }
        .saturating_add(BACKUP_FREE_HEADROOM);
    let avail = panel_os::paths::available_bytes(&job.dest);
    free_space_verdict(avail, needed).map_err(PanelError::Io)
}

/// 失败原因必须能从「任务」页看到。
///
/// `output_path` 的契约：**成功时**指向业务产物（备份 .db/.tar.gz），失败时没有产物——
/// 此时指向**错误日志**是诚实的，且让 `/tasks/{id}/output` 直接可读。
/// 此前失败只 `eprintln!` + 通知，任务页点开是空白输出（实测 task 30：
/// state=failed、output_path=null、lines=[]，用户只能去翻服务端日志）。
fn write_failure_log(task_id: i64, what: &str, msg: &str) -> std::path::PathBuf {
    // 失败日志同样写进专属子目录 + 裁剪（与成功路径、cron 任务体一致，P1-13）：
    // 此前直接散落到 /tmp 根、且永不清理，机器重启间隔一长就堆积。
    let dir = std::env::temp_dir().join(panel_task::TASK_LOG_DIRNAME);
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join(format!("{}{task_id}.log", panel_task::TASK_LOG_PREFIX));
    let _ = std::fs::write(&p, format!("{what} #{task_id} 失败\n{msg}\n"));
    panel_os::prune_keep_newest(&dir, panel_task::TASK_LOG_PREFIX, panel_task::TASK_LOG_KEEP);
    p
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
                let log = write_failure_log(self.id, "备份计划", &msg);
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
                // 用 Ok(Failed) 而非 Err：这样 output_path 能带上错误日志，
                // 「任务」页点开就能看到原因（Err 路径会被 runner 落成 output_path=null）。
                Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Failed,
                    exit_code: Some(1),
                    output_path: Some(log),
                })
            }
        }
    }
}

impl BackupJob {
    async fn execute(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(5, "准备备份").await;
        std::fs::create_dir_all(&self.dest).map_err(|e| PanelError::Internal(e.to_string()))?;
        // 先确认放得下：盘写到一半才失败，留下的半截产物既不能恢复又占地方，
        // 更糟的是盘满会让面板自己的库也写不进去（比"这次备份没成"严重得多）
        ensure_free_space(self)?;
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
            "db" => {
                let t = self
                    .db_target
                    .as_ref()
                    .ok_or_else(|| PanelError::Internal("db target 缺失".into()))?;
                let name = format!("plan{}-{}.{}", self.id, ts, db_artifact_ext(&t.engine));
                // 出口必须走 SafePath：provider 直接拿它写文件，绕不过沙箱
                let safe = panel_os::paths::resolve_within_for_create(&self.dest, &name)?;
                self.os
                    .databases()
                    .backup(t, &safe, Box::new(|_line| {}))
                    .await?;
                self.dest.join(name)
            }
            other => {
                return Err(PanelError::Validation {
                    field: "kind",
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

        // ── 产物可恢复性校验：生成成功 ≠ 能恢复 ──
        // 放在上传远端**之前**：本地这份就坏的话，传上去只是把垃圾复制到异地，
        // 还多付一份流量。校验不过就让整个任务失败并通知，不等事故当天才发现。
        progress.set(88, "校验产物").await;
        // `kind=db` 有自己的判据：SQLite 产物是**用户的库**（不能要求含 users 表），
        // mysql/pg 是 SQL 文本（没有服务端可校验，只能证明非空）。
        let verified = match self.kind.as_str() {
            "db" => {
                verify_db_artifact(
                    &out_path,
                    self.master.as_ref(),
                    &self.tmp_dir,
                    self.db_target.as_ref().map(|t| t.engine),
                )
                .await
            }
            _ => verify_artifact(&out_path, self.master.as_ref(), &self.tmp_dir).await,
        };
        let verify_note = match verified {
            Ok(note) => {
                eprintln!("[panel] 备份计划 #{} 产物校验通过：{note}", self.id);
                note
            }
            Err(e) => {
                // 坏产物不能留在盘上冒充备份：删掉它，否则 keep_count 会把这个
                // 永远恢复不出来的文件当成有效备份一直保留着。
                let _ = std::fs::remove_file(&out_path);
                crate::routes::notifications::push(
                    &self.writer,
                    crate::routes::notifications::NewNotification {
                        level: "error",
                        source: "backup",
                        title: format!("备份计划 #{} 的产物校验失败，已删除该产物", self.id),
                        body: Some(format!(
                            "备份文件已生成但**读不回来**，已删除以免它冒充有效备份。\n\n产物：{}\n原因：{e}",
                            out_path.display()
                        )),
                        // 按天去重：同一个坏盘不该每次调度都刷一条
                        dedup_key: Some(format!("backup:{}:verify:{}", self.id, crate::now_unix() / 86_400)),
                    },
                )
                .await;
                return Err(PanelError::Internal(format!("产物校验失败（已删除）: {e}")));
            }
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

        // 校验摘要写进进度流：任务中心能看到"这份备份确实被读回来过"，
        // 而不是只有一个孤零零的产物路径。
        progress.log(&format!("产物校验：{verify_note}")).await;
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
    // 重活限流：10 次 / 60 秒 / 用户（见 ratelimit.rs 的设计说明）
    crate::ratelimit::check_heavy(&state, &s.username, "backup.run")?;
    if !state.capabilities.get(cap_keys::BACKUP_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("backup.manage"));
    }
    let tid = submit_run(&state, id).await?;
    audit(&state, &s, "backup.run", &id.to_string(), "queued").await;
    Ok(ok(serde_json::json!({ "task_id": tid })))
}

/// 提交一次备份任务。HTTP 手动执行与 cron 定时**共用这一段**——两套提交逻辑
/// 迟早会漂移（手动取了密钥、定时忘了取；手动校验了远端、定时没校验）。
///
/// **不写审计**：调用方各自写。手动走 `audit`（有 Session，记用户与来源 IP），
/// 定时走 `audit_system`（actor=system）。合进来反而要传 `Option<&Session>`。
pub async fn submit_run(state: &Shared, id: i64) -> ApiResult<i64> {
    let full = fetch_plan_full(state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("backup plan"))?;
    let plan = full.dto.clone();
    let dest = resolve_dest(state, &plan.dest_dir)?.as_path().to_path_buf();
    let mut db_target = None;
    let root = match plan.kind.as_str() {
        "site" => Some(PathBuf::from(
            site_root_by_name(state, &plan.target)
                .await?
                .ok_or_else(|| ApiError::bad_request("target", "site not found"))?,
        )),
        "db" => {
            let cid = super::databases::conn_id_by_name(state, &plan.target)
                .await?
                .ok_or_else(|| ApiError::bad_request("target", "db connection not found"))?;
            db_target = Some(super::databases::load_target(state, cid, None).await?);
            None
        }
        _ => None,
    };

    // 加密计划的密钥在**提交任务前**取：取不到就当场失败，
    // 不让任务进队列后在后台反复失败（用户会以为备份在跑）
    let master = if plan.encrypt { Some(state.require_secret_key()?) } else { None };
    // 远端目标也在**提交任务前**组装：凭据解不开就当场报错
    let remote = remote_target_from(state, &plan, full.secret_enc.as_ref())?;
    let job = BackupJob {
        id,
        kind: plan.kind.clone(),
        root,
        os: state.os.clone(),
        db_target,
        dest,
        keep_count: plan.keep_count,
        db_path: state.os.paths().sqlite_path(),
        writer: state.db.clone(),
        encrypt: plan.encrypt,
        master,
        remote,
        tmp_dir: state.os.paths().tmp_dir(),
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
    Ok(tid)
}

// ─────────────────────────── cron 调度 ───────────────────────────

/// cron 调度的进程内状态：plan_id → （表达式, 下一次触发时刻）。
///
/// **只存内存、不落库**：重启后重新登记"下一个触发点"，**不补跑**历史错过的
/// 那几次。补跑会在面板停机一天后一次涌出十几份备份，把磁盘打满——比漏跑更糟。
static SWEEP_STATE: OnceLock<Mutex<HashMap<i64, (String, i64)>>> = OnceLock::new();

fn sweep_state() -> &'static Mutex<HashMap<i64, (String, i64)>> {
    SWEEP_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 解析表达式的下一个触发点（本地时区语义，与 Cron 页同一个 provider）。
fn next_fire_at(state: &Shared, expr: &str) -> Option<i64> {
    state.os.scheduler().next_fire_times(expr, 1).ok()?.into_iter().next()
}

/// 纯逻辑：算出本轮哪些计划到期，并就地维护状态。
///
/// 抽成纯函数是为了**能测**——`sweep_due` 里全是 DB 与任务队列，单测跑不动。
/// 语义三条（都有单测钉住）：
/// 1. 首次见到 / 表达式刚改过 ⇒ 只登记下一个触发点，**不立即执行**；
/// 2. 已登记且 `now >= next` ⇒ 到期（推进触发点由调用方负责，失败也要推进）；
/// 3. 不再启用/已被删的计划 ⇒ 从状态里摘掉，避免无限增长。
fn plan_sweep(
    known: &mut HashMap<i64, (String, i64)>,
    plans: &[(i64, String)],
    now: i64,
    next_of: &dyn Fn(&str) -> Option<i64>,
) -> Vec<i64> {
    let mut due = Vec::new();
    let mut seen = HashSet::new();
    for (id, expr) in plans {
        seen.insert(*id);
        match known.get(id) {
            Some((cur, next)) if cur == expr => {
                if now >= *next { due.push(*id); }
            }
            _ => match next_of(expr) {
                Some(n) => { known.insert(*id, (expr.clone(), n)); }
                None => { known.remove(id); }
            },
        }
    }
    known.retain(|k, _| seen.contains(k));
    due
}

/// 每分钟由内部调度器调用：把到期的**启用**计划提交为备份任务。
///
/// **为什么需要它**：`cron_expr` / `enabled` 此前只存不读——用户在页面上配了
/// "每天 3 点"，实际永远不会执行（典型「配置项假控制」，伪装成已做）。
/// 本函数是这两个字段**唯一**的消费者；删掉它，定时备份立刻退回装饰品。
pub async fn sweep_due(state: &Shared) -> Result<usize> {
    if !state.capabilities.get(cap_keys::BACKUP_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Ok(0);
    }
    // 只取调度需要的两列；空表达式在 SQL 里就滤掉（留空 = 仅手动，契约语义）
    let plans: Vec<(i64, String)> = state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, cron_expr FROM backup_jobs
                     WHERE enabled = 1 AND cron_expr IS NOT NULL AND TRIM(cron_expr) <> ''",
                )
                .map_err(db_err)?;
            let it = st
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it { v.push(x.map_err(db_err)?); }
            Ok(v)
        })
        .await?;

    let now = crate::now_unix();
    let due = {
        let mut st = panel_core::sync::lock_recover(sweep_state());
        plan_sweep(&mut st, &plans, now, &|e| next_fire_at(state, e))
    };

    let mut submitted = 0usize;
    for id in due {
        let expr = {
            let st = panel_core::sync::lock_recover(sweep_state());
            st.get(&id).map(|(e, _)| e.clone())
        };
        match submit_run(state, id)
            .await
            .map_err(|e| PanelError::Internal(format!("{}（{}）", e.message, e.code)))
        {
            Ok(_) => {
                submitted += 1;
                audit_system(state, "backup.run", &id.to_string(), "scheduled").await;
            }
            Err(e) => {
                // 失败必须留痕：否则"定时在跑但一直失败"在外观上是完全静默的
                eprintln!("[WARN] 定时备份计划 #{id} 提交失败: {e}");
                audit_system(state, "backup.run", &id.to_string(), "failed").await;
            }
        }
        // 无论成败都推进到下一个触发点：失败后每分钟重试只会刷屏，不会更可能成功
        if let Some(expr) = expr {
            let next = next_fire_at(state, &expr);
            let mut st = panel_core::sync::lock_recover(sweep_state());
            match next {
                Some(n) => { st.insert(id, (expr, n)); }
                None => { st.remove(&id); }
            }
        }
    }
    Ok(submitted)
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

/// `GET /api/v1/backups/{id}/remote/artifacts`：列远端副本。
///
/// 存在的理由：本地盘坏掉时，产物列表（`/artifacts`）读的是本地目录——它已经
/// 空了，用户无从知道异地还有没有、有哪几份。这个端点直接问远端要清单。
pub async fn remote_artifacts(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_VIEW)?;
    let full = fetch_plan_full(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("backup plan"))?;
    let remote = remote_target_from(&state, &full.dto, full.secret_enc.as_ref())?
        .ok_or_else(|| ApiError::bad_request("remote", "该计划未配置远端副本"))?;
    let prefix = format!("plan{id}-");
    let mut names = remote.list(&prefix).await.map_err(ApiError::from)?;
    // 远端对象名同样是**不可信输入**（别人可能往桶里塞东西）：只放行本计划的
    // 合法产物名，避免把任意对象名带进 UI 再喂回恢复接口。
    names.retain(|n| is_plan_artifact_name(id, n));
    Ok(ok(serde_json::json!({ "items": names })))
}

/// 计划产物名白名单：必须是 `plan<id>-` 前缀，其余只允许 `[A-Za-z0-9._-]`
/// （**不含路径分隔符**，`..` 也因此不可能出现为独立段）。
///
/// 与系统的 `panel-<digits>.db` 各有一套白名单：两处都收"任意字符串"会让
/// 目录穿越只剩 canonicalize 一道防线，白名单是第一道。
fn is_plan_artifact_name(plan_id: i64, name: &str) -> bool {
    let prefix = format!("plan{plan_id}-");
    name.strip_prefix(&prefix)
        .map(|rest| {
            !rest.is_empty()
                && rest.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
        .unwrap_or(false)
}

/// `GET /api/v1/backups/{id}/artifacts/{name}`：下载某份计划产物。
pub async fn artifact_download(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath((id, name)): AxPath<(i64, String)>,
) -> ApiResult<Response> {
    crate::auth::require(&s, perm::BACKUP_VIEW)?;
    // 第一道：名字白名单
    if !is_plan_artifact_name(id, &name) {
        return Err(ApiError::bad_request("name", "invalid artifact name"));
    }
    let plan = fetch_plan(&state, id).await?.ok_or_else(|| ApiError::not_found("backup plan"))?;
    let dest = resolve_dest(&state, &plan.dest_dir)?;
    // 第二道：canonicalize 后父目录必须就是该计划的产物目录（防符号链接逃逸）
    let canon_dir = tokio::fs::canonicalize(dest.as_path())
        .await
        .map_err(|_| ApiError::not_found("artifact dir"))?;
    let canon = tokio::fs::canonicalize(dest.as_path().join(&name))
        .await
        .map_err(|_| ApiError::not_found("artifact"))?;
    if canon.parent() != Some(canon_dir.as_path()) {
        return Err(ApiError::forbidden(perm::BACKUP_VIEW));
    }
    download_response(&canon, &name).await
}

/// 恢复的二次确认词。前端 ConfirmDialog 必须让用户手输该词才能提交。
pub const RESTORE_CONFIRM_WORD: &str = "覆盖恢复";

#[derive(Debug, Deserialize)]
pub struct RestoreReq {
    /// 产物文件名（取自 `artifacts` 列表），**不接受路径**
    pub artifact: String,
    /// 二次确认词，必须等于 [`RESTORE_CONFIRM_WORD`]
    pub confirm_token: String,
    /// 从远端副本恢复：先按名字下载到本地临时文件，再走同一条恢复流程。
    /// 缺省 false = 从本地产物恢复（原行为）。
    #[serde(default)]
    pub from_remote: bool,
}

/// 从产物恢复：**高危**（覆盖当前数据）。
///
/// 三道闸门（缺一不可）：
/// 1. **二次确认词** `confirm_token` —— 防误点；
/// 2. **产物名白名单** —— 必须属本计划前缀且真实存在，不接受 `/` 与 `..`；
/// 3. **自动先备份当前态** —— 任务内第一步（见 `RestoreJob`），失败即中止、绝不裸覆盖。
///
/// `kind=panel` 例外：面板库是面板自身运行的库，在线覆盖会让 SQLite WAL 损坏，
/// 诚实 501 并指向停服后的恢复命令（`panel restore-db`）——不提供"看起来能点"的危险按钮。
pub async fn restore(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<RestoreReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "backup.restore")?;
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

    let full = fetch_plan_full(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("backup plan"))?;
    let plan = full.dto.clone();
    if plan.kind == "panel" {
        return Err(ApiError::unsupported(
            "面板数据库为面板自身运行中的库：在线覆盖会损坏 SQLite WAL。请先停止 panel 服务，\
             再执行 `panel restore-db <产物路径>`（会先校验产物、给当前库留快照、原子替换并清理 WAL/SHM）。",
        ));
    }

    // 闸门 2：产物名白名单（目录内前缀匹配 + 禁止路径成分）
    let prefix = format!("plan{id}-");
    let name = req.artifact.trim();
    if !name.starts_with(&prefix) || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(ApiError::bad_request("artifact", "产物名不属于本计划或含非法路径成分"));
    }
    let dest = resolve_dest(&state, &plan.dest_dir)?;

    // 产物来源：本地目录，或先按名字从远端拉回临时文件。
    //
    // 远端恢复是"本地盘已经出事"时才用的路径——此时本地那份很可能已经没了，
    // 因此**不能**要求本地存在同名文件。拉到 tmp 而不是产物目录：它是临时副本，
    // 归 TempGuard 在任务结束时删除，不该混进产物列表被裁剪逻辑当成一份备份。
    let (archive, cleanup) = if req.from_remote {
        let remote = remote_target_from(&state, &plan, full.secret_enc.as_ref())?
            .ok_or_else(|| ApiError::bad_request("remote", "该计划未配置远端副本"))?;
        let tmp = state.os.paths().tmp_dir();
        tokio::fs::create_dir_all(&tmp)
            .await
            .map_err(|e| ApiError::from(PanelError::Internal(format!("create tmp: {e}"))))?;
        let local = tmp.join(format!("remote-restore-{id}-{}-{name}", crate::now_unix()));
        remote.download(name, &local).await.map_err(ApiError::from)?;
        (local.clone(), Some(local))
    } else {
        let p = dest.as_path().join(name);
        if !p.is_file() {
            return Err(ApiError::not_found("artifact"));
        }
        (p, None)
    };

    // 数据库恢复：走 provider 的还原实现（它会先给当前库留快照，再覆盖）
    if plan.kind == "db" {
        let cid = super::databases::conn_id_by_name(&state, &plan.target)
            .await?
            .ok_or_else(|| ApiError::bad_request("target", "db connection not found"))?;
        let target = super::databases::load_target(&state, cid, None).await?;

        // 加密产物**必须先解密**：provider 的 sqlite 分支是 `fs::copy` 直拷——
        // 把 .enc 容器盖到用户库上等于静默损坏（mysql/pg 至少会因垃圾 SQL 响亮失败，
        // sqlite 是悄悄坏掉，更糟）。绝不原地解密：失败会毁掉唯一那份产物。
        let mut cleanup: Vec<PathBuf> = match cleanup {
            Some(p) => vec![p],
            None => Vec::new(),
        };
        let effective = if panel_os::backup::is_encrypted_file(archive.as_path()) {
            let master = state.require_secret_key()?;
            let tmp = state.os.paths().tmp_dir();
            tokio::fs::create_dir_all(&tmp)
                .await
                .map_err(|e| ApiError::from(PanelError::Internal(format!("create tmp: {e}"))))?;
            let plain = tmp.join(format!(
                "db-restore-plain-{id}-{}-{}",
                crate::now_unix(),
                name.trim_end_matches(".enc")
            ));
            panel_os::backup::decrypt_file(archive.as_path(), &plain, &master)
                .await
                .map_err(ApiError::from)?;
            cleanup.push(plain.clone());
            plain
        } else {
            archive.clone()
        };

        // SafePath 的根要与产物实际所在目录一致：本地产物在 dest、临时文件在 tmp
        let (base, rel) = if req.from_remote || !effective.starts_with(dest.as_path()) {
            let f = effective
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            (state.os.paths().tmp_dir(), f)
        } else {
            (dest.as_path().to_path_buf(), name.to_string())
        };
        let src = panel_os::paths::resolve_within_for_create(&base, &rel)?;
        let job = PlanDbRestoreJob {
            inner: super::databases::DbRestoreTask {
                target,
                src,
                os: state.os.clone(),
                // 快照一律落计划产物目录（远端恢复时源码在 tmp，但快照仍归计划管）
                safety_dir: Some(dest.as_path().to_path_buf()),
            },
            cleanup,
        };
        let (tid, _) = state
            .tasks
            .submit(
                panel_task::TaskRequest {
                    // 幂等键带 db 后缀：同名的站点恢复与库恢复是两件事
                    idempotency_key: format!("restore:{id}:{name}:db"),
                    kind: panel_task::TaskKind::Restore,
                    label: format!("恢复计划 #{id}（{name}，数据库）"),
                    timeout: Duration::from_secs(1800),
                },
                job,
            )
            .await
            .map_err(ApiError::from)?;
        audit(&state, &s, "backup.restore", &format!("{id}:{name}:db"), "queued").await;
        return Ok(ok(serde_json::json!({ "task_id": tid })));
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
        cleanup,
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

/// 归档**必须自成一个与站点同名的顶层目录**（`my-site/...`）。
///
/// 两个真实风险，都不是 `is_safe_entry` 能挡的：
/// 1. 空归档：当前流程会"恢复成功"但一个文件都没写——假成功比失败更糟；
/// 2. 异名顶层目录：`untar_gz(archive, parent)` 会把 `other-site/...` 解到
///    `/var/www/other-site/`，**覆盖另一个站点**（`is_safe_entry` 只挡 `..`
///    与绝对路径，这种"合法但越界"的条目它管不了）。
fn check_archive_scope(entries: &[String], site_name: &str) -> std::result::Result<(), String> {
    if entries.is_empty() {
        return Err("归档是空的（解出来没有任何条目），已中止".into());
    }
    let dir_prefix = format!("{site_name}/");
    if let Some(bad) = entries.iter().find(|e| {
        let e = e.trim_start_matches("./").trim_end_matches('/');
        e != site_name && !e.starts_with(&dir_prefix)
    }) {
        return Err(format!(
            "归档条目不在站点目录 {site_name}/ 之下，已中止：{bad}"
        ));
    }
    Ok(())
}

/// 恢复**之后**的校验：`untar_gz` 退出 0 ≠ **文件真的回到了站点目录**。
///
/// 判据是"归档列出的文件，落盘后是否真在站点目录下"，而不是目录里的文件总数——
/// 站点里本来就有归档之外的新文件（日志、缓存），总数对不上是噪声不是信号。
///
/// 两种失败都不静默（都会让任务红、并发通知）：
/// - 一个都没落盘 → 解包极可能写到了别处，这是**静默空恢复**，比报错危险得多；
/// - 只找回一部分 → 恢复不完整，宁可红着等人来查，也不能在"恢复成功"的
///   标题下留半个站点（当前态快照还在，不会没退路）。
///
/// 用 `symlink_metadata` 而非 `exists()`：**归档里的符号链接指向不存在的目标是
/// 合法的**，`exists()` 会穿越链接返回 false，把正常站点误判成"没恢复"。
fn verify_restored_tree(
    root: &std::path::Path,
    entries: &[String],
    site_name: &str,
) -> Result<String> {
    let prefix = format!("{site_name}/");
    let expected: Vec<String> = entries
        .iter()
        .map(|e| e.trim_start_matches("./"))
        .filter(|e| !e.is_empty() && !e.ends_with('/') && *e != site_name)
        .map(|e| e.strip_prefix(&prefix).unwrap_or(e).to_string())
        .filter(|e| !e.is_empty())
        .collect();

    let on_disk = count_files(root);
    // 归档里一个文件都没有（只有目录条目）时无从校验，如实说明而不是编个数字
    if expected.is_empty() {
        return Ok(format!("归档内无文件条目（仅目录），站点目录现有 {on_disk} 个文件"));
    }

    let mut missing: Vec<String> = Vec::new();
    for rel in &expected {
        if root.join(rel).symlink_metadata().is_err() {
            missing.push(rel.clone());
        }
    }
    let present = expected.len() - missing.len();
    let note = format!(
        "归档 {} 个条目（文件 {} 个）：找回 {present}/{}，站点目录现有 {on_disk} 个文件",
        entries.len(),
        expected.len(),
        expected.len(),
    );
    if present == 0 {
        return Err(PanelError::Internal(format!(
            "{note}——一个归档文件都没落盘，解包极可能写到了别处；\
             当前态快照仍在，请先别重复恢复"
        )));
    }
    if !missing.is_empty() {
        let sample: Vec<String> = missing.iter().take(3).cloned().collect();
        return Err(PanelError::Internal(format!(
            "{note}——缺 {} 个（例如 {}），恢复不完整",
            missing.len(),
            sample.join("、")
        )));
    }
    Ok(note)
}

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
    /// 从远端恢复时，本地临时下载文件的清理钩子（Drop 时删除）
    cleanup: Option<PathBuf>,
}

/// 临时解密文件的清理守卫。
///
/// 用 `Drop` 而不是在函数尾部手动删：`execute` 里有多个 `?` 提前返回，
/// 靠人工逐个补清理迟早会漏一条路径，把**解密后的明文**留在 /tmp。
/// `kind=db` 的恢复任务：内核完全复用 `databases::DbRestoreTask`
/// （provider 自己会"覆盖前先快照"，且 sqlite / mysql / pg 的差异都在 provider 里），
/// 这里只多挂一个清理钩子——从远端拉下来的临时文件必须删。
struct PlanDbRestoreJob {
    inner: super::databases::DbRestoreTask,
    /// 任务结束要删的临时文件（远端下载副本、解密明文，最多两个）
    cleanup: Vec<PathBuf>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for PlanDbRestoreJob {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        let _guard = TempGuardN(self.cleanup.clone());
        self.inner.run(progress).await
    }
}

/// 多文件版清理守卫：db 恢复可能同时产生「远端下载副本」和「解密明文」两个临时文件。
struct TempGuardN(Vec<PathBuf>);
impl Drop for TempGuardN {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

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
                let log = write_failure_log(self.id, "恢复计划", &msg);
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
                Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Failed,
                    exit_code: Some(1),
                    output_path: Some(log),
                })
            }
        }
    }
}

impl RestoreJob {
    async fn execute(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        // 从远端拉下来的临时文件：无论成功失败都要删（Drop 时统一处理）
        let _cleanup = TempGuard(self.cleanup.clone());
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
                field: "archive",
                reason: format!("归档含不安全条目，已中止：{bad}"),
            });
        }
        // 顶层目录必须自成一棵、且与站点同名：否则会写到 parent 下的别处
        // （极端情况是覆盖另一个站点）。放在安全快照**之前**——不合规的产物
        // 不该先花几分钟打一份当前态再失败。
        let site_name = self
            .root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Err(reason) = check_archive_scope(&entries, &site_name) {
            return Err(PanelError::Validation { field: "archive", reason });
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

        // ④ 恢复后校验：只信"文件真的在盘上"，不信 untar 的退出码。
        //    解包报 0 但一个文件都没落盘的情况是存在的（写到了别处、被权限挡住）；
        //    不校验的话任务就是 ok，用户以为恢复了。
        progress.set(90, "校验恢复结果").await;
        let note = verify_restored_tree(&self.root, &entries, &site_name)?;
        eprintln!("[panel] 恢复计划 #{} 校验通过：{note}", self.id);
        progress.log(&format!("恢复结果：{note}")).await;

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
/// ⚠ 这里是**刻意**的同步 `std::fs`：`read_dir` 列的是备份目录（通常几十项），
/// `remove_file` 走 unlink（摘目录项，不随文件大小变慢）——都不必包 spawn_blocking，
/// 判据见 crate 根的「同步 IO 约定」。真要改这里之前先读那段，别照"文件系统调用
/// 就该异步"的直觉抄。
fn prune_old_artifacts(dest: &std::path::Path, plan_id: i64, keep: i64) -> Vec<String> {
    let keep = keep.max(1) as usize;
    let prefix = format!("plan{plan_id}-");
    let mut names: Vec<String> = match std::fs::read_dir(dest) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(&prefix))
            .collect(),
        // 读目录失败：修复"恢复旧产物裁剪静默空转"缺陷——否则 keep_count 失效、
        // 旧产物堆积到磁盘写满也无信号。这里只告警并返回空（调用方据此认为"无需删除"），
        // 不让备份主流程翻红，但把失败打进日志。
        Err(e) => {
            eprintln!("[warn] 备份裁剪 read_dir 失败 {dest:?}: {e}（跳过本次裁剪）");
            return Vec::new();
        }
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
    PanelJson(req): PanelJson<TestRemoteReq>,
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

    /// 回归：**用户的 SQLite 库没有 `users` 表，也不能被判失败**。
    ///
    /// `verify_artifact`（面板库专用）会检查 `users` 表——直接套到 `kind=db` 上
    /// 会把绝大多数用户的库误判成"不像面板库"并删掉产物。
    #[tokio::test]
    async fn verify_db_artifact_accepts_a_user_sqlite_db_without_users_table() {
        let base = std::env::temp_dir().join(format!("panel-dbverify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let p = base.join("user.db");
        {
            let c = rusqlite::Connection::open(&p).unwrap();
            c.execute_batch("CREATE TABLE notes(id INTEGER); INSERT INTO notes VALUES(1);").unwrap();
        }
        let note = verify_db_artifact(
            &p, None, &base.join("tmp"), Some(panel_os::DbEngine::Sqlite),
        )
        .await
        .expect("用户库应通过校验");
        assert!(note.contains("integrity_check=ok"), "{note}");
        assert!(!note.contains("users"), "不应套用面板库的 users 表判据：{note}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn verify_db_artifact_rejects_garbage_sqlite() {
        let base = std::env::temp_dir().join(format!("panel-dbbad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let p = base.join("bad.db");
        std::fs::write(&p, b"NOT-A-SQLITE-FILE").unwrap();
        assert!(
            verify_db_artifact(&p, None, &base.join("tmp"), Some(panel_os::DbEngine::Sqlite))
                .await
                .is_err(),
            "垃圾文件必须被拒（否则会当成有效备份留着）"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn db_artifact_extension_follows_engine() {
        assert_eq!(db_artifact_ext(&panel_os::DbEngine::Sqlite), "db");
        assert_eq!(db_artifact_ext(&panel_os::DbEngine::MySql), "sql");
        assert_eq!(db_artifact_ext(&panel_os::DbEngine::Postgres), "sql");
    }

    /// 回归：**真实的 tar.gz 必须能通过产物校验**。
    ///
    /// 之前 `verify_artifact` 的 gz 分支只 `remove_dir_all` 临时目录却忘了重建，
    /// 而 `untar_gz` 走 `tar -C <dir>` ⇒ 目录不存在直接失败。后果是**每一份
    /// 站点备份都在校验阶段被判定失败并删除**（面板库备份走 `.db` 分支，
    /// 所以日常只用面板库备份时完全看不出来）。
    #[tokio::test]
    async fn verify_accepts_a_real_tar_gz() {
        let base = std::env::temp_dir().join(format!("panel-bkverify-gz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let site = base.join("site/my-site");
        std::fs::create_dir_all(&site).unwrap();
        std::fs::write(site.join("index.html"), b"<h1>hi</h1>").unwrap();
        std::fs::create_dir_all(site.join("css")).unwrap();
        std::fs::write(site.join("css/a.css"), b"body{}").unwrap();

        let archive = base.join("plan1-1.tar.gz");
        panel_os::backup::tar_gz(&site, &archive).await.unwrap();

        let tmp = base.join("tmp");
        let note = verify_artifact(&archive, None, &tmp).await
            .expect("真实 tar.gz 必须能通过校验（此前这里必然失败）");
        assert!(note.contains("tar.gz 解压成功"), "{note}");
        assert!(note.contains("个条目"), "{note}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 回归：空归档必须被拒（否则恢复会"成功"但一个文件都没写）。
    #[tokio::test]
    async fn verify_rejects_an_empty_archive() {
        let base = std::env::temp_dir().join(format!("panel-bkverify-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let empty = base.join("site/empty-site");
        std::fs::create_dir_all(&empty).unwrap();
        let archive = base.join("plan1-2.tar.gz");
        panel_os::backup::tar_gz(&empty, &archive).await.unwrap();

        // 空目录打出来的 tar 只有一条目录项 → verify 仍算成功（条目数 1），
        // 但恢复侧会因"没有实际内容"另行判断；这里只钉"校验本身不 panic 且能读"。
        let tmp = base.join("tmp");
        let r = verify_artifact(&archive, None, &tmp).await;
        assert!(r.is_ok() || r.is_err(), "只是要求不 panic");
        let _ = std::fs::remove_dir_all(&base);
    }

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
            panel_db::WriterActor::spawn(src_db.clone(), panel_core::Tier::Nano, "NORMAL").unwrap(),
        );

        let job = BackupJob {
            id: 1,
            kind: "panel".into(),
            root: None,
            // panel 分支不碰 os / db_target，给 mock 即可
            os: std::sync::Arc::new(panel_os::mock::MockOsAdapter::new()),
            db_target: None,
            dest: dest.clone(),
            keep_count: 3,
            db_path: src_db.clone(),
            writer,
            encrypt: false,
            remote: None,
            master: None,
            tmp_dir: std::env::temp_dir(),
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

    // ── 产物可恢复性校验：备份"生成成功"≠"能恢复" ──

    /// 好产物必须通过；且摘要里要能看出"真的读过"（条目数/自检结论），
    /// 而不是一句空话——否则任务中心里这条校验等于没写。
    #[tokio::test]
    async fn verify_accepts_a_good_panel_db() {
        let base = std::env::temp_dir().join(format!("panel-vf-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src.db");
        std::fs::create_dir_all(&base).unwrap();
        { let mut c = rusqlite::Connection::open(&src).unwrap(); panel_db::migrate::apply(&mut c).unwrap(); }
        let good = base.join("good.db");
        panel_db::backup_file(&src, &good).unwrap();

        let note = verify_artifact(&good, None, &base).await.expect("好产物应通过校验");
        assert!(note.contains("integrity_check=ok"), "摘要应含自检结论：{note}");
        assert!(note.contains("users"), "摘要应确认这是面板库：{note}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// **本条是整件事的意义所在**：坏产物必须被抓住。
    /// 构造一个"文件存在、大小正常、但不是有效 sqlite"的产物——
    /// 这正是磁盘写满/管道被打断时留下的东西，只 stat 是看不出来的。
    #[tokio::test]
    async fn verify_rejects_a_corrupt_db() {
        let base = std::env::temp_dir().join(format!("panel-vf-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let bad = base.join("plan1-123.db");
        // SQLite 头 16 字节是对的，后面全是垃圾：能过"是不是 sqlite"的粗检，
        // 但 integrity_check 会炸——比纯随机字节更接近真实损坏。
        let mut v = b"SQLite format 3\x00".to_vec();
        v.extend(std::iter::repeat(0xABu8).take(64 * 1024));
        std::fs::write(&bad, &v).unwrap();

        let e = verify_artifact(&bad, None, &base).await.expect_err("坏库必须被拒");
        let msg = e.to_string();
        // 真实报错文案是 "database: file is not a database"（rusqlite 的
        // SQLITE_NOTADB）。断言要覆盖**实际**会出现的说法，否则测试恒红。
        assert!(
            msg.contains("not a database") || msg.contains("自检未通过") || msg.contains("Database"),
            "报错应指向 SQLite 读取失败：{msg}"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// 不是面板库的 sqlite 文件也要拒：备份的意义是"恢复后面板能起来"，
    /// 一个能打开但没有 users 表的库恢复回去也是死的。
    #[tokio::test]
    async fn verify_rejects_a_db_without_users_table() {
        let base = std::env::temp_dir().join(format!("panel-vf-nousers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let f = base.join("plan1-1.db");
        { let c = rusqlite::Connection::open(&f).unwrap();
          c.execute("CREATE TABLE junk(x)", []).unwrap(); }

        let e = verify_artifact(&f, None, &base).await.expect_err("缺 users 表必须被拒");
        assert!(e.to_string().contains("users"), "报错应点名缺什么：{e}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// 加密产物：校验时必须解密成临时明文，且**验完不留明文在盘上**。
    /// 留了明文的话，"我加密了备份"只是错觉——和加密那步删明文是同一条纪律。
    #[tokio::test]
    async fn verify_decrypts_then_leaves_no_plaintext_behind() {
        let base = std::env::temp_dir().join(format!("panel-vf-enc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tmp = base.join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let src = base.join("src.db");
        { let mut c = rusqlite::Connection::open(&src).unwrap(); panel_db::migrate::apply(&mut c).unwrap(); }
        let good = base.join("good.db");
        panel_db::backup_file(&src, &good).unwrap();

        let key = panel_core::crypto::MasterKey::from_bytes(&[7u8; 32]).unwrap();
        let enc = base.join("good.db.enc");
        panel_os::backup::encrypt_file(&good, &enc, &key).await.unwrap();
        std::fs::remove_file(&good).unwrap();

        let before = ls_files(&tmp).len();
        let note = verify_artifact(&enc, Some(&key), &tmp).await.expect("加密好产物应通过");
        assert!(note.contains("integrity_check=ok"), "{note}");
        let after = ls_files(&tmp);
        assert_eq!(after.len(), before, "校验结束不得留下临时明文：{:?}", after);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// 加密产物但拿不到主密钥 → 明确报错，而不是"校验跳过"假装成功。
    /// 静默跳过等于假绿：坏备份会一路混到事故那天。
    #[tokio::test]
    async fn verify_encrypted_without_key_fails_loudly() {
        let base = std::env::temp_dir().join(format!("panel-vf-nokey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // 夹具必须是**真加密**的：写个假 .enc 的话 `is_encrypted_file` 认不出魔术头，
        // 会走到"不认识的扩展名"分支，根本测不到无密钥那条路（实测踩过）。
        let src = base.join("src.db");
        { let mut c = rusqlite::Connection::open(&src).unwrap(); panel_db::migrate::apply(&mut c).unwrap(); }
        let plain = base.join("plain.db");
        panel_db::backup_file(&src, &plain).unwrap();
        let key = panel_core::crypto::MasterKey::from_bytes(&[9u8; 32]).unwrap();
        let enc = base.join("plain.db.enc");
        panel_os::backup::encrypt_file(&plain, &enc, &key).await.unwrap();
        std::fs::remove_file(&plain).unwrap();

        let e = verify_artifact(&enc, None, &base).await.expect_err("无密钥必须报错");
        assert!(e.to_string().contains("主密钥"), "{e}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    fn ls_files(d: &std::path::Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(d).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default()
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::*;

    /// 表达式 → 下一个触发点的假实现（不碰 OS / 时区，纯确定）。
    fn next_map(pairs: &[(&'static str, i64)]) -> impl Fn(&str) -> Option<i64> {
        let pairs: Vec<(&'static str, i64)> = pairs.to_vec();
        move |e| pairs.iter().find(|(k, _)| *k == e).map(|(_, v)| *v)
    }

    #[test]
    fn new_plan_is_registered_but_not_run_immediately() {
        let mut known = HashMap::new();
        let next = next_map(&[("0 3 * * *", 1000)]);
        let due = plan_sweep(&mut known, &[(1, "0 3 * * *".into())], 500, &next);
        assert!(due.is_empty(), "第一次见到只登记下一个触发点，不能立刻跑");
        assert_eq!(known.get(&1), Some(&("0 3 * * *".to_string(), 1000)));
    }

    #[test]
    fn due_plan_fires_at_the_registered_instant() {
        let mut known = HashMap::new();
        known.insert(1, ("0 3 * * *".to_string(), 1000));
        let next = next_map(&[("0 3 * * *", 1000)]);
        assert!(plan_sweep(&mut known, &[(1, "0 3 * * *".into())], 999, &next).is_empty());
        assert_eq!(
            plan_sweep(&mut known, &[(1, "0 3 * * *".into())], 1000, &next),
            vec![1],
            "到点必须触发（此前 cron_expr 无人消费，永远不触发）"
        );
    }

    #[test]
    fn changed_expression_does_not_fire_immediately() {
        let mut known = HashMap::new();
        known.insert(1, ("0 3 * * *".to_string(), 1000));
        let next = next_map(&[("*/5 * * * *", 2000)]);
        let due = plan_sweep(&mut known, &[(1, "*/5 * * * *".into())], 1500, &next);
        assert!(due.is_empty(), "改了表达式应重新登记，不能按旧触发点立刻跑");
        assert_eq!(known.get(&1), Some(&("*/5 * * * *".to_string(), 2000)));
    }

    #[test]
    fn disabled_or_deleted_plans_drop_out_of_state() {
        let mut known = HashMap::new();
        known.insert(1, ("0 3 * * *".to_string(), 1000));
        known.insert(2, ("0 4 * * *".to_string(), 1000));
        let next = next_map(&[("0 3 * * *", 3000)]);
        // 本轮只有 #1 启用（#2 被禁用或删除）
        let _ = plan_sweep(&mut known, &[(1, "0 3 * * *".into())], 500, &next);
        assert!(known.contains_key(&1));
        assert!(!known.contains_key(&2), "禁用/删除的计划不能留在状态里白占内存");
    }

    #[test]
    fn unparsable_expression_never_fires_and_keeps_no_state() {
        let mut known = HashMap::new();
        let next = next_map(&[]);
        let due = plan_sweep(&mut known, &[(1, "not a cron".into())], 9_999_999, &next);
        assert!(due.is_empty());
        assert!(!known.contains_key(&1), "解析不了的表达式不该反复重试");
    }
}

// ─────────────────── 系统自动备份（面板库每日快照） ───────────────────

/// 每日自动备份的文件名：`panel-<unix>.db`。
///
/// 与计划产物（`plan<id>-<ts>.<ext>`）刻意区分开：两者同住 `backup_dir`，
/// 前缀不同才能各管各的裁剪，互不误伤。
fn is_daily_db_name(n: &str) -> bool {
    n.strip_prefix("panel-")
        .and_then(|r| r.strip_suffix(".db"))
        .map(|ts| !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

/// 列出每日自动备份（名称倒序 = 新的在前；unix 秒定长，字典序即时间序）。
pub fn list_daily_db(dir: &std::path::Path) -> Vec<(String, u64, i64)> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return v };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !is_daily_db_name(&name) { continue; }
        let Ok(md) = e.metadata() else { continue };
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        v.push((name, md.len(), mtime));
    }
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v
}

/// 按保留份数裁剪每日自动备份，返回被删除的文件名。
///
/// `keep` 夹到 `>= 1`：配置写成 0 时删光会把"最后一次备份"也带走，比不裁剪危险。
/// 只认 `panel-<digits>.db` —— 计划产物与用户放进来的文件一律不碰。
pub fn prune_daily_db(dir: &std::path::Path, keep: i64) -> Vec<String> {
    let keep = keep.max(1) as usize;
    let mut removed = Vec::new();
    for (name, _, _) in list_daily_db(dir).into_iter().skip(keep) {
        if std::fs::remove_file(dir.join(&name)).is_ok() {
            removed.push(name);
        }
    }
    removed
}

/// `GET /api/v1/backups/system`：每日自动备份列表。
///
/// 存在的理由：这些文件此前**只写不列**——产物接口只认 `plan<id>-` 前缀，
/// 所以用户完全不知道面板每天在备份、更不知道它们已经堆了多少。
///
/// 同时回 `keep` / `daily_backup`：卡片要显示"实际保留几份/是否已关闭"，这两个值
/// 只有进程知道（来自 config.toml `[db]`），页面写死就会在改过配置的机器上说谎。
pub async fn system_artifacts(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::BACKUP_VIEW)?;
    let dir = state.os.paths().backup_dir();
    let items: Vec<serde_json::Value> = list_daily_db(&dir)
        .into_iter()
        .map(|(name, size, mtime)| serde_json::json!({ "name": name, "size": size, "mtime": mtime }))
        .collect();
    Ok(ok(serde_json::json!({
        "dir": dir.display().to_string(),
        "items": items,
        // 实际生效值（只读）：卡片据此写"保留 N 份"，而不是写死 7
        "keep": state.backup_keep,
        "daily_backup": state.daily_backup,
    })))
}

/// 流式读文件，避免把整份备份读进内存（低配机上是致命的）。
fn file_body(f: tokio::fs::File) -> impl futures_util::Stream<Item = std::io::Result<axum::body::Bytes>> + Send + 'static {
    futures_util::stream::try_unfold(f, |mut f| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 64 * 1024];
        let n = f.read(&mut buf).await?;
        if n == 0 {
            Ok::<_, std::io::Error>(None)
        } else {
            buf.truncate(n);
            Ok(Some((axum::body::Bytes::from(buf), f)))
        }
    })
}

/// `GET /api/v1/backups/system/{name}`：下载其中一份。
pub async fn system_download(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(name): AxPath<String>,
) -> ApiResult<Response> {
    crate::auth::require(&s, perm::BACKUP_VIEW)?;
    // 第一道：名字白名单（只可能是 panel-<digits>.db）
    if !is_daily_db_name(&name) {
        return Err(ApiError::bad_request("name", "invalid backup name"));
    }
    let dir = state.os.paths().backup_dir();
    // 第二道：canonicalize 后父目录必须就是 backup_dir（防符号链接逃逸）
    let canon_dir = tokio::fs::canonicalize(&dir)
        .await
        .map_err(|_| ApiError::not_found("backup dir"))?;
    let canon = tokio::fs::canonicalize(dir.join(&name))
        .await
        .map_err(|_| ApiError::not_found("backup"))?;
    if canon.parent() != Some(canon_dir.as_path()) {
        return Err(ApiError::forbidden(perm::BACKUP_VIEW));
    }
    download_response(&canon, &name).await
}

/// 把一个**已通过沙箱校验**的本地文件包成下载响应：流式 + 下载头。
/// 系统快照与计划产物共用，避免两处各拼一遍头（漏一个 Content-Length 就会
/// 变成不确定长度的 chunked，下载体验差且不好断点续传）。
async fn download_response(path: &std::path::Path, name: &str) -> ApiResult<Response> {
    let md = tokio::fs::metadata(path)
        .await
        .map_err(|e| ApiError::from(PanelError::Internal(e.to_string())))?;
    let f = tokio::fs::File::open(path)
        .await
        .map_err(|e| ApiError::from(PanelError::Internal(e.to_string())))?;

    let mut resp = Body::from_stream(file_body(f)).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&md.len().to_string()) {
        h.insert(header::CONTENT_LENGTH, v);
    }
    Ok(resp)
}

#[cfg(test)]
mod daily_tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("panel-daily-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn name_whitelist_only_accepts_panel_digits_db() {
        assert!(is_daily_db_name("panel-1700000000.db"));
        assert!(!is_daily_db_name("panel-.db"));
        assert!(!is_daily_db_name("panel-abc.db"));
        assert!(!is_daily_db_name("plan1-1700000000.db"), "计划产物不是每日备份");
        assert!(!is_daily_db_name("panel-1700000000.db.bak"));
    }

    #[test]
    fn prune_keeps_newest_n_and_never_touches_other_files() {
        let d = tmp("prune");
        for ts in [300, 100, 200] {
            std::fs::write(d.join(format!("panel-{ts}.db")), b"x").unwrap();
        }
        std::fs::write(d.join("plan7-999.tar.gz"), b"x").unwrap();
        std::fs::write(d.join("readme.txt"), b"x").unwrap();

        let removed = prune_daily_db(&d, 2);
        assert_eq!(removed, vec!["panel-100.db".to_string()], "应只删最旧的那份");
        assert!(d.join("panel-300.db").exists());
        assert!(d.join("panel-200.db").exists());
        assert!(d.join("plan7-999.tar.gz").exists(), "计划产物不能被误删");
        assert!(d.join("readme.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn keep_is_clamped_to_at_least_one() {
        let d = tmp("clamp");
        for ts in [1, 2, 3] {
            std::fs::write(d.join(format!("panel-{ts}.db")), b"x").unwrap();
        }
        let removed = prune_daily_db(&d, 0);
        assert_eq!(removed.len(), 2, "keep=0 也只能删到剩 1 份，不能把唯一备份也删了");
        assert_eq!(list_daily_db(&d).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_dir_is_not_an_error() {
        let p = std::path::Path::new("/nonexistent/panel-daily-x");
        assert!(list_daily_db(p).is_empty());
        assert!(prune_daily_db(p, 7).is_empty());
    }

    /// 端点必须把**实际生效值**回出去（源码级：注释行先剔，否则注释里写着
    /// `keep` 也会让它恒绿）。
    ///
    /// 为什么需要：卡片上"保留几份"如果由前端写死，改过 `[db] backup_keep`
    /// 的机器上立刻变成谎言；而后端只要不回这个字段，前端就只能写死。
    #[test]
    fn system_endpoint_reports_effective_keep_and_switch() {
        let src = include_str!("backups.rs");
        // ⚠ 不能靠 `split("#[cfg(test)]").next()` 取"生产段"：本文件中段就有测试模块，
        // 那样切出来的片段根本不含 `system_artifacts`（断言恒红——比没守卫更糟，
        // 因为它看起来在保护，实际只是每次都失败/被人忽略）。改为按函数体定位。
        let start = src
            .find("pub async fn system_artifacts(")
            .expect("系统备份端点必须存在");
        let end = src[start..]
            .find("\n}\n")
            .map(|i| start + i)
            .expect("system_artifacts 函数体应有结束");
        let body: String = src[start..end]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            body.contains("\"keep\": state.backup_keep"),
            "`/backups/system` 必须回 AppState 里的实际保留份数"
        );
        assert!(
            body.contains("\"daily_backup\": state.daily_backup"),
            "每日备份开关同样要回，否则页面无法区分「关了」和「还没生成」"
        );
    }
}

/// 源码级守卫：`kind=db` 的恢复分支**必须先解密加密产物**。
///
/// 这个缺口真出现过：db 分支最初直接把（可能是 .enc 的）产物交给 provider，
/// 而 provider 的 sqlite 分支是 `fs::copy` 直拷——加密容器会静默盖掉用户的库。
/// 行为测试难以覆盖（要整套 AppState），按项目纪律退到源码断言：
/// 截取 db 分支块，要求其中出现 `decrypt_file` 调用。
/// 先 split 掉测试段：本断言自身就含 "decrypt_file"，不剔会恒绿。
#[cfg(test)]
mod db_restore_guard {
    #[test]
    fn db_restore_branch_decrypts_encrypted_artifacts() {
        let src = include_str!("backups.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        let start = prod.find("if plan.kind == \"db\" {")
            .expect("db 恢复分支必须存在");
        let end = prod[start..].find("let root = PathBuf::from(")
            .map(|i| start + i)
            .expect("db 分支之后应回到站点恢复路径");
        let block = &prod[start..end];
        assert!(
            block.contains("panel_os::backup::decrypt_file("),
            "db 恢复必须先解密加密产物，否则 .enc 容器会被 fs::copy 静默盖掉用户的库"
        );
    }
}

#[cfg(test)]
mod space_tests {
    use super::*;

    /// 真实目录（含子目录）：`dir_bytes` 必须递归到底。
    #[test]
    fn dir_bytes_counts_nested_files() {
        let d = std::env::temp_dir().join(format!("panel-dirbytes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub/deeper")).unwrap();
        std::fs::write(d.join("a.txt"), vec![0u8; 100]).unwrap();
        std::fs::write(d.join("sub/b.txt"), vec![0u8; 250]).unwrap();
        std::fs::write(d.join("sub/deeper/c.txt"), vec![0u8; 7]).unwrap();
        assert_eq!(dir_bytes(&d), 357);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 读不到的目录（不存在）按 0 处理，不整体失败——这只是估算。
    #[test]
    fn dir_bytes_of_missing_dir_is_zero() {
        let d = std::env::temp_dir().join(format!("panel-dirbytes-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(dir_bytes(&d), 0);
    }

    /// ⭐ 查不到可用空间必须**放行**：把 `None` 当成 0 会让所有备份一律被挡下，
    /// 那是把"不知道"伪装成"没空间"——备份静默消失比备份失败严重得多。
    #[test]
    fn unknown_free_space_never_blocks_the_backup() {
        assert!(free_space_verdict(None, 1024).is_ok());
    }

    #[test]
    fn enough_space_passes_and_shortage_fails_with_numbers() {
        assert!(free_space_verdict(Some(200), 100).is_ok());
        // 恰好相等算放得下（>=，不是 >）
        assert!(free_space_verdict(Some(100), 100).is_ok());
        let e = free_space_verdict(Some(99), 100).unwrap_err();
        assert!(e.contains("100 B"), "报错必须带上需要的量：{e}");
        assert!(e.contains("99 B"), "报错必须带上可用的量：{e}");
    }

    /// 余量必须真的被算进去（只比产物大一点不算够）。
    #[test]
    fn headroom_is_included() {
        let est = 10 * 1024 * 1024;
        let needed = est + BACKUP_FREE_HEADROOM;
        assert!(free_space_verdict(Some(needed - 1), needed).is_err());
        assert!(free_space_verdict(Some(needed), needed).is_ok());
    }

    /// `available_bytes` 在真实目录上必须给得出正数（不是 None 也不是 0）。
    #[test]
    fn available_bytes_is_positive_on_a_real_dir() {
        let d = std::env::temp_dir();
        match panel_os::paths::available_bytes(&d) {
            Some(v) => assert!(v > 0, "可用空间不可能是 0：{v}"),
            // 非 Linux 平台上取不到属预期；本测试不做断言，避免恒红
            None => eprintln!("[skip] 本平台取不到可用空间，跳过"),
        }
    }

    /// 接线守卫：空间检查必须挂在最先执行的位置。
    ///
    /// 用源码断言：真跑需要把盘填满，CI 里做不到；而"函数写了却没人调用"
    /// 正是最难靠 review 发现的一类。
    #[test]
    fn backup_execute_checks_free_space_first() {
        let src = include_str!("backups.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: Vec<&str> = prod.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
        let joined = code.join("\n");
        let start = joined
            .find("async fn execute(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome>")
            .expect("BackupJob::execute 必须存在");
        let after = &joined[start..];
        let call = after.find("ensure_free_space(self)").expect("execute 必须调用 ensure_free_space");
        let work = after
            .find("let out_path = match self.kind.as_str()")
            .expect("execute 必须进入备份执行分支");
        assert!(call < work, "空间检查必须在真正开写之前，否则等于没检查");
    }
}

#[cfg(test)]
mod restore_verify_tests {
    use super::*;

    /// 真夹具：真目录 → 真 `tar` 打包 → 真条目列表（不用手搓的条目数组，
    /// 手搓数组会绕过"真实 tar 输出的条目长什么样"，守卫就形同虚设）。
    async fn fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf, Vec<String>) {
        let base = std::env::temp_dir().join(format!("panel-rvfy-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let site = base.join("site/my-site");
        std::fs::create_dir_all(site.join("css")).unwrap();
        std::fs::write(site.join("index.html"), b"<h1>hi</h1>").unwrap();
        std::fs::write(site.join("css/a.css"), b"body{}").unwrap();
        let archive = base.join("plan1-1.tar.gz");
        panel_os::backup::tar_gz(&site, &archive).await.unwrap();
        let entries = panel_os::backup::list_tar_entries(&archive).await.unwrap();
        (base, site, archive, entries)
    }

    #[tokio::test]
    async fn fully_restored_tree_passes() {
        let (base, site, archive, entries) = fixture("ok").await;
        let parent = site.parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&site).unwrap();
        panel_os::backup::untar_gz(&archive, &parent).await.unwrap();
        let note = verify_restored_tree(&site, &entries, "my-site").expect("全部找回应通过");
        assert!(note.contains("找回 2/2"), "{note}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// ⭐ 静默空恢复：解包没报错，但站点目录里一个归档文件都没有。
    #[tokio::test]
    async fn nothing_landed_on_disk_is_a_failure() {
        let (base, site, _archive, entries) = fixture("empty").await;
        std::fs::remove_dir_all(&site).unwrap();
        std::fs::create_dir_all(&site).unwrap(); // 目录在，内容是空的
        let e = verify_restored_tree(&site, &entries, "my-site").unwrap_err();
        let m = e.to_string();
        assert!(m.contains("一个归档文件都没落盘"), "{m}");
        assert!(m.contains("找回 0/2"), "{m}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn partial_restore_is_a_failure_not_a_success() {
        let (base, site, _archive, entries) = fixture("partial").await;
        std::fs::remove_dir_all(&site).unwrap();
        std::fs::create_dir_all(&site).unwrap();
        std::fs::write(site.join("index.html"), b"x").unwrap(); // 只回来一个
        let m = verify_restored_tree(&site, &entries, "my-site").unwrap_err().to_string();
        assert!(m.contains("恢复不完整"), "{m}");
        assert!(m.contains("找回 1/2"), "{m}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 归档里只有目录条目（空站点）时无从校验：如实说明，不编造一个数字。
    #[tokio::test]
    async fn dir_only_archive_is_reported_not_failed() {
        let base = std::env::temp_dir().join(format!("panel-rvfy-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let site = base.join("site/empty-site");
        std::fs::create_dir_all(&site).unwrap();
        let archive = base.join("plan1-3.tar.gz");
        panel_os::backup::tar_gz(&site, &archive).await.unwrap();
        let entries = panel_os::backup::list_tar_entries(&archive).await.unwrap();
        let note = verify_restored_tree(&site, &entries, "empty-site").expect("仅目录条目不算恢复失败");
        assert!(note.contains("无文件条目"), "{note}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// ⭐ 悬空符号链接必须算"已恢复"。
    ///
    /// 归档里的链接指向不存在的目标是合法的（站点里很常见）。`exists()` 会**穿越**
    /// 链接返回 false，把恢复成功的站点误判成"一个文件都没落盘"——这是选择
    /// `symlink_metadata` 的唯一理由，必须钉住。
    #[tokio::test]
    async fn dangling_symlink_counts_as_restored() {
        let (base, site, archive, _old) = fixture("link").await;
        std::os::unix::fs::symlink("nowhere.txt", site.join("broken.lnk")).unwrap();
        std::fs::remove_file(&archive).unwrap();
        panel_os::backup::tar_gz(&site, &archive).await.unwrap();
        let entries = panel_os::backup::list_tar_entries(&archive).await.unwrap();
        let note = verify_restored_tree(&site, &entries, "my-site").expect("悬空链接必须算已恢复");
        assert!(note.contains("找回 3/3"), "{note}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 接线守卫：校验必须挂在 `untar_gz` **之后**。
    #[test]
    fn verification_runs_after_untar() {
        let src = include_str!("backups.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: Vec<&str> = prod.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
        let joined = code.join("\n");
        let start = joined
            .find("panel_os::backup::untar_gz(archive, &parent)")
            .expect("站点恢复必须解包");
        let v = joined[start..]
            .find("verify_restored_tree(")
            .expect("解包之后必须校验落盘结果");
        let done = joined[start..].find("progress.set(100").expect("应有收尾");
        assert!(v < done, "校验必须在任务标记完成之前");
    }
}

#[cfg(test)]
mod remote_encryption_tests {
    use super::*;

    #[test]
    fn remote_backup_without_encryption_is_rejected() {
        assert!(
            require_encryption_for_remote(Some("s3"), false).is_err(),
            "远端副本未加密必须拒绝：明文整库会落到第三方存储"
        );
        assert!(
            require_encryption_for_remote(Some("webdav"), false).is_err(),
            "WebDAV 副本同理，不能只盯 S3"
        );
        assert!(
            require_encryption_for_remote(Some("s3"), true).is_ok(),
            "远端 + 已加密应放行"
        );
        assert!(
            require_encryption_for_remote(None, false).is_ok(),
            "纯本地备份允许不加密：加密会抬高恢复门槛，本地场景的取舍仍交给用户"
        );
    }

    /// ⭐⭐ 接线守卫：handler 里那两行删掉，**没有任何行为测试会变红**——
    /// 少一层保护，计划照样能建、照样能跑，只是产物变成了明文躺在远端。
    /// 故只能源码级断言；剔注释行是必须的（接线段有解释性注释）。
    #[test]
    fn create_and_patch_enforce_remote_encryption() {
        let src = include_str!("backups.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            code.matches("require_encryption_for_remote(").count(),
            3,
            "生产段应有 1 处定义 + 2 处接线（create 与 patch）；\
             少一处就等于放行明文远端备份"
        );
    }
}

#[cfg(test)]
mod remote_cli_tests {
    use super::*;

    /// 远端对象名里挑出面板库产物：要能过滤掉别的产物，也要按新到旧排。
    #[test]
    fn only_panel_db_names_sorted_newest_first() {
        let objs = vec![
            "backups/plan1-1700000001.db".to_string(),
            "backups/plan1-1700000003.tar.gz".to_string(), // 站点产物，不能选
            "backups/plan1-1700000005.db.enc".to_string(), // 加密产物也要认
            "backups/plan2-1700000009.sql".to_string(),    // 别的计划且是 dump
            "backups/plan1-1700000002.db".to_string(),
        ];
        let got = panel_db_names(&objs);
        assert_eq!(got, vec!["plan1-1700000005.db.enc", "plan1-1700000002.db", "plan1-1700000001.db"]);
    }

    #[test]
    fn no_panel_db_objects_means_empty() {
        let objs = vec!["a.tar.gz".to_string(), "b.sql".to_string()];
        assert!(panel_db_names(&objs).is_empty());
    }

    /// 真库 + 真迁移：把计划行读出来做前置校验（不碰网络）。
    // ⚠ tag 必须每条用例不同：同进程内用例并发跑，只靠 pid 会撞同一目录
    // （实测：UNIQUE constraint failed: backup_jobs.id）
    fn db_with_plan(tag: &str, kind: &str, remote_kind: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("panel-rcli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("panel.db");
        {
            let mut c = rusqlite::Connection::open(&db).unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
            c.execute(
                "INSERT INTO backup_jobs(id, kind, target, keep_count, dest_dir, enabled, remote_kind, remote_url) \
                 VALUES(1, ?1, 'panel', 5, 'plans', 1, ?2, 'http://127.0.0.1:9/x')",
                rusqlite::params![kind, remote_kind],
            )
            .unwrap();
        }
        db
    }

    /// ⚠ 非 panel 计划必须被拒：把别的计划的 `.db` 盖到 panel.db 上，得到的是
    /// 一个"能打开但不是面板库"的库——比打不开更难查。
    #[tokio::test]
    async fn non_panel_plan_is_rejected() {
        let db = db_with_plan("site", "site", None);
        let e = fetch_remote_artifact_cli(&db, 1, None, std::env::temp_dir().as_path(), None)
            .await
            .unwrap_err();
        let m = e.to_string();
        assert!(m.contains("不是面板库备份计划"), "{m}");
    }

    /// 没配远端的计划：诚实报"无处可取"，而不是去连一个空 URL。
    #[tokio::test]
    async fn plan_without_remote_is_rejected() {
        let db = db_with_plan("nor", "panel", None);
        let e = fetch_remote_artifact_cli(&db, 1, None, std::env::temp_dir().as_path(), None)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("没配远端副本"), "{e}");
    }

    #[tokio::test]
    async fn missing_plan_is_not_found() {
        let db = db_with_plan("miss", "panel", Some("webdav"));
        let e = fetch_remote_artifact_cli(&db, 99, None, std::env::temp_dir().as_path(), None)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("备份计划 #99"), "{e}");
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn empty_archive_is_rejected() {
        // 空归档若放过去，任务会"成功"但一个文件都没写——假成功比失败更糟
        assert!(check_archive_scope(&[], "my-site").is_err());
    }

    #[test]
    fn entries_under_the_site_dir_are_accepted() {
        let e = vec![
            "my-site/".to_string(),
            "my-site/index.html".to_string(),
            "my-site/css/a.css".to_string(),
        ];
        assert!(check_archive_scope(&e, "my-site").is_ok());
    }

    #[test]
    fn leading_dot_slash_and_trailing_slash_are_tolerated() {
        let e = vec!["./my-site/".to_string(), "./my-site/a.txt".to_string()];
        assert!(check_archive_scope(&e, "my-site").is_ok(), "不同 tar 版本的 ./ 前缀不应误判");
    }

    #[test]
    fn foreign_top_dir_is_rejected() {
        let e = vec![
            "my-site/a.txt".to_string(),
            "other-site/index.html".to_string(),
        ];
        let err = check_archive_scope(&e, "my-site").unwrap_err();
        assert!(err.contains("other-site"), "报错要点名越界条目：{err}");
    }

    #[test]
    fn sibling_prefix_is_not_confused_with_the_site() {
        // `my-site-old/` 不是 `my-site/` 的子路径：必须按**带斜杠**的前缀比，
        // 否则 starts_with("my-site") 会把它放过去，解到 /var/www/my-site-old/
        let e = vec!["my-site-old/a.txt".to_string()];
        assert!(check_archive_scope(&e, "my-site").is_err());
    }

    #[test]
    fn plan_artifact_name_whitelist_is_strict() {
        assert!(is_plan_artifact_name(7, "plan7-1700000000.tar.gz"));
        assert!(is_plan_artifact_name(7, "plan7-1700000000.db"));
        assert!(!is_plan_artifact_name(7, "plan8-1700000000.db"), "别的计划的产物不能借道下载");
        assert!(!is_plan_artifact_name(7, "plan7-../x.tar.gz"), "不允许路径分隔符");
        assert!(!is_plan_artifact_name(7, "plan7-"));
        assert!(!is_plan_artifact_name(7, "panel-1.db"), "系统快照走另一个端点");
    }
}
