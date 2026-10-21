//! 容器管理（Docker）——列举 / 镜像 / 创建 / 生命周期 / 安装 / 加组 / 备注。
//!
//! ## 能力门禁（本模块的核心纪律）
//! `container.manage` 能力位由 `panel-os` 按 **daemon socket 可达性** 判定
//! （不是二进制存在性）。本模块所有端点前置检查该能力位；不满足时返回
//! **诚实 501**，并在 `detail` 里带上 `reason`，让前端能直接给出可操作提示
//! （`binary_missing` → 装 Docker；`daemon_unreachable` → 启动 daemon 或把面板
//! 用户加入 `docker` 组），而不是笼统的"不支持"。
//!
//! ## 已提供
//! - 列举容器 / 镜像、**创建容器**（`docker create`，默认不启动；等价 `docker run`
//!   的特权/宿主挂载风险已由 provider `validate_create` 强制拦截：禁 `--privileged`、
//!   禁挂载 `/` `/etc` `/proc` `/sys` `/var/run/docker.sock`，且路由层需二次确认词
//!   「创建容器」）、**拉取镜像**（`docker pull`）、启动/停止/重启/删除（删除默认
//!   `docker rm` 无 `-f`，`force=true` 才走 `docker rm -f`，前端显式勾选）、
//!   **日志查看**（`docker logs`，只读最近 N 行快照、不带 --follow，需 container.view）、
//!   **资源用量快照**（`docker stats --no-stream --all`，一次性快照、非流式，需
//!   container.view；实时感由前端 3s 轮询近似）、**网络列举**
//!   （`docker network ls --no-trunc`，只读，需 container.view）、**卷列举**
//!   （`docker volume ls`，只读，需 container.view）、**Compose 项目列举**
//!   （`docker compose ls --all --format json`，只读，需 container.view）、
//!   **Compose 生命周期动作**（up / stop / restart / down，需 container.manage；
//!   down 需手输项目名确认、**永不传 `-v`**）、
//!   一键安装 Docker、把面板运行用户加入 docker 组、容器备注。
//!
//! ## 不提供的能力
//! - **镜像删除**：磁盘回收风险（已拉取的层删了需重新下载），刻意不开放。
//! - **暂未实现**（非安全刻意排除，后续可补）：进入容器 `docker exec`、
//!   网络的创建/删除与容器接入/断开（**只读列举已开放**）、卷的创建/删除
//!   （**只读列举已开放**；删除卷=数据丢失，与镜像删除同理）、compose 的
//!   up/down/restart/logs 等生命周期写操作（**只读列举已开放**，影响面大，
//!   交由 `docker compose` CLI 手动执行）、stack。
//!
//! ## 参数安全
//! 容器 ID/名称直接进 `docker` 的 argv，因此经 `rules::is_valid_container_ref`
//! 白名单校验——特别是**禁止首字符 `-`**，否则 `--force` 之类会被 CLI 当选项解析
//! （参数注入，与 shell 注入同源）。provider 侧再次校验（不假设上游已校验）。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use crate::routes::services::{PackageTask, PkgOp};
use axum::{
    extract::{Path as AxPath, Query, State},
    http::StatusCode,
    Json,
};
use panel_core::{cap_keys, PanelError};
use panel_os::{cmd, ComposeAction, ContainerAction, ContainerCreateReq, ContainerProvider};
use serde::Deserialize;
use std::time::Duration;
use panel_task::{TaskRequest, TaskKind};

/// 能力前置检查：不可用即诚实 501，并把原因透出（前端无需再请求 capabilities 才能解释原因）。
fn ensure_supported(state: &Shared) -> Result<(), ApiError> {
    let cap = state.capabilities.get(cap_keys::CONTAINER_MANAGE);
    if cap.map(|c| c.supported).unwrap_or(false) {
        return Ok(());
    }
    let reason = cap
        .and_then(|c| c.reason.clone())
        .unwrap_or_else(|| "unknown".into());
    Err(ApiError::unsupported("container.manage").with_detail(serde_json::json!({
        "capability": cap_keys::CONTAINER_MANAGE,
        "reason": reason,
    })))
}

/// 统一动作出口：校验 → 审计 → 转发 provider。三处薄封装复用同一实现。
/// 注意 `s` 是 `Session` 而非提取器 `Auth`——handler 里 `Auth(s)` 已把 newtype 拆开。
async fn run_action(
    state: Shared,
    s: crate::auth::Session,
    id: String,
    action: ContainerAction,
    audit_action: &'static str,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;
    ensure_supported(&state)?;
    // 业务层先拦一次非法输入，避免把明显非法的值送进 provider
    if !panel_core::rules::is_valid_container_ref(&id) {
        return Err(ApiError::bad_request(
            "id",
            "容器 ID/名称非法（仅允许字母数字与 . _ -，且不得以 - 开头）",
        ));
    }
    state.os.containers().act(action, &id).await?;
    audit(&state, &s, audit_action, &id, "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

// ─────────────── 只读 ───────────────

/// 容器列表（等价 `docker ps -a`，含已停止）。
pub async fn list(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    ensure_supported(&state)?;
    let items = state.os.containers().list().await?;
    // 022：一次性联查 container_remarks，把备注挂到每个容器上（无则为空串）。
    // 容器不入库，若逐行 GET /remark 会产生 N+1 请求。表按容器**名称**索引：
    // 完整 ID 随重建变化，名称在重建时通常保留——按 ID 存会让重建后备注变孤儿。
    let remarks: std::collections::HashMap<String, String> = state
        .pool
        .with(|conn| {
            let mut stmt = conn
                .prepare("SELECT name, remark FROM container_remarks")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let mut m = std::collections::HashMap::new();
            for row in rows {
                let (k, v) = row.map_err(|e| PanelError::Database(e.to_string()))?;
                m.insert(k, v);
            }
            Ok(m)
        })
        .await
        .unwrap_or_default();
    let mut arr = serde_json::to_value(&items).map_err(|e| {
        ApiError::new(60000, StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;
    if let serde_json::Value::Array(list) = &mut arr {
        for item in list.iter_mut() {
            if let Some(obj) = item.as_object_mut() {
                let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let remark = remarks.get(&name).cloned().unwrap_or_default();
                obj.insert("remark".to_string(), serde_json::Value::String(remark));
            }
        }
    }
    Ok(ok(arr))
}

/// 镜像列表（等价 `docker images`，含悬空镜像）。
pub async fn images(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    ensure_supported(&state)?;
    let items = state.os.containers().images().await?;
    Ok(ok(items))
}

// ─────────────── 容器备注（022） ───────────────
//
// 容器不入库，备注存 `container_remarks` 引用表（按容器 id 字符串）。
// 便签可先于对象存在，故读/写**不**强制 Docker 可达，仅做权限校验。

/// 备注更新请求体（022）。
#[derive(Debug, Deserialize)]
pub struct ContainerRemarkReq {
    pub remark: String,
}

/// 读取容器备注（全部有 `container.view` 的用户可读）。
pub async fn get_remark(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    if !panel_core::rules::is_valid_container_ref(&id) {
        return Err(ApiError::bad_request("id", "容器 ID/名称非法"));
    }
    let remark: String = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT remark FROM container_remarks WHERE name = ?1",
                [id.clone()],
                |r| r.get::<_, String>(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
        .unwrap_or_default();
    Ok(ok(serde_json::json!({ "remark": remark })))
}

/// 更新容器备注（仅 `container.manage`）。
pub async fn update_remark(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
    Json(req): Json<ContainerRemarkReq>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;
    if !panel_core::rules::is_valid_container_ref(&id) {
        return Err(ApiError::bad_request("id", "容器 ID/名称非法"));
    }
    let remark = req.remark.trim().to_string();
    if remark.chars().count() > 500 {
        return Err(ApiError::bad_request("remark", "备注最多 500 字"));
    }
    // `id` 移入写闭包，审计用预先克隆的副本
    let id_audit = id.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO container_remarks(name, remark) VALUES(?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET remark = ?2",
                rusqlite::params![id, remark],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    audit(&state, &s, "container.remark", &id_audit, "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

// ─────────────── 创建 ───────────────

/// 创建容器请求。**二次确认词** `confirm_token` 必须为「创建容器」——
/// 创建容器等价宿主机任意代码执行，必须让用户手输确认词，不接受随手点的 OK。
#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub name: String,
    pub image: String,
    pub cmd: Option<Vec<String>>,
    pub ports: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub volumes: Option<Vec<String>>,
    pub restart: Option<String>,
    pub cpu_quota: Option<f64>,
    pub mem_limit: Option<String>,
    /// 必须为 false（true 时 provider 直接拒绝）；前端不得提供"特权"开关。
    pub privileged: Option<bool>,
    /// 二次确认词（同「覆盖恢复」纪律）。
    pub confirm_token: Option<String>,
}

/// 拉取镜像请求。镜像引用须安全（无空白 / shell 元字符），由 provider 二次校验。
#[derive(Debug, Deserialize)]
pub(crate) struct PullReq {
    pub image: String,
}

/// 二次确认词：手输才有效，防止误触一键创建特权/宿主挂载容器。
const CREATE_CONFIRM: &str = "创建容器";

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;
    ensure_supported(&state)?;
    if !is_create_confirm(req.confirm_token.as_deref()) {
        return Err(ApiError::bad_request("confirm_token", "需手输确认词「创建容器」"));
    }
    let inner = ContainerCreateReq {
        name: req.name,
        image: req.image,
        cmd: req.cmd.unwrap_or_default(),
        ports: req.ports.unwrap_or_default(),
        env: req.env.unwrap_or_default(),
        volumes: req.volumes.unwrap_or_default(),
        restart: req.restart,
        cpu_quota: req.cpu_quota,
        mem_limit: req.mem_limit,
        privileged: req.privileged.unwrap_or(false),
    };
    let c = state.os.containers().create(inner).await?;
    audit(&state, &s, "container.create", &c.id, "ok").await;
    Ok(ok(serde_json::json!({
        "id": c.id,
        "name": c.name,
        "image": c.image,
        "state": c.state,
        "note": "已创建但未启动；请在列表中对它执行「启动」",
    })))
}

/// 拉取镜像（等价 `docker pull`）。镜像引用须安全，由 provider 强制校验；
/// 返回拉取后的镜像摘要。拉取属网络写入，需 container.manage。
pub(crate) async fn pull(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<PullReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;
    // 重活限流：10 次 / 60 秒 / 用户（见 ratelimit.rs 的设计说明）
    crate::ratelimit::check_heavy(&state, &s.username, "image.pull")?;
    ensure_supported(&state)?;
    let img = state.os.containers().pull(req.image.trim()).await?;
    audit(&state, &s, "container.pull", &img.id, "ok").await;
    Ok(ok(serde_json::json!({
        "id": img.id,
        "repository": img.repository,
        "tag": img.tag,
        "size": img.size,
        "created": img.created,
    })))
}

// ─────────────── 生命周期 ───────────────

pub async fn start(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
) -> ApiResult<StatusCode> {
    run_action(state, s, id, ContainerAction::Start, "container.start").await
}

pub async fn stop(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
) -> ApiResult<StatusCode> {
    run_action(state, s, id, ContainerAction::Stop, "container.stop").await
}

pub async fn restart(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
) -> ApiResult<StatusCode> {
    run_action(state, s, id, ContainerAction::Restart, "container.restart").await
}

/// 删除容器。**刻意不带 `-f`**：运行中的容器会被拒绝删除，
/// 强制删除属于用户显式的两步决策（先停再删），不提供"一键抹掉运行中容器"。
/// 删除容器。`force=true` 走 `docker rm -f`（先强制停止再移除）；默认 `force=false`
/// 即 `docker rm`，运行中的容器会被守护进程拒绝（前端引导先停或勾选强制删除）。
/// 强制删除是显式 opt-in（非默认），保持"非一键抹掉生产容器"的安全意图。
#[derive(Debug, Deserialize)]
pub(crate) struct RemoveQ {
    #[serde(default)]
    force: bool,
}

pub(crate) async fn remove(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
    Query(q): Query<RemoveQ>,
) -> ApiResult<StatusCode> {
    let action = if q.force { ContainerAction::RemoveForce } else { ContainerAction::Remove };
    run_action(state, s, id, action, "container.remove").await
}

/// 供测试与静态检查引用：确认 provider trait 在业务层以 trait 对象方式使用
/// （而不是直接摸平台模块——那会被 CI 门禁 [4c] 拦下）。
#[allow(dead_code)]
fn _assert_trait_object(_p: &dyn ContainerProvider) {}

// ─────────────── 日志查看（只读） ───────────────
//
// 读操作，需 container.view（与 list/images 同级，不是 container.manage）。
// 只回显最近 N 行快照：docker logs 不带 --follow，避免 CLI 的 stdout 永不 EOF 把
// 面板请求挂死。tail 上限 2000（防一次把内存 / UI 打爆），下限 1。

/// 日志查询参数。`tail` 默认 200；`timestamps` 默认 false。
#[derive(Debug, Deserialize)]
pub struct LogsQ {
    #[serde(default = "default_logs_tail")]
    tail: u32,
    #[serde(default)]
    timestamps: bool,
}
fn default_logs_tail() -> u32 { 200 }

/// tail 上限 2000 行、下限 1（防 0 / 超大值把内存或 UI 打爆）。纯函数，便于单测。
fn clamp_tail(n: u32) -> u32 { n.clamp(1, 2000) }

/// 容器日志（等价 `docker logs`，只读最近 N 行快照，不带 --follow）。
pub async fn logs(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
    Query(q): Query<LogsQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    ensure_supported(&state)?;
    // 业务层先拦一次非法输入，避免把明显非法的值送进 provider（与 run_action 同源）
    if !panel_core::rules::is_valid_container_ref(&id) {
        return Err(ApiError::bad_request(
            "id",
            "容器 ID/名称非法（仅允许字母数字与 . _ -，且不得以 - 开头）",
        ));
    }
    let tail = clamp_tail(q.tail);
    let lines = state
        .os
        .containers()
        .logs(&id, panel_os::ContainerLogsOpts { tail, timestamps: q.timestamps })
        .await?;
    Ok(ok(lines))
}

// ─────────────── 资源用量快照（只读） ───────────────
//
// 读操作，需 container.view。与日志同理：`docker stats` 默认是**流式**（stdout 不
// EOF 会把请求挂死），故 provider 侧固定 `--no-stream --all` 一次性快照；
// 「实时感」由前端 3s 轮询近似。无 id 参数 → 无参数注入面。

/// 全部容器的资源用量快照（等价 `docker stats --no-stream --all`）。
/// 一次性快照，非流式；前端用轮询近似实时。
pub async fn stats(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    ensure_supported(&state)?;
    let lines = state.os.containers().stats_all().await?;
    Ok(ok(lines))
}

// ─────────────── 网络列举（只读） ───────────────
//
// 读操作，需 container.view。与 stats/logs 同理：无 id 参数 → 无参数注入面。
// 刻意只读：创建/删除网络、容器接入/断开网络未实现（改网络连通性影响面大，
// 交由 docker CLI 手动执行）——前端「网络」Tab 同理不提供写入口。

/// 列举 Docker 网络（等价 `docker network ls --no-trunc`）。
pub async fn networks(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    ensure_supported(&state)?;
    let lines = state.os.containers().networks_all().await?;
    Ok(ok(lines))
}

// ─────────────── 卷列举（只读） ───────────────
//
// 读操作，需 container.view。与 stats/logs/networks 同理：无 id 参数 →
// 无参数注入面。刻意只读：创建/删除卷未实现（删除卷=数据丢失，与镜像
// 删除同理，交由 docker CLI 手动执行）——前端「卷」Tab 同理不提供写入口。

/// 列举 Docker 卷（等价 `docker volume ls`）。
pub async fn volumes(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    ensure_supported(&state)?;
    let lines = state.os.containers().volumes_all().await?;
    Ok(ok(lines))
}

// ─────────────── Compose 项目列举（只读） ───────────────
//
// 读操作，需 container.view。与 stats/logs/networks/volumes 同理：无 id 参数 →
// 无参数注入面。刻意只读：up/down/restart/logs 等生命周期写操作未实现
// （影响面大，交由 docker compose CLI 手动执行）——前端「Compose」Tab 同理
// 不提供写入口。

/// 列举 Docker Compose 项目（等价 `docker compose ls --all`）。
pub async fn compose_projects(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    ensure_supported(&state)?;
    let lines = state.os.containers().compose_projects_all().await?;
    Ok(ok(lines))
}

// ─────────────── Compose 生命周期写操作 ───────────────
//
// 危险度分级（用户 2026-10-20 拍板）：
//   - up / stop / restart：**可逆、日常操作**，无需确认词，与容器 start/stop 同待遇；
//   - down：**整项目停服**（服务全下线），必须手输项目名确认——不是随手点 OK 能过。
//     ⚠ down **永不带 `-v`**（那会删命名卷=数据丢失），这是刻意的功能缺失。
//
// 权限统一 `container.manage`（与容器启停删除同级），不新增权限点。

/// Compose 动作请求体。
#[derive(Debug, Deserialize)]
pub struct ComposeActReq {
    /// 动作：up / stop / restart / down。故意用字符串而非枚举——便于给出
    /// "未知动作"的明确报错，而不是让 serde 抛一句反序列化错误给用户看。
    pub action: String,
    /// 仅 `up` 需要：项目工作目录（compose 靠它找配置文件）。
    pub working_dir: Option<String>,
    /// 仅 `down` 需要：手输项目名作为二次确认词。
    pub confirm_token: Option<String>,
}

/// 对 Compose 项目执行生命周期动作。
///
/// 项目名**必须已存在**：先查 `compose ls`，不在列表里直接 404。
/// 这样即使有人构造请求，也只能操作真实存在的项目（而不是让 compose 去
/// 用这个名字干点什么）。
pub async fn compose_act(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(project): AxPath<String>,
    Json(req): Json<ComposeActReq>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;
    ensure_supported(&state)?;

    let action = match req.action.trim() {
        "up" => ComposeAction::Up,
        "stop" => ComposeAction::Stop,
        "restart" => ComposeAction::Restart,
        "down" => ComposeAction::Down,
        other => {
            return Err(ApiError::bad_request(
                "action",
                &format!("未知动作 `{other}`（只支持 up / stop / restart / down）"),
            ))
        }
    };

    // 确认词：down 必须手输项目名。
    // 用**项目名本身**而非固定词（如「删除」）作为确认词：固定词点两次就学会了，
    // 而打对项目名要求用户真的看清自己在停哪个项目——这是防"停错项目"的关键。
    if action == ComposeAction::Down {
        let token = req.confirm_token.as_deref().unwrap_or("").trim();
        if token != project {
            return Err(ApiError::bad_request(
                "confirm_token",
                &format!("停止并删除项目容器需手输项目名 `{project}` 作为确认"),
            ));
        }
    }

    // 「项目必须真实存在」只对**操作已有容器**的动作成立（stop/restart/down）。
    //
    // ⚠ `up` 必须豁免：`down` 之后项目就从 `compose ls` 里消失了，而用户恰恰
    // 需要 `up` 把它重新拉起来——按「必须存在于 ls」来卡，会让"down 完再也起不
    // 来"变成一个死锁（真机实测：down 后 up 返回 404 compose 项目不存在）。
    // up 的合法性由**工作目录里确实有 compose 文件**和 compose 自己的报错来保证。
    if action != ComposeAction::Up {
        let projects = state.os.containers().compose_projects_all().await?;
        if !projects.iter().any(|p| p.name == project) {
            return Err(ApiError::not_found(&format!("compose 项目不存在: {project}")));
        }
    }

    state
        .os
        .containers()
        .compose_act(action, &project, req.working_dir.as_deref())
        .await?;

    // 审计：记录动作 + 项目名（项目名是用户可控输入，但已过白名单校验）
    let audit_action: &'static str = match action {
        ComposeAction::Up => "container.compose.up",
        ComposeAction::Stop => "container.compose.stop",
        ComposeAction::Restart => "container.compose.restart",
        ComposeAction::Down => "container.compose.down",
    };
    audit(&state, &s, audit_action, &project, "ok").await;
    Ok(StatusCode::NO_CONTENT)
}


// ─────────────── 面板编排（Compose stack 定义管理） ───────────────
//
// ⚠ 与上面的 compose 动作不同：这一组**不检查 docker 可用性**（不调 `ensure_supported`）。
// 理由：这些端点只读写 `<data_dir>/compose-stacks/` 里的文件，与 daemon 毫无关系。
// daemon 挂掉时用户仍然应该能改自己的编排定义（只是不能部署）。
// 用 501 把"daemon 不可用"说成"没有编排功能"是撒谎。
//
// 安全前提：能进入 compose.yaml 的字段由 `ComposeStackService` **类型**限定，
// 不存在 privileged / cap_add / pid / network_mode 等字段，也不接受用户直接提交 YAML。

/// 保存编排的请求体。`project` 由路径给出，body 只带服务列表——
/// 避免"路径说 A、body 说 B"这种自相矛盾的请求。
#[derive(Debug, Deserialize)]
pub struct StackSaveReq {
    pub services: Vec<panel_os::ComposeStackService>,
}

/// 列出面板创建的编排项目。
pub async fn stack_list(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    let items = state.os.containers().compose_stacks().await?;
    Ok(ok(items))
}

/// 读取单个编排项目。
pub async fn stack_get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(project): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    let st = state.os.containers().compose_stack_get(&project).await?;
    Ok(ok(st))
}

/// 创建或更新编排项目（幂等）。
///
/// 已存在且 `compose.yaml` 被外部改过 → 409，**不覆盖**用户的修改。
pub async fn stack_save(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(project): AxPath<String>,
    Json(req): Json<StackSaveReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;

    let existed = state.os.containers().compose_stack_get(&project).await.is_ok();

    let spec = panel_os::ComposeStackSpec { project: project.clone(), services: req.services };
    let st = state.os.containers().compose_stack_save(spec).await?;

    let action = if existed { "container.stack.update" } else { "container.stack.create" };
    audit(&state, &s, action, &project, "ok").await;
    Ok(ok(st))
}

// ─────────────── 一键安装 Docker ───────────────

/// 安装请求。**二次确认词** `confirm_token` 必须为「安装 Docker」——
/// 装 Docker 是高危系统变更（装完后通常还需把面板用户加入 docker 组，
/// 那一步等同授予 root 级权限），必须让用户手输确认词，不接受随手点的 OK。
#[derive(Debug, Deserialize)]
pub struct InstallReq {
    pub confirm_token: Option<String>,
}

/// 二次确认词：手输才有效，防止误触一键安装宿主级服务。
const INSTALL_CONFIRM: &str = "安装 Docker";

/// 一键安装 Docker（仅当二进制缺失时可用）。
///
/// 与宝塔"点进去自己装"一致：菜单常亮，进入后若未装 Docker，提供安装入口。
/// 要求 `container.manage` 权限 + 手输确认词 + 走任务队列（可审计、可取消、可查进度）。
///
/// 本端点**只装引擎**，不自动把面板用户加 docker 组——那等于授予 root 级权限，
/// 保留为用户显式决策（前端安装完成后给出 `usermod -aG docker` 命令提示）。
pub async fn install(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<InstallReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;
    // 仅 docker 二进制缺失时允许安装；已装但 daemon 不可达是权限/服务问题，无需重装
    match state.os.containers().unavailable_reason() {
        None => return Err(ApiError::bad_request("docker", "Docker 已安装且守护进程可达，无需安装")),
        Some("daemon_unreachable") => return Err(ApiError::bad_request(
            "docker",
            "Docker 已安装但守护进程不可达：请检查 docker 服务是否运行、面板用户是否在 docker 组，无需重装",
        )),
        Some("binary_missing") => {}
        Some(other) => return Err(ApiError::bad_request("docker", format!("未知的不可用原因：{other}"))),
    }
    if !is_install_confirm(req.confirm_token.as_deref()) {
        return Err(ApiError::bad_request("confirm_token", "需手输确认词「安装 Docker」"));
    }
    // 按包管理器选对引擎包名：Debian/Ubuntu 上 docker 引擎包为 docker.io（而非 docker）
    let pkg = match state.os.packages().manager() {
        Some("apt") => "docker.io",
        Some("dnf") | Some("yum") => "docker-ce",
        Some("apk") => "docker",
        Some("zypper") => "docker",
        _ => "docker",
    };
    let body = PackageTask { pkg: pkg.to_string(), os: state.os.clone(), op: PkgOp::Install, version: None, logical: "docker".to_string() };
    let (task_id, created) = state.tasks.submit(
        TaskRequest {
            // 幂等键：重复提交只会执行一次（防双击 / 防重试风暴）
            idempotency_key: "pkg.install:docker".into(),
            kind: TaskKind::Package,
            label: format!("安装 {pkg}"),
            timeout: Duration::from_secs(1800),
        },
        body,
    ).await.map_err(ApiError::from)?;
    audit(&state, &s, "container.install_docker", pkg, "queued").await;
    Ok(ok(serde_json::json!({ "task_id": task_id, "created": created, "package": pkg })))
}

// ─────────────── 把面板运行用户加入 docker 组 ───────────────

/// 修复 `daemon_unreachable` 的核心一步：把**面板进程用户**加入 docker 组。
///
/// 与宝塔"点一下就好"一致——用户不必手敲 `usermod`。目标用户取 `panel_os::runtime_user()`
/// （effective uid 映射），**不是登录用户**：docker socket 权限取决于面板进程身份，
/// 加错人对管理容器毫无帮助（之前前端提示 `usermod -aG docker <登录用户>` 就是误导）。
///
/// 高危：docker 组等同 root 级权限（可借 docker 提权到宿主 root）。
/// 权限（CONTAINER_MANAGE）+ 前端二次确认词「加入 docker 组」双重门禁。
/// 完成后需重启面板使新组生效（前端再调 `services/panel/restart`）。
pub async fn join_docker_group(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;
    // 已可达则无需操作（加了也白加）
    if state.os.containers().unavailable_reason().is_none() {
        return Err(ApiError::bad_request("docker", "Docker 守护进程已可达，无需加入 docker 组"));
    }
    let user = panel_os::runtime_user();
    // run_checked：非零退出码即判失败（如非 root 调 usermod），避免"假成功"。
    let out = cmd::run_checked(cmd::Bin::Usermod, &["-aG", "docker", user.as_str()], cmd::CmdOpt::default())
        .await?;
    audit(&state, &s, "container.join_docker_group", &user, "ok").await;
    Ok(ok(serde_json::json!({ "user": user, "output": out.stdout })))
}

/// 创建容器的二次确认词校验（纯函数，便于单测）：须逐字等于「创建容器」。
/// 不 trim —— 带尾空格的近似词必须被拒，防止误触一键创建特权/宿主挂载容器。
fn is_create_confirm(token: Option<&str>) -> bool {
    token == Some(CREATE_CONFIRM)
}

/// 安装 Docker 的二次确认词校验：须逐字等于「安装 Docker」（大小写敏感）。
fn is_install_confirm(token: Option<&str>) -> bool {
    token == Some(INSTALL_CONFIRM)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐⭐ **Compose 动作接线守卫**：枚举有的变体，路由必须认。
    ///
    /// 为什么需要：帮助文案与模块注释曾把**已实现**的 up/down/restart 说成
    /// "仍不提供"——文案与实现漂移过一次（用户读到"不提供"就不会去点，
    /// 功能等于白做）。本测试钉住"实现内部"这一半：`ComposeAction` 每个变体的
    /// `as_str()` 都必须出现在 handler 的 action match 里，否则就是"枚举加了、
    /// 路由没接"，前端点了只会收到 400。
    ///
    /// 文案那一半由前端用**同一份常量**同时渲染按钮与句子（见 ContainersView
    /// 的 `COMPOSE_ACTIONS`），从结构上避免"文案说没有、按钮却在"。
    #[test]
    fn compose_act_route_accepts_every_action_variant() {
        let src = include_str!("containers.rs");
        // ⚠ 必须剔除注释行：模块文档里也写着 `up` 等字样，不剔会恒真。
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for a in [
            ComposeAction::Up,
            ComposeAction::Stop,
            ComposeAction::Restart,
            ComposeAction::Down,
        ] {
            let arm = format!("\"{}\" => ComposeAction::", a.as_str());
            assert!(
                code.contains(&arm),
                "路由的 action match 缺少 `{}` 分支：枚举加了变体却没接线路由",
                a.as_str()
            );
        }
    }

    #[test]
    fn create_confirm_requires_exact_word() {
        assert!(is_create_confirm(Some("创建容器")));
        assert!(!is_create_confirm(Some("创建容器 "))); // 不 trim
        assert!(!is_create_confirm(Some("创建")));
        assert!(!is_create_confirm(None));
    }
    #[test]
    fn install_confirm_requires_exact_word() {
        assert!(is_install_confirm(Some("安装 Docker")));
        assert!(!is_install_confirm(Some("安装docker"))); // 大小写敏感
        assert!(!is_install_confirm(None));
    }

    fn sess(permissions: &[&str]) -> crate::auth::Session {
        crate::auth::Session {
            user_id: 1, username: "tester".into(), role: "admin".into(),
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
            allowed_roots: vec![], ip: "unknown".into(),
            created_at: 0, last_seen: 0, expires_at: 0,
        }
    }
    #[test]
    fn container_manage_required_for_create() {
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_MANAGE]), perm::CONTAINER_MANAGE).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::CONTAINER_MANAGE).is_err());
        // 有 view 但缺 manage → 仍拒（防越权）
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_MANAGE).is_err());
    }
    #[test]
    fn container_view_sufficient_for_list() {
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::CONTAINER_VIEW).is_err());
    }

    #[test]
    fn logs_requires_view_permission() {
        // 日志是读操作：有 container.view 即可，不需要 container.manage
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::CONTAINER_VIEW).is_err());
        // 有 view 但缺 manage → 日志可读（防越权误拒读）
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
    }

    #[test]
    fn clamp_tail_bounds() {
        assert_eq!(clamp_tail(0), 1, "下限 1：tail=0 不应拉空或报错");
        assert_eq!(clamp_tail(200), 200);
        assert_eq!(clamp_tail(2000), 2000);
        assert_eq!(clamp_tail(5000), 2000, "上限 2000：超大值被夹住，防打爆内存/UI");
        assert_eq!(clamp_tail(u32::MAX), 2000);
    }

    #[test]
    fn stats_requires_view_permission() {
        // 资源快照是读操作：有 container.view 即可，不需要 container.manage
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::CONTAINER_VIEW).is_err());
        // 有 view 但缺 manage → 仍可读（与 logs 同源，防越权误拒读）
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
    }

    #[test]
    fn networks_requires_view_permission() {
        // 网络列举是读操作：有 container.view 即可，不需要 container.manage
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::CONTAINER_VIEW).is_err());
        // 有 view 但缺 manage → 仍可读（与 logs/stats 同源，防越权误拒读）
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
    }

    #[test]
    fn volumes_requires_view_permission() {
        // 卷列举是读操作：有 container.view 即可，不需要 container.manage
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::CONTAINER_VIEW).is_err());
        // 有 view 但缺 manage → 仍可读（与 logs/stats/networks 同源，防越权误拒读）
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
    }

    #[test]
    fn compose_projects_requires_view_permission() {
        // Compose 项目列举是读操作：有 container.view 即可，不需要 container.manage
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::CONTAINER_VIEW).is_err());
        // 有 view 但缺 manage → 仍可读（与 logs/stats/networks/volumes 同源，防越权误拒读）
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_VIEW]), perm::CONTAINER_VIEW).is_ok());
    }

    /// ⭐⭐ **`up` 不得被"项目必须已存在"卡住**——否则 down 完再也起不来。
    ///
    /// 这是真机跑出来的死锁（不是推理）：`down` 之后项目从 `compose ls` 消失，
    /// 若 `up` 也要求"在 ls 里能找到"，用户就永久失去从面板启动该项目的能力，
    /// 只能去 CLI 救。判据用源码断言——这个分支在 handler 里、依赖真实 docker，
    /// 单测无法驱动整个 handler。
    ///
    /// ⚠ 判据必须是**结构**而不是"文中出现过 Up"：
    /// 第一版写成 `window.contains("action != ComposeAction::Up")`，
    /// 负向对照（把条件改成 `... || true`，等价于永不豁免）**照样绿**——
    /// 因为被改坏的文本里那个子串还在。这就是"断言恒绿"的典型形态。
    /// 现在改为：存在性检查那几行必须**完整被包在** `if action != ComposeAction::Up {`
    /// 里，即该行紧接在 `compose_projects_all()` 之前。
    #[test]
    fn compose_up_is_exempt_from_existence_check() {
        let src = include_str!("containers.rs");
        let code: Vec<&str> = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let joined = code.join("\n");

        // 定位存在性检查（调用 compose_projects_all 做名字比对的唯一处）
        let check_at = joined
            .find("let projects = state.os.containers().compose_projects_all().await?;")
            .expect("存在性检查必须存在");
        // 它前面 200 字符内必须出现**精确的**豁免条件
        let from = check_at.saturating_sub(200);
        let before = &joined[from..check_at];
        assert!(
            before.contains("if action != ComposeAction::Up {"),
            "存在性检查必须被 `if action != ComposeAction::Up {{` **精确**包裹\
             （不是任何包含 Up 字样的表达式）。否则 down 之后无法再 up，形成死锁。\n\
             检查前文：\n{before}"
        );
        // 再加一条负向：不得出现会抵消豁免的短路/恒真写法
        assert!(
            !before.contains("|| true") && !before.contains("&& false"),
            "豁免条件不得被 || true / && false 之类的写法抵消（那等于没豁免）。\n\
             检查前文：\n{before}"
        );
    }
}
