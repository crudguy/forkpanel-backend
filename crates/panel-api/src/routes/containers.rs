//! 容器管理（Docker）——**只读列举 + 生命周期**。
//!
//! ## 能力门禁（本模块的核心纪律）
//! `container.manage` 能力位由 `panel-os` 按 **daemon socket 可达性** 判定
//! （不是二进制存在性）。本模块所有端点前置检查该能力位；不满足时返回
//! **诚实 501**，并在 `detail` 里带上 `reason`，让前端能直接给出可操作提示
//! （`binary_missing` → 装 Docker；`daemon_unreachable` → 启动 daemon 或把面板
//! 用户加入 `docker` 组），而不是笼统的"不支持"。
//!
//! ## 不提供的能力（刻意）
//! - **创建容器（`docker run`）**：等价宿主机任意代码执行（镜像 / 挂载宿主 / 特权 / 端口），
//!   必须配套独立的镜像白名单、禁止特权与宿主挂载、资源配额设计，以及二次确认。
//!   顺手加一个 `run` 接口是**安全债**，故不在本期范围。
//! - **镜像删除 / 拉取**：写操作面（含 registry 凭据与磁盘占用），后续单列。
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
    extract::{Path as AxPath, State},
    http::StatusCode,
    Json,
};
use panel_core::cap_keys;
use panel_os::{cmd, ContainerAction, ContainerCreateReq, ContainerProvider};
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
    Ok(ok(items))
}

/// 镜像列表（等价 `docker images`，含悬空镜像）。
pub async fn images(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_VIEW)?;
    ensure_supported(&state)?;
    let items = state.os.containers().images().await?;
    Ok(ok(items))
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

/// 二次确认词：手输才有效，防止误触一键创建特权/宿主挂载容器。
const CREATE_CONFIRM: &str = "创建容器";

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CONTAINER_MANAGE)?;
    ensure_supported(&state)?;
    if req.confirm_token.as_deref() != Some(CREATE_CONFIRM) {
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
pub async fn remove(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
) -> ApiResult<StatusCode> {
    run_action(state, s, id, ContainerAction::Remove, "container.remove").await
}

/// 供测试与静态检查引用：确认 provider trait 在业务层以 trait 对象方式使用
/// （而不是直接摸平台模块——那会被 CI 门禁 [4c] 拦下）。
#[allow(dead_code)]
fn _assert_trait_object(_p: &dyn ContainerProvider) {}

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
    if req.confirm_token.as_deref() != Some(INSTALL_CONFIRM) {
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
