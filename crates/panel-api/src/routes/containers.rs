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
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    Json,
};
use panel_core::cap_keys;
use panel_os::{ContainerAction, ContainerProvider};

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
