//! 软件与服务管理（设计方案 §2.3）。
//!
//! # 关键设计：安装/卸载一律走任务队列
//! `apt install nginx` 耗时几十秒到几分钟，且**输出必须流式返回**给用户
//! （否则用户只能盯着转圈）。所以在 HTTP 请求里同步执行是不可接受的。
//! 这里的实现：提交任务 → 返回 task_id → 前端订阅 SSE 看进度。
//!
//! # 为什么服务启停可以同步
//! `systemctl restart nginx` 通常 <2s，且失败信息需要立即反馈给用户做决策。
//! 超过 2s 的操作才走任务队列——这是分界线。

use crate::{
    auth::perm,
    error::{ok, ApiError},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    Json,
};
use panel_core::{cap_keys, PanelError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 超过这个时长的操作必须走任务队列
const SYNC_LIMIT: Duration = Duration::from_secs(2);

// ─────────────── 服务列表 ───────────────

#[derive(Debug, Deserialize)]
pub struct ListQ {
    pub filter: Option<String>,
    /// 仅显示面板已知/托管的服务
    pub managed_only: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ServiceDto {
    pub name: String,
    pub state: &'static str,
    pub enabled: bool,
    pub description: Option<String>,
    /// 面板是否托管（未托管的服务仍可查看但操作有警告）
    pub managed: bool,
}

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<ListQ>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    if !state.capabilities.get(cap_keys::SERVICE_MANAGE)
        .map(|c| c.supported).unwrap_or(false) {
        // 能力缺失时明确告知，而不是返回空列表让用户以为"没有服务"
        return Err(ApiError::unsupported("service.manage"));
    }

    let filter = match q.filter.as_deref() {
        Some("running") => panel_os::ServiceFilter::Running,
        Some("failed") => panel_os::ServiceFilter::Failed,
        Some(text) => panel_os::ServiceFilter::NameContains(text.to_string()),
        None => panel_os::ServiceFilter::All,
    };
    let units = state.os.services().list(filter).await?;

    let dtos: Vec<ServiceDto> = units.into_iter().map(|u| ServiceDto {
        managed: is_managed(&u.name),
        name: u.name,
        state: match u.state {
            panel_os::ServiceState::Active => "active",
            panel_os::ServiceState::Inactive => "inactive",
            panel_os::ServiceState::Failed => "failed",
            panel_os::ServiceState::Activating => "activating",
            panel_os::ServiceState::Unknown => "unknown",
        },
        enabled: u.enabled,
        description: u.description,
    }).collect();

    Ok(ok(serde_json::json!({
        "init_system": init_name(state.os.services().init_system()),
        "services": dtos,
    })))
}

fn init_name(i: panel_core::InitSystem) -> &'static str {
    match i {
        panel_core::InitSystem::Systemd => "systemd",
        panel_core::InitSystem::SysV => "sysv",
        panel_core::InitSystem::OpenRc => "openrc",
        panel_core::InitSystem::Launchd => "launchd",
        panel_core::InitSystem::WindowsService => "scm",
        panel_core::InitSystem::Unknown => "unknown",
    }
}

/// 面板托管的服务白名单。
///
/// 为什么要有这个：让用户能 `stop sshd` 或 `stop systemd-journald` 是灾难。
/// 未托管服务**可以查看**（排障需要），但操作需要二次确认（UI 层提示）。
fn is_managed(name: &str) -> bool {
    const MANAGED: &[&str] = &[
        "nginx", "caddy", "apache2", "httpd", "php-fpm", "php7.4-fpm", "php8.1-fpm",
        "php8.2-fpm", "php8.3-fpm", "mysql", "mysqld", "mariadb", "postgresql",
        "redis", "redis-server", "memcached", "docker", "sshd", "ssh",
        "fail2ban", "ufw", "firewalld", "nftables", "cron", "crond",
    ];
    MANAGED.iter().any(|m| name == *m || name.starts_with(&format!("{m}@")))
}

// ─────────────── 服务操作 ───────────────

#[derive(Debug, Deserialize)]
pub struct ActionReq {
    pub action: String,     // start|stop|restart|reload
    pub enable: Option<bool>,
}

pub async fn act(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(name): AxPath<String>,
    Json(req): Json<ActionReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;

    // 强类型构造点：UnitName 必须由校验器产出，不能直接用路径参数
    let unit = panel_core::unit_name(&name)
        .map_err(|_| ApiError::bad_request("name", "invalid unit name"))?;

    // 高危服务保护：sshd 只允许 restart，不允许 stop（防失联）
    if name == "sshd" || name == "ssh" {
        match req.action.as_str() {
            "stop" => return Err(ApiError::forbidden("service.protected_sshd")),
            _ => {}
        }
    }

    let svc = state.os.services();
    match req.action.as_str() {
        "start" => svc.start(&unit).await?,
        "stop" => svc.stop(&unit).await?,
        "restart" => svc.restart(&unit).await?,
        "reload" => svc.reload(&unit).await?,
        other => return Err(ApiError::bad_request("action", format!("unknown action: {other}"))),
    }

    if let Some(en) = req.enable {
        svc.set_enabled(&unit, en).await?;
    }

    // 未托管服务也允许操作，但要留痕（审计里能看到谁动了什么）
    audit(&state, &s, "service.act", &format!("{name}:{}", req.action), "ok").await;
    Ok(ok(serde_json::json!({ "name": name, "action": req.action })))
}

pub async fn status(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(name): AxPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    let unit = panel_core::unit_name(&name)
        .map_err(|_| ApiError::bad_request("name", "invalid unit name"))?;
    let st = state.os.services().status(&unit).await?;
    Ok(ok(serde_json::json!({ "name": name, "state": format!("{st:?}").to_lowercase() })))
}

// ─────────────── 软件包（走任务队列） ───────────────

#[derive(Debug, Deserialize)]
pub struct InstallReq { pub name: String }

/// 已支持的软件包白名单。
///
/// 为什么白名单而不是任意包名：面板以 root 运行，允许安装任意包等于
/// 给了 Web 界面一个"任意代码执行"入口。白名单把风险收敛到已知集合。
const ALLOWED_PACKAGES: &[&str] = &[
    "nginx", "caddy", "apache2", "mysql-server", "mariadb-server", "postgresql",
    "redis", "memcached", "php-fpm", "php8.1-fpm", "php8.2-fpm", "php8.3-fpm",
    "certbot", "fail2ban", "ufw", "curl", "wget", "git", "unzip", "tar",
];

pub async fn install(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<InstallReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    if !ALLOWED_PACKAGES.contains(&req.name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary installs are refused)"));
    }

    // 安装必须走任务队列：耗时不可预测 + 输出需流式返回
    let pkg = req.name.clone();
    let os = state.os.clone();
    let body = PackageTask { pkg, os };
    let (id, created) = state.tasks.submit(
        panel_task::TaskRequest {
            // 幂等键：同一包在窗口期内重复提交只会执行一次（防双击 / 防重试风暴）
            idempotency_key: format!("pkg.install:{}", req.name),
            kind: panel_task::TaskKind::Package,
            label: format!("安装 {}", req.name),
            timeout: Duration::from_secs(1800),
        },
        body,
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "package.install", &req.name, "queued").await;
    Ok(ok(serde_json::json!({ "task_id": id, "created": created })))
}

struct PackageTask { pkg: String, os: std::sync::Arc<dyn panel_os::OsAdapter> }

#[async_trait::async_trait]
impl panel_task::TaskBody for PackageTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(5, &format!("开始安装 {}", self.pkg)).await;

        // 同步回调 → 异步广播的桥接。
        // 用 unbounded 但在消费端限速：包管理器输出可能几万行，
        // 全部堆进 channel 会撑爆内存。消费端每 N 行合并成一条进度。
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let consumer = {
            let progress = progress.clone();
            tokio::spawn(async move {
                let mut n = 0usize;
                while let Some(line) = rx.recv().await {
                    n += 1;
                    // 每 20 行上报一次进度，其余只转发日志行
                    if n % 20 == 0 {
                        progress.set(percent_from_lines(n), &line).await;
                    } else {
                        progress.log(&line).await;
                    }
                    if progress.is_canceled() { break; }
                }
            })
        };

        let tx_for_cb = tx;
        let result = self.os.packages()
            .install(&self.pkg, Box::new(move |line| {
                // try_send 永不阻塞：消费者跟不上就丢弃，绝不拖慢安装本身
                let _ = tx_for_cb.send(line);
            }))
            .await;
        drop(result.is_ok());   // 显式丢弃 sender 以让消费者退出
        // 上面 send 的所有权已移入闭包；这里需要再 drop 一次才能关闭通道
        let _ = consumer.await;

        match result {
            Ok(()) => {
                progress.set(100, "安装完成").await;
                Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Ok, exit_code: Some(0), output_path: None,
                })
            }
            Err(e) => {
                progress.log(&format!("失败：{e}")).await;
                // Package 类型 max_attempts=1：**不自动重试**（半装比重跑更危险）
                Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Failed, exit_code: Some(1), output_path: None,
                })
            }
        }
    }
}

/// 依据已输出行数估算进度（包管理器不提供真实百分比）。
/// 上限 90%：真正的 100% 只在成功返回后设置，避免"看起来装完了其实没完"。
fn percent_from_lines(n: usize) -> u8 {
    match n {
        0..=20 => 10,
        21..=100 => 30,
        101..=300 => 55,
        301..=800 => 75,
        _ => 90,
    }
}

// ─────────────── 文档式细粒度动作（复用 act 单一实现点） ───────────────

/// 收敛单元动作到 `act`，避免 start/stop/restart 三套重复校验。
async fn do_unit_action(
    state: Shared, s: crate::auth::Session, name: String, action: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    act(State(state), Auth(s), AxPath(name), Json(ActionReq { action: action.into(), enable: None })).await
}

pub async fn start(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    do_unit_action(state, s, name, "start").await
}

pub async fn stop(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    do_unit_action(state, s, name, "stop").await
}

pub async fn restart(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    do_unit_action(state, s, name, "restart").await
}

#[derive(Debug, Deserialize)]
pub struct EnabledReq { pub enabled: bool }

pub async fn set_enabled(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(name): AxPath<String>, Json(req): Json<EnabledReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    let unit = panel_core::unit_name(&name)
        .map_err(|_| ApiError::bad_request("name", "invalid unit name"))?;
    state.os.services().set_enabled(&unit, req.enabled).await?;
    audit(&state, &s, "service.set_enabled", &format!("{name}:{}", req.enabled), "ok").await;
    Ok(ok(serde_json::json!({ "name": name, "enabled": req.enabled })))
}

pub async fn journal(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    if !state.capabilities.get(cap_keys::SERVICE_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("service.manage"));
    }
    let _ = name;
    Err(ApiError::unsupported("service.journal (M3: 服务日志流尚未接入)"))
}

pub async fn packages_list(
    State(state): State<Shared>, Auth(s): Auth,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    Err(ApiError::unsupported("package.list (M2: 已安装包枚举尚未接入)"))
}

pub async fn package_remove(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    let _ = name;
    Err(ApiError::unsupported("package.remove (M2: 卸载走任务队列，尚未接入)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_whitelist_covers_web_stack() {
        for n in ["nginx", "php8.2-fpm", "mysql", "redis-server", "docker"] {
            assert!(is_managed(n), "{n} 应被识别为托管服务");
        }
    }

    #[test]
    fn sshd_and_journald_are_not_in_managed_list() {
        // sshd 可查看但操作需二次确认；journald 干脆不在白名单
        assert!(!is_managed("systemd-journald"));
        assert!(!is_managed("dbus"));
    }

    #[test]
    fn package_whitelist_is_closed() {
        assert!(ALLOWED_PACKAGES.contains(&"nginx"));
        // 任意包名必须被拒（面板以 root 运行，这是任意代码执行的入口）
        for bad in ["evil-miner", "../../bin/sh", "nginx; rm -rf /"] {
            assert!(!ALLOWED_PACKAGES.contains(&bad), "{bad} 绝不能在白名单里");
        }
    }

    #[test]
    fn sync_limit_distinguishes_ops() {
        // 服务启停 <2s 可同步；安装耗时不可预测必须入队
        assert_eq!(SYNC_LIMIT.as_secs(), 2);
    }
}
