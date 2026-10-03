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
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    Json,
};
use panel_core::{cap_keys, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 超过这个时长的操作必须走任务队列。
///
/// 域规则备忘：同步接口必须秒级返回，长操作接入时以此为分流阈值；
/// 测试已锁定该值，接口落地前 `allow(dead_code)` 抑制未用告警。
#[allow(dead_code)]
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
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    if !state.capabilities.get(cap_keys::SERVICE_MANAGE)
        .map(|c| c.supported).unwrap_or(false) {
        // 能力缺失时明确告知，而不是返回空列表让用户以为"没有服务"
        return Err(ApiError::unsupported("service.manage"));
    }

    // ServiceFilter 是**结构体**（name_contains / state / only_panel_managed），不是枚举，
    // 故按字段组装；未指定的字段走 Default。
    let filter = match q.filter.as_deref() {
        Some("running") => panel_os::ServiceFilter {
            state: Some(panel_os::ServiceState::Active), ..Default::default()
        },
        Some("failed") => panel_os::ServiceFilter {
            state: Some(panel_os::ServiceState::Failed), ..Default::default()
        },
        Some(text) => panel_os::ServiceFilter {
            name_contains: Some(text.to_string()), ..Default::default()
        },
        None => panel_os::ServiceFilter::default(),
    };
    let filter = panel_os::ServiceFilter { only_panel_managed: q.managed_only.unwrap_or(false), ..filter };
    let units = state.os.services().list(filter).await?;

    let dtos: Vec<ServiceDto> = units.into_iter().map(|u| ServiceDto {
        // UnitName 是强类型标识，需 as_str() 取内部字符串
        managed: is_managed(u.name.as_str()),
        name: u.name.as_str().to_string(),
        state: match u.state {
            panel_os::ServiceState::Active => "active",
            panel_os::ServiceState::Inactive => "inactive",
            panel_os::ServiceState::Failed => "failed",
            panel_os::ServiceState::Activating => "activating",
            panel_os::ServiceState::Deactivating => "deactivating",
            panel_os::ServiceState::Unknown => "unknown",
        },
        enabled: u.enabled,
        // ServiceUnit.description 是 String，DTO 字段是 Option<String>（无描述时为 None）
        description: if u.description.is_empty() { None } else { Some(u.description) },
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
        panel_core::InitSystem::Scm => "scm",
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
) -> ApiResult<Json<serde_json::Value>> {
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
) -> ApiResult<Json<serde_json::Value>> {
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
) -> ApiResult<Json<serde_json::Value>> {
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
    let body = PackageTask { pkg, os, op: PkgOp::Install };
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

/// 安装/卸载共用同一任务体：结构一致（白名单→队列→底层），仅动词不同。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgOp { Install, Remove }

pub struct PackageTask { pub pkg: String, pub os: std::sync::Arc<dyn panel_os::OsAdapter>, pub op: PkgOp }

#[async_trait::async_trait]
impl panel_task::TaskBody for PackageTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        let installing = self.op == PkgOp::Install;
        let verb = if installing { "安装" } else { "卸载" };
        progress.set(5, &format!("开始{verb} {}", self.pkg)).await;

        // 输出缓冲：任务结束后落临时文件并经 output_path 登记，
        // 任务中心的 /tasks/{id}/output 才有内容可读（失败原因不丢）。
        // 只留尾部 MAX_BUF 行：包管理器输出可达几万行，全量落盘没必要。
        const MAX_BUF: usize = 400;
        let buf: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();

        let result: Option<String> = if installing {
            // 同步回调 → 异步广播的桥接。
            // 用 unbounded 但在消费端限速：包管理器输出可能几万行，
            // 全部堆进 channel 会撑爆内存。消费端每 N 行合并成一条进度。
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let consumer = {
                let progress = progress.clone();
                let buf = buf.clone();
                tokio::spawn(async move {
                    let mut n = 0usize;
                    while let Some(line) = rx.recv().await {
                        n += 1;
                        {
                            let mut b = buf.lock().unwrap();
                            if b.len() >= MAX_BUF { b.remove(0); }
                            b.push(line.clone());
                        }
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
            let r = self.os.packages()
                .install(&self.pkg, Box::new(move |line| {
                    // try_send 永不阻塞：消费者跟不上就丢弃，绝不拖慢安装本身
                    let _ = tx_for_cb.send(line);
                }))
                .await;
            // tx 已随上方回调闭包一起释放（闭包所有权在 install 内），通道关闭后
            // 消费者 recv() 返回 None 自然退出；这里只需等消费者收尾。
            let _ = consumer.await;
            r.err().map(|e| e.to_string())
        } else {
            // 卸载没有流式输出可桥接（remove 不带回调），失败原因原样落日志
            self.os.packages().remove(&self.pkg).await.err().map(|e| e.to_string())
        };

        if let Some(e) = &result {
            progress.log(&format!("失败：{e}")).await;
            let mut b = buf.lock().unwrap();
            if b.len() >= MAX_BUF { b.remove(0); }
            b.push(format!("失败：{e}"));
        }

        // 缓冲落盘 → 任务中心可读
        let mut output_path = None;
        let lines_snapshot: Vec<String> = buf.lock().unwrap().clone();
        if !lines_snapshot.is_empty() {
            let p = std::env::temp_dir().join(format!("panel-task-{}.log", progress.id()));
            if tokio::fs::write(&p, lines_snapshot.join("\n")).await.is_ok() {
                output_path = Some(p);
            }
        }

        match result {
            None => {
                progress.set(100, &format!("{verb}完成")).await;
                Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Ok, exit_code: Some(0), output_path,
                })
            }
            Some(_) => {
                // Package 类型 max_attempts=1：**不自动重试**（半装/半卸比重跑更危险）
                Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Failed, exit_code: Some(1), output_path,
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
) -> ApiResult<Json<serde_json::Value>> {
    act(State(state), Auth(s), AxPath(name), Json(ActionReq { action: action.into(), enable: None })).await
}

pub async fn start(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    do_unit_action(state, s, name, "start").await
}

pub async fn stop(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    do_unit_action(state, s, name, "stop").await
}

pub async fn restart(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    do_unit_action(state, s, name, "restart").await
}

#[derive(Debug, Deserialize)]
pub struct EnabledReq { pub enabled: bool }

pub async fn set_enabled(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(name): AxPath<String>, Json(req): Json<EnabledReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    let unit = panel_core::unit_name(&name)
        .map_err(|_| ApiError::bad_request("name", "invalid unit name"))?;
    state.os.services().set_enabled(&unit, req.enabled).await?;
    audit(&state, &s, "service.set_enabled", &format!("{name}:{}", req.enabled), "ok").await;
    Ok(ok(serde_json::json!({ "name": name, "enabled": req.enabled })))
}

#[derive(Debug, Deserialize)]
pub struct JournalQ { pub lines: Option<usize> }

pub async fn journal(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(name): AxPath<String>, Query(q): Query<JournalQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    if !state.capabilities.get(cap_keys::SERVICE_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("service.manage"));
    }
    let unit = panel_core::unit_name(&name)
        .map_err(|_| ApiError::bad_request("name", "invalid unit name"))?;
    let jq = panel_os::JournalQuery {
        lines: q.lines.unwrap_or(200).min(2000),
        ..Default::default()
    };
    let mut rx = state.os.services().journal(&unit, jq).await?;

    // 一次性收取：底层非 follow 模式输出完即关闭通道。兜底超时 10s，
    // 超时也已收到的行照常返回（部分日志好过请求悬挂）。
    let mut lines: Vec<String> = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(l) = rx.recv().await {
            lines.push(l);
            if lines.len() >= 2000 { break; }
        }
    }).await;

    Ok(ok(serde_json::json!({ "name": name, "lines": lines })))
}

// ─────────────── 服务配置（在线编辑单元文件 / drop-in） ───────────────

/// `unit`（默认）| `dropin`。非法值一律 400，**不做静默回退**——
/// 静默回退会让用户以为写的是 drop-in、实际却改写了单元文件本体。
fn parse_config_target(raw: Option<&str>) -> std::result::Result<panel_os::ConfigTarget, ApiError> {
    match raw.unwrap_or("unit") {
        "unit" => Ok(panel_os::ConfigTarget::Unit),
        "dropin" => Ok(panel_os::ConfigTarget::DropIn),
        _ => Err(ApiError::bad_request("target", "must be 'unit' or 'dropin'")),
    }
}

#[derive(Debug, Deserialize)]
pub struct ConfigGetQ { pub target: Option<String> }

#[derive(Debug, Deserialize)]
pub struct ConfigPutReq {
    /// 单元文件完整内容（由前端编辑器提交）
    pub content: String,
    /// 保存后是否重启服务（默认 false：仅 daemon-reload 重新加载单元）
    pub restart: Option<bool>,
    /// 写入目标：`unit` | `dropin`（默认 unit）
    pub target: Option<String>,
}

pub async fn config_get(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
    Query(q): Query<ConfigGetQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    if !state.capabilities.get(cap_keys::SERVICE_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("service.manage"));
    }
    let target = parse_config_target(q.target.as_deref())?;
    let unit = panel_core::unit_name(&name)
        .map_err(|_| ApiError::bad_request("name", "invalid unit name"))?;
    let cfg = state.os.services().config_read(&unit, target).await?;
    Ok(ok(serde_json::json!({
        "name": name,
        "path": cfg.path,
        "content": cfg.content,
        "writable": cfg.writable,
        // exists=false 表示目标文件尚不存在（drop-in 新建场景），前端据此提示"保存即创建"
        "exists": cfg.exists,
        "target": if target == panel_os::ConfigTarget::DropIn { "dropin" } else { "unit" },
    })))
}

pub async fn config_put(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(name): AxPath<String>, Json(req): Json<ConfigPutReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    if !state.capabilities.get(cap_keys::SERVICE_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("service.manage"));
    }
    let target = parse_config_target(req.target.as_deref())?;
    // 防御：单元文件不应无限大（256KiB 上限足够容纳任何真实 unit 文件）
    if req.content.len() > 256 * 1024 {
        return Err(ApiError::bad_request("content", "unit file too large (>256KiB)"));
    }
    let unit = panel_core::unit_name(&name)
        .map_err(|_| ApiError::bad_request("name", "invalid unit name"))?;
    state.os.services()
        .config_write(&unit, &req.content, req.restart.unwrap_or(false), target).await?;
    let ts = if target == panel_os::ConfigTarget::DropIn { "dropin" } else { "unit" };
    audit(&state, &s, "service.config_write", &format!("{name}:{ts}"), "ok").await;
    Ok(ok(serde_json::json!({ "name": name, "target": ts })))
}

pub async fn packages_list(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    // 语义是"管理白名单内软件的安装状态"，不是通用包管理器枚举：
    // 只在白名单范围内探测，避免全量 rpm/dpkg 扫描（慢且暴露无关信息）。
    let pkgs = state.os.packages().detect_installed(ALLOWED_PACKAGES).await?;
    let items: Vec<serde_json::Value> = pkgs.into_iter().map(|p| serde_json::json!({
        "name": p.name,
        "version": p.version,
        "manager": p.manager,
    })).collect();
    Ok(ok(serde_json::json!({ "packages": items })))
}

pub async fn package_remove(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    if !ALLOWED_PACKAGES.contains(&name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary removes are refused)"));
    }

    // 卸载与安装同权重：走任务队列 + 幂等键（与 install 不同键，避免互相吞并）
    let pkg = name.clone();
    let os = state.os.clone();
    let body = PackageTask { pkg, os, op: PkgOp::Remove };
    let (id, created) = state.tasks.submit(
        panel_task::TaskRequest {
            idempotency_key: format!("pkg.remove:{}", name),
            kind: panel_task::TaskKind::Package,
            label: format!("卸载 {}", name),
            timeout: Duration::from_secs(1800),
        },
        body,
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "package.remove", &name, "queued").await;
    Ok(ok(serde_json::json!({ "task_id": id, "created": created })))
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
