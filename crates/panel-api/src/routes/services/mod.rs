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

mod packages;
pub(crate) use packages::*;

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
use panel_os::version_major_jump;
use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use crate::extract::PanelJson;

/// 超过这个时长的操作必须走任务队列。
///
/// 域规则备忘：同步接口必须秒级返回，长操作接入时以此为分流阈值；
/// 测试已锁定该值，接口落地前 `allow(dead_code)` 抑制未用告警。
#[allow(dead_code)]
const SYNC_LIMIT: Duration = Duration::from_secs(2);

/// 第三方官方源「进程内确保一次」缓存：避免每次轮询都重跑 `apt-get update`。
///
/// 本机加源需 root（写 `/etc/apt/keyrings` + `sources.list.d` + `apt-get update`）。
/// 面板非 root 时 `ensure_repo` 会失败（`Io` 权限），这里只记一次日志、不阻塞探测——
/// 探测是锦上添花，绝不该让软件列表/可升级清单挂掉。
static ENSURED_EXTERNAL_REPOS: LazyLock<Mutex<std::collections::HashSet<&'static str>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

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
    // systemctl list-units 输出的单元名**带类型后缀**（redis-server.service），模板实例还形如
    // postgresql@17-main.service。比对前必须剥掉后缀——否则与上面这份无后缀名单永远比不上，
    // 结果是**所有服务都被标成"未托管"**（UI 上一片黄色徽标 + 停止要二次确认），
    // managed_only 过滤也形同虚设。这是"看着像在判定、实际恒为 false"的假逻辑。
    let base = name.strip_suffix(".service").unwrap_or(name);
    MANAGED.iter().any(|m| base == *m || base.starts_with(&format!("{m}@")))
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
    PanelJson(req): PanelJson<ActionReq>,
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

/// 按单元名直接查单个服务（绕开 `list` 的 `list-units --all`，dead 服务也能查到）。
///
/// 详情页用它加载服务，避免"刚装好还没启动的服务在列表反查里查不到 → 未找到该服务"。
/// 单元不存在（`show` 返回 None）→ 404。
pub async fn show(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    let unit = panel_core::unit_name(&name)
        .map_err(|_| ApiError::bad_request("name", "invalid unit name"))?;
    let found = state.os.services().show(&unit).await?;
    match found {
        Some(u) => {
            let dto = ServiceDto {
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
                description: if u.description.is_empty() { None } else { Some(u.description) },
            };
            Ok(ok(serde_json::json!({
                "init_system": init_name(state.os.services().init_system()),
                "service": dto,
            })))
        }
        None => Err(ApiError::not_found("service")),
    }
}

// ─────────────── 文档式细粒度动作（复用 act 单一实现点） ───────────────

/// 收敛单元动作到 `act`，避免 start/stop/restart 三套重复校验。
async fn do_unit_action(
    state: Shared, s: crate::auth::Session, name: String, action: &str,
) -> ApiResult<Json<serde_json::Value>> {
    act(State(state), Auth(s), AxPath(name), PanelJson(ActionReq { action: action.into(), enable: None })).await
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
    AxPath(name): AxPath<String>, PanelJson(req): PanelJson<EnabledReq>,
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
    AxPath(name): AxPath<String>, PanelJson(req): PanelJson<ConfigPutReq>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_whitelist_covers_web_stack() {
        for n in ["nginx", "php8.2-fpm", "mysql", "redis-server", "docker"] {
            assert!(is_managed(n), "{n} 应被识别为托管服务");
        }
    }

    /// hold 端点按**真实包名**落钉的映射不变量：Debian 上逻辑名 redis 的真名是
    /// redis-server，若哪天端点直接拿逻辑名去 set_hold，apt-mark 会钉到一个不存在
    /// 的包（退出码 0 但不生效）——UI 显示「已钉住」而升级照旧发生的假状态。
    /// 这条测试钉住映射本身；端点接线由实机（dev 实例 curl）覆盖。
    #[test]
    fn hold_uses_real_pkg_name_on_apt() {
        assert_eq!(real_pkg_name(Some("apt"), "redis"), "redis-server");
        assert_eq!(real_pkg_name(Some("apt"), "nginx"), "nginx");
        // 非 apt：别名表第二列（dnf 口径）；mock 管理器同样不得误用 apt 列
        assert_ne!(real_pkg_name(Some("mock"), "redis"), "redis-server");
        // 回填方向：探测/回读拿到真名必须能还原逻辑名（列表徽标据此匹配卡片）
        assert_eq!(logical_pkg_name("redis-server"), Some("redis"));
    }

    #[test]
    fn sshd_and_journald_are_not_in_managed_list() {
        // sshd 可查看但操作需二次确认；journald 干脆不在白名单
        assert!(!is_managed("systemd-journald"));
        assert!(!is_managed("dbus"));
    }

    #[test]
    fn package_whitelist_is_closed() {
        assert!(ALLOWED_PACKAGES.iter().any(|p| p.name == "nginx"));
        // 任意包名必须被拒（面板以 root 运行，这是任意代码执行的入口）
        for bad in ["evil-miner", "../../bin/sh", "nginx; rm -rf /"] {
            assert!(!ALLOWED_PACKAGES.iter().any(|p| p.name == bad), "{bad} 绝不能在白名单里");
        }
    }

    #[test]
    fn pkg_version_charset_is_restricted() {
        // 合法字符集：Debian 版本号常见形态（epoch、点、连字符、ubuntu 后缀、build 号）。
        for ok in ["1.2.3", "8.0.36-0ubuntu0.22.04.1", "1:1.24.0-1", "5:8.0.2", "1.0~rc1", "1.0+build2"] {
            assert!(validate_pkg_version(ok).is_ok(), "{ok} 应合法");
        }
        // 非法：空格 / 分号 / 路径分隔 / 反引号 / 命令替换 —— 都该被拒（防注入与误装）。
        for bad in ["1.0; rm -rf /", "../../bin/sh", "1 0", "$(id)", "1.0`whoami`"] {
            assert!(validate_pkg_version(bad).is_err(), "{bad} 应被拒");
        }
    }

    #[test]
    fn is_managed_must_tolerate_systemd_suffix() {
        // 回归守卫：systemctl list-units 输出的单元名带 .service 后缀（模板实例形如
        // postgresql@17-main.service）。上面的 managed_whitelist_covers_web_stack 只测了
        // 无后缀形态——于是线上真实数据（带后缀）全部匹配失败时，测试依然全绿。
        // 这里补的就是真实形态。
        for n in ["nginx.service", "redis-server.service", "mysql.service",
                  "php8.2-fpm.service", "postgresql@17-main.service"] {
            assert!(is_managed(n), "{n} 应被识别为托管服务");
        }
        // 未托管的仍必须是 false，别为了兼容后缀把判定放宽成"什么都算托管"
        assert!(!is_managed("some-random-app.service"));
        assert!(!is_managed("systemd-journald.service"));
    }

    #[test]
    fn pkg_name_aliases_roundtrip() {
        // Debian/Ubuntu 上 Redis 的真实包名是 redis-server，RHEL 上才是 redis
        assert_eq!(real_pkg_name(Some("apt"), "redis"), "redis-server");
        assert_eq!(real_pkg_name(Some("dnf"), "redis"), "redis");
        assert_eq!(real_pkg_name(Some("apk"), "apache2"), "httpd");
        // 探测结果要能回填成逻辑名，否则前端会同时看到 redis 与 redis-server 两个身份
        assert_eq!(logical_pkg_name("redis-server"), Some("redis"));
        // 无别名的包必须原样透传
        assert_eq!(real_pkg_name(Some("apt"), "nginx"), "nginx");
        assert_eq!(logical_pkg_name("nginx"), None);
        // 每个别名槽位都能反查回同一个逻辑名（否则 install 与 list 会对不上）
        for (logical, names) in PKG_NAME_ALIASES {
            for real in names {
                assert_eq!(logical_pkg_name(real), Some(*logical),
                    "{real} 应回填为 {logical}");
            }
        }
    }

    #[test]
    fn sync_limit_distinguishes_ops() {
        // 服务启停 <2s 可同步；安装耗时不可预测必须入队
        assert_eq!(SYNC_LIMIT.as_secs(), 2);
    }

    /// 每个白名单条目都必须带齐五项说明，且不能是占位空串。    ///
    /// 为什么值得一条测试：这五项会原样进 `catalog`，前端软件卡片的「说明」直接渲染它。
    /// 加新包时忘了填字段 **不会编译报错**（`&'static str` 有默认空串的诱惑），
    /// 用户看到的是「点开说明，几个标签下面全是空白」——比不提供说明更糟。
    /// 所以这里既查非空，也查长度下限（一两个字的敷衍值同样按空处理）。
    #[test]
    fn every_whitelisted_pkg_has_five_non_empty_help_fields() {
        assert!(!ALLOWED_PACKAGES.is_empty(), "白名单为空：测试前提不成立");
        for d in ALLOWED_PACKAGES {
            let fields = [
                ("summary", d.summary),
                ("features", d.features),
                ("scenes", d.scenes),
                ("entry", d.entry),
                ("howto", d.howto),
            ];
            for (name, v) in fields {
                assert!(!v.trim().is_empty(), "{} 的 {name} 为空", d.name);
                // 中文说明里 8 个字符已短到没有信息量（如「数据库」三字）
                assert!(
                    v.chars().count() >= 8,
                    "{} 的 {name} 过短（{} 字）：{v}",
                    d.name,
                    v.chars().count()
                );
            }
            // 入口字段必须表态：要么给出面板内入口，要么明说面板没有独立页面。
            // 这条挡住「留空」与「随手写句话糊过去」两种，逼迫作者真的去想入口在哪。
            let e = d.entry;
            assert!(
                e.contains("页") || e.contains("菜单") || e.contains("面板无独立页面"),
                "{} 的 entry 未说明任何入口（既没提页面/菜单，也没写「面板无独立页面」）：{e}",
                d.name
            );
        }
    }

    /// 说明字段是**纯文本**（前端用 `{{ }}` 插值，不跑 markdown），不得夹带 markdown 语法。
    ///
    /// 为什么值得一条测试：写文案时很自然会敲 `**须已存在**`、`` `/opt/blog` ``、
    /// `- ` 这类 markdown——它们会**原样显示**成星号和反引号，用户看到的是
    /// 「工作目录填绝对路径且\*\*须已存在\*\*」。编译、类型、界面截图都发现不了，
    /// 只有真的把弹窗打开逐字读才发现（本轮就是这么撞上的）。
    ///
    /// 判据只抓「确定会露出来」的三种：成对的 `**`、反引号、行首的 `- ` / `1. ` 列表标记。
    /// 不用「含 * 就算错」——文案里可能出现单个 `*` 作为通配符说明，那是合法内容。
    #[test]
    fn help_text_fields_are_plain_text_without_markdown() {
        assert!(!ALLOWED_PACKAGES.is_empty(), "白名单为空：测试前提不成立");
        for d in ALLOWED_PACKAGES {
            for (name, v) in [
                ("summary", d.summary),
                ("features", d.features),
                ("scenes", d.scenes),
                ("entry", d.entry),
                ("howto", d.howto),
            ] {
                assert!(!v.contains("**"), "{} 的 {name} 含 markdown 粗体 `**`（会原样显示）：{v}", d.name);
                assert!(!v.contains('`'), "{} 的 {name} 含 markdown 反引号（会原样显示）：{v}", d.name);
                assert!(
                    !v.trim_start().starts_with("- ") && !v.trim_start().starts_with("1. "),
                    "{} 的 {name} 以 markdown 列表标记开头（会原样显示）：{v}",
                    d.name
                );
            }
        }
    }

    /// 投影出的说明条数与白名单一一对应、name 不重复。
    ///
    /// `catalog` 是前端按 name 建 Map 消费的（`labelMap` / 说明表都是 Map），
    /// 一旦出现同名条目就只会保留最后一条，用户看到的是「某个软件的说明莫名跑到了
    /// 别的软件上」。白名单里手写 22 条字面量，这种手误必须由测试挡住。
    #[test]
    fn help_projection_matches_whitelist_one_to_one() {
        let projected: Vec<_> = crate::routes::pkg_help::projection(ALLOWED_PACKAGES.iter()).collect();
        assert_eq!(projected.len(), ALLOWED_PACKAGES.len());
        let mut seen = std::collections::HashSet::new();
        for h in &projected {
            assert!(seen.insert(h.name), "catalog 出现重复 name：{}", h.name);
            assert_eq!(h.label, ALLOWED_PACKAGES.iter()
                .find(|d| d.name == h.name).expect("投影出现白名单外条目").label);
        }
    }

    /// `howto` 必须**真的给出可抄的值**，不能是「看情况填」这类空话，也不能 22 条互抄。
    ///
    /// 为什么非要多一条测试：上面对 howto 只查了「非空且≥8 字」——而这一关极其好糊：
    /// 给 22 条全填「按页面提示填写即可」也能全绿，用户点开说明仍然一无所获。
    /// 「非空断言挡不住敷衍」是本项目踩过的老坑（守卫恒绿比没守卫更危险）。
    ///
    /// 三条判据分别挡三种偷懒写法：
    /// 1. **两两不同**：防 22 条复制同一句。
    /// 2. **至少给出一个可抄的具体值**（端口号 / 绝对路径 / 命令名 / 表单字段名）：
    ///    防「去页面里按提示配」这种听着对、实际没用的句子。
    /// 3. **长度下限 20 字**（比通用那条 8 字更严）：howto 要讲清填什么，一句短话必然
    ///    是在回避细节。
    ///
    /// 判据 2 的关键词表是**实测过的表单字段名与典型值**（见各条文案），不是凭空列的：
    /// 端口 3306/5432/6379/9000、路径 /opt/blog、命令 node/java -jar、字段「工作目录」
    /// 「启动命令」「域名」「用户名」「根目录」「端口」。新增包若确实不命中任何一项，
    /// 应把它加进这张表（说明该包引入了新的配置入口），而不是把断言删掉。
    #[test]
    fn howto_gives_concrete_values_not_vague_advice() {
        const CONCRETE_HINTS: &[&str] = &[
            // 端口 / 地址类典型值
            "127.0.0.1", "3306", "5432", "6379", "9000", "19999", "3000", "/run/php/",
            // 表单字段名（前端真实存在的 label）
            "名称", "域名", "根目录", "端口", "用户名", "工作目录", "启动命令", "邮箱", "站点",
            // 命令 / 路径类可抄值
            "node ", "java -jar", "/opt/", "/etc/", "http://",
        ];
        assert!(!ALLOWED_PACKAGES.is_empty(), "白名单为空：测试前提不成立");

        let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for d in ALLOWED_PACKAGES {
            assert!(
                d.howto.chars().count() >= 20,
                "{} 的 howto 过短（{} 字），讲不清要填什么：{}",
                d.name,
                d.howto.chars().count(),
                d.howto
            );
            assert!(
                CONCRETE_HINTS.iter().any(|h| d.howto.contains(h)),
                "{} 的 howto 没给出任何可抄的具体值（端口/路径/命令/字段名全无），\
                 属于「按提示填写即可」式空话：{}",
                d.name,
                d.howto
            );
            if let Some(prev) = seen.insert(d.howto, d.name) {
                panic!("{} 与 {prev} 的 howto 完全相同（复制粘贴未改内容）：{}", d.name, d.howto);
            }
        }
    }

    /// `units` 必须**真的能反查到条目**，且不能出现两个包抢同一个单元名。
    ///
    /// 为什么值得一条测试：`units` 是服务详情页的反查键。填错一个字符（`mariadb-service`
    /// 写成 `mariadb-server.service`、`grafana.server` 少个横线）不会编译报错、不会运行报错，
    /// 用户在服务详情页看到的就是「这个服务没有软件说明」——与「这个软件本来就没说明」
    /// 长得一模一样，无从区分。这类**静默落空**必须由测试挡住。
    ///
    /// 三条判据：
    /// 1. 每条都形如 `xxx.service` / `xxx.timer` / `xxx@.service`（后缀是 systemd 认识的
    ///    四种之一），且只含小写字母、数字、`.` `-` `@` `_`——大写或空格在 systemd 里
    ///    是非法单元名，这种值反查永远不命中。
    /// 2. **同一单元名不得挂在两个包上**：否则 `Map` 反查会静默取到其中一个，用户看到的
    ///    说明可能属于另一个软件（`caddy` 与假想中的 `caddy-api` 包就是这种风险）。
    /// 3. 同一包内不得重复登记同一单元（`&["nginx.service", "nginx.service"]`）。
    ///
    /// 另有一条**活性**判据：至少要有 10 个包登记了单元。若有人为了过测试把 22 条全清成
    /// `&[]`，上面三条都会平凡通过（空集合上没有违规项）——这正是「恒绿守卫」的典型形态，
    /// 必须显式钉住下界。
    #[test]
    fn pkg_units_are_real_systemd_unit_names_and_unique() {
        const UNIT_SUFFIXES: &[&str] = &[".service", ".socket", ".timer", ".target"];
        assert!(!ALLOWED_PACKAGES.is_empty(), "白名单为空：测试前提不成立");

        let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut with_units = 0usize;
        for d in ALLOWED_PACKAGES {
            if !d.units.is_empty() { with_units += 1; }
            for u in d.units {
                assert!(!u.is_empty(), "{} 的 units 里有空串（空串 = 反查恒不命中）", d.name);
                assert!(
                    UNIT_SUFFIXES.iter().any(|s| u.ends_with(s)),
                    "{} 的单元名 {u} 不以已知 systemd 单元后缀结尾（不会出现在服务列表里）",
                    d.name
                );
                assert!(
                    u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()
                        || matches!(c, '.' | '-' | '@' | '_')),
                    "{} 的单元名 {u} 含非法字符（systemd 单元名只用小写字母/数字/. - @ _）",
                    d.name
                );
                assert!(
                    !u.starts_with('.') && !u.contains(".."),
                    "{} 的单元名 {u} 形如隐藏文件或含连续点",
                    d.name
                );
                if let Some(prev) = seen.insert(u, d.name) {
                    panic!("单元名 {u} 同时登记在 {prev} 与 {} 上：详情页反查会静默取到其中一个，\
                            用户可能看到另一个软件的说明", d.name);
                }
            }
            // 同一包内自查重复（上面的全局表已覆盖，这里留一条更明确的报错文案）
            let mut local: Vec<&str> = Vec::new();
            for u in d.units {
                assert!(!local.contains(u), "{} 的 units 里 {u} 重复登记", d.name);
                local.push(u);
            }
        }
        // 活性下界：22 条里至少 10 条真的有常驻单元（实测 15 条有，5 条是运行时/工具链）。
        assert!(
            with_units >= 10,
            "只有 {with_units} 个包登记了服务单元（实测应有 ≥10）；\
             若确实是白名单整体改成无单元包，请同步更新这条下界与前端说明"
        );
    }
}
