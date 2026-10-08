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
use panel_os::version_major_jump;
use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

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
pub struct InstallReq {
    pub name: String,
    pub version: Option<String>,
    /// 跨主版本升级的二次确认标记。仅 `package_upgrade` 使用：检测到跨主版本
    /// （如 PostgreSQL 17→18、Node.js 20→24）且为 false 时，升级接口返回 409
    /// 强制前端弹窗确认——不能只靠前端拦截（直接调 API 即可绕过警告）。
    /// `package.install` 忽略此字段（全新安装无"当前版本"可比，不触发跨主版本判定）。
    pub confirm_major: Option<bool>,
}

/// 版本号字符白名单：用户可控输入。后端以数组传参交给包管理器（不走 shell，无命令注入
/// 风险），但奇字符会让 apt/dnf 直接报错、用户困惑。只允许版本号里合法出现的字符集。
/// 抽成独立函数便于单测——内联在 handler 里的校验无法被测试覆盖（已踩过 any/静默吞错的坑）。
fn validate_pkg_version(v: &str) -> ApiResult<()> {
    if v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '~' | ':' | '-')) {
        Ok(())
    } else {
        Err(ApiError::bad_request("version", "版本号只能包含字母、数字及 + . ~ : - 字符"))
    }
}

/// 已支持的软件包白名单。
///
/// 为什么白名单而不是任意包名：面板以 root 运行，允许安装任意包等于
/// 给了 Web 界面一个"任意代码执行"入口。白名单把风险收敛到已知集合。
/// 白名单条目：`name` 是对外逻辑名（UI 展示、install/remove 入参、幂等键、审计都用它），
/// `label` 是给人看的品牌名——刻意不带版本后缀，避免把主版本焊死在展示上
/// （例如 `apache2` 的 "2" 只是 Debian 给 Apache 2.x 打的包名后缀，真出 Apache 3 就尴尬了）。
struct PkgDef { name: &'static str, label: &'static str }

const ALLOWED_PACKAGES: &[PkgDef] = &[
    PkgDef { name: "nginx",          label: "Nginx" },
    PkgDef { name: "caddy",          label: "Caddy" },
    PkgDef { name: "apache2",        label: "Apache" },
    PkgDef { name: "mariadb-server", label: "MariaDB" },
    PkgDef { name: "postgresql",     label: "PostgreSQL" },
    PkgDef { name: "redis",          label: "Redis" },
    PkgDef { name: "memcached",      label: "Memcached" },
    // 只保留元包 php-fpm：它 Depends 当前发行版的默认 phpX.Y-fpm，任何一代
    // Debian/Ubuntu 上都必然可装。此前写死 php8.1/8.2/8.3-fpm 是想覆盖多发行版，
    // 但 Debian 每代只提供 1 个 PHP 版本（13→8.4、12→8.2、11→7.4），实测本机
    // 三条全部"仓库无此包"——即任意一台机器上最多 1 条有效，其余点了必失败。
    PkgDef { name: "php-fpm",        label: "PHP-FPM" },
    PkgDef { name: "certbot",        label: "Certbot" },
    PkgDef { name: "fail2ban",       label: "Fail2ban" },
    PkgDef { name: "ufw",            label: "UFW" },
    PkgDef { name: "minio",          label: "MinIO" },
    PkgDef { name: "valkey-server",  label: "Valkey" },
    PkgDef { name: "prometheus",     label: "Prometheus" },
    PkgDef { name: "grafana",        label: "Grafana" },
    PkgDef { name: "netdata",        label: "Netdata" },
    PkgDef { name: "haproxy",        label: "HAProxy" },
    PkgDef { name: "nodejs",         label: "Node.js" },
    PkgDef { name: "default-jdk",    label: "OpenJDK" },
    PkgDef { name: "wireguard-tools", label: "WireGuard" },
];

/// 白名单里**官方仓库通常不含**的包：需先在目标机上配好第三方软件源才能装。
///
/// 为什么单独维护而不是给 PkgDef 加字段：这只是"装之前要先配源"的提示信息，
/// 与包的身份（name/label）无关，混进 PkgDef 会让白名单每条字面量都变长。
///
/// 现状（2026-10-06 实测复核，Debian 13 trixie）：
/// - 有官方 apt 源、且已在 `panel-os/src/linux/repo.rs::THIRD_PARTY_REPOS` 登记
///   （密钥 URL + 官网公示指纹硬校验）的：`grafana` / `postgresql` / `redis` /
///   `nginx` / `nodejs`。由 `ensure_repo`（方案1）自动加源（校验 GPG 指纹 → 写隔离
///   keyring + sources.list.d → apt-get update）。实测加源后候选版本明显变新：
///   postgresql `17+278`(Debian) → `18+293.pgdg13+1`(PGDG)；
///   redis-server `8.0.2`(Debian) → `8.10.2`(Redis 官方源，与官网同步)；
///   nginx `1.26.3`(Debian) → `1.30.5`(nginx.org)。
///   故标 external 仅作"需联网加源"的弱提示，装/升级时能自动就绪。
///   （nodejs 一度因 deb.nodesource.com 超时而未接；后查明是**本机 IPv6 优先才超时、
///   强制 IPv4 即通**，遂接通并钉死指纹——详见 repo.rs 该条注释。）
/// - `netdata` / `minio`：**上游 apt 仓库均已下线**，`ensure_repo` 是 no-op，不会尝试加源。
///   netdata 的密钥仍能下载（指纹也对得上），但仓库元数据整体 404——连老牌 bookworm 的
///   InRelease 都是 404，故非"Debian 13 太新"，是仓库本身不可用；目录列表页仍能打开，
///   极易误判为可用，判定必须以 InRelease 200 为准（详见 `panel-os/src/linux/repo.rs` 注释）。
///   两者需走「直接下载 .deb / 静态安装」路径（方案3），不在自动加源范围内。
///
/// 面板保留这些入口（配好源后即可安装），UI 上标注提示，避免用户白点一次。
const EXTERNAL_SOURCE_PACKAGES: &[&str] = &[
    // 上游 apt 仓库已下线：ensure_repo 是 no-op，保留入口 + "需配源"提示。
    "minio", "netdata",
    // 自动加源（repo.rs 表内有定义）：UI 标"需配源"作弱提示，实际装/升级会自动加。
    // 这些包在 Debian stable 源里版本明显落后官网，已接各自上游官方源
    // （Grafana / PGDG / packages.redis.io / nginx.org / NodeSource）。
    "grafana", "postgresql", "redis", "nginx", "nodejs",
];

/// 逻辑包名 → 各发行版的**真实包名**（槽位 0 = Debian 系 apt，槽位 1 = 其它/RHEL 系）。
///
/// 为什么需要：同一个软件在不同发行版叫不同名字。Debian/Ubuntu 上 Redis 的包名是
/// `redis-server`（`redis` 是 Red Hat 系的名），此前探测只认 `redis` → Debian 上永远
/// 探测不到，用户看到的是"Redis 明明装了却不显示在已安装列表里"（本机实测：
/// redis-server 5:8.0.2 状态 ii，而白名单比对的是 redis，落空）。
///
/// 约定：`ALLOWED_PACKAGES` 里的都是**逻辑名**，对外一律用它（UI 展示、install/remove
/// 入参、幂等键、审计）；只有真正要交给 apt/dnf 的那一刻才换成真实包名。
const PKG_NAME_ALIASES: &[(&str, [&str; 2])] = &[
    ("redis", ["redis-server", "redis"]),
    ("apache2", ["apache2", "httpd"]),
];

/// 逻辑名 → 当前包管理器对应的真实包名（无别名条目则原样返回）。
pub fn real_pkg_name(manager: Option<&str>, logical: &str) -> String {
    match PKG_NAME_ALIASES.iter().find(|a| a.0 == logical) {
        Some(a) => a.1[if manager == Some("apt") { 0 } else { 1 }].to_string(),
        None => logical.to_string(),
    }
}

/// 真实包名 → 逻辑名：探测结果回填用，保证返回给前端的始终是逻辑名
/// （否则 Debian 上会吐出 `redis-server`，前端按逻辑名渲染的卡片/安装按钮就对不上了）。
pub fn logical_pkg_name(real: &str) -> Option<&'static str> {
    PKG_NAME_ALIASES.iter()
        .find(|a| a.1.iter().any(|n| *n == real))
        .map(|a| a.0)
}

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
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == req.name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary installs are refused)"));
    }
    // 版本是用户可控输入：虽然后端以数组传参交给 apt/dnf（不走 shell，无命令注入风险），
    // 但奇字符会让包管理器直接报错、用户困惑。这里只允许版本号里合法出现的字符集，
    // 把错误拦在入参阶段、给出清晰中文提示。
    if let Some(v) = &req.version {
        validate_pkg_version(v)?;
    }
    // 跨主版本升级二次确认：install 也能触发升级（已装包传最新版即等于升级），
    // 不能只在 upgrade 路径守，否则换端点即可绕过警告。未装包 current=None → 不触发，
    // 首次安装零影响。
    require_major_upgrade_confirm(&state, &req).await?;

    // 安装必须走任务队列：耗时不可预测 + 输出需流式返回
    // Debian 上 Redis 的真实包名是 redis-server —— 直接拿逻辑名去 apt install 会失败，
    // 故此处换成当前发行版的真名（幂等键与审计仍用逻辑名，见下方 clone）。
    let pkg = real_pkg_name(state.os.packages().manager(), &req.name);
    let os = state.os.clone();
    let body = PackageTask { pkg, os, op: PkgOp::Install, version: req.version.clone(), logical: req.name.clone() };
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

pub struct PackageTask { pub pkg: String, pub os: std::sync::Arc<dyn panel_os::OsAdapter>, pub op: PkgOp, pub version: Option<String>,
    /// 逻辑包名（= 白名单 ALLOWED_PACKAGES.name）。第三方官方源包（grafana/netdata）据此
    /// 在 install 前查 THIRD_PARTY_REPOS 自动加源；普通包在 ensure_repo 内是 no-op。
    pub logical: String }

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

        // 第三方官方源：无论安装、升级还是「换源」，都先确保源就绪。
        //
        // 为什么提到 Install 分支之外（原先只在 install 前调）：接官方源的主要目的
        // 就是给**已装**的包换源（Debian 的 postgresql 停在 17、redis 停在 8.0.2，
        // 想用 PGDG 的 18 / Redis 官方源的 8.2 就必须先加源再升级）。若只挂在 install
        // 分支，已装的包走 upgrade 路径时加不上源，恰好漏掉最需要它的场景。
        //
        // 幂等由 ensure_third_party_repo 自己保证（keyring+sources 已一致则跳过），
        // 故每次任务都调只是几次 stat，不产生额外 apt-get update。
        // 无第三方源的包（普通包 / 非 apt 发行版 / netdata / minio）在其内是 no-op。
        {
            let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = seen.clone();
            if let Err(e) = self.os.packages().ensure_repo(&self.logical, Box::new(move |line| {
                if let Ok(mut g) = sink.lock() { g.push(line); }
            })).await {
                let msg = e.to_string();
                progress.log(&format!("加源失败：{msg}")).await;
                return Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Failed, exit_code: Some(1), output_path: None,
                });
            }
        }

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
                .install(&self.pkg, self.version.as_deref(), Box::new(move |line| {
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
    // 打开软件管理即确保官方源落地（进程内只一次），让安装候选版本也反映官方源。
    ensure_external_repos_once(&state).await;
    // 语义是"管理白名单内软件的安装状态"，不是通用包管理器枚举：
    // 只在白名单范围内探测，避免全量 rpm/dpkg 扫描（慢且暴露无关信息）。
    // 按当前发行版的**真实包名**去探测，再把结果回填为**逻辑名**：
    // Debian 上 Redis 要查 redis-server，但对外仍要叫 redis（前端按逻辑名渲染、
    // 卸载接口也按逻辑名校验），否则同一个软件在 UI 上会出现两个身份。
    let manager = state.os.packages().manager();
    let probe: Vec<String> = ALLOWED_PACKAGES.iter().map(|d| real_pkg_name(manager, d.name)).collect();
    let probe: Vec<&str> = probe.iter().map(|s| s.as_str()).collect();
    let pkgs = state.os.packages().detect_installed(&probe).await?;
    let items: Vec<serde_json::Value> = pkgs.into_iter().map(|p| {
        // 探测到的是真实包名（Debian 上 redis 查 redis-server），先还原成逻辑名，
        // 再取对应 label；取不到（理论上不会）时退回逻辑名，保证 UI 至少有字可显示。
        let logical = logical_pkg_name(&p.name).unwrap_or(p.name.as_str());
        let (name, label) = match ALLOWED_PACKAGES.iter().find(|d| d.name == logical) {
            Some(d) => (d.name.to_string(), d.label.to_string()),
            None => (logical.to_string(), logical.to_string()),
        };
        serde_json::json!({ "name": name, "label": label, "version": p.version, "manager": p.manager })
    }).collect();
    // 完整白名单（name+label）随清单一起下发：前端据此给「已装」和「可装」两类都渲染
    // 友好品牌名，而不必在 CATEGORIES 里再维护一份标签（单一事实源在后端）。
    let catalog: Vec<serde_json::Value> = ALLOWED_PACKAGES.iter()
        .map(|d| serde_json::json!({
            "name": d.name,
            "label": d.label,
            // 提示"官方源通常不含，需先配第三方源"；配好源后装上不受影响
            "external": EXTERNAL_SOURCE_PACKAGES.contains(&d.name),
        }))
        .collect();
    Ok(ok(serde_json::json!({ "packages": items, "catalog": catalog })))
}

/// 查询某个白名单包在当前软件源里可供安装的版本（新→旧）。
///
/// 为什么单独成端点而不是塞进 packages_list：列包是高频调用（页面加载/轮询），
/// 而版本查询要为每个包跑一次 apt-cache——25 个包全查会明显拖慢列表。
/// 改为安装弹窗打开时才按单个包查询（懒加载）。
pub async fn package_versions(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    // 与 install 同一道围栏：只查白名单内的包，避免把本端点变成任意包元数据探针。
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary installs are refused)"));
    }
    let manager = state.os.packages().manager();
    let real = real_pkg_name(manager, &name);
    let v = state.os.packages().list_versions(&real).await?;
    // 空列表不是错误：查不到就退回"装最新版"，前端据此只显示一个选项。
    // installed 由包管理器给出，用于在下拉里标「（已安装）」。
    Ok(ok(serde_json::json!({ "name": name, "versions": v.versions, "installed": v.installed })))
}

/// 对「有官方源定义的外部包」确保源已落地（每个逻辑名进程内最多尝试一次）。
///
/// `ensure_repo` 内部对无源包（minio/netdata）是 no-op，故直接遍历白名单安全。
/// 进程内只跑一次：成功则缓存、失败也缓存（权限类失败重试无意义），不反复打 `apt-get update`。
/// 调用点：只读「可升级探测」与安装列表加载，确保「接官方源」在用户看到列表前就落地，
/// 否则只读探测只能看到发行版源的旧版，「接官方源」等于没接。
async fn ensure_external_repos_once(state: &Shared) {
    for &logical in EXTERNAL_SOURCE_PACKAGES {
        let first = ENSURED_EXTERNAL_REPOS.lock().unwrap().insert(logical);
        if !first {
            continue;
        }
        if let Err(e) = state.os.packages().ensure_repo(logical, Box::new(|_| {})).await {
            eprintln!(
                "[panel] 确保官方源 {logical} 失败（升级/探测将继续，但可能只能看到发行版源版本）：{e}"
            );
        }
    }
}

/// 探测白名单内**已安装且源里有新版**的包（B1：只读，供 UI 显示「有新版」徽标）。
///
/// 为什么单独成端点：与 packages_list 分开是因为它要跑一次 `apt list --upgradable`
/// （秒级子进程），而 packages_list 是页面/轮询高频调用；混在一起会让每次刷新都多付这个开销。
///
/// 权限用 PACKAGE_MANAGE（与安装同级）：升级会改动系统，viewer 不该看到可升级清单。
/// 探测失败**不报错**、返回空列表——探测是锦上添花，不该让整页软件列表挂掉。
pub async fn packages_upgradable(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_UPGRADE)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.upgrade"));
    }
    // 探测前先确保官方源已落地：否则只读探测只能看到发行版源的旧版，「接官方源」等于没接。
    // ensure_repo 进程内只跑一次（见 ensure_external_repos_once），不拖慢后续轮询。
    ensure_external_repos_once(&state).await;
    let up = state.os.packages().upgradable().await.unwrap_or_default();
    // 过滤到白名单（用真包名比对，因为 upgradable 返的是 redis-server 这类真名），
    // 再映射回逻辑名对外——与 install/remove 的"逻辑名对外"约定保持一致。
    let items: Vec<serde_json::Value> = ALLOWED_PACKAGES.iter().filter_map(|p| {
        let real = real_pkg_name(state.os.packages().manager(), p.name);
        up.iter().find(|u| u.name == real).map(|u| serde_json::json!({
            "name": p.name,            // 逻辑名（前端按它匹配已安装卡片）
            "label": p.label,
            "current": u.current,
            "candidate": u.candidate,
            "major": u.major,          // 跨主版本标记：前端据此弹窗二次确认
        }))
    }).collect();
    Ok(ok(serde_json::json!({ "items": items })))
}

/// 升级某个已安装软件到指定版本（A：复用 install pkg=version 路径）。
///
/// 为什么复用 install 而不新增 PkgOp::Upgrade：apt/dnf 的 `install pkg=version` 语义上
/// **本身就是覆盖升级**（已装 1.0 时执行 install pkg=1.2.3 就是升到 1.2.3），
/// 另立一个 op 只会让底层多一份完全同构的分支。升级与安装的差别只在 UI 语义与幂等键。
///
/// version 为空时表示"升到源里的最新版"（apt install pkg，不带版本约束）。
pub async fn package_upgrade(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<InstallReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_UPGRADE)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.upgrade"));
    }
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == req.name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary installs are refused)"));
    }
    if let Some(v) = &req.version {
        validate_pkg_version(v)?;
    }
    let real = real_pkg_name(state.os.packages().manager(), &req.name);

    // 跨主版本升级二次确认（与 install 共用同一守卫，单一事实源）。
    require_major_upgrade_confirm(&state, &req).await?;

    let pkg = real;
    let os = state.os.clone();
    let body = PackageTask { pkg, os, op: PkgOp::Install, version: req.version.clone(), logical: req.name.clone() };
    // 幂等键与 install 刻意不同（pkg.upgrade: vs pkg.install:）：否则用户先装了新版、
    // 又点「更新到旧版本」会被 install 的窗口期幂等吞掉，任务静默不执行。
    let (id, created) = state.tasks.submit(
        panel_task::TaskRequest {
            idempotency_key: format!("pkg.upgrade:{}", req.name),
            kind: panel_task::TaskKind::Package,
            label: format!("升级 {}", req.name),
            timeout: Duration::from_secs(1800),
        },
        body,
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "package.upgrade", &req.name, "queued").await;
    Ok(ok(serde_json::json!({ "task_id": id, "created": created })))
}

/// 跨主版本升级二次确认守卫（install 与 upgrade 两路共用，单一事实源）。
///
/// 已装包升到**跨主版本**候选（PostgreSQL 17→18、Node.js 20→24 等）时，未带
/// `confirm_major=true` 则 409 拒绝——不能只靠前端拦截，否则直接调 API 即可绕过。
/// 判定从 `upgradable()` 探测结果取候选版本、从 `apt-cache policy` 取已装版本，
/// 二者交 `version_major_jump` 判定，与 /packages/upgradable 列表里的 `major` 标记同源。
///
/// 未装包：`current` 经 upgradable + apt-cache policy 都取不到 → `major=false` → 不触发，
/// 故对「首次安装」零影响；仅当包**已装且**目标跨主版本时才拦截。
async fn require_major_upgrade_confirm(
    state: &Shared,
    req: &InstallReq,
) -> ApiResult<()> {
    let real = real_pkg_name(state.os.packages().manager(), &req.name);
    let up = state.os.packages().upgradable().await.unwrap_or_default();
    let entry = up.iter().find(|u| u.name == real);
    // candidate：用户显式指定版本优先，否则取 upgradable 探测到的目标版本
    let candidate = req.version.clone()
        .or_else(|| entry.as_ref().map(|u| u.candidate.clone()));
    // current：upgradable 探测里的已装版本；不在探测列表里（用户显式指定旧/新版）时
    // 退回 apt-cache policy 的已装版本
    let current = match entry {
        Some(u) => Some(u.current.clone()),
        None => state.os.packages().list_versions(&real).await.ok().and_then(|v| v.installed),
    };
    let major = match (&current, &candidate) {
        (Some(c), Some(n)) => version_major_jump(c, n),
        _ => false,
    };
    if major && !req.confirm_major.unwrap_or(false) {
        return Err(ApiError::conflict("major_upgrade").with_detail(serde_json::json!({
            "kind": "major_upgrade",
            "from": current,
            "to": candidate,
            "note": "跨主版本升级可能不向后兼容，通常需要数据迁移或服务重配。例如 PostgreSQL 17→18 须先执行 pg_upgrade 或逻辑备份恢复，期间服务不可用。确认前请务必先完成数据备份。",
        })));
    }
    Ok(())
}

pub async fn package_remove(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary removes are refused)"));
    }

    // 卸载与安装同权重：走任务队列 + 幂等键（与 install 不同键，避免互相吞并）
    let pkg = real_pkg_name(state.os.packages().manager(), &name);
    let os = state.os.clone();
    let body = PackageTask { pkg, os, op: PkgOp::Remove, version: None, logical: name.clone() };
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
}
