//! 面板托管的应用（v14 表 `apps`）。
//!
//! 一行 = 一个由面板拉起的进程 + 一个自动维护的反代站点。
//!
//! ## 职责边界（重要）
//! 面板**只负责把进程按 systemd 起来**，构建与依赖安装仍由用户在项目目录自行完成
//! （`AppRuntime::build_hint` 仅作前端提示，不落库、不执行）。这样面板不需要理解
//! 任何语言的包管理器，也不会因某语言构建工具变更而失效。
//!
//! ## 与 `sites` 正交
//! - `AppRuntime` 管**进程怎么起**（Node/Go/Rust/Java/Python/.NET/PHP/自定义）
//! - `SiteKind` 管**nginx 怎么接**（静态/反向代理/FastCGI/重定向）
//!
//! 所有运行时在 nginx 侧一律 `proxy_pass`，故本模块固定建 `kind=proxy` 站点。
//!
//! ## 权限：复用 service.view / service.manage，不新造权限点
//! 本质就是 systemd 单元托管，复用既有权限点最自然；新建权限点要动
//! `permissions_for_role` 与前端 CAP，对用户是额外心智负担。
//! 建站那一步由 `sites::apply` 自己 `require(site.manage)` 叠加校验。
//!
//! ## 一致性
//! DB 是唯一真相源，单元文件与 nginx 配置都是**投影**，每次保存整体重写。
//! 删应用必须同时删单元 + 删站点，否则留下孤儿单元或仍在对外服务的空站。

use crate::{
    auth::{perm, Session},
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    Json,
};
use panel_core::{PanelError, UnitName};
use panel_os::{app_unit_name, render_app_unit, AppRuntime, AppUnitSpec};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::extract::PanelJson;

/// rusqlite 错误 → 面板错误（与 `sites::db_err` 同范式）。
fn db_err(e: rusqlite::Error) -> PanelError {
    PanelError::Database(e.to_string())
}

/// 当前时刻（秒）。各模块私有一份是既有范式（`files::now_unix` / `auth::now_unix`），
/// 故不往 crate 根挪。
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ═══════════════════════════ DTO ═══════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct AppOut {
    pub id: i64,
    pub name: String,
    pub runtime: String,
    pub runtime_label: String,
    pub workdir: String,
    pub exec_start: String,
    pub run_user: Option<String>,
    /// 环境变量 `[[k, v], ...]`。**面板不代存秘密**（无加密存储，见 OpenAPI 备注）。
    pub env: Vec<(String, String)>,
    pub port: u16,
    pub auto_restart: bool,
    pub enabled: bool,
    pub domains: Vec<String>,
    pub created_at: i64,
    /// 单元名（`panel-app-<name>.service`），前端拿它去看日志
    pub unit: String,
    /// systemd 状态；探测失败为 `null` —— **不因探测失败让整页列表 500**
    /// （面板不该因为 systemd 抽风就看不了自己的数据）。
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub name: String,
    pub runtime: String,
    pub workdir: String,
    /// 留空则用运行时的默认命令（`AppRuntime::default_exec`）
    #[serde(default)]
    pub exec_start: Option<String>,
    #[serde(default)]
    pub run_user: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub auto_restart: Option<bool>,
    #[serde(default)]
    pub domains: Vec<String>,
    /// 停用态：只登记，不装单元、不建站点（对齐 `sites` 的停用守恒）
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PatchReq {
    #[serde(default)] pub runtime: Option<String>,
    #[serde(default)] pub workdir: Option<String>,
    #[serde(default)] pub exec_start: Option<String>,
    #[serde(default)] pub run_user: Option<String>,
    #[serde(default)] pub env: Option<Vec<(String, String)>>,
    #[serde(default)] pub port: Option<u16>,
    #[serde(default)] pub auto_restart: Option<bool>,
    #[serde(default)] pub domains: Option<Vec<String>>,
    #[serde(default)] pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ActReq {
    /// `start` / `stop` / `restart`
    pub act: String,
}

// ═══════════════════════════ 运行时目录 ═══════════════════════════

/// 运行时静态元数据（**前端下拉的唯一数据源**）。
///
/// 单一事实来源在 `panel_os::AppRuntime`，前端**不得**再硬编码一份语言表——
/// 两处各写一份必然漂移（新增运行时时前端静默缺项）。
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfo {
    pub key: &'static str,
    pub label: &'static str,
    pub default_port: u16,
    /// 面板包白名单里的系统包名；`null` = 面板不托管该运行时
    pub runtime_pkg: Option<&'static str>,
    pub default_exec: &'static str,
    /// 典型框架（确认没选错）
    pub typical: &'static str,
    /// 用途：这运行时跑的是什么（用户最先问的问题）
    pub purpose: &'static str,
    /// 什么情况下该选它（决策依据，不做性能排名）
    pub choose_when: &'static str,
    pub build_hint: &'static str,
}

pub async fn catalog(
    State(_state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    let items: Vec<RuntimeInfo> = AppRuntime::ALL
        .into_iter()
        .map(|r| RuntimeInfo {
            key: r.key(),
            label: r.label(),
            default_port: r.default_port(),
            runtime_pkg: r.runtime_pkg(),
            default_exec: r.default_exec(),
            typical: r.typical(),
            purpose: r.purpose(),
            choose_when: r.choose_when(),
            build_hint: r.build_hint(),
        })
        .collect();
    Ok(ok(serde_json::json!({ "runtimes": items })))
}

// ═══════════════════════════ 行映射 ═══════════════════════════

/// SELECT 列序的**唯一**定义处。列序与 `app_tuple` 的 `r.get(N)` 一一对应。
///
/// 改这里必须同步改那里——本项目已在 `SITE_SELECT` 上踩过一次错位坑
/// （加子查询列导致后续全部偏移，只有实机 apply 才暴露）。
const APP_SELECT: &str = "SELECT id, name, runtime, workdir, exec_start, run_user, env_json, \
                                port, auto_restart, enabled, domains_json, created_at \
                         FROM apps";

/// 按 id 查。**不用 `format!` 拼 WHERE**——门禁 ci/check-layering.sh [5] 禁止 SQL 字符串
/// 拼接（拼错了列序/漏了占位符都只在运行时报），故这里写死完整语句。
const APP_SELECT_BY_ID: &str = "SELECT id, name, runtime, workdir, exec_start, run_user, env_json, \
                                      port, auto_restart, enabled, domains_json, created_at \
                               FROM apps WHERE id = ?1";

type RawTuple = (
    i64, String, String, String, String, Option<String>, String,
    i64, i64, i64, String, i64,
);

/// 行 → 元组。**抽成独立函数而非内联闭包**：内联的话回归测试只能另抄一份逻辑，
/// 抄的必然漂移＝等于没测（本项目在 `databases.rs` 上踩过）。
fn app_tuple(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawTuple> {
    Ok((
        r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?,
        r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?,
    ))
}

/// DB 原始行（运行时 / JSON 尚未解析）。
#[derive(Debug, Clone)]
struct RawApp {
    id: i64,
    name: String,
    runtime: String,
    workdir: String,
    exec_start: String,
    run_user: Option<String>,
    env: Vec<(String, String)>,
    port: i64,
    auto_restart: i64,
    enabled: i64,
    domains: Vec<String>,
    created_at: i64,
}

fn tuple_to_raw(t: &RawTuple) -> RawApp {
    RawApp {
        id: t.0,
        name: t.1.clone(),
        runtime: t.2.clone(),
        workdir: t.3.clone(),
        exec_start: t.4.clone(),
        run_user: t.5.clone(),
        env: parse_pairs(&t.6),
        port: t.7,
        auto_restart: t.8,
        enabled: t.9,
        domains: parse_str_list(&t.10),
        created_at: t.11,
    }
}

fn parse_pairs(raw: &str) -> Vec<(String, String)> {
    serde_json::from_str::<Vec<Vec<String>>>(raw)
        .unwrap_or_default()
        .into_iter()
        .filter(|v| v.len() == 2)
        .map(|mut v| {
            let val = v.pop().unwrap_or_default();
            let k = v.pop().unwrap_or_default();
            (k, val)
        })
        .collect()
}

fn parse_str_list(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

// ═══════════════════════════ 查询 ═══════════════════════════

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    let tuples = state
        .pool
        .with(|conn| {
            let mut st = conn.prepare(APP_SELECT).map_err(db_err)?;
            let it = st.query_map([], app_tuple).map_err(db_err)?;
            it.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
        })
        .await?;
    // 一次性批量快照：N 个应用只起 1 次 `systemctl is-active`，避免列表逐单元各起一次进程。
    let raws: Vec<RawApp> = tuples.iter().map(tuple_to_raw).collect();
    let unit_names: Vec<UnitName> = raws.iter().filter_map(|r| unit_of(&r.name).ok()).collect();
    let snap = state.os.services().statuses(&unit_names).await.unwrap_or_default();
    let mut out = Vec::with_capacity(raws.len());
    for r in &raws {
        let state_name = unit_of(&r.name)
            .ok()
            .and_then(|u| snap.get(u.as_str()))
            .map(|s| format!("{s:?}").to_lowercase());
        out.push(row_to_out(r, state_name));
    }
    Ok(ok(out))
}

/// 单个应用详情。
pub async fn get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    let app = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("app"))?;
    Ok(ok(row_to_out(&app, resolve_state(&state, &app.name).await)))
}

async fn fetch_one(state: &Shared, id: i64) -> ApiResult<Option<RawApp>> {
    let t = state
        .pool
        .with(move |conn| {
            use rusqlite::OptionalExtension;
            let mut st = conn.prepare(APP_SELECT_BY_ID).map_err(db_err)?;
            st.query_row([id], app_tuple).optional().map_err(db_err)
        })
        .await?;
    Ok(t.as_ref().map(tuple_to_raw))
}

/// 单条路径的状态解析（列表走一次性批量快照 `statuses`，无需逐条 `status`）。
async fn resolve_state(state: &Shared, name: &str) -> Option<String> {
    match unit_of(name) {
        Ok(u) => state
            .os
            .services()
            .status(&u)
            .await
            .ok()
            .map(|s| format!("{s:?}").to_lowercase()),
        Err(_) => None,
    }
}

/// 行 → DTO。`state_name` 由调用方解析（列表走一次性批量快照 `statuses`，单条走 `resolve_state`），
/// 状态探测失败只把该项 `state` 置 `null`，**不让整页 500**。
fn row_to_out(row: &RawApp, state_name: Option<String>) -> AppOut {
    let runtime = AppRuntime::from_key(&row.runtime).unwrap_or(AppRuntime::Custom);
    AppOut {
        id: row.id,
        name: row.name.clone(),
        runtime: runtime.key().to_string(),
        runtime_label: runtime.label().to_string(),
        workdir: row.workdir.clone(),
        exec_start: row.exec_start.clone(),
        run_user: row.run_user.clone(),
        env: row.env.clone(),
        port: row.port as u16,
        auto_restart: row.auto_restart != 0,
        enabled: row.enabled != 0,
        domains: row.domains.clone(),
        created_at: row.created_at,
        unit: app_unit_name(&row.name),
        state: state_name,
    }
}

// ═══════════════════════════ 写入校验 ═══════════════════════════

/// 应用名：走**站点名白名单**（`rules::is_valid_site_name`）。
///
/// 同一个名字要同时用作 systemd 单元名片段与反代站点名，两边规则必须统一；
/// 再经 `app_unit_name` 折叠 `..`（那条规则允许 `a..b`，而 systemd 禁 `..`）。
fn validate_name(raw: &str) -> ApiResult<String> {
    let n = raw.trim().to_string();
    if !panel_core::rules::is_valid_site_name(&n) {
        return Err(ApiError::bad_request(
            "name",
            "应用名须字母数字开头，后可接字母数字与 . _ -，长度 1~63",
        ));
    }
    // 派生的单元名必须仍能过 systemd 校验，否则出现「校验过却装不进去」的死角
    if !panel_core::rules::is_valid_unit_name(&app_unit_name(&n)) {
        return Err(ApiError::bad_request("name", "该名字派生的 systemd 单元名不合法"));
    }
    Ok(n)
}

fn validate_runtime(raw: &str) -> ApiResult<AppRuntime> {
    AppRuntime::from_key(raw.trim()).ok_or_else(|| {
        ApiError::bad_request(
            "runtime",
            format!("不支持的运行时 {raw}（可选：node/go/rust/java/python/dotnet/php/custom）"),
        )
    })
}

/// 工作目录：**必须是已存在的绝对路径**。
///
/// 刻意**不**套站点根沙箱——应用代码常在 `/opt`、`/srv`、`~/apps`，
/// 那条沙箱是给「站点静态文件」用的，不该压到用户自己的项目上。
/// 但换行必须拒（会打断 systemd 单元结构）。
fn validate_workdir(raw: &str) -> ApiResult<String> {
    let w = raw.trim().to_string();
    if w.is_empty() {
        return Err(ApiError::bad_request("workdir", "工作目录不能为空"));
    }
    if w.contains(['\n', '\r', '\0']) {
        return Err(ApiError::bad_request("workdir", "工作目录含非法控制字符"));
    }
    let p = PathBuf::from(&w);
    if !p.is_absolute() {
        return Err(ApiError::bad_request("workdir", "工作目录须为绝对路径"));
    }
    if !p.is_dir() {
        return Err(ApiError::bad_request(
            "workdir",
            format!("工作目录不存在：{w}（请先放好代码）"),
        ));
    }
    Ok(w)
}

/// 启动命令：非空 + 无换行/控制字符（换行等于往单元文件注入新指令）。
fn validate_exec(raw: &str) -> ApiResult<String> {
    let e = raw.trim().to_string();
    if e.is_empty() {
        return Err(ApiError::bad_request("exec_start", "启动命令不能为空"));
    }
    if e.contains(['\n', '\r', '\0']) {
        return Err(ApiError::bad_request("exec_start", "启动命令含非法控制字符"));
    }
    // systemd 只接受纯命令名或绝对路径；`./app` 这类相对路径会让单元永不启动
    // （bad unit file setting）——提前拦下，别让用户建完才发现 systemd 拒载。
    if !panel_os::exec_start_is_valid(&e) {
        return Err(ApiError::bad_request(
            "exec_start",
            "启动命令须为程序名（如 app）或绝对路径（如 /opt/blog/app），systemd 不接受 ./app 这类相对路径",
        ));
    }
    Ok(e)
}

/// ELF 架构预检：把「Exec format error」这种要翻日志的玄学，变成创建时就说的原因。
///
/// 刻意做成**预检而非拒绝**：只在文件确实是 ELF 且架构与本机不符时报错。
/// 脚本、解释器启动（`node server.js`）、文件尚未编译（`app` 还不存在）都放行——
/// 那三种情况都不是架构问题，拦下反而挡正常用法。
fn check_exec_arch(workdir: &str, exec: &str) -> ApiResult<()> {
    if let Some(msg) = panel_os::exec_arch_mismatch(std::path::Path::new(workdir), exec) {
        return Err(ApiError::bad_request("exec_start", msg));
    }
    Ok(())
}

/// 端口占用预检：**别的应用**占着这个端口 → 拒（附占用者名字）；
/// 系统里有进程在监听 → 只**放行但不作数**（那多半就是这个应用自己，或
/// 用户刻意先起了调试进程）。绝不因为「端口被占」就把常见用法全禁掉。
///
/// 同时查「库内其它 app 的端口」——两个 app 抢 8080 会互相把对方的进程踢掉，
/// 这是**面板自己制造的**冲突，必须拦。系统级监听检测放在 `panel_os::port_in_use`，
/// 读 `/proc/net/tcp`（零子进程）。
async fn check_port(
    state: &Shared,
    port: u16,
    self_id: i64,
    self_name: &str,
) -> ApiResult<()> {
    // ① 面板内的冲突：另一个 app 已经登记了同一端口
    if let Some(other) = find_port_owner(state, port, self_id).await {
        return Err(ApiError::bad_request(
            "port",
            format!(
                "端口 {port} 已被应用「{other}」占用——两个应用抢同一端口会互相把对方踢下线，请换一个",
            ),
        ));
    }
    // ② 系统级监听：仅提示性质，不拒（自我占用是常态）
    let _ = (self_name, panel_os::port_in_use(port));
    Ok(())
}

/// 查库内占用某端口的**其它**应用名（`self_id` 排除自己，便于编辑时复用）。
async fn find_port_owner(state: &Shared, port: u16, self_id: i64) -> Option<String> {
    let p = i64::from(port);
    let sid = self_id;
    state
        .pool
        .with(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT name FROM apps WHERE port = ?1 AND id != ?2 LIMIT 1",
                    rusqlite::params![p, sid],
                    |r| r.get::<_, String>(0),
                )
                .ok())
        })
        .await
        .ok()
        .flatten()
}

/// 应用默认运行用户：`site-<应用名>`。
///
/// 站点隔离的**最小可用粒度**。此前 `run_user` 字段虽在单元渲染里生效，
/// 但**没人给它赋值** → 业务应用默认以 root 跑：一旦应用被拿下（RCE、
/// 依赖投毒、反代 SSRF），攻击者直接拿到 root。这是托管型面板最不该留的默认。
///
/// 命名用 `site-` 前缀而不是裸应用名：`site-blog` 与系统里可能存在的 `blog`
/// 用户彻底分开，且一眼能看出是面板托管的（`useradd` 的系统用户也会带
/// `system` 标记，两边都能查）。
pub fn default_run_user(app_name: &str) -> String {
    format!("site-{app_name}")
}

/// 确保运行用户存在；用户显式填了 `root` 等既有用户时**只校验、不创建**。
///
/// 返回实际使用的运行用户。刻意**不递归 chown 工作目录**——那会改掉用户
/// 仓库里所有文件的所有者（可能正被 git 跟踪，且是不可逆的副作用）；
/// 只把 `User=` 写进单元，目录权限由用户自己按需调整。
async fn ensure_run_user(state: &Shared, app_name: &str, explicit: Option<&str>) -> ApiResult<String> {
    let wanted: String = explicit
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| default_run_user(app_name));
    if !panel_core::rules::is_valid_system_user(&wanted) {
        return Err(ApiError::bad_request(
            "run_user",
            format!("运行用户「{wanted}」不合法（只允许小写字母/数字/下划线/连字符，且须字母或下划线开头）"),
        ));
    }
    // 已存在的用户（root / www-data / 上次建的 site-*）直接复用，不碰系统
    if state.os.users().exists(&wanted).await.unwrap_or(false) {
        return Ok(wanted);
    }
    // 用户显式指定了一个不存在的名字 → **不擅自创建**：那很可能是拼错了。
    // 只有面板自己派生的 `site-<应用名>` 才自动创建。
    if explicit.is_some() {
        return Err(ApiError::bad_request(
            "run_user",
            format!("系统里没有用户「{wanted}」，请先创建，或留空由面板自动分配 site-<应用名>"),
        ));
    }
    state
        .os
        .users()
        .ensure(&wanted, true, true)
        .await
        .map_err(|e| {
            ApiError::bad_request(
                "run_user",
                format!("无法创建运行用户「{wanted}」（面板需 root 权限）：{e}"),
            )
        })?;
    Ok(wanted)
}

fn validate_port(p: u16) -> ApiResult<u16> {
    if p == 0 {
        return Err(ApiError::bad_request("port", "端口须在 1~65535 之间"));
    }
    Ok(p)
}

fn validate_env(env: &[(String, String)]) -> ApiResult<Vec<(String, String)>> {
    for (k, v) in env {
        if k.is_empty() || k.contains(['\n', '\r', '\0', '=']) {
            return Err(ApiError::bad_request("env", format!("环境变量名不合法：{k:?}")));
        }
        if v.contains(['\n', '\r', '\0']) {
            return Err(ApiError::bad_request(
                "env",
                format!("环境变量 {k} 的值含非法控制字符"),
            ));
        }
    }
    Ok(env.to_vec())
}

/// 域名：逐个过域名校验器（≥2 级 + 真实 TLD + IPv4 语义）。
fn validate_domains(domains: &[String]) -> ApiResult<Vec<String>> {
    if domains.is_empty() {
        return Err(ApiError::bad_request(
            "domains",
            "至少需要一个域名（面板据此自动建反代站点）",
        ));
    }
    let mut out = Vec::with_capacity(domains.len());
    for d in domains {
        let dom = panel_core::domain(d.trim())
            .map_err(|e| ApiError::bad_request("domains", format!("域名 {d:?} 不合法：{e}")))?;
        out.push(dom.as_str().to_string());
    }
    Ok(out)
}

// ═══════════════════════════ 投影：单元 + 站点 ═══════════════════════════

/// 应用名 → 已校验的 `UnitName`（派生 `panel-app-<name>.service`）。
fn unit_of(name: &str) -> ApiResult<UnitName> {
    panel_core::unit_name(&app_unit_name(name)).map_err(|e| {
        // 60000 = 面板内部错误（各模块 `?` 自动转换走同一码）
        ApiError::new(
            60000,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("单元名不合法：{e}"),
        )
    })
}

/// 渲染单元文本（纯函数，不落盘）。
fn build_unit(app: &RawApp) -> ApiResult<String> {
    let unit = unit_of(&app.name)?;
    let spec = AppUnitSpec {
        unit: unit.as_str().to_string(),
        description: format!("ForkPanel 应用：{}", app.name),
        workdir: PathBuf::from(&app.workdir),
        exec_start: app.exec_start.clone(),
        run_user: app.run_user.clone(),
        env: app.env.clone(),
        port: app.port as u16,
        auto_restart: app.auto_restart != 0,
    };
    Ok(render_app_unit(&spec))
}

/// 建/更新反代站点（`kind=proxy`，上游指向应用端口）。
///
/// 复用 `sites::apply`——**绝不另写一份 nginx 渲染**，两处必然漂移。
///
/// `session` 显式下传而非从全局取：调用方就是当前请求，把它自己的 Session 递进去，
/// 内部 `require(site.manage)` 校验的仍是**本用户的真实权限**，不因「内部调用」绕过。
async fn apply_site(state: &Shared, session: &Session, app: &RawApp) -> ApiResult<()> {
    let req = super::sites::ApplyReq {
        name: app.name.clone(),
        domains: app.domains.clone(),
        // 反代站点不读 root，但 `apply` 要求非空。给站点根下的同名目录，
        // 语义上「这个站点对应的目录」；反代路径不会用到它。
        root: app.name.clone(),
        force_https: Some(true),
        kind: Some("proxy".into()),
        upstreams: Some(vec![format!("http://127.0.0.1:{}", app.port)]),
        fpm: None,
        spa: None,
        redirect_target: None,
        redirect_code: None,
        // 应用托管只建**单一反代站**；多路由是用户在「网站」页自己编排的事，
        // 这里不代填（传 None = 保留库中现有路由表，与 apply 的缺省语义一致）。
        routes: None,
        waf: None,
        // 应用托管是**面板自己**在维护配置，从不涉及"手动维护重新生成"——恒 None。
        regen_conf: None,
        // 应用托管不暴露「自定义片段」编辑（那是「网站」页的高级功能）——恒 None = 保留库中现值。
        custom_conf: None,
        // 高级配置（020）同理由面板自己维护，应用侧不开放：www 跳转关、TLS 取默认档、
        // HSTS 不开、无伪静态（应用多为反代站，伪静态对它无意义）。
        www_redirect: Some("off".to_string()),
        tls_profile: Some("modern".to_string()),
        tls_min: Some("TLSv1.2".to_string()),
        hsts: Some(false),
        hsts_max_age: Some(300),
        hsts_sub: Some(false),
        hsts_preload: Some(false),
        rewrite_preset: Some("none".to_string()),
        rewrite_custom: None,
        // 访问控制 / Basic Auth / 反代 / 日志（021）同理由面板自己维护，应用侧不开放
        ip_allow: None,
        ip_deny: None,
        auth_basic: Some(false),
        auth_user: None,
        auth_pass: None,
        lb_policy: Some("least_conn".to_string()),
        proxy_connect_timeout: Some(60),
        proxy_send_timeout: Some(60),
        proxy_read_timeout: Some(60),
        log_access: Some(false),
        log_error: Some(false),
        log_error_level: Some("error".to_string()),
    };
    // 直接 `?`：apply 失败必须让本次保存失败——否则 DB 说已建站、nginx 却没配置，
    // 用户下次排查会面对「应用在、站点不在」的错觉。
    // `apply` 返回 Json（must_use）——这里只要它成功，具体载荷由调用方各自查。
    let _ = super::sites::apply(State(state.clone()), Auth(session.clone()), PanelJson(req)).await?;
    Ok(())
}

/// 撤下自动建的站点。**失败不致命**——单元移除才是停用主路径。
///
/// 「站点没了但单元还在」只是不再对外服务；反过来「单元没了但站点还在反代空端口」
/// 会让用户看到 502，故宁可留前者。
async fn remove_site(state: &Shared, session: &Session, app: &RawApp) {
    let Some(row) = find_site_by_name(state, &app.name).await else {
        return;
    };
    let _ = super::sites::delete(State(state.clone()), Auth(session.clone()), AxPath(row)).await;
}

/// 按名字查站点 id（自动建的站点与本表同名）。
async fn find_site_by_name(state: &Shared, name: &str) -> Option<i64> {
    let name = name.to_string();
    // DB 异常与「查无此站」都归为 None——调用方本就只是「有则删、无则跳过」。
    state
        .pool
        .with(move |conn| {
            Ok(conn
                .query_row("SELECT id FROM sites WHERE name = ?1", [name], |r| {
                    r.get::<_, i64>(0)
                })
                .ok())
        })
        .await
        .ok()
        .flatten()
}

// ═══════════════════════════ CRUD ═══════════════════════════

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;

    let name = validate_name(&req.name)?;
    let runtime = validate_runtime(&req.runtime)?;
    let workdir = validate_workdir(&req.workdir)?;
    let exec = match req.exec_start.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => validate_exec(v)?,
        _ => {
            let d = runtime.default_exec();
            if d.is_empty() {
                return Err(ApiError::bad_request(
                    "exec_start",
                    "自定义运行时必须填写启动命令",
                ));
            }
            d.to_string()
        }
    };
    check_exec_arch(&workdir, &exec)?;
    let port = validate_port(req.port.unwrap_or(runtime.default_port()))?;
    // 端口冲突要在写库**之前**查：库里已有同名应用会走另一条分支，
    // 但端口冲突与「是否已存在」无关，新建时同样要拦。
    check_port(&state, port, 0, &name).await?;
    let env = validate_env(&req.env)?;
    let enabled = req.enabled.unwrap_or(true);
    // 停用态**仍校验并保存域名**：否则用户「先建后启用」时会发现域名全丢、还得重填。
    // 真正该跳过校验的场景只有 enabled=true 且传了空域名（那时必报错，因为要建站点）。
    let domains = if req.domains.is_empty() {
        if enabled {
            return Err(ApiError::bad_request(
                "domains",
                "至少需要一个域名（面板据此自动建反代站点）",
            ));
        }
        Vec::new()
    } else {
        validate_domains(&req.domains)?
    };

    // 先查重：给友好报错（撞唯一索引会变成 500 内部错误）
    if name_exists(&state, &name).await {
        return Err(ApiError::conflict(format!("应用 {name} 已存在")));
    }

    let mut row = RawApp {
        id: 0,
        name: name.clone(),
        runtime: runtime.key().to_string(),
        workdir,
        exec_start: exec,
        // 运行用户：缺省自动分配 `site-<应用名>`（系统用户 + nologin），
        // 并确保它存在。此前留空 = 以 root 跑业务进程。
        run_user: Some(ensure_run_user(&state, &name, req.run_user.as_deref()).await?),
        env,
        port: i64::from(port),
        auto_restart: i64::from(req.auto_restart.unwrap_or(true)),
        enabled: i64::from(enabled),
        domains,
        created_at: now_unix(),
    };

    if enabled {
        let unit_text = build_unit(&row)?;
        // 顺序不可颠倒：先装单元再下发站点。反过来 nginx 会转发到还不存在的进程。
        state
            .os
            .services()
            .install_unit(&unit_of(&name)?, &unit_text)
            .await?;
        apply_site(&state, &s, &row).await?;
    }

    row.id = insert_row(&state, &row).await?;
    audit(&state, &s, "app.create", &name, "ok").await;
    Ok(ok(row_to_out(&row, resolve_state(&state, &row.name).await)))
}

pub async fn patch(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<PatchReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    let Some(cur) = fetch_one(&state, id).await? else {
        return Err(ApiError::not_found("app"));
    };

    let mut next = cur.clone();
    if let Some(r) = req.runtime.as_deref() {
        next.runtime = validate_runtime(r)?.key().to_string();
    }
    if let Some(w) = req.workdir.as_deref() {
        next.workdir = validate_workdir(w)?;
    }
    if let Some(e) = req.exec_start.as_deref() {
        next.exec_start = validate_exec(e)?;
    }
    if req.run_user.is_some() {
        // 显式传了（含传空串 = 「改回自动」）才重算；没传这个字段就沿用库里的值，
        // 免得每次编辑都去碰系统用户。
        next.run_user = Some(ensure_run_user(&state, &cur.name, req.run_user.as_deref()).await?);
    }
    if let Some(env) = req.env.as_ref() {
        next.env = validate_env(env)?;
    }
    if let Some(p) = req.port {
        next.port = i64::from(validate_port(p)?);
    }
    if let Some(a) = req.auto_restart {
        next.auto_restart = i64::from(a);
    }
    if let Some(d) = req.domains.as_ref() {
        next.domains = validate_domains(d)?;
    }
    // 架构预检放在**所有字段合并之后**：改的可能是 workdir、也可能是 exec_start，
    // 只在「exec 变化」时查会漏掉「换到另一个目录里的同架构错产物」。
    if req.exec_start.is_some() || req.workdir.is_some() {
        check_exec_arch(&next.workdir, &next.exec_start)?;
    }
    // 端口冲突同理：**任何**字段变化都可能带着新端口进来（含 runtime 切换
    // 改写 default_port 的情况），故在合并后统一查，并排除自己。
    if req.port.is_some() || req.runtime.is_some() {
        check_port(&state, next.port as u16, id, &next.name).await?;
    }

    let new_enabled = req.enabled.unwrap_or(cur.enabled != 0);
    let was_enabled = cur.enabled != 0;
    next.enabled = i64::from(new_enabled);

    if new_enabled {
        let unit_text = build_unit(&next)?;
        state
            .os
            .services()
            .install_unit(&unit_of(&next.name)?, &unit_text)
            .await?;
        // 域名/端口变了、或从停用转启用 → 必须重新下发（上游端口可能也变了）
        if req.domains.is_some() || req.port.is_some() || req.enabled == Some(true) || !was_enabled {
            apply_site(&state, &s, &next).await?;
        }
    } else {
        // 停用：撤站点 + 停单元 + 删单元文件（对称清理，不留孤儿）
        remove_site(&state, &s, &cur).await;
        let unit = unit_of(&next.name)?;
        if let Err(stop_err) = state.os.services().stop(&unit).await {
            eprintln!("[warn] app.patch 停用：停单元 {unit} 失败（仍继续删单元文件）: {stop_err}");
        }
        state.os.services().remove_unit(&unit).await?;
        // ⚠ **不**清空 domains：停用只是「不托管」，不是「销毁」。
        //   清掉的话用户之后想重新启用会发现域名全丢、还得重填（本次实机就踩到：
        //   enabled=false 时存的域名被清，重新启用 → apply 报 "at least one domain required"）。
        //   真正删除应用走 DELETE，那里会连站点一起撤。
    }

    update_row(&state, id, &next).await?;
    audit(&state, &s, "app.patch", &next.name, "ok").await;
    Ok(ok(row_to_out(&next, resolve_state(&state, &next.name).await)))
}

pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    let Some(app) = fetch_one(&state, id).await? else {
        return Err(ApiError::not_found("app"));
    };

    // 顺序：撤站点（对外停止服务）→ 停单元 → 删单元文件 → 删 DB 行。
    // 刻意**不回滚已完成的清理**：下一次删除（幂等）会继续清。
    remove_site(&state, &s, &app).await;
    let unit = unit_of(&app.name)?;
    if let Err(stop_err) = state.os.services().stop(&unit).await {
        eprintln!("[warn] app.delete：停单元 {unit} 失败（仍继续删单元文件）: {stop_err}");
    }
    state.os.services().remove_unit(&unit).await?;
    delete_row(&state, id).await?;

    audit(&state, &s, "app.delete", &app.name, "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

/// 启停/重启。`stop` **不删单元**（那是 `patch(enabled=false)` / `delete` 的事），
/// 只把进程停下——用户临时挂起服务时用。
pub async fn act(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<ActReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "app.act")?;
    let Some(app) = fetch_one(&state, id).await? else {
        return Err(ApiError::not_found("app"));
    };
    let unit = unit_of(&app.name)?;
    let svc = state.os.services();
    match req.act.as_str() {
        "start" => svc.start(&unit).await?,
        "stop" => svc.stop(&unit).await?,
        "restart" => svc.restart(&unit).await?,
        other => {
            return Err(ApiError::bad_request(
                "act",
                format!("不支持的操作 {other}（可选 start/stop/restart）"),
            ))
        }
    }
    audit(&state, &s, "app.act", &app.name, "ok").await;
    Ok(ok(row_to_out(&app, resolve_state(&state, &app.name).await)))
}

// ═══════════════════════════ DB 写入 ═══════════════════════════

async fn name_exists(state: &Shared, name: &str) -> bool {
    let name = name.to_string();
    state
        .pool
        .with(move |conn| {
            Ok(conn
                .query_row("SELECT 1 FROM apps WHERE name = ?1", [name], |_| Ok(()))
                .is_ok())
        })
        .await
        .unwrap_or(false)
}

/// 写入一律走 `state.db.exec`（writer actor），**不用 `pool.with`**。
///
/// 两个原因：① 写必须串行（actor 天然满足，`pool.with` 是并发直连）；② `pool.with`
/// 的闭包要求 `'static`，捕获 `&RawApp` 会借用逃逸——须先把要用的字段克隆出来。
async fn insert_row(state: &Shared, a: &RawApp) -> ApiResult<i64> {
    // 逐字段克隆：闭包要`'static`，不能借用入参。
    let name = a.name.clone();
    let runtime = a.runtime.clone();
    let workdir = a.workdir.clone();
    let exec_start = a.exec_start.clone();
    let run_user = a.run_user.clone();
    let env_json = serde_json::to_string(&a.env).unwrap_or_else(|_| "[]".into());
    let domains_json = serde_json::to_string(&a.domains).unwrap_or_else(|_| "[]".into());
    let port = a.port;
    let auto_restart = a.auto_restart;
    let enabled = a.enabled;
    let created_at = a.created_at;

    // 同理：id 必须**在拿到 reply 后**再回查——闭包内`last_insert_rowid()`
    // 属于那条连接，而 reply 只回传 WriteAck（项目既有约束）。
    let new_id = state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO apps (name, runtime, workdir, exec_start, run_user, env_json, port, \
                                   auto_restart, enabled, domains_json, created_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                rusqlite::params![
                    name, runtime, workdir, exec_start, run_user,
                    env_json, port, auto_restart, enabled, domains_json, created_at,
                ],
            )
            .map_err(db_err)?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;

    if new_id.rows_changed == 0 {
        return Err(ApiError::new(
            60000,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "插入应用失败",
        ));
    }
    // 按唯一键回查id：唯一约束保证至多一行，且避免依赖连接外的 rowid
    let created_name = a.name.clone();
    let id = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT id FROM apps WHERE name = ?1",
                [created_name],
                |r| r.get::<_, i64>(0),
            )
            .map_err(db_err)
        })
        .await?;
    Ok(id)
}

async fn update_row(state: &Shared, id: i64, a: &RawApp) -> ApiResult<()> {
    let runtime = a.runtime.clone();
    let workdir = a.workdir.clone();
    let exec_start = a.exec_start.clone();
    let run_user = a.run_user.clone();
    let env_json = serde_json::to_string(&a.env).unwrap_or_else(|_| "[]".into());
    let domains_json = serde_json::to_string(&a.domains).unwrap_or_else(|_| "[]".into());
    let port = a.port;
    let auto_restart = a.auto_restart;
    let enabled = a.enabled;

    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE apps SET runtime=?2, workdir=?3, exec_start=?4, run_user=?5, env_json=?6, \
                        port=?7, auto_restart=?8, enabled=?9, domains_json=?10 WHERE id=?1",
                rusqlite::params![
                    id, runtime, workdir, exec_start, run_user,
                    env_json, port, auto_restart, enabled, domains_json,
                ],
            )
            .map_err(db_err)?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

async fn delete_row(state: &Shared, id: i64) -> ApiResult<()> {
    state
        .db
        .exec(move |conn| {
            conn.execute("DELETE FROM apps WHERE id = ?1", [id])
                .map_err(db_err)?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实建表 + 走**生产映射** `app_tuple` 读回。
    /// 若行映射写错类型或列序，本测试会红（不另抄一份逻辑）。
    #[test]
    fn app_tuple_reads_real_row() {
        use rusqlite::Connection;
        let mut conn = Connection::open_in_memory().unwrap();
        panel_db::migrate::apply(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO apps (name, runtime, workdir, exec_start, run_user, env_json, port, \
                               auto_restart, enabled, domains_json, created_at) \
             VALUES ('blog','go','/srv/blog','./app',NULL,'[[\"PORT\",\"3000\"]]',3000,1,1,'[\"blog.example.com\"]',1700000000)",
            [],
        )
        .unwrap();

        const SEL: &str = "SELECT id, name, runtime, workdir, exec_start, run_user, env_json, \
                                   port, auto_restart, enabled, domains_json, created_at \
                            FROM apps WHERE name = ?1";
        let mut st = conn.prepare(SEL).unwrap();
        let t = st.query_row(["blog"], app_tuple).unwrap();
        let raw = tuple_to_raw(&t);

        assert_eq!(raw.name, "blog");
        assert_eq!(raw.runtime, "go");
        assert_eq!(raw.port, 3000);
        assert_eq!(raw.env, vec![("PORT".to_string(), "3000".to_string())]);
        assert_eq!(raw.domains, vec!["blog.example.com".to_string()]);
        assert_ne!(raw.enabled, 0);
    }

    #[test]
    fn bad_json_degrades_to_empty_not_panic() {
        // 脏数据不该让整页列表 500
        assert!(parse_pairs("{oops").is_empty());
        assert!(parse_str_list("[1,2]").is_empty());
        let src = vec![("A".to_string(), "1".to_string())];
        assert_eq!(parse_pairs(&serde_json::to_string(&src).unwrap()), src);
    }

    #[test]
    fn exec_rejects_injection_and_control_chars() {
        assert!(validate_exec("").is_err());
        assert!(validate_exec("node\n[Install]").is_err());
        assert!(validate_exec(" node server.js ").is_ok());
    }

    #[test]
    fn env_rejects_newline_and_eq_in_key() {
        assert!(validate_env(&[("A".into(), "1".into())]).is_ok());
        assert!(validate_env(&[("A\nB".into(), "1".into())]).is_err());
        assert!(validate_env(&[("A=B".into(), "1".into())]).is_err());
        assert!(validate_env(&[("A".into(), "x\ny".into())]).is_err());
    }

    #[test]
    fn name_must_survive_unit_derivation() {
        assert!(validate_name("blog").is_ok());
        assert!(validate_name("my-app").is_ok());
        // 站点名白名单拒绝这些
        assert!(validate_name("").is_err());
        assert!(validate_name("a b").is_err());
        assert!(validate_name("-lead").is_err());
        assert!(validate_name(".").is_err());
    }

    /// 造一个可渲染单元的最小应用行。
    fn raw_app_for_test() -> RawApp {
        RawApp {
            id: 1,
            name: "blog".into(),
            runtime: "go".into(),
            workdir: "/opt/blog".into(),
            exec_start: "app".into(),
            run_user: None,
            env: Vec::new(),
            port: 8080,
            auto_restart: 1,
            enabled: 1,
            domains: vec!["blog.example.com".into()],
            created_at: 0,
        }
    }

    /// 默认运行用户必须是 `site-<应用名>`：业务进程**绝不该以 root 跑**。
    ///
    /// 这条判据的价值在于「字段在、但没人赋值」这类静默失效——`run_user`
    /// 从第一天起就在单元渲染里生效，却始终为 None，于是所有应用默认 root。
    #[test]
    fn default_run_user_is_site_scoped() {
        assert_eq!(default_run_user("blog"), "site-blog");
        assert_eq!(default_run_user("my-app"), "site-my-app");
        // 派生的名字必须能过系统用户校验（否则 ensure 一律失败）
        for n in ["blog", "my-app", "a", "app_2"] {
            let u = default_run_user(n);
            assert!(
                panel_core::rules::is_valid_system_user(&u),
                "{u} 必须是通过系统用户校验的名字"
            );
        }
    }

    /// 单元渲染里 `User=` / `Group=` 必须真的落进去（此前字段永远为 None，
    /// 于是渲染出的单元**根本没有** User= 行）。
    #[test]
    fn app_unit_contains_user_directive() {
        let mut a = raw_app_for_test();
        a.run_user = Some("site-blog".into());
        let unit = build_unit(&a).expect("应能渲染单元");
        assert!(unit.contains("User=site-blog"), "单元应含 User=:\n{unit}");
        assert!(unit.contains("Group=site-blog"), "单元应含 Group=:\n{unit}");
        // run_user 为 None 时不应输出空的 User=（systemd 会因空值拒载）
        let mut root_run = raw_app_for_test();
        root_run.run_user = None;
        let u2 = build_unit(&root_run).unwrap();
        assert!(!u2.contains("User="), "无运行用户时不该输出 User=:\n{u2}");
    }

    /// systemd 的硬约束：`ExecStart` 不接受相对路径（实测 bad unit file setting）。
    /// 这类坑编译期与纯函数测试都看不见，只有真 `systemd-analyze verify` 才暴露。
    #[test]
    fn exec_start_must_be_command_name_or_absolute_path() {
        assert!(panel_os::exec_start_is_valid("node server.js"));
        assert!(panel_os::exec_start_is_valid("app"));
        assert!(panel_os::exec_start_is_valid("/opt/blog/app"));
        assert!(!panel_os::exec_start_is_valid("./app"));
        assert!(!panel_os::exec_start_is_valid("../app"));
        assert!(!panel_os::exec_start_is_valid("bin/app"));
        assert!(!panel_os::exec_start_is_valid(""));
        // validate_exec 也必须拦住（面板侧的第一道门）
        assert!(validate_exec("./app").is_err());
        assert!(validate_exec("app").is_ok());
    }

    #[test]
    fn runtime_unknown_is_rejected_not_defaulted() {
        assert!(validate_runtime("go").is_ok());
        assert!(validate_runtime("rust").is_ok());
        assert!(validate_runtime("cobol").is_err());
    }
}