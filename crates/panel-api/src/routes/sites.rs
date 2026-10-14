//! 站点与 SSL 证书（设计方案 §2.4）。
//!
//! # 核心闭环：配置变更必须"先校验，后生效"
//! ```text
//! 渲染配置 → validate（nginx -t）→ 失败则中止   → 成功则原子替换 → reload
//!                                    ↑ 旧配置未动，站点不受影响
//! ```
//! 直接写配置文件再 reload，语法错误会导致 **reload 失败但文件已改**，
//! 下次重启服务就起不来。这是自建面板最常见的线上事故。
//!
//! # 一个必须写清的约束
//! `validate` 通常耗时 50~200ms（`nginx -t`）。**它绝不能落在写事务内**——
//! 实测长事务耗时 1:1 传导给其他写者（持有 1000ms → 其他写者等 1046ms）。
//!
//! # 数据模型 vs 配置下发
//! 站点的「定义」（`sites` 表）与「下发到 Web 服务器的配置」是两件事：
//! - `create` / `get` / `patch` / `delete` 只读写 `sites` 表（纯 DB，无需 web server 在场）。
//! - `apply` / `reload` 才真正渲染并下发到 Web 服务器；若 `webserver.manage`
//!   能力位为 `no`（本机未装 nginx/caddy），这两个动作诚实返回 501，绝不伪造成功。
//! - SSL 的 ACME 签发/续期同理：能力位 `ssl.acme` 为 `no` 时诚实 501；
//!   证书「删除」是纯 DB 操作，始终可用。
//! - `conf_get` / `conf_put` / `conf_restore`：站点已落盘配置的**原始读写**。
//!   GET 按落库 `conf_path` 读（不接受前端路径）；PUT 仅 owner、写入前必过
//!   `nginx -t`，成功后站点转「手动维护」（表单保存不再覆盖，见 016 迁移）；
//!   `conf_restore` 按表单重新渲染，恢复面板托管。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, audit_system, Auth, MaybeAuth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    response::{IntoResponse, Response},
    Json,
};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use panel_core::{cap_keys, domain, PanelError, Result, SafePath};
use panel_os::{paths::slug, tls};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─────────────── 数据行 / DTO ───────────────

/// `sites` 表的原始行（含从 `ssl_certs` 派生的 tls 标记）。
struct RawSite {
    id: i64,
    name: String,
    /// JSON 数组字符串
    domains: String,
    root: String,
    kind: String,
    enabled: i32,
    created_at: i64,
    tls: bool,
    waf_enabled: i32,
    waf_profile: Option<String>,
    waf_rate: Option<i64>,
    waf_burst: Option<i64>,
    /// JSON 数组：反代后端列表（static 站点为 NULL）
    upstreams_json: Option<String>,
    /// php-fpm 目标（unix:/path.sock | host:port）；非 php 站点为 NULL
    fpm: Option<String>,
    /// SPA 回退标志（kind=static 时有效）：1 = 开启
    spa: i32,
    /// 整站重定向目标 URL（kind=redirect 时存在）；其余为 NULL
    redirect_target: Option<String>,
    /// 整站重定向状态码 301/302/307/308（kind=redirect 时存在）；其余为 NULL
    redirect_code: Option<i64>,
    /// apply 写入的 nginx 配置路径；**从未成功下发则为 NULL / 空串**。
    /// 这是「配置是否真落到 Web 服务器」的唯一判据——`enabled` 只表示期望状态。
    conf_path: Option<String>,
    /// 多路由表 JSON 数组；非多路由站点为 `'[]'`（迁移给了 DEFAULT，不会有 NULL）
    routes_json: String,
    /// 手动维护标记（016 迁移）：1 = 磁盘配置由用户原始编辑维护，表单保存不覆盖
    manual_conf: i32,
    /// 部署指纹（017 迁移）：「配置文件最后一次落盘时表单部署相关字段的指纹」。
    /// 与当前表单指纹（`fingerprint_of`）不等 ⇒ 手动维护期间两边已分叉（conf_stale）。
    /// NULL = 无记录（旧行）——对手动维护站点按「未同步」对待。
    conf_snapshot: Option<String>,
    /// 自定义配置片段（019 迁移）：渲染时插在主 server 块尾部（托管态随表单
    /// 重渲染；纳入部署指纹——改动会自动触发未同步检测）。NULL / 空串 = 无。
    custom_conf: Option<String>,
    /// www ↔ 非 www 跳转（020）：off | to_www | to_bare
    www_redirect: String,
    /// 加密套件档位（020）：compat | modern | strict
    tls_profile: String,
    /// TLS 版本下限（020）：TLSv1 | TLSv1.1 | TLSv1.2 | TLSv1.3
    tls_min: String,
    hsts: i32,
    hsts_max_age: i64,
    hsts_sub: i32,
    hsts_preload: i32,
    /// 伪静态模板（020）：none | wordpress | laravel | thinkphp | typecho | discuz | custom
    rewrite_preset: String,
    rewrite_custom: Option<String>,
    /// **派生列**（非 sites 表的列）：最新留档版本的内容 hash，用于「外部修改检测」。
    /// NULL = 该站尚无留档，此时无从判定，一律按「无外部修改」处理（不谎报）。
    last_ver_hash: Option<String>,
    /// IP 白名单（021，逗号分隔）；NULL/空 = 不限制
    ip_allow: Option<String>,
    /// IP 黑名单（021，逗号分隔）；ip_allow 非空时被忽略
    ip_deny: Option<String>,
    auth_basic: i32,
    /// Basic Auth 用户名（口令不落库）
    auth_user: Option<String>,
    /// 负载均衡策略（021）：round_robin | least_conn | ip_hash
    lb_policy: String,
    proxy_connect_timeout: i64,
    proxy_send_timeout: i64,
    proxy_read_timeout: i64,
    /// 站点独立访问日志（021）：1 = 渲染 access_log 指令
    log_access: i32,
    log_error: i32,
    /// 错误日志级别（021）
    log_error_level: String,
    /// 对象说明（备注，022）：这台站点干嘛的、为什么这么配——手写意图，非系统日志
    remark: String,
    /// 上次成功下发（deploy + reload）的 unix 秒（023）；NULL = 从未下发。
    /// 停用（撤下配置）不更新——「撤下」不是「下发」。
    last_applied_at: Option<i64>,
}

impl RawSite {
    /// 库中现存的 WAF 配置（`waf_enabled=0` → `None`）。
    fn waf(&self) -> Option<panel_os::WafSpec> {
        if self.waf_enabled == 0 {
            return None;
        }
        Some(panel_os::WafSpec {
            profile: self
                .waf_profile
                .as_deref()
                .and_then(panel_os::WafProfile::parse)
                // 档位认不出来时退回**基础档**，而不是退回"无防护"：
                // 配置解析失败不该静默变成"一条规则都不拦"。
                .unwrap_or(panel_os::WafProfile::Basic),
            rate_per_sec: self.waf_rate.and_then(|n| u32::try_from(n).ok()).filter(|n| *n > 0),
            burst: self.waf_burst.and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct SiteOut {
    pub id: i64,
    pub name: String,
    pub domains: Vec<String>,
    pub root: String,
    /// API 口径：static | proxy（schema 内为 static | reverse_proxy）
    pub kind: String,
    pub enabled: bool,
    /// 配置是否已真实下发到 Web 服务器（`conf_path` 非空）。
    /// 与 `enabled`（期望状态）区分：新建后未 apply 时 enabled=true 而 deployed=false。
    pub deployed: bool,
    /// 是否已有绑定的 SSL 证书
    pub tls: bool,
    pub created_at: i64,
    /// WAF 是否启用
    pub waf_enabled: bool,
    /// WAF 档位（basic / strict）；未启用为 null
    pub waf_profile: Option<String>,
    /// CC 限速（次/秒）；null = 不限速
    pub waf_rate_per_sec: Option<i64>,
    pub waf_burst: Option<i64>,
    /// 反代后端列表（kind=proxy 时存在）
    pub upstreams: Option<Vec<String>>,
    /// php-fpm 目标（kind=php 时存在）
    pub fpm: Option<String>,
    /// SPA 回退（kind=static 时有效）：true = 启用 history 路由回退
    pub spa: bool,
    /// 整站重定向目标 URL（kind=redirect 时存在）；其余为 null
    pub redirect_target: Option<String>,
    /// 整站重定向状态码（kind=redirect 时存在；301/302/307/308）；其余为 null
    pub redirect_code: Option<u16>,
    /// 多路由表（kind=routed 时非空；其余恒为 `[]`——不返回 null，省前端分支）
    pub routes: Vec<RouteOut>,
    /// 手动维护：true = 磁盘上的配置文件由用户原始编辑维护，表单保存不再覆盖它
    /// （可用「恢复面板托管」清零；停用/重新启用路径同样清零）
    pub manual_conf: bool,
    /// 未同步（仅 manual_conf=true 且站点启用时有意义）：表单的部署相关字段与
    /// 「配置文件最后一次落盘时的指纹」不一致——即面板里看到的规格 ≠ 线上文件。
    /// 由「重新生成配置」（conf/restore）或重新下发（apply）清零。
    pub conf_stale: bool,
    /// 自定义配置片段（019）：插在主 server 块尾部；null = 无。owner 可编辑，
    /// 随「保存并应用」重渲染生效（托管态语义）。
    pub custom_conf: Option<String>,
    /// www ↔ 非 www 跳转（020）：off | to_www | to_bare
    pub www_redirect: String,
    /// 加密套件档位（020）：compat | modern | strict
    pub tls_profile: String,
    /// TLS 版本下限（020）：TLSv1 | TLSv1.1 | TLSv1.2 | TLSv1.3
    pub tls_min: String,
    /// HSTS（020）：开启后响应带 Strict-Transport-Security
    pub hsts: bool,
    pub hsts_max_age: i64,
    pub hsts_include_sub: bool,
    pub hsts_preload: bool,
    /// 伪静态模板（020）：none | wordpress | laravel | thinkphp | typecho | discuz | custom
    pub rewrite_preset: String,
    /// preset=custom 时的原始 rewrite 文本；其余为 null
    pub rewrite_custom: Option<String>,
    /// 外部修改（020）：磁盘上的配置文件与「最后一次落盘的内容」**不一致**——
    /// 文件在面板之外被改动过。面板**不会**静默覆盖它（无从判断是人工有意、
    /// 脚本误写还是攻击），由用户决定「重新生成覆盖」或「改成自定义片段」。
    /// 外部修改（020）：磁盘上的配置文件与「最后一次落盘的内容」**不一致**——
    /// 文件在面板之外被改动过。面板**不会**静默覆盖它（无从判断是人工有意、
    /// 脚本误写还是攻击），由用户决定「重新生成覆盖」或「改为自定义片段」。
    pub conf_external: bool,
    /// IP 白名单（021）：为空数组 = 不限制
    pub ip_allow: Vec<String>,
    /// IP 黑名单（021）：ip_allow 非空时前端应把它置灰（二者互斥）
    pub ip_deny: Vec<String>,
    /// HTTP Basic Auth 是否开启（021）
    pub auth_basic: bool,
    /// Basic Auth 用户名；未设置为 null（**口令永不返回**）
    pub auth_user: Option<String>,
    /// 负载均衡策略（021，多后端生效）：round_robin | least_conn | ip_hash
    pub lb_policy: String,
    /// 代理超时三项（021，秒）
    pub proxy_connect_timeout: i64,
    pub proxy_send_timeout: i64,
    pub proxy_read_timeout: i64,
    /// 是否写站点独立访问日志（021）
    pub log_access: bool,
    pub log_error: bool,
    /// 错误日志级别（021）
    pub log_error_level: String,
    /// 对象说明（备注，022）：这台站点干嘛的、为什么这么配
    pub remark: String,
    /// 上次成功下发（deploy + reload）的 unix 秒（023）；null = 从未下发
    pub last_applied_at: Option<i64>,
}

/// API 口径的单条路由。
///
/// 与 `panel_os::RouteKind` 一一对应，但**枚举值用小写字符串**（而非枚举类型）——
/// 前端只需原样回传，不该依赖 Rust 侧的枚举形状。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RouteOut {
    /// URL 前缀，必须以 `/` 开头；`/` 为兜底（最多一条）
    pub prefix: String,
    /// `proxy` | `static` | `php`
    pub kind: String,
    /// kind=proxy：后端列表
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<String>,
    /// kind=static：未命中是否回退 /index.html
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub spa: bool,
    /// kind=php：php-fpm 目标
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fpm: Option<String>,
    /// kind=php：入口脚本（相对站点根，须以 `/` 开头）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub front_controller: Option<String>,
    /// kind=static：该路由自己的根目录（可选，覆盖站点级 root）。留空继承站点级
    /// root；填了则这条静态路由从它自己的目录读文件。须落在 site_root 之内
    /// （apply 阶段经 resolve_site_root 约束，防路径穿越）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

/// API 口径（`proxy`）→ 库内口径（`reverse_proxy`）。
///
/// 两套名字的换算**只在这两个函数里**，不散落到别处——散开的下场就是之前那样：
/// `apply` 一律写死 `'static'`、`to_out` 又把一切非 `reverse_proxy` 都当静态，
/// 于是反代站在列表里显示成"静态"，前端编辑后一点"应用"就把线上站点改成静态站。
fn kind_to_db(k: &panel_os::SiteKind) -> &'static str {
    match k {
        panel_os::SiteKind::Static => "static",
        panel_os::SiteKind::ReverseProxy { .. } => "reverse_proxy",
        panel_os::SiteKind::Php { .. } => "php",
        panel_os::SiteKind::Redirect { .. } => "redirect",
        panel_os::SiteKind::Routed { .. } => "routed",
    }
}

/// 库内口径 → API 口径。未知值一律落到 `static`（**不是** `proxy`）：
/// 认不出来时降级成"静态"只是显示不准，认成反代则会让人按错误前提去改配置。
fn kind_to_api(k: &str) -> &'static str {
    match k {
        "reverse_proxy" => "proxy",
        "php" => "php",
        "redirect" => "redirect",
        "routed" => "routed",
        _ => "static",
    }
}

/// 库内 JSON → API 口径的路由列表。
///
/// 反向（API → 库内）由 `validate_routes` 负责：它先规范化再落库，
/// 所以这里读出来的都是**已规范化**的值，可直接回显给前端再提交。
fn routes_from_json(raw: &str) -> Vec<RouteOut> {
    serde_json::from_str(raw).unwrap_or_default()
}

/// 校验并规范化路由表。返回库内形态（`SiteRoutes`）。
///
/// 校验点（每条都对应一类真实事故或 nginx 行为）：
/// - **prefix 必须以 `/` 开头**——否则 nginx 的 `location` 语义不对；
/// - **prefix 只允许安全字符**（字母数字 / `-` `_` `.` `~` 与 `/`）——它会**直接进
///   nginx 配置文本**，带 `;`、`{`、`}`、空白、换行就是配置注入（可借此写出任意指令）；
/// - **不得重复**——两条同 prefix 谁生效取决于书写顺序，用户无法预期；
/// - **`/` 最多一条**——兜底重复同样无法预期；
/// - **必须有兜底 `/`**——否则漏掉的路径会落到 nginx 的默认 server（**别的站点**），
///   表现为「本站点随机串到别的站」，比 404 更难排查；
/// - 每条路由按 kind 校验必填项（反代至少一个后端 / PHP 必须给 front controller）。
fn validate_routes(routes: &[RouteOut]) -> ApiResult<panel_os::SiteRoutes> {
    if routes.is_empty() {
        return Err(ApiError::bad_request("routes", "至少需要一条路由"));
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::with_capacity(routes.len());
    let mut has_root = false;

    for (i, r) in routes.iter().enumerate() {
        let field = "routes";
        let prefix = r.prefix.trim();
        if !prefix.starts_with('/') {
            return Err(ApiError::bad_request(
                field,
                format!("第 {} 条路由的前缀「{}」必须以 / 开头", i + 1, r.prefix),
            ));
        }
        if prefix.len() > 128 {
            return Err(ApiError::bad_request(field, "路由前缀过长（上限 128 字符）"));
        }
        // 归一化：去掉末尾多余的 `/`（`/api/` ≡ `/api`），根前缀保持 `/`
        let prefix = if prefix.len() > 1 { prefix.trim_end_matches('/') } else { "/" };
        // 注入防线：只放行 URL 路径里合法且无害的字符
        if !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~'))
        {
            return Err(ApiError::bad_request(
                field,
                format!("路由前缀「{prefix}」含非法字符（只允许字母数字与 / - _ . ~）"),
            ));
        }
        if seen.contains(&prefix) {
            return Err(ApiError::bad_request(field, format!("路由前缀「{prefix}」重复")));
        }
        seen.push(prefix);
        if prefix == "/" {
            if has_root {
                return Err(ApiError::bad_request(field, "兜底路由「/」最多一条"));
            }
            has_root = true;
        }

        let kind = match r.kind.as_str() {
            "static" => {
                // 路由级 root：可选。只做轻量语法校验（注入字符），实际约束到 site_root
                // 在 apply 阶段做（那里有 state，与站点级 root 同一条 resolve_site_root）。
                let root = r.root.as_deref().map(str::trim).filter(|v| !v.is_empty());
                if let Some(rv) = root {
                    if rv.contains([';', '\n', '\r', '{', '}']) {
                        return Err(ApiError::bad_request(
                            field,
                            format!("第 {} 条路由（前缀 {prefix}）的根目录含非法字符", i + 1),
                        ));
                    }
                }
                panel_os::RouteKind::Static { spa: r.spa, root: root.map(|s| s.to_string()) }
            }
            "proxy" => {
                let ups: Vec<String> = r.upstreams.iter().map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
                if ups.is_empty() {
                    return Err(ApiError::bad_request(
                        field,
                        format!("第 {} 条路由（前缀 {prefix}）的反代至少需要一个后端", i + 1),
                    ));
                }
                panel_os::RouteKind::Proxy { upstreams: ups }
            }
            "php" => {
                let fpm = r.fpm.as_deref().map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| {
                    ApiError::bad_request(field, format!("第 {} 条路由（前缀 {prefix}）缺少 php-fpm 目标", i + 1))
                })?;
                // front_controller 必填：`^~` 前缀会屏蔽 `location ~ \.php$`，
                // 没有它就没有任何入口（详见 panel_os::RouteKind::Php 的说明）
                let fc = r
                    .front_controller
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        ApiError::bad_request(
                            field,
                            format!("第 {} 条路由（前缀 {prefix}）缺少 PHP 入口脚本（front_controller）", i + 1),
                        )
                    })?;
                if !fc.starts_with('/') {
                    return Err(ApiError::bad_request(
                        field,
                        format!("PHP 入口脚本「{fc}」必须以 / 开头（相对站点根）"),
                    ));
                }
                if fc.contains([';', '\n', '\r', '{', '}']) {
                    return Err(ApiError::bad_request(field, "PHP 入口脚本含非法字符"));
                }
                panel_os::RouteKind::Php { fpm: fpm.to_string(), front_controller: fc.to_string() }
            }
            other => {
                return Err(ApiError::bad_request(
                    field,
                    format!("第 {} 条路由的 kind「{other}」无效（只支持 proxy / static / php）", i + 1),
                ))
            }
        };
        out.push(panel_os::SiteRoute { prefix: prefix.to_string(), kind });
    }

    if !has_root {
        return Err(ApiError::bad_request(
            "routes",
            "必须有一条前缀为 / 的兜底路由（否则漏掉的路径会落到别的站点去）",
        ));
    }
    Ok(panel_os::SiteRoutes { routes: out })
}

/// 部署指纹：影响「渲染结果 / 磁盘配置内容」的字段快照（017 迁移）。
///
/// ⚠ **单一事实源**：apply 落库、conf PUT、conf restore、`to_out` 判定四处
/// 必须走同一个函数——本项目的高发 bug 就是「同一约束两条路径漏配」，指纹
/// 一旦两处口径不同，就会误报/漏报「未同步」。
///
/// 拼接用不可见分隔符 `\u{1f}`：这些值都可能含任意字符（域名 JSON、路由 JSON、
/// 路径），没有分隔符就可能出现 `("a", "bc")` 与 `("ab", "c")` 撞同一指纹。
///
/// ⚠ 新增「部署相关」字段（会影响 render 输出的）必须同时加进这里，
///   否则改该字段不会触发「未同步」提示（静默分叉复发）。
fn deploy_fingerprint(
    name: &str,
    domains_json: &str,
    root: &str,
    kind: &str,
    spa: bool,
    upstreams_json: Option<&str>,
    fpm: Option<&str>,
    redirect_target: Option<&str>,
    redirect_code: Option<i64>,
    waf_enabled: bool,
    waf_profile: Option<&str>,
    waf_rate: Option<i64>,
    waf_burst: Option<i64>,
    routes_json: &str,
    custom_conf: Option<&str>,
    // 高级配置（020）打包成的 JSON：9 个字段合成一段，避免参数表继续膨胀；
    // serde_json 键序固定（字典序），指纹可复现。
    advanced_json: &str,
) -> String {
    let mut s = String::with_capacity(256);
    let push = |s: &mut String, v: &str| { s.push_str(v); s.push('\u{1f}'); };
    push(&mut s, name);
    push(&mut s, domains_json);
    push(&mut s, root);
    push(&mut s, kind);
    push(&mut s, if spa { "1" } else { "0" });
    push(&mut s, upstreams_json.unwrap_or(""));
    push(&mut s, fpm.unwrap_or(""));
    push(&mut s, redirect_target.unwrap_or(""));
    push(&mut s, &redirect_code.map(|c| c.to_string()).unwrap_or_default());
    push(&mut s, if waf_enabled { "1" } else { "0" });
    push(&mut s, waf_profile.unwrap_or(""));
    push(&mut s, &waf_rate.map(|c| c.to_string()).unwrap_or_default());
    push(&mut s, &waf_burst.map(|c| c.to_string()).unwrap_or_default());
    push(&mut s, routes_json);
    // 自定义片段（019）参与渲染 → 必须进指纹：否则改了它「未同步」不会亮。
    push(&mut s, custom_conf.unwrap_or(""));
    // 高级配置（020）同样影响渲染输出（跳转块 / TLS 指令 / 伪静态）
    push(&mut s, advanced_json);
    s
}

/// 空列表 → None（渲染器据此整段跳过，不输出空注释块）。
fn nonempty(v: Vec<String>) -> Option<Vec<String>> {
    if v.is_empty() { None } else { Some(v) }
}

/// 逗号 / 空白分隔的列表字符串 → Vec（空 → 空数组：前端不必判断 null）。
fn split_list(v: &Option<String>) -> Vec<String> {
    v.as_deref()
        .map(|raw| {
            raw.split(|c: char| c == ',' || c.is_whitespace())
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 站点独立日志目录（021）：面板数据目录下的 `log/`。
fn site_log_dir(state: &Shared) -> std::path::PathBuf {
    state.os.paths().data_dir().join("log")
}

/// 该站点的 access / error 日志路径；未开启对应开关则为 None（沿用 nginx 全局日志）。
fn site_log_paths(
    state: &Shared,
    domains: &[String],
    access: bool,
    error: bool,
) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    let stem = slug(domains.first().map(|x| x.as_str()).unwrap_or("site"));
    let d = site_log_dir(state);
    (
        if access { Some(d.join(format!("{stem}.access.log"))) } else { None },
        if error { Some(d.join(format!("{stem}.error.log"))) } else { None },
    )
}

/// 代理超时归一（021）：1~3600 秒；缺省取库中现值（缺省再缺省为 60）。
fn timeout_db(
    req: Option<i64>,
    cur: Option<i64>,
    field: &'static str,
) -> std::result::Result<i64, ApiError> {
    match req {
        None => Ok(cur.unwrap_or(60)),
        Some(n) if (1..=3600).contains(&n) => Ok(n),
        Some(_) => Err(ApiError::bad_request(field, "超时需在 1 ~ 3600 秒之间")),
    }
}

/// 解析并校验 IP / CIDR 列表（这些值**直接进 nginx 配置文本**，必须白名单校验）。
/// 只接受 IPv4 与可选的前缀长度（0~32）——IPv6 暂不支持，宁可拒也不猜。
fn parse_ip_list(raw: &str) -> std::result::Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let t = part.trim();
        if t.is_empty() { continue }
        if !is_ipv4_or_cidr(t) {
            return Err(ApiError::bad_request(
                "ip_allow",
                format!("IP 地址「{t}」不合法（仅支持 IPv4 或 IPv4/前缀）"),
            ));
        }
        out.push(t.to_string());
    }
    Ok(out)
}

/// IPv4（点分十进制，每段 0~255）或 `IPv4/0~32`。
fn is_ipv4_or_cidr(s: &str) -> bool {
    let (ip, mask) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 { return false }
    for o in &octets {
        if o.is_empty() || o.len() > 3 || !o.bytes().all(|b| b.is_ascii_digit()) { return false }
        if o.parse::<u16>().map(|n| n > 255).unwrap_or(true) { return false }
    }
    match mask {
        None => true,
        Some(m) => {
            !m.is_empty()
                && m.bytes().all(|b| b.is_ascii_digit())
                && m.parse::<u8>().map(|n| n <= 32).unwrap_or(false)
        }
    }
}

/// Basic Auth 的 htpasswd 文件落盘路径（021）。
fn htpasswd_path(state: &Shared, domains: &[String]) -> std::path::PathBuf {
    let stem = slug(domains.first().map(|x| x.as_str()).unwrap_or("site"));
    state
        .os
        .paths()
        .data_dir()
        .join("htpasswd")
        .join(format!("panel-{stem}.htpasswd"))
}

/// 高级配置（020）的指纹片段。**读侧**（库值）与**写侧**（apply 解析后的值）
/// 必须用同一组键——两边键名或顺序不同就会误报「未同步」。
fn advanced_json_of(r: &RawSite) -> String {
    serde_json::json!({
        "hsts": r.hsts,
        "hsts_max_age": r.hsts_max_age,
        "hsts_preload": r.hsts_preload,
        "hsts_sub": r.hsts_sub,
        "rewrite_custom": r.rewrite_custom,
        "rewrite_preset": r.rewrite_preset,
        "tls_min": r.tls_min,
        "tls_profile": r.tls_profile,
        "rewrite_preset": r.rewrite_preset,
        "www": r.www_redirect,
        // 021：访问控制 / Basic Auth / 反代 / 日志同样影响渲染输出
        "ip_allow": r.ip_allow,
        "ip_deny": r.ip_deny,
        "auth_basic": r.auth_basic,
        "auth_user": r.auth_user,
        "lb_policy": r.lb_policy,
        "pct": r.proxy_connect_timeout,
        "pst": r.proxy_send_timeout,
        "prt": r.proxy_read_timeout,
        "log_access": r.log_access,
        "log_error": r.log_error,
        "log_level": r.log_error_level,
    })
    .to_string()
}

/// 当前库值的部署指纹（读侧口径：全部取**落库原样**——与 apply 写入口径同源）。
fn fingerprint_of(r: &RawSite) -> String {
    deploy_fingerprint(
        &r.name,
        &r.domains,
        &r.root,
        &r.kind,
        r.spa != 0,
        r.upstreams_json.as_deref(),
        r.fpm.as_deref(),
        r.redirect_target.as_deref(),
        r.redirect_code,
        r.waf_enabled != 0,
        r.waf_profile.as_deref(),
        r.waf_rate,
        r.waf_burst,
        &r.routes_json,
        r.custom_conf.as_deref(),
        &advanced_json_of(r),
    )
}

/// 「未同步」判据：手动维护 + 启用 + 指纹缺失或与当前表单指纹不一致。
/// 指纹缺失（NULL，旧行）按未同步对待——有疑问时向「提示」倾斜，而不是假装同步。
fn conf_stale_of(r: &RawSite) -> bool {
    r.enabled != 0
        && r.manual_conf != 0
        && r.conf_snapshot.as_deref() != Some(fingerprint_of(r).as_str())
}

fn to_out(r: &RawSite) -> SiteOut {
    SiteOut {
        id: r.id,
        name: r.name.clone(),
        domains: serde_json::from_str(&r.domains).unwrap_or_default(),
        root: r.root.clone(),
        kind: kind_to_api(&r.kind).to_string(),
        enabled: r.enabled != 0,
        deployed: r.conf_path.as_deref().map(|p| !p.is_empty()).unwrap_or(false),
        tls: r.tls,
        created_at: r.created_at,
        waf_enabled: r.waf_enabled != 0,
        waf_profile: r.waf_profile.clone(),
        waf_rate_per_sec: r.waf_rate,
        waf_burst: r.waf_burst,
        upstreams: r.upstreams_json.as_deref().and_then(|s| serde_json::from_str(s).ok()),
        fpm: r.fpm.clone(),
        spa: r.spa != 0,
        redirect_target: r.redirect_target.clone(),
        redirect_code: r.redirect_code.map(|n| n as u16),
        routes: routes_from_json(&r.routes_json),
        manual_conf: r.manual_conf != 0,
        conf_stale: conf_stale_of(r),
        custom_conf: r.custom_conf.clone(),
        www_redirect: r.www_redirect.clone(),
        tls_profile: r.tls_profile.clone(),
        tls_min: r.tls_min.clone(),
        hsts: r.hsts != 0,
        hsts_max_age: r.hsts_max_age,
        hsts_include_sub: r.hsts_sub != 0,
        hsts_preload: r.hsts_preload != 0,
        rewrite_preset: r.rewrite_preset.clone(),
        rewrite_custom: r.rewrite_custom.clone(),
        // 外部修改需要读磁盘比对 hash（异步），to_out 是纯映射 → 由 list() 侧
        // 逐条补算（见 `list` 内的 external_of 循环）。
        conf_external: false,
        ip_allow: split_list(&r.ip_allow),
        ip_deny: split_list(&r.ip_deny),
        auth_basic: r.auth_basic != 0,
        auth_user: r.auth_user.clone(),
        lb_policy: r.lb_policy.clone(),
        proxy_connect_timeout: r.proxy_connect_timeout,
        proxy_send_timeout: r.proxy_send_timeout,
        proxy_read_timeout: r.proxy_read_timeout,
        log_access: r.log_access != 0,
        log_error: r.log_error != 0,
        log_error_level: r.log_error_level.clone(),
        remark: r.remark.clone(),
        last_applied_at: r.last_applied_at,
    }
}

fn db_err(e: rusqlite::Error) -> PanelError {
    PanelError::Database(e.to_string())
}

/// SELECT 公共投影（含派生的 tls 计数）
const SITE_SELECT: &str = "s.id, s.name, s.domains, s.root, s.kind, s.enabled, s.created_at,
       (SELECT COUNT(*) FROM ssl_certs c WHERE c.site_id = s.id) AS tls_count,
       s.waf_enabled, s.waf_profile, s.waf_rate, s.waf_burst,
       s.upstreams_json, s.fpm, s.spa, s.redirect_target, s.redirect_code, s.conf_path,
       s.routes_json, s.manual_conf, s.conf_snapshot, s.custom_conf,
       s.www_redirect, s.tls_profile, s.tls_min, s.hsts, s.hsts_max_age,
       s.hsts_sub, s.hsts_preload, s.rewrite_preset, s.rewrite_custom,
       (SELECT v.hash FROM site_conf_versions v WHERE v.site_id = s.id ORDER BY v.id DESC LIMIT 1) AS last_ver_hash,
       s.ip_allow, s.ip_deny, s.auth_basic, s.auth_user, s.lb_policy,
       s.proxy_connect_timeout, s.proxy_send_timeout, s.proxy_read_timeout,
       s.log_access, s.log_error, s.log_error_level, s.remark, s.last_applied_at";
// ⚠ 列序与下方 `r.get(N)` 一一对应。加列**一律追加到末尾**（routes_json = 18、
//   manual_conf = 19、conf_snapshot = 20、custom_conf = 21、www_redirect = 22 …
//   rewrite_custom = 29、last_ver_hash = 30、ip_allow = 31 … log_error_level = 42、
//   remark = 43、last_applied_at = 44），这样既有索引全部不变——
//   中途插列会让每个 r.get 静默错位（本项目已踩过一次：tls_count 子查询列把后续
//   整体后移一位，apply 运行时才报 `Invalid column type`）。
//   三个 fetch 函数中的 get(18…30) 必须同步（last_ver_hash 是子查询派生列）。

/// 站点查询 SQL。
///
/// 字段列表来自编译期常量 `SITE_SELECT`——**没有用户输入参与**，不存在注入面。
/// 走 `format!` 而不是字面量，是为了让字段列表只维护一份、避免三处查询各自漂移
/// （代价是曾被门禁 [5] 误判：那条规则只认 `prepare(&format!` 这个形状）。
fn site_sql(suffix: &str) -> String {
    format!("SELECT {SITE_SELECT} FROM sites s {suffix}")
}

async fn fetch_all(state: &Shared) -> Result<Vec<RawSite>> {
    state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare(&site_sql("ORDER BY s.id"))
                .map_err(db_err)?;
            let it = st
                .query_map([], |r| {
                    Ok(RawSite {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        domains: r.get(2)?,
                        root: r.get(3)?,
                        kind: r.get(4)?,
                        enabled: r.get(5)?,
                        created_at: r.get(6)?,
                        tls: r.get::<_, i64>(7)? > 0,
                        waf_enabled: r.get(8)?,
                        waf_profile: r.get(9)?,
                        waf_rate: r.get(10)?,
                        waf_burst: r.get(11)?,
                    upstreams_json: r.get(12)?,
                    fpm: r.get(13)?,
                    spa: r.get(14)?,
                    redirect_target: r.get(15)?,
                    redirect_code: r.get(16)?,
                    conf_path: r.get(17)?,
                    routes_json: r.get(18)?,
                    manual_conf: r.get(19)?,
                    conf_snapshot: r.get(20)?,
                    custom_conf: r.get(21)?,
                    www_redirect: r.get(22)?,
                    tls_profile: r.get(23)?,
                    tls_min: r.get(24)?,
                    hsts: r.get(25)?,
                    hsts_max_age: r.get(26)?,
                    hsts_sub: r.get(27)?,
                    hsts_preload: r.get(28)?,
                    rewrite_preset: r.get(29)?,
                    rewrite_custom: r.get(30)?,
                    last_ver_hash: r.get(31)?,
                    ip_allow: r.get(32)?,
                    ip_deny: r.get(33)?,
                    auth_basic: r.get(34)?,
                    auth_user: r.get(35)?,
                    lb_policy: r.get(36)?,
                    proxy_connect_timeout: r.get(37)?,
                    proxy_send_timeout: r.get(38)?,
                    proxy_read_timeout: r.get(39)?,
                    log_access: r.get(40)?,
                    log_error: r.get(41)?,
                    log_error_level: r.get(42)?,
                    remark: r.get(43)?,
                    last_applied_at: r.get(44)?,
                    })
                })
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(db_err)?);
            }
            Ok(v)
        })
        .await
}

async fn fetch_one(state: &Shared, id: i64) -> Result<Option<RawSite>> {
    state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(&site_sql("WHERE s.id = ?1"))
                .map_err(db_err)?;
            let mut it = st.query_map([id], |r| {
                Ok(RawSite {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    domains: r.get(2)?,
                    root: r.get(3)?,
                    kind: r.get(4)?,
                    enabled: r.get(5)?,
                    created_at: r.get(6)?,
                    tls: r.get::<_, i64>(7)? > 0,
                    waf_enabled: r.get(8)?,
                    waf_profile: r.get(9)?,
                    waf_rate: r.get(10)?,
                    waf_burst: r.get(11)?,
                    upstreams_json: r.get(12)?,
                    fpm: r.get(13)?,
                    spa: r.get(14)?,
                    redirect_target: r.get(15)?,
                    redirect_code: r.get(16)?,
                    conf_path: r.get(17)?,
                    routes_json: r.get(18)?,
                    manual_conf: r.get(19)?,
                    conf_snapshot: r.get(20)?,
                    custom_conf: r.get(21)?,
                    www_redirect: r.get(22)?,
                    tls_profile: r.get(23)?,
                    tls_min: r.get(24)?,
                    hsts: r.get(25)?,
                    hsts_max_age: r.get(26)?,
                    hsts_sub: r.get(27)?,
                    hsts_preload: r.get(28)?,
                    rewrite_preset: r.get(29)?,
                    rewrite_custom: r.get(30)?,
                    last_ver_hash: r.get(31)?,
                    ip_allow: r.get(32)?,
                    ip_deny: r.get(33)?,
                    auth_basic: r.get(34)?,
                    auth_user: r.get(35)?,
                    lb_policy: r.get(36)?,
                    proxy_connect_timeout: r.get(37)?,
                    proxy_send_timeout: r.get(38)?,
                    proxy_read_timeout: r.get(39)?,
                    log_access: r.get(40)?,
                    log_error: r.get(41)?,
                    log_error_level: r.get(42)?,
                    remark: r.get(43)?,
                    last_applied_at: r.get(44)?,
                })
            })
            .map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await
}

async fn fetch_one_by_name(state: &Shared, name: &str) -> Result<Option<RawSite>> {
    let name = name.to_string();
    state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(&site_sql("WHERE s.name = ?1"))
                .map_err(db_err)?;
            let mut it = st.query_map([name], |r| {
                Ok(RawSite {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    domains: r.get(2)?,
                    root: r.get(3)?,
                    kind: r.get(4)?,
                    enabled: r.get(5)?,
                    created_at: r.get(6)?,
                    tls: r.get::<_, i64>(7)? > 0,
                    waf_enabled: r.get(8)?,
                    waf_profile: r.get(9)?,
                    waf_rate: r.get(10)?,
                    waf_burst: r.get(11)?,
                    upstreams_json: r.get(12)?,
                    fpm: r.get(13)?,
                    spa: r.get(14)?,
                    redirect_target: r.get(15)?,
                    redirect_code: r.get(16)?,
                    conf_path: r.get(17)?,
                    routes_json: r.get(18)?,
                    manual_conf: r.get(19)?,
                    conf_snapshot: r.get(20)?,
                    custom_conf: r.get(21)?,
                    www_redirect: r.get(22)?,
                    tls_profile: r.get(23)?,
                    tls_min: r.get(24)?,
                    hsts: r.get(25)?,
                    hsts_max_age: r.get(26)?,
                    hsts_sub: r.get(27)?,
                    hsts_preload: r.get(28)?,
                    rewrite_preset: r.get(29)?,
                    rewrite_custom: r.get(30)?,
                    last_ver_hash: r.get(31)?,
                    ip_allow: r.get(32)?,
                    ip_deny: r.get(33)?,
                    auth_basic: r.get(34)?,
                    auth_user: r.get(35)?,
                    lb_policy: r.get(36)?,
                    proxy_connect_timeout: r.get(37)?,
                    proxy_send_timeout: r.get(38)?,
                    proxy_read_timeout: r.get(39)?,
                    log_access: r.get(40)?,
                    log_error: r.get(41)?,
                    log_error_level: r.get(42)?,
                    remark: r.get(43)?,
                    last_applied_at: r.get(44)?,
                })
            })
            .map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await
}

/// 把站点根目录解析到面板托管目录 `site_root` 之内（绝不越界到任意文件系统位置）。
/// `input` 为空时用站点名作子目录。owner 即使 `allowed_roots` 为空也能建站。
///
/// 目标目录**允许尚不存在**（首次建站时必然如此），故走 `resolve_within_for_create`；
/// 同时自愈式确保 `site_root` 根存在，避免根缺失导致解析失败。
/// 把用户输入的站点根目录归一化为「相对 `site_root`」的形式，供 `resolve_within_for_create` 消费。
///
/// 目录选择器（`/files/list`，树根固定在 `/`）与库里落地的 `root` 都是**绝对路径**，
/// 而沙箱 [`panel_os::paths::resolve_within_for_create`] 只收相对 `site_root` 的路径
/// （防 `/etc/passwd` 直传）。故：
/// - 落在 `base` 之内的绝对路径 → 剥掉 `base` 前缀，转成相对（与 `files.rs::relativize` 同源）；
/// - 恰好等于 `base` 的绝对路径 → `.`（站点根目录本身）；
/// - 落在 `base` 之外的绝对路径 → 原样返回，交给沙箱判 `PathEscape`（**绝不**放行越界）；
/// - 相对路径 / 空串 → 原样返回（空串由调用方回填为站点名）。
///
/// 抽成纯函数便于单测：不碰 `state`、不触磁盘。
fn site_root_rel(base: &Path, input: &str, name: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return name.to_string();
    }
    if Path::new(trimmed).is_absolute() {
        match Path::new(trimmed).strip_prefix(base) {
            Ok(rest) => {
                let r = rest.to_string_lossy().to_string();
                if r.is_empty() { ".".to_string() } else { r }
            }
            // 绝对但不属于 site_root：保持原样，下方沙箱会判越界
            Err(_) => trimmed.to_string(),
        }
    } else {
        trimmed.to_string()
    }
}

fn resolve_site_root(state: &Shared, input: &str, name: &str) -> Result<SafePath> {
    let base = state.os.paths().site_root();
    // 自愈：托管根目录缺失时先创建（首次部署或目录被清理）
    let _ = std::fs::create_dir_all(&base);
    let rel = site_root_rel(&base, input, name);
    let resolved = panel_os::paths::resolve_within_for_create(&base, &rel)
        .map_err(|_| PanelError::PathEscape(rel.to_string()))?;
    // 自愈：确保站点根目录存在且对 Web 服务器可读（0o755）。
    // 不再依赖 umask 隐式保证——否则 root:root + 严 umask 下 www-data 会 403。
    // create / apply 两路都经此函数，权限保障单一事实源。
    ensure_site_root_dir(resolved.as_path());
    Ok(resolved)
}

/// 确保站点根目录存在且权限为 `0o755`（目录对 Web 服务器运行身份可读+可进入）。
///
/// 设计为纯函数（只吃路径、不碰 `state`），便于单测；失败一律静默——
/// 目录创建/权限是附带的收尾动作，不该因它失败就让建站/应用主流程报错
/// （真实权限问题由 Web 服务器 reload 时的 403 暴露，比这里硬失败更易定位）。
fn ensure_site_root_dir(dir: &Path) {
    if panel_os::fs::ensure_dir(dir, 0o755).is_err() {
        // 仅记录，不中断主流程
        eprintln!("[sites] 确保站点根目录权限失败: {}", dir.display());
    }
}

// ─────────────── 站点列表 ───────────────

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let rows = fetch_all(&state).await?;
    let mut dtos: Vec<SiteOut> = rows.iter().map(to_out).collect();
    // 外部修改检测（020）：`to_out` 是纯映射不做 IO，故在这里逐条补算——比对
    // 「磁盘内容 hash」与「最新留档版本 hash」，不等 = 文件在面板之外被改过。
    // 站点数量级很小（读 N 个配置文件），不必为此再引入缓存层。
    for (dto, r) in dtos.iter_mut().zip(rows.iter()) {
        dto.conf_external = external_of(r).await;
    }
    Ok(ok(dtos))
}

/// 站点托管根目录（只读）。
///
/// 前端的「选择目录」用它作为初始定位：站点根目录**可被 config 的
/// `[paths] site_root` 覆盖**（默认才是 /var/www），前端不能硬编码，
/// 否则在自定义部署下打开选择器会直接落到一个不存在的目录。
/// 顺带自愈式建目录（与 `resolve_site_root` 一致），避免首次打开即报 not found。
pub async fn root_info(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let root = state.os.paths().site_root();
    let _ = std::fs::create_dir_all(&root);
    Ok(ok(serde_json::json!({ "site_root": root.display().to_string() })))
}

// ─────────────── 创建站点（仅写库） ───────────────

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub name: String,
    pub domains: Vec<String>,
    /// 站点根目录（相对 site_root；留空则用站点名）。仅允许落在 site_root 之内。
    pub root: Option<String>,
    /// 创建后是否「启用」（默认 true）。
    ///
    /// 注意 `create` 只写库、不下发配置——无论此处传什么，站点都要等一次
    /// `apply` 才会真正对外服务。因此该字段决定的是**落库的初始状态**，
    /// 供前端编辑页的开关回显；后续翻转由 `patch` 负责真正同步 Web 服务器。
    pub enabled: Option<bool>,
}

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    // 没有 Web 服务器底座就不许建站：否则用户拿到一个「建好了但永远打不开」的
    // 空中楼阁，列表还会亮绿标。与 apply / reload 共用同一道守卫——绝不只在前端
    // 置灰（那样绕开 UI 仍能造出打不开的站点）。
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let name = validate_site_name(&req.name)?;
    if req.domains.is_empty() {
        return Err(ApiError::bad_request("domains", "at least one domain required"));
    }
    let mut domains = Vec::with_capacity(req.domains.len());
    for d in &req.domains {
        let dom = domain(d.trim())
            .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
        domains.push(dom.as_str().to_string());
    }
    let root = resolve_site_root(&state, req.root.as_deref().unwrap_or(""), &name)?;
    let enabled = req.enabled.unwrap_or(true);
    // 目录已由 resolve_site_root 自愈式创建并设为 0o755（不再依赖 umask）
    let root_str = root.as_path().display().to_string();
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());
    let now = crate::now_unix();
    // 这些变量在闭包之外（audit / fallback）还要用，先克隆一份给写事务
    let name_db = name.clone();
    let root_db = root_str.clone();

    let res = state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO sites(name, domains, root, kind, webserver, enabled, created_at)
                 VALUES(?1, ?2, ?3, 'static', 'nginx', ?4, ?5)",
                rusqlite::params![name_db, domains_json, root_db, enabled as i32, now],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| {
                if e.to_string().contains("UNIQUE") {
                    PanelError::Conflict("site name exists".into())
                } else {
                    PanelError::Database(e.to_string())
                }
            })
        })
        .await;

    match res {
        Ok(_) => {
            audit(&state, &s, "site.create", &name, "ok").await;
            let out = fetch_one_by_name(&state, &name)
                .await?
                .map(|r| to_out(&r))
                .unwrap_or_else(|| SiteOut {
                    id: -1,
                    name,
                    domains,
                    root: root_str,
                    kind: "static".into(),
                    enabled: true,
                    deployed: false,
                    tls: false,
                    created_at: now,
                    // 兜底分支：站点刚建、WAF **默认关闭**——防护能力的默认值
                    // 应当是"不替用户做决定"，开启是显式动作。
                    waf_enabled: false,
                    waf_profile: None,
                    waf_rate_per_sec: None,
                    waf_burst: None,
                    upstreams: None,
                    fpm: None,
                    spa: false,
                    redirect_target: None,
                    redirect_code: None,
                    routes: Vec::new(),
                    // 兜底分支：新建站点必非手动维护（manual_conf 默认 0）
                    manual_conf: false,
                    // 非手动维护恒无「未同步」（指纹判据要求 manual_conf=1）
                    conf_stale: false,
                    custom_conf: None,
                    www_redirect: "off".to_string(),
                    tls_profile: "modern".to_string(),
                    tls_min: "TLSv1.2".to_string(),
                    hsts: false,
                    hsts_max_age: 300,
                    hsts_include_sub: false,
                    hsts_preload: false,
                    rewrite_preset: "none".to_string(),
                    rewrite_custom: None,
                    conf_external: false,
                    ip_allow: Vec::new(),
                    ip_deny: Vec::new(),
                    auth_basic: false,
                    auth_user: None,
                    lb_policy: "least_conn".to_string(),
                    proxy_connect_timeout: 60,
                    proxy_send_timeout: 60,
                    proxy_read_timeout: 60,
                    log_access: false,
                    log_error: false,
                    log_error_level: "error".to_string(),
                    // 兜底分支：站点刚创建，尚无对象说明
                    remark: String::new(),
                    // 兜底分支：刚创建、尚未 apply，无下发时间
                    last_applied_at: None,
                });
            Ok(ok(out))
        }
        Err(e) => Err(ApiError::from(e)),
    }
}

// ─────────────── 站点详情 ───────────────

pub async fn get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    match fetch_one(&state, id).await? {
        Some(r) => Ok(ok(to_out(&r))),
        None => Err(ApiError::not_found("site")),
    }
}

// ─────────────── 更新站点（仅写库） ───────────────

#[derive(Debug, Deserialize)]
pub struct PatchReq {
    /// 站点名称（**支持改名**）。
    ///
    /// 改名牵动的只有这块「登记标识」本身，其余三样都与 name 无关，因此改名不会让站点
    /// 离线、也不需要重新下发配置：nginx 配置按**域名**派生（conf 文件名取首个 server_name
    /// 的 slug、`server_name` 指令就是 domains 本身）、root 在**建站时已固化成绝对路径**、
    /// 证书按 domain 绑定。唯一约束是全局唯一，冲突按 Conflict 如实返回。
    pub name: Option<String>,
    pub domains: Option<Vec<String>>,
    pub root: Option<String>,
    pub enabled: Option<bool>,
    /// `enabled` 翻转时本接口会**真正同步 Web 服务器配置**：停用=移除配置并 reload，
    /// 启用=按落库行重新渲染下发。其余字段只写库，不重发配置。
    /// `force_https` 仅影响后续 `apply` 渲染，库不单列存储。
    pub force_https: Option<bool>,
}

/// 重建某站点的 nginx 配置并渲染，返回 `(conf_path, 渲染文本)`。
///
/// `domains` / `root` 由调用方**显式传入**，而不是从 `row` 里读：`patch` 必须在写库
/// **之前**就用新值下发配置，此时新值只存在于内存中。其余字段（WAF / 类型 / 证书）
/// 都是 `patch` 不会改动的部分，从 `row` 取即可。
/// `force_https` 未落库，按「有 TLS 即开启」的 apply 默认语义补齐。
async fn render_spec_for_row(
    state: &Shared,
    row: &RawSite,
    domains: &[String],
    root: &str,
) -> Result<(PathBuf, String)> {
    if domains.is_empty() {
        return Err(PanelError::Internal(format!(
            "站点 {} 缺少域名，无法重新渲染配置",
            row.name
        )));
    }
    if root.trim().is_empty() {
        return Err(PanelError::Internal(format!(
            "站点 {} 根目录为空，无法重新渲染配置",
            row.name
        )));
    }
    let root = PathBuf::from(root);

    // WAF：从落库值重建（与 apply 的 build_waf 落库口径一致）
    let waf = if row.waf_enabled != 0 {
        Some(panel_os::WafSpec {
            profile: panel_os::WafProfile::parse(row.waf_profile.as_deref().unwrap_or("basic"))
                .unwrap_or(panel_os::WafProfile::Basic),
            rate_per_sec: row.waf_rate.map(|n| n as u32),
            burst: row.waf_burst.map(|n| n as u32).unwrap_or(0),
        })
    } else {
        None
    };

    // 类型：从 kind + upstreams_json / fpm 重建
    let kind = match row.kind.as_str() {
        "reverse_proxy" => {
            let ups: Vec<String> = row
                .upstreams_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            panel_os::SiteKind::ReverseProxy { upstreams: ups }
        }
        "php" => panel_os::SiteKind::Php {
            fpm: row.fpm.clone().unwrap_or_default(),
        },
        "redirect" => panel_os::SiteKind::Redirect {
            target: row.redirect_target.clone().unwrap_or_default(),
            code: row.redirect_code.map(|n| n as u16).unwrap_or(301),
        },
        // 库里存的是**已校验**的 JSON（写入方validate 过），故这里解析失败即
        // 降级成静态站——宁可显示成"静态"也不能让整个列表页报错。
        "routed" => match routes_from_json(&row.routes_json)
            .iter()
            .cloned()
            .collect::<Vec<RouteOut>>()
            .as_slice()
        {
            [] => panel_os::SiteKind::Static,
            rs => match validate_routes(rs) {
                Ok(rr) => panel_os::SiteKind::Routed { routes: rr },
                Err(_) => panel_os::SiteKind::Static,
            },
        },
        _ => panel_os::SiteKind::Static,
    };
    // SPA 回退仅对 static 有意义；其余类型忽略
    let spa = row.kind == "static" && row.spa != 0;

    // 证书：沿用 apply 的查找逻辑（证书文件缺失则不启用 TLS）
    let (tls_cert, tls_key) = match cert_domains_for_site(state, row.id).await? {
        Some(ds) if !ds.is_empty() => {
            let (c, k) = cert_paths_for(state, &ds);
            if c.is_file() && k.is_file() {
                (Some(c), Some(k))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };
    let has_tls = tls_cert.is_some() && tls_key.is_some();

    // 站点独立日志（021）：开启后指向面板自己的日志目录——它也是「下载 / 清空」的目标
    let (access_log_p, error_log_p) = site_log_paths(state, &domains, row.log_access != 0, row.log_error != 0);
    // 站点独立日志（021）：同上，nginx -t 前确保日志目录存在
    if access_log_p.is_some() || error_log_p.is_some() {
        let _ = std::fs::create_dir_all(site_log_dir(state));
    }
    let spec = panel_os::SiteSpec {
        server_names: domains.to_vec(),
        root,
        listen: vec![80, 443],
        kind,
        access_log: access_log_p,
        error_log: error_log_p,
        tls_cert,
        tls_key,
        force_https: has_tls,
        spa_fallback: spa,
        waf,
        // 路由表已在 `kind` 里（Routed 变体），此字段只是对照——渲染以 kind 为准
        routes: None,
        // 自定义片段（019）：从落库值重建（与 apply 落库口径一致）
        custom_conf: row.custom_conf.clone(),
        // 高级配置（020）：同上，全部取落库值
        www_redirect: Some(row.www_redirect.clone()),
        tls_profile: Some(row.tls_profile.clone()),
        tls_min: Some(row.tls_min.clone()),
        hsts: row.hsts != 0,
        hsts_max_age: row.hsts_max_age,
        hsts_include_sub: row.hsts_sub != 0,
        hsts_preload: row.hsts_preload != 0,
        rewrite_preset: Some(row.rewrite_preset.clone()),
        rewrite_custom: row.rewrite_custom.clone(),
        ip_allow: nonempty(split_list(&row.ip_allow)),
        ip_deny: nonempty(split_list(&row.ip_deny)),
        auth_basic: row.auth_basic != 0,
        auth_user: row.auth_user.clone(),
        auth_file: Some(htpasswd_path(state, &domains)).filter(|p| p.is_file()),
        lb_policy: Some(row.lb_policy.clone()),
        proxy_connect_timeout: row.proxy_connect_timeout,
        proxy_send_timeout: row.proxy_send_timeout,
        proxy_read_timeout: row.proxy_read_timeout,
        error_log_level: Some(row.log_error_level.clone()),
    };

    let (target, rendered) = state.os.webserver().render(&spec)?;
    state
        .os
        .webserver()
        .validate(&rendered)
        .await
        .map_err(|e| PanelError::ConfigInvalid { detail: e.to_string() })?;
    Ok((target, rendered))
}

/// 清理「孤儿」站点配置：下发新配置后，若落库的旧路径与本次目标不同，就把旧文件删掉。
///
/// 必要性来自命名规则——conf 文件名是 `panel-<slug(首个域名)>.conf`（见 `conf_path()`），
/// **域名一改文件名就跟着变**。只 deploy 新文件、不清理旧文件的话：旧域名的配置仍留在
/// conf.d 里，nginx 会**继续对外服务它**（站点表里已经没有那个域名了）；更糟的是此后
/// 「停用 / 删除站点」只按落库的 conf_path 删新文件，那个孤儿文件**永远删不掉**，
/// 得有人手工去 conf.d 里翻。
///
/// 调用时机固定在 **deploy 新配置之后**：先删后写会让站点在这一瞬间真的不可用。
/// `remove` 内部自带 reload，所以删过就不再需要调用方重载（返回 true 表示已重载过）。
/// 删除失败一律上抛（`?`）——静默吞掉就会留下「站点显示已改、旧域名却仍在线」的假成功。
async fn prune_stale_conf(
    state: &Shared,
    old_conf: Option<&str>,
    target: &std::path::Path,
) -> Result<bool> {
    let Some(old) = old_conf.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(false);
    };
    let old_path = PathBuf::from(old);
    // 路径相同 / 文件本就不存在：幂等跳过（站点从未 apply 过，或已被删过）
    if old_path == target || !old_path.is_file() {
        return Ok(false);
    }
    state.os.webserver().remove(&old_path).await?;
    Ok(true)
}

/// 下发收尾（023）：按需 reload + 记录「上次成功下发时间」。
///
/// 五条下发入口共用（apply / conf PUT / regen / rollback / 停用后重新启用）——
/// 漏一路就会出现「配置已真实下发、列表却显示从未下发」的假状态。
/// 铁律：先同步外部状态成功，才写库（`touch_applied` 只在 reload 成功后调）。
/// `pruned` = 旧配置已由 `prune_stale_conf` 移除（其内部自带 reload，不必再重载）。
async fn finish_deploy(state: &Shared, id: i64, pruned: bool) -> Result<()> {
    if !pruned {
        state.os.webserver().reload().await.map_err(|e| PanelError::Command {
            bin: "reload".to_string(),
            detail: format!("配置已写入但 reload 失败：{e}"),
        })?;
    }
    touch_applied(state, id).await;
    Ok(())
}

/// touch_applied 用的 SQL（单测直接引用本常量，不另抄一份）。
const TOUCH_APPLIED_SQL: &str = "UPDATE sites SET last_applied_at = ?1 WHERE id = ?2";

/// 落「上次成功下发时间」（023）。仅在外部已真实接收后调用；失败仅记录不中断——
/// 配置明明已下发，不能因为一个展示字段写库失败就把整次应用判成失败。
async fn touch_applied(state: &Shared, id: i64) {
    let now = crate::now_unix();
    if let Err(e) = state
        .db
        .exec(move |conn| {
            conn.execute(
                TOUCH_APPLIED_SQL,
                rusqlite::params![now, id],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
    {
        eprintln!("[sites] 记录上次下发时间失败（site {id}）: {e}");
    }
}

/// 备注更新请求体（022）。
#[derive(Debug, Deserialize)]
pub struct RemarkReq {
    pub remark: String,
}

/// 更新站点说明（对象备注，022）。内联编辑保存；仅 `site.manage`。
pub async fn update_remark(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<RemarkReq>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    // 先读后写：站点不存在返回 404（校验必须在读路径上，不能塞进 db.exec 闭包，
    // 否则闭包内的 NotFound 会被包成 Database → 端点误报 500）。
    if fetch_one(&state, id).await?.is_none() {
        return Err(ApiError::not_found("site"));
    }
    let remark = req.remark.trim().to_string();
    if remark.chars().count() > 500 {
        return Err(ApiError::bad_request("remark", "备注最多 500 字"));
    }
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET remark = ?1 WHERE id = ?2",
                rusqlite::params![remark, id],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    audit(&state, &s, "site.remark", &id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn patch(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<PatchReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let cur = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;

    // 计算新值（未提供的字段沿用现状）
    //
    // 名称：支持改名。nginx 配置按域名派生、root 已是绝对路径、证书按 domain 绑定，
    // 三者都与 name 无关 → 改名不需要重新下发任何东西，只改这一列即可。
    // root 的解析仍传**旧名**：只有 root 传空串时才会按 name 生成默认目录，沿用旧名
    // 可避免"改个名字顺带把站点目录也换了地方"这种隐式漂移。
    let new_name = match req.name.as_deref() {
        Some(raw) => validate_site_name(raw)?,
        None => cur.name.clone(),
    };
    if new_name != cur.name {
        // 唯一性**先读后判**，命中即 Conflict。不能指望写事务里的 UNIQUE 兜底：
        // `db.exec` 会把闭包内任何错误一律包成 Database，端点就误报成 500 了。
        let name_check = new_name.clone();
        let dup: i64 = state
            .pool
            .with(move |conn| {
                conn.query_row(
                    "SELECT COUNT(1) FROM sites WHERE name = ?1 AND id != ?2",
                    rusqlite::params![name_check, id],
                    |r| r.get(0),
                )
                .map_err(|e| PanelError::Database(e.to_string()))
            })
            .await?;
        if dup > 0 {
            return Err(ApiError::from(PanelError::Conflict("site name exists".into())));
        }
    }
    let domains: Vec<String> = if let Some(ref ds) = req.domains {
        if ds.is_empty() {
            return Err(ApiError::bad_request("domains", "at least one domain required"));
        }
        let mut out = Vec::with_capacity(ds.len());
        for d in ds {
            let dom = domain(d.trim())
                .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
            out.push(dom.as_str().to_string());
        }
        out
    } else {
        serde_json::from_str(&cur.domains).unwrap_or_default()
    };

    let root = if let Some(ref r) = req.root {
        resolve_site_root(&state, r, &cur.name)?.as_path().display().to_string()
    } else {
        cur.root.clone()
    };

    let old_enabled = cur.enabled != 0;
    let enabled = req.enabled.unwrap_or(old_enabled);
    let _ = req.force_https; // 仅作用于 apply 渲染，DB 不单列存储
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());

    // 当前落库的 conf_path：开关翻转时要改写它，未翻转则原样保留（含 NULL）。
    let mut conf_path: Option<String> = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT conf_path FROM sites WHERE id = ?1",
                [id],
                |r| r.get::<_, Option<String>>(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    // 真启用 / 真停用：enabled 翻转时同步 Web 服务器配置。
    //
    // 顺序是刻意的：**先同步外部状态，成功后才写库**。反过来的话，deploy / reload
    // 一旦失败，就会留下「库说已停用、站点却仍在对外服务」的假成功——用户看到开关
    // 是关的，站点照常访问，正是本次要修的 bug 类型。
    let web_manage = state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false);
    if web_manage && old_enabled != enabled {
        if enabled {
            // 假→真：用「本次提交的新 domains/root + 行内不变字段」重建配置并下发。
            // 站点此前可能从未 apply（无 conf_path），这里会补齐下发。
            let (target, rendered) = render_spec_for_row(&state, &cur, &domains, &root).await?;
            state.os.webserver().deploy(&target, &rendered).await?;
            // 域名改过则文件名跟着变：新配置已就位，**此刻**才轮到删旧域名遗留的孤儿
            // 配置。`remove` 自带 reload —— 删过就等于重载过了，下面不必再 reload 一次。
            let pruned = prune_stale_conf(&state, conf_path.as_deref(), &target).await?;
            finish_deploy(&state, id, pruned).await?;
            conf_path = Some(target.display().to_string());
        } else {
            // 真→假：移除配置，使站点真正下线（`remove` 内部含 reload）。
            if let Some(c) = conf_path.as_deref().filter(|c| !c.is_empty()) {
                // 手改内容不该静默消失：停用前先备份（与 apply「重新生成」同一安全网）。
                if cur.manual_conf != 0
                    && backup_manual_conf(&state, Path::new(c)).await.is_some()
                {
                    audit(&state, &s, "site.conf.backup", &id.to_string(), "ok").await;
                }
                state
                    .os
                    .webserver()
                    .remove(&PathBuf::from(c))
                    .await
                    .map_err(ApiError::from)?;
            }
            // 配置已从磁盘移除，落库的 conf_path 不再反映真实状态 → 置空。
            conf_path = Some(String::new());
        }
    }

    // 开关翻转会重新渲染（启用）或移除（停用）配置文件——手动维护状态随之结束：
    // 停用 = 文件已移除（无内容可护）；重新启用 = 按表单重新生成（不保留手改）。
    // 未翻转则原样保留（COALESCE(NULL, manual_conf)）。
    let clear_manual: Option<i32> = if old_enabled != enabled { Some(0) } else { None };

    // 部署指纹（017）随翻转同步：
    // - 假→真：文件按「本次提交的 name/domains/root + 行内其余字段」重新渲染 → 指纹=新值
    // - 真→假：文件已移除 → NULL
    // - 未翻转：文件未动 → 保持旧值（这样表单改名/改域名/改根目录后，
    //   手动维护站点的「未同步」提示会自然亮起，而不是静默分叉）
    let snap_patch: Option<String> = if old_enabled != enabled {
        if enabled {
            Some(deploy_fingerprint(
                &new_name,
                &domains_json,
                &root,
                &cur.kind,
                cur.spa != 0,
                cur.upstreams_json.as_deref(),
                cur.fpm.as_deref(),
                cur.redirect_target.as_deref(),
                cur.redirect_code,
                cur.waf_enabled != 0,
                cur.waf_profile.as_deref(),
                cur.waf_rate,
                cur.waf_burst,
                &cur.routes_json,
                cur.custom_conf.as_deref(),
                &advanced_json_of(&cur),
            ))
        } else {
            None
        }
    } else {
        cur.conf_snapshot.clone()
    };

    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET name = ?6, domains = ?1, root = ?2, enabled = ?3, conf_path = ?4,
                                  manual_conf = COALESCE(?7, manual_conf), conf_snapshot = ?8 WHERE id = ?5",
                rusqlite::params![domains_json, root, enabled as i32, conf_path, id, new_name, clear_manual, snap_patch],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.patch", &id.to_string(), "ok").await;
    match fetch_one(&state, id).await? {
        Some(r) => Ok(ok(to_out(&r))),
        None => Err(ApiError::not_found("site")),
    }
}

// ─────────────── 删除站点（CASCADE 删除其证书） ───────────────

pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let _cur = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;

    // F7：删站必须同步移除 nginx 配置并 reload，否则站点"已删除"却仍在对外服务。
    // 先取该站点的 conf_path，在删库行**之前**移除配置——配置删除失败则中止，
    // 避免产生"库里没了、配置还在"的孤儿站点。此查询走只读连接池。
    let conf_path = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT conf_path FROM sites WHERE id = ?1",
                [id],
                |r| r.get::<_, Option<String>>(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    if let Some(ref c) = conf_path {
        if !c.is_empty()
            && state
                .capabilities
                .get(cap_keys::WEBSERVER_MANAGE)
                .map(|x| x.supported)
                .unwrap_or(false)
        {
            let p = std::path::PathBuf::from(c);
            state.os.webserver().remove(&p).await.map_err(ApiError::from)?;
        }
    }

    state
        .db
        .exec(move |conn| {
            let n = conn
                .execute("DELETE FROM sites WHERE id = ?1", [id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;

    audit(&state, &s, "site.delete", &id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}


// ─── 配置校验与应用（核心闭环，拆至 sites/apply.rs；pub use 重导出端点） ───
mod apply;
pub use apply::*;

// ─── 站点配置查看/编辑/版本回滚（拆至 sites/conf.rs；pub use 重导出端点） ───
mod conf;
pub use conf::*;

// ─── SSL 证书 / ACME（拆至 sites/ssl.rs；pub use 重导出端点供 routes.rs） ───
mod ssl;
pub use ssl::*;

#[cfg(test)]
mod waf_tests;
#[cfg(test)]
mod kind_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod last_applied_tests;
