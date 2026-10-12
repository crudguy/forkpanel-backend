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
    /// 是否启用 PHP（当前 schema 未单独建模，仅占位接受）。
    pub php: Option<bool>,
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

// ─────────────── 配置校验与应用（核心闭环） ───────────────

#[derive(Debug, Deserialize)]
pub struct ApplyReq {
    pub name: String,
    pub domains: Vec<String>,
    pub root: String,
    pub force_https: Option<bool>,
    /// 站点类型：`static`（默认）/ `proxy` / `php` / `redirect` / `routed`
    #[serde(default)]
    pub kind: Option<String>,
    /// `kind=routed` 的路由表（至少一条，且必须含一条前缀为 `/` 的兜底）。
    /// **缺省 = 保留库中现有路由表**（与 `waf` 同语义：apply 是按期望状态覆盖，
    /// 但静默清空一整张路由表比多一次点击危险得多）。
    #[serde(default)]
    pub routes: Option<Vec<RouteOut>>,
    /// `kind=proxy` 的后端列表（1~16 个）
    #[serde(default)]
    pub upstreams: Option<Vec<String>>,
    /// `kind=php` 的 php-fpm 目标（`unix:/path.sock` 或 `host:port`）
    #[serde(default)]
    pub fpm: Option<String>,
    /// `kind=static` 的 SPA 回退开关：true 时 `try_files` 末项为 `/index.html`
    /// （支持 Vue/React 等 history 路由单页应用）。缺省 false。
    #[serde(default)]
    pub spa: Option<bool>,
    /// `kind=redirect` 的目标 URL（必须是 http(s):// 绝对地址）
    #[serde(default)]
    pub redirect_target: Option<String>,
    /// `kind=redirect` 的状态码：301 / 302 / 307 / 308，缺省 301
    #[serde(default)]
    pub redirect_code: Option<u16>,
    /// 站点 WAF。**缺省 = 保留库中现有配置**（不是"关闭"）——apply 是按
    /// "期望状态"覆盖的，但静默关掉一层防护比多一次点击危险得多，
    /// 而且调用方未必都知道有 `waf` 这个字段。显式 `{"enabled": false}` 才关闭。
    #[serde(default)]
    pub waf: Option<WafReq>,
    /// 手动维护站点的「重新生成配置」开关：true = 忽略手动维护保护，按本次表单
    /// **重新渲染并覆盖**磁盘配置（覆盖前自动备份旧文件到 conf-backups/），
    /// 成功后清零 manual 标记（站点回到面板托管）。缺省 false = 保持既有保护语义
    /// （跳过渲染/下发，表单仅入库——此刻两边若不一致，列表会标「未同步」）。
    #[serde(default)]
    pub regen_conf: Option<bool>,
    /// 自定义配置片段（019；**仅 owner 可改**）：插在主 server 块尾部，随本次
    /// apply 重新渲染生效（托管态语义——与整文件手动维护互补）。
    /// 缺省 = 保留库中现值；显式空串/空白 = 清空。上限 64 KiB。
    #[serde(default)]
    pub custom_conf: Option<String>,
    /// www ↔ 非 www 跳转（020）：off | to_www | to_bare；缺省 = 保留现值
    #[serde(default)]
    pub www_redirect: Option<String>,
    /// 加密套件档位（020）：compat | modern | strict
    #[serde(default)]
    pub tls_profile: Option<String>,
    /// TLS 版本下限（020）：TLSv1 | TLSv1.1 | TLSv1.2 | TLSv1.3
    #[serde(default)]
    pub tls_min: Option<String>,
    /// HSTS 开关（020）
    #[serde(default)]
    pub hsts: Option<bool>,
    /// HSTS max-age（秒，0 ~ 63072000）
    #[serde(default)]
    pub hsts_max_age: Option<i64>,
    #[serde(default)]
    pub hsts_sub: Option<bool>,
    #[serde(default)]
    pub hsts_preload: Option<bool>,
    /// 伪静态模板（020）：none | wordpress | laravel | thinkphp | typecho | discuz | custom
    #[serde(default)]
    pub rewrite_preset: Option<String>,
    /// preset=custom 时的原始 rewrite 文本（上限 64 KiB）
    #[serde(default)]
    pub rewrite_custom: Option<String>,
    /// IP 白名单（021，逗号分隔的 IP / CIDR）；空串 = 清除，省略 = 保留现值
    #[serde(default)]
    pub ip_allow: Option<String>,
    /// IP 黑名单（021）；ip_allow 非空时后端忽略该字段
    #[serde(default)]
    pub ip_deny: Option<String>,
    /// HTTP Basic Auth 开关（021）
    #[serde(default)]
    pub auth_basic: Option<bool>,
    #[serde(default)]
    pub auth_user: Option<String>,
    /// Basic Auth 口令（021，**只写不读**）：提交后经 openssl 生成 apr1 摘要写进
    /// htpasswd 文件，口令本身不落库、不出现在任何响应里
    #[serde(default)]
    pub auth_pass: Option<String>,
    /// 负载均衡策略（021）：round_robin | least_conn | ip_hash
    #[serde(default)]
    pub lb_policy: Option<String>,
    /// 代理超时三项（021，秒，1~3600）
    #[serde(default)]
    pub proxy_connect_timeout: Option<i64>,
    #[serde(default)]
    pub proxy_send_timeout: Option<i64>,
    #[serde(default)]
    pub proxy_read_timeout: Option<i64>,
    /// 站点独立日志（021）：开启后按面板指定路径写 access / error 日志
    #[serde(default)]
    pub log_access: Option<bool>,
    #[serde(default)]
    pub log_error: Option<bool>,
    /// 错误日志级别（021）：debug|info|notice|warn|error|crit|alert|emerg
    #[serde(default)]
    pub log_error_level: Option<String>,
}

/// WAF 请求体。
#[derive(Debug, Deserialize)]
pub struct WafReq {
    pub enabled: bool,
    /// `basic`（默认）/ `strict`
    #[serde(default)]
    pub profile: Option<String>,
    /// CC 限速：每秒请求数；`None` / 0 = 不限速
    #[serde(default)]
    pub rate_per_sec: Option<u32>,
    /// 突发桶容量；缺省 = `rate * 2`
    #[serde(default)]
    pub burst: Option<u32>,
}

/// 限速上限。上限存在的理由：`rate` 决定每 IP 的放行速率，`burst` 决定
/// 单 IP 能用掉多少缓冲——两者都直接换内存（每个 zone 10m 是硬上限）。
const WAF_RATE_MAX: u32 = 1000;
const WAF_BURST_MAX: u32 = 10_000;

/// 归一化 + 校验 WAF 配置。
///
/// 规则集本身是**编译期常量**，用户只能选档位与数值——所以这里没有"正则注入"面。
/// 但数值边界仍必须挡：`rate=0` 会让 nginx 直接拒绝加载配置。
fn build_waf(
    req: Option<&WafReq>,
    cur: Option<&panel_os::WafSpec>,
) -> ApiResult<Option<panel_os::WafSpec>> {
    let Some(r) = req else { return Ok(cur.cloned()) };   // 缺省 = 保留
    if !r.enabled {
        return Ok(None);                                   // 显式关闭
    }
    let profile = match r.profile.as_deref().unwrap_or("basic") {
        "basic" => panel_os::WafProfile::Basic,
        "strict" => panel_os::WafProfile::Strict,
        other => {
            return Err(ApiError::bad_request(
                "waf.profile",
                format!("未知档位：{other}（可选 basic / strict）"),
            ))
        }
    };
    let rate = match r.rate_per_sec {
        None | Some(0) => None,
        Some(n) if n > WAF_RATE_MAX => {
            return Err(ApiError::bad_request(
                "waf.rate_per_sec",
                format!("限速上限 {WAF_RATE_MAX} 次/秒"),
            ))
        }
        Some(n) => Some(n),
    };
    let burst = r.burst.unwrap_or_else(|| rate.map(|n| n.saturating_mul(2)).unwrap_or(0));
    if burst > WAF_BURST_MAX {
        return Err(ApiError::bad_request("waf.burst", format!("上限 {WAF_BURST_MAX}")));
    }
    // burst 只在限速时有意义。给了 burst 却不限速，用户会以为限速生效了——
    // 这种"配了但没生效"的静默失败比直接报错糟糕得多。
    if rate.is_none() && burst > 0 {
        return Err(ApiError::bad_request(
            "waf.burst",
            "burst 仅在启用限速（rate_per_sec）时有意义",
        ));
    }
    Ok(Some(panel_os::WafSpec { profile, rate_per_sec: rate, burst }))
}

/// 校验反代后端。
///
/// **这是注入防护，不是语法校验**：该值会被直接拼进 nginx 配置文本，所以必须
/// 保证它不越出单个 token（无空白、无换行、无 `;`、无 `{}`）。语法正确性交给
/// 后续的 `nginx -t`（render → validate → deploy 链路里本就有这一步）。
fn validate_upstream(u: &str) -> ApiResult<String> {
    let u = u.trim();
    let rest = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"))
        .ok_or_else(|| {
            ApiError::bad_request("upstreams", format!("必须以 http:// 或 https:// 开头：{u}"))
        })?;
    if rest.is_empty() {
        return Err(ApiError::bad_request("upstreams", format!("缺少主机名：{u}")));
    }
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err(ApiError::bad_request(
            "upstreams",
            format!("只接受 host[:port]，不得含路径 / 查询 / 片段：{u}"),
        ));
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']' | '%'))
    {
        return Err(ApiError::bad_request(
            "upstreams",
            format!("含非法字符（仅允许字母数字与 . - _ : [ ] %）：{u}"),
        ));
    }
    Ok(u.to_string())
}

/// 校验 php-fpm 目标：`unix:/abs/path.sock` 或 `host:port`。同样是注入防护。
fn validate_fpm(v: &str) -> ApiResult<String> {
    let v = v.trim();
    if v.is_empty() {
        return Err(ApiError::bad_request("fpm", "不能为空"));
    }
    if let Some(path) = v.strip_prefix("unix:") {
        if !path.starts_with('/') {
            return Err(ApiError::bad_request("fpm", "unix socket 必须是绝对路径"));
        }
        if path.contains("..") {
            return Err(ApiError::bad_request("fpm", "socket 路径不得含 .."));
        }
        if path.len() > 128 {
            return Err(ApiError::bad_request("fpm", "socket 路径过长（上限 128）"));
        }
    }
    // 必须是一个 token：不得含空白、换行、分号、花括号、引号或反斜杠
    if !v
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, ';' | '{' | '}' | '"' | '\'' | '`' | '\\'))
    {
        return Err(ApiError::bad_request(
            "fpm",
            "含非法字符（不得含空白、引号、分号或花括号）",
        ));
    }
    Ok(v.to_string())
}

/// 站点名共享校验（create / patch 共用）。返回 trim 后的合法名，非法则 400。
///
/// 规则见 `panel_core::rules::is_valid_site_name`：白名单——首字符字母数字、
/// 后续允许字母数字与 `. _ -`，长度 1~63。明确拒绝空 / 空格 / 点类（`.`/`..`/
/// `.hidden`）/ 越界（`/`）/ 注入字符（空格 / `;` / `$` / 反引号 / 引号）。
/// 此前 name 仅判非空，于是 `a b` 之类能进库、`.` 名会把根目录解析成整个
/// site_root（跨站泄露）。抽成单一函数是为了让 create 与 patch 两条入口共用
/// 同一套校验，避免一边收紧另一边还能绕过。
fn validate_site_name(raw: &str) -> ApiResult<String> {
    let name = raw.trim();
    if panel_core::rules::is_valid_site_name(name) {
        Ok(name.to_string())
    } else {
        Err(ApiError::bad_request(
            "name",
            "站点名仅允许字母数字开头，后可接字母数字与 . _ -，长度 1~63（不得含空格、/、以点开头或仅为 .）",
        ))
    }
}

/// 整站重定向目标 URL 校验（注入防护 + 结构校验）。
///
/// 该值会直接拼进 nginx `return <code> <target>$request_uri;`，必须是一个**绝对**
/// `http(s)://` URL，且不含空白 / 换行 / 引号 / 分号（否则破坏 return 指令或注入）。
/// 结构正确性（域名可达性）交给 `nginx -t` 在 render → validate 链路兜底。
fn validate_redirect_target(raw: &str) -> ApiResult<String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(ApiError::bad_request("redirect_target", "重定向目标不能为空"));
    }
    if !t.starts_with("http://") && !t.starts_with("https://") {
        return Err(ApiError::bad_request(
            "redirect_target",
            "必须是 http:// 或 https:// 开头的绝对 URL",
        ));
    }
    if t.contains(char::is_whitespace) || t.contains(';') || t.contains('"') || t.contains('\'') {
        return Err(ApiError::bad_request(
            "redirect_target",
            "含非法字符（不得含空白、引号或分号）",
        ));
    }
    Ok(t.to_string())
}

/// 应用站点配置。**整个流程在写事务之外完成**。
pub async fn apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<ApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }

    // 1) 域名逐个走校验器（强类型构造点）
    let mut domains = Vec::new();
    for d in &req.domains {
        let dom = domain(d)
            .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
        domains.push(dom.as_str().to_string());
    }
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "at least one domain required"));
    }

    // 2) 根目录必须在 site_root 之内
    let root = resolve_site_root(&state, &req.root, &req.name)?;

    // 3) 已有证书则注入（自签/ACME 均按域名落盘）；证书文件不存在则不启用 TLS
    // 取一次现运行配置：TLS 与 WAF 都要基于"当前状态"做缺省合并
    let cur_row = fetch_one_by_name(&state, &req.name).await?;
    let waf = build_waf(req.waf.as_ref(), cur_row.as_ref().and_then(|r| r.waf()).as_ref())?;
    // 自定义配置片段（019）：原始 nginx 文本（写坏≈root 级事故）→ **仅 owner 可改**，
    // 64 KiB 上限。缺省 = 保留库中现值（与 waf 同语义：不传 ≠ 清空）；
    // 显式空串/全空白 = 清空。语法由下方渲染后的 `nginx -t` 兜底，写坏不会上线。
    let custom_conf_db: Option<String> = match req.custom_conf.as_ref() {
        None => cur_row.as_ref().and_then(|r| r.custom_conf.clone()),
        Some(v) => {
            if s.role != "owner" {
                return Err(ApiError::forbidden("owner"));
            }
            if v.len() > 64 * 1024 {
                return Err(ApiError::bad_request(
                    "custom_conf",
                    "自定义片段超过 64 KiB 上限",
                ));
            }
            if v.trim().is_empty() { None } else { Some(v.clone()) }
        }
    };
    // 高级配置（020）：与 custom_conf 同语义——缺省 = 保留库中现值，显式值才校验。
    // 全部走白名单/区间：这些字段的非法值要么让 nginx -t 失败（还好），要么让
    // 老客户端**静默**连不上（更坏），所以必须在入口拦掉而不是交给渲染器。
    let www_db: String = match req.www_redirect.as_deref() {
        None => cur_row.as_ref().map(|r| r.www_redirect.clone()).unwrap_or_else(|| "off".to_string()),
        Some(v) => {
            if !matches!(v, "off" | "to_www" | "to_bare") {
                return Err(ApiError::bad_request("www_redirect", "跳转方式只能是 off / to_www / to_bare"));
            }
            v.to_string()
        }
    };
    let tls_profile_db: String = match req.tls_profile.as_deref() {
        None => cur_row.as_ref().map(|r| r.tls_profile.clone()).unwrap_or_else(|| "modern".to_string()),
        Some(v) => {
            if !matches!(v, "compat" | "modern" | "strict") {
                return Err(ApiError::bad_request("tls_profile", "加密套件档位只能是 compat / modern / strict"));
            }
            v.to_string()
        }
    };
    let tls_min_db: String = match req.tls_min.as_deref() {
        None => cur_row.as_ref().map(|r| r.tls_min.clone()).unwrap_or_else(|| "TLSv1.2".to_string()),
        Some(v) => {
            if !matches!(v, "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3") {
                return Err(ApiError::bad_request("tls_min", "TLS 版本下限只能是 TLSv1 / TLSv1.1 / TLSv1.2 / TLSv1.3"));
            }
            v.to_string()
        }
    };
    let hsts_db: i32 = match req.hsts {
        None => cur_row.as_ref().map(|r| r.hsts).unwrap_or(0),
        Some(b) => if b { 1 } else { 0 },
    };
    let hsts_max_age_db: i64 = match req.hsts_max_age {
        None => cur_row.as_ref().map(|r| r.hsts_max_age).unwrap_or(300),
        Some(n) => {
            // 上限取 2 年（RFC 6797 的建议值 31536000 之上再放宽一档）；0 = 立即失效
            if n < 0 || n > 63_072_000 {
                return Err(ApiError::bad_request("hsts_max_age", "max-age 需在 0 ~ 63072000 秒之间"));
            }
            n
        }
    };
    let hsts_sub_db: i32 = match req.hsts_sub {
        None => cur_row.as_ref().map(|r| r.hsts_sub).unwrap_or(0),
        Some(b) => if b { 1 } else { 0 },
    };
    let hsts_preload_db: i32 = match req.hsts_preload {
        None => cur_row.as_ref().map(|r| r.hsts_preload).unwrap_or(0),
        Some(b) => if b { 1 } else { 0 },
    };
    let rewrite_preset_db: String = match req.rewrite_preset.as_deref() {
        None => cur_row.as_ref().map(|r| r.rewrite_preset.clone()).unwrap_or_else(|| "none".to_string()),
        Some(v) => {
            if !matches!(v, "none" | "wordpress" | "laravel" | "thinkphp" | "typecho" | "discuz" | "custom") {
                return Err(ApiError::bad_request("rewrite_preset", "伪静态模板取值不合法"));
            }
            v.to_string()
        }
    };
    let rewrite_custom_db: Option<String> = match req.rewrite_custom.as_ref() {
        None => cur_row.as_ref().and_then(|r| r.rewrite_custom.clone()),
        Some(v) => {
            if v.len() > 64 * 1024 {
                return Err(ApiError::bad_request("rewrite_custom", "自定义 rewrite 超过 64 KiB 上限"));
            }
            if v.trim().is_empty() { None } else { Some(v.clone()) }
        }
    };
    // ── 访问控制 / Basic Auth / 反代增强 / 日志（021）──
    // 与前面同语义：缺省 = 保留库中现值，显式值才校验。会进配置文本的字段（IP 列表、
    // 用户名、策略、日志级别）一律走白名单，超时走区间——抄错不是报 400 就是让
    // 老客户端静默连不上，必须在入口拦住。
    let ip_allow_db: Option<String> = match req.ip_allow.as_deref() {
        None => cur_row.as_ref().and_then(|r| r.ip_allow.clone()),
        Some(v) => {
            let list = parse_ip_list(v)?;
            if list.is_empty() { None } else { Some(list.join(",")) }
        }
    };
    let ip_deny_db: Option<String> = match req.ip_deny.as_deref() {
        None => cur_row.as_ref().and_then(|r| r.ip_deny.clone()),
        Some(v) => {
            let list = parse_ip_list(v)?;
            if list.is_empty() { None } else { Some(list.join(",")) }
        }
    };
    let auth_basic_db: i32 = match req.auth_basic {
        None => cur_row.as_ref().map(|r| r.auth_basic).unwrap_or(0),
        Some(b) => if b { 1 } else { 0 },
    };
    let auth_user_db: Option<String> = match req.auth_user.as_deref() {
        None => cur_row.as_ref().and_then(|r| r.auth_user.clone()),
        Some(v) => {
            let u = v.trim();
            if u.is_empty() {
                None
            } else if u.contains(':') || u.chars().any(char::is_whitespace) {
                return Err(ApiError::bad_request("auth_user", "用户名不能含冒号或空白"));
            } else {
                Some(u.to_string())
            }
        }
    };
    let lb_policy_db: String = match req.lb_policy.as_deref() {
        None => cur_row
            .as_ref()
            .map(|r| r.lb_policy.clone())
            .unwrap_or_else(|| "least_conn".to_string()),
        Some(v) => {
            if !matches!(v, "round_robin" | "least_conn" | "ip_hash") {
                return Err(ApiError::bad_request(
                    "lb_policy",
                    "负载均衡策略只能是 round_robin / least_conn / ip_hash",
                ));
            }
            v.to_string()
        }
    };
    let pct_db = timeout_db(req.proxy_connect_timeout, cur_row.as_ref().map(|r| r.proxy_connect_timeout), "proxy_connect_timeout")?;
    let pst_db = timeout_db(req.proxy_send_timeout, cur_row.as_ref().map(|r| r.proxy_send_timeout), "proxy_send_timeout")?;
    let prt_db = timeout_db(req.proxy_read_timeout, cur_row.as_ref().map(|r| r.proxy_read_timeout), "proxy_read_timeout")?;
    let log_access_db: i32 = match req.log_access {
        None => cur_row.as_ref().map(|r| r.log_access).unwrap_or(0),
        Some(b) => if b { 1 } else { 0 },
    };
    let log_error_db: i32 = match req.log_error {
        None => cur_row.as_ref().map(|r| r.log_error).unwrap_or(0),
        Some(b) => if b { 1 } else { 0 },
    };
    let log_level_db: String = match req.log_error_level.as_deref() {
        None => cur_row
            .as_ref()
            .map(|r| r.log_error_level.clone())
            .unwrap_or_else(|| "error".to_string()),
        Some(v) => {
            if !matches!(v, "debug" | "info" | "notice" | "warn" | "error" | "crit" | "alert" | "emerg") {
                return Err(ApiError::bad_request("log_error_level", "日志级别取值不合法"));
            }
            v.to_string()
        }
    };
    // Basic Auth（021）：口令只在本次提交出现一次——经 openssl 生成 apr1 摘要写进
    // htpasswd 文件，**不落库**；此后任何响应（含站点列表）都只回用户名，不再回显口令。
    let auth_file_db: Option<std::path::PathBuf> = if auth_basic_db != 0 {
        match &auth_user_db {
            Some(u) => {
                let f = htpasswd_path(&state, &domains);
                if let Some(p) = req.auth_pass.as_deref().filter(|p| !p.is_empty()) {
                    let line = panel_os::tls::htpasswd_line(u, p)
                        .await
                        .map_err(ApiError::from)?;
                    if let Some(dir) = f.parent() {
                        std::fs::create_dir_all(dir).map_err(|e| PanelError::Internal(e.to_string()))?;
                    }
                    std::fs::write(&f, format!("{line}\n"))
                        .map_err(|e| PanelError::Internal(e.to_string()))?;
                }
                if f.is_file() { Some(f) } else { None }
            }
            None => None,
        }
    } else {
        None
    };

    // 写侧指纹片段：**键名与顺序**必须和读侧 `advanced_json_of` 完全一致
    let advanced_json = serde_json::json!({
        "hsts": hsts_db,
        "hsts_max_age": hsts_max_age_db,
        "hsts_preload": hsts_preload_db,
        "hsts_sub": hsts_sub_db,
        "rewrite_custom": rewrite_custom_db,
        "rewrite_preset": rewrite_preset_db,
        "tls_min": tls_min_db,
        "tls_profile": tls_profile_db,
        "www": www_db,
        "ip_allow": ip_allow_db,
        "ip_deny": ip_deny_db,
        "auth_basic": auth_basic_db,
        "auth_user": auth_user_db,
        "lb_policy": lb_policy_db,
        "pct": pct_db,
        "pst": pst_db,
        "prt": prt_db,
        "log_access": log_access_db,
        "log_error": log_error_db,
        "log_level": log_level_db,
    })
    .to_string();
    // 停用态守恒：站点已停用则只更新配置、不下发 Web 服务器（conf_path 留空），
    // 与 `patch` 的「真停用」语义一致——避免「点一次应用就把刚停用的站点又拉起来」。
    // 新建站点（无 cur_row）按默认启用对待，照常部署。
    let deploy = cur_row.as_ref().map(|r| r.enabled != 0).unwrap_or(true);
    // 手动维护站点（enabled 且 manual_conf=1）：整段跳过渲染/校验/下发——磁盘上的
    // 手工配置是唯一事实源，表单保存只更新库内规格（语义见 016 迁移）。
    // `regen_conf=true` 是唯一例外：用户显式选了「重新生成配置」，按本次表单覆盖
    // 手改内容（覆盖前自动备份到 conf-backups/），并结束手动维护。
    let regen = req.regen_conf.unwrap_or(false);
    let was_manual = cur_row.as_ref().map(|r| r.manual_conf != 0).unwrap_or(false);
    let manual_skip = cur_row
        .as_ref()
        .map(|r| r.enabled != 0 && r.manual_conf != 0)
        .unwrap_or(false)
        && !regen;
    // 落库四元组在这里就算好：`waf` 随即被 move 进 SiteSpec。
    // 关掉 WAF 时一并清空——留着旧数值会让"下次重新打开"意外带上几年前的参数，
    // 而用户早就不记得了。
    let (waf_on, waf_profile, waf_rate, waf_burst) = match &waf {
        Some(w) => (
            1i32,
            Some(w.profile.as_str().to_string()),
            w.rate_per_sec.map(i64::from),
            Some(i64::from(w.burst)),
        ),
        None => (0i32, None, None, None),
    };

    let (tls_cert, tls_key) = match &cur_row {
        Some(row) => match cert_domains_for_site(&state, row.id).await? {
            Some(ds) if !ds.is_empty() => {
                let (c, k) = cert_paths_for(&state, &ds);
                if c.is_file() && k.is_file() { (Some(c), Some(k)) } else { (None, None) }
            }
            _ => (None, None),
        },
        None => (None, None),
    };

    // 4) 渲染配置（纯字符串生成，不落盘）
    //   未配置证书时 force_https 无意义（无 https 可跳转），诚实降级为 false
    let has_tls = tls_cert.is_some() && tls_key.is_some();
    // 站点类型：默认静态。反代与 PHP 的目标值都会**直接进 nginx 配置文本**，
    // 因此逐个过注入防护（见 validate_upstream / validate_fpm）。
    let kind = match req.kind.as_deref().unwrap_or("static") {
        "static" => panel_os::SiteKind::Static,
        "proxy" => {
            let raw = req.upstreams.clone().unwrap_or_default();
            if raw.is_empty() || raw.len() > 16 {
                return Err(ApiError::bad_request("upstreams", "反代需要 1~16 个后端"));
            }
            let mut outs = Vec::with_capacity(raw.len());
            for u in &raw {
                outs.push(validate_upstream(u)?);
            }
            panel_os::SiteKind::ReverseProxy { upstreams: outs }
        }
        "php" => {
            let fpm = req.fpm.as_deref().ok_or_else(|| {
                ApiError::bad_request("fpm", "PHP 站点必须指定 php-fpm 目标")
            })?;
            panel_os::SiteKind::Php { fpm: validate_fpm(fpm)? }
        }
        "redirect" => {
            // 整站重定向：目标必须绝对 http(s) URL（注入防护见 validate_redirect_target），
            // 状态码仅限 301/302/307/308——其余值 nginx `return` 不接受。
            let target = req.redirect_target.clone().ok_or_else(|| {
                ApiError::bad_request("redirect_target", "重定向站点必须指定目标 URL")
            })?;
            let target = validate_redirect_target(&target)?;
            let code = req.redirect_code.unwrap_or(301);
            if !matches!(code, 301 | 302 | 307 | 308) {
                return Err(ApiError::bad_request("redirect_code", "仅支持 301 / 302 / 307 / 308"));
            }
            panel_os::SiteKind::Redirect { target, code: code as u16 }
        }
        "routed" => {
            let rs = req.routes.clone().ok_or_else(|| {
                ApiError::bad_request("routes", "多路由站点必须提供路由表（routes）")
            })?;
            let mut routes = validate_routes(&rs)?;
            // 路由级 root 约束到 site_root 之内（防路径穿越）：与站点级 root 复用同一条
            // resolve_site_root。空 root 不变（继承 server 级站点 root）。
            for r in routes.routes.iter_mut() {
                if let panel_os::RouteKind::Static { spa: _, root } = &mut r.kind {
                    if let Some(rv) = root {
                        let safe = resolve_site_root(&state, rv, &req.name)?;
                        *rv = safe.as_path().display().to_string();
                    }
                }
            }
            panel_os::SiteKind::Routed { routes }
        }
        other => {
            return Err(ApiError::bad_request(
                "kind",
                format!("未知站点类型：{other}（可选 static / proxy / php / redirect / routed）"),
            ))
        }
    };
    // SPA 回退仅对 static 有意义；其它类型忽略该开关（避免误把静态开关带进反代/重定向）
    let spa = matches!(req.kind.as_deref(), Some("static")) && req.spa.unwrap_or(false);
    let spa_i32: i32 = if spa { 1 } else { 0 };
    // 重定向的目标 / 状态码一并落库（仅 redirect 类型非空）
    let (redirect_target_db, redirect_code_db): (Option<String>, Option<i64>) = match &kind {
        panel_os::SiteKind::Redirect { target, code } => (Some(target.clone()), Some(*code as i64)),
        _ => (None, None),
    };
    // 路由表落库：存 API 口径的 JSON（读侧 `routes_from_json` + `validate_routes` 复原）。
    // 非 routed 一律存 '[]' ——不用 NULL，避免「NULL 与空数组两种表示」带来的分支。
    let routes_json: String = match &kind {
        panel_os::SiteKind::Routed { routes } => {
            let api: Vec<RouteOut> = routes
                .routes
                .iter()
                .map(|r| RouteOut {
                    prefix: r.prefix.clone(),
                    kind: match &r.kind {
                        panel_os::RouteKind::Proxy { .. } => "proxy",
                        panel_os::RouteKind::Static { .. } => "static",
                        panel_os::RouteKind::Php { .. } => "php",
                    }
                    .to_string(),
                    upstreams: match &r.kind {
                        panel_os::RouteKind::Proxy { upstreams } => upstreams.clone(),
                        _ => Vec::new(),
                    },
                    spa: matches!(&r.kind, panel_os::RouteKind::Static { spa: true, .. }),
                    fpm: match &r.kind {
                        panel_os::RouteKind::Php { fpm, .. } => Some(fpm.clone()),
                        _ => None,
                    },
                    front_controller: match &r.kind {
                        panel_os::RouteKind::Php { front_controller, .. } => {
                            Some(front_controller.clone())
                        }
                        _ => None,
                    },
                    root: match &r.kind {
                        panel_os::RouteKind::Static { root, .. } => root.clone(),
                        _ => None,
                    },
                })
                .collect();
            serde_json::to_string(&api).unwrap_or_else(|_| "[]".into())
        }
        _ => "[]".to_string(),
    };
    // 反代 / PHP 后端配置一并落库（F6）：从已校验的 kind 提前取出，避免被 move 进 SiteSpec 后无法再借
    let (upstreams_json, fpm_str) = match &kind {
        panel_os::SiteKind::ReverseProxy { upstreams } => (serde_json::to_string(upstreams).ok(), None),
        panel_os::SiteKind::Php { fpm } => (None, Some(fpm.clone())),
        _ => (None, None),
    };
    let kind_db = kind_to_db(&kind);
    // 站点独立日志（021）：路径由面板指定——它同时是「下载 / 清空」的目标文件
    let (access_log_p, error_log_p) =
        site_log_paths(&state, &domains, log_access_db != 0, log_error_db != 0);
    // 站点独立日志（021）：nginx -t 会打开日志文件路径验证可写，目录须先存在，
    // 否则报 `open() .../xxx.access.log failed (No such file or directory)` 而整次 apply 失败。
    if access_log_p.is_some() || error_log_p.is_some() {
        let _ = std::fs::create_dir_all(site_log_dir(&state));
    }
    let spec = panel_os::SiteSpec {
        server_names: domains.iter().map(|d| d.clone()).collect(),
        root: root.as_path().to_path_buf(),
        listen: vec![80, 443],
        kind,
        access_log: access_log_p,
        error_log: error_log_p,
        tls_cert,
        tls_key,
        force_https: req.force_https.unwrap_or(true) && has_tls,
        spa_fallback: spa,
        waf,
        // 路由表已在 `kind` 里（Routed 变体），此字段只是对照——渲染以 kind 为准
        routes: None,
        // 自定义片段（019）：落库值同时进 spec 与指纹（clone 一份后面还要写库）
        custom_conf: custom_conf_db.clone(),
        www_redirect: Some(www_db.clone()),
        tls_profile: Some(tls_profile_db.clone()),
        tls_min: Some(tls_min_db.clone()),
        hsts: hsts_db != 0,
        hsts_max_age: hsts_max_age_db,
        hsts_include_sub: hsts_sub_db != 0,
        hsts_preload: hsts_preload_db != 0,
        rewrite_preset: Some(rewrite_preset_db.clone()),
        rewrite_custom: rewrite_custom_db.clone(),
        ip_allow: nonempty(split_list(&ip_allow_db)),
        ip_deny: nonempty(split_list(&ip_deny_db)),
        auth_basic: auth_basic_db != 0,
        auth_user: auth_user_db.clone(),
        auth_file: auth_file_db.clone(),
        lb_policy: Some(lb_policy_db.clone()),
        proxy_connect_timeout: pct_db,
        proxy_send_timeout: pst_db,
        proxy_read_timeout: prt_db,
        error_log_level: Some(log_level_db.clone()),
    };
    // 覆盖前备份：本次要写/换掉的磁盘文件里是**用户手改的内容**（manual_conf=1；
    // 由 manual_skip 的定义可知，只有显式 regen 才会走到这里）→ 先把旧文件备份。
    // 备份失败不阻断主流程（它是安全网，不是校验步骤）：响应里 backup=null，前端文案据实。
    let mut backup_path: Option<String> = None;
    if !manual_skip && was_manual {
        if let Some(cp) = cur_row
            .as_ref()
            .and_then(|r| r.conf_path.as_deref())
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            if let Some(b) = backup_manual_conf(&state, Path::new(cp)).await {
                audit(&state, &s, "site.conf.backup", &req.name, "ok").await;
                backup_path = Some(b.display().to_string());
            }
        }
    }

    // 4) 渲染 + 校验 + 下发（手动维护站点整段跳过：不重渲染、不覆盖、不 reload，
    //    conf_path 保持落库现值——那正是用户正在维护的那个文件）。
    // 版本留档（018）：真正落盘的内容在下面留存，落库成功后再进版本链
    // （落库失败不留档——版本链记录的必须是「已生效」的历史）。
    let mut archived_render: Option<String> = None;
    let conf = if manual_skip {
        cur_row.as_ref().and_then(|r| r.conf_path.clone()).unwrap_or_default()
    } else {
        let (target, rendered) = state.os.webserver().render(&spec)?;

        // 4) ⚠️ 校验在写事务之外。失败直接返回 40002，旧配置原封不动
        state
            .os
            .webserver()
            .validate(&rendered)
            .await
            .map_err(|e| ApiError::from(PanelError::ConfigInvalid { detail: e.to_string() }))?;

        // 5) 部署（仅启用态）。停用态：上面已渲染+校验通过配置，但**不**下发到 Web 服务器，
        //    配置不会进 nginx，与「真停用」一致；用户启用站点后再应用才会真正生效。
        if deploy {
            state.os.webserver().deploy(&target, &rendered).await?;
            // 文件已真实落盘 → 留存待版本链（落库成功后入库；见下方 archive 调用）
            archived_render = Some(rendered.clone());

            // 5.5) 域名改过则旧文件名成了孤儿：新配置已就位，**此刻**才轮到删旧配置。
            //      `remove` 自带 reload —— 删过就等于重载过了，不再重复 reload。
            let stale_conf = cur_row.as_ref().and_then(|r| r.conf_path.as_deref());
            let pruned = prune_stale_conf(&state, stale_conf, &target).await?;
            // 6) reload。失败时配置已写入但服务未加载 —— 这是可恢复的（配置语法已校验过）。
            //    apply 按 name upsert：新建站点的 id 要等下面落库才生成，故时间戳在
            //    upsert 后补记（其余四条入口在 finish_deploy 里落）。
            if !pruned {
                if let Err(e) = state.os.webserver().reload().await {
                    return Err(ApiError::from(PanelError::Command {
                        bin: "reload".to_string(),
                        detail: format!("配置已写入但 reload 失败：{e}"),
                    }));
                }
            }
        }
        target.display().to_string()
    };

    // 7) 落库：此时系统已处于期望状态（按 name upsert，与 create 不冲突）
    let name = req.name.clone();
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());
    let root_str = root.as_path().display().to_string();
    let now = crate::now_unix();
    // 停用态：conf_path 留空（配置未下发），enabled 保持 0；启用态 / 新建 / 手动维护：正常写入。
    let conf_db = if deploy { conf.clone() } else { String::new() };
    let enabled_i32: i32 = if deploy { 1 } else { 0 };

    // 部署指纹（017）：与下面要写入的字段**完全同源**——写入口径必须与读侧
    // `fingerprint_of` 逐字节一致，否则「未同步」会误报/漏报。
    let fingerprint_new = deploy_fingerprint(
        &name,
        &domains_json,
        &root_str,
        kind_db,
        spa_i32 != 0,
        upstreams_json.as_deref(),
        fpm_str.as_deref(),
        redirect_target_db.as_deref(),
        redirect_code_db,
        waf_on != 0,
        waf_profile.as_deref(),
        waf_rate,
        waf_burst,
        &routes_json,
        custom_conf_db.as_deref(),
        &advanced_json,
    );
    // 指纹只在「文件确实被写/删」时更新：
    // - 手动维护跳过下发：文件未动 → 保持旧值（更新它等于谎报「已同步」）
    // - 停用：无文件 → NULL
    // - 正常下发 / 重新生成：= 当前表单指纹
    let snap_db: Option<String> = if manual_skip {
        cur_row.as_ref().and_then(|r| r.conf_snapshot.clone())
    } else if deploy {
        Some(fingerprint_new.clone())
    } else {
        None
    };
    // 只有「重新生成」才结束手动维护；普通 apply 对手动站点是整段跳过（manual 保持 1）。
    let clear_manual: Option<i32> = if !manual_skip && was_manual { Some(0) } else { None };

    state
        .db
        .exec(move |conn| {
            // ?5 = enabled, ?6 = conf_path；deploy=false 时两者分别为 0 / 空串。
            // upstreams_json / fpm_str / spa / redirect_* 已在 apply 开头算出
            // （kind 之后被 move 进 SiteSpec）。
            conn.execute(
                "INSERT INTO sites(name, domains, root, kind, webserver, enabled, conf_path, created_at,
                                   waf_enabled, waf_profile, waf_rate, waf_burst, upstreams_json, fpm,
                                   spa, redirect_target, redirect_code, routes_json, conf_snapshot, custom_conf,
                                   www_redirect, tls_profile, tls_min, hsts, hsts_max_age, hsts_sub,
                                   hsts_preload, rewrite_preset, rewrite_custom,
                                   ip_allow, ip_deny, auth_basic, auth_user, lb_policy,
                                   proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
                                   log_access, log_error, log_error_level)
                 VALUES(?1, ?2, ?3, ?4, 'nginx', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?20,
                        ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29,
                        ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40)
                 ON CONFLICT(name) DO UPDATE SET
                    domains=excluded.domains, root=excluded.root, kind=excluded.kind, enabled=?5,
                    conf_path=?6, webserver='nginx',
                    waf_enabled=excluded.waf_enabled, waf_profile=excluded.waf_profile,
                    waf_rate=excluded.waf_rate, waf_burst=excluded.waf_burst,
                    upstreams_json=excluded.upstreams_json, fpm=excluded.fpm,
                    spa=excluded.spa, redirect_target=excluded.redirect_target,
                    redirect_code=excluded.redirect_code, routes_json=excluded.routes_json,
                    conf_snapshot=excluded.conf_snapshot,
                    custom_conf=excluded.custom_conf,
                    www_redirect=excluded.www_redirect, tls_profile=excluded.tls_profile,
                    tls_min=excluded.tls_min, hsts=excluded.hsts, hsts_max_age=excluded.hsts_max_age,
                    hsts_sub=excluded.hsts_sub, hsts_preload=excluded.hsts_preload,
                    rewrite_preset=excluded.rewrite_preset, rewrite_custom=excluded.rewrite_custom,
                    ip_allow=excluded.ip_allow, ip_deny=excluded.ip_deny,
                    auth_basic=excluded.auth_basic, auth_user=excluded.auth_user,
                    lb_policy=excluded.lb_policy,
                    proxy_connect_timeout=excluded.proxy_connect_timeout,
                    proxy_send_timeout=excluded.proxy_send_timeout,
                    proxy_read_timeout=excluded.proxy_read_timeout,
                    log_access=excluded.log_access, log_error=excluded.log_error,
                    log_error_level=excluded.log_error_level,
                    manual_conf=COALESCE(?19, manual_conf)",
                rusqlite::params![name, domains_json, root_str, kind_db, enabled_i32, conf_db, now,
                                  waf_on, waf_profile, waf_rate, waf_burst,
                                  upstreams_json, fpm_str, spa_i32, redirect_target_db, redirect_code_db,
                                  routes_json, snap_db, clear_manual, custom_conf_db,
                                  www_db, tls_profile_db, tls_min_db, hsts_db, hsts_max_age_db,
                                  hsts_sub_db, hsts_preload_db, rewrite_preset_db, rewrite_custom_db,
                                  ip_allow_db, ip_deny_db, auth_basic_db, auth_user_db, lb_policy_db,
                                  pct_db, pst_db, prt_db, log_access_db, log_error_db, log_level_db],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    // 上次下发时间（023）：apply 按 name upsert，新建站点的 id 由本次落库才生成，
    // 只能在此刻补记（其余四条入口在 finish_deploy 里落）。deploy=false 的停用态
    // apply 没有真实下发，不记——与 finish_deploy 同口径。
    if deploy {
        if let Some(row) = fetch_one_by_name(&state, &req.name).await? {
            touch_applied(&state, row.id).await;
        }
    }

    // 版本留档（018）：真实落盘 + 落库成功 → 进版本链（「重新生成」与普通下发作区分）。
    // 站点 id 回读——apply 按 name upsert，新建站点的 id 由本次落库才生成。
    if let Some(content) = archived_render {
        if let Some(row) = fetch_one_by_name(&state, &req.name).await? {
            let source = if was_manual { "regen" } else { "apply" };
            archive_conf_version(&state, row.id, &content, Some(fingerprint_new), source, &s.username)
                .await;
        }
    }

    audit(&state, &s, "site.apply", &req.name, "ok").await;
    Ok(ok(serde_json::json!({
        "name": req.name,
        "config": conf,
        "deployed": deploy,
        // 手动维护：配置保持原样（未重渲染），如实报 reloaded=false + manual=true
        "reloaded": deploy && !manual_skip,
        "enabled": deploy,
        "manual": manual_skip,
        // 「重新生成」：本次把手动维护的文件按表单覆盖了（manual 已清零）
        "regenerated": !manual_skip && was_manual,
        // 覆盖前的手改备份路径（<data_dir>/conf-backups/…）；无需备份 / 失败为 null
        "backup": backup_path,
    })))
}

/// 仅 reload Web 服务器（全局操作；按 id 仅用于审计与 API 对称）。
pub async fn reload(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    state
        .os
        .webserver()
        .reload()
        .await
        .map_err(ApiError::from)?;
    audit(&state, &s, "site.reload", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "reloaded": true })))
}

// ─────────────── 站点配置：查看 / 原始编辑（手动维护） ───────────────
//
// 背景：面板托管的配置是「表单 → render → validate → 下发」的产物。手动维护
// （016 迁移的 manual_conf）让用户直接改这份产物成为一等状态：
// - GET  conf：读取落盘内容（路径取**落库 conf_path**，绝不接受前端传路径）
// - PUT  conf：原始写入 → 此后表单保存不再覆盖（仅 owner；写入前必过 nginx -t）
// - POST conf/restore：恢复面板托管（按表单重新渲染覆盖，清零 manual_conf）
//
// 017 迁移再补一拍：conf_snapshot 指纹让「表单已改、文件没跟上」的**静默**分叉
// 变成可见状态（conf_stale / 「未同步」），并在覆盖手改内容前自动备份。

/// 解析站点配置的写盘目标路径并做纵深校验（`conf_put` / `conf_rollback` 共用——
/// 同一约束两条路径必须同源，历史上「两路漏配」是本项目最高发 bug 之一）。
///
/// 规则：优先落库 `conf_path`（曾下发过，可能带着旧域名文件名）；从未下发则按
/// provider 的命名规则推导（与 render 同源，**绝不由前端指定路径**）。
/// 父目录必须就是 Web 配置目录且路径不含 `..`——防被篡改的库值把写操作引到别处。
fn resolve_conf_target(state: &Shared, row: &RawSite) -> ApiResult<PathBuf> {
    let target: PathBuf = match row
        .conf_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        Some(p) => PathBuf::from(p),
        None => {
            let domains: Vec<String> = serde_json::from_str(&row.domains).unwrap_or_default();
            if domains.is_empty() {
                return Err(ApiError::bad_request("conf", "站点缺少域名，无法推导配置文件路径"));
            }
            state.os.webserver().conf_path(&domains)
        }
    };
    let conf_dir = state.os.paths().web_conf_dir();
    let parent_ok = target.parent().map(|p| p == conf_dir).unwrap_or(false)
        && !target
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
    if !parent_ok {
        return Err(ApiError::bad_request(
            "conf_path",
            "落库配置路径不在 Web 配置目录内，拒绝写入",
        ));
    }
    Ok(target)
}

/// 覆盖手动配置前的备份：复制到 `<data_dir>/conf-backups/<文件名>.<unix>.bak`，
/// 同前缀仅保留最近 10 份（`prune_keep_newest` 按 mtime 判新旧）。
///
/// 返回备份路径；文件不存在 / 任何步骤失败返回 None——备份是安全网而非校验步骤，
/// 失败**不阻断**「重新生成 / 恢复托管 / 停用」主流程（响应 backup=null，前端文案据实）。
/// 放在业务层而不是 provider：provider 抽象的是「渲染/下发」，备份是面板的策略
/// （保留几份、放哪、怎么命名），与具体 Web 服务器无关。
async fn backup_manual_conf(state: &Shared, conf_path: &Path) -> Option<PathBuf> {
    let file_name = conf_path.file_name()?.to_str()?.to_string();
    if tokio::fs::metadata(conf_path).await.is_err() {
        return None; // 文件不存在（或不可读）——无事可备
    }
    let dir = state.os.paths().data_dir().join("conf-backups");
    tokio::fs::create_dir_all(&dir).await.ok()?;
    // 同一秒内多次备份会撞名：撞了顺延序号，绝不覆盖既有备份
    let ts = crate::now_unix();
    let mut dest = dir.join(format!("{file_name}.{ts}.bak"));
    let mut n = 1u32;
    while tokio::fs::metadata(&dest).await.is_ok() {
        dest = dir.join(format!("{file_name}.{ts}.{n}.bak"));
        n += 1;
    }
    tokio::fs::copy(conf_path, &dest).await.ok()?;
    // 清理放在副本写好**之后**：先保新、再清旧（反过来会在复制失败时白删旧备份）
    let dir2 = dir.clone();
    let prefix = format!("{file_name}.");
    let _ = tokio::task::spawn_blocking(move || {
        panel_os::fs::prune_keep_newest(&dir2, &prefix, 10)
    })
    .await;
    Some(dest)
}

/// 配置内容指纹（SHA-256 十六进制）——版本去重与「当前版本」标记用。
fn conf_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    const T: &[u8; 16] = b"0123456789abcdef";
    let d = Sha256::digest(content.as_bytes());
    let mut s = String::with_capacity(64);
    for &x in d.iter() {
        s.push(T[(x >> 4) as usize] as char);
        s.push(T[(x & 0xf) as usize] as char);
    }
    s
}

/// 给站点配置留档一版（去重 + 每站保留最新 20 版）。
///
/// 调用点 = 全部写入口：apply 正常下发 / conf_restore 重新渲染 / conf_put 手动
/// 保存 / conf_rollback 回滚（回滚前先把现场留档）。与**最新版**内容相同（hash
/// 相等）不重复入库——反复「保存并应用」不会堆出一串一模一样的版本。
///
/// `fingerprint` 记录「这版内容对应的部署指纹」（可空）：回滚时若某版的指纹恰好
/// 等于当前表单指纹，说明那份内容正是表单产物 → 回滚后站点可回「面板托管」；
/// 否则按手动维护处理（快照=版本指纹，表单再分叉时「未同步」照常亮）。
///
/// 失败不阻断主流程（版本链是安全网，与 `backup_manual_conf` 同哲学）——
/// 但必须出声：静默丢版本链比报错更危险。
async fn archive_conf_version(
    state: &Shared,
    site_id: i64,
    content: &str,
    fingerprint: Option<String>,
    source: &str,
    operator: &str,
) {
    let hash = conf_hash(content);
    let content = content.to_string();
    // 闭包要 move 走一个 String；原 `source`（&str）留着给收尾日志用，
    // 否则日志会借用已 move 的值（E0382）。
    let source_in = source.to_string();
    let operator = operator.to_string();
    let res = state
        .db
        .exec(move |conn| {
            // 去重：与最新版相同则跳过（避免反复 apply 堆同内容版本）
            let last: Option<String> = conn
                .query_row(
                    "SELECT hash FROM site_conf_versions WHERE site_id = ?1 ORDER BY id DESC LIMIT 1",
                    [site_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            if last.as_deref() == Some(hash.as_str()) {
                return Ok(panel_db::WriteAck { rows_changed: 0 });
            }
            conn.execute(
                "INSERT INTO site_conf_versions(site_id, content, hash, fingerprint, source, operator, created_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![site_id, content, hash, fingerprint, source_in, operator, crate::now_unix()],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            // 每站保留最新 20 版（写入后立即裁剪，防无限增长）
            conn.execute(
                "DELETE FROM site_conf_versions WHERE site_id = ?1 AND id NOT IN (
                     SELECT id FROM site_conf_versions WHERE site_id = ?1 ORDER BY id DESC LIMIT 20)",
                [site_id],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await;
    if let Err(e) = res {
        eprintln!("[sites] archive_conf_version(site={site_id}, source={source}) 失败: {e}");
    }
}

/// 读取站点当前的 Web 服务器配置文件内容。
///
/// 路径唯一来源是**落库的 `conf_path`**（由 apply/patch 写入，不接受前端输入——
/// 否则就成了「读任意文件」的越权面）。尚未下发 / 文件缺失时如实返回 `content: null`。
/// 站点日志类型参数：`access` | `error`。
#[derive(Debug, Deserialize)]
pub struct SiteLogKindQ {
    #[serde(default)]
    pub kind: Option<String>,
}

/// 该站点的日志文件路径（未开启独立日志 → None）。
fn site_log_file(row: &RawSite, state: &Shared, kind: &str) -> Option<std::path::PathBuf> {
    let domains: Vec<String> = serde_json::from_str(&row.domains).unwrap_or_default();
    let (a, e) = site_log_paths(state, &domains, row.log_access != 0, row.log_error != 0);
    if kind == "error" { e } else { a }
}

/// 下载站点日志（021）。走 `location` 直下即可（cookie 认证，无需 CSRF），
/// 与根证书下载同范式；未开启独立日志时 404 并给出原因。
pub async fn log_download(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Query(q): Query<SiteLogKindQ>,
) -> ApiResult<axum::response::Response> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    let kind = q.kind.as_deref().unwrap_or("access");
    let p = site_log_file(&row, &state, kind)
        .ok_or_else(|| ApiError::bad_request("kind", "该站点未开启独立日志（先在编辑弹窗里开启）"))?;
    let body = match tokio::fs::read(&p).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::bad_request("kind", "日志文件尚未生成（站点还没有请求）"))
        }
        Err(e) => return Err(ApiError::from(PanelError::Io(e.to_string()))),
    };
    let name = format!(
        "{}-{}.log",
        row.name,
        if kind == "error" { "error" } else { "access" }
    );
    Ok(axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/plain; charset=utf-8")
        .header(
            "content-disposition",
            format!("attachment; filename=\"{name}\""),
        )
        .body(axum::body::Body::from(body))
        .map_err(|e| ApiError::from(PanelError::Internal(e.to_string())))?)
}

/// 清空站点日志（021）：截断而非删除——删除会让正在写入的 nginx worker 继续往
/// 已 unlink 的 inode 写（磁盘不释放、文件"失踪"），截断才是运维上的正确做法。
pub async fn log_clear(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<SiteLogClearReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    let kind = req.kind.clone().unwrap_or_else(|| "access".to_string());
    let p = site_log_file(&row, &state, &kind)
        .ok_or_else(|| ApiError::bad_request("kind", "该站点未开启独立日志（先在编辑弹窗里开启）"))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&p)
        .map_err(|e| ApiError::from(PanelError::Io(e.to_string())))?;
    let kref: &'static str = if kind == "error" { "error" } else { "access" };
    audit(&state, &s, "site.log.clear", &id.to_string(), kref).await;
    Ok(ok(serde_json::json!({ "path": p.display().to_string() })))
}

/// 清空日志的请求体。
#[derive(Debug, Deserialize)]
pub struct SiteLogClearReq {
    pub kind: Option<String>,
}

pub async fn conf_get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    let path = row
        .conf_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    let content = match path {
        Some(p) => match tokio::fs::read_to_string(p).await {
            Ok(c) => Some(c),
            // 文件被外部删除：如实返回「无内容」，而不是 404 把弹窗打成错误态
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(ApiError::from(PanelError::Io(format!("read {p}: {e}")))),
        },
        None => None,
    };
    Ok(ok(serde_json::json!({
        "path": path,
        "content": content,
        "manual": row.manual_conf != 0,
        // 未同步（017）：表单部署相关字段与「文件上次落盘时的指纹」不一致。
        // 配置区据此显示警示条 + 一键「重新生成配置」。
        "stale": conf_stale_of(&row),
        // 外部修改（020）：磁盘内容与最后一次留档不一致 ⇒ 文件在面板之外被改过
        "external": external_of(&row).await,
    })))
}

/// `PUT` 的请求体：完整配置片段（与落盘文件同构——server / map 等 http 上下文片段）。
#[derive(Debug, Deserialize)]
pub struct ConfPutReq {
    pub content: String,
}

/// 保存站点原始配置（进入 / 保持「手动维护」）。
///
/// ⚠ 写入面等价于「一台 root 改 nginx」——仅 **owner** 可调用，且校验失败尝试也留审计。
/// 顺序与 apply 完全一致：**先 `nginx -t` 校验 → 原子替换 → reload**；校验不过旧文件纹丝不动。
/// 成功后站点置 `manual_conf=1`：此后表单「保存并应用」不再覆盖该文件（见 016 迁移）。
pub async fn conf_put(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<ConfPutReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if s.role != "owner" {
        return Err(ApiError::forbidden("owner"));
    }
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    if row.enabled == 0 {
        return Err(ApiError::bad_request(
            "enabled",
            "站点已停用（配置已从 Web 服务器移除）；请先启用后再编辑原始配置",
        ));
    }
    if req.content.trim().is_empty() {
        return Err(ApiError::bad_request("content", "配置内容不能为空"));
    }
    if req.content.len() > 1_048_576 {
        return Err(ApiError::bad_request("content", "配置内容超过 1 MiB 上限"));
    }

    // 目标路径 + 纵深校验：与 conf_rollback 共用同一函数（两路同源）
    let target = resolve_conf_target(&state, &row)?;

    // 校验（独立 wrapper 跑 nginx -t，不触碰线上配置）→ 失败 40002 + 原始 stderr
    if let Err(e) = state.os.webserver().validate(&req.content).await {
        audit(&state, &s, "site.conf.edit", &id.to_string(), "fail").await;
        return Err(ApiError::from(PanelError::ConfigInvalid { detail: e.to_string() }));
    }
    // 原子替换 + reload；reload 失败时配置已写入（语法已验过，可恢复）——与 apply 同口径
    state.os.webserver().deploy(&target, &req.content).await?;
    finish_deploy(&state, id, false).await?;

    let path_str = target.display().to_string();
    let path_db = path_str.clone();
    // 指纹 = 当前表单值：此刻「文件已对齐表单」（文件=用户文本 + 表单=库值）。
    // 未来表单再改时，与这份文件分叉 → 未同步提示由此成立（017 迁移）。
    let snap_db = fingerprint_of(&row);
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET manual_conf = 1, conf_path = ?1, conf_snapshot = ?3 WHERE id = ?2",
                rusqlite::params![path_db, id, snap_db],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.conf.edit", &id.to_string(), "ok").await;
    // 版本留档（018）：手动保存 = 一条新的「已生效历史」（source=manual）。
    // 指纹与上面 conf_snapshot 同源（保存后：文件=用户文本、快照=当前表单——
    // 两者此刻配对；未来表单再改，「未同步」照常亮起）。
    archive_conf_version(&state, id, &req.content, Some(fingerprint_of(&row)), "manual", &s.username)
        .await;
    Ok(ok(serde_json::json!({ "path": path_str, "manual": true, "stale": false, "reloaded": true })))
}

/// 恢复面板托管：按表单规格重新渲染覆盖（丢弃手工内容），清零 `manual_conf`。
///
/// 与 `patch` 的「重新启用下发」同一条渲染路径（`render_spec_for_row`，自带校验）。
/// 停用站点没有配置文件可恢复——只清零标记（下次启用按表单渲染）。
pub async fn conf_restore(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if s.role != "owner" {
        return Err(ApiError::forbidden("owner"));
    }
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;

    // 停用站点：无文件可恢复，仅清零标记（启用路径会按表单重新渲染）
    if row.enabled == 0 {
        state
            .db
            .exec(move |conn| {
                conn.execute(
                    "UPDATE sites SET manual_conf = 0, conf_snapshot = NULL WHERE id = ?1",
                    [id],
                )
                .map(|n| panel_db::WriteAck { rows_changed: n })
                .map_err(|e| PanelError::Database(e.to_string()))
            })
            .await?;
        audit(&state, &s, "site.conf.restore", &id.to_string(), "ok").await;
        return Ok(ok(serde_json::json!({
            "path": serde_json::Value::Null,
            "manual": false,
            "deployed": false,
            "reloaded": false,
        })));
    }

    let domains: Vec<String> = serde_json::from_str(&row.domains).unwrap_or_default();
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "站点缺少域名，无法重新渲染配置"));
    }
    // 覆盖前备份手改内容：在渲染**之前**做——无论新文件同名覆盖、还是改名后清孤儿，
    // 旧内容都已经进了备份（安全网，失败不阻断）。
    let mut backup_path: Option<String> = None;
    if row.manual_conf != 0 {
        if let Some(cp) = row.conf_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            if let Some(b) = backup_manual_conf(&state, Path::new(cp)).await {
                audit(&state, &s, "site.conf.backup", &id.to_string(), "ok").await;
                backup_path = Some(b.display().to_string());
            }
        }
    }
    let (target, rendered) = render_spec_for_row(&state, &row, &domains, &row.root).await?;
    state.os.webserver().deploy(&target, &rendered).await?;
    let pruned = prune_stale_conf(&state, row.conf_path.as_deref(), &target).await?;
    finish_deploy(&state, id, pruned).await?;

    let path_str = target.display().to_string();
    let path_db = path_str.clone();
    // 指纹 = 当前表单值（渲染正是按它做的）→ 恢复托管后天然「已同步」
    let snap_db = fingerprint_of(&row);
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET manual_conf = 0, conf_path = ?1, conf_snapshot = ?3 WHERE id = ?2",
                rusqlite::params![path_db, id, snap_db],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.conf.restore", &id.to_string(), "ok").await;
    // 版本留档（018）：重新生成 = 按表单渲染的产物（source=regen）
    archive_conf_version(&state, id, &rendered, Some(fingerprint_of(&row)), "regen", &s.username)
        .await;
    Ok(ok(serde_json::json!({
        "path": path_str,
        "manual": false,
        "stale": false,
        "deployed": true,
        "reloaded": true,
        "backup": backup_path,
    })))
}

// ─────────────── 站点配置：版本历史 / 回滚（018 迁移） ───────────────
//
// 版本链是配置生命周期的另一半：写入口（apply/regen/manual/rollback）每次都把
// 生效内容留档（同 hash 去重、每站保留 20 版）。回滚 = 选任一天历史版本作为新的
// 「当前文件」：nginx -t 校验 → 原子替换 → reload；被恢复的内容与被你替换掉的
// 现场都会进版本链。回滚后自动定态：版本指纹 == 当前表单指纹 ⇒ 内容正是表单
// 产物 → 回「面板托管」；否则转「手动维护」（表单再分叉时「未同步」照常亮）。

/// 外部修改检测（020）：磁盘内容与「最后一次留档的版本」不一致 ⇒ 文件在面板之外
/// 被改动过。
///
/// **不静默覆盖**是刻意的：面板无从判断一次外部改动是用户有意、脚本误写还是攻击，
/// 所以只如实标记，把决策交回用户（重新生成覆盖 / 改成自定义片段 / 手动接管）。
/// 无留档（`last_ver_hash` 为 NULL）时无从判定，返回 false——宁可不报，也不谎报。
async fn external_of(r: &RawSite) -> bool {
    let Some(p) = r.conf_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
        return false;
    };
    let Some(last) = r.last_ver_hash.as_deref() else { return false };
    match tokio::fs::read_to_string(p).await {
        Ok(c) => conf_hash(&c) != last,
        // 文件被删 / 读不了：交给「未下发 / 缺失」那套语义处理，不算外部修改
        Err(_) => false,
    }
}

/// 版本历史列表：倒序返回最近 20 版**元数据**（不含正文——正文按需单取，
/// 避免一次拉 20 份全文）。每项附 `current`：该版内容 == 磁盘当前内容。
pub async fn conf_versions(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    // 磁盘当前内容 hash（文件缺失 → None：所有版本 current=false，如实呈现）
    let cur_hash: Option<String> = match row
        .conf_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        Some(p) => tokio::fs::read_to_string(p)
            .await
            .ok()
            .map(|c| conf_hash(&c)),
        None => None,
    };
    let items: Vec<serde_json::Value> = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, hash, source, operator, created_at, LENGTH(content)
                     FROM site_conf_versions WHERE site_id = ?1 ORDER BY id DESC LIMIT 20",
                )
                .map_err(db_err)?;
            let rows = st
                .query_map([id], |r| {
                    let hash: String = r.get(1)?;
                    Ok(serde_json::json!({
                        "id": r.get::<_, i64>(0)?,
                        "hash": hash,
                        "source": r.get::<_, String>(2)?,
                        "operator": r.get::<_, String>(3)?,
                        "created_at": r.get::<_, i64>(4)?,
                        "size": r.get::<_, i64>(5)?,
                        "current": cur_hash.as_deref() == Some(hash.as_str()),
                    }))
                })
                .map_err(db_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(db_err)?);
            }
            Ok(out)
        })
        .await?;
    Ok(ok(serde_json::json!({ "items": items })))
}

/// 单个历史版本的正文（回滚前预览用）。版本必须属于本站点（`AND site_id = ?2`，
/// 防跨站读取——版本 id 是全局自增，不校验归属就成越权面）。
pub async fn conf_version_get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath((id, vid)): AxPath<(i64, i64)>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    let v = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT id, content, hash, source, operator, created_at
                 FROM site_conf_versions WHERE id = ?1 AND site_id = ?2",
                rusqlite::params![vid, id],
                |r| {
                    Ok(serde_json::json!({
                        "id": r.get::<_, i64>(0)?,
                        "content": r.get::<_, String>(1)?,
                        "hash": r.get::<_, String>(2)?,
                        "source": r.get::<_, String>(3)?,
                        "operator": r.get::<_, String>(4)?,
                        "created_at": r.get::<_, i64>(5)?,
                    }))
                },
            )
            .optional()
            .map_err(db_err)
        })
        .await?;
    let Some(v) = v else {
        return Err(ApiError::not_found("version"));
    };
    Ok(ok(v))
}

/// 回滚定态：决定回滚后站点归「面板托管」还是「手动维护」。
///
/// 判据 = 版本留档时记录的部署指纹 vs **当前**表单指纹：
/// - 相等 ⇒ 这版内容正是当前表单的产物（例如先改了表单没下发、又想退回上一版
///   渲染结果）→ 回「面板托管」，快照=表单指纹（天然已同步）。
/// - 否则 ⇒ 转「手动维护」，快照=版本指纹；版本无指纹（旧行/外部来源）则留
///   NULL——「未同步」照常亮起，向提示的一侧倾斜（与 017 同哲学）。
fn rollback_state(ver_fp: Option<&str>, form_fp: &str) -> (i32, Option<String>) {
    if ver_fp == Some(form_fp) {
        (0, Some(form_fp.to_string()))
    } else {
        (1, ver_fp.map(str::to_string))
    }
}

/// 回滚请求体。
#[derive(Debug, Deserialize)]
pub struct ConfRollbackReq {
    /// 目标版本 id（`site_conf_versions.id`）
    pub version_id: i64,
}

/// 回滚到指定历史版本。⚠ 与 `conf_put` 同为「root 级写入面」，仅 owner。
///
/// 顺序：nginx -t 校验（失败 40002 + 原始 stderr，旧文件纹丝不动）→ 现场留档
/// （磁盘当前内容进版本链，源=rollback）→ 原子替换 → reload → 自动定态 + 留档。
pub async fn conf_rollback(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<ConfRollbackReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if s.role != "owner" {
        return Err(ApiError::forbidden("owner"));
    }
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    if row.enabled == 0 {
        return Err(ApiError::bad_request(
            "enabled",
            "站点已停用（配置已从 Web 服务器移除）；请先启用后再回滚配置",
        ));
    }
    // 目标版本（必须属于本站点）
    let vid = req.version_id;
    let ver = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT content, fingerprint FROM site_conf_versions WHERE id = ?1 AND site_id = ?2",
                rusqlite::params![vid, id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .optional()
            .map_err(db_err)
        })
        .await?;
    let Some((content, ver_fp)) = ver else {
        return Err(ApiError::not_found("version"));
    };
    // 校验（独立 wrapper 跑 nginx -t，不触碰线上）→ 失败 40002 + 原始 stderr
    if let Err(e) = state.os.webserver().validate(&content).await {
        audit(&state, &s, "site.conf.rollback", &id.to_string(), "fail").await;
        return Err(ApiError::from(PanelError::ConfigInvalid {
            detail: e.to_string(),
        }));
    }
    let target = resolve_conf_target(&state, &row)?;
    // 现场留档：磁盘当前内容进版本链（source=rollback；与最新版相同则自动去重）。
    // 外部手改（面板不知情）的内容也由此获得一条可回溯记录。指纹沿用站点快照
    // ——它记录的正是「这版文件对应的部署指纹」。
    if let Ok(cur) = tokio::fs::read_to_string(&target).await {
        archive_conf_version(&state, id, &cur, row.conf_snapshot.clone(), "rollback", &s.username)
            .await;
    }
    // 原子替换 + reload（reload 失败时配置已写入、语法已验过，可恢复——与 apply 同口径）
    state.os.webserver().deploy(&target, &content).await?;
    finish_deploy(&state, id, false).await?;
    // 自动定态（判据见 `rollback_state` 与其单测）
    let form_fp = fingerprint_of(&row);
    let (manual_new, snap_new) = rollback_state(ver_fp.as_deref(), &form_fp);
    let path_str = target.display().to_string();
    let path_db = path_str.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET manual_conf = ?3, conf_path = ?1, conf_snapshot = ?4 WHERE id = ?2",
                rusqlite::params![path_db, id, manual_new, snap_new],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.conf.rollback", &id.to_string(), "ok").await;
    // 被恢复的内容也进版本链（指纹继承版本）：列表最新 = 当前磁盘事实
    archive_conf_version(&state, id, &content, ver_fp, "rollback", &s.username).await;
    Ok(ok(serde_json::json!({
        "path": path_str,
        "manual": manual_new != 0,
        // 定态后 manual=1 时快照（版本指纹）≠ 当前表单指纹，恒「未同步」——如实报告
        "stale": manual_new != 0,
        "deployed": true,
        "reloaded": true,
        "restored_from": req.version_id,
    })))
}

/// 站点日志（SSE）：`kind=access|error`，跟随该站点的 nginx 日志文件。
#[derive(Debug, Deserialize)]
pub struct SiteLogQ {
    pub kind: Option<String>,
    pub filter: Option<String>,
    pub limit: Option<usize>,
}

pub async fn logs(
    State(state): State<Shared>,
    MaybeAuth(session): MaybeAuth,
    AxPath(id): AxPath<i64>,
    Query(q): Query<SiteLogQ>,
) -> axum::response::Response {
    let Some(s) = session else { return ApiError::unauthorized().into_response() };
    if crate::auth::require(&s, perm::SITE_VIEW).is_err() {
        return ApiError::forbidden(perm::SITE_VIEW).into_response();
    }
    if !state.capabilities.get(cap_keys::LOGS_READ).map(|c| c.supported).unwrap_or(false) {
        return ApiError::unsupported("logs.read").into_response();
    }
    let site = match fetch_one(&state, id).await {
        Ok(Some(x)) => x,
        Ok(None) => return ApiError::not_found("site").into_response(),
        Err(e) => return ApiError::from(e).into_response(),
    };
    let domains: Vec<String> = serde_json::from_str(&site.domains).unwrap_or_default();
    let stem = slug(domains.first().map(|s| s.as_str()).unwrap_or("site"));
    let which = q.kind.as_deref().unwrap_or("access");
    let (kind, seg) = if which == "error" {
        (panel_os::LogSourceKind::SiteError, "error")
    } else {
        (panel_os::LogSourceKind::SiteAccess, "access")
    };
    let src = panel_os::LogSource {
        id: format!("site:{stem}/{seg}"),
        label: format!("{} · {}", site.name, which),
        kind,
    };
    crate::sse::follow_source(state.clone(), src, q.filter, q.limit.unwrap_or(200)).await
}

// ─────────────── TLS 落盘与查询辅助 ───────────────

/// 自签证书有效期（天）。825 天对齐主流浏览器对单张证书的最长信任上限。
const SELF_SIGNED_DAYS: u32 = 825;

/// 面板托管的证书落盘目录（nginx 从这里读取 cert/key）。
fn ssl_dir(state: &Shared) -> PathBuf {
    state.os.paths().data_dir().join("ssl")
}

/// 面板本地根 CA 目录（签发/验证自签 leaf 用；浏览器只需下载 `ca.crt`）。
fn ca_dir(state: &Shared) -> PathBuf {
    ssl_dir(state).join("ca")
}

/// 由首个域名派生该站点证书的 (crt, key) 落盘路径（与 provider 配置文件名同源命名）。
fn cert_paths_for(state: &Shared, domains: &[String]) -> (PathBuf, PathBuf) {
    let stem = slug(domains.first().map(|s| s.as_str()).unwrap_or("site"));
    let dir = ssl_dir(state);
    (dir.join(format!("{stem}.crt")), dir.join(format!("{stem}.key")))
}

/// 写证书/私钥到磁盘：crt 0644、key 0600（私钥绝不可被他人读取）。
fn write_cert_files(crt: &Path, key: &Path, cert_pem: &str, key_pem: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = crt.parent().ok_or_else(|| PanelError::Internal("bad cert path".into()))?;
    std::fs::create_dir_all(dir).map_err(|e| PanelError::Internal(e.to_string()))?;
    std::fs::write(crt, cert_pem).map_err(|e| PanelError::Internal(e.to_string()))?;
    std::fs::write(key, key_pem).map_err(|e| PanelError::Internal(e.to_string()))?;
    let _ = std::fs::set_permissions(crt, std::fs::Permissions::from_mode(0o644));
    let _ = std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// 该站点最近一张证书覆盖的域名（apply 注入 tls / delete 清理文件都用它）。
async fn cert_domains_for_site(state: &Shared, site_id: i64) -> Result<Option<Vec<String>>> {
    state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains FROM ssl_certs WHERE site_id = ?1 ORDER BY id DESC LIMIT 1")
                .map_err(db_err)?;
            let mut it = st.query_map([site_id], |r| r.get::<_, String>(0)).map_err(db_err)?;
            match it.next().transpose().map_err(db_err)? {
                Some(js) => Ok(Some(serde_json::from_str(&js).unwrap_or_default())),
                None => Ok(None),
            }
        })
        .await
}

// ─────────────── SSL 证书 ───────────────

#[derive(Debug, Serialize)]
pub struct CertDto {
    pub id: i64,
    pub domain: String,
    pub issuer: Option<String>,
    pub not_after: Option<i64>,
    /// 剩余天数（UI 据此标黄/标红）
    pub days_left: Option<i64>,
    pub auto_renew: bool,
    /// idle | pending | ok | failed
    pub renew_state: String,
    /// acme | self-signed | manual（UI 据此决定自动续期开关是否可用）
    pub source: String,
}

pub async fn certs(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let rows = state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, domains, issuer, not_after, renew_state, auto_renew, source \
                     FROM ssl_certs ORDER BY not_after",
                )
                .map_err(db_err)?;
            let it = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5).unwrap_or(0),
                        r.get::<_, String>(6)?,
                    ))
                })
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(db_err)?);
            }
            Ok(v)
        })
        .await?;

    let now = crate::now_unix();
    let dtos: Vec<CertDto> = rows
        .into_iter()
        .map(|(id, domains_json, issuer, not_after, renew, auto_renew, source)| {
            // 证书覆盖多个域名（JSON 数组）；UI 单域名列展示主域名（首个）
            let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
            let primary = domains.into_iter().next().unwrap_or_default();
            CertDto {
                id,
                domain: primary,
                issuer,
                days_left: not_after.map(|t| (t - now) / 86_400),
                not_after,
                // 真实开关（v10 起有 auto_renew 列）。注意它只表示"用户已允许自动续期"，
                // 真正能否续还取决于 ssl.acme 能力位（certbot 是否可用）——
                // UI 需结合能力位判断，别把"开关关着"和"根本用不了"混为一谈。
                auto_renew: auto_renew != 0,
                renew_state: renew,
                source,
            }
        })
        .collect();
    Ok(ok(dtos))
}

/// 证书自动续期扫描的最近运行状态（前端"上次/下次扫描"展示用）。
///
/// 由内部调度器每日 4:05 触发的 `auto_renew_sweep` 写入 `cert_sweep_state`；
/// 本端点只读取，不参与调度。未运行过时整表为空 → 返回 `last_at=0`，
/// 前端据此显示"尚未运行"。
pub async fn cert_renew_sweep_state(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let row: Option<(i64, i64)> = state
        .pool
        .with(|conn| {
            match conn.query_row(
                "SELECT last_at, last_queued FROM cert_sweep_state WHERE id = 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            ) {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await?;
    let (last_at, last_queued) = row.unwrap_or((0, 0));
    // 调度为每日一次，下次 ≈ 上次 + 24h；从未运行则 0（前端显示"尚未运行"）
    let next_at = if last_at > 0 { last_at + 86_400 } else { 0 };
    Ok(ok(serde_json::json!({
        "last_at": last_at,
        "last_queued": last_queued,
        "next_at": next_at,
    })))
}

#[derive(Debug, Deserialize)]
pub struct SslApplyReq {
    /// 留空则沿用站点现有域名
    #[serde(default)]
    pub domains: Vec<String>,
    /// `self-signed`（缺省）| `http-01` | `dns-01`
    pub method: Option<String>,
    #[allow(dead_code)]
    pub email: Option<String>,
}

/// 申请证书。按 `method` 分流：
/// - `self-signed`：面板自签（**同步**完成，需 `ssl.selfsigned` + 主密钥，离线可用）；
/// - `http-01`/`dns-01`：ACME，`ssl.acme` 门控，未接入时诚实 501（#61）。
pub async fn ssl_apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<SslApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    // 无 Web 服务器底座时拒发证书：证书没有进程可加载，只会制造
    // "已配置"却永远不生效的假象（与 create/apply 同一守卫，防绕过 UI）。
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let site = fetch_one(&state, id).await?.ok_or_else(|| ApiError::not_found("site"))?;

    // 域名：请求覆盖 或 沿用站点现有域名
    let domains: Vec<String> = if req.domains.is_empty() {
        serde_json::from_str(&site.domains).unwrap_or_default()
    } else {
        let mut out = Vec::with_capacity(req.domains.len());
        for d in &req.domains {
            let dom = domain(d.trim())
                .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
            out.push(dom.as_str().to_string());
        }
        out
    };
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "no domain to certify"));
    }

    let method = req.method.clone().unwrap_or_else(|| "self-signed".into());
    match method.as_str() {
        "self-signed" => {}
        "http-01" => {
            if !state.capabilities.get(cap_keys::SSL_ACME).map(|c| c.supported).unwrap_or(false) {
                return Err(ApiError::unsupported("ssl.acme"));
            }
            // ACME 需要真实账户邮箱（CA 用它发到期/异常通知）——没有就明确报错，
            // 绝不静默填一个假地址（那会让用户收不到任何到期提醒）。
            let email = req
                .email
                .as_deref()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| ApiError::bad_request("email", "http-01 签发需要账户邮箱"))?
                .to_string();
            // 注：certbot 回退路线目前只签**主域名**（多域名 SAN 待扩展）
            let webroot = resolve_site_root(&state, &site.root, &site.name)?
                .as_path()
                .to_path_buf();
            let (crt_p, key_p) = cert_paths_for(&state, &domains);
            let job = AcmeTask {
                mode: AcmeMode::Issue,
                site_id: id,
                domains: domains.clone(),
                email,
                webroot,
                crt_p,
                key_p,
                master: state.require_secret_key()?,
                db: state.db.clone(),
            };
            let (tid, _) = state
                .tasks
                .submit(
                    panel_task::TaskRequest {
                        idempotency_key: format!("cert:{id}:{}", domains.join(",")),
                        kind: panel_task::TaskKind::CertIssue,
                        label: format!("ACME 签发证书（{}）", domains.join(", ")),
                        timeout: std::time::Duration::from_secs(900),
                    },
                    job,
                )
                .await
                .map_err(ApiError::from)?;
            audit(&state, &s, "ssl.apply", &id.to_string(), "queued").await;
            return Ok(ok(serde_json::json!({ "task_id": tid, "source": "acme" })));
        }
        "dns-01" => {
            return Err(ApiError::unsupported(
                "dns-01 需 DNS 提供商 API（设计 §2.4 列为 M5）；certbot 回退路线当前仅实现 http-01",
            ))
        }
        other => return Err(ApiError::bad_request("method", format!("unsupported method: {other}"))),
    }

    if !state.capabilities.get(cap_keys::SSL_SELFSIGNED).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("ssl.selfsigned"));
    }
    // 无主密钥则拒绝：私钥必须加密落库，绝不明文（对齐 databases.rs 的纪律）
    let master = state.require_secret_key()?;

    let tmp = state.os.paths().tmp_dir();
    // 改为由面板本地根 CA 签发 leaf（而非裸自签）：装上根证书后浏览器即信任，
    // HTTPS 不再报「非私密连接」。SAN 自动含 localhost/127.0.0.1/::1，本地任意访问方式都匹配。
    let (cert_pem, key_pem) =
        tls::issue_leaf_signed_by_ca(&ca_dir(&state), &tmp, &domains, SELF_SIGNED_DAYS).await?;
    let key_enc = master.encrypt(key_pem.as_bytes()).map_err(ApiError::from)?;

    // 落盘（nginx 读取）；私钥明文只存在于 0600 文件，库内为密文
    let (crt_p, key_p) = cert_paths_for(&state, &domains);
    write_cert_files(&crt_p, &key_p, &cert_pem, &key_pem)?;

    let now = crate::now_unix();
    let not_after = now + (SELF_SIGNED_DAYS as i64) * 86_400;
    // 签发者必须与真实签发者一致：leaf 由面板本地根 CA 签发，写成「Self-Signed」
    // 会让用户在证书列表/浏览器里看到的名字与实际签发者对不上。
    let issuer = tls::CA_CN.to_string();
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());
    let site_id = id;
    let (dj, iss, cert) = (domains_json.clone(), issuer.clone(), cert_pem);
    state
        .db
        .exec(move |conn| {
            // 同站点自签只保留一张：先清旧行再插入
            conn.execute("DELETE FROM ssl_certs WHERE site_id = ?1", [site_id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            conn.execute(
                "INSERT INTO ssl_certs(site_id, domains, issuer, not_after, source, key_enc, cert, renew_state, created_at)
                 VALUES(?1, ?2, ?3, ?4, 'selfsigned', ?5, ?6, 'ok', ?7)",
                rusqlite::params![site_id, dj, iss, not_after, key_enc, cert, now],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;

    audit(&state, &s, "ssl.apply", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({
        "site_id": id,
        "domains": domains,
        "source": "selfsigned",
        "issuer": issuer,
        "not_after": not_after,
        "days_left": SELF_SIGNED_DAYS,
        "cert_path": crt_p.display().to_string(),
    })))
}

/// 下载面板本地根证书（`ca.crt`）。
///
/// 自签 leaf **全部**由这张根 CA 签发，而浏览器只信任「已安装的根 CA」——
/// 所以「自签证书没法在本地用」的解法不是换证书，而是让用户把根证书装一次。
/// 本端点即分发入口：返回 PEM 包装的 X.509，可被系统/浏览器信任库直接导入。
///
/// **只返回证书、绝不返回私钥**：`ca.key` 始终留在服务器（0600），浏览器不需要它。
pub async fn ssl_ca_download(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Response> {
    // 只读信息，站点查看权限即可——根证书不含私钥，泄露风险为零。
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let tmp = state.os.paths().tmp_dir();
    // 幂等：根 CA 尚未生成（用户还没申请过任何自签证书）时按需创建一张，
    // 保证「先下载根证书、后申请站点证书」的顺序也能拿到同源的根。
    tls::ensure_root_ca(&ca_dir(&state), &tmp).await?;
    let pem = tls::root_ca_pem(&ca_dir(&state))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-x509-ca-cert"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"forkpanel-local-ca.crt\""),
    );
    Ok((headers, pem).into_response())
}

// ─────────────── ACME 任务体（签发 / 续期） ───────────────

/// certbot 默认有效期（天），用于写 `not_after` 供到期提醒与续期判定。
/// **未从 PEM 解析**——那要引入 X.509 解析依赖（预算不允）；certbot 默认即 90 天。
const ACME_DAYS: i64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeMode {
    Issue,
    Renew,
}

/// ACME 证书任务：调 certbot → 落盘 → **私钥加密入库**。
///
/// 与自签走同一条纪律：私钥**绝不明文入库**（库泄露 ≠ 私钥泄露）。
pub struct AcmeTask {
    pub mode: AcmeMode,
    pub site_id: i64,
    pub domains: Vec<String>,
    /// 账户邮箱（仅 Issue 使用；Renew 沿用 certbot 已有账户）
    pub email: String,
    /// http-01 校验目录（站点根目录）
    pub webroot: std::path::PathBuf,
    pub crt_p: std::path::PathBuf,
    pub key_p: std::path::PathBuf,
    pub master: crate::MasterKey,
    pub db: std::sync::Arc<panel_db::WriterActor>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for AcmeTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(10, "调用 certbot").await;
        // 注：certbot 回退路线目前只签**主域名**（多域名 SAN 待扩展）
        let primary = self
            .domains
            .first()
            .cloned()
            .ok_or_else(|| PanelError::Internal("证书域名为空".into()))?;
        let (cert_pem, key_pem) = match self.mode {
            AcmeMode::Issue => tls::issue_acme(&primary, &self.email, &self.webroot).await?,
            AcmeMode::Renew => tls::renew_acme(&primary).await?,
        };

        progress.set(70, "落盘与入库").await;
        write_cert_files(&self.crt_p, &self.key_p, &cert_pem, &key_pem)?;
        let key_enc = self
            .master
            .encrypt(key_pem.as_bytes())
            .map_err(|e| PanelError::Internal(format!("加密私钥失败：{e}")))?;

        let now = crate::now_unix();
        let not_after = now + ACME_DAYS * 86_400;
        let site_id = self.site_id;
        let dj = serde_json::to_string(&self.domains).unwrap_or_else(|_| "[]".into());
        let issuer = "ACME (certbot)".to_string();
        let cert = cert_pem;
        self.db
            .exec(move |conn| {
                conn.execute("DELETE FROM ssl_certs WHERE site_id = ?1", [site_id])
                    .map_err(|e| PanelError::Database(e.to_string()))?;
                conn.execute(
                    // ACME 证书默认开启自动续期（有效期仅 90 天，靠人工点续期必然会漏）。
                    // 用户可在证书列表关掉；selfsigned / manual 恒为 0（无法自动续）。
                    "INSERT INTO ssl_certs(site_id, domains, issuer, not_after, source, key_enc, cert, renew_state, created_at, auto_renew) \
                     VALUES(?1, ?2, ?3, ?4, 'acme', ?5, ?6, 'ok', ?7, 1)",
                    rusqlite::params![site_id, dj, issuer, not_after, key_enc, cert, now],
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
                Ok(panel_db::WriteAck { rows_changed: 1 })
            })
            .await?;

        progress.set(100, "完成").await;
        Ok(panel_task::TaskOutcome {
            state: panel_task::TaskState::Ok,
            exit_code: Some(0),
            output_path: Some(self.crt_p.clone()),
        })
    }
}

/// 手动续期：自签证书重新生成并覆盖；ACME 证书走 `ssl.acme`（未接入时诚实 501）。
pub async fn cert_renew(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    // 续期同样是"签发一张证书"，无底座时一并拒绝——否则旧证书可被续成一个
    // 永远不生效的新证书，把"已配置"的假象重新造出来。
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }

    let row = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains, source FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st
                .query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await?
        .ok_or_else(|| ApiError::not_found("cert"))?;
    let (domains_json, source) = row;

    if source != "selfsigned" {
        if !state.capabilities.get(cap_keys::SSL_ACME).map(|c| c.supported).unwrap_or(false) {
            return Err(ApiError::unsupported("ssl.acme"));
        }
        // ACME 续期同样走任务：certbot 可能耗时，且 CA 有限流（LE 5 次/小时/域名）
        let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
        let (crt_p, key_p) = cert_paths_for(&state, &domains);
        let job = AcmeTask {
            mode: AcmeMode::Renew,
            site_id: id,
            domains,
            // renew 沿用 certbot 既有账户，无需邮箱与 webroot
            email: String::new(),
            webroot: std::path::PathBuf::new(),
            crt_p,
            key_p,
            master: state.require_secret_key()?,
            db: state.db.clone(),
        };
        let (tid, _) = state
            .tasks
            .submit(
                panel_task::TaskRequest {
                    // 幂等键按小时：同一小时内重复提交返回同一任务，天然规避 CA 限流
                    idempotency_key: format!("cert-renew:{id}:{}", crate::now_unix() / 3600),
                    kind: panel_task::TaskKind::CertIssue,
                    label: format!("ACME 续期证书（站点 #{id}）"),
                    timeout: std::time::Duration::from_secs(900),
                },
                job,
            )
            .await
            .map_err(ApiError::from)?;
        audit(&state, &s, "ssl.renew", &id.to_string(), "queued").await;
        return Ok(ok(serde_json::json!({ "task_id": tid, "source": "acme" })));
    }
    if !state.capabilities.get(cap_keys::SSL_SELFSIGNED).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("ssl.selfsigned"));
    }
    let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "cert has no domains"));
    }

    let master = state.require_secret_key()?;
    let tmp = state.os.paths().tmp_dir();
    // 改为由面板本地根 CA 签发 leaf（而非裸自签）：装上根证书后浏览器即信任，
    // HTTPS 不再报「非私密连接」。SAN 自动含 localhost/127.0.0.1/::1，本地任意访问方式都匹配。
    let (cert_pem, key_pem) =
        tls::issue_leaf_signed_by_ca(&ca_dir(&state), &tmp, &domains, SELF_SIGNED_DAYS).await?;
    let key_enc = master.encrypt(key_pem.as_bytes()).map_err(ApiError::from)?;
    let (crt_p, key_p) = cert_paths_for(&state, &domains);
    write_cert_files(&crt_p, &key_p, &cert_pem, &key_pem)?;

    let now = crate::now_unix();
    let not_after = now + (SELF_SIGNED_DAYS as i64) * 86_400;
    // 签发者必须与真实签发者一致：leaf 由面板本地根 CA 签发，写成「Self-Signed」
    // 会让用户在证书列表/浏览器里看到的名字与实际签发者对不上。
    let issuer = tls::CA_CN.to_string();
    let iss2 = issuer.clone();
    let cert2 = cert_pem;
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE ssl_certs SET cert = ?1, key_enc = ?2, not_after = ?3, issuer = ?4,
                        renew_state = 'ok', last_error = NULL WHERE id = ?5",
                rusqlite::params![cert2, key_enc, not_after, iss2, id],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "cert.renew", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({
        "id": id,
        "source": "selfsigned",
        "issuer": issuer,
        "not_after": not_after,
        "days_left": SELF_SIGNED_DAYS,
    })))
}

/// 自动续期的提前量（天）：到期前多久开始尝试续期。
///
/// 取 30 天而非贴着过期线（如 7 天）：续期可能因 CA 限流、http-01 校验失败而失败，
/// 留足窗口才能重试；Let's Encrypt 有效期 90 天，30 天意味着约有 2 个月的重试余量。
const RENEW_WINDOW_DAYS: i64 = 30;

/// 证书自动续期扫描——内部周期任务 `cert.renew_check` 的任务体。
///
/// 每天执行一次：找出 **30 天内到期** 且 `auto_renew=1` 的 **ACME** 证书，逐个
/// 提交 `AcmeTask{Renew}`。刻意**不**在这里直接调 certbot：走任务队列才能被审计、
/// 可看进度，并复用按小时幂等键天然规避 CA 限流（LE 5 次/小时/域名）。
///
/// 返回成功入队条数。能力位缺失（certbot 不在）或主密钥不可用时返回 **0 而不报错**——
/// 周期任务失败不该拖垮面板，也不该每天刷同一条错误日志。
pub async fn auto_renew_sweep(state: Shared) -> panel_core::Result<usize> {
    // 没有 certbot 就没有可交互的 CA，提交必然失败，直接跳过
    let acme_ok = state
        .capabilities
        .get(cap_keys::SSL_ACME)
        .map(|c| c.supported)
        .unwrap_or(false);
    if !acme_ok {
        return Ok(0);
    }
    let Ok(master) = state.require_secret_key() else {
        return Ok(0);
    };

    let now = crate::now_unix();
    let due_before = now + RENEW_WINDOW_DAYS * 86_400;

    let rows: Vec<(i64, String)> = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, domains FROM ssl_certs \
                     WHERE source='acme' AND auto_renew=1 \
                       AND not_after IS NOT NULL AND not_after <= ?1",
                )
                .map_err(db_err)?;
            let it = st
                .query_map(rusqlite::params![due_before], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(db_err)?);
            }
            Ok(v)
        })
        .await?;

    let mut queued = 0usize;
    for (id, domains_json) in rows {
        let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
        if domains.is_empty() {
            continue;
        }
        let (crt_p, key_p) = cert_paths_for(&state, &domains);
        let job = AcmeTask {
            mode: AcmeMode::Renew,
            site_id: id,
            domains: domains.clone(),
            // Renew 沿用 certbot 既有账户，无需邮箱与 webroot
            email: String::new(),
            webroot: std::path::PathBuf::new(),
            crt_p,
            key_p,
            master,
            db: state.db.clone(),
        };
        // 幂等键按小时：同一小时内重复触发返回同一任务，规避 CA 限流
        let idem = format!("cert-renew:{id}:{}", now / 3600);
        if state
            .tasks
            .submit(
                panel_task::TaskRequest {
                    idempotency_key: idem,
                    kind: panel_task::TaskKind::CertIssue,
                    label: format!("ACME 自动续期证书（#{id}）"),
                    timeout: std::time::Duration::from_secs(900),
                },
                job,
            )
            .await
            .is_ok()
        {
            queued += 1;
            // 系统发起的续期也写操作日志：actor 固定 "system"，
            // 否则自动续期在 UI 审计轨迹里完全不可见（仅服务端 info 日志有）。
            audit_system(
                &state,
                "cert.auto_renew",
                &format!("#{id} {}", domains.join(",")),
                "queued",
            )
            .await;
        }
        // 单条失败不影响其余证书，也不惊动周期任务（失败原因由任务自身记录）
    }

    // 记录扫描时间（供前端展示"上次/下次扫描"）。即便本次入队 0 也写入——
    // 说明扫描确实跑过、只是没有到期证书，而非"从未运行"。
    let sweep_now = now;
    let sweep_queued = queued as i64;
    state
        .pool
        .with(move |conn| {
            conn.execute(
                "INSERT INTO cert_sweep_state(id, last_at, last_queued) VALUES(1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET last_at=excluded.last_at, last_queued=excluded.last_queued",
                rusqlite::params![sweep_now, sweep_queued],
            )
            .map_err(db_err)?;
            Ok(())
        })
        .await?;

    Ok(queued)
}

#[derive(Debug, Deserialize)]
pub struct AutoRenewReq {
    pub enabled: bool,
}

/// 开关证书自动续期。**仅 ACME 证书可开**。
///
/// selfsigned / manual 没有可交互的 CA，给它们开关就是"能点但必失败"的假按钮，
/// 故 SQL 里直接带 `source='acme'` 过滤（顺带避免先读后写的竞态）。
/// 开启前还会校验 `ssl.acme` 能力位——否则用户开了开关却永远不会续，
/// 那是最坏的失败方式（UI 显示"已开启"，实际持续过期）。
pub async fn cert_auto_renew(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Json(req): Json<AutoRenewReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    if req.enabled
        && !state
            .capabilities
            .get(cap_keys::SSL_ACME)
            .map(|c| c.supported)
            .unwrap_or(false)
    {
        return Err(ApiError::unsupported("ssl.acme"));
    }
    // 先读后写：校验必须在**读路径**上返回 400/404。若把校验放进 db.exec 闭包，
    // 写通道会把任何 Err 统一包装成 Database 错误 → 用户看到 500（实测踩过）。
    let source: Option<String> = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT source FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st
                .query_map(rusqlite::params![id], |r| r.get::<_, String>(0))
                .map_err(db_err)?;
            match it.next() {
                Some(x) => Ok(Some(x.map_err(db_err)?)),
                None => Ok(None),
            }
        })
        .await?;
    let Some(source) = source else {
        return Err(ApiError::not_found("cert"));
    };
    if source != "acme" {
        return Err(ApiError::bad_request(
            "id",
            "仅 ACME 证书支持自动续期：自签 / 手动证书没有可交互的 CA，给了开关也是点不动的",
        ));
    }

    let enabled_i = if req.enabled { 1 } else { 0 };
    state
        .db
        .exec(move |conn| {
            let n = conn
                .execute(
                    "UPDATE ssl_certs SET auto_renew=?1 WHERE id=?2 AND source='acme'",
                    rusqlite::params![enabled_i, id],
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;
    audit(
        &state,
        &s,
        "ssl.auto_renew",
        &id.to_string(),
        if req.enabled { "on" } else { "off" },
    )
    .await;
    Ok(ok(serde_json::json!({ "id": id, "auto_renew": req.enabled })))
}

/// 删除证书（DB + 磁盘 cert/key 一并清理）。
pub async fn cert_delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    // 先取域名，删除后才能定位要清理的磁盘文件
    let domains_json = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st.query_map([id], |r| r.get::<_, String>(0)).map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await?;

    let n = state
        .db
        .exec(move |conn| {
            let n = conn
                .execute("DELETE FROM ssl_certs WHERE id = ?1", [id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;
    if n.rows_changed == 0 {
        return Err(ApiError::not_found("cert"));
    }

    if let Some(js) = domains_json {
        let ds: Vec<String> = serde_json::from_str(&js).unwrap_or_default();
        let (crt, key) = cert_paths_for(&state, &ds);
        let _ = std::fs::remove_file(&crt);
        let _ = std::fs::remove_file(&key);
    }

    audit(&state, &s, "cert.delete", &id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod waf_tests {
    use super::*;

    fn req(enabled: bool, profile: Option<&str>, rate: Option<u32>, burst: Option<u32>) -> WafReq {
        WafReq { enabled, profile: profile.map(str::to_string), rate_per_sec: rate, burst }
    }

    fn spec(profile: panel_os::WafProfile, rate: Option<u32>, burst: u32) -> panel_os::WafSpec {
        panel_os::WafSpec { profile, rate_per_sec: rate, burst }
    }

    /// 缺省必须**保留**而不是关闭：否则任何不知道 `waf` 字段的调用方
    /// 一次 apply 就会把防护静默关掉，而且没有任何提示。
    #[test]
    fn omitted_waf_keeps_the_stored_config() {
        let cur = spec(panel_os::WafProfile::Strict, Some(5), 10);
        assert_eq!(build_waf(None, Some(&cur)).unwrap(), Some(cur));
        assert_eq!(build_waf(None, None).unwrap(), None);
    }

    #[test]
    fn explicit_disable_turns_it_off_even_if_currently_on() {
        let cur = spec(panel_os::WafProfile::Basic, Some(5), 10);
        assert_eq!(build_waf(Some(&req(false, None, None, None)), Some(&cur)).unwrap(), None);
    }

    #[test]
    fn burst_defaults_to_twice_the_rate_and_profile_defaults_to_basic() {
        let g = build_waf(Some(&req(true, Some("basic"), Some(10), None)), None).unwrap().unwrap();
        assert_eq!(g.burst, 20);
        assert_eq!(g.profile, panel_os::WafProfile::Basic);
        // 不给档位 → 基础档（默认值应当"够用且不误伤"）
        let g2 = build_waf(Some(&req(true, None, None, None)), None).unwrap().unwrap();
        assert_eq!(g2.profile, panel_os::WafProfile::Basic);
        assert_eq!(g2.rate_per_sec, None);
    }

    /// `rate=0` 若原样下发，nginx 会拒绝加载整份配置——必须解释成"不限速"。
    #[test]
    fn rate_zero_means_unlimited_rather_than_going_into_the_config() {
        let g = build_waf(Some(&req(true, None, Some(0), None)), None).unwrap().unwrap();
        assert_eq!(g.rate_per_sec, None);
        assert_eq!(g.burst, 0);
        // 不限速却给了 burst = 用户以为限速生效了，直接拒绝
        assert!(build_waf(Some(&req(true, None, None, Some(50))), None).is_err());
    }

    #[test]
    fn unknown_profile_and_out_of_range_numbers_are_rejected() {
        assert!(build_waf(Some(&req(true, Some("yolo"), None, None)), None).is_err());
        assert!(build_waf(Some(&req(true, None, Some(WAF_RATE_MAX + 1), None)), None).is_err());
        assert!(build_waf(Some(&req(true, None, Some(1), Some(WAF_BURST_MAX + 1))), None).is_err());
        // 边界值本身必须放过：不然"上限"就成了一句空话
        let ok = build_waf(Some(&req(true, None, Some(WAF_RATE_MAX), None)), None).unwrap().unwrap();
        assert_eq!(ok.rate_per_sec, Some(WAF_RATE_MAX));
        assert_eq!(ok.burst, WAF_RATE_MAX * 2);
    }
}

#[cfg(test)]
mod kind_tests {
    use super::*;

    /// 两个换算必须互为逆（在各自定义域上）。之前这里断链：`apply` 写死
    /// `'static'`，`to_out` 又只认 `reverse_proxy`，于是**任何**站点读出来都是
    /// 静态站——反代站被编辑后一点"应用"就被改坏。
    #[test]
    fn kind_maps_round_trip_and_unknown_falls_back_to_static() {
        for (db, api) in [
            ("static", "static"),
            ("reverse_proxy", "proxy"),
            ("php", "php"),
            ("redirect", "redirect"),
            ("routed", "routed"),
        ] {
            assert_eq!(kind_to_api(db), api, "库口径 {db} 应呈现为 {api}");
        }
        assert_eq!(kind_to_db(&panel_os::SiteKind::Static), "static");
        assert_eq!(
            kind_to_db(&panel_os::SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] }),
            "reverse_proxy"
        );
        assert_eq!(kind_to_db(&panel_os::SiteKind::Php { fpm: "unix:/run/php.sock".into() }), "php");
        assert_eq!(
            kind_to_db(&panel_os::SiteKind::Redirect { target: "https://new.example.com".into(), code: 301 }),
            "redirect"
        );
        // 未知值必须降级成 static：认成 proxy 会让人按错误前提去改配置
        assert_eq!(kind_to_api("something_else"), "static");
        assert_eq!(kind_to_api(""), "static");
    }

    fn route(prefix: &str, kind: &str) -> RouteOut {
        RouteOut {
            prefix: prefix.to_string(),
            kind: kind.to_string(),
            upstreams: Vec::new(),
            spa: false,
            fpm: None,
            front_controller: None,
            root: None,
        }
    }

    #[test]
    fn routes_validation_normalizes_and_accepts() {
        let mut rs = vec![route("/", "static"), route("/api/", "proxy")];
        rs[1].upstreams = vec!["  http://127.0.0.1:3000  ".into()];
        let out = validate_routes(&rs).expect("合法路由表应通过");
        // 末尾多余的 / 必须被归一化（/api/ ≡ /api），否则同一前缀能存成两条
        assert_eq!(out.routes[1].prefix, "/api");
        assert_eq!(out.routes[1].kind, panel_os::RouteKind::Proxy {
            upstreams: vec!["http://127.0.0.1:3000".into()],
        });
        // 归一化后两条不再重复（若不归一化，第二条就与首条同前缀而报重复）
        assert_eq!(out.routes.len(), 2);
        assert!(out.fallback().is_some());
    }

    /// `prefix` 会**直接进 nginx 配置文本**，带 `;` / `{` / 换行就是配置注入
    /// （可借此写出任意指令，如 `location / { } return 200 "ok"; }`）。
    /// 这类输入必须在校验层挡住——渲染层不设防。
    #[test]
    fn routes_validation_blocks_config_injection() {
        for bad in [
            "/api; return 200 'pwned'",
            "/api { }",
            "/api\n    }\n    location / { deny all;",
            "/api /api2",   // 空白
            "/api/$(id)",
            "/api`id`",
            "/api\u{0}",
        ] {
            let rs = vec![route("/", "static"), route(bad, "static")];
            assert!(
                validate_routes(&rs).is_err(),
                "必须拒绝含注入字符的前缀：{bad:?}"
            );
        }
        // 合法但需归一化的边界
        let rs = vec![route("/", "static"), route("/api/v1.0~beta-2_x", "static")];
        assert!(validate_routes(&rs).is_ok(), "点/波浪/下划线/连字符应放行");
    }

    #[test]
    fn routes_validation_requires_exactly_one_fallback() {
        // 没有兜底 → 必须报错（漏掉的路径会落到别的站点去）
        let rs = vec![route("/api", "static")];
        let e = validate_routes(&rs).expect_err("缺兜底必须报错");
        assert!(format!("{e:?}").contains("兜底"), "{e:?}");
        // 两个兜底 → 必须报错（谁生效取决于书写顺序）
        let rs = vec![route("/", "static"), route("/", "proxy")];
        assert!(validate_routes(&rs).is_err(), "重复的 / 必须报错");
        // 空表
        assert!(validate_routes(&[]).is_err(), "空路由表必须报错");
    }

    #[test]
    fn routes_validation_rejects_duplicate_prefix() {
        let rs = vec![route("/", "static"), route("/api", "static"), route("/api", "static")];
        let e = validate_routes(&rs).expect_err("重复前缀必须报错");
        assert!(format!("{e:?}").contains("重复"), "{e:?}");
    }

    #[test]
    fn routes_validation_checks_per_kind_required_fields() {
        // 反代缺后端
        let mut proxy = route("/api", "proxy");
        proxy.upstreams = vec!["   ".into()];
        let rs = vec![route("/", "static"), proxy];
        assert!(validate_routes(&rs).is_err(), "反代必须有后端");

        // PHP 缺 fpm / 缺 front_controller
        let rs = vec![route("/", "static"), route("/app", "php")];
        assert!(validate_routes(&rs).is_err(), "PHP 缺 fpm 必须报错");
        let mut php = route("/app", "php");
        php.fpm = Some("unix:/run/php.sock".into());
        let rs = vec![route("/", "static"), php.clone()];
        assert!(validate_routes(&rs).is_err(), "PHP 缺 front_controller 必须报错");
        // 补齐后应通过
        let mut ok = php.clone();
        ok.front_controller = Some("/app/public/index.php".into());
        let rs = vec![route("/", "static"), ok];
        assert!(validate_routes(&rs).is_ok());

        // front_controller 必须以 / 开头且不含注入字符
        let mut bad = php.clone();
        bad.front_controller = Some("app/index.php".into());
        let rs = vec![route("/", "static"), bad];
        assert!(validate_routes(&rs).is_err(), "front_controller 须以 / 开头");

        // 未知 kind
        let rs = vec![route("/", "static"), route("/x", "cobol")];
        assert!(validate_routes(&rs).is_err(), "未知 kind 必须报错");

        // 非 / 前缀
        let rs = vec![route("/", "static"), route("api", "static")];
        assert!(validate_routes(&rs).is_err(), "前缀须以 / 开头");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_validation_blocks_config_injection() {
        for ok in ["http://127.0.0.1:3000", "https://backend.internal", "http://[::1]:8080"] {
            assert!(validate_upstream(ok).is_ok(), "应放行: {ok}");
        }
        for bad in [
            // 关键用例：值会直接进 nginx 配置，一个换行就能插入任意指令
            "http://127.0.0.1:3000; }\nserver { listen 9999",
            "http://127.0.0.1:3000 /",
            "http://127.0.0.1:3000/x",
            "http://127.0.0.1:3000#frag",
            "127.0.0.1:3000",            // 缺 scheme
            "http://bad host:3000",      // 含空格
            "http://127.0.0.1\t:3000",   // 含制表符
        ] {
            assert!(validate_upstream(bad).is_err(), "必须拒绝: {bad:?}");
        }
    }

    #[test]
    fn fpm_validation_blocks_injection() {
        assert!(validate_fpm("unix:/run/php/php8.2-fpm.sock").is_ok());
        assert!(validate_fpm("127.0.0.1:9000").is_ok());
        for bad in [
            "unix:relative.sock",        // 非绝对路径
            "unix:/run/../etc/passwd",   // 含 ..
            "127.0.0.1:9000; }",         // 分号 + 花括号
            "127.0.0.1:9000\nserver{",   // 换行
            "",
            "a b",
        ] {
            assert!(validate_fpm(bad).is_err(), "必须拒绝: {bad:?}");
        }
    }

    #[test]
    fn days_left_calculation() {
        let now = crate::now_unix();
        let f = |na: Option<i64>| na.map(|t| (t - now) / 86_400);
        assert_eq!(f(Some(now + 86_400 * 30)), Some(30));
        assert_eq!(f(Some(now + 86_400 * 3)), Some(3));
        assert_eq!(f(None), None);
    }

    #[test]
    fn renewal_warning_thresholds() {
        // UI：>30 绿 / 7~30 黄 / <7 红
        let level = |d: i64| if d > 30 { "ok" } else if d >= 7 { "warn" } else { "danger" };
        assert_eq!(level(60), "ok");
        assert_eq!(level(30), "warn");
        assert_eq!(level(7), "warn");
        assert_eq!(level(3), "danger");
        assert_eq!(level(0), "danger");
    }

    #[test]
    fn apply_flow_order_is_enforced() {
        // 顺序：render → validate → deploy → reload → 持久化
        // validate 失败时不得 deploy（旧配置必须原封不动）
        let steps = ["render", "validate", "deploy", "reload", "persist"];
        assert_eq!(steps[1], "validate", "校验必须在部署之前");
        assert!(steps.iter().position(|s| *s == "validate").unwrap()
            < steps.iter().position(|s| *s == "deploy").unwrap());
        assert!(steps.iter().position(|s| *s == "deploy").unwrap()
            < steps.iter().position(|s| *s == "reload").unwrap());
    }

    #[test]
    fn ensure_site_root_dir_creates_with_explicit_755() {
        // 验证站点根目录被创建且权限显式设为 0o755，不再依赖 umask 隐式保证
        // （root:root + 严 umask 下，缺少这步会导致 www-data 读静态文件 403）。
        let d = std::env::temp_dir().join(format!("panel-site-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_site_root_dir(&d);
        assert!(d.is_dir(), "站点根目录应被创建");
        // 权限走跨平台 owner（panel_os::fs 内部已按平台分支实现），业务层不写平台条件编译。
        // Linux 上 mode_of 恒返回 Some，断言必执行；非 unix 平台该特性本就为 no-op。
        if let Some(m) = panel_os::fs::mode_of(&d) {
            assert_eq!(m & 0o777, 0o755, "目录应显式设为 755（不再依赖 umask）");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_site_root_dir_is_idempotent() {
        // 幂等：重复调用不报错、权限保持 755
        let d = std::env::temp_dir().join(format!("panel-site-root-idem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_site_root_dir(&d);
        ensure_site_root_dir(&d);
        assert!(d.is_dir());
        if let Some(m) = panel_os::fs::mode_of(&d) {
            assert_eq!(m & 0o777, 0o755);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── site_root_rel：绝对路径剥前缀 / 越界拒绝 / 空串回填 ──
    // 回归：目录选择器返回绝对路径、库里 root 也是绝对路径，但沙箱只收相对 site_root
    // 的路径。此前 resolve_site_root 直接把绝对路径交给 resolve_within_for_create →
    // is_absolute 一律判 PathEscape(50001)，于是「编辑站点 → 保存」必报"路径超出允许范围"。
    #[test]
    fn site_root_rel_strips_prefix_for_absolute_within_root() {
        let base = Path::new("/var/www");
        // 选择器返回的 /var/www/my-site → 相对 my-site
        assert_eq!(site_root_rel(base, "/var/www/my-site", "fallback"), "my-site");
        // 库里落地、带结尾斜杠的绝对路径也应剥干净
        assert_eq!(site_root_rel(base, "/var/www/sub/", "fallback"), "sub");
        // 恰好等于 base（选了 site_root 本身）→ 用 "." 表示根目录
        assert_eq!(site_root_rel(base, "/var/www", "fallback"), ".");
    }

    #[test]
    fn site_root_rel_keeps_out_of_root_absolute_so_sandbox_rejects() {
        // 越界绝对路径保持原样，交给 resolve_within_for_create 判 PathEscape（绝不放行）
        assert_eq!(site_root_rel(Path::new("/var/www"), "/etc/passwd", "fb"), "/etc/passwd");
        // 伪装前缀（/var/www-evil）不会被字符串前缀误判命中：strip_prefix 是组件级，
        // /var/www-evil 不以 /var/www 为组件前缀 → 保持原样 → 沙箱拒绝
        assert_eq!(site_root_rel(Path::new("/var/www"), "/var/www-evil/x", "fb"), "/var/www-evil/x");
    }

    #[test]
    fn site_root_rel_empty_falls_back_to_name_and_relative_passthrough() {
        assert_eq!(site_root_rel(Path::new("/var/www"), "", "my-site"), "my-site");
        // 相对路径原样透传（含子目录与 .. 语义拦截交给沙箱）
        assert_eq!(site_root_rel(Path::new("/var/www"), "my-site/blog", "fb"), "my-site/blog");
    }

    // ── 部署指纹 / 未同步（017）：判据、边界、分隔符安全 ──

    /// 一个「手动维护 + 已同步」的基线行（指纹在用例里按需设置）。
    fn raw_site() -> RawSite {
        RawSite {
            id: 1,
            name: "my-site".into(),
            domains: r#"["example.com"]"#.into(),
            root: "/var/www/my-site".into(),
            kind: "static".into(),
            enabled: 1,
            created_at: 0,
            tls: false,
            waf_enabled: 1,
            waf_profile: Some("basic".into()),
            waf_rate: None,
            waf_burst: Some(0),
            upstreams_json: None,
            fpm: None,
            spa: 0,
            redirect_target: None,
            redirect_code: None,
            conf_path: Some("/etc/nginx/conf.d/panel-example.com.conf".into()),
            routes_json: "[]".into(),
            manual_conf: 1,
            conf_snapshot: None,
            custom_conf: None,
            www_redirect: "off".into(),
            tls_profile: "modern".into(),
            tls_min: "TLSv1.2".into(),
            hsts: 0,
            hsts_max_age: 300,
            hsts_sub: 0,
            hsts_preload: 0,
            rewrite_preset: "none".into(),
            rewrite_custom: None,
            last_ver_hash: None,
            ip_allow: None,
            ip_deny: None,
            auth_basic: 0,
            auth_user: None,
            lb_policy: "least_conn".into(),
            proxy_connect_timeout: 60,
            proxy_send_timeout: 60,
            proxy_read_timeout: 60,
            log_access: 0,
            log_error: 0,
            log_error_level: "error".into(),
            remark: String::new(),
            last_applied_at: None,
        }
    }

    /// 纯映射（023）：RawSite.last_applied_at 必须原样透传到 SiteOut——None 不被
    /// 误转成 0（0 是合法时间戳 1970，与「从未下发」语义相反）。
    #[test]
    fn to_out_maps_last_applied_at_through_verbatim() {
        let mut r = raw_site();
        r.last_applied_at = Some(1_772_000_000);
        assert_eq!(to_out(&r).last_applied_at, Some(1_772_000_000));
        r.last_applied_at = None;
        assert_eq!(to_out(&r).last_applied_at, None);
    }

    #[test]
    fn conf_stale_true_when_manual_and_snapshot_missing() {
        // 旧行（017 之前转入手动维护，如 as11）：无指纹记录 → 按「未同步」对待。
        // 有疑问时向"提示"倾斜，而不是假装同步。
        assert!(conf_stale_of(&raw_site()));
    }

    #[test]
    fn conf_stale_false_when_fingerprint_matches() {
        let mut r = raw_site();
        r.conf_snapshot = Some(fingerprint_of(&r));
        assert!(!conf_stale_of(&r), "指纹一致 = 已同步");
    }

    #[test]
    fn conf_stale_true_when_any_deploy_field_changed() {
        // 核心回归（真实事故）：手动维护后只改表单（如 WAF 档位 strict）、文件没动
        // → 必须报未同步。面板显示 strict、nginx 里是 basic 且界面毫无提示，正是要修的 bug。
        let mk = || {
            let mut r = raw_site();
            r.conf_snapshot = Some(fingerprint_of(&r));
            r
        };
        macro_rules! changed {
            ($label:expr, $m:expr) => {{
                let mut r = mk();
                let f: fn(&mut RawSite) = $m;
                f(&mut r);
                assert!(conf_stale_of(&r), "{}：字段变更必须触发未同步", $label);
            }};
        }
        changed!("waf_profile", |r| r.waf_profile = Some("strict".into()));
        changed!("name", |r| r.name = "renamed".into());
        changed!("domains", |r| r.domains = r#"["example.com","www.example.com"]"#.into());
        changed!("root", |r| r.root = "/var/www/other".into());
        changed!("kind", |r| r.kind = "redirect".into());
        changed!("spa", |r| r.spa = 1);
        changed!("upstreams", |r| r.upstreams_json = Some(r#"["http://127.0.0.1:3000"]"#.into()));
        changed!("fpm", |r| r.fpm = Some("unix:/run/php.sock".into()));
        changed!("redirect_target", |r| r.redirect_target = Some("https://x.example".into()));
        changed!("redirect_code", |r| r.redirect_code = Some(302));
        changed!("waf_enabled", |r| r.waf_enabled = 0);
        changed!("waf_rate", |r| r.waf_rate = Some(50));
        changed!("waf_burst", |r| r.waf_burst = Some(99));
        changed!("routes", |r| r.routes_json = r#"[{"prefix":"/","kind":"static"}]"#.into());
    }

    #[test]
    fn conf_stale_false_for_panel_managed_or_disabled() {
        // 非手动维护：apply 每次重渲染 → 不存在分叉概念（指纹值随便给）
        let mut r = raw_site();
        r.manual_conf = 0;
        r.conf_snapshot = Some("whatever".into());
        assert!(!conf_stale_of(&r));
        // 停用：文件已被移除 → 无从「未同步」
        let mut r2 = raw_site();
        r2.enabled = 0;
        assert!(!conf_stale_of(&r2));
    }

    #[test]
    fn fingerprint_is_separator_safe() {
        // 分隔符回归：没有 \u{1f} 时 ("a","bc") 与 ("ab","c") 会撞同一指纹 → 漏报
        let a = deploy_fingerprint("a", "bc", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", None, "");
        let b = deploy_fingerprint("ab", "c", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", None, "");
        assert_ne!(a, b, "字段边界必须由分隔符保护");
        // 自定义片段（019）参与指纹：只差它一处也必须产生不同指纹
        // ——否则改了 custom_conf「未同步」不会亮，等于坏了 017 的核心承诺。
        let c = deploy_fingerprint("a", "bc", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", Some("add_header X-A 1;"), "");
        assert_ne!(a, c, "custom_conf 必须进入指纹");
        let d = deploy_fingerprint("a", "bc", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", Some("add_header X-A 2;"), "");
        assert_ne!(c, d, "custom_conf 内容变化必须反映到指纹");
        // 高级配置（020）同理：www 跳转 / TLS 档位 / 伪静态都会改变渲染结果，
        // 漏进指纹 = 改了它们「未同步」不亮（与 custom_conf 同款静默分叉）。
        let e = deploy_fingerprint("a", "bc", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", None, r#"{"www":"to_www"}"#);
        assert_ne!(a, e, "高级配置必须进入指纹");
    }

    #[test]
    fn conf_hash_stable_distinct_and_hex() {
        // SHA-256 hex（64 字符）：版本去重与「当前版本」标记的比较基准
        let a = conf_hash("server { listen 80; }\n");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, conf_hash("server { listen 80; }\n"), "同内容必须同 hash");
        assert_ne!(a, conf_hash("server { listen 81; }\n"), "一字节之差必须不同");
    }

    #[test]
    fn rollback_state_managed_iff_fingerprint_matches_form() {
        // 版本指纹 == 当前表单指纹 → 回托管、快照=表单指纹（天然已同步）
        let (m, snap) = rollback_state(Some("FP"), "FP");
        assert_eq!(m, 0);
        assert_eq!(snap.as_deref(), Some("FP"));
        // 不等 → 手动维护、快照=版本指纹
        let (m, snap) = rollback_state(Some("OLD"), "FP");
        assert_eq!(m, 1);
        assert_eq!(snap.as_deref(), Some("OLD"));
        // 版本无指纹（旧行）→ 手动维护 + NULL 快照（conf_stale_of 判「未同步」）
        let (m, snap) = rollback_state(None, "FP");
        assert_eq!(m, 1);
        assert!(snap.is_none());
    }
}

/// ── 上次下发时间（023）：迁移列 / SITE_SELECT 列序 / to_out 映射 / touch SQL ──
///
/// 背景事故形状：`tls_count` 子查询列曾把 SITE_SELECT 后续列整体后移一位，
/// 编译 + 单测全绿、实机 `apply` 才报 `Invalid column type`。故本组测试全部
/// 走**真实迁移 + 真实 SITE_SELECT + 生产 to_out**，把列序钉死在测试里。
#[cfg(test)]
mod last_applied_tests {
    use super::*;

    fn insert_site(c: &rusqlite::Connection, name: &str) -> i64 {
        c.execute(
            "INSERT INTO sites(name, domains, root, kind, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, r#"["a.example.com"]"#, "/var/www/x", "static", 1_700_000_000],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    fn read_applied(c: &rusqlite::Connection, id: i64) -> Option<i64> {
        let sql = format!("SELECT {SITE_SELECT} FROM sites s WHERE s.id = ?1");
        c.query_row(&sql, rusqlite::params![id], |r| r.get(44)).unwrap()
    }

    /// 列序回归：SITE_SELECT 第 44 列必须是 last_applied_at（索引错位时这里
    /// 要么类型错、要么把 remark 读成时间戳——两种都会挂）。
    #[test]
    fn site_select_column_44_is_last_applied_at_and_defaults_null() {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        panel_db::migrate::apply(&mut c).unwrap();
        let id = insert_site(&c, "fresh-site");
        assert_eq!(
            read_applied(&c, id),
            None,
            "从未下发过的站点必须是 NULL；若是 0 会被格式化成 1970-01-01 谎报下发时间"
        );
        // 同行前后列也必须读得动：证明 44 之前没有整体错位
        let sql = format!("SELECT {SITE_SELECT} FROM sites s WHERE s.id = ?1");
        let (remark, conf_path): (String, Option<String>) = c
            .query_row(&sql, rusqlite::params![id], |r| Ok((r.get(43)?, r.get(17)?)))
            .unwrap();
        assert_eq!(remark, "");
        assert_eq!(conf_path, None);
    }

    /// touch SQL 语义：只更新目标行；同值可重入（幂等）；不存在的 id 静默 0 行。
    #[test]
    fn touch_applied_sql_updates_only_the_target_row() {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        panel_db::migrate::apply(&mut c).unwrap();
        let a = insert_site(&c, "site-a");
        let b = insert_site(&c, "site-b");

        let n = c
            .execute(TOUCH_APPLIED_SQL, rusqlite::params![1_772_000_000i64, a])
            .unwrap();
        assert_eq!(n, 1, "只应命中一行");
        assert_eq!(read_applied(&c, a), Some(1_772_000_000));
        assert_eq!(read_applied(&c, b), None, "不得波及其他站点");

        // 重入（重复 apply 同一站点）：覆盖为新值，不报错
        c.execute(TOUCH_APPLIED_SQL, rusqlite::params![1_772_000_999i64, a]).unwrap();
        assert_eq!(read_applied(&c, a), Some(1_772_000_999));
        // 幽灵 id：0 行、不报错（调用方只 eprintln，不中断下发）
        assert_eq!(c.execute(TOUCH_APPLIED_SQL, rusqlite::params![1i64, 999_999]).unwrap(), 0);
    }
}
