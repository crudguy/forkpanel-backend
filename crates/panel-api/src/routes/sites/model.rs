use super::*;


/// `sites` 表的原始行（含从 `ssl_certs` 派生的 tls 标记）。
pub(super) struct RawSite {
    pub(super) id: i64,
    pub(super) name: String,
    /// JSON 数组字符串
    pub(super) domains: String,
    pub(super) root: String,
    pub(super) kind: String,
    pub(super) enabled: i32,
    pub(super) created_at: i64,
    pub(super) tls: bool,
    pub(super) waf_enabled: i32,
    pub(super) waf_profile: Option<String>,
    pub(super) waf_rate: Option<i64>,
    pub(super) waf_burst: Option<i64>,
    /// JSON 数组：反代后端列表（static 站点为 NULL）
    pub(super) upstreams_json: Option<String>,
    /// php-fpm 目标（unix:/path.sock | host:port）；非 php 站点为 NULL
    pub(super) fpm: Option<String>,
    /// SPA 回退标志（kind=static 时有效）：1 = 开启
    pub(super) spa: i32,
    /// 整站重定向目标 URL（kind=redirect 时存在）；其余为 NULL
    pub(super) redirect_target: Option<String>,
    /// 整站重定向状态码 301/302/307/308（kind=redirect 时存在）；其余为 NULL
    pub(super) redirect_code: Option<i64>,
    /// apply 写入的 nginx 配置路径；**从未成功下发则为 NULL / 空串**。
    /// 这是「配置是否真落到 Web 服务器」的唯一判据——`enabled` 只表示期望状态。
    pub(super) conf_path: Option<String>,
    /// 多路由表 JSON 数组；非多路由站点为 `'[]'`（迁移给了 DEFAULT，不会有 NULL）
    pub(super) routes_json: String,
    /// 手动维护标记（016 迁移）：1 = 磁盘配置由用户原始编辑维护，表单保存不覆盖
    pub(super) manual_conf: i32,
    /// 部署指纹（017 迁移）：「配置文件最后一次落盘时表单部署相关字段的指纹」。
    /// 与当前表单指纹（`fingerprint_of`）不等 ⇒ 手动维护期间两边已分叉（conf_stale）。
    /// NULL = 无记录（旧行）——对手动维护站点按「未同步」对待。
    pub(super) conf_snapshot: Option<String>,
    /// 自定义配置片段（019 迁移）：渲染时插在主 server 块尾部（托管态随表单
    /// 重渲染；纳入部署指纹——改动会自动触发未同步检测）。NULL / 空串 = 无。
    pub(super) custom_conf: Option<String>,
    /// www ↔ 非 www 跳转（020）：off | to_www | to_bare
    pub(super) www_redirect: String,
    /// 加密套件档位（020）：compat | modern | strict
    pub(super) tls_profile: String,
    /// TLS 版本下限（020）：TLSv1 | TLSv1.1 | TLSv1.2 | TLSv1.3
    pub(super) tls_min: String,
    pub(super) hsts: i32,
    pub(super) hsts_max_age: i64,
    pub(super) hsts_sub: i32,
    pub(super) hsts_preload: i32,
    /// 伪静态模板（020）：none | wordpress | laravel | thinkphp | typecho | discuz | custom
    pub(super) rewrite_preset: String,
    pub(super) rewrite_custom: Option<String>,
    /// **派生列**（非 sites 表的列）：最新留档版本的内容 hash，用于「外部修改检测」。
    /// NULL = 该站尚无留档，此时无从判定，一律按「无外部修改」处理（不谎报）。
    pub(super) last_ver_hash: Option<String>,
    /// IP 白名单（021，逗号分隔）；NULL/空 = 不限制
    pub(super) ip_allow: Option<String>,
    /// IP 黑名单（021，逗号分隔）；ip_allow 非空时被忽略
    pub(super) ip_deny: Option<String>,
    pub(super) auth_basic: i32,
    /// Basic Auth 用户名（口令不落库）
    pub(super) auth_user: Option<String>,
    /// 负载均衡策略（021）：round_robin | least_conn | ip_hash
    pub(super) lb_policy: String,
    pub(super) proxy_connect_timeout: i64,
    pub(super) proxy_send_timeout: i64,
    pub(super) proxy_read_timeout: i64,
    /// 站点独立访问日志（021）：1 = 渲染 access_log 指令
    pub(super) log_access: i32,
    pub(super) log_error: i32,
    /// 错误日志级别（021）
    pub(super) log_error_level: String,
    /// 对象说明（备注，022）：这台站点干嘛的、为什么这么配——手写意图，非系统日志
    pub(super) remark: String,
    /// 上次成功下发（deploy + reload）的 unix 秒（023）；NULL = 从未下发。
    /// 停用（撤下配置）不更新——「撤下」不是「下发」。
    pub(super) last_applied_at: Option<i64>,
}

impl RawSite {
    /// 库中现存的 WAF 配置（`waf_enabled=0` → `None`）。
    pub(super) fn waf(&self) -> Option<panel_os::WafSpec> {
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
pub(super) fn kind_to_db(k: &panel_os::SiteKind) -> &'static str {
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
pub(super) fn kind_to_api(k: &str) -> &'static str {
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
pub(super) fn routes_from_json(raw: &str) -> Vec<RouteOut> {
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
pub(super) fn validate_routes(routes: &[RouteOut]) -> ApiResult<panel_os::SiteRoutes> {
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
pub(super) fn deploy_fingerprint(
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
pub(super) fn nonempty(v: Vec<String>) -> Option<Vec<String>> {
    if v.is_empty() { None } else { Some(v) }
}

/// 逗号 / 空白分隔的列表字符串 → Vec（空 → 空数组：前端不必判断 null）。
pub(super) fn split_list(v: &Option<String>) -> Vec<String> {
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
pub(crate) fn site_log_dir(state: &Shared) -> std::path::PathBuf {
    state.os.paths().data_dir().join("log")
}

/// 该站点的 access / error 日志路径；未开启对应开关则为 None（沿用 nginx 全局日志）。
pub(crate) fn site_log_paths(
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
pub(super) fn timeout_db(
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
pub(crate) fn parse_ip_list(raw: &str) -> std::result::Result<Vec<String>, ApiError> {
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
pub(super) fn is_ipv4_or_cidr(s: &str) -> bool {
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
pub(super) fn htpasswd_path(state: &Shared, domains: &[String]) -> std::path::PathBuf {
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
pub(super) fn advanced_json_of(r: &RawSite) -> String {
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
pub(super) fn fingerprint_of(r: &RawSite) -> String {
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
pub(super) fn conf_stale_of(r: &RawSite) -> bool {
    r.enabled != 0
        && r.manual_conf != 0
        && r.conf_snapshot.as_deref() != Some(fingerprint_of(r).as_str())
}

pub(super) fn to_out(r: &RawSite) -> SiteOut {
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

pub(super) fn db_err(e: rusqlite::Error) -> PanelError {
    PanelError::Database(e.to_string())
}

/// SELECT 公共投影（含派生的 tls 计数）
pub(super) const SITE_SELECT: &str = "s.id, s.name, s.domains, s.root, s.kind, s.enabled, s.created_at,
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
pub(super) fn site_sql(suffix: &str) -> String {
    format!("SELECT {SITE_SELECT} FROM sites s {suffix}")
}

pub(super) async fn fetch_all(state: &Shared) -> Result<Vec<RawSite>> {
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

pub(super) async fn fetch_one(state: &Shared, id: i64) -> Result<Option<RawSite>> {
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

pub(super) async fn fetch_one_by_name(state: &Shared, name: &str) -> Result<Option<RawSite>> {
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
pub(super) fn site_root_rel(base: &Path, input: &str, name: &str) -> String {
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

pub(super) fn resolve_site_root(state: &Shared, input: &str, name: &str) -> Result<SafePath> {
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
pub(super) fn ensure_site_root_dir(dir: &Path) {
    if panel_os::fs::ensure_dir(dir, 0o755).is_err() {
        // 仅记录，不中断主流程
        eprintln!("[sites] 确保站点根目录权限失败: {}", dir.display());
    }
}


