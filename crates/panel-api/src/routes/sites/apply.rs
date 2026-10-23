use super::*;
use crate::extract::PanelJson;


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
pub(crate) const WAF_RATE_MAX: u32 = 1000;
pub(crate) const WAF_BURST_MAX: u32 = 10_000;

/// 归一化 + 校验 WAF 配置。
///
/// 规则集本身是**编译期常量**，用户只能选档位与数值——所以这里没有"正则注入"面。
/// 但数值边界仍必须挡：`rate=0` 会让 nginx 直接拒绝加载配置。
pub(crate) fn build_waf(
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
pub(super) fn validate_upstream(u: &str) -> ApiResult<String> {
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
pub(super) fn validate_fpm(v: &str) -> ApiResult<String> {
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
pub(super) fn validate_site_name(raw: &str) -> ApiResult<String> {
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
    PanelJson(req): PanelJson<ApplyReq>,
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
            if !(0..=63_072_000).contains(&n) {
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
            panel_os::SiteKind::Redirect { target, code }
        }
        "routed" => {
            let rs = req.routes.clone().ok_or_else(|| {
                ApiError::bad_request("routes", "多路由站点必须提供路由表（routes）")
            })?;
            let mut routes = validate_routes(&rs)?;
            // 路由级 root 约束到 site_root 之内（防路径穿越）：与站点级 root 复用同一条
            // resolve_site_root。空 root 不变（继承 server 级站点 root）。
            for r in routes.routes.iter_mut() {
                // 模式合并（**不是** let-chain：后者要 1.88+，本项目 MSRV 1.80 用不了）；
                // 语义与原来两层 if 完全一致：root 为 None 时同样不进入分支。
                if let panel_os::RouteKind::Static { spa: _, root: Some(rv) } = &mut r.kind {
                    let safe = resolve_site_root(&state, rv, &req.name)?;
                    *rv = safe.as_path().display().to_string();
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
        server_names: domains.to_vec(),
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


