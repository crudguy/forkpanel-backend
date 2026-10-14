use super::*;


/// nginx 站点配置的渲染与下发。
///
/// 落盘约定：`LinuxPathLayout::web_conf_dir()` 即 nginx 的 `conf.d` 目录
/// （Debian 默认在 `nginx.conf` 里 `include /etc/nginx/conf.d/*.conf;`），
/// 每个站点写一个 `panel-<host>.conf`，**文件名由首个 server_name 派生**。
///
/// 闭环语义（与 `sites.rs` 一致）：
/// `render`（纯字符串）→ `validate`（写临时 wrapper 跑 `nginx -t`，**任何写入前**）
/// → `deploy`（同目录临时文件 + rename 原子替换）→ `reload`（`nginx -s reload`）。
///
/// **诚实边界**：若本机无 nginx（`name()=="none"`）或后端为 caddy（尚未实装），
/// 四个方法一律 `Unsupported`，能力位随之置 `no`，UI 自动置灰。
pub struct LinuxWebServer {
    pub(super) name: Option<&'static str>,
    pub(super) paths: Arc<LinuxPathLayout>,
}

impl LinuxWebServer {
    pub fn detect(paths: Arc<LinuxPathLayout>) -> Self {
        let name = if which("nginx") { Some("nginx") } else if which("caddy") { Some("caddy") } else { None };
        Self { name, paths }
    }

    /// 站点配置文件路径：`<web_conf_dir>/panel-<slug>.conf`
    /// （`pub` 是为了让 `WebServerProvider::conf_path` 对外暴露同一份计算——
    ///  trait 里同名方法委托到它，调用方经 `dyn` 也能拿到与 render 同源的路径）
    pub fn conf_path(&self, server_names: &[String]) -> PathBuf {
        let stem = server_names.first().map(|s| slug(s)).unwrap_or_else(|| "site".into());
        self.paths.web_conf_dir().join(format!("panel-{stem}.conf"))
    }
}

/// 进程内单调计数，拼接 tmp 文件名（避免并发 apply 撞名）
pub(super) fn uniq_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    C.fetch_add(1, Ordering::Relaxed)
}

/// 校验用的 wrapper 主配置：把站点片段包成一份合法主配置。
///
/// 抽成独立函数是为了让测试用**同一份** wrapper 去跑真实 nginx——测试里另抄一份
/// 必然漂移，而漂移的那份会把"真实校验"变成在验一个不存在的东西。
///
/// 三个细节各有原因：
/// - `error_log stderr`：不落日志文件，不污染宿主；
/// - **所有路径（pid、五个 temp 目录）都落到临时 prefix 内**：`nginx -t` 期间会
///   打开 pid 文件、还会 mkdir 这些 temp 目录。用编译期默认值（Debian 是
///   `/run/nginx.pid` 与 `/var/lib/nginx/*`）会让校验**依赖宿主状态**——目录缺失
///   或权限不足就直接失败，而这跟"配置本身对不对"毫无关系。语法校验就只该校验语法。
///   实测：只改 pid 不改 temp 路径，会挂在 `mkdir() "/var/lib/nginx/body" failed`。
/// - `include <frag>` 落在 `http` 块内：片段里的 `upstream` / `map` /
///   `limit_req_zone` 都只在 http 上下文合法，否则会得到一堆假阳性。
pub(super) fn validate_wrapper(base: &std::path::Path, frag: &std::path::Path) -> String {
    // 直接挂在 base 下而不是 base/tmp：nginx 建临时目录用的是单层 `mkdir()`，
    // 父目录必须已存在——多套一层就得自己先建，不如少一层。
    let tmp = base;
    let mut s = String::new();
    s.push_str("error_log stderr;\n");
    s.push_str(&format!("pid {};\n", base.join("nginx.pid").display()));
    s.push_str("events {}\nhttp {\n");
    // `access_log off` 必须显式写，且只能写在 http / server / location 级
    // （main 上下文会报 "directive is not allowed here"）。不写就会落到编译期的
    // 默认 access_log（Debian 是 /var/log/nginx/access.log），于是校验变成在测
    // "宿主能不能写那个日志文件"，而不是在测配置语法。
    s.push_str("    access_log off;\n");
    for (directive, name) in [
        ("client_body_temp_path", "body"),
        ("proxy_temp_path", "proxy"),
        ("fastcgi_temp_path", "fastcgi"),
        ("uwsgi_temp_path", "uwsgi"),
        ("scgi_temp_path", "scgi"),
    ] {
        s.push_str(&format!("    {directive} {}/{name};\n", tmp.display()));
    }
    s.push_str(&format!("    include {};\n}}\n", frag.display()));
    s
}

/// 抽出片段里需要**搬运**的相对 `include` 名（去重、保序）。
///
/// 只认整行的 `include <名>;`，跳过注释行、绝对路径与通配（前者 nginx 自己能读，
/// 后者需要真实目录，搬不了）。名字限制在 `[A-Za-z0-9_./-]` 且不含 `..`——
/// 这里读的是宿主文件，任何"聪明"的解析都只是扩大攻击面。
pub(super) fn relative_includes(rendered: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in rendered.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some(rest) = t.strip_prefix("include") else { continue };
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue; // 形如 `include_foo` 的无关指令
        }
        let Some(name) = rest.trim().strip_suffix(';') else { continue };
        let name = name.trim();
        if name.is_empty() || name.starts_with('/') || name.contains("*") || name.contains("..") {
            continue;
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/'))
        {
            continue;
        }
        if !out.iter().any(|x| x == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// 校验时相对 `include` 的**源目录**：nginx 主配置所在目录（`conf.d` 的上一级）。
///
/// 这是个假设——假定部署目录的父目录就是主配置目录（Debian / Arch / RHEL 均如此）。
/// 假设不成立时 [`stage_relative_includes`] 会如实报"读取失败"，而不是静默放行。
pub(super) fn nginx_conf_source_dir(web_conf_dir: &std::path::Path) -> std::path::PathBuf {
    web_conf_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/nginx"))
}

/// 把片段里**相对** `include` 的文件，从 nginx 主配置目录搬进校验用的临时 `conf/`。
///
/// 为什么必须搬：`include foo;` 的相对名在 nginx 中相对 **conf_prefix** 解析。
/// 生产时 conf_prefix 是主配置目录（Debian 是 `/etc/nginx`），而校验时因为用了
/// `-c <base>/conf/nginx.conf`，conf_prefix 变成临时目录——相对 include 一律找不到。
/// 不搬的话 PHP 站点的校验会报 `open() .../conf/fastcgi_params failed`：一个与真实
/// 配置毫无关系的**假失败**。（P2-8 起 validate 一直是坏的，所以这个坑没人踩到。）
///
/// 源文件缺失时**如实报错**：那份配置在真实 nginx 上会因为同样的原因加载失败，
/// 不是可以宽容的情况。
pub(super) async fn stage_relative_includes(
    rendered: &str,
    src_conf_dir: &std::path::Path,
    dest_conf_dir: &std::path::Path,
) -> Result<()> {
    for name in relative_includes(rendered) {
        let src = src_conf_dir.join(&name);
        let dst = dest_conf_dir.join(&name);
        let bytes = tokio::fs::read(&src).await.map_err(|e| PanelError::ConfigInvalid {
            detail: format!(
                "片段 include 了 `{name}`，但读取 {} 失败（{e}）——真实 nginx 会因同样的原因加载失败",
                src.display()
            ),
        })?;
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| PanelError::Internal(e.to_string()))?;
        }
        tokio::fs::write(&dst, bytes)
            .await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
    }
    Ok(())
}

/// `nginx -t` 的 argv（不含二进制）。抽出来同样是为了让测试与生产走同一份参数。
///
/// **必须同时给 `-p` 与 `-c`**：`-p` 只改 prefix，只有当二进制编译期的
/// `--conf-path` 是**相对路径**时，nginx 才会去读 `<prefix>/conf/nginx.conf`。
/// Debian / Ubuntu 的包把 conf-path 编成了绝对路径（`/etc/nginx/nginx.conf`），
/// 此时 `-p` 完全不生效——校验会变成替"系统的 nginx 配置"背书，而生成的片段
/// 一个字都没验过。本函数此前只给 `-p`，在 Debian 上就是这样**静默失灵**的：
/// 系统里没有 /etc/nginx/nginx.conf 时它报"文件不存在"，装了 nginx 之后它又
/// 恒为通过，两种表现都不指向真正的问题。
pub(super) fn nginx_test_argv(base: &std::path::Path) -> Vec<String> {
    vec![
        "-t".into(),
        "-p".into(),
        base.display().to_string(),
        "-c".into(), // ci-allow-layering[2]: nginx 的"配置文件"参数，与 shell 无关（非 shell 解释）
        base.join("conf/nginx.conf").display().to_string(),
    ]
}

/// 渲染 nginx `server{}` 块（纯函数，可黄金单测）。
/// www ↔ 非 www 的跳转对 `(来源域名, 目标域名)`；无需跳转（off / 条件不满足）为 None。
///
/// 只对**主域名**生效：`api.example.com` 被 to_www 改写成 `www.api.example.com`
/// 几乎不会是用户想要的，宁可少做。
pub(super) fn www_pair(names: &[String], mode: Option<&str>) -> Option<(String, String)> {
    let primary = names.first()?.trim();
    if primary.is_empty() { return None }
    let base = primary.strip_prefix("www.").unwrap_or(primary).to_string();
    match mode.unwrap_or("off") {
        // www → 裸域：域名表里得真有 `www.<base>` 才成立（否则无从可跳）
        "to_bare" => {
            let from = format!("www.{base}");
            if from == base || !names.iter().any(|n| n == &from) { return None }
            Some((from, base))
        }
        // 裸域 → www：主域名本身已带 www 前缀则无事可做
        "to_www" => {
            if primary.starts_with("www.") { return None }
            Some((base.clone(), format!("www.{base}")))
        }
        _ => None,
    }
}

/// TLS 版本下限 → nginx `ssl_protocols`（下限及以上）。未知/缺失按 `TLSv1.2`，
/// 与 020 迁移的默认值同口径。
pub(super) fn tls_protocols(min: Option<&str>) -> &'static str {
    match min.unwrap_or("TLSv1.2") {
        "TLSv1" => "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
        "TLSv1.1" => "TLSv1.1 TLSv1.2 TLSv1.3",
        "TLSv1.3" => "TLSv1.3",
        _ => "TLSv1.2 TLSv1.3",
    }
}

/// 加密套件档位 → nginx `ssl_ciphers`。三档预设——**不开放自由输入**：抄错
/// 要么让老客户端直接连不上、要么安全性不升反降，代价远大于收益。未知值按 modern。
pub(super) fn tls_ciphers(profile: Option<&str>) -> &'static str {
    match profile.unwrap_or("modern") {
        "compat" => "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:HIGH:!aNULL:!MD5",
        // 严格：只留 ECDHE + AES-GCM / CHACHA20（前向保密、无弱套件）。
        // ⚠ **不能**把 TLSv1.3 的套件名（TLS_AES_128_GCM_SHA256 等）填进 ssl_ciphers：
        // 那条指令只认 TLSv1.2 及以下的 OpenSSL 套件名，填了会让 nginx 以
        // `no cipher match` 直接 emerg 拒绝**整份**配置（实机验证踩到——单测只能
        // 比对字符串，看不出 nginx 是否接受）。「仅 TLSv1.3」由 `ssl_protocols
        // TLSv1.3` 表达，TLSv1.3 的套件由 nginx 自行协商，不需要（也不能）列举。
        "strict" => "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        _ => "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:HIGH:!aNULL:!MD5",
    }
}

/// 伪静态预置模板 → `location /` 内的 try_files 行（编译期常量）。
///
/// 这些框架的「正确 rewrite」长得几乎一样却极易写错（`$args` 与 `$query_string`
/// 之别、是否带 PATH_INFO），手写是新手最大的坑，故做成预置。`custom` 由调用方
/// 原样输出用户文本；返回 None = 不做伪静态（默认 `=404` 兜底）。
pub(super) fn php_try_files(preset: Option<&str>) -> Option<&'static str> {
    match preset.unwrap_or("none") {
        // ⚠ 常量**不带**结尾分号：由调用方统一拼（`;` 重复会让 nginx 直接 emerg
        // `unexpected ";"` ——实机验证踩到，单测的 `contains("...;")` 看不出来）。
        "wordpress" | "typecho" | "discuz" => Some("try_files $uri $uri/ /index.php?$args"),
        // ThinkPHP / Laravel 的差别不在这一行，而在 php location 里是否拆 PATH_INFO
        "laravel" | "thinkphp" => Some("try_files $uri $uri/ /index.php?$query_string"),
        _ => None,
    }
}

pub(super) fn render_nginx(spec: &SiteSpec) -> String {
    let names = spec.server_names.join(" ");
    // www ↔ 非 www 跳转（020）：命中时把「跳转来源域名」从主块 / 强制 HTTPS 块的
    // server_name 里**剔除**——两块同名会让 nginx 报 `conflicting server name`
    // 并按先声明者命中，跳转直接失效；再把「目标域名」补进主块。
    let www = www_pair(&spec.server_names, spec.www_redirect.as_deref());
    let main_names: String = match &www {
        Some((from, to)) => {
            let mut v: Vec<String> = spec.server_names.iter().filter(|n| *n != from).cloned().collect();
            if !v.iter().any(|n| n == to) { v.push(to.clone()); }
            v.join(" ")
        }
        None => names.clone(),
    };
    let has_tls = spec.tls_cert.is_some() && spec.tls_key.is_some();
    let http_ports: Vec<u16> = spec.listen.iter().copied().filter(|p| *p != 443).collect();
    let https_ports: Vec<u16> = spec.listen.iter().copied().filter(|p| *p == 443).collect();
    let mut out = String::new();

    // WebSocket 升级映射变量名（每站唯一，见下方 ReverseProxy 分支的 map 块）
    let ws_var = format!("${}_ws", upstream_name(&spec.server_names));

    // 文件头两句：旧文案「请勿手工修改」与「手动维护」功能矛盾（用户其实可以自改，
    // 只是要走面板入口）——第一句说清托管态会覆盖，第二句给出正确的自改路径。
    out.push_str("# 由 ForkPanel 自动生成（面板托管中：保存并应用会覆盖）。\n");
    out.push_str("# 如需自改：在面板「站点配置」区编辑并保存，将转为手动维护、不再被覆盖。\n");
    out.push_str(&format!("# site: {names}\n\n"));

    // ── force_https 且具备证书：80 端口整域 301 → https（独立 server 块）──
    if spec.force_https && has_tls {
        out.push_str("server {\n");
        if http_ports.is_empty() {
            out.push_str("    listen 80;\n");
        } else {
            for p in &http_ports { out.push_str(&format!("    listen {p};\n")); }
        }
        out.push_str(&format!("    server_name {main_names};\n"));
        out.push_str("    return 301 https://$host$request_uri;\n}\n\n");
    }

    // ── 负载均衡 upstream 块 + WebSocket 连接升级映射 ──
    // `upstream` / `map` 都是 **http 级**指令，必须排在 server 之前；塞进 server{}
    // 会直接语法错误（而且 nginx -t 会拒绝整份配置，不只是这个站点）。
    if let SiteKind::Routed { routes } = &spec.kind {
        // 多路由：**每条反代路由都要自己的 map 变量名**。若沿用站点级的名字，
        // 两条 `/api` 与 `/admin` 路由会共用一个 `$panel_x_ws`——map 变量
        // 本身可复用，但 upstream **块名**会撞车（nginx 直接 `duplicate upstream`
        // 拒绝加载整份配置）。故按 prefix 派生，见 route_upstream_name。
        for r in &routes.routes {
            if let RouteKind::Proxy { upstreams } = &r.kind {
                if !upstreams.is_empty() {
                    out.push_str(&render_ws_map(&route_ws_var(&spec.server_names, &r.prefix)));
                }
                if upstreams.len() > 1 {
                    out.push_str(&render_upstream_block(
                        &route_upstream_name(&spec.server_names, &r.prefix),
                        upstreams,
                        spec.lb_policy.as_deref(),
                    ));
                }
            }
        }
        out.push('\n');
    } else if let SiteKind::ReverseProxy { upstreams } = &spec.kind {
        // WebSocket 升级映射：用每站唯一的变量名（`upstream_name` 派生），避免多站点
        // conf 拼进同一 http 上下文时 map 重名导致 nginx 整份拒绝加载。
        // 用 map 按请求动态决定 Connection（带 Upgrade 头→upgrade，否则→close），
        // 这样普通请求仍走 keep-alive、WebSocket 握手才能成功——只写死
        // `Connection "upgrade"` 会让所有请求都带升级头、破坏后端连接复用。
        out.push_str(&render_ws_map(&ws_var));
        if upstreams.len() > 1 {
            out.push_str(&render_upstream_block(
                &upstream_name(&spec.server_names),
                upstreams,
                spec.lb_policy.as_deref(),
            ));
        }
    }

    // ── WAF 的 http 级片段（map / limit_req_zone），同样必须排在 server 之前 ──
    if let Some(w) = &spec.waf {
        out.push_str(&render_waf_http(&spec.server_names, w));
    }

    // ── www ↔ 非 www 跳转（020）：独立 server 块 + return 301 ──
    // 刻意**不用** `if ($host = ...)`：if 在 server 级虽可用，但与 location 内
    // rewrite 交互有已知陷阱；独立块语义直白，nginx 对精确 server_name 也更快。
    if let Some((from, to)) = &www {
        out.push_str("server {\n");
        if http_ports.is_empty() {
            out.push_str("    listen 80;\n");
        } else {
            for p in &http_ports { out.push_str(&format!("    listen {p};\n")); }
        }
        if has_tls {
            for p in &https_ports { out.push_str(&format!("    listen {p} ssl;\n")); }
            if let (Some(cert), Some(key)) = (&spec.tls_cert, &spec.tls_key) {
                out.push_str(&format!("    ssl_certificate     {};\n", cert.display()));
                out.push_str(&format!("    ssl_certificate_key {};\n", key.display()));
                out.push_str(&format!("    ssl_protocols {};\n", tls_protocols(spec.tls_min.as_deref())));
            }
        }
        // 有证书时直接跳 https（省掉「先跳 http 再被 force_https 跳 https」的二次
        // 跳转）；无证书则保持 $scheme，不把明文访问硬拗成 https。
        let scheme = if has_tls { "https" } else { "$scheme" };
        out.push_str(&format!("    server_name {from};\n"));
        out.push_str(&format!("    return 301 {scheme}://{to}$request_uri;\n}}\n\n"));
    }

    // ── 主 server 块 ──
    out.push_str("server {\n");
    // force_https+tls 时主块只留 443（80 已交给重定向块）
    let main_http: Vec<u16> = if spec.force_https && has_tls { Vec::new() } else { http_ports.clone() };
    // 无证书时**不**监听 443。443 是 HTTPS 专用端口，明文监听没有意义；更要命的是
    // 同机只要有**任一**站点用了 `listen 443 ssl`，这个裸 `listen 443` 会让 nginx 以
    // emerg 拒绝**整份**配置（"no ssl_certificate is defined for the listen ... ssl
    // directive"）——一个没证书的站点不该有能力打死全机 nginx。
    let mut wrote_listen = false;
    for p in &main_http {
        out.push_str(&format!("    listen {p};\n"));
        wrote_listen = true;
    }
    for p in &https_ports {
        if has_tls {
            out.push_str(&format!("    listen {p} ssl;\n"));
            wrote_listen = true;
        }
    }
    if !wrote_listen {
        out.push_str("    listen 80;\n");   // 兜底：一个 listen 都没写时不生成无监听的 server
    }
    out.push_str(&format!("    server_name {main_names};\n\n"));

    if let (Some(cert), Some(key)) = (&spec.tls_cert, &spec.tls_key) {
        out.push_str(&format!("    ssl_certificate     {};\n", cert.display()));
        out.push_str(&format!("    ssl_certificate_key {};\n", key.display()));
        out.push_str(&format!("    ssl_protocols {};\n", tls_protocols(spec.tls_min.as_deref())));
        out.push_str(&format!("    ssl_ciphers {};\n", tls_ciphers(spec.tls_profile.as_deref())));
        out.push_str("    ssl_prefer_server_ciphers on;\n");
        // 会话复用：减少重复握手。zone 名按站点派生，避免多站共用一个共享内存区
        out.push_str(&format!(
            "    ssl_session_cache shared:SSL_{}:10m;\n",
            upstream_name(&spec.server_names)));
        out.push_str("    ssl_session_timeout 1d;\n");
        if spec.hsts {
            let mut v = format!("max-age={}", spec.hsts_max_age.max(0));
            if spec.hsts_include_sub { v.push_str("; includeSubDomains"); }
            if spec.hsts_preload { v.push_str("; preload"); }
            out.push_str(&format!("    add_header Strict-Transport-Security \"{}\" always;\n", v));
        }
        out.push('\n');
    }

    // 整站重定向不输出 root / index（它只发 return，没有文件服务）
    if !matches!(spec.kind, SiteKind::Redirect { .. }) {
        out.push_str(&format!("    root {};\n", spec.root.display()));
        out.push_str("    index index.html index.htm;\n\n");
    }

    if let Some(al) = &spec.access_log { out.push_str(&format!("    access_log {};\n", al.display())); }
    if let Some(el) = &spec.error_log {
        // 级别（021）：错误日志不写级别也能跑，但默认的 error 之外常常要看 warn
        let lvl = spec.error_log_level.as_deref().unwrap_or("error");
        out.push_str(&format!("    error_log {} {lvl};\n", el.display()));
    }
    if spec.access_log.is_some() || spec.error_log.is_some() { out.push('\n'); }

    // ── 访问控制（021）：IP 白/黑名单 + HTTP Basic Auth ──
    // 白名单优先：ip_allow 非空即「只放行名单内、其余 deny all」，此时 ip_deny 忽略
    // ——`allow/deny` 是按顺序匹配的，两者混用极易写出与预期相反的规则。
    if let Some(list) = &spec.ip_allow {
        if !list.is_empty() {
            out.push_str("    # ── 访问控制：白名单（名单外一律拒绝）──\n");
            for ip in list { out.push_str(&format!("    allow {ip};\n")); }
            out.push_str("    deny all;\n\n");
        }
    } else if let Some(list) = &spec.ip_deny {
        if !list.is_empty() {
            out.push_str("    # ── 访问控制：黑名单 ──\n");
            for ip in list { out.push_str(&format!("    deny {ip};\n")); }
            out.push('\n');
        }
    }
    if spec.auth_basic {
        if let (Some(u), Some(f)) = (&spec.auth_user, &spec.auth_file) {
            out.push_str(&format!(
                "    auth_basic \"{u} 的受限区域\";\n    auth_basic_user_file {};\n\n",
                f.display()
            ));
        }
    }

    // ACME 挑战路径 + 敏感文件拒绝：**所有站点类型都发**，与 WAF 无关。
    //
    // 整站重定向例外：它只发 return、连 root 都不输出，挑战路径对它无意义
    //（重定向站点的证书由**目标站**的站点负责）。
    if !matches!(spec.kind, SiteKind::Redirect { .. }) {
        out.push_str(&render_acme_challenge_location(&spec.root));
        out.push_str(&render_deny_locations(
            spec.waf.as_ref().is_some_and(|w| w.profile == WafProfile::Strict),
        ));
    }

    if let Some(w) = &spec.waf {
        out.push_str(&render_waf_server(&spec.server_names, w));
    }

    match &spec.kind {
        SiteKind::Static => {
            // SPA 回退：history 路由的单页应用需要把所有未命中文件的路径交给
            // /index.html 处理；非 SPA 则 404（避免把未知路径当成 index 引发漏洞）。
            if spec.spa_fallback {
                out.push_str("    location / {\n        try_files $uri $uri/ /index.html;\n    }\n");
            } else {
                out.push_str("    location / {\n        try_files $uri $uri/ =404;\n    }\n");
            }
        }
        SiteKind::ReverseProxy { upstreams } => {
            let target = match upstreams.len() {
                // 单后端：直接 proxy_pass，不建 upstream 块（少一层间接，语义更直白）
                1 => upstreams[0].clone(),
                // 多后端：指向 upstream 名（块已在上方 http 级输出）
                _ => format!("http://{}", upstream_name(&spec.server_names)),
            };
            out.push_str("    location / {\n");
            out.push_str(&format!("        proxy_pass {target};\n"));
            // 超时三项（021）：默认各 60s；慢接口（导出/大模型）常常要调大读取超时
            out.push_str(&format!("        proxy_connect_timeout {}s;\n", spec.proxy_connect_timeout.max(1)));
            out.push_str(&format!("        proxy_send_timeout {}s;\n", spec.proxy_send_timeout.max(1)));
            out.push_str(&format!("        proxy_read_timeout {}s;\n", spec.proxy_read_timeout.max(1)));
            out.push_str("        proxy_set_header Host $host;\n");
            out.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
            out.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
            out.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
            // WebSocket：升级连接头 + HTTP/1.1 长连接（详见上方 map 块的说明）
            out.push_str("        proxy_http_version 1.1;\n");
            out.push_str("        proxy_set_header Upgrade $http_upgrade;\n");
            out.push_str(&format!("        proxy_set_header Connection {ws_var};\n"));
            out.push_str("    }\n");
        }
        SiteKind::Redirect { target, code } => {
            // 整站重定向：自动追加 $request_uri 保留原始路径与查询串。
            out.push_str(&format!("    return {code} {target}$request_uri;\n"));
        }
        SiteKind::Routed { routes } => {
            out.push_str(&render_routed_server(routes, spec));
        }
        SiteKind::Php { fpm } => {
            // `fastcgi_params` 由发行版提供（Debian: /etc/nginx/fastcgi_params）
            out.push_str("    location ~ \\.php$ {\n");
            out.push_str("        include fastcgi_params;\n");
            out.push_str(&format!("        fastcgi_pass {fpm};\n"));
            // ThinkPHP 走 PATH_INFO：把 `/index.php/a/b` 拆成脚本名 + PATH_INFO 交给框架
            if spec.rewrite_preset.as_deref() == Some("thinkphp") {
                out.push_str("        fastcgi_split_path_info ^(.+\\.php)(.*)$;\n");
                out.push_str("        fastcgi_param PATH_INFO $fastcgi_path_info;\n");
            }
            out.push_str("        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n");
            out.push_str("    }\n");
            // 伪静态（020）：预置模板替换默认 `=404` 兜底；custom 时原样输出用户文本
            out.push_str("    location / {\n");
            match (spec.rewrite_preset.as_deref().unwrap_or("none"), spec.rewrite_custom.as_deref()) {
                ("custom", Some(c)) if !c.trim().is_empty() => {
                    for line in c.trim_end().lines() {
                        out.push_str("        ");
                        out.push_str(line.trim());
                        out.push('\n');
                    }
                }
                (p, _) => out.push_str(&format!(
                    "        {};\n",
                    php_try_files(Some(p)).unwrap_or("try_files $uri $uri/ =404"))),
            }
            out.push_str("    }\n");
        }
    }

    // ── 自定义配置片段（owner 维护；可选）──
    // 插在主 server 块**尾部**（各类 location / WAF 段之后、闭合 `}` 之前），
    // 可补 add_header / location / 其它 server 级指令——与整文件手动维护互补：
    // 那种是「接管、不重渲」，这段始终随表单「保存并应用」重新渲染。
    // 内容原样透传（不重排缩进）：写坏由下发前的 `nginx -t` 拦截，不会带病上线。
    if let Some(cc) = spec
        .custom_conf
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        out.push_str("\n    # ── 自定义配置片段（owner 维护；随表单保存重新渲染）──\n");
        for line in cc.lines() {
            out.push_str(line);
            out.push('\n');
        }
    }

    out.push_str("}\n");
    out
}

/// WebSocket 升级映射块（http 级，必须排在 server 之前）。
///
/// 用 map 按请求动态决定 Connection（带 Upgrade 头→upgrade，否则→close），
/// 这样普通请求仍走 keep-alive、WebSocket 握手才能成功——只写死
/// `Connection "upgrade"` 会让所有请求都带升级头、破坏后端连接复用。
pub(super) fn render_ws_map(ws_var: &str) -> String {
    let mut o = String::new();
    o.push_str(&format!("map $http_upgrade {ws_var} {{\n"));
    o.push_str("    default upgrade;\n");
    o.push_str("    ''      close;\n");
    o.push_str("}\n\n");
    o
}

/// `upstream` 块（http 级）。`upstreams` 已是 `host:port` 或带 scheme 的完整 URL。
pub(super) fn render_upstream_block(name: &str, upstreams: &[String], policy: Option<&str>) -> String {
    let mut o = String::new();
    o.push_str(&format!("upstream {name} {{\n"));
    // 负载均衡策略（021）：只给三种互不冲突的取值——轮询不写指令（nginx 默认），
    // least_conn 对长连接/慢请求更均衡（默认），ip_hash 保证同一客户端落到同一后端。
    // 未知值回落 least_conn，不把坏值带进配置。
    match policy.unwrap_or("least_conn") {
        "round_robin" => {}
        "ip_hash" => o.push_str("    ip_hash;\n"),
        _ => o.push_str("    least_conn;\n"),
    }
    for u in upstreams {
        // upstream 的 server 指令只接受 host:port，不接受 scheme
        let hp = u.split_once("://").map(|(_, r)| r).unwrap_or(u.as_str());
        o.push_str(&format!("    server {hp};\n"));
    }
    o.push_str("}\n\n");
    o
}

/// 多路由的反代目标解析：单后端直连、多后端指向 upstream 块名。
pub(super) fn route_proxy_target(server_names: &[String], prefix: &str, upstreams: &[String]) -> String {
    match upstreams.len() {
        1 => upstreams[0].clone(),
        _ => format!("http://{}", route_upstream_name(server_names, prefix)),
    }
}

/// 多路由渲染：按 prefix 长度降序输出 `location ^~ <prefix>`。
///
/// 全部用 `^~`（**不用正则**）：带 `^~` 的前缀一旦命中就**不再走正则**，
/// 于是「用户写的 prefix」与「deny/WAF 里的正则 location」的优先级变得确定，
/// 不再取决于配置里的书写顺序——这正是引入多路由时必须一并锁掉的东西。
pub(super) fn render_routed_server(routes: &SiteRoutes, spec: &SiteSpec) -> String {
    let mut o = String::new();
    o.push_str("\n    # ── 多路由（按前缀长度降序；`^~` 保证不被正则抢走）──\n");
    for r in routes.sorted() {
        o.push_str(&format!("\n    # {} → {:?}\n", r.prefix, r.kind));
        match &r.kind {
            RouteKind::Static { spa, root } => {
                o.push_str(&format!("    location ^~ {} {{\n", r.prefix));
                // 路由级 root：覆盖 server 级站点 root（须为空或经 apply 约束到 site_root 内）。
                // 不填则继承 server root——最常见：整站一个根目录，各静态子路径共用。
                if let Some(rv) = root {
                    o.push_str(&format!("        root {};\n", rv));
                }
                if *spa {
                    o.push_str("        try_files $uri $uri/ /index.html;\n");
                } else {
                    o.push_str("        try_files $uri $uri/ =404;\n");
                }
                o.push_str("    }\n");
            }
            RouteKind::Proxy { upstreams } => {
                let target = route_proxy_target(&spec.server_names, &r.prefix, upstreams);
                o.push_str(&format!("    location ^~ {} {{\n", r.prefix));
                o.push_str(&format!("        proxy_pass {target};\n"));
                o.push_str(&format!("        proxy_connect_timeout {}s;\n", spec.proxy_connect_timeout.max(1)));
                o.push_str(&format!("        proxy_send_timeout {}s;\n", spec.proxy_send_timeout.max(1)));
                o.push_str(&format!("        proxy_read_timeout {}s;\n", spec.proxy_read_timeout.max(1)));
                o.push_str("        proxy_set_header Host $host;\n");
                o.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
                o.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
                o.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
                o.push_str("        proxy_http_version 1.1;\n");
                o.push_str("        proxy_set_header Upgrade $http_upgrade;\n");
                o.push_str(&format!(
                    "        proxy_set_header Connection {};\n",
                    route_ws_var(&spec.server_names, &r.prefix)
                ));
                o.push_str("    }\n");
            }
            RouteKind::Php { fpm, front_controller } => {
                // ⚠ 多路由下**不能**用 `location ~ \\.[Pp]hp$`：`^~` 前缀会屏蔽
                // 同级正则，那条正则永不执行 → PHP 请求落到静态处理（源码当文本下载，
                // 或404）。故改成现代框架的 front controller 形式：整个前缀交给
                // 入口脚本，由框架自己路由。这也是 Laravel/ThinkPHP 的标准部署法。
                o.push_str(&format!("    location ^~ {} {{\n", r.prefix));
                o.push_str("        include fastcgi_params;\n");
                o.push_str(&format!("        fastcgi_pass {fpm};\n"));
                o.push_str(&format!(
                    "        fastcgi_param SCRIPT_FILENAME $document_root{front_controller};\n"
                ));
                o.push_str(&format!(
                    "        fastcgi_param SCRIPT_NAME {front_controller};\n"
                ));
                o.push_str("    }\n");
            }
        }
    }
    o
}

/// upstream 块名：由首个 server_name 派生并净化（非字母数字 → `_`）。
///
/// 必须稳定且唯一——同一台机器上多站点的 upstream 名一旦撞车，
/// nginx 会拒绝加载整份配置（`duplicate upstream`）。
/// 多路由追加 `prefix` 成分，否则同一站点的两条反代路由会撞车。
/// 必须稳定且唯一——同一台机器上多站点的 upstream 名一旦撞车，
/// nginx 会拒绝加载整份配置（`duplicate upstream`）。
pub(super) fn upstream_name(server_names: &[String]) -> String {
    let base = server_names.first().map(|s| s.as_str()).unwrap_or("site");
    let mut out = String::from("panel_");
    for c in base.chars() {
        if c.is_ascii_alphanumeric() { out.push(c); } else { out.push('_'); }
    }
    out
}

// ───────────────── WAF 规则集（编译期常量） ─────────────────
//
// 写进 nginx 配置的字符串有两条硬约束，规则集必须自我遵守（有专门的回归测试钉住）：
// ① **不含空白 / `;` / `{` / `}`**：nginx 词法器用它们切分 token 与块，出现在正则
//    里会直接破坏配置结构——所以 `{8,}` 这类量词不能用；
// ② **不含反斜杠**：nginx 把 `\x` 当转义处理，`\s` / `\.` 是否被原样传给 PCRE
//    取决于引号内外的上下文，属于**不该去赌**的实现细节。一律改用字符类表达：
//    `\.` → `[.]`、`\s` → `[[:space:]]`（POSIX 类，无转义）。
// 于是规则集加不加引号行为完全一致。

/// 恶意 / 扫描器 UA（基础档）。只挑**特征明确的工具名**——刻意不含 curl / wget /
/// python：它们是大量正常脚本与健康检查的 UA，一刀切会误杀真实流量。
pub(super) const WAF_UA_BASIC: &str = "sqlmap|nikto|acunetix|nessus|dirbuster|gobuster|wfuzz|hydra|zgrab|nuclei|masscan|w3af|whatweb";
/// 严格档追加的 UA 备选
pub(super) const WAF_UA_STRICT_EXTRA: &str = "nmap|zaproxy|owasp-zap|burpsuite|skipfish|arachni|commix|wpscan|joomscan";

/// SQL 注入关键词（基础档）：只放**低误报**模式
pub(super) const WAF_SQLI_BASIC: &str = "union[[:space:](/*]+select|information_schema|sleep[(]|benchmark[(]|load_file[(]|into[[:space:]/]+outfile|waitfor[[:space:]]+delay|updatexml[(]|extractvalue[(]";
/// 严格档追加：误报更高，故不进默认档
pub(super) const WAF_SQLI_STRICT_EXTRA: &str = "or[[:space:]]+1[[:space:]]*=1|and[[:space:]]+1[[:space:]]*=1|[[:space:]]having[[:space:]]|concat_ws[(]|[[:space:]]xp_cmdshell";

/// XSS 关键词（基础档）
pub(super) const WAF_XSS_BASIC: &str = "[<]script|javascript:|onerror[[:space:]]*=|onload[[:space:]]*=|onmouseover[[:space:]]*=|document[.]cookie|srcdoc=|%3cscript";
/// 严格档追加
pub(super) const WAF_XSS_STRICT_EXTRA: &str = "[<]iframe|[<]object|[<]embed|[<]svg|onfocus[[:space:]]*=|onclick[[:space:]]*=|alert[(]|eval[(]";

/// 路径穿越 / 本地文件读取（基础档）
pub(super) const WAF_TRAV_BASIC: &str = "[.][.]/|%2e%2e|%252e|/etc/passwd|/proc/self/|/windows/win[.]ini";
/// 严格档追加
pub(super) const WAF_TRAV_STRICT_EXTRA: &str = "[.][.]%2f|%2f%2e%2e|/etc/shadow|/root/[.]ssh";

/// 档位合成：严格档 = 基础档 + 附加备选（**只增不减**）。
///
/// 结构化拼接而不是各写一份清单：两份清单必然漂移，而漂移的方向可能是"严格档
/// 反而少了某条基础规则"——用户以为开了更严的档，实际放松了防护。
pub(super) fn waf_rules(basic: &str, extra: &str, p: WafProfile) -> String {
    match p {
        WafProfile::Basic => basic.to_string(),
        WafProfile::Strict => format!("{basic}|{extra}"),
    }
}

pub(super) fn waf_ua(p: WafProfile) -> String { waf_rules(WAF_UA_BASIC, WAF_UA_STRICT_EXTRA, p) }
pub(super) fn waf_sqli(p: WafProfile) -> String { waf_rules(WAF_SQLI_BASIC, WAF_SQLI_STRICT_EXTRA, p) }
pub(super) fn waf_xss(p: WafProfile) -> String { waf_rules(WAF_XSS_BASIC, WAF_XSS_STRICT_EXTRA, p) }
pub(super) fn waf_trav(p: WafProfile) -> String { waf_rules(WAF_TRAV_BASIC, WAF_TRAV_STRICT_EXTRA, p) }

/// WAF 变量 / zone 名：复用 upstream 的净化规则（同一站点稳定且唯一）。
/// 多站点 zone 名撞车会让 nginx 拒绝加载**整份**配置，不只是这个站点。
pub(super) fn waf_token(server_names: &[String]) -> String { upstream_name(server_names) }

/// 多路由的 upstream 块名 / map 变量名：站点名 + prefix 派生。
///
/// prefix 的 `/` 与非字母数字统一替成 `_`，保证与 `upstream_name` 的净化规则一致；
/// 带上 prefix 是**必须的**——同一站点的 `/api` 与 `/admin` 各有多后端时，
/// 块名撞车会让 nginx 以 `duplicate upstream` 拒绝整份配置。
pub(super) fn route_upstream_name(server_names: &[String], prefix: &str) -> String {
    let base = upstream_name(server_names);
    let mut out = String::from(&base);
    for c in prefix.chars() {
        if c.is_ascii_alphanumeric() { out.push(c); } else { out.push('_'); }
    }
    out
}

/// 多路由的 WebSocket map 变量名（`$panel_x_api_ws` 形式）。
pub(super) fn route_ws_var(server_names: &[String], prefix: &str) -> String {
    format!("${}_ws", route_upstream_name(server_names, prefix))
}

/// WAF 的 **http 级**片段（`map` / `limit_req_zone` / `limit_req_status`）。
///
/// 为什么必须排在 server 之前：nginx 只在 http 上下文接受这些指令。放错位置
/// 不是"这个站点不生效"，而是 `nginx -t` 拒绝整份配置——**一个站点写错会让
/// 全机所有站点一起加载失败**。
pub(super) fn render_waf_http(server_names: &[String], w: &WafSpec) -> String {
    let t = waf_token(server_names);
    let strict = w.profile == WafProfile::Strict;
    let mut o = String::new();

    o.push_str(&format!("# ── WAF（{}）──\n", w.profile.as_str()));
    // 每条规则一个 map：只算一次、可读，再在 server 内用
    // `if ($var) { return 403; }` 拒绝。`if` 配 `return` 是官方认可的安全用法
    // （危险的是 `if` 里配 proxy_pass / 重写）。
    o.push_str(&format!("map $http_user_agent ${t}_ua {{\n    default 0;\n    \"~*{}\" 1;\n}}\n", waf_ua(w.profile)));
    o.push_str(&format!("map $request_uri ${t}_sqli {{\n    default 0;\n    \"~*{}\" 1;\n}}\n", waf_sqli(w.profile)));
    o.push_str(&format!("map $request_uri ${t}_xss {{\n    default 0;\n    \"~*{}\" 1;\n}}\n", waf_xss(w.profile)));
    o.push_str(&format!("map $request_uri ${t}_trav {{\n    default 0;\n    \"~*{}\" 1;\n}}\n", waf_trav(w.profile)));

    if strict {
        // 非白名单方法一律 405。`default 1` + 逐个放行，比列黑名单安全：
        // 将来 nginx 支持新方法时默认仍是拒绝。
        o.push_str(&format!(
            "map $request_method ${t}_method {{\n    default 1;\n    GET 0;\n    HEAD 0;\n    POST 0;\n    PUT 0;\n    DELETE 0;\n    PATCH 0;\n    OPTIONS 0;\n}}\n"
        ));
        // 空 UA：不少扫描器连 UA 都不发。同时列 "" 与 "-"——nginx 在请求头缺失时
        // 把变量取值为 "-"（不是空串），两个都写上就不必依赖具体版本的细节。
        o.push_str(&format!(
            "map $http_user_agent ${t}_noua {{\n    default 0;\n    \"\" 1;\n    \"-\" 1;\n}}\n"
        ));
    }

    if let Some(r) = w.rate_per_sec {
        // 10m 共享内存约记住 16 万个 IP。rate 必须 ≥1——nginx 会拒绝 rate=0r/s。
        o.push_str(&format!("limit_req_zone $binary_remote_addr zone={t}_rl:10m rate={r}r/s;\n"));
        // 默认超限返回 503，语义上应是 429（Too Many Requests）：503 会让监控
        // 误判成"服务挂了"，而实际只是这个客户端被限流。
        o.push_str("limit_req_status 429;\n");
    }
    o.push('\n');
    o
}

/// WAF 的 **server 级**片段（拦截判定 + 限速 + 隐藏文件拒绝）。
pub(super) fn render_waf_server(server_names: &[String], w: &WafSpec) -> String {
    let t = waf_token(server_names);
    let strict = w.profile == WafProfile::Strict;
    let mut o = String::new();

    o.push_str("\n    # ── WAF 拦截（命中即拒）──\n");
    o.push_str(&format!("    if (${t}_ua)   {{ return 403; }}\n"));
    o.push_str(&format!("    if (${t}_sqli) {{ return 403; }}\n"));
    o.push_str(&format!("    if (${t}_xss)  {{ return 403; }}\n"));
    o.push_str(&format!("    if (${t}_trav) {{ return 403; }}\n"));
    if strict {
        o.push_str(&format!("    if (${t}_noua)   {{ return 403; }}\n"));
        o.push_str(&format!("    if (${t}_method) {{ return 405; }}\n"));
    }
    if let Some(_r) = w.rate_per_sec {
        o.push_str(&format!("    limit_req zone={t}_rl burst={} nodelay;\n", w.burst));
    }

    o
}

/// 敏感文件拒绝规则。**默认站点就有，不依赖 WAF**。
///
/// 为什么单独抽出来、不做成 WAF 的一部分：WAF 是「可选的额外防护」，而
/// `.git` / `.env` / `*.sql` 这类文件一旦能被下载走，老 CMS 源码与数据库
/// 凭据就直接公开——这是**默认就该堵**的口子，不该等用户想起来开 WAF。
///
/// ⚠ **`/.well-known` 必须放行**：ACME http-01 的挑战文件就落在这里，
/// 一刀切会把证书签发/续期打死——"顺手加的一条规则让线上证书过期"是最难
/// 排查的那类事故（且表现为"证书莫名过期"，与本规则毫无字面关联）。
///
/// `strict` 仅在 WAF 严格档追加「目录类」规则：默认档只挡文件（误杀面极小），
/// 目录名匹配面大（`logs` / `backup` 这类名字在真实项目里很常见），故归严格档。
pub(super) fn render_deny_locations(strict: bool) -> String {
    let mut o = String::new();
    o.push_str("\n    # ── 敏感文件拒绝（默认生效，无需开启任何防护）──\n");
    // ⚠⚠ **必须用 server 级 `if`，不能用 `location ~` 正则**——这是本项目踩过的
    // 一个真坑（多路由上线后 `/.env` 直接 200 下载走源码）：
    //   nginx 的 location 优先级是「`=` > 前缀 `^~` > 正则 > 普通前缀」，
    //   而多路由的每条路由都是 `location ^~ /xxx`。前缀一旦 ^~ 就**永不再走正则**，
    //   于是 `location ^~ /` 命中 `/.env` 后，deny 的正则 location 被彻底跳过。
    // `if ($uri ~ …) { return 403; }` 在 rewrite 阶段执行、**早于 location 匹配**，
    // `^~` 拦不住它 —— 这是唯一能同时覆盖「静态/反代/PHP/多路由」四种站点的位置。
    // nginx 官方明确：`if` 里只用 `return` 是安全的（不要在 if 里放 proxy_pass 等）。
    //
    // 用 `$uri`（已解码、不含查询串）而非 `$request_uri`（含 ?query）：扩展名锚定 `$`
    // 才对得上，否则 `/a.sql?x=1` 会漏。
    //
    // ⚠ **`(?!)` 前面刻意不加 `^` 锚点**——要拦的是**任意层级**的隐藏文件。
    //   写成 `^/[.]` 时只拦顶层：`/admin/.env`、`/api/.env` 全部漏过（多路由让站点
    //   有了子路径，这个漏洞才暴露；实测 `/admin/.env` 直接返回了文件内容）。
    //   不加锚点后 `/[.]` 匹配任意位置的 `/.`，而 `/a.b.c` 这类正常名不受影响
    //   （`.` 前面是字母而非 `/`）。
    //   `(?!)` 是 PCRE 否定前瞻：放行 `/.well-known/`（ACME http-01 挑战文件落在这里，
    //   一刀切会把证书签发/续期打死，且症状是「证书莫名过期」，与本规则毫无字面关联）。
    o.push_str("    if ($uri ~ \"/[.](?!well-known/)\") { return 403; }\n");
    // 版本库目录：同样**不加 `^` 锚点**，覆盖任意层级（`/x/.git/config` 也拦）。
    // 上一条 `"/[.]"` 已能拦 `/.git/…`，但拦不住 `/x/.git/…`，故这条针对目录名。
    o.push_str("    if ($uri ~* \"/[.](git|svn|hg)(/|$)\") { return 403; }\n");
    // 备份与编辑器残留：正常站点不需要对外提供这些
    o.push_str("    if ($uri ~* \"[.](sql|bak|old|orig|swp|save|tar|gz|tgz|zip|7z|rar)$\") { return 403; }\n");
    if strict {
        o.push_str("    if ($uri ~* \"^/(config|conf|configs|logs?|backup|backups|dumps?|db|database)(/|$)\") { return 403; }\n");
    }
    o
}

/// ACME http-01 挑战路径：**在反代/PHP 站点也必须存在**。
///
/// 面板签发 ACME 证书时用 `certbot --webroot -w <站点根目录>`，挑战文件落在
/// `<站点根>/.well-known/acme-challenge/`。但反代站点只有一个
/// `location / { proxy_pass … }`——它会把挑战请求**也转给后端**，于是 certbot
/// 拉不到 token、签发静默失败（面板侧只看到"任务失败"，用户看不到原因）。
///
/// 用 `^~` 前缀匹配是关键：nginx 的 location 优先级是
/// 「精确 `=` > 前缀（`^~`）> 正则 > 普通前缀」，`^~` 一旦命中就**不再走正则**，
/// 因此 WAF/deny 里的正则规则不会把挑战路径抢走。
///
/// 只发这一条、覆盖所有站点类型（含静态）：静态站点本来就能从磁盘读到，
/// 显式写出来是为了让"挑战路径不被任何 deny 规则拦"成为**配置自带的保证**，
/// 而不是依赖别处的正则恰好放行。
pub(super) fn render_acme_challenge_location(root: &std::path::Path) -> String {
    format!(
        "\n    # ── ACME http-01 挑战路径（certbot 写入 <root>/.well-known/acme-challenge/）──\n{}    location ^~ /.well-known/acme-challenge/ {{\n        root {};\n        default_type \"text/plain\";\n        try_files $uri =404;\n    }}\n",
        "",
        root.display()
    )
}

#[async_trait]
impl WebServerProvider for LinuxWebServer {
    fn name(&self) -> &'static str { self.name.unwrap_or("none") }

    /// 委托给同名**固有方法**（`LinuxWebServer::conf_path`，类型限定调用消歧义）——
    /// 路径计算只有一份，render 与 PUT conf 拿到的目标必然一致。
    fn conf_path(&self, server_names: &[String]) -> PathBuf {
        LinuxWebServer::conf_path(self, server_names)
    }

    fn render(&self, spec: &SiteSpec) -> Result<(PathBuf, String)> {
        match self.name {
            Some("nginx") => {}
            Some("caddy") => return unsupported!("webserver.render: caddy 尚未实装（当前仅 nginx）"),
            _ => return unsupported!("webserver.render: 未检测到 nginx"),
        }
        if spec.server_names.is_empty() {
            return Err(PanelError::ConfigInvalid { detail: "server_names 为空".into() });
        }
        let target = self.conf_path(&spec.server_names);
        Ok((target, render_nginx(spec)))
    }

    /// 语法校验：把片段包进临时 wrapper 主配置后跑 `nginx -t`。**在 deploy 之前**，
    /// 失败则旧配置纹丝不动。
    ///
    /// wrapper 与 argv 都由 [`validate_wrapper`] / [`nginx_test_argv`] 生成——
    /// 生产与测试共用同一份，测试才不会"在验一个不存在的东西"。
    async fn validate(&self, rendered: &str) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.validate: 仅 nginx"); }
        let base = self.paths.tmp_dir()
            .join(format!("panel-validate-{}-{}", std::process::id(), uniq_counter()));
        let conf_dir = base.join("conf");
        tokio::fs::create_dir_all(&conf_dir).await.map_err(|e| PanelError::Internal(e.to_string()))?;

        // 片段：该站点配置
        let frag = base.join("site.conf");
        tokio::fs::write(&frag, rendered).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        // 片段的相对 include 也要在临时 conf/ 下可见（见 stage_relative_includes）
        stage_relative_includes(
            rendered,
            &nginx_conf_source_dir(&self.paths.web_conf_dir()),
            &conf_dir,
        )
        .await?;
        tokio::fs::write(conf_dir.join("nginx.conf"), validate_wrapper(&base, &frag))
            .await.map_err(|e| PanelError::Internal(e.to_string()))?;

        let argv = nginx_test_argv(&base);
        let argv_ref: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let r = crate::cmd::run(
            Bin::Nginx,
            &argv_ref,
            CmdOpt { timeout: Duration::from_secs(20), ..Default::default() },
        ).await;

        let _ = tokio::fs::remove_dir_all(&base).await;

        match r {
            Ok(o) if o.code == Some(0) => Ok(()),
            Ok(o) => Err(PanelError::ConfigInvalid {
                detail: if o.stderr.trim().is_empty() { o.stdout } else { o.stderr },
            }),
            Err(e) => Err(e),
        }
    }

    /// 原子替换：同目录写临时文件 → `rename`（同文件系统下 POSIX 保证原子）。
    async fn deploy(&self, target: &std::path::Path, content: &str) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.deploy: 仅 nginx"); }
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        }
        let tmp = target.with_extension(format!("tmp{}", std::process::id()));
        tokio::fs::write(&tmp, content).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).await;
        }
        tokio::fs::rename(&tmp, target).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn reload(&self) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.reload: 仅 nginx"); }
        // 优先对运行中的 master 发信号
        if let Ok(o) = crate::cmd::run(
            Bin::Nginx, &["-s", "reload"],
            CmdOpt { timeout: Duration::from_secs(10), ..Default::default() },
        ).await {
            if o.code == Some(0) { return Ok(()); }
        }
        // 回退 systemd（nginx 由 unit 托管时）
        let o = crate::cmd::run(
            Bin::Systemctl, &["reload", "nginx"],
            CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
        ).await?;
        if o.code == Some(0) { Ok(()) }
        else { Err(PanelError::Command { bin: "nginx".into(), detail: truncate_err(&o.stderr) }) }
    }

    async fn remove(&self, conf_path: &std::path::Path) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.remove: 仅 nginx"); }
        if conf_path.exists() {
            std::fs::remove_file(conf_path)
                .map_err(|e| PanelError::Io(format!("remove {}: {e}", conf_path.display())))?;
        }
        // 删完必须 reload：否则 nginx 仍按内存旧配置继续服务该站点（"已删除"却仍在线）
        self.reload().await
    }
}

