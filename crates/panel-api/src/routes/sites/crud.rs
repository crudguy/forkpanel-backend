use super::*;
use crate::extract::PanelJson;


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
    PanelJson(req): PanelJson<CreateReq>,
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
pub(super) async fn render_spec_for_row(
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
        "routed" => match routes_from_json(&row.routes_json).to_vec()
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
    let (access_log_p, error_log_p) = site_log_paths(state, domains, row.log_access != 0, row.log_error != 0);
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
        auth_file: Some(htpasswd_path(state, domains)).filter(|p| p.is_file()),
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
pub(super) async fn prune_stale_conf(
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
pub(super) async fn finish_deploy(state: &Shared, id: i64, pruned: bool) -> Result<()> {
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
pub(super) const TOUCH_APPLIED_SQL: &str = "UPDATE sites SET last_applied_at = ?1 WHERE id = ?2";

/// 落「上次成功下发时间」（023）。仅在外部已真实接收后调用；失败仅记录不中断——
/// 配置明明已下发，不能因为一个展示字段写库失败就把整次应用判成失败。
pub(super) async fn touch_applied(state: &Shared, id: i64) {
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
    PanelJson(req): PanelJson<RemarkReq>,
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
    PanelJson(req): PanelJson<PatchReq>,
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


