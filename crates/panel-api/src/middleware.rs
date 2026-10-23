//! 中间件（设计方案 §1.3）：会话注入、写操作 CSRF + 权限、安全响应头、请求体限流、请求级结构化日志。
//!
//! 分层纪律：中间件不写业务逻辑，只做"能不能进"与"要不要记"。

use crate::{
    auth::{self, Session, SessionCache},
    error::{ApiError, ApiResult},
    AppState,
};
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// 从请求中解析会话。失败返回 401/403 而非继续。
pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let sid = extract_cookie(req.headers(), "panel_sid");
    // 惰性恢复：内存未命中时按 sid_hash 查库重建 —— 面板重启后会话仍有效
    // （库里只有哈希，故只能验证重建，符合「凭据不落库」纪律）
    let session = match sid.as_ref() {
        Some(s) => state.sessions.get_or_restore(s, &state.pool).await,
        None => None,
    };
    match session {
        Some(s) => {
            // sid 一并透出：会话管理需区分「自己」（CurrentSid 提取器）
            if let Some(id) = &sid {
                req.extensions_mut().insert(crate::routes::CurrentSid(id.clone()));
            }
            req.extensions_mut().insert(s);
            next.run(req).await
        }
        None => ApiError::unauthorized().into_response(),
    }
}

/// 写操作守卫：CSRF + Origin 校验。**必须在 require_auth 之后。**
pub async fn guard_write(req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::POST | Method::PUT | Method::PATCH | Method::DELETE) {
        return next.run(req).await;
    }

    // 1) Origin 必须在白名单（防跨站）
    if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        // 严格同源：https://host 或 http://host（仅本地监听时允许 http）
        let ok = origin == format!("https://{host}") || origin == format!("http://{host}");
        if !ok { return ApiError::csrf().into_response(); }
    } else if req.headers().get(header::REFERER).is_some() {
        // 有 Referer 但无 Origin（老式表单）→ 拒绝
        return ApiError::csrf().into_response();
    }

    // 2) 双提交 token
    let cookie_token = extract_cookie(req.headers(), "panel_csrf");
    let header_token = req.headers().get("x-csrf-token").and_then(|v| v.to_str().ok());
    if !auth::csrf_ok(cookie_token.as_deref(), header_token) {
        return ApiError::csrf().into_response();
    }

    next.run(req).await
}

/// 安全响应头（设计方案 §1.3）。CSP 使用 nonce，禁止 inline script。
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    h.insert("Permissions-Policy", "geolocation=(), microphone=(), camera=()".parse().unwrap());
    // nonce 在渲染 index.html 时注入；API 响应不需要脚本执行
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            .parse()
            .unwrap(),
    );
    if req_uses_https() {
        h.insert(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains".parse().unwrap());
    }
    res
}

fn req_uses_https() -> bool {
    // 由部署决定：仅公网/启用 TLS 时下发 HSTS（本地 http 监听不下发，避免浏览器缓存后无法访问）
    std::env::var("PANEL_HSTS").map(|v| v == "1").unwrap_or(false)
}

/// 从扩展中取出会话，缺失即 401（供需要登录但不需特定权限的读接口使用）
pub fn session_of(req: &Request) -> ApiResult<Session> {
    req.extensions().get::<Session>().cloned().ok_or_else(ApiError::unauthorized)
}

pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        if kv.next()?.trim() == name {
            return kv.next().map(|v| v.trim().to_string());
        }
    }
    None
}

/// 请求体大小限制（设计方案 §1.2）：普通 JSON 1MB，文件上传单独走 100MB 的路由配置。
pub const BODY_LIMIT_JSON: usize = 1024 * 1024;
pub const BODY_LIMIT_UPLOAD: usize = 100 * 1024 * 1024;

/// 只读模式：所有写请求返回 403 READ_ONLY。
///
/// 判据取 `state.read_only`（启动期算一次），**不要在这里读环境变量**：
/// 此前正是"guard 只认环境变量、设置页也只展示环境变量"，导致 `config.toml` 的
/// `read_only = true` 是一条**配了不生效的假控制**——用户以为开了只读，实际写接口全通。
pub async fn read_only_guard(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if state.read_only && matches!(*req.method(), Method::POST | Method::PUT | Method::PATCH | Method::DELETE) {
        return ApiError::read_only().into_response();
    }
    next.run(req).await
}

pub type SharedSessions = Arc<SessionCache>;

// ═══════════════════════ 请求级结构化日志 ═══════════════════════

/// 请求级结构化日志（复盘 🟡 项）。每条请求一行，落 stderr（serve 启动时
/// stderr 已重定向进日志文件；systemd 部署下进 journald）：
///
/// ```text
/// [panel] [http] method=GET path=/api/v1/version status=200 dur_ms=3 user=admin rid=-
/// ```
///
/// # 字段取舍（都是有意为之，不是漏写）
///
/// - **不记 query string / body / Header**：token 与 PII 最常挂在这些地方
///   （下载链接、Bearer 头），请求日志要能默认开启而不泄密；
/// - **不记客户端 IP**：serve 未接线 `ConnectInfo`，`X-Forwarded-For` 在无
///   反向代理时等于客户端自填——记了是污染不是证据。登录 IP 已由审计日志
///   （`audit()` 的 `actor_ip`）留底，爆破追溯走那条线；
/// - **`user` 只读内存会话缓存**（`SessionCache::get`，不查库、不 restore）：
///   本层是**最外层**，看不到 `require_auth` 插进请求扩展的 Session
///   （Request 已 move 给内层），故独立解析一次 cookie。缓存未命中
///   （刚重启、会话待重建）时记 `-`——绝不为一行日志放大读流量；
/// - **panic 也有行**：本层套在 `CatchPanicLayer` 之外，panic 被转成结构化
///   500 后回流经过本层记 `status=500`；panic 详情另有一行 `[PANIC]`
///   （见 `panic_guard`）；
/// - **SSE / WebSocket 只有一条**：在流建立时落行（`dur_ms` 是建立耗时），
///   后续帧由 hyper 在本层之下驱动，不会按事件刷屏。
///
/// # 为什么不引入 tracing
///
/// panel-api 现有日志设施就是 `eprintln!`（依赖预算纪律：零新依赖）。且
/// tracing 事件在未装 subscriber 的上下文（库用法、测试）里被**静默丢弃**——
/// "看着配了、其实什么都没记"正是本项目反复踩过的假控制形态。
pub async fn request_log(
    State(state): State<Arc<SessionCache>>,
    req: Request,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let method = req.method().as_str().to_string();
    // 只取 path：HTTP 请求行不允许空格/控制字符，path 天然没有日志注入面
    // （与 rid / username 不同，那两个必须过 sanitize_log_field）。
    let path = req.uri().path().to_string();
    let rid = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| sanitize_log_field(v, RID_MAX_LEN))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "-".to_string());
    let user = session_cookie_user(&state, req.headers());
    let res = next.run(req).await;
    let line = format_request_line(
        &method,
        &path,
        res.status().as_u16(),
        started.elapsed().as_millis(),
        user.as_deref(),
        &rid,
    );
    eprintln!("{line}");
    res
}

/// `x-request-id` 上限：只是关联用，UUID 36 字符封顶。
const RID_MAX_LEN: usize = 64;
/// username 上限：与 `validate_username` 的 64 对齐。
const USER_MAX_LEN: usize = 64;

/// 从 cookie 解析会话并取 username。**只读内存缓存**：不查库、不 restore。
///
/// 与 `require_auth` 的分工：那个负责"能不能进"（失败即 401，必要时查库重建
/// 会话）；这个只负责"这条请求是谁"——取不到就记 `-`，日志永不放大读流量。
/// 收 `&SessionCache` 而非 `&AppState`：中间件只依赖它，窄依赖让测试面
/// （无需整个 AppState 夹具）与运行时成本都变小。
fn session_cookie_user(cache: &SessionCache, headers: &HeaderMap) -> Option<String> {
    let sid = extract_cookie(headers, "panel_sid")?;
    let session = cache.get(&sid)?;
    Some(sanitize_log_field(&session.username, USER_MAX_LEN))
}

/// 日志字段消毒：空白与控制字符 → `_`，并按**字符**截断（不会切坏 UTF-8）。
///
/// 为什么必须做：`x-request-id` 是客户端每请求可随意填的 Header；
/// `validate_username` 又只限长度不限字符集——直接拼进日志行，等于允许
/// 客户端**注入伪造字段甚至伪造整行**（如 `rid=" status=200"` 会多出一个
/// 假 token，`\n` 会多出一行假日志）。堵住空白 + 控制字符即同时堵死
/// "伪造 token"与"伪造换行"两条路径；中文等非空白字符原样保留
/// （用户名可能是中文，替换成 `_` 只会丢信息）。
fn sanitize_log_field(s: &str, max_len: usize) -> String {
    s.chars()
        .map(|c| if c.is_whitespace() || c.is_control() { '_' } else { c })
        .take(max_len)
        .collect()
}

/// 纯格式化：与中间件分离，字段顺序 / 缺省值 / 消毒都能做**精确字符串断言**
/// （项目纪律：断言要精确到结构，`contains` 那种过宽断言证明不了格式）。
fn format_request_line(
    method: &str,
    path: &str,
    status: u16,
    dur_ms: u128,
    user: Option<&str>,
    rid: &str,
) -> String {
    let user = user.filter(|u| !u.is_empty()).unwrap_or("-");
    let rid = if rid.is_empty() { "-" } else { rid };
    format!(
        "[panel] [http] method={method} path={path} status={status} dur_ms={dur_ms} user={user} rid={rid}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn cookie_parsing() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "panel_sid=abc123; panel_csrf=def456".parse().unwrap());
        assert_eq!(extract_cookie(&h, "panel_sid").unwrap(), "abc123");
        assert_eq!(extract_cookie(&h, "panel_csrf").unwrap(), "def456");
        assert!(extract_cookie(&h, "nope").is_none());
    }

    #[test]
    fn csrf_rejects_mismatch_and_missing() {
        assert!(auth::csrf_ok(Some("abc"), Some("abc")));
        assert!(!auth::csrf_ok(Some("abc"), Some("abd")));
        assert!(!auth::csrf_ok(Some("abc"), None));
    }

    // ⚠ 这是**常量规格锁**（改常量即红），不是恒真断言：clippy 的
    // `assertions_on_constants` 对"两个 const 比较"一律报警，但它看不出我们
    // 恰恰要锁住这些常量不被悄悄改掉。
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn body_limits_are_bounded() {
        assert_eq!(BODY_LIMIT_JSON, 1_048_576);
        assert!(BODY_LIMIT_UPLOAD > BODY_LIMIT_JSON);
    }

    // ═══════════════ 请求级结构化日志 ═══════════════

    /// 格式规格锁：字段顺序、缺省值（无会话 → `user=-`、空 rid → `rid=-`）。
    /// 精确到整行 eq——字段被删/换序/改名必须红。
    #[test]
    fn request_log_line_format_and_defaults() {
        assert_eq!(
            format_request_line("GET", "/api/v1/version", 200, 3, Some("admin"), "-"),
            "[panel] [http] method=GET path=/api/v1/version status=200 dur_ms=3 user=admin rid=-"
        );
        assert_eq!(
            format_request_line("POST", "/api/v1/auth/login", 401, 0, None, ""),
            "[panel] [http] method=POST path=/api/v1/auth/login status=401 dur_ms=0 user=- rid=-"
        );
        // 匿名公开端点同样有行（user=-），不是只记登录用户
        assert_eq!(
            format_request_line("GET", "/api/v1/version", 200, 12, None, "req-42"),
            "[panel] [http] method=GET path=/api/v1/version status=200 dur_ms=12 user=- rid=req-42"
        );
    }

    /// 消毒钉死两条注入路径：伪造 token（空格）与伪造整行（换行/转义序列）。
    #[test]
    fn sanitize_log_field_blocks_token_and_line_injection() {
        assert_eq!(sanitize_log_field("abc status=200", 64), "abc_status=200");
        assert_eq!(sanitize_log_field("a\nb", 64), "a_b");
        assert_eq!(sanitize_log_field("a\rb", 64), "a_b");
        assert_eq!(sanitize_log_field("a\tb", 64), "a_b");
        assert_eq!(sanitize_log_field("a\x1b[31mb", 64), "a_[31mb");
        // 值里带 `=` 不构成注入（解析方 splitn(2)，仍是同一个 token 的值）
        assert_eq!(sanitize_log_field("a=b", 64), "a=b");
        // 截断按字符：不会切坏 UTF-8，也不会让超长值撑爆日志行
        assert_eq!(sanitize_log_field("abcdef", 3), "abc");
        assert_eq!(sanitize_log_field("用户名", 2), "用户");
        // 非空白字符原样保留：中文用户名不丢信息
        assert_eq!(sanitize_log_field("管理员", 64), "管理员");
    }

    /// user 解析：真 SessionCache + 真 cookie。证明三件事——
    /// 命中 → username（且过消毒）、未命中 → None（记 `-`，不查库）、无 cookie → None。
    #[test]
    fn session_cookie_user_reads_memory_cache_only() {
        let cache = SessionCache::new(
            std::time::Duration::from_secs(1800),
            std::time::Duration::from_secs(43_200),
        );
        cache.insert(
            "sid-1".to_string(),
            Session {
                user_id: 7,
                username: "ad min".to_string(), // 带空格：证明消毒真的发生
                role: "owner".to_string(),
                permissions: vec![],
                allowed_roots: vec![],
                ip: "127.0.0.1".to_string(),
                created_at: 0,
                last_seen: 0,
                expires_at: 0,
            },
        );
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "other=x; panel_sid=sid-1".parse().unwrap());
        assert_eq!(session_cookie_user(&cache, &h).as_deref(), Some("ad_min"));

        h.insert(header::COOKIE, "panel_sid=no-such-sid".parse().unwrap());
        assert!(
            session_cookie_user(&cache, &h).is_none(),
            "缓存未命中必须记 `-`：不能为一行日志去查库/重建会话"
        );

        assert!(session_cookie_user(&cache, &HeaderMap::new()).is_none());
    }

    /// 中间件行为：真 axum Router + 真 Next 链，响应必须**原样透传**
    /// （状态码与 body 都不许被日志层碰坏）。
    ///
    /// 自带负向对照：把返回改成硬编码响应（或忘了 `res`）即红。
    #[tokio::test]
    async fn request_log_passes_response_through_unchanged() {
        use axum::body::Body;
        use axum::http::StatusCode;
        use axum::{routing::get, Router};
        use tower::ServiceExt;

        async fn ping() -> (StatusCode, &'static str) {
            (StatusCode::OK, "pong")
        }

        let cache = std::sync::Arc::new(SessionCache::new(
            std::time::Duration::from_secs(1800),
            std::time::Duration::from_secs(43_200),
        ));
        let app = Router::new()
            .route("/ping", get(ping))
            .layer(axum::middleware::from_fn_with_state(cache, request_log));

        let res = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .expect("中间件不应阻断请求");
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"pong", "响应体必须原样透传");
    }

    // 注：request_log 的接线 / 次序守卫已移至 panel-cli 的 main.rs
    // `wiring_guard_tests`——生产 serve 链在 main.rs 里又设了一次 SPA fallback
    // （`.fallback(embed::static_handler)`），日志层挂在本库 build_router 上罩不住
    // 它；完整论述见 routes.rs 接线段注释。
}
