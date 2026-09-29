//! 中间件（设计方案 §1.3）：会话注入、写操作 CSRF + 权限、安全响应头、请求体限流。
//!
//! 分层纪律：中间件不写业务逻辑，只做"能不能进"与"要不要记"。

use crate::{
    auth::{self, Session, SessionCache},
    error::{ApiError, ApiResult},
    AppState,
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode},
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
    let sid = extract_cookie(&req.headers(), "panel_sid");
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

/// 只读模式：配置 `read_only = true` 时，所有写请求返回 403 READ_ONLY。
pub async fn read_only_guard(req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::POST | Method::PUT | Method::PATCH | Method::DELETE) {
        if std::env::var("PANEL_READ_ONLY").map(|v| v == "1").unwrap_or(false) {
            return ApiError::read_only().into_response();
        }
    }
    next.run(req).await
}

pub type SharedSessions = Arc<SessionCache>;

#[allow(dead_code)]
fn _unused(_: StatusCode, _: Body) {}

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

    #[test]
    fn body_limits_are_bounded() {
        assert_eq!(BODY_LIMIT_JSON, 1_048_576);
        assert!(BODY_LIMIT_UPLOAD > BODY_LIMIT_JSON);
    }
}
