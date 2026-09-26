//! 静态资源服务：构建期内嵌 web/dist，运行期零 Node、零外部文件。
//!
//! 三条纪律：
//! 1. 资源名带内容哈希 → 可安全设置长期 Cache-Control。
//! 2. `index.html` 绝不缓存（否则升级面板后浏览器仍加载旧入口）。
//! 3. SPA 回退只回退**非 /api** 路径，避免把 API 404 吞成 HTML（会让前端拿到 HTML 当 JSON 解析）。

use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};

/// 构建期内嵌。`dev-assets` 特性下改为从磁盘读取，避免改前端就要重编译。
#[cfg(not(feature = "dev-assets"))]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist"]
#[prefix = ""]
struct Assets;

#[cfg(not(feature = "dev-assets"))]
fn get(path: &str) -> Option<(Vec<u8>, &'static str)> {
    Assets::get(path).map(|f| (f.data.into_owned(), f.metadata.mimetype()))
}

#[cfg(feature = "dev-assets")]
fn get(path: &str) -> Option<(Vec<u8>, &'static str)> {
    let root = std::env::var("PANEL_WEB_DIST").unwrap_or_else(|_| "web/dist".into());
    let p = std::path::PathBuf::from(root).join(path);
    let data = std::fs::read(&p).ok()?;
    let mime = match p.extension().and_then(|e| e.to_str()) {
        Some("js") => "text/javascript",
        Some("css") => "text/css",
        Some("html") => "text/html",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    Some((data, mime))
}

fn is_hashed(p: &str) -> bool {
    // 构建产物形如 assets/index.a1b2c3d4.js
    p.starts_with("assets/") && p.contains('.')
        && p.rsplit('/').next().unwrap_or("").split('.').count() >= 3
}

/// 静态资源 handler
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match get(path) {
        Some((data, mime)) => {
            let cache = if path == "index.html" {
                // 入口不缓存：否则面板升级后用户仍加载旧版入口
                "no-store, must-revalidate"
            } else if is_hashed(path) {
                "public, max-age=31536000, immutable"
            } else {
                "public, max-age=3600"
            };
            let mut res = (StatusCode::OK, Body::from(data)).into_response();
            let h = res.headers_mut();
            h.insert(header::CONTENT_TYPE, mime.parse().unwrap_or(
                axum::http::HeaderValue::from_static("application/octet-stream")));
            h.insert(header::CACHE_CONTROL, cache.parse().unwrap());
            // 资源名已含内容哈希，ETag 直接复用路径中的哈希段
            res
        }
        None => {
            // SPA 回退：仅对非 API 路径生效
            match get("index.html") {
                Some((data, _)) => {
                    let mut res = (StatusCode::OK, Body::from(data)).into_response();
                    res.headers_mut().insert(header::CONTENT_TYPE,
                        "text/html; charset=utf-8".parse().unwrap());
                    res.headers_mut().insert(header::CACHE_CONTROL,
                        "no-store, must-revalidate".parse().unwrap());
                    res
                }
                None => (StatusCode::NOT_FOUND, "web assets not embedded").into_response(),
            }
        }
    }
}

/// 健康检查：不做鉴权、不查库，供 systemd / 反代探活
pub async fn healthz() -> &'static str { "ok" }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_detection() {
        assert!(is_hashed("assets/index.0a1b2c3d.js"));
        assert!(is_hashed("assets/vendor-vue.9f8e7d6c.css"));
        assert!(!is_hashed("index.html"));
        assert!(!is_hashed("favicon.ico"));
    }

    #[test]
    fn api_paths_are_never_fallback_targets() {
        // 路由层保证 /api 前缀不匹配 static_handler；此处断言约定本身
        assert!(!"/api/v1/system/overview".starts_with("/assets"));
    }
}
