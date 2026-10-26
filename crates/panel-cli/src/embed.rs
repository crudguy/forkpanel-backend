//! 静态资源服务：构建期内嵌 web/dist，运行期零 Node、零外部文件。
//!
//! 四条纪律：
//! 1. 资源名带内容哈希 → 可安全设置长期 Cache-Control。
//! 2. `index.html` 绝不缓存（否则升级面板后浏览器仍加载旧入口）。
//! 3. SPA 回退只回退**非 /api** 路径，避免把 API 404 吞成 HTML（会让前端拿到 HTML 当 JSON 解析）。
//! 4. **构建产物只保留代码**：内嵌的 `web/dist` 必须是不含注释的产物——由前端
//!    `vite build`（`esbuild.legalComments:'none'` + `scripts/check-no-comments.mjs`）
//!    保证。Rust 源码注释不会进入二进制，故后端侧无需额外处理；但**不要**手工
//!    往 `web/dist` 里塞带注释的文件（否则守卫被绕过，注释会进二进制）。

use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};

/// 构建期内嵌。`dev-assets` 特性下改为从磁盘读取，避免改前端就要重编译。
#[cfg(not(feature = "dev-assets"))]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist"]
#[prefix = ""]
struct Assets;

#[cfg(not(feature = "dev-assets"))]
// 返回 String 而非 &'static str：rust-embed 的 mimetype() 借用自局部 EmbeddedFile，
// 不能把它的引用返回出去（E0515），故转成自有字符串。
fn get(path: &str) -> Option<(Vec<u8>, String)> {
    Assets::get(path).map(|f| (f.data.into_owned(), f.metadata.mimetype().to_string()))
}

#[cfg(feature = "dev-assets")]
fn get(path: &str) -> Option<(Vec<u8>, String)> {
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
    Some((data, mime.to_string()))
}

fn is_hashed(p: &str) -> bool {
    // 构建产物形如 assets/index.a1b2c3d4.js
    p.starts_with("assets/") && p.contains('.')
        && p.rsplit('/').next().unwrap_or("").split('.').count() >= 3
}

/// 该路径是否"本来就应该是一个静态文件"（而非前端路由）。
///
/// 判据：最后一段含 `.`（有扩展名）即认为是资源请求，例如 `assets/x.js`、
/// `favicon.ico`、`manifest.json`。SPA 路由（`/sites`、`/processes`）没有扩展名。
///
/// 为什么要分开：SPA 回退对**路由**是必要的（刷新 `/sites` 不能 404），但对
/// **资源**是错的——浏览器请求 `index.js` 拿到 `text/html` 会直接报 MIME 错误，
/// 而更糟的是**掩盖了真实故障**：部署缺了一个 chunk 时，页面看起来"200 正常"，
/// 实际报错信息与真因（文件没打进去）毫无关系。这与 `/api` 不回退 HTML 同源。
fn looks_like_asset(p: &str) -> bool {
    let last = p.rsplit('/').next().unwrap_or("");
    // 点号开头是隐藏文件（.well-known 之类），不当资源；纯点号结尾也不当资源
    !last.is_empty() && last != "." && last != ".." && last.contains('.') && !last.starts_with('.')
}

/// 静态资源 handler
pub async fn static_handler(uri: Uri) -> Response {
    let raw = uri.path().trim_start_matches('/');
    // 关键：**/api 路径绝不回退成 index.html**。
    // fallback 会兜住所有未匹配路由（含 /api/v1/xxx 的 404），若回退成 HTML，
    // 前端 client.ts 会把 HTML 当 JSON 解析，报出与真实原因无关的错。
    let is_api = raw == "api" || raw.starts_with("api/");
    let path = if raw.is_empty() { "index.html" } else { raw };

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
            // API 未命中 → 结构化 404（沿用 /api 的错误信封），绝不回退 HTML
            if is_api {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "code": 10004, "message": "not found", "data": null, "detail": null,
                    })),
                ).into_response();
            }
            // SPA 回退：仅对非 API **且非静态资源**的路径生效。
            // 资源请求（带扩展名）未命中必须如实 404：回退成 HTML 会让浏览器
            // 报 MIME 错误，且把「部署缺文件」这个真因掩盖成"看起来 200 正常"。
            if looks_like_asset(path) {
                return (StatusCode::NOT_FOUND, "asset not embedded").into_response();
            }
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

    /// /api 未命中必须返回结构化 404 JSON，**绝不能**回退成 index.html：
    /// 否则前端 client.ts 会把 HTML 当 JSON 解析，报错与真实原因完全无关。
    #[tokio::test]
    async fn api_paths_are_never_fallback_targets() {
        let res = static_handler(Uri::from_static("/api/v1/does-not-exist")).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let ctype = res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ctype.starts_with("application/json"),
                "/api 未命中必须返回 JSON，实际为 {ctype:?}");
    }

    /// 非 API 的未知路径才走 SPA 回退（返回 index.html）。
    #[tokio::test]
    async fn non_api_paths_fall_back_to_spa() {
        let res = static_handler(Uri::from_static("/some/spa/route")).await;
        assert_eq!(res.status(), StatusCode::OK);
        let ctype = res
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ctype.starts_with("text/html"),
            "SPA 回退应返回 HTML，实际为 {ctype:?}"
        );
    }

    /// 缺失的**静态资源**绝不能回退成 index.html。
    ///
    /// 这是本条修复的核心判据：回退后浏览器拿到 `text/html` 的 `.js` 会报 MIME
    /// 错误，而真因（chunk 没打进二进制）被一个"200 正常"彻底掩盖。
    #[tokio::test]
    async fn missing_assets_are_real_404_not_spa_fallback() {
        // 用一定不存在的 hash，避免依赖当前构建产物
        for path in [
            "/assets/index.__definitely_missing__.js",
            "/favicon.__missing__.ico",
        ] {
            let res = static_handler(Uri::from_static(path)).await;
            assert_eq!(
                res.status(),
                StatusCode::NOT_FOUND,
                "{path} 未命中必须 404，而不是回退 HTML"
            );
            let ctype = res
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(
                !ctype.starts_with("text/html"),
                "{path} 不得返回 HTML（会把 MIME 错误与真因混在一起），实际 {ctype:?}"
            );
        }
    }

    /// `looks_like_asset` 的正反两态：SPA 路由不算资源，带扩展名才算。
    /// 边界（点号开头 / 仅点号结尾）单独钉住——它们决定了这些路径会不会被误判成资源。
    #[test]
    fn asset_detection_distinguishes_routes_from_files() {
        // 资源：应当 404，不回退
        assert!(looks_like_asset("assets/index.abc123.js"));
        assert!(looks_like_asset("favicon.ico"));
        assert!(looks_like_asset("manifest.json"));
        assert!(looks_like_asset("deep/nested/file.css"));
        // 路由：应当回退 SPA
        assert!(!looks_like_asset("sites"));
        assert!(!looks_like_asset("processes/detail"));
        assert!(!looks_like_asset(""));
        // 边界
        assert!(!looks_like_asset(".well-known"));      // 点号开头 = 隐藏文件，不当资源
        assert!(!looks_like_asset("dir/."));            // 纯点号
        assert!(!looks_like_asset("."));
        assert!(!looks_like_asset(".."));
    }
}
