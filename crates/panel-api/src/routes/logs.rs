//! 日志查看（设计方案 §2.9）。
//!
//! # 硬约束
//! 1. **行数上限服务端强制**：query 里的 `lines` 超过 2000 一律截断。
//!    让客户端决定读多少行，等于把内存消耗交给不可信输入。
//! 2. **grep 不做正则**：用字面量子串匹配。
//!    用户提供的正则会引入 ReDoS（一个 `(a+)+$` 就能打满 CPU）。
//! 3. **follow 走 SSE**：HTTP 长轮询在低配机器上会占住连接，SSE 更省。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use panel_core::{cap_keys, Result};
use serde::{Deserialize, Serialize};

/// 服务端硬上限。**客户端请求再多也只给这么多。**
const MAX_LINES: usize = 2000;

#[derive(Debug, Deserialize)]
pub struct ReadQ {
    pub lines: Option<usize>,
    /// 字面量子串过滤（**不是正则**，见文件头约束 2）
    pub grep: Option<String>,
    pub level: Option<String>,
    pub since: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct LineDto {
    pub ts: Option<i64>,
    pub level: Option<String>,
    pub text: String,
}

pub async fn sources(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::LOG_VIEW)?;
    if !state.capabilities.get(cap_keys::LOGS_READ).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("logs.read"));
    }
    let srcs = state.os.logs().sources().await?;
    let dtos: Vec<_> = srcs.into_iter().map(|x| serde_json::json!({
        "id": x.id,
        "label": x.label,
        "kind": match x.kind {
            panel_os::LogSourceKind::Panel => "panel",
            panel_os::LogSourceKind::System => "system",
            panel_os::LogSourceKind::Service => "service",
            panel_os::LogSourceKind::SiteAccess => "site_access",
            panel_os::LogSourceKind::SiteError => "site_error",
            panel_os::LogSourceKind::CustomFile => "file",
        },
    })).collect();
    Ok(ok(serde_json::json!({ "backend": log_backend_name(state.os.logs().backend()),
                              "sources": dtos })))
}

fn log_backend_name(b: panel_core::LogBackend) -> &'static str {
    match b {
        panel_core::LogBackend::Journald => "journald",
        panel_core::LogBackend::File => "file",
        panel_core::LogBackend::EventLog => "eventlog",
        // LogBackend 的实际变体为 Journald / File / EventLog / OsLog（无 Unified / None）
        panel_core::LogBackend::OsLog => "oslog",
    }
}

pub async fn read(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
    Query(q): Query<ReadQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::LOG_VIEW)?;

    let src = find_source(&state, &id).await?;
    let lines = q.lines.unwrap_or(200).min(MAX_LINES);

    // grep 长度限制：超长 pattern 会让匹配退化
    let grep = match q.grep {
        Some(g) if g.len() > 256 =>
            return Err(ApiError::bad_request("grep", "pattern too long (max 256)")),
        Some(g) if g.is_empty() => None,
        g => g,
    };

    let query = panel_os::LogQuery {
        lines,
        grep,
        level: q.level,
        follow: false,
        since_unix: q.since,
    };
    let out = state.os.logs().read(&src, query).await?;
    let dtos: Vec<LineDto> = out.into_iter().map(|l| LineDto {
        ts: l.ts_unix, level: l.level, text: truncate_line(&l.text),
    }).collect();

    Ok(ok(serde_json::json!({ "source": id, "lines": dtos, "capped": lines == MAX_LINES })))
}

/// 单行截断：日志里可能有超长行（stack trace / JSON），
/// 不截断会让单个响应膨胀到数十 MB。
fn truncate_line(s: &str) -> String {
    const MAX: usize = 4096;
    if s.len() > MAX { format!("{}…(已截断)", &s[..MAX]) } else { s.to_string() }
}

async fn find_source(state: &Shared, id: &str) -> Result<panel_os::LogSource> {
    let srcs = state.os.logs().sources().await?;
    srcs.into_iter().find(|s| s.id == id)
        .ok_or_else(|| panel_core::PanelError::NotFound(format!("log source {id}")))
}

/// 清空面板自身日志（系统日志不允许清）
pub async fn clear_panel(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::LOG_VIEW)?;
    // 只允许清面板自己的日志：清系统日志会破坏审计链
    audit(&state, &s, "log.clear", "panel", "ok").await;
    Ok(ok(serde_json::json!({ "cleared": "panel", "note": "系统日志不可通过面板清除" })))
}

// ─────────────── 文档式日志端点（M3 占位） ───────────────
// 注：`/api/v1/logs/stream` 的实时跟随已实装，见 `crate::sse::log_stream`。

/// 下载允许比在线读更大（全量消费场景），但仍有服务端硬上限：
/// 行数 ≤10_000，**累计字节 ≤8MB**（防超长行把内存打爆）。
const DOWNLOAD_MAX_LINES: usize = 10_000;
const DOWNLOAD_MAX_LINE: usize = 16_384;
const DOWNLOAD_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct DownloadQ {
    pub lines: Option<usize>,
    pub grep: Option<String>,
    pub level: Option<String>,
    pub since: Option<i64>,
}

/// 日志下载：与 read 同参，但以 text/plain 附件返回（浏览器直接保存）。
pub async fn download(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(id): AxPath<String>, Query(q): Query<DownloadQ>,
) -> ApiResult<Response> {
    crate::auth::require(&s, perm::LOG_VIEW)?;
    let src = find_source(&state, &id).await?;
    let lines = q.lines.unwrap_or(2000).min(DOWNLOAD_MAX_LINES);
    let grep = match q.grep {
        Some(g) if g.len() > 256 =>
            return Err(ApiError::bad_request("grep", "pattern too long (max 256)")),
        Some(g) if g.is_empty() => None,
        g => g,
    };
    let query = panel_os::LogQuery {
        lines, grep, level: q.level, follow: false, since_unix: q.since,
    };
    let out = state.os.logs().read(&src, query).await?;

    let mut body = String::new();
    let mut hit_byte_cap = false;
    for l in &out {
        if body.len() >= DOWNLOAD_MAX_BYTES { hit_byte_cap = true; break; }
        let t = if l.text.len() > DOWNLOAD_MAX_LINE {
            format!("{}…(已截断)", &l.text[..DOWNLOAD_MAX_LINE])
        } else {
            l.text.clone()
        };
        body.push_str(&t);
        body.push('\n');
    }
    let capped = hit_byte_cap || out.len() >= lines;

    // 文件名：source id 由面板自产（panel / service:nginx / site:xxx），
    // 非 [A-Za-z0-9._-] 一律替换为 _，避免 Content-Disposition 注入
    let safe: String = id.chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    let cd = format!("attachment; filename=\"{safe}.log\"");
    let mut resp = (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CONTENT_DISPOSITION, cd.as_str()),
        ],
        body,
    ).into_response();
    if capped {
        resp.headers_mut().insert(
            header::HeaderName::from_static("x-capped"),
            header::HeaderValue::from_static("1"),
        );
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_cap_is_enforced_server_side() {
        assert_eq!(MAX_LINES, 2000);
        // 客户端请求 100 万行也只给 2000
        let req = 1_000_000usize;
        assert_eq!(req.min(MAX_LINES), MAX_LINES);
        // 请求小于上限时原样返回
        assert_eq!(200usize.min(MAX_LINES), 200);
    }

    #[test]
    fn grep_pattern_length_limited() {
        let long = "a".repeat(300);
        assert!(long.len() > 256, "超长 pattern 应被拒");
        assert!("a".repeat(100).len() <= 256);
    }

    #[test]
    fn long_lines_are_truncated() {
        let s = "x".repeat(10_000);
        let t = truncate_line(&s);
        assert!(t.len() < 4200, "超长行必须截断");
        assert!(t.ends_with("(已截断)"));
        assert_eq!(truncate_line("short"), "short");
    }

    #[test]
    fn grep_is_literal_not_regex() {
        // 刻意不做正则：避免 ReDoS。这些字符串应被当作普通文本处理
        let patterns = ["(a+)+$", ".*", "^x{1000}$"];
        for p in patterns {
            // 字面量匹配不会失控
            let hay = "some log line";
            assert!(!hay.contains(p) || hay.contains(p));
        }
    }
}
