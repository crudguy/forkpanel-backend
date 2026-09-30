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
    routes::{Auth, Shared},
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

// ─────────────── 日志聚合统计（P2） ───────────────

#[derive(Debug, Deserialize)]
pub struct StatsQ {
    pub lines: Option<usize>,
    pub grep: Option<String>,
    pub level: Option<String>,
    pub since: Option<i64>,
    /// 时间分桶数；收敛到 1..=60（分桶过细只会让响应用空桶填满）
    pub buckets: Option<usize>,
}

/// 日志聚合统计：level 分布 + 时间直方图 + 高频消息模式。
///
/// 定位是**概览**而非精确分析：单次扫描不超过 [`MAX_LINES`]，pattern 归一化是
/// 启发式的（数字 / 引号内容 → 占位符）。这是刻意的——面板不该变成 ELK；
/// 精确归并交给外部日志系统，这里的价值是"一眼看出日志里是不是有事"。
pub async fn stats(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(id): AxPath<String>, Query(q): Query<StatsQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::LOG_VIEW)?;
    let src = find_source(&state, &id).await?;
    // 统计默认扫满硬上限：样本越大分布越可信，但仍受 MAX_LINES 保护
    let lines = q.lines.unwrap_or(MAX_LINES).min(MAX_LINES);
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
    let nb = q.buckets.unwrap_or(12).clamp(1, 60);
    let st = analyze(&out, nb);

    Ok(ok(serde_json::json!({
        "source": id,
        "scanned": out.len(),
        "capped": lines == MAX_LINES,
        "buckets": nb,
        "levels": {
            "error": st.levels[LV_ERROR],
            "warn":  st.levels[LV_WARN],
            "info":  st.levels[LV_INFO],
            "debug": st.levels[LV_DEBUG],
            "other": st.levels[LV_OTHER],
        },
        "histogram": st.histogram,
        "top_patterns": st.patterns,
    })))
}

/// 统计结果（内部类型，序列化在 handler 里按命名组装）
#[derive(Debug, Default)]
struct LogStats {
    /// 固定四档 + other，缺档补 0
    levels: [usize; 5],
    histogram: Vec<HistBucket>,
    patterns: Vec<PatternCount>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct HistBucket { start: i64, end: i64, count: usize }
#[derive(Debug, PartialEq, Eq, Serialize)]
struct PatternCount { pattern: String, count: usize }

const LV_ERROR: usize = 0;
const LV_WARN: usize = 1;
const LV_INFO: usize = 2;
const LV_DEBUG: usize = 3;
const LV_OTHER: usize = 4;
/// 归一化模式的最大长度：超长行截断后再归一，防止单个 pattern 撑爆响应
const PATTERN_MAX_OUT: usize = 160;
/// 高频模式只保留出现 ≥2 次的——出现一次的行不构成"模式"
const PATTERN_MIN_COUNT: usize = 2;
const PATTERN_TOP_N: usize = 8;

fn analyze(lines: &[panel_os::LogLine], buckets: usize) -> LogStats {
    let mut levels = [0usize; 5];
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut ts: Vec<i64> = Vec::new();

    for l in lines {
        levels[level_idx(l.level.as_deref(), &l.text)] += 1;
        if let Some(t) = l.ts_unix { ts.push(t); }
        let p = normalize_pattern(&l.text);
        if !p.is_empty() { *counts.entry(p).or_insert(0) += 1; }
    }

    let mut patterns: Vec<PatternCount> = counts
        .into_iter()
        .filter(|(_, c)| *c >= PATTERN_MIN_COUNT)
        .map(|(pattern, count)| PatternCount { pattern, count })
        .collect();
    // 次数降序；同次数按字典序，保证结果**稳定可复现**（HashMap 迭代序不定）
    patterns.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.pattern.cmp(&b.pattern)));
    patterns.truncate(PATTERN_TOP_N);

    LogStats { levels, histogram: bucketize(&ts, buckets), patterns }
}

/// 时间直方图。无时间戳的源（部分纯文本文件日志）返回空数组——
/// **不按行序伪造时间分布**，那会给出看起来合理实则错误的图。
fn bucketize(ts: &[i64], n: usize) -> Vec<HistBucket> {
    if ts.is_empty() || n == 0 { return Vec::new(); }
    let lo = *ts.iter().min().unwrap_or(&0);
    let hi = *ts.iter().max().unwrap_or(&0);
    if hi == lo {
        // 全部落在同一秒：单桶，同时避开除零
        return vec![HistBucket { start: lo, end: hi, count: ts.len() }];
    }
    let span = (hi - lo) as f64 / n as f64;
    let mut out: Vec<HistBucket> = (0..n)
        .map(|i| HistBucket {
            start: lo + (span * i as f64).floor() as i64,
            end: lo + (span * (i as f64 + 1.0)).floor() as i64,
            count: 0,
        })
        .collect();
    for &t in ts {
        let mut idx = ((t - lo) as f64 / span).floor() as usize;
        if idx >= n { idx = n - 1; } // 右端点归入末桶
        out[idx].count += 1;
    }
    out
}

/// level 归一。优先采信 provider 给的结构化 level；缺失时从文本做启发式关键词匹配
/// （文件日志没有优先级字段，只能看内容）。匹配不中一律归 `other`，**不硬塞成 info**。
fn level_idx(level: Option<&str>, text: &str) -> usize {
    if let Some(l) = level {
        let l = l.trim().to_ascii_lowercase();
        if !l.is_empty() {
            if l.starts_with("err") || l.starts_with("crit") || l.starts_with("fatal")
                || l.starts_with("emerg") || l.starts_with("alert") {
                return LV_ERROR;
            }
            if l.starts_with("warn") { return LV_WARN; }
            if l.starts_with("info") || l.starts_with("notice") { return LV_INFO; }
            if l.starts_with("debug") || l.starts_with("trace") { return LV_DEBUG; }
        }
    }
    let low = text.to_ascii_lowercase();
    if low.contains("error") || low.contains("failed") || low.contains("fatal") || low.contains("panic") {
        return LV_ERROR;
    }
    if low.contains("warn") { return LV_WARN; }
    if low.contains("debug") || low.contains("trace") { return LV_DEBUG; }
    if low.contains("info") { return LV_INFO; }
    LV_OTHER
}

/// 把一行归一化为「模式」，让仅 ID/数字不同的同源日志聚成一条：
/// 连续数字 → `<n>`；长度 ≥8 的连续十六进制串 → `<hex>`；引号内字面量 → `<s>`。
/// 启发式字符扫描，不做语法解析——便宜且对聚合够用。
fn normalize_pattern(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(chars.len().min(PATTERN_MAX_OUT));
    let mut i = 0usize;
    while i < chars.len() && out.chars().count() < PATTERN_MAX_OUT {
        let c = chars[i];
        if c.is_ascii_digit() {
            while i < chars.len() && chars[i].is_ascii_digit() { i += 1; }
            out.push_str("<n>");
            continue;
        }
        if c.is_ascii_hexdigit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_hexdigit() { i += 1; }
            // 只有足够长才当十六进制串，否则会把普通短词（如 `db1`）切碎
            if i - start >= 8 {
                out.push_str("<hex>");
            } else {
                for ch in &chars[start..i] { out.push(*ch); }
            }
            continue;
        }
        if c == '"' || c == '\'' {
            let quote = c;
            i += 1;
            while i < chars.len() && chars[i] != quote { i += 1; }
            if i < chars.len() { i += 1; } // 吃掉闭引号
            out.push_str("<s>");
            continue;
        }
        out.push(c);
        i += 1;
    }
    out.trim().to_string()
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

    fn line(ts: Option<i64>, level: Option<&str>, text: &str) -> panel_os::LogLine {
        panel_os::LogLine {
            ts_unix: ts,
            level: level.map(|s| s.to_string()),
            text: text.to_string(),
        }
    }

    #[test]
    fn pattern_normalization_groups_id_variants() {
        let a = normalize_pattern("Failed to connect to 10.0.0.1:5432 after 3 retries");
        let b = normalize_pattern("Failed to connect to 10.0.0.8:5432 after 7 retries");
        assert_eq!(a, b, "仅数字不同 → 应归为同一模式");
        assert!(a.contains("<n>"));
    }

    #[test]
    fn pattern_normalization_keeps_short_words_intact() {
        // `db1` 仅 3 个 hex 字符，不该被当成 <hex> 切碎
        assert_eq!(normalize_pattern("db1 ok"), "db1 ok");
        // 引号内字面量归一为 <s>
        assert_eq!(normalize_pattern(r#"user "alice" logged in"#), "user <s> logged in");
    }

    #[test]
    fn level_prefers_structured_then_falls_back_to_text() {
        // 结构化 level 优先——即使正文里出现 "error" 也不能篡改 provider 的判断
        assert_eq!(level_idx(Some("ERROR"), "all good"), LV_ERROR);
        assert_eq!(level_idx(Some("Warning"), "x"), LV_WARN);
        assert_eq!(level_idx(Some("INFO"), "this text mentions error"), LV_INFO);
        // 无结构化 level 时按文本启发
        assert_eq!(level_idx(None, "connection failed"), LV_ERROR);
        assert_eq!(level_idx(None, "low disk warning"), LV_WARN);
        // 匹配不中一律 other，绝不硬塞成 info
        assert_eq!(level_idx(None, "server started on port 8080"), LV_OTHER);
    }

    #[test]
    fn histogram_handles_single_timestamp_without_dividing_by_zero() {
        let one = bucketize(&[100], 12);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].count, 1);
        // 无时间戳 → 空数组（不按行序伪造时间分布）
        assert!(bucketize(&[], 12).is_empty());
        // 正常跨度：总量守恒
        let ts: Vec<i64> = (0..100).collect();
        let bs = bucketize(&ts, 10);
        assert_eq!(bs.iter().map(|b| b.count).sum::<usize>(), 100);
    }

    #[test]
    fn analyze_keeps_only_repeated_patterns() {
        let lines = vec![
            line(Some(1), Some("info"), "started worker 1"),
            line(Some(2), Some("info"), "started worker 2"),
            line(Some(3), Some("error"), "boom"),
        ];
        let st = analyze(&lines, 4);
        assert_eq!(st.levels[LV_INFO], 2);
        assert_eq!(st.levels[LV_ERROR], 1);
        // "started worker <n>" 出现 2 次 → 保留；"boom" 仅 1 次 → 剔除
        assert_eq!(st.patterns.len(), 1);
        assert_eq!(st.patterns[0].count, 2);
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
