//! 拦截事件（WAF 页「威胁日志」）。
//!
//! 采集器周期性读取「开了独立 access log」的站点日志，把被拦截/拒绝的请求
//! （HTTP 403 / 405 / 429）按 nginx **combined** 格式解析成结构化事件落库；
//! 查询端供前端列表 / 筛选。
//!
//! # 三条必须写清的边界
//! - **无规则级归因**：WAF 规则 / 敏感文件拒绝 / IP 黑名单在 nginx 与 caddy 里都返回
//!   同色 403，access log 无标记可区分。故只存状态码，UI 诚实说明"无法区分是哪条规则"。
//! - **只覆盖开了独立 access log 的站点**（`log_access` 列）：没开的站点没有日志可采。
//! - 采集是**增量 + 断点续传**：偏移记已消费字节，只推进到最后一个完整行（半行留到下轮），
//!   文件变小（轮转/截断）则从头读。
//!
//! # 无额外依赖
//! combined 解析与 time_local→unix 全部手写（依赖预算已满，不引 regex / chrono）。
//! 时间换算用 Howard Hinnant 的 days_from_civil（有单测钉住 1970/2026 两个已知值）。

use crate::{
    auth::perm,
    error::{ok, ApiResult},
    routes::{Auth, Shared},
};
use axum::{
    extract::{Query, State},
    Json,
};
use panel_core::{PanelError, Result};
use serde::Deserialize;

/// 事件保留天数：采集时顺带清理更早的事件，防无界增长。
const RETENTION_DAYS: i64 = 30;
/// 视为"被拦截/拒绝"的状态码：403 拦截/拒绝、405 方法被拒（严格档）、429 限速。
const BLOCK_STATUSES: [u16; 3] = [403, 405, 429];
/// 单轮单站最多读的新字节数：防站点被刷时首读就把内存/写事务撑爆，余量下一轮续。
const MAX_READ_BYTES: u64 = 1024 * 1024;

// ─────────────────────────── combined 格式解析 ───────────────────────────

/// combined 格式一行解析后的字段。
struct AccessLine {
    remote_addr: String,
    ts: i64,
    method: String,
    uri: String,
    status: u16,
    referer: String,
    user_agent: String,
}

/// 取第一个空白分隔的 token，返回 (token, 关闭空白后的剩余)。
fn next_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(char::is_whitespace) {
        Some(i) => Some((&s[..i], &s[i..])),
        None => Some((s, "")),
    }
}

/// 读一个双引号字段（处理 `\"` 与 `\\` 转义），返回 (反转义内容, 关闭引号后的剩余)。
fn read_quoted(s: &str) -> Option<(String, &str)> {
    let inner = s.trim_start().strip_prefix('"')?;
    let mut out = String::new();
    let mut it = inner.char_indices();
    while let Some((i, c)) = it.next() {
        match c {
            '"' => return Some((out, &inner[i + 1..])),
            '\\' => {
                // 反转义：吃掉下一字符原样放入（\" → "，\\ → \）
                if let Some((_, nc)) = it.next() {
                    out.push(nc);
                }
            }
            _ => out.push(c),
        }
    }
    None // 没有关闭引号
}

/// `"METHOD URI PROTOCOL"` → (method, uri)。method = 首个 token、protocol = 末个 token、
/// **uri = 中间全部**——URI 含空格也完整保留（攻击载荷常把 SQLi 写在路径里，截断就丢了关键信息）。
/// 字段不足时 uri 取整串、method 空。
fn split_request(req: &str) -> (String, String) {
    let Some((method, rest)) = req.split_once(' ') else {
        return (String::new(), req.to_string());
    };
    let uri = match rest.rsplit_once(' ') {
        Some((u, _proto)) => u,
        None => rest,
    };
    (method.to_string(), uri.to_string())
}

fn month_num(m: &str) -> Option<i64> {
    Some(match m {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    })
}

/// `+0800` / `-0500` → 偏移秒数。
fn parse_tz(tz: &str) -> Option<i64> {
    let sign = match tz.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let d = &tz[1..];
    if d.len() != 4 {
        return None;
    }
    let hh: i64 = d[..2].parse().ok()?;
    let mm: i64 = d[2..].parse().ok()?;
    Some(sign * (hh * 3600 + mm * 60))
}

/// 民用历 → 天数（Howard Hinnant `days_from_civil`），无依赖。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;                                        // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                // [0, 146096]
    era * 146097 + doe - 719468
}

/// nginx `time_local`：`dd/Mon/yyyy:HH:MM:SS +ZZZZ`（本地时区）→ unix 秒（UTC）。
fn parse_time_local(s: &str) -> Option<i64> {
    let (dt, tz) = s.split_once(' ')?;
    let (date_part, time_part) = dt.split_once(':')?;
    let mut dp = date_part.split('/');
    let day: i64 = dp.next()?.parse().ok()?;
    let mon = month_num(dp.next()?)?;
    let year: i64 = dp.next()?.parse().ok()?;
    let mut tp = time_part.split(':');
    let hh: i64 = tp.next()?.parse().ok()?;
    let mm: i64 = tp.next()?.parse().ok()?;
    let ss: i64 = tp.next()?.parse().ok()?;
    let off = parse_tz(tz)?;
    Some(days_from_civil(year, mon, day) * 86400 + hh * 3600 + mm * 60 + ss - off)
}

/// 解析 nginx combined 格式一行；无法识别返回 None（调用方跳过，不当错误）。
///
/// 形如：`1.2.3.4 - - [16/Oct/2026:15:38:00 +0800] "GET /.env HTTP/1.1" 403 152 "-" "curl/7.81.0"`
fn parse_combined(line: &str) -> Option<AccessLine> {
    let (remote_addr, rest) = next_token(line)?;
    let (_ident, rest) = next_token(rest)?; // 通常 "-"
    let (_user, rest) = next_token(rest)?; // remote_user，"-" 或用户名
    let inner = rest.trim_start().strip_prefix('[')?;
    let close = inner.find(']')?;
    let ts = parse_time_local(&inner[..close])?;
    let rest = &inner[close + 1..];
    let (request, rest) = read_quoted(rest.trim_start())?;
    let (status_s, rest) = next_token(rest.trim_start())?;
    let (_bytes, rest) = next_token(rest.trim_start())?;
    let (referer, rest) = read_quoted(rest.trim_start())?;
    let (user_agent, _rest) = read_quoted(rest.trim_start())?;
    let status: u16 = status_s.parse().ok()?;
    let (method, uri) = split_request(&request);
    Some(AccessLine { remote_addr: remote_addr.to_string(), ts, method, uri, status, referer, user_agent })
}

// ─────────────────────────── 采集器 ───────────────────────────

/// 采集一轮：读各开日志站点的 access log 增量，落 403/405/429 事件、推进偏移、清理旧事件。
///
/// 由内部周期任务 `waf.collect` 调用（单线程、无并发，故偏移读-改-写不会竞态）。
pub async fn collect_block_events(state: &Shared) -> Result<()> {
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    // 1. 开了独立 access log 的站点
    let sites: Vec<(String, String)> = state
        .pool
        .with(|conn| {
            let mut stmt = conn
                .prepare("SELECT name, domains FROM sites WHERE log_access != 0")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| PanelError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await?;

    // 2. 读采集偏移
    let offsets: HashMap<String, i64> = state
        .pool
        .with(|conn| {
            let mut stmt = conn
                .prepare("SELECT site, offset FROM block_collect_offset")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .map_err(|e| PanelError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(rows.into_iter().collect())
        })
        .await?;

    let now = now_unix();
    for (name, domains_json) in &sites {
        let domains: Vec<String> = serde_json::from_str(domains_json).unwrap_or_default();
        let Some(path) = crate::routes::sites::site_log_paths(state, &domains, true, false).0 else { continue };
        let start = offsets.get(name).copied().unwrap_or(0).max(0) as u64;

        // 3. seek 到偏移，只读新字节（上限 MAX_READ_BYTES）；文件不存在/读失败 → 跳过本轮
        let read = match tokio::fs::File::open(&path).await {
            Ok(mut f) => {
                let len = match f.metadata().await {
                    Ok(m) => m.len(),
                    Err(_) => continue,
                };
                let start = if len < start { 0 } else { start }; // 轮转/截断 → 从头
                if f.seek(std::io::SeekFrom::Start(start)).await.is_err() {
                    continue;
                }
                let mut buf = vec![0u8; ((len - start).min(MAX_READ_BYTES)) as usize];
                match f.read_exact(&mut buf).await {
                    Ok(_) => Some((start, buf)),
                    Err(_) => None, // 读取中被轮转等 → 跳过本轮
                }
            }
            Err(_) => None,
        };
        let Some((start, buf)) = read else { continue };

        // 只处理到最后一个完整行；半行留到下轮（偏移不越过它）
        let consumed = match buf.iter().rposition(|&b| b == b'\n') {
            Some(i) => (i + 1) as u64,
            None => 0,
        };
        if consumed == 0 {
            continue;
        }
        let new_offset = start + consumed;
        let text = String::from_utf8_lossy(&buf[..consumed as usize]);

        // 4. 收集 403/405/429 事件
        let mut evs: Vec<(i64, String, String, String, i64, String, String)> = Vec::new();
        for line in text.lines() {
            if let Some(a) = parse_combined(line) {
                if BLOCK_STATUSES.contains(&a.status) {
                    evs.push((a.ts, a.remote_addr, a.method, a.uri, a.status as i64, a.referer, a.user_agent));
                }
            }
        }

        // 5. 写事件 + 推进偏移 + 清理旧事件。偏移恒推进——非拦截行不堆积、也不会漏（半行留痕）。
        let name_c = name.clone();
        let cutoff = now - RETENTION_DAYS * 86400;
        state
            .db
            .exec(move |conn| {
                for (ts, addr, method, uri, status, referer, ua) in &evs {
                    conn.execute(
                        "INSERT INTO block_events(site, ts, remote_addr, method, uri, status, referer, user_agent) \
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        rusqlite::params![name_c, ts, addr, method, uri, status, referer, ua],
                    )
                    .map_err(|e| PanelError::Database(e.to_string()))?;
                }
                conn.execute(
                    "INSERT OR REPLACE INTO block_collect_offset(site, offset) VALUES(?1, ?2)",
                    rusqlite::params![name_c, new_offset],
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
                conn.execute("DELETE FROM block_events WHERE ts < ?1", rusqlite::params![cutoff])
                    .map_err(|e| PanelError::Database(e.to_string()))?;
                Ok(panel_db::WriteAck { rows_changed: evs.len() })
            })
            .await?;
    }
    Ok(())
}

// ─────────────────────────── 查询 ───────────────────────────

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub site: Option<String>,
    pub status: Option<u16>,
    pub since: Option<i64>, // unix 秒下限
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// 拦截事件列表（读需 `site.view`）。按站点 / 状态 / 时间过滤 + 分页，最新在前。
///
/// 过滤项用**固定 SQL + 可空参数**（`? IS NULL OR col = ?`）表达——禁 format! 拼 SQL
/// （分层门禁），又能优雅支持"不传即不过滤"。
pub async fn list_events(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500) as i64;
    let offset = q.offset.unwrap_or(0) as i64;
    let items: Vec<serde_json::Value> = state
        .pool
        .with(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, site, ts, remote_addr, method, uri, status, referer, user_agent FROM block_events \
                     WHERE (?1 IS NULL OR site = ?1) AND (?2 IS NULL OR status = ?2) AND (?3 IS NULL OR ts >= ?3) \
                     ORDER BY ts DESC, id DESC LIMIT ?4 OFFSET ?5",
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(
                    rusqlite::params![q.site, q.status.map(|s| s as i64), q.since, limit, offset],
                    |r| {
                        Ok(serde_json::json!({
                            "id": r.get::<_, i64>(0)?,
                            "site": r.get::<_, String>(1)?,
                            "ts": r.get::<_, i64>(2)?,
                            "remote_addr": r.get::<_, String>(3)?,
                            "method": r.get::<_, String>(4)?,
                            "uri": r.get::<_, String>(5)?,
                            "status": r.get::<_, i64>(6)?,
                            "referer": r.get::<_, String>(7)?,
                            "user_agent": r.get::<_, String>(8)?,
                        }))
                    },
                )
                .map_err(|e| PanelError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await?;
    Ok(ok(serde_json::Value::Array(items)))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_combined_line() {
        let line = r#"1.2.3.4 - - [16/Oct/2026:15:38:00 +0800] "GET /.env HTTP/1.1" 403 152 "-" "curl/7.81.0""#;
        let a = parse_combined(line).expect("应解析成功");
        assert_eq!(a.remote_addr, "1.2.3.4");
        assert_eq!(a.method, "GET");
        assert_eq!(a.uri, "/.env");
        assert_eq!(a.status, 403);
        assert_eq!(a.referer, "-");
        assert_eq!(a.user_agent, "curl/7.81.0");
        // 15:38 +0800 = 07:38 UTC
        assert_eq!(a.ts, 20742 * 86400 + 7 * 3600 + 38 * 60);
    }

    #[test]
    fn user_agent_with_spaces_and_quotes() {
        // UA 含空格与转义引号；referer 是完整 URL
        let line = r#"10.0.0.9 - alice [01/Jan/2026:00:00:00 +0000] "POST /api?q=1 OR 1=1 HTTP/2.0" 403 0 "https://ex.com/a b" "Mozilla/5.0 (X11) \"Weird\" Bot""#;
        let a = parse_combined(line).expect("UA 含转义引号也应解析");
        assert_eq!(a.remote_addr, "10.0.0.9");
        assert_eq!(a.method, "POST");
        assert_eq!(a.uri, "/api?q=1 OR 1=1"); // splitn(3)：uri 不含协议
        assert_eq!(a.status, 403);
        assert_eq!(a.referer, "https://ex.com/a b");
        assert_eq!(a.user_agent, "Mozilla/5.0 (X11) \"Weird\" Bot");
        // 2026-01-01 00:00:00 +0000
        assert_eq!(a.ts, days_from_civil(2026, 1, 1) * 86400);
    }

    #[test]
    fn days_from_civil_known_values() {
        assert_eq!(days_from_civil(1970, 1, 1), 0, "Unix 纪元");
        // 2026-01-01 与 2026-10-16 相差天数已知（非闰年边界内）
        assert_eq!(days_from_civil(2026, 1, 1) - days_from_civil(1970, 1, 1), 20454);
    }

    #[test]
    fn tz_offset_signs() {
        assert_eq!(parse_tz("+0800"), Some(8 * 3600));
        assert_eq!(parse_tz("-0500"), Some(-5 * 3600));
        assert_eq!(parse_tz("+0000"), Some(0));
        assert_eq!(parse_tz("bad"), None);
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(parse_combined("").is_none(), "空行");
        assert!(parse_combined("garbage no brackets here").is_none(), "无 [] 时间");
        assert!(parse_combined(r#"1.2.3.4 - - [16/Oct/2026:15:38:00 +0800] "GET / HTTP/1.1" abc 0 "-" "-""#).is_none(), "状态码非数字");
        assert!(parse_combined(r#"1.2.3.4 - - [not-a-time] "GET / HTTP/1.1" 200 0 "-" "-""#).is_none(), "时间非法");
    }

    #[test]
    fn block_status_classification() {
        // 只有 403/405/429 算拦截；200/301/500 不算
        for st in [403u16, 405, 429] {
            assert!(BLOCK_STATUSES.contains(&st));
        }
        for st in [200u16, 301, 404, 500, 502] {
            assert!(!BLOCK_STATUSES.contains(&st));
        }
    }
}
