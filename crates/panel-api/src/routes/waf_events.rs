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
//! combined 解析与 time_local→unix 全部手写（依赖预算上限 38、去重后现约 22，不引 regex / chrono）。
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
    /// 命中归因（新增字段，**可缺**）：面板自定义 log_format 在 combined 末尾多一个
    /// `"$fw_hit"`。老站点（尚未重新应用配置）的日志仍是纯 combined，此时为空串。
    /// 容错解析而不是强制要求——收紧成必需会让升级瞬间已有的日志全部采集失败。
    rule: String,
}

/// 待落库的拦截事件。用具名结构体而不是 8 元组：字段一多，元组里的
/// `String` 顺序就纯靠位置记忆，插入新字段极易把 referer 和 UA 写反，
/// 而两者都是字符串、编译期完全无法发现（clippy 的 type_complexity 也在提醒这件事）。
struct PendingEvent {
    ts: i64,
    remote_addr: String,
    method: String,
    uri: String,
    status: i64,
    referer: String,
    user_agent: String,
    /// 已映射的中文规则名；未知标记原样保留，空串＝未归因
    rule: String,
}

/// `$fw_hit` 标记 → 用户可读的规则名。
///
/// ⚠ 这些字符串与 `panel-os` 渲染器里的 `set $fw_hit "<name>"` **一一对应**，
/// 改一边必须改另一边（`waf_hit_tags_round_trip` 单测在 panel-os 侧钉住）。
/// 未知标记原样透出（不吞掉）：将来加规则而忘了登记时，UI 会显示原始标记，
/// 比静默显示"未知"更容易发现问题。
fn rule_label(tag: &str) -> Option<&'static str> {
    match tag.trim_matches('"') {
        "" => None,
        "waf_ua" => Some("恶意 UA"),
        "waf_sqli" => Some("SQL 注入"),
        "waf_xss" => Some("XSS"),
        "waf_trav" => Some("路径穿越"),
        "waf_noua" => Some("空 UA"),
        "waf_method" => Some("非常见方法"),
        "waf_hidden" => Some("隐藏文件"),
        "waf_repo" => Some("版本库目录"),
        "waf_backup" => Some("备份文件"),
        "waf_path" => Some("敏感路径"),
        "ip_allow" => Some("IP 白名单外"),
        "ip_deny" => Some("IP 黑名单"),
        _ => None,
    }
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
///
/// 跨模块复用于审计导出（`audit.rs` 把 unix 秒格式化成可读时间）：
/// 同一份历法换算只应存在一处，否则某个边缘日期会在两个出口给出不同结果。
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;                                        // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                // [0, 146096]
    era * 146097 + doe - 719468
}

/// 天数 → 民用历 `(y, m, d)`（Howard Hinnant `civil_from_days`，`days_from_civil` 的逆）。
pub(crate) fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;                                            // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;       // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                     // [0, 365]
    let mp = (5 * doy + 2) / 153;                                          // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1;                                  // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 };                         // [1, 12]
    ((if m <= 2 { y + 1 } else { y }), m, d)
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
    let (user_agent, rest) = read_quoted(rest.trim_start())?;
    // 第五个带引号字段 = `$fw_hit`（面板自定义格式）；纯 combined 没有它 → 空串。
    let rule = read_quoted(rest.trim_start()).map(|(r, _)| r.to_string()).unwrap_or_default();
    let status: u16 = status_s.parse().ok()?;
    let (method, uri) = split_request(&request);
    Some(AccessLine { remote_addr: remote_addr.to_string(), ts, method, uri, status, referer, user_agent, rule })
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
        let mut evs: Vec<PendingEvent> = Vec::new();
        for line in text.lines() {
            if let Some(a) = parse_combined(line) {
                if BLOCK_STATUSES.contains(&a.status) {
                    // 归因标记落成用户可读标签；未知标记原样保留（便于发现漏登记）。
                    let rule = match rule_label(&a.rule) {
                        Some(label) => label.to_string(),
                        None => a.rule.trim().trim_matches('"').to_string(),
                    };
                    evs.push(PendingEvent {
                        ts: a.ts,
                        remote_addr: a.remote_addr,
                        method: a.method,
                        uri: a.uri,
                        status: a.status as i64,
                        referer: a.referer,
                        user_agent: a.user_agent,
                        rule,
                    });
                }
            }
        }

        // 5. 写事件 + 推进偏移 + 清理旧事件。偏移恒推进——非拦截行不堆积、也不会漏（半行留痕）。
        let name_c = name.clone();
        let cutoff = now - RETENTION_DAYS * 86400;
        state
            .db
            .exec(move |conn| {
                for e in &evs {
                    conn.execute(
                        "INSERT INTO block_events(site, ts, remote_addr, method, uri, status, referer, user_agent, rule) \
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        rusqlite::params![
                            name_c,
                            e.ts,
                            e.remote_addr,
                            e.method,
                            e.uri,
                            e.status,
                            e.referer,
                            e.user_agent,
                            e.rule
                        ],
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

    // 采集后做阈值告警检查（旁路：失败不影响采集结果）
    crate::routes::waf_alert::check_block_alerts(state).await;
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
                    "SELECT id, site, ts, remote_addr, method, uri, status, referer, user_agent, rule FROM block_events \
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
                            // 空串 = 未归因（老配置未重渲染，或该请求不是被规则拦的）
                            "rule": r.get::<_, String>(9)?,
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

use panel_core::now_unix;

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
        // 纯 combined 没有 $fw_hit 字段：必须解析成功、归因为空串（不能因缺字段就丢弃整行，
        // 否则升级瞬间还没重渲染的老站点日志会被整片跳过）
        assert_eq!(a.rule, "", "纯 combined 的归因应为空串而非解析失败");
        // 15:38 +0800 = 07:38 UTC
        assert_eq!(a.ts, 20742 * 86400 + 7 * 3600 + 38 * 60);
    }

    /// 面板自定义格式（combined + `"$fw_hit"`）：末位字段要能读出来。
    #[test]
    fn parses_line_with_hit_tag() {
        let line = r#"1.2.3.4 - - [16/Oct/2026:15:38:00 +0800] "GET /?q=1+union+select HTTP/1.1" 403 152 "-" "sqlmap/1.7" "waf_sqli""#;
        let a = parse_combined(line).expect("带归因字段的行也应解析");
        assert_eq!(a.status, 403);
        assert_eq!(a.user_agent, "sqlmap/1.7", "UA 不能被归因字段吞掉");
        assert_eq!(a.rule, "waf_sqli");
        assert_eq!(rule_label(&a.rule), Some("SQL 注入"));
    }

    /// 归因标记 → 标签的映射：空串不冒认、未知标记不吞掉（留给 UI 显示原始值）。
    #[test]
    fn rule_label_maps_known_and_keeps_unknown() {
        assert_eq!(rule_label(""), None, "空串=未归因，绝不能当成某条规则");
        assert_eq!(rule_label("waf_hidden"), Some("隐藏文件"));
        assert_eq!(rule_label("ip_deny"), Some("IP 黑名单"));
        assert_eq!(rule_label("brand_new_rule"), None, "未知标记应原样透出");
    }

    /// ⚠ 跨 crate 契约：渲染器写出的 `$fw_hit` 标记，必须全部能被这里读懂。
    /// 两处字符串分别住在 panel-os / panel-api，改一边漏另一边会**静默**退化成
    /// 「未知标记」——这条测试是唯一的交叉校验点。
    ///
    /// 扫描口径：渲染器有两种写法——① 字面量 `set $fw_hit "ip_allow";`；
    /// ② 辅助闭包 `hit("waf_ua")`（闭包里 format! 展开）。**不能直接扫
    /// `set $fw_hit \"`**：那会把闭包自身的 `format!("…{name}…")` 当成标记名。
    #[test]
    fn every_emitted_hit_tag_is_mapped() {
        let src = panel_testutil::production_source(
            include_str!("../../../panel-os/src/linux/providers/webserver.rs"),
        );
        let mut tags: Vec<String> = Vec::new();

        // ① 字面量写法
        for cap in src.split("set $fw_hit \\\"").skip(1) {
            let tag: String = cap.chars().take_while(|c| *c != '"' && *c != '\\').collect();
            if !tag.is_empty() && !tag.starts_with('{') {
                tags.push(tag);
            }
        }
        // ② 闭包调用写法（源码文本是 `hit("waf_sqli")`——单个反斜杠都没有，
        // 所以分隔串就是 `hit("` 这五个字符；写成 `hit(\"` 会一个都匹配不到）
        for cap in src.split("hit(\"").skip(1) {
            let tag: String = cap.chars().take_while(|c| *c != '"' && *c != '\\').collect();
            if !tag.is_empty() {
                tags.push(tag);
            }
        }

        tags.sort();
        tags.dedup();
        assert!(tags.len() >= 12, "应扫到全部 12 个归因标记，实际 {:?}", tags);
        for tag in &tags {
            assert!(
                rule_label(tag).is_some(),
                "渲染器写出了 {tag}，但 rule_label() 不认识它（两处字符串已漂移）"
            );
        }
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
