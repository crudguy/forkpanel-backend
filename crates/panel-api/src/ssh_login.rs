//! SSH 登录 / 爆破记录：从**统一日志源**（journald）解析 sshd 事件。
//!
//! 为什么不直接读 `/var/log/auth.log`：Debian 13 默认只有 journald，文件由
//! rsyslog 额外落盘，装不装不确定。统一日志源已经做了「journald 优先」探测，
//! 这里复用 `LogProvider::read()`，既不在业务层写 journalctl 命令行，也不会
//! 在文件后端上假装能读结构化时间（`ts_unix` 为 None 时如实记 0）。
//!
//! 解析是纯函数，测试用**真实 journal 消息样本**（不是手写理想串）：
//!   - `Failed password for invalid user systemd from 192.168.1.80 port 58930 ssh2`
//!   - `pam_unix(sshd:auth): authentication failure; ... rhost=192.168.1.80`
//!   - `Connection closed by invalid user systemd 192.168.1.80 port 56898 [preauth]`
//!   - `Accepted publickey for admin from 192.168.1.80 port 59001 ssh2`
//!
//! 爆破判定按 IP + 时间窗聚合，不靠关键词猜：同一来源在 300s 内失败 >= 5 次
//! 才升级为 `brute_force`。时间未知（文件源）时不参与聚合——宁可漏标，也不能
//! 把无时间戳的日志全塞进同一个窗口造成误报。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// 爆破聚合窗口（秒）。
pub const WINDOW_SECS: i64 = 300;
/// 窗口内失败次数达到该值才算爆破。
pub const BRUTE_THRESHOLD: usize = 5;
/// 单次读取 journal 的上限（与 LogQuery 的服务端硬限制一致）。
pub const FETCH_LINES: usize = 2000;

/// 一条 SSH 登录事件。`result` / `risk` 用稳定英文值落库，中文标签在前端映射。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SshLoginEvent {
    /// 事件秒级时间戳；日志源无结构化时间时为 0（前端显示「—」）。
    pub ts_unix: i64,
    pub ip: String,
    pub user: String,
    /// `success` | `failed`
    pub result: String,
    /// `none` | `failed_password` | `invalid_user` | `root_attempt` | `root_login` | `brute_force`
    pub risk: String,
    /// 原始日志摘要（截断到 300 字符），便于核对判定是否准确。
    pub detail: String,
}

/// 查询筛选。字符串筛选一律**字面量子串**（不做正则，避免 ReDoS）。
#[derive(Debug, Default, Deserialize)]
pub struct SshLoginFilter {
    pub ip: Option<String>,
    pub user: Option<String>,
    /// 精确匹配 `success` / `failed`。
    pub result: Option<String>,
    /// 精确匹配 risk 值。
    pub risk: Option<String>,
    pub limit: Option<usize>,
}

/// IP 粗校验：IPv4 点分四段或 IPv6 含冒号。只用于排除 `foo1.2` 这类误提取。
fn looks_like_ip(s: &str) -> bool {
    if s.is_empty() || !s.as_bytes()[0].is_ascii_digit() {
        return false;
    }
    if s.contains(':') {
        return s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    }
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// 从日志文本里取来源 IP。顺序按真实日志里出现的形态排，命中即返回。
fn extract_ip(s: &str) -> Option<String> {
    // pam_unix 的 `rhost=192.168.1.80`（行尾可能是空格或分隔）
    if let Some(i) = s.find("rhost=") {
        let rest = &s[i + "rhost=".len()..];
        let ip: String = rest.chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
            .collect();
        if looks_like_ip(&ip) { return Some(ip); }
    }
    // `from 192.168.1.80 port 58930`
    if let Some(i) = s.find(" from ") {
        let rest = &s[i + " from ".len()..];
        let ip: String = rest.chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
            .collect();
        if looks_like_ip(&ip) { return Some(ip); }
    }
    // `Connection closed by invalid user systemd 192.168.1.80 port 56898`
    if let Some(i) = s.find(" port ") {
        let head = &s[..i];
        if let Some(sp) = head.rfind(' ') {
            let ip = &head[sp + 1..];
            if looks_like_ip(ip) { return Some(ip.to_string()); }
        }
    }
    // `srclimit_penalise: 192.168.1.80/32: ...`
    for tok in s.split(|c: char| c.is_whitespace() || c == ':') {
        let t = tok.strip_suffix("/32").unwrap_or(tok);
        if looks_like_ip(t) { return Some(t.to_string()); }
    }
    None
}

/// 取用户名。`invalid user` 前缀要剥掉，否则会把「invalid」当成用户名展示。
fn extract_user(s: &str) -> Option<String> {
    if let Some(i) = s.find(" for ") {
        let rest = &s[i + " for ".len()..];
        let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
        let user: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        // 必须后跟 ` from ` 才算登录用户：`for penalty: failed authentication`
        // 这类限流日志里的 "for" 不是用户上下文，不能把 "penalty:" 当用户展示。
        let tail = rest.strip_prefix(user.as_str()).unwrap_or("");
        if !user.is_empty() && user != "invalid" && tail.starts_with(" from ") {
            return Some(user);
        }
    }
    if let Some(i) = s.find(" by invalid user ") {
        let rest = &s[i + " by invalid user ".len()..];
        let user: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        if !user.is_empty() { return Some(user); }
    }
    None
}

/// 判定结果是否满足「登录事件」定义。非登录行（如 `Connection closed`）返回 None，
/// 避免把每条 sshd 调试日志都算成一次爆破。
fn classify(s: &str) -> Option<(&'static str, &'static str)> {
    if s.contains("Accepted password") || s.contains("Accepted publickey") || s.contains("Accepted keyboard-interactive") {
        return Some(("success", "success"));
    }
    if s.contains("Failed password") || s.contains("authentication failure")
        || s.contains("failed authentication") || s.contains("Invalid user ")
        || s.contains("invalid user ") {
        return Some(("failed", "failed"));
    }
    None
}

/// 解析单条 journal 消息。不是 sshd 登录事件时返回 None（调用方跳过）。
pub fn parse_line(text: &str, ts_unix: i64) -> Option<SshLoginEvent> {
    let (result, kind) = classify(text)?;
    let ip = extract_ip(text)?;
    let user = extract_user(text).unwrap_or_else(|| "unknown".into());
    let risk = match (kind, user.as_str(), text.contains("invalid user") || text.contains("Invalid user ")) {
        ("success", "root", _) => "root_login",
        ("success", _, _) => "none",
        (_, "root", _) => "root_attempt",
        (_, _, true) => "invalid_user",
        _ => "failed_password",
    };
    let detail: String = text.chars().take(300).collect();
    Some(SshLoginEvent {
        ts_unix: ts_unix.max(0),
        ip, user, result: result.into(), risk: risk.into(), detail,
    })
}

/// 同一 IP 在窗口内失败达阈值时，把这些失败事件标记为 `brute_force`。
/// 只处理有时间戳的事件；时间未知的文件源不参与，避免误报。
pub fn mark_brute_force(events: &mut [SshLoginEvent]) {
    let mut by_ip: HashMap<String, Vec<(usize, i64)>> = HashMap::new();
    for (i, e) in events.iter().enumerate() {
        if e.result == "failed" && e.ts_unix > 0 {
            by_ip.entry(e.ip.clone()).or_default().push((i, e.ts_unix));
        }
    }
    for (_, mut v) in by_ip {
        v.sort_by_key(|x| x.1);
        let mut left = 0usize;
        for right in 0..v.len() {
            while v[right].1 - v[left].1 > WINDOW_SECS { left += 1; }
            if right + 1 - left >= BRUTE_THRESHOLD {
                for (idx, _) in &v[left..=right] {
                    events[*idx].risk = "brute_force".into();
                }
            }
        }
    }
}

/// 过滤 + 排序 + 限量。返回的是新向量，不改动入参（便于上层算 total）。
pub fn filter_events(events: Vec<SshLoginEvent>, q: &SshLoginFilter) -> Vec<SshLoginEvent> {
    let fip = q.ip.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let fuser = q.user.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let fresult = q.result.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let frisk = q.risk.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);

    let mut out: Vec<SshLoginEvent> = events.into_iter()
        .filter(|e| fip.map(|v| e.ip.contains(v)).unwrap_or(true))
        .filter(|e| fuser.map(|v| e.user.to_ascii_lowercase().contains(&v.to_ascii_lowercase())).unwrap_or(true))
        .filter(|e| fresult.map(|v| e.result == v).unwrap_or(true))
        .filter(|e| frisk.map(|v| e.risk == v).unwrap_or(true))
        .collect();
    out.sort_by(|a, b| b.ts_unix.cmp(&a.ts_unix).then_with(|| a.ip.cmp(&b.ip)));
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实 journald MESSAGE 样本（从本机 `journalctl -u ssh -o json` 取）。
    #[test]
    fn parses_real_journal_messages() {
        let lines = [
            ("sshd-session[1136964]: Failed password for invalid user systemd from 192.168.1.80 port 58930 ssh2", "failed", "systemd", "192.168.1.80", "invalid_user"),
            ("sshd[936]: srclimit_penalise: 192.168.1.80/32: activating ipv4 penalty of 17.607 seconds for penalty: failed authentication", "failed", "unknown", "192.168.1.80", "failed_password"),
            ("sshd-session[1136961]: Connection closed by invalid user systemd 192.168.1.80 port 56898 [preauth]", "failed", "systemd", "192.168.1.80", "invalid_user"),
            ("sshd-session[10]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.80", "failed", "unknown", "192.168.1.80", "failed_password"),
            ("sshd-session[11]: Accepted publickey for admin from 192.168.1.80 port 59001 ssh2", "success", "admin", "192.168.1.80", "none"),
            ("sshd-session[12]: Accepted password for root from 10.0.0.9 port 50001 ssh2", "success", "root", "10.0.0.9", "root_login"),
        ];
        for (text, result, user, ip, risk) in lines {
            let e = parse_line(text, 1_800_000_000).unwrap_or_else(|| panic!("解析失败：{text}"));
            assert_eq!(e.result, result, "结果错：{text}");
            assert_eq!(e.user, user, "用户错：{text}");
            assert_eq!(e.ip, ip, "IP 错：{text}");
            assert_eq!(e.risk, risk, "风险类型错：{text}");
        }
    }

    #[test]
    fn root_failure_is_root_attempt_not_invalid_user() {
        let e = parse_line("sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2", 100).unwrap();
        assert_eq!(e.risk, "root_attempt");
        assert_eq!(e.user, "root");
    }

    #[test]
    fn non_login_ssh_noise_is_skipped() {
        assert!(parse_line("sshd[1]: Server listening on 0.0.0.0 port 22.", 100).is_none());
        assert!(parse_line("sshd[1]: pam_unix(sshd:session): session opened for user admin", 100).is_none());
    }

    #[test]
    fn marks_brute_force_only_within_window_and_threshold() {
        let base = 1_800_000_000;
        let mut events: Vec<SshLoginEvent> = (0..5)
            .map(|i| parse_line(
                &format!("sshd[1]: Failed password for invalid user u from 5.6.7.8 port {i} ssh2"),
                base + i * 30,
            ).unwrap())
            .collect();
        // 另一个 IP 也在同一时刻失败，但不足阈值 → 不得被牵连
        events.push(parse_line("sshd[1]: Failed password for u from 9.9.9.9 port 1 ssh2", base).unwrap());
        // 同 IP 但超出窗口的旧事件 → 不得被算进爆破
        events.push(parse_line("sshd[1]: Failed password for u from 5.6.7.8 port 99 ssh2", base - WINDOW_SECS - 1).unwrap());

        mark_brute_force(&mut events);
        assert_eq!(events[..5].iter().filter(|e| e.risk == "brute_force").count(), 5);
        assert_eq!(events[5].risk, "failed_password", "别 IP 不得被牵连");
        assert_eq!(events[6].risk, "failed_password", "窗口外旧事件不得被算进爆破");
    }

    #[test]
    fn no_timestamp_never_counts_as_brute_force() {
        let mut events: Vec<SshLoginEvent> = (0..8)
            .map(|i| parse_line(
                &format!("sshd[1]: Failed password for u from 5.6.7.8 port {i} ssh2"), 0,
            ).unwrap())
            .collect();
        mark_brute_force(&mut events);
        assert!(events.iter().all(|e| e.risk == "failed_password"), "无时间戳时不得误报爆破");
    }

    #[test]
    fn filter_is_literal_substring_and_exact_enum() {
        let events = vec![
            parse_line("sshd[1]: Failed password for invalid user systemd from 192.168.1.80 port 1 ssh2", 300).unwrap(),
            parse_line("sshd[1]: Accepted publickey for admin from 10.0.0.9 port 2 ssh2", 200).unwrap(),
        ];
        let by_ip = filter_events(events.clone(), &SshLoginFilter { ip: Some("192.168".into()), ..Default::default() });
        assert_eq!(by_ip.len(), 1);
        assert_eq!(by_ip[0].user, "systemd");
        let by_result = filter_events(events.clone(), &SshLoginFilter { result: Some("success".into()), ..Default::default() });
        assert_eq!(by_result.len(), 1);
        assert_eq!(by_result[0].user, "admin");
        let by_risk = filter_events(events.clone(), &SshLoginFilter { risk: Some("invalid_user".into()), ..Default::default() });
        assert_eq!(by_risk.len(), 1);
        // 排序：时间新的在前
        let all = filter_events(events, &SshLoginFilter::default());
        assert_eq!(all[0].ts_unix, 300);
    }

    /// 源码守卫：判据剔注释后仍须钉住「时间未知不聚合」与「字面量子串筛选」，
    /// 防止后人图省事把 `ts_unix > 0` 或 `contains` 改回正则 / 全量聚合。
    #[test]
    fn parsing_rules_are_wired_in_production() {
        let src = panel_testutil::production_source(include_str!("ssh_login.rs"));
        assert!(src.contains("e.ts_unix > 0"), "无时间戳不得参与爆破聚合");
        assert!(src.contains("e.ip.contains(v)"), "IP 筛选须为字面量子串");
        assert!(!src.contains("Regex::new"), "不得引入正则筛选（ReDoS）");
    }
}
