//! 计划任务的 **真实 Linux 实现**（设计方案 §2.8，M5 落地）。
//!
//! 载体：当前面板进程所属用户的系统 crontab（`crontab` / `crontab -l` /
//! `crontab <file>`）。面板停了任务照样跑，表达式语义即 cron 五段。
//!
//! # 安全与边界
//! - **只管理自己写的规则**：每个面板任务前有一行标记
//!   `# panel:cron:<id> user=<user>`；删除/替换只动这些块，绝不触碰用户其他 crontab 内容。
//! - `enabled=false` 通过在 cron 行前加 `# panel:off ` 注释落地——禁用是真禁用，
//!   而不是只改元数据。
//! - 写入走临时文件（0600）→ `crontab <file>`，不碰 stdin（cmd 模块强制 stdin=null）。
//! - 命令原文原样写回，业务层已对 `command` 长度与 `user` 做过校验，这里不再重复。

use crate::cmd::{Bin, CmdOpt};
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{Capability, PanelError, Result};
use std::time::Duration;

/// 标记前缀，后接 `:<id> user=<user>`
const MARK: &str = "# panel:cron:";
/// 禁用行前缀（跟在标记行之后）
const OFF: &str = "# panel:off ";

#[derive(Default)]
pub struct LinuxScheduler;

#[derive(Debug)]
enum Entry {
    Raw(String),
    Job { id: String, user: String, expr: String, command: String, enabled: bool, max_overlap: u32 },
}

fn parse_crontab(lines: &[String]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if let Some(rest) = line.strip_prefix(MARK) {
            // 解析 `# panel:cron:<id> user=<user>`
            let (id, user) = match rest.split_once(" user=") {
                Some((id, user)) => (id.trim().to_string(), user.trim().to_string()),
                None => (rest.trim().to_string(), whoami()),
            };
            if i + 1 < lines.len() {
                let body = &lines[i + 1];
                let (enabled, payload) = if let Some(p) = body.strip_prefix(OFF) {
                    (false, p)
                } else {
                    (true, body.as_str())
                };
                if let Some(job) = parse_job_line(&id, &user, payload, enabled) {
                    out.push(job);
                    i += 2;
                    continue;
                }
            }
            // 标记损坏：当原始行保留，避免误吞
            out.push(Entry::Raw(line.clone()));
            i += 1;
        } else {
            out.push(Entry::Raw(line.clone()));
            i += 1;
        }
    }
    out
}

/// `<expr> <command>` → Job（前 5 段为表达式，其余为命令）。
/// `command` 可能是被 flock 互斥包裹过的形式（P2-3 防重入），这里负责还原。
fn parse_job_line(id: &str, user: &str, payload: &str, enabled: bool) -> Option<Entry> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() < 6 { return None; }   // 5 段 + 至少 1 个命令词
    let expr = parts[..5].join(" ");
    let body = parts[5..].join(" ");
    let (command, max_overlap) = match unwrap_overlap_guard(&body) {
        Some((c, m)) => (c, m),
        None => (body, 1),
    };
    Some(Entry::Job {
        id: id.to_string(),
        user: user.to_string(),
        expr,
        command,
        enabled,
        max_overlap,
    })
}

fn serialize(entries: &[Entry]) -> String {
    let mut s = String::new();
    for e in entries {
        match e {
            Entry::Raw(line) => { s.push_str(line); s.push('\n'); }
            Entry::Job { id, user, expr, command, enabled, max_overlap } => {
                // P2-3 防重入：max_overlap<=1 且宿主有 flock 时，用互斥锁包裹命令。
                // max_overlap==0（不限制）或 >1（OS 级并发计数未实装）→ 裸命令。
                let body = if *max_overlap <= 1 && Bin::Flock.available() {
                    wrap_overlap_guard(id, command)
                } else {
                    command.clone()
                };
                s.push_str(&format!("{MARK}{id} user={user}\n"));
                if *enabled {
                    s.push_str(expr); s.push(' '); s.push_str(&body); s.push('\n');
                } else {
                    s.push_str(OFF); s.push_str(expr); s.push(' '); s.push_str(&body); s.push('\n');
                }
            }
        }
    }
    s
}

/// 把任意字符串安全地包进单引号（内部 `'` → `'\''`），供 `sh -c '<…>'` 嵌入。
/// 这是 POSIX 下嵌入任意文本的标准做法，且与 [`unwrap_overlap_guard`] 互逆。
fn shell_quote_single(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' { out.push_str("'\\''"); } else { out.push(c); }
    }
    out.push('\'');
    out
}

/// 用 flock 互斥锁包裹命令：锁占用时本行直接结束（命令被跳过），`|| true` 压零退出码。
fn wrap_overlap_guard(id: &str, command: &str) -> String {
    format!(
        "flock -n /run/lock/panel-cron-{id} -- sh -c {q} || true", // ci-allow-layering[2]: 生成的是写进 crontab 的命令文本（交给 cron 执行），面板自身不解释 shell
        q = shell_quote_single(command),
    )
}

/// 逆操作：识别本模块生成的 `flock -n /run/lock/panel-cron-<id> -- sh -c '<cmd>' || true`
/// 形式，还原出原始 `command` 与 `max_overlap`(=1)。非该形式返回 None（调用方按裸命令处理）。
fn unwrap_overlap_guard(body: &str) -> Option<(String, u32)> {
    const P: &str = "flock -n /run/lock/panel-cron-";
    let b = body.trim_start();
    if !b.starts_with(P) { return None; }
    let rest = &b[P.len()..];
    let marker = "sh -c "; // ci-allow-layering[2]: 逆解析上一行生成文本用的分隔串，此处无 shell 执行
    let idx = rest.find(marker)?;
    let after = &rest[idx + marker.len()..];
    if !after.starts_with('\'') { return None; }
    // 解析 POSIX 单引号串：内嵌引号由 `'\''`（关-转义-开，4 字符）编码，
    // 与 `shell_quote_single` 严格互逆。遇真正的结束 `'`（其后非 `\'` 再 `'`）停止。
    let mut s = String::new();
    let bytes = after.as_bytes();
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' if i + 3 < bytes.len()
                && bytes[i + 1] == b'\\' && bytes[i + 2] == b'\'' && bytes[i + 3] == b'\'' =>
            {
                // 内嵌引号：整段 `'\''` 还原为一个 `'`，跳到重开的 `'` 之后
                s.push('\'');
                i += 4;
            }
            b'\'' => break,
            c => { s.push(c as char); i += 1; }
        }
    }
    Some((s, 1))
}

async fn read_crontab() -> Result<Vec<String>> {
    let out = crate::cmd::run(Bin::Crontab, &["-l"], CmdOpt::default()).await?;
    match out.code {
        Some(0) => Ok(out.stdout.lines().map(|l| l.to_string()).collect()),
        // 没有 crontab 是正常状态，不是错误
        Some(1) if out.stderr.contains("no crontab") => Ok(Vec::new()),
        _ => Err(PanelError::Command {
            bin: "crontab".into(),
            detail: format!("crontab -l failed: code={:?} {}", out.code, out.stderr.trim()),
        }),
    }
}

async fn write_crontab(text: &str) -> Result<()> {
    // 写临时文件（0600）再 `crontab <file>`：避免 stdin 注入，且保留用户其他内容
    let dir = std::env::temp_dir();
    let path = dir.join(format!("panel-crontab-{}.tmp", std::process::id()));
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| PanelError::Io(format!("open {path:?}: {e}")))?;
        use std::io::Write;
        f.write_all(text.as_bytes()).map_err(|e| PanelError::Io(format!("write {path:?}: {e}")))?;
    }
    let res = crate::cmd::run(Bin::Crontab, &[path.to_str().unwrap_or("/dev/null")],
        CmdOpt { timeout: Duration::from_secs(15), ..Default::default() }).await;
    let _ = std::fs::remove_file(&path);
    let out = res?;
    if out.code != Some(0) {
        return Err(PanelError::Command {
            bin: "crontab".into(),
            detail: format!("crontab install failed: {}", out.stderr.trim()),
        });
    }
    Ok(())
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".into())
}

#[async_trait]
impl SchedulerProvider for LinuxScheduler {
    fn validate_expression(&self, expr: &str) -> Result<()> {
        let f: Vec<&str> = expr.split_whitespace().collect();
        if f.len() != 5 {
            return Err(PanelError::Validation {
                field: "expr".into(),
                reason: format!("需要 5 段，实际 {} 段", f.len()),
            });
        }
        let bounds = [(0u32, 59u32), (0, 23), (1, 31), (1, 12), (0, 7)];
        for (i, field) in f.iter().enumerate() {
            parse_field(field, bounds[i].0, bounds[i].1)
                .map_err(|e| PanelError::Validation {
                    field: "expr".into(),
                    reason: format!("第 {} 段 `{}` 非法：{}", i + 1, field, e),
                })?;
        }
        Ok(())
    }

    fn next_fire_times(&self, expr: &str, n: usize) -> Result<Vec<i64>> {
        next_fire_times(expr, n)
    }

    async fn list(&self) -> Result<Vec<ScheduledJob>> {
        let entries = parse_crontab(&read_crontab().await?);
        Ok(entries.into_iter().filter_map(|e| match e {
            Entry::Job { id, user, expr, command, enabled, max_overlap } => Some(ScheduledJob {
                id, expression: expr, command, user, enabled,
                timeout: Duration::from_secs(1800),
                max_overlap,
                webhook_url: None,
                webhook_events: Vec::new(),
            }),
            Entry::Raw(_) => None,
        }).collect())
    }

    async fn upsert(&self, job: ScheduledJob) -> Result<()> {
        // 二次校验（业务层已校验，这里兜底，杜绝非法表达式落盘）
        self.validate_expression(&job.expression)?;
        let mut entries = parse_crontab(&read_crontab().await?);
        let replaced = {
            let mut found = false;
            for e in entries.iter_mut() {
                if let Entry::Job { id, .. } = e {
                    if *id == job.id { found = true; break; }
                }
            }
            found
        };
        if replaced {
            for e in entries.iter_mut() {
                if let Entry::Job { id, user, expr, command, enabled, max_overlap } = e {
                    if *id == job.id {
                        *user = job.user.clone();
                        *expr = job.expression.clone();
                        *command = job.command.clone();
                        *enabled = job.enabled;
                        *max_overlap = job.max_overlap;
                    }
                }
            }
        } else {
            entries.push(Entry::Job {
                id: job.id, user: job.user, expr: job.expression,
                command: job.command, enabled: job.enabled,
                max_overlap: job.max_overlap,
            });
        }
        write_crontab(&serialize(&entries)).await
    }

    async fn remove(&self, id: &str) -> Result<()> {
        let mut entries = parse_crontab(&read_crontab().await?);
        let before = entries.len();
        entries.retain(|e| match e {
            Entry::Job { id: jid, .. } => jid != id,
            Entry::Raw(_) => true,
        });
        if entries.len() == before {
            return Err(PanelError::NotFound(format!("cron job `{id}` 不存在")));
        }
        write_crontab(&serialize(&entries)).await
    }

    async fn runs(&self, _id: &str, _limit: usize) -> Result<Vec<JobRun>> {
        // 系统 crontab 默认不记录历史；返回空（UI 显示"暂无执行记录"），不假装成功
        Ok(Vec::new())
    }
}

// ─────────────── 表达式解析 ───────────────

/// 把单段（如 `*/15`、`1,2,5-9`、`3`）解析为允许值集合。
fn parse_field(s: &str, min: u32, max: u32) -> std::result::Result<Vec<u32>, String> {
    if s == "*" { return Ok((min..=max).collect()); }
    let mut set = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() { return Err("空项".into()); }
        // 步长 */n 或 a-b/n 或 a/n
        let (range, step) = match part.split_once('/') {
            Some((r, st)) => {
                let st: u32 = st.parse().map_err(|_| format!("步长非法 `{st}`"))?;
                if st == 0 { return Err("步长不能为 0".into()); }
                (r, st)
            }
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            let a: u32 = a.parse().map_err(|_| format!("范围起点 `{a}`"))?;
            let b: u32 = b.parse().map_err(|_| format!("范围终点 `{b}`"))?;
            if a > b { return Err(format!("反向区间 {a}-{b}")); }
            (a, b)
        } else {
            let v: u32 = range.parse().map_err(|_| format!("数值 `{range}`"))?;
            (v, v)
        };
        if lo < min || hi > max { return Err(format!("越界 {lo}-{hi}（允许 {min}-{max}）")); }
        let mut v = lo;
        while v <= hi {
            if !set.contains(&v) { set.push(v); }
            v = v.saturating_add(step);
            if step == 0 { break; }
        }
    }
    set.sort_unstable();
    Ok(set)
}

// ─────────────── 下次触发时间（自包含日历，不引第三方） ───────────────

/// days since 1970-01-01（UTC 午夜）→ (年, 月, 日)。Howard Hinnant 的 civil_from_days。
fn ymd_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let y = if m <= 2 { (y + 1) as i32 } else { y as i32 };
    (y, m, d)
}

/// (年, 月, 日) → days since 1970-01-01（当前实现未直接调用，保留供未来 date 精确化）
#[allow(dead_code)]
fn days_from_ymd(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m as i64 - 3 } else { m as i64 + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe as i64 * 365 + yoe as i64 / 4 - yoe as i64 / 100 + doy;
    era as i64 * 146097 + doe - 719468
}

fn is_leap(y: i32) -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

fn dow_from_days(z: i64) -> u8 {
    // 1970-01-01 是周四(=4, 周日=0)；步长 7 循环
    ((z % 7) + 4).rem_euclid(7) as u8
}

/// 本地时区相对 UTC 的偏移秒数（东八区 = +28800）。
///
/// crontab 的触发语义是**服务器本地时间**（`0 9 * * *` = 本地 09:00），而
/// 纪元秒是世界时的——不做偏移换算，预览就会在非 UTC 机器上整体漂移
/// （东八区差 8 小时，等于给用户看错的时刻）。用 libc `localtime_r`
/// （线程安全版）读 `tm_gmtoff`；任何失败一律退回 0（退化为 UTC 语义，
/// 不 panic 不阻塞）。
/// 供 panel-task 的内部调度器复用：每日类任务同样必须以本地时间为准，
/// 否则东八区上"03:10 执行"会漂到 11:10。
pub fn local_utc_offset_secs_at(now_unix: i64) -> i64 {
    let t = now_unix as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::localtime_r(&t, &mut tm) };
    if ok.is_null() { 0 } else { tm.tm_gmtoff as i64 }
}

/// 暴力枚举下 n 次触发（分钟粒度）。expr 非法或超出 1 年窗口返回空。
fn next_fire_times(expr: &str, n: usize) -> Result<Vec<i64>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(next_fire_times_from(expr, n, now, local_utc_offset_secs_at(now)))
}

/// 纯函数核心：`now_unix`（UTC 纪元秒）与 `off`（本地偏移秒）显式注入，
/// 避开对系统时钟/时区的隐式依赖——回归测试才能钉死本地语义。
/// 返回值仍是 **UTC 纪元秒**（与全仓时间戳约定一致，前端负责本地渲染）。
fn next_fire_times_from(expr: &str, n: usize, now_unix: i64, off: i64) -> Vec<i64> {
    let f: Vec<&str> = expr.split_whitespace().collect();
    if f.len() != 5 { return Vec::new(); }
    let mins = parse_field(f[0], 0, 59).unwrap_or_default();
    let hrs = parse_field(f[1], 0, 23).unwrap_or_default();
    let doms = parse_field(f[2], 1, 31).unwrap_or_default();
    let mons = parse_field(f[3], 1, 12).unwrap_or_default();
    let dows = parse_field(f[4], 0, 7).unwrap_or_default();
    if mins.is_empty() || hrs.is_empty() || doms.is_empty() || mons.is_empty() || dows.is_empty() {
        return Vec::new();
    }
    let dom_star = f[2] == "*";
    let dow_star = f[4] == "*";

    let mut cursor = (now_unix / 60 + 1) * 60;   // 下一整分钟起
    let mut out = Vec::new();
    let limit = cursor + 366 * 24 * 3600;        // 最多看 1 年
    while cursor < limit && out.len() < n {
        // civil 字段一律按**本地时间**取：cursor 是 UTC 纪元秒，
        // 加偏移后才是「钟面时刻」；命中后推回的仍是 UTC 纪元秒。
        let local = cursor + off;
        let days = local.div_euclid(86400);
        let sec_of_day = local.rem_euclid(86400);
        let (_y, mo, d) = ymd_from_days(days);
        let h = (sec_of_day / 3600) as u32;
        let mi = ((sec_of_day % 3600) / 60) as u32;
        let dow = dow_from_days(days);
        let dow_norm = if dow == 7 { 0 } else { dow };
        let dom_ok = doms.contains(&d);
        let dow_ok = dows.contains(&(dow_norm as u32));
        let day_match = if !dom_star && !dow_star { dom_ok || dow_ok } else { dom_ok && dow_ok };
        if mons.contains(&mo) && hrs.contains(&h) && mins.contains(&mi) && day_match {
            out.push(cursor);
        }
        cursor += 60;
    }
    out
}

#[allow(dead_code)]
fn _assert_calendar() {
    // 1970-01-01 → (1970,1,1)，周四
    let (y, m, d) = ymd_from_days(0);
    assert_eq!((y, m, d), (1970, 1, 1));
    assert_eq!(dow_from_days(0), 4);
    // 闰年 2 月 29 天
    assert!(is_leap(2024) && !is_leap(2023));
}

impl LinuxScheduler {
    #[allow(dead_code)]
    pub fn detect() -> Self { Self }
}

impl Capable for LinuxScheduler {
    fn capability(&self) -> Capability {
        // crontab 是这套实现唯一的载体：命令不存在，整套能力就不存在。
        // ⚠️ 曾经在能力矩阵里被写死成 `no("not_implemented")`，
        // 结果底下这套完整实现永远走不到，所有 cron 端点都返回 501。
        const SEARCH: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin",
                                  "/usr/local/bin", "/usr/local/sbin"];
        let found = SEARCH.iter()
            .any(|d| std::path::Path::new(d).join("crontab").is_file());
        if found { Capability::yes("crontab") } else { Capability::no("binary_missing") }
    }
}

#[cfg(test)]
mod tz_tests {
    use super::{next_fire_times_from, unwrap_overlap_guard, wrap_overlap_guard};

    const OFF8: i64 = 8 * 3600; // 东八区

    /// 本地钟面渲染辅助：把 UTC 纪元秒按 offset 渲染成 (时, 分)
    fn hm(t: i64, off: i64) -> (u32, u32) {
        let s = (t + off).rem_euclid(86400);
        ((s / 3600) as u32, ((s % 3600) / 60) as u32)
    }

    /// **回归（东八区漂移）**：`0 9 * * *` 的每次触发，按本地钟面必须是 09:00。
    /// 旧实现按 UTC 取 civil 字段，本机渲染出的会是 17:00——crontab 真实
    /// 触发却在本地 09:00，预览整体漂 8 小时。
    #[test]
    fn daily_9am_is_local_not_utc() {
        // 固定 now：2026-01-15 00:00 UTC（避免依赖系统时钟）
        let now: i64 = 17_684_448_000;
        let out = next_fire_times_from("0 9 * * *", 5, now, OFF8);
        assert_eq!(out.len(), 5, "应找出 5 次触发");
        for t in &out {
            assert!(*t > now, "触发时刻必须晚于 now");
            assert_eq!(hm(*t, OFF8), (9, 0), "本地钟面必须是 09:00（UTC 渲染则会是 01:00）");
        }
        // 相邻触发间隔恰好 24h
        assert_eq!(out[1] - out[0], 86_400);
    }

    /// 负偏移（西半球）同样成立：`30 22 * * *` → 本地 22:30
    #[test]
    fn negative_offset_also_local() {
        let now: i64 = 17_684_448_000;
        let off = -5 * 3600;
        let out = next_fire_times_from("30 22 * * *", 3, now, off);
        assert_eq!(out.len(), 3);
        for t in &out {
            assert_eq!(hm(*t, off), (22, 30));
        }
    }

    /// 步进/列表/范围语法照常工作（本地语义下）
    #[test]
    fn step_and_list_syntax() {
        let now: i64 = 17_684_448_000; // 周四
        // 每 15 分钟：相邻间隔 900s
        let out = next_fire_times_from("*/15 * * * *", 3, now, 0);
        assert_eq!(out.len(), 3);
        assert_eq!(out[1] - out[0], 900);
        // 多值列表 0,30
        let out = next_fire_times_from("0,30 12 * * *", 4, now, 0);
        assert_eq!(out[1] - out[0], 1_800);
        // dom 与 dow 同时非星号 → OR 语义（Vixie cron 约定）
        let out = next_fire_times_from("0 0 13 * 5", 8, now, 0); // 13 号或周五
        assert!(out.len() >= 2);
    }

    /// 永不触发的表达式：返回空（诚实预览），而不是死循环
    #[test]
    fn impossible_expr_returns_empty_within_window() {
        let now: i64 = 17_684_448_000;
        // 2 月 31 日不存在 → 1 年窗口内零命中
        let out = next_fire_times_from("0 5 31 2 *", 5, now, 0);
        assert!(out.is_empty());
    }

    // ── P2-3 重叠保护包裹/还原（与 crontab 真实写入互逆，否则会双包裹）──

    #[test]
    fn overlap_guard_roundtrip_plain() {
        let cmd = "echo hello world";
        let wrapped = wrap_overlap_guard("job1", cmd);
        assert!(wrapped.starts_with("flock -n /run/lock/panel-cron-job1 -- sh -c '"));
        let (back, m) = unwrap_overlap_guard(&wrapped).unwrap();
        assert_eq!(back, cmd);
        assert_eq!(m, 1);
    }

    #[test]
    fn overlap_guard_roundtrip_with_special_chars() {
        // 含单引号、分号、空格——这些若被错误拼接进 shell 会注入；单引号转义必须可逆
        for cmd in ["sh -c 'echo a'", "a;b && c | d", "echo 'it''s ok'", "rm -rf / ; id"] {
            let wrapped = wrap_overlap_guard("x", cmd);
            let (back, _) = unwrap_overlap_guard(&wrapped).expect("应能还原");
            assert_eq!(back, cmd, "还原后必须与原文一致（防双包裹/注入）");
        }
    }

    #[test]
    fn overlap_guard_not_applied_to_plain_command() {
        // 非本模块生成的包裹形式不识别 → 整行作为命令，max_overlap 默认 1
        assert_eq!(unwrap_overlap_guard("0 9 * * * /usr/bin/backup.sh"), None);
    }
}
