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
    Job { id: String, user: String, expr: String, command: String, enabled: bool },
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

/// `<expr> <command>` → Job（前 5 段为表达式，其余为命令）
fn parse_job_line(id: &str, user: &str, payload: &str, enabled: bool) -> Option<Entry> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() < 6 { return None; }   // 5 段 + 至少 1 个命令词
    let expr = parts[..5].join(" ");
    let command = parts[5..].join(" ");
    Some(Entry::Job {
        id: id.to_string(),
        user: user.to_string(),
        expr,
        command,
        enabled,
    })
}

fn serialize(entries: &[Entry]) -> String {
    let mut s = String::new();
    for e in entries {
        match e {
            Entry::Raw(line) => { s.push_str(line); s.push('\n'); }
            Entry::Job { id, user, expr, command, enabled } => {
                s.push_str(&format!("{MARK}{id} user={user}\n"));
                if *enabled {
                    s.push_str(expr); s.push(' '); s.push_str(command); s.push('\n');
                } else {
                    s.push_str(OFF); s.push_str(expr); s.push(' '); s.push_str(command); s.push('\n');
                }
            }
        }
    }
    s
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
            Entry::Job { id, user, expr, command, enabled } => Some(ScheduledJob {
                id, expression: expr, command, user, enabled,
                timeout: Duration::from_secs(1800),
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
                if let Entry::Job { id, user, expr, command, enabled } = e {
                    if *id == job.id {
                        *user = job.user.clone();
                        *expr = job.expression.clone();
                        *command = job.command.clone();
                        *enabled = job.enabled;
                    }
                }
            }
        } else {
            entries.push(Entry::Job {
                id: job.id, user: job.user, expr: job.expression,
                command: job.command, enabled: job.enabled,
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

/// 暴力枚举下 n 次触发（分钟粒度）。expr 非法或超出 1 年窗口返回空。
fn next_fire_times(expr: &str, n: usize) -> Result<Vec<i64>> {
    let f: Vec<&str> = expr.split_whitespace().collect();
    if f.len() != 5 { return Ok(Vec::new()); }
    let mins = parse_field(f[0], 0, 59).unwrap_or_default();
    let hrs = parse_field(f[1], 0, 23).unwrap_or_default();
    let doms = parse_field(f[2], 1, 31).unwrap_or_default();
    let mons = parse_field(f[3], 1, 12).unwrap_or_default();
    let dows = parse_field(f[4], 0, 7).unwrap_or_default();
    if mins.is_empty() || hrs.is_empty() || doms.is_empty() || mons.is_empty() || dows.is_empty() {
        return Ok(Vec::new());
    }
    let dom_star = f[2] == "*";
    let dow_star = f[4] == "*";

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut cursor = (now / 60 + 1) * 60;   // 下一整分钟起
    let mut out = Vec::new();
    let limit = cursor + 366 * 24 * 3600;   // 最多看 1 年
    while cursor < limit && out.len() < n {
        let days = cursor / 86400;
        let sec_of_day = cursor % 86400;
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
    Ok(out)
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
