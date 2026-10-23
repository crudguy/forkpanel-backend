//! AI 运维助手（#52 / roadmap P2-2）。
//!
//! **定位（诚实版）**：内核是**内置规则诊断引擎**——把面板独有的数据面
//! （指标 + 进程 + 服务状态 + 实时日志 + 安全基线 + 备份记录）汇成诊断上下文，
//! 用确定性规则产出「证据 + 建议」。自然语言理解是**轻量关键词路由**，不是大模型。
//! **LLM 叙事层（可选）**：若面板设置里已配置 LLM（endpoint/model/api_key），
//! `diagnose` 会用规则诊断的结构化结果请求一次 OpenAI 兼容对话补全，生成 `narrative`
//! 人话解读；未配置或调用失败/超时则优雅降级，回退纯规则报告（响应不含 `narrative`）。
//!
//! **护栏**：助手**只读**。Findings 里的 `action` 只有 `navigate`（跳转视图）
//! 一种——不携带任何可自动执行的语义；任何处置动作仍由用户在对应视图内
//! 走既有端点与权限。响应也不是流式（SSE 留给 LLM 接入后再上）。
//!
//! **外发纪律（P0-2）**：叙事层会把诊断数据 POST 到管理员配置的第三方端点，
//! 因此三条闸门缺一不可——① **独立开关** `assistant.llm_narrative`，缺省关，
//! 关时 `settings::llm_config()` 直接返回 None（不外发任何数据）；
//! ② **发送前脱敏**（`redact_for_llm`：IPv4/邮箱/密钥样式键值/Bearer）；
//! ③ **披露**：会外发什么由 `settings::NARRATIVE_NOTE` 单一维护并原样展示。

use crate::auth::perm;
use crate::error::{ok, ApiResult};
use crate::routes::{Auth, Shared};
use axum::{extract::State, Json};
use panel_os::{LogQuery, ProcessInfo, ProcessSort, ServiceFilter, ServiceState, SystemSnapshot};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use crate::extract::PanelJson;

/// 进程采样差分窗口。`top_processes` 与 `snapshot` 共享同一 prev 采样点，
/// 窗口太短会让 CPU% 退化为 tick 量化噪声。
const SAMPLE_WINDOW: Duration = Duration::from_millis(400);

// ───────────────────────── DTO（契约见 openapi.yaml） ─────────────────────────

#[derive(Debug, Serialize)]
pub struct AssistantReport {
    pub question: String,
    /// 命中的诊断域：all|cpu|mem|disk|log|service|security|backup
    pub scope: &'static str,
    pub generated_at: i64,
    pub summary: String,
    /// LLM 人话叙事（可选）：仅当面板已配置 LLM 且调用成功时填充；
    /// 未配置/失败/超时则省略（serde skip_serializing_if），回退纯规则报告。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub narrative: Option<String>,
    pub findings: Vec<Finding>,
    /// 体检基线：即使无异常也给出关键真实数值
    pub ctx: ContextBrief,
}

#[derive(Debug, Serialize)]
pub struct ContextBrief {
    pub cpu_pct: f32,
    pub load1: f32,
    pub load5: f32,
    pub load15: f32,
    pub mem_used_kib: u64,
    pub mem_total_kib: u64,
    pub proc_count: u32,
    pub uptime_sec: u64,
    pub top_disk: Option<DiskBrief>,
}

#[derive(Debug, Serialize)]
pub struct DiskBrief {
    pub mount: String,
    pub used_pct: f32,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    /// 稳定规则标识（如 `cpu.high`）
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    /// 证据：**直接引用采集到的真实数据**（进程名/PID/挂载点/日志行…）
    pub evidence: Vec<String>,
    pub suggestion: String,
    /// 人工确认入口：仅导航（kind=navigate），绝不自动执行
    pub action: Option<Action>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Crit,
}

#[derive(Debug, Serialize)]
pub struct Action {
    pub kind: &'static str,
    /// 面板内视图路由（如 `/services`）
    pub view: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct DiagnoseReq {
    pub question: Option<String>,
}

// ───────────────────────── 诊断上下文 ─────────────────────────

/// 汇聚后的诊断上下文。字段全部是**原始数据的可序列化投影**，
/// 便于纯函数 `run_diagnosis` 做单测（不依赖 OS provider）。
struct Ctx {
    snap: SystemSnapshot,
    top_cpu: Vec<ProcessInfo>,
    top_mem: Vec<ProcessInfo>,
    failed_units: Vec<String>,
    /// 最近 error 级日志文本（≤20 行）
    err_lines: Vec<String>,
    /// 安全基线风险项 (key, title, current)
    sec_risks: Vec<(String, String, String)>,
    backup_plans: i64,
    /// 距最近一次成功备份的秒数；`None` = 从未成功过
    backup_last_ok_age: Option<i64>,
}

/// 并行采集全部上下文。**单路失败只降级不报错**——诊断不能因为
/// 某个探针挂了而整体 500，缺失的维度以空值参与规则（对应规则自然沉默）。
///
/// ⚠ 指标三连（snapshot / top_cpu / top_mem）**必须串行**：它们共享同一个
/// prev 采样点（`LinuxMetrics.prev`），并行调用会互相清零差分窗口——
/// CPU% 全部失真（曾致「结论 77% 却点名 systemd 0.0%」的证据脱节）。
/// 全局快照先行，留出真实差分窗口后再取进程排行。
async fn collect(state: &Shared) -> Ctx {
    let os = state.os.as_ref();

    let snap = os.metrics().snapshot().await;
    // 与 LinuxMetrics 无共享状态的四路，可安全并行
    let (units, sec, err_lines, backup) = tokio::join!(
        os.services().list(ServiceFilter::default()),
        os.security().baseline(),
        collect_err_lines(os),
        backup_status(&state.pool),
    );
    tokio::time::sleep(SAMPLE_WINDOW).await;
    // per-process CPU% 需要两次扫描才有差分基线（per-pid prev 首次为空 → 全 0），
    // 先做一次暖场扫描填充基线，再取真实窗口内的排行——否则证据与结论脱节。
    let _warm = os.metrics().top_processes(5, ProcessSort::Cpu).await;
    tokio::time::sleep(SAMPLE_WINDOW).await;
    let top_cpu = os.metrics().top_processes(5, ProcessSort::Cpu).await;
    // top_mem 只用 rss（瞬时值，与差分窗口无关）；放最后避免污染 top_cpu 窗口
    let top_mem = os.metrics().top_processes(3, ProcessSort::Memory).await;

    let snap = snap.unwrap_or_else(|_| SystemSnapshot {
        ts_unix: 0,
        uptime_sec: 0,
        cpu: panel_os::CpuSample {
            total_pct: 0.0, per_core_pct: None, load1: 0.0, load5: 0.0, load15: 0.0,
        },
        mem: panel_os::MemSample {
            total_kib: 0, used_kib: 0, available_kib: 0,
            buffers_kib: 0, cached_kib: 0, swap_total_kib: 0, swap_used_kib: 0,
        },
        disks: Vec::new(),
        nets: Vec::new(),
        proc_count: 0,
        tcp_conns: 0,
        temps: Vec::new(),
    });
    let failed_units = units
        .unwrap_or_default()
        .into_iter()
        .filter(|u| u.state == ServiceState::Failed)
        .map(|u| u.name.as_str().to_string())
        .collect();
    let sec_risks = sec
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.applicable && !c.ok)
        .map(|c| (c.key, c.title, c.current))
        .collect();
    let (backup_plans, backup_last_ok_age) = backup;

    Ctx { snap, top_cpu: top_cpu.unwrap_or_default(), top_mem: top_mem.unwrap_or_default(),
          failed_units, err_lines, sec_risks, backup_plans, backup_last_ok_age }
}

/// 抓取系统源最近的 error 级日志文本（有界，不 follow）。
async fn collect_err_lines(os: &dyn panel_os::OsAdapter) -> Vec<String> {
    let Ok(srcs) = os.logs().sources().await else { return Vec::new() };
    let Some(sys) = srcs.into_iter().find(|s| s.id == "system") else { return Vec::new() };
    let q = LogQuery { lines: 200, grep: None, level: None, follow: false, since_unix: None };
    let Ok(lines) = os.logs().read(&sys, q).await else { return Vec::new() };
    lines
        .into_iter()
        .filter(|l| l.level.as_deref() == Some("error"))
        .take(20)
        .map(|l| l.text)
        .collect()
}

/// 备份计划数 + 最近一次**成功**备份距今秒数。
async fn backup_status(pool: &Arc<crate::ReadPool>) -> (i64, Option<i64>) {
    let Ok((plans, last_ok)) = pool
        .with(|conn| {
            let plans: i64 = conn
                .query_row("SELECT COUNT(*) FROM backup_jobs", [], |r| r.get(0))
                .unwrap_or(0);
            let last: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(last_run_at),0) FROM backup_jobs WHERE last_result='ok'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            Ok((plans, last))
        })
        .await
    else {
        return (0, None);
    };
    let age = if last_ok > 0 { Some((crate::now_unix() - last_ok).max(0)) } else { None };
    (plans, age)
}

// ───────────────────────── 问句路由 ─────────────────────────

/// 轻量关键词路由（中英混合，大小写不敏感）。未命中 → 全量体检。
fn route_scope(q: &str) -> &'static str {
    let q = q.to_lowercase();
    let has = |kw: &[&str]| kw.iter().any(|k| q.contains(k));
    if has(&["cpu", "负载", "load", "处理器", "算力"]) { "cpu" }
    else if has(&["内存", "mem", "oom", "泄漏"]) { "mem" }
    else if has(&["磁盘", "disk", "空间", "满了", "存储"]) { "disk" }
    else if has(&["日志", "log", "报错", "错误", "error", "异常"]) { "log" }
    else if has(&["服务", "service", "挂了", "failed", "失败", "单元"]) { "service" }
    else if has(&["安全", "security", "基线", "加固"]) { "security" }
    else if has(&["备份", "backup"]) { "backup" }
    else { "all" }
}

// ───────────────────────── 规则诊断引擎（纯函数） ─────────────────────────

fn run_diagnosis(ctx: &Ctx, scope: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let on = |dom: &str| scope == "all" || scope == dom;

    // R1 CPU：85% crit / 70% warn（证据 = Top CPU 进程，直接点名）
    if on("cpu") {
        let cpu = ctx.snap.cpu.total_pct;
        if cpu >= 70.0 {
            let sev = if cpu >= 85.0 { Severity::Crit } else { Severity::Warn };
            let evidence = if ctx.top_cpu.is_empty() {
                vec!["进程采样为空（采集降级）".into()]
            } else {
                ctx.top_cpu.iter().take(3)
                    .map(|p| format!("{} (pid {}) — CPU {:.1}%", p.name, p.pid, p.cpu_pct))
                    .collect()
            };
            out.push(Finding {
                id: "cpu.high", severity: sev,
                title: format!("CPU 使用率 {}（{cpu:.0}%）",
                    if sev == Severity::Crit { "过高" } else { "偏高" }),
                evidence,
                suggestion: "按占用排行定位来源：异常进程可直接终止；业务高峰则考虑错峰、扩容或迁移。".into(),
                action: Some(Action { kind: "navigate", view: "/processes" }),
            });
        }
    }

    // R2 负载：load5 超过核数 1.5 倍 → warn（核数不可知时规则沉默，不瞎猜）
    if on("cpu") {
        if let Some(cores) = ctx.snap.cpu.per_core_pct.as_ref().map(|c| c.len()) {
            let l5 = ctx.snap.cpu.load5;
            if cores > 0 && l5 > cores as f32 * 1.5 {
                out.push(Finding {
                    id: "load.high", severity: Severity::Warn,
                    title: format!("系统负载超过核数（load5={l5:.2}，{cores} 核）"),
                    evidence: vec![format!("load1={:.2} load5={:.2} load15={:.2}",
                        ctx.snap.cpu.load1, ctx.snap.cpu.load5, ctx.snap.cpu.load15)],
                    suggestion: "负载高但 CPU 利用率不高时，通常是 IO 等待——结合磁盘与日志页排查。".into(),
                    action: Some(Action { kind: "navigate", view: "/system" }),
                });
            }
        }
    }

    // R3 内存压力：可用 <10% crit / <20% warn（证据 = Top RSS 进程）
    if on("mem") {
        let m = &ctx.snap.mem;
        if m.total_kib > 0 {
            let avail_pct = m.available_kib as f64 * 100.0 / m.total_kib as f64;
            if avail_pct < 20.0 {
                let sev = if avail_pct < 10.0 { Severity::Crit } else { Severity::Warn };
                let mut evidence = vec![format!(
                    "内存 {} / {}（可用 {avail_pct:.0}%），swap 已用 {}",
                    human_kib(m.used_kib), human_kib(m.total_kib), human_kib(m.swap_used_kib))];
                evidence.extend(ctx.top_mem.iter().take(2)
                    .map(|p| format!("RSS 大户：{} (pid {}) — {}", p.name, p.pid, human_kib(p.rss_kib))));
                out.push(Finding {
                    id: "mem.pressure", severity: sev,
                    title: format!("内存可用空间吃紧（{avail_pct:.0}%）"),
                    evidence,
                    suggestion: "先确认 RSS 大户是否异常泄漏；必要时重启对应服务或加大 swap 兜底。".into(),
                    action: Some(Action { kind: "navigate", view: "/processes" }),
                });
            }
        }
    }

    // R4 磁盘：单挂载点 ≥90% crit / ≥80% warn（一个发现聚合多个挂载点证据）
    if on("disk") {
        let mut hot: Vec<(String, f64, u64, u64)> = Vec::new();
        for d in &ctx.snap.disks {
            if d.total_bytes == 0 { continue; }
            let pct = d.used_bytes as f64 * 100.0 / d.total_bytes as f64;
            if pct >= 80.0 {
                hot.push((d.mount_point.display().to_string(), pct, d.used_bytes, d.total_bytes));
            }
        }
        hot.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        if !hot.is_empty() {
            let crit = hot.iter().any(|(_, p, _, _)| *p >= 90.0);
            out.push(Finding {
                id: "disk.full",
                severity: if crit { Severity::Crit } else { Severity::Warn },
                title: format!("磁盘空间紧张（最高 {:.0}%）", hot[0].1),
                evidence: hot.iter().take(4)
                    .map(|(m, p, u, t)| format!("{m} — {p:.0}%（{} / {}）",
                        human_bytes(*u), human_bytes(*t)))
                    .collect(),
                suggestion: "清理日志/临时文件或扩容；面板日志与备份目录占用可在文件页定位。".into(),
                action: Some(Action { kind: "navigate", view: "/files" }),
            });
        }
    }

    // R5 服务失败：有 failed 单元 → crit（service 页可直接看 journal）
    if on("service") && !ctx.failed_units.is_empty() {
        let shown: Vec<String> = ctx.failed_units.iter().take(5).cloned().collect();
        let extra = ctx.failed_units.len() - shown.len();
        out.push(Finding {
            id: "service.failed", severity: Severity::Crit,
            title: format!("有 {} 个 systemd 单元处于 failed 状态", ctx.failed_units.len()),
            evidence: { let mut e = shown; if extra > 0 { e.push(format!("…等 {} 个", extra)); } e },
            suggestion: "到服务页查看失败单元的 journal 输出，定位退出原因后再决定重启或修复。".into(),
            action: Some(Action { kind: "navigate", view: "/services" }),
        });
    }

    // R6 错误日志：采样窗口（最近 200 行）内 error 级 → 20 条以上 crit
    if on("log") && !ctx.err_lines.is_empty() {
        let n = ctx.err_lines.len();
        let trunc = |s: &str| if s.chars().count() > 100 {
            format!("{}…", s.chars().take(100).collect::<String>())
        } else { s.to_string() };
        out.push(Finding {
            id: "log.errors",
            severity: if n >= 20 { Severity::Crit } else { Severity::Warn },
            title: format!("系统日志最近出现 {n} 条 error 级记录"),
            evidence: ctx.err_lines.iter().rev().take(3).map(|t| trunc(t)).collect(),
            suggestion: "在日志页按关键字过滤定位源头；反复出现的同一错误优先处理。".into(),
            action: Some(Action { kind: "navigate", view: "/logs" }),
        });
    }

    // R7 安全基线：有未通过项 → warn（逐条列 key + 当前值）
    if on("security") && !ctx.sec_risks.is_empty() {
        out.push(Finding {
            id: "security.risks", severity: Severity::Warn,
            title: format!("安全基线有 {} 项未通过", ctx.sec_risks.len()),
            evidence: ctx.sec_risks.iter().take(5)
                .map(|(k, t, cur)| format!("{k} — {t}（{cur}）")).collect(),
            suggestion: "到安全页逐项核对修复建议；写回类操作需 root 并先备份，面板会二次确认。".into(),
            action: Some(Action { kind: "navigate", view: "/security" }),
        });
    }

    // R8 备份：没计划 → info 提醒；有计划但从未成功 / 距上次成功 >7 天 → warn
    if on("backup") {
        match (ctx.backup_plans, ctx.backup_last_ok_age) {
            (0, _) => out.push(Finding {
                id: "backup.missing", severity: Severity::Info,
                title: "尚未配置任何备份计划".into(),
                evidence: vec!["backup_jobs 表为空".into()],
                suggestion: "为面板数据与关键站点建一个每日备份计划——出事时它是唯一的后悔药。".into(),
                action: Some(Action { kind: "navigate", view: "/backups" }),
            }),
            (_, None) => out.push(Finding {
                id: "backup.never_ok", severity: Severity::Warn,
                title: "备份计划从未成功执行过".into(),
                evidence: vec![format!("已配置 {0} 个计划，但无 last_result=ok 记录", ctx.backup_plans)],
                suggestion: "到备份页手动执行一次并检查产物，确认目标目录可写。".into(),
                action: Some(Action { kind: "navigate", view: "/backups" }),
            }),
            (_, Some(age)) if age > 7 * 86_400 => out.push(Finding {
                id: "backup.stale", severity: Severity::Warn,
                title: format!("距上次成功备份已 {} 天", age / 86_400),
                evidence: vec![format!("最近一次成功备份距今 {} 秒", age)],
                suggestion: "检查计划是否被禁用或执行失败，手动触发一次验证链路。".into(),
                action: Some(Action { kind: "navigate", view: "/backups" }),
            }),
            _ => {}
        }
    }

    out
}

/// 汇总一句话结论（诚实：有真实数值兜底，而不是空话）。
fn build_summary(ctx: &Ctx, findings: &[Finding]) -> String {
    let (crit, warn, info) = findings.iter().fold((0, 0, 0), |(c, w, i), f| match f.severity {
        Severity::Crit => (c + 1, w, i),
        Severity::Warn => (c, w + 1, i),
        Severity::Info => (c, w, i + 1),
    });
    if findings.is_empty() {
        format!("未发现异常：CPU {:.0}%，内存可用 {}，进程 {}。",
            ctx.snap.cpu.total_pct,
            human_kib(ctx.snap.mem.available_kib),
            ctx.snap.proc_count)
    } else {
        let mut s = String::from("发现 ");
        let mut parts = Vec::new();
        if crit > 0 { parts.push(format!("{crit} 项严重")); }
        if warn > 0 { parts.push(format!("{warn} 项风险")); }
        if info > 0 { parts.push(format!("{info} 项提醒")); }
        s.push_str(&parts.join("、"));
        s.push_str("，证据均来自当前系统实采数据，处置请在对应页面人工确认。");
        s
    }
}

fn brief(ctx: &Ctx) -> ContextBrief {
    let top_disk = ctx.snap.disks.iter()
        .filter(|d| d.total_bytes > 0)
        .map(|d| (d.mount_point.display().to_string(),
                  d.used_bytes as f64 * 100.0 / d.total_bytes as f64))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(mount, pct)| DiskBrief { mount, used_pct: pct as f32 });
    ContextBrief {
        cpu_pct: ctx.snap.cpu.total_pct,
        load1: ctx.snap.cpu.load1,
        load5: ctx.snap.cpu.load5,
        load15: ctx.snap.cpu.load15,
        mem_used_kib: ctx.snap.mem.used_kib,
        mem_total_kib: ctx.snap.mem.total_kib,
        proc_count: ctx.snap.proc_count,
        uptime_sec: ctx.snap.uptime_sec,
        top_disk,
    }
}

/// LLM 叙事请求超时。宁可让用户多等若干秒拿到人话解读，也不要挂住一个 axum worker；
/// 超时即视为「叙事不可用」，回退纯规则报告（不影响 findings/summary）。
const NARRATIVE_TIMEOUT: Duration = Duration::from_secs(20);

// ───────────────────────── 外发脱敏（P0-2） ─────────────────────────

/// 密钥样式键值的关键词（大小写不敏感）。命中后**保留键名、替换值**——
/// 键名本身（"api_key"）不敏感，敏感的是后面的凭证。
const SECRET_KWS: &[&str] = &[
    "api_key", "api-key", "apikey", "access_key", "access-key",
    "secret_key", "secret-key", "private_key", "private-key",
    "auth_token", "token", "secret", "password", "passwd", "pwd",
    "authorization", "credentials", "credential", "key",
];

/// 认证 Scheme 词：值恰为其中之一时，继续吃掉下一个 token
/// （`Authorization: Bearer xyz` 的值以空白分两段，只吃一段会漏掉真凭证）。
fn is_auth_scheme(v: &str) -> bool {
    v.eq_ignore_ascii_case("bearer") || v.eq_ignore_ascii_case("basic")
        || v.eq_ignore_ascii_case("token") || v.eq_ignore_ascii_case("apikey")
        || v.eq_ignore_ascii_case("key")
}

/// 键值"值"的终止符（引号已在调用方单独处理）。
fn is_value_terminator(c: char) -> bool {
    matches!(c, ',' | ';' | ')' | ']' | '}')
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

fn matches_ci(ch: &[char], i: usize, kw: &str) -> bool {
    let kw: Vec<char> = kw.chars().collect();
    if i + kw.len() > ch.len() { return false; }
    ch[i..i + kw.len()].iter().zip(kw.iter()).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// `Bearer <token>`（大小写不敏感）。返回 token 结束位置（不含）。
fn bearer_at(ch: &[char], i: usize) -> Option<usize> {
    if i > 0 && is_word_char(ch[i - 1]) { return None; }
    if !matches_ci(ch, i, "bearer") { return None; }
    let mut j = i + 6;
    while j < ch.len() && (ch[j] == ' ' || ch[j] == '\t') { j += 1; }
    let tok = j;
    while j < ch.len() && !ch[j].is_whitespace() { j += 1; }
    (j > tok).then_some(j)
}

/// 密钥样式键值。返回 `(值起始, 值结束)`——调用方原样复制 `[i, 值起始)`
/// （键名 + 分隔符），把值替换为 `<redacted>`。
fn secret_kv_at(ch: &[char], i: usize) -> Option<(usize, usize)> {
    if i > 0 && is_word_char(ch[i - 1]) { return None; }
    for kw in SECRET_KWS {
        if !matches_ci(ch, i, kw) { continue; }
        let mut j = i + kw.chars().count();
        // 键名后紧跟字母 ⇒ 是更长的标识符（"tokens:"），不是密钥键
        if j < ch.len() && ch[j].is_ascii_alphabetic() { continue; }
        while j < ch.len() && (ch[j] == ' ' || ch[j] == '\t') { j += 1; }
        if j >= ch.len() || (ch[j] != '=' && ch[j] != ':') { continue; }
        j += 1;
        while j < ch.len() && (ch[j] == ' ' || ch[j] == '\t') { j += 1; }
        let vstart = j;
        if j < ch.len() && (ch[j] == '"' || ch[j] == '\'') {
            // 引号值：整体吃到配对引号（"p@ss w0rd" 中间有空白也不能漏）
            let q = ch[j];
            j += 1;
            while j < ch.len() && ch[j] != q { j += 1; }
            if j < ch.len() { j += 1; }
        } else {
            while j < ch.len() && !ch[j].is_whitespace() && !is_value_terminator(ch[j]) { j += 1; }
            let val: String = ch[vstart..j].iter().collect();
            if is_auth_scheme(&val) {
                while j < ch.len() && ch[j].is_whitespace() { j += 1; }
                while j < ch.len() && !ch[j].is_whitespace() && !is_value_terminator(ch[j]) { j += 1; }
            }
        }
        if j > vstart { return Some((vstart, j)); }
        return None; // "password:" 后没有值——不是泄漏，原样放过
    }
    None
}

/// IPv4（每段 ≤255，四段）。返回结束位置（不含）。
fn ipv4_at(ch: &[char], i: usize) -> Option<usize> {
    // 前边界：不从更长数字/版本串的中段开始匹配
    if i > 0 && (ch[i - 1].is_ascii_digit() || ch[i - 1] == '.') { return None; }
    let mut j = i;
    let mut groups = 0;
    while groups < 4 {
        let mut n: u32 = 0;
        let mut digits = 0;
        while j < ch.len() && ch[j].is_ascii_digit() && digits < 3 {
            n = n * 10 + (ch[j] as u32 - '0' as u32);
            j += 1;
            digits += 1;
        }
        if digits == 0 || n > 255 { return None; }
        groups += 1;
        if groups == 4 { break; }
        if j >= ch.len() || ch[j] != '.' { return None; }
        j += 1;
    }
    // 后边界："1.2.3.4.5" 不是 IP，不整体吃
    if j < ch.len() && (ch[j].is_ascii_digit() || ch[j] == '.') { return None; }
    Some(j)
}

/// 邮箱（local@domain，域名须含点且不以点/连字符收尾）。返回结束位置（不含）。
fn email_at(ch: &[char], i: usize) -> Option<usize> {
    if i > 0 && is_word_char(ch[i - 1]) { return None; }
    let mut j = i;
    while j < ch.len()
        && (ch[j].is_ascii_alphanumeric() || matches!(ch[j], '.' | '_' | '%' | '+' | '-'))
    {
        j += 1;
    }
    if j == i || j >= ch.len() || ch[j] != '@' { return None; }
    j += 1;
    let dom_start = j;
    let mut last_dot = None;
    while j < ch.len() && (ch[j].is_ascii_alphanumeric() || ch[j] == '.' || ch[j] == '-') {
        if ch[j] == '.' { last_dot = Some(j); }
        j += 1;
    }
    match last_dot {
        Some(p) if p > dom_start && p + 1 < j && ch[j - 1] != '.' && ch[j - 1] != '-' => Some(j),
        _ => None,
    }
}

/// 发送给第三方 LLM 前的脱敏。**纯函数、零新增依赖**（本仓无 regex，也不为它开
/// 依赖口子——直接依赖有预算，且这四类形态手写判定比引正则更可控）。
///
/// 覆盖四类高危形态（journald error 行的常见泄漏）：
/// 1. IPv4——内网地址拓扑；
/// 2. 邮箱——账号 / PII；
/// 3. `api_key=…` / `token: …` 等密钥样式键值（键名保留、值替换）；
/// 4. `Bearer <token>`——HTTP 认证头（含 `Authorization: Bearer x` 两段值）。
///
/// **刻意不覆盖**：绝对路径与主机名。路径是诊断的核心证据（哪个站点的日志、
/// 哪个二进制在报错），主机名在单机面板场景基本就是机器自己的名字；为它们脱敏
/// 会让叙事层基本失效。披露文案（`settings::NARRATIVE_NOTE`）如实列出覆盖范围，
/// 不夸大"已完全脱敏"。
///
/// 取舍原则：**宁可多脱、不可漏脱**。版本号 "8.2.4.1" 被误伤成 `<ip>` 可以接受
/// （叙事仍然通顺），漏一个内网 IP 或一个密钥就是真泄漏。
pub(crate) fn redact_for_llm(s: &str) -> String {
    let ch: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < ch.len() {
        if let Some(end) = bearer_at(&ch, i) {
            out.push_str("Bearer <redacted>");
            i = end;
            continue;
        }
        if let Some((vstart, vend)) = secret_kv_at(&ch, i) {
            out.extend(ch[i..vstart].iter());
            out.push_str("<redacted>");
            i = vend;
            continue;
        }
        if let Some(end) = email_at(&ch, i) {
            out.push_str("<email>");
            i = end;
            continue;
        }
        if let Some(end) = ipv4_at(&ch, i) {
            out.push_str("<ip>");
            i = end;
            continue;
        }
        out.push(ch[i]);
        i += 1;
    }
    out
}

/// 把结构化诊断拼成给 LLM 的纯数据提示词。**只含我们真实采集到的字段**——
/// 系统提示明确要求不得编造诊断中没有的数据，从源头杜绝幻觉式臆测。
/// 所有携带原始数据的字段出盒前经 `redact_for_llm` 脱敏（P0-2）。
fn build_prompt(scope: &str, summary: &str, findings: &[Finding]) -> String {
    // 出盒前脱敏：summary 与 evidence 是唯二携带原始数据的字段（进程 cmdline、
    // 日志原文都在 evidence 里）。title/suggestion 是规则生成的固定文案，
    // 一并过脱敏只是廉价保险。
    let mut s = String::new();
    s.push_str(&format!("诊断范围：{scope}\n一句话结论：{}\n", redact_for_llm(summary)));
    if findings.is_empty() {
        s.push_str("未发现异常项。\n");
    } else {
        s.push_str("发现项（按严重度，证据均为系统实采）：\n");
        for f in findings {
            let sev = match f.severity {
                Severity::Crit => "严重",
                Severity::Warn => "风险",
                Severity::Info => "提醒",
            };
            s.push_str(&format!(
                "- [{}] {}。证据：{}。建议：{}\n",
                sev, redact_for_llm(&f.title), redact_for_llm(&f.evidence.join("；")),
                redact_for_llm(&f.suggestion)
            ));
        }
    }
    s.push_str(
        "\n请用简体中文写一段 2-4 句的人话总结：先说整体状况，再点最关键的一两件事与优先处置，\
         不要给出命令行，不要编造诊断结果里没有的数据。",
    );
    s
}

/// 请求一次 OpenAI 兼容 `/chat/completions`，把规则诊断转成人话叙事。
/// **全链路失败即 `None`**——LLM 是增强层，任何错误（无配置/网络/超时/非 2xx/解析失败）
/// 都不许影响主报告；错误只在后端日志留痕，前端永远拿到一份可用的规则诊断。
async fn generate_narrative(
    cfg: &crate::routes::settings::LlmConfig,
    scope: &str,
    summary: &str,
    findings: &[Finding],
) -> Option<String> {
    let prompt = build_prompt(scope, summary, findings);
    let client = reqwest::Client::builder().timeout(NARRATIVE_TIMEOUT).build().ok()?;
    let url = format!("{}/chat/completions", cfg.endpoint.trim_end_matches('/'));
    let body = serde_json::json!({
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": "你是服务器运维助手，擅长把结构化诊断翻译成运维人员能一眼看懂的人话。"},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 400,
    });
    let resp = client.post(&url).bearer_auth(&cfg.api_key).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    v.get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .map(|s| s.trim().to_string())
}

// ───────────────────────── 端点 ─────────────────────────

/// POST /api/v1/assistant/diagnose
/// 挂在独立子路由（仅 require_auth，不经 guard_write/read_only_guard）：
/// 诊断是**只读**语义，只读模式下同样可用；POST 仅为承载 question 请求体。
pub async fn diagnose(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<DiagnoseReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;

    let question = req.question.unwrap_or_default();
    let scope = route_scope(&question);
    let ctx = collect(&state).await;
    let findings = run_diagnosis(&ctx, scope);
    let summary = build_summary(&ctx, &findings);
    // LLM 叙事：仅当已配置且调用成功才填充；失败/未配置 → None（优雅降级）。
    let narrative = match crate::routes::settings::llm_config(&state).await {
        Ok(Some(cfg)) => generate_narrative(&cfg, scope, &summary, &findings).await,
        _ => None,
    };
    let report = AssistantReport {
        question,
        scope,
        generated_at: crate::now_unix(),
        summary,
        narrative,
        findings,
        ctx: brief(&ctx),
    };
    Ok(ok(report))
}

// ───────────────────────── 小工具 ─────────────────────────

/// KiB 人读（MiB/GiB，一位小数）。
fn human_kib(kib: u64) -> String {
    if kib >= 1024 * 1024 { format!("{:.1} GiB", kib as f64 / 1024.0 / 1024.0) }
    else if kib >= 1024 { format!("{:.1} MiB", kib as f64 / 1024.0) }
    else { format!("{kib} KiB") }
}

/// 字节人读。
pub(crate) fn human_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < U.len() - 1 { v /= 1024.0; u += 1; }
    if u == 0 { format!("{b} B") } else { format!("{v:.1} {}", U[u]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_os::{CpuSample, DiskSample, MemSample};

    fn snap(cpu: f32, load5: f32, cores: Option<Vec<f32>>, avail_pct: f64) -> SystemSnapshot {
        let total = 8_000_000u64; // KiB ≈ 7.6GiB
        SystemSnapshot {
            ts_unix: 0, uptime_sec: 0,
            cpu: CpuSample { total_pct: cpu, per_core_pct: cores, load1: 1.0, load5, load15: 1.0 },
            mem: MemSample {
                total_kib: total,
                used_kib: (total as f64 * (1.0 - avail_pct / 100.0)) as u64,
                available_kib: (total as f64 * avail_pct / 100.0) as u64,
                buffers_kib: 0, cached_kib: 0, swap_total_kib: 0, swap_used_kib: 0,
            },
            disks: Vec::new(), nets: Vec::new(), proc_count: 128, tcp_conns: 0,
            temps: Vec::new(),
        }
    }

    fn ctx(snap: SystemSnapshot) -> Ctx {
        Ctx {
            snap, top_cpu: vec![], top_mem: vec![], failed_units: vec![],
            err_lines: vec![], sec_risks: vec![], backup_plans: 1, backup_last_ok_age: Some(60),
        }
    }

    #[test]
    fn scope_routing_hits_expected_domains() {
        assert_eq!(route_scope("为什么 CPU 这么高"), "cpu");
        assert_eq!(route_scope("Load 好高"), "cpu");
        assert_eq!(route_scope("内存是不是泄漏了"), "mem");
        assert_eq!(route_scope("磁盘满了怎么办"), "disk");
        assert_eq!(route_scope("最近的报错看一下"), "log");
        assert_eq!(route_scope("nginx 服务挂了"), "service");
        assert_eq!(route_scope("安全基线扫描"), "security");
        assert_eq!(route_scope("备份多久跑一次"), "backup");
        assert_eq!(route_scope("系统体检"), "all");
        assert_eq!(route_scope(""), "all");
    }

    #[test]
    fn cpu_high_names_the_process() {
        let mut c = ctx(snap(92.0, 1.0, Some(vec![0.5; 4]), 50.0));
        c.top_cpu = vec![ProcessInfo {
            pid: 7, ppid: 1, name: "mining_frenzy".into(),
            cpu_pct: 91.0, rss_kib: 1024, cmdline: String::new(), user: None,
        }];
        let f = run_diagnosis(&c, "all");
        let cpu = f.iter().find(|x| x.id == "cpu.high").expect("应有 cpu.high");
        assert_eq!(cpu.severity, Severity::Crit);
        assert!(cpu.evidence.iter().any(|e| e.contains("mining_frenzy")), "证据应点名进程");
    }

    #[test]
    fn all_clear_yields_empty_and_summary_is_factual() {
        let c = ctx(snap(12.0, 0.5, Some(vec![0.1; 4]), 60.0));
        assert!(run_diagnosis(&c, "all").is_empty(), "健康上下文不应产生发现");
    }

    #[test]
    fn disk_ninety_percent_is_crit() {
        let mut c = ctx(snap(10.0, 0.5, Some(vec![0.1; 4]), 60.0));
        c.snap.disks = vec![DiskSample {
            mount_point: "/".into(), device: "/dev/sda1".into(), fs_type: "ext4".into(),
            total_bytes: 1000, used_bytes: 920, is_network_fs: false,
        }];
        let f = run_diagnosis(&c, "disk");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Crit);
        assert!(f[0].evidence[0].contains("/"), "证据应含挂载点");
    }

    #[test]
    fn mem_pressure_at_five_percent_is_crit() {
        let c = ctx(snap(10.0, 0.5, Some(vec![0.1; 4]), 5.0));
        let f = run_diagnosis(&c, "mem");
        assert_eq!(f[0].severity, Severity::Crit);
        assert_eq!(f[0].id, "mem.pressure");
    }

    #[test]
    fn load_rule_silent_without_core_count() {
        // per_core=None（低配档位）时不得凭空报负载
        let c = ctx(snap(10.0, 99.0, None, 60.0));
        assert!(run_diagnosis(&c, "cpu").iter().all(|f| f.id != "load.high"));
    }

    #[test]
    fn backup_rules_cover_all_three_states() {
        let mut c = ctx(snap(10.0, 0.5, Some(vec![0.1; 4]), 60.0));
        c.backup_plans = 0; c.backup_last_ok_age = None;
        assert_eq!(run_diagnosis(&c, "backup")[0].id, "backup.missing");
        c.backup_plans = 2;
        assert_eq!(run_diagnosis(&c, "backup")[0].id, "backup.never_ok");
        c.backup_last_ok_age = Some(9 * 86_400);
        assert_eq!(run_diagnosis(&c, "backup")[0].id, "backup.stale");
        c.backup_last_ok_age = Some(3600);
        assert!(run_diagnosis(&c, "backup").is_empty(), "最近备份成功 → 无发现");
    }

    #[test]
    fn narrative_prompt_carries_real_findings_only() {
        // 约束：提示词只能含我们真实采集到的字段，不得凭空给 LLM 喂系统内部数据。
        let f = Finding {
            id: "cpu.high",
            severity: Severity::Crit,
            title: "CPU 使用率过高（92%）".into(),
            evidence: vec!["mining_frenzy (pid 7) — CPU 91.0%".into()],
            suggestion: "按占用排行定位来源进程".into(),
            action: Some(Action { kind: "navigate", view: "/processes" }),
        };
        let p = build_prompt("cpu", "发现 1 项严重", std::slice::from_ref(&f));
        assert!(p.contains("cpu"), "应含诊断域");
        assert!(p.contains("发现 1 项严重"), "应含一句话结论");
        assert!(p.contains("mining_frenzy"), "应含真实证据（进程点名）");
        assert!(p.contains("不要编造"), "应约束 LLM 不得编造数据");
    }

    #[test]
    fn redact_for_llm_covers_the_four_leak_shapes() {
        // ① IPv4（端口等上下文保留）；四段点串的后边界防误伤
        assert_eq!(redact_for_llm("连接 10.0.0.5:443 失败"), "连接 <ip>:443 失败");
        assert_eq!(redact_for_llm("从 10.0.0.1 到 10.0.0.2 不通"), "从 <ip> 到 <ip> 不通");
        assert_eq!(redact_for_llm("版本 1.2.3.4.5 发布"), "版本 1.2.3.4.5 发布");
        // ② 邮箱（域名须含点；无点的本地账号不误判为邮箱）
        assert_eq!(redact_for_llm("联系 admin@example.com 处理"), "联系 <email> 处理");
        assert_eq!(redact_for_llm("root@localhost 本地账号"), "root@localhost 本地账号");
        // ③ 密钥样式键值：键名保留、值替换（大小写不敏感；引号值整体吃）
        assert_eq!(redact_for_llm("api_key=sk-live-12345"), "api_key=<redacted>");
        assert_eq!(redact_for_llm("password: hunter2"), "password: <redacted>");
        assert_eq!(redact_for_llm("TOKEN=abc"), "TOKEN=<redacted>");
        assert_eq!(redact_for_llm(r#"secret="p@ss w0rd""#), r#"secret=<redacted>"#);
        // 键名后紧跟字母 ⇒ 是更长的标识符，不是密钥键
        assert_eq!(redact_for_llm("tokens: 12"), "tokens: 12");
        // 有键无值不是泄漏，原样放过
        assert_eq!(redact_for_llm("password:"), "password:");
        // ④ Bearer：Authorization 两段值整体吃；裸 Bearer 也吃
        assert_eq!(
            redact_for_llm("Authorization: Bearer abc123"),
            "Authorization: <redacted>"
        );
        assert_eq!(redact_for_llm("bearer xyz 拒绝"), "Bearer <redacted> 拒绝");
    }

    #[test]
    fn redact_for_llm_keeps_diagnostic_signal() {
        // 路径与主机名**刻意不脱敏**——它们是诊断的核心证据（哪个日志、哪台机器）。
        // 这条测试钉住取舍：谁把这里改成脱敏，先改披露文案再改。
        let line = "nginx: [error] open() /var/log/nginx/error.log failed on web-01.corp";
        assert_eq!(redact_for_llm(line), line);
        assert_eq!(
            redact_for_llm("CPU 使用率 92%，内存可用 5%"),
            "CPU 使用率 92%，内存可用 5%"
        );
    }

    #[test]
    fn narrative_prompt_is_redacted_before_leaving_the_box() {
        // 端到端：build_prompt 是唯一出盒载荷（generate_narrative 只发它），
        // 证据里的四类高危形态一样都不许原样离开本机。
        let f = Finding {
            id: "log.errors",
            severity: Severity::Warn,
            title: "近期错误日志".into(),
            evidence: vec![
                "sshd[42]: Failed password for root from 10.0.0.5 port 22".into(),
                "app: smtp relay to admin@example.com rejected, api_key=sk-live-9f8e7d".into(),
            ],
            suggestion: "检查 /var/log/auth.log 与发信配置".into(),
            action: None,
        };
        let p = build_prompt("log", "内网 10.0.0.5 有暴力破解痕迹", std::slice::from_ref(&f));
        assert!(!p.contains("10.0.0.5"), "IP 必须脱敏");
        assert!(!p.contains("admin@example.com"), "邮箱必须脱敏");
        assert!(!p.contains("sk-live-9f8e7d"), "密钥必须脱敏");
        assert!(
            p.contains("<ip>") && p.contains("<email>") && p.contains("<redacted>"),
            "应有脱敏占位符"
        );
        // 诊断信号仍在——脱敏脱到叙事失效同样是失败
        assert!(p.contains("sshd") && p.contains("Failed password"), "进程与事件类型要保留");
        assert!(p.contains("/var/log/auth.log"), "路径是诊断证据，刻意不脱敏");
    }
}
