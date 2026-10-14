use super::*;


/// 统一日志源：**journald 优先**（有 `journalctl`），站点访问/错误日志走**文件 tail**。
///
/// 约束（与 `routes/logs.rs` 一致）：
/// - 行数上限 2000（服务端强制）；
/// - 过滤是**字面量子串**——journalctl `--grep` 是正则（ReDoS 风险），故在 Rust 侧过滤；
/// - 文件 tail 有界（最多回读 4MB），follow 用 500ms 轮询并检测轮转/截断。
pub struct LinuxLogs {
    backend: Option<LogBackend>,
    paths: Arc<LinuxPathLayout>,
}

impl LinuxLogs {
    pub fn detect(paths: Arc<LinuxPathLayout>) -> Self {
        let backend = if which("journalctl") { Some(LogBackend::Journald) } else { None };
        Self { backend, paths }
    }

    fn has_journal(&self) -> bool { matches!(self.backend, Some(LogBackend::Journald)) }

    /// 是否至少有一个可用日志源（journald 或站点日志文件）。能力位据此判定。
    pub fn available(&self) -> bool {
        if self.has_journal() { return true; }
        std::fs::read_dir(self.paths.web_log_dir())
            .map(|rd| rd.flatten().any(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.ends_with(".access.log") || n.ends_with(".error.log")
            }))
            .unwrap_or(false)
    }

    /// 站点日志源 id → 文件路径：`site:<stem>/access|error`
    fn site_file(&self, id: &str) -> Option<PathBuf> {
        let rest = id.strip_prefix("site:")?;
        let (stem, which) = rest.split_once('/')?;
        let ext = match which { "access" => "access.log", "error" => "error.log", _ => return None };
        Some(self.paths.web_log_dir().join(format!("{stem}.{ext}")))
    }
}

pub(super) fn is_file_source(kind: LogSourceKind) -> bool {
    matches!(kind, LogSourceKind::SiteAccess | LogSourceKind::SiteError | LogSourceKind::CustomFile)
}

/// 有界文件 tail：最多回读 4MB，取最后 n 行，按需字面量过滤。
pub(super) fn read_file_tail(path: &Path, n: usize, grep: Option<&str>, q: &LogQuery) -> Vec<LogLine> {
    use std::io::{Read, Seek, SeekFrom};
    const CAP: u64 = 4 * 1024 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else { return Vec::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len > CAP { let _ = f.seek(SeekFrom::Start(len - CAP)); }
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let mut it = text.lines();
    if len > CAP { it.next(); }   // 截断处的首行可能不完整 → 丢弃
    let mut out: Vec<LogLine> = it
        .filter(|l| grep.map(|g| g.is_empty() || l.contains(g)).unwrap_or(true))
        .map(|l| LogLine { ts_unix: None, level: None, text: l.to_string() })
        // level / since 与统计（analyze::level_idx → normalize_log_level）同口径。
        // 文件源的行没有时间戳：since 命中不了任何行——这是诚实的（"只要某时刻
        // 之后的日志"，而我们从不知道这些行的时刻），前端会按数据禁用该控件。
        .filter(|l| crate::traits::level_matches(q.level.as_deref(), l.level.as_deref(), &l.text))
        .filter(|l| q.since_unix.map(|s| l.ts_unix.is_some_and(|t| t >= s)).unwrap_or(true))
        .collect();
    if out.len() > n { out = out.split_off(out.len() - n); }
    out
}

/// 文件跟随：500ms 轮询读新增行；文件被截断/轮转（长度回退）即从头重读。
/// level 与一次性读同口径（normalize_log_level 文本兜底）。
pub(super) fn follow_file(path: PathBuf, grep: Option<String>, level: Option<String>) -> tokio::sync::mpsc::Receiver<LogLine> {
    use std::io::{Read, Seek, SeekFrom};
    let (tx, rx) = tokio::sync::mpsc::channel::<LogLine>(64);
    tokio::spawn(async move {
        let mut pos: u64 = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut iv = tokio::time::interval(Duration::from_millis(500));
        loop {
            iv.tick().await;
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if meta.len() < pos { pos = 0; }
            if meta.len() == pos { continue; }
            let Ok(mut f) = std::fs::File::open(&path) else { continue };
            if f.seek(SeekFrom::Start(pos)).is_err() { continue; }
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_err() { continue; }
            pos += buf.len() as u64;
            let text = String::from_utf8_lossy(&buf);
            for line in text.lines() {
                if let Some(g) = &grep {
                    if !g.is_empty() && !line.contains(g.as_str()) { continue; }
                }
                if !crate::traits::level_matches(level.as_deref(), None, line) { continue; }
                if tx.send(LogLine { ts_unix: None, level: None, text: line.to_string() }).await.is_err() {
                    return;
                }
            }
        }
    });
    rx
}

pub(super) fn journal_source_args(src: &LogSource) -> Vec<String> {
    match src.kind {
        LogSourceKind::Panel => vec!["-u".into(), "panel.service".into()],
        LogSourceKind::Service => vec!["-u".into(), src.id.clone()],
        _ => Vec::new(),   // system：不加过滤
    }
}

pub(super) fn prio_name(p: &str) -> String {
    match p { "0" | "1" | "2" | "3" => "error", "4" => "warn", "5" | "6" => "info", "7" => "debug",
              _ => "info" }.to_string()
}

/// 解析 `journalctl -o json` 的单行。
pub(super) fn parse_journal_json(line: &str) -> Option<LogLine> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let text = match v.get("MESSAGE") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => return None,
    };
    let ts_unix = v
        .get("__REALTIME_TIMESTAMP")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .map(|us| us / 1_000_000);
    let level = v.get("PRIORITY").and_then(|x| x.as_str()).map(prio_name);
    Some(LogLine { ts_unix, level, text })
}

pub(super) async fn journal_read(src: &LogSource, n: usize, q: &LogQuery) -> Result<Vec<LogLine>> {
    // 过滤在 Rust 侧做（journalctl --grep 是正则）：多取一些再筛，保证过滤后仍够 n 行。
    // level 同理——且刻意**不**用 journalctl 的 -p：那是"此级及更严重"的阈值语义，
    // 与面板统计/筛选的"精确档位"口径不同（选 warn 应只出 warn，不该混入 error）。
    let filtered = q.grep.is_some() || q.level.is_some();
    let fetch = if filtered { (n * 8).min(2000) } else { n };
    let mut args: Vec<String> = vec![
        "-n".into(), fetch.to_string(), "--no-pager".into(), "-o".into(), "json".into(),
    ];
    args.extend(journal_source_args(src));
    // since 走 journalctl 原生参数：@<unix> 精确到秒，服务端过滤，无需拉回再丢
    if let Some(s) = q.since_unix { args.push("--since".into()); args.push(format!("@{s}")); }
    let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = crate::cmd::run(
        Bin::Journalctl, &aref,
        CmdOpt { timeout: Duration::from_secs(10), ..Default::default() },
    ).await?;
    let mut lines: Vec<LogLine> = out.stdout
        .lines()
        .filter_map(parse_journal_json)
        .filter(|l| q.grep.as_deref().map(|g| g.is_empty() || l.text.contains(g)).unwrap_or(true))
        .filter(|l| crate::traits::level_matches(q.level.as_deref(), l.level.as_deref(), &l.text))
        .collect();
    if lines.len() > n { lines = lines.split_off(lines.len() - n); }
    Ok(lines)
}

pub(super) fn journal_follow(src: &LogSource) -> Result<tokio::sync::mpsc::Receiver<String>> {
    let mut args: Vec<String> = vec![
        "-f".into(), "-n".into(), "0".into(), "--no-pager".into(), "-o".into(), "json".into(),
    ];
    args.extend(journal_source_args(src));
    let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    crate::cmd::spawn_stream(Bin::Journalctl, &aref, 64)
}

#[async_trait]
impl LogProvider for LinuxLogs {
    fn backend(&self) -> LogBackend { self.backend.unwrap_or(LogBackend::File) }

    async fn sources(&self) -> Result<Vec<LogSource>> {
        let mut v = Vec::new();
        if self.has_journal() {
            v.push(LogSource { id: "system".into(), label: "系统日志（journald）".into(), kind: LogSourceKind::System });
            v.push(LogSource { id: "panel".into(), label: "面板日志（journald）".into(), kind: LogSourceKind::Panel });
        }
        // 站点访问/错误日志（扫描 web_log_dir；无需 DB）
        let dir = self.paths.web_log_dir();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let mut items: Vec<(String, String, LogSourceKind)> = Vec::new();
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(stem) = name.strip_suffix(".access.log") {
                    items.push((format!("site:{stem}/access"), format!("站点 {stem} · 访问日志"), LogSourceKind::SiteAccess));
                } else if let Some(stem) = name.strip_suffix(".error.log") {
                    items.push((format!("site:{stem}/error"), format!("站点 {stem} · 错误日志"), LogSourceKind::SiteError));
                }
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            for (id, label, kind) in items {
                v.push(LogSource { id, label, kind });
            }
        }
        Ok(v)
    }

    async fn read(&self, src: &LogSource, q: LogQuery) -> Result<Vec<LogLine>> {
        let n = q.lines.clamp(1, 2000);
        if is_file_source(src.kind) {
            let path = self.site_file(&src.id)
                .ok_or_else(|| PanelError::NotFound(format!("log source {}", src.id)))?;
            return Ok(read_file_tail(&path, n, q.grep.as_deref(), &q));
        }
        if self.has_journal() {
            return journal_read(src, n, &q).await;
        }
        unsupported!("logs.read: 无 journald 且非文件源")
    }

    async fn follow(&self, src: &LogSource, q: LogQuery) -> Result<tokio::sync::mpsc::Receiver<LogLine>> {
        if is_file_source(src.kind) {
            let path = self.site_file(&src.id)
                .ok_or_else(|| PanelError::NotFound(format!("log source {}", src.id)))?;
            return Ok(follow_file(path, q.grep.clone(), q.level.clone()));
        }
        if self.has_journal() {
            let mut raw = journal_follow(src)?;
            let (tx, rx) = tokio::sync::mpsc::channel::<LogLine>(64);
            // level 在解析后过滤（PRIORITY 字段此时才可用）；与一次性读同口径
            let level = q.level.clone();
            tokio::spawn(async move {
                while let Some(l) = raw.recv().await {
                    let parsed = parse_journal_json(&l)
                        .unwrap_or(LogLine { ts_unix: None, level: None, text: l.clone() });
                    if !crate::traits::level_matches(level.as_deref(), parsed.level.as_deref(), &parsed.text) {
                        continue;
                    }
                    if tx.send(parsed).await.is_err() { break; }
                }
            });
            return Ok(rx);
        }
        unsupported!("logs.follow: 无 journald 且非文件源")
    }
}

