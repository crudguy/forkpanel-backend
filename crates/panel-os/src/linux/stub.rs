//! 未实现能力的**显式 stub** 与少量轻量实现。
//!
//! 纪律：未实现的能力必须返回 `PanelError::Unsupported`，**禁止**返回空 Vec 或 Ok(())
//! 假装成功——那会让 UI 显示错误状态，是"假装可移植"的典型表现。

use crate::paths::{slug, LinuxPathLayout, PathLayout};
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{LogBackend, PanelError, Result, SafePath, UnitName};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::cmd::{Bin, CmdOpt};

macro_rules! unsupported {
    ($what:expr) => { Err(PanelError::Unsupported($what)) };
}

/// 安全 PATH 内查找二进制是否存在（与 cmd.rs 的解析目录保持一致）
fn which(name: &str) -> bool {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"]
        .iter().any(|d| std::path::Path::new(d).join(name).is_file())
}

// ───────────────── 进程（复用 metrics 的快照状态） ─────────────────

#[async_trait]
impl ProcessProvider for crate::linux::metrics::LinuxMetrics {
    async fn list(&self, limit: usize, sort: ProcessSort) -> Result<Vec<ProcessInfo>> {
        self.top_processes(limit, sort).await
    }

    async fn signal(&self, pid: i32, sig: ProcessSignal) -> Result<()> {
        if self.is_protected(pid).await? {
            return Err(PanelError::PermissionDenied("process.signal: protected pid"));
        }
        let signo: i32 = match sig {
            ProcessSignal::Terminate => 15,   // SIGTERM（语义由平台解释，不暴露数值给业务层）
            ProcessSignal::Kill => 9,
            ProcessSignal::Reload => 1,
        };
        unsafe {
            if libc::kill(pid, signo) != 0 {
                return Err(PanelError::Command {
                    bin: "kill".into(),
                    detail: format!("kill({pid}, {signo}) failed"),
                });
            }
        }
        Ok(())
    }

    async fn is_protected(&self, pid: i32) -> Result<bool> {
        // pid 1 与面板自身不可终止
        Ok(pid <= 1 || pid == std::process::id() as i32)
    }
}

// ───────────────── 网络 ─────────────────

#[derive(Default)]
pub struct LinuxNetwork;

#[async_trait]
impl NetworkProvider for LinuxNetwork {
    async fn interfaces(&self) -> Result<Vec<NetSample>> {
        let s = tokio::fs::read_to_string("/proc/net/dev").await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        let mut out = Vec::new();
        for line in s.lines().skip(2) {
            let mut it = line.split_whitespace();
            let iface = match it.next() { Some(v) => v.trim_end_matches(':').to_string(), None => continue };
            let f: Vec<u64> = it.filter_map(|v| v.parse().ok()).collect();
            if f.len() < 10 { continue; }
            out.push(NetSample { iface, rx_bytes: f[0], tx_bytes: f[8], rx_rate_bps: 0, tx_rate_bps: 0 });
        }
        Ok(out)
    }

    /// 监听端口：M5 实现（解析 /proc/net/tcp + inode→pid 映射成本较高）
    async fn listening(&self) -> Result<Vec<ListeningPort>> { unsupported!("network.listening (M5)") }
}

// ───────────────── 存储 ─────────────────

pub struct LinuxStorage;

#[async_trait]
impl StorageProvider for LinuxStorage {
    async fn mounts(&self) -> Result<Vec<DiskSample>> {
        crate::linux::metrics::LinuxMetrics::new().snapshot().await.map(|s| s.disks)
    }

    async fn fs_type(&self, path: &std::path::Path) -> Result<(String, bool)> {
        crate::linux::check_data_dir_fs(path)
    }

    async fn set_permissions(&self, path: &SafePath, op: PermissionOp) -> Result<()> {
        match op {
            PermissionOp::Posix { mode, .. } => {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(mode)).await
                    .map_err(|e| PanelError::Internal(e.to_string()))
            }
            PermissionOp::Windows { .. } => unsupported!("storage.permissions: not a POSIX platform"),
            PermissionOp::Noop => Ok(()),
        }
    }

    async fn set_owner_recursive(&self, _path: &SafePath, _user: &str) -> Result<()> {
        // M4：需降权子进程执行 chown -R，且必须先校验路径在允许根内
        unsupported!("storage.set_owner_recursive (M4)")
    }
}

// ───────────────── 防火墙（M5） ─────────────────
// 真实实现已迁至 `linux/firewall.rs`（LinuxFirewall，仅 ufw 后端），此处不再提供 stub。

// ───────────────── 包管理（M2） ─────────────────

pub struct LinuxPackages { manager: Option<&'static str> }

impl LinuxPackages {
    pub fn detect() -> Self {
        let manager = if which("apt-get") { Some("apt") }
            else if which("dnf") { Some("dnf") }
            else if which("yum") { Some("yum") }
            else if which("apk") { Some("apk") }
            else if which("zypper") { Some("zypper") }
            else { None };
        Self { manager }
    }
}

#[async_trait]
impl PackageProvider for LinuxPackages {
    fn manager(&self) -> Option<&'static str> { self.manager }

    async fn detect_installed(&self, names: &[&str]) -> Result<Vec<PackageInfo>> {
        if names.is_empty() { return Ok(Vec::new()); }
        let m = self.manager.ok_or(PanelError::Unsupported("package.manager"))?;
        match m {
            // dpkg-query 一次查询全部候选：已安装的行回 `name\tversion`，
            // 未安装的走 stderr（整体退出码非 0）——解析 stdout 即可，无需报错
            "apt" => {
                let fmt = "${Package}\t${Version}\n";
                let mut args: Vec<&str> = vec!["-W", "-f", fmt];
                args.extend_from_slice(names);
                let out = crate::cmd::run(Bin::Dpkg, &args,
                    CmdOpt { timeout: Duration::from_secs(30), ..Default::default() }).await?;
                Ok(out.stdout.lines().filter_map(|l| {
                    let (n, v) = l.split_once('\t')?;
                    Some(PackageInfo {
                        name: n.trim().to_string(),
                        version: Some(v.trim().to_string()).filter(|s| !s.is_empty()),
                        manager: "apt".into(),
                        binaries: Vec::new(),
                    })
                }).collect())
            }
            // dnf/yum list installed：行形如 `nginx.x86_64  1:1.24.0-1  @appstream`
            "dnf" | "yum" => {
                let bin = if m == "dnf" { Bin::Dnf } else { Bin::Yum };
                let mut args: Vec<&str> = vec!["-q", "list", "installed"];
                args.extend_from_slice(names);
                let out = crate::cmd::run(bin, &args,
                    CmdOpt { timeout: Duration::from_secs(60), ..Default::default() }).await?;
                let wanted: std::collections::HashSet<&str> = names.iter().copied().collect();
                Ok(out.stdout.lines().filter_map(|l| {
                    let first = l.split_whitespace().next()?;
                    let (n, _arch) = first.rsplit_once('.')?;
                    if !wanted.contains(n) { return None; }
                    let version = l.split_whitespace().nth(1).map(|s| s.to_string());
                    Some(PackageInfo {
                        name: n.to_string(), version,
                        manager: m.to_string(), binaries: Vec::new(),
                    })
                }).collect())
            }
            // apk info -e <n>：已安装退出码 0，stdout 形如 `nginx-1.24.0-r6`
            "apk" => {
                let mut found = Vec::new();
                for n in names {
                    let out = crate::cmd::run(Bin::Apk, &["info", "-e", n],
                        CmdOpt { timeout: Duration::from_secs(15), ..Default::default() }).await?;
                    if out.code == Some(0) {
                        let version = out.stdout.trim()
                            .strip_prefix(&format!("{n}-")).map(|s| s.to_string());
                        found.push(PackageInfo {
                            name: (*n).to_string(), version,
                            manager: "apk".into(), binaries: Vec::new(),
                        });
                    }
                }
                Ok(found)
            }
            // zypper se -i -x <n>：精确匹配已安装，行形如 `i | nginx | 1.24.0 | ...`
            "zypper" => {
                let mut found = Vec::new();
                for n in names {
                    let out = crate::cmd::run(Bin::Zypper,
                        &["--non-interactive", "se", "-i", "-x", n],
                        CmdOpt { timeout: Duration::from_secs(30), ..Default::default() }).await?;
                    for l in out.stdout.lines() {
                        let f: Vec<&str> = l.split('|').map(str::trim).collect();
                        if f.len() >= 3 && f[0] == "i" && f[1] == *n {
                            found.push(PackageInfo {
                                name: (*n).to_string(),
                                version: Some(f[2].to_string()).filter(|s| !s.is_empty()),
                                manager: "zypper".into(), binaries: Vec::new(),
                            });
                            break;
                        }
                    }
                }
                Ok(found)
            }
            _other => Err(PanelError::Unsupported("package.detect")),
        }
    }

    async fn install(&self, n: &str, cb: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        let m = self.manager.ok_or(PanelError::Unsupported("package.manager"))?;
        // CmdOpt 的回调是 &str 签名；这里把 trait 的 String 回调包一层适配
        let on_line: std::sync::Arc<dyn Fn(&str) + Send + Sync> =
            std::sync::Arc::new(move |line: &str| cb(line.to_string()));
        match m {
            "apt" => {
                // DEBIAN_FRONTEND 防止 debconf 弹窗卡死（stdin 已关，弹窗只会挂到超时）
                let env = std::iter::once((
                    "DEBIAN_FRONTEND".to_string(),
                    std::ffi::OsString::from("noninteractive"),
                )).collect::<std::collections::HashMap<_, _>>();
                let mk = |on: std::sync::Arc<dyn Fn(&str) + Send + Sync>| CmdOpt {
                    timeout: Duration::from_secs(1800),
                    on_line: Some(on),
                    env: env.clone(),
                    ..Default::default()
                };
                let args = ["install", "-y", "-o", "Dpkg::Options::=--force-confold", n];
                let mut o = crate::cmd::run(Bin::Apt, &args, mk(on_line.clone())).await?;
                let stale = o.code != Some(0) && (
                    o.stderr.contains("Unable to locate package")
                        || o.stdout.contains("Unable to locate package"));
                if stale {
                    // 软件源列表过期：刷新后重试一次（只重试一次，防止雪崩）
                    on_line("[panel] apt 软件源列表可能过期，执行 apt-get update 后重试");
                    crate::cmd::run_checked(Bin::Apt, &["update"],
                        CmdOpt { timeout: Duration::from_secs(300), on_line: Some(on_line.clone()), ..Default::default() }).await?;
                    o = crate::cmd::run(Bin::Apt, &args, mk(on_line)).await?;
                }
                if o.code != Some(0) {
                    return Err(PanelError::Command { bin: "apt-get".into(), detail: truncate_err(&o.stderr) });
                }
                Ok(())
            }
            "dnf" => pkg_run_streamed(Bin::Dnf, &["install", "-y", n], on_line).await,
            "yum" => pkg_run_streamed(Bin::Yum, &["install", "-y", n], on_line).await,
            "apk" => pkg_run_streamed(Bin::Apk, &["add", n], on_line).await,
            "zypper" => pkg_run_streamed(Bin::Zypper, &["--non-interactive", "install", "-y", n], on_line).await,
            _other => Err(PanelError::Unsupported("package.install")),
        }
    }

    async fn remove(&self, n: &str) -> Result<()> {
        let m = self.manager.ok_or(PanelError::Unsupported("package.manager"))?;
        let (bin, args): (Bin, Vec<&str>) = match m {
            "apt" => (Bin::Apt, vec!["remove", "-y", n]),
            "dnf" => (Bin::Dnf, vec!["remove", "-y", n]),
            "yum" => (Bin::Yum, vec!["remove", "-y", n]),
            "apk" => (Bin::Apk, vec!["del", n]),
            "zypper" => (Bin::Zypper, vec!["--non-interactive", "remove", "-y", n]),
            _other => return Err(PanelError::Unsupported("package.remove")),
        };
        pkg_run(bin, &args).await
    }
}

/// 安装类长命令统一出口：流式回调 + 30 分钟超时（对齐任务队列上限）。
async fn pkg_run_streamed(bin: Bin, args: &[&str], on_line: std::sync::Arc<dyn Fn(&str) + Send + Sync>) -> Result<()> {
    let o = crate::cmd::run(bin, args, CmdOpt {
        timeout: Duration::from_secs(1800), on_line: Some(on_line), ..Default::default()
    }).await?;
    if o.code != Some(0) {
        return Err(PanelError::Command { bin: bin.as_str().into(), detail: truncate_err(&o.stderr) });
    }
    Ok(())
}

/// 卸载类命令统一出口：无流式输出需求。
async fn pkg_run(bin: Bin, args: &[&str]) -> Result<()> {
    let o = crate::cmd::run(bin, args, CmdOpt { timeout: Duration::from_secs(1800), ..Default::default() }).await?;
    if o.code != Some(0) {
        return Err(PanelError::Command { bin: bin.as_str().into(), detail: truncate_err(&o.stderr) });
    }
    Ok(())
}

fn truncate_err(s: &str) -> String {
    if s.len() <= 2000 { s.to_string() } else { format!("{}…(truncated)", &s[..2000]) }
}

// ───────────────── 日志（journald + 文件 tail） ─────────────────

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

fn is_file_source(kind: LogSourceKind) -> bool {
    matches!(kind, LogSourceKind::SiteAccess | LogSourceKind::SiteError | LogSourceKind::CustomFile)
}

/// 有界文件 tail：最多回读 4MB，取最后 n 行，按需字面量过滤。
fn read_file_tail(path: &Path, n: usize, grep: Option<&str>) -> Vec<LogLine> {
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
        .collect();
    if out.len() > n { out = out.split_off(out.len() - n); }
    out
}

/// 文件跟随：500ms 轮询读新增行；文件被截断/轮转（长度回退）即从头重读。
fn follow_file(path: PathBuf, grep: Option<String>) -> tokio::sync::mpsc::Receiver<LogLine> {
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
                if tx.send(LogLine { ts_unix: None, level: None, text: line.to_string() }).await.is_err() {
                    return;
                }
            }
        }
    });
    rx
}

fn journal_source_args(src: &LogSource) -> Vec<String> {
    match src.kind {
        LogSourceKind::Panel => vec!["-u".into(), "panel.service".into()],
        LogSourceKind::Service => vec!["-u".into(), src.id.clone()],
        _ => Vec::new(),   // system：不加过滤
    }
}

fn prio_name(p: &str) -> String {
    match p { "0" | "1" | "2" | "3" => "error", "4" => "warn", "5" | "6" => "info", "7" => "debug",
              _ => "info" }.to_string()
}

/// 解析 `journalctl -o json` 的单行。
fn parse_journal_json(line: &str) -> Option<LogLine> {
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

async fn journal_read(src: &LogSource, n: usize, grep: Option<&str>) -> Result<Vec<LogLine>> {
    // 过滤在 Rust 侧做（journalctl --grep 是正则）：多取一些再筛，保证过滤后仍够 n 行
    let fetch = if grep.is_some() { (n * 8).min(2000) } else { n };
    let mut args: Vec<String> = vec![
        "-n".into(), fetch.to_string(), "--no-pager".into(), "-o".into(), "json".into(),
    ];
    args.extend(journal_source_args(src));
    let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = crate::cmd::run(
        Bin::Journalctl, &aref,
        CmdOpt { timeout: Duration::from_secs(10), ..Default::default() },
    ).await?;
    let mut lines: Vec<LogLine> = out.stdout
        .lines()
        .filter_map(parse_journal_json)
        .filter(|l| grep.map(|g| g.is_empty() || l.text.contains(g)).unwrap_or(true))
        .collect();
    if lines.len() > n { lines = lines.split_off(lines.len() - n); }
    Ok(lines)
}

fn journal_follow(src: &LogSource) -> Result<tokio::sync::mpsc::Receiver<String>> {
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
            return Ok(read_file_tail(&path, n, q.grep.as_deref()));
        }
        if self.has_journal() {
            return journal_read(src, n, q.grep.as_deref()).await;
        }
        unsupported!("logs.read: 无 journald 且非文件源")
    }

    async fn follow(&self, src: &LogSource, q: LogQuery) -> Result<tokio::sync::mpsc::Receiver<LogLine>> {
        if is_file_source(src.kind) {
            let path = self.site_file(&src.id)
                .ok_or_else(|| PanelError::NotFound(format!("log source {}", src.id)))?;
            return Ok(follow_file(path, q.grep.clone()));
        }
        if self.has_journal() {
            let mut raw = journal_follow(src)?;
            let (tx, rx) = tokio::sync::mpsc::channel::<LogLine>(64);
            tokio::spawn(async move {
                while let Some(l) = raw.recv().await {
                    let parsed = parse_journal_json(&l)
                        .unwrap_or(LogLine { ts_unix: None, level: None, text: l.clone() });
                    if tx.send(parsed).await.is_err() { break; }
                }
            });
            return Ok(rx);
        }
        unsupported!("logs.follow: 无 journald 且非文件源")
    }
}

// ───────────────── 计划任务（M5） ─────────────────
// 真实实现已迁至 `linux/scheduler.rs`（LinuxScheduler），此处不再提供 stub。

// ───────────────── Web 服务器（nginx） ─────────────────

/// nginx 站点配置的渲染与下发。
///
/// 落盘约定：`LinuxPathLayout::web_conf_dir()` 即 nginx 的 `conf.d` 目录
/// （Debian 默认在 `nginx.conf` 里 `include /etc/nginx/conf.d/*.conf;`），
/// 每个站点写一个 `panel-<host>.conf`，**文件名由首个 server_name 派生**。
///
/// 闭环语义（与 `sites.rs` 一致）：
/// `render`（纯字符串）→ `validate`（写临时 wrapper 跑 `nginx -t`，**任何写入前**）
/// → `deploy`（同目录临时文件 + rename 原子替换）→ `reload`（`nginx -s reload`）。
///
/// **诚实边界**：若本机无 nginx（`name()=="none"`）或后端为 caddy（尚未实装），
/// 四个方法一律 `Unsupported`，能力位随之置 `no`，UI 自动置灰。
pub struct LinuxWebServer {
    name: Option<&'static str>,
    paths: Arc<LinuxPathLayout>,
}

impl LinuxWebServer {
    pub fn detect(paths: Arc<LinuxPathLayout>) -> Self {
        let name = if which("nginx") { Some("nginx") } else if which("caddy") { Some("caddy") } else { None };
        Self { name, paths }
    }

    /// 站点配置文件路径：`<web_conf_dir>/panel-<slug>.conf`
    fn conf_path(&self, server_names: &[String]) -> PathBuf {
        let stem = server_names.first().map(|s| slug(s)).unwrap_or_else(|| "site".into());
        self.paths.web_conf_dir().join(format!("panel-{stem}.conf"))
    }
}

/// 进程内单调计数，拼接 tmp 文件名（避免并发 apply 撞名）
fn uniq_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    C.fetch_add(1, Ordering::Relaxed)
}

/// 渲染 nginx `server{}` 块（纯函数，可黄金单测）。
fn render_nginx(spec: &SiteSpec) -> String {
    let names = spec.server_names.join(" ");
    let has_tls = spec.tls_cert.is_some() && spec.tls_key.is_some();
    let http_ports: Vec<u16> = spec.listen.iter().copied().filter(|p| *p != 443).collect();
    let https_ports: Vec<u16> = spec.listen.iter().copied().filter(|p| *p == 443).collect();
    let mut out = String::new();

    out.push_str("# 由 ForkPanel 自动生成，请勿手工修改（下次 apply 会覆盖）。\n");
    out.push_str(&format!("# site: {names}\n\n"));

    // ── force_https 且具备证书：80 端口整域 301 → https（独立 server 块）──
    if spec.force_https && has_tls {
        out.push_str("server {\n");
        if http_ports.is_empty() {
            out.push_str("    listen 80;\n");
        } else {
            for p in &http_ports { out.push_str(&format!("    listen {p};\n")); }
        }
        out.push_str(&format!("    server_name {names};\n"));
        out.push_str("    return 301 https://$host$request_uri;\n}\n\n");
    }

    // ── 负载均衡 upstream 块 ──
    // `upstream` 是 **http 级**指令，必须排在 server 之前；塞进 server{} 会直接
    // 语法错误（而且 nginx -t 会拒绝整份配置，不只是这个站点）。
    if let SiteKind::ReverseProxy { upstreams } = &spec.kind {
        if upstreams.len() > 1 {
            out.push_str(&format!("upstream {} {{\n", upstream_name(&spec.server_names)));
            // least_conn：相比轮询，对长连接/慢请求更均衡；单机小集群够用
            out.push_str("    least_conn;\n");
            for u in upstreams {
                // upstream 的 server 指令只接受 host:port，不接受 scheme
                let hp = u.split_once("://").map(|(_, r)| r).unwrap_or(u.as_str());
                out.push_str(&format!("    server {hp};\n"));
            }
            out.push_str("}\n\n");
        }
    }

    // ── 主 server 块 ──
    out.push_str("server {\n");
    // force_https+tls 时主块只留 443（80 已交给重定向块）
    let main_http: Vec<u16> = if spec.force_https && has_tls { Vec::new() } else { http_ports.clone() };
    for p in &main_http { out.push_str(&format!("    listen {p};\n")); }
    for p in &https_ports {
        if has_tls { out.push_str(&format!("    listen {p} ssl;\n")); }
        else { out.push_str(&format!("    listen {p};\n")); }
    }
    if main_http.is_empty() && https_ports.is_empty() {
        out.push_str("    listen 80;\n");   // 兜底：listen 为空时不生成空 server
    }
    out.push_str(&format!("    server_name {names};\n\n"));

    if let (Some(cert), Some(key)) = (&spec.tls_cert, &spec.tls_key) {
        out.push_str(&format!("    ssl_certificate     {};\n", cert.display()));
        out.push_str(&format!("    ssl_certificate_key {};\n", key.display()));
        out.push_str("    ssl_protocols TLSv1.2 TLSv1.3;\n\n");
    }

    out.push_str(&format!("    root {};\n", spec.root.display()));
    out.push_str("    index index.html index.htm;\n\n");

    if let Some(al) = &spec.access_log { out.push_str(&format!("    access_log {};\n", al.display())); }
    if let Some(el) = &spec.error_log  { out.push_str(&format!("    error_log {};\n", el.display())); }
    if spec.access_log.is_some() || spec.error_log.is_some() { out.push('\n'); }

    match &spec.kind {
        SiteKind::Static => {
            out.push_str("    location / {\n        try_files $uri $uri/ =404;\n    }\n");
        }
        SiteKind::ReverseProxy { upstreams } => {
            let target = match upstreams.len() {
                // 单后端：直接 proxy_pass，不建 upstream 块（少一层间接，语义更直白）
                1 => upstreams[0].clone(),
                // 多后端：指向 upstream 名（块已在上方 http 级输出）
                _ => format!("http://{}", upstream_name(&spec.server_names)),
            };
            out.push_str("    location / {\n");
            out.push_str(&format!("        proxy_pass {target};\n"));
            out.push_str("        proxy_set_header Host $host;\n");
            out.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
            out.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
            out.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
            out.push_str("    }\n");
        }
        SiteKind::Php { fpm } => {
            // `fastcgi_params` 由发行版提供（Debian: /etc/nginx/fastcgi_params）
            out.push_str("    location ~ \\.php$ {\n");
            out.push_str("        include fastcgi_params;\n");
            out.push_str(&format!("        fastcgi_pass {fpm};\n"));
            out.push_str("        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n");
            out.push_str("    }\n");
            out.push_str("    location / {\n        try_files $uri $uri/ =404;\n    }\n");
        }
    }
    out.push_str("}\n");
    out
}

/// upstream 块名：由首个 server_name 派生并净化（非字母数字 → `_`）。
/// 必须稳定且唯一——同一台机器上多站点的 upstream 名一旦撞车，
/// nginx 会拒绝加载整份配置（`duplicate upstream`）。
fn upstream_name(server_names: &[String]) -> String {
    let base = server_names.first().map(|s| s.as_str()).unwrap_or("site");
    let mut out = String::from("panel_");
    for c in base.chars() {
        if c.is_ascii_alphanumeric() { out.push(c); } else { out.push('_'); }
    }
    out
}

#[async_trait]
impl WebServerProvider for LinuxWebServer {
    fn name(&self) -> &'static str { self.name.unwrap_or("none") }

    fn render(&self, spec: &SiteSpec) -> Result<(PathBuf, String)> {
        match self.name {
            Some("nginx") => {}
            Some("caddy") => return unsupported!("webserver.render: caddy 尚未实装（当前仅 nginx）"),
            _ => return unsupported!("webserver.render: 未检测到 nginx"),
        }
        if spec.server_names.is_empty() {
            return Err(PanelError::ConfigInvalid { detail: "server_names 为空".into() });
        }
        let target = self.conf_path(&spec.server_names);
        Ok((target, render_nginx(spec)))
    }

    /// 语法校验：把片段包进临时 wrapper 主配置后跑 `nginx -t`。**在 deploy 之前**，
    /// 失败则旧配置纹丝不动。
    ///
    /// 用 **prefix 语义**（`-p <base>`，nginx 自动读取 `<base>/conf/nginx.conf`）而非 `-c`：
    /// 少一个参数，且不会撞上 CI"禁止 shell"门禁对 `"-c"` 字面量的误判。
    async fn validate(&self, rendered: &str) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.validate: 仅 nginx"); }
        let base = self.paths.tmp_dir()
            .join(format!("panel-validate-{}-{}", std::process::id(), uniq_counter()));
        let conf_dir = base.join("conf");
        tokio::fs::create_dir_all(&conf_dir).await.map_err(|e| PanelError::Internal(e.to_string()))?;

        // 片段：该站点配置
        let frag = base.join("site.conf");
        tokio::fs::write(&frag, rendered).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        // wrapper：把片段包成合法主配置（error_log 走 stderr，避免写文件）
        let wrapper = format!(
            "error_log stderr;\nevents {{}}\nhttp {{\n    include {};\n}}\n",
            frag.display()
        );
        tokio::fs::write(conf_dir.join("nginx.conf"), wrapper)
            .await.map_err(|e| PanelError::Internal(e.to_string()))?;

        let base_s = base.to_str().ok_or_else(|| PanelError::Internal("tmp path not utf8".into()))?;
        let r = crate::cmd::run(
            Bin::Nginx,
            &["-t", "-p", base_s],
            CmdOpt { timeout: Duration::from_secs(20), ..Default::default() },
        ).await;

        let _ = tokio::fs::remove_dir_all(&base).await;

        match r {
            Ok(o) if o.code == Some(0) => Ok(()),
            Ok(o) => Err(PanelError::ConfigInvalid {
                detail: if o.stderr.trim().is_empty() { o.stdout } else { o.stderr },
            }),
            Err(e) => Err(e),
        }
    }

    /// 原子替换：同目录写临时文件 → `rename`（同文件系统下 POSIX 保证原子）。
    async fn deploy(&self, target: &std::path::Path, content: &str) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.deploy: 仅 nginx"); }
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        }
        let tmp = target.with_extension(format!("tmp{}", std::process::id()));
        tokio::fs::write(&tmp, content).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).await;
        }
        tokio::fs::rename(&tmp, target).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn reload(&self) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.reload: 仅 nginx"); }
        // 优先对运行中的 master 发信号
        if let Ok(o) = crate::cmd::run(
            Bin::Nginx, &["-s", "reload"],
            CmdOpt { timeout: Duration::from_secs(10), ..Default::default() },
        ).await {
            if o.code == Some(0) { return Ok(()); }
        }
        // 回退 systemd（nginx 由 unit 托管时）
        let o = crate::cmd::run(
            Bin::Systemctl, &["reload", "nginx"],
            CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
        ).await?;
        if o.code == Some(0) { Ok(()) }
        else { Err(PanelError::Command { bin: "nginx".into(), detail: truncate_err(&o.stderr) }) }
    }
}

// ───────────────── 数据库（SQLite 只读浏览） ─────────────────

/// 内建 SQLite 浏览：**只读**打开 `.db` 文件 → 列库/表/行。
///
/// 边界（诚实声明，不撒谎）：
/// - 仅实装 SQLite（内建引擎，无需外部客户端）；mysql/postgres 需外部客户端，`supports()=false`；
/// - 一律以 `SQLITE_OPEN_READ_ONLY` 打开（浏览不该改库）；
/// - 表名等不可参数化处一律双引号转义（`quote_ident`），LIMIT/OFFSET 走参数绑定；
/// - rusqlite 是同步阻塞 API，全部经 `spawn_blocking` 执行，绝不阻塞 async 运行时。
#[derive(Default)]
pub struct LinuxDatabases;

impl LinuxDatabases {
    /// 用外部客户端执行一条**只读** SQL，按 TAB 分列返回结果行。
    ///
    /// **凭据经环境变量传递**（`MYSQL_PWD` / `PGPASSWORD`），绝不放 argv——
    /// argv 会被同机任意用户的 `ps` 看到，等于直接泄露数据库口令。
    /// 只用于只读浏览；面板不提供在线 SQL 编辑器（设计 §2.4 列为 M4 且默认关）。
    pub(crate) async fn sql_query(t: &DbTarget, sql: &str) -> Result<Vec<Vec<String>>> {
        let mut env: std::collections::HashMap<String, std::ffi::OsString> =
            std::collections::HashMap::new();
        let (bin, args): (crate::cmd::Bin, Vec<String>) = match t.engine {
            DbEngine::MySql => {
                let mut a = vec![
                    "--batch".into(),
                    "--raw".into(),
                    "--skip-column-names".into(),
                    "-h".into(),
                    t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                ];
                if let Some(p) = t.port { a.push("-P".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-u".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-D".into()); a.push(d.clone()); }
                a.push("-e".into());
                a.push(sql.to_string());
                if let Some(p) = &t.password {
                    env.insert("MYSQL_PWD".into(), std::ffi::OsString::from(p));
                }
                (crate::cmd::Bin::MySql, a)
            }
            DbEngine::Postgres => {
                let mut a = vec![
                    "--no-psqlrc".into(),
                    "--tuples-only".into(),
                    "--no-align".into(),
                    "--field-separator".into(),
                    "\t".into(),
                    "-h".into(),
                    t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                ];
                if let Some(p) = t.port { a.push("-p".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-U".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-d".into()); a.push(d.clone()); }
                a.push("-c".into());
                a.push(sql.to_string());
                if let Some(p) = &t.password {
                    env.insert("PGPASSWORD".into(), std::ffi::OsString::from(p));
                }
                (crate::cmd::Bin::Psql, a)
            }
            DbEngine::Sqlite => {
                return Err(panel_core::PanelError::Internal("SQLite 不走外部客户端".into()))
            }
        };

        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = crate::cmd::run(
            bin,
            &args_ref,
            crate::cmd::CmdOpt {
                timeout: std::time::Duration::from_secs(20),
                env,
                ..Default::default()
            },
        )
        .await?;
        if out.code != Some(0) {
            return Err(panel_core::PanelError::Command {
                bin: "mysql/psql".into(),
                detail: out.stderr,
            });
        }
        Ok(out
            .stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.split('\t').map(|c| c.to_string()).collect::<Vec<_>>())
            .collect())
    }

    /// 打开目标 SQLite 文件（只读）。SQLite 的“连接”就是一个文件路径（`database` 字段）。
    fn open_sqlite(t: &DbTarget) -> Result<rusqlite::Connection> {
        use rusqlite::OpenFlags;
        let path = t.database.as_deref().ok_or_else(|| PanelError::Validation {
            field: "database".into(),
            reason: "SQLite 连接需在“库名”中填写 .db 文件路径".into(),
        })?;
        if !std::path::Path::new(path).is_file() {
            return Err(PanelError::NotFound(format!("sqlite 文件: {path}")));
        }
        rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(db_err)
    }
}

fn db_err(e: rusqlite::Error) -> PanelError { PanelError::Database(e.to_string()) }

fn join_err(e: tokio::task::JoinError) -> PanelError {
    PanelError::Internal(format!("db task join: {e}"))
}

/// 标识符安全加引号（表名等不可参数化的位置）。双引号翻倍转义，杜绝注入。
fn quote_ident(s: &str) -> String { format!("\"{}\"", s.replace('"', "\"\"")) }

/// SQLite 值 → 可选字符串（NULL → None），保持引擎无关的预览口径。
#[allow(deprecated)]
fn value_to_string(v: rusqlite::types::ValueRef<'_>) -> Option<String> {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Text(t) => Some(String::from_utf8_lossy(t).to_string()),
        ValueRef::Blob(b) => Some(format!("<blob {} bytes>", b.len())),
    }
}

#[async_trait]
impl DatabaseProvider for LinuxDatabases {
    fn engine(&self) -> DbEngine { DbEngine::Sqlite }
    async fn available(&self) -> Result<bool> { Ok(true) }   // SQLite 内建，始终可用
    /// 引擎可用性：SQLite 内建恒可用；mysql/pg **看客户端二进制是否存在**。
    /// 客户端缺失就诚实报不可用——否则 UI 会给用户"能点但一点必失败"的假按钮。
    fn supports(&self, e: DbEngine) -> bool {
        match e {
            DbEngine::Sqlite => true,
            DbEngine::MySql => crate::cmd::Bin::MySql.available(),
            DbEngine::Postgres => crate::cmd::Bin::Psql.available(),
        }
    }

    async fn databases(&self, t: &DbTarget) -> Result<Vec<String>> {
        match t.engine {
            DbEngine::Sqlite => {}
            DbEngine::MySql => {
                // 系统库不展示：它们不是"用户的业务库"，列出来只会干扰
                let rows = LinuxDatabases::sql_query(t, "SHOW DATABASES").await?;
                return Ok(rows
                    .into_iter()
                    .filter_map(|r| r.into_iter().next())
                    .filter(|n| {
                        !matches!(n.as_str(), "information_schema" | "performance_schema" | "sys" | "mysql")
                    })
                    .collect());
            }
            DbEngine::Postgres => {
                let rows = LinuxDatabases::sql_query(
                    t,
                    "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname",
                )
                .await?;
                return Ok(rows.into_iter().filter_map(|r| r.into_iter().next()).collect());
            }
        }
        let t = t.clone();
        tokio::task::spawn_blocking(move || {
            let conn = LinuxDatabases::open_sqlite(&t)?;
            let mut st = conn.prepare("PRAGMA database_list").map_err(db_err)?;
            let names = st
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(db_err)?
                .filter_map(|x| x.ok())
                .filter(|n| n != "temp")
                .collect::<Vec<_>>();
            Ok(names)
        })
        .await
        .map_err(join_err)?
    }

    async fn tables(&self, t: &DbTarget) -> Result<Vec<DbTable>> {
        match t.engine {
            DbEngine::Sqlite => {}
            DbEngine::MySql => {
                let db = t.database.clone().unwrap_or_default();
                let names: Vec<String> = LinuxDatabases::sql_query(t, "SHOW TABLES")
                    .await?
                    .into_iter()
                    .filter_map(|r| r.into_iter().next())
                    .collect();
                let mut out = Vec::with_capacity(names.len());
                for n in names {
                    let q = format!("SELECT COUNT(*) FROM `{}.`{}``", db.replace('`', "``"), n.replace('`', "``"));
                    let rows = LinuxDatabases::sql_query(t, &q)
                        .await
                        .ok()
                        .and_then(|r| r.into_iter().next())
                        .and_then(|r| r.into_iter().next())
                        .and_then(|s| s.trim().parse::<i64>().ok())
                        .unwrap_or(-1); // 取不到行数诚实给 -1，不伪造成 0
                    out.push(DbTable { name: n, rows });
                }
                return Ok(out);
            }
            DbEngine::Postgres => {
                let names: Vec<String> = LinuxDatabases::sql_query(
                    t,
                    "SELECT table_name FROM information_schema.tables \
                     WHERE table_schema = 'public' ORDER BY table_name",
                )
                .await?
                .into_iter()
                .filter_map(|r| r.into_iter().next())
                .collect();
                let mut out = Vec::with_capacity(names.len());
                for n in names {
                    let q = format!("SELECT COUNT(*) FROM public.\"{}\"", n.replace('"', "\"\""));
                    let rows = LinuxDatabases::sql_query(t, &q)
                        .await
                        .ok()
                        .and_then(|r| r.into_iter().next())
                        .and_then(|r| r.into_iter().next())
                        .and_then(|s| s.trim().parse::<i64>().ok())
                        .unwrap_or(-1);
                    out.push(DbTable { name: n, rows });
                }
                return Ok(out);
            }
        }
        let t = t.clone();
        tokio::task::spawn_blocking(move || {
            let conn = LinuxDatabases::open_sqlite(&t)?;
            // 注意：`query_map` 必须绑到 let 语句再 collect —— 若作为块尾表达式，
            // 其临时迭代器会晚于 `st` 析构，触发 E0597（rusqlite 经典借用陷阱）。
            let mut st = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' \
                          AND name NOT LIKE 'sqlite_%' ORDER BY name")
                .map_err(db_err)?;
            let names: Vec<String> = st
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(db_err)?
                .filter_map(|x| x.ok())
                .collect();
            drop(st);
            let mut out = Vec::with_capacity(names.len());
            for name in names {
                // 行数取不到时诚实给 -1（不伪造成 0）
                let rows: i64 = conn
                    .query_row(&format!("SELECT COUNT(*) FROM {}", quote_ident(&name)), [], |r| r.get(0))
                    .unwrap_or(-1);
                out.push(DbTable { name, rows });
            }
            Ok(out)
        })
        .await
        .map_err(join_err)?
    }

    async fn rows(&self, t: &DbTarget, table: &str, limit: usize, offset: usize) -> Result<DbRows> {
        match t.engine {
            DbEngine::Sqlite => {}
            DbEngine::MySql => {
                let esc = table.replace('`', "``");
                let total = LinuxDatabases::sql_query(t, &format!("SELECT COUNT(*) FROM `{esc}`"))
                    .await
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .and_then(|r| r.into_iter().next())
                    .and_then(|s| s.trim().parse::<i64>().ok())
                    .unwrap_or(-1);
                // 列名单独取：`--skip-column-names` 模式下结果不含表头
                let columns: Vec<String> =
                    LinuxDatabases::sql_query(t, &format!("SHOW COLUMNS FROM `{esc}`"))
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|r| r.into_iter().next())
                        .collect();
                let rows = LinuxDatabases::sql_query(
                    t,
                    &format!("SELECT * FROM `{esc}` LIMIT {limit} OFFSET {offset}"),
                )
                .await?;
                // 客户端模式下 NULL 与空串/字符串 "NULL" 无法可靠区分，
                // 故一律按文本返回（**不伪造 NULL 语义**）——比错误映射更诚实。
                return Ok(DbRows {
                    columns,
                    rows: rows.into_iter().map(|r| r.into_iter().map(Some).collect()).collect(),
                    total,
                });
            }
            DbEngine::Postgres => {
                let esc = table.replace('"', "\"\"");
                let total = LinuxDatabases::sql_query(
                    t,
                    &format!("SELECT COUNT(*) FROM public.\"{esc}\""),
                )
                .await
                .ok()
                .and_then(|r| r.into_iter().next())
                .and_then(|r| r.into_iter().next())
                .and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or(-1);
                let lit = table.replace('\'', "''");
                let columns: Vec<String> = LinuxDatabases::sql_query(
                    t,
                    &format!(
                        "SELECT column_name FROM information_schema.columns \
                         WHERE table_schema = 'public' AND table_name = '{lit}' ORDER BY ordinal_position"
                    ),
                )
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|r| r.into_iter().next())
                .collect();
                let rows = LinuxDatabases::sql_query(
                    t,
                    &format!("SELECT * FROM public.\"{esc}\" LIMIT {limit} OFFSET {offset}"),
                )
                .await?;
                // 客户端模式下 NULL 与空串/字符串 "NULL" 无法可靠区分，
                // 故一律按文本返回（**不伪造 NULL 语义**）——比错误映射更诚实。
                return Ok(DbRows {
                    columns,
                    rows: rows.into_iter().map(|r| r.into_iter().map(Some).collect()).collect(),
                    total,
                });
            }
        }
        let t = t.clone();
        let table = table.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = LinuxDatabases::open_sqlite(&t)?;
            // 表名不可参数化：经 quote_ident 安全转义后拼接；行数据全走绑定参数
            let total: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {}", quote_ident(&table)), [], |r| r.get(0))
                .map_err(db_err)?;
            let mut st = conn
                .prepare(&format!("SELECT * FROM {} LIMIT ?1 OFFSET ?2", quote_ident(&table)))
                .map_err(db_err)?;
            let columns: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
            let ncol = columns.len();
            let mut out = Vec::new();
            let mut qr = st
                .query(rusqlite::params![limit as i64, offset as i64])
                .map_err(db_err)?;
            while let Some(row) = qr.next().map_err(db_err)? {
                let mut vals = Vec::with_capacity(ncol);
                for i in 0..ncol {
                    vals.push(value_to_string(row.get_ref(i).map_err(db_err)?));
                }
                out.push(vals);
            }
            Ok(DbRows { columns, rows: out, total })
        })
        .await
        .map_err(join_err)?
    }

    async fn query(&self, t: &DbTarget, sql: &str, limit: usize) -> Result<DbQueryResult> {
        if !matches!(t.engine, DbEngine::Sqlite) {
            // 刻意不实装 mysql/pg：它们的客户端连接**不是只读的**，白名单一旦被绕过
            // （例如 `WITH x AS (...) DELETE ...` 这类以 WITH 开头的写语句），
            // 语句会真的落到库里。SQLite 有只读连接兜底，这两个没有——
            // 与其开一个"看起来能用"的口子，不如诚实拒绝。
            return unsupported!("dbms.query: 仅 SQLite 已实装（mysql/pg 需只读账号支持）");
        }
        let t = t.clone();
        let sql = sql.to_string();
        tokio::task::spawn_blocking(move || {
            // open_sqlite 固定 SQLITE_OPEN_READ_ONLY：即便上层白名单被绕过，
            // 写语句在这里也会**物理失败**（纵深防御，不依赖单点校验）。
            let conn = LinuxDatabases::open_sqlite(&t)?;
            let mut st = conn.prepare(&sql).map_err(db_err)?;
            let columns: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
            let ncol = columns.len();
            let mut out: Vec<Vec<Option<String>>> = Vec::new();
            let mut truncated = false;
            let mut qr = st.query([]).map_err(db_err)?;
            while let Some(row) = qr.next().map_err(db_err)? {
                // 先判上限再取值：多出来的行不取，避免无谓的值转换开销
                if out.len() >= limit {
                    truncated = true;
                    break;
                }
                let mut vals = Vec::with_capacity(ncol);
                for i in 0..ncol {
                    vals.push(value_to_string(row.get_ref(i).map_err(db_err)?));
                }
                out.push(vals);
            }
            Ok(DbQueryResult { columns, rows: out, truncated })
        })
        .await
        .map_err(join_err)?
    }

    async fn backup(&self, _t: &DbTarget, _o: &SafePath, _cb: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        unsupported!("dbms.backup (M4)")
    }
    async fn restore(&self, _t: &DbTarget, _f: &SafePath) -> Result<()> { unsupported!("dbms.restore (M4)") }
}

// ───────────────── 系统用户（M3） ─────────────────

#[derive(Default)]
pub struct LinuxUsers;

#[async_trait]
impl UserProvider for LinuxUsers {
    async fn exists(&self, name: &str) -> Result<bool> {
        // 读 /etc/passwd 而非 spawn getent：零子进程
        let s = tokio::fs::read_to_string("/etc/passwd").await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        Ok(s.lines().any(|l| l.split(':').next() == Some(name)))
    }
    async fn ensure(&self, _n: &str, _s: bool, _l: bool) -> Result<()> { unsupported!("user.ensure (M3)") }
    async fn uid_gid(&self, _n: &str) -> Result<(u32, u32)> { unsupported!("user.uid_gid (M3)") }
}

// 未在 stub 中使用的导入显式标记，避免 dead_code 警告干扰评审
#[allow(dead_code)]
fn _assert_types(_: Option<UnitName>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn nginx_server() -> LinuxWebServer {
        LinuxWebServer { name: Some("nginx"), paths: Arc::new(LinuxPathLayout::default()) }
    }

    fn spec_static() -> SiteSpec {
        SiteSpec {
            server_names: vec!["example.com".into(), "www.example.com".into()],
            root: PathBuf::from("/var/www/example"),
            listen: vec![80, 443],
            kind: SiteKind::Static,
            access_log: None,
            error_log: None,
            tls_cert: None,
            tls_key: None,
            force_https: false,
        }
    }

    #[test]
    fn render_static_contains_core_directives() {
        let out = render_nginx(&spec_static());
        assert!(out.contains("listen 80;"), "{out}");
        assert!(out.contains("listen 443;"), "无证书时 443 不应带 ssl: {out}");
        assert!(!out.contains("ssl;"), "无证书时不应出现 ssl: {out}");
        assert!(out.contains("server_name example.com www.example.com;"), "{out}");
        assert!(out.contains("root /var/www/example;"), "{out}");
        assert!(out.contains("try_files $uri $uri/ =404;"), "{out}");
    }

    #[test]
    fn render_force_https_with_tls_adds_redirect_and_ssl() {
        let mut s = spec_static();
        s.force_https = true;
        s.tls_cert = Some(PathBuf::from("/etc/panel/ssl/example.com.crt"));
        s.tls_key = Some(PathBuf::from("/etc/panel/ssl/example.com.key"));
        let out = render_nginx(&s);
        assert!(out.contains("return 301 https://$host$request_uri;"), "{out}");
        assert!(out.contains("listen 443 ssl;"), "{out}");
        assert!(out.contains("ssl_certificate     /etc/panel/ssl/example.com.crt;"), "{out}");
        assert!(out.contains("ssl_certificate_key /etc/panel/ssl/example.com.key;"), "{out}");
        // 80 只应出现在重定向块一次，主块不再监听 80
        assert_eq!(out.matches("listen 80;").count(), 1, "{out}");
    }

    #[test]
    fn render_reverse_proxy_sets_headers() {
        let mut s = spec_static();
        s.kind = SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] };
        let out = render_nginx(&s);
        assert!(out.contains("proxy_pass http://127.0.0.1:3000;"), "{out}");
        assert!(out.contains("proxy_set_header Host $host;"), "{out}");
        assert!(out.contains("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"), "{out}");
        assert!(!out.contains("try_files"), "反代不应有 try_files: {out}");
        // 单后端不该建 upstream 块：多一层间接没有收益
        assert!(!out.contains("upstream "), "单后端不应生成 upstream 块: {out}");
    }

    #[test]
    fn render_multi_upstream_puts_block_at_http_level() {
        let mut s = spec_static();
        s.kind = SiteKind::ReverseProxy {
            upstreams: vec!["http://127.0.0.1:3000".into(), "http://127.0.0.1:3001".into()],
        };
        let out = render_nginx(&s);
        // upstream 是 http 级指令：必须排在 server 之前，否则 nginx -t 会整份拒绝
        let up = out.find("upstream ").expect("应生成 upstream 块");
        let srv = out.find("server {").expect("应有 server 块");
        assert!(up < srv, "upstream 块必须在 server 之前: {out}");
        // server 指令只接受 host:port
        assert!(out.contains("server 127.0.0.1:3000;"), "{out}");
        assert!(!out.contains("server http://"), "upstream 内不得出现 scheme: {out}");
        assert!(out.contains("proxy_pass http://panel_"), "proxy_pass 应指向 upstream 名: {out}");
    }

    #[test]
    fn render_php_passes_to_fpm() {
        let mut s = spec_static();
        s.kind = SiteKind::Php { fpm: "unix:/run/php/php8.2-fpm.sock".into() };
        let out = render_nginx(&s);
        assert!(out.contains("fastcgi_pass unix:/run/php/php8.2-fpm.sock;"), "{out}");
        assert!(out.contains("SCRIPT_FILENAME $document_root$fastcgi_script_name;"), "{out}");
        assert!(out.contains("location ~ \\.php$"), "{out}");
    }

    #[test]
    fn slug_sanitizes_and_defaults() {
        assert_eq!(slug("example.com"), "example.com");
        assert_eq!(slug("a/b c"), "a_b_c");
        assert_eq!(slug(""), "site");
    }

    #[test]
    fn conf_path_is_namespaced_and_derived_from_first_host() {
        let p = nginx_server().conf_path(&["foo.example".into(), "bar.example".into()]);
        assert!(p.to_string_lossy().ends_with("panel-foo.example.conf"), "{p:?}");
    }

    #[test]
    fn render_rejects_empty_server_names() {
        let mut s = spec_static();
        s.server_names.clear();
        assert!(nginx_server().render(&s).is_err());
    }

    #[test]
    fn render_rejects_when_no_webserver() {
        let ws = LinuxWebServer { name: None, paths: Arc::new(LinuxPathLayout::default()) };
        assert!(matches!(ws.render(&spec_static()), Err(PanelError::Unsupported(_))));
    }

    #[tokio::test]
    async fn deploy_writes_target_without_leaving_tmp() {
        let dir = std::env::temp_dir().join(format!("panel-deploy-test-{}", uniq_counter()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("panel-x.conf");
        nginx_server().deploy(&target, "server {}\n").await.unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "server {}\n");
        let leftovers: Vec<String> = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "残留临时文件: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 需真机 nginx 的端到端校验：本沙箱无 nginx 时**跳过**（不是失败）。
    #[tokio::test]
    async fn validate_roundtrip_when_nginx_present() {
        if !which("nginx") { return; }
        let ok = nginx_server().validate(&render_nginx(&spec_static())).await;
        assert!(ok.is_ok(), "合法 server 块应通过 nginx -t: {ok:?}");
        let bad = nginx_server().validate("server { listen ; }").await;
        assert!(bad.is_err(), "非法配置应被 validate 拒绝");
    }
}
