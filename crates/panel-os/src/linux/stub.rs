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

/// apt 写操作的**等锁**参数：`-o DPkg::Lock::Timeout=<秒>`。
///
/// 为什么需要：apt/dpkg 的锁是**全局独占**的。外部 apt（终端里手敲的、
/// unattended-upgrades）持锁时，apt 默认**立刻**以退出码 100 失败。
/// 本机 `/var/log/apt/history.log` 实证：面板的 task 12/14 都是撞上用户终端里的
/// `apt purge libreoffice …`(22:39) / `apt upgrade`(22:44) 而失败的——
/// 面板内部排队救不了这种情况，只能让 apt 自己等。
///
/// 实测（Debian 13 / apt 3.x，两次并发 no-op install）：
/// - 不带该选项 → 立即 exit 100《E: 无法获得锁 … 锁正由进程 N（apt-get）持有》
/// - 带 `=8` → 打印《正在等待缓存锁》→ 等 2s → exit 0
///
/// 取 300s：覆盖常见的外部 apt 事务，又远小于任务超时（1800s），不会把任务卡死。
/// 等待期间 apt 的《正在等待缓存锁》会作为日志行推到前端，用户看得见"在等什么"。
///
/// ⚠️ **刻意不用于只读页面路径**（`repo.rs` 的 ensure_repo → apt-get update）：
/// 那条路径由 `GET /packages/*` 触发，必须快速失败；让它等锁会把一次普通页面
/// 请求阻塞数分钟，比失败更糟。
const APT_LOCK_TIMEOUT: &str = "DPkg::Lock::Timeout=300";

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

/// 拼装交给包管理器的安装目标（包名 + 可选版本）。
/// apt 用 `name=version`（等号语法），dnf/yum/apk/zypper 用 `name-version`（连字符），
/// 无版本则原样返回包名。纯函数、可单测——避免版本拼接散落各分支又不可测。
pub(crate) fn pkg_install_target(manager: &str, name: &str, version: Option<&str>) -> String {
    match version {
        None => name.to_string(),
        Some(v) => match manager {
            "apt" => format!("{name}={v}"),
            _ => format!("{name}-{v}"),
        },
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
                // 为什么要 `${db:Status-Abbrev}`：dpkg-query 对**未安装**的包名也会输出一行
                // （名字 + 空版本），此前只按"有输出行"判定 → 没装过的 apache2 被列进
                // "已安装软件"（本机实测 apache2 状态 unknown ok not-installed）。
                // Status-Abbrev 形如 "ii "（已安装）/ "rc "（删剩配置）/ "un "（未知），
                // 只认 "ii"。不能改用"版本非空"判断——那只是绕开同一个问题的表面现象。
                let fmt = "${Package}\t${Version}\t${db:Status-Abbrev}\n";
                let mut args: Vec<&str> = vec!["-W", "-f", fmt];
                args.extend_from_slice(names);
                let out = crate::cmd::run(Bin::Dpkg, &args,
                    CmdOpt { timeout: Duration::from_secs(30), ..Default::default() }).await?;
                Ok(out.stdout.lines().filter_map(|l| {
                    let mut it = l.split('\t');
                    let n = it.next()?.trim();
                    let v = it.next()?.trim();
                    let status = it.next()?.trim();
                    if !status.starts_with("ii") { return None }
                    Some(PackageInfo {
                        name: n.to_string(),
                        version: Some(v.to_string()).filter(|s| !s.is_empty()),
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

    async fn install(&self, n: &str, version: Option<&str>, cb: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        let m = self.manager.ok_or(PanelError::Unsupported("package.manager"))?;
        // CmdOpt 的回调是 &str 签名；这里把 trait 的 String 回调包一层适配
        let on_line: std::sync::Arc<dyn Fn(&str) + Send + Sync> =
            std::sync::Arc::new(move |line: &str| cb(line.to_string()));
        // 拼装交给包管理器的安装目标：apt 用 name=version，其余用 name-version，无版本则原样。
        let target = pkg_install_target(m, n, version);
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
                let args = ["install", "-y", "-o", "Dpkg::Options::=--force-confold",
                            "-o", APT_LOCK_TIMEOUT, target.as_str()];
                let mut o = crate::cmd::run(Bin::Apt, &args, mk(on_line.clone())).await?;
                let stale = o.code != Some(0) && (
                    o.stderr.contains("Unable to locate package")
                        || o.stdout.contains("Unable to locate package"));
                if stale {
                    // 软件源列表过期：刷新后重试一次（只重试一次，防止雪崩）
                    on_line("[panel] apt 软件源列表可能过期，执行 apt-get update 后重试");
                    crate::cmd::run_checked(Bin::Apt, &["-o", APT_LOCK_TIMEOUT, "update"],
                        CmdOpt { timeout: Duration::from_secs(300), on_line: Some(on_line.clone()), ..Default::default() }).await?;
                    o = crate::cmd::run(Bin::Apt, &args, mk(on_line)).await?;
                }
                if o.code != Some(0) {
                    // 指定版本但仓库里没有该版本时，apt 报 'Version x for y was not found'，
                    // 原话甩给用户看不懂；转成中文提示，避免等 30 分钟超时后才懵。
                    let detail = match version {
                        Some(v) if o.stderr.contains("was not found") || o.stderr.contains("has no candidate") =>
                            format!("指定版本 {v} 在软件源中不可用（可能未收录或需启用 backports/security 源）"),
                        _ => truncate_err(&o.stderr),
                    };
                    return Err(PanelError::Command { bin: "apt-get".into(), detail });
                }
                Ok(())
            }
            "dnf" => pkg_run_streamed(Bin::Dnf, &["install", "-y", target.as_str()], on_line).await,
            "yum" => pkg_run_streamed(Bin::Yum, &["install", "-y", target.as_str()], on_line).await,
            "apk" => pkg_run_streamed(Bin::Apk, &["add", target.as_str()], on_line).await,
            "zypper" => pkg_run_streamed(Bin::Zypper, &["--non-interactive", "install", "-y", target.as_str()], on_line).await,
            _other => Err(PanelError::Unsupported("package.install")),
        }
    }

    async fn remove(&self, n: &str) -> Result<()> {
        let m = self.manager.ok_or(PanelError::Unsupported("package.manager"))?;
        let (bin, args): (Bin, Vec<&str>) = match m {
            "apt" => (Bin::Apt, vec!["remove", "-y", "-o", APT_LOCK_TIMEOUT, n]),
            "dnf" => (Bin::Dnf, vec!["remove", "-y", n]),
            "yum" => (Bin::Yum, vec!["remove", "-y", n]),
            "apk" => (Bin::Apk, vec!["del", n]),
            "zypper" => (Bin::Zypper, vec!["--non-interactive", "remove", "-y", n]),
            _other => return Err(PanelError::Unsupported("package.remove")),
        };
        pkg_run(bin, &args).await
    }

    async fn list_versions(&self, n: &str) -> Result<PackageVersions> {
        let m = self.manager.ok_or(PanelError::Unsupported("package.manager"))?;
        match m {
            "apt" => {
                // LC_ALL=C 是必须的：apt 输出标题随 locale 变化（中文下是"版本列表："，
                // 英文才是 "Version table:"），按字面量找标题在非英语环境会直接解析为空。
                let mut env = std::collections::HashMap::new();
                env.insert("LC_ALL".to_string(), std::ffi::OsString::from("C"));
                let o = crate::cmd::run(Bin::AptCache, &["policy", n], CmdOpt {
                    timeout: Duration::from_secs(30), env, ..Default::default()
                }).await?;
                Ok(PackageVersions {
                    versions: parse_apt_policy_versions(&o.stdout),
                    installed: parse_apt_policy_installed(&o.stdout),
                })
            }
            // dnf/yum 也有版本查询，但面板当前发行版支持面以 apt 为主；
            // 返回空列表让调用方退回"装最新版"，而不是报 unsupported 挡住安装。
            _other => Ok(PackageVersions::default()),
        }
    }

    async fn ensure_repo(&self, logical: &str, on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        // 仅 apt 发行版支持加 apt 源；其它发行版（dnf/apk/...）无对应实现，直接报 unsupported
        let m = self.manager.ok_or(PanelError::Unsupported("package.manager"))?;
        if m != "apt" {
            return Err(PanelError::Unsupported("package.ensure_repo (non-apt)"));
        }
        match crate::linux::repo::third_party_repo(logical) {
            // 命中第三方源：下载校验 GPG → 写 keyring/sources → apt update
            Some(repo) => crate::linux::repo::ensure_third_party_repo(repo, on_line).await,
            // 白名单内普通包 / 无第三方源的包（含 minio）：no-op，不影响既有路径
            None => Ok(()),
        }
    }

    /// 只读探测：给定**真实包名**，报出其中「版本表最高版本高于已安装版本」的项。
    ///
    /// 为什么不用 `apt list --upgradable`（此前实现）：它按 apt 的 **Candidate** 判定，
    /// 而 Candidate 会被 pin / `NotAutomatic` / 源优先级压低。一旦 Candidate 低于已安装
    /// 版本，apt 就**永不列出**该包——哪怕版本表里另有更高版本（实测：pin 后 Candidate
    /// 降到 1.30.2，版本表最高仍是 1.30.5）。用户侧表现即「官方源明明有新版，面板却永远
    /// 不提示有更新」。改用版本表最高版与已装版本直接比较，与安装弹窗默认值（versions[0]）
    /// **同源**，两处判据不可能再打架。
    ///
    /// 只实现了 apt 的批量查询；其它包管理器返回空列表（探测是锦上添花，非错误）。
    async fn upgradable(&self, names: &[&str]) -> Result<Vec<UpgradablePkg>> {
        let Some(mgr) = self.manager else { return Ok(Vec::new()) };
        if mgr != "apt" || names.is_empty() { return Ok(Vec::new()) }
        // LC_ALL=C 必需：解析依赖 "Version table:" / "Installed:" 两个英文标题，
        // 非英语 locale 下会本地化（本机中文下是"版本列表："），解析将恒为空。
        let mut env = std::collections::HashMap::new();
        env.insert("LC_ALL".to_string(), std::ffi::OsString::from("C"));
        // 一次查全部：apt-cache policy 支持多包，逐个 spawn 实测 20 个包 ~1.5s，批量 ~0.6s。
        let mut args: Vec<&str> = vec!["policy"];
        args.extend_from_slice(names);
        let o = match crate::cmd::run(Bin::AptCache, &args, CmdOpt {
            timeout: Duration::from_secs(60), env, ..Default::default()
        }).await {
            Ok(o) => o,
            // 探测是锦上添花：任何失败都降级为空列表，绝不拖累整页。
            Err(e) => {
                tracing::warn!("apt-cache policy failed: {e}");
                return Ok(Vec::new());
            }
        };
        // 源配置损坏等致命错误下 apt 退出非 0，此时 stdout 为空，解析结果自然为空。
        if o.code != Some(0) {
            tracing::warn!("apt-cache policy exited {:?}, treating as no upgradable", o.code);
        }
        let mut res: Vec<UpgradablePkg> = Vec::new();
        for (name, body) in split_apt_policy_blocks(&o.stdout) {
            // apt 把"找不到的包"写 stderr、不产生块；这里再按请求名过滤一次，
            // 防止解析意外把非请求包当结果返回。
            if !names.contains(&name.as_str()) { continue; }
            let installed = parse_apt_policy_installed(&body);
            let versions = parse_apt_policy_versions(&body);
            let Some((current, candidate)) =
                crate::traits::upgradable_pair(installed.as_deref(), &versions)
            else { continue };
            // 跨主版本判定（PostgreSQL 17→18 / Node.js 20→24）交给共享函数，
            // 与升级接口守卫同一套逻辑，避免两处各写一份漂移。
            // 必须先算好：结构体字段按书写顺序求值，写在 current/candidate 之后
            // 就是"借用已移动的值"，编译期直接报 E0382。
            let major = crate::traits::version_major_jump(&current, &candidate);
            res.push(UpgradablePkg { name, current, candidate, major });
        }
        Ok(res)
    }
}

/// 从 `apt-cache policy <pkg>` 输出里抽版本（新→旧由 apt 自身顺序决定）。
///
/// 输出形态（LC_ALL=C）：
/// ```text
/// nginx:
///   Installed: (none)
///   Candidate: 1.26.3-3+deb13u9
///   Version table:
///      1.26.3-3+deb13u9 500
///         500 http://security.debian.org/... amd64 Packages
///      1.26.3-3+deb13u7 500
///         500 http://deb.debian.org/... amd64 Packages
/// ```
/// 版本行 = 缩进 + 版本 + 空白 + 优先级数字；其下更深的缩进是来源行，须跳过
/// （来源行也可能以数字开头，按"缩进更浅 + 尾随优先级"才能区分）。
pub(crate) fn parse_apt_policy_versions(out: &str) -> Vec<String> {
    let mut versions: Vec<String> = Vec::new();
    let mut in_table = false;
    for line in out.lines() {
        // 必须按 trim 后判定：apt 输出里该标题本身是缩进的（"  Version table:"），
        // 直接用 starts_with 会永远匹配不上 → 解析结果恒为空（弹窗只余"最新版"）。
        if line.trim_start().starts_with("Version table:") { in_table = true; continue; }
        if !in_table { continue; }
        let t = line.trim();
        if t.is_empty() { continue; }
        // apt 用 "***" 标记当前已安装的那一行（形如 "*** 5:8.0.2-3+deb13u3 500"），
        // 不剥掉它就是三列 → 会被下面的"恰好两列"判定跳过，导致**已安装的包
        // 漏掉自己正在用的版本**（nginx 未装不触发，redis 已装才暴露）。
        let t = t.trim_start_matches('*').trim_start();
        // 形如 "1.26.3-3+deb13u9 500"：两列，第二列是纯数字优先级
        let mut it = t.split_whitespace();
        match (it.next(), it.next(), it.next()) {
            (Some(v), Some(prio), None) if prio.chars().all(|c| c.is_ascii_digit()) => {
                if !versions.contains(&v.to_string()) { versions.push(v.to_string()); }
            }
            // 来源行（"500 http://..."）是三列，直接跳过
            _ => {}
        }
    }
    versions
}

/// 从 `apt-cache policy` 输出里取当前**已安装**版本（`Installed:` 行）。
///
/// 未安装时 apt 输出 `Installed: (none)`，此时返回 None。
/// 交给 apt 自己回答而不是让前端反查已安装列表：逻辑名↔真实包名不一致时
/// （php-fpm ↔ php8.4-fpm）前端反查会漏，apt 不会。
pub(crate) fn parse_apt_policy_installed(out: &str) -> Option<String> {
    for line in out.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("Installed:") {
            let v = v.trim();
            // (none) 是 apt 表示"未安装"的固定写法
            if v.is_empty() || v == "(none)" { return None; }
            return Some(v.to_string());
        }
    }
    None
}

/// 把 `apt-cache policy <pkg>...` 的**多包**输出切成 `(包名, 该包正文)` 对。
///
/// 多包一次查询是刻意的：逐个 spawn 实测 20 个包 ~1.5s，单次批量 ~0.6s。
/// 块头是**行首顶格**（无缩进）的 `名字:`；其余行（`Installed:` / `Candidate:` /
/// `Version table:` / 版本行 / 来源行）都缩进，属当前块。apt 把"找不到的包"写 stderr、
/// 不产生块，故调用方仍需按请求名过滤。
///
/// 本机实测形态（LC_ALL=C）：
/// ```text
/// nginx:
///   Installed: (none)
///   Candidate: 1.30.5-1~trixie
///   Version table:
///      1.30.5-1~trixie 500
///         500 https://nginx.org/packages/debian trixie/nginx amd64 Packages
/// redis-server:
///   Installed: 6:8.10.2-1rl1~trixie1
/// ```
pub(crate) fn split_apt_policy_blocks(out: &str) -> Vec<(String, String)> {
    let mut res: Vec<(String, String)> = Vec::new();
    for line in out.lines() {
        if let Some(name) = policy_block_header(line) {
            res.push((name, String::new()));
            continue;
        }
        if let Some((_, body)) = res.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    res
}

/// 判定某行是否为 `apt-cache policy` 的包块头：**顶格**且以 `:` 结尾，`:` 前是合法包名。
///
/// 顶格是必要条件（`Installed:` / `Version table:` 都缩进）；以 `:` 结尾则顺带排掉
/// apt 写在第 0 列的错误行——它们是 `N: Unable to locate package foo` 这种"以包名
/// 结尾"的形态，`strip_suffix(':')` 直接返回 None。
fn policy_block_header(line: &str) -> Option<String> {
    if line.starts_with(' ') || line.starts_with('\t') { return None; }
    let name = line.strip_suffix(':')?;
    if name.is_empty() { return None; }
    // 排除 apt 的单字母消息前缀（N:/W:/E:）
    if name.len() == 1 && matches!(name, "N" | "W" | "E") { return None; }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        .then(|| name.to_string())
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

/// 校验用的 wrapper 主配置：把站点片段包成一份合法主配置。
///
/// 抽成独立函数是为了让测试用**同一份** wrapper 去跑真实 nginx——测试里另抄一份
/// 必然漂移，而漂移的那份会把"真实校验"变成在验一个不存在的东西。
///
/// 三个细节各有原因：
/// - `error_log stderr`：不落日志文件，不污染宿主；
/// - **所有路径（pid、五个 temp 目录）都落到临时 prefix 内**：`nginx -t` 期间会
///   打开 pid 文件、还会 mkdir 这些 temp 目录。用编译期默认值（Debian 是
///   `/run/nginx.pid` 与 `/var/lib/nginx/*`）会让校验**依赖宿主状态**——目录缺失
///   或权限不足就直接失败，而这跟"配置本身对不对"毫无关系。语法校验就只该校验语法。
///   实测：只改 pid 不改 temp 路径，会挂在 `mkdir() "/var/lib/nginx/body" failed`。
/// - `include <frag>` 落在 `http` 块内：片段里的 `upstream` / `map` /
///   `limit_req_zone` 都只在 http 上下文合法，否则会得到一堆假阳性。
fn validate_wrapper(base: &std::path::Path, frag: &std::path::Path) -> String {
    // 直接挂在 base 下而不是 base/tmp：nginx 建临时目录用的是单层 `mkdir()`，
    // 父目录必须已存在——多套一层就得自己先建，不如少一层。
    let tmp = base;
    let mut s = String::new();
    s.push_str("error_log stderr;\n");
    s.push_str(&format!("pid {};\n", base.join("nginx.pid").display()));
    s.push_str("events {}\nhttp {\n");
    // `access_log off` 必须显式写，且只能写在 http / server / location 级
    // （main 上下文会报 "directive is not allowed here"）。不写就会落到编译期的
    // 默认 access_log（Debian 是 /var/log/nginx/access.log），于是校验变成在测
    // "宿主能不能写那个日志文件"，而不是在测配置语法。
    s.push_str("    access_log off;\n");
    for (directive, name) in [
        ("client_body_temp_path", "body"),
        ("proxy_temp_path", "proxy"),
        ("fastcgi_temp_path", "fastcgi"),
        ("uwsgi_temp_path", "uwsgi"),
        ("scgi_temp_path", "scgi"),
    ] {
        s.push_str(&format!("    {directive} {}/{name};\n", tmp.display()));
    }
    s.push_str(&format!("    include {};\n}}\n", frag.display()));
    s
}

/// 抽出片段里需要**搬运**的相对 `include` 名（去重、保序）。
///
/// 只认整行的 `include <名>;`，跳过注释行、绝对路径与通配（前者 nginx 自己能读，
/// 后者需要真实目录，搬不了）。名字限制在 `[A-Za-z0-9_./-]` 且不含 `..`——
/// 这里读的是宿主文件，任何"聪明"的解析都只是扩大攻击面。
fn relative_includes(rendered: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in rendered.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some(rest) = t.strip_prefix("include") else { continue };
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue; // 形如 `include_foo` 的无关指令
        }
        let Some(name) = rest.trim().strip_suffix(';') else { continue };
        let name = name.trim();
        if name.is_empty() || name.starts_with('/') || name.contains('*') || name.contains("..") {
            continue;
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/'))
        {
            continue;
        }
        if !out.iter().any(|x| x == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// 校验时相对 `include` 的**源目录**：nginx 主配置所在目录（`conf.d` 的上一级）。
///
/// 这是个假设——假定部署目录的父目录就是主配置目录（Debian / Arch / RHEL 均如此）。
/// 假设不成立时 [`stage_relative_includes`] 会如实报"读取失败"，而不是静默放行。
fn nginx_conf_source_dir(web_conf_dir: &std::path::Path) -> std::path::PathBuf {
    web_conf_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/nginx"))
}

/// 把片段里**相对** `include` 的文件，从 nginx 主配置目录搬进校验用的临时 `conf/`。
///
/// 为什么必须搬：`include foo;` 的相对名在 nginx 中相对 **conf_prefix** 解析。
/// 生产时 conf_prefix 是主配置目录（Debian 是 `/etc/nginx`），而校验时因为用了
/// `-c <base>/conf/nginx.conf`，conf_prefix 变成临时目录——相对 include 一律找不到。
/// 不搬的话 PHP 站点的校验会报 `open() .../conf/fastcgi_params failed`：一个与真实
/// 配置毫无关系的**假失败**。（P2-8 起 validate 一直是坏的，所以这个坑没人踩到。）
///
/// 源文件缺失时**如实报错**：那份配置在真实 nginx 上会因为同样的原因加载失败，
/// 不是可以宽容的情况。
async fn stage_relative_includes(
    rendered: &str,
    src_conf_dir: &std::path::Path,
    dest_conf_dir: &std::path::Path,
) -> Result<()> {
    for name in relative_includes(rendered) {
        let src = src_conf_dir.join(&name);
        let dst = dest_conf_dir.join(&name);
        let bytes = tokio::fs::read(&src).await.map_err(|e| PanelError::ConfigInvalid {
            detail: format!(
                "片段 include 了 `{name}`，但读取 {} 失败（{e}）——真实 nginx 会因同样的原因加载失败",
                src.display()
            ),
        })?;
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| PanelError::Internal(e.to_string()))?;
        }
        tokio::fs::write(&dst, bytes)
            .await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
    }
    Ok(())
}

/// `nginx -t` 的 argv（不含二进制）。抽出来同样是为了让测试与生产走同一份参数。
///
/// **必须同时给 `-p` 与 `-c`**：`-p` 只改 prefix，只有当二进制编译期的
/// `--conf-path` 是**相对路径**时，nginx 才会去读 `<prefix>/conf/nginx.conf`。
/// Debian / Ubuntu 的包把 conf-path 编成了绝对路径（`/etc/nginx/nginx.conf`），
/// 此时 `-p` 完全不生效——校验会变成替"系统的 nginx 配置"背书，而生成的片段
/// 一个字都没验过。本函数此前只给 `-p`，在 Debian 上就是这样**静默失灵**的：
/// 系统里没有 /etc/nginx/nginx.conf 时它报"文件不存在"，装了 nginx 之后它又
/// 恒为通过，两种表现都不指向真正的问题。
fn nginx_test_argv(base: &std::path::Path) -> Vec<String> {
    vec![
        "-t".into(),
        "-p".into(),
        base.display().to_string(),
        "-c".into(), // ci-allow-layering[2]: nginx 的"配置文件"参数，与 shell 无关（非 shell 解释）
        base.join("conf/nginx.conf").display().to_string(),
    ]
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

    // ── WAF 的 http 级片段（map / limit_req_zone），同样必须排在 server 之前 ──
    if let Some(w) = &spec.waf {
        out.push_str(&render_waf_http(&spec.server_names, w));
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

    if let Some(w) = &spec.waf {
        out.push_str(&render_waf_server(&spec.server_names, w));
    }

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

// ───────────────── WAF 规则集（编译期常量） ─────────────────
//
// 写进 nginx 配置的字符串有两条硬约束，规则集必须自我遵守（有专门的回归测试钉住）：
// ① **不含空白 / `;` / `{` / `}`**：nginx 词法器用它们切分 token 与块，出现在正则
//    里会直接破坏配置结构——所以 `{8,}` 这类量词不能用；
// ② **不含反斜杠**：nginx 把 `\x` 当转义处理，`\s` / `\.` 是否被原样传给 PCRE
//    取决于引号内外的上下文，属于**不该去赌**的实现细节。一律改用字符类表达：
//    `\.` → `[.]`、`\s` → `[[:space:]]`（POSIX 类，无转义）。
// 于是规则集加不加引号行为完全一致。

/// 恶意 / 扫描器 UA（基础档）。只挑**特征明确的工具名**——刻意不含 curl / wget /
/// python：它们是大量正常脚本与健康检查的 UA，一刀切会误杀真实流量。
const WAF_UA_BASIC: &str = "sqlmap|nikto|acunetix|nessus|dirbuster|gobuster|wfuzz|hydra|zgrab|nuclei|masscan|w3af|whatweb";
/// 严格档追加的 UA 备选
const WAF_UA_STRICT_EXTRA: &str = "nmap|zaproxy|owasp-zap|burpsuite|skipfish|arachni|commix|wpscan|joomscan";

/// SQL 注入关键词（基础档）：只放**低误报**模式
const WAF_SQLI_BASIC: &str = "union[[:space:](/*]+select|information_schema|sleep[(]|benchmark[(]|load_file[(]|into[[:space:]/]+outfile|waitfor[[:space:]]+delay|updatexml[(]|extractvalue[(]";
/// 严格档追加：误报更高，故不进默认档
const WAF_SQLI_STRICT_EXTRA: &str = "or[[:space:]]+1[[:space:]]*=1|and[[:space:]]+1[[:space:]]*=1|[[:space:]]having[[:space:]]|concat_ws[(]|[[:space:]]xp_cmdshell";

/// XSS 关键词（基础档）
const WAF_XSS_BASIC: &str = "[<]script|javascript:|onerror[[:space:]]*=|onload[[:space:]]*=|onmouseover[[:space:]]*=|document[.]cookie|srcdoc=|%3cscript";
/// 严格档追加
const WAF_XSS_STRICT_EXTRA: &str = "[<]iframe|[<]object|[<]embed|[<]svg|onfocus[[:space:]]*=|onclick[[:space:]]*=|alert[(]|eval[(]";

/// 路径穿越 / 本地文件读取（基础档）
const WAF_TRAV_BASIC: &str = "[.][.]/|%2e%2e|%252e|/etc/passwd|/proc/self/|/windows/win[.]ini";
/// 严格档追加
const WAF_TRAV_STRICT_EXTRA: &str = "[.][.]%2f|%2f%2e%2e|/etc/shadow|/root/[.]ssh";

/// 档位合成：严格档 = 基础档 + 附加备选（**只增不减**）。
///
/// 结构化拼接而不是各写一份清单：两份清单必然漂移，而漂移的方向可能是"严格档
/// 反而少了某条基础规则"——用户以为开了更严的档，实际放松了防护。
fn waf_rules(basic: &str, extra: &str, p: WafProfile) -> String {
    match p {
        WafProfile::Basic => basic.to_string(),
        WafProfile::Strict => format!("{basic}|{extra}"),
    }
}

fn waf_ua(p: WafProfile) -> String { waf_rules(WAF_UA_BASIC, WAF_UA_STRICT_EXTRA, p) }
fn waf_sqli(p: WafProfile) -> String { waf_rules(WAF_SQLI_BASIC, WAF_SQLI_STRICT_EXTRA, p) }
fn waf_xss(p: WafProfile) -> String { waf_rules(WAF_XSS_BASIC, WAF_XSS_STRICT_EXTRA, p) }
fn waf_trav(p: WafProfile) -> String { waf_rules(WAF_TRAV_BASIC, WAF_TRAV_STRICT_EXTRA, p) }

/// WAF 变量 / zone 名：复用 upstream 的净化规则（同一站点稳定且唯一）。
/// 多站点 zone 名撞车会让 nginx 拒绝加载**整份**配置，不只是这个站点。
fn waf_token(server_names: &[String]) -> String { upstream_name(server_names) }

/// WAF 的 **http 级**片段（`map` / `limit_req_zone` / `limit_req_status`）。
///
/// 为什么必须排在 server 之前：nginx 只在 http 上下文接受这些指令。放错位置
/// 不是"这个站点不生效"，而是 `nginx -t` 拒绝整份配置——**一个站点写错会让
/// 全机所有站点一起加载失败**。
fn render_waf_http(server_names: &[String], w: &WafSpec) -> String {
    let t = waf_token(server_names);
    let strict = w.profile == WafProfile::Strict;
    let mut o = String::new();

    o.push_str(&format!("# ── WAF（{}）──\n", w.profile.as_str()));
    // 每条规则一个 map：只算一次、可读，再在 server 内用
    // `if ($var) { return 403; }` 拒绝。`if` 配 `return` 是官方认可的安全用法
    // （危险的是 `if` 里配 proxy_pass / 重写）。
    o.push_str(&format!("map $http_user_agent ${t}_ua {{\n    default 0;\n    \"~*{}\" 1;\n}}\n", waf_ua(w.profile)));
    o.push_str(&format!("map $request_uri ${t}_sqli {{\n    default 0;\n    \"~*{}\" 1;\n}}\n", waf_sqli(w.profile)));
    o.push_str(&format!("map $request_uri ${t}_xss {{\n    default 0;\n    \"~*{}\" 1;\n}}\n", waf_xss(w.profile)));
    o.push_str(&format!("map $request_uri ${t}_trav {{\n    default 0;\n    \"~*{}\" 1;\n}}\n", waf_trav(w.profile)));

    if strict {
        // 非白名单方法一律 405。`default 1` + 逐个放行，比列黑名单安全：
        // 将来 nginx 支持新方法时默认仍是拒绝。
        o.push_str(&format!(
            "map $request_method ${t}_method {{\n    default 1;\n    GET 0;\n    HEAD 0;\n    POST 0;\n    PUT 0;\n    DELETE 0;\n    PATCH 0;\n    OPTIONS 0;\n}}\n"
        ));
        // 空 UA：不少扫描器连 UA 都不发。同时列 "" 与 "-"——nginx 在请求头缺失时
        // 把变量取值为 "-"（不是空串），两个都写上就不必依赖具体版本的细节。
        o.push_str(&format!(
            "map $http_user_agent ${t}_noua {{\n    default 0;\n    \"\" 1;\n    \"-\" 1;\n}}\n"
        ));
    }

    if let Some(r) = w.rate_per_sec {
        // 10m 共享内存约记住 16 万个 IP。rate 必须 ≥1——nginx 会拒绝 rate=0r/s。
        o.push_str(&format!("limit_req_zone $binary_remote_addr zone={t}_rl:10m rate={r}r/s;\n"));
        // 默认超限返回 503，语义上应是 429（Too Many Requests）：503 会让监控
        // 误判成"服务挂了"，而实际只是这个客户端被限流。
        o.push_str("limit_req_status 429;\n");
    }
    o.push('\n');
    o
}

/// WAF 的 **server 级**片段（拦截判定 + 限速 + 隐藏文件拒绝）。
fn render_waf_server(server_names: &[String], w: &WafSpec) -> String {
    let t = waf_token(server_names);
    let strict = w.profile == WafProfile::Strict;
    let mut o = String::new();

    o.push_str("\n    # ── WAF 拦截（命中即拒）──\n");
    o.push_str(&format!("    if (${t}_ua)   {{ return 403; }}\n"));
    o.push_str(&format!("    if (${t}_sqli) {{ return 403; }}\n"));
    o.push_str(&format!("    if (${t}_xss)  {{ return 403; }}\n"));
    o.push_str(&format!("    if (${t}_trav) {{ return 403; }}\n"));
    if strict {
        o.push_str(&format!("    if (${t}_noua)   {{ return 403; }}\n"));
        o.push_str(&format!("    if (${t}_method) {{ return 405; }}\n"));
    }
    if let Some(_r) = w.rate_per_sec {
        o.push_str(&format!("    limit_req zone={t}_rl burst={} nodelay;\n", w.burst));
    }

    // 隐藏文件 / 目录探测。
    // **必须放行 `/.well-known`**：ACME http-01 的挑战文件就落在这里，一刀切会把
    // 证书续期打死——"顺手加的一条规则让线上证书过期"是最难排查的那类事故。
    o.push_str("    location ~ /[.](?!well-known/) { deny all; }\n");
    if strict {
        // 备份与编辑器残留：正常站点不该被下载到这些
        o.push_str("    location ~* [.](sql|bak|old|orig|swp|save|tar|gz|zip|env)$ { deny all; }\n");
    }
    o
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
    /// wrapper 与 argv 都由 [`validate_wrapper`] / [`nginx_test_argv`] 生成——
    /// 生产与测试共用同一份，测试才不会"在验一个不存在的东西"。
    async fn validate(&self, rendered: &str) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.validate: 仅 nginx"); }
        let base = self.paths.tmp_dir()
            .join(format!("panel-validate-{}-{}", std::process::id(), uniq_counter()));
        let conf_dir = base.join("conf");
        tokio::fs::create_dir_all(&conf_dir).await.map_err(|e| PanelError::Internal(e.to_string()))?;

        // 片段：该站点配置
        let frag = base.join("site.conf");
        tokio::fs::write(&frag, rendered).await.map_err(|e| PanelError::Internal(e.to_string()))?;
        // 片段的相对 include 也要在临时 conf/ 下可见（见 stage_relative_includes）
        stage_relative_includes(
            rendered,
            &nginx_conf_source_dir(&self.paths.web_conf_dir()),
            &conf_dir,
        )
        .await?;
        tokio::fs::write(conf_dir.join("nginx.conf"), validate_wrapper(&base, &frag))
            .await.map_err(|e| PanelError::Internal(e.to_string()))?;

        let argv = nginx_test_argv(&base);
        let argv_ref: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let r = crate::cmd::run(
            Bin::Nginx,
            &argv_ref,
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

    async fn remove(&self, conf_path: &std::path::Path) -> Result<()> {
        if self.name != Some("nginx") { return unsupported!("webserver.remove: 仅 nginx"); }
        if conf_path.exists() {
            std::fs::remove_file(conf_path)
                .map_err(|e| PanelError::Io(format!("remove {}: {e}", conf_path.display())))?;
        }
        // 删完必须 reload：否则 nginx 仍按内存旧配置继续服务该站点（"已删除"却仍在线）
        self.reload().await
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
                a.push("-c".into()); // ci-allow-layering[2]: 这是 `psql -c <sql>` 的客户端参数，与 shell 无关
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

    async fn backup(&self, t: &DbTarget, o: &SafePath, on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        match t.engine {
            DbEngine::Sqlite => {
                let src = t.database.as_deref().ok_or_else(|| PanelError::Validation {
                    field: "database",
                    reason: "SQLite 连接需在「库名」中填写 .db 文件路径".into(),
                })?;
                if !std::path::Path::new(src).is_file() {
                    return Err(PanelError::NotFound(format!("sqlite 文件: {src}")));
                }
                // 在线文件复制：SQLite 文件在面板自身库上就是直接 cp（与 DbRestoreTask 同源口径）。
                // 大库一致性由备份任务在库空闲期执行保证，这里不引入 rusqlite 在线热备依赖。
                std::fs::copy(src, o.as_path()).map_err(|e| PanelError::Io(e.to_string()))?;
                on_line("SQLite 文件已复制".into());
                Ok(())
            }
            DbEngine::MySql => {
                let mut env: std::collections::HashMap<String, std::ffi::OsString> = std::collections::HashMap::new();
                if let Some(p) = &t.password { env.insert("MYSQL_PWD".into(), std::ffi::OsString::from(p)); }
                let mut a: Vec<String> = vec![
                    "--result-file".into(), o.as_path().to_string_lossy().into(),
                    "--single-transaction".into(), "--routines".into(), "--triggers".into(),
                    "--events".into(), "--skip-lock-tables".into(),
                    "-h".into(), t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                ];
                if let Some(p) = t.port { a.push("-P".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-u".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-D".into()); a.push(d.clone()); }
                let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
                on_line("mysqldump 导出中…".into());
                // 凭据走 MYSQL_PWD 环境变量（绝不进 argv，ps 可见 = 泄露口令）；
                // --result-file 直接落盘，stdout 为空，避免大库撑爆内存捕获。
                crate::cmd::run_checked(
                    crate::cmd::Bin::MySqlDump, &args,
                    crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), env, ..Default::default() },
                ).await?;
                on_line("MySQL 备份完成".into());
                Ok(())
            }
            DbEngine::Postgres => {
                let mut env: std::collections::HashMap<String, std::ffi::OsString> = std::collections::HashMap::new();
                if let Some(p) = &t.password { env.insert("PGPASSWORD".into(), std::ffi::OsString::from(p)); }
                let mut a: Vec<String> = vec![
                    "-f".into(), o.as_path().to_string_lossy().into(),
                    "-h".into(), t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                ];
                if let Some(p) = t.port { a.push("-p".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-U".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-d".into()); a.push(d.clone()); }
                let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
                on_line("pg_dump 导出中…".into());
                crate::cmd::run_checked(
                    crate::cmd::Bin::PgDump, &args,
                    crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), env, ..Default::default() },
                ).await?;
                on_line("PostgreSQL 备份完成".into());
                Ok(())
            }
        }
    }

    async fn restore(&self, t: &DbTarget, from: &SafePath) -> Result<()> {
        match t.engine {
            DbEngine::Sqlite => {
                let dst = t.database.as_deref().ok_or_else(|| PanelError::Validation {
                    field: "database",
                    reason: "SQLite 连接需在「库名」中填写 .db 文件路径".into(),
                })?;
                // 覆盖前先留快照（与 DbRestoreTask 同源安全网）：出问题可据此回滚
                if std::path::Path::new(dst).is_file() {
                    let bak = format!(
                        "{}.bak-{}", dst,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    );
                    std::fs::copy(dst, &bak).map_err(|e| PanelError::Io(e.to_string()))?;
                }
                std::fs::copy(from.as_path(), dst).map_err(|e| PanelError::Io(e.to_string()))?;
                Ok(())
            }
            DbEngine::MySql => {
                let mut env: std::collections::HashMap<String, std::ffi::OsString> = std::collections::HashMap::new();
                if let Some(p) = &t.password { env.insert("MYSQL_PWD".into(), std::ffi::OsString::from(p)); }
                let mut a: Vec<String> = vec!["-h".into(), t.host.clone().unwrap_or_else(|| "127.0.0.1".into())];
                if let Some(p) = t.port { a.push("-P".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-u".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-D".into()); a.push(d.clone()); }
                a.push("-e".into());
                a.push(format!("source {}", from.as_path().to_string_lossy()));
                let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
                crate::cmd::run_checked(
                    crate::cmd::Bin::MySql, &args,
                    crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), env, ..Default::default() },
                ).await?;
                Ok(())
            }
            DbEngine::Postgres => {
                let mut env: std::collections::HashMap<String, std::ffi::OsString> = std::collections::HashMap::new();
                if let Some(p) = &t.password { env.insert("PGPASSWORD".into(), std::ffi::OsString::from(p)); }
                let mut a: Vec<String> = vec![
                    "-h".into(), t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                    "-f".into(), from.as_path().to_string_lossy().into(),
                ];
                if let Some(p) = t.port { a.push("-p".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-U".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-d".into()); a.push(d.clone()); }
                let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
                crate::cmd::run_checked(
                    crate::cmd::Bin::Psql, &args,
                    crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), env, ..Default::default() },
                ).await?;
                Ok(())
            }
        }
    }
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
    use crate::traits::DatabaseProvider;

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
            waf: None,
        }
    }

    fn spec_waf(profile: WafProfile, rate: Option<u32>, burst: u32) -> SiteSpec {
        let mut s = spec_static();
        s.waf = Some(WafSpec { profile, rate_per_sec: rate, burst });
        s
    }

    /// 规则集必须遵守的硬约束：不含空白 / `;` / `{` / `}` / 反斜杠 / 引号。
    /// 前四者会破坏 nginx 的词法结构（正则里的 `{8,}` 量词因此不可用）；
    /// 反斜杠的转义语义在引号内外不一致——**不依赖它**才不用赌具体实现。
    #[test]
    fn pkg_install_target_formats_version_per_manager() {
        // apt 用等号语法；dnf/yum/apk/zypper 用连字符；无版本原样返回包名。
        assert_eq!(pkg_install_target("apt", "nginx", Some("1.22.1-9")), "nginx=1.22.1-9");
        assert_eq!(pkg_install_target("dnf", "nginx", Some("1.22.1")), "nginx-1.22.1");
        assert_eq!(pkg_install_target("yum", "redis", Some("5.0.2")), "redis-5.0.2");
        assert_eq!(pkg_install_target("apt", "nginx", None), "nginx");
        assert_eq!(pkg_install_target("dnf", "nginx", None), "nginx");
    }

    #[test]
    fn parse_apt_policy_versions_picks_only_version_rows() {
        // 样本取自本机 LC_ALL=C apt-cache policy nginx 的真实形态
        let out = "nginx:\n  Installed: (none)\n  Candidate: 1.26.3-3+deb13u9\n  Version table:\n\
                   1.26.3-3+deb13u9 500\n    500 http://security.debian.org/debian-security amd64 Packages\n\
                   1.26.3-3+deb13u7 500\n    500 http://deb.debian.org/debian amd64 Packages\n";
        let v = parse_apt_policy_versions(out);
        assert_eq!(v, vec!["1.26.3-3+deb13u9".to_string(), "1.26.3-3+deb13u7".to_string()]);

        // 来源行（"500 http://..."）绝不能被当成版本——它以数字开头，极易误提
        for got in &v {
            assert!(!got.starts_with("500"), "来源行的优先级被误当版本：{got}");
            assert!(!got.starts_with("http"), "来源 URL 被误当版本：{got}");
        }

        // 已安装的包：当前版本行带 "***" 前缀（本机 redis-server 真实形态）。
        // 不剥掉该标记就会漏掉正在使用的版本——这是实测才暴露的 bug，钉住它。
        let installed = "redis-server:\n  Installed: 5:8.0.2-3+deb13u3\n  Version table:\n\
                         *** 5:8.0.2-3+deb13u3 500\n     500 http://security.debian.org amd64 Packages\n\
                         5:8.0.2-3+deb13u2 500\n     500 http://deb.debian.org amd64 Packages\n";
        assert_eq!(
            parse_apt_policy_versions(installed),
            vec!["5:8.0.2-3+deb13u3".to_string(), "5:8.0.2-3+deb13u2".to_string()],
            "*** 标记的已安装版本必须被抽出"
        );
        assert_eq!(parse_apt_policy_installed(installed), Some("5:8.0.2-3+deb13u3".to_string()));

        // 未安装：apt 写 "Installed: (none)"，必须返回 None 而不是把 "(none)" 当版本号
        let not_installed = "nginx:\n  Installed: (none)\n  Candidate: 1.26.3-3+deb13u9\n  Version table:\n\
                             1.26.3-3+deb13u9 500\n";
        assert_eq!(parse_apt_policy_installed(not_installed), None);

        // 没有 Version table（如包不存在）→ 空列表，调用方退回"装最新版"
        assert!(parse_apt_policy_versions("N: Unable to locate package foo\n").is_empty());
        // 中文 locale 下标题不同，解析器只看英文标题，故必须靠调用方传 LC_ALL=C
        assert!(parse_apt_policy_versions("版本列表：\n     1.0 500\n").is_empty());
    }

    #[test]
    fn waf_rule_sets_stay_token_safe() {
        for pat in [
            WAF_UA_BASIC, WAF_UA_STRICT_EXTRA,
            WAF_SQLI_BASIC, WAF_SQLI_STRICT_EXTRA,
            WAF_XSS_BASIC, WAF_XSS_STRICT_EXTRA,
            WAF_TRAV_BASIC, WAF_TRAV_STRICT_EXTRA,
        ] {
            assert!(!pat.is_empty(), "规则集不该为空");
            for bad in [' ', '\t', '\n', ';', '{', '}', '\\', '"', '\''] {
                assert!(
                    !pat.contains(bad),
                    "规则集含非法字符 {bad:?}，会破坏 nginx 词法：{pat}"
                );
            }
        }
    }

    /// 分层只能是"加规则"，不能是"换一套规则"——否则打开严格档反而可能放松某项防护。
    #[test]
    fn strict_profile_only_adds_rules() {
        for (b, s) in [
            (waf_ua(WafProfile::Basic), waf_ua(WafProfile::Strict)),
            (waf_sqli(WafProfile::Basic), waf_sqli(WafProfile::Strict)),
            (waf_xss(WafProfile::Basic), waf_xss(WafProfile::Strict)),
            (waf_trav(WafProfile::Basic), waf_trav(WafProfile::Strict)),
        ] {
            assert!(s.starts_with(&b), "严格档必须包含基础档的全部备选：\n基础: {b}\n严格: {s}");
        }
        // 高误报备选不得出现在默认档
        assert!(!waf_sqli(WafProfile::Basic).contains("1[[:space:]]*=1"));
        assert!(!waf_xss(WafProfile::Basic).contains("eval[(]"));
    }

    #[test]
    fn waf_http_directives_precede_the_server_block() {
        let out = render_nginx(&spec_waf(WafProfile::Basic, Some(10), 20));
        let zone = out.find("limit_req_zone").expect("限速开启时应有 limit_req_zone");
        let map = out.find("map $http_user_agent").expect("应有 UA map");
        let srv = out.find("server {").expect("应有 server 块");
        assert!(zone < srv, "limit_req_zone 是 http 级指令，必须排在 server 之前：\n{out}");
        assert!(map < srv, "map 是 http 级指令，必须排在 server 之前：\n{out}");
        assert!(out.contains("rate=10r/s"), "{out}");
        assert!(out.contains("burst=20 nodelay"), "{out}");
        assert!(out.contains("limit_req_status 429"), "超限应 429（503 会被监控误判成服务挂了）：\n{out}");
    }

    #[test]
    fn waf_basic_vs_strict_differences() {
        let basic = render_nginx(&spec_waf(WafProfile::Basic, None, 0));
        assert!(basic.contains("if ($panel_example_com_ua)   { return 403; }"), "{basic}");
        assert!(basic.contains("if ($panel_example_com_sqli) { return 403; }"), "{basic}");
        assert!(basic.contains("if ($panel_example_com_xss)  { return 403; }"), "{basic}");
        assert!(basic.contains("if ($panel_example_com_trav) { return 403; }"), "{basic}");
        assert!(!basic.contains("_method"), "基础档不该限制请求方法：\n{basic}");
        assert!(!basic.contains("_noua"), "基础档不该拦空 UA：\n{basic}");
        assert!(!basic.contains("limit_req zone="), "未配置限速就不该出现 limit_req：\n{basic}");

        let strict = render_nginx(&spec_waf(WafProfile::Strict, None, 0));
        assert!(strict.contains("_noua)   { return 403; }"), "{strict}");
        assert!(strict.contains("_method) { return 405; }"), "非白名单方法应 405 而非 403：\n{strict}");
        // 严格档专有：备份 / 残留文件拒绝。基础档不该有（误杀风险更高）
        assert!(strict.contains("env)$ { deny all; }"), "严格档应拦备份 / 残留文件：\n{strict}");
        assert_eq!(basic.matches("deny all;").count(), 1, "基础档应只有一条 deny 规则（隐藏文件）：\n{basic}");
        assert_eq!(strict.matches("deny all;").count(), 2, "严格档应多一条备份 / 残留文件拒绝：\n{strict}");
    }

    #[test]
    fn well_known_is_exempt_from_the_dotfile_deny() {
        let out = render_nginx(&spec_waf(WafProfile::Basic, None, 0));
        assert!(
            out.contains("(?!well-known/)"),
            "隐藏文件规则必须放行 /.well-known —— ACME http-01 挑战文件就落在那里，\
             一刀切会把证书续期打死：\n{out}"
        );
    }

    #[test]
    fn no_waf_means_no_waf_directives() {
        let out = render_nginx(&spec_static());
        for bad in ["map $", "limit_req", "WAF", "well-known"] {
            assert!(!out.contains(bad), "未启用 WAF 时不该出现 {bad:?}：\n{out}");
        }
    }

    /// 真机语法校验：把渲染结果交给**真实的** `nginx -t`。
    ///
    /// 上面那些断言只能证明"生成的东西符合我以为的 nginx 语法"——那正是最容易错的
    /// 地方（`map` 的上下文、`if` 在 server 级是否合法、PCRE 前瞻、`limit_req` 参数、
    /// 引号内反斜杠的转义）。只有真解析器说了算。
    ///
    /// 本机没有 nginx 时**跳过并打印原因**，绝不假装通过。可用 `PANEL_NGINX_BIN`
    /// 指定任意二进制（例如从 .deb 里 `dpkg-deb -x` 解出来的，无需安装）。
    #[tokio::test]
    async fn rendered_config_passes_real_nginx_syntax_check() {
        let bin = std::path::PathBuf::from(
            std::env::var("PANEL_NGINX_BIN").unwrap_or_else(|_| "/usr/sbin/nginx".into()),
        );
        if !bin.is_file() {
            eprintln!(
                "跳过：未找到 nginx 二进制（{} 不存在；可用 PANEL_NGINX_BIN 指定）",
                bin.display()
            );
            return;
        }
        // 相对 include 的源目录。本机没装 nginx 时，可以指向从 .deb 里解出来的
        // `etc/nginx`（那里有 fastcgi_params 等发行版文件）。
        let conf_src = std::path::PathBuf::from(
            std::env::var("PANEL_NGINX_CONF_DIR").unwrap_or_else(|_| "/etc/nginx".into()),
        );
        if !conf_src.is_dir() {
            eprintln!(
                "跳过：未找到 nginx 配置目录（{} 不存在；可用 PANEL_NGINX_CONF_DIR 指定）",
                conf_src.display()
            );
            return;
        }

        // 组合覆盖全部渲染分支：3 种站点类型 × 2 个 WAF 档位 × 限速开关，外加无 WAF 基线
        let mut specs: Vec<SiteSpec> = Vec::new();
        for kind in [
            SiteKind::Static,
            SiteKind::ReverseProxy {
                upstreams: vec!["http://127.0.0.1:3000".into(), "http://127.0.0.1:3001".into()],
            },
            SiteKind::Php { fpm: "unix:/run/php/php8.2-fpm.sock".into() },
        ] {
            for profile in [WafProfile::Basic, WafProfile::Strict] {
                for rate in [None, Some(10u32)] {
                    let mut s = spec_static();
                    s.kind = kind.clone();
                    // 非特权环境下 :80/:443 会被内核拒绝 bind —— **`nginx -t` 会真的去
                    // bind**（它靠端口冲突来检测配置里的重复 `listen`），于是校验会因
                    // 权限失败，而这与配置内容无关。测试改用高位端口：WAF 片段与端口
                    // 无关，结论不受影响。
                    s.listen = vec![18080, 18443];
                    s.waf = Some(WafSpec { profile, rate_per_sec: rate, burst: 20 });
                    specs.push(s);
                }
            }
        }
        let mut baseline = spec_static();
        baseline.listen = vec![18080, 18443];
        specs.push(baseline);

        let base = std::env::temp_dir()
            .join(format!("panel-nginx-t-{}-{}", std::process::id(), uniq_counter()));
        std::fs::create_dir_all(base.join("conf")).unwrap();
        std::fs::create_dir_all(base.join("logs")).unwrap();

        for (i, s) in specs.iter().enumerate() {
            let frag = base.join("site.conf");
            let rendered = render_nginx(s);
            std::fs::write(&frag, &rendered).unwrap();
            // **复用生产那三份实现**（wrapper / argv / include 搬运），不另抄一份：
            // 抄一份必然漂移，而漂移的方向恰恰是"测试通过了、生产那套没通过"。
            stage_relative_includes(&rendered, &conf_src, &base.join("conf"))
                .await
                .unwrap();
            std::fs::write(base.join("conf/nginx.conf"), validate_wrapper(&base, &frag)).unwrap();

            let out = std::process::Command::new(&bin)
                .args(nginx_test_argv(&base))
                .output()
                .expect("启动 nginx 失败");
            assert!(
                out.status.success(),
                "第 {i} 份配置未通过真实 nginx 语法校验（kind={:?}）：\n{}\n--- 渲染结果 ---\n{}",
                s.kind,
                String::from_utf8_lossy(&out.stderr),
                render_nginx(s)
            );
        }

        // ── 阴性对照：喂一份**故意非法**的片段，必须被判失败 ──
        // 这一条才是真正钉住本次修复的断言。旧实现只给 `-p`，而 Debian 的 nginx
        // 把 `--conf-path` 编成了绝对路径 → `-p` 不生效 → 无论片段多离谱，测的
        // 都是系统的 /etc/nginx/nginx.conf：系统里没装 nginx 时它报"文件不存在"，
        // 装了 nginx 之后它又**恒为通过**。两种表现都不指向真正的问题，
        // 而生成片段里的语法错误会一路部署到线上（reload 失败留下坏配置，
        // 下次 nginx 重启直接起不来）。
        let bad = base.join("bad.conf");
        std::fs::write(&bad, "this_is_not_an_nginx_directive 1;\n").unwrap();
        std::fs::write(base.join("conf/nginx.conf"), validate_wrapper(&base, &bad)).unwrap();
        let out = std::process::Command::new(&bin)
            .args(nginx_test_argv(&base))
            .output()
            .expect("启动 nginx 失败");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "非法片段必须被判失败，否则说明校验根本没读到它");
        assert!(
            err.contains("bad.conf"),
            "报错应当指向我们自己生成的片段文件（证明真的读到了它），实际是：{err}"
        );

        let _ = std::fs::remove_dir_all(&base);
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

    // ── 数据库备份/恢复：sqlite roundtrip + mysql/pg 客户端缺失诚实 501 ──
    #[tokio::test]
    async fn sqlite_backup_and_restore_roundtrip() {
        use panel_core::SafePath;
        let dir = std::env::temp_dir().join(format!("fp_dbtest_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("app.db");
        {
            let c = rusqlite::Connection::open(&src).unwrap();
            c.execute("CREATE TABLE t(x INTEGER)", []).unwrap();
            c.execute("INSERT INTO t VALUES (42)", []).unwrap();
        }
        let bak = dir.join("app.backup.db");
        let target = DbTarget {
            engine: DbEngine::Sqlite,
            host: None, port: None, user: None, password: None,
            database: Some(src.to_string_lossy().into()),
        };
        let prov: &dyn DatabaseProvider = &LinuxDatabases::default();
        prov
            .backup(&target, unsafe { &SafePath::from_raw(bak.clone()) }, Box::new(|_| {}))
            .await
            .unwrap();
        assert!(bak.is_file(), "备份文件应生成");
        // 篡改源库，再从备份恢复
        {
            let c = rusqlite::Connection::open(&src).unwrap();
            c.execute("UPDATE t SET x = 999", []).unwrap();
        }
        prov
            .restore(&target, unsafe { &SafePath::from_raw(bak.clone()) })
            .await
            .unwrap();
        let v: i64 = rusqlite::Connection::open(&src).unwrap()
            .query_row("SELECT x FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 42, "恢复后应回到备份时的 42");
        // 还原应留覆盖前快照（自愈网）
        let snap = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("app.db.bak-"));
        assert!(snap, "还原应生成 .bak 快照");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mysql_backup_unsupported_when_client_missing() {
        // 沙箱无 mysqldump：诚实 Unsupported（前端据此置灰），而非假装成功
        if crate::cmd::Bin::MySqlDump.available() { return; }
        let target = DbTarget {
            engine: DbEngine::MySql,
            host: Some("127.0.0.1".into()), port: Some(3306),
            user: Some("u".into()), password: Some("p".into()), database: Some("db".into()),
        };
        let prov: &dyn DatabaseProvider = &LinuxDatabases::default();
        let r = prov.backup(&target, unsafe { &SafePath::from_raw(std::env::temp_dir().join("x.sql")) }, Box::new(|_| {}))
            .await;
        assert!(matches!(r, Err(panel_core::PanelError::Unsupported(_))), "缺失客户端应 Unsupported: {r:?}");
    }
    #[test]
    fn version_major_jump_detects_cross_major_and_ignores_minor() {
        // 跨主版本：PostgreSQL 17→18、Node.js 20→24
        assert!(version_major_jump("17+278", "18+293.pgdg13+1"), "PG 17→18 应判跨主版本");
        assert!(version_major_jump("20.19.0", "24.21.0"), "Node 20→24 应判跨主版本");
        // 仅次/修订版本：Redis 8.0.2→8.10.2、Nginx 1.26→1.30、Node 18.19→18.20
        assert!(!version_major_jump("5:8.0.2", "5:8.10.2"), "Redis 8.0.2→8.10.2 仅次版本");
        assert!(!version_major_jump("1.26.3-3+deb13u9", "1.30.5-1"), "Nginx 1.26→1.30 仅次版本");
        assert!(!version_major_jump("18.19.0", "18.20.0"), "Node 18→18 仅修订");
        // 带 epoch 仍正确剥除：redis 5:8.x 同主版本
        assert!(!version_major_jump("5:8.0.2", "5:8.1.0"));
    }

    #[test]
    fn version_major_jump_handles_unparseable_gracefully() {
        // 解析不出主版本号时保守返回 false（不当作跨主版本，避免误阻断常规升级）
        assert!(!version_major_jump("nightly", "1.0.0"));
        assert!(!version_major_jump("1.0.0", ""));
        assert!(!version_major_jump("", ""));
    }

    #[test]
    fn split_apt_policy_blocks_reads_real_multi_package_output() {
        // 本机实测：`LC_ALL=C apt-cache policy nginx redis-server` 的真实形态
        let out = r"nginx:
  Installed: (none)
  Candidate: 1.30.5-1~trixie
  Version table:
     1.30.5-1~trixie 500
        500 https://nginx.org/packages/debian trixie/nginx amd64 Packages
     1.26.3-3+deb13u9 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
redis-server:
  Installed: 6:8.10.2-1rl1~trixie1
  Candidate: 6:8.10.2-1rl1~trixie1
  Version table:
 *** 6:8.10.2-1rl1~trixie1 500
        500 https://packages.redis.io/deb trixie/main amd64 Packages
";
        let blocks = split_apt_policy_blocks(out);
        assert_eq!(blocks.len(), 2, "应切出两个包块：{blocks:?}");
        assert_eq!(blocks[0].0, "nginx");
        assert_eq!(blocks[1].0, "redis-server");
        // 每块正文喂给既有解析器，结果必须与单包查询一致（含 "*** " 已安装标记）
        assert_eq!(parse_apt_policy_installed(&blocks[0].1), None);
        assert_eq!(
            parse_apt_policy_versions(&blocks[0].1),
            vec!["1.30.5-1~trixie".to_string(), "1.26.3-3+deb13u9".to_string()]
        );
        assert_eq!(
            parse_apt_policy_installed(&blocks[1].1),
            Some("6:8.10.2-1rl1~trixie1".to_string())
        );
        assert_eq!(
            parse_apt_policy_versions(&blocks[1].1),
            vec!["6:8.10.2-1rl1~trixie1".to_string()]
        );
    }

    #[test]
    fn split_apt_policy_blocks_ignores_apt_error_lines() {
        // apt 把"找不到的包"写在 col 0，且以包名（而非 ':'）结尾 → 绝不能被当成块头
        let out = "N: Unable to locate package nosuchpkg\nnginx:\n  Installed: (none)\n";
        let blocks = split_apt_policy_blocks(out);
        assert_eq!(blocks.len(), 1, "错误行不该产生块：{blocks:?}");
        assert_eq!(blocks[0].0, "nginx");
    }

    /// 真实复现（2026-10-08 受控 apt 沙箱实测，逐字取自 `LC_ALL=C apt-cache policy demo-pkg`）：
    /// apt preferences 把包钉在**已安装版本**后，`Candidate` 被压低到 1.0，`apt list --upgradable`
    /// 对该包**沉默**；但版本表里仍有更高版 2.0。旧口径（Candidate）会永远漏报这种更新，
    /// 新口径必须据版本表报出「1.0 → 2.0」——这正是用户报告的「官方源有新版却总说已是最新」。
    #[test]
    fn pinned_candidate_below_installed_still_reports_update() {
        let out = r"demo-pkg:
  Installed: 1.0
  Candidate: 1.0
  Version table:
     2.0 500
        500 file:/tmp/apt-e2e/repo ./ Packages
 *** 1.0 1001
        500 file:/tmp/apt-e2e/repo ./ Packages
        100 /tmp/apt-e2e/var/lib/dpkg/status
";
        let blocks = split_apt_policy_blocks(out);
        assert_eq!(blocks.len(), 1);
        let body = &blocks[0].1;
        // 前置事实：真实输出确如所料——Installed = Candidate = 1.0（apt 自认无可升级），
        // 但版本表最高仍是 2.0。
        assert_eq!(parse_apt_policy_installed(body), Some("1.0".to_string()));
        let versions = parse_apt_policy_versions(body);
        assert_eq!(versions, vec!["2.0".to_string(), "1.0".to_string()]);
        // 新口径：取版本表最高版与已装版本比较 → 必须报出更新。
        assert_eq!(
            crate::traits::upgradable_pair(Some("1.0"), &versions),
            Some(("1.0".to_string(), "2.0".to_string())),
            "Candidate 被 pin 压低时仍应据版本表报出更新（旧口径漏报的场景）"
        );
    }}
