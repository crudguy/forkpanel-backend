use super::*;


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

/// 从 `dpkg -L <pkg>` 的输出里挑出该包 shipping 的**主** systemd 单元：
/// 位于 `.../systemd/system/` 下、以 `.service` 结尾、且**非模板**（不含 `@`）的单元。
///
/// 选择主单元的规则（避免 nginx 误选 `nginx-debug.service`）：
/// 1. 优先 stem 与包名完全一致者（`nginx` → `nginx.service`，而非 `nginx-debug.service`）；
/// 2. 否则取**最短**的 stem（主服务单元名通常最短，`*-debug`/`-worker` 等变体更长）。
///
/// 抽成纯函数以便单测——不依赖真实 dpkg，fixture 即 `dpkg -L` 的真实片段。
pub(super) fn service_unit_from_dpkg_list(out: &str, pkg: &str) -> Option<String> {
    let exact = format!("{pkg}.service");
    let mut candidates: Vec<&str> = Vec::new();
    for l in out.lines() {
        if l.ends_with(".service") && l.contains("systemd/system/") {
            let base = l.rsplit('/').next().unwrap_or(l);
            if base.contains("@") { continue; }   // 跳过模板单元（postgresql@.service 等）
            candidates.push(base);
        }
    }
    if candidates.is_empty() { return None; }
    // 规则 1：stem 与包名完全一致优先
    if let Some(m) = candidates.iter().find(|b| **b == exact.as_str()) {
        return Some(m.to_string());
    }
    // 规则 2：否则取最短 stem（主服务单元名最短）
    candidates.sort_by_key(|b| b.len());
    Some(candidates[0].to_string())
}

/// dpkg Status-Abbrev 是否表示「文件在盘上」——**当前状态位（第二位）== 'i'**。
///
/// 三位 = `<期望动作><当前状态><错误标记>`。期望动作在 `apt-mark hold` 后会从
/// `i` 变 `h`：被钉住的包是 `hi ` 而非 `ii `，仍然实打实装着。早期实现只认
/// `ii`，导致 hold 功能上线时被钉住的包**整条从面板消失**（实机回归：
/// hold nginx →「已安装软件」少了 nginx，hold 徽标也无处显示）。
///
/// 其余形态：`rc ` 删剩配置（要）、`un ` 未安装（本就要排除）、
/// `iF`/`iU` 半装半配（坏了，不算可用）。空串/短串保守判 false。
pub(super) fn dpkg_status_installed(status: &str) -> bool {
    status.as_bytes().get(1) == Some(&b'i')
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
                // Status-Abbrev 三位 = <期望动作><当前状态><错误标记>：`ii ` 已安装、
                // `rc ` 删剩配置、`un ` 未安装。判据取**第二位**（当前状态）== 'i'：
                // 第一位（期望动作）在 `apt-mark hold` 后会从 i 变 h——被钉住的包是
                // `hi ` 而非 `ii `，只认 "ii" 会让钉住的包整条从面板消失
                // （实机：hold nginx 后「已安装软件」少了 nginx，且 hold 徽标无处显示）。
                // 不能改用"版本非空"判断——那只是绕开同一个问题的表面现象。
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
                    // 第二位 == 'i'（installed）：同时接纳 `ii `（普通已装）与
                    // `hi `（apt-mark hold 钉住的已装）；排除 `rc `/`un `/半装态。
                    if !dpkg_status_installed(status) { return None }
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

    async fn service_unit(&self, name: &str) -> Result<Option<String>> {
        match self.manager {
            // 直接问 dpkg 这个包装了哪些 .service 文件，绕开 systemctl list-units 对
            // enabled-but-dead 单元的遗漏（详见 PackageProvider::service_unit 的说明）。
            Some("apt") => {
                let out = crate::cmd::run(
                    Bin::Dpkg, &["-L", name],
                    CmdOpt { timeout: Duration::from_secs(10), ..Default::default() },
                ).await?;
                Ok(service_unit_from_dpkg_list(&out.stdout, name))
            }
            _ => Ok(None),
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

    async fn holds(&self) -> Result<Vec<String>> {
        // 非 apt 一律空集：语义是「此系统无 hold 概念」，不是错误。
        if self.manager != Some("apt") { return Ok(Vec::new()); }
        // showhold 一次输出全部被钉包名（每行一个）；无任何 hold 时退出码 0、
        // 输出为空。用 run_checked：apt-mark 缺失（极少数精简镜像）应如实报错，
        // 而不是把「查询失败」伪装成「没有 hold」——后者会让 UI 隐藏入口，
        // 用户以为自己的包没被钉，实则状态未知。
        let out = crate::cmd::run_checked(
            Bin::AptMark, &["showhold"],
            CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
        ).await?;
        Ok(out.stdout.lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect())
    }

    async fn set_hold(&self, name: &str, held: bool) -> Result<()> {
        let m = self.manager.ok_or(PanelError::Unsupported("package.manager"))?;
        if m != "apt" { return Err(PanelError::Unsupported("package.hold")); }
        // 子命令编译期二选一；包名由调用方白名单校验后作为单个 argv 传入。
        let sub = if held { "hold" } else { "unhold" };
        crate::cmd::run_checked(
            Bin::AptMark, &[sub, name],
            CmdOpt { timeout: Duration::from_secs(30), ..Default::default() },
        ).await?;
        Ok(())
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
            (Some(v), Some(prio), None) if prio.chars().all(|c| c.is_ascii_digit())
                && !versions.contains(&v.to_string()) => { versions.push(v.to_string()); }
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
pub(super) fn policy_block_header(line: &str) -> Option<String> {
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
pub(super) async fn pkg_run_streamed(bin: Bin, args: &[&str], on_line: std::sync::Arc<dyn Fn(&str) + Send + Sync>) -> Result<()> {
    let o = crate::cmd::run(bin, args, CmdOpt {
        timeout: Duration::from_secs(1800), on_line: Some(on_line), ..Default::default()
    }).await?;
    if o.code != Some(0) {
        return Err(PanelError::Command { bin: bin.as_str().into(), detail: truncate_err(&o.stderr) });
    }
    Ok(())
}

/// 卸载类命令统一出口：无流式输出需求。
pub(super) async fn pkg_run(bin: Bin, args: &[&str]) -> Result<()> {
    let o = crate::cmd::run(bin, args, CmdOpt { timeout: Duration::from_secs(1800), ..Default::default() }).await?;
    if o.code != Some(0) {
        return Err(PanelError::Command { bin: bin.as_str().into(), detail: truncate_err(&o.stderr) });
    }
    Ok(())
}

pub(super) fn truncate_err(s: &str) -> String {
    if s.len() <= 2000 { s.to_string() } else { format!("{}…(truncated)", &s[..2000]) }
}

