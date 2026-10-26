//! macOS 路径布局。
//!
//! # 为什么不能复用 `LinuxPathLayout`
//!
//! Linux 默认值是 `/etc/forkpanel`、`/var/www`、`/var/lib/forkpanel`、
//! `/var/log/forkpanel`。macOS 上：
//! - `/etc` 受 SIP 保护，普通用户不可写；
//! - `/var/www` 在 macOS 上不是站点目录惯例（且默认不存在）；
//! - `/var/lib` 同样不存在。
//!
//! 直接复用会让面板以非 root 启动时**必然**在建目录处失败，而错误信息是
//! "Permission denied: /var/lib/forkpanel"——用户完全不知道这是平台错配。
//!
//! # 取值依据（macOS 文件系统层次惯例）
//!
//! | 用途 | 位置 | 依据 |
//! | --- | --- | --- |
//! | 配置 | `~/Library/Application Support/ForkPanel` | Apple 官方推荐的应用私有数据位置 |
//! | 数据 | 同上 | 同上（配置与数据同目录，便于整体备份/迁移） |
//! | 日志 | `~/Library/Logs/ForkPanel` | macOS 惯例的日志位置（Console.app 可见） |
//! | 站点根 | `~/Sites` | Apple 传统站点目录；不存在时首次建站会创建 |
//! | Web 配置 | `<config>/nginx/conf.d` | 跟随配置目录，避免写 `/opt/homebrew/etc` |
//! | 容器 socket | `~/.docker/run/docker.sock` | Docker Desktop for Mac 的默认路径 |
//!
//! 注意 `default_web_user()` 返回 `_www`：macOS 内置的 Web 服务身份
//! （`dscl . -read /Users/_www` 可查），与 Linux 的 `www-data` 对应。

use crate::paths::PathLayout;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct MacPathLayout {
    /// 可被 `config.toml [paths] config` 覆盖
    config_dir: PathBuf,
    site_root: PathBuf,
    data_dir: PathBuf,
    log_dir: PathBuf,
}

/// 用户主目录。取不到时回退到 `/tmp`——**刻意不让它 panic**：
/// 布局构造发生在 CLI 启动最早期，此时 panic 等于面板完全不可用，
/// 而回退到 /tmp 至少能起来、能在 doctor 里报出"主目录不可解析"。
fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

impl Default for MacPathLayout {
    fn default() -> Self {
        let h = home();
        let app_support = h.join("Library").join("Application Support").join("ForkPanel");
        Self {
            config_dir: app_support.clone(),
            // 数据与配置同目录：macOS 用户习惯把整个应用目录一起备份/迁移，
            // 而 Linux 把 /etc 与 /var/lib 分开是因为 root 与系统服务语义。
            data_dir: app_support,
            log_dir: h.join("Library").join("Logs").join("ForkPanel"),
            site_root: h.join("Sites"),
        }
    }
}

impl MacPathLayout {
    pub fn with_overrides(
        mut self,
        config: Option<PathBuf>,
        site_root: Option<PathBuf>,
        data_dir: Option<PathBuf>,
        log_dir: Option<PathBuf>,
    ) -> Self {
        if let Some(v) = config { self.config_dir = v; }
        if let Some(v) = site_root { self.site_root = v; }
        if let Some(v) = data_dir { self.data_dir = v; }
        if let Some(v) = log_dir { self.log_dir = v; }
        // 刻意保留 config_dir 与 data_dir 各自独立：用户可能只想改其一。
        // 默认值相同只是"默认",不是"绑定"。
        self
    }
}

impl PathLayout for MacPathLayout {
    fn config_dir(&self) -> PathBuf { self.config_dir.clone() }
    fn data_dir(&self) -> PathBuf { self.data_dir.clone() }
    fn log_dir(&self) -> PathBuf { self.log_dir.clone() }
    fn cache_dir(&self) -> PathBuf { self.data_dir.join("cache") }
    fn tmp_dir(&self) -> PathBuf { self.data_dir.join("tmp") }
    fn site_root(&self) -> PathBuf { self.site_root.clone() }

    /// nginx 的 conf.d。跟随**配置目录**而非 `/opt/homebrew/etc/nginx`：
    /// Homebrew 的前缀在 Intel（`/usr/local`）与 Apple Silicon（`/opt/homebrew`）
    /// 上不同，写死任一个都会在另一种机器上失效。
    fn web_conf_dir(&self) -> PathBuf { self.config_dir.join("nginx").join("conf.d") }
    fn caddy_sites_dir(&self) -> PathBuf { self.config_dir.join("caddy").join("sites") }
    fn web_log_dir(&self) -> PathBuf { self.log_dir.join("web") }

    /// launchd 的用户级 LaunchAgents 目录。
    /// 用用户级（`~/Library/LaunchAgents`）而非系统级（`/Library/LaunchDaemons`）：
    /// 后者需要 root，而 Phase 1 的目标就是"非 root 也能起来"。
    fn service_dir(&self) -> PathBuf { home().join("Library").join("LaunchAgents") }

    /// macOS 仍保留 crontab（虽已被 Apple 标记为不推荐，但 `crontab(1)` 可用）。
    /// 返回 `/var/at/tabs` 需要 root；这里给用户级脚本目录的兄弟路径，
    /// 实际 crontab 操作走 `crontab` 命令而非直接写文件（Phase 4）。
    fn cron_dir(&self) -> PathBuf { self.config_dir.join("cron") }

    fn script_dir(&self) -> PathBuf { self.data_dir.join("scripts") }
    fn backup_dir(&self) -> PathBuf { self.data_dir.join("backups") }

    /// Docker Desktop for Mac 的用户级 socket。
    /// 与 Linux 的 `/var/run/docker.sock`（守护进程系统级）不同：macOS 上
    /// Docker 跑在虚拟机里，socket 由用户态进程暴露。
    fn container_socket(&self) -> PathBuf {
        home().join(".docker").join("run").join("docker.sock")
    }

    /// macOS 内置 Web 身份。与 Linux 的 `www-data` 对应。
    fn default_web_user(&self) -> &'static str { "_www" }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// conformance 契约 3：所有路径必须非空（空路径会导致"写到根目录"）。
    #[test]
    fn all_paths_are_non_empty() {
        let p = MacPathLayout::default();
        for (name, dir) in [
            ("config", p.config_dir()), ("data", p.data_dir()), ("log", p.log_dir()),
            ("cache", p.cache_dir()), ("tmp", p.tmp_dir()), ("site_root", p.site_root()),
            ("web_conf", p.web_conf_dir()), ("caddy", p.caddy_sites_dir()),
            ("web_log", p.web_log_dir()), ("service", p.service_dir()),
            ("cron", p.cron_dir()), ("script", p.script_dir()), ("backup", p.backup_dir()),
            ("socket", p.container_socket()),
        ] {
            assert!(!dir.as_os_str().is_empty(), "{name} 不得为空");
        }
        assert!(!p.default_web_user().is_empty());
        assert!(p.sqlite_path().ends_with("panel.db"));
    }

    /// 默认值必须落在**用户可写**的 `~/Library` 下，而不是 `/etc`、`/var`
    /// ——那正是照搬 Linux 布局会踩的坑（SIP 保护 + 目录不存在）。
    #[test]
    fn defaults_are_under_home_not_system_dirs() {
        let p = MacPathLayout::default();
        for dir in [p.config_dir(), p.data_dir(), p.log_dir(), p.site_root()] {
            assert!(
                !dir.starts_with("/etc") && !dir.starts_with("/var/lib") && !dir.starts_with("/var/www"),
                "macOS 默认路径不得落在 Linux 系统目录：{}", dir.display()
            );
        }
    }

    /// 覆盖必须逐项生效，且不影响未覆盖项（否则"只改 data"会连带改掉 config）。
    #[test]
    fn overrides_apply_independently() {
        let base = MacPathLayout::default();
        let orig_log = base.log_dir();
        let p = base.with_overrides(None, None, Some(PathBuf::from("/opt/data")), None);
        assert_eq!(p.data_dir(), PathBuf::from("/opt/data"));
        assert_eq!(p.log_dir(), orig_log, "未覆盖的日志目录不应被改动");
    }
}
