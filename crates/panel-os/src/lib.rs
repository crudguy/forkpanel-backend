//! OS 抽象层（设计方案 §0.3）。业务层**只**通过本 trait 访问操作系统能力。
//!
//! ```ignore
//! let os: Arc<dyn OsAdapter> = default_adapter();
//! let snap = os.metrics().snapshot().await?;          // 不做任何平台判断
//! if os.capabilities()["firewall.manage"].supported { /* UI 才显示防火墙页 */ }
//! ```

pub mod backup;
pub mod cmd;
pub mod fs;
pub mod linux;
pub mod mock_files;
pub mod mock;
pub mod paths;
/// 敏感路径黑名单（唯一事实源）。linux 与 mock 两路实现共用。
pub mod sensitive;
pub mod tls;
pub mod traits;

pub use cmd::{run, run_checked, run_shell, run_sync, spawn_stream, Bin, CmdOpt, CmdOutput};
pub use fs::{
    elf_arch_of, ensure_dir, exec_arch_mismatch, host_machine, is_root, mode_of, port_in_use,
    prune_keep_newest, read_password, set_mode, write_private, ElfArch, PortInUse,
};
pub use linux::scheduler::local_utc_offset_secs_at;
pub use paths::{layout_with_overrides, resolve_within, PathLayout, PathOverrides};
pub use traits::*;

use panel_core::{Capability, CapabilityMap, PlatformInfo};
use std::sync::Arc;

/// 平台能力聚合入口。**新增平台 = 新增一个 impl，业务层零改动。**
pub trait OsAdapter: Send + Sync + 'static {
    fn platform(&self) -> PlatformInfo;
    /// 能力矩阵：前端菜单/按钮的唯一开关来源（禁止前端写 if (isLinux)）
    fn capabilities(&self) -> CapabilityMap;
    /// 宿主规模：`(总内存 MB, CPU 数)`，用于档位探测。
    /// 必须走 trait —— CLI 里直接读 /proc/meminfo 会让平台知识泄漏到业务层。
    fn host_profile(&self) -> (u64, u32);

    fn paths(&self) -> &dyn PathLayout;
    fn metrics(&self) -> &dyn MetricsProvider;
    fn processes(&self) -> &dyn ProcessProvider;
    fn services(&self) -> &dyn ServiceProvider;
    fn packages(&self) -> &dyn PackageProvider;
    fn firewall(&self) -> &dyn FirewallProvider;
    fn network(&self) -> &dyn NetworkProvider;
    fn users(&self) -> &dyn UserProvider;
    fn storage(&self) -> &dyn StorageProvider;
    fn files(&self) -> &dyn FileProvider;
    fn logs(&self) -> &dyn LogProvider;
    fn scheduler(&self) -> &dyn SchedulerProvider;
    fn webserver(&self) -> &dyn WebServerProvider;
    fn databases(&self) -> &dyn DatabaseProvider;
    fn security(&self) -> &dyn SecurityProvider;
    fn containers(&self) -> &dyn ContainerProvider;
    fn terminal(&self) -> &dyn TerminalProvider;
}

/// 按编译目标选择实现。
///
/// 分支顺序即语义：`force-mock` **优先**于真实平台（它的用途就是
/// "在任意机器上用假数据跑通逻辑"）；再 Linux；最后兜底 mock。
///
/// **本面板只支持 Linux**：Windows 服务器有原生 IIS、macOS 服务器 Apple 已停更，
/// 两者都不在支持范围内（老板 2026-10 裁决）。非 Linux 目标不提供真实适配器，
/// 编到别的 target 上只会拿到 mock——显式如此，而不是留一个从未真机跑过的
/// "看起来支持"的分支。
pub fn default_adapter() -> Arc<dyn OsAdapter> {
    #[cfg(feature = "force-mock")]
    { Arc::new(mock::MockOsAdapter::new()) }

    #[cfg(all(target_os = "linux", not(feature = "force-mock")))]
    { Arc::new(linux::LinuxOsAdapter::new()) }

    #[cfg(not(any(target_os = "linux", feature = "force-mock")))]
    { Arc::new(mock::MockOsAdapter::new()) }
}

/// 由配置覆盖构造适配器（**跨平台入口**，供 CLI 的 `serve` 使用）。
///
/// 为什么必须有这个入口，而不是让 CLI 直接 `Arc::new(linux::LinuxOsAdapter::with_paths(..))`：
/// 1. **可移植性**：业务层一旦引用 `panel_os::linux::*` 就绑死在 Linux，
///    非 Linux 目标编译不过（CI 门禁 [4c] 正是拦这个）。
/// 2. **`force-mock` 会失效**：`serve` 绕过 `default_adapter()` 直接起真实平台适配器，
///    于是"无 Linux / 无 root 环境下用 mock 跑逻辑"这一已声明的能力形同虚设。
///
/// 入参是**值**而非平台类型，具体用哪个 `PathLayout` 实现由本函数内部决定。
pub fn adapter_with_overrides(
    config_dir: Option<std::path::PathBuf>,
    site_root: Option<std::path::PathBuf>,
    data_dir: Option<std::path::PathBuf>,
    log_dir: Option<std::path::PathBuf>,
) -> Arc<dyn OsAdapter> {
    adapter_with(PathOverrides { config_dir, site_root, data_dir, log_dir })
}

/// 同 [`adapter_with_overrides`]，但收 [`PathOverrides`] 具名结构体。
///
/// 布局**必须**经 `paths::layout_with_overrides()` 构造：CLI 的 `build_layout()`
/// 走的是同一个工厂，从而保证"适配器内部的布局"与"CLI 建目录/打印用的布局"
/// 是同一份语义，不会因两处各写一遍而静默分叉。
pub fn adapter_with(ov: PathOverrides) -> Arc<dyn OsAdapter> {
    #[cfg(feature = "force-mock")]
    {
        // mock 布局是内存视图，配置覆盖无意义；显式丢弃以避免"看起来生效了"
        let _ = ov;
        Arc::new(mock::MockOsAdapter::new())
    }
    #[cfg(all(target_os = "linux", not(feature = "force-mock")))]
    {
        let layout = paths::LinuxPathLayout::default().with_overrides(
            ov.config_dir, ov.site_root, ov.data_dir, ov.log_dir);
        Arc::new(linux::LinuxOsAdapter::with_paths(Arc::new(layout)))
    }
    #[cfg(not(any(target_os = "linux", feature = "force-mock")))]
    {
        let _ = ov;
        Arc::new(mock::MockOsAdapter::new())
    }
}

/// 发信号能力：euid 0 才能作用于他人进程（POSIX）。
///
/// 刻意抽成**纯函数**：直接在 `capabilities()` 里调 `is_root()` 的话，CI（非 root）
/// 恒得到 no，测试只能覆盖一半分支，另一半（root 时 yes）永远跑不到——判据成立与否
/// 取决于跑测试的人是谁，这本身就是"判据指向错"的一种。
pub fn signal_capability(is_root: bool) -> Capability {
    if is_root { Capability::yes("posix") } else { Capability::no("non_root") }
}

impl OsAdapter for linux::LinuxOsAdapter {
    fn platform(&self) -> PlatformInfo { self.platform.clone() }

    fn host_profile(&self) -> (u64, u32) { linux::host_profile() }

    fn files(&self) -> &dyn FileProvider { &*self.files }

    fn capabilities(&self) -> CapabilityMap {
        use panel_core::cap_keys as k;
        let mut m = CapabilityMap::new();
        m.insert(k::METRICS_READ.into(), Capability::yes("procfs"));
        // 进程**列表**与**发信号**是两种权限，必须分开判定：/proc 对所有用户可读，
        // 但向他人进程发信号要求 euid 0（否则 kill(2) 一律 EPERM）。合一位的后果是
        // 非 root 部署的杀进程按钮照常可点，点了才失败——正是能力位要提前挡住的事。
        m.insert(k::PROCESS_LIST.into(), Capability::yes("procfs"));
        m.insert(k::PROCESS_SIGNAL.into(), signal_capability(is_root()));
        m.insert(k::SERVICE_MANAGE.into(), match self.services.init_system() {
            panel_core::InitSystem::Systemd => Capability::yes("systemd"),
            panel_core::InitSystem::SysV => Capability::yes("sysv"),
            panel_core::InitSystem::OpenRc => Capability::yes("openrc"),
            _ => Capability::no("init_unknown"),
        });
        m.insert(k::PACKAGE_INSTALL.into(), match self.packages.manager() {
            Some(mgr) => Capability::yes(mgr),
            None => Capability::no("no_package_manager"),
        });

        // 升级能力与安装同源：apt 的 `install pkg=version` 本身就是覆盖升级。
        // 同样只有"存在包管理器"才yes——没有包管理器时升级无从谈起（诚实置灰，
        // 不能让菜单可见、点了才报错）。
        m.insert(k::PACKAGE_UPGRADE.into(), match self.packages.manager() {
            Some(mgr) => Capability::yes(mgr),
            None => Capability::no("no_package_manager"),
        });
        m.insert(k::FILE_READ.into(), Capability::yes("posix"));
        m.insert(k::FILE_WRITE.into(), Capability::yes("posix"));
        m.insert(k::FIREWALL_MANAGE.into(), self.firewall.capability());
        m.insert(k::FAIL2BAN.into(), self.firewall.fail2ban_capability());
        // 仅 nginx 已实装渲染/下发；caddy 已探测但 render 未实现，
        // 不能"探测到就报 yes"——那正是"假装可移植"。诚实置 no 并给出原因。
        m.insert(k::WEBSERVER_MANAGE.into(), match self.webserver.name() {
            // nginx 完整实装；caddy 基础样板已实装（render + validate/deploy/reload CLI），
            // 与 nginx 同样按二进制存在性诚实判定。未覆盖的高级特性（WAF/精细TLS/IP名单/
            // BasicAuth/伪静态/www跳转/多域名）见 render_caddy 顶部注释——是"部分支持"而非不可用。
            "nginx" => Capability::yes("nginx"),
            "caddy" => Capability::yes("caddy"),
            _ => Capability::no("binary_missing"),
        });
        // scheduler 已随 crontab 落地，能力位必须跟着实现走（不要写死 no）
        m.insert(k::SCHEDULER_MANAGE.into(), self.scheduler.capability());
        // 以下为 M4/M5 待实现：显式 no，UI 自动置灰
        // 日志：有 journald 或站点日志文件即可读（诚实：无任何源则 no）
        m.insert(k::LOGS_READ.into(), if self.logs.available() {
            Capability::yes(match self.logs.backend() {
                panel_core::LogBackend::Journald => "journald",
                panel_core::LogBackend::File => "file",
            })
        } else {
            Capability::no("no_log_source")
        });
        // 数据库浏览：SQLite 内建引擎已实装 → yes；mysql/postgres 未实装，逐连接再判
        m.insert(k::DBMS_MANAGE.into(), if self.databases.supports(DbEngine::Sqlite) {
            Capability::yes("sqlite")
        } else {
            Capability::no("no_engine")
        });
        // ACME：按设计 §5.3 的"certbot 回退实现"路线（内置 instant-acme 留作后续，
        // 需评估 DNS-01 与各家 CA 兼容性）。能力位看**二进制存在性**——
        // 没有 certbot 就诚实置灰，绝不给出"能点但必失败"的假按钮。
        m.insert(k::SSL_ACME.into(), if crate::cmd::Bin::Certbot.available() {
            Capability::yes("certbot")
        } else {
            Capability::no("certbot_missing")
        });
        // 面板自签：本机有 openssl 即可（离线可用），与 ACME 相互独立
        m.insert(k::SSL_SELFSIGNED.into(), if tls::available() {
            Capability::yes("openssl")
        } else {
            Capability::no("openssl_missing")
        });
        // 备份计划：面板内建（SQLite 在线备份 + tar），与平台能力无关
        m.insert(k::BACKUP_MANAGE.into(), Capability::yes("builtin"));
        // 容器：**看守护进程可达性，不看二进制存在性**。
        // 装好 docker 但面板身份连不上 socket 是常态（不在 docker 组 / daemon 未跑）；
        // 若按"二进制存在"就报 yes，用户会得到一个点了必报错的假按钮。
        m.insert(k::CONTAINER_MANAGE.into(), match self.containers.unavailable_reason() {
            None => Capability::yes(self.containers.engine().as_str()),
            Some(reason) => Capability::no(reason),
        });
        // 容器"入口"能力：恒 supported（即使 engine=None 也 yes("none")）。
        // 刻意与 CONTAINER_MANAGE 分离——菜单点亮与否不应被"daemon 是否可达"卡住，
        // 否则用户会以为功能缺失/没做完。进入页面后再按 daemon 状态分流展示。
        m.insert(k::CONTAINER_VIEW.into(), Capability::yes(self.containers.engine().as_str()));
        // 终端：本机有可用交互 shell 即可。**能力位只管"能不能开"**，
        // 真正的准入还叠加 SYSTEM_MANAGE 权限 + 只读模式拒绝（见 routes/terminal.rs）。
        m.insert(k::TERMINAL_MANAGE.into(), match self.terminal.shell() {
            Some(sh) => Capability::yes(sh.as_str()),
            None => Capability::no("binary_missing"),
        });
        // 用户与角色管理是面板内建功能，与操作系统能力无关，任何平台恒支持
        m.insert(k::USER_MANAGE.into(), Capability::yes("builtin"));
        m
    }

    fn paths(&self) -> &dyn PathLayout { &*self.paths }
    fn metrics(&self) -> &dyn MetricsProvider { &*self.metrics }
    fn processes(&self) -> &dyn ProcessProvider { &*self.metrics }
    fn services(&self) -> &dyn ServiceProvider { &*self.services }
    fn packages(&self) -> &dyn PackageProvider { &*self.packages }
    fn firewall(&self) -> &dyn FirewallProvider { &*self.firewall }
    fn network(&self) -> &dyn NetworkProvider { &*self.network }
    fn users(&self) -> &dyn UserProvider { &*self.users }
    fn storage(&self) -> &dyn StorageProvider { &*self.storage }
    fn logs(&self) -> &dyn LogProvider { &*self.logs }
    fn scheduler(&self) -> &dyn SchedulerProvider { &*self.scheduler }
    fn webserver(&self) -> &dyn WebServerProvider { &*self.webserver }
    fn databases(&self) -> &dyn DatabaseProvider { &*self.databases }
    fn security(&self) -> &dyn SecurityProvider { &*self.security }
    fn containers(&self) -> &dyn ContainerProvider { &*self.containers }
    fn terminal(&self) -> &dyn TerminalProvider { &*self.terminal }
}

/// 启动自检：数据目录落在网络文件系统上时必须拒绝启动（WAL 不可用）
pub fn startup_fs_check(paths: &dyn PathLayout) -> panel_core::Result<()> {
    let (fs, is_network) = linux::check_data_dir_fs(&paths.data_dir())?;
    if is_network {
        return Err(panel_core::PanelError::Internal(
            format!("data dir on network filesystem ({fs}): SQLite WAL is unsafe here; \
                     move data_dir to a local filesystem")));
    }
    Ok(())
}

/// 面板进程当前的运行用户名（effective uid 映射）。
///
/// 用于"把谁加入 docker 组"这类需要面板**真实身份**的动作——docker socket 的权限
/// 取决于面板进程用户，而不是登录用户；取错人（如登录用户）对管理容器毫无帮助。
///
/// 实现：读 /etc/passwd 把 effective uid 映射成用户名，**绝不调用子进程**
/// （`id -un` 会引入命令注入面）。无对应条目时回退 "root"。
pub fn runtime_user() -> String {
    let uid = unsafe { libc::geteuid() };
    crate::linux::files::uid_to_name(uid).unwrap_or_else(|| "root".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::cap_keys;

    #[test]
    fn adapter_exposes_capability_matrix() {
        let os = default_adapter();
        let caps = os.capabilities();
        // 能力矩阵必须包含关键位，且不允许空
        assert!(caps.contains_key(cap_keys::METRICS_READ));
        assert!(caps.contains_key(cap_keys::FIREWALL_MANAGE));
        assert!(!caps.is_empty());
    }

    #[test]
    fn paths_are_never_empty() {
        let os = default_adapter();
        assert!(!os.paths().data_dir().as_os_str().is_empty());
        assert!(!os.paths().site_root().as_os_str().is_empty());
        assert!(!os.paths().default_web_user().is_empty());
    }

    /// mock 的 hold 读写必须闭环（幂等 + 全集语义）：预览模式下 UI 的
    /// 「钉住/取消」切换靠这组进程内状态回读——闭环断一条，用户侧表现
    /// 就是「点了没反应」或「刷新后钉住状态丢了」，而构建全绿。
    #[tokio::test]
    async fn mock_package_hold_roundtrip_is_idempotent() {
        let os = mock::MockOsAdapter::new();
        let p = os.packages();
        p.set_hold("nginx", true).await.unwrap();
        p.set_hold("redis-server", true).await.unwrap();
        // 重复 hold 同一包：幂等——不报错，也不产生重复项
        p.set_hold("nginx", true).await.unwrap();
        let mut held = p.holds().await.unwrap();
        held.sort();
        assert_eq!(held, vec!["nginx".to_string(), "redis-server".to_string()]);
        // 取消后从全集消失（不是标记为"取消的 hold"——集合语义）
        p.set_hold("nginx", false).await.unwrap();
        assert_eq!(p.holds().await.unwrap(), vec!["redis-server".to_string()]);
        // 对未 hold 的包再 unhold：同样幂等成功
        p.set_hold("never-held", false).await.unwrap();
    }

    /// 二轮审计 P2-5：`process.signal` 按特权判定，与 `process.list` 分流。
    /// 两条分支都必须跑到——只有一条的测试等于没测另一条。
    #[test]
    fn signal_capability_follows_privilege() {
        let yes = signal_capability(true);
        assert!(yes.supported, "root 下必须 yes：否则按钮白白置灰，用户用不上能用的功能");
        let no = signal_capability(false);
        assert!(!no.supported, "非 root 必须 no：kill 必然 EPERM，不能等用户点了才知道");
        assert_eq!(no.reason.as_deref(), Some("non_root"),
            "原因码要能直接给用户看（前端展示 reason），不能是空的");
    }

    /// 适配器必须**经 `signal_capability()` 判定**，不许直接写死 yes。
    /// 纯函数那条测试只能证明"函数本身对"，证明不了"适配器真的调了它"——
    /// 写死 `Capability::yes("posix")` 时，行为测试照样全绿（它们自己往 map 里
    /// 塞值，与适配器无关），于是能力位退回"登记了但没人读"：后端门与前端
    /// 置灰双双变成永不触发的死代码。这正是"假控制"的另一种形态。
    #[test]
    fn process_signal_is_decided_by_privilege_not_hardcoded() {
        // 读本文件生产段：注释里逐字写着这个调用，不剔注释就会恒真。
        let code = panel_testutil::production_source(include_str!("lib.rs"));
        let got = code.matches("k::PROCESS_SIGNAL.into(), signal_capability(").count();
        assert_eq!(got, 1,
            "`process.signal` 必须由 signal_capability() 判定，实际接线 {got} 处。\n\n            少了＝又被写死成常量（能力位退回没人在读的装饰）；\n            多了＝插入点重复——先确认语义，再改这里。");
    }
}
