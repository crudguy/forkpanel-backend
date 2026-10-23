//! 敏感路径黑名单（**唯一事实源**）。
//!
//! ## 为什么单独成文件
//! 原先 `linux/files.rs` 与 `mock_files.rs` 各写一份 `DENY_EXACT`，两份必然漂移，
//! 漂移的那份就是漏网的那份（`is_sensitive_path` 的 trait 注释早已点名此风险）。
//! 现在两个平台实现都调 [`is_sensitive_path_str`]，mock 与真实行为天然一致。
//!
//! ## 判定口径
//! 只做精确 / 前缀 / 后缀匹配，**不做模糊匹配**（模糊匹配容易误伤且难审计）。
//!
//! ## 收录标准（谁该进黑名单）
//! 进黑名单的判据是「**改坏它会立刻让机器不可登录、不可启动，或以 root 身份执行
//! 任意代码**」。据此收录：认证与账号数据库、sudo/PAM、动态链接器预加载、
//! 定时任务、systemd 单元、init 脚本、防火墙持久化配置（nftables/iptables/ufw，
//! 写坏=下次重放时网络全锁）、fail2ban 配置（action 规则以 root 执行命令）、
//! 内核参数与模块加载（sysctl 的 core_pattern 可指向程序、modprobe.d 的
//! install 行可执行任意命令）、root 的登录壳脚本（与 /etc/profile 同族）。
//!
//! 反过来说，**不进**黑名单的也要有理由：`/etc/hosts`、`/etc/resolv.conf`、
//! `/etc/hostname` 属于常见运维改动且坏了可恢复，保留可写；**非 root 用户自己
//! 的 `~/.bashrc` 同样保留可写**——那份脚本只以该用户身份执行，不构成提权向量
//! （root 的才是，故只精确收 `/root/` 下那几个启动文件名）。
//!
//! ## 事故记录（2026-10-21）
//! 故障注入时用面板的 `PUT /files/write` 直接覆盖了 `/etc/passwd`（返回 200），
//! 当场把机器的用户数据库写成 5 字节，sudo 报「passwd 数据库中没有您」。
//! 黑名单当时只有 `/etc/shadow` / `/etc/gshadow` / `/etc/sudoers` —— 挡住了
//! **读口令**，却没挡住**改账号**。本文件就是那次事故的直接产物。

/// 精确匹配（单个文件）
const DENY_EXACT: &[&str] = &[
    // 账号数据库：改坏=无人可登录（事故现场）
    "/etc/passwd", "/etc/group", "/etc/passwd-", "/etc/group-",
    // 口令数据库与它们的备份
    "/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-",
    // sudo
    "/etc/sudoers",
    // 动态链接器预加载：写一行任意 .so = 任何进程启动即以该进程身份执行代码
    "/etc/ld.so.preload",
    // 名称解析与 PAM 的单文件形态
    "/etc/nsswitch.conf", "/etc/pam.conf",
    // 动态链接器主配置（`.d/` 目录走前缀）
    "/etc/ld.so.conf",
    // 登录壳会执行的全局脚本
    "/etc/profile", "/etc/bash.bashrc", "/etc/environment",
    // 定时任务本体（root 的 crontab = 定时以 root 执行任意命令）
    "/etc/crontab",
    // 面板主密钥：改坏=全部备份与凭据无法解密（位于数据目录，非 /etc）
    "/var/lib/forkpanel/master.key",
    // 防火墙持久化：netfilter-persistent / nftables.service 在启动时重放这些
    // 文件，写坏（或写成 deny-all）= 下次重启网络全锁，远程不可登录
    "/etc/nftables.conf",
    "/etc/default/ufw",             // ufw 开关与默认策略（ENABLED/DEFAULT_*_POLICY）
    // TCP wrappers：一条 `ALL: ALL` 即可拒掉包括 SSH 在内的全部登录
    "/etc/hosts.allow", "/etc/hosts.deny",
    // 内核参数：kernel.core_pattern 可写成「|/路径」= 任意程序以 root 执行；
    // 其余参数（如 pid_max）可让系统迅速不可用
    "/etc/sysctl.conf",
    // 开机加载的内核模块：列 .ko 路径 = 下次启动即以内核身份执行任意代码
    "/etc/modules",
    // 文件系统挂载表：写坏 = 下次重启挂载失败，**机器起不来**，与 nftables.conf
    // 同族（都是「改坏只在下次启动才暴露」，届时人已在机房外）
    "/etc/fstab",
    // root 的登录/交互壳启动脚本：与 /etc/profile 同族，但只对 root 生效
    // （非 root 用户自己的 ~/.bashrc 不在此列，理由见模块头）
    "/root/.bashrc", "/root/.bash_profile", "/root/.bash_login",
    "/root/.profile", "/root/.bash_logout",
];

/// 前缀匹配（整个目录 / 一族文件）
const DENY_PREFIX: &[&str] = &[
    // 既有：SSH / TLS 私钥 / 面板自身数据
    "/etc/ssh/", "/etc/ssl/private/", "/etc/forkpanel/",
    "/root/.ssh/", "/proc/", "/sys/", "/dev/",
    // sudo 片段（drop-in 与主文件等价）
    "/etc/sudoers.d/",
    // PAM：改一行即可让任何用户免密登录
    "/etc/pam.d/",
    // 定时任务：root 的 crontab 条目 = 定时以 root 执行任意命令
    // （`/etc/crontab` 本体在精确表；这里只放目录，避免 `crontab.bak` 被误拒）
    "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
    "/etc/cron.weekly/", "/etc/cron.monthly/", "/var/spool/cron/",
    // systemd：单元文件可直接指定 ExecStart 为任意命令。
    // ⚠ 发行版包单元的**真实位置**在 /usr/lib/systemd/（Debian 上 /lib 是 /usr/lib
    // 的 symlink），/etc/systemd/ 多为管理员覆盖位——只收 /etc 会漏掉整个发行版单元
    // 目录，往那里写 ExecStart= 同样是以 root 执行任意代码。
    "/etc/systemd/", "/run/systemd/", "/lib/systemd/", "/usr/lib/systemd/",
    // init / 启动脚本
    "/etc/init.d/", "/etc/init/", "/etc/rcS.d/", "/etc/rc.local",
    // 动态链接器配置目录（主配置在精确表）
    "/etc/ld.so.conf.d/",
    // 登录脚本目录
    "/etc/profile.d/",
    // 资源限制与安全策略（可让 root 进程被内核杀掉 / 提权）
    "/etc/security/",
    // 防火墙持久化目录：iptables-persistent 从 rules.v4/v6 重放；ufw 规则树
    "/etc/iptables/", "/etc/ufw/",
    // fail2ban 配置树：action.d 的命令模板与 jail 内联 action 都以 root 执行。
    // filter.d 等只读文件一并拒绝——整树拒绝比逐文件区分更可审计，且面板文件页
    // 本就不是 fail2ban 的编辑入口（真要在面板里改请走「终端」或 SSH）。
    "/etc/fail2ban/",
    // 内核参数 drop-in（与 /etc/sysctl.conf 等价）
    "/etc/sysctl.d/",
    // 开机模块加载：modules-load.d 列 .ko；modprobe.d 的 install 行可执行任意命令
    "/etc/modules-load.d/", "/etc/modprobe.d/",
    // AppArmor profile：enforce 档语法错误会让依赖它的服务起不来（不可启动）
    "/etc/apparmor.d/",
];

/// 后缀匹配（任何用户下的同名文件）
const DENY_SUFFIX: &[&str] = &[
    "/authorized_keys",
    // OpenSSH 旧式公钥文件（AuthorizedKeysFile 的兼容名），与上一行等价
    "/authorized_keys2",
    "/.ssh/id_rsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519", "/.ssh/identity",
    // OpenSSH 默认私钥名补齐：id_dsa（旧算法）与两个 FIDO 变体（_sk 后缀）
    "/.ssh/id_dsa", "/.ssh/id_ecdsa_sk", "/.ssh/id_ed25519_sk",
];

/// 面板库本体是否敏感——**必须按运行时路径判定**，不能只靠常量。
///
/// 为什么不能写进 `DENY_EXACT`：`sqlite_path = <data_dir>/panel.db`（`paths.rs:31`），
/// 而 `[paths].data` 是**可配置项**。写死 `/var/lib/forkpanel/panel.db` 会在任何改过
/// data 目录的部署上失效，而且失效得无声无息（黑名单看起来还在）。
///
/// 收录理由同 `master.key`：覆盖它 = 会话、审计、加密凭据、LLM 配置全毁，
/// **面板即登录系统立刻不可登录**。
///
/// `db_path` 为 `None`（取不到运行时路径）时**一律判定为不敏感**：宁可漏挡一次也不
/// 误挡整个数据目录——漏挡的那次会在文件页被明确拒绝，误挡会让数据目录变成黑洞。
pub fn is_panel_db_path(s: &str, db_path: Option<&str>) -> bool {
    match db_path {
        Some(db) => !db.is_empty() && s == db,
        None => false,
    }
}

/// 按**字符串**判定敏感（平台无关，供 linux 与 mock 共用）。
///
/// 输入是文件路径的字符串形式（已 canonicalize 的形态由调用方保证）。
pub fn is_sensitive_path_str(s: &str) -> bool {
    if DENY_EXACT.contains(&s) {
        return true;
    }
    if DENY_PREFIX.iter().any(|x| s.starts_with(x)) {
        return true;
    }
    DENY_SUFFIX.iter().any(|x| s.ends_with(x))
}

#[cfg(test)]
mod tests {
    use super::is_sensitive_path_str as deny;

    /// 事故回归：`/etc/passwd` 必须在黑名单内。
    /// 这条断言的价值=再有人把账号文件放开时测试直接红。
    #[test]
    fn passwd_family_is_denied() {
        for p in [
            "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
            "/etc/passwd-", "/etc/shadow-", "/etc/sudoers",
        ] {
            assert!(deny(p), "必须拒绝: {p}");
        }
    }

    #[test]
    fn code_execution_vectors_are_denied() {
        for p in [
            "/etc/ld.so.preload",
            "/etc/crontab",
            "/etc/cron.d/evil",
            "/var/spool/cron/crontabs/root",
            "/etc/systemd/system/backdoor.service",
            "/etc/sudoers.d/all",
            "/etc/pam.d/common-auth",
            "/etc/profile.d/evil.sh",
            "/etc/init.d/evil",
            "/root/.ssh/authorized_keys",
            "/home/www/.ssh/authorized_keys",
            "/root/.ssh/id_rsa",
        ] {
            assert!(deny(p), "必须拒绝: {p}");
        }
    }

    /// 安装布局统一为 forkpanel 后缀后，黑名单必须保护**真实**目录，而不是历史遗留的
    /// `/etc/panel`（那个目录在按 install.sh 部署时根本不存在）。主密钥尤其关键：
    /// 它在数据目录 `/var/lib/forkpanel/master.key`，此前未被任何黑名单项覆盖。
    #[test]
    fn forkpanel_install_tree_and_master_key_are_denied() {
        // 安装树（config 目录整体拒绝，含任意子文件）
        assert!(deny("/etc/forkpanel/ssl/key.pem"));
        // 主密钥：数据目录里的面板根密钥
        assert!(deny("/var/lib/forkpanel/master.key"), "面板主密钥必须在黑名单内");
        // 反向：站点文件等日常路径仍可写
        assert!(!deny("/var/www/site/index.html"));
    }

    /// 反向：常见运维文件**必须可写**，否则文件管理器失去一大半用途。
    #[test]
    fn everyday_ops_files_are_allowed() {
        for p in [
            "/etc/hosts", "/etc/resolv.conf", "/etc/hostname",
            "/www/site/index.html", "/home/a/notes.txt",
            "/etc/nginx/nginx.conf",          // 站点配置由面板自己生成/编辑
            "/etc/crontab.bak",               // 不是 crontab 本体
            "/etc/passwdx",                   // 不是 passwd
            "/etc/sysctl.conf.bak",           // 备份不是本体（同 crontab.bak）
            "/root/.bashrc.bak",              // 备份不会被 shell 执行
            "/home/www/.bashrc",              // 非 root 用户自己的 rc：不构成提权
        ] {
            assert!(!deny(p), "不该拒绝: {p}");
        }
        // 既有语义：`/root/.ssh/` 整目录拒绝（不只是私钥）——历史行为，保持不变
        assert!(deny("/root/.ssh/config"));
    }

    /// 模糊匹配会误伤：前缀必须是完整路径段，不能命中 `/etc/cron*` 之类的无关文件。
    #[test]
    fn prefix_matching_is_path_aware() {
        assert!(deny("/etc/cron.d/job"));
        assert!(!deny("/etc/cronx"));        // 不是 /etc/cron.d/
        assert!(!deny("/etc/systemddir"));   // 不是 /etc/systemd/
        assert!(!deny("/etc/ufwx/rules"));    // 不是 /etc/ufw/
        assert!(!deny("/etc/fail2ban.conf")); // 不是 /etc/fail2ban/（目录前缀）
        assert!(!deny("/etc/modulesfoo"));    // 不是 /etc/modules（精确匹配）
    }

    /// 复盘 P0-1 补齐的缺口。收录标准见模块头：防火墙持久化（写坏=网络全锁）、
    /// fail2ban（action 以 root 执行）、内核参数与模块（core_pattern / modprobe
    /// install 可执行任意代码）、root 登录壳脚本、SSH 同名公私钥文件。
    #[test]
    fn firewall_kernel_and_root_shell_configs_are_denied() {
        for p in [
            // 防火墙持久化：重放时写坏 = 网络全锁
            "/etc/nftables.conf",
            "/etc/iptables/rules.v4",
            "/etc/iptables/rules.v6",
            "/etc/default/ufw",
            "/etc/ufw/ufw.conf",
            "/etc/ufw/user.rules",
            // TCP wrappers：一条规则拒掉全部登录
            "/etc/hosts.allow",
            "/etc/hosts.deny",
            // fail2ban：action.d 命令模板 / jail 内联 action 都以 root 执行
            "/etc/fail2ban/jail.local",
            "/etc/fail2ban/action.d/iptables-multiport.conf",
            "/etc/fail2ban/filter.d/sshd.conf",
            // 内核参数与模块加载
            "/etc/sysctl.conf",
            "/etc/sysctl.d/99-panel.conf",
            "/etc/modules",
            "/etc/modules-load.d/evil.conf",
            "/etc/modprobe.d/evil.conf",
            // AppArmor：enforce 档坏 = 依赖服务起不来
            "/etc/apparmor.d/usr.sbin.sshd",
            // root 的登录/交互壳脚本：bash 启动即执行
            "/root/.bashrc",
            "/root/.bash_profile",
            "/root/.bash_login",
            "/root/.profile",
            "/root/.bash_logout",
            // SSH 公私钥同名文件（旧式 authorized_keys2 + 默认私钥名补齐）
            "/root/.ssh/authorized_keys2",
            "/home/www/.ssh/authorized_keys2",
            "/root/.ssh/id_dsa",
            "/home/a/.ssh/id_ecdsa_sk",
            "/home/a/.ssh/id_ed25519_sk",
        ] {
            assert!(deny(p), "必须拒绝: {p}");
        }
    }

    /// 二轮审计 P0-3~5 补齐的三类缺口（此前只收了 /etc 下的同名物）。
    #[test]
    fn second_audit_gaps_are_denied() {
        // systemd 发行版单元目录：写 ExecStart= 即 root 执行任意代码
        for p in [
            "/usr/lib/systemd/system/evil.service",
            "/lib/systemd/system/evil.service",
            "/usr/lib/systemd/system/sshd.service",
        ] {
            assert!(deny(p), "必须拒绝: {p}");
        }
        // 挂载表：写坏 = 不可启动
        assert!(deny("/etc/fstab"));
        // 反向：不应误伤
        assert!(!deny("/etc/fstab.d/foo"));    // 不是 fstab 本体（同 crontab.bak 口径）
        assert!(!deny("/usr/lib/systemdxx"));   // 不是 /usr/lib/systemd/
    }

    /// 面板库本体：路径可配 ⇒ 只能按运行时值判定，且**只认这一个文件**。
    #[test]
    fn panel_db_is_denied_by_runtime_path() {
        use super::is_panel_db_path as is_db;
        assert!(is_db("/var/lib/forkpanel/panel.db", Some("/var/lib/forkpanel/panel.db")));
        // 自定义数据目录同样生效（写死常量做不到这一点）
        assert!(is_db("/opt/panel/data/panel.db", Some("/opt/panel/data/panel.db")));
        // 同目录的其它文件不受影响（数据目录里还有 trash / uploads / 备份产物）
        assert!(!is_db("/opt/panel/data/master.key", Some("/opt/panel/data/panel.db")));
        assert!(!is_db("/opt/panel/data/trash/x", Some("/opt/panel/data/panel.db")));
        // 只认这一个文件，不放宽成「整个数据目录都不可碰」
        assert!(!is_db("/opt/panel/data/panel.db-journal", Some("/opt/panel/data/panel.db")));
        // 取不到运行时路径时不误挡
        assert!(!is_db("/var/lib/forkpanel/panel.db", None));
        assert!(!is_db("/var/lib/forkpanel/panel.db", Some("")));
    }
}
