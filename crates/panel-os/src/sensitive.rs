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
//! 定时任务、systemd 单元、init 脚本。
//!
//! 反过来说，**不进**黑名单的也要有理由：`/etc/hosts`、`/etc/resolv.conf`、
//! `/etc/hostname` 属于常见运维改动且坏了可恢复，保留可写。
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
    // systemd：单元文件可直接指定 ExecStart 为任意命令
    "/etc/systemd/", "/run/systemd/",
    // init / 启动脚本
    "/etc/init.d/", "/etc/init/", "/etc/rcS.d/", "/etc/rc.local",
    // 动态链接器配置目录（主配置在精确表）
    "/etc/ld.so.conf.d/",
    // 登录脚本目录
    "/etc/profile.d/",
    // 资源限制与安全策略（可让 root 进程被内核杀掉 / 提权）
    "/etc/security/",
];

/// 后缀匹配（任何用户下的同名文件）
const DENY_SUFFIX: &[&str] = &[
    "/authorized_keys",
    "/.ssh/id_rsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519", "/.ssh/identity",
];

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
    }
}
