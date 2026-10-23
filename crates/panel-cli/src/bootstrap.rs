//! 首次初始化：主密钥、owner 账号、目录权限、引导令牌。
//!
//! # 主密钥与秘密加密（M0 阻塞项已关闭）
//! 主密钥（`master.key`，0600）在 `init`/`serve` 阶段生成并加载进内存，
//! 用于 AES-256-GCM 加密 SSL 私钥与数据库口令（见 `panel_core::crypto::MasterKey`）。
//! 无主密钥时，任何"写入真实秘密"的操作被拒绝（降级关闭，绝不明文入库）。
//! schema 中的 `key_enc` / `password_enc` 字段由对应 handler 填充。

use panel_core::{PanelError, Result, Tier};
use panel_os::{fs, PathLayout};
use std::path::{Path, PathBuf};

/// 主密钥长度（32 字节）。仅用于后续 AES-256-GCM 的密钥派生。
pub const MASTER_KEY_LEN: usize = 32;

pub fn master_key_path(data_dir: &Path) -> PathBuf { data_dir.join("master.key") }

/// 生成主密钥并写入 0600 文件。
pub fn ensure_master_key(data_dir: &Path) -> Result<Vec<u8>> {
    let p = master_key_path(data_dir);
    if p.exists() {
        return std::fs::read(&p).map_err(|e| PanelError::Internal(format!("read master key: {e}")));
    }
    let mut k = vec![0u8; MASTER_KEY_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
    fs::write_private(&p, &k, 0o600)?;
    Ok(k)
}

/// 目录初始化：数据目录 0700、日志目录 0750、脚本目录 0750
pub fn ensure_dirs(layout: &dyn PathLayout) -> Result<()> {
    for (dir, mode) in [
        (layout.data_dir(), 0o700),
        (layout.log_dir(), 0o750),
        (layout.cache_dir(), 0o700),
        (layout.tmp_dir(), 0o700),
        (layout.script_dir(), 0o750),
        (layout.backup_dir(), 0o700),
    ] {
        fs::ensure_dir(&dir, mode)?;
    }
    Ok(())
}

// 引导令牌已迁移至 `panel_api::auth`（generate_bootstrap_token / BootstrapGuard）：
// 令牌由 serve 注入 AppState、由 /api/v1/auth/bootstrap 消费，生命周期归 panel-api 管。

/// 从终端读取口令（关回显）。平台差异由 `panel_os::fs` 处理。
pub fn read_password(prompt: &str) -> Result<String> { fs::read_password(prompt) }

/// 生成 systemd 单元文件内容。
///
/// 刻意使用 `PathLayout::service_dir()` 决定安装位置，可写目录由调用方传入。
/// 安全相关的硬化项都是 systemd 的原生能力，比自己实现更可靠。
///
/// `optional_writable`：**允许不存在**的可写目录，一律带 `-` 前缀下发。
/// systemd 对无前缀的缺失路径直接让单元 226/NAMESPACE 起不来（无法 reopen
/// 一个不存在的目录），所以「没装 nginx/caddy 的机器」与「装了的机器」
/// 必须共用同一份单元文本，差别只在 systemd 侧忽略缺失项。
pub fn systemd_unit(bin: &str, config: &str, tier: Tier, writable: &[std::path::PathBuf],
                    optional_writable: &[std::path::PathBuf]) -> String {
    let mem_max = match tier {
        Tier::Nano => "96M",
        Tier::Small => "192M",
        Tier::Standard => "384M",
    };
    format!(
        r#"[Unit]
Description=Lightweight server management panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} --config {config} serve
Restart=on-failure
RestartSec=3

# —— 硬化：面板确实需要 root（要管理服务/防火墙），但只给它必需的权限 ——
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
# 数据/日志/站点目录需要可写，其余只读（由 PathLayout 提供，非硬编码）
# 可选档（web 服务器 conf drop-in）带 - 前缀：不存在时 systemd 忽略而非拒绝启动
ReadWritePaths={writable}

# —— 资源上限：与「常驻 ≤12MB」目标一致，防止异常时拖垮整机 ——
MemoryMax={mem_max}
CPUQuota=20%
TasksMax=256

[Install]
WantedBy=multi-user.target
"#,
        bin = bin, config = config, mem_max = mem_max,
        writable = {
            let mut v: Vec<String> = writable.iter().map(|p| p.display().to_string()).collect();
            v.extend(optional_writable.iter().map(|p| format!("-{}", p.display())));
            v.join(" ")
        }
    )
}

/// 从路径布局推导 systemd 单元的放行目录，返回 `(必填, 可选)` 两档。
///
/// - **必填**：数据 / 日志 / 站点 / 配置四目录——面板自身的立足点，缺一个就
///   起不来或丢数据。无 `-` 前缀：缺了就该让单元红，而不是 silent 半残运行。
/// - **可选**：web 服务器 conf drop-in（nginx `conf.d` / caddy `sites`）——
///   站点部署时**直写**的 /etc 落点（`LinuxWebServer::deploy`）。不放行它们，
///   `ProtectSystem=strict` 下官方单元部署后建站必然 EROFS；但它们可能不存在
///   （没装 web 服务器）⇒ 带 `-` 前缀，systemd 忽略缺失项。
///
/// 收敛成函数而不是在 main.rs 里拼 vec：「单元到底放行了哪些目录」需要一条
/// 回归测试盯着，且调用方（CLI 与测试）必须同源。
pub fn writable_dirs(layout: &dyn panel_os::PathLayout)
    -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    let required = vec![
        layout.data_dir(),
        layout.log_dir(),
        layout.site_root(),
        layout.config_dir(),
    ];
    let optional = vec![
        layout.web_conf_dir(),
        layout.caddy_sites_dir(),
    ];
    (required, optional)
}

/// 生成外部探活脚本内容（`sh`，放 `PathLayout::script_dir()`）。
///
/// **为什么需要它**：`Restart=on-failure` 只覆盖「进程死了」，**不覆盖**
/// 「进程活着但不服务」——事件循环被某个请求卡死、监听 socket 丢失但主线程没退，
/// 这类故障 systemd 从外部看不出来，服务会一直挂着直到有人登上服务器才发现。
///
/// 判定用 `/api/v1/version`（免登录 GET，语义 = "服务还能不能回话"）。
/// 刻意**不用** `/healthz`：那个在 embed 层，进程活着就一定 200，探不到
/// "HTTP 服务已死但主线程还在"——正是要抓的那类故障。
///
/// **连续两次失败才重启**（用 marker 文件记状态）：单次失败多为瞬时抖动
/// （重启窗口、CPU 饱和、探活自身超时），误把好服务重启掉的代价高于漏一次报。
/// 恢复成功即清除 marker，不会把一分钟前的失败记成连续失败。
pub fn healthcheck_script(service_name: &str, port: u16) -> String {
    // shebang 独立成行：`ci-allow-layering[2]` 的行内豁免必须落在**含 `/bin/sh`
    // 的那一行**上，而它写在多行原始字符串里会污染生成的脚本内容。故拆出来单写。
    let shebang = "#!/bin/sh"; // ci-allow-layering[2]: 生成的是探活脚本文本，交给 systemd oneshot 执行；面板自身不解释 shell，与 scheduler.rs 生成 crontab 命令文本同性质
    format!(
        r#"{shebang}
# ForkPanel 外部探活：HTTP 200 才算活；连续两次失败才重启面板。
# 由 panel-healthcheck.timer 每分钟触发。也可手动执行自检。
set -u

SVC="{service_name}"
URL="http://127.0.0.1:{port}/api/v1/version"
MARKER="/tmp/.panel-healthcheck-${{SVC}}.fail"

if curl -fsS -o /dev/null --max-time 10 "$URL" 2>/dev/null; then
  # 恢复：清掉上一次的失败标记，避免把间隔很久的两次失败当成连续失败
  rm -f "$MARKER"
  exit 0
fi

# 第一次失败：只记录并退出（不重启）——给瞬时抖动留机会
if [ ! -f "$MARKER" ]; then
  touch "$MARKER"
  echo "$(date -Is) probe failed once, waiting for next run" >&2
  exit 1
fi

# 第二次连续失败：重启面板，并清标记（若重启后仍失败，下一轮再从"第一次"计起，
# 形成重试节奏，而不是每分钟都无条件重启）
echo "$(date -Is) probe failed twice in a row, restarting $SVC" >&2
rm -f "$MARKER"
systemctl restart "$SVC" || true
exit 1
"#,
        port = port, service_name = service_name, shebang = shebang
    )
}

/// 生成探活的 systemd service + timer 单元内容。
///
/// 端口与脚本路径由调用方传入（从 `Config` / `PathLayout` 读出），与
/// [`systemd_unit`] 同纪律：不硬编码。`script_dir` 不存在时 systemd 会报
/// "executable path is not absolute"，故安装前必须确保目录已建。
pub fn healthcheck_units(service_name: &str, script: &std::path::Path) -> (String, String) {
    let hc_service = format!(
        r#"[Unit]
Description=ForkPanel liveness probe (restarts panel if it stops answering)
After=network-online.target {service_name}.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={script}
# 探活脚本自己决定是否重启（连续两次失败），故这里绝不 Restart：
# 若设了 Restart=on-failure，一次瞬时失败就会被 systemd 反复重跑，
# 与脚本内的"两次才重启"叠加成更激进的策略。
Restart=no

[Install]
WantedBy=multi-user.target
"#,
        service_name = service_name, script = script.display()
    );

    let hc_timer = format!(
        r#"[Unit]
Description=Run ForkPanel liveness probe every minute

[Timer]
# 距上次激活 60s 后触发（而非 OnCalendar：面板刚重启过的那一分钟不必立刻再探）
OnUnitActiveSec=60
AccuracySec=15s
# 错过的时间不补跑：机器休眠/重启后不会积一堆探活排队执行
Persistent=false
Unit={service_name}-healthcheck.service

[Install]
WantedBy=timers.target
"#,
        service_name = service_name
    );

    (hc_service, hc_timer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_is_32_bytes_and_0600() {
        let d = std::env::temp_dir().join(format!("panel-bootstrap-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = master_key_path(&d);
        let _ = std::fs::remove_file(&p);
        let k = ensure_master_key(&d).unwrap();
        assert_eq!(k.len(), MASTER_KEY_LEN);
        // 二次调用读取已有密钥，不重新生成
        let k2 = ensure_master_key(&d).unwrap();
        assert_eq!(k, k2);
        if let Some(m) = fs::mode_of(&p) {
            assert_eq!(m & 0o777, 0o600, "主密钥必须 0600");
        }
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn bootstrap_token_is_hex_and_unique() {
        // 令牌生成已迁移至 panel_api::auth（含一次性/过期行为测试），此处仅确认再导出可用
        let a = panel_api::auth::generate_bootstrap_token();
        let b = panel_api::auth::generate_bootstrap_token();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    // ── 外部探活：堵住 Restart=on-failure 覆盖不到的"活着但不服务" ──

    #[test]
    fn healthcheck_script_probes_version_not_healthz() {
        let sh = healthcheck_script("panel", 2083);
        // 判定必须打 /api/v1/version：/healthz 在 embed 层，进程活着就恒 200，
        // 探不到"HTTP 服务已死但主线程还在"——那正是要抓的故障。
        assert!(sh.contains("/api/v1/version"), "必须探 API 而非 embed 静态路由：{sh}");
        assert!(!sh.contains("/healthz"), "/healthz 探不到要抓的故障，不应作为判据：{sh}");
        // 端口来自 Config，不硬编码
        assert!(sh.contains("127.0.0.1:2083"), "端口应来自调用方：{sh}");
    }

    #[test]
    fn healthcheck_script_requires_two_consecutive_failures_before_restart() {
        let sh = healthcheck_script("panel", 2083);
        // marker 机制：第一次失败只 touch 不重启，第二次才 restart。
        // 少了这层，一次瞬时抖动就会把好服务重启掉（误报代价高于漏报）。
        assert!(sh.contains("touch \"$MARKER\""), "第一次失败只记录：{sh}");
        assert!(sh.contains("systemctl restart \"$SVC\""), "第二次连续失败才重启：{sh}");
        // 恢复时必须清 marker，否则间隔很久的两次失败会被误判为连续失败
        assert!(sh.contains("rm -f \"$MARKER\""), "恢复后须清除失败标记：{sh}");
    }

    #[test]
    fn healthcheck_units_have_no_restart_and_fire_every_minute() {
        let (svc, timer) = healthcheck_units("panel", std::path::Path::new("/var/lib/forkpanel/scripts/healthcheck.sh"));
        // service 绝不能 Restart：脚本自己实现"两次才重启"，systemd 再叠一层
        // 会把策略变得更激进（一次失败就反复重跑）。
        assert!(svc.contains("Restart=no"), "探活 service 不得自行重试：{svc}");
        assert!(svc.contains("ExecStart=/var/lib/forkpanel/scripts/healthcheck.sh"), "脚本路径由调用方给：{svc}");
        assert!(timer.contains("OnUnitActiveSec=60"), "每分钟探一次：{timer}");
        assert!(timer.contains("Unit=panel-healthcheck.service"), "timer 必须指向探活 service：{timer}");
        // 错过的探活不补跑，否则机器休眠后会在开机时堆积执行
        assert!(timer.contains("Persistent=false"), "错过的探活不应补跑：{timer}");
    }

    #[test]
    fn systemd_unit_has_no_hardcoded_service_dir_and_is_hardened() {
        let u = systemd_unit("panel", "config.toml", Tier::Nano, &[std::path::PathBuf::from("data")], &[]);
        assert!(u.contains("MemoryMax=96M"), "nano 档位内存上限");
        assert!(u.contains("NoNewPrivileges=yes"));
        assert!(u.contains("ProtectSystem=strict"));
        assert!(u.contains("CPUQuota=20%"));
        // 单元内容本身不应包含服务目录路径（那是安装位置，由 PathLayout 决定）
        assert!(!u.contains("systemd/system"), "安装位置应由 PathLayout 决定，不得写死在单元内容里");
    }

    #[test]
    fn standard_tier_gets_higher_cap() {
        let u = systemd_unit("panel", "config.toml", Tier::Standard, &[std::path::PathBuf::from("data")], &[]);
        assert!(u.contains("MemoryMax=384M"));
    }

    /// 回归：ReadWritePaths 必须逐字反映调用方传入的可写目录（来自配置感知的
    /// PathLayout），不得写死默认值。历史上 Cmd::SystemdUnit 用 `os.paths()`
    /// 默认布局构造 writable，而 ExecStart 指向用户自定义的 --config ⇒ 一旦
    /// config.toml 覆盖了 [paths]，ProtectSystem=strict 下面板写不进真实
    /// 数据/日志/站点目录 ⇒ 起不来或丢数据。
    #[test]
    fn read_write_paths_track_configured_layout() {
        let custom = vec![
            std::path::PathBuf::from("/srv/fp/data"),
            std::path::PathBuf::from("/srv/fp/log"),
            std::path::PathBuf::from("/srv/fp/www"),
            std::path::PathBuf::from("/srv/fp/conf"),
        ];
        let u = systemd_unit("panel", "/srv/fp/conf/config.toml", Tier::Small, &custom, &[]);
        let line = u.lines().find(|l| l.starts_with("ReadWritePaths=")).unwrap();
        assert_eq!(
            line,
            "ReadWritePaths=/srv/fp/data /srv/fp/log /srv/fp/www /srv/fp/conf",
            "ReadWritePaths 必须与配置 [paths] 一致，不能回落默认 /var/lib/forkpanel 等"
        );
        assert!(u.contains("ExecStart=panel --config /srv/fp/conf/config.toml serve"));
    }

    /// 回归：可选档必须带 `-` 前缀。systemd 对**无前缀的缺失路径**直接让单元
    /// 226/NAMESPACE 起不来——没装 nginx/caddy 的机器上漏了前缀就是起不来。
    #[test]
    fn optional_writable_paths_use_dash_prefix() {
        let u = systemd_unit("panel", "config.toml", Tier::Nano,
                             &[std::path::PathBuf::from("/srv/fp/data")],
                             &[std::path::PathBuf::from("/etc/nginx/conf.d")]);
        let line = u.lines().find(|l| l.starts_with("ReadWritePaths=")).unwrap();
        assert_eq!(line, "ReadWritePaths=/srv/fp/data -/etc/nginx/conf.d");
    }

    /// 回归：站点 conf 的 /etc 落点必须进 ReadWritePaths（可选档）。
    /// 少了它，`ProtectSystem=strict` 下官方单元部署后建站必然 EROFS——
    /// `LinuxWebServer::deploy` 直写 web_conf_dir / caddy_sites_dir，
    /// 而单元只放行数据/日志/站点/配置四目录（自 16826ae 起冲突至今）。
    #[test]
    fn writable_dirs_cover_web_conf_drop_in_dirs() {
        use panel_os::PathLayout as _;
        let layout = panel_os::paths::LinuxPathLayout::default();
        let (required, optional) = writable_dirs(&layout);
        assert_eq!(required, vec![layout.data_dir(), layout.log_dir(),
                                   layout.site_root(), layout.config_dir()],
                   "必填四目录保持原状");
        assert!(optional.contains(&layout.web_conf_dir()), "nginx conf.d 必须放行");
        assert!(optional.contains(&layout.caddy_sites_dir()), "caddy sites 必须放行");
        // 组合生成一遍：六条目、四必填两可选、顺序稳定
        let u = systemd_unit("panel", "config.toml", Tier::Small, &required, &optional);
        let line = u.lines().find(|l| l.starts_with("ReadWritePaths=")).unwrap();
        let expect = format!(
            "ReadWritePaths={} {} {} {} -{} -{}",
            layout.data_dir().display(), layout.log_dir().display(),
            layout.site_root().display(), layout.config_dir().display(),
            layout.web_conf_dir().display(), layout.caddy_sites_dir().display(),
        );
        assert_eq!(line, expect);
    }
}
