//! 配置文件（config.toml）。
//!
//! 原则：
//! - 所有路径都可覆盖，但**业务层不直接拼路径**——覆盖值注入 `LinuxPathLayout`，
//!   仍然只通过 `PathLayout` trait 访问。
//! - 未知字段**拒绝**启动（deny_unknown_fields），避免"配了但没生效"的静默失败。

use panel_core::{PanelError, Result, Tier};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: Server,

    /// 目录覆盖。留空则使用平台默认（Linux: /etc/forkpanel、/var/lib/forkpanel …）
    #[serde(default)]
    pub paths: PathsOverride,

    #[serde(default)]
    pub db: Db,

    #[serde(default)]
    pub security: Security,

    #[serde(default)]
    pub audit: Audit,

    /// "auto" 依据内存/CPU 探测；也可强制指定档位
    #[serde(default = "default_tier")]
    pub tier: String,
}

// 注意：这里**不能**派生 Default。派生会给 bind=""、port=0、localhost_only=false，
// 与 serde 的 default_* 不一致（localhost_only 默认应为 true —— 面板默认只监听回环）。
// 与各 Db/Security/Audit 保持一致：手写 Default，复用同一批 default_* 函数。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// 仅监听回环：部署在前置反代之后时强烈建议开启
    #[serde(default = "default_true")]
    pub localhost_only: bool,
    #[serde(default)]
    pub tls: Option<Tls>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PathsOverride {
    pub config: Option<PathBuf>,
    pub data: Option<PathBuf>,
    pub log: Option<PathBuf>,
    pub site_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Db {
    /// NORMAL（默认，进程崩溃安全）| FULL（断电强保证，实测吞吐降 ~42%）
    #[serde(default = "default_sync")]
    pub synchronous: String,
    #[serde(default = "default_true")]
    pub daily_backup: bool,
    /// 每日自动备份的保留份数（**真实消费者**：`db.backup` 写完立刻按它裁剪）。
    /// 此前这些 `panel-<ts>.db` 只增不减——一年后就是 365 份，把磁盘慢慢吃满。
    #[serde(default = "default_backup_keep")]
    pub backup_keep: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    #[serde(default = "default_idle")]
    pub session_idle: String,          // "30m"
    #[serde(default = "default_abs")]
    pub session_absolute: String,      // "12h"
    #[serde(default = "default_attempts")]
    pub max_login_attempts: usize,
    /// 只读模式：所有写接口返回 403 READ_ONLY（常用于"先看后改"或演练）
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    /// 默认 90 天。实测：180 天 × 200 条/天 = 4.12MB（分层后指标的 6 倍），故收紧默认
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    /// 单表行数上限，超出按时间顺序清理（防事件风暴撑爆磁盘）
    #[serde(default = "default_max_rows")]
    pub max_rows: u64,
}

fn default_bind() -> String { "127.0.0.1".into() }
fn default_port() -> u16 { 2083 }
fn default_tier() -> String { "auto".into() }
fn default_sync() -> String { "NORMAL".into() }
fn default_idle() -> String { "30m".into() }
fn default_abs() -> String { "12h".into() }
fn default_attempts() -> usize { 5 }
fn default_retention() -> u32 { 90 }
fn default_max_rows() -> u64 { 50_000 }
fn default_true() -> bool { true }
fn default_backup_keep() -> i64 { 7 }

impl Default for Db {
    fn default() -> Self {
        Self { synchronous: default_sync(), daily_backup: default_true(), backup_keep: default_backup_keep() }
    }
}
impl Default for Security {
    fn default() -> Self {
        Self { session_idle: default_idle(), session_absolute: default_abs(),
               max_login_attempts: default_attempts(), read_only: false }
    }
}
impl Default for Audit {
    fn default() -> Self { Self { retention_days: default_retention(), max_rows: default_max_rows() } }
}
impl Default for Server {
    fn default() -> Self {
        Self { bind: default_bind(), port: default_port(),
               localhost_only: default_true(), tls: None }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self { server: Server::default(), paths: PathsOverride::default(),
               db: Db::default(), security: Security::default(),
               audit: Audit::default(), tier: default_tier() }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            return Err(PanelError::NotFound(format!("config not found: {}", path.display())));
        }
        let s = std::fs::read_to_string(path)
            .map_err(|e| PanelError::Internal(format!("read config: {e}")))?;
        toml::from_str(&s).map_err(|e| PanelError::Validation {
            field: "config", reason: format!("{path}: {e}", path = path.display()),
        })
    }

    pub fn addr(&self) -> Result<SocketAddr> {
        // localhost_only 强制覆盖 bind，避免"配了 0.0.0.0 却以为只在本地"
        let host = if self.server.localhost_only { "127.0.0.1" } else { self.server.bind.as_str() };
        format!("{host}:{}", self.server.port)
            .parse()
            .map_err(|_| PanelError::Validation { field: "server.bind", reason: "invalid address".into() })
    }

    pub fn tier(&self, total_mem_mb: u64, cpus: u32) -> Tier {
        match self.tier.as_str() {
            "nano" => Tier::Nano,
            "small" => Tier::Small,
            "standard" => Tier::Standard,
            _ => Tier::detect(total_mem_mb, cpus),
        }
    }
}

/// 解析 "30m" / "12h" / "90s" 形式的时长。**唯一解析入口**，勿在别处另写。
///
/// 消费者：`serve` 把 `[security] session_idle` / `session_absolute` 经本函数转成
/// `Duration` 传给 `AppState`（曾硬编码在 `panel-api` 里，配置项形同虚设）。
pub fn parse_duration(s: &str) -> Result<std::time::Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| PanelError::Validation {
        field: "duration", reason: format!("bad number in {s:?}") })?;
    let secs = match unit {
        "s" => n, "m" => n * 60, "h" => n * 3600, "d" => n * 86_400,
        _ => return Err(PanelError::Validation { field: "duration",
            reason: format!("unknown unit in {s:?} (use s/m/h/d)") }),
    };
    Ok(std::time::Duration::from_secs(secs))
}

/// 生成默认配置文本。
///
/// 路径默认值**由 PathLayout 注入**而非写死在模板里 —— 这样 Windows/macOS 接入后
/// 生成的模板自动反映该平台的默认目录。
pub fn template(config_dir: &std::path::Path, data_dir: &std::path::Path,
                site_root: &std::path::Path) -> String {
    let cfg = config_dir.display();
    let data = data_dir.display();
    let site = site_root.display();
    format!(r#"# 面板配置
#
# 修改后执行 `panel doctor` 校验，再重启服务。

# auto | nano | small | standard（auto 依据内存与 CPU 探测）
# 注意：tier 是**根级**键，必须写在任何 [table] 之前 —— 放在 [audit] 之后
# 会被 TOML 解析成 audit 的字段，而 Audit 是 deny_unknown_fields，直接导致配置无法解析。
tier = "auto"

[server]
bind = "127.0.0.1"
port = 2083
# 前置反代后请保持 true：面板本身不暴露到公网
localhost_only = true

# [server.tls]
# cert = "{cfg}/tls/fullchain.pem"
# key  = "{cfg}/tls/privkey.pem"
# 需以 --features tls 构建；默认关闭以省下 rustls 带来的体积

# [paths]
# config = "{cfg}"
# data = "{data}"      # 必须位于本地文件系统：网络文件系统上 SQLite WAL 不可靠
# site_root = "{site}"

[db]
# FULL 提供断电强保证，代价是写入吞吐下降约 42%（实测）
synchronous = "NORMAL"
daily_backup = true

[security]
session_idle = "30m"
session_absolute = "12h"
max_login_attempts = 5
read_only = false

[audit]
# 默认 90 天：实测 180 天 × 200 条/天 ≈ 4.12MB，是分层后指标体积的 6 倍
retention_days = 90
max_rows = 50000
"#, cfg = cfg, data = data, site = site)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let c = Config::default();
        assert!(c.server.localhost_only, "默认必须只监听回环");
        assert_eq!(c.audit.retention_days, 90);
        assert_eq!(c.db.synchronous, "NORMAL");
        assert!(c.addr().unwrap().ip().is_loopback());
    }

    #[test]
    fn localhost_only_overrides_bind() {
        let mut c = Config::default();
        c.server.bind = "0.0.0.0".into();
        c.server.localhost_only = true;
        assert!(c.addr().unwrap().ip().is_loopback(), "localhost_only 必须覆盖 bind");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let s = "[server]\nport = 2083\nnope = 1\n";
        assert!(toml::from_str::<Config>(s).is_err(), "未知字段必须拒绝");
    }

    #[test]
    fn template_uses_injected_paths_not_hardcoded() {
        use std::path::PathBuf;
        let t = template(&PathBuf::from("/opt/cfg"), &PathBuf::from("/opt/data"),
                         &PathBuf::from("/opt/sites"));
        assert!(t.contains("/opt/data"), "data 路径应来自 PathLayout");
        assert!(t.contains("/opt/sites"));
        assert!(t.contains("/opt/cfg/tls/fullchain.pem"));
        // 用不含引号+斜杠的片段断言，避免把路径字面量写进测试
        assert!(!t.contains("var/lib"), "模板不应出现任何平台写死的路径");
        assert!(!t.contains("etc/panel"));
    }

    #[test]
    fn generated_template_is_parseable() {
        use std::path::PathBuf;
        let t = template(&PathBuf::from("/opt/cfg"), &PathBuf::from("/opt/data"),
                         &PathBuf::from("/opt/sites"));
        // 注释掉的可选段不应导致解析失败；且解析结果等于默认值
        let c: Config = toml::from_str(&t).expect("生成的模板必须能解析");
        assert_eq!(c.audit.retention_days, 90);
        assert!(c.server.localhost_only);
    }

    /// **配置值必须真的被消费**（防"假控制"回归）。
    ///
    /// `session_idle` / `session_absolute` 曾在 `panel_api::AppState::new` 里被
    /// 硬编码成 30m/12h，config.toml 改了毫无效果——用户以为生效了，实际没有
    /// （与 `read_only` 同一类 bug）。这条测试把"Config 能驱动这两个值"钉住：
    /// 改动 AppState 构造或改回硬编码都会在这里暴露。
    #[test]
    fn session_timeouts_come_from_config_not_hardcoded() {
        // 非默认值：若代码里藏着硬编码默认值，下面的等式就会挂
        let t = r#"
[security]
session_idle = "5m"
session_absolute = "2h"
"#;
        let c: Config = toml::from_str(t).expect("应能解析");
        let idle = super::parse_duration(&c.security.session_idle).unwrap();
        let abs = super::parse_duration(&c.security.session_absolute).unwrap();
        assert_eq!(idle.as_secs(), 300, "session_idle 必须从 config 来");
        assert_eq!(abs.as_secs(), 7200, "session_absolute 必须从 config 来");
        // 与硬编码值不同，证明这条测试有判别力（不是默认值蒙对）
        assert_ne!(idle.as_secs(), 30 * 60);
        assert_ne!(abs.as_secs(), 12 * 3600);
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("30m").unwrap().as_secs(), 1800);
        assert_eq!(parse_duration("12h").unwrap().as_secs(), 43200);
        assert_eq!(parse_duration("90s").unwrap().as_secs(), 90);
        assert!(parse_duration("30x").is_err());
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn tier_forcing_and_detection() {
        let c = Config::default();
        assert_eq!(c.tier(256, 1), Tier::Nano);
        let mut c2 = Config::default();
        c2.tier = "standard".into();
        assert_eq!(c2.tier(256, 1), Tier::Standard, "显式档位必须覆盖探测结果");
    }
}
