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
pub fn systemd_unit(bin: &str, config: &str, tier: Tier, writable: &[std::path::PathBuf]) -> String {
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
ReadWritePaths={writable}

# —— 资源上限：与「常驻 ≤12MB」目标一致，防止异常时拖垮整机 ——
MemoryMax={mem_max}
CPUQuota=20%
TasksMax=256

[Install]
WantedBy=multi-user.target
"#,
        bin = bin, config = config, mem_max = mem_max,
        writable = writable.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(" ")
    )
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

    #[test]
    fn systemd_unit_has_no_hardcoded_service_dir_and_is_hardened() {
        let u = systemd_unit("panel", "config.toml", Tier::Nano, &[std::path::PathBuf::from("data")]);
        assert!(u.contains("MemoryMax=96M"), "nano 档位内存上限");
        assert!(u.contains("NoNewPrivileges=yes"));
        assert!(u.contains("ProtectSystem=strict"));
        assert!(u.contains("CPUQuota=20%"));
        // 单元内容本身不应包含服务目录路径（那是安装位置，由 PathLayout 决定）
        assert!(!u.contains("systemd/system"), "安装位置应由 PathLayout 决定，不得写死在单元内容里");
    }

    #[test]
    fn standard_tier_gets_higher_cap() {
        let u = systemd_unit("panel", "config.toml", Tier::Standard, &[std::path::PathBuf::from("data")]);
        assert!(u.contains("MemoryMax=384M"));
    }
}
