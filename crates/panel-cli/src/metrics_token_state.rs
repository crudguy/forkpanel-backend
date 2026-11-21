//! Prometheus scrape token 的**独立状态源**。
//!
//! 为什么不能只用 config.toml：`deploy/config.toml` 被 git 跟踪，dev / E2E 又直接
//! 拿它当运行配置。把静态 Bearer token 填进去，一次「全部提交」就会把凭据写进
//! 仓库历史（与 2026-11-16 公网 IP 事故同一类）。按 `public_ip_state` 的先例，
//! 新部署的 token 挪到不受版本控制的位置，优先级：
//!
//! 1. `PANEL_METRICS_TOKEN` 环境变量（systemd drop-in 最省事）；
//! 2. `<data_dir>/metrics.token` 文件（0600，一行明文）；
//! 3. `config.toml [metrics] scrape_token` —— **仅老部署只读回退**，永不回写。
//!
//! 本模块只有读取与「写独立文件」两条路，没有任何 config.toml 写入口（守卫钉死）。

use std::path::{Path, PathBuf};

use panel_core::{PanelError, Result};

/// 环境变量名。systemd drop-in 设置即可，无需碰被跟踪的 config.toml。
pub const ENV_VAR: &str = "PANEL_METRICS_TOKEN";

/// 状态文件名。`.token` 后缀便于 .gitignore 精确匹配。
pub const STATE_FILE: &str = "metrics.token";

pub fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATE_FILE)
}

/// 读独立状态文件；不存在、读失败、空白内容均视为未配置。
pub fn read_file(data_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(state_path(data_dir)).ok()?;
    let t = raw.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

/// 有效 token：环境变量 > 状态文件 > config 旧值（老部署平滑迁移）。
/// 三段都 trim + 空白过滤，避免 `scrape_token = " "` 这种"看着配了其实裸奔"。
pub fn effective(data_dir: &Path, legacy_config_token: Option<&str>) -> Option<String> {
    let clean = |s: &str| {
        let t = s.trim();
        if t.is_empty() { None } else { Some(t.to_string()) }
    };
    std::env::var(ENV_VAR).ok().as_deref().and_then(clean)
        .or_else(|| read_file(data_dir))
        .or_else(|| legacy_config_token.and_then(clean))
}

/// 原子写入 0600 到 data_dir 独立文件。**绝不写 config.toml**。
/// 临时名与目标名不同——同名会边读边写、产物无限增长（项目已踩过）。
pub fn write(data_dir: &Path, token: &str) -> Result<()> {
    let t = token.trim();
    if t.is_empty() {
        return Err(PanelError::Validation {
            field: "token",
            reason: "scrape token 不能为空".into(),
        });
    }
    std::fs::create_dir_all(data_dir)
        .map_err(|e| PanelError::Internal(format!("create data dir: {e}")))?;
    let target = state_path(data_dir);
    let tmp = data_dir.join(format!(".{STATE_FILE}.tmp"));
    panel_os::write_private(&tmp, format!("{t}\n").as_bytes(), 0o600)?;
    std::fs::rename(&tmp, &target)
        .map_err(|e| PanelError::Internal(format!("replace {}: {e}", target.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "panel-metrics-token-{}-{}-{tag}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_then_read_roundtrip_with_0600() {
        let d = tmp_dir("roundtrip");
        assert_eq!(read_file(&d), None);
        write(&d, " s3cr3t-token \n").unwrap();
        assert_eq!(read_file(&d).as_deref(), Some("s3cr3t-token"));
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(state_path(&d)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "token 必须是 0600，实际 {mode:o}");
        }
        assert!(!d.join(format!(".{STATE_FILE}.tmp")).exists(), "临时文件须被 rename 清掉");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_blank_token_without_writing() {
        let d = tmp_dir("blank");
        assert!(write(&d, "   ").is_err(), "空白 token 必须拒绝");
        assert!(!state_path(&d).exists(), "拒绝时不得落盘");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn effective_prefers_state_file_over_legacy_config() {
        std::env::remove_var(ENV_VAR);
        let d = tmp_dir("effective");
        assert_eq!(
            effective(&d, Some("legacy-token")).as_deref(),
            Some("legacy-token"),
            "老部署状态文件未生成时用 config 旧值兜底"
        );
        write(&d, "file-token").unwrap();
        assert_eq!(
            effective(&d, Some("legacy-token")).as_deref(),
            Some("file-token"),
            "状态文件一旦存在即以它为准（且永不回写 config）"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn blank_inputs_never_enable_metrics() {
        std::env::remove_var(ENV_VAR);
        let d = tmp_dir("blank-input");
        assert_eq!(effective(&d, Some("   ")), None, "空白 config 值不得算配了");
        std::fs::write(state_path(&d), "  \n").unwrap();
        assert_eq!(effective(&d, None), None, "空白状态文件不得算配了");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// ⭐ 源码守卫：环境变量优先级必须真接线，且绝不写回被 git 跟踪的 config。
    #[test]
    fn token_source_never_writes_tracked_config() {
        let src = panel_testutil::production_source(include_str!("metrics_token_state.rs"));
        assert!(src.contains("std::env::var(ENV_VAR)"), "环境变量优先级必须接线");
        assert!(src.contains("data_dir.join(STATE_FILE)"), "状态文件须落在 data_dir");
        assert!(!src.contains("write_config_key"), "绝不能写回 config.toml（被 git 跟踪）");
        assert!(!src.contains("config.toml"), "生产代码不得包含 config.toml 写入目标");
    }
}
