//! 公网出口 IP 的**独立状态文件**（运行期唯一写入目标）。
//!
//! 为什么不写 config.toml：配置文件在建仓库里是 `deploy/config.toml`，被 git 跟踪，
//! 而 IP 是**部署者所在网络的实际出口地址**（可能是真实服务器 IP）。dev 与 E2E
//! 直接拿它当运行配置，`panel init` / 「核准 IP」一探测就写回去，工作区立刻变脏，
//! 一旦「全部提交」就会把真实 IP 提交进仓库历史（2026-11-16 已发生过一次）。
//! 故把展示性事实挪到数据目录的独立状态文件——数据与配置分离，目录本就不入库。
//!
//! 兼容性：`Config.info.public_ip` 字段仍保留并校验，仅作为**老部署的只读回退源**。
//! 新写入一律走本模块，serve 读取时状态文件优先、config 旧值兜底，平滑迁移。
//! 校验复用 [`panel_core::public_ip::parse_public_ip`] 唯一入口，不另写第二套判据。

use std::path::{Path, PathBuf};

use panel_core::{PanelError, Result};

/// 状态文件名。带 `.state` 后缀以防与常见配置名撞车，也便于 `.gitignore` 精确匹配。
pub const STATE_FILE: &str = "public-ip.state";

/// 状态文件路径：`data_dir/public-ip.state`。目录由 `PathLayout` 提供，
/// 业务层不出现任何 OS 路径字面量。
pub fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATE_FILE)
}

/// 读取状态文件中的公网 IP。文件不存在、读失败或内容非法都返回 `None`——
/// 这是可选展示信息，任何异常都不该让 overview / 设置页报错。
pub fn read(data_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(state_path(data_dir)).ok()?;
    panel_core::public_ip::parse_public_ip(&raw).map(|ip| ip.to_string())
}

/// 启动时的**有效 IP**：独立状态文件优先，config.toml `[info]` 旧值兜底。
/// 抽成纯函数以便钉住迁移语义——老部署升级后状态文件尚未生成，不能把
/// config 里原有的 IP 丢掉；但一旦状态文件存在，就以它为准，永远不回写 config。
pub fn effective(data_dir: &Path, legacy_config_ip: Option<String>) -> Option<String> {
    read(data_dir).or(legacy_config_ip)
}

/// 原子写入公网 IP 到状态文件：先校验合法，再写临时文件 + rename。
///
/// - 临时名带独立 `.<file>.tmp` 前缀，**不与目标同名**（同名会边读边写、产物无限增长）；
/// - 权限收敛到 0600（IP 虽非密钥，但属部署事实，不就该 world-readable）；
/// - 写失败时原状态文件保持不动（rename 的原子性）。
pub fn write(data_dir: &Path, ip: &str) -> Result<()> {
    let parsed = panel_core::public_ip::parse_public_ip(ip).ok_or_else(|| PanelError::Validation {
        field: "public_ip",
        reason: format!("{ip:?} 不是合法 IP 地址"),
    })?;
    std::fs::create_dir_all(data_dir)
        .map_err(|e| PanelError::Internal(format!("create data dir: {e}")))?;
    let target = state_path(data_dir);
    let tmp = data_dir.join(format!(".{STATE_FILE}.tmp"));
    panel_os::write_private(&tmp, format!("{parsed}\n").as_bytes(), 0o600)?;
    std::fs::rename(&tmp, &target)
        .map_err(|e| PanelError::Internal(format!("replace {}: {e}", target.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        // 带 pid+序号不解决并发（多个测试进程仍可能撞），这里每次用原子计数器+pid。
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "panel-public-ip-{}-{}-{tag}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_then_read_roundtrip() {
        let d = tmp_dir("roundtrip");
        assert_eq!(read(&d), None, "初始无文件必须返回 None");
        write(&d, " 203.0.113.7\n").unwrap();
        assert_eq!(read(&d).as_deref(), Some("203.0.113.7"), "写入后读回应归一化");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_invalid_ip_without_writing() {
        let d = tmp_dir("invalid");
        assert!(write(&d, "not-an-ip").is_err(), "垃圾值必须拒绝");
        assert!(!state_path(&d).exists(), "拒绝时不得落盘");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn read_tolerates_missing_and_garbage() {
        let d = tmp_dir("garbage");
        assert_eq!(read(&d), None, "不存在的文件返回 None");
        std::fs::write(state_path(&d), "<html>oops</html>").unwrap();
        assert_eq!(read(&d), None, "回显服务故障页不得被当成 IP");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn overwrite_keeps_latest_value() {
        let d = tmp_dir("overwrite");
        write(&d, "203.0.113.7").unwrap();
        write(&d, "2001:db8::1").unwrap();
        assert_eq!(read(&d).as_deref(), Some("2001:db8::1"), "二次写入必须覆盖旧值");
        assert!(!d.join(format!(".{STATE_FILE}.tmp")).exists(), "临时文件须被 rename 清掉");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn effective_prefers_state_file_over_legacy_config() {
        let d = tmp_dir("effective");
        // 老部署：状态文件还没生成，用 config 旧值兜底（升级不丢）
        assert_eq!(
            effective(&d, Some("198.51.100.9".into())).as_deref(),
            Some("198.51.100.9"),
            "状态文件缺失时必须回退 config 旧值"
        );
        // 状态文件一旦存在即以它为准，覆盖 config 旧值（且不回写 config）
        write(&d, "203.0.113.7").unwrap();
        assert_eq!(
            effective(&d, Some("198.51.100.9".into())).as_deref(),
            Some("203.0.113.7"),
            "状态文件须优先于 config 旧值"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
