//! 发布版本元数据：版本比较 + 架构 → tarball 命名。
//!
//! **为什么单列一个模块**：检查更新（`panel-api`）与执行升级（`panel-cli`）必须用
//! 同一套「谁更新」的判断；两边各写一份 semver 解析，迟早出现「页面说有新版、
//! CLI 说没有」这种自相矛盾。

/// 只取数字核心：`v0.2.1-rc1` → `[0,2,1]`；解析失败返回 `None`。
///
/// 预发布（rc/beta）不参与大小比较——同一核心的 rc 不应被当作可升级；
/// 是否预发布由调用方单独展示。
pub fn parse_core(v: &str) -> Option<[u64; 3]> {
    let s = v.trim().trim_start_matches('v').trim_start_matches('V');
    let core = s.split(['-', '+']).next()?;
    let mut out = [0u64; 3];
    let mut it = core.split('.');
    for slot in out.iter_mut() {
        *slot = it.next()?.parse().ok()?;
    }
    Some(out)
}

/// `latest` 的数字核心是否大于 `current`。
///
/// 版本号形态不认识时返回 `false`：宁可不提示更新，也不要让用户去跑一次
/// 无意义的升级（升级本身是有风险的操作）。
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_core(latest), parse_core(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// 运行架构 → 发行包架构名。只支持本面板实际分发的两种。
pub fn arch_slug() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// 发行包文件名（与 `deploy/build-static.sh` 的产出名严格一致）。
pub fn tarball_name(arch: &str) -> String {
    format!("panel-linux-{arch}.tar.gz")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_core_accepts_v_prefix_and_prerelease() {
        assert_eq!(parse_core("v0.1.0"), Some([0, 1, 0]));
        assert_eq!(parse_core("0.2.1"), Some([0, 2, 1]));
        assert_eq!(parse_core("v1.0.0-rc1"), Some([1, 0, 0]));
        assert_eq!(parse_core("v1.0.0+build7"), Some([1, 0, 0]));
    }

    #[test]
    fn parse_core_rejects_malformed() {
        assert_eq!(parse_core(""), None);
        assert_eq!(parse_core("v0.1"), None, "缺段不能被当成 0");
        assert_eq!(parse_core("v0.x.0"), None);
        assert_eq!(parse_core("latest"), None);
    }

    #[test]
    fn newer_only_when_numeric_core_is_greater() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("v0.1.1", "0.1.0"));
        assert!(is_newer("v1.0.0", "0.99.99"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0-rc1", "0.1.0"), "同核心的预发布不算可升级");
        assert!(!is_newer("v0.0.9", "0.1.0"));
        assert!(!is_newer("garbage", "0.1.0"), "无法解析时不得宣称有更新");
    }

    #[test]
    fn tarball_name_matches_build_output() {
        assert_eq!(tarball_name("amd64"), "panel-linux-amd64.tar.gz");
        assert_eq!(tarball_name("arm64"), "panel-linux-arm64.tar.gz");
    }
}
