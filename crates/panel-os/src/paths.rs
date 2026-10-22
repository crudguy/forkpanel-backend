//! 全平台路径布局 —— 消灭硬编码的第一道防线（设计方案 §0.3.4）。
//!
//! 规则：业务层**禁止**出现 "/etc/nginx"、"/var/www"、'/' 拼接等字面量，
//! 一律通过 `PathLayout` 获取。CI 门禁 grep 这些字面量（见 ci/check-layering.sh）。

use std::path::{Path, PathBuf};

pub trait PathLayout: Send + Sync {
    fn config_dir(&self) -> PathBuf;
    fn data_dir(&self) -> PathBuf;
    fn log_dir(&self) -> PathBuf;
    fn cache_dir(&self) -> PathBuf;
    fn tmp_dir(&self) -> PathBuf;
    fn site_root(&self) -> PathBuf;
    fn web_conf_dir(&self) -> PathBuf;      // nginx conf.d / caddy sites / IIS 配置目录
    fn web_log_dir(&self) -> PathBuf;
    fn service_dir(&self) -> PathBuf;       // systemd unit / launchd plist / 无意义时返回空
    fn cron_dir(&self) -> PathBuf;
    fn script_dir(&self) -> PathBuf;        // 计划任务脚本（受限目录，防任意命令）
    fn backup_dir(&self) -> PathBuf;
    /// 容器守护进程的本地套接字（Linux: docker/podman 的 unix socket）。
    /// 返回**空路径**表示该平台无此概念（如 Windows 走命名管道）。
    /// 这是"守护进程是否可达"探测的入口——二进制存在不代表可用。
    fn container_socket(&self) -> PathBuf;
    /// 默认站点运行身份（Linux: www-data；Windows: IIS AppPool 身份；macOS: _www）
    fn default_web_user(&self) -> &'static str;
    fn sqlite_path(&self) -> PathBuf { self.data_dir().join("panel.db") }
}

/// 站点标识的文件名安全化：仅保留 `[A-Za-z0-9._-]`，其余替换为 `_`，空串回退 `site`。
///
/// 站点配置文件（`panel-<slug>.conf`）与站点日志文件（`<slug>.access.log`）都由此派生，
/// 保证 **provider 与业务层命名一致**，避免两处各写一份而漂移。
pub fn slug(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    if out.is_empty() { out.push_str("site"); }
    out
}

// ───────────────────────── Linux 实现 ─────────────────────────

#[derive(Clone)]
pub struct LinuxPathLayout {
    /// 允许被配置覆盖（config.toml [paths]），但**不允许业务层绕过 trait 直接拼接**
    prefix: PathBuf,
    site_root: PathBuf,
    data_dir: PathBuf,
    log_dir: PathBuf,
}

impl Default for LinuxPathLayout {
    fn default() -> Self {
        Self {
            prefix: PathBuf::from("/etc/panel"),
            site_root: PathBuf::from("/var/www"),
            data_dir: PathBuf::from("/var/lib/panel"),
            log_dir: PathBuf::from("/var/log/panel"),
        }
    }
}

impl LinuxPathLayout {
    pub fn with_overrides(mut self, config: Option<PathBuf>, site_root: Option<PathBuf>,
                          data_dir: Option<PathBuf>, log_dir: Option<PathBuf>) -> Self {
        if let Some(v) = config { self.prefix = v; }
        if let Some(v) = site_root { self.site_root = v; }
        if let Some(v) = data_dir { self.data_dir = v; }
        if let Some(v) = log_dir { self.log_dir = v; }
        self
    }
}

impl PathLayout for LinuxPathLayout {
    fn config_dir(&self) -> PathBuf { self.prefix.clone() }
    fn data_dir(&self) -> PathBuf { self.data_dir.clone() }
    fn log_dir(&self) -> PathBuf { self.log_dir.clone() }
    fn cache_dir(&self) -> PathBuf { self.data_dir.join("cache") }
    fn tmp_dir(&self) -> PathBuf { self.data_dir.join("tmp") }
    fn site_root(&self) -> PathBuf { self.site_root.clone() }
    fn web_conf_dir(&self) -> PathBuf {
        // 仅作为默认值：实际应由 WebServerProvider 探测（不同发行版差异大）
        if self.prefix.join("nginx").exists() { self.prefix.join("nginx/conf.d") }
        else { PathBuf::from("/etc/nginx/conf.d") }
    }
    fn web_log_dir(&self) -> PathBuf { self.log_dir.join("web") }
    fn service_dir(&self) -> PathBuf { PathBuf::from("/etc/systemd/system") }
    fn cron_dir(&self) -> PathBuf { PathBuf::from("/etc/cron.d") }
    fn script_dir(&self) -> PathBuf { self.data_dir.join("scripts") }
    fn backup_dir(&self) -> PathBuf { self.data_dir.join("backups") }
    /// Docker/Podman 的默认 unix socket。rootless 场景（`$XDG_RUNTIME_DIR/docker.sock`）
    /// 不在探测范围内——面板通常以服务身份运行，探测的是系统级 daemon。
    fn container_socket(&self) -> PathBuf { PathBuf::from("/var/run/docker.sock") }
    fn default_web_user(&self) -> &'static str { "www-data" }
}

// ───────────────────────── Windows 实现（预留骨架） ─────────────────────────
// 接入顺序见设计方案 §0.4.2 Step 2：先实现只读 trait，此处仅给出 PathLayout 形状。
// 注意：使用 `PathBuf::join`（而非 '/' 字面量），sep() 不再需要——Rust 的 Path 已处理分隔符。

#[cfg(feature = "os-windows")]
pub struct WindowsPathLayout { program_data: PathBuf }

#[cfg(feature = "os-windows")]
impl Default for WindowsPathLayout {
    fn default() -> Self { Self { program_data: PathBuf::from(r"C:\ProgramData\panel") } }
}

#[cfg(feature = "os-windows")]
impl PathLayout for WindowsPathLayout {
    fn config_dir(&self) -> PathBuf { self.program_data.join("config") }
    fn data_dir(&self) -> PathBuf { self.program_data.join("data") }
    fn log_dir(&self) -> PathBuf { self.program_data.join("logs") }
    fn cache_dir(&self) -> PathBuf { self.program_data.join("cache") }
    fn tmp_dir(&self) -> PathBuf { self.program_data.join("tmp") }
    fn site_root(&self) -> PathBuf { self.program_data.join("sites") }
    fn web_conf_dir(&self) -> PathBuf { self.program_data.join("iis") }   // IIS 走 appcmd，非文件优先
    fn web_log_dir(&self) -> PathBuf { self.program_data.join("logs").join("web") }
    fn service_dir(&self) -> PathBuf { PathBuf::new() }                    // SCM 无单元文件概念
    fn cron_dir(&self) -> PathBuf { self.program_data.join("tasks") }
    fn script_dir(&self) -> PathBuf { self.program_data.join("scripts") }
    fn backup_dir(&self) -> PathBuf { self.program_data.join("backups") }
    /// Windows 上 Docker 走命名管道（npipe:////./pipe/docker_engine），无 unix socket
    fn container_socket(&self) -> PathBuf { PathBuf::new() }
    fn default_web_user(&self) -> &'static str { "IIS AppPool\\DefaultAppPool" }
}

// ───────────────────────── 路径沙箱 ─────────────────────────
//
// 所有用户输入路径必须过此函数。流程：
//   拼接 → canonicalize（解析 .. 与符号链接）→ 前缀断言 → 可选 lstat 校验
// 任一失败返回 PanelError::PathEscape（HTTP 50001）。

use panel_core::{PanelError, Result, SafePath};

/// 判断 `child` 是否位于 `root` 之内（逐组件比较，避免字符串前缀误判
/// 如 /var/www-evil 被 /var/www 前缀命中）
pub fn is_within(root: &Path, child: &Path) -> bool {
    let r = match root.canonicalize() { Ok(p) => p, Err(_) => return false };
    let c = match child.canonicalize() { Ok(p) => p, Err(_) => return false };
    // Path::starts_with 是**组件级**比较，天然排除 /var/www-evil 被 /var/www 命中的误判
    c.starts_with(&r)
}

/// 安全路径解析：root 为用户可见的允许根，input 为用户提供的相对或绝对输入
pub fn resolve_within(root: &Path, input: &str) -> Result<SafePath> {
    if input.is_empty() {
        return Err(PanelError::Validation { field: "path", reason: "empty path".into() });
    }
    if input.contains('\0') {
        return Err(PanelError::Validation { field: "path", reason: "NUL byte in path".into() });
    }
    // 拒绝绝对路径混入（防止 /etc/passwd 直接传入）
    if Path::new(input).is_absolute() {
        return Err(PanelError::PathEscape(input.into()));
    }
    let joined = root.join(input);
    // 语义层拦截：任何 ".." 组件
    if Path::new(input).components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(PanelError::PathEscape(input.into()));
    }
    let canonical = joined.canonicalize()
        .map_err(|_| PanelError::NotFound(input.into()))?;
    let root_canon = root.canonicalize()
        .map_err(|_| PanelError::Internal("allowed root missing".into()))?;
    if !canonical.starts_with(&root_canon) {
        return Err(PanelError::PathEscape(input.into()));
    }
    // SAFETY: 已完成 canonicalize + 前缀断言
    Ok(unsafe { SafePath::from_raw(canonical) })
}

/// 与 `resolve_within` 同款沙箱约束，但**允许目标路径尚不存在**。
///
/// 适用场景：创建站点 / 数据库等「先登记、目录随后落地」的动作。
/// `resolve_within` 会 canonicalize 目标本身，要求它已存在；本函数只
/// canonicalize「允许根」`root`，再把它与 `input` 做组件级拼接并断言前缀，
/// 因此对尚未创建的子目录同样安全，且仍拦截绝对路径与 `..` 逃逸。
pub fn resolve_within_for_create(root: &Path, input: &str) -> Result<SafePath> {
    if input.is_empty() {
        return Err(PanelError::Validation { field: "path", reason: "empty path".into() });
    }
    if input.contains('\0') {
        return Err(PanelError::Validation { field: "path", reason: "NUL byte in path".into() });
    }
    // 拒绝绝对路径混入（防止 /etc/passwd 直接传入）
    if Path::new(input).is_absolute() {
        return Err(PanelError::PathEscape(input.into()));
    }
    // 语义层拦截：任何 ".." 组件
    if Path::new(input).components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(PanelError::PathEscape(input.into()));
    }
    // 仅 canonicalize 允许根（要求根存在）。根缺失属部署/配置错误 → Internal
    let root_canon = root
        .canonicalize()
        .map_err(|_| PanelError::Internal(format!("allowed root missing: {}", root.display())))?;
    let joined = root_canon.join(input);
    // 组件级前缀断言（input 已无 ".."/绝对路径，拼接不会逃逸，此为纵深防御）
    if !joined.starts_with(&root_canon) {
        return Err(PanelError::PathEscape(input.into()));
    }
    // SAFETY: 已 canonicalize root + 拒绝 ".." + 组件级前缀断言
    Ok(unsafe { SafePath::from_raw(joined) })
}

/// `path` 所在文件系统的**可用**字节数（`f_bavail`：非 root 用户真正能用的那部分，
/// 已扣除给 root 预留的额度）。
///
/// 返回 `None` 表示**取不到**（非 Linux / statvfs 失败 / 路径含 NUL）。调用方必须
/// 把 `None` 当成"不知道"来处理——**绝不能当成 0**：当成 0 会把所有备份一律挡下，
/// 那是把"查不到"伪装成"没空间"，比不检查更糟。
#[cfg(target_os = "linux")]
pub fn available_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return None;
        }
        Some(st.f_bavail as u64 * st.f_frsize as u64)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn available_bytes(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_root() -> PathBuf {
        let d = std::env::temp_dir().join(format!("panel-paths-{}", std::process::id()));
        let _ = fs::create_dir_all(d.join("site"));
        d
    }

    #[test]
    fn rejects_absolute_and_traversal() {
        let root = tmp_root();
        for bad in ["../etc/passwd", "/etc/passwd", "..", "../..", "a/../../b"] {
            assert!(resolve_within(&root, bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn accepts_inside_root() {
        let root = tmp_root();
        fs::write(root.join("site/index.html"), b"ok").unwrap();
        assert!(resolve_within(&root, "site/index.html").is_ok());
        assert!(resolve_within(&root, "site").is_ok());
    }

    #[test]
    fn prefix_is_component_wise() {
        // /var/www-evil 不应被 /var/www 视为内部
        assert!(!is_within(Path::new("/var/www"), Path::new("/var/www-evil/x")));
    }

    #[test]
    fn for_create_accepts_not_yet_existing_child() {
        // 根存在、但目标子目录尚不存在时（首建站点的典型场景）仍应解析成功
        let root = tmp_root();
        assert!(resolve_within_for_create(&root, "brand/new-site").is_ok());
        assert!(resolve_within_for_create(&root, "site").is_ok());
    }

    #[test]
    fn for_create_still_rejects_traversal() {
        let root = tmp_root();
        for bad in ["../escape", "/abs/path", "a/../../b", ".."] {
            assert!(resolve_within_for_create(&root, bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn for_create_rejects_missing_root() {
        let missing = std::env::temp_dir().join(format!("panel-paths-missing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&missing);
        // 允许根缺失 → Internal，而非静默越界
        assert!(resolve_within_for_create(&missing, "x").is_err());
    }
}
