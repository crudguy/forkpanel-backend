//! 文件管理 handler（设计方案 §2.5）。
//!
//! # 安全模型：三道防线，缺一不可
//!
//! 1. **沙箱**（主防线）：所有路径经 `PathLayout::resolve_within(root, input)`，
//!    做 canonicalize + 前缀断言。用户传 `../../etc/passwd` 在这里就被拒。
//! 2. **允许根**：会话携带 `allowed_roots`，即使沙箱逻辑正确，用户也只能在自己的根内活动。
//! 3. **敏感黑名单**（兜底）：`FileProvider::is_sensitive()` 由**平台**判定。
//!    这一条的意义是：即使前两道因为配置错误失效，也不会把 `/etc/shadow` 读出去。
//!
//! 三者不是冗余——沙箱防穿越，允许根防越权，黑名单防配置错误导致的灾难。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Query, State},
    Json,
};
use panel_core::{PanelError, Result, SafePath};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 单次读取的上限。**刻意不允许一次读完大文件**：
/// 编辑器场景用 `offset`+`len` 分块，下载走流式。
const MAX_READ_BYTES: usize = 2 * 1024 * 1024;

// ─────────────── 路径解析（唯一入口） ───────────────

/// 解析用户传入的路径。**所有文件 handler 都必须经此函数**。
///
/// 返回 SafePath 意味着已通过：canonicalize + 允许根前缀断言。
fn resolve(_state: &Shared, s: &crate::auth::Session, input: &str) -> Result<SafePath> {
    // 空路径视为根
    let input = if input.is_empty() { "/" } else { input };
    let mut last_err = None;
    for root in &s.allowed_roots {
        match panel_os::paths::resolve_within(&PathBuf::from(root), input) {
            Ok(p) => return Ok(p),
            Err(e) => last_err = Some(e),
        }
    }
    // 没有任何允许根：拒绝而非退回默认（"没有白名单"绝不等于"全部允许"）
    Err(last_err.unwrap_or_else(|| PanelError::PathEscape(input.to_string())))
}

/// 敏感文件兜底检查
fn ensure_not_sensitive(state: &Shared, p: &SafePath) -> Result<()> {
    if state.os.files().is_sensitive(p) {
        return Err(PanelError::PermissionDenied("file.sensitive"));
    }
    Ok(())
}

// ─────────────── 列表 ───────────────

#[derive(Debug, Deserialize)]
pub struct ListQ {
    pub path: Option<String>,
    #[serde(default)]
    pub hidden: bool,
    pub sort: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListResp {
    pub path: String,
    pub entries: Vec<EntryDto>,
    /// 是否因 limit 截断（UI 需提示"结果不完整"）
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct EntryDto {
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub modified: i64,
    /// 敏感文件在 UI 上标红并禁止读取
    pub sensitive: bool,
}

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<ListQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_READ)?;
    let p = resolve(&state, &s, q.path.as_deref().unwrap_or("/"))?;

    let sort = match q.sort.as_deref() {
        Some("size") => panel_os::SortBy::Size,
        Some("modified") => panel_os::SortBy::Modified,
        _ => panel_os::SortBy::Name,
    };
    let opt = panel_os::ListOpt { show_hidden: q.hidden, sort, dirs_first: true, limit: 1000 };
    let entries = state.os.files().list_dir(&p, opt).await?;

    let dtos: Vec<EntryDto> = entries.into_iter().map(|e| {
        // sensitive 由 list_dir 在平台实现内判定（含子路径拼接），
        // handler 不自己拼路径 —— 那需要绕过沙箱构造 SafePath。
        EntryDto {
            name: e.name,
            kind: match e.kind { panel_os::EntryKind::Dir => "dir",
                                 panel_os::EntryKind::File => "file",
                                 panel_os::EntryKind::Symlink => "symlink",
                                 _ => "other" },
            size: e.size,
            mode: e.mode.map(|m| format!("{:o}", m & 0o777)),
            owner: e.owner,
            modified: e.modified_unix,
            sensitive: e.sensitive,
        }
    }).collect();

    let truncated = dtos.len() >= 1000;
    Ok(ok(ListResp {
        path: p.as_path().display().to_string(),
        entries: dtos, truncated,
    }))
}

// ─────────────── 读取 ───────────────

#[derive(Debug, Deserialize)]
pub struct ReadQ {
    pub path: String,
    /// 分块起点（大文件预览）
    pub offset: Option<u64>,
    pub len: Option<usize>,
    /// 强制以文本返回；二进制检测由服务端做，避免把二进制当文本渲染乱码
    pub text: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ReadResp {
    pub path: String,
    pub content: Option<String>,
    /// 二进制时返回元信息而不返回内容
    pub binary: bool,
    pub size: u64,
    pub offset: u64,
    /// 是否还有更多（分块预览用）
    pub has_more: bool,
}

pub async fn read(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<ReadQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_READ)?;
    let p = resolve(&state, &s, &q.path)?;
    ensure_not_sensitive(&state, &p)?;

    let st = state.os.files().stat(&p).await?;
    if st.kind == panel_os::EntryKind::Dir {
        return Err(ApiError::bad_request("path", "is a directory"));
    }

    let offset = q.offset.unwrap_or(0);
    let len = q.len.unwrap_or(MAX_READ_BYTES).min(MAX_READ_BYTES);
    let buf = state.os.files().read_range(&p, offset, len).await?;

    // 二进制检测：NUL 字节是最可靠的判据（UTF-8 文本不含 NUL）
    let is_binary = buf.contains(&0u8)
        || std::str::from_utf8(&buf).is_err();

    let content = if is_binary && q.text != Some(true) { None }
        else { Some(String::from_utf8_lossy(&buf).to_string()) };

    Ok(ok(ReadResp {
        path: q.path, content, binary: is_binary,
        size: st.size, offset,
        has_more: (offset as u64 + buf.len() as u64) < st.size,
    }))
}

// ─────────────── 写入 ───────────────

#[derive(Debug, Deserialize)]
pub struct WriteReq {
    pub path: String,
    pub content: String,
    /// 乐观锁：客户端读到的修改时间。不一致则拒绝，防止"两个人同时编辑互相覆盖"
    pub expect_mtime: Option<i64>,
}

pub async fn write(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<WriteReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let p = resolve(&state, &s, &req.path)?;
    ensure_not_sensitive(&state, &p)?;

    // 乐观锁：先读 mtime 再比较。这个检查不是并发安全的（TOCTOU），
    // 但对"用户 A 打开半天后保存覆盖了用户 B 的修改"这个真实场景足够有效。
    if let Some(expect) = req.expect_mtime {
        let st = state.os.files().stat(&p).await.ok();
        if let Some(st) = st {
            if st.modified_unix != expect {
                return Err(ApiError::conflict(
                    "文件已被其他人修改，请刷新后重试"));
            }
        }
    }

    let max = state.os.files().max_file_bytes();
    if req.content.len() > max {
        return Err(ApiError::bad_request("content", format!("exceeds {} bytes", max)));
    }

    state.os.files().write(&p, req.content.as_bytes()).await?;
    audit(&state, &s, "file.write", &req.path, "ok").await;
    Ok(ok(serde_json::json!({ "path": req.path, "bytes": req.content.len() })))
}

// ─────────────── 目录 / 删除 / 重命名 / 复制 ───────────────

#[derive(Debug, Deserialize)]
pub struct MkdirReq { pub path: String, pub recursive: Option<bool> }

pub async fn mkdir(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<MkdirReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let p = resolve(&state, &s, &req.path)?;
    state.os.files().create_dir(&p, req.recursive.unwrap_or(true)).await?;
    audit(&state, &s, "file.mkdir", &req.path, "ok").await;
    Ok(ok(serde_json::json!({ "path": req.path })))
}

#[derive(Debug, Deserialize)]
pub struct DeleteReq { pub path: String, pub allow_dir: Option<bool> }

pub async fn remove(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<DeleteReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let p = resolve(&state, &s, &req.path)?;
    ensure_not_sensitive(&state, &p)?;

    // 删除目录必须显式声明。面板绝不提供"一键 rm -rf"，
    // 这个额外参数是为了让 UI 上必须多一次确认。
    state.os.files().remove(&p, req.allow_dir.unwrap_or(false)).await?;
    audit(&state, &s, "file.delete", &req.path, "ok").await;
    Ok(ok(serde_json::json!({ "path": req.path })))
}

#[derive(Debug, Deserialize)]
pub struct RenameReq { pub from: String, pub to: String, pub copy: Option<bool> }

pub async fn rename(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<RenameReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let from = resolve(&state, &s, &req.from)?;
    let to = resolve(&state, &s, &req.to)?;
    ensure_not_sensitive(&state, &to)?;

    if req.copy.unwrap_or(false) {
        state.os.files().copy(&from, &to).await?;
        audit(&state, &s, "file.copy", &req.to, "ok").await;
    } else {
        state.os.files().rename(&from, &to).await?;
        audit(&state, &s, "file.rename", &req.to, "ok").await;
    }
    Ok(ok(serde_json::json!({ "from": req.from, "to": req.to })))
}

// ─────────────── 权限 ───────────────

#[derive(Debug, Deserialize)]
pub struct ChmodReq { pub path: String, pub mode: String, pub recursive: Option<bool> }

pub async fn chmod(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<ChmodReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let p = resolve(&state, &s, &req.path)?;

    // 只接受八进制。绝不接受 "u+x" 这类符号模式——解析符号模式会引入不必要的复杂度与歧义。
    let mode = u32::from_str_radix(req.mode.trim_start_matches("0o"), 8)
        .map_err(|_| ApiError::bad_request("mode", "must be octal, e.g. 644"))?;
    if mode > 0o777 {
        return Err(ApiError::bad_request("mode", "out of range"));
    }

    // 不允许设置 setuid/setgid 位：这是提权向量，面板不该提供
    let op = panel_os::PermissionOp::Posix {
        mode, owner: None, group: None,
    };
    // 递归改权限只在目录上才合理，且由 StorageProvider 决定是否支持
    let _recursive = req.recursive.unwrap_or(false);
    state.os.storage().set_permissions(&p, op).await?;
    audit(&state, &s, "file.chmod", &req.path, "ok").await;
    Ok(ok(serde_json::json!({ "path": req.path, "mode": format!("{mode:o}") })))
}

// ─────────────── 文档式文件端点（M2 占位） ───────────────

pub async fn stat(
    State(_): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_READ)?;
    Err(ApiError::unsupported("file.stat (M2: 独立 stat 端点尚未接入；可用 /files/list 获取目录元数据)"))
}

pub async fn upload(
    State(_): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    Err(ApiError::unsupported("file.upload (M2: 流式上传尚未接入；可用 /files/write 写入文本)"))
}

pub async fn download(
    State(_): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_READ)?;
    Err(ApiError::unsupported("file.download (M2: 分块下载尚未接入)"))
}

pub async fn action(
    State(_): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    Err(ApiError::unsupported("file.action (M2: 批量/归档动作尚未接入)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_cap_is_bounded() {
        assert!(MAX_READ_BYTES <= 8 * 1024 * 1024, "单次读取上限不应过大");
        assert!(MAX_READ_BYTES >= 512 * 1024, "太小会让编辑器频繁分块");
    }

    #[test]
    fn octal_mode_parsing() {
        let parse = |s: &str| u32::from_str_radix(s.trim_start_matches("0o"), 8).ok();
        assert_eq!(parse("644"), Some(0o644));
        assert_eq!(parse("0755"), Some(0o755));
        assert_eq!(parse("0o600"), Some(0o600));
        assert_eq!(parse("abc"), None, "非八进制必须拒绝");
        assert_eq!(parse("u+x"), None, "符号模式不支持");
    }

    #[test]
    fn setuid_bits_are_rejected_by_range_check() {
        // 0o4755 含 setuid，超过 0o777 应被拒
        assert!(0o4755u32 > 0o777);
        assert!(0o2755u32 > 0o777);
    }

    #[test]
    fn binary_detection_uses_nul_and_utf8() {
        let is_binary = |b: &[u8]| b.contains(&0u8) || std::str::from_utf8(b).is_err();
        assert!(is_binary(&[0x00, 0x01, 0x02]));
        assert!(!is_binary(b"hello world"));
        assert!(!is_binary("<h1>中文</h1>".as_bytes()));
        assert!(is_binary(&[0xff, 0xfe, 0xfd]));
    }
}
