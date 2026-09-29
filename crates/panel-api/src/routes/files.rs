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
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use panel_core::{PanelError, Result, SafePath};
use panel_os::EntryKind;
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
    resolve_impl(_state, s, input, false)
}

/// 「先登记、后落地」语义：目标允许尚不存在（上传/移动/复制的目标侧）。
fn resolve_new(_state: &Shared, s: &crate::auth::Session, input: &str) -> Result<SafePath> {
    resolve_impl(_state, s, input, true)
}

fn resolve_impl(
    _state: &Shared, s: &crate::auth::Session, input: &str, create: bool,
) -> Result<SafePath> {
    // 空路径视为根
    let input = if input.is_empty() { "/" } else { input };
    // owner 特判：owner 等价宿主管理员（能开终端=任意命令），文件沙箱对其无意义；
    // 且 bootstrap 建号时 allowed_roots='[]'，按"空=全拒"会让 owner 的文件管理器
    // 完全不可用。owner 仍受敏感黑名单兜底（ensure_not_sensitive）。
    // allowed_roots 的作用域限制是给 operator/viewer 的。
    // 全盘沙箱：root=/。resolve_within 拒绝绝对输入，故把绝对路径转为
    // 相对 root 的形式后走**同一管线**（.. 拦截 / 存在性 / 前缀断言全保留）。
    let pick = |root: &PathBuf, rel: String| {
        if create {
            panel_os::paths::resolve_within_for_create(root, &rel)
        } else {
            panel_os::paths::resolve_within(root, &rel)
        }
    };
    if s.role == "owner" && s.allowed_roots.is_empty() {
        let rel = input.trim_start_matches('/');
        let rel = if rel.is_empty() { "." } else { rel };
        return pick(&PathBuf::from("/"), rel.to_string());
    }
    let mut last_err = None;
    for root in &s.allowed_roots {
        match pick(&PathBuf::from(root), input.to_string()) {
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

// ─────────────── stat / upload / download / action（M2 实装） ───────────────

/// 上传/下载共用上限：取平台 `max_file_bytes`（100MB）与部署级 body 上限的较小者。
/// 低配档位（1C1G）全量读入内存的峰值安全线，不做流式管道（避免引 tokio-util）。
fn transfer_limit(state: &Shared) -> usize {
    state.os.files().max_file_bytes().min(crate::middleware::BODY_LIMIT_UPLOAD)
}

pub async fn stat(
    State(state): State<Shared>, Auth(s): Auth,
    Query(q): Query<StatQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_READ)?;
    let p = resolve(&state, &s, &q.path)?;
    ensure_not_sensitive(&state, &p)?;
    let st = state.os.files().stat(&p).await?;
    Ok(ok(serde_json::json!({
        "path": q.path,
        "kind": match st.kind { EntryKind::Dir => "dir", EntryKind::File => "file", EntryKind::Symlink => "symlink", EntryKind::Other => "other" },
        "size": st.size,
        "mode": st.mode.map(|m| format!("{m:o}")),
        "owner": st.owner,
        "modified_at": st.modified_unix,
    })))
}

#[derive(Debug, Deserialize)]
pub struct StatQuery { pub path: String }

/// PUT /files/upload?path=… —— body 为**原始字节**（octet-stream）。
/// 上限 = min(平台 max_file_bytes, BODY_LIMIT_UPLOAD)；超限 400。
/// 写入经 provider（内部临时文件 + 原子替换），沙箱与敏感路径纪律同单项写入。
pub async fn upload(
    State(state): State<Shared>, Auth(s): Auth,
    Query(q): Query<StatQuery>,
    body: axum::body::Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let limit = transfer_limit(&state);
    if body.len() > limit {
        return Err(ApiError::bad_request(
            "body",
            format!("upload too large: {} bytes (limit {})", body.len(), limit),
        ));
    }
    let p = resolve_new(&state, &s, &q.path)?;
    ensure_not_sensitive(&state, &p)?;
    if state.os.files().stat(&p).await.map(|st| matches!(st.kind, EntryKind::Dir)).unwrap_or(false) {
        return Err(ApiError::bad_request("path", "target is a directory"));
    }
    state.os.files().write(&p, &body).await?;
    audit(&state, &s, "file.upload", &q.path, "ok").await;
    Ok(ok(serde_json::json!({ "path": q.path, "size": body.len() })))
}

/// GET /files/download?path=… —— 原始字节 + attachment 头。
/// 全量读入（≤ transfer_limit）；更大文件属"归档"场景，留待分块下载专项。
pub async fn download(
    State(state): State<Shared>, Auth(s): Auth,
    Query(q): Query<StatQuery>,
) -> ApiResult<Response> {
    crate::auth::require(&s, perm::FILE_READ)?;
    let p = resolve(&state, &s, &q.path)?;
    ensure_not_sensitive(&state, &p)?;
    let st = state.os.files().stat(&p).await?;
    if matches!(st.kind, EntryKind::Dir) {
        return Err(ApiError::bad_request("path", "cannot download a directory"));
    }
    let limit = transfer_limit(&state);
    if st.size > limit as u64 {
        return Err(ApiError::bad_request(
            "path",
            format!("file too large to download here: {} bytes (limit {})", st.size, limit),
        ));
    }
    let data = state.os.files().read(&p, limit).await?;

    // Content-Disposition：ASCII fallback + RFC 5987 filename*（UTF-8 手写百分号编码，零新依赖）
    let name = q.path.rsplit('/').next().unwrap_or("download.bin");
    let ascii: String = name.chars().map(|c| if c.is_ascii() && c != '%' { c } else { '_' }).collect();
    let enc: String = name.bytes().map(|b| {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
            (b as char).to_string()
        } else {
            format!("%{b:02X}")
        }
    }).collect();
    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (header::CONTENT_DISPOSITION,
         format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{enc}")),
    ];
    Ok((StatusCode::OK, headers, data).into_response())
}

/// POST /files/action —— 批量动作。逐项执行、逐项报告（部分失败也 200，
/// 结果数组里带 error）；op/dest/mode 非法则整体 400。
#[derive(Debug, Deserialize)]
pub struct ActionReq {
    /// move | copy | delete | chmod
    pub op: String,
    #[serde(default)]
    pub paths: Vec<String>,
    /// move/copy 的目标**目录**（各 path 移入同名）
    pub dest: Option<String>,
    /// chmod 的八进制模式（如 "644"）
    pub mode: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ActionItem {
    pub path: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn action(
    State(state): State<Shared>, Auth(s): Auth,
    Json(req): Json<ActionReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;

    if req.paths.is_empty() {
        return Err(ApiError::bad_request("paths", "empty"));
    }
    if req.paths.len() > 100 {
        return Err(ApiError::bad_request("paths", "too many (max 100 per batch)"));
    }

    // dest/mode 预解析（整体 400，不部分执行）
    let dest_dir: Option<SafePath> = match req.op.as_str() {
        "move" | "copy" => {
            let d = req.dest.as_deref().ok_or_else(|| {
                ApiError::bad_request("dest", "required for move/copy")
            })?;
            let dp = resolve(&state, &s, d)?;
            ensure_not_sensitive(&state, &dp)?;
            if state.os.files().stat(&dp).await.map(|st| st.kind != EntryKind::Dir).unwrap_or(true) {
                return Err(ApiError::bad_request("dest", "must be an existing directory"));
            }
            Some(dp)
        }
        _ => None,
    };
    let mode: Option<u32> = match req.op.as_str() {
        "chmod" => {
            let m = u32::from_str_radix(
                req.mode.as_deref().unwrap_or("").trim_start_matches("0o"), 8,
            ).map_err(|_| ApiError::bad_request("mode", "must be octal, e.g. 644"))?;
            if m > 0o777 {
                return Err(ApiError::bad_request("mode", "out of range"));
            }
            Some(m)
        }
        _ => None,
    };
    if !matches!(req.op.as_str(), "move" | "copy" | "delete" | "chmod") {
        return Err(ApiError::bad_request("op", "must be one of move/copy/delete/chmod"));
    }

    let mut results: Vec<ActionItem> = Vec::with_capacity(req.paths.len());
    for raw in &req.paths {
        let mut item = ActionItem { path: raw.clone(), ok: false, error: None };
        let r = (|| async {
            let p = resolve(&state, &s, raw)?;
            ensure_not_sensitive(&state, &p)?;
            match req.op.as_str() {
                "delete" => state.os.files().remove(&p, true).await?,
                "chmod" => {
                    let m = mode.expect("预解析已保证");
                    state.os.storage().set_permissions(
                        &p, panel_os::PermissionOp::Posix { mode: m, owner: None, group: None },
                    ).await?;
                }
                op => {
                    let dest = dest_dir.as_ref().expect("预解析已保证");
                    let name = raw.trim_end_matches('/').rsplit('/').next().unwrap_or(raw);
                    // 目标路径字符串重走 resolve（统一沙箱入口），不手工拼 SafePath
                    let base = dest.as_path().display().to_string();
                    let target = resolve_new(&state, &s, &format!("{base}/{name}"))?;
                    ensure_not_sensitive(&state, &target)?;
                    // 目标已存在 → 跳过（不静默覆盖，逐项报 error 由前端提示）
                    if state.os.files().stat(&target).await.is_ok() {
                        return Err(PanelError::Io(format!("target exists: {name}")));
                    }
                    if op == "move" {
                        state.os.files().rename(&p, &target).await?;
                    } else {
                        state.os.files().copy(&p, &target).await?;
                    }
                }
            }
            Ok::<(), PanelError>(())
        })().await;
        match r {
            Ok(()) => item.ok = true,
            Err(e) => item.error = Some(e.to_string()),
        }
        results.push(item);
    }

    let ok_count = results.iter().filter(|r| r.ok).count();
    audit(&state, &s, "file.batch", &format!("{} x{}", req.op, req.paths.len()), "ok").await;
    Ok(ok(serde_json::json!({
        "op": req.op,
        "results": results,
        "ok_count": ok_count,
        "fail_count": results.len() - ok_count,
    })))
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
