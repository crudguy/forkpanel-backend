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
use std::path::{Path, PathBuf};
use crate::extract::PanelJson;

/// 单次读取的上限。**刻意不允许一次读完大文件**：
/// 编辑器场景用 `offset`+`len` 分块，下载走流式。
const MAX_READ_BYTES: usize = 2 * 1024 * 1024;

// ─────────────── 路径解析（唯一入口） ───────────────

/// 解析用户传入的路径。**所有文件 handler 都必须经此函数**。
///
/// 返回 SafePath 意味着已通过：canonicalize + 允许根前缀断言。
pub(crate) fn resolve(_state: &Shared, s: &crate::auth::Session, input: &str) -> Result<SafePath> {
    resolve_impl(_state, s, input, false)
}

/// 「先登记、后落地」语义：目标允许尚不存在（上传/移动/复制的目标侧）。
pub(crate) fn resolve_new(_state: &Shared, s: &crate::auth::Session, input: &str) -> Result<SafePath> {
    resolve_impl(_state, s, input, true)
}

/// 把用户输入归一化为「相对某个允许根」的形式；已是相对路径则原样返回。
///
/// ## 为什么必须有这一步
/// 沙箱 [`panel_os::paths::resolve_within`] **拒绝绝对路径**（防 `/etc/passwd` 直传），
/// 但回收站元数据里的 `original_path` 来自 `SafePath`（canonicalize 的产物）——
/// **必然是绝对路径**。
///
/// ## 此前 bug：同一约束在两条路径上漏配
/// owner 分支（root=/）做了 `trim_start_matches('/')`，非 owner 分支却把绝对路径
/// **原样**交给沙箱，被 `is_absolute` 一律判为 `PathEscape`。后果是
/// operator/viewer 的回收站**恢复** 100% 必失败（列表/删除/清空都正常，独独恢复坏），
/// 且错误信息是含义不清的 "10006 path escape"，用户无从归因。
///
/// 之所以长期没暴露：本机 dev 库只有一个 owner（`allowed_roots=[]`），
/// 走的是 owner 分支。抽成公共函数供两路共用，而不是在两处各抄一遍。
///
/// ## 安全性
/// 落在该根**以外**的绝对路径 → `strip_prefix` 失败即拒绝；落在根内的才交给沙箱
/// 做完整校验（`..` 拦截 / 存在性 / canonicalize 前缀断言全部保留）。
pub(crate) fn relativize(root: &Path, input: &str) -> Result<String> {
    let p = Path::new(input);
    if !p.is_absolute() { return Ok(input.to_string()); }
    match p.strip_prefix(root) {
        Ok(r) => {
            let rel = r.to_string_lossy().to_string();
            Ok(if rel.is_empty() { ".".to_string() } else { rel })
        }
        // 绝对路径但不在该允许根内 —— 与该根无关，调用方会记下错误并试下一个根
        Err(_) => Err(PanelError::PathEscape(input.to_string())),
    }
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
        return pick(&PathBuf::from("/"), relativize(Path::new("/"), input)?);
    }
    let mut last_err = None;
    for root in &s.allowed_roots {
        // 关键：绝对路径（回收站 original_path 就是这种）先转成相对该根的形式，
        // 否则沙箱的 is_absolute 拦截会让非 owner 的恢复操作永远失败。
        let rel = match relativize(Path::new(root), input) {
            Ok(r) => r,
            Err(e) => { last_err = Some(e); continue }
        };
        match pick(&PathBuf::from(root), rel) {
            Ok(p) => return Ok(p),
            Err(e) => last_err = Some(e),
        }
    }
    // 没有任何允许根：拒绝而非退回默认（"没有白名单"绝不等于"全部允许"）
    Err(last_err.unwrap_or_else(|| PanelError::PathEscape(input.to_string())))
}

/// 把平台给出的 mode 渲染成**契约规定的八进制串**（如 "644"）。
///
/// ## 为什么必须掩掉类型位
/// Linux 的 `st_mode` 含文件类型位（`S_IFREG`=0o100000、`S_IFDIR`=0o040000、
/// `S_IFLNK`=0o120000）。直接 `format!("{m:o}")` 会让普通文件渲染成 `"100644"`，
/// 而契约 `FileStatOut.mode` 写的是「八进制串（如 644）」。
///
/// 此前 `list` 用了 `m & 0o777`、`stat` 却没有，**同一个字段两个端点语义不同**——
/// 任何按 `stat.mode` 判权的调用方都会算错。当前 UI 只消费 list 的 mode，故该
/// bug 长期静默，直到 2026-10-20 真机 E2E 抓出。
///
/// 抽成单一函数是刻意的：测试只能钉住**被生产代码真正调用**的实现，
/// 若测试自己写一份格式化闭包，把 handler 改坏测试照样绿（已实测）。
pub(crate) fn perm_octal(m: u32) -> String {
    format!("{:o}", m & 0o777)
}

/// 敏感文件兜底检查
pub(crate) fn ensure_not_sensitive(state: &Shared, p: &SafePath) -> Result<()> {
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
            mode: e.mode.map(perm_octal),
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
        has_more: (offset + buf.len() as u64) < st.size,
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
    PanelJson(req): PanelJson<WriteReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    // 写目标**可能尚不存在**（新建文件）。必须走 resolve_new(create=true)：
    // resolve 会 canonicalize 目标本身并要求它已存在，否则写新文件一律
    // NotFound(10004)。这与 mkdir/上传一致——覆盖已存在文件时 resolve_new 同样正确。
    // 此前 write 误用 resolve，导致「写新文件」100% 失败（错误信息为
    // "not found: <相对路径形态>"，因 relativize 已把前导 / 转成相对根的形式）。
    let p = resolve_new(&state, &s, &req.path)?;
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
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<MkdirReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    // 目标目录**尚不存在**，必须走 resolve_new(create=true)：resolve 会 canonicalize
    // 目标本身并要求它已存在，否则一律 NotFound(10004) →「新建目录」100% 失败。
    let p = resolve_new(&state, &s, &req.path)?;
    state.os.files().create_dir(&p, req.recursive.unwrap_or(true)).await?;
    audit(&state, &s, "file.mkdir", &req.path, "ok").await;
    Ok(ok(serde_json::json!({ "path": req.path })))
}

#[derive(Debug, Deserialize)]
pub struct DeleteReq { pub path: String, pub allow_dir: Option<bool> }

pub async fn remove(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<DeleteReq>,
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

// ─────────────── 回收站（软删除） ───────────────
//
// 设计：产物是**逐条自描述目录**（`<data_dir>/trash/<id>/{archive.tar.gz,meta.json}`），
// 不维护全局索引。好处是崩溃安全——没有"索引与实体不一致"的窗口；purge 就是删目录。
//
// 为什么用 tar.gz 而不是原地 `rename` 进回收站：
//   1. 跨分区 `rename` 直接 EXDEV 失败，而被管理的站点目录常在另一块盘；
//   2. 归档天然统一处理文件与目录两种情形；
//   3. 复用备份模块**已验证**的实现（含 `..` 逃逸校验、超时、进程收敛），
//      不必新写一套递归拷贝/删除。

const TRASH_META: &str = "meta.json";
const TRASH_ARCHIVE: &str = "archive.tar.gz";
/// 回收站列表上限：回收站不该成为无限增长的垃圾场
const TRASH_LIST_MAX: usize = 1000;

fn trash_root(state: &Shared) -> PathBuf {
    state.os.paths().data_dir().join("trash")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn io_err(ctx: &str, e: std::io::Error) -> ApiError {
    ApiError::from(PanelError::Io(format!("{ctx}: {e}")))
}

/// 回收站 id：纳秒时间戳 + 进程号。字符集锁死在 `[0-9a-f-]`——
/// 该串会参与路径拼接，必须在**生成侧**就限定，不能指望使用侧过滤。
fn new_trash_id() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{ns:x}-{:x}", std::process::id())
}

/// 校验**外部传入**的 id（列表/恢复/purge 都会带）。与生成侧同字符集，杜绝 `../` 注入。
fn is_valid_trash_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

async fn count_dir_entries(p: &std::path::Path) -> usize {
    let mut n = 0usize;
    if let Ok(mut rd) = tokio::fs::read_dir(p).await {
        while let Ok(Some(_)) = rd.next_entry().await {
            n += 1;
        }
    }
    n
}

/// 读一条元数据；损坏条目返回 None（由调用方跳过）——
/// 一条坏数据不该让整个回收站不可用。
async fn read_trash_meta(entry_dir: &std::path::Path) -> Option<serde_json::Value> {
    let raw = tokio::fs::read(entry_dir.join(TRASH_META)).await.ok()?;
    serde_json::from_slice::<serde_json::Value>(&raw).ok()
}

#[derive(Debug, Deserialize)]
pub struct TrashReq { pub path: String }

/// 把**已校验**的单个路径移入回收站（`trash` handler 与批量 `action` 共用）。
///
/// 顺序刻意为「先归档、后删除」：归档失败时原文件必须还在；
/// 删除失败则连归档一起回滚，避免"原件还在、回收站也有一份"的双份歧义。
async fn trash_one(state: &Shared, p: &SafePath) -> Result<serde_json::Value> {
    let st = state.os.files().stat(p).await?;
    let kind = if st.kind == EntryKind::Dir { "dir" } else { "file" };

    let entry_dir = trash_root(state).join(new_trash_id());
    tokio::fs::create_dir_all(&entry_dir).await
        .map_err(|e| PanelError::Io(format!("创建回收站条目失败: {e}")))?;
    let archive = entry_dir.join(TRASH_ARCHIVE);

    if let Err(e) = panel_os::backup::tar_gz(p.as_path(), &archive).await {
        let _ = tokio::fs::remove_dir_all(&entry_dir).await;
        return Err(e);
    }
    if let Err(e) = state.os.files().remove(p, true).await {
        let _ = tokio::fs::remove_dir_all(&entry_dir).await;
        return Err(e);
    }

    let entry = serde_json::json!({
        "id": entry_dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        "original_path": p.as_path().to_string_lossy(),
        "name": p.as_path().file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        "deleted_at": now_unix(),
        "kind": kind,
        "size_bytes": st.size,
    });
    let bytes = serde_json::to_vec_pretty(&entry)
        .map_err(|e| PanelError::Internal(format!("序列化回收站元数据失败: {e}")))?;
    tokio::fs::write(entry_dir.join(TRASH_META), bytes).await
        .map_err(|e| PanelError::Io(format!("写入回收站元数据失败: {e}")))?;
    Ok(entry)
}

/// 移入回收站（软删除）。与 `remove`（永久删除）刻意分成两个端点：
/// 用户误删是高频事件，恢复路径必须存在。
pub async fn trash(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<TrashReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let p = resolve(&state, &s, &req.path)?;
    ensure_not_sensitive(&state, &p)?;
    let entry = trash_one(&state, &p).await?;
    audit(&state, &s, "file.trash", &req.path, "ok").await;
    Ok(ok(entry))
}

/// 回收站列表（新 → 旧）。
pub async fn trash_list(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_READ)?;
    let root = trash_root(&state);
    let mut rd = match tokio::fs::read_dir(&root).await {
        Ok(r) => r,
        // 回收站尚未建立不是错误：如实返回空列表
        Err(_) => return Ok(ok(serde_json::json!({ "items": [] }))),
    };
    let mut items: Vec<serde_json::Value> = Vec::new();
    while let Ok(Some(ent)) = rd.next_entry().await {
        if items.len() >= TRASH_LIST_MAX { break; }
        let dir = ent.path();
        if !dir.is_dir() { continue; }
        // 元数据缺失/损坏的条目直接跳过——**不顺手删除**：那是用户可能的恢复数据，
        // 删不删得由人明确决定。
        if let Some(md) = read_trash_meta(&dir).await {
            items.push(md);
        }
    }
    items.sort_by(|a, b| {
        let ta = a.get("deleted_at").and_then(|x| x.as_i64()).unwrap_or(0);
        let tb = b.get("deleted_at").and_then(|x| x.as_i64()).unwrap_or(0);
        tb.cmp(&ta)
    });
    Ok(ok(serde_json::json!({ "items": items })))
}

#[derive(Debug, Deserialize)]
pub struct TrashIdReq { pub id: String }

/// 从回收站恢复。
///
/// **恢复目标重新走完整沙箱**（`resolve_new`）：回收站元数据是磁盘上的普通文件，
/// 不能因为"是我们自己写的"就信任——被篡改的 meta 可以指向任意路径。
pub async fn trash_restore(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<TrashIdReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    if !is_valid_trash_id(&req.id) {
        return Err(ApiError::bad_request("id", "非法回收站 id"));
    }
    let entry_dir = trash_root(&state).join(&req.id);
    let md = read_trash_meta(&entry_dir).await
        .ok_or_else(|| ApiError::from(PanelError::NotFound("回收站条目不存在或元数据损坏".into())))?;

    let original = md.get("original_path").and_then(|v| v.as_str()).unwrap_or_default();
    let target = resolve_new(&state, &s, original)?;
    ensure_not_sensitive(&state, &target)?;

    // 父目录必须已存在：原父目录若已被删，恢复无处安放（面板不越权替用户建目录）
    let parent = target.as_path().parent()
        .ok_or_else(|| ApiError::bad_request("path", "原路径无父目录"))?
        .to_path_buf();
    if tokio::fs::symlink_metadata(&parent).await.is_err() {
        return Err(ApiError::bad_request("path", "原目录已不存在，无法恢复"));
    }
    // 原位置已有同名文件则拒绝：**绝不覆盖**——那会吃掉用户后来新建的文件
    if tokio::fs::symlink_metadata(target.as_path()).await.is_ok() {
        return Err(ApiError::bad_request("path", "原位置已有同名文件，请先移走它再恢复"));
    }

    let archive = entry_dir.join(TRASH_ARCHIVE);
    // 归档条目逃逸校验：归档虽由本面板产出，仍按不可信输入对待（纵深防御）
    for name in panel_os::backup::list_tar_entries(&archive).await? {
        if !panel_os::backup::is_safe_entry(&name) {
            return Err(ApiError::bad_request("archive", format!("归档含非法条目: {name}")));
        }
    }
    panel_os::backup::untar_gz(&archive, &parent).await?;
    tokio::fs::remove_dir_all(&entry_dir).await
        .map_err(|e| io_err("清理回收站条目失败", e))?;

    audit(&state, &s, "file.trash.restore", original, "ok").await;
    Ok(ok(serde_json::json!({ "restored": original })))
}

#[derive(Debug, Deserialize)]
pub struct TrashPurgeReq { pub id: Option<String> }

/// 彻底删除：给 `id` 删一条，不给则**清空**回收站。返回删除条数。
pub async fn trash_purge(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<TrashPurgeReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let root = trash_root(&state);

    let (target, single) = match req.id.as_deref() {
        Some(id) => {
            if !is_valid_trash_id(id) {
                return Err(ApiError::bad_request("id", "非法回收站 id"));
            }
            (root.join(id), true)
        }
        None => (root.clone(), false),
    };

    let n = if single {
        usize::from(tokio::fs::symlink_metadata(&target).await.is_ok())
    } else {
        count_dir_entries(&target).await
    };
    match tokio::fs::remove_dir_all(&target).await {
        Ok(()) => {}
        // 目录本就不存在 → 视为已清空（幂等，不报错）
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err("清空回收站失败", e)),
    }
    audit(&state, &s, "file.trash.purge", req.id.as_deref().unwrap_or("all"), "ok").await;
    Ok(ok(serde_json::json!({ "purged": n })))
}

#[derive(Debug, Deserialize)]
pub struct RenameReq { pub from: String, pub to: String, pub copy: Option<bool> }

pub async fn rename(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<RenameReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    // from 必须已存在（resolve）；to 通常是**尚不存在的新名字**，必须 resolve_new，
    // 否则「重命名到新名」一律 NotFound(10004)。覆盖已存在的 to 时 resolve_new 同样正确。
    let from = resolve(&state, &s, &req.from)?;
    let to = resolve_new(&state, &s, &req.to)?;
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

/// 解析并校验 chmod 的八进制模式。
///
/// **抽成独立函数是为了让测试真的能测它**：此前校验内联在 handler 里，测试只能
/// 断言 `0o4755 > 0o777` 这种字面量算术（恒真，压根没碰到生产代码）——测试名写着
/// "setuid 被拒"，实际什么都没测。handler 与测试共用同一份实现，杜绝"测试自持实现"。
///
/// 范围检查（> 0o777 即拒）同时承担**拒绝 setuid/setgid 位**的职责：
/// 0o4755 / 0o2755 都超出 0o777 ⇒ 提权位进不来。
fn parse_mode(raw: &str) -> ApiResult<u32> {
    let mode = u32::from_str_radix(raw.trim_start_matches("0o"), 8)
        .map_err(|_| ApiError::bad_request("mode", "must be octal, e.g. 644"))?;
    if mode > 0o777 {
        return Err(ApiError::bad_request("mode", "out of range"));
    }
    Ok(mode)
}

pub async fn chmod(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<ChmodReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let p = resolve(&state, &s, &req.path)?;

    // 只接受八进制。绝不接受 "u+x" 这类符号模式——解析符号模式会引入不必要的复杂度与歧义。
    let mode = parse_mode(&req.mode)?;

    // 不允许设置 setuid/setgid 位：这是提权向量，面板不该提供
    let op = panel_os::PermissionOp::Posix {
        mode, owner: None, group: None,
    };
    // 此前写成 `let _recursive = req.recursive.unwrap_or(false);` —— 只赋值、从未使用，
    // 于是用户勾了「递归」却只改了顶层，而且没有任何提示。静默失效比直接报错更危险：
    // 用户以为整棵目录树都改了，子文件权限其实原封不动（安全相关操作尤其不能假成功）。
    // 底层 StorageProvider::set_permissions 目前只作用于传入路径本身、无 recursive 语义，
    // 在扩展该 trait 之前显式拒绝，而不是假装生效。
    if req.recursive.unwrap_or(false) {
        return Err(ApiError::bad_request(
            "recursive", "recursive chmod is not supported: only the given path is changed"));
    }
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
        // 必须掩掉文件类型位（`m & 0o777`），与 list 的 EntryDto.mode 保持同一语义。
        // 此前直接用 `{m:o}`，Linux 的 mode 含 S_IFREG(0o100000)，输出 "100644"，
        // 而契约 FileStatOut.mode 明写「八进制串（如 644）」——同一个字段在两个端点
        // 语义不同，任何按 stat.mode 判权的调用方都会算错（当前 UI 只用 list 的 mode，
        // 故未暴露）。判据：stat 对 644 文件必须回 "644" 而非 "100644"。
        "mode": st.mode.map(perm_octal),
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
    PanelJson(req): PanelJson<ActionReq>,
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
    if !matches!(req.op.as_str(), "move" | "copy" | "delete" | "trash" | "chmod") {
        return Err(ApiError::bad_request("op", "must be one of move/copy/delete/trash/chmod"));
    }

    let mut results: Vec<ActionItem> = Vec::with_capacity(req.paths.len());
    for raw in &req.paths {
        let mut item = ActionItem { path: raw.clone(), ok: false, error: None };
        let r = (|| async {
            let p = resolve(&state, &s, raw)?;
            ensure_not_sensitive(&state, &p)?;
            match req.op.as_str() {
                "delete" => state.os.files().remove(&p, true).await?,
                // 软删除：批量操作里最容易被误触的一个，故默认走回收站
                "trash" => { trash_one(&state, &p).await?; }
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

    // ⚠ 这是**常量规格锁**（改常量即红），不是恒真断言：clippy 的
    // `assertions_on_constants` 对"两个 const 比较"一律报警，但它看不出我们
    // 恰恰要锁住这些常量不被悄悄改掉。
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn read_cap_is_bounded() {
        assert!(MAX_READ_BYTES <= 8 * 1024 * 1024, "单次读取上限不应过大");
        assert!(MAX_READ_BYTES >= 512 * 1024, "太小会让编辑器频繁分块");
    }

    #[test]
    fn trash_id_charset_is_locked_down() {
        // 生成侧只产 [0-9a-f-]，且必须自洽通过自己的校验
        let id = new_trash_id();
        assert!(is_valid_trash_id(&id), "生成的 id 必须通过自身校验: {id}");
        // 拒绝一切可参与路径逃逸的输入
        for bad in ["../etc", "a/b", "", ".", "..", "x y", "a\\b", "a..b"] {
            assert!(!is_valid_trash_id(bad), "必须拒绝非法 id: {bad:?}");
        }
        assert!(!is_valid_trash_id(&"a".repeat(65)), "超长 id 必须拒绝");
    }

    #[test]
    fn trash_id_is_unique_across_calls() {
        assert_ne!(new_trash_id(), new_trash_id(), "纳秒时间戳 + pid 应保证不撞");
    }

    // ── relativize（回收站恢复的绝对路径归一化） ──
    // 背景：非 owner 的回收站恢复曾 100% 失败——只有 owner 分支归一化了绝对路径。

    #[test]
    fn relativize_passes_relative_input_through() {
        assert_eq!(relativize(Path::new("/srv/site"), "a/b.txt").unwrap(), "a/b.txt");
        assert_eq!(relativize(Path::new("/srv/site"), "a").unwrap(), "a");
    }

    #[test]
    fn relativize_strips_allowed_root_from_absolute_path() {
        // 回收站 original_path 的真实形态：SafePath 经 canonicalize → 绝对路径
        let root = Path::new("/srv/site");
        assert_eq!(relativize(root, "/srv/site/a/b.txt").unwrap(), "a/b.txt");
        // root 配置带尾斜杠时必须同样成立（strip_prefix 按组件比较）
        assert_eq!(relativize(Path::new("/srv/site/"), "/srv/site/a/b.txt").unwrap(), "a/b.txt");
    }

    #[test]
    fn relativize_maps_root_itself_to_dot() {
        assert_eq!(relativize(Path::new("/srv/site"), "/srv/site").unwrap(), ".");
        assert_eq!(relativize(Path::new("/srv/site/"), "/srv/site").unwrap(), ".");
    }

    #[test]
    fn relativize_rejects_absolute_path_outside_root() {
        // 落在允许根外的绝对路径必须拒绝——否则 allowed_roots 作用域形同虚设
        let e = relativize(Path::new("/srv/site"), "/etc/passwd").unwrap_err();
        assert!(matches!(e, PanelError::PathEscape(_)),
            "根外绝对路径必须被拒，实际得到: {e:?}");
    }

    /// 端到端回归：非 owner 用**绝对路径**解析允许根内的文件，必须成功。
    ///
    /// 这条链路就是回收站恢复走的：restore 从元数据读出绝对路径的 original_path，
    /// 再交给 `resolve_new`。修复前 absolute→resolve_within 必然 PathEscape。
    #[test]
    fn absolute_path_within_allowed_root_resolves_end_to_end() {
        let root = std::env::temp_dir()
            .join(format!("panel-relativize-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let f = root.join("sub").join("f.txt");
        std::fs::write(&f, b"x").unwrap();

        let abs = f.to_string_lossy().to_string();
        let rel = relativize(Path::new(&root), &abs)
            .unwrap_or_else(|e| panic!("allowed root 内的绝对路径应被归一化: {abs} -> {e}"));
        assert_eq!(rel, "sub/f.txt");

        // 归一化结果必须能通过完整沙箱（.. 拦截 / 存在性 / 前缀断言）
        let sp = panel_os::paths::resolve_within(&root, &rel)
            .unwrap_or_else(|e| panic!("沙箱应接受根内相对路径: {rel} -> {e}"));
        assert_eq!(sp.as_path(), std::fs::canonicalize(&f).unwrap());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 回归守卫：写**新文件**的目标路径必须经 `resolve_within_for_create` 解析，
    /// 而非 `resolve_within`（后者要求目标已存在，会把「写新文件」判为 NotFound）。
    ///
    /// 这正是 `write` handler 的修复点：此前误用 `resolve`（=resolve_impl(..., create=false)），
    /// 导致 owner + 空 allowed_roots 下写 `/tmp/x/new.txt` 报
    /// "not found: tmp/x/new.txt"（前导 / 被 relativize 转成相对根的形态）。
    ///
    /// 这里直接复现 owner 分支的归一化链路：relativize(root="/", abs) → 相对路径 → 沙箱。
    /// 断言：for_create 接受「不存在的目标」，而 resolve_within 拒绝之（负向对照）。
    #[test]
    fn write_new_file_target_resolves_via_for_create_not_resolve_within() {
        let root = Path::new("/");
        let abs = "/tmp/forkpanel-fm-e2e-guard/hello.txt";
        // 确保不是本机真实存在的文件，纯粹测「不存在目标」的解析语义
        let _ = std::fs::remove_file(abs);

        let rel = relativize(root, abs)
            .unwrap_or_else(|e| panic!("owner 下绝对路径必须被归一化: {abs} -> {e}"));
        // relativize 把前导 / 去掉 → 相对根的形式
        assert_eq!(rel, "tmp/forkpanel-fm-e2e-guard/hello.txt");

        // 修复后的链路：for_create 接受尚不存在的目标
        let sp = panel_os::paths::resolve_within_for_create(root, &rel)
            .expect("写新文件目标必须可解析（修复后应走 for_create）");
        assert_eq!(sp.as_path(), std::path::Path::new("/tmp/forkpanel-fm-e2e-guard/hello.txt"));

        // 负向对照：旧链路 resolve_within 会拒绝（目标不存在 → NotFound）
        let old = panel_os::paths::resolve_within(root, &rel);
        assert!(old.is_err(), "旧 write 链路（resolve_within）对不存在目标必须失败，否则修复无效");
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

    /// 守卫：`stat` 与 `list` 的 mode 必须是**同一语义**（权限位，掩掉文件类型位）。
    ///
    /// 契约 `FileStatOut.mode` 写的是「八进制串（如 644）」；若直接 `format!("{m:o}")`，
    /// Linux 的 mode 含 `S_IFREG`(0o100000)，stat 会回 `"100644"` 而 list 回 `"644"`。
    /// 同一字段两个端点含义不同 ⇒ 任何按 `stat.mode` 判权的调用方都算错。
    /// 当前 UI 只消费 list 的 mode，故该 bug 长期静默（真机实测 2026-10-20 发现）。
    #[test]
    fn stat_and_list_report_the_same_mode_semantics() {
        // 直接测**生产代码里真正被 handler 调用的那个函数**。
        // 早期版本在这里写了一个本地 `perm` 闭包，结果把 stat 改回 `{m:o}` 测试照样绿
        // ——恒绿守卫已实测过，故改为调用 perm_octal 本身。
        // raw 值取自真机 stat：普通文件 / chmod 后 / 目录 / 符号链接
        assert_eq!(perm_octal(0o100644), "644", "普通 644 文件不得渲染成 100644");
        assert_eq!(perm_octal(0o100600), "600", "chmod 600 之后");
        assert_eq!(perm_octal(0o040755), "755", "目录只取权限位");
        assert_eq!(perm_octal(0o120777), "777", "符号链接只取权限位");
        // 断言活性：若 perm_octal 退化成不带掩码的 `{m:o}`，下面必红
        for raw in [0o100644u32, 0o100600, 0o040755, 0o120777] {
            assert_ne!(format!("{raw:o}"), perm_octal(raw),
                "perm_octal 必须与裸 {{m:o}} 有差异，否则说明掩码没生效: {raw:o}");
        }
    }

    #[test]
    fn setuid_bits_are_rejected_by_range_check() {
        // 真·调用被测函数：此前这里只断言 `0o4755 > 0o777`（字面量算术，**恒真**，
        // 从没碰到任何生产代码）——测试名写着"setuid 被拒"，实际什么都没测。
        assert!(parse_mode("4755").is_err(), "0o4755 含 setuid，必须被范围检查拒掉");
        assert!(parse_mode("2755").is_err(), "0o2755 含 setgid，必须被范围检查拒掉");
        assert!(parse_mode("755").is_ok(), "合法八进制应通过");
        assert!(parse_mode("0o755").is_ok(), "0o 前缀应被接受");
        assert!(parse_mode("999").is_err(), "非八进制串应被拒");
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
