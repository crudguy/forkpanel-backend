//! 大文件分片上传（断点续传）。
//!
//! ## 为什么需要
//! 单请求上传既受 `BODY_LIMIT_UPLOAD` 限制，又"要么全成、要么全败"——传 500MB
//! 到 90% 断线，得从头再来。分片把"一次长事务"拆成"若干可独立重试的短事务"：
//! 断在哪、从哪续。
//!
//! ## 落盘布局
//! `<data_dir>/uploads/<upload_id>/{meta.json, part-00000, part-00001, …}`
//!
//! 与回收站走同一套思路：**逐条自描述目录、不维护全局索引**——没有"索引与实体
//! 不一致"的窗口，中止就是删目录。已上传分片靠**扫目录**得出，因此面板重启后
//! 续传能力自然还在（不需要把状态放内存）。
//!
//! ## 安全纪律
//! 1. `upload_id` 由服务端生成、字符集锁死 `[0-9a-f-]`；外部传入的 id 过同一套校验
//!    （它会参与路径拼接，必须杜绝 `../`）；
//! 2. **完成时目标路径重新走完整沙箱**（`files::resolve_new`）：`meta.json` 是磁盘上
//!    的普通文件，不能因为"是我们写的"就信任——被篡改的 meta 可以指向任意路径；
//! 3. **分片大小由服务端定档**：让客户端选分片大小，等于让它决定面板的内存占用；
//! 4. 合并后**核对字节数**，不符即删除目标并报错——宁可报错，也不留一个
//!    "大小不对但看起来正常"的文件；
//! 5. 会话归属校验：多用户下不能让 A 续传 B 的会话；对他人的会话**统一按不存在**
//!    处理（否则会话 id 可枚举）。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, files, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    http::StatusCode,
    Json,
};
use panel_core::PanelError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use crate::extract::PanelJson;

const UPLOAD_META: &str = "meta.json";
/// 分片大小：服务端定档（见模块头第 3 条）。
///
/// **必须 ≤ `middleware::BODY_LIMIT_UPLOAD`**，且分片路由必须挂在"放宽了 body 上限"
/// 的那个 router 上——否则分片会在进 handler 之前就被 axum 拒掉，表现为
/// **上传静默失败**（实测踩过：4MB 分片撞上 axum 默认的 2MB 上限，只有末片能过）。
/// 有单测钉住这个约束。
const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// 单个上传会话的总大小上限：分片是为了"传得可靠"，不是为了让磁盘被塞满
const MAX_TOTAL_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// 未完成会话保留时长，超时视为放弃
const SESSION_TTL_SECS: i64 = 24 * 3600;

#[derive(Debug, Serialize, Deserialize)]
struct UploadMeta {
    upload_id: String,
    /// 目标路径。**仅作记录**——完成时会重新走一遍沙箱校验
    path: String,
    size: u64,
    chunk_size: usize,
    created_at: i64,
    user_id: i64,
}

fn io_err(ctx: &str, e: std::io::Error) -> ApiError {
    ApiError::from(PanelError::Io(format!("{ctx}: {e}")))
}

fn uploads_root(state: &Shared) -> PathBuf {
    state.os.paths().data_dir().join("uploads")
}

fn session_dir(state: &Shared, id: &str) -> PathBuf {
    uploads_root(state).join(id)
}

/// 与回收站同一套 id 约定：纳秒时间戳 + 进程号，字符集 `[0-9a-f-]`。
/// 该串参与路径拼接，所以**在生成侧**就锁死字符集。
fn new_upload_id() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{ns:x}-{:x}", std::process::id())
}

/// 校验**外部传入**的 upload_id。
fn valid_upload_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// 分片文件名：定长序号，便于人工查看目录时保持顺序。
fn part_name(index: usize) -> String {
    format!("part-{index:05}")
}

fn total_chunks(size: u64) -> usize {
    (size as usize).div_ceil(CHUNK_SIZE)
}

async fn read_meta_at(dir: &Path) -> Option<UploadMeta> {
    let raw = tokio::fs::read(dir.join(UPLOAD_META)).await.ok()?;
    serde_json::from_slice(&raw).ok()
}

async fn write_meta(dir: &Path, m: &UploadMeta) -> ApiResult<()> {
    let bytes = serde_json::to_vec_pretty(m).map_err(|e| {
        ApiError::from(PanelError::Internal(format!("序列化上传元数据失败: {e}")))
    })?;
    tokio::fs::write(dir.join(UPLOAD_META), bytes)
        .await
        .map_err(|e| io_err("写入上传元数据失败", e))
}

/// 载入会话并校验**归属**。
///
/// 不属于当前用户时统一返回 NotFound（而不是 Forbidden）：会话 id 是从时间戳
/// 派生的，若用 403 区分"存在但不属于你"，等于给了一个枚举探测的接口。
/// owner 例外——它等价宿主管理员，文件沙箱对其本就无意义。
async fn load_session(
    state: &Shared, s: &crate::auth::Session, id: &str,
) -> ApiResult<UploadMeta> {
    if !valid_upload_id(id) {
        return Err(ApiError::bad_request("upload_id", "非法 upload_id"));
    }
    let meta = read_meta_at(&session_dir(state, id)).await.ok_or_else(|| {
        ApiError::from(PanelError::NotFound(format!("上传会话 {id}")))
    })?;
    if meta.user_id != s.user_id && s.role != "owner" {
        return Err(ApiError::from(PanelError::NotFound(format!("上传会话 {id}"))));
    }
    Ok(meta)
}

/// 清理超时的未完成会话。
///
/// 两个触发点（P2-1）：
/// ① `init` 开新上传时顺手做——启动后不必等一个周期就能回收历史残包；
/// ② 内置调度 `uploads.sweep`（1h 一次）——**这条才是主路径**：此前只有 ①，
///    长期没人开新上传的闲置面板永远不清理。
///
/// 保守原则不变：拿不到创建时间（meta 缺失）时用目录 mtime 兜底，仍拿不到就
/// **留着**——宁可下次再看，也不凭猜测删掉别人正在传的数据。
pub async fn sweep_expired(state: &Shared) {
    let root = uploads_root(state);
    let Ok(mut rd) = tokio::fs::read_dir(&root).await else { return };
    let now = crate::now_unix();
    while let Ok(Some(ent)) = rd.next_entry().await {
        let dir = ent.path();
        if !dir.is_dir() {
            continue;
        }
        let stale = match read_meta_at(&dir).await {
            Some(m) => now - m.created_at > SESSION_TTL_SECS,
            // 连 meta 都没有的目录：拿不到创建时间，用目录 mtime 兜底。
            // 宁可留着（下次再看），也不凭猜测删——删错的是别人正在传的数据。
            None => tokio::fs::metadata(&dir)
                .await
                .ok()
                .and_then(|md| md.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| now - d.as_secs() as i64 > SESSION_TTL_SECS)
                .unwrap_or(false),
        };
        if stale {
            let _ = tokio::fs::remove_dir_all(&dir).await;
        }
    }
}

// ─────────────── 端点 ───────────────

#[derive(Debug, Deserialize)]
pub struct InitReq {
    pub path: String,
    pub size: u64,
}

/// 开始一次分片上传。返回 `upload_id` 与服务端定档的分片大小。
pub async fn init(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<InitReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    if req.size == 0 {
        return Err(ApiError::bad_request(
            "size",
            "空文件请直接用 PUT /files/upload（分片没有意义）",
        ));
    }
    if req.size > MAX_TOTAL_BYTES {
        return Err(ApiError::bad_request(
            "size",
            format!("超过分片上传上限（{MAX_TOTAL_BYTES} 字节）"),
        ));
    }
    // 目标路径**先校验一次**：早失败，别让用户传完 10GB 才发现路径非法
    let target = files::resolve_new(&state, &s, &req.path)?;
    files::ensure_not_sensitive(&state, &target)?;

    // 保留这次"顺手清理"：启动后立刻回收历史残包，不必等第一个调度周期。
    sweep_expired(&state).await;

    let id = new_upload_id();
    let dir = session_dir(&state, &id);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| io_err("创建上传会话失败", e))?;
    let meta = UploadMeta {
        upload_id: id.clone(),
        path: req.path.clone(),
        size: req.size,
        chunk_size: CHUNK_SIZE,
        created_at: crate::now_unix(),
        user_id: s.user_id,
    };
    write_meta(&dir, &meta).await?;
    audit(&state, &s, "file.multipart.init", &req.path, "ok").await;
    Ok(ok(serde_json::json!({
        "upload_id": id,
        "chunk_size": CHUNK_SIZE,
        "total_chunks": total_chunks(req.size),
        "received": [],
    })))
}

#[derive(Debug, Deserialize)]
pub struct ChunkQ {
    pub upload_id: String,
    pub index: usize,
}

/// 上传单个分片。**大小必须精确匹配**——不符即拒。
///
/// 严格校验的理由：分片大小对不上说明客户端算错了偏移或中途断了，
/// 放过去只会在"合并后才字节数不符"时才发现，那时已经白传一整轮。
pub async fn chunk(
    State(state): State<Shared>, Auth(s): Auth,
    Query(q): Query<ChunkQ>, body: axum::body::Bytes,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let meta = load_session(&state, &s, &q.upload_id).await?;
    let total = total_chunks(meta.size);
    if q.index >= total {
        return Err(ApiError::bad_request(
            "index",
            format!("分片下标越界（共 {total} 片）"),
        ));
    }
    let expected = if q.index + 1 == total {
        (meta.size - (q.index as u64) * (meta.chunk_size as u64)) as usize
    } else {
        meta.chunk_size
    };
    if body.len() != expected {
        return Err(ApiError::bad_request(
            "body",
            format!("分片大小不符：第 {} 片期望 {expected} 字节，收到 {}", q.index, body.len()),
        ));
    }
    let dir = session_dir(&state, &q.upload_id);
    tokio::fs::write(dir.join(part_name(q.index)), &body)
        .await
        .map_err(|e| io_err("写入分片失败", e))?;
    Ok(StatusCode::NO_CONTENT)
}

/// 查询已上传的分片——**断点续传就靠它**。
pub async fn status(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_READ)?;
    let meta = load_session(&state, &s, &id).await?;
    let total = total_chunks(meta.size);
    let dir = session_dir(&state, &id);
    let mut received: Vec<usize> = Vec::new();
    for i in 0..total {
        if tokio::fs::symlink_metadata(dir.join(part_name(i))).await.is_ok() {
            received.push(i);
        }
    }
    Ok(ok(serde_json::json!({
        "upload_id": id,
        "path": meta.path,
        "size": meta.size,
        "chunk_size": meta.chunk_size,
        "total_chunks": total,
        "received": received,
    })))
}

/// 合并分片、落盘为目标文件。
pub async fn complete(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    let meta = load_session(&state, &s, &id).await?;
    let total = total_chunks(meta.size);
    let dir = session_dir(&state, &id);

    // 缺片 → 报错但**保留会话**，让客户端续传（清掉就等于逼它重传全部）
    let mut missing: Vec<usize> = Vec::new();
    let mut parts: Vec<PathBuf> = Vec::with_capacity(total);
    for i in 0..total {
        let p = dir.join(part_name(i));
        if tokio::fs::symlink_metadata(&p).await.is_ok() {
            parts.push(p);
        } else {
            missing.push(i);
        }
    }
    if !missing.is_empty() {
        return Err(ApiError::bad_request(
            "chunks",
            format!(
                "仍有 {} 片未上传（前几片：{:?}）",
                missing.len(),
                &missing[..missing.len().min(8)]
            ),
        ));
    }

    // **重新走沙箱**：meta.json 是磁盘上的普通文件，不因"是我们写的"就信任
    let target = files::resolve_new(&state, &s, &meta.path)?;
    files::ensure_not_sensitive(&state, &target)?;

    let written = state
        .os
        .files()
        .merge_chunks(&parts, &target)
        .await
        .map_err(ApiError::from)?;

    // 字节数不符 = 数据不可信。删掉目标，而不是留下一个"大小不对但看着正常"的文件。
    // 删除**失败必须说真话**：否则残留文件还在原地，用户却收到「已放弃」（以为已清理）。
    if written != meta.size {
        let cleanup = match state.os.files().remove(&target, false).await {
            Ok(()) => "，残留目标已删除".to_string(),
            Err(e) => format!("，且删除残留目标失败（{e}）——请手动清理 {}", target.as_path().display()),
        };
        return Err(ApiError::from(PanelError::Internal(format!(
            "合并后字节数 {written} 与声明 {} 不符，已放弃该次上传{cleanup}",
            meta.size
        ))));
    }

    let _ = tokio::fs::remove_dir_all(&dir).await;
    audit(&state, &s, "file.multipart.complete", &meta.path, "ok").await;
    Ok(ok(serde_json::json!({ "path": meta.path, "size": written })))
}

/// 中止上传并清理分片（幂等：会话已不存在也算成功）。
pub async fn abort(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::FILE_WRITE)?;
    if !valid_upload_id(&id) {
        return Err(ApiError::bad_request("upload_id", "非法 upload_id"));
    }
    // 已存在的会话要校验归属；不存在的直接当成功（幂等）
    if read_meta_at(&session_dir(&state, &id)).await.is_some() {
        let _ = load_session(&state, &s, &id).await?;
    }
    let dir = session_dir(&state, &id);
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err("中止上传失败", e)),
    }
    audit(&state, &s, "file.multipart.abort", &id, "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐⭐ **谎报警卫**（审计 P2-8）：字节数不符时「已放弃」的文案必须与清理结果一致。
    ///
    /// 曾是 `let _ = ...remove(...)`——删除残留失败也照报「已放弃」，用户以为
    /// 已清理、磁盘上却留着残文件。这类接线改动不会红任何行为测试（mock 的
    /// remove 恒 Ok，造不出失败路径），只能源码级断言。
    #[test]
    fn size_mismatch_cleanup_never_lies() {
        let src = include_str!("multipart.rs");
        // multipart.rs 只有一个尾部测试模块（本模块），split 取生产段安全。
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        // ① 旧谎报形态不得复活
        assert!(!code.contains("let _ = state.os.files().remove(&target"),
            "清理结果被丢弃——字节数不符时删除失败会谎报「已放弃」");
        // ② 清理结果必须分支处理
        assert!(code.contains("match state.os.files().remove(&target, false).await"),
            "remove 结果必须 match：成功与失败要走不同文案");
        // ③ 失败文案必须给出可操作的出路（手动清理 + 路径）
        assert!(code.contains("请手动清理"),
            "删除失败的文案必须说真话并给出手动清理路径");
    }

    #[test]
    fn upload_id_charset_is_locked_down() {
        let id = new_upload_id();
        assert!(valid_upload_id(&id), "生成的 id 必须自洽: {id}");
        for bad in ["../etc", "a/b", "", ".", "..", "x y"] {
            assert!(!valid_upload_id(bad), "必须拒绝: {bad:?}");
        }
        assert!(!valid_upload_id(&"a".repeat(65)));
    }

    #[test]
    fn chunk_count_and_last_chunk_size_are_exact() {
        // 整除：正好两片，两片都是整片
        assert_eq!(total_chunks((CHUNK_SIZE * 2) as u64), 2);
        // 余 1 字节：仍需第三片，且第三片只有 1 字节
        let size = (CHUNK_SIZE * 2 + 1) as u64;
        let total = total_chunks(size);
        assert_eq!(total, 3);
        let last = size - (total as u64 - 1) * CHUNK_SIZE as u64;
        assert_eq!(last, 1, "末片余量必须精确，否则分片校验会永远对不上");
    }

    #[test]
    fn part_names_sort_in_order() {
        // 定长序号：字典序与上传顺序一致（人工排查目录时不会看错）
        let mut names: Vec<String> = (0..12).rev().map(part_name).collect();
        names.sort();
        assert_eq!(names.first().unwrap(), &part_name(0));
        assert_eq!(names.last().unwrap(), &part_name(11));
    }

    // ⚠ 这是**常量规格锁**（改常量即红），不是恒真断言：clippy 的
    // `assertions_on_constants` 对"两个 const 比较"一律报警，但它看不出我们
    // 恰恰要锁住这些常量不被悄悄改掉。
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn chunk_size_must_fit_the_relaxed_body_limit() {
        // 分片路由挂在放宽了 body 上限的 router 上（file_upload_r）。若 CHUNK_SIZE
        // 超过该上限，**每一片都会在进 handler 之前被 axum 拒掉**，而且表现为
        // "上传静默失败"——这个坑实测踩过（4MB 分片撞上 axum 默认的 2MB 上限，
        // 只有 2MB 的末片能过，症状是"完整上传时永远缺前几片"）。
        // 改分片大小的人，请先看这条断言。
        assert!(
            CHUNK_SIZE <= crate::middleware::BODY_LIMIT_UPLOAD,
            "CHUNK_SIZE({CHUNK_SIZE}) 超过 BODY_LIMIT_UPLOAD({})：分片会被 axum 提前拒掉",
            crate::middleware::BODY_LIMIT_UPLOAD
        );
        // 也不能太小：分片过碎会让请求数爆炸（10GB 用 64KB 分片 = 16 万个请求）
        assert!(CHUNK_SIZE >= 1024 * 1024, "分片过小会让请求数爆炸");
    }
}
