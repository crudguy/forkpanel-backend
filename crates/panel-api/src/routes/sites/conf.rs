use super::*;
use crate::extract::PanelJson;

//
// 背景：面板托管的配置是「表单 → render → validate → 下发」的产物。手动维护
// （016 迁移的 manual_conf）让用户直接改这份产物成为一等状态：
// - GET  conf：读取落盘内容（路径取**落库 conf_path**，绝不接受前端传路径）
// - PUT  conf：原始写入 → 此后表单保存不再覆盖（仅 owner；写入前必过 nginx -t）
// - POST conf/restore：恢复面板托管（按表单重新渲染覆盖，清零 manual_conf）
//
// 017 迁移再补一拍：conf_snapshot 指纹让「表单已改、文件没跟上」的**静默**分叉
// 变成可见状态（conf_stale / 「未同步」），并在覆盖手改内容前自动备份。

/// 解析站点配置的写盘目标路径并做纵深校验（`conf_put` / `conf_rollback` 共用——
/// 同一约束两条路径必须同源，历史上「两路漏配」是本项目最高发 bug 之一）。
///
/// 规则：优先落库 `conf_path`（曾下发过，可能带着旧域名文件名）；从未下发则按
/// provider 的命名规则推导（与 render 同源，**绝不由前端指定路径**）。
/// 父目录必须就是 Web 配置目录且路径不含 `..`——防被篡改的库值把写操作引到别处。
fn resolve_conf_target(state: &Shared, row: &RawSite) -> ApiResult<PathBuf> {
    let target: PathBuf = match row
        .conf_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        Some(p) => PathBuf::from(p),
        None => {
            let domains: Vec<String> = serde_json::from_str(&row.domains).unwrap_or_default();
            if domains.is_empty() {
                return Err(ApiError::bad_request("conf", "站点缺少域名，无法推导配置文件路径"));
            }
            state.os.webserver().conf_path(&domains)
        }
    };
    let conf_dir = state.os.paths().web_conf_dir();
    let parent_ok = target.parent().map(|p| p == conf_dir).unwrap_or(false)
        && !target
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
    if !parent_ok {
        return Err(ApiError::bad_request(
            "conf_path",
            "落库配置路径不在 Web 配置目录内，拒绝写入",
        ));
    }
    Ok(target)
}

/// 覆盖手动配置前的备份：复制到 `<data_dir>/conf-backups/<文件名>.<unix>.bak`，
/// 同前缀仅保留最近 10 份（`prune_keep_newest` 按 mtime 判新旧）。
///
/// 返回备份路径；文件不存在 / 任何步骤失败返回 None——备份是安全网而非校验步骤，
/// 失败**不阻断**「重新生成 / 恢复托管 / 停用」主流程（响应 backup=null，前端文案据实）。
/// 放在业务层而不是 provider：provider 抽象的是「渲染/下发」，备份是面板的策略
/// （保留几份、放哪、怎么命名），与具体 Web 服务器无关。
pub(super) async fn backup_manual_conf(state: &Shared, conf_path: &Path) -> Option<PathBuf> {
    let file_name = conf_path.file_name()?.to_str()?.to_string();
    if tokio::fs::metadata(conf_path).await.is_err() {
        return None; // 文件不存在（或不可读）——无事可备
    }
    let dir = state.os.paths().data_dir().join("conf-backups");
    tokio::fs::create_dir_all(&dir).await.ok()?;
    // 同一秒内多次备份会撞名：撞了顺延序号，绝不覆盖既有备份
    let ts = crate::now_unix();
    let mut dest = dir.join(format!("{file_name}.{ts}.bak"));
    let mut n = 1u32;
    while tokio::fs::metadata(&dest).await.is_ok() {
        dest = dir.join(format!("{file_name}.{ts}.{n}.bak"));
        n += 1;
    }
    tokio::fs::copy(conf_path, &dest).await.ok()?;
    // 清理放在副本写好**之后**：先保新、再清旧（反过来会在复制失败时白删旧备份）
    let dir2 = dir.clone();
    let prefix = format!("{file_name}.");
    let _ = tokio::task::spawn_blocking(move || {
        panel_os::fs::prune_keep_newest(&dir2, &prefix, 10)
    })
    .await;
    Some(dest)
}

/// 配置内容指纹（SHA-256 十六进制）——版本去重与「当前版本」标记用。
pub(super) fn conf_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    const T: &[u8; 16] = b"0123456789abcdef";
    let d = Sha256::digest(content.as_bytes());
    let mut s = String::with_capacity(64);
    for &x in d.iter() {
        s.push(T[(x >> 4) as usize] as char);
        s.push(T[(x & 0xf) as usize] as char);
    }
    s
}

/// 给站点配置留档一版（去重 + 每站保留最新 20 版）。
///
/// 调用点 = 全部写入口：apply 正常下发 / conf_restore 重新渲染 / conf_put 手动
/// 保存 / conf_rollback 回滚（回滚前先把现场留档）。与**最新版**内容相同（hash
/// 相等）不重复入库——反复「保存并应用」不会堆出一串一模一样的版本。
///
/// `fingerprint` 记录「这版内容对应的部署指纹」（可空）：回滚时若某版的指纹恰好
/// 等于当前表单指纹，说明那份内容正是表单产物 → 回滚后站点可回「面板托管」；
/// 否则按手动维护处理（快照=版本指纹，表单再分叉时「未同步」照常亮）。
///
/// 失败不阻断主流程（版本链是安全网，与 `backup_manual_conf` 同哲学）——
/// 但必须出声：静默丢版本链比报错更危险。
pub(super) async fn archive_conf_version(
    state: &Shared,
    site_id: i64,
    content: &str,
    fingerprint: Option<String>,
    source: &str,
    operator: &str,
) {
    let hash = conf_hash(content);
    let content = content.to_string();
    // 闭包要 move 走一个 String；原 `source`（&str）留着给收尾日志用，
    // 否则日志会借用已 move 的值（E0382）。
    let source_in = source.to_string();
    let operator = operator.to_string();
    let res = state
        .db
        .exec(move |conn| {
            // 去重：与最新版相同则跳过（避免反复 apply 堆同内容版本）
            let last: Option<String> = conn
                .query_row(
                    "SELECT hash FROM site_conf_versions WHERE site_id = ?1 ORDER BY id DESC LIMIT 1",
                    [site_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            if last.as_deref() == Some(hash.as_str()) {
                return Ok(panel_db::WriteAck { rows_changed: 0 });
            }
            conn.execute(
                "INSERT INTO site_conf_versions(site_id, content, hash, fingerprint, source, operator, created_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![site_id, content, hash, fingerprint, source_in, operator, crate::now_unix()],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            // 每站保留最新 20 版（写入后立即裁剪，防无限增长）
            conn.execute(
                "DELETE FROM site_conf_versions WHERE site_id = ?1 AND id NOT IN (
                     SELECT id FROM site_conf_versions WHERE site_id = ?1 ORDER BY id DESC LIMIT 20)",
                [site_id],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await;
    if let Err(e) = res {
        eprintln!("[sites] archive_conf_version(site={site_id}, source={source}) 失败: {e}");
    }
}

/// 读取站点当前的 Web 服务器配置文件内容。
///
/// 路径唯一来源是**落库的 `conf_path`**（由 apply/patch 写入，不接受前端输入——
/// 否则就成了「读任意文件」的越权面）。尚未下发 / 文件缺失时如实返回 `content: null`。
/// 站点日志类型参数：`access` | `error`。
#[derive(Debug, Deserialize)]
pub struct SiteLogKindQ {
    #[serde(default)]
    pub kind: Option<String>,
}

/// 该站点的日志文件路径（未开启独立日志 → None）。
fn site_log_file(row: &RawSite, state: &Shared, kind: &str) -> Option<std::path::PathBuf> {
    let domains: Vec<String> = serde_json::from_str(&row.domains).unwrap_or_default();
    let (a, e) = site_log_paths(state, &domains, row.log_access != 0, row.log_error != 0);
    if kind == "error" { e } else { a }
}

/// 下载站点日志（021）。走 `location` 直下即可（cookie 认证，无需 CSRF），
/// 与根证书下载同范式；未开启独立日志时 404 并给出原因。
pub async fn log_download(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Query(q): Query<SiteLogKindQ>,
) -> ApiResult<axum::response::Response> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    let kind = q.kind.as_deref().unwrap_or("access");
    let p = site_log_file(&row, &state, kind)
        .ok_or_else(|| ApiError::bad_request("kind", "该站点未开启独立日志（先在编辑弹窗里开启）"))?;
    let body = match tokio::fs::read(&p).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::bad_request("kind", "日志文件尚未生成（站点还没有请求）"))
        }
        Err(e) => return Err(ApiError::from(PanelError::Io(e.to_string()))),
    };
    let name = format!(
        "{}-{}.log",
        row.name,
        if kind == "error" { "error" } else { "access" }
    );
    Ok(axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/plain; charset=utf-8")
        .header(
            "content-disposition",
            format!("attachment; filename=\"{name}\""),
        )
        .body(axum::body::Body::from(body))
        .map_err(|e| ApiError::from(PanelError::Internal(e.to_string())))?)
}

/// 清空站点日志（021）：截断而非删除——删除会让正在写入的 nginx worker 继续往
/// 已 unlink 的 inode 写（磁盘不释放、文件"失踪"），截断才是运维上的正确做法。
pub async fn log_clear(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<SiteLogClearReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    let kind = req.kind.clone().unwrap_or_else(|| "access".to_string());
    let p = site_log_file(&row, &state, &kind)
        .ok_or_else(|| ApiError::bad_request("kind", "该站点未开启独立日志（先在编辑弹窗里开启）"))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&p)
        .map_err(|e| ApiError::from(PanelError::Io(e.to_string())))?;
    let kref: &'static str = if kind == "error" { "error" } else { "access" };
    audit(&state, &s, "site.log.clear", &id.to_string(), kref).await;
    Ok(ok(serde_json::json!({ "path": p.display().to_string() })))
}

/// 清空日志的请求体。
#[derive(Debug, Deserialize)]
pub struct SiteLogClearReq {
    pub kind: Option<String>,
}

pub async fn conf_get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    let path = row
        .conf_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    let content = match path {
        Some(p) => match tokio::fs::read_to_string(p).await {
            Ok(c) => Some(c),
            // 文件被外部删除：如实返回「无内容」，而不是 404 把弹窗打成错误态
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(ApiError::from(PanelError::Io(format!("read {p}: {e}")))),
        },
        None => None,
    };
    Ok(ok(serde_json::json!({
        "path": path,
        "content": content,
        "manual": row.manual_conf != 0,
        // 未同步（017）：表单部署相关字段与「文件上次落盘时的指纹」不一致。
        // 配置区据此显示警示条 + 一键「重新生成配置」。
        "stale": conf_stale_of(&row),
        // 外部修改（020）：磁盘内容与最后一次留档不一致 ⇒ 文件在面板之外被改过
        "external": external_of(&row).await,
    })))
}

/// `PUT` 的请求体：完整配置片段（与落盘文件同构——server / map 等 http 上下文片段）。
#[derive(Debug, Deserialize)]
pub struct ConfPutReq {
    pub content: String,
}

/// 保存站点原始配置（进入 / 保持「手动维护」）。
///
/// ⚠ 写入面等价于「一台 root 改 nginx」——仅 **owner** 可调用，且校验失败尝试也留审计。
/// 顺序与 apply 完全一致：**先 `nginx -t` 校验 → 原子替换 → reload**；校验不过旧文件纹丝不动。
/// 成功后站点置 `manual_conf=1`：此后表单「保存并应用」不再覆盖该文件（见 016 迁移）。
pub async fn conf_put(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<ConfPutReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if s.role != "owner" {
        return Err(ApiError::forbidden("owner"));
    }
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    if row.enabled == 0 {
        return Err(ApiError::bad_request(
            "enabled",
            "站点已停用（配置已从 Web 服务器移除）；请先启用后再编辑原始配置",
        ));
    }
    if req.content.trim().is_empty() {
        return Err(ApiError::bad_request("content", "配置内容不能为空"));
    }
    if req.content.len() > 1_048_576 {
        return Err(ApiError::bad_request("content", "配置内容超过 1 MiB 上限"));
    }

    // 目标路径 + 纵深校验：与 conf_rollback 共用同一函数（两路同源）
    let target = resolve_conf_target(&state, &row)?;

    // 校验（独立 wrapper 跑 nginx -t，不触碰线上配置）→ 失败 40002 + 原始 stderr
    if let Err(e) = state.os.webserver().validate(&req.content).await {
        audit(&state, &s, "site.conf.edit", &id.to_string(), "fail").await;
        return Err(ApiError::from(PanelError::ConfigInvalid { detail: e.to_string() }));
    }
    // 原子替换 + reload；reload 失败时配置已写入（语法已验过，可恢复）——与 apply 同口径
    state.os.webserver().deploy(&target, &req.content).await?;
    finish_deploy(&state, id, false).await?;

    let path_str = target.display().to_string();
    let path_db = path_str.clone();
    // 指纹 = 当前表单值：此刻「文件已对齐表单」（文件=用户文本 + 表单=库值）。
    // 未来表单再改时，与这份文件分叉 → 未同步提示由此成立（017 迁移）。
    let snap_db = fingerprint_of(&row);
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET manual_conf = 1, conf_path = ?1, conf_snapshot = ?3 WHERE id = ?2",
                rusqlite::params![path_db, id, snap_db],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.conf.edit", &id.to_string(), "ok").await;
    // 版本留档（018）：手动保存 = 一条新的「已生效历史」（source=manual）。
    // 指纹与上面 conf_snapshot 同源（保存后：文件=用户文本、快照=当前表单——
    // 两者此刻配对；未来表单再改，「未同步」照常亮起）。
    archive_conf_version(&state, id, &req.content, Some(fingerprint_of(&row)), "manual", &s.username)
        .await;
    Ok(ok(serde_json::json!({ "path": path_str, "manual": true, "stale": false, "reloaded": true })))
}

/// 恢复面板托管：按表单规格重新渲染覆盖（丢弃手工内容），清零 `manual_conf`。
///
/// 与 `patch` 的「重新启用下发」同一条渲染路径（`render_spec_for_row`，自带校验）。
/// 停用站点没有配置文件可恢复——只清零标记（下次启用按表单渲染）。
pub async fn conf_restore(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if s.role != "owner" {
        return Err(ApiError::forbidden("owner"));
    }
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;

    // 停用站点：无文件可恢复，仅清零标记（启用路径会按表单重新渲染）
    if row.enabled == 0 {
        state
            .db
            .exec(move |conn| {
                conn.execute(
                    "UPDATE sites SET manual_conf = 0, conf_snapshot = NULL WHERE id = ?1",
                    [id],
                )
                .map(|n| panel_db::WriteAck { rows_changed: n })
                .map_err(|e| PanelError::Database(e.to_string()))
            })
            .await?;
        audit(&state, &s, "site.conf.restore", &id.to_string(), "ok").await;
        return Ok(ok(serde_json::json!({
            "path": serde_json::Value::Null,
            "manual": false,
            "deployed": false,
            "reloaded": false,
        })));
    }

    let domains: Vec<String> = serde_json::from_str(&row.domains).unwrap_or_default();
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "站点缺少域名，无法重新渲染配置"));
    }
    // 覆盖前备份手改内容：在渲染**之前**做——无论新文件同名覆盖、还是改名后清孤儿，
    // 旧内容都已经进了备份（安全网，失败不阻断）。
    let mut backup_path: Option<String> = None;
    if row.manual_conf != 0 {
        if let Some(cp) = row.conf_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            if let Some(b) = backup_manual_conf(&state, Path::new(cp)).await {
                audit(&state, &s, "site.conf.backup", &id.to_string(), "ok").await;
                backup_path = Some(b.display().to_string());
            }
        }
    }
    let (target, rendered) = render_spec_for_row(&state, &row, &domains, &row.root).await?;
    state.os.webserver().deploy(&target, &rendered).await?;
    let pruned = prune_stale_conf(&state, row.conf_path.as_deref(), &target).await?;
    finish_deploy(&state, id, pruned).await?;

    let path_str = target.display().to_string();
    let path_db = path_str.clone();
    // 指纹 = 当前表单值（渲染正是按它做的）→ 恢复托管后天然「已同步」
    let snap_db = fingerprint_of(&row);
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET manual_conf = 0, conf_path = ?1, conf_snapshot = ?3 WHERE id = ?2",
                rusqlite::params![path_db, id, snap_db],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.conf.restore", &id.to_string(), "ok").await;
    // 版本留档（018）：重新生成 = 按表单渲染的产物（source=regen）
    archive_conf_version(&state, id, &rendered, Some(fingerprint_of(&row)), "regen", &s.username)
        .await;
    Ok(ok(serde_json::json!({
        "path": path_str,
        "manual": false,
        "stale": false,
        "deployed": true,
        "reloaded": true,
        "backup": backup_path,
    })))
}

// ─────────────── 站点配置：版本历史 / 回滚（018 迁移） ───────────────
//
// 版本链是配置生命周期的另一半：写入口（apply/regen/manual/rollback）每次都把
// 生效内容留档（同 hash 去重、每站保留 20 版）。回滚 = 选任一天历史版本作为新的
// 「当前文件」：nginx -t 校验 → 原子替换 → reload；被恢复的内容与被你替换掉的
// 现场都会进版本链。回滚后自动定态：版本指纹 == 当前表单指纹 ⇒ 内容正是表单
// 产物 → 回「面板托管」；否则转「手动维护」（表单再分叉时「未同步」照常亮）。

/// 外部修改检测（020）：磁盘内容与「最后一次留档的版本」不一致 ⇒ 文件在面板之外
/// 被改动过。
///
/// **不静默覆盖**是刻意的：面板无从判断一次外部改动是用户有意、脚本误写还是攻击，
/// 所以只如实标记，把决策交回用户（重新生成覆盖 / 改成自定义片段 / 手动接管）。
/// 无留档（`last_ver_hash` 为 NULL）时无从判定，返回 false——宁可不报，也不谎报。
pub(super) async fn external_of(r: &RawSite) -> bool {
    let Some(p) = r.conf_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
        return false;
    };
    let Some(last) = r.last_ver_hash.as_deref() else { return false };
    match tokio::fs::read_to_string(p).await {
        Ok(c) => conf_hash(&c) != last,
        // 文件被删 / 读不了：交给「未下发 / 缺失」那套语义处理，不算外部修改
        Err(_) => false,
    }
}

/// 版本历史列表：倒序返回最近 20 版**元数据**（不含正文——正文按需单取，
/// 避免一次拉 20 份全文）。每项附 `current`：该版内容 == 磁盘当前内容。
pub async fn conf_versions(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    // 磁盘当前内容 hash（文件缺失 → None：所有版本 current=false，如实呈现）
    let cur_hash: Option<String> = match row
        .conf_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        Some(p) => tokio::fs::read_to_string(p)
            .await
            .ok()
            .map(|c| conf_hash(&c)),
        None => None,
    };
    let items: Vec<serde_json::Value> = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, hash, source, operator, created_at, LENGTH(content)
                     FROM site_conf_versions WHERE site_id = ?1 ORDER BY id DESC LIMIT 20",
                )
                .map_err(db_err)?;
            let rows = st
                .query_map([id], |r| {
                    let hash: String = r.get(1)?;
                    Ok(serde_json::json!({
                        "id": r.get::<_, i64>(0)?,
                        "hash": hash,
                        "source": r.get::<_, String>(2)?,
                        "operator": r.get::<_, String>(3)?,
                        "created_at": r.get::<_, i64>(4)?,
                        "size": r.get::<_, i64>(5)?,
                        "current": cur_hash.as_deref() == Some(hash.as_str()),
                    }))
                })
                .map_err(db_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(db_err)?);
            }
            Ok(out)
        })
        .await?;
    Ok(ok(serde_json::json!({ "items": items })))
}

/// 单个历史版本的正文（回滚前预览用）。版本必须属于本站点（`AND site_id = ?2`，
/// 防跨站读取——版本 id 是全局自增，不校验归属就成越权面）。
pub async fn conf_version_get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath((id, vid)): AxPath<(i64, i64)>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    let v = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT id, content, hash, source, operator, created_at
                 FROM site_conf_versions WHERE id = ?1 AND site_id = ?2",
                rusqlite::params![vid, id],
                |r| {
                    Ok(serde_json::json!({
                        "id": r.get::<_, i64>(0)?,
                        "content": r.get::<_, String>(1)?,
                        "hash": r.get::<_, String>(2)?,
                        "source": r.get::<_, String>(3)?,
                        "operator": r.get::<_, String>(4)?,
                        "created_at": r.get::<_, i64>(5)?,
                    }))
                },
            )
            .optional()
            .map_err(db_err)
        })
        .await?;
    let Some(v) = v else {
        return Err(ApiError::not_found("version"));
    };
    Ok(ok(v))
}

/// 回滚定态：决定回滚后站点归「面板托管」还是「手动维护」。
///
/// 判据 = 版本留档时记录的部署指纹 vs **当前**表单指纹：
/// - 相等 ⇒ 这版内容正是当前表单的产物（例如先改了表单没下发、又想退回上一版
///   渲染结果）→ 回「面板托管」，快照=表单指纹（天然已同步）。
/// - 否则 ⇒ 转「手动维护」，快照=版本指纹；版本无指纹（旧行/外部来源）则留
///   NULL——「未同步」照常亮起，向提示的一侧倾斜（与 017 同哲学）。
pub(super) fn rollback_state(ver_fp: Option<&str>, form_fp: &str) -> (i32, Option<String>) {
    if ver_fp == Some(form_fp) {
        (0, Some(form_fp.to_string()))
    } else {
        (1, ver_fp.map(str::to_string))
    }
}

/// 回滚请求体。
#[derive(Debug, Deserialize)]
pub struct ConfRollbackReq {
    /// 目标版本 id（`site_conf_versions.id`）
    pub version_id: i64,
}

/// 回滚到指定历史版本。⚠ 与 `conf_put` 同为「root 级写入面」，仅 owner。
///
/// 顺序：nginx -t 校验（失败 40002 + 原始 stderr，旧文件纹丝不动）→ 现场留档
/// （磁盘当前内容进版本链，源=rollback）→ 原子替换 → reload → 自动定态 + 留档。
pub async fn conf_rollback(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<ConfRollbackReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    if s.role != "owner" {
        return Err(ApiError::forbidden("owner"));
    }
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let row = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("site"))?;
    if row.enabled == 0 {
        return Err(ApiError::bad_request(
            "enabled",
            "站点已停用（配置已从 Web 服务器移除）；请先启用后再回滚配置",
        ));
    }
    // 目标版本（必须属于本站点）
    let vid = req.version_id;
    let ver = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT content, fingerprint FROM site_conf_versions WHERE id = ?1 AND site_id = ?2",
                rusqlite::params![vid, id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .optional()
            .map_err(db_err)
        })
        .await?;
    let Some((content, ver_fp)) = ver else {
        return Err(ApiError::not_found("version"));
    };
    // 校验（独立 wrapper 跑 nginx -t，不触碰线上）→ 失败 40002 + 原始 stderr
    if let Err(e) = state.os.webserver().validate(&content).await {
        audit(&state, &s, "site.conf.rollback", &id.to_string(), "fail").await;
        return Err(ApiError::from(PanelError::ConfigInvalid {
            detail: e.to_string(),
        }));
    }
    let target = resolve_conf_target(&state, &row)?;
    // 现场留档：磁盘当前内容进版本链（source=rollback；与最新版相同则自动去重）。
    // 外部手改（面板不知情）的内容也由此获得一条可回溯记录。指纹沿用站点快照
    // ——它记录的正是「这版文件对应的部署指纹」。
    if let Ok(cur) = tokio::fs::read_to_string(&target).await {
        archive_conf_version(&state, id, &cur, row.conf_snapshot.clone(), "rollback", &s.username)
            .await;
    }
    // 原子替换 + reload（reload 失败时配置已写入、语法已验过，可恢复——与 apply 同口径）
    state.os.webserver().deploy(&target, &content).await?;
    finish_deploy(&state, id, false).await?;
    // 自动定态（判据见 `rollback_state` 与其单测）
    let form_fp = fingerprint_of(&row);
    let (manual_new, snap_new) = rollback_state(ver_fp.as_deref(), &form_fp);
    let path_str = target.display().to_string();
    let path_db = path_str.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE sites SET manual_conf = ?3, conf_path = ?1, conf_snapshot = ?4 WHERE id = ?2",
                rusqlite::params![path_db, id, manual_new, snap_new],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "site.conf.rollback", &id.to_string(), "ok").await;
    // 被恢复的内容也进版本链（指纹继承版本）：列表最新 = 当前磁盘事实
    archive_conf_version(&state, id, &content, ver_fp, "rollback", &s.username).await;
    Ok(ok(serde_json::json!({
        "path": path_str,
        "manual": manual_new != 0,
        // 定态后 manual=1 时快照（版本指纹）≠ 当前表单指纹，恒「未同步」——如实报告
        "stale": manual_new != 0,
        "deployed": true,
        "reloaded": true,
        "restored_from": req.version_id,
    })))
}

/// 站点日志（SSE）：`kind=access|error`，跟随该站点的 nginx 日志文件。
#[derive(Debug, Deserialize)]
pub struct SiteLogQ {
    pub kind: Option<String>,
    pub filter: Option<String>,
    pub limit: Option<usize>,
}

pub async fn logs(
    State(state): State<Shared>,
    MaybeAuth(session): MaybeAuth,
    AxPath(id): AxPath<i64>,
    Query(q): Query<SiteLogQ>,
) -> axum::response::Response {
    let Some(s) = session else { return ApiError::unauthorized().into_response() };
    if crate::auth::require(&s, perm::SITE_VIEW).is_err() {
        return ApiError::forbidden(perm::SITE_VIEW).into_response();
    }
    if !state.capabilities.get(cap_keys::LOGS_READ).map(|c| c.supported).unwrap_or(false) {
        return ApiError::unsupported("logs.read").into_response();
    }
    let site = match fetch_one(&state, id).await {
        Ok(Some(x)) => x,
        Ok(None) => return ApiError::not_found("site").into_response(),
        Err(e) => return ApiError::from(e).into_response(),
    };
    let domains: Vec<String> = serde_json::from_str(&site.domains).unwrap_or_default();
    let stem = slug(domains.first().map(|s| s.as_str()).unwrap_or("site"));
    let which = q.kind.as_deref().unwrap_or("access");
    let (kind, seg) = if which == "error" {
        (panel_os::LogSourceKind::SiteError, "error")
    } else {
        (panel_os::LogSourceKind::SiteAccess, "access")
    };
    let src = panel_os::LogSource {
        id: format!("site:{stem}/{seg}"),
        label: format!("{} · {}", site.name, which),
        kind,
    };
    // 站点日志流契约无 level 参数（access 无级别、error 已按 kind 区分）→ 传 None
    crate::sse::follow_source(state.clone(), src, q.filter, None, q.limit.unwrap_or(200)).await
}


