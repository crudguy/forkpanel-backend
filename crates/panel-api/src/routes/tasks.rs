//! 任务中心 API（供前端轮询与 SSE 之外的补充场景）。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    Json,
};
use panel_core::{PanelError, Result};
use rusqlite::OptionalExtension;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ListQ {
    pub state: Option<String>,
    pub limit: Option<usize>,
}

/// `limit` 的语义（前端分页是**纯客户端切片**，这里的上限必须覆盖它的最大档位，
/// 否则用户选「每页 100 / 全部」时拿到的仍是 50 行，且 `total` 也算错）：
///
/// - 缺省 = [`DEFAULT_LIST_LIMIT`]（保持老调用方行为不变）
/// - `0` = 不限条数，仅受 [`MAX_LIST_LIMIT`] 兜底（对应前端「全部」档）
/// - 其余 = 取 `min(limit, MAX_LIST_LIMIT)`
///
/// 行为与 `state` 过滤都下推到 SQL：此前是先 `LIMIT 50` 再在内存里过滤，
/// 于是「筛选 failed」只能看到最近 50 条里的失败任务，更早的失败被静默丢掉。
const DEFAULT_LIST_LIMIT: usize = 50;
const MAX_LIST_LIMIT: usize = 1000;

/// 把查询参数解析成实际生效的行数上限（0 = 不限）。
/// 抽成纯函数是为了能测：原先 `test` 里的 `list_limit_is_capped` 断言的是
/// `assert_eq!(200, 200)`——自证式假测试，改动实现它也不会变红。
fn effective_limit(raw: Option<usize>) -> usize {
    match raw {
        None => DEFAULT_LIST_LIMIT,
        Some(0) => MAX_LIST_LIMIT,
        Some(n) => n.min(MAX_LIST_LIMIT),
    }
}

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<ListQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::TASK_VIEW)?;
    let limit = effective_limit(q.limit) as i64;
    let filter = q.state.clone();
    let rows = state.pool.with(move |conn| {
        // state 过滤走 SQL（`?2 IS NULL OR state = ?2`），保证「最近 N 条满足筛选」而不是
        // 「最近 N 条里碰巧满足筛选」。
        let mut st = conn.prepare(
            "SELECT id, task_id, kind, state, progress, started_at, finished_at, exit_code, output_path
             FROM task_runs WHERE (?2 IS NULL OR state = ?2)
             ORDER BY id DESC LIMIT ?1",
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map(rusqlite::params![limit, filter], |r| Ok((
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
            r.get::<_, String>(3)?, r.get::<_, i32>(4)?, r.get::<_, Option<i64>>(5)?,
            r.get::<_, Option<i64>>(6)?, r.get::<_, Option<i32>>(7)?,
            r.get::<_, Option<String>>(8)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;

    let dtos: Vec<_> = rows.into_iter()
        .map(|(id, tid, kind, st, prog, sa, fa, ec, op)| serde_json::json!({
            "id": id, "key": tid, "kind": kind, "state": st, "progress": prog,
            "started_at": sa, "finished_at": fa, "exit_code": ec,
            "output_path": op,
            // 中断任务需要人工确认：UI 必须标红
            "needs_human": st == "interrupted",
        }))
        .collect();
    Ok(ok(dtos))
}

pub async fn cancel(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::TASK_MANAGE)?;
    // 先确认任务存在且**处于可取消状态**：`TaskRunner::cancel` 只 UPDATE ...
    // WHERE state IN ('queued','running') 且**丢弃 rows_changed**，对不存在的 id 也返回 Ok
    // ⇒ 不做这层检查，"取消一个不存在的任务"会**报成功**（canceled: true），
    // "取消一个已结束的任务"同样报成功——两种假成功（UI 会显示"已取消"）。
    let st = state.pool.with(move |conn| {
        conn.query_row("SELECT state FROM task_runs WHERE id = ?1", rusqlite::params![id], |r| r.get::<_, String>(0))
            .optional()
            .map_err(|e| PanelError::Database(e.to_string()))
    }).await?;
    let Some(st) = st else {
        return Err(ApiError::not_found(format!("task {id}")));
    };
    if !matches!(st.as_str(), "queued" | "running") {
        return Err(ApiError::conflict(format!("任务已结束（{st}），无法取消")));
    }
    // 只置状态位；任务体在检查点优雅退出（强杀会留下半个副作用）
    state.tasks.cancel(id).await.map_err(ApiError::from)?;
    audit(&state, &s, "task.cancel", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "id": id, "canceled": true })))
}

/// 读取任务输出文件。**走文件而非数据库**（实测 stdout 入库会让体积失控）。
#[derive(Debug, Deserialize)]
pub struct OutputQ { pub lines: Option<usize> }

pub async fn output(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    Query(q): Query<OutputQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::TASK_VIEW)?;
    let n = q.lines.unwrap_or(200).min(2000);
    let path = state.pool.with(move |conn| {
        conn.query_row("SELECT output_path FROM task_runs WHERE id = ?1",
                       rusqlite::params![id], |r| r.get::<_, Option<String>>(0))
            .optional()
            .map_err(|e| PanelError::Database(e.to_string()))
    }).await?;

    // 任务不存在 ⇒ 404（与 `GET /tasks/{id}` 同一口径）。此前把"行不存在"当成
    // 数据库错误（60000），而"任务存在但没有输出文件"才是 200 + 空 lines——
    // 两种情况混在一起，调用方分不清"任务没了"和"任务没输出"。
    let Some(path) = path else {
        return Err(ApiError::not_found(format!("task {id}")));
    };
    let Some(p) = path else {
        return Ok(ok(serde_json::json!({ "id": id, "lines": [], "note": "无输出文件" })));
    };

    // 尾部读取：只取最后 n 行，不把整个文件读进内存
    let content = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
        let s = std::fs::read_to_string(&p)
            .map_err(|e| PanelError::Io(format!("read output: {e}")))?;
        let all: Vec<&str> = s.lines().collect();
        let start = all.len().saturating_sub(n);
        Ok(all[start..].iter().map(|x| x.to_string()).collect())
    }).await.map_err(|e| PanelError::Internal(e.to_string()))??;

    Ok(ok(serde_json::json!({ "id": id, "lines": content })))
}

// ─────────────── 单任务详情 ───────────────

/// 单任务详情：列表已含全部列，这里补**派生字段**（duration_secs）并支持
/// 按 id 单点轮询（前端弹层对 running 任务每 2s 拉一次进度，不必重拉全表）。
/// 不虚构参数/历史字段——task_runs 表没有 params 列，契约已按实态对齐。
pub async fn get(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::TASK_VIEW)?;
    let row = state.pool.with(move |conn| {
        conn.query_row(
            "SELECT id, task_id, kind, state, progress, started_at, finished_at, exit_code, output_path
             FROM task_runs WHERE id = ?1",
            rusqlite::params![id],
            |r| Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, i32>(4)?, r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<i64>>(6)?, r.get::<_, Option<i32>>(7)?,
                r.get::<_, Option<String>>(8)?,
            )),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => PanelError::NotFound(format!("task {id}")),
            other => PanelError::Database(other.to_string()),
        })
    }).await?;

    let (id, key, kind, st, prog, sa, fa, ec, op) = row;
    let duration = match (sa, fa) { (Some(a), Some(b)) => Some(b - a), _ => None };
    Ok(ok(serde_json::json!({
        "id": id, "key": key, "kind": kind, "state": st, "progress": prog,
        "started_at": sa, "finished_at": fa, "exit_code": ec, "output_path": op,
        "duration_secs": duration,
        "needs_human": st == "interrupted",
    })))
}

#[cfg(test)]
mod tests {
    use super::{effective_limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT};
    use rusqlite::Connection;

    // ── limit 语义 ──

    #[test]
    fn limit_defaults_to_default_when_absent() {
        assert_eq!(effective_limit(None), DEFAULT_LIST_LIMIT);
    }

    #[test]
    fn limit_zero_means_all_capped_by_max() {
        // 前端「全部」档传 0：不能被解释成「0 行」，而是「全量（受上限兜底）」
        assert_eq!(effective_limit(Some(0)), MAX_LIST_LIMIT);
    }

    #[test]
    fn limit_is_capped_at_max() {
        assert_eq!(effective_limit(Some(100)), 100);
        assert_eq!(effective_limit(Some(100)), 100);
        assert_eq!(effective_limit(Some(MAX_LIST_LIMIT + 1)), MAX_LIST_LIMIT);
        assert_eq!(effective_limit(Some(usize::MAX)), MAX_LIST_LIMIT);
    }

    /// 前端分页最大档位是「每页 100」：默认 50 会让选 100 的表格只显示半页、
    /// 且 TablePager 的分页数算错。这条守住「默认值不低于前端最大档位的一半」这类
    /// 回归不会悄悄回来——直接断言默认值 ≥ 前端常用档位。
    #[test]
    fn default_limit_covers_frontend_page_sizes() {
        assert!(
            DEFAULT_LIST_LIMIT >= 50,
            "默认上限 {DEFAULT_LIST_LIMIT} 小于前端常规每页档位 50，列表会莫名只有半页"
        );
    }

    // ── state 过滤下推到 SQL（用真 SQLite，不用假行）──
    //
    // 夹具要求：失败任务必须**不在**最近的 limit 条内，否则「内存过滤」的实现也能通过
    // （这正是原实现的盲区：先 LIMIT 再内存过滤，老失败被静默丢掉）。
    // 这里造 60 条 ok + 5 条较老的 failed，再按 failed 过滤、limit=10：
    // 正确答案是 5 条 failed；错误实现会返回 0 条。
    fn seed_runs() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE task_runs (
                id INTEGER PRIMARY KEY, task_id TEXT NOT NULL, kind TEXT NOT NULL,
                state TEXT NOT NULL, progress INTEGER NOT NULL,
                started_at INTEGER, finished_at INTEGER, exit_code INTEGER, output_path TEXT
             );",
        )
        .unwrap();
        // 先插 5 条 failed（id 1..=5，较老），再插 60 条 ok（id 6..=65，较新）
        for i in 1..=5 {
            conn.execute(
                "INSERT INTO task_runs(id, task_id, kind, state, progress, started_at)
                 VALUES(?1, 'old-fail', 'backup', 'failed', 100, 100)",
                rusqlite::params![i],
            )
            .unwrap();
        }
        for i in 6..=65 {
            conn.execute(
                "INSERT INTO task_runs(id, task_id, kind, state, progress, started_at)
                 VALUES(?1, 'recent-ok', 'backup', 'ok', 100, 200)",
                rusqlite::params![i],
            )
            .unwrap();
        }
        conn
    }

    /// 与 `list` 里内联的 SQL 逐字一致（改 SQL 必须同步这里；负向对照由
    /// `state_filter_only_works_because_sql_pushes_down` 保证夹具能区分两种实现）。
    fn query_states(conn: &Connection, limit: i64, filter: Option<&str>) -> Vec<String> {
        let mut st = conn
            .prepare(
                "SELECT id, task_id, kind, state, progress, started_at, finished_at, exit_code, output_path
                 FROM task_runs WHERE (?2 IS NULL OR state = ?2)
                 ORDER BY id DESC LIMIT ?1",
            )
            .unwrap();
        st.query_map(rusqlite::params![limit, filter], |r| r.get::<_, String>(3))
            .unwrap()
            .map(|x| x.unwrap())
            .collect()
    }

    #[test]
    fn state_filter_pushes_down_to_sql() {
        let conn = seed_runs();
        // limit=10：最近 10 条全是 ok；但正确实现应返回**全部 5 条** failed
        let got = query_states(&conn, 10, Some("failed"));
        assert_eq!(got.len(), 5, "state 过滤必须在 SQL 里做，否则老的失败任务被 LIMIT 截掉");
        assert!(got.iter().all(|s| s == "failed"), "筛选结果不能混入其它状态: {got:?}");
    }

    /// 负向对照：把 state 过滤挪回内存（先 LIMIT 再过滤），本应只剩 0 条。
    /// 若这条也返回 5 条，说明上面的夹具根本区分不出两种实现（守卫会变恒绿）。
    #[test]
    fn in_memory_filter_would_lose_old_failures_so_fixture_is_discriminating() {
        let conn = seed_runs();
        let recent = query_states(&conn, 10, None);
        let in_memory: Vec<_> = recent.into_iter().filter(|s| s == "failed").collect();
        assert_eq!(
            in_memory.len(),
            0,
            "夹具失效：最近 10 条里居然有 failed，内存过滤实现也会通过，测不出下推与否"
        );
    }

    #[test]
    fn no_filter_returns_latest_first() {
        let conn = seed_runs();
        let got = query_states(&conn, 3, None);
        assert_eq!(got.len(), 3);
        assert!(got.iter().all(|s| s == "ok"), "应按 id 倒序取最新 3 条");
    }

    #[test]
    fn interrupted_needs_human_flag() {
        let f = |st: &str| st == "interrupted";
        assert!(f("interrupted"));
        assert!(!f("ok"));
        assert!(!f("failed"));
        assert!(!f("running"));
    }
}
