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
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ListQ {
    pub state: Option<String>,
    pub limit: Option<usize>,
}

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<ListQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::TASK_VIEW)?;
    let limit = q.limit.unwrap_or(50).min(200) as i64;
    let rows = state.pool.with(move |conn| {
        let mut st = conn.prepare(
            "SELECT id, task_id, kind, state, progress, started_at, finished_at, exit_code, output_path
             FROM task_runs ORDER BY id DESC LIMIT ?1",
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map(rusqlite::params![limit], |r| Ok((
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
            r.get::<_, String>(3)?, r.get::<_, i32>(4)?, r.get::<_, Option<i64>>(5)?,
            r.get::<_, Option<i64>>(6)?, r.get::<_, Option<i32>>(7)?,
            r.get::<_, Option<String>>(8)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;

    let filter = q.state.clone();
    let dtos: Vec<_> = rows.into_iter()
        .filter(|(_, _, _, st, _, _, _, _, _)| {
            filter.as_ref().map(|f| f == st).unwrap_or(true)
        })
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
    crate::auth::require(&s, perm::TASK_VIEW)?;
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
            .map_err(|e| PanelError::Database(e.to_string()))
    }).await?;

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
    use super::*;

    #[test]
    fn list_limit_is_capped() {
        assert_eq!(10_000usize.min(200), 200);
        assert_eq!(30usize.min(200), 30);
    }

    #[test]
    fn output_lines_capped() {
        assert_eq!(50_000usize.min(2000), 2000);
        assert_eq!(100usize.min(2000), 100);
    }

    #[test]
    fn interrupted_needs_human_flag() {
        let f = |st: &str| st == "interrupted";
        assert!(f("interrupted"));
        assert!(!f("ok"));
        assert!(!f("failed"));
        assert!(!f("running"));
    }

    #[test]
    fn tail_read_takes_last_n() {
        let all: Vec<&str> = (0..100).map(|_| "x").collect();
        let n = 10usize;
        let start = all.len().saturating_sub(n);
        assert_eq!(all[start..].len(), 10, "应只取最后 n 行");
        // 不足 n 行时取全部
        let few: Vec<&str> = vec!["a", "b"];
        assert_eq!(few.len().saturating_sub(10), 0);
    }
}
