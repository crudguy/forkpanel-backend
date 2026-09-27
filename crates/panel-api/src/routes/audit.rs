//! 审计日志查询（设计方案 §3.4 / §2.13）。
//!
//! 与 `routes.rs::audit()` 写端对应：所有写操作已在响应阶段落库到 `audit_log`
//! （列：ts, actor, actor_ip, action, target, result, detail_json）。
//! 本端点提供只读回溯，复用既有的读连接池模式。

use crate::{auth::perm, error::{ok, ApiError, ApiResult}, routes::{Auth, Shared}};
use axum::extract::{Query, State};
use axum::Json;
use panel_core::PanelError;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuditQ {
    pub limit: Option<usize>,
}

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<AuditQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::AUDIT_VIEW)?;
    // 服务端硬上限：避免一次性拉取全量审计表撑爆内存
    let limit = (q.limit.unwrap_or(100)).min(1000) as i64;
    let rows = state.pool.with(move |conn| {
        let mut st = conn.prepare(
            "SELECT ts, actor, action, target, result, detail_json \
             FROM audit_log ORDER BY ts DESC LIMIT ?1")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map(rusqlite::params![limit], |r| Ok((
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
            r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, Option<String>>(5)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;

    let dtos: Vec<_> = rows.into_iter().map(|(ts, actor, action, target, result, detail)| {
        serde_json::json!({
            "ts": ts, "actor": actor, "action": action,
            "target": target, "result": result, "detail": detail,
        })
    }).collect();
    Ok(ok(dtos))
}
