//! 审计日志查询（设计方案 §3.4 / §2.13）。
//!
//! 与 `routes.rs::audit()` 写端对应：所有写操作已在响应阶段落库到 `audit_log`
//! （列：id, ts, actor, actor_ip, action, target, result, detail_json）。
//! 本端点提供只读回溯，复用既有的读连接池模式。
//!
//! ## 契约对齐（此前实现与 openapi.yaml 脱节）
//! 契约声明了 `page` / `page_size` / `action` / `actor`，且 `AuditEntry` 含
//! `id` / `actor_ip` / `detail_json`；旧实现只有 `limit`，且不返回 `id` / `actor_ip`。
//! 现按契约补齐，并额外支持 `result` / `q`（关键词）/ `since` / `until`（时间窗）。
//! 返回体沿用项目既有的分页约定（见 `FileList`）：`{ items, page, page_size, total }`。
//!
//! ## 边界纪律
//! - 分页参数显式校验并回 400，不静默截断（静默截断会让"看完了"变成假象）；
//! - 所有筛选值走**绑定参数**（`rusqlite::types::Value`），绝不拼接 SQL；
//! - 筛选值长度设上限，避免超长输入把查询拖成全表扫描。

use crate::{auth::perm, error::{ok, ApiError, ApiResult}, routes::{Auth, Shared}};
use axum::extract::{Query, State};
use axum::Json;
use panel_core::PanelError;
use rusqlite::types::Value;
use serde::Deserialize;

/// 单页条数上限（与契约 `PageSize` 一致）。
const MAX_PAGE_SIZE: usize = 100;
/// 筛选值长度上限：actor/action/result 都是短枚举式字符串，超长必为误传或滥用。
const FILTER_MAX: usize = 128;

#[derive(Debug, Deserialize)]
pub struct AuditQ {
    /// 页码，从 1 开始
    pub page: Option<usize>,
    /// 每页条数（1..=100）
    pub page_size: Option<usize>,
    /// 兼容旧调用方：等价 `page_size`（同样受 1..=100 约束）
    pub limit: Option<usize>,
    pub actor: Option<String>,
    pub action: Option<String>,
    pub result: Option<String>,
    /// 关键词：模糊匹配 target / detail_json
    pub q: Option<String>,
    /// 起始时间戳（含），Unix 秒
    pub since: Option<i64>,
    /// 截止时间戳（含），Unix 秒
    pub until: Option<i64>,
}

/// 归一化筛选值：去空白、空串视为未传、超长回 400。
fn norm_filter(v: Option<String>, field: &'static str) -> Result<Option<String>, ApiError> {
    match v {
        None => Ok(None),
        Some(s) => {
            let t = s.trim().to_string();
            if t.is_empty() { return Ok(None) }
            if t.len() > FILTER_MAX {
                return Err(ApiError::bad_request(
                    field,
                    format!("筛选值过长（上限 {FILTER_MAX} 字符）"),
                ))
            }
            Ok(Some(t))
        }
    }
}

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<AuditQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::AUDIT_VIEW)?;

    // ── 参数校验：越界一律 400，不做静默截断 ──
    let page = q.page.unwrap_or(1);
    if page == 0 {
        return Err(ApiError::bad_request("page", "页码从 1 开始"));
    }
    let page_size = q.page_size.or(q.limit).unwrap_or(20);
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(ApiError::bad_request(
            "page_size",
            format!("每页条数需在 1..={MAX_PAGE_SIZE}"),
        ));
    }
    if let (Some(since), Some(until)) = (q.since, q.until) {
        if since > until {
            return Err(ApiError::bad_request("since", "起始时间不能晚于截止时间"));
        }
    }
    let actor = norm_filter(q.actor, "actor")?;
    let action = norm_filter(q.action, "action")?;
    let result = norm_filter(q.result, "result")?;
    let kw = norm_filter(q.q, "q")?;

    let offset = (page.saturating_sub(1) as i64).saturating_mul(page_size as i64);

    // ── 组装 WHERE：全部走绑定参数，杜绝 SQL 注入 ──
    let mut wh = String::from(" WHERE 1=1");
    // Value 是 Send + 'static，满足 pool.with 的闭包约束（Box<dyn ToSql> 不是 Send）
    let mut params: Vec<Value> = Vec::new();
    if let Some(v) = &actor {
        wh.push_str(" AND actor = ?");
        params.push(Value::Text(v.clone()));
    }
    if let Some(v) = &action {
        wh.push_str(" AND action = ?");
        params.push(Value::Text(v.clone()));
    }
    if let Some(v) = &result {
        wh.push_str(" AND result = ?");
        params.push(Value::Text(v.clone()));
    }
    if let Some(v) = &kw {
        wh.push_str(" AND (target LIKE ? OR detail_json LIKE ?)");
        let like = format!("%{v}%");
        params.push(Value::Text(like.clone()));
        params.push(Value::Text(like));
    }
    if let Some(v) = q.since {
        wh.push_str(" AND ts >= ?");
        params.push(Value::Integer(v));
    }
    if let Some(v) = q.until {
        wh.push_str(" AND ts <= ?");
        params.push(Value::Integer(v));
    }

    let count_sql = format!("SELECT COUNT(*) FROM audit_log{wh}");
    let list_sql = format!(
        "SELECT id, ts, actor, actor_ip, action, target, result, detail_json \
         FROM audit_log{wh} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
    );

    let (items, total): (Vec<serde_json::Value>, i64) = state.pool.with(move |conn| {
        // ① 总数（分页必需；与列表共用同一套筛选条件）
        let total: i64 = conn
            .query_row(
                &count_sql,
                rusqlite::params_from_iter(params.iter()),
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;

        // ② 当前页：LIMIT/OFFSET 追加在筛选参数之后，顺序必须与 SQL 占位符一致
        params.push(Value::Integer(page_size as i64));
        params.push(Value::Integer(offset));

        let mut st = conn
            .prepare(&list_sql)
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st
            .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                Ok((
                    r.get::<_, i64>(0)?,                    // id
                    r.get::<_, i64>(1)?,                    // ts
                    r.get::<_, String>(2)?,                 // actor
                    r.get::<_, Option<String>>(3)?,         // actor_ip
                    r.get::<_, String>(4)?,                 // action
                    r.get::<_, Option<String>>(5)?,         // target
                    r.get::<_, String>(6)?,                 // result
                    r.get::<_, Option<String>>(7)?,         // detail_json
                ))
            })
            .map_err(|e| PanelError::Database(e.to_string()))?;

        let mut v = Vec::new();
        for x in it {
            let (id, ts, actor, actor_ip, action, target, result, detail) =
                x.map_err(|e| PanelError::Database(e.to_string()))?;
            v.push(serde_json::json!({
                "id": id, "ts": ts, "actor": actor, "actor_ip": actor_ip,
                "action": action, "target": target, "result": result,
                "detail_json": detail,
            }));
        }
        Ok((v, total))
    }).await?;

    Ok(ok(serde_json::json!({
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
    })))
}
