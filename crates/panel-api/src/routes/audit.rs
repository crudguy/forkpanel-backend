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
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use panel_core::PanelError;
use rusqlite::types::Value;
use serde::Deserialize;

/// 单页条数上限（与契约 `PageSize` 一致）。
const MAX_PAGE_SIZE: usize = 100;
/// 筛选值长度上限：actor/action/result 都是短枚举式字符串，超长必为误传或滥用。
const FILTER_MAX: usize = 128;
/// 导出条数上限：审计是取证用途，允许一次拿全量；但必须有硬顶，
/// 否则 90 天 × 5 万行在大流量面板上会把整个响应攒进内存。
const EXPORT_MAX_ROWS: usize = 50_000;

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

/// 归一化的筛选条件（已过长度校验、空串已丢弃）。
///
/// 列表与导出共用同一份，避免两边对"哪些参数该生效"判断漂移——
/// 导出条件若与列表不一致，用户会拿着两份互相对不上的审计材料去取证。
#[derive(Debug)]
struct Filters {
    actor: Option<String>,
    action: Option<String>,
    result: Option<String>,
    kw: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
}

impl Filters {
    /// 校验并归一化；错误一律带具体字段名，前端能把提示落到输入框上。
    fn parse(q: &AuditQ) -> Result<Self, ApiError> {
        if let (Some(since), Some(until)) = (q.since, q.until) {
            if since > until {
                return Err(ApiError::bad_request("since", "起始时间不能晚于截止时间"));
            }
        }
        Ok(Self {
            actor: norm_filter(q.actor.clone(), "actor")?,
            action: norm_filter(q.action.clone(), "action")?,
            result: norm_filter(q.result.clone(), "result")?,
            kw: norm_filter(q.q.clone(), "q")?,
            since: q.since,
            until: q.until,
        })
    }

    /// 组装 WHERE：全部走绑定参数，杜绝 SQL 注入。
    fn where_clause(&self) -> (String, Vec<Value>) {
        let mut wh = String::from(" WHERE 1=1");
        // Value 是 Send + 'static，满足 pool.with 的闭包约束（Box<dyn ToSql> 不是 Send）
        let mut params: Vec<Value> = Vec::new();
        if let Some(v) = &self.actor {
            wh.push_str(" AND actor = ?");
            params.push(Value::Text(v.clone()));
        }
        if let Some(v) = &self.action {
            wh.push_str(" AND action = ?");
            params.push(Value::Text(v.clone()));
        }
        if let Some(v) = &self.result {
            wh.push_str(" AND result = ?");
            params.push(Value::Text(v.clone()));
        }
        if let Some(v) = &self.kw {
            wh.push_str(" AND (target LIKE ? OR detail_json LIKE ?)");
            let like = format!("%{v}%");
            params.push(Value::Text(like.clone()));
            params.push(Value::Text(like));
        }
        if let Some(v) = self.since {
            wh.push_str(" AND ts >= ?");
            params.push(Value::Integer(v));
        }
        if let Some(v) = self.until {
            wh.push_str(" AND ts <= ?");
            params.push(Value::Integer(v));
        }
        (wh, params)
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
    let f = Filters::parse(&q)?;
    let (wh, params) = f.where_clause();

    let offset = (page.saturating_sub(1) as i64).saturating_mul(page_size as i64);

    let count_sql = format!("SELECT COUNT(*) FROM audit_log{wh}");
    let list_sql = format!(
        "SELECT id, ts, actor, actor_ip, action, target, result, detail_json \
         FROM audit_log{wh} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
    );

    let (items, total): (Vec<serde_json::Value>, i64) = state.pool.with(move |conn| {
        let mut params = params;
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

// ─────────────────────── 导出（CSV） ───────────────────────

/// CSV 单元格转义。
///
/// 两件事必须同时做，缺一个都会出事：
/// 1. **公式注入**：审计内容含用户可控文本（用户名、站点名、文件名、失败原因），
///    以 `= + - @` 开头时 Excel/WPS 会当公式执行（`=cmd|'/c calc'!A1` 那条老路）。
///    业界通行做法是前置单引号把它钉成文本。
/// 2. **RFC 4180 引号**：含逗号/引号/换行的字段必须整体用 `"` 包裹、内部 `"` 翻倍。
///
/// ⚠ 顺序不能反：先判公式注入再包裹引号，否则 `"=x"` 绕过检测。
fn csv_cell(v: &str) -> String {
    let needs_quote = v.contains(',') || v.contains('"') || v.contains('\n') || v.contains('\r');
    let dangerous = matches!(v.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'));
    let mut body = String::with_capacity(v.len() + 2);
    if dangerous {
        // 前置单引号；这一步之后就一定含特殊字符语义，但单引号本身不需要引号包裹，
        // 仍按 needs_quote 走统一逻辑，保持输出稳定可对。
        body.push('\'');
    }
    body.push_str(v);
    if needs_quote || dangerous {
        format!("\"{}\"", body.replace('"', "\"\""))
    } else {
        body
    }
}

/// 时间戳转 `YYYY-MM-DD HH:MM:SS`（UTC）。
///
/// 为什么不用本地时区：审计是取证材料，跨机器比对必须同一基准；
/// 面板其余部分（journald、WAF 事件）也按 UTC 落，保持一致。
///
/// 复用 `waf_events::civil_from_days`（无依赖实现），不为此引入 chrono：
/// 本仓连 `time` 都只用于 ACME 解析，为一行格式化加依赖不值得。
fn fmt_ts(ts: i64) -> String {
    // 向下取整的除法：负数时间戳（1970 前）用 `/` 会朝 0 截断，算出前一天。
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = crate::routes::waf_events::civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

/// GET /api/v1/audit/export —— 按与列表完全相同的筛选条件导出 CSV 附件。
///
/// 存在理由：审计材料的实际用途是取证、合规复查与交给外部，而 `GET /audit`
/// 只有分页 JSON，用户只能一页页手工抄。导出复用 `Filters`，保证"看到的
/// 就是导出的"——两套条件必然漂移，是审计场景最不能接受的那类 bug。
pub async fn export(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<AuditQ>,
) -> ApiResult<Response> {
    crate::auth::require(&s, perm::AUDIT_VIEW)?;

    let f = Filters::parse(&q)?;
    let (wh, params) = f.where_clause();
    let sql = format!(
        "SELECT id, ts, actor, actor_ip, action, target, result, detail_json \
         FROM audit_log{wh} ORDER BY ts DESC, id DESC LIMIT ?"
    );

    let (rows, capped) = state
        .pool
        .with(move |conn| {
            let mut params = params;
            // 多取一行用来判断"是否还有更多"，从而诚实地告诉用户被截断了
            params.push(Value::Integer(EXPORT_MAX_ROWS as i64 + 1));
            let mut st = conn
                .prepare(&sql)
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let it = st
                .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, Option<String>>(7)?,
                    ))
                })
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(|e| PanelError::Database(e.to_string()))?);
            }
            let capped = v.len() > EXPORT_MAX_ROWS;
            v.truncate(EXPORT_MAX_ROWS);
            Ok((v, capped))
        })
        .await?;

    // 表头同时给机器列名与中文表头：前者便于脚本解析，后者便于人看
    let mut body = String::from(
        "id,时间(UTC),操作者,来源IP,动作,目标,结果,明细\n",
    );
    for (id, ts, actor, actor_ip, action, target, result, detail) in rows {
        let line = [
            id.to_string(),
            fmt_ts(ts),
            actor,
            actor_ip.unwrap_or_default(),
            action,
            target.unwrap_or_default(),
            result,
            detail.unwrap_or_default(),
        ]
        .iter()
        .map(|c| csv_cell(c))
        .collect::<Vec<_>>()
        .join(",");
        body.push_str(&line);
        body.push('\n');
    }

    // ⚠ BOM：不加 BOM，Excel 双击打开中文表头就是乱码（即"导出功能能用但没法看"）。
    // 代价是脚本读取时要跳过 BOM，实际多按 utf-8-sig 读即可。
    let payload = format!("\u{feff}{body}");
    // 文件名时间戳 `YYYYmmdd-HHMMSS`（UTC），由 fmt_ts 的输出压缩分隔符得到
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d) = crate::routes::waf_events::civil_from_days(now.div_euclid(86_400));
    let secs = now.rem_euclid(86_400);
    let cd = format!(
        "attachment; filename=\"audit-{y:04}{mo:02}{d:02}-{:02}{:02}{:02}.csv\"",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    );

    let mut resp = (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, cd.as_str()),
        ],
        payload,
    )
        .into_response();
    // 被截断时明确下发标记，别让用户以为拿到了全量
    if capped {
        resp.headers_mut().insert(
            header::HeaderName::from_static("x-capped"),
            header::HeaderValue::from_static("1"),
        );
    }
    // 导出是敏感操作（等于把全部操作轨迹带走），必须留痕
    let n = body.lines().count().saturating_sub(1);
    crate::routes::audit(
        &state,
        &s,
        "audit.export",
        &format!("rows={n}{}", if capped { " capped" } else { "" }),
        "ok",
    )
    .await;
    Ok(resp)
}

// ─────────────────────── 哈希链校验 ───────────────────────

/// GET /api/v1/audit/verify —— 全链校验，返回是否完整。
///
/// 为什么需要这个端点：哈希链的价值全在"能随时验证"。只有库里存着链、
/// 却没有一键校验的入口，运维永远不会发现断链——那这把锁等于没装。
///
/// 只读，但仍要求 `AUDIT_VIEW`：校验结果会暴露"第几条记录被动过"，
/// 属于敏感的取证信息。
pub async fn verify(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::AUDIT_VIEW)?;

    // 没有主密钥就**无法校验**——如实说 501，绝不返回 "ok: true"。
    // 这是本仓反复强调的纪律：能力位/降级路径不撒谎。
    let key = state.master_key.ok_or_else(|| {
        ApiError::unsupported(
            "audit.verify: master key not loaded (检查 /var/lib/forkpanel/master.key 权限 0600)",
        )
    })?;

    let outcome = state
        .pool
        .with(move |conn| {
            crate::audit_chain::verify(conn, &key)
                .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    // 未上链的行数（迁移前历史）：必须如实报出来，不能让用户以为整表都受保护
    let unchained: i64 = state
        .pool
        .with(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM audit_log WHERE hash IS NULL",
                [],
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    let (status, checked, broken_at, reason): (&str, usize, Option<i64>, Option<String>) =
        match outcome {
            crate::audit_chain::VerifyOutcome::Intact { checked } => ("intact", checked, None, None),
            crate::audit_chain::VerifyOutcome::Broken { at_id, reason } => {
                ("broken", 0, Some(at_id), Some(reason))
            }
            crate::audit_chain::VerifyOutcome::NotChained => ("not_chained", 0, None, None),
        };

    Ok(ok(serde_json::json!({
        "status": status,
        "checked": checked,
        // 未上链的历史行数：迁移前记录，如实披露
        "unchained": unchained,
        "broken_at_id": broken_at,
        "reason": reason,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ───────── CSV 单元格转义 ─────────

    #[test]
    fn plain_cell_is_untouched() {
        assert_eq!(csv_cell("auth.login"), "auth.login");
        assert_eq!(csv_cell(""), "");
    }

    /// 公式注入是审计导出最容易被忽略的真风险：`target` 里可能存着用户可控的
    /// 站点名/文件名/失败原因，Excel 打开即执行。
    #[test]
    fn formula_injection_is_neutralised() {
        for payload in ["=cmd|'/c calc'!A1", "+1+1", "-1+1", "@SUM(A1)"] {
            let got = csv_cell(payload);
            assert!(
                got.starts_with("\"'"),
                "{payload} 必须以引号包裹的单引号开头，实际 {got}"
            );
        }
    }

    /// 负向对照的反面：普通文本**不能**被误加单引号，否则每个字段都变脏。
    #[test]
    fn non_formula_values_get_no_quote_prefix() {
        assert_eq!(csv_cell("admin"), "admin");
        assert_eq!(csv_cell("1.2.3.4"), "1.2.3.4");
        assert_eq!(csv_cell("2026-11-18 08:00:00"), "2026-11-18 08:00:00");
    }

    #[test]
    fn commas_quotes_and_newlines_follow_rfc4180() {
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("he said \"hi\""), "\"he said \"\"hi\"\"\"");
        assert_eq!(csv_cell("line1\nline2"), "\"line1\nline2\"");
    }

    /// 顺序回归：先引号包裹再判公式会让 `"=x"` 漏网。
    #[test]
    fn formula_check_happens_on_raw_value_not_after_quoting() {
        let got = csv_cell("=1,2");
        assert!(got.starts_with("\"'="), "实际 {got}");
    }

    // ───────── 时间格式化 ─────────

    #[test]
    fn fmt_ts_known_values() {
        assert_eq!(fmt_ts(0), "1970-01-01 00:00:00");
        // 2026-01-01T00:00:00Z = days_from_civil(2026,1,1)*86400
        let t = crate::routes::waf_events::days_from_civil(2026, 1, 1) * 86_400;
        assert_eq!(fmt_ts(t), "2026-01-01 00:00:00");
        assert_eq!(fmt_ts(t + 86_399), "2026-01-01 23:59:59");
    }

    /// 1970 前的时间戳：`/` 朝零截断会算出前一天，必须用 `div_euclid`。
    #[test]
    fn fmt_ts_handles_pre_epoch() {
        assert_eq!(fmt_ts(-1), "1969-12-31 23:59:59");
        assert_eq!(fmt_ts(-86_401), "1969-12-30 23:59:59");
    }

    /// `civil_from_days` 与 `days_from_civil` 必须互为逆运算；顺带覆盖闰年 2/29。
    #[test]
    fn civil_and_days_roundtrip() {
        use crate::routes::waf_events::{civil_from_days, days_from_civil};
        for (y, m, d) in [
            (1970, 1, 1),
            (2000, 2, 29),
            (2024, 2, 29),
            (2026, 11, 18),
            (1999, 12, 31),
            (2100, 3, 1),
        ] {
            let z = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(z), (y, m, d), "{y}-{m}-{d} 往返不一致");
        }
    }

    // ───────── 筛选口径一致性 ─────────

    /// 列表与导出共用 `Filters`：这里钉住"空串/纯空白视为未传"，
    /// 否则导出会把 `actor=""` 当成真实条件而返回空集，用户以为审计丢了数据。
    #[test]
    fn blank_filters_are_treated_as_absent() {
        let q = AuditQ {
            page: None, page_size: None, limit: None,
            actor: Some("   ".into()),
            action: Some("".into()),
            result: None, q: None, since: None, until: None,
        };
        let f = Filters::parse(&q).expect("空筛选不应报错");
        let (wh, params) = f.where_clause();
        assert_eq!(wh, " WHERE 1=1");
        assert!(params.is_empty());
    }

    /// 关键词必须落成两个绑定参数（target 与 detail_json 各一个），
    /// 且都带 `%` 包裹——钉住参数个数，防止后续有人改成单边匹配。
    #[test]
    fn keyword_filter_binds_two_like_params() {
        let q = AuditQ {
            page: None, page_size: None, limit: None,
            actor: None, action: None, result: None,
            q: Some("panel".into()), since: None, until: None,
        };
        let (wh, params) = Filters::parse(&q).expect("关键词合法").where_clause();
        assert!(wh.contains("target LIKE ? OR detail_json LIKE ?"), "实际 {wh}");
        assert_eq!(params.len(), 2, "关键词应绑定 2 个参数");
        for p in &params {
            match p {
                Value::Text(s) => assert_eq!(s, "%panel%"),
                other => panic!("应为 Text 绑定值，实际 {other:?}"),
            }
        }
    }

    /// 时间窗反了必须 400，且错误字段指向 since（前端据此定位输入框）。
    #[test]
    fn inverted_time_window_is_rejected() {
        let q = AuditQ {
            page: None, page_size: None, limit: None,
            actor: None, action: None, result: None, q: None,
            since: Some(200), until: Some(100),
        };
        let err = Filters::parse(&q).expect_err("起始晚于截止必须拒绝");
        assert_eq!(err.code, 10001, "应为参数错误码，实际 {}", err.code);
    }
}
