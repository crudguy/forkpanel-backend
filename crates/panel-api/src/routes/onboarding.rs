//! 首启上手清单（评估报告 C2：首次登录应给出「5 步上手」）。
//!
//! 存储：复用 `settings` 表 kv，键 `onboarding.state`，值形如
//! `{"checked":["trust_ca"],"dismissed":false,"updated_at":1739…}`。
//! 与 `dashboard.rs` 同构：通用 `/settings` PATCH 只放行 AI 三键，故自带专用端点。
//!
//! ⭐**为什么不能只靠「用户勾选」**：清单若纯由勾选驱动，进度就会撒谎——
//! 建了站但没勾显示未完成（噪音），勾了但没做显示已完成（更危险：清单的意义
//! 是「这台机器还差什么」）。所以 `done = 用户勾选 ∪ 后端可判定的真实状态`，
//! 且 `auto=true`（由真实状态判定）的步骤在前端禁用勾选框：勾了也不会改变
//! 结果，做成可点就是假动作。
//!
//! 权限：GET 只需登录（清单是给所有人看的「这台机器还差什么」）；
//! PUT（勾选 / 不再显示）需 `settings.manage`——清单是面板级共享进度，
//! 不能让任意只读账号把它关掉。

use crate::auth::perm;
use crate::error::{ok, ApiError, ApiResult};
use crate::routes::{audit, Auth, Shared};
use axum::{extract::State, Json};
use panel_core::PanelError;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::extract::PanelJson;

const K_ONBOARDING: &str = "onboarding.state";

/// 步骤定义。`auto_sql` = 用真实数据判定该步是否已完成（None = 后端无法判定，
/// 只能靠用户自己勾，如「信任根证书」发生在**用户本机浏览器**上）。
struct StepDef {
    id: &'static str,
    title: &'static str,
    desc: &'static str,
    /// 前端路由（清单每步「前往」直达的路径）
    route: &'static str,
    auto_sql: Option<&'static str>,
}

/// 顺序即清单顺序：信任根证书 → 创建站点 → 申请证书 → 开启 WAF → 备份计划。
/// 与评估报告 C2 的建议一致，也与证书页自身的提示（"尚未建站时也应先信任根证书"）呼应。
const STEPS: [StepDef; 5] = [
    StepDef {
        id: "trust_ca",
        title: "信任面板根证书",
        desc: "在证书页下载根证书并导入本机/浏览器信任链。之后访问面板自签证书的站点才不会报警。",
        route: "/certs",
        auto_sql: None,
    },
    StepDef {
        id: "create_site",
        title: "创建第一个站点",
        desc: "在网站页新建站点：填域名与根目录，创建后需「应用」才会真正下发配置。",
        route: "/sites",
        auto_sql: Some("SELECT COUNT(*) FROM sites"),
    },
    StepDef {
        id: "issue_cert",
        title: "为站点申请证书",
        desc: "在证书页申请（或导入）证书并绑到站点。自签证书仅供内网/测试，公网请用 ACME。",
        route: "/certs",
        auto_sql: Some("SELECT COUNT(*) FROM ssl_certs"),
    },
    StepDef {
        id: "enable_waf",
        title: "开启 WAF 防护",
        desc: "在 WAF 页为站点开启规则集（basic / strict）与 CC 限速。开启前先确认业务不受影响。",
        route: "/waf",
        auto_sql: Some("SELECT COUNT(*) FROM sites WHERE waf_enabled = 1"),
    },
    StepDef {
        id: "backup_plan",
        title: "配置备份计划",
        desc: "在备份页建一个定时计划。注意：加密备份的主密钥丢了就再也解不开，务必另行保管。",
        route: "/backups",
        auto_sql: Some("SELECT COUNT(*) FROM backup_jobs"),
    },
];

fn known_ids() -> Vec<&'static str> {
    STEPS.iter().map(|s| s.id).collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepOut {
    pub id: String,
    pub title: String,
    pub desc: String,
    pub route: String,
    /// 用户手动勾选
    pub checked: bool,
    /// 由后端真实状态判定已完成（此时勾选框禁用：勾不勾结果都一样）
    pub auto: bool,
    /// checked || auto —— 前端只看这个
    pub done: bool,
}

/// 落库形态。字段全带默认值：存量脏数据（少字段 / 类型不符）一律回落空进度，
/// 绝不因为一个展示层偏好让概览页报错。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
struct Stored {
    checked: Vec<String>,
    dismissed: bool,
    updated_at: Option<i64>,
}


fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn render(checked: &[String], auto: &[bool]) -> Vec<StepOut> {
    STEPS
        .iter()
        .zip(auto.iter())
        .map(|(s, &auto_done)| {
            let checked = checked.iter().any(|c| c == s.id);
            StepOut {
                id: s.id.to_string(),
                title: s.title.to_string(),
                desc: s.desc.to_string(),
                route: s.route.to_string(),
                checked,
                auto: auto_done,
                done: checked || auto_done,
            }
        })
        .collect()
}

/// 逐个跑自动判定 SQL。表不存在（老库 / 迁移未跑）时不算错误——按「未完成」处理，
/// 清单照样渲染；判据：这是展示层偏好，不能因为一个 count 查询失败就 500。
fn auto_flags(conn: &rusqlite::Connection) -> Vec<bool> {
    STEPS
        .iter()
        .map(|s| match s.auto_sql {
            Some(sql) => conn
                .query_row(sql, [], |r| r.get::<_, i64>(0))
                .map(|n| n > 0)
                .unwrap_or(false),
            None => false,
        })
        .collect()
}

// ───────────────────────── GET ─────────────────────────

pub async fn get(State(state): State<Shared>, Auth(_s): Auth) -> ApiResult<Json<serde_json::Value>> {
    let (raw, auto) = state
        .pool
        .with(|conn| {
            let raw: Option<String> = conn
                .query_row(
                    "SELECT value_json FROM settings WHERE key = ?1",
                    [K_ONBOARDING],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let auto = auto_flags(conn);
            Ok((raw, auto))
        })
        .await?;

    let st: Stored = raw
        .and_then(|s| serde_json::from_str::<Stored>(&s).ok())
        .unwrap_or_default();

    let steps = render(&st.checked, &auto);
    let done_count = steps.iter().filter(|s| s.done).count();

    Ok(ok(json!({
        "steps": steps,
        "dismissed": st.dismissed,
        "updated_at": st.updated_at,
        "done_count": done_count,
        "total": STEPS.len(),
    })))
}

// ───────────────────────── PUT ─────────────────────────

pub async fn put(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(body): PanelJson<Value>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SETTINGS_MANAGE)?;

    // ── 校验（任一不满足 → 400，不部分写入）──
    let checked_raw = match body.get("checked") {
        None => Vec::new(),
        Some(v) => v
            .as_array()
            .ok_or_else(|| ApiError::bad_request("checked", "checked 须为字符串数组"))?
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| ApiError::bad_request("checked", "checked 元素须为字符串"))
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
    };
    let ids = known_ids();
    let mut checked: Vec<String> = Vec::with_capacity(checked_raw.len());
    for c in checked_raw {
        if !ids.contains(&c.as_str()) {
            return Err(ApiError::bad_request("checked", format!("未知步骤 id `{c}`")));
        }
        if !checked.contains(&c) {
            checked.push(c);
        }
    }
    let dismissed = match body.get("dismissed") {
        None => false,
        Some(v) => v
            .as_bool()
            .ok_or_else(|| ApiError::bad_request("dismissed", "dismissed 须为布尔值"))?,
    };

    let st = Stored { checked, dismissed, updated_at: Some(now_unix()) };
    let value = serde_json::to_string(&st).expect("onboarding serialize");

    let key = K_ONBOARDING.to_string();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO settings(key, value_json) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
                rusqlite::params![key, value],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;

    audit(&state, &s, "settings.onboarding_put", K_ONBOARDING, "ok").await;

    // 写回后即时回算（含自动判定），让前端不必再打一次 GET
    let auto = state.pool.with(|conn| Ok(auto_flags(conn))).await?;
    let steps = render(&st.checked, &auto);
    let done_count = steps.iter().filter(|s| s.done).count();

    Ok(ok(json!({
        "steps": steps,
        "dismissed": st.dismissed,
        "updated_at": st.updated_at,
        "done_count": done_count,
        "total": STEPS.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(ids: &[&str]) -> Vec<bool> {
        STEPS.iter().map(|s| ids.contains(&s.id)).collect()
    }

    #[test]
    fn steps_are_five_and_ordered() {
        assert_eq!(STEPS.len(), 5);
        assert_eq!(
            known_ids(),
            vec!["trust_ca", "create_site", "issue_cert", "enable_waf", "backup_plan"]
        );
        // 每步都必须有前端落点，否则「前往」是个死链
        assert!(STEPS.iter().all(|s| s.route.starts_with('/')));
    }

    #[test]
    fn trust_ca_is_manual_only() {
        // 信任根证书发生在用户本机浏览器上，后端无从判定 → 必须留给用户勾
        let t = STEPS.iter().find(|s| s.id == "trust_ca").expect("trust_ca");
        assert!(t.auto_sql.is_none());
        // 其余四步都必须能自动判定，否则清单会退化成「勾了才算」的假进度
        assert!(STEPS.iter().filter(|s| s.id != "trust_ca").all(|s| s.auto_sql.is_some()));
    }

    #[test]
    fn auto_done_overrides_unchecked() {
        // 真实状态已完成 ⇒ 即使没勾也必须是 done，且 auto=true（前端据此禁用勾选框）
        let out = render(&[], &flags(&["create_site"]));
        let s = out.iter().find(|x| x.id == "create_site").expect("create_site");
        assert!(s.done, "自动判定的步骤必须算完成");
        assert!(s.auto);
        assert!(!s.checked);
    }

    #[test]
    fn manual_check_counts_when_no_auto() {
        let out = render(&["trust_ca".to_string()], &flags(&[]));
        let s = out.iter().find(|x| x.id == "trust_ca").expect("trust_ca");
        assert!(s.done && s.checked && !s.auto);
    }

    #[test]
    fn unknown_checked_ids_are_ignored_by_render() {
        // render 不负责校验（校验在 PUT 里做），但不得因未知 id 影响其它步骤
        let out = render(&["nope".to_string()], &flags(&[]));
        assert_eq!(out.iter().filter(|s| s.done).count(), 0);
        assert_eq!(out.len(), STEPS.len());
    }

    #[test]
    fn stored_defaults_on_dirty_payload() {
        // 存量脏值（类型完全不对）必须回落空进度，而不是 panic / 500
        let bad = serde_json::from_str::<Stored>(r#"{"checked":"not-an-array"}"#);
        assert!(bad.is_err(), "类型不符应按解析失败处理，由调用方 unwrap_or_default 兜底");
        let empty = serde_json::from_str::<Stored>("{}").expect("少字段可用默认值");
        assert!(empty.checked.is_empty());
        assert!(!empty.dismissed);
        assert!(empty.updated_at.is_none());
    }
}
