//! 概览页卡片布局（评估报告 A1 的个性化部分：指标卡拖拽排序 / 显隐）。
//!
//! 存储：复用 `settings` 表的 kv（键 `dashboard.cards`，值为 `{"cards":[…]}` JSON）。
//! 刻意**不走**通用 `/settings` PATCH——那套白名单只放行 AI 三键；本模块自带
//! 专用端点与校验，读写各自内聚（GET 读偏好，PUT 整体替换）。
//!
//! 权限：GET 只需登录（布局是展示层偏好，被所有查看概览的账号读取）；
//! PUT 需 `settings.manage`（布局是面板级共享配置，须防任意操作者改乱）。
//!
//! 容错：GET 对缺失 / 损坏 / 不合法的存量值一律回落默认布局——绝不因脏数据
//! 让概览页报错（展示层偏好坏了就用默认，不是数据事故）。

use crate::auth::perm;
use crate::error::{ok, ApiError, ApiResult};
use crate::routes::{audit, Auth, Shared};
use axum::{extract::State, Json};
use panel_core::PanelError;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// kv 键名。与通用 settings PATCH 的 runtime 白名单互不干涉。
const K_DASHBOARD_CARDS: &str = "dashboard.cards";

/// 合法卡片 id（顺序即默认顺序）。与前端概览页 ovCards 一一对应；
/// 任一端新增卡片时须两端同步加 id。
const CARD_IDS: [&str; 5] = ["cpu", "mem", "disk", "load", "net"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CardPref {
    pub id: String,
    pub visible: bool,
}

fn default_cards() -> Vec<CardPref> {
    CARD_IDS
        .iter()
        .map(|id| CardPref { id: (*id).to_string(), visible: true })
        .collect()
}

/// 校验并归一化布局。规则（任一不满足 → Err，不部分写入）：
/// - `cards` 为 1..=5 的数组；
/// - id 必须 ∈ 白名单且不重复（数组顺序即展示顺序）；
/// - 至少一张 visible（全隐藏的概览没有任何意义）。
fn parse_layout(v: &Value) -> Result<Vec<CardPref>, String> {
    let arr = v
        .get("cards")
        .and_then(Value::as_array)
        .ok_or_else(|| "缺少 cards 数组".to_string())?;
    if arr.is_empty() || arr.len() > CARD_IDS.len() {
        return Err(format!("cards 长度须为 1..={}", CARD_IDS.len()));
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "每张卡片须含字符串 id".to_string())?;
        let visible = item
            .get("visible")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("卡片 `{id}` 缺少 visible 布尔值"))?;
        if !CARD_IDS.contains(&id) {
            return Err(format!("未知卡片 id `{id}`"));
        }
        if !seen.insert(id.to_string()) {
            return Err(format!("卡片 id `{id}` 重复"));
        }
        out.push(CardPref { id: id.to_string(), visible });
    }
    if !out.iter().any(|c| c.visible) {
        return Err("至少保留一张可见卡片".to_string());
    }
    Ok(out)
}

// ───────────────────────── GET ─────────────────────────

pub async fn get(State(state): State<Shared>, Auth(_s): Auth) -> ApiResult<Json<serde_json::Value>> {
    let raw: Option<String> = state
        .pool
        .with(|conn| {
            conn.query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [K_DASHBOARD_CARDS],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    let cards = raw
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| parse_layout(&v).ok())
        .unwrap_or_else(default_cards);

    Ok(ok(json!({ "cards": cards })))
}

// ───────────────────────── PUT ─────────────────────────

pub async fn put(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(body): Json<Value>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SETTINGS_MANAGE)?;

    let cards = parse_layout(&body).map_err(|e| ApiError::bad_request("cards", e))?;
    let value = serde_json::to_string(&json!({ "cards": &cards })).expect("layout serialize");

    let key = K_DASHBOARD_CARDS.to_string();
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

    audit(&state, &s, "settings.dashboard_put", K_DASHBOARD_CARDS, "ok").await;

    Ok(ok(json!({ "cards": cards })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_covers_all_known_ids_in_order() {
        let d = default_cards();
        assert_eq!(d.len(), CARD_IDS.len());
        assert_eq!(
            d.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            CARD_IDS.to_vec()
        );
        assert!(d.iter().all(|c| c.visible));
    }

    #[test]
    fn parse_accepts_reorder_and_hidden() {
        let v = json!({"cards":[
            {"id":"net","visible":true},
            {"id":"cpu","visible":false},
            {"id":"mem","visible":true}
        ]});
        let cards = parse_layout(&v).expect("合法布局");
        assert_eq!(
            cards,
            vec![
                CardPref { id: "net".into(), visible: true },
                CardPref { id: "cpu".into(), visible: false },
                CardPref { id: "mem".into(), visible: true },
            ]
        );
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        assert!(parse_layout(&json!({})).is_err(), "缺 cards 数组");
        assert!(parse_layout(&json!({"cards": []})).is_err(), "空数组");
        assert!(
            parse_layout(&json!({"cards":[{"id":"gpu","visible":true}]})).is_err(),
            "未知 id"
        );
        assert!(
            parse_layout(&json!({"cards":[{"id":"cpu","visible":true},{"id":"cpu","visible":false}]})).is_err(),
            "重复 id"
        );
        assert!(
            parse_layout(&json!({"cards":[{"id":"cpu"}]})).is_err(),
            "缺 visible"
        );
        assert!(
            parse_layout(&json!({"cards":[{"id":"cpu","visible":false}]})).is_err(),
            "全部隐藏"
        );
        let six: Vec<Value> = (0..6)
            .map(|i| json!({"id": CARD_IDS[i % 5], "visible": true}))
            .collect();
        assert!(parse_layout(&json!({"cards": six})).is_err(), "超过上限");
    }
}
