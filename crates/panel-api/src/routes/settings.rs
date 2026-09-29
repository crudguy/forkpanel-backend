//! 面板设置（设计方案 §2.11）。
//!
//! **诚实三段模型**——settings 表的 8 个种子行当前**全部是死数据**（无运行时
//! 消费点），绝不能伪装成"可改即生效"：
//! - `runtime`：真正可改且立即生效的键（当前 = AI 助手 LLM 三键）
//! - `deployment`：部署级配置（read_only / tier），**只读展示**实际生效值，
//!   修改必须走 config.toml / 环境变量并重启——PATCH 这类键返回 400
//! - `reserved`：种子预留、尚未接线的键（audit/metrics retention 等），
//!   展示表内值并标注 `wired:false`，后续接线后挪入 runtime
//!
//! 秘密纪律：`assistant.llm_api_key` 经主密钥 AES-GCM 加密，hex 编码存
//! TEXT（`enc:<hex>` 前缀防呆）；GET **只回 set 布尔，绝不回明文**。

use crate::auth::perm;
use crate::error::{ok, ApiError, ApiResult};
use crate::routes::{audit, Auth, Shared};
use axum::{extract::State, Json};
use panel_core::PanelError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const K_LLM_ENDPOINT: &str = "assistant.llm_endpoint";
const K_LLM_MODEL: &str = "assistant.llm_model";
const K_LLM_API_KEY: &str = "assistant.llm_api_key";

/// runtime 白名单：PATCH 只接受这三个键。
const RUNTIME_KEYS: [&str; 3] = [K_LLM_ENDPOINT, K_LLM_MODEL, K_LLM_API_KEY];

/// 部署级键：在 settings 表里只有死种子，实际生效值来自 config.toml/env。
const DEPLOYMENT_KEYS: [&str; 4] =
    ["read_only", "tier", "max_login_attempts", "session_idle_timeout"];

#[derive(Debug, Deserialize)]
pub struct PatchReq {
    pub settings: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
pub struct LlmRuntime {
    endpoint: Option<String>,
    model: Option<String>,
    /// 只回布尔，**绝不回明文**
    api_key_set: bool,
}

#[derive(Debug, Serialize)]
pub struct SettingsReport {
    runtime: LlmRuntime,
    /// 部署级：只读展示实际生效值（改它们请走 config.toml / 环境变量）
    deployment: Value,
    /// 种子预留、未接线（wired:false）
    reserved: Value,
}

// ───────────────────────── GET ─────────────────────────

pub async fn get(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SETTINGS_MANAGE)?;

    let table = load_table(&state).await?;

    // runtime：LLM 三键（api_key 只判存在）
    let sval = |k: &str| -> Option<String> {
        table
            .get(k)
            .and_then(|j| serde_json::from_str::<Value>(j).ok())
            .and_then(|v| v.as_str().map(str::to_string))
    };
    let runtime = LlmRuntime {
        endpoint: sval(K_LLM_ENDPOINT),
        model: sval(K_LLM_MODEL),
        api_key_set: table.contains_key(K_LLM_API_KEY),
    };

    // deployment：只读展示实际生效值（不取自 settings 表）
    let deployment = json!({
        "read_only": std::env::var("PANEL_READ_ONLY").map(|v| v == "1").unwrap_or(false),
        "tier": tier_str(state.tier),
        "hint": "部署级配置：修改请编辑 config.toml（read_only 亦支持环境变量 PANEL_READ_ONLY）并重启面板",
    });

    // reserved：种子预留，值取表内（缺省回落种子字面量），一律 wired:false
    let reserved = json!({
        "wired": false,
        "note": "种子预留键，运行时尚未消费（接线后将挪入 runtime）",
        "values": {
            "audit_retention_days":      table.get("audit_retention_days").cloned().unwrap_or_else(|| "90".into()),
            "audit_max_rows":            table.get("audit_max_rows").cloned().unwrap_or_else(|| "50000".into()),
            "metrics_retention_1m_days": table.get("metrics_retention_1m_days").cloned().unwrap_or_else(|| "7".into()),
            "metrics_retention_1h_days": table.get("metrics_retention_1h_days").cloned().unwrap_or_else(|| "90".into()),
            "session_idle_timeout":      table.get("session_idle_timeout").cloned().unwrap_or_else(|| "\"30m\"".into()),
            "max_login_attempts":        table.get("max_login_attempts").cloned().unwrap_or_else(|| "5".into()),
        },
    });

    Ok(ok(SettingsReport { runtime, deployment, reserved }))
}

async fn load_table(state: &Shared) -> ApiResult<BTreeMap<String, String>> {
    let rows: Vec<(String, String)> = state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare("SELECT key, value_json FROM settings")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let it = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(|e| PanelError::Database(e.to_string()))?);
            }
            Ok(v)
        })
        .await?;
    Ok(rows.into_iter().collect())
}

// ───────────────────────── PATCH ─────────────────────────

pub async fn patch(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<PatchReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SETTINGS_MANAGE)?;
    if req.settings.is_empty() {
        return Err(ApiError::bad_request("settings", "empty patch"));
    }

    // 预校验：白名单 + 逐键类型/取值校验（任一非法 → 整体 400，不部分写入）
    let mut ops: Vec<(&str, Option<String>)> = Vec::new();
    for (k, v) in &req.settings {
        if !RUNTIME_KEYS.contains(&k.as_str()) {
            let reason = if DEPLOYMENT_KEYS.contains(&k.as_str()) {
                format!("`{k}` 是部署级配置：请编辑 config.toml 并重启（此处 PATCH 会造成『改了却不生效』的谎言）")
            } else {
                format!("未知或预留键 `{k}`（预留键接线后才会开放）")
            };
            return Err(ApiError::bad_request("key", reason));
        }
        match (k.as_str(), v) {
            (K_LLM_ENDPOINT, Value::Null)
            | (K_LLM_MODEL, Value::Null)
            | (K_LLM_API_KEY, Value::Null) => ops.push((k.as_str(), None)), // null = 清除
            (K_LLM_ENDPOINT, Value::String(url)) => {
                let url = url.trim();
                let ok = (url.starts_with("http://") || url.starts_with("https://"))
                    && url.len() <= 256
                    && !url.ends_with('/');
                if !ok {
                    return Err(ApiError::bad_request(
                        "settings",
                        "assistant.llm_endpoint 必须为 http(s) URL（≤256 字符、无尾斜杠）",
                    ));
                }
                ops.push((k.as_str(), Some(url.to_string())));
            }
            (K_LLM_MODEL, Value::String(m)) => {
                let m = m.trim();
                if m.is_empty() || m.len() > 128 {
                    return Err(ApiError::bad_request("settings", "assistant.llm_model 须为 1..=128 字符"));
                }
                ops.push((k.as_str(), Some(m.to_string())));
            }
            (K_LLM_API_KEY, Value::String(key)) => {
                let key = key.trim();
                if key.is_empty() || key.len() > 512 || key.starts_with("enc:") {
                    return Err(ApiError::bad_request(
                        "settings",
                        "assistant.llm_api_key 须为明文密钥 1..=512 字符（enc: 前缀为系统保留）",
                    ));
                }
                ops.push((k.as_str(), Some(key.to_string())));
            }
            (_, other) => {
                return Err(ApiError::bad_request("settings", format!("`{k}` 期望 string 或 null，得到 {other}")));
            }
        }
    }

    // api_key 需要主密钥（提前判定，避免半途失败造成部分写入）
    let needs_key = ops.iter().any(|(k, v)| *k == K_LLM_API_KEY && v.is_some());
    let master = if needs_key { Some(state.require_secret_key()?) } else { None };

    // 预构建最终 value_json（api_key 在此加密：AES-GCM → hex，enc: 前缀）
    let mut rows: Vec<(String, Option<String>)> = Vec::with_capacity(ops.len());
    for (k, v) in ops {
        let json = match (k, v) {
            (K_LLM_API_KEY, Some(plain)) => {
                let master = master.as_ref().expect("needs_key 已判定");
                let blob = master.encrypt(plain.as_bytes()).map_err(ApiError::from)?;
                let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
                Some(serde_json::to_string(&format!("enc:{hex}")).expect("string json"))
            }
            (_, Some(s)) => Some(serde_json::to_string(&s).expect("string json")),
            (_, None) => None, // 清除
        };
        rows.push((k.to_string(), json));
    }

    state
        .db
        .exec(move |conn| {
            for (k, json) in rows {
                match json {
                    Some(j) => {
                        conn.execute(
                            "INSERT INTO settings(key, value_json) VALUES(?1, ?2)
                             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
                            rusqlite::params![k, j],
                        )
                        .map_err(|e| PanelError::Database(e.to_string()))?;
                    }
                    None => {
                        conn.execute("DELETE FROM settings WHERE key = ?1", [k])
                            .map_err(|e| PanelError::Database(e.to_string()))?;
                    }
                }
            }
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;

    audit(&state, &s, "settings.patch",
        &req.settings.keys().cloned().collect::<Vec<_>>().join(","), "ok").await;

    // 回读 runtime 段（api_key 永不明文）
    get(State(state), Auth(s)).await
}

fn tier_str(t: panel_core::Tier) -> String {
    match t {
        panel_core::Tier::Nano => "nano",
        panel_core::Tier::Small => "small",
        panel_core::Tier::Standard => "standard",
    }
    .to_string()
}
