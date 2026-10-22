//! 面板设置（设计方案 §2.11）。
//!
//! **诚实三段模型**——settings 表的 8 个种子行当前**全部是死数据**（无运行时
//! 消费点），绝不能伪装成"可改即生效"：
//! - `runtime`：真正可改且立即生效的键（当前 = AI 助手 LLM 三键）
//! - `deployment`：部署级配置（read_only / tier / max_login_attempts / session_idle /
//!   session_absolute / audit_retention_days / audit_max_rows / localhost_only /
//!   db_daily_backup / db_synchronous / db_backup_keep），**只读展示**实际生效值，
//!   修改必须走 config.toml / 环境变量并重启——PATCH 这类键返回 400
//! - `reserved`：种子预留、尚未接线的键（audit/metrics retention 等），
//!   展示表内值并标注 `wired:false`。⚠ 注意：审计保留**实际已通过 config.toml
//!   `[audit]` 实现**（部署级，见 `main.rs` 的 `prune_audit`），指标保留为内置
//!   默认（`aggregator::Retention::default()` = 7d/90d）；本表种子**不**是生效来源。
//!   将来若把保留策略迁到设置页再消费这些键，务必移除 config.toml 那一路，
//!   勿让两路并存造成双源冲突。
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
use crate::extract::PanelJson;

const K_LLM_ENDPOINT: &str = "assistant.llm_endpoint";
const K_LLM_MODEL: &str = "assistant.llm_model";
const K_LLM_API_KEY: &str = "assistant.llm_api_key";

/// runtime 白名单：PATCH 只接受这三个键。
const RUNTIME_KEYS: [&str; 3] = [K_LLM_ENDPOINT, K_LLM_MODEL, K_LLM_API_KEY];

/// 部署级键：在 settings 表里只有死种子，实际生效值来自 config.toml/env。
const DEPLOYMENT_KEYS: [&str; 11] = [
    "read_only",
    "tier",
    "max_login_attempts",
    "session_idle",
    "session_absolute",
    "audit_retention_days",
    "audit_max_rows",
    "localhost_only",
    "db_daily_backup",
    "db_synchronous",
    "db_backup_keep",
];

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

/// LLM 运行时配置（明文 api_key）。仅在三键齐全时构造，`llm_config` 返回 `None`
/// 表示未配置——调用方据此优雅降级（不生成叙事，回退纯规则报告）。
pub struct LlmConfig {
    pub endpoint: String,
    pub model: String,
    /// 已解密的明文密钥（仅内存使用，绝不落日志/回显）
    pub api_key: String,
}

/// 读取已保存的 LLM 配置；三键任一缺失或 api_key 解密失败 → `None`（优雅降级）。
/// 复用本模块的 `load_table` 与 `plain_api_key`，密钥处理集中在此一处。
pub async fn llm_config(state: &Shared) -> ApiResult<Option<LlmConfig>> {
    let table = load_table(state).await?;
    let endpoint = table
        .get(K_LLM_ENDPOINT)
        .and_then(|j| serde_json::from_str::<Value>(j).ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.is_empty());
    let model = table
        .get(K_LLM_MODEL)
        .and_then(|j| serde_json::from_str::<Value>(j).ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.is_empty());
    let raw = table.get(K_LLM_API_KEY);
    let (endpoint, model, raw) = match (endpoint, model, raw) {
        (Some(e), Some(m), Some(r)) => (e, m, r),
        _ => return Ok(None),
    };
    let api_key = match plain_api_key(state, raw) {
        Some(k) => k,
        None => return Ok(None), // 密钥存储损坏（主密钥轮换等）→ 视作未配置
    };
    Ok(Some(LlmConfig { endpoint, model, api_key }))
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
        "read_only": state.read_only,
        "tier": tier_str(state.tier),
        "max_login_attempts": state.logins.max_attempts(),
        "session_idle": fmt_dur(state.session_idle),
        "session_absolute": fmt_dur(state.session_absolute),
        "audit_retention_days": state.audit_retention_days,
        "audit_max_rows": state.audit_max_rows,
        "localhost_only": state.localhost_only,
        "db_daily_backup": state.daily_backup,
        "db_synchronous": state.db_synchronous,
        "db_backup_keep": state.backup_keep,
        "hint": "部署级配置：config.toml [security] 的 read_only / max_login_attempts / session_idle / session_absolute、[audit] 的 retention_days / max_rows、[server] 的 localhost_only、[db] 的 daily_backup / synchronous / backup_keep 改后重启生效（此处 PATCH 会造成『改了却不生效』的谎言，故拒绝）",
    });

    // reserved：种子预留，值取表内（缺省回落种子字面量），一律 wired:false
    let reserved = json!({
        "wired": false,
        "note": "审计保留已由 config.toml [audit] 驱动（部署级，改后重启生效）；指标保留为内置默认(7d/90d)；二者均不读本表键。本键为将来迁入设置页的占位，请勿单独接线（会与部署配置双源冲突）",
        "values": {
            "audit_retention_days":      table.get("audit_retention_days").cloned().unwrap_or_else(|| "90".into()),
            "audit_max_rows":            table.get("audit_max_rows").cloned().unwrap_or_else(|| "50000".into()),
            "metrics_retention_1m_days": table.get("metrics_retention_1m_days").cloned().unwrap_or_else(|| "7".into()),
            "metrics_retention_1h_days": table.get("metrics_retention_1h_days").cloned().unwrap_or_else(|| "90".into()),
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
    PanelJson(req): PanelJson<PatchReq>,
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
                // 与「测试连接」共用同一条约束（valid_endpoint），避免两条路径漂移
                let ok = valid_endpoint(url);
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

// ─────────────────── 测试连接（C10 验证闭环）───────────────────

/// endpoint 合法性。**PATCH 与「测试连接」必须共用这一条约束**——同一约束拆在
/// 两条路径上是本仓踩过的高频 bug（一处校验一处不校验 → "能存但测不通"）。
fn valid_endpoint(url: &str) -> bool {
    (url.starts_with("http://") || url.starts_with("https://"))
        && url.len() <= 256
        && !url.ends_with('/')
}

/// 探测超时。宁可让用户等 8 秒后拿到明确超时，也不要挂住一个 axum worker。
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

#[derive(Debug, Deserialize)]
pub struct TestLlmReq {
    /// 省略（或 null）= 用库里已存的值；填了则以本次为准（**先测后存**）
    pub endpoint: Option<String>,
    pub model: Option<String>,
    /// 明文密钥：省略则用库里已存的那把（库里是主密钥加密的，此处解开后只用不存）
    pub api_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TestLlmResp {
    pub ok: bool,
    pub latency_ms: u64,
    pub endpoint: String,
    pub model: Option<String>,
    /// 该 model 是否出现在 /v1/models 的返回里（model 未配置时恒 false）
    pub model_found: bool,
    /// 可用模型数量（解析失败为 null）
    pub model_count: Option<usize>,
    pub status: Option<u16>,
    /// 人话结论：成功摘要 / 失败原因
    pub detail: String,
}

/// 非 2xx 的失败原因。**只回显响应体前 200 字符且不含任何请求侧内容**——
/// 端点由管理员填写，本函数回显的内容可能是内网服务的报错，截断是必要的。
fn status_detail(status: u16, body: &str) -> String {
    let tail: String = body.chars().take(200).collect();
    let brief = if tail.is_empty() { String::new() } else { format!("：{tail}") };
    match status {
        401 => format!("密钥被拒绝（HTTP 401）——API Key 无效或已撤销{brief}"),
        403 => format!("无访问权限（HTTP 403）——Key 可能没有该模型/接口的权限{brief}"),
        404 => format!("接口不存在（HTTP 404）——Endpoint 可能少写了 /v1{brief}"),
        429 => format!("被限流（HTTP 429）——稍后重试{brief}"),
        s if s >= 500 => format!("服务端错误（HTTP {s}）——对方服务异常{brief}"),
        s => format!("未预期的响应（HTTP {s}）{brief}"),
    }
}

/// 请求层失败（连不上 / 超时 / TLS）的原因。reqwest 的错误类型已能区分这几类，
/// 不区分的话用户只能看到一句 "error sending request"。
fn err_detail(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        format!("连接超时（{}s 内无响应）", TEST_TIMEOUT.as_secs())
    } else if e.is_connect() {
        "无法建立连接：主机名解析失败、端口不通或被防火墙拒绝".to_string()
    } else if e.is_request() {
        format!("请求被拒绝（多半是 Endpoint 不被识别为 http/https）：{e}")
    } else if e.is_body() || e.is_decode() {
        format!("响应读取/解析失败（对方返回的可能不是 JSON）：{e}")
    } else {
        format!("请求失败：{e}")
    }
}

/// 从 `enc:<hex>` 解出明文（库里 api_key 的落库形态）。
fn plain_api_key(state: &Shared, raw: &str) -> Option<String> {
    let s = serde_json::from_str::<Value>(raw).ok().and_then(|v| v.as_str().map(str::to_string))?;
    let hex = s.strip_prefix("enc:")?;
    let blob: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect();
    if blob.is_empty() || blob.len() * 2 != hex.len() {
        return None;
    }
    let master = state.require_secret_key().ok()?;
    master.decrypt(&blob).ok().and_then(|b| String::from_utf8(b).ok())
}

/// `POST /api/v1/settings/llm/test`——真实探测 OpenAI 兼容的 `/v1/models`。
///
/// 设计要点：
/// - **先测后存**：请求里带的 endpoint/model/api_key 优先于库里的值，用户改完
///   输入框就能验证，不必先保存才知道配错了（C10 原话："避免保存后才报错"）。
/// - **绝不 500**：所有探测失败都落成 `ok:false + detail`，配置错了是用户的事，
///   不是服务器错误——返回 500 会让前端把"密钥填错"显示成"请求失败"。
/// - **密钥不落日志、不回显**：只回布尔与结论。
/// - 端点由管理员填写 ⇒ 这是一次由管理员发起的外发请求（SSRF 面）；仅
///   `settings.manage` 可调用，且响应体截断到 200 字符。
pub async fn test_llm(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<TestLlmReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SETTINGS_MANAGE)?;

    let table = load_table(&state).await?;
    let stored = |k: &str| -> Option<String> {
        table
            .get(k)
            .and_then(|j| serde_json::from_str::<Value>(j).ok())
            .and_then(|v| v.as_str().map(str::to_string))
    };

    let endpoint = match req.endpoint.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(e) => e.to_string(),
        None => stored(K_LLM_ENDPOINT).unwrap_or_default(),
    };
    if endpoint.is_empty() {
        return Err(ApiError::bad_request("endpoint", "尚未配置 API Endpoint，无法测试"));
    }
    if !valid_endpoint(&endpoint) {
        return Err(ApiError::bad_request(
            "endpoint",
            "API Endpoint 须为 http(s) URL（≤256 字符、无尾斜杠）",
        ));
    }
    let model = match req.model.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(m) => Some(m.to_string()),
        None => stored(K_LLM_MODEL),
    };
    let api_key = match req.api_key.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(k) => Some(k.to_string()),
        None => table
            .get(K_LLM_API_KEY)
            .and_then(|raw| plain_api_key(&state, raw)),
    };

    let client = match reqwest::Client::builder().timeout(TEST_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            return Ok(ok(TestLlmResp {
                ok: false,
                latency_ms: 0,
                endpoint,
                model,
                model_found: false,
                model_count: None,
                status: None,
                detail: format!("无法创建 HTTP 客户端：{e}"),
            }))
        }
    };

    let url = format!("{endpoint}/models");
    let started = std::time::Instant::now();
    let mut call = client.get(&url).header("accept", "application/json");
    if let Some(k) = api_key.as_deref() {
        call = call.bearer_auth(k);
    }
    let outcome = call.send().await;
    let latency_ms = started.elapsed().as_millis() as u64;

    let resp: TestLlmResp = match outcome {
        Err(e) => TestLlmResp {
            ok: false,
            latency_ms,
            endpoint,
            model,
            model_found: false,
            model_count: None,
            status: None,
            detail: err_detail(&e),
        },
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            if !(200..300).contains(&status) {
                TestLlmResp {
                    ok: false,
                    latency_ms,
                    endpoint,
                    model,
                    model_found: false,
                    model_count: None,
                    status: Some(status),
                    detail: status_detail(status, &body),
                }
            } else {
                let v = serde_json::from_str::<Value>(&body).ok();
                let ids: Vec<String> = v
                    .as_ref()
                    .and_then(|v| v.get("data"))
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.get("id").and_then(Value::as_str).map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let model_count = if v.is_some() { Some(ids.len()) } else { None };
                let model_found = model.as_deref().map(|m| ids.iter().any(|i| i == m)).unwrap_or(false);
                let detail = match (model.as_deref(), model_count, model_found) {
                    (Some(m), Some(_), false) => format!(
                        "连通（{} ms，可用模型 {} 个），但列表里没有 `{m}`——请核对模型名",
                        latency_ms,
                        ids.len()
                    ),
                    (Some(m), None, _) => format!(
                        "连通（{} ms），但响应不是预期的 OpenAI 兼容 JSON，无法核对 `{m}`",
                        latency_ms
                    ),
                    (Some(_), Some(_), true) => {
                        format!("连通且模型可用（{} ms，可用模型 {} 个）", latency_ms, ids.len())
                    }
                    (None, Some(_), _) => format!("连通（{} ms，可用模型 {} 个）", latency_ms, ids.len()),
                    (None, None, _) => format!("连通（{} ms），但响应不是 JSON", latency_ms),
                };
                TestLlmResp {
                    ok: true,
                    latency_ms,
                    endpoint,
                    model,
                    model_found,
                    model_count,
                    status: Some(status),
                    detail,
                }
            }
        }
    };

    audit(
        &state,
        &s,
        "settings.llm_test",
        &resp.endpoint,
        if resp.ok { "ok" } else { "fail" },
    )
    .await;

    Ok(ok(resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 部署级键清单的契约：所有已接线并按「只读部署级」展示的键必须在册（PATCH 才能
    /// 给出「部署级」精确拒绝，而非退化成「未知或预留键」），且 deployment 与 runtime
    /// 白名单不得重叠。68d0fc1 接入审计保留两项时未钉测试，本条补齐并把
    /// localhost_only / db_daily_backup 一并锁住——删任一键都会让 PATCH 文案静默降级。
    #[test]
    fn deployment_keys_cover_audit_retention_and_stay_disjoint_from_runtime() {
        for k in [
            "read_only", "tier", "max_login_attempts", "session_idle",
            "session_absolute", "audit_retention_days", "audit_max_rows",
            "localhost_only", "db_daily_backup", "db_synchronous",
            "db_backup_keep",
        ] {
            assert!(DEPLOYMENT_KEYS.contains(&k), "deployment 白名单缺 `{k}`");
        }
        // 同一键不能既「可 PATCH 即生效」又「只读部署级」——语义自相矛盾
        for k in RUNTIME_KEYS {
            assert!(!DEPLOYMENT_KEYS.contains(&k), "`{k}` 不能同时属 runtime 与 deployment");
        }
        // 无重复（contains 判不出重复；重复会让清单本身失真）
        let mut seen = std::collections::HashSet::new();
        for k in DEPLOYMENT_KEYS {
            assert!(seen.insert(k), "DEPLOYMENT_KEYS 重复项：{k}");
        }
    }

    #[test]
    fn endpoint_rule_is_shared_by_patch_and_probe() {
        // PATCH 与「测试连接」共用 valid_endpoint：任一处退化成自己的一份判断，
        // 就会出现"能存但测不通"或"能测但存不下"。
        assert!(valid_endpoint("https://api.openai.com/v1"));
        assert!(valid_endpoint("http://127.0.0.1:11434/v1"), "内网/本地网关是合法用例");
        assert!(!valid_endpoint("https://api.openai.com/v1/"), "尾斜杠会拼出 //models");
        assert!(!valid_endpoint("ftp://x/v1"), "非 http(s)");
        assert!(!valid_endpoint("api.openai.com/v1"), "缺 scheme");
        let long = format!("https://{}", "a".repeat(300));
        assert!(!valid_endpoint(&long), "超长");
    }

    #[test]
    fn status_detail_names_the_cause_and_truncates_body() {
        assert!(status_detail(401, "").contains("密钥被拒绝"));
        assert!(status_detail(404, "").contains("Endpoint 可能少写了 /v1"));
        assert!(status_detail(503, "").contains("服务端错误"));
        // 端点由管理员填写 ⇒ 回显必须截断（否则可能把内网服务的整页报错带出来）。
        // 数回显字符而不是字节：detail 里有中文，String::len() 是字节数。
        let d = status_detail(401, &"x".repeat(5000));
        assert_eq!(d.chars().filter(|c| *c == 'x').count(), 200, "回显须截断到 200 字符：{d}");
    }

    #[tokio::test]
    async fn err_detail_distinguishes_connect_failure() {
        // 端口 1 必然连不上（无外发、无依赖）；若这条都拿不到 is_connect，
        // 用户看到的就只剩一句 "error sending request"。
        let c = reqwest::Client::builder()
            .timeout(TEST_TIMEOUT)
            .build()
            .expect("client");
        let e = c
            .get("http://127.0.0.1:1/models")
            .send()
            .await
            .expect_err("端口 1 应拒绝连接");
        let d = err_detail(&e);
        assert!(d.contains("无法建立连接"), "分类失准：{d}");
    }
}

/// 把 Duration 渲染成 config.toml 同款 "30m"/"12h"/"90s"（deployment 段展示用）。
fn fmt_dur(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s % 3600 == 0 { format!("{}h", s / 3600) }
    else if s % 60 == 0 { format!("{}m", s / 60) }
    else { format!("{}s", s) }
}

fn tier_str(t: panel_core::Tier) -> String {
    match t {
        panel_core::Tier::Nano => "nano",
        panel_core::Tier::Small => "small",
        panel_core::Tier::Standard => "standard",
    }
    .to_string()
}
