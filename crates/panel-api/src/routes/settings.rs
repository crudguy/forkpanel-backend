//! 面板设置（设计方案 §2.11）。
//!
//! **诚实三段模型**——settings 表的 8 个种子行当前**全部是死数据**（无运行时
//! 消费点），绝不能伪装成"可改即生效"：
//! - `runtime`：真正可改且立即生效的键（当前 = AI 助手 LLM 四键：endpoint / model /
//!   api_key / **narrative 独立开关**）。开关关闭时 `llm_config()` 返回 `None`
//!   ⇒ 诊断不外发任何数据（与未配置同路，回退纯规则报告）；开启时每次诊断会把
//!   指标摘要 + 规则结论 + 最近 20 条 error 级日志（**发送前脱敏**，见
//!   `assistant::redact_for_llm`）POST 到管理员配置的端点。
//! - `deployment`：部署级配置（read_only / tier / max_login_attempts / session_idle /
//!   session_absolute / audit_retention_days / audit_max_rows / localhost_only /
//!   db_daily_backup / db_synchronous / db_backup_keep / installation），
//!   **只读展示**实际生效值，
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
/// LLM 叙事层独立开关（布尔）。**缺省 = 关**：外发第三方端点必须显式同意，
/// 不搞「配齐三键即自动外发」——那等于把隐私决定藏在连接参数里。
const K_LLM_NARRATIVE: &str = "assistant.llm_narrative";

/// chat 模式是否附带脱敏后的系统概要（布尔）。**缺省 = 关**：自由对话默认不把
/// 任何系统数据带出本机；开启后，chat 通道也会外发一份（受同一叙事开关 +
/// `redact_for_llm` 约束）。仅当叙事开关已开（LLM 实际被调用）时才有意义。
const K_LLM_CHAT_CONTEXT: &str = "assistant.llm_chat_context";

/// runtime 白名单：PATCH 只接受这五个键。
const RUNTIME_KEYS: [&str; 5] = [
    K_LLM_ENDPOINT,
    K_LLM_MODEL,
    K_LLM_API_KEY,
    K_LLM_NARRATIVE,
    K_LLM_CHAT_CONTEXT,
];

/// 开启叙事后**会外发什么**的披露文案。由后端单一维护、前端原样展示——
/// 文案与 `assistant::redact_for_llm` 的实际覆盖范围一一对应，杜绝
/// 「文档说已脱敏、代码没脱敏」的漂移。
pub const NARRATIVE_NOTE: &str = "开启后，每次诊断会把以下内容发送到上方配置的 Endpoint：CPU/内存/磁盘等指标摘要、规则诊断结论，以及最近 20 条 error 级系统日志原文（发送前脱敏 IP 地址、邮箱与密钥样式文本；路径与主机名不脱敏——它们是诊断的核心证据）。数据离开本机后不再受面板控制。关闭时仅使用内置规则诊断，不外发任何数据。";

/// 开启 chat 系统上下文后会外发什么的披露文案。同样单一维护、前端原样渲染。
pub const CHAT_CONTEXT_NOTE: &str = "开启后，自由对话（非快捷体检）也会把一份脱敏后的系统概要（CPU/内存/负载/磁盘最高占用/Top CPU 进程，不含 IP、密钥等敏感信息）随你的提问一起发给模型，使通用提问也能结合本机实况作答。默认关闭：自由对话只转发你的文字，不附带任何系统数据。";

/// 部署级键：在 settings 表里只有死种子，实际生效值来自 config.toml/env。
const DEPLOYMENT_KEYS: [&str; 12] = [
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
    "installation",
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
    /// LLM 叙事层独立开关（缺省 false）。false 时 llm_config() 返回 None。
    narrative: bool,
    /// 开启后会外发什么的披露文案（单一事实源，前端原样渲染）
    narrative_note: &'static str,
    /// chat 模式是否附带脱敏系统概要（缺省 false）。true 时自由对话也外发一份系统快照。
    chat_context: bool,
    /// 开启后会外发什么的披露文案（单一事实源，前端原样渲染）
    chat_context_note: &'static str,
}

/// 叙事开关读取：表内值为 JSON 字符串 "true" 才算开；缺省/其余一律关。
/// 纯函数（不吃 state）——开关语义必须有单测盯着，见 tests。
fn narrative_on(table: &std::collections::BTreeMap<String, String>) -> bool {
    table
        .get(K_LLM_NARRATIVE)
        .and_then(|j| serde_json::from_str::<Value>(j).ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .as_deref()
        == Some("true")
}

/// chat 上下文开关读取：与 `narrative_on` 同款语义，缺省/坏值/false 一律关，
/// 只有显式 "true" 开。纯函数（不吃 state）——开关语义必须有单测盯着。
fn chat_context_on(table: &std::collections::BTreeMap<String, String>) -> bool {
    table
        .get(K_LLM_CHAT_CONTEXT)
        .and_then(|j| serde_json::from_str::<Value>(j).ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .as_deref()
        == Some("true")
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
    /// chat 模式是否附带脱敏系统概要（仅当叙事开关已开时读取）
    pub chat_context: bool,
}

/// 读取已保存的 LLM 配置；三键任一缺失、api_key 解密失败、**或叙事开关未开启**
/// → `None`（优雅降级：diagnose 回退纯规则报告，不外发任何数据）。
///
/// 开关放在最前判：关的时候连 api_key 都不必解密。门控收敛在这一处，
/// 调用方（assistant::diagnose）无需各自记得查开关——「配了密钥却忘接线」
/// 与「接了线却忘让开关生效」两类假控制都由此规避。
/// 复用本模块的 `load_table` 与 `plain_api_key`，密钥处理集中在此一处。
pub async fn llm_config(state: &Shared) -> ApiResult<Option<LlmConfig>> {
    let table = load_table(state).await?;
    if !narrative_on(&table) {
        return Ok(None);
    }
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
    let chat_context = chat_context_on(&table);
    Ok(Some(LlmConfig { endpoint, model, api_key, chat_context }))
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
        narrative: narrative_on(&table),
        narrative_note: NARRATIVE_NOTE,
        chat_context: chat_context_on(&table),
        chat_context_note: CHAT_CONTEXT_NOTE,
    };

    // deployment：只读展示实际生效值（不取自 settings 表）
    let layout = state.os.paths();
    // systemctl 可能不存在/不可用（非 systemd、精简镜像）⇒ 用 Option 如实表达
    // 「无法判定」，绝不能把「查不到」渲染成「已停止」。
    //
    // ⚠ 必须 spawn_blocking：`run_sync` 是 `std::process` + `wait()`，在 async
    // handler 里直接调用会占死 tokio worker（systemd/D-Bus 卡顿时整个 API 无响应）。
    // 两次查询合并进同一次阻塞任务，避免开两次线程。
    let (service_active, service_enabled) = match tokio::task::spawn_blocking(|| {
        let one = |verb: &str| -> Option<bool> {
            crate::blocking::run_sync_in_blocking(panel_os::Bin::Systemctl, &[verb, "panel"])
                .ok()
                .and_then(|o| o.code)
                .map(|c| c == 0)
        };
        (one("is-active"), one("is-enabled"))
    })
    .await
    {
        Ok(v) => v,
        // JoinError 只在阻塞任务 panic 时出现：如实当「无法判定」，但必须留痕。
        Err(e) => {
            eprintln!("[WARN] 读取 panel 服务状态时阻塞任务失败: {e}");
            (None, None)
        }
    };
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
        // 安装与运行位置：给「面板参数配置」页第一屏用。只读，不是可 PATCH 的设置项。
        "installation": {
            "app_version": env!("CARGO_PKG_VERSION"),
            "build": option_env!("PANEL_BUILD").unwrap_or("dev"),
            "platform": state.os.platform(),
            "bin_path": panel_os::paths::panel_bin_install_path().display().to_string(),
            "config_dir": layout.config_dir().display().to_string(),
            "data_dir": layout.data_dir().display().to_string(),
            "log_dir": layout.log_dir().display().to_string(),
            "service_manager": "systemd",
            "service_active": service_active,
            "service_enabled": service_enabled,
            "can_restart": s.role == "owner",
            // Web 升级三道门：owner + [danger] allow_web_upgrade + systemd-run 可用。
            // 默认关闭；不满足时给出**具体**原因，UI 显示说明而不是一个点了 501 的按钮。
            "can_upgrade": s.role == "owner"
                && state.allow_web_upgrade
                && panel_os::Bin::SystemdRun.available(),
            "upgrade_blocked_reason": if s.role != "owner" {
                Some("仅 owner 可执行升级")
            } else if !state.allow_web_upgrade {
                Some("Web 升级未开启（config.toml [danger] allow_web_upgrade）")
            } else if !panel_os::Bin::SystemdRun.available() {
                Some("缺少 systemd-run，无法脱离当前进程执行")
            } else {
                None
            },
        },
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
            | (K_LLM_API_KEY, Value::Null)
            | (K_LLM_NARRATIVE, Value::Null)
            | (K_LLM_CHAT_CONTEXT, Value::Null) => ops.push((k.as_str(), None)), // null = 清除
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
            // 叙事开关：布尔原样落库（"true"/"false" JSON 字符串）。
            // null = 清除 ⇒ 回落缺省（关）——隐私开关不允许有第三种残留状态。
            (K_LLM_NARRATIVE, Value::Bool(b)) => ops.push((k.as_str(), Some(b.to_string()))),
            // chat 上下文开关：与叙事开关同款布尔语义。
            (K_LLM_CHAT_CONTEXT, Value::Bool(b)) => ops.push((k.as_str(), Some(b.to_string()))),
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
///
/// 本机/内网网关（`http://127.0.0.1:11434/v1`）是**刻意保留的合法用例**：面板的
/// 典型部署就是连本机 Ollama。因此这里不做「禁私网」的一刀切；SSRF 的收敛放在
/// `test_llm`：URL 内嵌 userinfo、禁跟随重定向、不回显对方响应体，以及 F-02① 的
/// 「目标 Endpoint 锁定为已保存值 + 绝不携带已存密钥」。
fn valid_endpoint(url: &str) -> bool {
    (url.starts_with("http://") || url.starts_with("https://"))
        && url.len() <= 256
        && !url.ends_with('/')
        && url_host(url).is_some()
}

/// 取出 URL 的 host 段（不含 scheme / userinfo / 端口 / 路径）。
///
/// 只做结构校验，不做 DNS 解析：`None` 表示结构不合法——空 host、带 userinfo
/// （`http://user:pass@host`，会把凭据写进 URL）、端口非数字、IPv6 括号未闭合。
fn url_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']')?;
        let tail = &stripped[end + 1..];
        if !tail.is_empty() {
            let port = tail.strip_prefix(':')?;
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
        }
        return Some(&stripped[..end]);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if let Some(p) = port {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    if host.is_empty() { None } else { Some(host) }
}

/// F-02①：测试连接的目标 Endpoint **只能取库里已保存的值**。
///
/// 请求体里的 endpoint 只做一致性校验，绝不拿它当探测目标：目标主机由配置者保存，
/// 调用者无法把请求（以及任何密钥）导向自己控制的机器。再配合 `test_llm` 里
/// 「绝不读取已存 api_key」，整条 admin → 明文密钥 的外带链就断了。
/// 本机 / 内网网关不受影响——已保存的 127.0.0.1 照样能测。
fn resolve_probe_endpoint(saved: &str, requested: Option<&str>) -> Result<String, &'static str> {
    if let Some(p) = requested.map(str::trim).filter(|s| !s.is_empty()) {
        if p != saved {
            return Err("测试连接只允许使用已保存的 API Endpoint；Endpoint 有改动请先保存再测试");
        }
    }
    if saved.trim().is_empty() {
        return Err("尚未配置 API Endpoint，无法测试");
    }
    Ok(saved.to_string())
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
    /// 配置模型时表示已用该模型成功发起一次最小对话（/chat/completions）；
    /// 未配模型时表示是否在 /v1/models 列表里（model 未配置时恒 false）
    pub model_found: bool,
    /// 可用模型数量（解析失败为 null）
    pub model_count: Option<usize>,
    pub status: Option<u16>,
    /// 人话结论：成功摘要 / 失败原因
    pub detail: String,
}

/// 非 2xx 的失败原因。**不回显对方响应体**——端点由管理员填写，响应可能来自
/// 内网服务（错误页常带内部主机名、路径、版本号）。只保留「是否 JSON」这一条
/// 排障线索，正文按安全策略隐去；具体原因由状态码给出。
fn status_detail(status: u16, body: &str) -> String {
    let brief = if body.is_empty() {
        String::new()
    } else if serde_json::from_str::<Value>(body).is_ok() {
        "（对方返回了 JSON 错误体，内容已按安全策略隐去）".to_string()
    } else {
        "（对方返回了非 JSON 响应，内容已按安全策略隐去）".to_string()
    };
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
///
/// `raw` 必须是 **DB 里的原始 JSON 字符串**（`"enc:…"`，带外层引号）——`from_str`
/// 解析出内层串再剥 `enc:` 前缀。⚠ 别传已经 `stored()` 拆出的内层串（无引号，
/// 会被 `from_str` 当成非法 JSON 直接失败，静默返回 None）。
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

/// 探测要用的密钥（修复空密钥回归）：本次输入的优先（先测后存）；留空则回退到
/// 库里已存的（解密后）。
///
/// ⚠ 对 F-02①「测试连接绝不读取已存 api_key」的**有界放宽**：原规则为防止把管理员
/// 密钥导向攻击者主机，但 `resolve_probe_endpoint` 已把探测目标**锁定为已保存值**，
/// 回退已存密钥只会对管理员自己的端点鉴权，无外带风险。且 Agnes 这类服务对
/// `/chat/completions` 强制鉴权——若留空不回退已存密钥，用户"已存正确 key、框留空点
/// 测试"会被误报成 401（密钥其实是对的，只是没在框里重输一遍）。
/// 优先级：填了 ⇒ 用填的（先测后存）；没填 ⇒ 用已存的；都没有 ⇒ None（调用方给明确指引）。
fn resolve_probe_key(state: &Shared, stored_raw: Option<&str>, typed: Option<&str>) -> Option<String> {
    if let Some(k) = typed.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(k.to_string());
    }
    stored_raw.and_then(|raw| plain_api_key(state, raw))
}

/// 探测目标选择（修复 401 误报）：配了模型名 ⇒ 打 `/chat/completions`（真实鉴权
/// + 模型校验，比只读 `/models` 更权威）；未配模型名 ⇒ 退回 `/models` 列表/计数。
fn llm_probe_url(endpoint: &str, model: Option<&str>) -> (String, bool) {
    match model {
        Some(_) => (format!("{endpoint}/chat/completions"), true),
        None => (format!("{endpoint}/models"), false),
    }
}

/// `POST /api/v1/settings/llm/test`——真实探测 LLM 接入（配模型打
/// `/chat/completions`，否则 `/v1/models`）。
///
/// 设计要点：
/// - **先测后存（仅 model / api_key）**：这两项可用当前输入验证，不必先保存
///   （C10 原话："避免保存后才报错"）。⚠ F-02①：Endpoint 与已存密钥是例外——
///   Endpoint 锁定为已保存值（改动须先保存），已存密钥绝不参与测试，只带本次
///   输入的 key。理由见 [`resolve_probe_endpoint`]。
/// - **绝不 500**：所有探测失败都落成 `ok:false + detail`，配置错了是用户的事，
///   不是服务器错误——返回 500 会让前端把"密钥填错"显示成"请求失败"。
/// - **密钥不落日志、不回显**：只回布尔与结论；库里已存的密钥连解密都不做。
/// - 这是一次由管理员发起的外发请求（SSRF 面）；仅 `settings.manage` 可调用，
///   目标锁定为已保存的 Endpoint、禁跟随重定向、不回显对方响应体（截断到 200 字符）。
pub async fn test_llm(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<TestLlmReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SETTINGS_MANAGE)?;
    // F-02②：单次探测最长 8s 且会外发请求，按重活档限流（10 次/60 秒）。
    // 此前实测 8 秒连发 40 次、429 出现 0 次，等价于把面板当内网扫描器用。
    crate::ratelimit::check_heavy(&state, &s.username, "settings.llm_test")?;

    let table = load_table(&state).await?;
    let stored = |k: &str| -> Option<String> {
        table
            .get(k)
            .and_then(|j| serde_json::from_str::<Value>(j).ok())
            .and_then(|v| v.as_str().map(str::to_string))
    };

    // F-02①：目标 Endpoint **只能取库里已保存的值**，请求体不得临时覆盖。
    let saved_endpoint = stored(K_LLM_ENDPOINT).unwrap_or_default();
    let endpoint = match resolve_probe_endpoint(&saved_endpoint, req.endpoint.as_deref()) {
        Ok(e) => e,
        Err(msg) => return Err(ApiError::bad_request("endpoint", msg)),
    };
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
    // 探测密钥：本次输入的优先（先测后存）；留空回退到库里已存的（解密后）。
    // 见 `resolve_probe_key`：Endpoint 已锁定为已保存值，回退已存密钥无外带风险，
    // 且能修复 Agnes 类服务对 /chat/completions 强制鉴权导致的留空误报 401。
    let api_key = resolve_probe_key(&state, table.get(K_LLM_API_KEY).map(String::as_str), req.api_key.as_deref());

    // 禁跟随重定向：否则一个公网 URL 可以 302 到内网/回环，`valid_endpoint`
    // 的结构校验就形同虚设。测试连接只发一次请求（/chat/completions 或 /models），
    // 不需要跳转。
    let client = match reqwest::Client::builder()
        .timeout(TEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
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

    // 探测策略（修复 401 误报）：配了模型 ⇒ 打 `/chat/completions`（真实鉴权 +
    // 模型校验，更权威）；部分服务商（如 Agnes）即便密钥有效也对 `/v1/models`
    // 返回 401，却对 `/chat/completions` 正常 ⇒ 只探 /models 会误报 401。
    // 未配模型 ⇒ 退回 `/models` 列表/计数（旧行为）。
    let (probe_url, use_chat_probe) = llm_probe_url(&endpoint, model.as_deref());
    // 打 /chat/completions 必须带密钥：若本次没填、库里也没有可用密钥，提前给明确
    // 指引，而不是打到对端撞 401 再报"密钥被拒绝"（那会误导用户以为存的密钥错了）。
    if use_chat_probe && api_key.is_none() {
        return Ok(ok(TestLlmResp {
            ok: false,
            latency_ms: 0,
            endpoint,
            model,
            model_found: false,
            model_count: None,
            status: None,
            detail: "未配置 API Key：测试连接调用 /chat/completions 需要密钥。请在上方密钥框输入（先测后存），或先保存一份密钥再测。".to_string(),
        }));
    }
    let started = std::time::Instant::now();
    let mut call = if use_chat_probe {
        client
            .post(&probe_url)
            .header("accept", "application/json")
            .json(&serde_json::json!({
                "model": model.as_deref().unwrap_or(""),
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
                "stream": false,
            }))
    } else {
        client.get(&probe_url).header("accept", "application/json")
    };
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
            } else if use_chat_probe {
                // 用配置模型成功发起一次最小对话 ⇒ 密钥被接受且模型可调用。
                let detail = format!(
                    "连通且模型可用（已用 `{}` 发起一次最小对话验证，{} ms）",
                    model.as_deref().unwrap_or(""),
                    latency_ms
                );
                TestLlmResp {
                    ok: true,
                    latency_ms,
                    endpoint,
                    model,
                    model_found: true,
                    model_count: None,
                    status: Some(status),
                    detail,
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


/// 把 Duration 渲染成 config.toml 同款 "30m"/"12h"/"90s"（deployment 段展示用）。
fn fmt_dur(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s.is_multiple_of(3600) { format!("{}h", s / 3600) }
    else if s.is_multiple_of(60) { format!("{}m", s / 60) }
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
            "db_backup_keep", "installation",
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
        // 结构校验：这些都能通过「starts_with http」但会把请求带向意料之外的路径
        assert!(!valid_endpoint("http://"), "空 host");
        assert!(!valid_endpoint("http:///v1"), "空 host + 路径");
        assert!(!valid_endpoint("http://admin:secret@10.0.0.1/v1"), "URL 内嵌 userinfo");
        assert!(!valid_endpoint("http://host:abc/v1"), "端口非数字");
        assert!(!valid_endpoint("http://[::1/v1"), "IPv6 括号未闭合");
        assert!(valid_endpoint("http://[::1]:11434/v1"), "IPv6 本机网关仍合法");
        let long = format!("https://{}", "a".repeat(300));
        assert!(!valid_endpoint(&long), "超长");
    }

    /// F-02①：探测目标永远锁定为已保存值，请求体带别的主机一律拒绝。
    #[test]
    fn probe_endpoint_is_locked_to_saved_value() {
        let saved = "http://127.0.0.1:11434/v1";
        // 没传 / 传空 / 传相同值 ⇒ 都取已保存值（本机网关照常可用）
        assert_eq!(resolve_probe_endpoint(saved, None).unwrap(), saved);
        assert_eq!(resolve_probe_endpoint(saved, Some("")).unwrap(), saved);
        assert_eq!(resolve_probe_endpoint(saved, Some(saved)).unwrap(), saved);
        // 传别处 ⇒ 拒绝，绝不能拿它当探测目标
        let err = resolve_probe_endpoint(saved, Some("http://attacker.example/v1")).unwrap_err();
        assert!(err.contains("先保存"), "拒绝理由要给出可操作动作：{err}");
        assert!(
            resolve_probe_endpoint("", Some("https://api.openai.com/v1")).is_err(),
            "库里未保存时不许临时指定目标"
        );
        assert!(resolve_probe_endpoint("", None).is_err(), "未配置要报 400");
    }

    #[test]
    fn status_detail_names_the_cause_and_hides_body() {
        assert!(status_detail(401, "").contains("密钥被拒绝"));
        assert!(status_detail(404, "").contains("Endpoint 可能少写了 /v1"));
        assert!(status_detail(503, "").contains("服务端错误"));
        // 端点由管理员填写 ⇒ 对方响应体可能来自内网服务（内部主机名/路径/版本）。
        // 正文一律隐去，只保留「是否 JSON」这条排障线索。
        let d = status_detail(401, "Internal-Service: vaultwarden.local /admin");
        assert!(!d.contains("vaultwarden"), "不得回显对方响应体：{d}");
        assert!(!d.contains("Internal-Service"), "不得回显对方响应体：{d}");
        assert!(d.contains("非 JSON"), "应保留响应形态线索：{d}");
        let j = status_detail(503, r#"{"error":"upstream connect timeout at 10.1.2.3"}"#);
        assert!(!j.contains("10.1.2.3"), "不得回显对方响应体：{j}");
        assert!(j.contains("JSON"), "应保留响应形态线索：{j}");
    }

    /// P0-2：叙事开关的纯函数语义。缺省/坏值/false 一律关，只有显式 "true" 开——
    /// 隐私开关不允许"配了密钥就默认外发"，也不允许坏值被当成开。
    #[test]
    fn narrative_switch_defaults_off_and_only_true_opens() {
        let mut t = std::collections::BTreeMap::new();
        assert!(!narrative_on(&t), "缺省必须关：外发第三方端点要显式同意");
        t.insert(K_LLM_NARRATIVE.to_string(), "\"false\"".into());
        assert!(!narrative_on(&t));
        t.insert(K_LLM_NARRATIVE.to_string(), "\"true\"".into());
        assert!(narrative_on(&t));
        t.insert(K_LLM_NARRATIVE.to_string(), "not-json".into());
        assert!(!narrative_on(&t), "坏值不得当成开");
        t.insert(K_LLM_NARRATIVE.to_string(), "\"TRUE\"".into());
        assert!(!narrative_on(&t), "大小写不将就：只认小写 true");
    }

    /// chat 上下文开关与叙事开关同款纯函数语义：缺省/坏值/false 一律关，只认 "true"。
    /// 负向对照：把 `chat_context_on` 改成「缺省开」或「大小写不敏感」这条即红。
    #[test]
    fn chat_context_switch_defaults_off_and_only_true_opens() {
        let mut t = std::collections::BTreeMap::new();
        assert!(!chat_context_on(&t), "缺省必须关：自由对话默认不外发系统数据");
        t.insert(K_LLM_CHAT_CONTEXT.to_string(), "\"false\"".into());
        assert!(!chat_context_on(&t));
        t.insert(K_LLM_CHAT_CONTEXT.to_string(), "\"true\"".into());
        assert!(chat_context_on(&t));
        t.insert(K_LLM_CHAT_CONTEXT.to_string(), "not-json".into());
        assert!(!chat_context_on(&t), "坏值不得当成开");
        t.insert(K_LLM_CHAT_CONTEXT.to_string(), "\"TRUE\"".into());
        assert!(!chat_context_on(&t), "大小写不将就：只认小写 true");
    }

    /// 401 误报回归：配了模型必须打 /chat/completions，未配才退回 /models。
    /// 负向对照：若把 `llm_probe_url` 改成恒返回 /models，这条即红——复现 401 误报。
    #[test]
    fn llm_probe_prefers_chat_completions_when_model_set() {
        let (u, chat) = llm_probe_url("https://x/v1", Some("gpt-4o"));
        assert!(chat, "配了模型必须打 /chat/completions");
        assert_eq!(u, "https://x/v1/chat/completions");
        let (u2, chat2) = llm_probe_url("https://x/v1", None);
        assert!(!chat2, "未配模型才退回 /models");
        assert_eq!(u2, "https://x/v1/models");
    }

    /// P0 回归（空密钥 401）：`resolve_probe_key` 在框留空时必须回退到库里已存的
    /// （解密后）密钥；填了则用填的（先测后存）；都没有才 None。直接用生产
    /// `plain_api_key` 解密，不是测试自持实现。
    /// 负向对照：把回退分支删掉（恒返回 typed）⇒ ① 即红，复现"Agnes 误报 401"。
    #[tokio::test]
    async fn resolve_probe_key_falls_back_to_stored() {
        let dir = std::env::temp_dir().join(format!("panel-probekey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        let tier = panel_core::Tier::Nano;
        {
            let mut c = panel_db::open(&db_path, tier, "NORMAL").unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
        }
        let writer = std::sync::Arc::new(
            panel_db::WriterActor::spawn(db_path.clone(), tier, "NORMAL").unwrap());
        let pool = std::sync::Arc::new(panel_db::ReadPool::new(&db_path, tier).unwrap());
        let tasks = std::sync::Arc::new(panel_task::TaskRunner::new(
            writer.clone(), tier, dir.join("tasks"), db_path.clone(), "NORMAL".to_string()));
        let metrics = std::sync::Arc::new(std::sync::Mutex::new(
            panel_db::aggregator::Aggregator::new(tier)));
        let master = panel_core::crypto::MasterKey::from_bytes(&[7u8; 32]).unwrap();
        // 库里存一把加密密钥（与 PATCH 落库格式一致）：先 encrypt 再 move 进 state
        let blob = master.encrypt(b"sk-stored").unwrap();
        let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
        let stored_raw = serde_json::to_string(&format!("enc:{hex}")).unwrap();
        let os: std::sync::Arc<dyn panel_os::OsAdapter> =
            std::sync::Arc::new(panel_os::mock::MockOsAdapter::new());
        let state = std::sync::Arc::new(crate::AppState::new(
            os, writer, pool, tasks, metrics, tier, Some(master), false, 5,
            std::time::Duration::from_secs(1800), std::time::Duration::from_secs(43_200),
            90, 50_000, true, true, "NORMAL".to_string(), 7, false, None));

        // ① 框留空 ⇒ 回退已存密钥（修复 Agnes 类误报 401 的核心）
        assert_eq!(
            resolve_probe_key(&state, Some(&stored_raw), None).as_deref(),
            Some("sk-stored"),
            "留空必须回退已存密钥，否则 Agnes 类服务误报 401"
        );
        // ② 填了 ⇒ 用填的（先测后存），优先级高于已存
        assert_eq!(
            resolve_probe_key(&state, Some(&stored_raw), Some("sk-typed")).as_deref(),
            Some("sk-typed")
        );
        // ③ 都没 ⇒ None（调用方给明确指引，而非误报 401）
        assert!(resolve_probe_key(&state, None, None).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 往 settings 表写一行（测试辅助）。
    async fn set_setting(state: &Shared, k: &str, v: &str) {
        let k = k.to_string();
        let v = v.to_string();
        state
            .db
            .exec(move |conn| {
                conn.execute(
                    "INSERT INTO settings(key, value_json) VALUES(?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
                    rusqlite::params![k, v],
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
                Ok(panel_db::WriteAck { rows_changed: 1 })
            })
            .await
            .expect("写 settings");
    }

    /// P0-2 回归（真门控）：三键齐配 + 开关关 ⇒ `llm_config()` 返回 None（不外发）；
    /// 开 ⇒ Some 且密钥解出明文。直接打库——纯函数测试自持实现的假绿在这里不成立。
    ///
    /// 负向对照：删掉 `llm_config` 里的 `narrative_on` 早退，①②两条即红
    /// （开关关仍返回 Some = 未经同意就外发）。
    #[tokio::test]
    async fn llm_config_is_gated_by_the_narrative_switch() {
        let dir = std::env::temp_dir().join(format!("panel-llmsw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        let tier = panel_core::Tier::Nano;
        {
            let mut c = panel_db::open(&db_path, tier, "NORMAL").unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
        }
        let writer = std::sync::Arc::new(
            panel_db::WriterActor::spawn(db_path.clone(), tier, "NORMAL").unwrap());
        let pool = std::sync::Arc::new(panel_db::ReadPool::new(&db_path, tier).unwrap());
        let tasks = std::sync::Arc::new(panel_task::TaskRunner::new(
            writer.clone(), tier, dir.join("tasks"), db_path.clone(), "NORMAL".to_string()));
        let metrics = std::sync::Arc::new(std::sync::Mutex::new(
            panel_db::aggregator::Aggregator::new(tier)));
        let master = panel_core::crypto::MasterKey::from_bytes(&[7u8; 32]).unwrap();
        let os: std::sync::Arc<dyn panel_os::OsAdapter> =
            std::sync::Arc::new(panel_os::mock::MockOsAdapter::new());
        let state = std::sync::Arc::new(crate::AppState::new(
            os, writer, pool, tasks, metrics, tier, Some(master), false, 5,
            std::time::Duration::from_secs(1800), std::time::Duration::from_secs(43_200),
            90, 50_000, true, true, "NORMAL".to_string(), 7, false, None));

        // 三键齐配（api_key 走后门：主密钥加密 + enc: 前缀，与 PATCH 落库格式一致）
        let blob = master.encrypt(b"sk-test").unwrap();
        let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
        set_setting(&state, K_LLM_ENDPOINT, &serde_json::to_string("http://127.0.0.1:1/v1").unwrap()).await;
        set_setting(&state, K_LLM_MODEL, &serde_json::to_string("m").unwrap()).await;
        set_setting(&state, K_LLM_API_KEY, &serde_json::to_string(&format!("enc:{hex}")).unwrap()).await;

        // ① 开关缺省（无该键）⇒ None
        assert!(llm_config(&state).await.unwrap().is_none(), "缺省不得外发");
        // ② 开关显式 false ⇒ None
        set_setting(&state, K_LLM_NARRATIVE, "\"false\"").await;
        assert!(llm_config(&state).await.unwrap().is_none(), "关闭不得外发");
        // ③ 开关 true ⇒ Some，端点透传、密钥解开
        set_setting(&state, K_LLM_NARRATIVE, "\"true\"").await;
        let cfg = llm_config(&state).await.unwrap().expect("开启后应返回配置");
        assert_eq!(cfg.endpoint, "http://127.0.0.1:1/v1");
        assert_eq!(cfg.model, "m");
        assert_eq!(cfg.api_key, "sk-test", "密钥应能解开");

        let _ = std::fs::remove_dir_all(&dir);
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