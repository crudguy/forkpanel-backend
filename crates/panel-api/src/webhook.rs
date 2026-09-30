//! Webhook 投递（P2-3 cron 回调 / P2-10 通知通道 共用）。
//!
//! **设计选择**：原计划用 `reqwest`（占 1 个直接依赖位），但项目硬纪律是"全项目唯一
//! 子进程出口在 `panel-os::cmd`"，且依赖预算 [8] 仅剩 1 位（当前 37/38）。改用
//! `Bin::Curl` 经 cmd 唯一出口投递，**零新增依赖、复用子进程纪律**，且保留预算余量。
//!
//! 纪律：
//! 1. 仅接受 http/https，且经 `validate_url` 拦截控制字符与 `file://` 等危险协议（防 SSRF）。
//! 2. URL 与 JSON body 各自作为**单个 argv 参数**传给 curl，不经 shell、无拼接注入。
//! 3. 固定 `--max-time` 上限 + `--fail`（HTTP 错误不当成功）。
//! 4. 投递失败只返回 Err，**绝不中断调用方业务**（通知/回调失败不应让主任务失败）。

use crate::{
    auth::perm,
    error::{ok, ApiResult},
    routes::{Auth, Shared},
};
use axum::{extract::State, Json};
use panel_core::PanelError;
use panel_os::cmd::{Bin, CmdOpt};
use serde_json::Value;
use std::time::Duration;

/// 校验 Webhook URL：仅 http/https、长度有界、无控制字符/空格。
pub fn validate_url(url: &str) -> Result<(), PanelError> {
    if url.len() > 2048 {
        return Err(PanelError::Validation { field: "webhook_url", reason: "too long".into() });
    }
    if url.is_empty()
        || url.contains(|c: char| c.is_control() || c == ' ' || c == '\n' || c == '\r')
    {
        return Err(PanelError::Validation {
            field: "webhook_url",
            reason: "illegal characters".into(),
        });
    }
    // 仅允许 http/https 绝对 URL；拒绝 file://、ftp://、相对等（防 SSRF / 本地文件读取）
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(PanelError::Validation {
            field: "webhook_url",
            reason: "only http(s) allowed".into(),
        });
    }
    Ok(())
}

/// 投递一次 Webhook。失败返回 Err，由调用方决定记录/忽略。
pub async fn fire(url: &str, payload: &Value) -> Result<(), PanelError> {
    validate_url(url)?;
    if !Bin::Curl.available() {
        // 宿主无 curl：诚实失败（前端据此提示），不假装投递成功
        return Err(PanelError::Unsupported("curl"));
    }
    let body = serde_json::to_string(payload)
        .map_err(|e| PanelError::Internal(format!("webhook json: {e}")))?;
    let out = panel_os::cmd::run(
        Bin::Curl,
        &[
            "--silent", "--show-error", "--fail",
            "--max-time", "10",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-H", "User-Agent: forkpanel-webhook/0.1",
            "--data", &body,
            url,
        ],
        CmdOpt { timeout: Duration::from_secs(12), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Err(PanelError::Command {
            bin: "curl".into(),
            detail: format!("webhook exit={:?} {}", out.code, truncate(&out.stderr, 500)),
        });
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() > n { format!("{}…", &s[..n]) } else { s.to_string() }
}

// ─────────────── 端点：测试 Webhook（向给定 URL 发一条测试事件） ───────────────

#[derive(Debug, serde::Deserialize)]
pub struct TestReq {
    pub url: String,
}

/// POST /api/v1/cron/webhook/test —— 验证 URL 可达且接受 POST JSON。
/// 测试属"探针"语义：失败不返回 HTTP 错误，而以 `{ok:false, error}` 呈现，
/// 让用户看到具体原因（curl 未装 / 网络不可达 / 对方 4xx）。
pub async fn test(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<TestReq>,
) -> ApiResult<Json<Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    // Webhook 投递不依赖 scheduler 能力；curl 可用性在 fire 内判定。
    let _ = &state;
    let payload = serde_json::json!({
        "event": "test",
        "panel": "forkpanel",
        "ts": crate::now_unix(),
    });
    match fire(&req.url, &payload).await {
        Ok(()) => Ok(ok(serde_json::json!({ "ok": true }))),
        Err(e) => Ok(ok(serde_json::json!({ "ok": false, "error": e.to_string() }))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation_blocks_dangerous_schemes() {
        assert!(validate_url("https://example.com/hook").is_ok());
        assert!(validate_url("http://192.168.1.10:9000/x").is_ok());
        // 非 http(s)
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("javascript:alert(1)").is_err());
        // 控制字符 / 空格
        assert!(validate_url("https://a.com/x y").is_err());
        assert!(validate_url("https://a.com/\n").is_err());
        // 超长
        assert!(validate_url(&format!("https://a.com/{}", "x".repeat(2049))).is_err());
    }

    #[test]
    fn url_validation_requires_absolute_http() {
        // 相对/无协议一律拒绝（防 SSRF 与本地文件）
        assert!(validate_url("/internal/api").is_err());
        assert!(validate_url("example.com").is_err());
    }
}
