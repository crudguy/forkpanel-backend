//! 错误码与 HTTP 映射（设计方案 §3.4 错误码分段）。

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use panel_core::PanelError;
use serde_json::json;

/// handler 统一返回类型。注意：**不是** `panel_core::Result`（它只有 1 个泛型参数，
/// 固定第二参数为 PanelError）。handler 必须把领域错误经 `From<PanelError>` 转成 ApiError。
pub type ApiResult<T> = Result<T, ApiError>;

/// 统一错误：携带错误码、人类可读消息与可选明细
#[derive(Debug)]
pub struct ApiError {
    pub code: u32,
    pub status: StatusCode,
    pub message: String,
    pub detail: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(code: u32, status: StatusCode, message: impl Into<String>) -> Self {
        Self { code, status, message: message.into(), detail: None }
    }
    pub fn with_detail(mut self, d: serde_json::Value) -> Self { self.detail = Some(d); self }

    pub fn bad_request(field: &'static str, reason: impl Into<String>) -> Self {
        Self::new(10001, StatusCode::BAD_REQUEST, "invalid input")
            .with_detail(json!({ "field": field, "reason": reason.into() }))
    }
    pub fn unauthorized() -> Self { Self::new(10002, StatusCode::UNAUTHORIZED, "not authenticated") }
    pub fn forbidden(perm: &'static str) -> Self {
        Self::new(10003, StatusCode::FORBIDDEN, "permission denied")
            .with_detail(json!({ "required": perm }))
    }
    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new(10004, StatusCode::NOT_FOUND, what.into())
    }
    pub fn conflict(what: impl Into<String>) -> Self {
        Self::new(10005, StatusCode::CONFLICT, what.into())
    }
    pub fn too_many_requests(retry_after: u64) -> Self {
        Self::new(10006, StatusCode::TOO_MANY_REQUESTS, "rate limited")
            .with_detail(json!({ "retry_after_secs": retry_after }))
    }
    pub fn read_only() -> Self { Self::new(10007, StatusCode::FORBIDDEN, "read-only mode") }
    pub fn csrf() -> Self { Self::new(10008, StatusCode::FORBIDDEN, "csrf token missing or invalid") }
    pub fn unsupported(what: impl Into<String>) -> Self {
        Self::new(10009, StatusCode::NOT_IMPLEMENTED, what.into())
    }
    /// 首启引导令牌无效/已过期/已使用（10010 已预留给 MFA 动态口令）
    pub fn bootstrap_invalid() -> Self {
        Self::new(10011, StatusCode::UNAUTHORIZED, "bootstrap token invalid or expired")
    }
}

/// 领域错误 → HTTP 错误的**唯一**映射点，保证错误码在前后端一致
impl From<PanelError> for ApiError {
    fn from(e: PanelError) -> Self {
        let code = e.code();
        let status = match code {
            10001 => StatusCode::BAD_REQUEST,
            10003 => StatusCode::FORBIDDEN,
            10004 => StatusCode::NOT_FOUND,
            10005 => StatusCode::CONFLICT,
            10009 => StatusCode::NOT_IMPLEMENTED,
            30000 => StatusCode::BAD_GATEWAY,      // 外部命令失败
            40002 => StatusCode::UNPROCESSABLE_ENTITY, // 配置校验失败（nginx -t）
            50001 => StatusCode::BAD_REQUEST,      // 路径越界
            50002 => StatusCode::INTERNAL_SERVER_ERROR, // 文件 / IO 失败
            60000 => StatusCode::INTERNAL_SERVER_ERROR,
            80003 => StatusCode::GATEWAY_TIMEOUT,
            10999 => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let detail = match &e {
            PanelError::Validation { field, reason } => Some(json!({"field": field, "reason": reason})),
            PanelError::Command { bin, detail } => Some(json!({"bin": bin, "stderr": detail})),
            PanelError::ConfigInvalid { detail } => Some(json!({"output": detail})),
            PanelError::PermissionDenied(p) => Some(json!({"required": p})),
            _ => None,
        };
        Self { code, status, message: e.to_string(), detail }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // 安全：不回显内部堆栈；detail 已在构造侧做过裁剪
        let body = json!({
            "code": self.code,
            "message": self.message,
            "data": null,
            "detail": self.detail,
        });
        (self.status, Json(body)).into_response()
    }
}

/// 成功响应包装。注意：不实现 From<T>，避免业务值被静默包装而绕过审计。
pub fn ok<T: serde::Serialize>(data: T) -> axum::response::Json<serde_json::Value> {
    Json(json!({ "code": 0, "message": "ok", "data": data }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_error_maps_to_segment() {
        let e: ApiError = PanelError::PathEscape("../../etc/passwd".into()).into();
        assert_eq!(e.code, 50001);
        assert_eq!(e.status, StatusCode::BAD_REQUEST);

        let e: ApiError = PanelError::PermissionDenied("site.manage").into();
        assert_eq!(e.code, 10003);
        assert_eq!(e.status, StatusCode::FORBIDDEN);

        let e: ApiError = PanelError::Unsupported("firewall.apply").into();
        assert_eq!(e.code, 10009);
        assert_eq!(e.status, StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn config_invalid_is_422() {
        let e: ApiError = PanelError::ConfigInvalid { detail: "nginx: [emerg] unknown directive".into() }.into();
        assert_eq!(e.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn csrf_and_readonly_codes() {
        assert_eq!(ApiError::csrf().code, 10008);
        assert_eq!(ApiError::read_only().code, 10007);
    }
}
