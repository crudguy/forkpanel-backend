//! 请求体提取器：`PanelJson<T>` —— 把 axum 的默认 rejection 收进统一信封。
//!
//! ## 为什么不用 `axum::Json` 直接当提取器
//! `Json::<T>` 的 `Rejection` 是 `JsonRejection`，axum 会把它直接渲染成
//! **422 + 纯文本英文**：
//!
//! ```text
//! Failed to deserialize the JSON body into the target type: missing field `expr` at line 1 column 9
//! ```
//!
//! 三个问题：
//! 1. **破坏信封契约**：全站响应都是 `{code,message,data,request_id}`，只有这一条是裸文本；
//! 2. **英文 + 内部实现细节**漏给用户（前端 `errorText` 拿不到 `message`，只能显示
//!    `statusText` = "Unprocessable Entity"）；
//! 3. **字段名只藏在英文句子里**，脚本调用方没法结构化处理。
//!
//! 本提取器把 rejection 翻成 10001（`detail.field` + 中文 reason），原文用 `eprintln!`
//! 留在服务端日志（与其他 handler 的日志口径一致）。
//!
//! ⚠ **注意顺序**：提取发生在 handler 之前，所以"未授权用户发坏 body"会先拿到 10001
//! 而不是 403 —— 这只会透露字段名，不泄露数据；要彻底按权限先拒需把鉴权提到
//! 路由层中间件，属更大改动，暂不做。

use axum::extract::{FromRequest, Json, Request};
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// 与 `axum::Json` 用法一致，但失败时返回统一信封。
pub struct PanelJson<T>(pub T);

impl<T, S> FromRequest<S> for PanelJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(PanelJson(v)),
            Err(rej) => {
                let raw = rej.body_text();
                eprintln!("[panel-api] 请求体解析失败: {raw}");
                Err(ApiError::bad_request("body", humanize(&raw)))
            }
        }
    }
}

/// 把 serde/axum 的英文 rejection 文本翻成一句用户能懂的中文。
///
/// 只覆盖真实会遇到的几类（缺字段 / 类型不符 / 不是合法 JSON / 空 body）。
/// 刻意**不**尝试完整解析英文句子——匹配不上就退到通用文案，原文已在日志里。
fn humanize(raw: &str) -> String {
    let s = raw.trim();

    // missing field `expr`
    if let Some(rest) = s.split("missing field `").nth(1) {
        if let Some(field) = rest.split('`').next() {
            return format!("缺少必填字段「{field}」");
        }
    }
    // 语法层失败（`{oops` 之类）——axum 的文案以这句开头，先于字段级错误判断
    if s.contains("Failed to parse the request body as JSON") {
        return "请求体不是合法的 JSON（语法错误）".to_string();
    }
    // `name: invalid type: integer 1, expected a string` —— 前缀就是字段路径
    if let Some(idx) = s.find(": invalid type:") {
        // axum 会把整句前缀带进来（`Failed to …: name`），字段名是最后一个 ": " 之后那段
        let raw_field = s[..idx].rsplit(": ").next().unwrap_or("");
        // 只接受"像字段路径"的前缀（含点号表示嵌套），避免把整句英文当前缀
        if !raw_field.is_empty()
            && raw_field.len() < 64
            && raw_field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            return format!("字段「{raw_field}」类型不正确");
        }
        return "字段类型不正确（请检查数值/布尔/字符串是否填错）".to_string();
    }
    // expected value at line 1 column 1
    if s.contains("expected value") || s.contains("expected ident") || s.contains("EOF") {
        return "请求体不是合法的 JSON".to_string();
    }
    if s.contains("length limit") {
        return "请求体过大".to_string();
    }
    if s.contains("Failed to buffer") || s.contains("body") && s.contains("empty") {
        return "请求体为空或读取失败".to_string();
    }
    "请求体格式不正确".to_string()
}

#[cfg(test)]
mod tests {
    use super::humanize;

    /// 判据取自 axum/serde 的真实文案（见 commit 说明里的复现记录）。
    /// 只断言"翻成了中文且带关键信息"，不断言整句——文案可调，语义不能丢。
    #[test]
    fn humanizes_missing_field() {
        let raw = "Failed to deserialize the JSON body into the target type: \
                   missing field `expr` at line 1 column 9";
        let zh = humanize(raw);
        assert!(zh.contains("expr"), "必须保留字段名，否则用户不知道该补什么: {zh}");
        assert!(zh.contains("缺少"), "{zh}");
    }

    #[test]
    fn humanizes_type_mismatch() {
        let zh = humanize("Failed to deserialize the JSON body into the target type: \
                           invalid type: string \"abc\", expected u32 at line 1 column 20");
        assert!(zh.contains("类型"), "{zh}");
    }

    #[test]
    fn humanizes_field_prefixed_type_error() {
        let zh = humanize(
            "Failed to deserialize the JSON body into the target type: \
             name: invalid type: integer `1`, expected a string at line 1 column 9",
        );
        assert!(zh.contains("name"), "字段路径要保留: {zh}");
        assert!(zh.contains("类型"), "{zh}");
    }

    #[test]
    fn humanizes_json_syntax_error() {
        let zh = humanize(
            "Failed to parse the request body as JSON: key must be a string at line 1 column 2",
        );
        assert!(zh.contains("JSON"), "{zh}");
        assert!(zh.contains("语法"), "{zh}");
    }

    #[test]
    fn humanizes_syntax_error_and_unknown() {
        assert!(humanize("expected value at line 1 column 1").contains("JSON"));
        // 匹配不上时给通用文案，不能把英文原文透出去
        let zh = humanize("some brand new rejection we have not seen");
        assert_eq!(zh, "请求体格式不正确");
        assert!(!zh.is_ascii(), "兜底文案也必须是中文");
    }
}
