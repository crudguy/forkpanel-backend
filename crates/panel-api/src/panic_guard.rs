//! panic 兜底：把 handler panic 转成**结构化 500**，而不是掐断连接。
//!
//! # 为什么需要
//! axum/hyper 默认不接 panic：handler 里任何一次 `unwrap`/`expect` 失败都会让
//! **连接任务**崩溃——客户端看到的是 "connection reset" 或空响应，不是 500；
//! 前端只能报"网络错误"，服务端日志里也只剩一段裸 panic 栈，没有请求上下文。
//!
//! 这**不替代**"把 unwrap 修掉"（例见 `routes/auth.rs` 登录回读那处）：兜底不掩盖
//! bug，它只保证**单个请求崩溃不影响其它请求**，并把 panic 记录到服务端日志便于归因。
//!
//! # 为什么用 tower-http 而不是手写
//! 手写需要 `poll` 级别的 `catch_unwind` + Pin 投影（`unsafe`），而 `tower-http` 的
//! `CatchPanicLayer` **本仓依赖树里已经存在**（axum 的传递依赖），启用 `catch-panic`
//! 特性为零新增 crate。安全相关的兜底不该自造轮子。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// 内部错误码：与 `ApiError::new(10999, …)` 同码（如 spawn_blocking join 失败）。
/// 前端按 `code` 归类，故必须与既有内部错误一致，不能另造一个。
pub const INTERNAL_ERROR_CODE: u32 = 10999;

/// panic 兜底处理器（交给 `CatchPanicLayer::custom`）。
///
/// 契约：
/// - **日志留全**：panic 载荷写 stderr（服务端日志），便于定位；
/// - **响应不回详情**：panic 文本可能含内部路径/数据，回给客户端等于泄露；
/// - **自身绝不 panic**：只用 `json!` 构造，不做 `to_value(...).unwrap()`。
pub fn handle_panic(payload: Box<dyn std::any::Any + Send>) -> Response {
    let detail = panic_message(&*payload);
    eprintln!("[PANIC] handler panicked（已转为 500，详情仅记服务端）: {detail}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "code": INTERNAL_ERROR_CODE,
            "message": "internal error",
            "data": null,
            "request_id": "-",
        })),
    )
        .into_response()
}

/// 从 panic 载荷取可读信息。`panic!("...")` 产生 `&str`，`panic!("{}", x)` / `unwrap()`
/// 产生 `String`；其它（如 `panic_any(42)`）如实标注，不硬转。
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    #[test]
    fn panic_message_reads_str_and_string_payloads() {
        let a: Box<dyn Any + Send> = Box::new("boom");
        assert_eq!(panic_message(&*a), "boom");
        let b: Box<dyn Any + Send> = Box::new(String::from("bang"));
        assert_eq!(panic_message(&*b), "bang");
        let c: Box<dyn Any + Send> = Box::new(42u32);
        assert!(panic_message(&*c).contains("non-string"));
    }

    /// 端到端：真实 Router + 真实 panic → 500 结构化响应（而不是 panic 冒泡）。
    ///
    /// 这条自带负向对照：把 `.layer(...)` 去掉后，handler 的 panic 会直接冒泡进测试，
    /// `oneshot` 根本不会返回 Response，测试必然变红。
    #[tokio::test]
    async fn panicking_handler_becomes_structured_500() {
        use axum::{body::Body, http::Request, routing::get, Router};
        use tower::ServiceExt;

        // 显式声明返回类型：edition 2024 不做 never-type 回退，若让 `panic!` 的 `!`
        // 自动收敛到 `()`，axum 的 `IntoResponse` 约束就不满足（编译期报错）。
        async fn boom() -> StatusCode {
            panic!("boom-for-test")
        }

        let app = Router::new()
            .route("/boom", get(boom))
            .layer(tower_http::catch_panic::CatchPanicLayer::custom(handle_panic));

        let res = app
            .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
            .await
            .expect("panic 应被兜底层接住，oneshot 必须返回 Response");
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"].as_u64(), Some(u64::from(INTERNAL_ERROR_CODE)));
        assert_eq!(v["message"], "internal error");
    }

    /// **接线守卫**：兜底层必须真的套进 `build_router`。
    /// 上面的单测是自己套的 Router，抓不到"忘了接进生产路由"（本项目的老坑）。
    #[test]
    fn panic_guard_is_wired_into_build_router() {
        // 生产段：剔注释 + 剥离测试块（注释里留着 needle 而真实挂载被删时，
        // 只 split 的旧写法会假绿）
        let prod = crate::test_support::production_source(include_str!("routes.rs"));
        assert!(
            prod.contains("CatchPanicLayer::custom(crate::panic_guard::handle_panic)"),
            "build_router 必须套 panic 兜底层：否则 handler panic 会掐断连接（前端只看到网络错误）"
        );
    }
}
