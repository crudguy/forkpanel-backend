//! HTTP（设计方案 §3.4）。
//!
//! 分层纪律：
//! - handler 只做三件事：参数校验 → 权限断言 → 调 service（本骨架直接调 OsAdapter）→ 包装响应。
//! - handler **禁止**出现 SQL（走 panel-db）、**禁止**出现进程调用（走 panel-os）、
//!   **禁止**出现路径字面量（走 PathLayout）。
//! - 所有写操作必须可审计：由 `Audit` 中间件在响应阶段落库。

pub mod auth;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod sse;
pub mod routes;

use error::{ApiError, ApiResult};
use panel_core::{crypto::MasterKey, CapabilityMap, Tier};
use panel_db::ReadPool;
use std::sync::Arc;

/// 全应用共享状态
pub struct AppState {
    pub os: Arc<dyn panel_os::OsAdapter>,
    pub db: Arc<panel_db::WriterActor>,
    pub pool: Arc<ReadPool>,
    pub tasks: Arc<panel_task::TaskRunner>,
    /// 指标环形缓冲（内存）。SSE 与实时接口都读它，避免"每客户端一份采集"。
    pub metrics: Arc<std::sync::Mutex<panel_db::aggregator::Aggregator>>,
    pub tier: Tier,
    /// 启动期计算一次，避免每请求重建（能力探测涉及文件系统查询）
    pub capabilities: CapabilityMap,
    pub sessions: Arc<crate::auth::SessionCache>,
    pub logins: Arc<crate::auth::LoginGuard>,
    /// 主密钥（32 字节，内存常驻，不落库）。为 None 时所有"写入真实秘密"的操作被拒绝。
    pub master_key: Option<MasterKey>,
    pub started_at: i64,
}

impl AppState {
    pub fn new(os: Arc<dyn panel_os::OsAdapter>, db: Arc<panel_db::WriterActor>,
               pool: Arc<ReadPool>, tasks: Arc<panel_task::TaskRunner>,
               metrics: Arc<std::sync::Mutex<panel_db::aggregator::Aggregator>>,
               tier: Tier, master_key: Option<MasterKey>) -> Self {
        let capabilities = os.capabilities();
        Self {
            os, db, pool, tasks, metrics, tier, capabilities,
            sessions: Arc::new(crate::auth::SessionCache::new(
                std::time::Duration::from_secs(30 * 60),
                std::time::Duration::from_secs(12 * 3600),
            )),
            logins: Arc::new(crate::auth::LoginGuard::new()),
            master_key,
            started_at: now_unix(),
        }
    }

    /// 需要写入/读取真实秘密（SSL 私钥、数据库口令）时调用；无主密钥则拒绝。
    pub fn require_secret_key(&self) -> Result<MasterKey, ApiError> {
        self.master_key.ok_or_else(|| {
            ApiError::unsupported("secret storage unavailable: master key not loaded (检查 /etc/panel/master.key 权限 0600)")
        })
    }
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub type State = Arc<AppState>;

/// 统一响应信封（设计方案 §3.4）。前端按 `code` 分段映射文案。
#[derive(Debug, serde::Serialize)]
pub struct Envelope<T> {
    pub code: u32,
    pub message: &'static str,
    pub data: Option<T>,
    pub request_id: String,
}

impl<T: serde::Serialize> Envelope<T> {
    pub fn ok(data: T, rid: String) -> Self {
        Self { code: 0, message: "ok", data: Some(data), request_id: rid }
    }
}

/// 把 `Result<T, ApiError>` 转成 HTTP 响应（IntoResponse 在 error.rs 中实现）
pub type HandlerResult<T> = ApiResult<T>;

#[allow(dead_code)]
fn _assert_send_sync() {
    fn is<T: Send + Sync>() {}
    is::<AppState>();
    is::<ApiError>();
}
