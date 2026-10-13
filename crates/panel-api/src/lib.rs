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
pub mod remote_store;
pub mod routes;
pub mod sse;
pub mod totp;
pub mod webhook;

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
    /// 首启引导令牌（一次性、只存内存）。serve 首启无 owner 时生成。
    pub bootstrap: Arc<crate::auth::BootstrapGuard>,
    /// 主密钥（32 字节，内存常驻，不落库）。为 None 时所有"写入真实秘密"的操作被拒绝。
    pub master_key: Option<MasterKey>,
    pub started_at: i64,
    /// 采集循环最近一次采样结果的缓存。**HTTP 接口一律读它，不要自己调
    /// `os.metrics().snapshot()`**——原因见 `cached_snapshot()` 的注释。
    pub last_snapshot: tokio::sync::RwLock<Option<Arc<panel_os::traits::SystemSnapshot>>>,
}

impl AppState {
    pub fn new(os: Arc<dyn panel_os::OsAdapter>, db: Arc<panel_db::WriterActor>,
               pool: Arc<ReadPool>, tasks: Arc<panel_task::TaskRunner>,
               metrics: Arc<std::sync::Mutex<panel_db::aggregator::Aggregator>>,
               tier: Tier, master_key: Option<MasterKey>) -> Self {
        let capabilities = os.capabilities();
        // 会话持久化：把写者交给 SessionCache（`sessions` 表 001 已定义、此前无人使用）。
        // 先 clone——下方 struct 字面量会把 db move 进字段。
        let sessions_db = db.clone();
        Self {
            os, db, pool, tasks, metrics, tier, capabilities,
            sessions: Arc::new(crate::auth::SessionCache::new_with_db(
                std::time::Duration::from_secs(30 * 60),
                std::time::Duration::from_secs(12 * 3600),
                sessions_db,
            )),
            logins: Arc::new(crate::auth::LoginGuard::new()),
            bootstrap: Arc::new(crate::auth::BootstrapGuard::new()),
            master_key,
            started_at: now_unix(),
            last_snapshot: tokio::sync::RwLock::new(None),
        }
    }

    /// 最近一次采集循环产出的快照（只读缓存）。
    ///
    /// 为什么必须有它：CPU 是「区间使用率」而不是瞬时值——`panel-os` 用一份
    /// **共享的 `prev`** 记录 (busy, sum)，`delta_pct` 算的是「距上一次采样以来」
    /// 的占比，而 `prev` 是**谁调用谁重置**。于是 HTTP 接口直接调 `snapshot()`
    /// 会同时造成两个后果：① 自己拿到一个窗口被截断的抖动值；② 把采集循环的
    /// 下一次采样窗口也截短。实测同一 ts：`/system/overview` 51.14% 而环形缓冲
    /// 54.41%，负载抖动时更夸张（23.19% vs 72.80%）。
    ///
    /// 规则：**采集循环独占采样**，其它调用方只读它写好的结果。
    pub async fn cached_snapshot(&self) -> Option<Arc<panel_os::traits::SystemSnapshot>> {
        self.last_snapshot.read().await.clone()
    }

    /// 采集循环完成一次采样后调用：写缓存，供 HTTP 接口读取。
    pub async fn record_snapshot(&self, snap: Arc<panel_os::traits::SystemSnapshot>) {
        *self.last_snapshot.write().await = Some(snap);
    }

    /// 需要写入/读取真实秘密（SSL 私钥、数据库口令）时调用；无主密钥则拒绝。
    pub fn require_secret_key(&self) -> ApiResult<MasterKey> {
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

/// 把 `ApiResult<T>` 转成 HTTP 响应（IntoResponse 在 error.rs 中实现）
pub type HandlerResult<T> = ApiResult<T>;

#[allow(dead_code)]
fn _assert_send_sync() {
    fn is<T: Send + Sync>() {}
    is::<AppState>();
    is::<ApiError>();
}
