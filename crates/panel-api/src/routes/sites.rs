//! 站点与 SSL 证书（设计方案 §2.4）。
//!
//! # 核心闭环：配置变更必须"先校验，后生效"
//! ```text
//! 渲染配置 → validate（nginx -t）→ 失败则中止   → 成功则原子替换 → reload
//!                                    ↑ 旧配置未动，站点不受影响
//! ```
//! 直接写配置文件再 reload，语法错误会导致 **reload 失败但文件已改**，
//! 下次重启服务就起不来。这是自建面板最常见的线上事故。
//!
//! # 一个必须写清的约束
//! `validate` 通常耗时 50~200ms（`nginx -t`）。**它绝不能落在写事务内**——
//! 实测长事务耗时 1:1 传导给其他写者（持有 1000ms → 其他写者等 1046ms）。
//!
//! # 数据模型 vs 配置下发
//! 站点的「定义」（`sites` 表）与「下发到 Web 服务器的配置」是两件事：
//! - `create` / `get` / `patch` / `delete` 只读写 `sites` 表（纯 DB，无需 web server 在场）。
//! - `apply` / `reload` 才真正渲染并下发到 Web 服务器；若 `webserver.manage`
//!   能力位为 `no`（本机未装 nginx/caddy），这两个动作诚实返回 501，绝不伪造成功。
//! - SSL 的 ACME 签发/续期同理：能力位 `ssl.acme` 为 `no` 时诚实 501；
//!   证书「删除」是纯 DB 操作，始终可用。
//! - `conf_get` / `conf_put` / `conf_restore`：站点已落盘配置的**原始读写**。
//!   GET 按落库 `conf_path` 读（不接受前端路径）；PUT 仅 owner、写入前必过
//!   `nginx -t`，成功后站点转「手动维护」（表单保存不再覆盖，见 016 迁移）；
//!   `conf_restore` 按表单重新渲染，恢复面板托管。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, audit_system, Auth, MaybeAuth, Shared},
};
use axum::{
    extract::{Path as AxPath, Query, State},
    response::{IntoResponse, Response},
    Json,
};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use panel_core::{cap_keys, domain, PanelError, Result, SafePath};
use panel_os::{paths::slug, tls};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};


// ─── 数据行 / DTO（基础层，拆至 sites/model.rs；pub use 重导出供各段 + 测试） ───
mod model;
pub use model::*;

// ─── 站点 CRUD（列表/创建/详情/更新/删除，拆至 sites/crud.rs；pub use 重导出端点） ───
mod crud;
pub use crud::*;

// ─── 配置校验与应用（核心闭环，拆至 sites/apply.rs；pub use 重导出端点） ───
mod apply;
pub use apply::*;

// ─── 站点配置查看/编辑/版本回滚（拆至 sites/conf.rs；pub use 重导出端点） ───
mod conf;
pub use conf::*;

// ─── SSL 证书 / ACME（拆至 sites/ssl.rs；pub use 重导出端点供 routes.rs） ───
mod ssl;
pub use ssl::*;

#[cfg(test)]
mod waf_tests;
#[cfg(test)]
mod kind_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod last_applied_tests;
