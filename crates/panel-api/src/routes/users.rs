//! 用户管理（设计方案 §2.12）。管理员 CRUD、角色/权限分配、禁用/删除。
//!
//! 安全纪律：
//! - owner 角色不可经 API 创建/修改/删除（仅首启引导建唯一 owner，见 auth.rs::bootstrap）。
//! - 禁止自锁：不能禁用自己、不能把自己权限降到失去 `user.manage`（无法再恢复）。
//! - 禁用/删除立即踢掉目标现有会话（state.sessions.remove_by_user）。
//! - 每个写操作都审计操作人（actor = 当前会话用户名）。

use crate::{
    auth::{self, perm},
    error::{ApiError, ApiResult, ok},
    routes::{audit, Auth, Shared},
};
use axum::extract::{Path as AxPath, State};
use axum::http::StatusCode;
use axum::Json;
use panel_core::PanelError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::extract::PanelJson;

/// API 可创建/分配的角色（owner 除外——它是引导态专属，不可经 API 操作）
const ASSIGNABLE_ROLES: &[&str] = &["admin", "operator", "viewer"];

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub allowed_roots: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PatchReq {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub allowed_roots: Option<Vec<String>>,
    #[serde(default)]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserOut {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub allowed_roots: Vec<String>,
    pub mfa_enabled: bool,
    pub disabled: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

fn parse_roots(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

/// 该角色是否具备 `user.manage`。**异步**：自定义角色的权限在库里，
/// 只查内置定义会把"自定义角色含 user.manage"误判成不含，从而阻止一次
/// 合法的自我调整（是保守方向的误伤，但仍然是误伤）。
async fn role_has_user_manage(state: &Shared, role: &str) -> bool {
    auth::permissions_for_role_resolved(state, role)
        .await
        .iter()
        .any(|p| p == perm::USER_MANAGE)
}

/// 角色是否可经 API 分配：内置可分配名单 ∪ 数据库中的自定义角色。
///
/// `owner` 刻意排除在外——owner 只能由 CLI/引导流程产生，不能经 API 再造一个：
/// 多个 owner 会让"唯一不可剥夺的管理员"这个前提悄然消失。
async fn ensure_role_assignable(state: &Shared, role: &str) -> ApiResult<()> {
    if ASSIGNABLE_ROLES.contains(&role) {
        return Ok(());
    }
    if auth::BUILTIN_ROLES.contains(&role) {
        return Err(ApiError::bad_request(
            "role",
            format!("角色 `{role}` 不可经 API 分配（owner 只能由引导流程创建）"),
        ));
    }
    let r = role.to_string();
    let exists = state
        .pool
        .with(move |conn| {
            conn.query_row("SELECT 1 FROM roles WHERE name = ?1", [r], |x| x.get::<_, i64>(0))
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
                .map_err(|e: rusqlite::Error| PanelError::Database(e.to_string()))
        })
        .await?;
    if exists.is_none() {
        return Err(ApiError::bad_request("role", format!("角色 `{role}` 不存在")));
    }
    Ok(())
}

/// **防提权**：不能创建/调整为权限超出自己的账号。
///
/// 没有这一条，任何一个拥有 `user.manage` 的人都可以凭空造一个权限更大的角色
/// 再据为己有——整条 RBAC 就成了摆设。
async fn ensure_no_escalation(state: &Shared, role: &str, granted: &[String]) -> ApiResult<()> {
    for p in auth::permissions_for_role_resolved(state, role).await {
        if !granted.iter().any(|g| g == &p) {
            return Err(ApiError::bad_request(
                "role",
                format!("不能分配权限超出自己的账号（该角色需要 `{p}`）"),
            ));
        }
    }
    Ok(())
}

pub async fn list(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    let rows = state.pool.with(|conn| {
        let mut stmt = conn.prepare(
            "SELECT id, username, role, allowed_roots, disabled, created_at, last_login_at, mfa_enabled_at \
             FROM users ORDER BY id ASC")
            .map_err(|e| PanelError::Database(e.to_string()))?;
        let rows = stmt.query_map([], |r| Ok((
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
            r.get::<_, String>(3)?, r.get::<_, i32>(4)?, r.get::<_, i64>(5)?,
            r.get::<_, Option<i64>>(6)?, r.get::<_, Option<i64>>(7)?,
        ))).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows { out.push(row.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(out)
    }).await.map_err(ApiError::from)?;

    let users: Vec<UserOut> = rows.into_iter().map(|(id, u, role, roots, dis, c, l, mfa_at)| UserOut {
        id, username: u, role, allowed_roots: parse_roots(&roots),
        // 与 /auth/me 同口径：mfa_enabled_at 非空即已启用。此前硬编码 false，
        // 导致用户列表永远显示「未启用」、契约里的 mfa_enabled 字段形同虚设。
        mfa_enabled: mfa_at.is_some(), disabled: dis != 0, created_at: c, last_login_at: l,
    }).collect();
    Ok(ok(users))
}

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<CreateReq>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    crate::auth::require(&s, perm::USER_MANAGE)?;

    // 1) 校验输入（只读）
    let username = auth::validate_username(&req.username).map_err(ApiError::from)?;
    auth::check_password_policy(&req.password).map_err(ApiError::from)?;
    // 角色必须真实存在（内置可分配名单 ∪ 自定义角色），且不得超出自己的权限
    ensure_role_assignable(&state, &req.role).await?;
    ensure_no_escalation(&state, &req.role, &s.permissions).await?;
    let role = req.role.clone();
    let roots_json = serde_json::to_string(&req.allowed_roots).unwrap_or_else(|_| "[]".into());

    // 2) argon2 哈希（贵，放 blocking 池）
    let tier = state.tier;
    let pwd = req.password.clone();
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&pwd, &auth::HashParams::for_tier(tier)))
        .await
        .map_err(|e| ApiError::new(10999, StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(ApiError::from)?;

    // 3) 单写事务：INSERT（用户名唯一约束冲突 → 409）
    let now = crate::now_unix();
    let uname = username.clone();
    state.db.exec(move |conn| {
        conn.execute(
            "INSERT INTO users(username, pwd_hash, role, allowed_roots, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![uname, hash, role, roots_json, now],
        ).map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                PanelError::Conflict("username".into())
            } else {
                PanelError::Database(e.to_string())
            }
        })?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await.map_err(ApiError::from)?;

    audit(&state, &s, "user.create", &username, "ok").await;
    Ok((StatusCode::CREATED, ok(json!({ "username": username }))))
}

pub async fn patch(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<PatchReq>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::USER_MANAGE)?;

    // 1) 取目标用户（含 role/disabled，用于自锁与 owner 守卫）
    let target = state.pool.with(move |conn| {
        let r = conn.query_row(
            "SELECT id, role, disabled FROM users WHERE id = ?1",
            rusqlite::params![id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i32>(2)?)),
        );
        match r {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(PanelError::NotFound("user".into())),
            Err(e) => Err(PanelError::Database(e.to_string())),
        }
    }).await.map_err(ApiError::from)?;
    let (target_id, target_role, target_disabled) = target;

    // 2) owner 不可经 API 改（role/disabled）；改密也走独立端点以保持单一入口
    if target_role == "owner" {
        return Err(ApiError::forbidden("owner 账号不可经 API 修改，请在服务器终端操作"));
    }

    // 3) 自锁防护：不能禁用自己、不能把自己降到失去 user.manage
    if target_id == s.user_id {
        if req.disabled == Some(true) {
            return Err(ApiError::forbidden("不能禁用当前登录账号"));
        }
        if let Some(ref new_role) = req.role {
            if !role_has_user_manage(&state, new_role).await {
                return Err(ApiError::forbidden(
                    "不能将自身权限降至失去 user.manage（会锁死自己）",
                ));
            }
        }
    }

    // 4) 角色合法性：必须存在，且不得超出自己的权限
    if let Some(ref new_role) = req.role {
        ensure_role_assignable(&state, new_role).await?;
        ensure_no_escalation(&state, new_role, &s.permissions).await?;
    }

    // 5) 组装变更（只读计算）
    let new_role = req.role.clone().unwrap_or(target_role.clone());
    let new_roots = req.allowed_roots.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
    let new_disabled = req.disabled.unwrap_or(target_disabled != 0);
    let new_pwd_hash = match req.password {
        Some(ref p) => {
            auth::check_password_policy(p).map_err(ApiError::from)?;
            let tier = state.tier;
            let p2 = p.clone();
            Some(tokio::task::spawn_blocking(move || auth::hash_password(&p2, &auth::HashParams::for_tier(tier)))
                .await
                .map_err(|e| ApiError::new(10999, StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map_err(ApiError::from)?)
        }
        None => None,
    };

    // 6) 单写事务应用
    state.db.exec(move |conn| {
        if let Some(h) = new_pwd_hash {
            conn.execute("UPDATE users SET pwd_hash = ?1 WHERE id = ?2",
                rusqlite::params![h, target_id]).map_err(|e| PanelError::Database(e.to_string()))?;
        }
        if let Some(roots) = new_roots {
            conn.execute("UPDATE users SET allowed_roots = ?1 WHERE id = ?2",
                rusqlite::params![roots, target_id]).map_err(|e| PanelError::Database(e.to_string()))?;
        }
        conn.execute("UPDATE users SET role = ?1, disabled = ?2 WHERE id = ?3",
            rusqlite::params![new_role, new_disabled as i32, target_id])
            .map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await.map_err(ApiError::from)?;

    // 7) 禁用/改密后立即踢下线
    if new_disabled || req.password.is_some() {
        state.sessions.remove_by_user(target_id);
    }

    audit(&state, &s, "user.patch", &target_id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::USER_MANAGE)?;

    // 1) 取目标（含 role），用于守卫
    let target = state.pool.with(move |conn| {
        let r = conn.query_row(
            "SELECT id, role FROM users WHERE id = ?1",
            rusqlite::params![id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        );
        match r {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(PanelError::NotFound("user".into())),
            Err(e) => Err(PanelError::Database(e.to_string())),
        }
    }).await.map_err(ApiError::from)?;
    let (target_id, target_role) = target;

    // 2) 不能删自己
    if target_id == s.user_id {
        return Err(ApiError::forbidden("不能删除当前登录账号"));
    }
    // 3) owner 不可经 API 删除
    if target_role == "owner" {
        return Err(ApiError::forbidden("owner 账号不可经 API 删除"));
    }

    // 4) 删除（影响 0 行 → 已不存在）
    let ack = state.db.exec(move |conn| {
        let n = conn.execute("DELETE FROM users WHERE id = ?1", rusqlite::params![target_id])
            .map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: n })
    }).await.map_err(ApiError::from)?;
    if ack.rows_changed == 0 {
        return Err(ApiError::not_found("user"));
    }

    // 5) 立即踢下线
    state.sessions.remove_by_user(target_id);

    audit(&state, &s, "user.delete", &target_id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}
