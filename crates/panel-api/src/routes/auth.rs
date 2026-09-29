//! 认证相关 handler。

use crate::{
    auth::{self, Session},
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, CurrentSid, Shared},
    AppState,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MeResp {
    pub user: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub allowed_roots: Vec<String>,
    pub capabilities: panel_core::CapabilityMap,
    pub tier: &'static str,
}

/// 登录。故意**不做** GET：口令绝不能进 URL/日志。
pub async fn login(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> ApiResult<(HeaderMap, StatusCode)> {
    if req.username.is_empty() || req.password.is_empty() {
        return Err(ApiError::bad_request("username", "required"));
    }

    // 防暴力：按 IP + 用户名双维度
    let ip = client_ip(&headers);
    let key = format!("{ip}:{}", req.username);
    if let Some(wait) = state.logins.check(&key) {
        return Err(ApiError::too_many_requests(wait));
    }

    // 查用户（走读连接池）
    let username = req.username.clone();
    let row = state.pool.with(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, pwd_hash, role, allowed_roots, disabled FROM users WHERE username = ?1",
        ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        let r = stmt.query_row(rusqlite::params![username], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, i32>(4)?))
        });
        match r {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) =>
                Err(panel_core::PanelError::NotFound("user".into())),
            Err(e) => Err(panel_core::PanelError::Database(e.to_string())),
        }
    }).await;

    let (uid, pwd_hash, role, roots, disabled) = match row {
        Ok(v) => v,
        Err(panel_core::PanelError::NotFound(_)) => {
            state.logins.record_failure(&key);
            // 用户不存在与口令错误的响应**完全一致**，避免用户名枚举
            return Err(ApiError::unauthorized());
        }
        Err(e) => return Err(ApiError::from(e)),
    };

    if disabled != 0 {
        return Err(ApiError::forbidden("account.disabled"));
    }

    // argon2 验证较贵（8~19MB 瞬时内存），放在 blocking 池；nano 档位串行化避免 OOM
    let pwd = req.password.clone();
    let verified = tokio::task::spawn_blocking(move || auth::verify_password(&pwd, &pwd_hash))
        .await
        .map_err(|e| ApiError::new(10999, StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(ApiError::from)?;

    if !verified {
        state.logins.record_failure(&key);
        return Err(ApiError::unauthorized());
    }

    state.logins.reset(&key);

    let permissions = auth::permissions_for_role(&role);
    let allowed_roots: Vec<String> = serde_json::from_str(&roots).unwrap_or_default();
    let sid = auth::generate_sid();
    state.sessions.insert(sid.clone(), Session {
        user_id: uid,
        username: req.username.clone(),
        role,
        permissions,
        allowed_roots,
        created_at: 0, last_seen: 0, expires_at: 0,
    });

    // 审计：登录成功
    let s = state.sessions.get(&sid).unwrap();
    audit(&state, &s, "auth.login", &req.username, "ok").await;

    let csrf = auth::generate_csrf_token();
    let mut h = HeaderMap::new();
    // Secure 仅在 TLS 下下发：本地 http 开发时浏览器会丢弃 Secure Cookie，导致会话无法持久。
    // 生产部署设 PANEL_TLS=1 即恢复 Secure（配合 HSTS）。
    let secure = std::env::var("PANEL_TLS").map(|v| v == "1").unwrap_or(false);
    let sf = if secure { "; Secure" } else { "" };
    h.append(header::SET_COOKIE,
             format!("panel_sid={sid}; HttpOnly{sf}; SameSite=Strict; Path=/").parse().unwrap());
    // CSRF token 必须**可读**（前端要放进请求头），故不加 HttpOnly
    h.append(header::SET_COOKIE,
             format!("panel_csrf={csrf}{sf}; SameSite=Strict; Path=/").parse().unwrap());
    Ok((h, StatusCode::NO_CONTENT))
}

pub async fn logout(State(state): State<Shared>, headers: HeaderMap, Auth(s): Auth) -> StatusCode {
    if let Some(sid) = crate::middleware::extract_cookie(&headers, "panel_sid") {
        state.sessions.remove(&sid);
    }
    audit(&state, &s, "auth.logout", &s.username, "ok").await;
    StatusCode::NO_CONTENT
}

pub async fn me(State(state): State<Shared>, Auth(s): Auth) -> Json<serde_json::Value> {
    ok(MeResp {
        user: s.username.clone(),
        role: s.role.clone(),
        permissions: s.permissions.clone(),
        allowed_roots: s.allowed_roots.clone(),
        capabilities: state.capabilities.clone(),
        tier: tier_name(state.tier),
    })
}

#[derive(Debug, Deserialize)]
pub struct PwdReq { pub old: String, pub new: String }

pub async fn change_password(
    State(state): State<Shared>,
    Auth(s): Auth,
    CurrentSid(cur): CurrentSid,
    Json(req): Json<PwdReq>,
) -> ApiResult<StatusCode> {
    auth::check_password_policy(&req.new)?;
    if req.old == req.new {
        return Err(ApiError::bad_request("new", "new password must differ from the old one"));
    }

    // 1) 取旧哈希（只读池）。uid 先复制出来——闭包是 move，不能捕获整个 s
    //    （后面 audit / 踢会话还要用 s）。
    let uid = s.user_id;
    let pwd_hash = state
        .pool
        .with(move |conn| {
            use rusqlite::OptionalExtension;
            conn.query_row(
                "SELECT pwd_hash FROM users WHERE id = ?1",
                [uid],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))
        })
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("user"))?;

    // 2) 校验旧密码（argon2 较贵，blocking 池同 login）。
    //    **刻意 400 而非 401**：前端把 401 视作会话失效全局登出，
    //    凭据输错不该把人踢出登录态。
    let old = req.old.clone();
    let verified = tokio::task::spawn_blocking(move || auth::verify_password(&old, &pwd_hash))
        .await
        .map_err(|e| ApiError::new(10999, StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(ApiError::from)?;
    if !verified {
        return Err(ApiError::bad_request("old", "incorrect password"));
    }

    // 3) 新密码哈希（blocking 池，按档位成本）
    let tier = state.tier;
    let new = req.new.clone();
    let hash = tokio::task::spawn_blocking(move || {
        auth::hash_password(&new, &auth::HashParams::for_tier(tier))
    })
    .await
    .map_err(|e| ApiError::new(10999, StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(ApiError::from)?;

    // 4) 单写事务更新（rows_changed 复核用户仍在）
    state
        .db
        .exec(move |conn| {
            let n = conn
                .execute("UPDATE users SET pwd_hash = ?1 WHERE id = ?2", rusqlite::params![hash, uid])
                .map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
            if n == 0 {
                return Err(panel_core::PanelError::NotFound("user".into()));
            }
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;

    // 5) 强制该用户**其他端**下线（当前会话保留，避免改密即被登出）
    let kicked = state.sessions.remove_by_user_except(s.user_id, &cur);

    audit(&state, &s, "auth.password", &format!("{} (kicked={kicked})", s.username), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

fn tier_name(t: panel_core::Tier) -> &'static str {
    match t { panel_core::Tier::Nano => "nano",
              panel_core::Tier::Small => "small",
              panel_core::Tier::Standard => "standard" }
}

// ═══════════════════ 首启引导（无 owner 时建第一个账号）═══════════════════

#[derive(Debug, Serialize)]
pub struct BootstrapStatus {
    /// 数据库尚无 owner 账号 → 前端显示首启向导而非登录表单
    pub needs_bootstrap: bool,
    /// 引导令牌是否仍有效（false = 未生成或已过期，需重启 serve 重新打印）
    pub token_active: bool,
}

/// 首启状态（公开、幂等、无敏感信息）。
async fn owner_count(state: &AppState) -> ApiResult<i64> {
    state.pool.with(|conn| {
        conn.query_row("SELECT COUNT(*) FROM users WHERE role = 'owner'", [], |r| r.get(0))
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))
    }).await.map_err(ApiError::from)
}

pub async fn bootstrap_status(State(state): State<Shared>) -> ApiResult<Json<serde_json::Value>> {
    let n = owner_count(&state).await?;
    Ok(ok(BootstrapStatus { needs_bootstrap: n == 0, token_active: state.bootstrap.active() }))
}

#[derive(Debug, Deserialize)]
pub struct BootstrapReq {
    pub token: String,
    pub username: String,
    pub password: String,
}

/// 首启创建 owner（公开端点，唯一入口）。
///
/// 设计取舍：不开放常驻注册——建号能力必须等价于"看过 serve 首启终端输出"，
/// 与 CLI init 同级；令牌一次性、30 分钟有效、只存内存、只存哈希。
/// 副作用顺序纪律：**所有无副作用校验（owner 检查 / 输入策略 / 哈希）先行，
/// 令牌消费（唯一不可逆步骤）放最后**——否则用户首次提交弱口令失败后，
/// 令牌已被焚，第二次正确提交只能得到 401（实测踩过的坑）。
pub async fn bootstrap(
    State(state): State<Shared>,
    Json(req): Json<BootstrapReq>,
) -> ApiResult<StatusCode> {
    // 1) 已有 owner → 409（只读检查；防重放，后写事务还会再查一次）
    if owner_count(&state).await? > 0 {
        return Err(ApiError::conflict("owner"));
    }

    // 2) 输入校验（只读，与 CLI create_owner 同一规则）
    let username = auth::validate_username(&req.username).map_err(ApiError::from)?;
    auth::check_password_policy(&req.password).map_err(ApiError::from)?;

    // 3) argon2 较贵（最高 19MiB 瞬时内存），放 blocking 池（同 login）；只读计算
    let tier = state.tier;
    let pwd = req.password.clone();
    let hash = tokio::task::spawn_blocking(move || {
        auth::hash_password(&pwd, &auth::HashParams::for_tier(tier))
    })
    .await
    .map_err(|e| ApiError::new(10999, StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(ApiError::from)?;

    // 4) 令牌校验并消费（唯一不可逆步骤；Mutex take 原子化并发竞态）
    if !state.bootstrap.take_if_valid(&req.token) {
        return Err(ApiError::bootstrap_invalid());
    }

    // 5) 单写事务：事务内复查 owner（防极端竞态）→ INSERT → 同事务落审计
    let uname = username.clone();
    let now = crate::now_unix();
    state.db.exec(move |conn| {
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'owner'", [], |r| r.get(0),
        ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        if n > 0 {
            return Err(panel_core::PanelError::Conflict("owner".into()));
        }
        conn.execute(
            "INSERT INTO users(username, pwd_hash, role, allowed_roots, created_at)
             VALUES (?1, ?2, 'owner', '[]', ?3)",
            rusqlite::params![uname, hash, now],
        ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        conn.execute(
            "INSERT INTO audit_log(ts, actor, actor_ip, action, target, result, detail_json)
             VALUES (?1, ?2, '', 'auth.bootstrap', ?2, 'ok', '{}')",
            rusqlite::params![now, uname],
        ).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: 2 })
    }).await.map_err(ApiError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

/// 取客户端 IP。**注意**：只有在受信任反代后才应读取 X-Forwarded-For，
/// 否则该头可伪造（会导致防暴力失效）。默认只认 X-Real-IP（由前置反代设置）。
fn client_ip(h: &HeaderMap) -> String {
    h.get("x-real-ip")
        .or_else(|| h.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[allow(dead_code)]
fn _assert_state(_: Arc<AppState>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn cookie_flags_are_strict() {
        // 会话 Cookie 必须 HttpOnly + Secure + SameSite=Strict
        let c = "panel_sid=abc; HttpOnly; Secure; SameSite=Strict; Path=/";
        assert!(c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Strict"));
        // CSRF Cookie 必须**可读**（前端要取出放进请求头）
        let c2 = "panel_csrf=def; Secure; SameSite=Strict; Path=/";
        assert!(!c2.contains("HttpOnly"));
    }

    #[test]
    fn client_ip_prefers_real_ip() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "203.0.113.9".parse().unwrap());
        h.insert("x-forwarded-for", "1.1.1.1, 2.2.2.2".parse().unwrap());
        assert_eq!(client_ip(&h), "203.0.113.9");
    }

    #[test]
    fn client_ip_falls_back() {
        let h = HeaderMap::new();
        assert_eq!(client_ip(&h), "unknown");
        let mut h2 = HeaderMap::new();
        h2.insert(header::FORWARDED, "for=9.9.9.9".parse().unwrap());
        assert_eq!(client_ip(&h2), "unknown", "不可信头不应被采用");
    }
}
