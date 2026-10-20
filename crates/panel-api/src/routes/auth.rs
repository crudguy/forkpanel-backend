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
    /// MFA 是否已启用（审计 F8）：此前前端靠「重复 enroll 得到的 400 中文文案」
    /// 反推状态——刷新即丢、后端改文案即失效。由 /auth/me 权威下发。
    pub mfa_enabled: bool,
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
        // 被拦下的尝试**同样计数**（P2-11，2026-10-20 决定）。
        //
        // 此前不计：快速连点会冻结在「1 次/秒」的软限速上，`n` 停在 max_attempts，
        // 永远到不了 lock_after 的 15 分钟锁定——实测攻击者保持 1 req/s 可在 2 小时内
        // 试约 7200 个口令，而面板以 root 运行，弱口令场景下这个速率偏危险。
        //
        // 现在计入后（实测同一 LoginGuard）：
        // - 攻击者连点：第 11 次即进 15 分钟锁定，2 小时内最多 10 次有效尝试；
        // - 正常用户手快连错：第 16 次被锁 15 分钟（现状是永不锁定）。
        // 后者是可接受的代价：连续输错 16 次口令已不属于"手快"，且面板明确告知
        // 剩余等待时间，用户可换用户名或等锁过期。
        //
        // ⚠ 计数必须放在 return 之前：放过这一条就等于回到旧行为。
        state.logins.record_failure(&key);
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

    // ── 第二因子：口令对了还不够，启用 MFA 的账户还必须出示动态口令 ──
    let uid_for_mfa = uid;
    let mfa_row = state
        .pool
        .with(move |conn| {
            let r = conn.query_row(
                "SELECT mfa_enabled_at, mfa_secret_enc, mfa_recovery_codes FROM users WHERE id = ?1",
                [uid_for_mfa],
                |r| {
                    Ok((
                        r.get::<_, Option<i64>>(0)?,
                        r.get::<_, Option<Vec<u8>>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            );
            match r {
                Ok(v) => Ok(v),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok((None, None, None)),
                Err(e) => Err(panel_core::PanelError::Database(e.to_string())),
            }
        })
        .await?;

    if let (Some(_enabled_at), secret_enc, codes_json) = mfa_row {
        let input = req.totp.clone().unwrap_or_default();
        if input.is_empty() {
            // 明确告知缺什么，而不是笼统 401——否则前端无法区分"密码错"与"缺验证码"
            return Err(ApiError::bad_request("totp", "该账户已启用 MFA，请提供动态口令"));
        }
        let Some(blob) = secret_enc else {
            return Err(ApiError::unsupported("MFA 数据缺失，请联系管理员重置"));
        };
        let master = state.require_secret_key()?;
        let secret = master.decrypt(&blob).map_err(ApiError::from)?;

        if crate::totp::verify(&secret, &input, crate::now_unix()) {
            // 动态口令通过
        } else {
            // 退而校验**一次性恢复码**：命中即用掉一个（不重复使用）
            let given = crate::totp::hash_recovery_code(&input);
            let mut codes: Vec<String> = codes_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                .unwrap_or_default();
            if let Some(pos) = codes.iter().position(|c| c == &given) {
                codes.remove(pos);
                let remain = serde_json::to_string(&codes).unwrap_or_else(|_| "[]".into());
                let uid2 = uid;
                let _ = state
                    .db
                    .exec(move |conn| {
                        conn.execute(
                            "UPDATE users SET mfa_recovery_codes = ?1 WHERE id = ?2",
                            rusqlite::params![remain, uid2],
                        )
                        .map(|_| panel_db::WriteAck { rows_changed: 1 })
                        .map_err(|e| panel_core::PanelError::Database(e.to_string()))
                    })
                    .await;
            } else {
                // 第二因子错误同样计入防暴力（否则可无限爆破 6 位码）
                state.logins.record_failure(&key);
                return Err(ApiError::unauthorized());
            }
        }
    }

    state.logins.reset(&key);

    // 写入最后登录时间：users 页「最后登录」列与账号审计都依赖它。
    // 此前全后端对该列**只 SELECT 不 UPDATE**（users.rs 只读出 last_login_at），
    // 于是它恒为 NULL、用户页永远显示"从未登录"，即便刚登录过——等于功能缺失。
    // 纯写且失败不影响登录本身（不能因为一条审计字段写失败就拒绝登录），故忽略结果。
    let uid_login_at = uid;
    let _ = state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE users SET last_login_at = ?1 WHERE id = ?2",
                rusqlite::params![crate::now_unix(), uid_login_at],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))
        })
        .await;

    // 自定义角色的权限存在库里，故走异步解析；内置角色走"未命中则回退内置"的路径。
    // 权限在这里**快照**进会话：角色权限后续变更需重新登录才生效（已知边界）。
    let permissions = auth::permissions_for_role_resolved(&state, &role).await;
    let allowed_roots: Vec<String> = serde_json::from_str(&roots).unwrap_or_default();
    let sid = auth::generate_sid();
    state.sessions.insert(sid.clone(), Session {
        user_id: uid,
        username: req.username.clone(),
        role,
        permissions,
        allowed_roots,
        // 登录这一刻的来源 IP，之后所有审计记录都带它（见 Session::ip）
        ip: ip.clone(),
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
    // MFA 状态随 me 一起下发（审计 F8），省一次专门的状态接口。
    // mfa_enabled_at 非空 = 已启用。me 的本职是身份下发，MFA 状态查询
    // 失败时降级为 false（不挡整个会话接口），SecurityView 的 enroll
    // 请求仍会对已启用情况给出明确 400。
    let uid = s.user_id;
    let mfa_enabled = state
        .pool
        .with(move |conn| {
            use rusqlite::OptionalExtension;
            conn.query_row(
                "SELECT mfa_enabled_at FROM users WHERE id = ?1",
                [uid],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()
            .map(|x| x.flatten().is_some())
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))
        })
        .await
        .unwrap_or(false);
    ok(MeResp {
        user: s.username.clone(),
        role: s.role.clone(),
        permissions: s.permissions.clone(),
        allowed_roots: s.allowed_roots.clone(),
        capabilities: state.capabilities.clone(),
        tier: tier_name(state.tier),
        mfa_enabled,
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
// ─────────────── MFA（TOTP，RFC 6238） ───────────────

#[derive(Debug, Serialize)]
pub struct MfaEnrollResp {
    /// base32 密钥（手工录入用）
    pub secret: String,
    /// 验证器扫码用
    pub otpauth_uri: String,
    /// **一次性返回**的恢复码明文；库里只存哈希，此后**无法再取回**
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MfaCodeReq {
    /// 6 位动态口令，或一次性恢复码
    pub code: String,
}

/// 取当前用户的 MFA 材料：(secret 密文, 恢复码哈希列表, 启用时间)
async fn mfa_material(
    state: &AppState,
    uid: i64,
) -> ApiResult<(Option<Vec<u8>>, Vec<String>, Option<i64>)> {
    let row = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT mfa_secret_enc, mfa_recovery_codes, mfa_enabled_at FROM users WHERE id = ?1",
                [uid],
                |r| {
                    Ok((
                        r.get::<_, Option<Vec<u8>>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))
        })
        .await?;
    let codes: Vec<String> = row
        .1
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default();
    Ok((row.0, codes, row.2))
}

/// 统一的第二因子校验：动态口令**或**恢复码任一命中即可。
fn factor_ok(secret: Option<&[u8]>, codes: &[String], input: &str) -> bool {
    if let Some(s) = secret {
        if crate::totp::verify(s, input, crate::now_unix()) {
            return true;
        }
    }
    let given = crate::totp::hash_recovery_code(input);
    codes.iter().any(|c| c == &given)
}

/// POST /auth/mfa/enroll —— 生成密钥与恢复码。**此刻尚未生效**，须 verify 通过才启用；
/// 这样即使 enroll 后用户没完成绑定，也不会把自己锁在门外。
pub async fn mfa_enroll(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    let (_, _, enabled) = mfa_material(&state, s.user_id).await?;
    if enabled.is_some() {
        return Err(ApiError::bad_request("mfa", "已启用 MFA；如需更换请先关闭"));
    }
    let master = state.require_secret_key()?;
    let secret = crate::totp::gen_secret();
    let b32 = crate::totp::base32_encode(&secret);
    let codes = crate::totp::gen_recovery_codes(crate::totp::RECOVERY_CODE_COUNT);
    let hashed: Vec<String> = codes.iter().map(|c| crate::totp::hash_recovery_code(c)).collect();
    let enc = master.encrypt(&secret).map_err(ApiError::from)?;
    let codes_json = serde_json::to_string(&hashed).unwrap_or_else(|_| "[]".into());
    let uid = s.user_id;
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE users SET mfa_secret_enc = ?1, mfa_recovery_codes = ?2 WHERE id = ?3",
                rusqlite::params![enc, codes_json, uid],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))
        })
        .await?;

    Ok(ok(MfaEnrollResp {
        otpauth_uri: crate::totp::otpauth_uri(&s.username, &b32),
        secret: b32,
        recovery_codes: codes,
    }))
}

/// POST /auth/mfa/verify —— 用动态口令确认绑定后正式启用。
pub async fn mfa_verify(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<MfaCodeReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let (secret_enc, _codes, enabled) = mfa_material(&state, s.user_id).await?;
    if enabled.is_some() {
        return Err(ApiError::bad_request("mfa", "MFA 已启用"));
    }
    let Some(blob) = secret_enc else {
        return Err(ApiError::bad_request("mfa", "请先调用 enroll 生成密钥"));
    };
    let master = state.require_secret_key()?;
    let secret = master.decrypt(&blob).map_err(ApiError::from)?;
    // 绑定时只认动态口令（不认恢复码）——恢复码是"逃生通道"，不能用来完成绑定
    if !crate::totp::verify(&secret, &req.code, crate::now_unix()) {
        return Err(ApiError::bad_request("code", "动态口令不正确"));
    }
    let uid = s.user_id;
    let now = crate::now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE users SET mfa_enabled_at = ?1 WHERE id = ?2",
                rusqlite::params![now, uid],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))
        })
        .await?;
    audit(&state, &s, "auth.mfa.enable", &s.username, "ok").await;
    Ok(ok(true))
}

/// POST /auth/mfa/disable —— 关闭 MFA。**必须出示第二因子**，
/// 否则一个被劫持的会话就能顺手关掉受害者账户的 MFA。
pub async fn mfa_disable(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<MfaCodeReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let (secret_enc, codes, enabled) = mfa_material(&state, s.user_id).await?;
    if enabled.is_none() {
        return Err(ApiError::bad_request("mfa", "MFA 未启用"));
    }
    let secret = match (&secret_enc, &state.master_key) {
        (Some(blob), Some(master)) => master.decrypt(blob).ok(),
        _ => None,
    };
    if !factor_ok(secret.as_deref(), &codes, &req.code) {
        return Err(ApiError::bad_request("code", "动态口令或恢复码不正确"));
    }
    let uid = s.user_id;
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE users SET mfa_secret_enc = NULL, mfa_recovery_codes = NULL, mfa_enabled_at = NULL WHERE id = ?1",
                [uid],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))
        })
        .await?;
    audit(&state, &s, "auth.mfa.disable", &s.username, "ok").await;
    Ok(ok(true))
}

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

    /// **源码级守卫**：429 分支必须真的记一次失败（P2-11）。
    ///
    /// 为什么不能用行为测试：`LoginGuard` 的单测自己调 `record_failure`，把
    /// handler 里那行删掉它照样绿——这正是本项目踩过的「守卫自持实现 ⇒ 恒绿」。
    /// 唯一可靠的办法是直接盯住那段源码。
    ///
    /// ⚠ 断言前**必须剔除注释行**：本函数上方的说明文字里就写着
    /// `record_failure`，不剔除会让断言恒命中（同理，断言目标是"代码里的调用"，
    /// 不是"文件里出现过这个字符串"）。
    #[test]
    fn login_429_branch_records_the_failure() {
        let src = include_str!("auth.rs");
        // 只取 login 函数体内、check 被拦下的那个 if 块（从 `if let Some(wait)` 到
        // `return Err(ApiError::too_many_requests` 之间的代码行）
        let code: Vec<&str> = src
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//")          // 剔除行注释
            })
            .collect();
        let joined = code.join("\n");
        let start = joined
            .find("if let Some(wait) = state.logins.check(&key)")
            .expect("429 判定分支必须存在");
        let end_rel = joined[start..]
            .find("too_many_requests(wait)")
            .expect("429 返回必须存在");
        let block = &joined[start..start + end_rel];
        assert!(
            block.contains("record_failure(&key)"),
            "429 分支必须调用 record_failure 才算「拦下也计数」（P2-11）；\
             否则被打回的尝试不推进计数，攻击者可用 1 req/s 长期在线爆破。\
             当前块内容：\n{block}"
        );
    }
}
