//! 认证相关 handler。

use crate::{
    auth::{self, Session},
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, CurrentSid, Shared},
    AppState,
};
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use crate::extract::PanelJson;

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
    PanelJson(req): PanelJson<LoginReq>,
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
                // ⚠ 写库结果**绝不能吞**：消费记录没落库 = 这个恢复码仍在库里、
                // 可无限次复用，等于把一次性恢复码变成永久口令，MFA 第二因子被架空。
                // 曾写作 `let _ = ...` ⇒ 写库失败照样放行且无任何留痕（二轮审计 P0-7）。
                // 另注意：这里必须用 execute 的**真实行数**构造 WriteAck——原先硬编码
                // `rows_changed: 1`，即便 UPDATE 一行都没命中也自称成功。
                match state
                    .db
                    .exec(move |conn| {
                        conn.execute(
                            "UPDATE users SET mfa_recovery_codes = ?1 WHERE id = ?2",
                            rusqlite::params![remain, uid2],
                        )
                        .map(|n| panel_db::WriteAck { rows_changed: n })
                        .map_err(|e| panel_core::PanelError::Database(e.to_string()))
                    })
                    .await
                {
                    Ok(ack) if ack.rows_changed > 0 => {}
                    Ok(_) => {
                        eprintln!("[panel] ⚠ [auth] 恢复码消费未命中任何账号，拒绝本次登录");
                        return Err(ApiError::mfa_recovery_persist_failed());
                    }
                    Err(e) => {
                        eprintln!(
                            "[panel] ⚠ [auth] 恢复码消费写库失败，拒绝本次登录（否则该码可无限复用）：{e}"
                        );
                        return Err(ApiError::mfa_recovery_persist_failed());
                    }
                }
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
    // 先构造会话值再插入，**插入后不回读**。
    //
    // 旧写法是 `insert(...); let s = sessions.get(&sid).unwrap();`——而 `get()` 会按
    // `expires_at > now` 判过期并顺手删除。`[security] session_idle = "0s"` 是**合法
    // 字符串**（解析成功、不触发 dur_or 的回落警告），插入时 `expires_at == now`，
    // 回读必为 None ⇒ **每次登录都 panic**（一次配置即可自锁死面板）。
    let sess = Session {
        user_id: uid,
        username: req.username.clone(),
        role,
        permissions,
        allowed_roots,
        // 登录这一刻的来源 IP，之后所有审计记录都带它（见 Session::ip）
        ip: ip.clone(),
        created_at: 0, last_seen: 0, expires_at: 0,
    };
    state.sessions.insert(sid.clone(), sess.clone());

    // 审计：登录成功（用刚构造的会话，不回读）
    audit(&state, &sess, "auth.login", &req.username, "ok").await;

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
    PanelJson(req): PanelJson<PwdReq>,
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

/// 取引导令牌的响应（data.token = 一次性引导令牌明文）。
#[derive(Debug, Serialize)]
pub struct BootstrapTokenResponse {
    /// 一次性引导令牌明文（== 内存守卫持有的令牌；仅 localhost 可取，bootstrap 后失效）。
    pub token: String,
}

/// **无终端初始化**：首启页「从文件读取令牌」按钮经此端点取令牌。
///
/// 安全模型（与令牌落盘联动）：
/// - 令牌文件 `<data_dir>/bootstrap.token` 由 serve 首启写入，权限 0600、root 拥有；
/// - 本端点**只接受回环地址的 peer**（非 loopback 一律 403）——远程攻击者即使
///   能访问端口也拿不到令牌；SSH 隧道 / 本地反代终止在 loopback，故可信；
/// - 仅在 `needs_bootstrap && token_active` 时返回文件内容；bootstrap 成功后文件即删，
///   此后返回 404（已初始化的面板不会把令牌留在内存或磁盘上）。
pub async fn bootstrap_token(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> ApiResult<Json<serde_json::Value>> {
    // ① 第一道闸：非回环请求**一律拒绝**，且不暴露任何引导状态（不区分"已初始化/已过期"）。
    if !is_loopback(addr) {
        return Err(ApiError::forbidden(
            "bootstrap-token is only served to loopback peers",
        ));
    }
    // ② 仅首启未初始化且令牌仍有效时才有东西可取。
    if owner_count(&state).await? > 0 || !state.bootstrap.active() {
        return Err(ApiError::not_found("bootstrap token unavailable"));
    }
    // ③ 取文件内容（== 内存令牌明文；文件不存在 = 不该发生，仍按 404 处理）。
    let path = state.os.paths().data_dir().join("bootstrap.token");
    let tok = std::fs::read_to_string(&path)
        .map_err(|_| ApiError::not_found("bootstrap token unavailable"))?;
    let tok = tok.trim();
    if tok.is_empty() {
        return Err(ApiError::not_found("bootstrap token unavailable"));
    }
    Ok(ok(BootstrapTokenResponse { token: tok.to_string() }))
}

/// 回环判定（纯函数，便于单测）。IPv4 127.0.0.0/8 与 IPv6 ::1 视为回环；
/// 链路本地（fe80::/10）、私有地址（192.168/10/172.16）、公网地址**都不是**回环——
/// 它们绝不能当作"本地可信"放行。
fn is_loopback(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// bootstrap 成功后删除令牌文件（0600 的明文令牌不应在初始化后残留磁盘）。
/// 幂等：文件不存在也 OK（如文件从未写出，或已被别的路径删掉）。
pub(crate) fn clear_bootstrap_token_file(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join("bootstrap.token"));
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
    PanelJson(req): PanelJson<MfaCodeReq>,
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
    PanelJson(req): PanelJson<MfaCodeReq>,
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
    PanelJson(req): PanelJson<BootstrapReq>,
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

    // 初始化完成：磁盘上 0600 的明文令牌文件即删（不应在 owner 创建后残留）。
    let tok_dir = state.os.paths().data_dir();
    clear_bootstrap_token_file(&tok_dir);

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

    // ── 无终端初始化：引导令牌「仅 localhost 可取」+ bootstrap 后文件即删 ──

    /// 回环判定纯函数：IPv4 127/8 与 IPv6 ::1 视为回环；私有/公网/链路本地都不是回环。
    #[test]
    fn is_loopback_discriminates() {
        assert!(is_loopback("127.0.0.1:1234".parse().unwrap()));
        assert!(is_loopback("127.255.255.254:1".parse().unwrap()));
        assert!(is_loopback("[::1]:1234".parse().unwrap()));
        assert!(!is_loopback("203.0.113.9:1234".parse().unwrap()), "公网地址不是回环");
        assert!(!is_loopback("192.168.1.5:1234".parse().unwrap()), "私有地址不是回环");
        assert!(!is_loopback("10.0.0.1:1234".parse().unwrap()), "私有地址不是回环");
        assert!(!is_loopback("[fe80::1]:1234".parse().unwrap()), "链路本地不是回环");
    }

    /// 引导令牌文件清理：存在即删，且幂等（不存在也不 panic）—— bootstrap 后磁盘不应残留明文。
    #[test]
    fn clear_bootstrap_token_file_removes_it() {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("panel-btc-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bootstrap.token");
        std::fs::write(&p, "x").unwrap();
        assert!(p.exists(), "前置：令牌文件应已写入");
        clear_bootstrap_token_file(&dir);
        assert!(!p.exists(), "bootstrap 成功后令牌文件必须被删除");
        // 幂等：不存在也能调用
        clear_bootstrap_token_file(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 辅助：带上伪造的 ConnectInfo 打一次 bootstrap_token 端点，返回状态码。
    async fn call_bootstrap_token(app: &axum::Router, addr: std::net::SocketAddr) -> axum::http::StatusCode {
        let mut req = axum::http::Request::builder()
            .uri("/api/v1/auth/bootstrap-token")
            .body(axum::body::Body::empty())
            .unwrap();
        // 绕过 make-service 直接注入 ConnectInfo，模拟真实连接的来源地址。
        req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
        let res = tower::ServiceExt::oneshot(app.clone(), req).await.expect("router 应能处理请求");
        res.status()
    }

    /// **行为测试**：回环判定在真实 handler 上生效——伪造远端 ConnectInfo → 403；回环 → 取令牌。
    ///
    /// 同时验证 bootstrap 成功后令牌文件被删除（文件即删路径）。
    #[tokio::test]
    async fn bootstrap_token_endpoint_only_over_loopback() {
        // 带 pid + 序号：并行跑测试时各用各的目录，避免共用一个 t.db / 令牌文件互相干扰
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("panel-bte-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let data_dir = base.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let db_path = base.join("t.db");
        let tier = panel_core::Tier::Nano;
        {
            let mut c = panel_db::open(&db_path, tier, "NORMAL").unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
        }
        let writer = std::sync::Arc::new(
            panel_db::WriterActor::spawn(db_path.clone(), tier, "NORMAL").unwrap());
        let pool = std::sync::Arc::new(panel_db::ReadPool::new(&db_path, tier).unwrap());
        let tasks = std::sync::Arc::new(panel_task::TaskRunner::new(
            writer.clone(), tier, base.join("tasks"), db_path.clone(), "NORMAL".to_string()));
        let metrics = std::sync::Arc::new(std::sync::Mutex::new(
            panel_db::aggregator::Aggregator::new(tier)));
        // 走跨平台入口而非直接构造 LinuxOsAdapter：后者会让 panel-api 绑死 Linux
        // （CI 门禁 [4c]）。同时保证测试用的 layout 与生产同源（同一工厂）。
        let os = panel_os::adapter_with(panel_os::PathOverrides {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        });
        let state = std::sync::Arc::new(crate::AppState::new(
            os, writer, pool, tasks, metrics, tier, None, false, 5,
            std::time::Duration::from_secs(1800), std::time::Duration::from_secs(43_200),
            90, 50_000, true, true, "NORMAL".to_string(), 7, false));

        // 写入与内存一致的令牌，并落盘到 data_dir（与 handler 读取路径同源）
        let tok = "deadbeefdeadbeefdeadbeefdeadbeef";
        state.bootstrap.set(tok, std::time::Duration::from_secs(60));
        let tok_path = state.os.paths().data_dir().join("bootstrap.token");
        std::fs::write(&tok_path, tok).unwrap();
        assert!(tok_path.exists(), "前置：令牌文件应已落盘");

        let app = crate::routes::build_router(state.clone());

        // ① 远程 peer → 403（不暴露是否已初始化）
        let res = call_bootstrap_token(&app, "203.0.113.9:55555".parse().unwrap()).await;
        assert_eq!(res, axum::http::StatusCode::FORBIDDEN, "非回环请求必须 403");

        // ② 回环 peer + 未初始化 + 令牌有效 + 文件存在 → 200 且返回令牌
        let res = call_bootstrap_token(&app, "127.0.0.1:55555".parse().unwrap()).await;
        assert_eq!(res, axum::http::StatusCode::OK, "回环未初始化应返回令牌");
        let mut req2 = axum::http::Request::builder()
            .uri("/api/v1/auth/bootstrap-token")
            .body(axum::body::Body::empty()).unwrap();
        // 与 call_bootstrap_token 一致：手动 oneshot 必须显式注入回环 ConnectInfo，
        // 否则 handler 的 ConnectInfo 提取失败、返回空体、JSON 解析直接 panic。
        req2.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:55555".parse::<std::net::SocketAddr>().unwrap()));
        let resp = tower::ServiceExt::oneshot(app.clone(), req2).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(bytes.as_ref()).unwrap();
        assert_eq!(body["data"]["token"].as_str(), Some(tok), "返回的令牌应等于落盘明文");

        // ③ bootstrap 成功后令牌文件被删
        super::bootstrap(
            axum::extract::State(state.clone()),
            crate::extract::PanelJson(BootstrapReq {
                token: tok.to_string(),
                username: "owner".to_string(),
                password: "Tr0ub4dor&3xy".to_string(),
            }),
        ).await.expect("bootstrap 应成功");
        assert!(!tok_path.exists(), "bootstrap 成功后令牌文件必须被删除");

        let _ = std::fs::remove_dir_all(&base);
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

    /// **源码级守卫**：登录审计不得回读刚插入的会话。
    ///
    /// `SessionCache::get()` 会按 `expires_at > now` 判过期并顺手删除；而 `insert` 设
    /// `expires_at = now + idle_timeout`。`[security] session_idle = "0s"` 是**合法**
    /// 字符串（解析成功、不触发 dur_or 的回落警告），此时回读必为 None ⇒ 旧写法的
    /// `.unwrap()` 会让**每次登录 panic**（一次配置即可自锁死面板）。
    /// 纯函数单测抓不到 handler 里的那行调用，只能盯源码。
    #[test]
    fn login_audit_does_not_refetch_the_session() {
        let src = include_str!("auth.rs");
        // 先剔掉测试段：本断言的字符串里就写着 `sessions.get(&sid).unwrap()`，
        // 不剔会自己命中自己（「判据指向错」类恒绿）。
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        let joined: Vec<&str> = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let joined = joined.join("\n");
        assert!(
            !joined.contains("sessions.get(&sid).unwrap()"),
            "登录路径不得回读刚插入的会话：0 秒 session_idle 下回读为 None ⇒ panic"
        );
        assert!(
            joined.contains("audit(&state, &sess, \"auth.login\""),
            "登录审计必须使用刚构造的会话值（不回读）"
        );
    }

    /// ⭐⭐ **接线守卫**：恢复码消费的写库结果**不得**被 `let _ =` 吞掉。
    /// 吞掉的后果是该恢复码仍留在库里、可无限次复用（一次性恢复码变永久口令），
    /// 而**没有任何行为测试会因此变红**——登录照样成功。
    #[test]
    fn recovery_code_persist_failure_is_not_swallowed() {
        let src = include_str!("auth.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        let code: String = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let at = code
            .find("UPDATE users SET mfa_recovery_codes")
            .expect("源码里找不到恢复码 UPDATE（改名后请同步本守卫）");
        // 取该 UPDATE 所在语句块（向后 900 字符，足够覆盖整个 exec 调用）
        let block = &code[at..(at + 900).min(code.len())];
        assert!(
            block.contains("mfa_recovery_persist_failed"),
            "恢复码写库失败必须拒绝登录：吞掉结果会让该恢复码无限复用，且不留下任何痕迹"
        );
        assert!(
            !block.contains("let _ ="),
            "恢复码写库不得用 `let _ =` 吞掉结果"
        );
        // 真实行数：硬编码 rows_changed: 1 会让「一行都没命中」也自称成功
        assert!(
            block.contains("WriteAck { rows_changed: n }"),
            "WriteAck 必须用 execute 的真实行数，硬编码 1 会让未命中的 UPDATE 也自称成功"
        );
    }

}
