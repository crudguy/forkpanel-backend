//! 安全中心（设计方案 §2.10）：基线检查、在线会话管理。
//!
//! `baseline` 为**只读**扫描，输出契约 `SecurityBaselineItem[]`（分级发现项）。
//! 一键修复（`baseline_apply`）已实装但**仅限 sshd 三项白名单**：
//! 先备份 → 写 drop-in（`00-panel-baseline.conf`）→ `sshd -t` 语法校验 →
//! `sshd -T` 复核生效值 → 不通过回滚；校验器不可用则拒绝修改（绝不把人锁在门外）。
//! 会话管理：SessionCache 以内存为快路径，同时落 `sessions` 表 **（只存 sid 哈希）**；
//! 面板重启后按哈希惰性重建，会话**不再**全员登出。

use crate::{auth::perm, error::{ok, ApiError, ApiResult}, routes::{audit, Auth, CurrentSid, Shared}};
use axum::extract::{Path as AxPath, Query, State};
use axum::{Json, http::StatusCode};
use panel_core::cap_keys;
use serde::Deserialize;
use serde_json::json;
use crate::extract::PanelJson;

/// 只读安全基线扫描。
pub async fn baseline(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    let items = state.os.security().baseline().await?;
    let out: Vec<serde_json::Value> = items
        .into_iter()
        .map(|c| serde_json::json!({
            "key": c.key,
            "title": c.title,
            "ok": c.ok,
            "current": c.current,
            "expected": c.expected,
            "advice": c.advice,
            "applicable": c.applicable,
        }))
        .collect();
    Ok(ok(out))
}

/// 一键修复：**高危**（写回系统安全配置，需 root + 二次确认 + 先备份）。
/// **已实装**（仅 sshd 白名单三项，见模块文档与 provider 层 `apply_ssh_item`）：安全网
/// 全在 provider——先备份 → 写 drop-in → `sshd -t` 校验 → `sshd -T` 复核生效值
/// → 不通过回滚；校验器不可用则拒绝修改。写主配置会被 drop-in 遮蔽（假绿）。
/// 白名单外 key / sshd 缺失由 provider 以 `Validation` 拒绝（是 400 而非 501，但同样
/// 绝不半吊子写入把系统/SSH 锁死）。旧注释「未实装前诚实 501」已过时：端点早已接通。
/// 一键修复的二次确认词（写回系统配置属高危，必须手输确认）
pub const APPLY_CONFIRM_WORD: &str = "确认修复";

#[derive(Debug, Deserialize)]
pub struct BaselineApplyReq {
    /// 基线项 key；**白名单**由 provider 层判定（ssh.permit_root_login / ssh.password_auth / ssh.pubkey_auth）
    pub key: String,
    /// 二次确认词，须等于 [`APPLY_CONFIRM_WORD`]
    pub confirm_token: String,
}

/// 一键修复指定基线项（**高危写**）。
///
/// 安全网全部在 provider 层（`panel-os/linux/security.rs`）：
/// 先备份 → 写 drop-in → `sshd -t` 语法校验 → `sshd -T` 生效值复核 → 不通过立刻回滚；
/// **校验器不可用时拒绝修改**。这里只做权限、确认词与审计。
pub async fn baseline_apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<BaselineApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    if !is_apply_confirm(&req.confirm_token) {
        return Err(ApiError::bad_request(
            "confirm_token",
            format!("请输入确认词「{APPLY_CONFIRM_WORD}」以继续"),
        ));
    }

    let r = state.os.security().apply(&req.key).await.map_err(ApiError::from)?;
    audit(
        &state,
        &s,
        "security.baseline.apply",
        &req.key,
        if r.changed { "changed" } else { "unchanged" },
    )
    .await;
    Ok(ok(r))
}

/// 在线会话列表（管理员视图，数据源=内存 SessionCache）。
/// **ip 刻意不采集**（会话层没有对端地址管道）——不伪造数据，前端不展示该列。
pub async fn sessions(
    State(state): State<Shared>,
    Auth(s): Auth,
    CurrentSid(cur): CurrentSid,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    let now = crate::now_unix();
    let rows: Vec<serde_json::Value> = state
        .sessions
        .list()
        .into_iter()
        .map(|(sid, sess)| {
            json!({
                "id": sid,
                "user": sess.username,
                "role": sess.role,
                // 诚实占位：会话层无对端 IP，返回 null（前端不渲染该信息）
                "ip": Option::<String>::None,
                "created_at": sess.created_at,
                "last_seen": sess.last_seen,
                "expires_at": sess.expires_at,
                "idle_secs": (now - sess.last_seen).max(0),
                "current": sid == cur,
            })
        })
        .collect();
    let total = rows.len();
    Ok(ok(json!({ "sessions": rows, "total": total })))
}

/// 吊销指定会话。允许吊销自己的当前会话（= 自我登出，前端下个请求 401 跳登录）。
pub async fn revoke_session(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<String>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    let gone = state.sessions.remove(&id);
    if !gone {
        return Err(ApiError::not_found("session"));
    }
    // 审计不落完整 sid（sid=凭据，落库等于泄密），截断前 8 位
    audit(&state, &s, "session.revoke", &format!("{}…", &id[..id.len().min(8)]), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

/// 一键修复的二次确认词校验（纯函数，便于单测）：须逐字等于「确认修复」
/// （trim 容忍首尾空白）。近似词/空词一律拒绝，防止误触高危 SSH 配置写回。
fn is_apply_confirm(token: &str) -> bool {
    token.trim() == APPLY_CONFIRM_WORD
}

// ─────────────── SSH 端口（P1-7） ───────────────

/// 改 SSH 端口的二次确认词。与「确认修复」分开一个词是刻意的：
/// 改端口比改加固项的后果更直接（立刻可能连不上），不该复用同一句话。
pub const SSH_PORT_CONFIRM_WORD: &str = "确认改端口";

#[derive(Debug, Deserialize)]
pub struct SshPortReq {
    /// 新端口（1-65535）
    pub port: u16,
    /// 过渡期是否同时保留旧端口。**默认 true**（`#[serde(default)]` 让缺省为 false
    /// 的坑不出现——这里显式声明默认值语义由前端传），见 `keep_old_default`。
    #[serde(default)]
    pub keep_old: Option<bool>,
    /// 二次确认词，须等于 [`SSH_PORT_CONFIRM_WORD`]
    pub confirm_token: String,
}

/// `keep_old` 缺省时的取值：**保留旧端口**。
///
/// 缺省必须偏保守。若默认 false，任何前端漏传都会把用户唯一的回退通道关掉；
/// 保留旧端口的代价只是多开一个监听，比"连不上"轻得多。
fn keep_old_default(v: Option<bool>) -> bool {
    v.unwrap_or(true)
}

fn is_port_confirm(token: &str) -> bool {
    token.trim() == SSH_PORT_CONFIRM_WORD
}

/// 读取 SSH 端口现状（只读，`security.manage`）。
pub async fn ssh_port(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    let st = state.os.security().ssh_port().await.map_err(ApiError::from)?;
    Ok(ok(st))
}

/// 修改 SSH 端口（**高危写**：改错即失联，需 root + 二次确认）。
///
/// 安全网全在 provider（`linux/ssh_port.rs`）：端口占用预检 → 备份 → 写 drop-in
/// → `sshd -t` 校验 → 失败回滚。这里只做权限、确认词与审计。
pub async fn ssh_port_set(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<SshPortReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    if !is_port_confirm(&req.confirm_token) {
        return Err(ApiError::bad_request(
            "confirm_token",
            format!("请输入确认词「{SSH_PORT_CONFIRM_WORD}」以继续"),
        ));
    }
    let keep_old = keep_old_default(req.keep_old);
    let r = state
        .os
        .security()
        .set_ssh_port(req.port, keep_old)
        .await
        .map_err(ApiError::from)?;
    audit(
        &state,
        &s,
        "security.ssh_port.set",
        &format!("port={} keep_old={keep_old}", req.port),
        if r.changed { "changed" } else { "unchanged" },
    )
    .await;
    Ok(ok(r))
}

// ─────────────── SSH 登录 / 爆破记录 ───────────────

/// SSH 登录与爆破记录（只读）。数据源是统一日志源的 system/journald 源，
/// 从 sshd 消息解析来源 IP / 用户 / 结果 / 风险类型，筛选在服务端完成。
///
/// 不直接读 `/var/log/auth.log`：Debian 13 默认只有 journald，文件是否存在
/// 取决于 rsyslog 装没装；统一日志源已做过探测，这里只认 trait。无 journald
/// 时如实回 `source="unavailable"` + 空列表，不伪造数据。
pub async fn ssh_logins(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<crate::ssh_login::SshLoginFilter>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SECURITY_MANAGE)?;
    if !state.capabilities.get(cap_keys::LOGS_READ).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("logs.read"));
    }
    crate::ratelimit::check_read(&state, &s.username, "security.ssh_logins")?;

    let mut events = Vec::new();
    let mut source = "unavailable";
    if let Some(src) = state.os.logs().sources().await?
        .into_iter()
        .find(|x| x.kind == panel_os::LogSourceKind::System)
    {
        let lines = state.os.logs().read(&src, panel_os::LogQuery {
            lines: crate::ssh_login::FETCH_LINES,
            grep: Some("sshd".into()),
            level: None,
            follow: false,
            since_unix: None,
        }).await?;
        source = "journald";
        for l in lines {
            if let Some(e) = crate::ssh_login::parse_line(&l.text, l.ts_unix.unwrap_or(0)) {
                events.push(e);
            }
        }
    }
    let total = events.len();
    crate::ssh_login::mark_brute_force(&mut events);
    let rows = crate::ssh_login::filter_events(events, &q);
    Ok(ok(json!({
        "rows": rows,
        "total": total,
        "source": source,
        "truncated": total >= crate::ssh_login::FETCH_LINES,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_confirm_requires_exact_word() {
        assert!(is_apply_confirm("确认修复"));
        assert!(is_apply_confirm("  确认修复  ")); // trim 容忍首尾空白
        assert!(!is_apply_confirm("确认修复X"));
        assert!(!is_apply_confirm("确认"));
        assert!(!is_apply_confirm(""));
        assert!(!is_apply_confirm("  "));
    }

    fn sess(permissions: &[&str]) -> crate::auth::Session {
        crate::auth::Session {
            user_id: 1,
            username: "tester".into(),
            role: "admin".into(),
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
            allowed_roots: vec![],
            ip: "unknown".into(),
            created_at: 0,
            last_seen: 0,
            expires_at: 0,
        }
    }

    /// RBAC：基线扫描/修复/会话管理端点都要求 SECURITY_MANAGE。
    #[test]
    fn baseline_requires_security_manage() {
        assert!(crate::auth::require(&sess(&[perm::SECURITY_MANAGE]), perm::SECURITY_MANAGE).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::SECURITY_MANAGE).is_err());
        // 有别的 manage 权限但缺本权限 → 仍拒（防越权）
        assert!(crate::auth::require(&sess(&[perm::CONTAINER_MANAGE]), perm::SECURITY_MANAGE).is_err());
    }

    #[test]
    fn sessions_requires_security_manage() {
        assert!(crate::auth::require(&sess(&[perm::SECURITY_MANAGE]), perm::SECURITY_MANAGE).is_ok());
        assert!(crate::auth::require(&sess(&[]), perm::SECURITY_MANAGE).is_err());
    }

    /// 改端口的确认词必须与一键修复**不同**：两件事后果不同，
    /// 复用同一个词会让"手熟"变成风险。
    #[test]
    fn ssh_port_confirm_word_is_distinct_and_exact() {
        assert_ne!(SSH_PORT_CONFIRM_WORD, APPLY_CONFIRM_WORD);
        assert!(is_port_confirm("确认改端口"));
        assert!(is_port_confirm("  确认改端口  "));
        // 近似词一律拒绝
        assert!(!is_port_confirm("确认改端口X"));
        assert!(!is_port_confirm("确认端口"));
        assert!(!is_port_confirm(""));
        // **交叉**：拿一键修复的词去改端口必须被拒（否则两个词的区分形同虚设）
        assert!(!is_port_confirm(APPLY_CONFIRM_WORD));
        assert!(!is_apply_confirm(SSH_PORT_CONFIRM_WORD));
    }

    /// `keep_old` 缺省必须保留旧端口。缺省偏保守——漏传时宁可多开一个监听，
    /// 也不能把用户唯一的回退通道关掉。
    #[test]
    fn keep_old_defaults_to_true() {
        assert!(keep_old_default(None), "缺省必须保留旧端口");
        assert!(keep_old_default(Some(true)));
        assert!(!keep_old_default(Some(false)));
    }

    /// 接线守卫：`/api/v1/security/ssh-port` 必须 GET+PUT 同时挂，
    /// 且必须走 `security.manage` 权限。路由被改写（比如只留 GET、
    /// 或错挂到只读权限）时这里变红——源码断言指向 routes.rs 真实文本。
    #[test]
    fn ssh_port_route_is_wired_as_get_plus_put() {
        let src = panel_testutil::production_source(include_str!("../routes.rs"));
        let line: Vec<&str> = src
            .lines()
            .filter(|l| l.contains("/api/v1/security/ssh-port"))
            .collect();
        assert_eq!(line.len(), 1, "ssh-port 路由必须恰好挂一次，实际 {} 次", line.len());
        let l = line[0];
        assert!(l.contains("get(security::ssh_port)"), "必须挂 GET：{l}");
        assert!(l.contains("put(security::ssh_port_set)"), "必须挂 PUT：{l}");
    }

    /// 写端点必须要求 SECURITY_MANAGE（越权改 SSH 端口 = 直接把机主锁在门外）。
    #[test]
    fn ssh_port_set_requires_security_manage() {
        let src = panel_testutil::production_source(include_str!("security.rs"));
        let start = src.find("pub async fn ssh_port_set").expect("ssh_port_set 必须定义");
        // 只取该函数体到下一个函数定义的区间，避免扫到别的函数的 require
        let rest = &src[start..];
        let end = rest[1..].find("pub async fn ").map(|i| i + 1).unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("perm::SECURITY_MANAGE"),
            "ssh_port_set 必须校验 SECURITY_MANAGE 权限"
        );
        // 确认词校验也必须在（只靠前端拦 = 可绕过 API）
        assert!(body.contains("is_port_confirm"), "ssh_port_set 必须校验确认词");
    }

    /// 接线守卫：端点必须真挂 GET；实现必须做权限 + 只读限流 + 统一日志源，
    /// 且不得在业务层直接拼 journalctl 命令（分层门禁的同类坑）。
    #[test]
    fn ssh_logins_route_is_wired_with_guards() {
        let routes = panel_testutil::production_source(include_str!("../routes.rs"));
        let line: Vec<&str> = routes.lines()
            .filter(|l| l.contains("/api/v1/security/ssh-logins"))
            .collect();
        assert_eq!(line.len(), 1, "ssh-logins 路由必须恰好挂一次");
        assert!(line[0].contains("get(security::ssh_logins)"), "必须挂 GET");

        let src = panel_testutil::production_source(include_str!("security.rs"));
        let start = src.find("pub async fn ssh_logins").expect("ssh_logins 必须定义");
        let body = &src[start..];
        assert!(body.contains("perm::SECURITY_MANAGE"), "必须校验 security.manage");
        assert!(body.contains("check_read("), "journald 是重活，必须走只读限流");
        assert!(body.contains("LogSourceKind::System"), "必须走统一日志源的 system 源");
        assert!(!body.contains("Journalctl"), "业务层不得直接拼 journalctl 命令");
    }
}
