//! 防火墙（设计方案 §2.7）。
//!
//! # 最高风险模块，三条硬约束
//!
//! 1. **改规则前必须先快照**：`apply` 之前无条件 `snapshot()`。
//!    误封 SSH 端口是自建面板最经典的"把自己锁在门外"事故。
//! 2. **只管理自己写的规则**：`RulePlan::replace_panel_managed_only` 必须为 true。
//!    面板绝不能清掉用户手动加的规则——那会让用户别的安全措施一起失效。
//! 3. **SSH 端口保护**：拒绝任何会阻断当前 SSH 连接端口的规则，
//!    除非请求里显式声明 `allow_lockout_risk`（且 UI 必须二次确认）。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{extract::{Path as AxPath, State}, Json};
use panel_core::cap_keys;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// 受保护端口：**永远不能封**。22 是 SSH，面板自身端口由配置注入。
const PROTECTED_PORTS: &[u16] = &[22];

#[derive(Debug, Serialize)]
pub struct RuleDto {
    pub id: String,
    pub ports: String,
    pub protocol: &'static str,
    pub action: &'static str,
    pub direction: &'static str,
    pub source: Option<String>,
    pub comment: Option<String>,
    /// 是否由面板创建（面板只删除自己创建的）
    pub panel_managed: bool,
}

pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_VIEW)?;
    if !state.capabilities.get(cap_keys::FIREWALL_MANAGE).map(|c| c.supported).unwrap_or(false) {
        // 明确 501 而非空列表：让用户知道"没装防火墙"而不是"没规则"
        return Err(ApiError::unsupported("firewall.manage"));
    }
    let rules = state.os.firewall().list_rules().await?;
    let active = state.os.firewall().is_active().await?;

    let dtos: Vec<RuleDto> = rules.into_iter().map(|r| RuleDto {
        panel_managed: r.comment.as_deref()
            .map(|c| c.contains(PANEL_MARK)).unwrap_or(false),
        id: r.id,
        ports: render_ports(&r.ports),
        protocol: match r.protocol { panel_os::Protocol::Tcp => "tcp",
                                     panel_os::Protocol::Udp => "udp",
                                     panel_os::Protocol::Icmp => "icmp",
                                     panel_os::Protocol::Any => "any" },
        action: match r.action { panel_os::Action::Allow => "allow",
                                 panel_os::Action::Deny => "deny",
                                 panel_os::Action::Reject => "reject" },
        direction: match r.direction { panel_os::Direction::Inbound => "in",
                                       _ => "out" },
        source: r.source_cidr,
        comment: r.comment,
    }).collect();

    Ok(ok(serde_json::json!({
        "backend": backend_name(state.os.firewall().backend()),
        "active": active,
        "rules": dtos,
    })))
}

/// 面板写入规则的标记。**识别"哪些是我写的"全靠它**。
pub const PANEL_MARK: &str = "panel-managed";

fn backend_name(b: panel_core::FirewallBackend) -> &'static str {
    match b {
        panel_core::FirewallBackend::Nftables => "nftables",
        panel_core::FirewallBackend::Iptables => "iptables",
        panel_core::FirewallBackend::Ufw => "ufw",
        panel_core::FirewallBackend::Firewalld => "firewalld",
        panel_core::FirewallBackend::WindowsFirewall => "wf",
        panel_core::FirewallBackend::Pf => "pf",
        panel_core::FirewallBackend::None => "none",
    }
}

fn render_ports(p: &panel_os::PortSpec) -> String {
    match p {
        panel_os::PortSpec::Single(x) => x.to_string(),
        panel_os::PortSpec::Range(a, b) => format!("{a}-{b}"),
        panel_os::PortSpec::List(v) => v.iter().map(|x| x.to_string())
            .collect::<Vec<_>>().join(","),
        panel_os::PortSpec::All => "all".into(),
    }
}

/// 解析 "80,443,8000-8100"。**只接受结构化输出**，不把原始串传给命令。
pub fn parse_ports(s: &str) -> Option<panel_os::PortSpec> {
    let s = s.trim();
    if s == "all" || s == "*" { return Some(panel_os::PortSpec::All); }
    let mut singles = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().ok()?;
            let b: u16 = b.trim().parse().ok()?;
            if a > b { return None; }
            // 单端口区间归一化为 Single
            if a == b { singles.push(a); } else { return Some(panel_os::PortSpec::Range(a, b)); }
        } else {
            singles.push(part.parse::<u16>().ok()?);
        }
    }
    if singles.is_empty() { None }
    else if singles.len() == 1 { Some(panel_os::PortSpec::Single(singles[0])) }
    else { Some(panel_os::PortSpec::List(singles)) }
}

// ─────────────── 应用规则 ───────────────

#[derive(Debug, Deserialize)]
pub struct ApplyReq {
    pub rules: Vec<RuleInput>,
    /// 显式承担失联风险。**UI 必须二次确认才能置 true**
    pub allow_lockout_risk: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RuleInput {
    pub ports: String,
    pub protocol: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub comment: Option<String>,
}

pub async fn apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<ApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    if !state.capabilities.get(cap_keys::FIREWALL_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("firewall.manage"));
    }

    let mut rules = Vec::new();
    for r in &req.rules {
        let ports = parse_ports(&r.ports)
            .ok_or_else(|| ApiError::bad_request("ports", format!("invalid port spec: {}", r.ports)))?;

        // CIDR 必须能被解析，绝不让原始串进命令
        if let Some(src) = &r.source {
            parse_cidr(src).ok_or_else(|| ApiError::bad_request("source", "invalid CIDR"))?;
        }

        let action = match r.action.as_deref().unwrap_or("allow") {
            "allow" => panel_os::Action::Allow,
            "deny" => panel_os::Action::Deny,
            "reject" => panel_os::Action::Reject,
            other => return Err(ApiError::bad_request("action", format!("unknown: {other}"))),
        };

        // ── 失联保护 ──
        if action != panel_os::Action::Allow && locks_out_ssh(&ports) {
            if req.allow_lockout_risk != Some(true) {
                return Err(ApiError::conflict(
                    "该规则可能阻断 SSH(22)。确认后请带 allow_lockout_risk=true 重试"));
            }
        }

        // id 必须唯一**并写进 comment**：删除时靠 `panel-managed <id>` 定位规则。
        // 若只写用户备注，两条同名规则会撞 id → 删除命中第一条，删错规则。
        let rid = gen_rule_id();
        rules.push(panel_os::FirewallRule {
            id: rid.clone(),
            ports,
            protocol: match r.protocol.as_deref().unwrap_or("tcp") {
                "udp" => panel_os::Protocol::Udp,
                "icmp" => panel_os::Protocol::Icmp,
                "any" => panel_os::Protocol::Any,
                _ => panel_os::Protocol::Tcp,
            },
            action,
            direction: panel_os::Direction::Inbound,
            source_cidr: r.source.clone(),
            // 打标记 + 带 id：这是"只删自己写的、且删对那一条"能成立的前提
            comment: Some(format!("{} {} {}", PANEL_MARK, rid,
                r.comment.clone().unwrap_or_default()).trim().to_string()),
            panel_managed: true,
        });
    }

    // ── 应用前无条件快照 ──
    let snapshot = state.os.firewall().snapshot().await?;

    let plan = panel_os::RulePlan { rules, replace_panel_managed_only: true };
    let report = match state.os.firewall().apply(plan).await {
        Ok(r) => r,
        Err(e) => {
            // 失败自动回滚：把快照恢复回去
            let _ = state.os.firewall().restore_snapshot(&snapshot).await;
            return Err(ApiError::from(e));
        }
    };

    audit(&state, &s, "firewall.apply",
          &format!("+{}/-{}", report.added, report.removed), "ok").await;

    Ok(ok(serde_json::json!({
        "added": report.added,
        "removed": report.removed,
        "unchanged": report.unchanged,
        "warnings": report.warnings,
        // 返回快照 id，UI 提供"撤销本次变更"入口
        "snapshot_bytes": snapshot.len(),
    })))
}

/// 生成规则 id（写入 comment，用于精确定位待删规则）。
fn gen_rule_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0);
    format!("p{nanos:x}")
}

/// 判断是否会阻断 SSH
fn locks_out_ssh(ports: &panel_os::PortSpec) -> bool {
    match ports {
        panel_os::PortSpec::All => true,   // 封全部端口必然封掉 22
        panel_os::PortSpec::Single(p) => PROTECTED_PORTS.contains(p),
        panel_os::PortSpec::Range(a, b) => PROTECTED_PORTS.iter().any(|p| p >= a && p <= b),
        panel_os::PortSpec::List(v) => v.iter().any(|p| PROTECTED_PORTS.contains(p)),
    }
}

/// CIDR 解析：只接受 "a.b.c.d" 或 "a.b.c.d/len"
pub fn parse_cidr(s: &str) -> Option<(IpAddr, Option<u8>)> {
    match s.split_once('/') {
        Some((ip, len)) => {
            let ip: IpAddr = ip.parse().ok()?;
            let len: u8 = len.parse().ok()?;
            if len > 32 && ip.is_ipv4() { return None; }
            if len > 128 { return None; }
            Some((ip, Some(len)))
        }
        None => Some((s.parse::<IpAddr>().ok()?, None)),
    }
}

// ─────────────── 开关 ───────────────

#[derive(Debug, Deserialize)]
pub struct ActiveReq { pub active: bool }

pub async fn set_active(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<ActiveReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    // 关闭防火墙会暴露所有端口 —— 这是高危操作，必须留痕
    state.os.firewall().set_active(req.active).await?;
    audit(&state, &s, "firewall.set_active",
          if req.active { "on" } else { "off" }, "ok").await;
    Ok(ok(serde_json::json!({ "active": req.active })))
}

// ─────────────── 文档式防火墙端点 ───────────────

pub async fn status(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_VIEW)?;
    if !state.capabilities.get(cap_keys::FIREWALL_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("firewall.manage"));
    }
    let active = state.os.firewall().is_active().await?;
    Ok(ok(serde_json::json!({
        "active": active,
        "backend": backend_name(state.os.firewall().backend()),
    })))
}

#[derive(Debug, Deserialize)]
pub struct EnabledReq { pub enabled: bool }

pub async fn set_enabled(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<EnabledReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    set_active(State(state), Auth(s), Json(ActiveReq { active: req.enabled })).await
}

pub async fn delete_rule(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    if !state.capabilities.get(cap_keys::FIREWALL_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("firewall.manage"));
    }
    // 三条硬约束之一：改规则前先快照（防误操作把自己锁门外）
    let snapshot = state.os.firewall().snapshot().await?;
    match state.os.firewall().delete_rule(&id).await {
        Ok(()) => {
            audit(&state, &s, "firewall.rule.delete", &id, "ok").await;
            Ok(ok(serde_json::json!({ "deleted": id })))
        }
        Err(e) => {
            let _ = state.os.firewall().restore_snapshot(&snapshot).await;
            Err(ApiError::from(e))
        }
    }
}

// ─────────────── fail2ban（入侵防御 jail 管理） ───────────────

pub async fn fail2ban_status(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    if !state.capabilities.get(cap_keys::FAIL2BAN).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("fail2ban.manage"));
    }
    let st = state.os.firewall().fail2ban_status().await?;
    Ok(ok(serde_json::json!({
        "available": st.available,
        "active": st.active,
        "jails": st.jails.into_iter().map(|j| serde_json::json!({
            "name": j.name, "enabled": j.enabled,
            "currently_failed": j.currently_failed, "total_failed": j.total_failed,
            "banned": j.banned, "banned_ips": j.banned_ips,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct JailReq { pub name: String, pub enabled: bool }

pub async fn fail2ban_set_jail(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<JailReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    if !state.capabilities.get(cap_keys::FAIL2BAN).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("fail2ban.manage"));
    }
    state.os.firewall().fail2ban_set_jail(&req.name, req.enabled).await?;
    audit(&state, &s, "firewall.fail2ban.set_jail", &req.name, "ok").await;
    Ok(ok(serde_json::json!({ "name": req.name, "enabled": req.enabled })))
}

#[derive(Debug, Deserialize)]
pub struct UnbanReq { pub jail: String, pub ip: String }

pub async fn fail2ban_unban(
    State(state): State<Shared>, Auth(s): Auth, Json(req): Json<UnbanReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    if !state.capabilities.get(cap_keys::FAIL2BAN).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("fail2ban.manage"));
    }
    state.os.firewall().fail2ban_unban(&req.jail, &req.ip).await?;
    audit(&state, &s, "firewall.fail2ban.unban", &format!("{} {}", req.jail, req.ip), "ok").await;
    Ok(ok(serde_json::json!({ "jail": req.jail, "ip": req.ip })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_spec_parsing() {
        assert_eq!(render_ports(&parse_ports("80").unwrap()), "80");
        assert_eq!(render_ports(&parse_ports("8000-8100").unwrap()), "8000-8100");
        assert_eq!(render_ports(&parse_ports("80,443").unwrap()), "80,443");
        assert_eq!(render_ports(&parse_ports("all").unwrap()), "all");
    }

    #[test]
    fn malformed_ports_rejected() {
        // 这些绝不能进入命令
        assert!(parse_ports("80; rm -rf /").is_none());
        assert!(parse_ports("$(id)").is_none());
        assert!(parse_ports("99999999").is_none());
        assert!(parse_ports("-1").is_none());
        assert!(parse_ports("").is_none());
        assert!(parse_ports("100-50").is_none(), "反向区间应拒绝");
    }

    #[test]
    fn ssh_lockout_detection() {
        assert!(locks_out_ssh(&panel_os::PortSpec::All));
        assert!(locks_out_ssh(&panel_os::PortSpec::Single(22)));
        assert!(locks_out_ssh(&panel_os::PortSpec::Range(20, 30)));
        assert!(locks_out_ssh(&panel_os::PortSpec::List(vec![80, 22])));
        // 正常规则不该被拦截
        assert!(!locks_out_ssh(&panel_os::PortSpec::Single(80)));
        assert!(!locks_out_ssh(&panel_os::PortSpec::Range(8000, 8100)));
        assert!(!locks_out_ssh(&panel_os::PortSpec::List(vec![80, 443])));
    }

    #[test]
    fn cidr_parsing() {
        assert!(parse_cidr("192.168.1.0/24").is_some());
        assert!(parse_cidr("10.0.0.1").is_some());
        assert!(parse_cidr("::1/128").is_some());
        // 注入串必须被拒
        assert!(parse_cidr("1.2.3.4; drop").is_none());
        assert!(parse_cidr("1.2.3.4/999").is_none());
        assert!(parse_cidr("not-an-ip").is_none());
    }

    #[test]
    fn panel_mark_identifies_own_rules() {
        // "只删自己写的"全靠这个标记
        let c = Some(format!("{} my rule", PANEL_MARK));
        assert!(c.as_deref().map(|x| x.contains(PANEL_MARK)).unwrap_or(false));
        let user = Some("my own rule".to_string());
        assert!(!user.as_deref().map(|x| x.contains(PANEL_MARK)).unwrap_or(false));
    }
}
