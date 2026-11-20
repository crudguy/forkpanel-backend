//! 防火墙（设计方案 §2.7）。
//!
//! # 最高风险模块，三条硬约束
//!
//! 1. **改规则前必须先快照**：`apply` 之前无条件 `snapshot()`。
//!    误封 SSH 端口是自建面板最经典的"把自己锁在门外"事故。
//! 2. **只管理自己写的规则**：幂等比对只认带 `panel-managed` 标记的规则，
//!    `delete_rule` 拒绝删用户自建规则；`apply` 一律追加，不删既有规则（F-20）。
//!    面板绝不能清掉用户手动加的规则——那会让用户别的安全措施一起失效。
//! 3. **SSH 端口保护**：拒绝任何会阻断当前 SSH 连接端口的规则。
//!    封禁当前 SSH 端口时**必须**同时提供 `new_ssh_port`：先把 SSH 迁到新端口
//!    并 reload 生效（旧端口过渡期保留），再放行新端口、应用封禁规则；
//!    任一步失败全程回滚（SSH 配置 + 防火墙快照）。不存在"确认风险就能盲封"
//!    的逃生阀——允许盲封等于允许把自己永久锁在门外。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{extract::{Path as AxPath, Query, State}, Json};
use panel_core::{cap_keys, unit_name};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use crate::extract::PanelJson;

/// 读不到 SSH 配置时的兜底保护端口（SSH 传统默认端口）。
///
/// ⚠ 它**不是**“SSH 端口”本身：P1-7 支持改端口，真实受保护端口必须由
/// [`protected_ports`] 现读 `security().ssh_port()`。写死 22 会让用户把 SSH
/// 改到 2222 后封 2222 畅通无阻——正是“保护看着有、实际盯错对象”的锁死风险。
const FALLBACK_SSH_PORT: u16 = 22;

/// 当前受保护的 SSH 端口集合（升序去重）。
///
/// 22 只是兜底，真实保护对象现读：sshd 的生效端口 + 配置里的全部端口
/// （过渡期可能同时听 22 与 2222，两个都必须保护）。
/// 读取失败时保守退回 [22] 并打 warn——绝不能因为读不到就取消保护。
async fn protected_ports(state: &Shared) -> Vec<u16> {
    let mut v = vec![FALLBACK_SSH_PORT];
    match state.os.security().ssh_port().await {
        Ok(st) => {
            v.push(st.effective);
            v.extend(st.configured);
        }
        Err(e) => eprintln!("[warn] firewall: 读取 SSH 端口失败，按 {FALLBACK_SSH_PORT} 兜底保护：{e}"),
    }
    v.sort_unstable();
    v.dedup();
    v
}

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
    // 只读观察值：默认策略 + 本机监听端口。读不到整个规则列表仍要可用，
    // 但必须留痕——静默吞成"未启用"会让用户误判端口状态。
    let inbound = match state.os.firewall().inbound_state().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[warn] firewall list: 读取入站状态失败: {e}");
            Default::default()
        }
    };

    let dtos: Vec<RuleDto> = rules.into_iter().map(|r| RuleDto {
        // 用规则自身的标记位，而不是回看 comment 前缀：`to_rule` 已把标记剥成纯用户备注
        // （不剥的话回滚重放会层层嵌套），再拿 comment 判断会让所有面板规则变成 false，
        // 前端因此不再给它们显示删除入口。
        panel_managed: r.panel_managed,
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
        // 面板规则的 comment 里存着内部标记与 id，展示前洗成用户备注（F-20）。
        comment: panel_os::user_comment(r.comment.as_deref()),
    }).collect();

    let protected = protected_ports(&state).await;
    Ok(ok(serde_json::json!({
        "backend": backend_name(state.os.firewall().backend()),
        "active": active,
        "rules": dtos,
        // 前端据此在提交前拦“封禁 SSH 端口”；安全边界仍在后端 apply。
        "protected_ports": protected,
        // 只读观察值（不是可编辑规则）：accept = 下方未列出的端口默认可访问。
        "default_policy": inbound.default_policy,
        "listening_ports": inbound.listening_ports,
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
        panel_core::FirewallBackend::None => "none",
    }
}

fn render_ports(p: &panel_os::PortSpec) -> String {
    match p {
        panel_os::PortSpec::Single(x) => x.to_string(),
        panel_os::PortSpec::Range(a, b) => format!("{a}-{b}"),
        panel_os::PortSpec::List(v) => v.iter().map(render_ports).collect::<Vec<_>>().join(","),
        panel_os::PortSpec::All => "all".into(),
    }
}

/// 解析 "80,443,8000-8100"。**只接受结构化输出**，不把原始串传给命令。
pub fn parse_ports(s: &str) -> Option<panel_os::PortSpec> {
    let s = s.trim();
    if s == "all" || s == "*" { return Some(panel_os::PortSpec::All); }
    // 收集所有规格（单端口 + 区间），不再遇到区间就提前 return，避免同组单端口被静默丢弃。
    let mut parts: Vec<panel_os::PortSpec> = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().ok()?;
            let b: u16 = b.trim().parse().ok()?;
            if a > b { return None; }
            // 单端口区间归一化为 Single；否则保留 Range
            if a == b { parts.push(panel_os::PortSpec::Single(a)); } else { parts.push(panel_os::PortSpec::Range(a, b)); }
        } else {
            parts.push(panel_os::PortSpec::Single(part.parse::<u16>().ok()?));
        }
    }
    if parts.is_empty() { None }
    else if parts.len() == 1 { Some(parts.pop().unwrap()) }
    else { Some(panel_os::PortSpec::List(parts)) }
}

// ─────────────── 应用规则 ───────────────

#[derive(Debug, Deserialize)]
pub struct ApplyReq {
    pub rules: Vec<RuleInput>,
    /// 显式承担失联风险。兼容旧客户端保留字段，但**不再作为封禁 SSH 的逃生阀**：
    /// 现在封禁 SSH 端口必须给出 `new_ssh_port` 走"先迁移后封禁"（见 apply）。
    pub allow_lockout_risk: Option<bool>,
    /// 新 SSH 端口：封禁规则命中当前 SSH 端口时**必填**。面板会先把 SSH 迁到
    /// 这个端口、reload 生效并自动放行，然后才应用封禁规则。
    pub new_ssh_port: Option<u16>,
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
    PanelJson(req): PanelJson<ApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "firewall.apply")?;
    if !state.capabilities.get(cap_keys::FIREWALL_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("firewall.manage"));
    }

    // SSH 保护端口必须现读。写死 22 会在用户把 SSH 改到 2222 后失效，
    // 任由 deny 规则把自己锁在门外（P0）。
    let protected = protected_ports(&state).await;
    let ssh_state = state.os.security().ssh_port().await.ok();

    // 快照必须在任何变更之前取：若放在 SSH 迁移之后，snapshot() 自身失败会直接
    // 返回错误，而 SSH 配置与监听已经改过 —— 用户看到失败提示，机器却处于半迁移态。
    let snapshot = state.os.firewall().snapshot().await?;

    let mut rules = Vec::new();
    let mut blocks_ssh = false;
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
        // 命中当前 SSH 端口的封禁规则不再允许"点个风险确认就盲封"：必须有新端口，
        // 走下面的"先迁移后封禁"原子流程。allow_lockout_risk 仅为兼容旧字段保留，
        // 不再能绕过这道门——否则等于留着一个 API 后门把自己锁死。
        if action != panel_os::Action::Allow && locks_out_ssh(&ports, &protected) {
            blocks_ssh = true;
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
            // 只存用户备注：面板标记由实现层（nft / ufw）写 comment 时统一加一次。
            // 这里再拼一次会得到 `panel-managed <impl_id> panel-managed <rid>` 的双层前缀
            // （现场已有这类数据），回滚重放还会层层累加，最终撞上 comment 长度上限。
            comment: r.comment.clone(),
            panel_managed: true,
        });
    }

    // ── SSH 迁移编排 ──
    // 封禁命中当前 SSH 端口时，必须"先迁移、后封禁"：把 SSH 迁到新端口并
    // reload 生效（keep_old=true 让旧端口过渡期仍在听），再在防火墙放行新端口，
    // 最后才应用用户的封禁规则。全程任一步失败都回滚到操作前状态。
    let mut ssh_migration: Option<(u16, u16)> = None; // (新端口, 迁移前的生效端口)
    if blocks_ssh {
        let new_port = req.new_ssh_port.ok_or_else(|| ApiError::bad_request(
            "new_ssh_port",
            "该规则会封禁当前 SSH 端口，必须同时提供一个新的 SSH 端口用于迁移，避免失联",
        ))?;
        new_port_is_safe(new_port, &rules, &protected)
            .map_err(|reason| ApiError::bad_request("new_ssh_port", reason))?;

        let old_port = ssh_state.as_ref().map(|st| st.effective).unwrap_or(FALLBACK_SSH_PORT);
        let sec = state.os.security();
        // 单元名必须在写配置前解析：若解析失败发生在写之后，SSH 配置已改却没回滚。
        let sshd = unit_name("sshd").map_err(|_| ApiError::bad_request("sshd", "invalid unit name"))?;

        // ① 写新端口配置：keep_old=true 是安全关键——在 reload 前后旧端口都在听，
        //    不存在"新端口没起来、旧端口又没了"的窗口。方法自带 sshd -t 校验与写失败回滚。
        sec.set_ssh_port(new_port, true).await.map_err(ApiError::from)?;

        // ② reload 让新端口真正监听。失败则回滚 SSH 配置（回到只有旧端口）再 reload。
        if let Err(e) = state.os.services().reload(&sshd).await {
            let _ = sec.set_ssh_port(old_port, false).await;               // 尽力回滚配置
            let _ = state.os.services().reload(&sshd).await;               // 尽力回滚监听
            return Err(ApiError::from(e));
        }
        ssh_migration = Some((new_port, old_port));

        // ③ 把"放行新端口"前置到规则列表：封禁旧端口之前，新端口必须已通。
        //    用面板托管的 allow 规则，跟随同一份快照，回滚时一起撤销。
        rules.insert(0, panel_os::FirewallRule {
            id: gen_rule_id(),
            ports: panel_os::PortSpec::Single(new_port),
            protocol: panel_os::Protocol::Tcp,
            action: panel_os::Action::Allow,
            direction: panel_os::Direction::Inbound,
            source_cidr: None,
            comment: Some("panel ssh migration".into()),
            panel_managed: true,
        });
    }

    // F-20：apply 是「确保存在」的追加语义，绝不删既有规则；删除走 delete_rule(id)。
    let plan = panel_os::RulePlan { rules };
    let report = match state.os.firewall().apply(plan).await {
        Ok(r) => r,
        Err(e) => {
            // 失败自动回滚：防火墙快照 + SSH 配置（迁过去的端口必须收回来）
            if let Err(rollback_err) = state.os.firewall().restore_snapshot(&snapshot).await {
                eprintln!("[warn] firewall.apply 失败，回滚快照也失败（规则可能处于半应用状态）: {rollback_err}");
            }
            if let Some((_, old_port)) = ssh_migration {
                let _ = state.os.security().set_ssh_port(old_port, false).await;
                if let Ok(unit) = unit_name("sshd") { let _ = state.os.services().reload(&unit).await; }
            }
            return Err(ApiError::from(e));
        }
    };

    if let Some((new_port, _)) = ssh_migration {
        audit(&state, &s, "firewall.ssh_migrate",
              &format!("ssh -> {new_port}, then block old port"), "ok").await;
    }
    audit(&state, &s, "firewall.apply",
          &format!("+{}/-{}", report.added, report.removed), "ok").await;

    Ok(ok(serde_json::json!({
        "added": report.added,
        "removed": report.removed,
        "unchanged": report.unchanged,
        "warnings": report.warnings,
        // 快照只用于本次 apply 失败时的自动回滚；前端目前没有撤销入口，别写成已有。
        "snapshot_bytes": snapshot.len(),
        "ssh_migrated_to": ssh_migration.map(|(n, _)| n),
    })))
}

/// 校验用户提供的"新 SSH 端口"是否安全可用。
///
/// 三条判据缺一不可（都是实测会踩的坑）：
/// 1. 端口在 1..=65535；
/// 2. **不在**任何封禁规则的端口集里——否则 SSH 迁过去又被同一批规则封掉，
///    等于白迁还让用户以为有退路（最危险的假保护）；
/// 3. **不等于**任何当前受保护端口——迁到旧端口等于没迁。
fn new_port_is_safe(new_port: u16, rules: &[panel_os::FirewallRule], protected: &[u16]) -> Result<(), String> {
    if new_port == 0 { return Err("新 SSH 端口必须在 1-65535 之间".into()) }
    if protected.contains(&new_port) {
        return Err(format!("新 SSH 端口 {new_port} 与当前 SSH 端口相同，等于没有迁移"))
    }
    for r in rules {
        // 只有 deny / reject 才会封住端口；allow 规则里的同端口无妨
        if r.action == panel_os::Action::Allow { continue }
        if locks_out_ssh(&r.ports, &[new_port]) {
            return Err(format!("新 SSH 端口 {new_port} 也在本次封禁的端口范围内，迁过去仍会被封禁"))
        }
    }
    Ok(())
}

/// 生成规则 id（写入 comment，用于精确定位待删规则）。
fn gen_rule_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0);
    format!("p{nanos:x}")
}

/// 判断是否会阻断当前 SSH 端口。`protected` 由 [`protected_ports`] 现读，
/// 不能传常量——否则 SSH 改端口后保护对象错位。
fn locks_out_ssh(ports: &panel_os::PortSpec, protected: &[u16]) -> bool {
    match ports {
        panel_os::PortSpec::All => true,   // 封全部端口必然封掉 SSH
        panel_os::PortSpec::Single(p) => protected.contains(p),
        panel_os::PortSpec::Range(a, b) => protected.iter().any(|p| p >= a && p <= b),
        panel_os::PortSpec::List(v) => v.iter().any(|x| locks_out_ssh(x, protected)),
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
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<ActiveReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "firewall.set_active")?;
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
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<EnabledReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    set_active(State(state), Auth(s), PanelJson(ActiveReq { active: req.enabled })).await
}

pub async fn delete_rule(
    State(state): State<Shared>, Auth(s): Auth, AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "firewall.rule_delete")?;
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
            if let Err(rollback_err) = state.os.firewall().restore_snapshot(&snapshot).await {
                eprintln!("[warn] firewall.rule.delete 失败，回滚快照也失败（规则可能处于半应用状态）: {rollback_err}");
            }
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
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<JailReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "fail2ban.set_jail")?;
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
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<UnbanReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "fail2ban.unban")?;
    if !state.capabilities.get(cap_keys::FAIL2BAN).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("fail2ban.manage"));
    }
    state.os.firewall().fail2ban_unban(&req.jail, &req.ip).await?;
    audit(&state, &s, "firewall.fail2ban.unban", &format!("{} {}", req.jail, req.ip), "ok").await;
    Ok(ok(serde_json::json!({ "jail": req.jail, "ip": req.ip })))
}

// ── fail2ban jail 封禁参数（运行期） ──

/// 参数范围：maxretry 1..=10000；bantime/findtime 1..=30 天（秒）。
/// 只接受 i64，负数/0/超大值一律 400——把非法值传给 fail2ban-client 轻则无效重则
/// 让 jail 永久封禁所有 IP（bantime=0 在部分版本表示永久），故必须在入口挡死。
fn valid_jail_params(maxretry: i64, bantime: i64, findtime: i64) -> bool {
    (1..=10_000).contains(&maxretry)
        && (1..=2_592_000).contains(&bantime)
        && (1..=2_592_000).contains(&findtime)
}

#[derive(Debug, Deserialize)]
pub struct JailParamsQuery { pub jail: String }

#[derive(Debug, Deserialize)]
pub struct JailParamsReq {
    pub jail: String,
    pub maxretry: i64,
    pub bantime: i64,
    pub findtime: i64,
}

fn validate_jail_name(jail: &str) -> Result<(), ApiError> {
    if !panel_os::is_safe_jail_name(jail) {
        return Err(ApiError::bad_request("jail", "jail 名只允许字母数字与 _ -"));
    }
    Ok(())
}

/// 读取 jail 当前**运行期**参数（非 jail.local 文件值）。
pub async fn fail2ban_get_params(
    State(state): State<Shared>, Auth(s): Auth, Query(q): Query<JailParamsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    validate_jail_name(&q.jail)?;
    if !state.capabilities.get(cap_keys::FAIL2BAN).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("fail2ban.manage"));
    }
    let (maxretry, bantime, findtime) =
        state.os.firewall().fail2ban_get_params(&q.jail).await?;
    Ok(ok(serde_json::json!({
        "jail": q.jail, "maxretry": maxretry,
        "bantime": bantime, "findtime": findtime, "persistent": false
    })))
}

/// 下发 jail 封禁参数（**仅运行期生效**，重启 fail2ban 后回落 jail.local）。
/// 面板不写 jail.local（敏感路径），因此 UI 必须把 `persistent=false` 明确展示。
pub async fn fail2ban_set_params(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<JailParamsReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::FIREWALL_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "fail2ban.set_params")?;
    validate_jail_name(&req.jail)?;
    if !valid_jail_params(req.maxretry, req.bantime, req.findtime) {
        return Err(ApiError::bad_request(
            "params", "maxretry 需在 1..10000，bantime/findtime 需在 1..2592000 秒",
        ));
    }
    if !state.capabilities.get(cap_keys::FAIL2BAN).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("fail2ban.manage"));
    }
    state.os.firewall().fail2ban_set_params(
        &req.jail, req.maxretry, req.bantime, req.findtime,
    ).await?;
    audit(&state, &s, "firewall.fail2ban.set_params", &req.jail, "ok").await;
    Ok(ok(serde_json::json!({
        "jail": req.jail, "maxretry": req.maxretry,
        "bantime": req.bantime, "findtime": req.findtime, "persistent": false
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_rule(spec: &str) -> panel_os::FirewallRule {
        panel_os::FirewallRule {
            id: "t".into(),
            ports: parse_ports(spec).unwrap(),
            protocol: panel_os::Protocol::Tcp,
            action: panel_os::Action::Deny,
            direction: panel_os::Direction::Inbound,
            source_cidr: None,
            comment: None,
            panel_managed: true,
        }
    }

    #[test]
    fn new_ssh_port_rejects_unsafe_choices() {
        // 合法：新端口既不是当前 SSH 端口，也不在封禁集里
        assert!(new_port_is_safe(2222, &[deny_rule("22")], &[22]).is_ok());
        // ① 端口 0
        assert!(new_port_is_safe(0, &[], &[22]).is_err());
        // ② 迁到当前 SSH 端口本身 = 没迁
        assert!(new_port_is_safe(22, &[], &[22]).is_err());
        // ③ 迁过去又被同一批规则封掉 = 假保护（最危险）
        assert!(new_port_is_safe(2222, &[deny_rule("2222")], &[22]).is_err());
        assert!(new_port_is_safe(2222, &[deny_rule("2200-2300")], &[22]).is_err());
        assert!(new_port_is_safe(2222, &[deny_rule("22,2222")], &[22]).is_err());
        assert!(new_port_is_safe(2222, &[deny_rule("all")], &[22]).is_err());
        // allow 规则里的同端口无妨（放行不是封禁）
        let mut allow = deny_rule("2222"); allow.action = panel_os::Action::Allow;
        assert!(new_port_is_safe(2222, &[allow], &[22]).is_ok());
    }

    /// 接线守卫：纯函数单测全绿也挡不住 apply 退回"带 allow_lockout_risk 就盲封"。
    /// 必须扫 apply 函数体，确认迁移链路真的接了：要求 new_ssh_port、写配置、
    /// reload、放行新端口、失败回滚 SSH 配置。
    #[test]
    fn apply_requires_ssh_migration_not_blind_allow() {
        let src = panel_testutil::production_source(include_str!("firewall.rs"));
        let start = src.find("pub async fn apply").expect("apply 必须存在");
        let rest = &src[start..];
        let end = rest.find("fn new_port_is_safe").expect("apply 之后应有 new_port_is_safe");
        let body = &rest[..end];
        assert!(body.contains("blocks_ssh"), "apply 必须检测封禁是否命中 SSH");
        assert!(body.contains("new_ssh_port"), "apply 必须要求新 SSH 端口");
        assert!(body.contains("set_ssh_port(new_port, true)"),
            "apply 必须先写新端口配置且 keep_old=true 保住过渡期旧端口");
        assert!(body.contains("services().reload"), "apply 必须 reload sshd 让新端口生效");
        assert!(body.contains("panel ssh migration"), "apply 必须在防火墙放行新端口");
        assert!(body.contains("set_ssh_port(old_port, false)"), "apply 失败必须回滚 SSH 配置");
        // 顺序守卫：快照 / 单元名解析必须早于任何写入。曾把两者放在 SSH 迁移之后，
        // 它们一旦失败 SSH 已在半迁移态却无人回滚，用户只看到「操作失败」。
        let at_snapshot = body.find("firewall().snapshot()").expect("apply 必须取快照");
        let at_unit = body.find("unit_name(\"sshd\")").expect("apply 必须解析 sshd 单元名");
        let at_write = body.find("set_ssh_port(new_port, true)").expect("apply 必须写新端口");
        assert!(at_snapshot < at_write, "快照必须在改 SSH 配置之前");
        assert!(at_unit < at_write, "sshd 单元名解析必须在改 SSH 配置之前");
        assert!(!body.contains("allow_lockout_risk != Some(true)"),
            "不得保留'带风险确认就盲封'的逃生阀");
    }

    #[test]
    fn jail_params_reject_zero_negative_and_oversized_values() {
        assert!(valid_jail_params(5, 600, 600));
        assert!(valid_jail_params(1, 1, 1));
        assert!(valid_jail_params(10_000, 2_592_000, 2_592_000));
        // bantime=0 在部分 fail2ban 版本表示"永久封禁"，必须堵死
        for bad in [
            (0, 600, 600), (5, 0, 600), (5, 600, 0),
            (-1, 600, 600), (5, -1, 600), (5, 600, -1),
            (10_001, 600, 600), (5, 2_592_001, 600), (5, 600, 2_592_001),
        ] {
            assert!(!valid_jail_params(bad.0, bad.1, bad.2), "{bad:?} 不得下发");
        }
    }

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
        let p = [22u16];
        assert!(locks_out_ssh(&panel_os::PortSpec::All, &p));
        assert!(locks_out_ssh(&panel_os::PortSpec::Single(22), &p));
        assert!(locks_out_ssh(&panel_os::PortSpec::Range(20, 30), &p));
        assert!(locks_out_ssh(&panel_os::PortSpec::List(vec![panel_os::PortSpec::Single(80), panel_os::PortSpec::Single(22)]), &p));
        // 正常规则不该被拦截
        assert!(!locks_out_ssh(&panel_os::PortSpec::Single(80), &p));
        assert!(!locks_out_ssh(&panel_os::PortSpec::Range(8000, 8100), &p));
        assert!(!locks_out_ssh(&panel_os::PortSpec::List(vec![panel_os::PortSpec::Single(80), panel_os::PortSpec::Single(443)]), &p));
    }

    /// P0 回归：SSH 已改到 2222 时，封 2222 必须命中、封 22 不再命中。
    /// 写死 [22] 的实现会让这条测试直接变红。
    #[test]
    fn ssh_lockout_uses_supplied_ports_not_hardcoded_22() {
        assert!(locks_out_ssh(&panel_os::PortSpec::Single(2222), &[2222]));
        assert!(!locks_out_ssh(&panel_os::PortSpec::Single(22), &[2222]));
        // 过渡期两个端口都在听，两个都必须保护
        assert!(locks_out_ssh(&panel_os::PortSpec::Single(22), &[22, 2222]));
        assert!(locks_out_ssh(&panel_os::PortSpec::Single(2222), &[22, 2222]));
        assert!(locks_out_ssh(&panel_os::PortSpec::Range(2200, 2300), &[2222]));
        assert!(!locks_out_ssh(&panel_os::PortSpec::Single(8080), &[22, 2222]));
    }

    /// 接线守卫：纯函数单测全绿也挡不住 apply 退回写死常量，必须扫函数体。
    #[test]
    fn firewall_apply_uses_dynamic_ssh_ports_not_hardcoded_constant() {
        let src = panel_testutil::production_source(include_str!("firewall.rs"));
        assert!(!src.contains("PROTECTED_PORTS"), "不得再有写死的受保护端口常量");
        assert_eq!(src.matches("async fn protected_ports").count(), 1);
        let start = src.find("pub async fn apply").expect("apply 必须存在");
        let rest = &src[start..];
        let end = rest.find("fn gen_rule_id").expect("apply 之后应有 gen_rule_id");
        let body = &rest[..end];
        assert!(body.contains("let protected = protected_ports(&state).await"),
            "apply 必须现读 SSH 保护端口");
        assert!(body.contains("locks_out_ssh(&ports, &protected)"),
            "失联校验必须用现读端口集，不能传常量");
        assert!(!body.contains("locks_out_ssh(&ports, PROTECTED_PORTS)"));
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
