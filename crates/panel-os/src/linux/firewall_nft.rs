//! 防火墙的 **nftables 后端（真实 Linux 实现）**（设计方案 §2.7，M5 落地）。
//!
//! 与 ufw 后端同样严格落实三条硬约束：
//! 1. 改规则前无条件 `snapshot()`（路由 `apply` 已调用）；
//! 2. **只管理面板自己写的规则**：规则 comment 带 `panel-managed <id>` 标记，
//!    `delete_rule` / `apply`（先删全部面板规则再重加）都只碰这些规则，绝不删用户既有规则；
//! 3. SSH(22) 端口保护在路由层（`locks_out_ssh` + `allow_lockout_risk`）拦截。
//!
//! 设计要点：
//! - 专用表 `table inet panelfw` + 链 `chain input`（`policy accept`，**不改默认策略**，
//!   避免误锁 SSH）。面板规则只做 `accept`/`drop`/`reject`，不碰链策略。
//! - 命令全部经 `cmd::run`（argv 直传，不经 shell），杜绝注入；需判成败的用 `run_checked`。
//! - 能力位诚实：`nft` 二进制缺失时 `capability()` 报不支持，前端据此置灰，绝不伪造成功。
//!
//! 已知边界（如实）：
//! - `Protocol::Icmp` 渲染为 `icmp`（仅匹配 IPv4 ICMP）；IPv6 的 `icmpv6` 暂未单独建模。
//! - `Protocol::Any` 且指定端口时，兜底渲染为 `tcp dport`（nft 的 `dport` 必须依附传输层协议）。
//! - fail2ban 由独立服务管理，本后端不接管（能力位报 `no`）。

use crate::cmd::{Bin, CmdOpt};
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{Capability, FirewallBackend, PanelError, Result};
use std::time::Duration;

const TABLE: &str = "panelfw";
const CHAIN: &str = "input";

pub struct NftFirewall;

impl NftFirewall {
    /// 探测是否可用（仅 `nft` 二进制存在时启用）。
    pub fn available() -> bool {
        Bin::Nft.available()
    }

    /// 实际命令执行（不校验退出码，供「删一条/查表」这类允许失败的步骤用）。
    async fn nft(&self, args: &[&str], timeout: Duration) -> Result<crate::cmd::CmdOutput> {
        crate::cmd::run(Bin::Nft, args, CmdOpt { timeout, ..Default::default() }).await
    }

    /// 需判成败的命令（建表、加规则），失败即报错。
    async fn nft_checked(&self, args: &[&str], timeout: Duration) -> Result<crate::cmd::CmdOutput> {
        crate::cmd::run_checked(Bin::Nft, args, CmdOpt { timeout, ..Default::default() }).await
    }

    fn ensure_nft(&self) -> Result<()> {
        if !Bin::Nft.available() {
            return Err(PanelError::Unsupported("firewall: 需要 nft 命令（当前后端不可用）"));
        }
        Ok(())
    }

    /// 确保面板专用表与链存在（幂等）。`add table` 幂等；链用 `run` 忽略已存在错误。
    async fn ensure_table(&self) -> Result<()> {
        self.nft_checked(
            &["add", "table", "inet", TABLE],
            Duration::from_secs(10),
        ).await?;
        // 链定义含 `{}` 与 `;`，作为多个 argv token 传入（argv 直传，不经 shell）。
        let _ = self.nft(
            &[
                "add", "chain", "inet", TABLE, CHAIN,
                "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}",
            ],
            Duration::from_secs(10),
        ).await;
        Ok(())
    }

    /// 解析当前面板链里的规则（含 handle 与 comment），只返回带 `panel-managed` 标记者。
    async fn list_panel_handles(&self) -> Result<Vec<(u32, String, String)>> {
        let out = self.nft(&["-a", "list", "table", "inet", TABLE], Duration::from_secs(10)).await?;
        if out.code != Some(0) {
            return Ok(vec![]); // 表不存在 → 空（不是错误）
        }
        Ok(parse_panel_rules(&out.stdout))
    }
}

#[async_trait]
impl FirewallProvider for NftFirewall {
    fn backend(&self) -> FirewallBackend {
        FirewallBackend::Nftables
    }

    fn capability(&self) -> Capability {
        if Bin::Nft.available() {
            Capability::yes("nft")
        } else {
            Capability::no("binary_missing")
        }
    }

    async fn is_active(&self) -> Result<bool> {
        self.ensure_nft()?;
        let out = self.nft(&["list", "table", "inet", TABLE], Duration::from_secs(10)).await?;
        Ok(out.code == Some(0))
    }

    async fn set_active(&self, active: bool) -> Result<()> {
        self.ensure_nft()?;
        if active {
            self.ensure_table().await?;
        } else {
            // 停用 = 删掉整张面板表（只含面板规则，不碰用户其它规则）
            let _ = self.nft(&["delete", "table", "inet", TABLE], Duration::from_secs(10)).await;
        }
        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        self.ensure_nft()?;
        let out = self.nft(&["-a", "list", "table", "inet", TABLE], Duration::from_secs(10)).await?;
        if out.code != Some(0) {
            return Ok(vec![]);
        }
        Ok(parse_panel_rules(&out.stdout)
            .into_iter()
            .filter_map(to_rule)
            .collect())
    }

    async fn apply(&self, plan: RulePlan) -> Result<ApplyReport> {
        self.ensure_nft()?;
        self.ensure_table().await?;

        // 1) 先删所有面板自有规则（按 handle，逆序避免删一条后 handle 前移）
        let mut removed = 0;
        for (h, _, _) in self.list_panel_handles().await?.into_iter().rev() {
            let hs = h.to_string();
            if self.nft(
                &["delete", "rule", "inet", TABLE, CHAIN, "handle", &hs],
                Duration::from_secs(15),
            ).await.is_ok() {
                removed += 1;
            }
        }

        // 2) 加新规则（每条带 panel-managed <id> 标记）
        let mut added = 0;
        let mut warnings = Vec::new();
        for rule in &plan.rules {
            let id = gen_id();
            let expr = render_rule(rule, &id);
            let e = expr.as_str();
            match self.nft_checked(
                &["add", "rule", "inet", TABLE, CHAIN, e],
                Duration::from_secs(20),
            ).await {
                Ok(_) => added += 1,
                Err(err) => warnings.push(format!("add {} 失败: {}", rule.id, err)),
            }
        }
        Ok(ApplyReport { added, removed, unchanged: 0, warnings })
    }

    async fn delete_rule(&self, id: &str) -> Result<()> {
        self.ensure_nft()?;
        let handles = self.list_panel_handles().await?;
        let target = handles
            .into_iter()
            .find(|(_, c, _)| panel_id(c).as_deref() == Some(id))
            .ok_or_else(|| PanelError::NotFound(format!("firewall rule `{id}`")))?;

        // 只可能命中面板自有规则（list_panel_handles 已按标记过滤），不会删用户规则
        let h = target.0.to_string();
        self.nft_checked(
            &["delete", "rule", "inet", TABLE, CHAIN, "handle", &h],
            Duration::from_secs(15),
        ).await?;
        Ok(())
    }

    async fn snapshot(&self) -> Result<Vec<u8>> {
        self.ensure_nft()?;
        let out = self.nft(&["-a", "list", "table", "inet", TABLE], Duration::from_secs(10)).await?;
        Ok(out.stdout.into_bytes())
    }

    async fn restore_snapshot(&self, data: &[u8]) -> Result<()> {
        self.ensure_nft()?;
        // 绕开 nft 的 stdin 限制：删表重建，再按快照里的规则重加（保留原 panel-managed id）
        let _ = self.nft(&["delete", "table", "inet", TABLE], Duration::from_secs(10)).await;
        self.ensure_table().await?;
        let text = String::from_utf8_lossy(data);
        for r in parse_panel_rules(&text) {
            // 先取 id（借用 r.1），再整体把 r 交给 to_rule（按值消费），否则 move 后无法再用
            let id = panel_id(&r.1).unwrap_or_else(|| "restored".into());
            if let Some(rule) = to_rule(r) {
                let expr = render_rule(&rule, &id);
                let _ = self.nft(
                    &["add", "rule", "inet", TABLE, CHAIN, expr.as_str()],
                    Duration::from_secs(20),
                ).await;
            }
        }
        Ok(())
    }

    fn fail2ban_capability(&self) -> Capability {
        Capability::no("nftables 后端不接管 fail2ban")
    }

    async fn fail2ban_status(&self) -> Result<Fail2banStatus> {
        Ok(Fail2banStatus { available: false, active: false, jails: vec![] })
    }

    async fn fail2ban_set_jail(&self, _name: &str, _enabled: bool) -> Result<()> {
        Err(PanelError::Unsupported("nftables 后端不接管 fail2ban"))
    }

    async fn fail2ban_unban(&self, _jail: &str, _ip: &str) -> Result<()> {
        Err(PanelError::Unsupported("nftables 后端不接管 fail2ban"))
    }
}

// ═══════════════════════════ 纯函数：解析 / 渲染 ═══════════════════════════

/// 从 `nft -a list` 输出抽取面板自有规则：`(handle, comment, expr)`。
/// 只认带 `panel-managed` 标记者。行格式示例：
/// `tcp dport 22 accept comment "panel-managed p1 ssh" # handle 3`
fn parse_panel_rules(text: &str) -> Vec<(u32, String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // 真实编号在行尾 `# handle N`；用 rsplit_once 取最后一个（handle 必在末尾）
        let Some((rest, hstr)) = line.rsplit_once("# handle ") else { continue };
        let handle: u32 = match hstr.trim().split_whitespace().next().and_then(|s| s.parse().ok()) {
            Some(h) => h,
            None => continue,
        };
        let rest = rest.trim();
        // 抽 comment（首个 `"..."` 闭包内），剩余为规则表达式
        let (expr, comment) = match rest.split_once("comment \"") {
            Some((e, c)) => {
                let c = c.split('"').next().unwrap_or("").to_string();
                (e.trim().to_string(), c)
            }
            None => (rest.to_string(), String::new()),
        };
        if !comment.contains("panel-managed") {
            continue; // 绝不碰用户自建规则
        }
        out.push((handle, comment, expr));
    }
    out
}

/// 把 `(handle, comment, expr)` 转成 `FirewallRule`（过滤掉无法识别动作的规则）。
fn to_rule((handle, comment, expr): (u32, String, String)) -> Option<FirewallRule> {
    let id = panel_id(&comment).unwrap_or_else(|| format!("rule-{handle}"));
    let action = if expr.contains("reject") {
        Action::Reject
    } else if expr.contains("drop") {
        Action::Deny
    } else if expr.contains("accept") {
        Action::Allow
    } else {
        return None; // 无动作 → 不是面板管理的规则
    };
    let protocol = if expr.contains("udp") {
        Protocol::Udp
    } else if expr.contains("icmp") {
        Protocol::Icmp
    } else if expr.contains("tcp") {
        Protocol::Tcp
    } else {
        Protocol::Any
    };
    // 面板只管理 input 链
    let direction = Direction::Inbound;
    let ports = extract_ports(&expr).unwrap_or(PortSpec::All);
    let source_cidr = extract_source(&expr);
    Some(FirewallRule {
        id,
        ports,
        protocol,
        action,
        direction,
        source_cidr,
        comment: Some(comment),
        panel_managed: true,
    })
}

/// 从表达式抽取 `dport` 规格（支持单端口、范围 `a-b`、集合 `{a, b}`）。
fn extract_ports(expr: &str) -> Option<PortSpec> {
    let idx = expr.find("dport")?;
    let rest = expr[idx + 5..].trim_start();
    let spec: &str = if let Some(after) = rest.strip_prefix('{') {
        // 保留花括号，交给 `parse_spec` 统一解析集合（如 `{ 80, 443 }`）。
        // 若在此处剥掉花括号，parse_spec 收到 "80, 443" 会误判为单端口而回退 All。
        let close = after.find('}')?;
        rest[..close + 2].trim()
    } else {
        rest.split_whitespace().next()?
    };
    Some(parse_spec(spec))
}

/// 把单个 dport 规格串解析为 `PortSpec`。
fn parse_spec(spec: &str) -> PortSpec {
    if let Some(inner) = spec.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        let mut v = Vec::new();
        for part in inner.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            if let Some((a, b)) = p.split_once('-') {
                if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                    v.push(PortSpec::Range(a, b));
                }
            } else if let Ok(pn) = p.parse::<u16>() {
                v.push(PortSpec::Single(pn));
            }
        }
        if v.is_empty() {
            PortSpec::All
        } else {
            PortSpec::List(v)
        }
    } else if let Some((a, b)) = spec.split_once('-') {
        if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
            PortSpec::Range(a, b)
        } else {
            PortSpec::All
        }
    } else if let Ok(p) = spec.parse::<u16>() {
        PortSpec::Single(p)
    } else {
        PortSpec::All
    }
}

/// 从表达式抽取源 CIDR（或集合），原样保留（重渲染时回灌）。
fn extract_source(expr: &str) -> Option<String> {
    let idx = expr.find("saddr")?;
    let tok = expr[idx + 5..].trim_start().split_whitespace().next()?;
    Some(tok.to_string())
}

/// 把 `FirewallRule` 渲染成 nft 规则串（含 `panel-managed <id>` comment）。
fn render_rule(rule: &FirewallRule, id: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(cidr) = &rule.source_cidr {
        // 含 ':' 视为 IPv6，否则 IPv4
        if cidr.contains(':') {
            parts.push(format!("ip6 saddr {cidr}"));
        } else {
            parts.push(format!("ip saddr {cidr}"));
        }
    }
    let proto = match rule.protocol {
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::Tcp => "tcp",
        _ => "",
    };
    match &rule.ports {
        PortSpec::All => {
            if !proto.is_empty() {
                parts.push(proto.to_string());
            }
        }
        spec => {
            let p = render_spec(spec);
            if proto.is_empty() {
                // Any 协议 + 指定端口：nft 的 dport 必须依附传输层协议，兜底为 tcp
                parts.push(format!("tcp dport {p}"));
            } else {
                parts.push(format!("{proto} dport {p}"));
            }
        }
    }
    let action = match rule.action {
        Action::Deny => "drop",
        Action::Reject => "reject",
        _ => "accept",
    };
    parts.push(action.to_string());
    let user = sanitize_comment(rule.comment.as_deref().unwrap_or(""));
    parts.push(format!("comment \"panel-managed {id} {user}\""));
    parts.join(" ")
}

/// 把 `PortSpec` 渲染成 nft 的 dport 值。
fn render_spec(spec: &PortSpec) -> String {
    match spec {
        PortSpec::Single(x) => format!("{x}"),
        PortSpec::Range(a, b) => format!("{a}-{b}"),
        PortSpec::List(v) => {
            let inner: Vec<String> = v
                .iter()
                .map(|s| match s {
                    PortSpec::Single(x) => format!("{x}"),
                    PortSpec::Range(a, b) => format!("{a}-{b}"),
                    _ => String::new(),
                })
                .filter(|s| !s.is_empty())
                .collect();
            format!("{{ {} }}", inner.join(", "))
        }
        PortSpec::All => "all".to_string(),
    }
}

/// 清洗 comment：去掉会破坏 nft 引号的字符，限长。
fn sanitize_comment(s: &str) -> String {
    s.replace('"', "'")
        .replace('\n', " ")
        .replace('\r', " ")
        .chars()
        .take(200)
        .collect()
}

/// 从 comment 提取面板规则 id（`panel-managed <id> ...`）。
fn panel_id(comment: &str) -> Option<String> {
    let c = comment.strip_prefix("panel-managed")?.trim();
    let id = c.split_whitespace().next()?;
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

fn gen_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("p{:x}", nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 渲染 → 解析 必须往返一致（幂等性的基础，纯函数、无需 nft 二进制）。
    #[test]
    fn render_parse_roundtrip() {
        let cases = vec![
            FirewallRule {
                id: "p1".into(), ports: PortSpec::Single(22), protocol: Protocol::Tcp,
                action: Action::Allow, direction: Direction::Inbound, source_cidr: None,
                comment: Some("ssh".into()), panel_managed: true,
            },
            FirewallRule {
                id: "p2".into(), ports: PortSpec::Single(8080), protocol: Protocol::Tcp,
                action: Action::Deny, direction: Direction::Inbound,
                source_cidr: Some("10.0.0.0/8".into()), comment: Some("web".into()), panel_managed: true,
            },
            FirewallRule {
                id: "p3".into(), ports: PortSpec::List(vec![PortSpec::Single(80), PortSpec::Single(443)]),
                protocol: Protocol::Tcp, action: Action::Allow, direction: Direction::Inbound,
                source_cidr: None, comment: None, panel_managed: true,
            },
            FirewallRule {
                id: "p4".into(), ports: PortSpec::Range(8000, 8100), protocol: Protocol::Udp,
                action: Action::Reject, direction: Direction::Inbound,
                source_cidr: Some("192.168.1.5".into()), comment: Some("dns".into()), panel_managed: true,
            },
        ];
        for r in &cases {
            let expr = render_rule(r, &r.id);
            // 把渲染结果当成一个 nft 规则行，反解回 FirewallRule
            let parsed = to_rule((0u32, format!("panel-managed {} {}", r.id, r.comment.clone().unwrap_or_default()), expr.clone()));
            let p = parsed.expect("应能解析渲染结果");
            assert_eq!(p.ports, r.ports, "端口往返不一致: {expr}");
            assert_eq!(p.protocol, r.protocol, "协议往返不一致: {expr}");
            assert_eq!(p.action, r.action, "动作往返不一致: {expr}");
            assert_eq!(p.source_cidr, r.source_cidr, "源 CIDR 往返不一致: {expr}");
        }
    }

    /// 解析真实 `nft -a list` 片段，只认面板规则、忽略用户规则与链定义行。
    #[test]
    fn parse_real_nft_output() {
        const OUT: &str = "\
table inet panelfw {
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport 22 accept comment \"panel-managed p1 ssh\" # handle 3
        ip saddr 10.0.0.0/8 tcp dport 8080 drop comment \"panel-managed p2 web\" # handle 5
        tcp dport { 80, 443 } accept comment \"panel-managed p3\" # handle 7
    }
}
";
        let rules = parse_panel_rules(OUT);
        assert_eq!(rules.len(), 3, "链定义行与表头不得计入");
        assert_eq!(panel_id(&rules[0].1).as_deref(), Some("p1"));
        assert_eq!(rules[0].0, 3, "必须用 nft 自己的 handle 编号");
        let r2 = to_rule(rules[1].clone()).unwrap();
        assert_eq!(r2.action, Action::Deny);
        assert_eq!(r2.source_cidr.as_deref(), Some("10.0.0.0/8"));
        assert!(matches!(r2.ports, PortSpec::Single(8080)));
    }

    /// 只删面板自有规则：用户规则（无 panel-managed 标记）必须被忽略。
    #[test]
    fn only_panel_managed_rules_are_kept() {
        const OUT: &str = "\
table inet panelfw {
    chain input {
        tcp dport 22 accept comment \"my own ssh rule\" # handle 2
        tcp dport 8080 drop comment \"panel-managed p9\" # handle 4
    }
}
";
        let rules: Vec<_> = parse_panel_rules(OUT).into_iter().filter_map(to_rule).collect();
        assert_eq!(rules.len(), 1, "用户自建规则不得被当成面板规则");
        assert_eq!(rules[0].id, "p9");
    }

    #[test]
    fn panel_id_extraction() {
        assert_eq!(panel_id("panel-managed p1 ssh").as_deref(), Some("p1"));
        assert_eq!(panel_id("my own rule").as_deref(), None);
        assert_eq!(panel_id("").as_deref(), None);
    }

    /// 能力位不能撒谎：nft 缺失时后端必须报不支持。
    #[test]
    fn capability_is_honest() {
        // 本测试环境若无 nft 二进制，capability 必须 no；有则 yes。
        // 不假设二进制存在，只验证与 Bin::Nft.available() 一致。
        let fw = NftFirewall;
        assert_eq!(fw.capability().supported, Bin::Nft.available(),
                   "能力位必须与二进制实际可用性一致，否则前端会伪造成功");
    }
}
