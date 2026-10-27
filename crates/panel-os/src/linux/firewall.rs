//! 防火墙的 **真实 Linux 实现（仅 ufw 后端）**（设计方案 §2.7，M5 落地）。
//!
//! ⚠️ 这是全项目最高风险模块。三条硬约束在此严格落实：
//! 1. 改规则前无条件 `snapshot()`（路由 `apply` 已调用）；
//! 2. **只管理面板自己写的规则**：规则 comment 带 `panel-managed <id>` 标记，
//!    `delete_rule` / `apply(replace_panel_managed_only)` 都只碰这些规则，绝不删用户既有规则；
//! 3. SSH(22) 端口保护在路由层（`locks_out_ssh` + `allow_lockout_risk`）拦截。
//!
//! 非 ufw 后端（nftables/iptables/firewalld/none）一律 `Unsupported`——
//! 不在未验证的后端上伪装成功。本实现要求 `ufw` 命令存在且为激活后端。

use crate::cmd::{Bin, CmdOpt};
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{Capability, FirewallBackend, PanelError, Result};
use std::time::Duration;

pub struct LinuxFirewall { backend: FirewallBackend }

impl LinuxFirewall {
    pub fn detect() -> Self {
        // ⚠️ ufw **优先**：本实现只支持 ufw。若按"命令是否存在"排序，
        // 在同时装有 nft/iptables 的机器上会选中一个用不了的后端，
        // 明明装了 ufw 却报不可用。
        let backend = if which("ufw") { FirewallBackend::Ufw }
            else if which("nft") { FirewallBackend::Nftables }
            else if which("iptables") { FirewallBackend::Iptables }
            else if which("firewall-cmd") { FirewallBackend::Firewalld }
            else { FirewallBackend::None };
        Self { backend }
    }

    async fn ufw(&self, args: &[&str], timeout: Duration) -> Result<crate::cmd::CmdOutput> {
        crate::cmd::run(Bin::Ufw, args, CmdOpt { timeout, ..Default::default() }).await
    }

    fn ensure_ufw(&self) -> Result<()> {
        if self.backend != FirewallBackend::Ufw {
            return Err(PanelError::Unsupported("firewall: 仅 ufw 后端支持，当前后端不可用"));
        }
        Ok(())
    }
}

/// 安全 PATH 内查找二进制是否**可执行**。
///
/// 与 `stub::which` 走同一判据（`cmd::is_executable_file`）：普通文件 + 有执行位。
/// 原先这里自己拼了一份 `is_file()` 检查，与 `stub` 那份逐字重复——两处一旦
/// 漂移，就会出现「防火墙认 nft 可用、容器不认」这类怪现象。
fn which(name: &str) -> bool {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"]
        .iter()
        .any(|d| crate::cmd::is_executable_file(&std::path::Path::new(d).join(name)))
}

/// 单条原始规则（来自 `ufw status numbered` 解析）
struct RawRule {
    /// `ufw status numbered` 给出的**真实编号**。
    /// ⚠️ 删除必须用它：过滤后的数组下标 ≠ ufw 编号（表头/表尾/v6 行都会被跳过），
    ///    用下标调 `ufw delete N` 会删掉**别的**规则。
    num: Option<u32>,
    to: String,
    action: String,     // ALLOW / DENY / REJECT
    dir: String,        // IN / OUT
    from: String,       // Anywhere 或 CIDR
    comment: Option<String>,
}

/// 解析 `ufw status [numbered]` 的规则行。
///
/// 兼容两种格式：`[ 1] 22/tcp ALLOW IN Anywhere # comment` 与无编号的 `22/tcp ALLOW IN Anywhere`。
/// 无法识别的行（表头、分割线、v6 行）一律跳过——正因为会跳过，**索引绝不能当编号用**。
fn parse_status(text: &str) -> Vec<RawRule> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // 剥离 `[ N]` 编号前缀
        let (num, rest) = match line.strip_prefix('[').and_then(|l| l.split_once(']')) {
            Some((n, r)) => (n.trim().parse::<u32>().ok(), r.trim()),
            None => (None, line),
        };
        // 拆 comment：'#' 之后是注释
        let (rule_part, comment) = match rest.split_once('#') {
            Some((r, c)) => (r.trim(), Some(c.trim().to_string())),
            None => (rest.trim(), None),
        };
        let t: Vec<&str> = rule_part.split_whitespace().collect();
        // 形如 `22/tcp  ALLOW IN  Anywhere` 至少 4 段
        if t.len() < 4 { continue; }
        let action = t[1];
        let dir = t[2];
        if !matches!(action, "ALLOW" | "DENY" | "REJECT") { continue; }
        if !matches!(dir, "IN" | "OUT") { continue; }
        out.push(RawRule {
            num,
            to: t[0].to_string(),
            action: action.to_string(),
            dir: dir.to_string(),
            from: t[3].to_string(),
            comment,
        });
    }
    out
}

/// 面板自有规则的编号，**逆序**返回（从大到小删除，避免删一条后编号整体前移）。
async fn panel_rule_numbers(fw: &LinuxFirewall) -> Result<Vec<u32>> {
    let out = fw.ufw(&["status", "numbered"], Duration::from_secs(10)).await?;
    let mut nums: Vec<u32> = parse_status(&out.stdout).into_iter()
        .filter(|r| r.comment.as_deref().map(|c| c.contains("panel-managed")).unwrap_or(false))
        .filter_map(|r| r.num)
        .collect();
    nums.sort_unstable_by(|a, b| b.cmp(a));
    Ok(nums)
}

/// 删除单条编号规则。`--force` 避免 ufw 在非交互下等待确认而挂住。
async fn delete_number(fw: &LinuxFirewall, n: u32) -> Result<()> {
    let num = n.to_string();
    let out = fw.ufw(&["--force", "delete", &num], Duration::from_secs(15)).await?;
    if out.code != Some(0) {
        return Err(PanelError::Command { bin: "ufw".into(), detail: out.stderr.trim().to_string() });
    }
    Ok(())
}

/// 从 comment 提取面板规则 id（`panel-managed <id> ...`）
fn panel_id(comment: &Option<String>) -> Option<String> {
    let c = comment.as_ref()?;
    let rest = c.strip_prefix("panel-managed")?.trim();
    let id = rest.split_whitespace().next()?;
    if id.is_empty() { None } else { Some(id.to_string()) }
}

/// 解析 `ufw status` 的 `To` 列（`<port>/<proto>`、`Anywhere`、`<a>:<b>/<proto>`）
/// → (端口规格, 协议)。协议是 `FirewallRule.protocol` 字段（PortSpec 本身不携带协议）。
fn parse_to(to: &str) -> (PortSpec, Protocol) {
    if to == "Anywhere" { return (PortSpec::All, Protocol::Any); }
    let (ports, proto) = match to.split_once('/') {
        Some((p, pr)) => (p, proto_from(pr)),
        None => (to, Protocol::Tcp),
    };
    if let Some((a, b)) = ports.split_once(':') {
        if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
            return (PortSpec::Range(a, b), proto);
        }
    }
    if let Ok(p) = ports.parse::<u16>() {
        (PortSpec::Single(p), proto)
    } else {
        (PortSpec::All, proto)
    }
}

fn proto_from(s: &str) -> Protocol {
    match s.to_ascii_lowercase().as_str() {
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "any" => Protocol::Any,
        _ => Protocol::Tcp,
    }
}

/// 把端口规格渲染成 ufw 可接受的参数片段（不含协议）。
/// ufw 接受逗号分隔的「端口 / 区间」混合，如 `80,443,8000:8100`，
/// 因此 List 直接递归拼接即可在单条规则内表达混合规格（此前被 silently 丢弃）。
fn port_to_arg(spec: &PortSpec) -> String {
    match spec {
        PortSpec::Single(x) => format!("{x}"),
        PortSpec::Range(a, b) => format!("{a}:{b}"),
        PortSpec::List(v) => v.iter().map(port_to_arg).collect::<Vec<_>>().join(","),
        PortSpec::All => "all".into(),
    }
}

fn action_from(s: &str) -> Action {
    match s {
        "DENY" => Action::Deny,
        "REJECT" => Action::Reject,
        _ => Action::Allow,
    }
}

fn gen_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("p{:x}", nanos)
}

#[async_trait]
impl FirewallProvider for LinuxFirewall {
    fn backend(&self) -> FirewallBackend { self.backend }

    fn capability(&self) -> Capability {
        match self.backend {
            // 只有 ufw 真能跑。其余后端报 no —— 否则前端显示"支持"，
            // 用户一点删除才收到 501，是典型的"能力位撒谎"。
            FirewallBackend::Ufw => Capability::yes("ufw"),
            FirewallBackend::None => Capability::no("binary_missing"),
            FirewallBackend::Nftables => Capability::no("仅支持 ufw，当前检测到 nftables"),
            FirewallBackend::Iptables => Capability::no("仅支持 ufw，当前检测到 iptables"),
            FirewallBackend::Firewalld => Capability::no("仅支持 ufw，当前检测到 firewalld"),
        }
    }

    async fn is_active(&self) -> Result<bool> {
        self.ensure_ufw()?;
        let out = self.ufw(&["status"], Duration::from_secs(10)).await?;
        Ok(out.stdout.lines().next().map(|l| l.to_ascii_lowercase().contains("active")).unwrap_or(false))
    }

    async fn set_active(&self, active: bool) -> Result<()> {
        self.ensure_ufw()?;
        let args: &[&str] = if active { &["--force", "enable"] } else { &["disable"] };
        let out = self.ufw(args, Duration::from_secs(20)).await?;
        if out.code != Some(0) {
            return Err(PanelError::Command { bin: "ufw".into(), detail: out.stderr.trim().to_string() });
        }
        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        self.ensure_ufw()?;
        // 必须用 numbered：删除要靠这里的编号，否则会删错规则
        let out = self.ufw(&["status", "numbered"], Duration::from_secs(10)).await?;
        let raw = parse_status(&out.stdout);
        Ok(raw.into_iter().enumerate().map(|(i, r)| {
            let id = panel_id(&r.comment)
                .unwrap_or_else(|| format!("rule-{}", r.num.unwrap_or(i as u32 + 1)));
            let panel_managed = r.comment.as_deref().map(|c| c.contains("panel-managed")).unwrap_or(false);
            let (ports, proto) = parse_to(&r.to);
            FirewallRule {
                id,
                ports,
                protocol: proto,
                action: action_from(&r.action),
                direction: if r.dir == "OUT" { Direction::Outbound } else { Direction::Inbound },
                source_cidr: if r.from == "Anywhere" { None } else { Some(r.from) },
                comment: r.comment,
                panel_managed,
            }
        }).collect())
    }

    async fn apply(&self, plan: RulePlan) -> Result<ApplyReport> {
        self.ensure_ufw()?;
        // 现状：只取面板自有规则（带 ufw 真实编号），用于幂等判定与过期清理。
        // ⚠ 只认带 `panel-managed` 标记的规则，绝不碰用户既有规则。
        let existing = panel_rules_with_nums(self).await?;

        let mut added = 0;
        let mut removed = 0;
        let mut unchanged = 0;
        // 注：apply 不再吞失败为假成功，故不再累积 warnings；保留空 Vec 以保持 ApplyReport 结构稳定。
        let warnings = Vec::new();

        // 1) 过期清理：现有面板规则若已不在期望计划中（或内容变化），逆序删
        //    （从大到小删，避免删一条后编号整体前移误删别的规则）。
        let mut stale: Vec<u32> = existing.iter()
            .filter(|(_, e)| !plan.rules.iter().any(|d| rule_eq(e, d)))
            .map(|(n, _)| *n)
            .collect();
        stale.sort_unstable_by(|a, b| b.cmp(a));
        for n in stale {
            if delete_number(self, n).await.is_ok() { removed += 1; }
        }

        // 2) 新增/更新：已存在且功能一致的跳过（幂等，计数 unchanged），其余写入。
        for rule in &plan.rules {
            if existing.iter().any(|(_, e)| rule_eq(e, rule)) {
                unchanged += 1;
                continue;
            }
            let id = gen_id();
            let comment = format!("panel-managed {} {}",
                id, rule.comment.clone().unwrap_or_default().trim());
            let mut args: Vec<String> = Vec::new();
            args.push(match rule.action { Action::Deny => "deny", Action::Reject => "reject", _ => "allow" }.into());
            let port = port_to_arg(&rule.ports);
            match &rule.ports {
                PortSpec::All => args.push("in".into()),
                _ => args.push(format!("{port}/{}", proto_str(rule.protocol))),
            }
            if let Some(src) = &rule.source_cidr {
                args.push("from".into());
                args.push(src.clone());
            }
            args.push("comment".into());
            args.push(comment);
            let sargs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let out = self.ufw(&sargs, Duration::from_secs(20)).await?;
            if out.code == Some(0) {
                added += 1;
            } else {
                // ufw 真实失败（最常见：非 root / 无 CAP_NET_ADMIN 报 Operation not permitted）。
                // 必须返回 Err 而非 "Ok + warning"——否则是假成功：上层以为规则已生效，
                // 也让一致性测试的"权限不足则 skip"分支永远到不了（此前 CI 恒红的根因）。
                // API 路由已对 Err 做回滚 + 返回错误（见 panel-api firewall.rs）。
                return Err(PanelError::Command {
                    bin: "ufw".into(),
                    detail: format!("add {} 失败: {}", rule.id, out.stderr.trim()),
                });
            }
        }

        Ok(ApplyReport { added, removed, unchanged, warnings })
    }

    async fn delete_rule(&self, id: &str) -> Result<()> {
        self.ensure_ufw()?;
        let out = self.ufw(&["status", "numbered"], Duration::from_secs(10)).await?;
        let target = parse_status(&out.stdout).into_iter()
            .find(|r| {
                // 两种 id 都要能匹配：面板标记里的真实 id，或按编号回退的 rule-N
                panel_id(&r.comment).as_deref() == Some(id)
                    || r.num.map(|n| format!("rule-{n}")).as_deref() == Some(id)
            })
            .ok_or_else(|| PanelError::NotFound(format!("firewall rule `{id}`")))?;

        // 三条硬约束之二：绝不删用户自己加的规则
        if !target.comment.as_deref().map(|c| c.contains("panel-managed")).unwrap_or(false) {
            return Err(PanelError::PermissionDenied("只允许删除面板自己创建的规则"));
        }

        let n = target.num
            .ok_or_else(|| PanelError::Internal("ufw 未返回规则编号，拒绝按猜测删除".into()))?;
        delete_number(self, n).await
    }

    async fn snapshot(&self) -> Result<Vec<u8>> {
        self.ensure_ufw()?;
        let out = self.ufw(&["status"], Duration::from_secs(10)).await?;
        Ok(out.stdout.into_bytes())
    }

    async fn restore_snapshot(&self, data: &[u8]) -> Result<()> {
        self.ensure_ufw()?;
        let text = String::from_utf8_lossy(data);
        let snap_rules: Vec<FirewallRule> = parse_status(&text).into_iter().filter_map(|r| {
            if !r.comment.as_deref().map(|c| c.contains("panel-managed")).unwrap_or(false) { return None; }
            let (ports, proto) = parse_to(&r.to);
            Some(FirewallRule {
                id: panel_id(&r.comment).unwrap_or_default(),
                ports,
                protocol: proto,
                action: action_from(&r.action),
                direction: if r.dir == "OUT" { Direction::Outbound } else { Direction::Inbound },
                source_cidr: if r.from == "Anywhere" { None } else { Some(r.from) },
                comment: r.comment,
                panel_managed: true,
            })
        }).collect();
        // 清掉当前面板自有规则，再按快照重建（同样按真实编号逆序删）
        if let Ok(nums) = panel_rule_numbers(self).await {
            for n in nums { let _ = delete_number(self, n).await; }
        }
        for rule in &snap_rules {
            let id = gen_id();
            let comment = format!("panel-managed {} {}", id,
                rule.comment.clone().unwrap_or_default().trim());
            let mut args: Vec<String> = vec![match rule.action { Action::Deny => "deny", Action::Reject => "reject", _ => "allow" }.into()];
            let port = port_to_arg(&rule.ports);
            match &rule.ports {
                PortSpec::All => args.push("in".into()),
                _ => args.push(format!("{port}/{}", proto_str(rule.protocol))),
            }
            if let Some(src) = &rule.source_cidr { args.push("from".into()); args.push(src.clone()); }
            args.push("comment".into());
            args.push(comment);
            let sargs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let _ = self.ufw(&sargs, Duration::from_secs(20)).await;
        }
        Ok(())
    }

    fn fail2ban_capability(&self) -> Capability {
        // fail2ban 与防火墙后端正交，统一委托共享实现（见 fail2ban.rs）。
        super::fail2ban::Fail2ban::capability()
    }

    async fn fail2ban_status(&self) -> Result<Fail2banStatus> {
        super::fail2ban::Fail2ban::status().await
    }

    async fn fail2ban_set_jail(&self, name: &str, enabled: bool) -> Result<()> {
        super::fail2ban::Fail2ban::set_jail(name, enabled).await
    }

    async fn fail2ban_unban(&self, jail: &str, ip: &str) -> Result<()> {
        super::fail2ban::Fail2ban::unban(jail, ip).await
    }
}

/// 列出当前**面板自有**规则及其 ufw 真实编号（幂等判定 / 过期清理用）。
/// 只认带 `panel-managed` 标记的规则，绝不碰用户既有规则。
/// 作为自由函数（同模块可访问 LinuxFirewall 的私有 `ufw`）以避免塞进 trait impl。
async fn panel_rules_with_nums(fw: &LinuxFirewall) -> Result<Vec<(u32, FirewallRule)>> {
    let out = fw.ufw(&["status", "numbered"], Duration::from_secs(10)).await?;
    let raw = parse_status(&out.stdout);
    let mut v = Vec::new();
    for r in raw {
        if !r.comment.as_deref().map(|c| c.contains("panel-managed")).unwrap_or(false) { continue; }
        let num = match r.num { Some(n) => n, None => continue };
        let id = panel_id(&r.comment).unwrap_or_else(|| format!("rule-{}", num));
        let (ports, proto) = parse_to(&r.to);
        v.push((num, FirewallRule {
            id,
            ports,
            protocol: proto,
            action: action_from(&r.action),
            direction: if r.dir == "OUT" { Direction::Outbound } else { Direction::Inbound },
            source_cidr: if r.from == "Anywhere" { None } else { Some(r.from) },
            comment: r.comment,
            panel_managed: true,
        }));
    }
    Ok(v)
}

fn proto_str(p: Protocol) -> &'static str {
    match p { Protocol::Udp => "udp", Protocol::Icmp => "icmp", Protocol::Any => "any", _ => "tcp" }
}

/// 两条规则「功能上是否一致」：比较端口 / 协议 / 动作 / 方向 / 来源，
/// 忽略内部随机 id 与注释（这些都随每次写入变化，不代表规则语义变化）。
/// 用于 apply 的幂等判定——同一份期望计划二次 apply 时，已存在的规则应被识别为 unchanged。
fn rule_eq(e: &FirewallRule, d: &FirewallRule) -> bool {
    e.ports == d.ports
        && e.protocol == d.protocol
        && e.action == d.action
        && e.direction == d.direction
        && e.source_cidr == d.source_cidr
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ufw status numbered` 的真实输出片段（含表头、分割线、v6 行、comment）
    const SAMPLE: &str = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 3] 8080/tcp                   ALLOW IN    Anywhere                   # panel-managed p1 web
[ 4] 9000:9100/tcp              ALLOW IN    10.0.0.0/8                 # panel-managed p2
";

    /// 回归测试：删除曾误用**过滤后的数组下标**当 ufw 编号。
    /// 表头/v6 行被跳过，下标与编号就此错位 —— `ufw delete N` 会删掉别的规则。
    #[test]
    fn numbers_come_from_ufw_not_from_row_index() {
        let raw = parse_status(SAMPLE);
        assert_eq!(raw.len(), 3, "表头、分割线、v6 行都应被跳过");
        assert_eq!(raw[0].num, Some(1));
        assert_eq!(raw[1].num, Some(3), "必须是 ufw 自己的编号 3，不是下标 1");
        assert_eq!(raw[2].num, Some(4), "必须是 ufw 自己的编号 4，不是下标 2");
    }

    #[test]
    fn unnumbered_status_still_parses() {
        let raw = parse_status("80/tcp ALLOW IN Anywhere\n443/udp ALLOW IN Anywhere\n");
        assert_eq!(raw.len(), 2);
        assert!(raw.iter().all(|r| r.num.is_none()), "无编号格式不应凭空造编号");
    }

    #[test]
    fn panel_id_extracts_rule_id() {
        assert_eq!(panel_id(&Some("panel-managed p1 web".into())).as_deref(), Some("p1"));
        assert_eq!(panel_id(&Some("panel-managed p2".into())).as_deref(), Some("p2"));
        // 用户自建规则没有面板 id
        assert_eq!(panel_id(&Some("my own rule".into())), None);
        assert_eq!(panel_id(&None), None);
    }

    #[test]
    fn panel_rules_are_identified_by_mark() {
        let raw = parse_status(SAMPLE);
        let managed: Vec<u32> = raw.iter()
            .filter(|r| r.comment.as_deref().map(|c| c.contains("panel-managed")).unwrap_or(false))
            .filter_map(|r| r.num).collect();
        // 只认带标记的两条，绝不碰第 1 条（用户自己的 SSH 放行规则）
        assert_eq!(managed, vec![3, 4]);
    }

    #[test]
    fn port_and_proto_parsing() {
        assert!(matches!(parse_to("22/tcp").0, PortSpec::Single(22)));
        assert!(matches!(parse_to("22/tcp").1, Protocol::Tcp));
        assert!(matches!(parse_to("9000:9100/tcp").0, PortSpec::Range(9000, 9100)));
        assert!(matches!(parse_to("53/udp").1, Protocol::Udp));
        assert!(matches!(parse_to("Anywhere").0, PortSpec::All));
    }

    /// 能力位不能撒谎：只支持 ufw，其余后端必须报不支持，
    /// 否则前端显示"可用"、用户一点就收到 501。
    #[test]
    fn capability_is_honest_about_unsupported_backends() {
        assert!(LinuxFirewall { backend: FirewallBackend::Ufw }.capability().supported);
        for b in [FirewallBackend::Nftables, FirewallBackend::Iptables,
                  FirewallBackend::Firewalld, FirewallBackend::None] {
            assert!(!LinuxFirewall { backend: b }.capability().supported,
                    "{b:?} 不应报为支持");
        }
    }
}
