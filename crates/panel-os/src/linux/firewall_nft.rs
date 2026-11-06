//! 防火墙的 **nftables 后端（真实 Linux 实现）**（设计方案 §2.7，M5 落地）。
//!
//! 与 ufw 后端同样严格落实三条硬约束：
//! 1. 改规则前无条件 `snapshot()`（路由 `apply` 已调用）；
//! 2. **只管理面板自己写的规则**：规则 comment 带 `panel-managed <id>` 标记，
//!    `delete_rule` / `apply` 的幂等比对都只认这些规则，绝不删用户既有规则；
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
//! - fail2ban 由独立服务管理，经共享实现 `fail2ban.rs` 接管：能力位只按
//!   `fail2ban-client` 二进制存在性判定，与本 nft 后端无因果关系（fail2ban 配
//!   nftables banaction 封禁时，fail2ban-client 照样能管理 jail 与解封）。

use crate::cmd::{Bin, CmdOpt};
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{Capability, FirewallBackend, PanelError, Result};
use std::path::PathBuf;
use std::time::Duration;

const TABLE: &str = "panelfw";
const CHAIN: &str = "input";

pub struct NftFirewall {
    /// 规则持久化文件：内容是 `nft list table` 的原样输出，可被 `nft -f` 直接重放。
    /// `None` = 不持久化（单测 / 无数据目录场景）。
    persist_path: Option<PathBuf>,
}

impl NftFirewall {
    pub fn new(persist_path: Option<PathBuf>) -> Self {
        Self { persist_path }
    }

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

    /// 把当前内核态规则落到 `persist_path`（`nft list table` 的输出本身就能被 `nft -f` 重放）。
    /// 表不存在（已停用）时删除文件——否则下次启动会把"已停用"恢复成启用。
    async fn persist(&self) -> Result<()> {
        let Some(path) = &self.persist_path else { return Ok(()) };
        let out = self.nft(&["list", "table", "inet", TABLE], Duration::from_secs(10)).await?;

        if out.code != Some(0) {
            match tokio::fs::remove_file(path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(PanelError::Internal(
                    format!("删除持久化文件 {} 失败: {e}", path.display()))),
            }
            return Ok(());
        }

        let Some(dir) = path.parent() else {
            return Err(PanelError::Internal(format!("持久化路径无父目录: {}", path.display())));
        };
        tokio::fs::create_dir_all(dir).await.map_err(|e| PanelError::Internal(
            format!("创建目录 {} 失败: {e}", dir.display())))?;

        // 先写临时文件再 rename：写到一半掉电不会留下半截脚本（半截 = 下次启动校验失败）
        let tmp = path.with_extension("nft.tmp");
        tokio::fs::write(&tmp, &out.stdout).await.map_err(|e| PanelError::Internal(
            format!("写入 {} 失败: {e}", tmp.display())))?;
        tokio::fs::rename(&tmp, path).await.map_err(|e| PanelError::Internal(
            format!("rename {} → {} 失败: {e}", tmp.display(), path.display())))?;
        Ok(())
    }

    /// 落盘失败不让主操作失败（规则已在内核生效），但必须留痕——绝不静默。
    async fn persist_warn(&self, op: &str) {
        if let Err(e) = self.persist().await {
            eprintln!("[warn] firewall {op}: 操作已生效，但规则持久化失败（重启后会丢失）: {e}");
        }
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
        // 启用后落盘（哪怕只是空表）、停用后删文件：否则下次启动会把"已停用"恢复成启用
        self.persist_warn("set_active").await;
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

        // 现状：只取面板自有规则，**仅用于幂等判定**。
        // ⚠ F-20：apply 是追加语义，绝不删既有规则；删除只走 delete_rule(id)。
        let existing: Vec<FirewallRule> = self.list_panel_handles().await?
            .into_iter().filter_map(to_rule).collect();

        // 与 ufw 后端共用同一份判据：只回答「要加哪几条」，不产出「要删什么」。
        let additions = plan_additions(&existing, &plan.rules);
        let unchanged = plan.rules.len() - additions.len();
        let mut added = 0;
        // apply 不再删除任何规则：removed 恒 0；失败也不吞成 warning（假成功）。
        let removed = 0;
        let mut warnings = Vec::new();

        for i in additions {
            let rule = &plan.rules[i];
            let id = gen_id();
            let expr = render_rule(rule, &id);
            let e = expr.as_str();
            if let Err(err) = self.nft_checked(
                &["add", "rule", "inet", TABLE, CHAIN, e],
                Duration::from_secs(20),
            ).await {
                return Err(PanelError::Command {
                    bin: "nft".into(),
                    detail: format!("add {} 失败: {}", rule.id, err),
                });
            }
            added += 1;
        }
        // 落盘失败不升级为 apply 失败（规则已在内核生效），但必须让前端看见
        if let Err(e) = self.persist().await {
            warnings.push(format!("规则已写入内核但持久化失败（重启后会丢失）: {e}"));
        }
        Ok(ApplyReport { added, removed, unchanged, warnings })
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
        self.persist_warn("delete_rule").await;
        Ok(())
    }

    async fn snapshot(&self) -> Result<Vec<u8>> {
        self.ensure_nft()?;
        let out = self.nft(&["-a", "list", "table", "inet", TABLE], Duration::from_secs(10)).await?;
        Ok(out.stdout.into_bytes())
    }

    async fn restore_snapshot(&self, data: &[u8]) -> Result<()> {
        self.ensure_nft()?;
        let text = String::from_utf8_lossy(data);

        // 空快照 = 当时表还不存在（首次 enable 之前的 apply 就会走到这里）。
        // 此时"恢复"的正确语义是让表回到不存在，而不是建一张空表：
        // 空表会让 is_active() 变成 true，等于失败回滚反而偷偷把防火墙启用了。
        if text.trim().is_empty() {
            let _ = self.nft(&["delete", "table", "inet", TABLE], Duration::from_secs(10)).await;
            self.persist_warn("restore_snapshot").await;
            return Ok(());
        }

        // 绕开 nft 的 stdin 限制：删表重建，再按快照里的规则重加（保留原 panel-managed id）
        let _ = self.nft(&["delete", "table", "inet", TABLE], Duration::from_secs(10)).await;
        self.ensure_table().await?;
        for r in parse_panel_rules(&text) {
            // 先取 id（借用 r.1），再整体把 r 交给 to_rule（按值消费），否则 move 后无法再用
            let id = panel_id(&r.1).unwrap_or_else(|| "restored".into());
            if let Some(rule) = to_rule(r) {
                let expr = render_rule(&rule, &id);
                // 回滚失败必须冒泡：以前这里用 `let _ =` 吞掉错误，回滚"假成功"会让上层
                // 以为规则已复原，实际停在半应用状态，连日志都没有一行。
                self.nft_checked(
                    &["add", "rule", "inet", TABLE, CHAIN, expr.as_str()],
                    Duration::from_secs(20),
                ).await.map_err(|e| PanelError::Command {
                    bin: "nft".into(),
                    detail: format!("回滚重放 {} 失败: {}", rule.id, e),
                })?;
            }
        }
        self.persist_warn("restore_snapshot").await;
        Ok(())
    }

    async fn restore_persisted(&self) -> Result<()> {
        let Some(path) = &self.persist_path else { return Ok(()) };
        self.ensure_nft()?;

        // 表已存在 = 本次开机后已经生效过（用户刚操作，或上一次恢复已装回）。
        // 此时用文件覆盖会抹掉现行状态，必须跳过。
        let out = self.nft(&["list", "table", "inet", TABLE], Duration::from_secs(10)).await?;
        if out.code == Some(0) {
            return Ok(());
        }

        let bytes = match tokio::fs::read(path).await {
            Ok(b) => b,
            // 从未启用过 → 没有文件，正常
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(PanelError::Internal(
                format!("读取持久化文件 {} 失败: {e}", path.display()))),
        };
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(());
        }
        let p = path.to_string_lossy().to_string();

        // 先 `-c` 干跑校验：坏文件（例如掉电截断）不能把内核表建成半残状态
        let check = self.nft(&["-c", "-f", &p], Duration::from_secs(20)).await?; // ci-allow-layering[2]: nft 的 -c 是 dry-run check 开关，不是 sh -c；argv 直传不经 shell
        if check.code != Some(0) {
            return Err(PanelError::Command {
                bin: "nft".into(),
                detail: format!("持久化文件 {} 校验失败: {}", path.display(), check.stderr.trim()),
            });
        }
        self.nft_checked(&["-f", &p], Duration::from_secs(20)).await.map_err(|e| {
            PanelError::Command {
                bin: "nft".into(),
                detail: format!("从 {} 恢复规则失败: {e}", path.display()),
            }
        })?;
        Ok(())
    }

    fn fail2ban_capability(&self) -> Capability {
        // fail2ban 与防火墙后端正交（fail2ban 配 nftables banaction 封禁时亦然），
        // 统一委托共享实现，按 fail2ban-client 二进制存在性诚实判定——不再武断判死。
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
        let handle: u32 = match hstr.split_whitespace().next().and_then(|s| s.parse().ok()) {
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
        // 存成"用户备注"而不是原始 comment：原始值里含 `panel-managed <id>` 前缀，
        // 下次 render_rule 会再拼一层标记（现场已出现
        // `panel-managed pA panel-managed pB` 的双层数据，每回滚/重放一次多一层）。
        // 读取侧的兼容由 `user_comment` 的循环剥前缀兜住，这里只保证新写入不再嵌套。
        comment: user_comment(Some(&comment)),
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
    let tok = expr[idx + 5..].split_whitespace().next()?;
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
        .replace(['\n', '\r'], " ")
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
        let fw = NftFirewall::new(None);
        assert_eq!(fw.capability().supported, Bin::Nft.available(),
                   "能力位必须与二进制实际可用性一致，否则前端会伪造成功");
    }

    /// nft 后端的 fail2ban 能力位必须与共享实现一致（按 fail2ban-client 存在性，
    /// 不得因后端是 nft 就被判死）。防未来有人回退成硬编码 `no`。
    #[test]
    fn fail2ban_capability_delegates_to_shared_impl() {
        let fw = NftFirewall::new(None);
        assert_eq!(
            fw.fail2ban_capability().supported,
            crate::linux::fail2ban::Fail2ban::capability().supported,
            "nft 后端的 fail2ban 能力位必须与共享实现一致，不得硬编码 no"
        );
    }

    /// 回滚重放不得让 comment 层层嵌套。
    /// 现场数据已出现 `panel-managed pA panel-managed pB ssh`：旧实现把整条 comment
    /// （含前缀）当用户备注回灌，重放一次多一层，最终撞上 sanitize_comment 的 200 字符截断。
    #[test]
    fn restore_replay_does_not_nest_panel_mark() {
        const OUT: &str = "\
table inet panelfw {
    chain input {
        tcp dport 22 accept comment \"panel-managed pNew panel-managed pOld ssh\" # handle 9
    }
}
";
        let r = parse_panel_rules(OUT).into_iter().next().expect("应解析出 1 条");
        let rule = to_rule(r).expect("应能转成 FirewallRule");
        assert_eq!(rule.comment.as_deref(), Some("ssh"), "读取侧必须剥掉全部面板标记");

        // 模拟 restore_snapshot：用新 id 重写同一条规则
        let expr = render_rule(&rule, "pNext");
        assert_eq!(expr.matches("panel-managed").count(), 1,
                   "重写后只允许一层标记，实际: {expr}");
        assert!(expr.contains("comment \"panel-managed pNext ssh\""),
                "用户备注必须原样保留: {expr}");
    }
}
