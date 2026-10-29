//! 公网暴露参数的校验规则（**唯一事实源**）。
//!
//! 为什么单独成模块：同一条规则有三个消费者——CLI 的 `panel expose`、面板内的
//! Web 向导（`POST /api/v1/system/expose/apply`）、以及 `deploy/expose-public.sh`
//! 脚本自身。此前 Rust 侧只写在 `panel-cli/src/main.rs` 里，前端向导要用就得再抄
//! 一份；两份校验迟早漂移出一个放行、另一个拒绝的诡异 bug（用户填对了却被拒，
//! 或填错了被放进脚本）。故把规则收敛到 panel-core（纯字符串逻辑，无 IO），
//! CLI 与后端 handler 共用，脚本侧仍保留同名校验做纵深防御。
//!
//! 与脚本 `validate_domain` / `validate_cidr` 的口径必须保持一致——改这里请同步
//! 改 `deploy/expose-public.sh`，否则两端会给出互相矛盾的结论。

/// 域名校验：至少两级、每段只允许字母数字连字符、段首段尾不能是连字符、
/// 顶级域不得含数字（这条挡住 `1.2.3.4` 被当域名使）。
///
/// 返回 `Err(原因)` 时原因可直接展示给用户（中文、说明"错在哪"）。
pub fn validate_domain(d: &str) -> std::result::Result<(), String> {
    if d.is_empty() || d.len() > 253 {
        return Err("域名不能为空且长度不超过 253".into());
    }
    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() < 2 {
        return Err("域名至少需要两级（如 example.com）".into());
    }
    let tld = parts[parts.len() - 1];
    for p in &parts {
        if p.is_empty() {
            return Err("存在空段".into());
        }
        if !p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("段 {p:?} 只能含字母数字连字符"));
        }
        if p.starts_with('-') || p.ends_with('-') {
            return Err(format!("段 {p:?} 首尾不能是连字符"));
        }
    }
    if tld.chars().any(|c| c.is_ascii_digit()) {
        return Err("顶级域不能含数字（会把 IP 当域名）".into());
    }
    Ok(())
}

/// CIDR 校验：本版只认 IPv4；掩码 0（0.0.0.0/0）**单独挡下**——形式上"给了 allow"
/// 实质上等于不设限制，正是 fail-closed 要防的那扇门。省略掩码时按 /32 处理。
///
/// 收窄到与 RFC 4632 一致的两点（CLI / Web 向导 / 脚本三端共用本函数，故只在此一处收紧）：
/// - **前导零**八位组与掩码（如 `192.168.001.1` / `192.168.1.1/024`）必须拒绝——
///   它们在不同解析器里口径不一，且毫无必要；放行只会引入"同一条 CIDR 两端结论不同"的隐患。
/// - **主机位必须全 0**（`203.0.113.5/24` 这类非法的"网络地址之外还写主机位"）——否则
///   nginx 的 `allow` 只覆盖一个地址却伪装成网段，用户以为白名单是整段、实则只有一台。
pub fn validate_cidr(c: &str) -> std::result::Result<(), String> {
    if c.contains(':') {
        return Err("IPv6 暂不支持（请在生成的 nginx 配置里自行加 allow）".into());
    }
    let (ip, mask_str) = match c.split_once('/') {
        Some((ip, m)) => (ip, m),
        None => (c, "32"),
    };
    if mask_str.is_empty() || !mask_str.chars().all(|x| x.is_ascii_digit()) {
        return Err("掩码必须是数字".into());
    }
    if mask_str.len() > 1 && mask_str.starts_with('0') {
        return Err("掩码不能有前导零（如 /024）".into());
    }
    let mask: u32 = mask_str.parse().map_err(|_| "掩码解析失败".to_string())?;
    if mask > 32 {
        return Err("掩码超过 32".into());
    }
    if mask == 0 {
        return Err("掩码 0（0.0.0.0/0）等于不设限制，被拒绝".into());
    }
    if ip.len() > 15 {
        return Err("IP 长度异常".into());
    }
    let oct: Vec<&str> = ip.split('.').collect();
    if oct.len() != 4 {
        return Err("IPv4 必须四段".into());
    }
    let mut ip32: u32 = 0;
    for n in &oct {
        if n.is_empty() || !n.chars().all(|x| x.is_ascii_digit()) {
            return Err(format!("段 {n:?} 非法"));
        }
        if n.len() > 1 && n.starts_with('0') {
            return Err(format!("段 {n:?} 不能有前导零"));
        }
        let v: u32 = n.parse().map_err(|_| format!("段 {n:?} 解析失败"))?;
        if v > 255 {
            return Err(format!("段 {n:?} 超过 255"));
        }
        ip32 = (ip32 << 8) | v;
    }
    // 主机位必须全 0（mask == 32 时无主机位，跳过）。
    if mask < 32 {
        let host_bits = (!0u32) >> mask; // 低 (32 - mask) 位为 1
        if ip32 & host_bits != 0 {
            return Err(format!("网络地址 {ip}/{mask} 的主机位必须全为 0"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 正向 + 反向成对断言：只测"好的能过"会漏掉"坏的也放行"。
    #[test]
    fn domain_accepts_valid_and_rejects_invalid() {
        for ok in ["example.com", "panel.example.com", "a-b.example.org", "x.io"] {
            assert!(validate_domain(ok).is_ok(), "{ok} 应通过");
        }
        for (bad, why) in [
            ("", "空"),
            ("localhost", "单级"),
            ("1.2.3.4", "IP 冒充域名"),
            ("exa mple.com", "空格"),
            ("-bad.com", "段首连字符"),
            ("bad-.com", "段尾连字符"),
            ("bad..com", "空段"),
        ] {
            assert!(validate_domain(bad).is_err(), "{bad}（{why}）应被拒");
        }
    }

    /// 掩码 0 是这道门的核心：`0.0.0.0/0` 与裸写 `0.0.0.0/0` 都必须被拒。
    #[test]
    fn cidr_rejects_open_and_ipv6() {
        for ok in ["1.2.3.4/32", "10.0.0.0/8", "192.168.1.0/24", "1.2.3.4"] {
            assert!(validate_cidr(ok).is_ok(), "{ok} 应通过");
        }
        for (bad, why) in [
            ("0.0.0.0/0", "开放全网"),
            ("1.2.3.4/0", "掩码 0"),
            ("::1/128", "IPv6"),
            ("1.2.3/24", "三段"),
            ("1.2.3.256/32", "超 255"),
            ("1.2.3.4/33", "掩码超 32"),
            ("1.2.3.4/abc", "掩码非数字"),
            ("192.168.001.1/24", "前导零八位组"),
            ("1.02.3.4/24", "前导零八位组"),
            ("192.168.1.1/024", "前导零掩码"),
            ("203.0.113.5/24", "主机位非 0"),
            ("10.0.0.1/8", "主机位非 0"),
        ] {
            assert!(validate_cidr(bad).is_err(), "{bad}（{why}）应被拒");
        }
    }

    /// 前导零与主机位非 0 的收紧：合法写法（网络地址、主机位全 0）仍必须通过。
    #[test]
    fn cidr_rejects_leading_zero_and_host_bits() {
        for ok in [
            "1.2.3.4/32",
            "10.0.0.0/8",
            "192.168.1.0/24",
            "203.0.113.0/24",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ] {
            assert!(validate_cidr(ok).is_ok(), "{ok} 应通过");
        }
        for (bad, why) in [
            ("192.168.001.1/24", "前导零八位组"),
            ("1.02.3.4/24", "前导零八位组"),
            ("192.168.1.1/024", "前导零掩码"),
            ("203.0.113.5/24", "主机位非 0"),
            ("10.0.0.1/8", "主机位非 0"),
            ("172.16.5.0/12", "主机位非 0"),
        ] {
            assert!(validate_cidr(bad).is_err(), "{bad}（{why}）应被拒");
        }
    }
}
