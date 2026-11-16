//! 公网出口 IP 的解析与归一化（**唯一校验入口**）。
//!
//! 消费者：`panel init` 探测写入、`validate_implemented` 校验手写值、
//! Web 端「核准 IP」（POST /system/public-ip）探测回读——三处共用本函数，
//! 任何一处的判据改动都在这里生效，不会漂移成两份语义。

/// 解析并归一化公网 IP 文本：只接受 IPv4/IPv6 字面量。回显服务的输出偶尔
/// 带杂质（多余空行、HTML 错误页），宁可判定失败不写配置，也不把垃圾落盘。
/// 纯函数，无网络调用；探测本体在 [`panel_os::publicip`]（子进程唯一出口侧）。
pub fn parse_public_ip(s: &str) -> Option<std::net::IpAddr> {
    let s = s.trim();
    if s.is_empty() || s.chars().any(|c| c.is_whitespace()) { return None; }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_ip_literals() {
        assert_eq!(parse_public_ip("203.0.113.7"), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(parse_public_ip(" 2001:db8::1\n"), Some("2001:db8::1".parse().unwrap()),
            "首尾空白允许（curl 输出常带换行）");
        assert_eq!(parse_public_ip(""), None, "空输出不算探测成功");
        assert_eq!(parse_public_ip("1.2.3.4 x"), None, "内嵌杂质必须整体拒绝");
        assert_eq!(parse_public_ip("1.2.3.4/24"), None, "带掩码不是纯 IP");
        assert_eq!(parse_public_ip("999.1.1.1"), None, "越界段不是合法 IP");
        assert_eq!(parse_public_ip("<html>oops</html>"), None, "回显服务故障页必须拒绝");
    }
}
