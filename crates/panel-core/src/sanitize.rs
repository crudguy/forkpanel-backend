//! 外部命令输出回显给 API 客户端前的脱敏**唯一收口**。
//!
//! 背景（production-readiness §3.3 P1）：`PanelError::Command` / `ConfigInvalid` 的
//! detail 会经两条路同时回到客户端——`Display` 把它拼进 `message`
//! （`command failed [{bin}]: {detail}`），`error.rs` 把它拼进 `detail.stderr` /
//! `detail.output`。而 nginx -t / certbot / curl 的 stderr 会携带：
//! - 面板校验临时目录（`panel-validate-<pid>-<n>`，泄露 `[paths].tmp` 布局且对客户端无用）；
//! - ACME 账户邮箱与账户目录 ID（certbot 注册/续期失败时）；
//! - 调用方自己才知道的敏感串（如 certbot `-m` 邮箱）。
//!
//! 因此脱敏必须发生在**构造侧**（本模块），而不是 API 边界：到 error.rs 时
//! message 早已拼好，只裁 detail 字段等于没裁（message 照漏）。
//!
//! 规则刻意保守，保留诊断价值（指令名、行号、真实配置路径原样保留）：
//! 1. `extra_secrets` 里每个非空串 → `<redacted>`（调用方最知道自己泄漏了什么）；
//! 2. 校验临时目录：`…panel-validate-<pid>-<n>` 连同路径前缀 → `<validate-workdir>`，
//!    其后缀（`conf/site.conf:12` 这类文件名+行号）保留——行号是排障关键；
//! 3. ACME 账户目录 ID：`…/accounts/<host>/directory/<id>` → id 段换成 `<acme-account>`；
//! 4. 邮箱形态 token → `<email>`；
//! 5. 限长 `max_len`，按 **char** 计而非字节——`&s[..n]` 截断多字节 UTF-8 会 panic
//!    （中文站名/路径进 stderr 时真会炸）。

/// 外部命令输出脱敏后的默认最大长度（按 char 计）。
pub const EXTERNAL_OUTPUT_MAX: usize = 1000;

/// 脱敏外部命令的 stderr/stdout 文本，供回显给 API 客户端。
/// `extra_secrets` 传调用方已知的敏感串（空串自动跳过）。
pub fn external_output(raw: &str, extra_secrets: &[&str], max_len: usize) -> String {
    let mut s = raw.trim().to_string();
    for sec in extra_secrets {
        if !sec.is_empty() {
            s = s.replace(sec, "<redacted>");
        }
    }
    let s = redact_validate_workdir(&s);
    let s = redact_acme_account_id(&s);
    let s = redact_emails(&s);
    truncate_chars(&s, max_len)
}

/// 常用形：trim + 无额外敏感串 + 默认限长。
/// 等价 `external_output(raw, &[], EXTERNAL_OUTPUT_MAX)`。
pub fn stderr(raw: &str) -> String {
    external_output(raw, &[], EXTERNAL_OUTPUT_MAX)
}

/// token 分隔符：空白 + 引号 + 尖括号 + 括号。路径里不会用这些字符做组件边界。
fn is_delim(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')')
}

/// 规则 2：`panel-validate-<digits>-<digits>` 连同其路径前缀 → `<validate-workdir>`。
/// 形状不符（如 `panel-validate-tmp`）原样保留——宁可漏脱敏也不误伤正常文本。
fn redact_validate_workdir(s: &str) -> String {
    const MARK: &str = "panel-validate-";
    let mut out = String::with_capacity(s.len());
    let mut copied = 0; // 已复制到 out 的字节位置
    let mut scan = 0;
    while let Some(rel) = s[scan..].find(MARK) {
        let m = scan + rel;
        // 目录名结尾：MARK + 数字 + '-' + 数字
        let after = &s[m + MARK.len()..];
        let d1 = after.bytes().take_while(u8::is_ascii_digit).count();
        let dir_end = if d1 > 0 && after[d1..].starts_with('-') {
            let t = &after[d1 + 1..];
            let d2 = t.bytes().take_while(u8::is_ascii_digit).count();
            if d2 > 0 { Some(m + MARK.len() + d1 + 1 + d2) } else { None }
        } else {
            None
        };
        match dir_end {
            Some(end) => {
                // 前缀：从 m 往回吃到上一个分隔符之后（覆盖 `/tmp/xxx/` 这段）
                let wstart = s[..m]
                    .rfind(is_delim)
                    .map(|i| i + 1) // 分隔符均为 ASCII，+1 是安全字符边界
                    .unwrap_or(0);
                if wstart < copied {
                    // 与上一处替换区间重叠（理论上不可能，防御），按不替换处理
                    scan = m + MARK.len();
                    continue;
                }
                out.push_str(&s[copied..wstart]);
                out.push_str("<validate-workdir>");
                copied = end;
                scan = end;
            }
            None => scan = m + MARK.len(),
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// 规则 3：certbot 账户路径 `…/accounts/<host>/directory/<id>` 的 id 段 → `<acme-account>`。
/// 必须同 token 内先出现 `accounts/` 才动手，避免误伤普通路径里的 `directory/`。
fn redact_acme_account_id(s: &str) -> String {
    const DIR: &str = "/directory/";
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut scan = 0;
    while let Some(rel) = s[scan..].find(DIR) {
        let m = scan + rel;
        let tok_start = s[..m].rfind(is_delim).map(|i| i + 1).unwrap_or(0);
        let id_start = m + DIR.len();
        let id_end = s[id_start..]
            .find(|c: char| c == '/' || is_delim(c))
            .map(|x| id_start + x)
            .unwrap_or(s.len());
        if s[tok_start..m].contains("accounts/") && id_end > id_start && tok_start >= copied {
            out.push_str(&s[copied..id_start]);
            out.push_str("<acme-account>");
            copied = id_end;
            scan = id_end;
        } else {
            scan = id_start;
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// 规则 4：邮箱形态 token（`local@domain.tld`，`@` 前非空、`@` 后含 `.`）→ `<email>`。
fn redact_emails(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            // token 边界：往两边吃到分隔符
            let tstart = s[..i].rfind(is_delim).map(|x| x + 1).unwrap_or(0);
            let tend = s[i..].find(is_delim).map(|x| i + x).unwrap_or(s.len());
            let local = &s[tstart..i];
            let domain = &s[i + 1..tend];
            if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && tstart >= copied {
                out.push_str(&s[copied..tstart]);
                out.push_str("<email>");
                copied = tend;
                i = tend;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[copied..]);
    out
}

/// 按 char 截断（多字节 UTF-8 安全），超长追加省略标记。
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max).collect();
        format!("{kept}…(truncated)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_plain_nginx_diagnostic_untouched() {
        // 真实配置路径 + 指令名 + 行号是排障关键，必须原样保留
        let raw = "nginx: [emerg] unknown directive \"gzip_static\" in /etc/nginx/sites-enabled/a.conf:3";
        let got = external_output(raw, &[], EXTERNAL_OUTPUT_MAX);
        assert_eq!(got, raw, "无敏感内容的诊断输出不得被改写");
    }

    #[test]
    fn redacts_validate_workdir_but_keeps_file_and_line() {
        let raw = "nginx: [emerg] unknown directive \"foo\" in /var/tmp/x/panel-validate-4242-7/conf/site.conf:12";
        let got = external_output(raw, &[], EXTERNAL_OUTPUT_MAX);
        assert!(!got.contains("4242"), "临时目录 pid 必须脱敏：{got}");
        assert!(!got.contains("/var/tmp/x"), "tmp 布局不得外泄：{got}");
        assert!(
            got.contains("<validate-workdir>/conf/site.conf:12"),
            "文件名+行号是排障关键，必须保留：{got}"
        );
    }

    #[test]
    fn redacts_workdir_without_prefix_too() {
        // caddy validate 相对路径形态
        let got = external_output("panel-validate-1-2/Caddyfile:3: unrecognized", &[], EXTERNAL_OUTPUT_MAX);
        assert!(got.starts_with("<validate-workdir>/Caddyfile:3"), "{got}");
    }

    #[test]
    fn malformed_workdir_name_is_left_alone() {
        // 形状不符宁可漏脱敏也不误伤
        let raw = "panel-validate-tmp/conf/site.conf";
        assert_eq!(external_output(raw, &[], EXTERNAL_OUTPUT_MAX), raw);
    }

    #[test]
    fn redacts_acme_account_id() {
        let raw = "See /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/9f8abc7d/regr.json";
        let got = external_output(raw, &[], EXTERNAL_OUTPUT_MAX);
        assert!(!got.contains("9f8abc7d"), "ACME 账户 ID 必须脱敏：{got}");
        assert!(got.contains("/directory/<acme-account>/regr.json"), "{got}");
    }

    #[test]
    fn plain_directory_path_is_not_misread_as_acme() {
        let raw = "open() \"/srv/www/directory/index.html\" failed";
        assert_eq!(external_output(raw, &[], EXTERNAL_OUTPUT_MAX), raw);
    }

    #[test]
    fn redacts_email_tokens() {
        let raw = "Account registered: admin@example.com\nSending email to ops@corp.cn.";
        let got = external_output(raw, &[], EXTERNAL_OUTPUT_MAX);
        assert!(!got.contains("admin@example.com"), "{got}");
        assert!(got.contains("<email>"), "{got}");
    }

    #[test]
    fn at_sign_without_domain_dot_is_not_an_email() {
        // nginx 里 `user@backend`（无域名点）不算邮箱，别误伤
        let raw = "proxy_pass http://user@backend";
        assert_eq!(external_output(raw, &[], EXTERNAL_OUTPUT_MAX), raw);
    }

    #[test]
    fn extra_secrets_are_redacted_first() {
        let got = external_output(
            "certbot -m boss@corp.cn failed, see boss@corp.cn account",
            &["boss@corp.cn"],
            EXTERNAL_OUTPUT_MAX,
        );
        assert!(!got.contains("boss@corp.cn"), "{got}");
        assert!(got.contains("<redacted>"), "{got}");
    }

    #[test]
    fn empty_secret_is_skipped() {
        // 空串 secret 若不过滤会把全文炸成 <redacted>
        let raw = "anything";
        assert_eq!(external_output(raw, &[""], EXTERNAL_OUTPUT_MAX), raw);
    }

    #[test]
    fn truncation_counts_chars_not_bytes() {
        // 多字节 UTF-8（中文站名）按字节切会 panic / 截出乱码
        let raw = "错误".repeat(600); // 1200 char，2400 字节
        let got = external_output(&raw, &[], 1000);
        assert!(got.ends_with("…(truncated)"), "{got}");
        assert_eq!(got.chars().count(), 1000 + "…(truncated)".chars().count());
    }
}
