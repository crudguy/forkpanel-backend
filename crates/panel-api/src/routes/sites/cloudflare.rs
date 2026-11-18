//! Cloudflare DNS API 客户端（P2-10：ACME dns-01）。
//!
//! # 为什么 dns-01 必须有这个东西
//! http-01 证明「你能控制这个站点的 HTTP 响应」，dns-01 证明「你能控制这个域名的
//! DNS」。后者的证明手段只有一个：在 `_acme-challenge.<域名>` 写一条 CA 指定的
//! TXT 记录。**没有厂商无关的写入通道**——必须拿到具体 DNS 服务商的 API 凭据。
//! 所以本模块不是"顺手多接一个 API"，而是 dns-01 得以存在的前提。
//!
//! # 安全边界（这个模块能改用户的 DNS，必须自己收紧）
//! 1. **只写 TXT 记录**，且记录名**必须**以 `_acme-challenge.` 开头或等于
//!    `_acme-challenge`。凭据被滥用时，能改的东西被钉死在这一个前缀里——
//!    改不了 A 记录（劫持流量）、改不了 MX（拦邮件）、删不了别人的记录。
//! 2. **只删本模块创建的记录**（按 id 删，不按名字批量删）。按名字删会在
//!    用户自己也有同名 TXT 时误删——那不是我们能碰的数据。
//! 3. **不跟随重定向**：否则一个被投毒的响应可以把请求导向任意主机。
//! 4. 凭据**只出现在 Authorization 头**，不进 URL、不进日志、不进错误文案。
//!
//! # 为什么不用 certbot 的 dns-cloudflare 插件
//! 插件要求把凭据写进一个 ini 文件再传给 certbot（`--dns-cloudflare-credentials`）。
//! 那等于**把明文凭据落到磁盘上**，与「凭据密文入库、明文不落盘」的既有纪律冲突，
//! 且事后清理容易漏（certbot 失败时留下的临时文件、备份、日志）。
//! 自己实现 `--manual` 的 auth/cleanup 钩子反而更安全：凭据从内存直传给 HTTP 请求，
//! 全程不落盘。代价是要自己维护这两个 hook 脚本（见 [`render_hook_script`]）。

use panel_core::{PanelError, Result};
use serde_json::Value;

/// Cloudflare API 基址。**编译期常量**，不接受用户输入——
/// 否则凭据会被发往用户指定的任意主机（最典型的一类凭据外带）。
const CF_API: &str = "https://api.cloudflare.com/client/v4";

/// 单次请求超时。DNS 记录写入是交互式操作（用户正等着看结果），
/// 但比 LLM 探测宽松：Cloudflare 偶发慢响应。
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// ACME 挑战记录名的固定前缀（RFC 8555 §8.4）。
pub const ACME_PREFIX: &str = "_acme-challenge";

/// 凭据探测结果。用于"保存前先验证 token 能不能用"，
/// 避免用户存了一个已吊销的 token、等到签发时才报错。
#[derive(Debug, Clone, serde::Serialize)]
pub struct CfCheck {
    pub ok: bool,
    /// 该 token 可见的 zone 数量（0 = token 有效但没有任何 zone 权限，常见于漏配 Zone.Zone:Read）
    pub zone_count: usize,
    /// 前若干个 zone 名，便于用户确认自己接的是哪个账号
    pub zones: Vec<String>,
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        // 见模块文档第 3 条：跳转会把凭据带去任意主机
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| PanelError::Internal(format!("无法创建 HTTP 客户端：{e}")))
}

/// 把 reqwest 的传输层错误翻成用户能据以行动的话。
/// 不翻译的话用户只看到 `error sending request`，无从判断是 token 错还是网络不通。
fn transport_err(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        format!("请求 Cloudflare 超时（{}s 内无响应）", TIMEOUT.as_secs())
    } else if e.is_connect() {
        "无法连接 api.cloudflare.com：本机出网被阻断或 DNS 解析失败".to_string()
    } else if e.is_decode() {
        format!("Cloudflare 返回的不是 JSON：{e}")
    } else {
        format!("请求失败：{e}")
    }
}

/// 统一解析 Cloudflare 的响应信封 `{success, errors:[{code,message}], result}`。
///
/// ⚠ Cloudflare 的典型失败是 **HTTP 200 + `success:false`**（如 token 无效是
/// 400 但 zone 不存在是 404，而权限不足有时是 200）。只看状态码会把
/// "成功"误判成真，接着去读 `result` 拿到 null 才崩——报错信息就变成
/// "解析失败"而不是真正原因。所以这里**先看 success**。
fn parse_envelope(body: &Value, what: &str) -> Result<Value> {
    let ok = body.get("success").and_then(Value::as_bool).unwrap_or(false);
    if !ok {
        let mut msgs: Vec<String> = Vec::new();
        if let Some(arr) = body.get("errors").and_then(Value::as_array) {
            for e in arr {
                let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
                let msg = e.get("message").and_then(Value::as_str).unwrap_or("");
                if !msg.is_empty() {
                    msgs.push(format!("[{code}] {msg}"));
                }
            }
        }
        let detail = if msgs.is_empty() {
            "Cloudflare 返回 success=false 但未给出原因".to_string()
        } else {
            msgs.join("；")
        };
        return Err(PanelError::Validation {
            field: "dns",
            reason: format!("{what}失败：{detail}"),
        });
    }
    Ok(body.get("result").cloned().unwrap_or(Value::Null))
}

/// 校验 ACME 记录名。**这是本模块最重要的安全闸**。
///
/// 允许的形态只有两种：
/// - `_acme-challenge.<domain>`（常规签发）
/// - `_acme-challenge`（裸挑战名，极少数委托场景）
///
/// 拒绝的理由不只是"写错地方"，更是**权限收敛**：凭据一旦被误用/泄露，
/// 能改的目标被钉死在这个前缀，动不了 A / MX / NS 记录。
pub fn validate_record_name(name: &str) -> Result<()> {
    let n = name.trim().trim_end_matches('.');
    if n.is_empty() {
        return Err(PanelError::Validation {
            field: "record",
            reason: "记录名不能为空".into(),
        });
    }
    // 大小写不敏感：DNS 本身不区分大小写
    let lower = n.to_ascii_lowercase();
    let ok = lower == ACME_PREFIX
        || (lower.starts_with(ACME_PREFIX) && lower[ACME_PREFIX.len()..].starts_with('.'));
    if !ok {
        return Err(PanelError::Validation {
            field: "record",
            reason: format!(
                "拒绝写入 `{n}`：本功能只允许操作 `{ACME_PREFIX}.*` 下的 TXT 记录。\
                 限定前缀是为了把凭据的破坏面收敛到 ACME 挑战，动不了 A/MX/NS 等记录"
            ),
        });
    }
    Ok(())
}

/// 校验记录类型：只允许 TXT。
pub fn validate_record_type(ty: &str) -> Result<()> {
    if ty.eq_ignore_ascii_case("TXT") {
        Ok(())
    } else {
        Err(PanelError::Validation {
            field: "type",
            reason: format!("拒绝写入 {ty} 记录：本功能只写 TXT（ACME 挑战的唯一载体）"),
        })
    }
}

/// 用 token 列一次 zones，验证凭据是否可用。
pub async fn check_token(token: &str) -> Result<CfCheck> {
    let t = token.trim();
    if t.is_empty() {
        return Err(PanelError::Validation {
            field: "token",
            reason: "API Token 不能为空".into(),
        });
    }
    let c = client()?;
    let resp = c
        .get(format!("{CF_API}/zones?per_page=50"))
        .bearer_auth(t)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| PanelError::Command {
            bin: "cloudflare".into(),
            detail: transport_err(&e),
        })?;
    // token 本身要进脱敏白名单：Cloudflare 某些错误会把 token 片段回显
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let sanitized = |s: String| panel_core::sanitize::external_output(&s, &[t], 400);
    let result = match parse_envelope(&body, "校验 API Token ") {
        Ok(r) => r,
        Err(e) => {
            // 把 HTTP 状态码补进文案：单看 "Authentication error" 分不清是 401 还是 403
            let msg = sanitized(format!("{e}（HTTP {status}）"));
            return Err(PanelError::Validation {
                field: "token",
                reason: msg,
            });
        }
    };
    let arr = result.as_array().cloned().unwrap_or_default();
    let zones: Vec<String> = arr
        .iter()
        .filter_map(|z| z.get("name").and_then(Value::as_str).map(str::to_string))
        .take(5)
        .collect();
    Ok(CfCheck {
        ok: true,
        zone_count: arr.len(),
        zones,
    })
}

/// 从域名反查 zone 名。Cloudflare 的 zone 是"注册域 + 可选子域"，而 ACME 给的
/// 域名可能是 `a.b.example.com`，zone 却是 `example.com`。逐个后缀试探是通用做法。
///
/// 返回 `(zone_id, zone_name)`。
pub async fn find_zone(token: &str, domain: &str) -> Result<(String, String)> {
    let d = domain.trim().trim_end_matches('.');
    if d.is_empty() {
        return Err(PanelError::Validation {
            field: "domain",
            reason: "域名不能为空".into(),
        });
    }
    let c = client()?;
    let labels: Vec<&str> = d.split('.').collect();
    // 从最长的后缀开始试：a.b.example.com → a.b.example.com, b.example.com, example.com
    // 最少保留两段（example.com）——单段（com）不是任何人的 zone。
    for i in 0..labels.len().saturating_sub(1) {
        let candidate = labels[i..].join(".");
        let resp = c
            .get(format!("{CF_API}/zones?name={}", urlenc(&candidate)))
            .bearer_auth(token.trim())
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PanelError::Command {
                bin: "cloudflare".into(),
                detail: transport_err(&e),
            })?;
        let body: Value = resp.text().await.ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        let result = match parse_envelope(&body, "查询 zone ") {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        if let Some(first) = result.as_array().and_then(|a| a.first()) {
            let id = first.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            let name = first.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            if !id.is_empty() {
                return Ok((id, name));
            }
        }
    }
    Err(PanelError::Validation {
        field: "domain",
        reason: format!(
            "在 Cloudflare 账号下找不到 `{d}` 所属的 zone。\
             常见原因：① 该域名的 NS 还没指到 Cloudflare；② Token 少了 Zone:Read 权限"
        ),
    })
}

/// 创建 TXT 记录，返回记录 id（cleanup 时按 id 删）。
pub async fn create_txt(token: &str, zone_id: &str, name: &str, content: &str) -> Result<String> {
    validate_record_name(name)?;
    validate_record_type("TXT")?;
    if content.trim().is_empty() {
        return Err(PanelError::Validation {
            field: "content",
            reason: "TXT 内容不能为空".into(),
        });
    }
    let c = client()?;
    let payload = serde_json::json!({
        "type": "TXT",
        "name": name.trim().trim_end_matches('.'),
        "content": content,
        // ACME 校验要能立刻查到，不能等缓存过期
        "ttl": 60,
    });
    let resp = c
        .post(format!("{CF_API}/zones/{zone_id}/dns_records"))
        .bearer_auth(token.trim())
        .header("Accept", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| PanelError::Command {
            bin: "cloudflare".into(),
            detail: transport_err(&e),
        })?;
    let body: Value = resp.text().await.ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let result = parse_envelope(&body, "创建 TXT 记录 ")?;
    let id = result.get("id").and_then(Value::as_str).unwrap_or("").to_string();
    if id.is_empty() {
        return Err(PanelError::Validation {
            field: "dns",
            reason: "创建记录成功但未返回记录 id，无法在验证后清理".into(),
        });
    }
    Ok(id)
}

/// 删除**本模块创建的** TXT 记录（按 id）。
///
/// ⚠ 刻意不提供"按名字删全部"——用户自己可能也有同名 TXT（如多个 ACME 客户端
/// 并存时的历史记录），按名字删会误删不是我们创建的数据。
pub async fn delete_txt(token: &str, zone_id: &str, record_id: &str) -> Result<()> {
    if record_id.trim().is_empty() {
        return Err(PanelError::Validation {
            field: "record_id",
            reason: "记录 id 为空，拒绝删除（防误删整域）".into(),
        });
    }
    let c = client()?;
    let resp = c
        .delete(format!("{CF_API}/zones/{zone_id}/dns_records/{record_id}"))
        .bearer_auth(token.trim())
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| PanelError::Command {
            bin: "cloudflare".into(),
            detail: transport_err(&e),
        })?;
    let body: Value = resp.text().await.ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    // 清理失败不该让签发整体失败（证书可能已经签下来了）；由调用方决定是否忽略
    parse_envelope(&body, "删除 TXT 记录 ")?;
    Ok(())
}

/// 兜底清理：删掉 `_acme-challenge.<domain 所属 zone>` 下**形似 ACME 挑战**的
/// TXT 记录。
///
/// 判据只认「名字正好是该域的 _acme-challenge」+「内容形似 base64url 且长度接近
/// 43 字符」——用户自己放的验证 TXT（如 SPF/站点验证）名字不同、内容不同，不动。
/// 宁可漏删也不能误删：误删用户的 DNS 记录是不可挽回的破坏。
pub async fn cleanup_acme_records(token: &str, domain: &str) -> Result<usize> {
    let (zone_id, zone_name) = find_zone(token, domain).await?;
    let want = format!(
        "{}.{}",
        ACME_PREFIX,
        zone_name.trim_end_matches('.').to_ascii_lowercase()
    );
    let c = client()?;
    let resp = c
        .get(format!(
            "{CF_API}/zones/{zone_id}/dns_records?type=TXT&name={}",
            urlenc(&want)
        ))
        .bearer_auth(token.trim())
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| PanelError::Command {
            bin: "cloudflare".into(),
            detail: transport_err(&e),
        })?;
    let body: Value = resp.text().await.ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let result = parse_envelope(&body, "查询残留挑战记录 ")?;
    let mut n = 0usize;
    for rec in result.as_array().cloned().unwrap_or_default() {
        let name = rec.get("name").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
        let content = rec.get("content").and_then(Value::as_str).unwrap_or("");
        let id = rec.get("id").and_then(Value::as_str).unwrap_or("");
        if name != want || id.is_empty() {
            continue;
        }
        // ACME 的 dns-01 TXT 值是 32 字节 SHA-256 的 base64url（无填充）= 43 字符
        if !looks_like_acme_txt(content) {
            continue;
        }
        if delete_txt(token, &zone_id, id).await.is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

/// ACME dns-01 挑战值形态：base64url 字符集、无 `=` 填充、长度 43。
/// 放宽到 40..=50 以容忍不同 CA 的编码微差，但**不放宽字符集**——
/// 用户手写的说明性 TXT（含空格、中文、`v=spf1` 之类）一律不动。
fn looks_like_acme_txt(s: &str) -> bool {
    let t = s.trim();
    (40..=50).contains(&t.len())
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// 极简的 query 参数编码。只用于 zone 名（字母数字、点、连字符），
/// 但不做编码仍然不安全——域名里理论上可以有点号以外的东西。
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_name_accepts_acme_prefix() {
        assert!(validate_record_name("_acme-challenge.example.com").is_ok());
        assert!(validate_record_name("_acme-challenge.example.com.").is_ok());
        assert!(validate_record_name("_ACME-CHALLENGE.Example.COM").is_ok());
        assert!(validate_record_name("_acme-challenge").is_ok());
    }

    #[test]
    fn record_name_rejects_everything_else() {
        // 指向 apex / 子域 / 其它服务 —— 这些是"能改用户 DNS 就会造成实际伤害"的目标
        for bad in [
            "example.com",
            "www.example.com",
            "@",
            "",
            "   ",
            "_acme-challengeX.example.com", // 前缀像但分隔符不对
            "_dmarc.example.com",
            "mail.example.com",
        ] {
            assert!(
                validate_record_name(bad).is_err(),
                "应拒绝 `{bad}`，但它通过了——前缀闸失效等于凭据可改任意记录"
            );
        }
    }

    #[test]
    fn record_type_only_txt() {
        assert!(validate_record_type("TXT").is_ok());
        assert!(validate_record_type("txt").is_ok());
        for bad in ["A", "AAAA", "MX", "NS", "CNAME", ""] {
            assert!(validate_record_type(bad).is_err(), "应拒绝 {bad} 记录");
        }
    }

    #[test]
    fn envelope_success_false_is_error_even_on_http_200() {
        // Cloudflare 最典型的坑：HTTP 200 + success:false
        let body: Value = serde_json::from_str(
            r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"result":null}"#,
        )
        .unwrap();
        let e = parse_envelope(&body, "校验 ").unwrap_err();
        let s = format!("{e}");
        assert!(s.contains("9109"), "应带出 CF 的错误码，实际：{s}");
        assert!(s.contains("Invalid access token"), "应带出原因，实际：{s}");
    }

    #[test]
    fn envelope_success_true_returns_result() {
        let body: Value = serde_json::from_str(r#"{"success":true,"errors":[],"result":[{"id":"z1"}]}"#).unwrap();
        let r = parse_envelope(&body, "x").unwrap();
        assert_eq!(r[0]["id"], "z1");
    }

    #[test]
    fn envelope_missing_success_is_treated_as_failure() {
        // 非 JSON / 被中间设备改写的响应：宁可报错，也不把 null 当成功往下读
        let body: Value = serde_json::from_str(r#"{"result":null}"#).unwrap();
        assert!(parse_envelope(&body, "x").is_err());
    }

    #[test]
    fn urlenc_escapes_non_safe_bytes() {
        assert_eq!(urlenc("example.com"), "example.com");
        assert_eq!(urlenc("a b"), "a%20b");
        assert_eq!(urlenc("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlenc("中文"), "%E4%B8%AD%E6%96%87");
    }
}
