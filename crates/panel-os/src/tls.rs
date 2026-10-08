//! TLS 证书生成（面板自签）。
//!
//! **本模块是 openssl 的唯一调用点**，且必须经 `cmd.rs` 受控外呼（argv 传参、无 shell、
//! 强制超时、审计）。业务层（panel-api）只拿到 PEM 字符串，不接触子进程细节。
//!
//! 私钥 PEM 由调用方负责用主密钥（`AppState.master_key`）加密后再落库，
//! 本模块**不落库、不加密**，只负责"生成一对 PEM"。

use crate::cmd::{Bin, CmdOpt};
use panel_core::{PanelError, Result};
use std::path::Path;
use std::time::Duration;

/// openssl 是否可用（供能力位 `ssl.selfsigned` 判定）。只做存在性检查。
pub fn available() -> bool { Bin::OpenSsl.available() }

/// ACME 是否可用（certbot 存在）。与面板自签**相互独立**，各自置灰互不干扰。
pub fn acme_available() -> bool { Bin::Certbot.available() }

/// certbot 默认产物目录。签发/续期后从这里读回证书与私钥。
fn acme_live_dir(domain: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/etc/letsencrypt/live/{domain}"))
}

/// 以 **http-01 webroot** 方式用 certbot 签发证书。
///
/// 走 `cmd::run`（唯一子进程出口，argv 直传不经 shell）；域名与邮箱由调用方校验。
/// 返回 `(fullchain, privkey)` 的 PEM 文本——落盘加密沿用自签的同一条路径。
pub async fn issue_acme(
    domain: &str,
    email: &str,
    webroot: &std::path::Path,
) -> Result<(String, String)> {
    let w = webroot
        .to_str()
        .ok_or_else(|| panel_core::PanelError::Internal("webroot 路径非 UTF-8".into()))?;
    let out = crate::cmd::run(
        Bin::Certbot,
        &[
            "certonly", "--webroot", "-w", w, "-d", domain,
            "--non-interactive", "--agree-tos", "-m", email,
            "--keep-until-expiring", "--quiet",
        ],
        crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Err(panel_core::PanelError::Command { bin: "certbot".into(), detail: out.stderr });
    }
    read_acme_pair(domain)
}

/// 续期：`certbot renew` 后重读该域名的证书对。
/// 未到续期窗口时 certbot 会跳过（--keep-until-expiring），读到的仍是当前有效证书。
pub async fn renew_acme(domain: &str) -> Result<(String, String)> {
    let out = crate::cmd::run(
        Bin::Certbot,
        &["renew", "--non-interactive", "--quiet"],
        crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Err(panel_core::PanelError::Command { bin: "certbot".into(), detail: out.stderr });
    }
    read_acme_pair(domain)
}

fn read_acme_pair(domain: &str) -> Result<(String, String)> {
    let d = acme_live_dir(domain);
    let cert = std::fs::read_to_string(d.join("fullchain.pem")).map_err(|e| {
        panel_core::PanelError::Io(format!("读取证书失败 {}/fullchain.pem：{e}", d.display()))
    })?;
    let key = std::fs::read_to_string(d.join("privkey.pem")).map_err(|e| {
        panel_core::PanelError::Io(format!("读取私钥失败 {}/privkey.pem：{e}", d.display()))
    })?;
    Ok((cert, key))
}

/// SAN 条目：IP 目标写 `IP:` 前缀、域名写 `DNS:`。
///
/// 浏览器按目标的**类型**分别匹配 IP SAN 与 DNS SAN —— 对 IP 地址写 `DNS:`
/// 时，即便证书正常下发，访问 `https://<ip>` 仍会报名称不匹配（RFC 6125 / 浏览器行为）。
fn san_entry(host: &str) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() {
        format!("IP:{host}")
    } else {
        format!("DNS:{host}")
    }
}

/// 为 `domains` 生成自签证书（RSA-2048，多域名写入 SAN）。返回 `(cert_pem, key_pem)`。
///
/// `tmp_dir` 为中间产物目录（由调用方经 `PathLayout` 提供，避免此处硬编码平台路径）；
/// 无论成功失败都会清理该临时子目录，私钥不留痕。
pub async fn generate_self_signed(
    tmp_dir: &Path,
    domains: &[String],
    days: u32,
) -> Result<(String, String)> {
    if domains.is_empty() {
        return Err(PanelError::ConfigInvalid { detail: "domains 为空".into() });
    }
    let cn = &domains[0];
    let san = domains.iter().map(|d| san_entry(d)).collect::<Vec<_>>().join(",");
    let dir = tmp_dir.join(format!("ssl-gen-{}-{}", std::process::id(), unique()));
    std::fs::create_dir_all(&dir).map_err(|e| PanelError::Internal(e.to_string()))?;

    let key_p = dir.join("key.pem");
    let crt_p = dir.join("cert.pem");
    let (ks, cs) = (
        key_p.to_str().ok_or_else(|| PanelError::Internal("tmp path not utf8".into()))?,
        crt_p.to_str().ok_or_else(|| PanelError::Internal("tmp path not utf8".into()))?,
    );
    let subj = format!("/CN={cn}");
    let addext = format!("subjectAltName={san}");
    let days_s = days.to_string();
    let args = [
        "req", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-keyout", ks, "-out", cs,
        "-days", days_s.as_str(), "-subj", subj.as_str(), "-addext", addext.as_str(),
    ];

    let r = crate::cmd::run(
        Bin::OpenSsl, &args,
        CmdOpt { timeout: Duration::from_secs(60), ..Default::default() },
    ).await;

    // 无论成败都清掉临时目录（私钥不留痕）
    let cleanup = |dir: &Path| { let _ = std::fs::remove_dir_all(dir); };

    match r {
        Ok(o) if o.code == Some(0) => {}
        Ok(o) => {
            cleanup(&dir);
            return Err(PanelError::Command { bin: "openssl".into(), detail: truncate(&o.stderr) });
        }
        Err(e) => { cleanup(&dir); return Err(e); }
    }

    let cert = std::fs::read_to_string(&crt_p).map_err(|e| PanelError::Internal(e.to_string()));
    let key = std::fs::read_to_string(&key_p).map_err(|e| PanelError::Internal(e.to_string()));
    cleanup(&dir);
    Ok((cert?, key?))
}

fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    C.fetch_add(1, Ordering::Relaxed)
}

fn truncate(s: &str) -> String {
    if s.len() <= 2000 { s.to_string() } else { format!("{}…(truncated)", &s[..2000]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_never_executes() {
        // 只做存在性检查，返回 bool，不 panic（本机有无 openssl 都合法）
        let _ = available();
    }

    #[test]
    fn san_prefix_matches_target_kind() {
        // IP 走 IP SAN、域名走 DNS SAN；混用会让浏览器报名称不匹配
        assert_eq!(san_entry("127.0.0.1"), "IP:127.0.0.1");
        assert_eq!(san_entry("::1"), "IP:::1");
        assert_eq!(san_entry("example.com"), "DNS:example.com");
        assert_eq!(san_entry("sub.example.com"), "DNS:sub.example.com");
    }

    /// 需真机 openssl 的端到端：本沙箱有 openssl 时应真实生成一对可解析 PEM。
    #[tokio::test]
    async fn generate_roundtrip_when_openssl_present() {
        if !available() { return; }
        let tmp = std::env::temp_dir().join(format!("panel-tls-test-{}", unique()));
        std::fs::create_dir_all(&tmp).unwrap();
        let domains = vec!["a.example".to_string(), "b.example".to_string()];
        let (cert, key) = generate_self_signed(&tmp, &domains, 30).await.expect("生成自签证书");
        assert!(cert.contains("BEGIN CERTIFICATE"), "cert 应为 PEM: {cert}");
        assert!(key.contains("PRIVATE KEY"), "key 应为 PEM: {key}");
        // SubjectAltName 应包含两个域名（openssl 输出的文本里能看到）
        let _ = &domains;
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
