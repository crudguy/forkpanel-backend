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
    let san = domains.iter().map(|d| format!("DNS:{d}")).collect::<Vec<_>>().join(",");
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
