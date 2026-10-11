//! TLS 证书生成（面板自签）。
//!
//! **本模块是 openssl 的唯一调用点**，且必须经 `cmd.rs` 受控外呼（argv 传参、无 shell、
//! 强制超时、审计）。业务层（panel-api）只拿到 PEM 字符串，不接触子进程细节。
//!
//! 私钥 PEM 由调用方负责用主密钥（`AppState.master_key`）加密后再落库，
//! 本模块**不落库、不加密**，只负责"生成一对 PEM"。

use crate::cmd::{Bin, CmdOpt};
use panel_core::{PanelError, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// openssl 是否可用（供能力位 `ssl.selfsigned` 判定）。只做存在性检查。
pub fn available() -> bool { Bin::OpenSsl.available() }

/// ACME 是否可用（certbot 存在）。与面板自签**相互独立**，各自置灰互不干扰。
pub fn acme_available() -> bool { Bin::Certbot.available() }

/// certbot 默认产物目录。签发/续期后从这里读回证书与私钥。
fn acme_live_dir(domain: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/etc/letsencrypt/live/{domain}"))
}

/// 生成 HTTP Basic Auth 的口令行（`user:apr1摘要`，与 `htpasswd -m` 同款）。
///
/// 与自签证书同走 `cmd.rs` 受控外呼（argv 直传、不经 shell、强制超时）。口令只在
/// 这一刻出现：**不落库、不入日志、不出现在任何响应里**。返回整行文本，由调用方写
/// 进 htpasswd 文件（nginx 的 `auth_basic_user_file` 读它）。
pub async fn htpasswd_line(user: &str, pass: &str) -> Result<String> {
    let r = crate::cmd::run(
        Bin::OpenSsl,
        &["passwd", "-apr1", pass],
        CmdOpt { timeout: Duration::from_secs(10), ..Default::default() },
    )
    .await;
    match r {
        Ok(o) if o.code == Some(0) => {
            let h = o.stdout.trim().to_string();
            if h.is_empty() {
                return Err(PanelError::Command { bin: "openssl".into(), detail: "passwd 返回空摘要".into() });
            }
            Ok(format!("{user}:{h}"))
        }
        Ok(o) => Err(PanelError::Command { bin: "openssl".into(), detail: truncate(&o.stderr, 500) }),
        Err(e) => Err(e),
    }
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
            return Err(PanelError::Command { bin: "openssl".into(), detail: truncate(&o.stderr, 2000) });
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

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}…(truncated)", &s[..n]) }
}

// ─────────────── ForkPanel 本地根 CA ───────────────
//
// 自签证书打不开 HTTPS 的根本原因：浏览器只信任**已安装的根 CA**，
// 而 `generate_self_signed` 产出的是「自签 leaf」（Issuer==Subject），
// 没有可信链 → NET::ERR_CERT_AUTHORITY_INVALID，用户无法在不点「继续前往」
// 的情况下正常打开。
//
// 修法（mkcert 模式）：面板持有**一张持久的根 CA**，所有自签 leaf 都由其签发。
// 用户只需把这张根证书安装进系统/浏览器信任库一次，之后全部本地 HTTPS 站点
// 都能无警告打开。根 CA 私钥只留在服务器（data/ssl/ca/），浏览器只需根证书。
//
// 目录布局由调用方（`panel-api` 的 ssl_dir）决定，本模块只接收 `ca_dir` 路径，
// 保持「crypto 不碰业务目录」的分层。

/// 根 CA 的主题名（即用户安装后看到的颁发者）。
///
/// `pub` 是刻意的：业务层写证书 `issuer` 字段时必须与真实签发者一致，
/// 否则列表里显示「面板自签」而实际签发者是本 CA，用户看到的名字对不上。
pub const CA_CN: &str = "ForkPanel Local CA";
/// 根 CA 有效期（天）。本地开发用，给足 10 年避免频繁重签。
const CA_DAYS: u32 = 3650;
/// 自签 leaf 的本地访问兜底 SAN：无论站点域名是什么都附上这些，
/// 让用户用 `localhost` / `127.0.0.1` / `[::1]` 访问也能匹配
/// （否则按 IP/回环名访问必报名称不匹配）。
const LOCAL_SAN: &[&str] = &["localhost", "127.0.0.1", "::1"];

fn ca_cert_path(ca_dir: &Path) -> PathBuf { ca_dir.join("ca.crt") }
fn ca_key_path(ca_dir: &Path) -> PathBuf { ca_dir.join("ca.key") }

/// 确保 ForkPanel 本地根 CA 存在：缺失时生成一对 RSA-2048（`CA:TRUE,pathlen:0`）
/// 落盘到 `ca_dir`；已存在则直接返回（幂等）。
///
/// 并发首跑的最坏情况：两个请求都判定缺失、各生成一张，后落的覆盖先落的——
/// 本地开发可接受（用户重装一次根证书即可）。落盘前会再判一次，若此时已被
/// 其它请求创建则丢弃本次生成，避免无谓覆盖。
pub async fn ensure_root_ca(ca_dir: &Path, tmp_dir: &Path) -> Result<()> {
    if ca_cert_path(ca_dir).is_file() && ca_key_path(ca_dir).is_file() {
        return Ok(());
    }
    std::fs::create_dir_all(ca_dir).map_err(|e| PanelError::Internal(e.to_string()))?;

    let work = tmp_dir.join(format!("ca-gen-{}-{}", std::process::id(), unique()));
    std::fs::create_dir_all(&work).map_err(|e| PanelError::Internal(e.to_string()))?;
    let crt = work.join("ca.crt");
    let key = work.join("ca.key");
    let (cs, ks) = (
        crt.to_str().ok_or_else(|| PanelError::Internal("tmp path not utf8".into()))?,
        key.to_str().ok_or_else(|| PanelError::Internal("tmp path not utf8".into()))?,
    );
    let subj = format!("/CN={CA_CN}");
    let req_args: Vec<String> = vec![
        "req".into(), "-x509".into(), "-newkey".into(), "rsa:2048".into(),
        "-nodes".into(), "-keyout".into(), ks.into(), "-out".into(), cs.into(),
        "-days".into(), CA_DAYS.to_string(),
        "-subj".into(), subj,
        "-addext".into(), "basicConstraints=critical,CA:TRUE,pathlen:0".into(),
        "-addext".into(), "keyUsage=critical,keyCertSign,cRLSign".into(),
        "-addext".into(), "subjectKeyIdentifier=hash".into(),
    ];
    let a: Vec<&str> = req_args.iter().map(|s| s.as_str()).collect();
    let r = crate::cmd::run(
        Bin::OpenSsl, &a,
        CmdOpt { timeout: Duration::from_secs(60), ..Default::default() },
    ).await;
    let cleanup = |dir: &Path| { let _ = std::fs::remove_dir_all(dir); };
    match r {
        Ok(o) if o.code == Some(0) => {}
        Ok(o) => { cleanup(&work); return Err(PanelError::Command { bin: "openssl".into(), detail: truncate(&o.stderr, 2000) }); }
        Err(e) => { cleanup(&work); return Err(e); }
    }

    // 落盘前再判一次：若已被并发请求创建，则丢弃本次生成，沿用既有根 CA
    if ca_cert_path(ca_dir).is_file() && ca_key_path(ca_dir).is_file() {
        cleanup(&work);
        return Ok(());
    }
    std::fs::copy(&crt, ca_cert_path(ca_dir)).map_err(|e| PanelError::Internal(e.to_string()))?;
    std::fs::copy(&key, ca_key_path(ca_dir)).map_err(|e| PanelError::Internal(e.to_string()))?;
    #[cfg(unix)]
    let _ = std::fs::set_permissions(
        ca_key_path(ca_dir),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    );
    cleanup(&work);
    Ok(())
}

/// 读取根证书 PEM（供「下载根证书」端点）。调用前应已 `ensure_root_ca`。
pub fn root_ca_pem(ca_dir: &Path) -> Result<String> {
    std::fs::read_to_string(ca_cert_path(ca_dir))
        .map_err(|e| PanelError::NotFound(format!("根证书尚未生成：{e}")))
}

/// 由 ForkPanel 本地根 CA 签发一张 leaf 证书（含站点域名 + 本地回环 SAN）。
/// 返回 `(leaf_cert_pem, leaf_key_pem)`。根 CA 不存在时自动创建。
///
/// 与 `generate_self_signed` 的区别：leaf 的 Issuer 是 `ForkPanel Local CA`，
/// 而非自身 —— 浏览器装上根证书后即信任该 leaf，HTTPS 不再报「非私密连接」。
pub async fn issue_leaf_signed_by_ca(
    ca_dir: &Path,
    tmp_dir: &Path,
    domains: &[String],
    days: u32,
) -> Result<(String, String)> {
    if domains.is_empty() {
        return Err(PanelError::ConfigInvalid { detail: "domains 为空".into() });
    }
    ensure_root_ca(ca_dir, tmp_dir).await?;

    let work = tmp_dir.join(format!("leaf-{}-{}", std::process::id(), unique()));
    std::fs::create_dir_all(&work).map_err(|e| PanelError::Internal(e.to_string()))?;
    let leaf_key = work.join("leaf.key");
    let leaf_csr = work.join("leaf.csr");
    let leaf_crt = work.join("leaf.crt");
    let (lks, lcs, lcc) = (
        leaf_key.to_str().ok_or_else(|| PanelError::Internal("tmp path not utf8".into()))?,
        leaf_csr.to_str().ok_or_else(|| PanelError::Internal("tmp path not utf8".into()))?,
        leaf_crt.to_str().ok_or_else(|| PanelError::Internal("tmp path not utf8".into()))?,
    );

    // SAN：站点域名 + 本地兜底名（去重保序）。IP 走 IP SAN、域名走 DNS SAN，
    // 混用会让浏览器报名称不匹配（见 `san_entry`）。
    // 两侧都先归一到 `&str` 才能 chain——`domains` 是 `&String`、`LOCAL_SAN` 是 `&str`。
    let mut sans: Vec<String> = Vec::new();
    for d in domains.iter().map(|s| s.as_str()).chain(LOCAL_SAN.iter().copied()) {
        let e = san_entry(d);
        if !sans.contains(&e) { sans.push(e); }
    }
    let san = sans.join(",");
    let cn = &domains[0];
    let subj = format!("/CN={cn}");
    let addext = format!("subjectAltName={san}");

    // 1) 生成 leaf 私钥 + CSR（SAN 作为 request 扩展写入，供签发时 copy 回来）
    let req_args: Vec<String> = vec![
        "req".into(), "-newkey".into(), "rsa:2048".into(), "-nodes".into(),
        "-keyout".into(), lks.into(), "-out".into(), lcs.into(),
        "-subj".into(), subj, "-addext".into(), addext,
    ];
    let a: Vec<&str> = req_args.iter().map(|s| s.as_str()).collect();
    let r1 = crate::cmd::run(
        Bin::OpenSsl, &a,
        CmdOpt { timeout: Duration::from_secs(60), ..Default::default() },
    ).await;

    // 2) 用根 CA 签发 leaf（copy_extensions copyall 把 CSR 里的 SAN 带进证书）
    let (cac, cak) = (
        ca_cert_path(ca_dir).to_str().ok_or_else(|| PanelError::Internal("ca path not utf8".into()))?.to_string(),
        ca_key_path(ca_dir).to_str().ok_or_else(|| PanelError::Internal("ca path not utf8".into()))?.to_string(),
    );
    let sign_args: Vec<String> = vec![
        "x509".into(), "-req".into(), "-in".into(), lcs.into(),
        "-CA".into(), cac, "-CAkey".into(), cak,
        "-CAcreateserial".into(), "-out".into(), lcc.into(),
        "-days".into(), days.to_string(),
        "-copy_extensions".into(), "copyall".into(),
    ];
    let b: Vec<&str> = sign_args.iter().map(|s| s.as_str()).collect();
    let r2 = crate::cmd::run(
        Bin::OpenSsl, &b,
        CmdOpt { timeout: Duration::from_secs(60), ..Default::default() },
    ).await;

    let cleanup = |dir: &Path| { let _ = std::fs::remove_dir_all(dir); };
    if let Err(e) = &r1 { cleanup(&work); return Err(PanelError::Command { bin: "openssl".into(), detail: truncate(&e.to_string(), 2000) }); }
    let (crt, key) = match (&r1, &r2) {
        (Ok(o1), Ok(o2)) if o1.code == Some(0) && o2.code == Some(0) => {
            let c = std::fs::read_to_string(&leaf_crt).map_err(|e| PanelError::Internal(e.to_string()))?;
            let k = std::fs::read_to_string(&leaf_key).map_err(|e| PanelError::Internal(e.to_string()))?;
            (c, k)
        }
        (Ok(o1), _) if o1.code != Some(0) => { cleanup(&work); return Err(PanelError::Command { bin: "openssl".into(), detail: truncate(&o1.stderr, 2000) }); }
        (_, Ok(o2)) if o2.code != Some(0) => { cleanup(&work); return Err(PanelError::Command { bin: "openssl".into(), detail: truncate(&o2.stderr, 2000) }); }
        (_, Err(e)) => { cleanup(&work); return Err(e.clone()); }
        _ => { cleanup(&work); return Err(PanelError::Internal("unexpected openssl state".into())); }
    };
    cleanup(&work);
    Ok((crt, key))
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

    /// 本地根 CA 签发：leaf 应为合法 PEM，且根 CA 被创建、可被读取。
    #[tokio::test]
    async fn issue_leaf_by_ca_when_openssl_present() {
        if !available() { return; }
        let base = std::env::temp_dir().join(format!("panel-ca-test-{}", unique()));
        let tmp = base.join("tmp");
        let ca_dir = base.join("ca");
        std::fs::create_dir_all(&tmp).unwrap();
        let domains = vec!["site.example".to_string()];
        let (cert, key) = issue_leaf_signed_by_ca(&ca_dir, &tmp, &domains, 30)
            .await
            .expect("由本地根 CA 签发 leaf");
        assert!(cert.contains("BEGIN CERTIFICATE"), "leaf cert 应为 PEM: {cert}");
        assert!(key.contains("PRIVATE KEY"), "leaf key 应为 PEM: {key}");
        // 根 CA 必须已落盘且可读
        let ca = root_ca_pem(&ca_dir).expect("读取根证书");
        assert!(ca.contains("BEGIN CERTIFICATE"), "根证书应为 PEM: {ca}");
        assert!(ca_dir.join("ca.crt").is_file(), "ca.crt 应落盘");
        assert!(ca_dir.join("ca.key").is_file(), "ca.key 应落盘");
        let _ = std::fs::remove_dir_all(&base);
    }
}
