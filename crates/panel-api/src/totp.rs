//! TOTP（RFC 6238）与一次性恢复码。
//!
//! 为什么是 HMAC-**SHA1**：RFC 6238 定义了 SHA1/SHA256/SHA512 三档，但
//! Google Authenticator / 多数主流验证器**只实现 SHA1 档**。为兼容性取 SHA1——
//! TOTP 的安全性来自共享密钥与 30 秒窗口，不依赖 SHA1 的抗碰撞性。
//!
//! 新增依赖：`sha1`（`hmac` 与 `sha2` 本就已有）。依赖预算 36 → 37（上限 38）。

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// 时间步长（秒）。30 秒是 RFC 6238 与所有主流验证器的默认值。
pub const STEP_SECS: i64 = 30;
/// 允许的时间步漂移（前后各 1 步）——抵抗手机时钟不准，但不至于放大到 90 秒窗口。
const DRIFT_STEPS: i64 = 1;
pub const RECOVERY_CODE_COUNT: usize = 10;

/// HOTP（RFC 4226）：动态截断后取 6 位。
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut m = HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 接受任意长度密钥");
    m.update(&counter.to_be_bytes());
    let h = m.finalize().into_bytes();
    let offset = (h[h.len() - 1] & 0x0f) as usize;
    let bin = ((h[offset] & 0x7f) as u32) << 24
        | (h[offset + 1] as u32) << 16
        | (h[offset + 2] as u32) << 8
        | (h[offset + 3] as u32);
    bin % 1_000_000
}

/// TOTP：以 30 秒为步长的 HOTP。
pub fn totp(secret: &[u8], at_unix: i64) -> u32 {
    hotp(secret, (at_unix / STEP_SECS) as u64)
}

/// 校验用户输入的 6 位码，允许 ±1 个时间步漂移。
///
/// **常量时间无关**（比较的是 u32），但防暴力由登录限速（LoginGuard）承担。
pub fn verify(secret: &[u8], code: &str, at_unix: i64) -> bool {
    let Ok(input) = code.trim().parse::<u32>() else {
        return false;
    };
    let step = at_unix / STEP_SECS;
    (-DRIFT_STEPS..=DRIFT_STEPS).any(|d| hotp(secret, (step + d) as u64) == input)
}

/// 生成 TOTP 共享密钥（20 字节，RFC 4226 建议 ≥16）。
pub fn gen_secret() -> [u8; 20] {
    let mut b = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// `otpauth://` URI——验证器 App 扫码录入用。
pub fn otpauth_uri(username: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/ForkPanel:{username}?secret={secret_b32}&issuer=ForkPanel&digits=6&period=30"
    )
}

// ─────────────── base32（RFC 4648，无 padding） ───────────────

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 4) / 5 * 8);
    let mut bits = 0u16;
    let mut nbits = 0u8;
    for &b in bytes {
        bits = (bits << 8) | b as u16;
        nbits += 8;
        while nbits >= 5 {
            out.push(B32_ALPHABET[((bits >> (nbits - 5)) & 0x1f) as usize] as char);
            nbits -= 5;
        }
    }
    if nbits > 0 {
        out.push(B32_ALPHABET[((bits << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for c in s.trim().to_ascii_uppercase().chars() {
        if c == '=' || c == ' ' || c == '-' {
            continue;
        }
        let v = B32_ALPHABET.iter().position(|&a| a == c as u8)? as u32;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            out.push((bits >> (nbits - 8)) as u8);
            nbits -= 8;
        }
    }
    Some(out)
}

// ─────────────── 一次性恢复码 ───────────────

/// 生成恢复码（明文，**只在 enroll 时返回一次**）。格式 `XXXX-XXXX`。
pub fn gen_recovery_codes(n: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let v = rng.next_u32();
        let s = format!("{:08X}", v);
        let code = format!("{}-{}", &s[0..4], &s[4..8]);
        if !out.contains(&code) {
            out.push(code);
        }
    }
    out
}

/// 恢复码的**哈希**（sha256 hex）。库里绝不存明文——泄露库不应直接得到可用恢复码。
pub fn hash_recovery_code(code: &str) -> String {
    use sha2::{Digest, Sha256};
    let norm = normalize_recovery_code(code);
    let d = Sha256::digest(norm.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// 归一化：忽略大小写与分隔符，避免用户手抄时格式不同导致校验失败。
pub fn normalize_recovery_code(code: &str) -> String {
    code.trim().to_ascii_uppercase().replace(['-', ' '], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B 官方测试向量（SHA1 档，8 位输出）
    fn rfc_secret() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }

    #[test]
    fn rfc6238_test_vectors() {
        // 计数器 = T/30
        assert_eq!(hotp(&rfc_secret(), 1), 94287082 % 1_000_000);
        assert_eq!(hotp(&rfc_secret(), 37037036), 7081804 % 1_000_000);
        // 注：本实现按 RFC 取 6 位，故断言值是官方 8 位结果的**后 6 位**
        assert_eq!(hotp(&rfc_secret(), 41152263), 89005924 % 1_000_000);
    }

    #[test]
    fn base32_roundtrip() {
        for n in [1usize, 2, 3, 5, 10, 20] {
            let b: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let enc = base32_encode(&b);
            assert_eq!(base32_decode(&enc), Some(b), "n={n} 往返应一致");
        }
    }

    #[test]
    fn base32_of_rfc_secret_decodes_back() {
        // RFC 4648 对 "12345678901234567890" 的标准编码
        let enc = base32_encode(&rfc_secret());
        assert_eq!(enc, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&enc), Some(rfc_secret()));
    }

    #[test]
    fn verify_accepts_current_and_adjacent_steps() {
        let s = rfc_secret();
        let t = 1_700_000_000;
        let step = t / STEP_SECS;
        // 当前步
        assert!(verify(&s, &format!("{:06}", hotp(&s, step as u64)), t));
        // 前一步（时钟快）
        assert!(verify(&s, &format!("{:06}", hotp(&s, (step - 1) as u64)), t));
        // 后一步（时钟慢）
        assert!(verify(&s, &format!("{:06}", hotp(&s, (step + 1) as u64)), t));
        // 两步之外必须拒绝（否则窗口被放大到 150 秒）
        assert!(!verify(&s, &format!("{:06}", hotp(&s, (step + 2) as u64)), t));
        assert!(!verify(&s, &format!("{:06}", hotp(&s, (step - 2) as u64)), t));
        // 垃圾输入
        assert!(!verify(&s, "abcdef", t));
        assert!(!verify(&s, "", t));
    }

    #[test]
    fn recovery_codes_are_unique_and_normalized() {
        let codes = gen_recovery_codes(RECOVERY_CODE_COUNT);
        assert_eq!(codes.len(), 10);
        let mut uniq = codes.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), 10, "恢复码不得重复");
        // 大小写与分隔符不影响哈希
        let c = &codes[0];
        let lower = c.to_ascii_lowercase();
        assert_eq!(hash_recovery_code(c), hash_recovery_code(&lower));
        assert_eq!(hash_recovery_code(c), hash_recovery_code(&c.replace('-', " ")));
    }
}
