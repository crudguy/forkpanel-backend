//! 应用层密钥加密（关闭 M0 阻塞项）。
//!
//! 设计约束（见《设计方案》§1.3）：
//! - SQLite 中存储的密钥（SSL 私钥、数据库口令）**绝不明文入库**；
//!   数据目录 0700 + 备份文件加密之外的第二道防线。
//! - 主密钥来自 `/etc/panel/master.key`（0600）或环境变量 `PANEL_MASTER_KEY`，
//!   **不落库**（见 `panel-cli/bootstrap.rs`）。
//! - 本模块保持**零 IO**：只做 AES-256-GCM 计算；从文件/环境变量读取主密钥由调用方完成。
//!
//! 密文格式：`nonce(12 字节) || ciphertext(+GCM tag 16 字节)`。

use crate::{PanelError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;

/// AES-256-GCM 要求的密钥长度。
pub const KEY_LEN: usize = 32;
/// GCM nonce 长度。
pub const NONCE_LEN: usize = 12;

/// 主密钥（32 字节）。仅驻留内存，不序列化、不落盘。
#[derive(Clone, Copy)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// 从 32 字节原始主密钥构造。长度不符返回错误（绝不静默截断）。
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != KEY_LEN {
            return Err(PanelError::Internal(format!(
                "master key length {} != {KEY_LEN}",
                b.len()
            )));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(b);
        Ok(MasterKey(k))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] { &self.0 }

    /// 加密任意明文，返回 `nonce || ciphertext+tag`。
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            // aead::Payload.aad 固定为 `&[u8]`（非 Option）；不使用关联数据时传空切片。
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: b"" })
            .map_err(|e| PanelError::Internal(format!("aes-gcm encrypt: {e}")))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// 解密 `nonce || ciphertext+tag`，返回明文。
    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_LEN {
            return Err(PanelError::Internal("ciphertext too short".into()));
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: b"" })
            .map_err(|e| PanelError::Internal(format!("aes-gcm decrypt: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = MasterKey::from_bytes(&[7u8; KEY_LEN]).unwrap();
        let plain = b"super-secret-private-key-material";
        let blob = key.encrypt(plain).unwrap();
        assert_ne!(&blob, plain);
        assert_eq!(key.decrypt(&blob).unwrap(), plain);
    }

    #[test]
    fn wrong_key_fails() {
        let a = MasterKey::from_bytes(&[1u8; KEY_LEN]).unwrap();
        let b = MasterKey::from_bytes(&[2u8; KEY_LEN]).unwrap();
        let blob = a.encrypt(b"x").unwrap();
        assert!(b.decrypt(&blob).is_err(), "错误主密钥必须解密失败");
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(MasterKey::from_bytes(&[0u8; 16]).is_err());
        assert!(MasterKey::from_bytes(&[0u8; 64]).is_err());
    }

    #[test]
    fn nonce_is_unique_per_encryption() {
        let key = MasterKey::from_bytes(&[9u8; KEY_LEN]).unwrap();
        let a = key.encrypt(b"same").unwrap();
        let b = key.encrypt(b"same").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN], "每次加密应使用不同 nonce");
    }
}
