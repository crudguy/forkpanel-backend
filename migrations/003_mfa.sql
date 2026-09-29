-- v3：MFA（TOTP）所需列
--
-- 设计 §1.3 要求 TOTP + 10 个一次性恢复码。**恢复码不是可选项**：
-- 用户丢失手机即永久锁死账户，没有恢复码的 MFA 是把可用性一起锁掉了。
--
-- 恢复码与会话 sid 同一纪律：**只存哈希**（高熵随机码，sha256 足够，
-- 不需要 argon2 那种慢哈希——恢复码不是口令，且慢哈希会让批量生成明显卡顿）。

ALTER TABLE users ADD COLUMN mfa_enabled_at    INTEGER;
ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT;
