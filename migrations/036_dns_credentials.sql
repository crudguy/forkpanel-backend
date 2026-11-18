-- 036：DNS 提供商 API 凭据（P2-10，ACME dns-01 的前提）。
--
-- 为什么必须有这张表：dns-01 的证明方式是「在 `_acme-challenge.<域名>` 下放一条
-- 指定内容的 TXT 记录」。这与 http-01 放 HTTP 文件是**同一个证明的两种载体**，
-- 但 dns-01 没有通用的、与厂商无关的写入通道——必须拿到具体服务商的 API 凭据。
-- 没有凭据表，dns-01 就只能永远是 501。
--
-- 设计取舍：
-- - **按 provider 唯一**（UNIQUE），而非每站点一条：一个 Cloudflare Token 通常
--   管多个 zone，按站点存会让用户为同一账号重复粘贴 N 次，且轮换凭据要改 N 处。
--   站点 → 用哪家的关系由签发时的 `dns_provider` 指定，不在这里绑死。
-- - **凭据密文入库**（secret_enc，AES-GCM + 主密钥，带 `enc:` 前缀），与
--   私钥 / 数据库口令 / LLM api_key 同一套纪律：库泄露 ≠ DNS 控制权泄露。
--   ⚠ 明文字段一律不建——没有列可写，就没有"顺手写明文"这一条路。
-- - **只存一个 token 字段**而不是"用户名+密码+token+..."的宽表：Cloudflare 的
--   现代鉴权就是一枚 API Token（Zone.DNS:Edit 权限）。宽表会让前端不得不为每家
--   提供商画不同的表单，而我们只接一家时那些列全是死的（"配置项假控制"）。
--   将来接入需要多字段的厂商（如阿里云 AccessKey+Secret）时，另开 `secret2_enc`
--   或把 token 存成 JSON——那是那时的事，现在不预留空列。
-- - `zone_hint` 留空 = 自动探测（用 token 反查域名所属 zone）。填了则跳过探测，
--   适合 token 权限受限、列不出 zone 的场景。
-- - `last_check_at` / `last_check_ok` / `last_check_msg`：把"凭据到底还能不能用"
--   落库，避免用户在一个已经失效的 token 上反复重试签发、误以为是自己域名配错。
CREATE TABLE IF NOT EXISTS dns_credentials (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    provider       TEXT    NOT NULL,
    label          TEXT    NOT NULL DEFAULT '',
    secret_enc     TEXT    NOT NULL,
    zone_hint      TEXT    NOT NULL DEFAULT '',
    last_check_at  INTEGER NOT NULL DEFAULT 0,
    last_check_ok  INTEGER NOT NULL DEFAULT 0,
    last_check_msg TEXT    NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    UNIQUE (provider)
);

-- 站点优先走哪家 DNS 签发（空串 = 未指定，签发时按唯一可用凭据推断）。
-- 单独一列而不是新表：一个站点的 dns 偏好是单个值，配对表纯属过度设计。
ALTER TABLE sites ADD COLUMN dns_provider TEXT NOT NULL DEFAULT '';
