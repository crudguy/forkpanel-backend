-- 041：记录 ACME 证书首签时用的挑战方式。
--
-- 为什么必须落库：dns-01 的续期不能靠裸 `certbot renew`——首签时 hook 依赖的
-- 环境变量（token 文件 / zone / 记录名）只在进程内存里，certbot 的续期配置
-- 不会保存这些自定义变量。续期必须重新解密凭据、走一遍 dns-01 写 TXT 的流程；
-- 而 `ssl_certs.source` 只有 'acme' 一个值，区分不了 http-01 与 dns-01。
-- 空串 = 历史证书 / http-01（沿用 certbot renew），'dns-01' = 重签并写 TXT。
ALTER TABLE ssl_certs ADD COLUMN challenge TEXT NOT NULL DEFAULT '';
