-- v9：反代 / PHP 站点的后端配置落库
--
-- 修复两类数据退化：
-- 1) 反代(PHP)站点重启后无法复原——`apply` 之前只写 `kind`，`upstreams`/`fpm` 无列可存，
--    进程重启或同名重建时拿不到后端目标；
-- 2) 编辑页点「应用」就退化为静态站——`upstreams`/`fpm` 未随站点一起持久化，
--    任何一次重应用都会丢失后端配置。
--
-- 反代后端用 JSON 数组字符串存储（与 `domains` 同构），php-fpm 目标是单值。
-- 两者对 static 站点恒为 NULL，不影响既有行。

ALTER TABLE sites ADD COLUMN upstreams_json TEXT;   -- JSON 数组：["http://127.0.0.1:3000", ...]
ALTER TABLE sites ADD COLUMN fpm            TEXT;   -- php-fpm 目标：unix:/path.sock | host:port
