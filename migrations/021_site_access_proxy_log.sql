-- 021: 访问控制 / 反代增强 / 站点日志（设计文档 P6 + P3 + P8）
--
-- 三组都是「渲染器多一行指令就能省掉用户手写一大段」的能力，且都容易写错：
--   ip_allow / ip_deny   —— `allow` / `deny` 是按顺序匹配的，混用极易写错。文档给的
--     规则是**白名单优先**：ip_allow 非空即进入白名单模式（其余全拒），此时 ip_deny
--     被忽略（UI 上互斥置灰）。写入侧做 IP/CIDR 语法白名单校验（这些值直接进配置文本）。
--   auth_basic / auth_user —— HTTP Basic Auth。口令**不落库**（只在其提交时经 openssl
--     生成 apr1 摘要写进 htpasswd 文件），故列里只有开关与用户名。
--   lb_policy / proxy_*_timeout —— 多后端时的负载均衡策略与三项代理超时。单后端时
--     upstream 块不存在，策略自然不生效（渲染器按 upstreams 数量决定）。
--   log_access / log_error / log_error_level —— 站点自己的访问/错误日志。此前站点
--     没有独立日志（沿用 nginx 全局），既没法按站点排查，也没法「下载 / 清空」；
--     开启后由面板指定路径，该文件即下载与清空的唯一目标。NULL = 不单独记录。
--
-- 全部字段进部署指纹（deploy_fingerprint 的 advanced_json）：改动会触发「未同步」。
ALTER TABLE sites ADD COLUMN ip_allow          TEXT;
ALTER TABLE sites ADD COLUMN ip_deny           TEXT;
ALTER TABLE sites ADD COLUMN auth_basic        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN auth_user         TEXT;
ALTER TABLE sites ADD COLUMN lb_policy         TEXT    NOT NULL DEFAULT 'least_conn';
ALTER TABLE sites ADD COLUMN proxy_connect_timeout INTEGER NOT NULL DEFAULT 60;
ALTER TABLE sites ADD COLUMN proxy_send_timeout    INTEGER NOT NULL DEFAULT 60;
ALTER TABLE sites ADD COLUMN proxy_read_timeout    INTEGER NOT NULL DEFAULT 60;
ALTER TABLE sites ADD COLUMN log_access        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN log_error         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN log_error_level   TEXT    NOT NULL DEFAULT 'error';
