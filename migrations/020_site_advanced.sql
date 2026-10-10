-- 020: 站点高级配置（www 跳转 / TLS 强化 / 伪静态）
--
-- 背景：这三组都是「字段固定、极易写错、出错后果严重」的典型——手写 `if ($host …)`
-- 有已知陷阱、ssl_ciphers 抄错会直接让老客户端连不上、伪静态 rewrite 是新手最大
-- 的坑。把它们做成表单字段，由渲染器产出，价值最高。
--
-- 设计与取舍：
--   www_redirect  off|to_www|to_bare —— 只对**主域名**（domains[0]）生效，其余
--     域名不动：子域（api.example.com）被一起 rewrite 成 www.api.example.com
--     几乎不会是用户想要的，宁可少做。
--     实现刻意用**独立 server 块 + return 301**，不用文档里的 `if ($host …)`：
--     if 在 server 级虽可用，但与 location 内 rewrite 交互时有陷阱，独立块
--     语义直白、nginx 匹配也更快。
--   tls_profile / tls_min  加密套件档位与 TLS 版本下限，均取预设值（不开放
--     自由输入）——自由填 ssl_ciphers 的出错代价远大于收益。
--   hsts*  HSTS 一旦生效在 max-age 期间**无法通过服务端撤回**，故默认关，
--     max-age 默认只给 300 秒（验证通过后再调大），includeSubDomains /
--     preload 各自独立开关（UI 需二次确认）。
--   rewrite_preset / rewrite_custom  伪静态预置模板（编译期常量，见 stub.rs）；
--     custom 时片段走 rewrite_custom（上限 64 KiB，仅 php 类型有意义）。
--
-- 全部字段都进部署指纹（deploy_fingerprint 的 advanced_json）：改动会照常
-- 触发「未同步」检测，不会形成静默分叉。NULL / 空串 = 不使用。
ALTER TABLE sites ADD COLUMN www_redirect   TEXT    NOT NULL DEFAULT 'off';
ALTER TABLE sites ADD COLUMN tls_profile    TEXT    NOT NULL DEFAULT 'modern';
ALTER TABLE sites ADD COLUMN tls_min        TEXT    NOT NULL DEFAULT 'TLSv1.2';
ALTER TABLE sites ADD COLUMN hsts           INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN hsts_max_age   INTEGER NOT NULL DEFAULT 300;
ALTER TABLE sites ADD COLUMN hsts_sub       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN hsts_preload   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN rewrite_preset TEXT    NOT NULL DEFAULT 'none';
ALTER TABLE sites ADD COLUMN rewrite_custom TEXT;
