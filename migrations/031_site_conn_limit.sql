-- 站点级并发连接数上限（P1-5）。
-- NULL / 0 = 不限制；有值时 nginx 渲染 limit_conn_zone + limit_conn。
-- 与 WAF 同属一个开关：waf_enabled=0 时本值不参与渲染。
ALTER TABLE sites ADD COLUMN waf_conn_max INTEGER;
