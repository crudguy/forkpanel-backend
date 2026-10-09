-- v13：静态站点 SPA 回退 + 整站重定向类型
--
-- 1) SPA 回退：history 路由的单页应用（Vue/React 等）需要把所有未命中文件的路径
--    交给 /index.html，新增 `spa` 标志列（0/1），render 时决定 try_files 末项。
-- 2) 整站重定向：新增站点类型 redirect（库内 kind='redirect'），目标 URL 与状态码
--    落 `redirect_target` / `redirect_code`。两者对既有 static/proxy/php 站点恒为
--    默认值（spa=0、redirect_target/code 为 NULL），不影响既有行。

ALTER TABLE sites ADD COLUMN spa             INTEGER NOT NULL DEFAULT 0;  -- SPA 回退标志
ALTER TABLE sites ADD COLUMN redirect_target TEXT;                        -- 重定向目标 URL
ALTER TABLE sites ADD COLUMN redirect_code   INTEGER;                     -- 重定向状态码 301/302/307/308
