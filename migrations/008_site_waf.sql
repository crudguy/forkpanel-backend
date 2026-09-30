-- v8：站点 WAF（Web 应用防火墙）
--
-- 定位：**站点级防护**——为面板管理的站点生成拦截规则，逐站开关、可选档位。
-- 与"保护面板自身 API"是两件事（后者由 capability 门禁与 CSRF 负责）。
--
-- 设计取舍：
-- 1) 规则集是**编译期常量**，用户只能选档位（basic / strict）与数值（限速）。
--    刻意**不开放"自定义正则"**：那等于把配置注入面直接交出去，而且一条写坏的
--    正则会让 nginx 拒绝加载**整份**配置——一个站点写错，全机站点一起挂。
-- 2) 关掉 WAF 时把档位/数值一并清空（`waf_enabled=0` 即足够表达"关"，
--    但留着旧值会让"重新打开"意外带上几年前的参数）。
-- 3) 用整数列而不是 JSON：这几个值要参与"缺省=保留现值"的合并（见 apply 的
--    WafReq 三态语义），列式更好读也更好判空。

ALTER TABLE sites ADD COLUMN waf_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN waf_profile TEXT;     -- basic | strict
ALTER TABLE sites ADD COLUMN waf_rate    INTEGER;  -- CC 限速：每秒请求数（NULL = 不限速）
ALTER TABLE sites ADD COLUMN waf_burst   INTEGER;  -- 突发桶容量（仅在限速时有效）
