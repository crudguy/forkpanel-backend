-- 032：WAF 策略模板也带并发连接数上限（补齐 031 的站点级 limit_conn）。
--
-- 为什么需要：031 让站点能配 `waf_conn_max`，但模板（026）只存了 rate/burst，
-- 套用模板会把站点的连接数上限**重置**——用户以为模板保存了完整预设，实际漏了一项。
-- 与 rate 一样用 0 表示不限（NULL 亦可，这里统一 NOT NULL DEFAULT 0，查询少一处分支）。
ALTER TABLE waf_templates ADD COLUMN conn_max INTEGER NOT NULL DEFAULT 0;
