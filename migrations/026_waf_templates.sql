-- 026：WAF 策略模板。
--
-- 站点 WAF + 访问控制本是 sites 表列（waf_enabled/waf_profile/waf_rate/waf_burst/
-- ip_allow/ip_deny）。模板把「一套 WAF + 访问控制预设」存成可复用单元：套用到某站
-- 即把该站的这些列设成模板值（套用动作由前端经既有 POST /sites/apply 完成，模板
-- 本身不触碰站点部署管线）。
--
-- 设计取舍：
-- - 只存**归一后的值**：profile 限 basic/strict、rate≤1000、burst≤10000、burst 仅在
--   限速时有效、IP 仅 IPv4/CIDR——与 sites apply 的 build_waf / parse_ip_list 同源，
--   故不在此重复约束，落库前由 handler 复用同一校验（避免两处漂移）。
-- - name UNIQUE：模板名是用户辨识与套用时的选择依据，重名会混淆；唯一冲突由 handler
--   先读后判返回 409（db.exec 会把闭包错误一律包成 500，不能依赖 UNIQUE 兜底）。
-- - 布尔/枚举均用 TEXT/INTEGER + 注释写清取值；时间用 unix 秒（与全库一致）。
CREATE TABLE waf_templates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    waf_profile  TEXT    NOT NULL DEFAULT 'basic',
    rate_per_sec INTEGER NOT NULL DEFAULT 0,
    burst        INTEGER NOT NULL DEFAULT 0,
    ip_allow     TEXT    NOT NULL DEFAULT '',
    ip_deny      TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
