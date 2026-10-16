-- 028：WAF 拦截告警配置（单例）。
--
-- 配合 027 的 block_events：采集后按「近 window_min 分钟内每站拦截数 > threshold」
-- 推送一条站内通知（notifications 表，source=security）。命中即报警，无需用户盯日志。
--
-- 设计取舍：
-- - **单例表**（id 恒为 1）：告警是全局面的一处配置，不是每站一份——为每站各配一套
--   阈值属过度设计，且会让"到底几条规则在跑"变糊。默认开、50 次 / 5 分钟。
-- - **去重靠时间桶**：通知落库用 dedup_key = waf_alert:{site}:{ts/(window*60)}，
--   同一窗内每站至多一条（INSERT OR IGNORE），攻击持续则每窗一条，不刷屏。
-- - 阈值/窗宽上限：threshold ≤ 10 万、window_min ≤ 1440（24h）——防误填天文数字。
CREATE TABLE waf_alert_cfg (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    enabled    INTEGER NOT NULL DEFAULT 1,
    threshold  INTEGER NOT NULL DEFAULT 50,
    window_min INTEGER NOT NULL DEFAULT 5,
    updated_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO waf_alert_cfg(id, enabled, threshold, window_min, updated_at)
    VALUES (1, 1, 50, 5, 0);
