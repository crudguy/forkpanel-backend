-- v2：站内通知
--
-- 面板此前没有任何告警出口：证书续期失败、备份失败、任务失败都只有 eprintln，
-- 用户**无从知晓**。本表提供站内通知（in-app），是运维闭环的"最后一公里"。
--
-- 设计取舍：**不做邮件/Webhook 外部通道** —— 那需要 reqwest/lettre（各占一个
-- 直接依赖位），而依赖预算门禁 [8] 上限 38、当前 36，须留给更高价值模块。
-- 站内通知零新增依赖，且对单机面板已覆盖主要场景（面板内可见即可处置）。

CREATE TABLE IF NOT EXISTS notifications (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    level     TEXT NOT NULL,              -- info | warn | crit
    source    TEXT NOT NULL,              -- backup | restore | cert | task | security | system
    title     TEXT NOT NULL,
    body      TEXT,
    -- 去重键：同一键只落一条（SQLite UNIQUE 允许多个 NULL，故可空=不去重）。
    -- 调用方按需把时间粒度编进键里（如按天：backup:3:fail:20260929）。
    dedup_key TEXT UNIQUE,
    read      INTEGER NOT NULL DEFAULT 0  -- 0=未读 1=已读
);

CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(read, ts DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_ts     ON notifications(ts DESC);
