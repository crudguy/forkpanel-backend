-- 证书自动续期扫描的运行状态（供前端展示"上次/下次扫描"）。
-- 单行表（id 恒为 1）：last_at = 最近一次扫描的 Unix 秒，last_queued = 该次入队证书数。
-- 由内部调度器每日 4:05 触发的 auto_renew_sweep 写入；未运行过时整表为空（端点返回 0）。
CREATE TABLE cert_sweep_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    last_at     INTEGER NOT NULL DEFAULT 0,
    last_queued INTEGER NOT NULL DEFAULT 0
);
