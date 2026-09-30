-- v4：计划任务重叠保护 + Webhook 触发
--
-- P2-3 两项增强：
--   1) max_overlap：并发上限。==1 时由 Linux 实现用 flock 互斥锁包裹 cron 命令，
--      避免上次未跑完又被触发（典型：每分钟任务跑了 5 分钟）。>1 或 0 表示不强制
--      （OS 级 N>1 计数并发未实装，诚实标注）。
--   2) webhook_url / webhook_events：任务成功/失败/开始时向该 URL POST JSON。
--      走 cmd 唯一出口的 curl（Bin::Curl），零新增依赖、复用子进程纪律，
--      不占依赖预算第 38 位（原计划用 reqwest，改为 curl 更一致、更省）。

ALTER TABLE cron_jobs ADD COLUMN max_overlap   INTEGER NOT NULL DEFAULT 1;
ALTER TABLE cron_jobs ADD COLUMN webhook_url   TEXT;
ALTER TABLE cron_jobs ADD COLUMN webhook_events TEXT;   -- 逗号分隔：start,success,failure
