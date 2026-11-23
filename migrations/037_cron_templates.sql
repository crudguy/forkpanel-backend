-- v37：计划任务模板
--
-- 模板只承载「新建任务的表单预填值」：用户选一个模板把字段填进新建表单，
-- 之后可以任意修改。它**不**与 cron_jobs 建立外键关系，原因是：
--   · 任务名是 crontab 里的标识（Job.id），一个模板可以被用很多次、生成不同名字的任务；
--   · 删模板不应影响已建出来的任务——模板是脚手架，不是父对象。
--
-- description 是给人看的「这个模板是干什么的」（如「每天凌晨备份数据库到 /data」），
-- 在前端模板列表里作为副标题展示，避免用户只能靠名字猜。
--
-- 不存 enabled：新建任务一律默认启用，启用与否是任务实例的属性，不是模板的。

CREATE TABLE cron_templates (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL UNIQUE,   -- 模板名（同样作为展示与选择标识）
    description  TEXT    NOT NULL DEFAULT '',
    expr         TEXT    NOT NULL,
    command      TEXT    NOT NULL,
    user         TEXT    NOT NULL DEFAULT 'root',
    timeout_sec  INTEGER NOT NULL DEFAULT 1800,
    webhook_url  TEXT,                       -- NULL/空串 = 不回调
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
