-- 012_task_idempotency.sql
-- 幂等键原子约束：同一 task_id 同时只能有一个**非终态**任务行。
--
-- 背景：submit() 的步骤 1（查内存 idempotency map）与步骤 2（INSERT 落库）之间
-- 没有原子保护。writer actor 虽串行执行各 INSERT 闭包，但两个并发、相同
-- idempotency_key 的请求会都通过 map 检查（此时 map 尚未写入），于是各 INSERT 一条，
-- 建出重复任务——防双击 / 防重试风暴的目的落空。
--
-- 修复思路：把"查 + 建"的原子性下沉到数据库这一唯一真相源。部分唯一索引只约束
-- 非终态行，终态行不受限，从而保留"用户确实想重跑同一操作（再来一次）"的语义。
--
-- 防御性清理：历史版本无此约束，极端并发下可能已积累同 key 的重复非终态行。
-- 若直接建唯一索引会在有重复数据的库上启动失败，故先保留每 key 最新一行、删其余。
-- 正常库不命中（删除 0 行）。

CREATE TEMP TABLE _dup_task_ids AS
SELECT id FROM task_runs
WHERE state IN ('queued', 'running')
  AND id NOT IN (
    SELECT MAX(id) FROM task_runs
    WHERE state IN ('queued', 'running')
    GROUP BY task_id
  );

DELETE FROM task_runs WHERE id IN (SELECT id FROM _dup_task_ids);
DROP TABLE _dup_task_ids;

CREATE UNIQUE INDEX IF NOT EXISTS idx_task_runs_idempotent_active
    ON task_runs(task_id)
    WHERE state IN ('queued', 'running');
