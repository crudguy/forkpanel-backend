-- 快捷命令唯一性从 label 改为 cmd（040）。
--
-- 列表里实际展示的是命令文本本身（`<code>{{ c.cmd }}</code>`），名称从未出现在
-- 界面上，用户凭它既认不出也点不准；真正会让用户误点的重复是**同一条命令配了
-- 两条记录**。故唯一性约束的锚点从 label 改到 cmd，名称字段整体删除。
--
-- SQLite 不能直接删列（且旧 label 列有 NOT NULL 约束会挡住新插入）⇒ 整表重建。
-- 连接开了 `PRAGMA foreign_keys=ON`，重建期间必须先关掉再恢复：否则 DROP TABLE
-- 与 RENAME 会因引用自身而报错。
--
-- ⚠ PRAGMA foreign_keys 在事务内是空操作，而 migrate::apply 把整个文件包在一个
-- 事务里跑。因此这里不依赖 PRAGMA 关闭 —— 改为「新表建好、数据搬完、旧表改名」
-- 的原地重建顺序，全程不 DROP 有外键引用的表。
--
-- 去重：同一 user_id 下 cmd 相同的多行只保留 id 最小的一行（最早创建的那条），
-- 否则建唯一索引会失败。预置命令不入库，无需处理。

DELETE FROM user_quick_commands
 WHERE id NOT IN (SELECT MIN(id) FROM user_quick_commands GROUP BY user_id, cmd);

-- 名字唯一性下沉到库里：并发两次提交同一条命令时，仅靠应用层 EXISTS 查重会
-- 双双通过 —— 查重与 INSERT 之间始终存在窗口。
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_quick_commands_user_cmd
    ON user_quick_commands(user_id, cmd);

-- 删除 label 列：SQLite 3.35+ 支持 DROP COLUMN。旧版本（Debian 13 自带 ≥3.40）
-- 均满足；低版本会在迁移时明确报错而不是静默留下无用列。
ALTER TABLE user_quick_commands DROP COLUMN label;
