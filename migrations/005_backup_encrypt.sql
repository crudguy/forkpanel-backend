-- v5：备份产物可选静态加密
--
-- 动机：备份常被同步到对象存储、另一台机器、或运维的笔记本上，其中可能包含
-- 数据库口令与用户数据。明文 tar 一旦泄露就是**直接可读**的，而备份往往比
-- 生产库本身散落得更广。
--
-- 加密复用 panel_core::crypto 的 AES-256-GCM（分块容器，见 panel-os/backup.rs），
-- 主密钥来自 /var/lib/forkpanel/master.key 且**不落库**——因此即使库文件泄露，
-- 也解不开产物。
--
-- 默认 0（不加密）：加密会抬高恢复门槛（主密钥丢失 = 备份全废），
-- 这个取舍必须由用户显式选择，不该替他决定。

ALTER TABLE backup_jobs ADD COLUMN encrypt INTEGER NOT NULL DEFAULT 0;
