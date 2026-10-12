-- 022: 对象说明（备注）字段 + 容器/本机备注引用表
--
-- 三类「备注」的存储策略（见设计文档）：
--   1) 对象说明（一对一、常驻）：直接加列到主表 —— sites / db_connections。
--   2) 容器备注：容器是 Docker 实时列举、不入库，故用引用表按容器 id 存。
--   3) 本机说明：单机面板没有 hosts 表，用单例 server_note 表（id 恒为 1）。

-- ⚠ 存量行兼容：ADD COLUMN 必须带 `NOT NULL DEFAULT ''`——不带默认值时
-- SQLite 对既有行填 NULL，而 Rust 侧按 String 读（`r.get::<_, String>`），
-- 列表端点会在老库上直接 InvalidColumnType 500。带默认值则存量行读回 ''。
ALTER TABLE sites ADD COLUMN remark TEXT NOT NULL DEFAULT '';
ALTER TABLE db_connections ADD COLUMN remark TEXT NOT NULL DEFAULT '';

CREATE TABLE container_remarks (
    name    TEXT PRIMARY KEY,
    remark  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_container_remarks_name ON container_remarks(name);

CREATE TABLE server_note (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    content TEXT NOT NULL DEFAULT ''
);
INSERT INTO server_note (id, content) VALUES (1, '');
