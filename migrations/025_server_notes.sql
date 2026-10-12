-- 025: 本机便签改多条（server_note 单例 → server_notes 列表）
--
-- 起因：单例便签逼用户把「运维禁忌 / 网络变更 / 待办」混进一段 500 字，
-- 首页编辑框撑到八行还得手动拖（已另做 auto-grow，但单条 500 字的天花板
-- 仍在）。改为多条独立便签，每条仍是轻量说明。
--
-- 数据保迁：旧单例内容整体迁入为第一条（id 固定 1），存量数据不丢；
-- 空内容（纯空白）不迁——空便签没有意义，迁入只会得到一条占位空行。
-- created_at/updated_at 取迁移时刻：便签时间戳是展示信息而非审计数据，
-- 原单例表本就没有时间列，无从恢复更精确的值。
--
-- 旧表 server_note 迁后即无引用，DROP 消除「到底该读哪张表」的歧义
-- （025 之前的二进制在新库上会因缺表报错——单向升级，属预期）。

CREATE TABLE server_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    content    TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT INTO server_notes (id, content, created_at, updated_at)
    SELECT 1, content,
           CAST(strftime('%s', 'now') AS INTEGER),
           CAST(strftime('%s', 'now') AS INTEGER)
    FROM server_note
    WHERE id = 1 AND TRIM(content) <> '';

DROP TABLE server_note;
