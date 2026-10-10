-- 018: 站点配置版本历史（回滚的「记忆」）
--
-- 背景：在此之前，「站点配置」只有"现状"没有"过去"——手动保存改坏了、
-- 「按表单重新生成」覆盖错了，唯一的兜底是 conf-backups/ 下按时间堆的
-- 裸 `.bak` 文件（还得上服务器翻文件名猜内容）。本迁移给配置一条带元数据
-- 的版本链：每次落盘自动留档，页面上一键查看与回滚。
--
-- 字段：
--   content  = 完整配置文本（含 ForkPanel 头注释）
--   hash     = content 的 SHA-256（十六进制）——去重与「当前版本」标记用
--   fingerprint = 该版内容对应的「部署指纹」（017 conf_snapshot 同口径；可空）：
--              apply/regen 版 = 当次新指纹；manual 版 = 保存时的表单指纹；
--              rollback 现场留档 = 当时的 conf_snapshot（可能为 NULL）。
--              回滚定态判定用：版指纹 == 当前表单指纹 ⇒ 内容是表单产物 ⇒ 回托管
--   source   = 写入口：apply（表单下发）/ regen（按表单重新生成）/
--              manual（手动保存）/ rollback（回滚前的现场留档）
--   operator = 触发的用户名（与审计日志同源）
--
-- 去重规则（应用层，panel-api sites.rs archive_conf_version）：
-- 与**最新版**内容相同（hash 相等）不重复入库——反复「保存并应用」
-- 不会堆出一串一模一样的版本。保留上限：每站最新 20 版（写入后立即裁剪）。
--
-- site_id 挂 ON DELETE CASCADE：删站点时版本链一并清掉（与 ssl_certs 同范式，
-- 连接层已 `PRAGMA foreign_keys=ON`，见 panel-db lib.rs 的 open()）。
CREATE TABLE IF NOT EXISTS site_conf_versions (
    id          INTEGER PRIMARY KEY,
    site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    content     TEXT    NOT NULL,
    hash        TEXT    NOT NULL,
    fingerprint TEXT,
    source      TEXT    NOT NULL,
    operator    TEXT    NOT NULL,
    created_at  INTEGER NOT NULL
);
-- 主查询形态：取某站最新 N 版（WHERE site_id=? ORDER BY id DESC）
CREATE INDEX IF NOT EXISTS idx_site_conf_versions_site
    ON site_conf_versions(site_id, id DESC);
