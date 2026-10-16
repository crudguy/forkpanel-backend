-- 027：拦截事件（WAF 页「威胁日志」的数据源）。
--
-- 采集器周期性读取「开了独立 access log」的站点日志，把被拦截/拒绝的请求
-- （HTTP 403 / 405 / 429）解析成结构化事件落库，供 WAF 页查询展示。
--
-- 设计取舍：
-- - **append-only 事件表 + 按站点的采集偏移表**：采集增量、断点续传；偏移记的是
--   "已读字节数"，只推进到最后一个完整行，半行留给下一轮（避免截断的跨轮行）。
-- - **不做规则级归因**（如实边界）：WAF 规则 / 敏感文件拒绝 / IP 黑名单在 nginx 与
--   caddy 里都返回同色 403，access log 无标记可区分——要归因需改渲染加日志标记，
--   属另一片、有 config 风险。故这里只存状态码，UI 诚实说明"无法区分是哪条规则"。
-- - 保留策略：采集时顺带 DELETE 超过保留期的旧事件，防无界增长（镜像清理类任务思路）。
-- - 时间用 unix 秒（nginx time_local 已转 UTC）；IP/method/uri/ua 取自 combined 格式。
CREATE TABLE block_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site        TEXT    NOT NULL,
    ts          INTEGER NOT NULL,
    remote_addr TEXT    NOT NULL DEFAULT '',
    method      TEXT    NOT NULL DEFAULT '',
    uri         TEXT    NOT NULL DEFAULT '',
    status      INTEGER NOT NULL,
    referer     TEXT    NOT NULL DEFAULT '',
    user_agent  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_block_events_site_ts ON block_events(site, ts);
CREATE INDEX idx_block_events_ts ON block_events(ts);

-- 采集偏移：每站点已消费到的字节偏移（增量采集、断点续传）
CREATE TABLE block_collect_offset (
    site   TEXT PRIMARY KEY,
    offset INTEGER NOT NULL DEFAULT 0
);
