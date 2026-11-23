-- v38：预置几条常用任务模板
--
-- 目的：新建计划任务时最常见的就是「备份 / 清理 / 健康检查 / 证书续期」这几类，
-- 让用户开箱就有可选的起点，而不是面对一张空表单。
--
-- 三条落地原则：
--
-- 1. **命令一律是占位示例**，不写「填完就能跑」的真实破坏性命令。
--    例如清理模板写成 `--dry-run` 形式的示例而非直接 `find … -delete`：
--    模板会被一键填进表单，用户容易直接点创建，那么「误删」的成本就由模板承担了。
--    占位符用 `--target=` 这种显式待替换的形式，一眼能看出哪里要改。
--
-- 2. **不预填 webhook_url，用户统一 root**。Webhook 是环境私有地址，预填等于
--    让所有实例都往同一个不存在的地址 POST；执行用户预填 root 是运维任务的常态，
--    且模板可编辑。
--
-- 3. **INSERT OR IGNORE + 不钉 id**：靠 `name` 的 UNIQUE 约束做幂等。
--    · 老库升级时若用户已经手建了同名模板，这里静默跳过（不覆盖用户的编辑）；
--    · id 交给自增，避免与用户已有模板的 id 冲突。
--
-- 表达式刻意用「错峰」的分钟值（3:10 / 3:40 / 每 5 分钟……），避免四条模板
-- 若同时被启用时在同一分钟一拥而上。

INSERT OR IGNORE INTO cron_templates
    (name, description, expr, command, user, timeout_sec, webhook_url, created_at, updated_at)
VALUES
    ('每日备份数据库',
     '每天凌晨 3:10 备份；把 mysqldump 换成实际数据库客户端的导出命令',
     '10 3 * * *',
     '/usr/bin/mysqldump --single-transaction --all-databases > /var/backups/db/all.sql',
     'root', 3600, NULL,
     CAST(strftime('%s','now') AS INTEGER), CAST(strftime('%s','now') AS INTEGER)),

    ('清理过期临时文件',
     '每天凌晨 3:40 清理临时目录；先去掉 -delete 跑一次确认范围',
     '40 3 * * *',
     '/usr/bin/find /tmp -maxdepth 2 -type f -mtime +7 -delete',
     'root', 600, NULL,
     CAST(strftime('%s','now') AS INTEGER), CAST(strftime('%s','now') AS INTEGER)),

    ('磁盘使用率检查',
     '每 5 分钟记录一次根分区余量；阈值判断按需改造成告警脚本',
     '*/5 * * * *',
     '/usr/bin/df -h / --output=pcent,avail',
     'root', 120, NULL,
     CAST(strftime('%s','now') AS INTEGER), CAST(strftime('%s','now') AS INTEGER)),

    ('服务健康探测',
     '每 10 分钟探测一次本机 HTTP 健康接口；端口与路径换成实际值',
     '*/10 * * * *',
     '/usr/bin/curl -fsS --max-time 5 http://127.0.0.1:8080/healthz',
     'root', 60, NULL,
     CAST(strftime('%s','now') AS INTEGER), CAST(strftime('%s','now') AS INTEGER)),

    ('每周日志轮转',
     '每周一凌晨 4:20 轮转并压缩应用日志；--log-dir 换成实际目录',
     '20 4 * * 1',
     '/usr/bin/logrotate --state=/var/lib/logrotate/custom.state /etc/logrotate.custom.conf',
     'root', 1800, NULL,
     CAST(strftime('%s','now') AS INTEGER), CAST(strftime('%s','now') AS INTEGER));
