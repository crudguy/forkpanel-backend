-- v10：证书自动续期开关
--
-- 背景：ACME 证书（Let's Encrypt）有效期只有 90 天，靠人记得手动点「续期」必然
-- 会漏——漏了就是站点 HTTPS 直接不可用。所以到期前自动续是**刚需**，不是锦上添花。
--
-- 语义边界（必须写清楚，否则会变成"假开关"）：
-- 1) 仅 `source='acme'` 的证书可开启。selfsigned / manual 没有可交互的 CA，
--    根本无法自动续期，给它们开关就是"能点但必失败"的假按钮；
-- 2) 开关本身**不代表已经在续**——真正的续期由内部周期任务 `cert.renew_check`
--    执行（每天扫一次，命中 30 天内到期者才提交续期任务）。能力位 `ssl.acme`
--    不可用（certbot 缺失）时该任务会跳过，UI 需据此显示"不可用"而非"已关闭"；
-- 3) 默认 0（关）。ACME **新签发**的证书由代码显式置 1（见 sites.rs 入库处），
--    既有行保持 0，不擅自替用户打开开关。

ALTER TABLE ssl_certs ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0;
