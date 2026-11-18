-- 035：审计日志哈希链（P2-11）——把「防误改」升级为「改过就一定看得出来」。
--
-- 030 的触发器只能挡住**经 SQL 接口**的 UPDATE/DELETE；能写库文件的 root 进程
-- 可以直接 DROP TRIGGER 再改，或干脆用 sqlite3 打开文件改。那种情况下 030
-- 一声不吭，事后无从发现。本迁移补上**可检测性**：
--
--   每条记录携带 prev_hash（上一条的链值）与 hash：
--     hash = HMAC-SHA256(key = master.key, msg = id|ts|actor|actor_ip|action|
--                        target|result|detail_json|prev_hash)
--
-- 于是篡改任意一条的字段、删除或插入一条，都会让**后一条的 prev_hash 对不上**，
-- 且因为密钥在 memfd（不落盘、不在库里），改完数据也**无法重算**出合法的链值。
--
-- 边界（诚实）：这不是区块链，也不防「连库里所有行一起删光」（那时的检测信号是
-- 「链尾锚点对不上」，见 audit_hash_anchor 表——它记在**另一张表**里，root 若把
-- 两张表都清空属于彻底擦除，检测手段应转向异机备份/外部告警）。
--
-- 老数据：既有行的 prev_hash / hash 存 NULL。**不回填**——回填需要密钥在迁移期
-- 可用，而迁移在 serve 启动早期执行、此时 master.key 未必已加载；更重要的是
-- 回填会让"迁移前的历史"与"迁移后的链"混成一条，反而掩盖了真正的分界点。
-- 校验逻辑因此必须以「第一条 prev_hash 非 NULL 的行」作为链起点。

ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN hash      TEXT;

-- 链尾锚点：只保留一行（id 恒为 1），记录当前链尾的 id 与 hash。
-- 用途：即使 audit_log 的尾部被整段删除，锚点仍指向"曾经到过哪一条"，
-- 比对时立刻发现缺口。清理任务在 prune 之后同步收敛锚点（见 cleanup::prune_audit）。
CREATE TABLE audit_hash_anchor (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    last_id   INTEGER NOT NULL,
    last_hash TEXT    NOT NULL,
    updated_ts INTEGER NOT NULL
);

-- 未启用哈希链的库（老库升级后、或 master.key 缺失的部署）锚点是空表，
-- 校验端点会如实回答「未启用」，绝不假装校验通过。
