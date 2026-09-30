-- v7：备份远端存储（WebDAV / S3 兼容）
--
-- 动机：本地备份挡不住"整机没了"——磁盘故障、误删、机房事故会把备份一起带走。
-- 备份的价值有一半在"异地"，而此前只有本地目录。
--
-- 设计取舍：
-- 1) 走 curl（`Bin::Curl`，cmd 唯一出口）而**不引 HTTP 客户端 crate**：
--    依赖预算只剩 1 位；且 curl 自带 `--aws-sigv4`，S3 签名不必自己实现
--    （手写 SigV4 是典型的高风险重复劳动）。
-- 2) 凭据**加密存储**（主密钥 AES-256-GCM，与 DB 口令同一套），绝不落明文。
--    远端凭据泄露等于把备份仓库的钥匙交出去，这一条没有商量余地。
-- 3) 远端**不做独立裁剪**：本地按 keep_count 裁剪时，同步删除远端同名对象。
--    这样不需要 LIST 能力（WebDAV PROPFIND 与 S3 ListObjects 得各写一套），
--    而"远端清单 == 本地清单"本身就是更可控的语义——用户不会遇到
--    "远端悄悄堆了几百个旧备份"这种事。

ALTER TABLE backup_jobs ADD COLUMN remote_kind       TEXT;     -- NULL | webdav | s3
ALTER TABLE backup_jobs ADD COLUMN remote_url        TEXT;     -- webdav: 目标目录 URL；s3: endpoint
ALTER TABLE backup_jobs ADD COLUMN remote_bucket     TEXT;     -- s3: bucket 名
ALTER TABLE backup_jobs ADD COLUMN remote_prefix     TEXT;     -- s3: key 前缀（可空）
ALTER TABLE backup_jobs ADD COLUMN remote_region     TEXT;     -- s3: region
ALTER TABLE backup_jobs ADD COLUMN remote_user       TEXT;     -- webdav 用户名 / s3 access key
ALTER TABLE backup_jobs ADD COLUMN remote_secret_enc BLOB;     -- 主密钥加密的密码 / secret key
