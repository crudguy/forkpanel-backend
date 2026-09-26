-- 001_init.sql —— 初始 schema
--
-- 说明：
-- 1. journal_mode/synchronous 等 PRAGMA 由 Rust 启动时设置（不能在事务内执行），见 db::open()。
-- 2. 体积预算依据实测（见《量化假设实测附录》）：
--    - metrics_1m（7 天）≈ 544 KB，metrics_1h（90 天）≈ 124 KB，合计 < 1 MB
--    - audit_log（90 天 × 50 条/天）≈ 360 KB；180 天 × 200 条/天 ≈ 4.12 MB（默认不采用）
--    - 稳态总库目标 ≤ 8 MB（nano 档）
-- 3. 每行指标约 55 字节；每行审计约 120 字节。

PRAGMA foreign_keys = ON;

-- ─────────────── 身份与授权 ───────────────

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    pwd_hash      TEXT    NOT NULL,             -- argon2id 编码串
    role          TEXT    NOT NULL DEFAULT 'operator',  -- owner|admin|operator|viewer
    allowed_roots TEXT    NOT NULL DEFAULT '[]',        -- JSON 数组，目录作用域
    mfa_secret_enc BLOB,                        -- 主密钥加密
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE sessions (
    id           INTEGER PRIMARY KEY,
    sid_hash     TEXT    NOT NULL UNIQUE,       -- 只存哈希
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip           TEXT,
    ua           TEXT,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_exp  ON sessions(expires_at);

CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    token_hash   TEXT    NOT NULL UNIQUE,
    scopes       TEXT    NOT NULL,              -- JSON 数组，权限点子集
    allowed_cidr TEXT    NOT NULL DEFAULT '[]',
    expires_at   INTEGER,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);

-- ─────────────── 审计（只追加，禁止 UPDATE/DELETE 除清理任务外） ───────────────

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    actor       TEXT    NOT NULL,
    actor_ip    TEXT,
    action      TEXT    NOT NULL,
    target      TEXT,
    result      TEXT    NOT NULL,               -- ok|denied|error
    detail_json TEXT                            -- 截断至 ≤ 2KB；大对象写入任务输出文件
);
CREATE INDEX idx_audit_ts     ON audit_log(ts);
CREATE INDEX idx_audit_actor  ON audit_log(actor);
CREATE INDEX idx_audit_action ON audit_log(action);
-- 保留策略：默认 90 天 + 单表 5 万行上限（settings.audit_retention_days 可覆盖为 180，需提示体积）
-- 清理分档（实测结论）：≤5 万行一次性 DELETE；5~50 万 LIMIT 5000；>50 万 LIMIT 10000

-- ─────────────── 站点与证书 ───────────────

CREATE TABLE sites (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    domains    TEXT    NOT NULL,                -- JSON 数组
    root       TEXT    NOT NULL,
    kind       TEXT    NOT NULL,                -- static|reverse_proxy
    webserver  TEXT    NOT NULL DEFAULT 'nginx',
    enabled    INTEGER NOT NULL DEFAULT 1,
    conf_path  TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE ssl_certs (
    id           INTEGER PRIMARY KEY,
    site_id      INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    domains      TEXT    NOT NULL,
    issuer       TEXT,
    not_after    INTEGER,
    source       TEXT    NOT NULL,              -- acme|manual|selfsigned
    key_enc      BLOB    NOT NULL,              -- 主密钥加密的私钥
    cert         TEXT    NOT NULL,
    renew_state  TEXT    NOT NULL DEFAULT 'idle',
    last_error   TEXT,
    created_at   INTEGER NOT NULL
);
CREATE INDEX idx_certs_expiry ON ssl_certs(not_after);

-- ─────────────── 数据库与备份 ───────────────

CREATE TABLE db_connections (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    engine      TEXT    NOT NULL,               -- sqlite|mysql|postgres
    host        TEXT,
    port        INTEGER,
    username    TEXT,
    password_enc BLOB,                          -- 主密钥加密
    default_db  TEXT,
    tls_mode    TEXT    NOT NULL DEFAULT 'prefer'
);

CREATE TABLE backup_jobs (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL,               -- db|site|panel
    target      TEXT    NOT NULL,
    cron_expr   TEXT,
    keep_count  INTEGER NOT NULL DEFAULT 7,
    dest_dir    TEXT    NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run_at INTEGER,
    last_result TEXT
);

-- ─────────────── 计划任务 ───────────────

CREATE TABLE cron_jobs (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    expr         TEXT    NOT NULL,
    kind         TEXT    NOT NULL,              -- script|backup|cert_renew|internal
    payload_json TEXT    NOT NULL DEFAULT '{}',
    enabled      INTEGER NOT NULL DEFAULT 1,
    timeout_sec  INTEGER NOT NULL DEFAULT 1800,
    last_run_at  INTEGER,
    last_status  TEXT
);

-- ─────────────── 任务中心 ───────────────

CREATE TABLE task_runs (
    id           INTEGER PRIMARY KEY,
    task_id      TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    state        TEXT    NOT NULL,              -- queued|running|ok|failed|canceled|interrupted
    progress     INTEGER NOT NULL DEFAULT 0,
    started_at   INTEGER,
    finished_at  INTEGER,
    exit_code    INTEGER,
    output_path  TEXT                           -- 输出写入文件而非 DB（避免膨胀）
);
CREATE INDEX idx_tasks_state ON task_runs(state);
CREATE INDEX idx_tasks_start ON task_runs(started_at);

-- ─────────────── 指标（分层存储，严禁写入 1s 原始点） ───────────────

CREATE TABLE metrics_1m (
    ts          INTEGER PRIMARY KEY,            -- 对齐到分钟
    cpu_pct     REAL    NOT NULL,
    mem_used_kib INTEGER NOT NULL,
    mem_total_kib INTEGER NOT NULL,
    swap_used_kib INTEGER NOT NULL DEFAULT 0,
    disk_used_bytes INTEGER NOT NULL DEFAULT 0,
    disk_total_bytes INTEGER NOT NULL DEFAULT 0,
    net_in_bps  INTEGER NOT NULL DEFAULT 0,
    net_out_bps INTEGER NOT NULL DEFAULT 0,
    load1       REAL    NOT NULL DEFAULT 0
);
-- 保留 7 天（10080 行 ≈ 544 KB）；nano 档位不落盘，仅内存环形缓冲

CREATE TABLE metrics_1h (
    ts          INTEGER PRIMARY KEY,            -- 对齐到小时
    cpu_pct     REAL    NOT NULL,
    mem_used_kib INTEGER NOT NULL,
    mem_total_kib INTEGER NOT NULL,
    swap_used_kib INTEGER NOT NULL DEFAULT 0,
    disk_used_bytes INTEGER NOT NULL DEFAULT 0,
    disk_total_bytes INTEGER NOT NULL DEFAULT 0,
    net_in_bps  INTEGER NOT NULL DEFAULT 0,
    net_out_bps INTEGER NOT NULL DEFAULT 0,
    load1       REAL    NOT NULL DEFAULT 0
);
-- 保留 90 天（2160 行 ≈ 124 KB）

-- ─────────────── 设置与迁移 ───────────────

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
INSERT INTO settings(key, value_json) VALUES
    ('tier', '"auto"'),
    ('audit_retention_days', '90'),
    ('audit_max_rows', '50000'),
    ('metrics_retention_1m_days', '7'),
    ('metrics_retention_1h_days', '90'),
    ('session_idle_timeout', '"30m"'),
    ('max_login_attempts', '5'),
    ('read_only', 'false');

CREATE TABLE schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL,
    checksum   TEXT    NOT NULL
);
INSERT INTO schema_migrations(version, applied_at, checksum) VALUES
    (1, strftime('%s','now'), '001_init');
