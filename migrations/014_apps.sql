-- v14：面板托管的应用（systemd 单元 + 自动反代站点）
--
-- 设计要点：
-- 1) **一行 = 一个由面板拉起的进程**。面板只负责「把进程按 systemd 起来」，
--    构建与依赖安装仍由用户在项目目录自行完成（构建步骤只在前端做提示，不落库）。
-- 2) `runtime` 只描述「怎么把进程拉起来」，**不改变 nginx 的接入方式**：所有运行时
--    一律走反向代理（`proxy_pass http://127.0.0.1:<port>`）。因此本表与 `sites` 的分工
--    是正交的——`sites.kind` 管接入协议，`apps.runtime` 管进程怎么起。
-- 3) 反代站点由面板自动创建/维护，名与本表 `name` 相同（站点的 upstream 指向本表 port）。
--    域名存这里而非复用 sites.domains，因为「应用」是真相源、站点是它的投影。
-- 4) `env_json` / `domains_json` 用 JSON 数组存，避免再开两张关联表——面板的场景里
--    这两者都是「随应用整体读写」的短列表，没有独立查询需求。

CREATE TABLE apps (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL UNIQUE,            -- 应用名（同时派生 systemd 单元名与反代站点名）
    runtime      TEXT    NOT NULL,                   -- node|go|java|python|dotnet|php|custom
    workdir      TEXT    NOT NULL,                   -- 工作目录（绝对路径，须已存在，否则 systemd CHDIR 失败）
    exec_start   TEXT    NOT NULL,                   -- 启动命令（进 systemd ExecStart=）
    run_user     TEXT,                               -- 运行用户；NULL = root
    env_json     TEXT    NOT NULL DEFAULT '[]',      -- JSON 数组 [[k,v], ...]
    port         INTEGER NOT NULL,                   -- 监听端口（反代目标 + 页面展示）
    auto_restart INTEGER NOT NULL DEFAULT 1,         -- 崩溃自动重启（Restart=always）
    enabled      INTEGER NOT NULL DEFAULT 1,         -- 1=已托管并运行（单元已装+站点已下发）0=已停用
    domains_json TEXT    NOT NULL DEFAULT '[]',      -- 自动反代站点的域名 JSON 数组
    created_at   INTEGER NOT NULL
);
