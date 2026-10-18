# 环境变量

面板在**运行期**读取的环境变量集中在此。都不设置时全部走默认值——默认值即
「本地开发 / 单机自托管」的合理姿态。

> 配置项（监听地址、目录、TLS、会话时长、只读模式基线…）走 `config.toml`，
> 不读环境变量；见 `deploy/config.toml` 与 `docs/deployment.md`。
> 本文每一行都对着源码核过（`grep -rn 'env::var' crates/`），没有凭印象写的条目。

## 运行期

| 变量 | 取值 | 默认 | 影响面 |
|---|---|---|---|
| `PANEL_READ_ONLY` | `1` = 开，其它值 = 关 | 关 | 开启后所有写请求（POST/PUT/PATCH/DELETE）返回 `403`（`code 10007`），Web 终端入口同样拒绝。与 `config.toml` 的 `[security] read_only` 是**或**的关系——任一为真即开（`panel_api::read_only_from`） |
| `PANEL_HSTS` | `1` = 开 | 关 | 响应下发 `Strict-Transport-Security` 头。仅公网 / TLS 部署才开：本地 http 监听时开，会让浏览器缓存后无法访问 |
| `PANEL_TLS` | `1` = 开 | 关 | 会话 cookie 加 `Secure` 属性。面板经 TLS（自身或前置反代）对外服务时才开 |
| `PANEL_SSHD_CONFIG` | 文件绝对路径 | `/etc/ssh/sshd_config` | 安全基线页读取并解析的 sshd 主配置路径；测试与非标准部署可用它指向别处 |
| `RUST_LOG` | `tracing` 过滤器语法 | `info` | 日志级别与按模块过滤，如 `debug`、`panel_api=debug,info` |
| `PANEL_WEB_DIST` | 目录路径 | `web/dist` | **仅 `dev-assets` 特性构建**生效：前端静态资源从磁盘读取而非打进二进制。改前端后免重编后端 |
| `HOME` | 目录 | `/root` | 注入 Web 终端的 PTY 会话（没有它 `~` 不展开、`cd` 无默认目录）；同时作为终端的起始目录 |
| `USER` | 用户名 | `root` | 注入 PTY 会话；systemd 类计划任务的执行身份 |
| `SHELL` | 可执行文件路径 | `/usr/bin/<探测到的 shell>` | PTY 会话默认启动的 shell |

## 编译期

| 变量 | 说明 |
|---|---|
| `PANEL_BUILD` | `option_env!` 读取，出现在 `GET /api/v1/version` 的 `build` 字段。CI 可注入 commit / 流水线号；本地不设为 `dev` |

## 曾被注释提及、但**并不存在**的变量

`PANEL_MASTER_KEY` —— `panel-core/src/crypto.rs` 的注释曾声称主密钥可来自该环境
变量，实际代码从未读取（注释已修）。主密钥只来自 `<data_dir>/master.key`（0600，
`init` / `serve` 时生成、内存常驻），**不读环境变量、不落库**。

## 相关

- 高危并发上限（Web 终端 4 路）目前是编译期常量，靠注释与前端 `MAX_TABS=4`
  手工对齐——属审计 P2-5 待办（计划由 `/api/v1/capabilities` 下发，消除两处 4
  漂移的风险）。
