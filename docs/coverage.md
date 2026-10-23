# ForkPanel（叉叉面板）· §3.4 接口契约覆盖矩阵

> 来源：设计文档 `轻量Linux服务器管理面板设计方案.md` → §3.4 关键接口约定（核心路由表）。
> 目的：证明前后端分离后，文档所列接口已**全量接线**，并如实标注实现状态。
> 判定方法：后端 `crates/panel-api/src/routes*.rs` 中凡返回 `ApiError::unsupported("…(Mx: …)")` 者记为「🟡 结构化 501」；
> 其余返回 `ok(...)/Json(...)` 者记为「✅ 已实现」。前端是否调用由契约门禁校验（PASS）。
>
> **本版为 2026-09-30 刷新**：P0（站点/SSL、数据库、用户）与 P1（容器、安全基线、备份、日志 SSE）、
> P2（终端、AI 助手）已落地；本机不可验项（ACME/caddy/mysql-pg/ufw 真机）如实标注。

## 图例

| 标记 | 含义 |
|---|---|
| ✅ | 已实现：handler 返回真实数据或 `202 {task_id}` |
| 🟡 | 结构化 501：按里程碑（M2/M3/M4/M5）尚未实现，返回 `ApiError::unsupported("…(Mx: 说明)")`，**绝不伪造数据** |
| 🟠 | 已实现但**本沙箱不可真机验证**（依赖 nginx/ufw/公网等），能力位诚实置灰 |
| 🔵 | 契约超集：§3.4 未列出但已写入 `endpoints.ts` 契约表面，供后续扩展 |

## 1. 认证与 CSRF

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| POST `/auth/login` | 登录 + Set-Cookie | ✅ | 登录限速 + 一次性引导令牌首启向导 | LoginView |
| POST `/auth/logout` | 清会话 | ✅ | | auth store |
| GET `/auth/me` | 当前用户/权限/能力 | ✅ | | auth store |
| POST `/auth/password` | 改密（需 CSRF） | ✅ | **曾为假桩已修**：真校验 old + argon2 档位哈希 + 单写事务更新 + 吊销该用户其他会话；凭据错返回 400（非 401，避免前端误登出） | SettingsView |

## 2. 系统 / 监控 / 指标

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/system/capabilities` | 能力矩阵（驱动 UI 灰态） | ✅ | 含诚实降级原因（daemon_unreachable 等） | 各视图 |
| GET `/system/overview` | 一次性快照卡片 | ✅ | | DashboardView |
| GET `/metrics/realtime` | 最近 N 秒环形缓冲 | ✅ | | DashboardView |
| GET `/metrics/history` | 历史区间 | ✅ | | ProfessionalView |
| GET `/version` | 版本协商 | ✅ | | — |

## 3. 进程

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/processes` | 进程列表（排序/分页） | ✅ | | ProcessesView |
| POST `/processes/{pid}/kill` | 终止进程（term/hup/kill） | ✅ | 信号可选 | ProcessesView |

## 4. 服务 / 软件

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/services` + start/stop/restart/enabled/journal/config 全套 | 服务管理 | ✅ | journal/config 读写含 drop-in 建议 | ServicesView |
| GET `/packages` + install/remove | 软件安装（→202 task） | ✅ | | ServicesView |

## 5. 站点 / 证书（SSL）——#44/#58/#59/#60 落地

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/sites` / POST `/sites` / POST `/sites/apply` | 站点列表/新建/配置下发 | ✅ / ✅ / 🟠 | apply 走 nginx render→validate→deploy→reload；**本沙箱无 nginx**，真机验证 | SitesView |
| GET/PATCH/DELETE `/sites/{id}` | 单体详情/更新/删除 | ✅ | 删除级联证书与磁盘 | SitesView |
| POST `/sites/{id}/reload` | 重载 | 🟠 | `nginx -s reload`→回退 systemctl；沙箱不可验 | SitesView |
| GET `/sites/{id}/logs` | 访问/错误日志 | ✅ | **SSE**（#59 并入日志实时流） | SitesView |
| POST `/sites/{id}/ssl/apply` | 证书签发 | ✅ | **self-signed 同步签发**（openssl，key 经主密钥加密落盘 0600）；`method=http-01` → ✅ 走 certbot 任务（需账户邮箱，仅签主域名）；`method=dns-01` → 🟡 需 DNS 提供商 API（M5） | SitesView |
| GET `/certs` / POST `/certs/{id}/renew` / DELETE `/certs/{id}` | 证书列表/续期/删除 | ✅ | 续期=自签重签；删除连磁盘文件清理 | SitesView |

## 6. 文件

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/files/list` / `read` / `write` / mkdir/delete/rename/chmod | 浏览/读写/单项操作 | ✅ | 写自动 .bak | FilesView |
| GET `/files/stat` | 独立 stat | ✅ | kind/size/mode/owner/mtime | FilesView |
| PUT `/files/upload` | 上传（octet-stream） | ✅ | 原子替换；上限 min(100MB, 平台上限)；目标为目录 400；**owner 空 allowed_roots 特判放行全盘（敏感黑名单兜底）** | FilesView（多选上传） |
| GET `/files/download` | 下载 | ✅ | attachment 头 + RFC5987 文件名；目录 400；上限同上传 | FilesView（行内下载） |
| POST `/files/action` | 批量 move/copy/delete/chmod | ✅ | 逐项执行逐项报告（部分失败 200）；**同名冲突不静默覆盖**；≤100 项/批 | FilesView（多选批量条） |

## 7. 数据库——#45/#62/#63 落地

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET/POST `/db/connections` | 连接管理 | ✅ | **schema 对齐修复**：列名 `default_db`（原代码引用不存在的 `database` 列，CRUD 从未跑通） | DatabasesView |
| GET `/db/{conn}/databases` | 库列表 | ✅ | SQLite 只读打开 | DatabasesView |
| GET `/db/{conn}/{db}/tables` | 表列表（含行数） | ✅ | mysql/pg ✅（客户端存在即启用；密码经 `MYSQL_PWD`/`PGPASSWORD` 传，**绝不进 argv**；行数取不到给 -1 不伪造） | DatabasesView |
| GET `/db/{conn}/{db}/{table}/rows` | 行预览（分页，禁 Web SQL） | ✅ | NULL 保真；缺表/连接优雅 404；mysql/pg ✅（客户端模式下 NULL 与空串无法区分，一律按文本返回，**不伪造 NULL 语义**） | DatabasesView |
| POST `/db/{conn}/backup` | 备份（→202 task） | ✅ | **VACUUM INTO 不可在写者事务内**——改独立连接备份（根因修复） | DatabasesView |
| 🔵 POST `/db/{conn}/restore` | 恢复 | ✅/🟡 | 三引擎均已实装（任务化：确认词 + 源文件沙箱校验 + **非 sqlite 先导出当前态快照**）。**PG ✅ 真机闭环验证（2026-10-22，PG 17.11：备份→漂移→恢复，数据逐行对上）**；mysql 🟡（开发机无 `mysqldump`，导出/导入路径未真机跑过）；SQLite ✅（provider 内 `.bak-<ts>` 快照） | — |

## 8. 防火墙

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/firewall/status` / rules / enabled 增删 | ufw 全套 | 🟠 | 已实装（编号规则/仅面板自建可删）；**本沙箱无 ufw**，能力位诚实置灰，真机验证 | FirewallView |

## 9. 安全——#48 落地

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/security/baseline` | 基线检查 | ✅ | 6 项只读检查；OpenSSH 默认值语义已修正并有单测 | SecurityView |
| POST `/security/baseline/apply` | 应用基线 | ✅ | 已实装（**仅限 sshd 三项白名单**）：确认词 + 先备份 → 写 → `sshd -t` 校验 → 不通过回滚；**sshd 不可用则拒绝修改**（宁可不修也不锁死 SSH） | SecurityView |
| GET `/security/sessions` | 在线会话 | ✅ | 内存 SessionCache 快照（重启即清零，如实标注）；`current` 标记自己；**ip 刻意不采集**（无对端地址管道，返回 null 不伪造） | SecurityView |
| DELETE `/security/sessions/{id}` | 吊销会话 | ✅ | 允许吊销自己的当前会话（=自我登出）；404 对不存在会话；审计只落 sid 前 8 位（sid=凭据不落库） | SecurityView |

## 10. 计划任务（cron）

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET/POST `/cron/jobs` + PATCH/DELETE/`run`/`runs` | 全套 | ✅ | run 走任务队列 | CronView |
| POST `/cron/preview` | 下次 5 次预览 | ✅ | 委托 provider `next_fire_times`（**顺手修掉本地时区漂移 bug**：civil 字段原按 UTC 取，东八区预览差 8 小时；现经 libc localtime_r 读 tm_gmtoff，回归测试钉死本地语义）；空 next = 一年内无命中 | CronView（新建/编辑均可预览） |

## 11. 日志——#50 落地

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/logs/sources` / 🔵 `/logs/{id}` | 源/读取 | ✅ | journald + 站点文件源自动发现 | LogsView |
| GET `/logs/stream` | 跟随 | ✅ | **SSE**（journald spawn_stream / 文件轮询 tail，字面量过滤在 Rust 侧） | LogsView（实时跟随开关） |
| GET `/logs/{id}/download` | 日志下载 | ✅ | text/plain 附件（RFC 兼容文件名净化）；与 read 同参（lines/grep/level/since）；行 ≤10_000 且累计 ≤8MB 双上限，超限 X-Capped:1；grep 过滤实测生效 | LogsView（下载按钮，沿用当前过滤） |

## 12. 任务中心

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/tasks` + cancel + output | 列表/取消/输出 | ✅ | | TasksView |
| GET `/tasks/{id}` | 单体详情 | ✅ | 全列 + duration_secs 派生；404 对不存在；**契约 Task schema 已按实态对齐**（id:integer/key/output_path，删掉不存在的 stage）；前端运行中任务每 2s 轮询详情刷进度 | TasksView（弹层轮询） |

## 13. 设置 / 用户 / 审计——#46 落地用户

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/settings` / PATCH `/settings` | 面板设置 | ✅ | **三段诚实模型**：runtime（AI 助手 LLM 三键，api_key 主密钥加密、GET 永不明文）可改即生效；deployment（read_only/tier）只读展示；reserved 种子键如实标注未接线。PATCH 部署级键 400 | SettingsView |
| GET/POST `/users` + PATCH/DELETE `/users/{id}` | 用户管理 | ✅ | 含降级/自操作守卫全套（13 项守卫冒烟通过） | UsersView |
| GET `/audit` | 审计（分页/过滤） | ✅ | | AuditView |

## 14. SSE 事件

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 |
|---|---|---|---|
| GET `/events/{metrics,tasks,logs}` | 多频道 | ✅ | 连接数上限 + 统一 SSE 基座 |

## 15. 新增模块（契约超集，roadmap P1/P2 落地）

| 方法 + 路径 | 模块 | 后端状态 | 备注 |
|---|---|---|---|
| GET `/containers`、`/containers/images`；POST `/{id}/start\|stop\|restart`；DELETE `/{id}` | 容器（#47） | ✅ | 能力位看**守护进程可达性**（socket EACCES→daemon_unreachable 501）；参数注入白名单（禁首字符 `-`）；**创建容器不做**（等价任意代码执行，待专项） |
| GET `/api/v1/terminal`（WS） | Web 终端（#51） | ✅ | PTY 收敛 `spawn_pty`；八道卫士升级前判定；Origin 同源替代 CSRF；空闲 15min SIGHUP；并发 ≤4 |
| POST `/api/v1/assistant/diagnose` | AI 助手（#52） | ✅ | 内置规则诊断（8 规则 + 关键词路由）；只读护栏（action 仅 navigate）；LLM 层待接入 |
| `/api/v1/backups` CRUD + `/{id}/run` + `/{id}/remote/artifacts` + `/{id}/artifacts/{name}` | 备份计划（#49） | ✅ | panel=独立连接快照 / site=tar.gz / **db=按引擎导出（.db / .sql）**；**cron 由 `backup.sweep` 每分钟调度（只推进不补跑）**；**keep_count 自动清理 ✅**；**备份前空间水位检查 ✅**（估算值 + 64 MiB 余量，加密按 2 倍峰值；mysql/pg 估不出则跳过，**查不到可用空间一律放行**）；**产物可下载 ✅**；**远端可读（清单 + 从远端恢复）✅，S3 列表自动翻页 ✅**（ListObjectsV2 单次上限 1000，不翻页会让远端看起来只有 1000 个产物）；**restore ✅**（site 与 db：确认词 + 产物名白名单 + 自动先备份当前态 + 归档逃逸/范围校验；**恢复后校验落盘结果 ✅**（逐条比对归档文件是否真在站点目录下，一个都没落盘/只找回一部分 → 任务置 failed，不静默报成功）；panel 库走 `panel restore-db`，在线恢复仍 🟡）|
| `/api/v1/security/baseline` | 安全基线（#48） | ✅ | 见 §9 |
| GET `/api/v1/backups/system`、`/backups/system/{name}` | 系统自动备份（面板库每日快照） | ✅ | 列表 + 下载（`^panel-[0-9]+\\.db$` 白名单 + canonicalize 父目录校验）；响应回**实际生效**的 `keep`（config.toml `[db] backup_keep`）与 `daily_backup`——此前卡片只写"由 backup_keep 控制"却不给值，改成 3 份的机器上仍在暗示 7；现由后端守卫 + 前端源码守卫双向钉住 |

## 16. 站内通知 / 会话持久化 / MFA（2026-09-30 补齐）

| 方法 + 路径 | 模块 | 后端状态 | 备注 |
|---|---|---|---|
| GET `/notifications`、`/notifications/unread-count`；POST `/{id}/read`、`/read-all`；DELETE `/{id}` | 站内通知 | ✅ | 002 表；`dedup_key` 唯一约束去重。**刻意不做邮件/Webhook**——需 reqwest/lettre，依赖预算上限 38、去重后第三方直接依赖现约 22（`check-layering.sh` [8] 实测）。落点：备份失败（按天去重）、恢复失败（不去重） |
| `sessions` 表落库（001 已定义、此前零引用） | 会话持久化 | ✅ | **只存 sid 哈希**；中间件 `get_or_restore` 惰性重建 → 重启不再全员登出；DB 写入 spawn 到 runtime，绝不持 MutexGuard 跨 await |
| `/auth/mfa/{enroll,verify,disable}` + 登录第二因子 | MFA（TOTP） | ✅ | RFC 6238 HMAC-SHA1（验证器兼容档）+ 10 个恢复码（只存哈希，一次性消费）；**关闭 MFA 必须出示第二因子** |

## 覆盖结论（2026-09-30 三次刷新：P2 批次 + T1~T5）

- **契约完整度：100%**，且新增端点全部**先写契约再实现**（前端副本按事实源同步）。
- **P2 已完成**：
  - **可观测性**：指标温感（hwmon 温度进 `SystemSnapshot.temps`；无 hwmon 的机器返回
    空数组，**不报错也不伪造 0°C**）、日志聚合统计（level 分布 / 时间直方图 / 高频模式；
    无时间戳的源返回空数组，**不按行序伪造分布**）。
  - **数据兜底**：文件回收站（软删除 / 恢复 / 清空。产物是逐条自描述目录 + tar 归档，
    跨分区安全；恢复目标**重走完整沙箱**且**绝不覆盖**同名文件）、
    备份产物**静态加密**（AES-256-GCM 分块容器；主密钥不落库，加密成功才删明文）。
  - **数据库**：只读 SQL 控制台（**仅 SQLite**——只读连接是物理兜底；双层校验 =
    首关键词白名单 + 写关键词黑名单，且先剥注释、抹引号串内容再判定）。
  - **站点**：反向代理 / 负载均衡（`upstream` least_conn，块置于 http 级）、
    PHP（php-fpm）。目标值走**注入防护**（会直接进 nginx 配置文本）。
  - **权限**：自定义角色 RBAC（内置角色由代码定义不落库、防提权子集约束、
    内置名保留、被用户引用的角色不可删除）。
  - **同批并入**：容器创建、cron 防重入（`max_overlap` + flock）与 Webhook 回调、
    fail2ban 接线（由并行工作产出，见对应提交说明）。
- **本轮追加（T1~T5，同日）**：
  - **文件分片续传**：会话式分片 + 断点续传。顺带修掉一个真 bug——分片路由漏挂
    `DefaultBodyLimit`（只加在了单请求上传那条上），4MiB 分片被 axum 默认的 2MiB 上限
    **静默整片拒掉**，症状是"上传永远缺前几片"。
  - **备份远端副本**（WebDAV / S3 兼容，走 `curl --aws-sigv4`，**零新依赖**）：
    凭据加密存储且**永不回显**；远端失败记 `partial` + 告警——**不谎报 ok，也不把
    本地成功翻转为失败**；本地裁剪时按名字同步删远端对象，于是"远端清单 == 本地清单"。
  - **站点 WAF**（SQLi / XSS / 路径穿越 / 敏感文件探测 / 恶意 UA / CC 限速）：
    规则集是**编译期常量**，只开放档位与数值（不开放自定义正则——那等于交出注入面）；
    `map` / `limit_req_zone` 置于 http 级；**`/.well-known` 始终放行**（ACME 挑战文件在那里）。
  - **分层门禁回绿**：[4c] 真修、shell 执行下沉到 `cmd.rs`、[5] 从根上消除；
    新增"带理由的行内豁免"机制并做了三态负向验证。
  - **插件系统设计稿**：`docs/design-plugin-system.md`——**只出设计，未实施**。
- **剩余 🟡 清单**（结构化 501 或如实降级，**均为刻意不做或需外部条件**，不是"来不及做"）：
  - `dns-01`（需 DNS 提供商 API，设计列 M5）；
  - 备份 `kind=panel` 的**在线**恢复（面板库在线覆盖会损坏 SQLite WAL）；停服后可用
  `panel restore-db <产物>` 一条命令恢复（验产物 → 留快照 → 原子替换 → 清 WAL/SHM）；
  **本地盘没了可用 `--remote <计划 id>` 从远端副本取回**（真机验证：WebDAV 上传 → 删本地产物 → 停服 → `--remote` 取回并恢复，服务起得来、数据逐项对上，临时副本无残留）；
  - mysql/pg 的**还原**（需外部客户端写路径）与 **SQL 控制台**——这两个客户端连接
    **不是只读的**，开任意 SQL 入口等于给面板开一个写库的口子，故诚实拒绝，
    而不是"先跑起来再说"；
  - **磁盘 SMART**（需 `smartctl`）与 **GPU 指标**（需 `nvidia-smi`）——按二进制存在性置灰；
  - **日志全文检索（FTS5）**（需 rusqlite 的 FTS5 特性；当前提供的是聚合统计）；
  - **i18n**：属大工程，尚未开工（不是"做了一半"）。
  - **插件系统**：**已有设计稿但未实施**（`docs/design-plugin-system.md`），
    落地需按 M1~M4 分期评审；本文件不把它计入已覆盖。
- **🟠 真机验证项**：nginx 下发/reload、ufw、mysql 真连（postgres ✅ 已于 2026-10-22
  在本机 17.11 实例上端到端验证）、ACME（需公网 80 + certbot）、
  容器创建（需可达的 docker daemon）、fail2ban（需已安装并运行）、加密备份的恢复
  （需主密钥在位）——能力位按二进制/客户端存在性诚实置灰，沙箱内只验证降级路径。
  另：站点 WAF 的**实际拦截效果**需真实承载流量才能验收（配置**语法**已由真实 `nginx -t`
  校验，见 `panel-os` 的 `rendered_config_passes_real_nginx_syntax_check`）。
- **能力驱动 UI**：未支持能力一律 EmptyState/置灰 + 原因，绝不假装可用。

## 真机 E2E 脚本（十域，`ci/e2e-*.sh`）

对**运行中的真实后端**打请求的脚本化验收，弥补"单测只覆盖纯逻辑、覆盖不到
路由注册 + 能力位门禁 + OS provider 真实落盘"的空白。

| 脚本 | 真机覆盖 | **刻意不做**（破坏性/需外部条件） | 断言 |
|---|---|---|---|
| `e2e-files` | 列目录 / 读写 / 重命名 / chmod / 软删 / 回收站恢复与清空 / stat / **敏感路径黑名单真机断言**（复盘 P0-1 新条目读写全拒 + 普通 /etc 文件仍可写 + list 标记） | —（临时根目录自建自删，零残留；黑名单写请求在任何 OS 操作前被拒，不落盘） | 76 |
| `e2e-backups` | 计划 CRUD、`/backups/system` 的 keep 与 settings 跨端点对账、run→task→artifacts→下载、panel 在线恢复诚实 501 | 不恢复生产库 | 23 |
| `e2e-containers` | 能力位（按 daemon 可达性）、7 类只读端点、创建安全闸门 6 条（缺确认词/特权/敏感挂载/非法名/错词） | **不创建真实容器** | 15 |
| `e2e-cron` | 能力位、读端点、预览、11 条创建校验拒绝、创建→手动执行→任务输出与状态回写→删除 | —（用 `echo` 产证据，末了删 crontab 条目） | 34 |
| `e2e-databases` | 6 条连接校验拒绝、SQLite 浏览全链路（库→schema→表→行→CSV 导出）、只读 SQL 闸门、生命周期 | 不碰 mysql/pg（需远端） | 42 |
| `e2e-sites` | 能力位、读端点、7 条创建拒绝、纯 DB 生命周期、SSL `http-01`/`dns-01` 诚实 501 | **不 apply/reload 真实 nginx、不签证书** | 36 |
| `e2e-firewall` | 能力位、读端点、apply 拒绝（端口/CIDR/动作）+ **SSH 失联保护冲突** | **不写真实 iptables/nft、不改启停、不删规则** | 17 |
| `e2e-rbac` | 用户/角色 CRUD、owner 与自锁守卫（403）、**防提权**（第二会话：仅 `user.manage` 的用户不能授予自己没有的权限）、内置角色保留、被引用角色不可删、部署级设置拒绝 PATCH、审计 `user.create`/`role.create` 真写入 | 不建 owner、不动真实用户 | 63 |
| `e2e-security` | WAF 模板校验与 CRUD（profile/限速/burst/IP 列表）、拦截事件过滤、告警阈值与窗宽越界、安全基线（只读 + 错误确认词 10001）、在线会话（恰一 current、差集识别并吊销自己新建的会话 204） | **绝不用正确确认词调 `baseline/apply`**（会写回 sshd）；告警只原值回写；只吊销本次新建的会话 | 40 |
| `e2e-observe` | 系统概览与指标（overview 字段齐全、realtime/history、`gran` 非法 10001）、日志源与读取（行形状、histogram、未知源 404、grep 超长 10001）、通知（未读数、只碰不存在的 id）、本机便签完整生命周期、任务中心（详情/输出/不存在 404） | 通知 read-all 与任务 cancel **不碰**（前者改用户可见状态、后者会打断真实任务）；日志 download 不落文件 | 46 |

合计 **377 条断言**。运行方式：

```bash
make e2e-all                                    # 十域串行跑完并聚合（上线前整机自检）
make e2e-containers BASE=http://127.0.0.1:2084  # 单域
```

- 凭据走 `PANEL_E2E_USER` / `PANEL_E2E_PASS`（默认 dev 的 `admin/DevPreview2026x`）。
- 拒绝分支一律**钉死具体错误码**（`10001`/`10005`/`50001`），不用"期望非 0"——
  否则 URL 写错命中 404 时会假绿（数据库脚本实测踩过：404 冒充了 5 条业务拒绝）。
- 聚合器以**退出码为权威信号**：某域退出码非 0 即判失败，即使结果行写着 `FAIL=0`。
  后端不可达时首个脚本即 `[skip]`，聚合器立即停止并明确"未验证任何东西"。
- **不进 `make check`**：CI 无真机服务，脚本只会走 `[skip]` 分支——那是恒绿，
  比没有守卫更危险。人工在真机跑。

### 浏览器级 UI 冒烟（`ci/e2e-ui.sh`，20 条断言）

十域 E2E 全部打在 **API** 上；前端 74 个 UI 文件（32 views + 42 components）此前
**没有任何渲染测试**（vitest 只收 `src/**/*.test.ts` 且无 vue 插件）。而本项目踩过的
最深一坑正是这一类——**新增子组件忘了 import ⇒ 静默不渲染**（Vue 把未知标签当普通
元素渲染出空内容，仅 console warning；vue-tsc / build / 单测全绿），后端 E2E 永远
抓不到，只有拿浏览器看 DOM 才能发现。

`ci/e2e-ui.sh` 用 agent-browser 驱动真实浏览器：登录 → 概览（标题 + **数据驱动**卡片
「共 N 个」+ 顶栏 CPU 实时值）→ 容器页 6 个 Tab 逐一断言**边界引导 banner 真实在 DOM
里** → 用户 / 设置 / 备份 / 文件 / 日志 / 数据库各页主区非空且内容可辨认。

- **只读浏览**：不点任何写操作按钮，不建 / 删资源。
- 断言看 **DOM 文本**，不看 HTTP 200（200 只说明路由通了）。
- 需要浏览器（agent-browser）与前端 dev server（默认 5173，代理 `/api`→2083）；
  缺任一则**显式 `[skip]`**，不假装通过。
- 刻意**不进 `make e2e-all`**：它是浏览器层，与 API 层混在一起会让 API 门禁依赖浏览器环境。

> 本节不改变上文 🟠 项的结论：nginx `reload`、ufw 真实下发、真实容器创建、ACME、
> fail2ban 仍**未被脚本覆盖**（破坏性或需公网/外部条件）。脚本只验证这些能力的
> **只读面与拒绝分支**；cron / databases(SQLite) / backups / files 的**非破坏性真实
> 路径**已由脚本覆盖。

> 按分工约定：AI 仅做本地 `git commit`，`push` 由用户自行执行。
