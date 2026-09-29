# ForkPanel（叉叉面板）· §3.4 接口契约覆盖矩阵

> 来源：设计文档 `轻量Linux服务器管理面板设计方案.md` → §3.4 关键接口约定（核心路由表）。
> 目的：证明前后端分离后，文档所列接口已**全量接线**，并如实标注实现状态。
> 判定方法：后端 `crates/panel-api/src/routes*.rs` 中凡返回 `ApiError::unsupported("…(Mx: …)")` 者记为「🟡 结构化 501」；
> 其余返回 `ok(...)/Json(...)` 者记为「✅ 已实现」。前端是否调用由契约门禁校验（PASS）。
>
> **本版为 2026-09-29 刷新**：P0（站点/SSL、数据库、用户）与 P1（容器、安全基线、备份、日志 SSE）、
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
| POST `/sites/{id}/ssl/apply` | 证书签发 | ✅ | **self-signed 同步签发**（openssl，key 经主密钥加密落盘 0600）；`method=acme` → 🟡 需 certbot + 公网（#61） | SitesView |
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
| GET `/db/{conn}/{db}/tables` | 表列表（含行数） | ✅ | mysql/pg 🟡 需外部客户端 | DatabasesView |
| GET `/db/{conn}/{db}/{table}/rows` | 行预览（分页，禁 Web SQL） | ✅ | NULL 保真；缺表/连接优雅 404 | DatabasesView |
| POST `/db/{conn}/backup` | 备份（→202 task） | ✅ | **VACUUM INTO 不可在写者事务内**——改独立连接备份（根因修复） | DatabasesView |
| 🔵 POST `/db/{conn}/restore` | 恢复 | 🟡 | 破坏性操作，需先备份当前态 + 二次确认（原标 ✅ 系误标，纠正） | — |

## 8. 防火墙

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/firewall/status` / rules / enabled 增删 | ufw 全套 | 🟠 | 已实装（编号规则/仅面板自建可删）；**本沙箱无 ufw**，能力位诚实置灰，真机验证 | FirewallView |

## 9. 安全——#48 落地

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/security/baseline` | 基线检查 | ✅ | 6 项只读检查；OpenSSH 默认值语义已修正并有单测 | SecurityView |
| POST `/security/baseline/apply` | 应用基线 | 🟡 | 写回系统安全配置属高危：需 root + 先备份 + 二次确认（未实装不硬上） | — |
| GET `/security/sessions` | 在线会话 | ✅ | 内存 SessionCache 快照（重启即清零，如实标注）；`current` 标记自己；**ip 刻意不采集**（无对端地址管道，返回 null 不伪造） | SecurityView |
| DELETE `/security/sessions/{id}` | 吊销会话 | ✅ | 允许吊销自己的当前会话（=自我登出）；404 对不存在会话；审计只落 sid 前 8 位（sid=凭据不落库） | SecurityView |

## 10. 计划任务（cron）

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET/POST `/cron/jobs` + PATCH/DELETE/`run`/`runs` | 全套 | ✅ | run 走任务队列 | CronView |
| POST `/cron/preview` | 下次 5 次预览 | 🟡 | M3 小功能 | — |

## 11. 日志——#50 落地

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/logs/sources` / 🔵 `/logs/{id}` | 源/读取 | ✅ | journald + 站点文件源自动发现 | LogsView |
| GET `/logs/stream` | 跟随 | ✅ | **SSE**（journald spawn_stream / 文件轮询 tail，字面量过滤在 Rust 侧） | LogsView（实时跟随开关） |
| GET `/logs/download` | 区间下载 | 🟡 | M3 小功能 | — |

## 12. 任务中心

| 方法 + 路径 | 文档要求 | 后端状态 | 备注 | 前端视图 |
|---|---|---|---|---|
| GET `/tasks` + cancel + output | 列表/取消/输出 | ✅ | | TasksView |
| GET `/tasks/{id}` | 单体详情 | 🟡 | M2 小功能 | — |

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
| `/api/v1/backups` CRUD + `/{id}/run` + `/{id}/artifacts` | 备份计划（#49） | ✅ | panel=独立连接快照 / site=tar.gz；**restore 🟡**；keep_count 自动清理待做 |
| `/api/v1/security/baseline` | 安全基线（#48） | ✅ | 见 §9 |

## 覆盖结论（2026-09-29）

- **契约完整度：100%**，且新增模块全部先进 `openapi.yaml` 再实现（前端副本按事实源同步）。
- **剩余 🟡 清单**（结构化 501，均如实返回原因）：files stat/upload/download/action、baseline/apply、tasks/{id}、cron/preview、logs/download、db 与备份的 restore、ACME。
- **🟠 真机验证项**：nginx 下发/reload、ufw、mysql/postgres 链路、ACME——能力位诚实置灰，沙箱内只验证降级路径。
- **能力驱动 UI**：未支持能力一律 EmptyState/置灰 + 原因，绝不假装可用。

> 按分工约定：AI 仅做本地 `git commit`，`push` 由用户自行执行。
