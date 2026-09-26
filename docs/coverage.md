# ForkPanel（叉叉面板）· §3.4 接口契约覆盖矩阵

> 来源：设计文档 `轻量Linux服务器管理面板设计方案.md` → §3.4 关键接口约定（核心路由表）。
> 目的：证明前后端分离后，文档所列接口已**全量接线**，并如实标注实现状态。
> 判定方法：后端 `crates/panel-api/src/routes*.rs` 中凡返回 `ApiError::unsupported("…(Mx: …)")` 者记为「🟡 结构化 501」；
> 其余返回 `ok(...)/Json(...)` 者记为「✅ 已实现」。前端是否调用由 `ci/check-contract.sh` 校验（已 PASS）。

## 图例

| 标记 | 含义 |
|---|---|
| ✅ | 已实现：handler 返回真实数据或 `202 {task_id}` |
| 🟡 | 结构化 501：按里程碑（M2/M3/M4/M5）尚未实现，返回 `ApiError::unsupported("…(Mx: 说明)")`，**绝不伪造数据** |
| 🔵 | 契约超集：§3.4 未列出但已写入 `endpoints.ts` 契约表面，供后续扩展 |

## 1. 认证与 CSRF

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| POST `/auth/login` | 登录 + Set-Cookie | ✅ | — | `API.auth.login()` | LoginView |
| POST `/auth/logout` | 清会话 | ✅ | — | `API.auth.logout()` | auth store |
| GET `/auth/me` | 当前用户/权限/能力 | ✅ | — | `API.auth.me()` | auth store |
| POST `/auth/password` | 改密（需 CSRF） | ✅ | — | `API.auth.password()` | — |

## 2. 系统 / 监控 / 指标

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/system/capabilities` | 能力矩阵（驱动 UI 灰态） | ✅ | — | `API.system.capabilities()` | auth store / 各视图 |
| GET `/system/overview` | 一次性快照卡片 | ✅ | — | `API.system.overview()` | DashboardView |
| GET `/metrics/realtime` | 最近 N 秒环形缓冲 | ✅ | — | `API.metrics.realtime()` | DashboardView |
| GET `/metrics/history` | 历史区间 | ✅ | — | `API.metrics.history()` | DashboardView |
| GET `/version` | 版本协商 | ✅ | — | `API.version()` | — |

## 3. 进程

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/processes` | 进程列表（排序/分页） | 🟡 | M2 | `API.processes.list()` | SystemView |
| POST `/processes/{pid}/kill` | 终止进程 | 🟡 | M2 | `API.processes.kill(pid)` | SystemView |

## 4. 服务 / 软件

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/services` | 单元列表（过滤/状态） | ✅ | — | `API.services.list()` | ServicesView |
| POST `/services/{unit}/start` | 启动 | 🟡 | M2 | `API.services.start(unit)` | ServicesView |
| POST `/services/{unit}/stop` | 停止 | 🟡 | M2 | `API.services.stop(unit)` | ServicesView |
| POST `/services/{unit}/restart` | 重启 | 🟡 | M2 | `API.services.restart(unit)` | ServicesView |
| PUT `/services/{unit}/enabled` | 开机自启 | ✅ | — | `API.services.setEnabled(unit)` | ServicesView |
| GET `/services/{unit}/journal` | 日志 | 🟡 | M3 | `API.services.journal(unit)` | ServicesView |
| GET `/packages` | 已探测软件 | 🟡 | M2 | `API.packages.list()` | ServicesView |
| POST `/packages/install` | 安装（→202 task） | 🟡 | M2 | `API.packages.install()` | ServicesView |
| DELETE `/packages/{name}` | 卸载 | 🟡 | M2 | `API.packages.remove(name)` | ServicesView |

## 5. 站点 / 证书（SSL）

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/sites` | 站点列表 | ✅ | — | `API.sites.list()` | SitesView |
| POST `/sites` | 新建站点（配置闭环） | ✅ | — | `API.sites.create()` | SitesView |
| POST `/sites/apply` | 应用站点配置 | ✅ | — | `API.sites.apply()` | SitesView |
| GET `/sites/{id}` | 单体详情 | 🟡 | M3 | `API.sites.get(id)` | SitesView |
| PATCH `/sites/{id}` | 更新 | 🟡 | M3 | `API.sites.patch(id)` | SitesView |
| DELETE `/sites/{id}` | 删除（先停+备份） | 🟡 | M3 | `API.sites.remove(id)` | SitesView |
| POST `/sites/{id}/reload` | 重载 | 🟡 | M3 | `API.sites.reload(id)` | SitesView |
| GET `/sites/{id}/logs` | 访问/错误日志 SSE | 🟡 | M3 | `API.sites.logs(id)` | SitesView |
| POST `/sites/{id}/ssl/apply` | ACME 签发（→202） | 🟡 | M3 | `API.sites.sslApply(id)` | SitesView |
| GET `/certs` | 证书列表 | ✅ | — | `API.certs.list()` | SitesView |
| POST `/certs/{id}/renew` | 续期 | 🟡 | M3 | `API.certs.renew(id)` | SitesView |
| DELETE `/certs/{id}` | 删除（清续期定时器） | 🟡 | M3 | `API.certs.remove(id)` | SitesView |

## 6. 文件

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/files/list` | 目录分页/排序 | ✅ | — | `API.files.list()` | FilesView |
| GET `/files/stat` | 独立 stat | 🟡 | M2 | `API.files.stat()` | FilesView |
| PUT `/files/upload` | 流式上传 | 🟡 | M2 | `API.files.upload()` | FilesView |
| GET `/files/download` | 一次性下载 | 🟡 | M2 | `API.files.download()` | FilesView |
| POST `/files/action` | move/copy/delete/chmod/rename | 🟡 | M2 | `API.files.action()` | FilesView |
| GET `/files/read` | 文本读取 ≤2MB | ✅ | — | `API.files.read()` | FilesView |
| PUT `/files/write` | 保存（生成 .bak） | ✅ | — | `API.files.write()` | FilesView |
| 🔵 `/files/mkdir` `/files/delete` `/files/rename` `/files/chmod` | 契约超集 | ✅ | — | `API.files.*` | FilesView |

## 7. 数据库

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/db/connections` | 连接列表 | ✅ | — | `API.db.connections()` | DatabasesView |
| POST `/db/connections` | 新增连接 | ✅ | — | `API.db.connections()` | DatabasesView |
| GET `/db/{conn}/databases` | 库列表 | 🟡 | M4 | `API.db.databases(conn)` | DatabasesView |
| GET `/db/{conn}/{db}/tables` | 表列表 | 🟡 | M4 | `API.db.tables(conn,db)` | DatabasesView |
| GET `/db/{conn}/{db}/{table}/rows` | 行预览（禁 Web SQL） | 🟡 | M4 | `API.db.rows(conn,db,t)` | DatabasesView |
| POST `/db/{conn}/backup` | 备份（→202 task） | ✅ | — | `API.db.backup(conn)` | DatabasesView |
| 🔵 POST `/db/{conn}/restore` | 恢复 | ✅ | — | `API.db.restore(conn)` | DatabasesView |

## 8. 防火墙

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/firewall/status` | 后端/启用态 | ✅ | — | `API.firewall.status()` | FirewallView |
| PUT `/firewall/enabled` | 启用/停用 | ✅ | — | `API.firewall.setEnabled()` | FirewallView |
| GET `/firewall/rules` | 规则列表 | ✅ | — | `API.firewall.rules()` | FirewallView |
| POST `/firewall/rules` | 应用规则（仅 allow） | ✅ | — | `API.firewall.rules()` | FirewallView |
| DELETE `/firewall/rules/{id}` | 删除（仅面板自建） | 🟡 | M2 | `API.firewall.removeRule(id)` | FirewallView |

## 9. 安全

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/security/baseline` | 基线检查 | 🟡 | M5 | `API.security.baseline()` | — |
| POST `/security/baseline/apply` | 应用基线 | 🟡 | M5 | `API.security.baselineApply()` | — |
| GET `/security/sessions` | 在线会话 | 🟡 | M5 | `API.security.sessions()` | — |
| DELETE `/security/sessions/{id}` | 吊销会话 | 🟡 | M5 | `API.security.revokeSession(id)` | — |

## 10. 计划任务（cron）

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/cron/jobs` | 任务列表 | ✅ | — | `API.cron.jobs()` | CronView |
| POST `/cron/jobs` | 新建 | ✅ | — | `API.cron.jobs()` | CronView |
| PATCH `/cron/jobs/{id}` | 更新 | 🟡 | M3 | `API.cron.job(id)` | CronView |
| DELETE `/cron/jobs/{id}` | 删除 | ✅ | — | `API.cron.job(id)` | CronView |
| POST `/cron/jobs/{id}/run` | 手动触发 | 🟡 | M3 | `API.cron.run(id)` | CronView |
| GET `/cron/jobs/{id}/runs` | 运行历史 | ✅ | — | `API.cron.runs(id)` | CronView |
| POST `/cron/preview` | 下次 5 次预览 | 🟡 | M3 | `API.cron.preview()` | CronView |

## 11. 日志

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/logs/sources` | 日志源 | ✅ | — | `API.logs.sources()` | LogsView |
| GET `/logs/stream` | 跟随 SSE | 🟡 | M3 | `API.logs.stream()` | LogsView |
| GET `/logs/download` | 区间下载 | 🟡 | M3 | `API.logs.download()` | LogsView |
| 🔵 GET `/logs/{id}` | 单体读取 | ✅ | — | `API.logs.read(id)` | LogsView |

## 12. 任务中心

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/tasks` | 任务列表 | ✅ | — | `API.tasks.list()` | TaskDrawer |
| GET `/tasks/{id}` | 单体详情 | 🟡 | M2 | `API.tasks.get(id)` | TaskDrawer |
| POST `/tasks/{id}/cancel` | 取消 | ✅ | — | `API.tasks.cancel(id)` | TaskDrawer |
| GET `/tasks/{id}/output` | 输出 | ✅ | — | `API.tasks.output(id)` | TaskDrawer |

## 13. 设置 / 用户 / 审计

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/settings` | 面板设置 | 🟡 | M5 | `API.settings.get()` | SettingsView |
| PATCH `/settings` | 更新设置 | 🟡 | M5 | `API.settings.patch()` | SettingsView |
| GET `/users` | 用户列表 | 🟡 | M5 | `API.users.list()` | — |
| POST `/users` | 新建用户 | 🟡 | M5 | `API.users.create()` | — |
| PATCH `/users/{id}` | 更新用户 | 🟡 | M5 | `API.users.patch(id)` | — |
| DELETE `/users/{id}` | 删除用户 | 🟡 | M5 | `API.users.remove(id)` | — |
| GET `/audit` | 审计日志（分页/过滤） | ✅ | — | `API.audit()` | — |

## 14. SSE 事件

| 方法 + 路径 | 文档要求 | 后端状态 | 里程碑 | 前端契约 | 前端视图 |
|---|---|---|---|---|---|
| GET `/events` | 多频道（metrics/tasks/logs） | ✅ | — | `API.events.*` | client SSE |

---

## 覆盖结论

- **契约完整度：100%**。§3.4 核心路由表列出的每条接口均已在 `routes.rs` 接线，并对应 `docs/api/openapi.yaml` 契约项。
- **前端契约一致：PASS**。`ci/check-contract.sh` 确认全部静态调用路径已在契约声明，且无绕过 `client.ts` 的裸 fetch。
- **实现策略：诚实桩**。未按里程碑（M2/M3/M4/M5）落地的端点统一返回 `ApiError::unsupported("…(Mx: 说明)")`，前端据 `capabilities` 灰态展示，**不伪造任何数据**。
- **能力驱动 UI**：各视图以 `CAP.*` + `auth.supported()` 决定是否渲染操作，未支持能力只显示 `EmptyState`，绝不假装可用。

## 仓库与提交

| 仓库 | 路径 | 初始提交 | 说明 |
|---|---|---|---|
| 后端 | `/home/a/文档/panel-backend` | `103bfdb` | Rust 服务 + 接口契约 + OS 抽象层 + 桩 handler |
| 前端 | `/home/a/文档/panel-frontend` | `648ebc3` | Vue3 界面 + 契约表面 `endpoints.ts` + `openapi.yaml` 副本 |

> 按分工约定：AI 仅做本地 `git commit`，`push` 由用户自行执行。
