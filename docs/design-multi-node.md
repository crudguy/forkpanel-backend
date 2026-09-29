# ForkPanel 多机 / 集群管理 · 架构方案（#53 / roadmap P2-3）

> 状态：**设计稿（未实施）**。本文档只定架构与边界，落地前需按分期逐张卡片评审。
> 前置：#44~#52 已落地的设施（能力矩阵、任务中心、SSE、审计、备份、终端）。

## 1. 背景与目标

ForkPanel 当前是**单实例**架构：一个 `panel serve` 进程 = 采集 + 存储 + API + 前端，`AppState` 内聚全部状态。多机管理的诉求是「一台面板管 N 台机器」。

**目标（对应卡片验收）**
1. 添加节点 → 中心可见节点状态（在线/离线/版本/能力）
2. 统一节点视图（指标、服务、日志在 hub 一处查看）
3. 批量任务下发（复用既有任务中心，受权限与确认约束）

**非目标（定位使然，明确不做）**
- 不做配置管理/编排引擎（Ansible/K8s 生态已存在，面板不做 DSL）
- 不做跨节点服务发现/负载均衡
- 规模上限按 **≤20 节点**设计——超过即进入专业编排器的主场；低配取向（hub 本身可能跑在 1C1G 上）优先于水平扩展
- 不做节点间互信（星型拓扑，节点彼此不可见）

## 2. 现状约束盘点（为什么不能"顺手"做）

| 组件 | 现状 | 多机影响 | 处置 |
|---|---|---|---|
| `AppState` | 进程内单例，含 OS adapter/DB/任务/会话 | 节点数据不能塞进同一 adapter | hub 增加 **节点注册表 + 每节点通道**，AppState 增 `ClusterState` 子结构，不动既有字段 |
| `OsAdapter` | 面向"本机"的能力聚合 | 节点侧需要同款能力 | **panel-agent 复用 panel-os**（同 crate，不复制代码） |
| `SessionCache` | 进程内存 | 仅 hub 存在会话，无影响 | 不变 |
| `TaskRunner` | `submit(req, impl TaskBody)`，TaskBody 单方法 trait | 批量下发需要"远程执行体" | 新增 `RemoteTask` TaskBody：把载荷投递到节点通道并等待回执（见 §6） |
| 调度器 `sched.register` | 周期任务（指标采样/备份/续期） | 节点健康巡检可复用 | 新增 `cluster.probe` 周期任务 |
| 鉴权 | Cookie `panel_sid` + CSRF（WS 用 Origin） | agent 是无浏览器端 | 节点走**独立 `/api/v1/cluster/*` 路由族 + node token**，不复用 Cookie 语义 |
| 审计 | hub 本机动作落库 | 节点动作必须可追责 | 节点任务在 hub 侧落审计（操作者=发起人，目标=node:id） |
| 契约门禁 | `endpoints.ts` 静态对照 openapi.yaml | 新端点必须进契约 | §8 的端点全部进 openapi.yaml |

## 3. 总体架构：Hub-Centric + Agent 出站长连

```
┌────────────────────────── Hub（现有 panel serve 扩展）──────────────────────────┐
│  前端(节点切换器)   /api/v1/*（本机不变）   /api/v1/cluster/*（新增）              │
│  AppState ── ClusterState { nodes: 注册表, channels: hub→agent 发送端 }          │
│  TaskRunner ── RemoteTask（批量下发）        Scheduler ── cluster.probe（巡检）   │
│  SQLite ── nodes 表 / tasks.node_id                                            │
└───────────────▲────────────────────────────────────────────────┬───────────────┘
                │ ①出站 WSS 长连（node token）                    │ ②REST（enroll）
┌───────────────┴────────────┐          ┌────────────────────────▼─────────────┐
│ panel-agent（新 bin，≤5MB） │          │ panel-agent（首次接入）               │
│  panel-os 全套能力          │          │  携带一次性 enroll token               │
│  出站 ws://hub/cluster/ws   │          │  POST /cluster/enroll → node token    │
│  不监听任何入站端口          │          └───────────────────────────────────────┘
│  本地执行：观测上报/任务体   │
└─────────────────────────────┘
```

**核心原则：agent 只出不进。** agent 主动向 hub 建立长连，hub 的所有指令都走这条已建立的连接下发。节点无需公网入站、无需开端口、NAT 后照常工作——这也是把攻击面收敛到"伪造 hub"与"泄露 node token"两点的关键。

## 4. 关键决策表

| # | 决策点 | 候选 | **推荐** | 理由 |
|---|---|---|---|---|
| D1 | 通信方向 | A. hub→agent 入站（SSH/agent 监听）<br>B. agent→hub 出站长连 | **B** | 节点零入站攻击面；NAT 可用；与终端/日志的既有长连经验（WS/SSE）同源 |
| D2 | 长连协议 | A. WebSocket<br>B. SSE+POST<br>C. gRPC | **A（WebSocket）** | 双向、单连接复用多类消息；axum `ws` feature 已启用，传递依赖已到位（终端先例）；gRPC 新增依赖与体积不可接受 |
| D3 | 序列化 | A. JSON<br>B. 二进制（protobuf） | **A 起步，预留 B** | ≤20 节点带宽不敏感；控制消息走 Text(JSON)、指标/日志块走 Binary；结构体两端都已 serde |
| D4 | 鉴权 | A. 每节点静态 token<br>B. mTLS<br>C. enroll 一次性令牌换长期 token | **C（B 为后续可选）** | 复用首启引导令牌的成熟先例（一次性、30 分钟）；mTLS 证书分发在低配场景运维成本过高，留作企业版后手 |
| D5 | 任务派发 | A. hub 直改节点（旁路任务中心）<br>B. 复用 TaskRunner + RemoteTask | **B** | 幂等/进度/审计/取消全部白得；`TaskBody` 单方法 trait 加一个实现即可，零侵入 |
| D6 | 节点数据存储 | A. 节点数据全量入 hub SQLite<br>B. 按需拉取+短缓存 | **B** | 20 节点 × 全量指标入库会撑爆低配盘；只持久化**节点注册信息与任务记录**，观测数据走通道实时取、不落盘（与 SSE 同哲学） |
| D7 | 节点权限 | A. 逐节点 RBAC<br>B. hub 统一权限 + 节点维度审计 | **B** | 引入"某用户只能管某节点"会让 RBAC 表翻倍；首版以**操作者权限在 hub 判定**、节点动作全审计兜底，节点级授权列后续 |

## 5. panel-agent（新二进制）

- **来源**：新 workspace 成员 `crates/panel-agent`，**复用 panel-os**（OsAdapter 全套 provider 与安全收敛不变：子进程唯一出口 `cmd.rs`、PTY 收敛、fs 沙箱）。
- **形态**：单文件二进制 + systemd unit（`panel-agent.service`）；无嵌入前端；tier 恒按 Nano 预算（目标 RSS < 15MB 稳态）。
- **不监听任何端口**（本地调试 socket 可选）。
- **CLI**：`panel-agent enroll --hub https://hub:2083 --token <一次性令牌>` → 交换 node token 存 `0600` 本地文件；`panel-agent run` 按配置重连（指数退避）。
- **依赖预算**：直接新增 `tokio-tungstenite`（或复用 axum ws 的客户端侧）+ 既有 workspace 依赖；门禁 [8] 当前 36/38，加入后 37/38，**预算是本方案最紧的硬约束**——若超，优先把 hub 的 `rand`/`time` 等合并裁剪。

## 6. Agent 协议（WS 帧语义）

连接建立后 agent 先发 `hello`，hub 校验 node token + 记录版本/能力快照。之后全双工：

| 方向 | 类型 | 载荷 | 说明 |
|---|---|---|---|
| agent→hub | `hello` | node token、agent 版本、OsAdapter 能力快照、主机名 | hub 据此注册/更新节点 |
| agent→hub | `metrics` | SystemSnapshot（复用既有 serde 结构） | 周期上报（默认 10s，可调） |
| hub→agent | `probe` | — | hub 主动探活（巡检超时 = 判离线） |
| hub→agent | `query` | `{req_id, kind: services\|logs\|files\|processes, params}` | 只读查询（M2） |
| agent→hub | `query_result` | `{req_id, data \| error}` | 对应回执 |
| hub→agent | `task` | `{req_id, task_kind, params}` | 任务下发（M3，见 §9 护栏） |
| agent→hub | `task_progress` / `task_result` | `{req_id, progress\|outcome}` | 对接 hub 任务中心实时进度 |
| 双向 | `ping/pong` | — | 保活（60s） |

- 所有 `hub→agent` 消息带 `req_id`（ulid/自增），agent 幂等去重；超时未回执由 hub 判失败（可重试幂等类任务）。
- **消息上限**：单帧 ≤ 1MiB；日志块按 64KB 分帧（复用日志 tail 的有界读取纪律）。

## 7. 数据模型（hub SQLite）

```sql
CREATE TABLE nodes (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,          -- 用户可读名
    hostname    TEXT NOT NULL,
    agent_ver   TEXT NOT NULL,
    token_hash  TEXT NOT NULL,                 -- node token 仅存哈希（argon2，同口令纪律）
    caps_json   TEXT NOT NULL,                 -- 能力快照（webserver.manage 是否可用等）
    enrolled_at INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,              -- 心跳时间（判离线：>3×上报周期）
    enabled     INTEGER NOT NULL DEFAULT 1,
    note        TEXT
);
ALTER TABLE tasks ADD COLUMN node_id INTEGER REFERENCES nodes(id);  -- NULL=hub 本机
```

- `nodes` CRUD + 启停（禁用=拒绝其连接）走契约与门禁；**token 只存哈希**，与口令同一纪律。
- 任务中心列表按 `node_id` 渲染"目标节点"列；批量任务 = N 行 tasks 共享一个 batch_key（新增列）。

## 8. Hub API 面（全部进 openapi.yaml，前端契约门禁强制）

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api/v1/cluster/nodes` | GET/POST | 列表 / 登记新节点（POST 返回**一次性 enroll token**，打印一次即焚） |
| `/api/v1/cluster/nodes/{id}` | PATCH/DELETE | 改名/禁用/删除（删除需 ConfirmDialog 输入节点名） |
| `/api/v1/cluster/enroll` | POST | **agent 专用**（node 路由族，无 Cookie）：enroll token → node token |
| `/api/v1/cluster/ws` | GET(WS) | **agent 专用**长连（node token 头鉴权；不做 Origin 校验——非浏览器端，token 即凭据） |
| `/api/v1/cluster/batch` | POST | 批量任务：`{node_ids[], task_kind, params}` → 按 node_id 拆行入任务中心，**owner + 二次确认** |

- 权限：`cluster.view` / `cluster.manage`（新增 perm 点，owner/admin 全量、operator 视图+批量观测、viewer 只读）。
- node token 路由族与 Cookie 路由物理隔离（独立 Router，同 terminal 先例），**CSRF/Origin 逻辑不适用于机器端**。

## 9. 安全护栏（对应卡片"AI/批量高危"纪律）

1. **分级开放**：M1 只读观测 → M2 只读查询 → M3 才放开任务；每级独立评审，不上线跳级。
2. **批量任务 = 高危写**：仅 `system.manage` 及以上可发起；ConfirmDialog 输入 `执行` 确认词；任务体逐节点审计（操作者/节点/参数截断）。
3. **agent 侧最小信任**：agent 只实现白名单处理器（观测/只读查询/明确 task_kind），收到未知消息一律忽略并告警；**绝不提供任意 shell 下发**——Web 终端不上节点（PTY 属交互单会话，批量通道装载它=把任意代码执行引入集群面；确需远程终端走 M4 专项设计）。
4. **node token 泄露应对**：hub 一键吊销（删 nodes 行+拒连）；enroll token 30 分钟一次性（复用引导令牌机制）。
5. **hub 被伪造**：agent 侧校验 hub 证书/固定公钥指纹（可选配置 `--pin-fingerprint`），防 DNS 劫持把节点引到假 hub。

## 10. 前端（对齐现有交互语言）

- 顶栏加**节点切换器**（本机/各节点下拉）；选中节点后，主机/进程/服务/日志/文件页的数据源切换（URL 加 `?node=`，刷新/分享保持）。
- 新页 `ClusterView`：节点列表（在线状态灯/版本/最后心跳/能力徽章）+ 添加节点向导（展示一次性 enroll 命令）+ 批量任务面板（选节点 × 选动作，二次确认）。
- 任务中心条目加"节点"徽章；节点离线时该节点任务标灰并提示。

## 11. 分期落地（每期独立验收，均可回到单实例不受损）

| 期 | 范围 | 验收 | 风险 |
|---|---|---|---|
| M1 观测 | agent bin + enroll/hello/metrics + nodes 表 + ClusterView 只读 + 节点切换器（指标/主机监控） | 添加节点→中心 10s 内可见指标与能力快照 | 🟢 低（全部只读、零写路径） |
| M2 只读查询 | query 通道（services/logs/processes/files 只读）+ 对应前端数据源切换 | 节点日志/服务状态在 hub 查看 | 🟡 中（通道背压与超时治理） |
| M3 批量任务 | RemoteTask + batch API + 确认 UI + 审计 | 批量下发任务 → 逐节点进度/结果可见 | 🔴 高（远程写；严格走 §9-2/3） |
| M4 后手（另立项） | 远程终端、mTLS、节点级授权 | — | — |

**回滚保证**：全部改动在 `cluster.*` 命名空间与独立 crate 内；`AppState` 既有字段不动；不启用（无节点注册）时代码路径零介入——单实例行为与今天逐字节一致。

## 12. 复用清单（不重新发明）

| 既有设施 | 在本方案中的角色 |
|---|---|
| 首启引导令牌（一次性、30 分钟） | enroll token 机制直接同款 |
| `TaskBody` 单方法 trait | `RemoteTask` 一个实现接入批量下发 |
| 能力矩阵（CapabilityMap） | agent hello 上报 → hub 展示节点能力徽章、任务前置校验 |
| SSE 管道 | 节点指标/任务进度向浏览器推送复用既有频道模式 |
| WS 守卫经验（终端：Origin 替代 CSRF） | cluster 路由族鉴权独立成文，避免误套浏览器语义 |
| 审计 + 确认词 ConfirmDialog | 批量任务全程留痕 + 二次确认 |
| 分层门禁 CI | agent 复用 panel-os 自动受 [1][3][4] 门禁约束 |

## 13. 风险登记

| 级别 | 风险 | 缓解 |
|---|---|---|
| 🔴 | 批量通道被滥用为任意代码执行 | 白名单 task_kind、无 shell 下发、owner+确认词+逐节点审计（§9-3） |
| 🔴 | node token 泄露 → 节点被冒充 | 仅存哈希、一键吊销、agent 侧 hub 指纹固定（§9-4/5） |
| 🟡 | 依赖预算超限（门禁 [8] 36/38） | agent 与 hub 共享 workspace 依赖；必要时裁剪 hub 侧低频依赖 |
| 🟡 | 长连断线风暴（hub 重启 → 20 节点同时重连） | agent 指数退避 + 抖动；hub 半开连接上限 |
| 🟡 | 低配 hub 内存（20 节点长连） | 每连接缓冲上限、观测数据不落盘（D6）、Nano 档关闭集群 |
| 🟢 | 与单实例行为回归冲突 | §11 回滚保证：独立命名空间 + 未启用零介入 |
