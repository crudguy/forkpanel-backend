# ForkPanel（叉叉面板）· 轻量 Linux 服务器管理面板 · 后端

**技术栈**：Rust（edition 2021，MSRV 1.75）+ axum + rusqlite(SQLite) + tokio
**形态**：单文件静态二进制，内嵌前端产物，无运行时依赖，面向低配 Linux VPS 单机部署
**配套前端**：[forkpanel-frontend](https://github.com/your-org/forkpanel-frontend)（独立仓库）

---

## 本仓库职责（与前端彻底分离）

| 关注点 | 归属 |
|---|---|
| 业务逻辑、数据持久化、鉴权/RBAC/CSRF、OS 抽象层、任务调度 | **本仓库（后端）** |
| 界面与交互、能力矩阵驱动的菜单/按钮、SSE 消费 | panel-frontend（前端） |

> **通信边界**：前端**只**通过 `https://<host>/api/v1/*`（REST + SSE）与后端通信。
> 两端之间唯一的"接口契约"是 [`docs/api/openapi.yaml`](docs/api/openapi.yaml)（OpenAPI 3.1）。
> 前端不持有任何后端实现细节，后端不输出任何 UI。

## 分层架构（强制纪律，CI 门禁 `ci/check-layering.sh` 校验）

```
L1 传输层  axum router · TLS(rustls) · 会话/CSRF/限流/请求体大小
L2 接口层  handler（薄）：参数校验 · 权限断言 · 响应封装
L3 业务层  service：领域规则 · 事务边界 · 审计 · 任务编排
L4 数据层  repository（rusqlite + WAL）· 迁移 · 备份
L5 OS 抽象层 trait OsAdapter（Linux 当前唯一实现，其余返回 Unsupported）
L6 任务/调度 tokio 后台任务 · 采样 · 续期 · 备份 · cron
```

四条不可协商纪律（违反即 CI 失败）：
1. 进程出口唯一：`Command::new` 仅允许出现在 `panel-os/src/cmd.rs`。
2. 无 shell：禁止 `sh -c`/`bash -c`；`Bin` 为封闭枚举。
3. 路径与平台不入业务层：业务层禁止 `/etc`/`/var`/`/proc` 与 `cfg(target_os)`；路径来自 `PathLayout`，能力来自 `CapabilityMap`。
4. SQL 只走绑定参数：禁止 `format!` 拼 SQL。

## 目录

```
Cargo.toml            workspace（release: opt-level=z / lto=fat / panic=abort / strip）
crates/
  panel-core/         零 IO 领域模型：错误码、能力矩阵、档位、强类型标识、校验器、crypto
  panel-os/            ★ OS 抽象层：trait + linux 实现 + cmd.rs + validate + mock
  panel-db/            SQLite：WriterActor 单写串行化 + ReadPool + 迁移 + 备份 + 环形缓冲
  panel-api/           axum：router、middleware、handler、SSE、错误码
  panel-task/          任务队列、调度器、cron 执行器
  panel-cli/           二进制入口：init/doctor/migrate/serve/backup/systemd-unit
migrations/            内嵌 SQL（编号 + 校验和）
docs/api/openapi.yaml  ★ 前后端唯一接口契约（事实源）
docs/abi/             抽象层接口冻结文档
deploy/               systemd unit、安装/卸载脚本、默认配置
ci/                   分层门禁 + 注入/鉴权/CLI/任务/模块仿真用例集
```

## 构建与运行

```bash
# 需要 Rust 工具链（建议 1.75+；交叉编译用 cargo-zigbuild 出 musl 静态二进制）
cargo build --release
cargo test  --workspace

# 无 Linux / 无 root 环境：用内存 mock 适配器跑全部逻辑（能力位返回 Unsupported）
cargo build --release --features force-mock

# 启动（需 root 才能管理服务/写 /etc；非特权下降级而非崩溃）
panel serve --bind 127.0.0.1:2083
```

## 接口契约

- 唯一事实源：`docs/api/openapi.yaml`（OpenAPI 3.1）。
- 前端消费其副本并生成类型；两端以 `GET /api/v1/version` 的 `api` 字段做版本协商。
- 修改契约时：**先改 openapi.yaml，再改两端实现**，并跑 `ci/check-api-contract.sh`。

## 已知约束

本仓库在该生成/评审环境下**未做 Rust 编译验证**（环境无 Rust 工具链、crates.io 不可达）。
代码按文档架构与既有骨架模式编写，需在具备工具链与目标机的环境中 `cargo build` 修编译错误后再行部署。
首次 `cargo build` 预计需修正的均为机械性问题（async_trait 生命周期、libc 字段类型等），不改架构形状。
