# ForkPanel（叉叉面板）· 轻量 Linux 服务器管理面板 · 后端

**技术栈**：Rust（edition 2021，MSRV 1.75）+ axum + rusqlite(SQLite) + tokio
**形态**：单文件静态二进制，内嵌前端产物，无运行时依赖，面向低配 Linux VPS 单机部署
**配套前端**：[forkpanel-frontend](https://github.com/crudguy/forkpanel-frontend)（独立仓库）

---

## 安装（一键，无需编译）

在以 root / sudo 执行的 Linux 机器上：

```bash
# 两步法（推荐，比 curl | sh 更稳）：先把脚本下到本地，确认完整再执行
# —— 避免管道中途断流让 sh 只执行到半截脚本（留下脏状态）；wget 自带重试+续传
wget -O get-panel.sh https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh
# 没有 wget 时：curl -fSL --retry 5 --retry-delay 2 -o get-panel.sh <同一 URL>
sudo sh get-panel.sh
```

装完后从日志取一次性初始化令牌，浏览器打开对应端口完成引导：

```bash
journalctl -u panel -n 50 --no-pager      # 找到引导令牌
```

> 安装器会按架构（amd64 / arm64）下载**静态二进制**、**校验 ed25519 签名**（验不过绝不执行）、
> 落 systemd 单元与开机自启，并随机分配一个 ≥10000 的端口避开扫描。
>
> 详细说明（指定版本 / 切镜像源 / 升级 / 卸载）：[docs/distribution.md](docs/distribution.md)

**支持**：Linux（Debian / Ubuntu / CentOS / Rocky / Alma / Alpine 等，需 systemd）；架构 amd64 / arm64。
面板默认只监听 `127.0.0.1`，远程请用 SSH 隧道：`ssh -L <端口>:127.0.0.1:<端口> user@server`。

## 从源码构建

```bash
git clone https://github.com/crudguy/forkpanel-backend.git
git clone https://github.com/crudguy/forkpanel-frontend.git forkpanel-frontend
cd forkpanel-backend
# 前端产物必须同步进本仓 web/dist（rust-embed 编译期内嵌），详见文档
```

完整步骤与常见坑：[docs/building-from-source.md](docs/building-from-source.md)

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
docs/                  deployment / coverage / env；审查报告见
                       audit-2026-10-17.md（全文）与 audit-2026-10-17-summary.md（归纳版）
deploy/               systemd unit、安装/卸载脚本、默认配置
ci/                   分层门禁 + 注入/鉴权/CLI/任务/模块仿真用例集
```

> **新人建议先读** [`docs/audit-2026-10-17-summary.md`](docs/audit-2026-10-17-summary.md)：
> 全项目审查结论、19 项发现的处置记录，以及「哪些看着像问题其实不是」的清单
> （避免重复排查）。

## 构建与运行

```bash
# 需要 Rust 工具链（建议 1.75+；交叉编译用 cargo-zigbuild 出 musl 静态二进制）
cargo build --release
cargo test  --workspace

# 无 Linux / 无 root 环境：用内存 mock 适配器跑全部逻辑（能力位返回 Unsupported）
cargo build -p panel-cli --release --features panel-os/force-mock

# 启动（需 root 才能管理服务/写 /etc；非特权下降级而非崩溃）
panel serve                       # 监听地址取自 config.toml 的 [server].bind / port（dev 默认 2083）
```

## 接口契约

- 唯一事实源：`docs/api/openapi.yaml`（OpenAPI 3.1）。
- 前端消费其副本并生成类型；两端以 `GET /api/v1/version` 的 `api` 字段做版本协商。
- 修改契约时：**先改 openapi.yaml，再改两端实现**，并跑 `ci/check-api-contract.sh`
  （含契约结构体检 `ci/check_openapi.py`：YAML 语法 + 前后端副本逐字节一致）。
  契约正文大量使用 flow 风格单行（`{ a: 1 }`），**值里出现 `{`/`}` 必须加单引号**，
  否则整份文件无法被 YAML 解析器读取——该脚本会定位到行号。

## 质量门禁（`make check` 一条命令跑全部；CI 同路径自动跑）

`make check` = 5 个静态门禁 + `cargo test --workspace`；`make audit` 单独成目标
（依赖安全扫描，GitHub Actions 里也是独立 job——避免本机没装 cargo-audit 就红主门禁）。
按改动类型可单独跑对应 `ci/` 门禁：

- 分层 / 权限：`ci/check-layering.sh`、`ci/check-permissions.sh`
- 前后端契约：`ci/check-api-contract.sh`（内含契约结构体检 `ci/check_openapi.py`）
- 依赖安全：`ci/check-audit.sh`——`cargo audit` 扫 `Cargo.lock` 已知漏洞（RustSec advisory-db）。
  需先 `cargo install cargo-audit`；**找不到即判失败**（恒绿纪律：静默跳过比没门禁更危险）。
  联网更新 advisory-db 失败时自动回退本地缓存 `~/.cargo/advisory-db`（首次 `cargo audit` 生成），
  建议定期联网刷新以纳入新公布 advisory。默认只有**漏洞**才红，unmaintained 等 warning 不拦
  （要连 warning 一起拒可自行加 `-D warnings`）。

## 前端页面（索引）

前端约 27 个路由：登录 + 概览 + 主机监控（实时趋势 / 专业快照 / 进程管理）+ 软件与服务（软件 / 服务 / 服务详情）+ 网站 / 应用 / WAF / 证书 / 文件 / 数据库 / 容器 / 备份 + 安全（防火墙规则 / 安全基线）+ 任务（计划任务 / 任务中心）+ 日志（系统日志 / 审计日志）+ 通知 / 终端 / AI 助手 / 设置 / 用户。

完整「路由 → 标题 → 视图组件」映射表见前端仓库 README 的「页面 / 路由」一节。

## 已知约束

- 构建验证：本环境已具备 Rust 工具链（`cargo 1.98.x`），`cargo build` / `cargo test` 可运行；首次构建需拉取 crates.io 依赖，离线环境会失败。
- 实跑前务必 `cargo build --bin panel`：`cargo test` 不产生可执行，改完需重新构建二进制再起 `panel serve`（见 deploy/ 部署流程）。
- 业务层不依赖 IO、核心规则测试集中在 `panel-core/src/lib.rs::tests`：改 core 规则补该处用例即可，勿另建镜像测试。
