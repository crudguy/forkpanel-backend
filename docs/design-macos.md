# macOS 适配方案与分期计划

> 目标：让 ForkPanel 在 macOS 上可编译、可启动、可用（按能力诚实降级）。
> 本文是**只读调研**的产出，不含实现。所有结论均以当前代码为准（已逐条核对行号）。

## 0. 结论先行

**架构已经准备好了，缺的是 macOS 实现本身。**

跨平台骨架不是"事后补的"，而是从一开始按可移植设计的：

| 已具备的基础设施 | 位置 | 说明 |
| --- | --- | --- |
| `OsAdapter` 聚合 trait（16 个 provider） | `panel-os/src/lib.rs:34` | 业务层只经此访问 OS；注释明写「新增平台 = 新增一个 impl」 |
| 平台分流入口 | `lib.rs:62` `default_adapter()`、`lib.rs:79` `adapter_with_overrides()` | 已按 `cfg(target_os)` 分流，非 Linux 落 mock |
| 领域模型预置 macOS 变体 | `panel-core/src/lib.rs:100,109,114` | `Os::Macos`、`InitSystem::Launchd`、`FirewallBackend::Pf` **都已存在** |
| 一致性测试（验收判据） | `panel-os/tests/conformance.rs` | 11 条契约，**全部与 Linux 无关**，注释写明「新平台必须全过」 |
| 显式降级纪律 | `panel-os/src/linux/stub/mod.rs:3` | 未实现返回 `Unsupported`，**禁止**返回空 Vec 假装成功 |
| 分层门禁 | `ci/check-layering.sh` `[4]` `[4b]` `[4c]` | 已把 `panel_os::macos::` 列入受限前缀；业务层禁 `cfg(target_os)`、禁直读 `/proc` |

**因此本方案不涉及架构改造，只涉及"填一个 macOS 实现 + 拆掉两处 Linux 硬绑定"。**

## 1. 一个必须先修的前置缺陷（Phase 0，独立于平台选择）

### `build_layout()` 绑死 Linux 路径布局

```rust
// crates/panel-cli/src/main.rs:1136
fn build_layout(_os: &Arc<dyn panel_os::OsAdapter>, cfg: Option<&Config>) -> panel_os::paths::LinuxPathLayout {
    let base = panel_os::paths::LinuxPathLayout::default();   // ← 具体类型，非 dyn PathLayout
    ...
}
```

问题：
1. 返回**具体类型** `LinuxPathLayout` 而非 `Arc<dyn PathLayout>`，CLI 层因此绑死 Linux；
2. `_os` 参数被忽略（下划线前缀即"我没用"），适配器与布局各走各路；
3. 默认值是 `/etc/forkpanel`、`/var/www`、`/var/lib/forkpanel`（`paths.rs:58-67`），macOS 上这些目录并不存在，且 `/var/www` 不是 macOS 的站点目录惯例。

而 `panel_os::adapter_with_overrides()`（`lib.rs:79`）内部**自己**构造 `LinuxPathLayout`，`serve` 路径上（`main.rs:272`）真正生效的是它——`build_layout()` 只被用于「读配置前」的早期探测。即：**两处各建一份布局，靠参数巧合保持一致**，这本身就是脆弱点。

修法：把 `build_layout` 改为经 `OsAdapter` 取平台布局（`os.paths()`），或抽 `PathLayout` 的构造工厂进 `panel-os`。**这条无论最终做不做 macOS 都该修**，属既有代码的可移植性债务。

## 2. 16 个 provider 的 macOS 工作量分级

依据：文件行数 + 是否依赖平台专有接口。

### A 组：几乎可直接复用（Unix/POSIX 通用，0~50 行改动）

| provider | 现有实现 | macOS 动作 |
| --- | --- | --- |
| `StorageProvider` | `linux/stub/storage.rs` 33 行 | 直接复用；`statvfs` BSD 语义相同 |
| `ProcessProvider` | `/proc` 扫描（`metrics.rs:333+`） | 需替代，见 B 组 |
| 路径沙箱 `resolve_within` | `paths.rs:180-212` | **零改动**（纯路径语义，已通过 conformance 契约 10） |
| `sensitive.rs` 黑名单 | 309 行 | 增补 macOS 敏感路径（`/etc/sudoers`、`/System`、`/Library/LaunchDaemons`） |
| `fs.rs` 的 `is_root`/`set_mode`/`read_password` | 已有 `#[cfg(unix)]` 分支 | **零改动**（macOS 命中 unix 分支） |
| `fs.rs` 的 `check_data_dir` | `fs.rs:71-72` **已显式支持 macOS** | 零改动（BSD statfs 语义相同） |

### B 组：必须重写（平台专有接口，各 200~500 行）

| provider | Linux 现状 | macOS 替代方案 | 量级 |
| --- | --- | --- | --- |
| `MetricsProvider` | 452 行，纯读 `/proc/stat`、`/proc/meminfo`、`/proc/net/dev`、`/sys/class/hwmon` | `host_statistics64`(CPU/内存)、`if_msghdr2`(网络)、`statfs`(磁盘)、`IOKit`(温度，可选) | **大** |
| `ProcessProvider` | `/proc/<pid>/stat` 扫描 | `libproc`(`proc_listpids`/`proc_pidinfo`) 或 `ps -axo` | 中 |
| `ServiceProvider` | systemd（`services.rs` 614 行） | `launchctl`（`list`/`load`/`unload`/`kickstart`）+ plist 读写 | **大** |
| `FirewallProvider` | nftables/iptables（`firewall*.rs` 987 行） | `pf`（`pfctl`，需 root + `/etc/pf.conf`） | **大** |
| `PackageProvider` | apt/dnf/apk（`stub/packages.rs` 507 行） | `brew`（`list`/`install`/`upgrade`/`info --json`）；无 brew 则 Unsupported | 中 |
| `WebServerProvider` | nginx/caddy（`stub/webserver.rs` 1437 行） | nginx（brew 装）基本可复用渲染逻辑；路径改 `/opt/homebrew/etc/nginx` | 中 |
| `SchedulerProvider` | crontab（`scheduler.rs` 568 行） | crontab 在 macOS 仍可用（已废弃但工作）；或 `launchd` 定时 | 小~中 |
| `LogProvider` | journald + 文件（`stub/logs.rs` 240 行） | `log show`(统一日志) + 文件；`Journald` 变体不适用 | 中 |
| `UserProvider` | `/etc/passwd`（`stub/users.rs` 203 行） | `dscl`(`/Local/Default/Users`) 或直接读写 `/etc/passwd`（macOS 仍存在） | 小 |
| `NetworkProvider` | `/proc/net/*` | `getifaddrs` + `libproc` | 中 |
| `TerminalProvider` | shell 探测（54 行） | 复用，PATH 需含 `/opt/homebrew/bin` | 小 |
| `DatabaseProvider` | sqlite/mysql/pg CLI 调用（994 行） | 复用（CLI 同名），路径探测加 Homebrew 前缀 | 小 |
| `ContainerProvider` | docker CLI + socket（1457 行） | 复用；socket 路径 `~/.docker/run/docker.sock`（Docker Desktop） | 小~中 |
| `SecurityProvider` | 464 行 | 大量 Linux 专有检查，macOS 先 Unsupported | 大（可延后） |

### C 组：可先整体 Unsupported（诚实置灰）

`SecurityProvider`（基线检查）、`fail2ban`（macOS 无此生态）、`WafSpec` 相关。
按既有纪律返回 `Unsupported` + 能力位 `no(reason)` 即可，前端自动置灰。

## 3. 分期计划

每期都以 **conformance 用例逐条点亮** 作为客观验收判据，不靠"我觉得做完了"。

### Phase 0：解耦前置（无 macOS 代码，纯重构）
- 修 `build_layout()` 绑死 `LinuxPathLayout`（第 1 节）。
- `which()` 的 PATH 列表（`stub/mod.rs`）抽出为平台常量，避免 macOS 上找不到 brew 前缀。
- **验收**：现有 Linux 全量测试与门禁不变绿→不红即可合并（纯重构，行为不变）。

### Phase 1：能编译、能启动、能登录（最小可运行）
- 新建 `panel-os/src/macos/`（`mod.rs` + `paths.rs` + 各 provider 先 `Unsupported`）。
- `MacPathLayout`：`~/Library/Application Support/ForkPanel`（data）、`~/Library/Logs/ForkPanel`、`/opt/homebrew/var/www`（site_root）、`/opt/homebrew/etc/forkpanel`（config）。
- `detect_platform()` 返回 `Os::Macos` + 真实 `sw_vers` 版本。
- `capabilities()` 全部诚实置 no（除 `user.manage` 等内建位），前端菜单自然置灰。
- `lib.rs` 的 `default_adapter()` / `adapter_with_overrides()` 加 `cfg(target_os="macos")` 分支。
- **验收**：macOS 上 `cargo build` 通过；`cargo test -p panel-os --test conformance` 通过契约 1/2/3/9/10（能力自洽、平台信息、路径非空、Unsupported 显式、沙箱拒穿越）；面板能启动、能完成首启、能登录。

### Phase 2：可观测（看板可用）
- `MacMetrics`：CPU/内存/磁盘/网络/负载。**契约 4（快照自洽）点亮**。
- `MacProcesses`：列表 + PID 1 保护 + 信号。**契约 5、6 点亮**。
- `MacNetwork`：接口与监听端口。
- **验收**：看板与进程页真实数据显示正确；conformance 契约 4/5/6 绿。

### Phase 3：文件与终端（管理能力可用）
- `MacFiles`：复用 `fs.rs` 的 unix 分支 + 沙箱；补 macOS 敏感路径。
- `MacTerminal`：复用，PATH 含 brew 前缀。
- **验收**：文件管理器浏览/编辑/上传可用；终端可开。

### Phase 4：服务与包（运维能力）
- `MacServices`（launchctl）+ `MacPackages`（brew）。**契约 7（状态机）点亮**。
- **验收**：服务页可停起；包页可装/卸（brew 存在时）。

### Phase 5+：Web/日志/防火墙/数据库/容器（按需排期）

## 4. 主要风险

| 风险 | 说明 | 缓解 |
| --- | --- | --- |
| **pf 需要 root** | macOS 的 `pfctl` 改规则要 sudo；面板非 root 时整套防火墙不可用 | 能力位诚实 `no(non_root)`；提示用户以 sudo 启动 |
| **launchctl 语义差异大** | systemd 的 unit 概念在 launchd 是 plist + label，`ServiceUnit` 字段不完全对应 | 允许字段留空并注明；conformance 契约 7 只要求状态机不乱 |
| **brew 非系统自带** | 干净 macOS 无 brew，包管理与多数服务安装都依赖它 | 能力位按 `Bin::Brew.available()` 判定，缺失即置灰 |
| **SIP 限制** | 系统完整性保护使 `/System`、`/usr` 部分不可写 | 敏感路径黑名单 + site_root 放在用户可写目录 |
| **无法在 Linux CI 验证 macOS** | 现有 CI 是本机 Debian | 依赖 conformance 的"平台无关"设计；macOS 侧需另设 `macos-latest` runner 或本地验证 |
| **`/proc` 假设散落** | 已由门禁 `[4b]` 扫出业务层禁读，但 `linux/` 内部大量使用，不可直接复用 | macOS 实现独立目录，不 import `linux::*` |

## 5. 与既有纪律的一致性

- **能力位不撒谎**：所有未实现能力 `Capability::no(reason)`，前端自动置灰，不出现"点了必失败"的假按钮。
- **Unsupported ≠ 空结果**：沿用 `stub/mod.rs:3` 的纪律，conformance 契约 9 专门钉这条。
- **业务层零改动**：所有平台知识进 `panel-os/src/macos/`，`ci/check-layering.sh` 的 `[4]`/`[4b]`/`[4c]` 保持全绿。
- **不做"假装可移植"**：不在 Linux 实现里加 `if is_macos`，而是真正独立实现。

## 6. 待老板确认

1. Phase 0 的 `build_layout()` 重构是否现在就做（它与平台无关，属既有债务）。
2. Phase 1 是否接受「先全部置灰、能登录」作为第一交付（而非一次做完看板）。
3. macOS 验证环境：是否有真机/CI runner 可用？没有的话 Phase 2+ 无法客观验收。
