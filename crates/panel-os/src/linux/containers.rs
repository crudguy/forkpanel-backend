//! 容器管理（Docker CLI 后端）。
//!
//! ## 为什么经 CLI 而不是直接打 Docker HTTP API
//! 面板已经有一条**唯一且受控**的子进程出口（`cmd::run`：argv 直传、无 shell、
//! 固定 PATH、强制超时、输出截断、审计）。走 CLI 复用它即可，无需再引入一套
//! HTTP-over-unix-socket 客户端与认证协商（socket 权限本身就是认证边界）。
//!
//! ## 诚实性设计（本文件的核心）
//! **"装了 docker" ≠ "能用 docker"**。本机实测的典型形态：`docker` 二进制在
//! `/usr/bin/docker`、socket 也在，但面板进程不在 `docker` 组 → 连接被拒。
//! 所以能力判定一律看 **socket 可达性**，不看二进制存在性；不可用时给出
//! 可直接行动的 reason（`binary_missing` / `daemon_unreachable`），
//! 前端据此置灰并提示"把面板用户加入 docker 组"，而不是给一个点了就报错的假按钮。
//!
//! ## 已提供与边界
//! 已实现：列举 / 镜像 / `create`（= `docker create`，**默认不启动**而非 `docker run`）
//! / `pull` / 生命周期（start/stop/restart/rm/rm -f）/ 安装 / 加组 / **日志查看**
//! （`docker logs`，只读最近 N 行快照，不带 --follow）/ **资源用量快照**
//! （`docker stats --no-stream --all`，只读一次性快照，不带流式否则阻塞）/
//! **网络列举**（`docker network ls --no-trunc`，只读）/ **卷列举**
//! （`docker volume ls`，只读；⚠ volume ls 无 --no-trunc，卷名是用户定义
//! 名称而非哈希、默认不截断）/ **Compose 项目列举**
//! （`docker compose ls --all --format json`，只读；⚠ compose 的 --format
//! 只接受 `table` / `json` 两个字面量，Go 模板形态会被拒——与 network/volume
//! 的命令形态不同，勿照抄，故走 JSON 解析）。
//! `create` 的宿主机任意代码执行风险由 `validate_create` 强制拦截：禁 `--privileged`、
//! 禁挂载 `/` `/etc` `/proc` `/sys` `/var/run/docker.sock`，且路由层需二次确认词
//! 「创建容器」。
//! **已开放**的 compose 生命周期写操作：`up` / `stop` / `restart` / `down`
//! （`down` **永不传 `-v`**，见 [`ComposeAction::Down`]）；面板编排（stack 定义）
//! 见 [`crate::linux::compose_stack`]。
//! **未提供**（刻意，非遗漏）：镜像删除（磁盘回收风险）；`docker exec`；
//! 卷的创建/删除（**只读列举已开放**；删除卷=数据丢失，与镜像删除同理）；
//! compose **项目级日志**（`docker compose logs` 未接，请用 CLI）；
//! `docker compose` 的 `pull` / `build` / `scale` 等其余子命令。
//! 网络侧刻意**只读列举**：创建/删除网络、容器接入/断开网络等写操作未实现
//! （改网络连通性影响面大，交由 `docker` CLI 手动执行）。
//! 卷侧刻意**只读列举**：创建/删除卷未实现（删除卷有数据丢失风险，
//! 交由 `docker` CLI 手动执行）。

use crate::cmd::{Bin, CmdOpt};
use crate::linux::compose_stack;
use crate::paths::{LinuxPathLayout, PathLayout};
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{PanelError, Result};
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// 单次 docker 调用的超时。列举在容器很多时可能慢，给足余量；
/// 生命周期动作（start/stop）本身很快，但 stop 有 10s 优雅期。
const LIST_TIMEOUT: Duration = Duration::from_secs(20);
const ACT_TIMEOUT: Duration = Duration::from_secs(60);
/// 拉取镜像可能很大、且经镜像源转发，超时给足（10 分钟）。
const PULL_TIMEOUT: Duration = Duration::from_secs(600);

/// `docker stop` 的优雅停机等待秒数（默认 10s，显式写出避免依赖 CLI 默认值变化）
const STOP_GRACE_SECS: &str = "10";

pub struct LinuxContainers {
    engine: ContainerEngine,
    /// 探测结论（构造期一次性求值；`available()` 是纯读，不做重复探测）
    reachable: bool,
    /// 面板数据目录。编排（compose stack）的文件落在 `<data_dir>/compose-stacks/`，
    /// 所以这里必须留下目录——`detect` 接收 `paths` 后不能只取 socket 就丢掉。
    data_dir: std::path::PathBuf,
}

impl LinuxContainers {
    pub fn detect(paths: Arc<LinuxPathLayout>) -> Self {
        // 二进制存在性：`Bin::available()` 只做文件检查，不执行任何命令
        let engine = if Bin::Docker.available() { ContainerEngine::Docker } else { ContainerEngine::None };
        // 可达性：对 socket 做一次 connect（权限不足 / daemon 未运行都会立即失败）
        let reachable = engine != ContainerEngine::None && socket_connectable(&paths.container_socket());
        let data_dir = paths.data_dir();
        Self { engine, reachable, data_dir }
    }

    /// 编排根目录（`<data_dir>/compose-stacks`）
    fn stacks_root(&self) -> std::path::PathBuf {
        crate::linux::compose_stack::stacks_root(&self.data_dir)
    }

    /// 调用前的统一前置检查：不可用即诚实报错，绝不返回空列表冒充"没有容器"。
    fn ensure_ready(&self) -> Result<()> {
        match self.unavailable_reason() {
            None => Ok(()),
            Some("binary_missing") => Err(PanelError::Unsupported("container engine binary not found")),
            Some(_) => Err(PanelError::Unsupported("container daemon unreachable")),
        }
    }

    /// 统一的输出处理：非 0 退出码 → 把 CLI 的 stderr 原样上抛（含真实原因）。
    fn check(out: &crate::cmd::CmdOutput, what: &str) -> Result<()> {
        if out.code == Some(0) {
            return Ok(());
        }
        let detail = if out.stderr.trim().is_empty() { out.stdout.trim() } else { out.stderr.trim() };
        Err(PanelError::Command {
            bin: "docker".into(),
            detail: format!("{what}: {detail}"),
        })
    }

    /// 探测 `docker compose` 子命令是否真的可用。
    ///
    /// 返回 `Some(reason)` 表示**能力缺失**（应报 501 而不是 502），`None` 表示可用。
    /// 只在 `compose ls` 真的失败后调用——正常路径不额外付一次子进程开销。
    ///
    /// 为什么要单独探测，而不是看 socket 是否可达：`container.manage` 能力位只按
    /// 守护进程 socket 可达性判定，**compose 是 Docker 的 CLI 插件**，与 daemon
    /// 完全无关。宿主完全可能「docker 能用、compose 插件没装」（Debian 上
    /// `docker.io` 包不带 compose 插件，需另装 `docker-compose-plugin`）。
    ///
    /// 判据 `docker compose version` 的退出码：插件缺失时 docker 回
    /// `docker: unknown command: docker compose`（真机实测文案），退出码非 0；
    /// 插件存在则打印版本号、退出码 0。**不比对 stderr 文案**——文案随 docker
    /// 版本变化，只认退出码这个稳定契约（V1 独立二进制 `docker-compose` 不在
    /// 本探测范围，本项目只用 `docker compose` 子命令形态）。
    async fn compose_unavailable_reason(&self) -> Option<&'static str> {
        let out = match crate::cmd::run(
            Bin::Docker,
            &["compose", "version"],
            CmdOpt { timeout: LIST_TIMEOUT, ..Default::default() },
        )
        .await
        {
            Ok(o) => o,
            // 探测命令本身跑不起来（二进制消失/超时）⇒ 无法证明 compose 可用。
            // 返回 None 让后续 `compose ls` 自己去报错（那会给出真实 stderr），
            // 而不是在这里武断地宣称"compose 不可用"——探测失败 ≠ 能力缺失。
            Err(_) => return None,
        };
        compose_probe_verdict(out.code)
    }

    /// 创建前的安全校验（固有方法，供 `create` 调用；非 trait 方法）。
    /// provider 层强制：业务层不得假设上游已校验。
    fn validate_create(&self, req: &ContainerCreateReq) -> Result<()> {
        if !panel_core::rules::is_valid_container_ref(&req.name) {
            return Err(PanelError::Validation {
                field: "name",
                reason: "容器名非法（仅允许字母数字与 . _ -，且不得以 - 开头）".into(),
            });
        }
        if req.privileged {
            // 等价宿主机 root：面板绝不提供创建特权容器的入口
            return Err(PanelError::Validation {
                field: "privileged",
                reason: "面板禁止创建特权容器（privileged 必须为 false）".into(),
            });
        }
        if req.image.trim().is_empty() {
            return Err(PanelError::Validation { field: "image", reason: "镜像名不能为空".into() });
        }
        if !image_is_safe(&req.image) {
            return Err(PanelError::Validation { field: "image", reason: "镜像名含非法字符（空白或 shell 元字符）".into() });
        }
        for v in &req.volumes {
            if let Some(s) = sensitive_host_mount(v) {
                return Err(PanelError::Validation {
                    field: "volumes",
                    reason: format!("禁止挂载宿主敏感路径：{s}"),
                });
            }
        }
        for p in &req.ports {
            if !port_mapping_is_safe(p) {
                return Err(PanelError::Validation {
                    field: "ports",
                    reason: format!("端口映射格式非法（应为 host:container[/proto]）：{p}"),
                });
            }
        }
        if let Some(r) = &req.restart {
            if !matches!(r.as_str(), "no" | "on-failure" | "always" | "unless-stopped") {
                return Err(PanelError::Validation { field: "restart", reason: "未知重启策略".into() });
            }
        }
        if let Some(m) = &req.mem_limit {
            if !mem_limit_is_safe(m) {
                return Err(PanelError::Validation { field: "mem_limit", reason: "内存上限格式非法（如 512m / 2g）".into() });
            }
        }
        if let Some(c) = req.cpu_quota {
            if c <= 0.0 || c.is_nan() || c.is_infinite() {
                return Err(PanelError::Validation { field: "cpu_quota", reason: "CPU 配额必须为正数".into() });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ContainerProvider for LinuxContainers {
    fn engine(&self) -> ContainerEngine { self.engine }

    fn available(&self) -> bool { self.reachable }

    fn unavailable_reason(&self) -> Option<&'static str> {
        if self.engine == ContainerEngine::None {
            Some("binary_missing")
        } else if !self.reachable {
            Some("daemon_unreachable")
        } else {
            None
        }
    }

    async fn list(&self) -> Result<Vec<ContainerSummary>> {
        self.ensure_ready()?;
        // `--no-trunc` 保留完整 ID：UI 展示可裁剪，但操作必须用完整 ID
        let out = crate::cmd::run(
            Bin::Docker,
            &["ps", "-a", "--no-trunc", "--format", "{{json .}}"],
            CmdOpt { timeout: LIST_TIMEOUT, ..Default::default() },
        ).await?;
        LinuxContainers::check(&out, "docker ps")?;
        Ok(parse_ps(&out.stdout))
    }

    async fn images(&self) -> Result<Vec<ImageSummary>> {
        self.ensure_ready()?;
        let out = crate::cmd::run(
            Bin::Docker,
            &["images", "--no-trunc", "--format", "{{json .}}"],
            CmdOpt { timeout: LIST_TIMEOUT, ..Default::default() },
        ).await?;
        LinuxContainers::check(&out, "docker images")?;
        Ok(parse_images(&out.stdout))
    }

    async fn act(&self, action: ContainerAction, id: &str) -> Result<()> {
        self.ensure_ready()?;
        // 参数注入防线：该值直接进 argv，`--force` 会被 docker 当选项解析。
        // 白名单校验在调用点也要做（provider 不得假设上游已校验）。
        if !panel_core::rules::is_valid_container_ref(id) {
            return Err(PanelError::Validation {
                field: "id",
                reason: "容器 ID/名称含非法字符（仅允许字母数字与 . _ -，且不得以 - 开头）".into(),
            });
        }
        let args: Vec<&str> = match action {
            ContainerAction::Start => vec!["start", id],
            ContainerAction::Stop => vec!["stop", "-t", STOP_GRACE_SECS, id],
            ContainerAction::Restart => vec!["restart", "-t", STOP_GRACE_SECS, id],
            // 非强制删除**不带 -f**：运行中的容器会被守护进程拒绝，属默认安全行为——
            // 强制删除需显式 `force` 参数（前端确认框里默认不勾选的复选框），
            // 仍是用户的显式决策，不给"一键抹掉生产容器"。
            ContainerAction::Remove => vec!["rm", id],
            // 强制删除：先强制停止再移除（docker rm -f）。仅当调用方显式传 force 时走此分支。
            ContainerAction::RemoveForce => vec!["rm", "-f", id],
        };
        let out = crate::cmd::run(
            Bin::Docker,
            &args,
            CmdOpt { timeout: ACT_TIMEOUT, ..Default::default() },
        ).await?;
        LinuxContainers::check(&out, &format!("docker {}", action.as_str()))
    }

    async fn create(&self, req: ContainerCreateReq) -> Result<ContainerSummary> {
        self.ensure_ready()?;
        self.validate_create(&req)?;

        // 所有动态值先落进 owned buffer，再统一借出 &str —— 既避免 f64 格式化产生的
        // 临时值生命周期问题，也确保**没有任何用户输入以整体字符串形式拼进 argv**
        // （每个字段都是独立的 argv 元素，docker 不会把它当 shell 解析）。
        let mut owned: Vec<String> = vec!["create".into(), "--name".into(), req.name.clone()];
        if let Some(r) = &req.restart {
            owned.push("--restart".into());
            owned.push(r.clone());
        }
        if let Some(c) = req.cpu_quota {
            owned.push("--cpus".into());
            owned.push(c.to_string());
        }
        if let Some(m) = &req.mem_limit {
            owned.push("--memory".into());
            owned.push(m.clone());
        }
        for p in &req.ports {
            owned.push("-p".into());
            owned.push(p.clone());
        }
        for e in &req.env {
            owned.push("-e".into());
            owned.push(e.clone());
        }
        for v in &req.volumes {
            owned.push("-v".into());
            owned.push(v.clone());
        }
        owned.push(req.image.clone());
        for c in &req.cmd {
            owned.push(c.clone());
        }
        let args: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();

        let out = crate::cmd::run(
            Bin::Docker,
            &args,
            CmdOpt { timeout: ACT_TIMEOUT, ..Default::default() },
        ).await?;
        LinuxContainers::check(&out, "docker create")?;

        // `docker create` 成功时 stdout 即完整容器 id；默认**不启动**——
        // 运行生产容器是用户显式的第二步（列表里 start），不提供"创建即运行"的一键风险。
        let id = out.stdout.trim().to_string();
        Ok(ContainerSummary {
            id,
            name: req.name,
            image: req.image,
            state: "created".into(),
            status: "Created".into(),
            ports: req.ports.join(","),
            created: String::new(),
            // 面板 `docker create` 出来的容器没有 compose 标签——它不是 compose 创建的。
            // 硬编码 None 而非去查标签：此刻容器刚建、`docker ps` 未必能立刻看到它。
            compose_project: None,
            compose_service: None,
        })
    }
    async fn pull(&self, image: &str) -> Result<ImageSummary> {
        self.ensure_ready()?;
        // 注入防线：image 直接进 argv，须先校验无空白 / shell 元字符（与 create 同源）。
        if !image_is_safe(image) {
            return Err(PanelError::Validation {
                field: "image",
                reason: "镜像引用含非法字符（仅允许字母数字与 . _ : / -，不得含空白或 shell 元字符）".into(),
            });
        }
        let out = crate::cmd::run(
            Bin::Docker,
            &["pull", image],
            CmdOpt { timeout: PULL_TIMEOUT, ..Default::default() },
        ).await?;
        LinuxContainers::check(&out, "docker pull")?;
        // 拉取成功后回填镜像摘要：解析 image 的 repo:tag（处理 registry 主机端口），
        // 到 images() 里找匹配项；找不到则退回最小摘要（拉取本身已成功）。
        let last_seg = image.rsplit('/').next().unwrap_or(image);
        let (repo_full, tag) = match last_seg.split_once(':') {
            Some((r, t)) if !r.is_empty() => (image[..image.len() - t.len() - 1].to_string(), t.to_string()),
            _ => (image.to_string(), "latest".to_string()),
        };
        let imgs = self.images().await?;
        Ok(imgs.into_iter().find(|i| i.repository == repo_full && i.tag == tag)
            .unwrap_or(ImageSummary {
                id: String::new(),
                repository: repo_full,
                tag,
                size: String::new(),
                created: String::new(),
            }))
    }

    async fn logs(&self, id: &str, opts: ContainerLogsOpts) -> Result<Vec<ContainerLogLine>> {
        self.ensure_ready()?;
        // 参数注入防线：与 `act` 同源——id 直接进 argv，先校验字符集。
        if !panel_core::rules::is_valid_container_ref(id) {
            return Err(PanelError::Validation {
                field: "id",
                reason: "容器 ID/名称含非法字符（仅允许字母数字与 . _ -，且不得以 - 开头）".into(),
            });
        }
        // 所有动态值先落 owned buffer 再借 &str：id 不会被任何用户输入以整体串拼进 argv。
        // 不带 `--follow`：实时跟随会挂住 CLI（stdout 不 EOF），面板只回显最近 N 行快照。
        let tail_s = opts.tail.to_string();
        let mut owned: Vec<String> = vec!["logs".into(), "--tail".into(), tail_s];
        if opts.timestamps {
            owned.push("--timestamps".into());
        }
        owned.push(id.to_string());
        let args: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let out = crate::cmd::run(
            Bin::Docker,
            &args,
            CmdOpt { timeout: Duration::from_secs(20), ..Default::default() },
        ).await?;
        LinuxContainers::check(&out, "docker logs")?;
        Ok(parse_logs(&out.stdout, opts.timestamps))
    }

    async fn stats_all(&self) -> Result<Vec<ContainerStatsLine>> {
        self.ensure_ready()?;
        // `--no-stream`：一次性快照后 CLI 立即退出。若用默认流式模式，stdout 不 EOF、
        // `docker stats` 会一直跑下去，把请求挂死——与 logs 不带 --follow 同理。
        // `--all`：连已停止的容器一并列出（其用量为空，前端展示「—」）。
        // 无 id 参数 → 无参数注入面；format 里的字段名是编译期常量，不经用户输入。
        let args = [
            "stats",
            "--no-stream",
            "--all",
            "--format",
            // 字段间用 Tab 分隔：用量串（如 "12.5MiB / 2GiB"）本身含空格，
            // 用空格分隔会被撕裂，Tab 才是安全分隔符。
            "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}",
        ];
        let out = crate::cmd::run(
            Bin::Docker,
            &args,
            CmdOpt { timeout: Duration::from_secs(20), ..Default::default() },
        )
        .await?;
        LinuxContainers::check(&out, "docker stats")?;
        Ok(parse_stats(&out.stdout))
    }

    async fn networks_all(&self) -> Result<Vec<ContainerNetworkLine>> {
        self.ensure_ready()?;
        // 只读列举：无 id/名称参数 → 无参数注入面；format 里的字段名是编译期
        // 常量，不经用户输入。`--no-trunc` 保留完整 ID（UI 展示可裁剪），
        // 与 list/images 同口径。
        let args = [
            "network",
            "ls",
            "--no-trunc",
            "--format",
            // 字段间用 Tab 分隔，与 stats 同纪律：网络四字段本身不含空格，但
            // 统一 Tab 可让「漏写 --format 时的默认表格输出」被解析器拒绝
            // （表格行按 Tab 拆只有 1 段），而不是把表头行当成数据行。
            "{{.Name}}\t{{.Driver}}\t{{.Scope}}\t{{.ID}}",
        ];
        let out = crate::cmd::run(
            Bin::Docker,
            &args,
            CmdOpt { timeout: LIST_TIMEOUT, ..Default::default() },
        )
        .await?;
        LinuxContainers::check(&out, "docker network ls")?;
        Ok(parse_networks(&out.stdout))
    }

    async fn volumes_all(&self) -> Result<Vec<ContainerVolumeLine>> {
        self.ensure_ready()?;
        // 只读列举：无参数 → 无参数注入面；format 字段名是编译期常量。
        // ⚠ volume ls **没有** --no-trunc（真机探活：带该 flag 直接
        // unknown flag）——卷名是用户定义的名称而非哈希，默认不截断，
        // 与 network ls 的命令形态不同，勿照抄。
        let args = [
            "volume",
            "ls",
            "--format",
            // 字段间 Tab 分隔，与 stats/networks 同纪律：默认表格仅两列
            // （空格填充），按 Tab 拆每行只有 1 段 → 整表被解析器拒绝，
            // 而不是把表头行当成一条合法卷。
            "{{.Name}}	{{.Driver}}	{{.Mountpoint}}",
        ];
        let out = crate::cmd::run(
            Bin::Docker,
            &args,
            CmdOpt { timeout: LIST_TIMEOUT, ..Default::default() },
        )
        .await?;
        LinuxContainers::check(&out, "docker volume ls")?;
        Ok(parse_volumes(&out.stdout))
    }

    async fn compose_projects_all(&self) -> Result<Vec<ContainerComposeProjectLine>> {
        self.ensure_ready()?;
        // ⚠ 先区分「compose 子命令不存在」与「有子命令但执行失败」：前者是**能力缺失**
        // （诚实地报 Unsupported → 501，前端据此置灰并提示装插件），后者才是真错误。
        // 修复前此处直接 `check()`：插件没装时 docker 回 "docker: unknown command"，
        // 被包成 `PanelError::Command`（30000）→ **502 Bad Gateway**，前端只弹一条
        // 带原始 stderr 的红条，与本模块「诚实 501 + 可行动 reason」的纪律相悖。
        if let Some(reason) = self.compose_unavailable_reason().await {
            return Err(PanelError::Unsupported(reason));
        }
        // 只读列举：无参数 → 无参数注入面；format 值是编译期常量。
        // ⚠ compose 的 --format **只接受 table | json 两个字面量**（真机探活
        // v5.6.0：`--format '{{.Name}}\t…'` 直接被拒 "could not be parsed"），
        // 与 network/volume 的 Go 模板形态不同，勿照抄——故走 JSON 解析
        // （serde_json 已是本 crate 依赖，journalctl -o json 在用）。
        // `--all` 含已停止项目，与 list() 的 `docker ps -a` 同口径；不带则
        // 只列 running（真机探活：停止项目被隐藏）。
        let args = ["compose", "ls", "--all", "--format", "json"];
        let out = crate::cmd::run(
            Bin::Docker,
            &args,
            CmdOpt { timeout: LIST_TIMEOUT, ..Default::default() },
        )
        .await?;
        LinuxContainers::check(&out, "docker compose ls")?;
        parse_compose_projects(&out.stdout)
    }

    async fn compose_act(
        &self,
        action: ComposeAction,
        project: &str,
        working_dir: Option<&str>,
    ) -> Result<()> {
        self.ensure_ready()?;
        // ⚠ 项目名直接进 argv，必须严格校验：**禁止首字符 `-`**（否则 `--all` 之类
        // 会被 CLI 当选项）、禁止空白与 shell 元字符。这与 `is_valid_container_ref`
        // 是同一条纪律——compose 项目名的合法字符集更窄（docker 自己要求
        // `[a-z0-9][a-z0-9_-]*`），但这里只做"安全"下限校验，不越权替用户判合法性。
        validate_compose_project(project)?;

        if action.needs_working_dir() && working_dir.map(str::trim).unwrap_or("").is_empty() {
            return Err(PanelError::Validation {
                field: "working_dir",
                reason: "up 需要项目工作目录（compose 靠目录里的配置文件决定启动什么）".into(),
            });
        }
        if let Some(dir) = working_dir {
            validate_compose_working_dir(dir)?;
        }

        if let Some(reason) = self.compose_unavailable_reason().await {
            return Err(PanelError::Unsupported(reason));
        }

        // argv 逐段构造，项目名/目录只作为**独立参数**，绝不做字符串拼接。
        let mut args: Vec<&str> = vec!["compose"];
        if let Some(dir) = working_dir.map(str::trim).filter(|d| !d.is_empty()) {
            args.push("--project-directory");
            args.push(dir);
        }
        args.push("-p");
        args.push(project);
        match action {
            ComposeAction::Up => args.extend(["up", "-d"]),
            ComposeAction::Stop => args.push("stop"),
            ComposeAction::Restart => args.push("restart"),
            // ⚠ 绝不追加 `-v`：那会删掉命名卷（数据丢失）。见 ComposeAction::Down 注释。
            ComposeAction::Down => args.push("down"),
        }

        let out = crate::cmd::run(
            Bin::Docker,
            &args,
            CmdOpt { timeout: ACT_TIMEOUT, ..Default::default() },
        )
        .await?;
        LinuxContainers::check(&out, "docker compose")?;
        Ok(())
    }

    // ── 面板编排（compose stack）──
    //
    // ⚠ 这三个方法**不调用 `ensure_ready()`**：编排文件的读写只碰
    // `<data_dir>/compose-stacks/`，与 docker daemon 毫无关系。daemon 不可用时
    // 用户仍然应该能查看/编辑自己的编排定义（只是不能部署）。
    // 声明 501 会撒谎——那会让"daemon 挂了"看起来像"面板没有编排功能"。

    async fn compose_stacks(&self) -> Result<Vec<ComposeStack>> {
        let root = self.stacks_root();
        tokio::task::spawn_blocking(move || compose_stack::list_stacks(&root))
            .await
            .map_err(|e| PanelError::Internal(format!("编排列举任务失败: {e}")))?
    }

    async fn compose_stack_get(&self, project: &str) -> Result<ComposeStack> {
        validate_compose_project(project)?;
        let root = self.stacks_root();
        let project = project.to_string();
        tokio::task::spawn_blocking(move || compose_stack::load_stack(&root, &project))
            .await
            .map_err(|e| PanelError::Internal(format!("编排读取任务失败: {e}")))?
    }

    async fn compose_stack_save(&self, spec: ComposeStackSpec) -> Result<ComposeStack> {
        // 校验放在阻塞任务外：它是纯 CPU 且失败率高（用户输错很常见），
        // 没必要为一次拒绝去占一个 blocking 线程。
        compose_stack::validate_stack_spec(&spec)?;
        let root = self.stacks_root();
        tokio::task::spawn_blocking(move || compose_stack::save_stack(&root, &spec))
            .await
            .map_err(|e| PanelError::Internal(format!("编排保存任务失败: {e}")))?
    }
}

/// Compose 项目名安全校验（进 argv 白名单）。返回 `Err` 时附可读原因。
///
/// 允许的字符集：字母数字 `_` `-` `.`，**且不得以 `-` 开头**。
/// 不允许 `--`/空格/引号/`;`/`|`/`$` 等——项目名是用户可控输入，
/// 任何一项漏过都能变成参数注入或（若将来改成 shell 调用）命令注入。
pub fn validate_compose_project(project: &str) -> Result<()> {
    let p = project.trim();
    if p.is_empty() {
        return Err(PanelError::Validation { field: "project", reason: "项目名不能为空".into() });
    }
    if p.starts_with('-') {
        return Err(PanelError::Validation {
            field: "project",
            reason: "项目名不得以 - 开头（会被 docker 当作选项解析）".into(),
        });
    }
    if !p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
        return Err(PanelError::Validation {
            field: "project",
            reason: "项目名只能包含字母、数字、下划线、连字符与点".into(),
        });
    }
    Ok(())
}

/// Compose 工作目录校验：必须是绝对路径、不得含 `..`（路径穿越）。
///
/// 为什么不校验"目录里真的有 compose 文件"：那是 compose 自己的职责，
/// 它的报错（`no configuration file provided`）比我们猜的准确；这里只拦
/// **安全**问题（相对路径 / 穿越 / 控制字符），不越权做业务判断。
pub fn validate_compose_working_dir(dir: &str) -> Result<()> {
    let d = dir.trim();
    if d.is_empty() {
        return Ok(());
    }
    if !d.starts_with('/') {
        return Err(PanelError::Validation {
            field: "working_dir",
            reason: "工作目录必须是绝对路径".into(),
        });
    }
    // 逐段检查而不是字符串 `contains("..")`：后者会把合法的 `..foo` 目录误杀。
    if d.split('/').any(|seg| seg == "..") {
        return Err(PanelError::Validation {
            field: "working_dir",
            reason: "工作目录不得包含 ..（路径穿越）".into(),
        });
    }
    if d.chars().any(|c| c.is_control()) {
        return Err(PanelError::Validation {
            field: "working_dir",
            reason: "工作目录不得包含控制字符".into(),
        });
    }
    Ok(())
}

/// 判定 `docker compose version` 的结果是否代表「compose 能力缺失」。
///
/// 抽出成纯函数是为了能单测——`cmd::run` 走固定绝对路径解析，单测里无法注入替身，
/// 而这条判定的正确与否直接决定用户拿到的是「可行动的 501」还是「莫名其妙的 502」。
///
/// - `Some(0)`：插件在，可用 → `None`
/// - 其他退出码：插件缺失或无法执行 → `Some("compose_unavailable")`
/// - `None`（被信号杀死、未拿到退出码）：**不归因为能力缺失**，返回 `None`
///   让调用方把原始错误抛出去。宁可报一个真实错误，也不要错误地宣称"没装插件"。
fn compose_probe_verdict(code: Option<i32>) -> Option<&'static str> {
    match code {
        Some(0) => None,
        Some(_) => Some("compose_unavailable"),
        None => None,
    }
}

/// 解析 `docker logs` 输出（不带 --follow）：每行一条，stdout/stderr 已合并。
/// 带 `--timestamps` 时每行前缀为 RFC3339 时间戳 + 空格，拆出作为 `ts`；
/// 不带则为纯日志文本（`ts` 为 None）。
fn parse_logs(stdout: &str, with_ts: bool) -> Vec<ContainerLogLine> {
    stdout
        .lines()
        .map(|l| {
            if with_ts {
                if let Some((ts, rest)) = l.split_once(' ') {
                    ContainerLogLine { ts: Some(ts.to_string()), text: rest.to_string() }
                } else {
                    ContainerLogLine { ts: None, text: l.to_string() }
                }
            } else {
                ContainerLogLine { ts: None, text: l.to_string() }
            }
        })
        .collect()
}

/// 解析 `docker stats --no-stream` 输出：每行一条，按 Tab 拆 7 段。
/// 字段不足的行直接跳过（容器刚起、daemon 尚未采样时会吐空行或短行），
/// 不做臆测填充——缺数据时宁可少一行，也不要造一个假用量。
fn parse_stats(stdout: &str) -> Vec<ContainerStatsLine> {
    stdout
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() != 7 {
                return None;
            }
            Some(ContainerStatsLine {
                name: f[0].to_string(),
                cpu_perc: f[1].to_string(),
                mem_usage: f[2].to_string(),
                mem_perc: f[3].to_string(),
                net_io: f[4].to_string(),
                block_io: f[5].to_string(),
                pids: f[6].to_string(),
            })
        })
        .collect()
}

/// 解析 `docker network ls --no-trunc --format` 输出：每行一条，按 Tab 拆 4 段。
/// 字段不足的行直接跳过（不做臆测填充——宁可少一行，也不要造一个假网络）。
/// 该解析同时是「必须带 `--format`」的契约：默认表格输出（表头 + 空格填充列）
/// 按 Tab 拆每行只有 1 段、整表被拒，绝不会把表头误当数据行。
fn parse_networks(stdout: &str) -> Vec<ContainerNetworkLine> {
    stdout
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() != 4 {
                return None;
            }
            Some(ContainerNetworkLine {
                name: f[0].to_string(),
                driver: f[1].to_string(),
                scope: f[2].to_string(),
                id: f[3].to_string(),
            })
        })
        .collect()
}

/// 解析 `docker volume ls --format` 输出：每行一条，按 Tab 拆 3 段。
/// 字段不足的行直接跳过（不做臆测填充——宁可少一行，也不要造一个假卷）。
/// 该解析同时是「必须带 `--format`」的契约：默认表格输出（表头 + 空格填充列）
/// 按 Tab 拆每行只有 1 段、整表被拒，绝不会把表头误当数据行。
fn parse_volumes(stdout: &str) -> Vec<ContainerVolumeLine> {
    stdout
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() != 3 {
                return None;
            }
            Some(ContainerVolumeLine {
                name: f[0].to_string(),
                driver: f[1].to_string(),
                mountpoint: f[2].to_string(),
            })
        })
        .collect()
}

/// `docker compose ls --all --format json` 的数组元素原始结构。
/// 字段经 `rename` 与 compose 的 PascalCase JSON 键逐字对齐；刻意**不用**
/// `#[serde(default)]`：缺字段即解析失败并上抛，绝不臆测填充——
/// 宁可整表报错，也不造一个假项目。
#[derive(Debug, Deserialize)]
struct RawComposeProject {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "ConfigFiles")]
    config_files: String,
}

/// 解析 `docker compose ls --all --format json` 输出（JSON 数组）。
/// **必须带 `--format json`** 是该解析的契约：漏写时 docker 输出人类表格
/// （表头 `NAME STATUS CONFIG FILES` + 空格填充列），serde_json 解析失败
/// 并上抛错误，绝不会把表头当成一条合法项目——与 stats/networks/volumes
/// 的 Tab 纪律同向：解析器天然拒绝非契约输出，而非静默吞掉。
/// 空串按空表处理（不同 compose 版本对 0 项目的输出可能是 `[]` 或空串，
/// 二者都不含项目信息）；其余非法形态一律报错。
fn parse_compose_projects(stdout: &str) -> Result<Vec<ContainerComposeProjectLine>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let raw: Vec<RawComposeProject> = serde_json::from_str(trimmed).map_err(|e| {
        PanelError::Internal(format!(
            "docker compose ls 输出不是合法 JSON（--format json 未生效？）: {e}"
        ))
    })?;
    Ok(raw
        .into_iter()
        .map(|p| ContainerComposeProjectLine {
            name: p.name,
            status: p.status,
            config_files: p.config_files,
        })
        .collect())
}

// ─────────────── 创建安全校验（纯函数，可离线单测） ───────────────

/// 镜像名不得含空白或 shell 元字符：docker 把 image 当单参数，
/// 含空白会分裂 argv、含元字符可能被 shell 误解析（虽本项目走 argv 直传，仍守底线）。
pub(crate) fn image_is_safe(img: &str) -> bool {
    if img.is_empty() {
        return false; // 空镜像名本身即非法
    }
    !img.chars().any(|c| c.is_whitespace() || ";&|$`\\'\"<>(){}".contains(c))
}

/// 若卷挂载的宿主源路径命中敏感目录，返回该路径（供错误信息）；否则 None。
/// 具名卷（不含 `/`）放行；宿主路径（`/...`）才进入敏感判定。
pub(crate) fn sensitive_host_mount(spec: &str) -> Option<&'static str> {
    let src = spec.split(':').next().unwrap_or("").trim();
    if src.is_empty() || !src.starts_with('/') {
        return None; // 空或具名卷
    }
    const SENSITIVE: &[&str] = &["/", "/etc", "/var/run/docker.sock", "/proc", "/sys", "/var/run"];
    for s in SENSITIVE {
        if src == *s || src.starts_with(&format!("{s}/")) {
            return Some(s);
        }
    }
    None
}

/// 端口映射 `host:container[/proto]`：端口须为数字，proto 仅 tcp/udp。
pub(crate) fn port_mapping_is_safe(p: &str) -> bool {
    let (hp, proto) = match p.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (p, None),
    };
    if let Some(proto) = proto {
        if proto != "tcp" && proto != "udp" {
            return false;
        }
    }
    match hp.split_once(':') {
        Some((h, c)) => !h.is_empty() && !c.is_empty()
            && h.chars().all(|x| x.is_ascii_digit() || x == '-')
            && c.chars().all(|x| x.is_ascii_digit() || x == '-'),
        None => false, // 必须有 host:container
    }
}

/// 内存上限 `^\d+[kmg]?$`（大小写不敏感，单位可选）。
pub(crate) fn mem_limit_is_safe(m: &str) -> bool {
    let b = m.trim();
    if b.is_empty() {
        return false;
    }
    let digits: String = b.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return false;
    }
    let unit = &b[digits.len()..];
    unit.is_empty() || unit.eq_ignore_ascii_case("k") || unit.eq_ignore_ascii_case("m")
        || unit.eq_ignore_ascii_case("g")
}

/// 守护进程可达性探测：对 unix socket 做一次 connect。
///
/// - 权限不足（不在 docker 组）→ `EACCES`，立即返回 false
/// - daemon 未运行（socket 文件残留）→ `ECONNREFUSED`，立即返回 false
/// - socket 不存在 → `ENOENT`，立即返回 false
///
/// 三种情况对使用者都是"不可用"，无需区分（reason 统一为 `daemon_unreachable`），
/// 但 UI 提示里会同时给出"加入 docker 组 / 启动 daemon"两条排查建议。
fn socket_connectable(p: &Path) -> bool {
    if p.as_os_str().is_empty() {
        return false; // 未配置 socket 路径（无从探测，按不可达处理）
    }
    std::os::unix::net::UnixStream::connect(p).is_ok()
}

// ─────────────── 纯解析层（可离线单测；CLI 输出格式与 daemon 无关） ───────────────

/// 从 JSON 对象里取字符串字段，缺失或非字符串一律回退空串。
/// 刻意宽容：docker 版本间字段增删不应对面板构成致命错误。
fn jstr(v: &serde_json::Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or_default().to_string()
}

/// 解析 `docker ps -a --format '{{json .}}'`：每行一个 JSON 对象。
/// 非 `{` 开头的行（CLI 警告等）直接跳过，不使整个列表失败。
/// 从 `docker ps` 的 `Labels` 字段里取出某个标签值。
///
/// ⚠⚠ **必须按键精确匹配，绝不能用 `contains`**。真机实测的标签串里存在
/// **前缀重叠**：
/// ```text
/// com.docker.compose.project=forkpanel-labelprobe
/// com.docker.compose.project.config_files=/tmp/cprobe/docker-compose.yml
/// com.docker.compose.project.working_dir=/tmp/cprobe
/// ```
/// 用 `contains("com.docker.compose.project")` 会同时命中三条，取到的可能是
/// 配置文件路径而不是项目名（且首条命中顺序取决于 docker 输出顺序，不稳定）。
///
/// `Labels` 是**逗号分隔的 `k=v` 扁平串**（不是 JSON 数组、不是 map）——
/// 真机 `docker ps --format '{{json .}}'` 实测确认。值里可能含 `=`（如 URL 查询
/// 串），故只在**第一个** `=` 处切分。
fn label_value(labels: &str, key: &str) -> Option<String> {
    for kv in labels.split(',') {
        // ⚠ 用 `let ... else { continue }` 而不是 `?`：`?` 会在遇到第一个不含
        // `=` 的片段时**直接让整个函数返回 None**，从而漏掉后面真正的目标标签。
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        if k.trim() == key {
            let v = v.trim();
            // 空值按"没有这个标签"处理：compose 不会写空项目名，出现空值宁可当无。
            return if v.is_empty() { None } else { Some(v.to_string()) };
        }
    }
    None
}

/// `Labels` 串 → (compose 项目名, compose 服务名)。两者都没有则均为 None。
fn compose_identity(labels: &str) -> (Option<String>, Option<String>) {
    (
        label_value(labels, "com.docker.compose.project"),
        label_value(labels, "com.docker.compose.service"),
    )
}

/// 解析 `docker ps -a --no-trunc --format '{{json .}}'` 输出：每行一个 JSON 对象。
/// 非 JSON 行（CLI 警告、空行）直接跳过——与 `docker ps` 混入警告时的容错一致。
fn parse_ps(stdout: &str) -> Vec<ContainerSummary> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| {
            let (compose_project, compose_service) = compose_identity(&jstr(&v, "Labels"));
            ContainerSummary {
                id: jstr(&v, "ID"),
                name: jstr(&v, "Names"),
                image: jstr(&v, "Image"),
                state: jstr(&v, "State"),
                status: jstr(&v, "Status"),
                ports: jstr(&v, "Ports"),
                // 用绝对时间而非 `RunningFor`（"3 hours ago"）：后者对已退出容器语义不明确
                created: jstr(&v, "CreatedAt"),
                compose_project,
                compose_service,
            }
        })
        .collect()
}

/// 解析 `docker images --format '{{json .}}'`（含 `<none>` 悬空镜像，与 CLI 一致）。
fn parse_images(stdout: &str) -> Vec<ImageSummary> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| ImageSummary {
            id: jstr(&v, "ID"),
            repository: jstr(&v, "Repository"),
            tag: jstr(&v, "Tag"),
            size: jstr(&v, "Size"),
            created: jstr(&v, "CreatedAt"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // 真实 `docker ps -a --format '{{json .}}'` 的样本行（字段与 docker 29.x 一致）
    const PS_SAMPLE: &str = concat!(
        r#"{"Command":"\"/docker-entrypoint.sh nginx -g 'daemon off;'\"","CreatedAt":"2026-09-20 08:12:33 +0800 CST","ID":"3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a","Image":"nginx:1.27-alpine","Labels":"maintainer=NGINX Docker Maintainers","LocalVolumes":"1","Mounts":"/data","Names":"web-proxy","Networks":"bridge","Ports":"0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp","RunningFor":"9 days ago","Size":"2.1MB (virtual 55.3MB)","State":"running","Status":"Up 9 days"}"#,
        "\n",
        r#"{"Command":"\"/bin/sh -c sleep 5\"","CreatedAt":"2026-09-29 11:00:00 +0800 CST","ID":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","Image":"alpine:3.20","Labels":"","LocalVolumes":"0","Mounts":"","Names":"oneshot","Networks":"bridge","Ports":"","RunningFor":"2 hours ago","Size":"0B (virtual 7.8MB)","State":"exited","Status":"Exited (0) 2 hours ago"}"#,
    );

    const IMAGES_SAMPLE: &str = concat!(
        r#"{"Containers":"1","CreatedAt":"2026-07-11 10:00:00 +0800 CST","CreatedSince":"2 months ago","Digest":"\u003cnone\u003e","ID":"sha256:1111111111111111111111111111111111111111111111111111111111111111","Repository":"nginx","SharedSize":"N/A","Size":"55.3MB","Tag":"1.27-alpine","UniqueSize":"N/A","VirtualSize":"55.3MB"}"#,
        "\n",
        r#"{"Containers":"N/A","CreatedAt":"2026-09-01 10:00:00 +0800 CST","CreatedSince":"4 weeks ago","Digest":"\u003cnone\u003e","ID":"sha256:2222222222222222222222222222222222222222222222222222222222222222","Repository":"\u003cnone\u003e","SharedSize":"N/A","Size":"7.8MB","Tag":"\u003cnone\u003e","UniqueSize":"N/A","VirtualSize":"7.8MB"}"#,
    );

    #[test]
    fn parses_container_list() {
        let v = parse_ps(PS_SAMPLE);
        assert_eq!(v.len(), 2);

        assert_eq!(v[0].name, "web-proxy");
        assert_eq!(v[0].image, "nginx:1.27-alpine");
        assert_eq!(v[0].state, "running");
        assert_eq!(v[0].status, "Up 9 days");
        assert_eq!(v[0].ports, "0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp");
        assert_eq!(v[0].id.len(), 64, "应保留完整 ID（--no-trunc）");

        assert_eq!(v[1].name, "oneshot");
        assert_eq!(v[1].state, "exited");
        assert!(v[1].ports.is_empty(), "无端口映射应为空串而非缺字段报错");
    }

    #[test]
    fn parses_image_list_including_dangling() {
        let v = parse_images(IMAGES_SAMPLE);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].repository, "nginx");
        assert_eq!(v[0].tag, "1.27-alpine");
        assert_eq!(v[0].size, "55.3MB");
        // 悬空镜像必须保留（与 `docker images` 行为一致），由 UI 决定是否隐藏
        assert_eq!(v[1].repository, "<none>");
        assert_eq!(v[1].tag, "<none>");
    }

    #[test]
    fn tolerates_warnings_and_malformed_lines() {
        // CLI 往 stdout 混入警告行 / 半截 JSON 时，只跳过坏行，不整体失败
        let noisy = format!("WARNING: something\n{{ not json }}\n{PS_SAMPLE}\n");
        let v = parse_ps(&noisy);
        assert_eq!(v.len(), 2, "坏行应被跳过，好行仍解析");
    }

    #[test]
    fn missing_fields_fall_back_to_empty() {
        let v = parse_ps(r#"{"ID":"abc","Names":"x"}"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, "abc");
        assert_eq!(v[0].name, "x");
        assert_eq!(v[0].image, "", "缺字段回退空串，不 panic");
        assert_eq!(v[0].created, "");
    }

    #[test]
    fn empty_engine_is_honest() {
        // 无 socket 路径（空）→ 不可达；`unavailable_reason` 必须给出可行动原因
        let c = LinuxContainers { engine: ContainerEngine::None, reachable: false, data_dir: std::path::PathBuf::new() };
        assert!(!c.available());
        assert_eq!(c.unavailable_reason(), Some("binary_missing"));
        assert!(matches!(
            c.ensure_ready(),
            Err(PanelError::Unsupported(_))
        ));
    }

    #[test]
    fn binary_present_but_daemon_down_is_reported_as_unreachable() {
        // 本机真实形态：二进制在、socket 不可连（权限/未启动）→ 诚实报 daemon_unreachable
        let c = LinuxContainers { engine: ContainerEngine::Docker, reachable: false, data_dir: std::path::PathBuf::new() };
        assert_eq!(c.engine().as_str(), "docker");
        assert!(!c.available());
        assert_eq!(c.unavailable_reason(), Some("daemon_unreachable"));
    }

    #[test]
    fn nonexistent_socket_is_not_connectable() {
        assert!(!socket_connectable(Path::new("/nonexistent/panel-test.sock")));
        assert!(!socket_connectable(Path::new("")), "空路径表示平台无此概念");
    }

    #[test]
    fn action_subcommands_are_fixed() {
        // 子命令是编译期常量，不受输入影响；Remove 刻意不带 -f
        assert_eq!(ContainerAction::Start.as_str(), "start");
        assert_eq!(ContainerAction::Stop.as_str(), "stop");
        assert_eq!(ContainerAction::Remove.as_str(), "remove");
        assert_eq!(ContainerAction::RemoveForce.as_str(), "remove --force");
        assert_eq!(STOP_GRACE_SECS, "10");
    }

    #[test]
    fn detect_uses_configured_socket_path() {
        // 探测必须走 PathLayout（业务层不硬编码路径），此处验证布局确实提供该值
        let layout = LinuxPathLayout::default();
        assert_eq!(layout.container_socket(), std::path::PathBuf::from("/var/run/docker.sock"));
    }

    // ───────── 创建安全校验（纯函数） ─────────

    #[test]
    fn image_is_safe_rejects_shell_meta_and_whitespace() {
        assert!(!image_is_safe("nginx; rm -rf /"));
        assert!(!image_is_safe("foo $(id)"));
        assert!(!image_is_safe("img`whoami`"));
        assert!(!image_is_safe("a b"));        // 空白会分裂 argv
        assert!(!image_is_safe("a|b"));
        assert!(!image_is_safe(""));          // 空
    }

    #[test]
    fn image_is_safe_allows_normal_refs() {
        assert!(image_is_safe("nginx:1.27-alpine"));
        assert!(image_is_safe("registry.example.com/lib/app:latest"));
        assert!(image_is_safe("sha256:abcdef"));
    }

    #[test]
    fn sensitive_host_mount_blocks_root_and_docker_sock() {
        assert_eq!(sensitive_host_mount("/:/host"), Some("/"));
        assert_eq!(sensitive_host_mount("/etc:/etc"), Some("/etc"));
        assert_eq!(sensitive_host_mount("/var/run/docker.sock:/var/run/docker.sock"), Some("/var/run/docker.sock"));
        assert_eq!(sensitive_host_mount("/proc:/proc"), Some("/proc"));
        assert_eq!(sensitive_host_mount("/var/run:/x"), Some("/var/run"));
    }

    #[test]
    fn sensitive_host_mount_allows_named_volume_and_data() {
        assert!(sensitive_host_mount("myvol:/data").is_none());          // 具名卷
        assert!(sensitive_host_mount("/srv/data:/data").is_none());      // 非敏感宿主路径
        assert!(sensitive_host_mount("").is_none());
    }

    #[test]
    fn port_mapping_is_safe_valid() {
        assert!(port_mapping_is_safe("8080:80"));
        assert!(port_mapping_is_safe("8080:80/tcp"));
        assert!(port_mapping_is_safe("53:53/udp"));
        assert!(port_mapping_is_safe("8080-8090:80"));                   // 范围端口
        assert!(!port_mapping_is_safe("80"));                            // 缺 host:container
        assert!(!port_mapping_is_safe("host:80"));                       // host 非数字
        assert!(!port_mapping_is_safe("80:container"));                  // container 非数字
        assert!(!port_mapping_is_safe("80:80/icmp"));                    // 非法 proto
    }

    #[test]
    fn mem_limit_is_safe_valid() {
        assert!(mem_limit_is_safe("512m"));
        assert!(mem_limit_is_safe("2g"));
        assert!(mem_limit_is_safe("1024"));        // 纯字节数也接受
        assert!(!mem_limit_is_safe(""));
        assert!(!mem_limit_is_safe("big"));
        assert!(!mem_limit_is_safe("512x"));
    }

    #[test]
    fn parse_logs_plain() {
        // 不带时间戳：整行即文本，ts 为 None
        let v = parse_logs("hello world\nwarn: low disk\n", false);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].ts, None);
        assert_eq!(v[0].text, "hello world");
        assert_eq!(v[1].text, "warn: low disk");
    }

    #[test]
    fn parse_logs_with_timestamps() {
        // 带时间戳：前缀 RFC3339 + 空格拆出；空格后可能含冒号（级别），整体归 text。
        let line = "2026-10-20T08:00:00.123456789Z INFO started ok";
        let v = parse_logs(line, true);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ts.as_deref(), Some("2026-10-20T08:00:00.123456789Z"));
        assert_eq!(v[0].text, "INFO started ok");
    }

    #[test]
    fn parse_logs_timestamps_without_space_falls_back() {
        // 理论上 docker 带 --timestamps 必有空格，但容错：没空格时 ts=None、整行归 text
        let v = parse_logs("2026-10-20T08:00:00Z-no-space", true);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ts, None);
        assert_eq!(v[0].text, "2026-10-20T08:00:00Z-no-space");
    }

    #[test]
    fn parse_stats_plain() {
        // 用量串本身含空格（"12.5MiB / 2GiB"），只有 Tab 分隔才拆得对
        let line = "web\t1.52%\t12.5MiB / 2GiB\t0.61%\t1.2MB / 800kB\t50MB / 0B\t8";
        let v = parse_stats(&format!("{line}\n"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "web");
        assert_eq!(v[0].cpu_perc, "1.52%");
        assert_eq!(v[0].mem_usage, "12.5MiB / 2GiB");
        assert_eq!(v[0].mem_perc, "0.61%");
        assert_eq!(v[0].net_io, "1.2MB / 800kB");
        assert_eq!(v[0].block_io, "50MB / 0B");
        assert_eq!(v[0].pids, "8");
    }

    #[test]
    fn parse_stats_skips_short_and_empty_lines() {
        // 容器刚起 / daemon 未采样时会吐空行或字段不足的行：跳过而非造数据
        let raw = "web\t1.52%\t12.5MiB / 2GiB\t0.61%\t1.2MB / 800kB\t50MB / 0B\t8\n\nshort\t1%\ncache\t0%\t0B / 0B\t0%\t0B / 0B\t0B / 0B\t2\n";
        let v = parse_stats(raw);
        assert_eq!(v.len(), 2, "只保留两行完整数据，空行与短行被跳过");
        assert_eq!(v[0].name, "web");
        assert_eq!(v[1].name, "cache");
    }

    #[test]
    fn parse_stats_rejects_space_separated_fake() {
        // 负向对照：若实现误用空格分隔，"12.5MiB / 2GiB" 会被撕裂成 9 段而被拒。
        // 断言「撕裂的行进不来」，防止将来有人把分隔符从 Tab 改成空格。
        let bad = "web 1.52% 12.5MiB / 2GiB 0.61% 1.2MB / 800kB 50MB / 0B 8";
        assert!(parse_stats(bad).is_empty(), "空格分隔不得被解析成合法行");
    }

    #[test]
    fn parse_networks_plain() {
        // 真机样本（docker 29.9.1，--no-trunc）：ID 为完整 64 位
        let line = "bridge\tbridge\tlocal\tc1e0dbe7f933cad0ac2c639d9f78afe63e0b54c7671948123324b6068ef1cc0e";
        let v = parse_networks(&format!("{line}\n"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "bridge");
        assert_eq!(v[0].driver, "bridge");
        assert_eq!(v[0].scope, "local");
        assert_eq!(v[0].id.len(), 64, "应保留完整 ID（--no-trunc）");
    }

    #[test]
    fn parse_networks_skips_short_and_empty_lines() {
        // 空行 / 字段不足的行跳过，不造数据（与 parse_stats 同纪律）
        let raw = "bridge\tbridge\tlocal\tc1e0\n\nhost\thost\nnone\tnull\tlocal\t7380\n";
        let v = parse_networks(raw);
        assert_eq!(v.len(), 2, "只保留两行完整数据，空行与短行被跳过");
        assert_eq!(v[0].name, "bridge");
        assert_eq!(v[1].name, "none");
    }

    #[test]
    fn parse_networks_rejects_default_table_output() {
        // 负向对照：若实现漏写 --format，docker 输出默认表格（表头 + 空格填充列，
        // 真机样本）。按 Tab 拆每行只有 1 段 → 整表被拒、返回空，
        // 而不是把表头行当成一条合法网络。断言「默认表格形态进不来」，
        // 防止将来有人删掉 --format 还以为能跑。
        let table = "NETWORK ID     NAME      DRIVER    SCOPE\nc1e0dbe7f933   bridge    bridge    local\n5391e507e83a   host      host      local\n";
        assert!(parse_networks(table).is_empty(), "默认表格输出不得被解析成合法行");
    }

    #[test]
    fn parse_volumes_plain() {
        // 真机样本（docker 29.9.1，临时卷 forkpanel-e2e-probe 实测输出）
        let line = "forkpanel-e2e-probe\tlocal\t/var/lib/docker/volumes/forkpanel-e2e-probe/_data";
        let v = parse_volumes(&format!("{line}\n"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "forkpanel-e2e-probe");
        assert_eq!(v[0].driver, "local");
        assert_eq!(v[0].mountpoint, "/var/lib/docker/volumes/forkpanel-e2e-probe/_data");
    }

    #[test]
    fn parse_volumes_skips_short_and_empty_lines() {
        // 空行 / 字段不足的行跳过，不造数据（与 parse_networks 同纪律）
        let raw = "web-data\tlocal\t/var/lib/docker/volumes/web-data/_data\n\ndb-data\tlocal\n";
        let v = parse_volumes(raw);
        assert_eq!(v.len(), 1, "只保留一行完整数据，空行与短行被跳过");
        assert_eq!(v[0].name, "web-data");
    }

    #[test]
    fn parse_volumes_rejects_default_table_output() {
        // 负向对照：若实现漏写 --format，docker 输出默认表格（表头 + 空格
        // 填充列，真机样本：仅 DRIVER / VOLUME NAME 两列）。按 Tab 拆每行
        // 只有 1 段 → 整表被拒、返回空，而不是把表头当成一条合法卷。
        let table = "DRIVER    VOLUME NAME\nlocal     forkpanel-e2e-probe\n";
        assert!(parse_volumes(table).is_empty(), "默认表格输出不得被解析成合法行");
    }

    #[test]
    fn parse_compose_projects_real_probe() {
        // 真机样本（docker compose v5.6.0，临时项目 forkpanel-compose-probe
        // 实测输出：--all --format json）
        let json = r#"[{"Name":"forkpanel-compose-probe","Status":"running(1)","ConfigFiles":"/tmp/forkpanel-compose-probe/docker-compose.yml"}]"#;
        let v = parse_compose_projects(json).expect("真机 JSON 样本必须解析成功");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "forkpanel-compose-probe");
        assert_eq!(v[0].status, "running(1)");
        assert_eq!(v[0].config_files, "/tmp/forkpanel-compose-probe/docker-compose.yml");
    }

    #[test]
    fn parse_compose_projects_empty_array() {
        // 真机 0 项目输出即 `[]`（探针实测）→ 空表，不是错误
        let v = parse_compose_projects("[]").expect("空数组必须解析为空表");
        assert!(v.is_empty());
    }

    #[test]
    fn parse_compose_projects_rejects_default_table_output() {
        // 负向对照：若实现漏写 --format json，docker 输出人类表格（真机样本）。
        // serde_json 解析失败并上抛错误——绝不会把表头当成一条合法项目
        // （与 parse_networks / parse_volumes 的 Tab 纪律同向）。
        let table = "NAME                      STATUS              CONFIG FILES\nforkpanel-compose-probe   running(1)          /tmp/forkpanel-compose-probe/docker-compose.yml\n";
        assert!(
            parse_compose_projects(table).is_err(),
            "默认表格输出不得被解析成合法项目"
        );
    }

    #[test]
    fn parse_compose_projects_rejects_missing_field() {
        // 缺字段（如旧版 compose 不带 ConfigFiles）→ 整表报错，不臆测填充
        let json = r#"[{"Name":"x","Status":"running(1)"}]"#;
        assert!(
            parse_compose_projects(json).is_err(),
            "缺字段的 JSON 不得被部分接受"
        );
    }

    /// **诚实性守卫**：compose 插件缺失必须被判成「能力缺失」（→501），    /// 而不是让它掉进 `check()` 变成 502 Bad Gateway。
    ///
    /// 回归场景（本测试要抓的）：把 `compose_projects_all` 里那段
    /// `compose_unavailable_reason` 预检删掉，`docker compose ls` 就会以非 0 退出，
    /// 被包成 `PanelError::Command`（30000）→ HTTP 502，前端弹原始 stderr 红条，
    /// 而用户真正需要的是"请安装 docker-compose-plugin"这句可行动提示。
    #[test]
    fn compose_probe_verdict_flags_missing_plugin() {
        // 插件存在：`docker compose version` 退出码 0
        assert_eq!(compose_probe_verdict(Some(0)), None, "插件可用时不得报能力缺失");

        // 插件缺失：docker 回 `docker: unknown command: docker compose`，退出码 1
        // （真机实测文案见注释；这里只认退出码，不比对文案）
        assert_eq!(
            compose_probe_verdict(Some(1)),
            Some("compose_unavailable"),
            "非 0 退出码必须判为能力缺失，否则会退化成 502"
        );

        // 未拿到退出码（被信号杀死）≠ 能力缺失：不得武断宣称没装插件
        assert_eq!(
            compose_probe_verdict(None),
            None,
            "拿不到退出码时应让原始错误上抛，不归因为能力缺失"
        );
    }

    /// ⚠⚠ **前缀重叠陷阱**（真机实测的标签串，逐字取自 docker 输出）。
    ///
    /// `com.docker.compose.project` 同时是
    /// `com.docker.compose.project.config_files` 与 `...project.working_dir` 的
    /// **真前缀**。用 `contains` 实现会命中三条中的任意一条，取到的可能是配置文件
    /// 路径。本测试把 config_files 与 working_dir 放在**前面**，确保实现若用
    /// `contains` 会先命中它们而失败。
    #[test]
    fn compose_identity_does_not_confuse_project_with_config_files() {
        let labels = "com.docker.compose.project.config_files=/tmp/cprobe/docker-compose.yml,\
com.docker.compose.project.working_dir=/tmp/cprobe,\
com.docker.compose.project=forkpanel-labelprobe,\
com.docker.compose.service=web";
        let (project, service) = compose_identity(labels);
        assert_eq!(
            project.as_deref(),
            Some("forkpanel-labelprobe"),
            "必须取到项目名，而不是 config_files/working_dir 的路径"
        );
        assert_eq!(service.as_deref(), Some("web"));
    }

    #[test]
    fn compose_identity_is_none_for_plain_container() {
        // 非 compose 创建的容器（如 `docker run` / 面板 `docker create`）没有这些标签
        let labels = "maintainer=nginx@gmail.com,org.opencontainers.image.version=1.27";
        assert_eq!(compose_identity(labels), (None, None));
        // 空 Labels 是常态（无标签容器），不得 panic
        assert_eq!(compose_identity(""), (None, None));
    }

    #[test]
    fn compose_identity_tolerates_junk_segments() {
        // 片段里没有 `=` 时不能整体放弃（`split_once(...)?` 会提前返回 None，
        // 从而漏掉后面真正的标签——这是本函数写错过一次的 bug）
        let labels = "noequals,\
com.docker.compose.project=proj";
        let (project, _) = compose_identity(labels);
        assert_eq!(project.as_deref(), Some("proj"), "无 `=` 的片段应跳过而非终止解析");
    }

    #[test]
    fn compose_identity_treats_empty_value_as_absent() {
        // 值为空 ⇒ 视为没有该标签（compose 不会写空项目名）
        let (project, service) = compose_identity("com.docker.compose.project=,com.docker.compose.service=");
        assert_eq!(project, None);
        assert_eq!(service, None);
    }

    /// 端到端：`docker ps` 的真实 JSON 行 → `ContainerSummary` 带上 compose 身份。
    /// 用真机抓到的字段集合（含 Labels）构造，确保 parse_ps 的接线不会漏。
    #[test]
    fn parse_ps_extracts_compose_identity() {
        let line = r#"{"ID":"abc123","Names":"forkpanel-labelprobe-web-1","Image":"alpine:3.20","State":"running","Status":"Up 2 minutes","Ports":"","CreatedAt":"2026-10-20 16:53:00 +0800 CST","Labels":"com.docker.compose.project.config_files=/tmp/cprobe/docker-compose.yml,com.docker.compose.project=forkpanel-labelprobe,com.docker.compose.service=web"}"#;
        let v = parse_ps(line);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].compose_project.as_deref(), Some("forkpanel-labelprobe"));
        assert_eq!(v[0].compose_service.as_deref(), Some("web"));
    }

    // ── Compose 写操作的安全不变量 ──

    /// ⭐⭐ **`down` 绝不能带 `-v`**：`-v` 会删除项目的命名卷（数据丢失）。
    ///
    /// 这是本模块最重要的单条不变量。判据直接从**源码**取 `compose_act` 的
    /// argv 构造段，断言 `Down` 分支只 push `"down"`，不含 `-v`/`--volumes`。
    ///
    /// 为什么用源码断言而不是行为测试：`compose_act` 会真的调用 docker，
    /// 单测里跑不起来；而这条规则的失效后果（用户以为只是停服务，实际数据没了）
    /// 严重到不能只靠人工 review。⚠ 断言前必须剔除注释行——注释里明明白白
    /// 写着「绝不追加 -v」，不剔除会恒绿。
    #[test]
    fn compose_down_never_passes_volumes_flag() {
        let src = include_str!("containers.rs");
        // 只取 argv 构造的那几行（从 `match action {` 到 `};` 之后的 run 调用前）
        let code: Vec<&str> = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let joined = code.join("\n");
        let start = joined
            .find("ComposeAction::Up => args.extend([\"up\", \"-d\"]),")
            .expect("argv 构造段必须存在");
        let end = joined[start..]
            .find("let out = crate::cmd::run(")
            .expect("argv 构造段必须以 run 调用结束");
        let block = &joined[start..start + end];
        assert!(
            block.contains("\"down\""),
            "Down 分支必须存在。当前块：\n{block}"
        );
        assert!(
            !block.contains("\"-v\"") && !block.contains("\"--volumes\"") && !block.contains("-v "),
            "down 绝不能带 -v/--volumes（会删除命名卷 = 数据丢失）。\n\
             这是有意的功能缺失，不是遗漏。当前块：\n{block}"
        );
    }

    /// 项目名白名单：首字符 `-` 必须被拒（否则 `--all` 之类会被 docker 当选项）。
    #[test]
    fn compose_project_rejects_leading_dash() {
        assert!(validate_compose_project("--all").is_err(), "首字符 - 是参数注入");
        assert!(validate_compose_project("-p").is_err());
        assert!(validate_compose_project("").is_err());
        assert!(validate_compose_project("   ").is_err());
    }

    /// 项目名白名单：shell 元字符与空白一律拒绝。
    #[test]
    fn compose_project_rejects_metacharacters() {
        for bad in ["a b", "a;b", "a|b", "a$(id)", "a`id`", "a/b", "a&&b", "a'b"] {
            assert!(
                validate_compose_project(bad).is_err(),
                "`{bad}` 含危险字符，必须被拒"
            );
        }
        // 合法项目名必须放行（别把正常用法一起拦了）
        for good in ["web-stack", "my_app", "app.v2", "Web123"] {
            assert!(
                validate_compose_project(good).is_ok(),
                "`{good}` 是合法项目名，不应被拒"
            );
        }
    }

    /// 工作目录：必须绝对路径、不得 `..` 穿越。
    #[test]
    fn compose_working_dir_rejects_relative_and_traversal() {
        assert!(validate_compose_working_dir("/srv/web").is_ok());
        assert!(validate_compose_working_dir("").is_ok(), "空表示不提供");
        assert!(validate_compose_working_dir("srv/web").is_err(), "相对路径必须被拒");
        assert!(
            validate_compose_working_dir("/srv/../../etc").is_err(),
            "路径穿越必须被拒"
        );
        // ⚠ 目录名里含 `..` 但不是穿越段（如 `..foo`）应当放行——
        // 用 `contains("..")` 实现会误杀，本断言专门钉这一点。
        assert!(
            validate_compose_working_dir("/srv/..foo").is_ok(),
            "`..foo` 是合法目录名，不是路径穿越"
        );
    }

    /// 只有 `up` 需要工作目录（真机实测：`-p` 无法定位配置文件）。
    #[test]
    fn compose_only_up_needs_working_dir() {
        assert!(ComposeAction::Up.needs_working_dir());
        for a in [ComposeAction::Stop, ComposeAction::Restart, ComposeAction::Down] {
            assert!(
                !a.needs_working_dir(),
                "{} 只操作已有容器，靠 -p 就够，不该强制要求目录",
                a.as_str()
            );
        }
    }
}
