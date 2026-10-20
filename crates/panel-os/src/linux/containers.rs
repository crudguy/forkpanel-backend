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
//! / `pull` / 生命周期（start/stop/restart/rm/rm -f）/ 安装 / 加组。
//! `create` 的宿主机任意代码执行风险由 `validate_create` 强制拦截：禁 `--privileged`、
//! 禁挂载 `/` `/etc` `/proc` `/sys` `/var/run/docker.sock`，且路由层需二次确认词
//! 「创建容器」。
//! **未提供**：镜像删除（磁盘回收风险，刻意不开放）；`docker logs` / `exec` / `stats`、
//! 网络 / 卷管理、compose / stack 暂未实现（非安全刻意排除，后续可补）。

use crate::cmd::{Bin, CmdOpt};
use crate::paths::{LinuxPathLayout, PathLayout};
use crate::traits::*;
use async_trait::async_trait;
use panel_core::{PanelError, Result};
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
}

impl LinuxContainers {
    pub fn detect(paths: Arc<LinuxPathLayout>) -> Self {
        // 二进制存在性：`Bin::available()` 只做文件检查，不执行任何命令
        let engine = if Bin::Docker.available() { ContainerEngine::Docker } else { ContainerEngine::None };
        // 可达性：对 socket 做一次 connect（权限不足 / daemon 未运行都会立即失败）
        let reachable = engine != ContainerEngine::None && socket_connectable(&paths.container_socket());
        Self { engine, reachable }
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
}

// ─────────────── 创建安全校验（纯函数，可离线单测） ───────────────

/// 镜像名不得含空白或 shell 元字符：docker 把 image 当单参数，
/// 含空白会分裂 argv、含元字符可能被 shell 误解析（虽本项目走 argv 直传，仍守底线）。
fn image_is_safe(img: &str) -> bool {
    if img.is_empty() {
        return false; // 空镜像名本身即非法
    }
    !img.chars().any(|c| c.is_whitespace() || ";&|$`\\'\"<>(){}".contains(c))
}

/// 若卷挂载的宿主源路径命中敏感目录，返回该路径（供错误信息）；否则 None。
/// 具名卷（不含 `/`）放行；宿主路径（`/...`）才进入敏感判定。
fn sensitive_host_mount(spec: &str) -> Option<&'static str> {
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
fn port_mapping_is_safe(p: &str) -> bool {
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
fn mem_limit_is_safe(m: &str) -> bool {
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
        return false; // 该平台无 unix socket 概念（如 Windows 命名管道）
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
fn parse_ps(stdout: &str) -> Vec<ContainerSummary> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| ContainerSummary {
            id: jstr(&v, "ID"),
            name: jstr(&v, "Names"),
            image: jstr(&v, "Image"),
            state: jstr(&v, "State"),
            status: jstr(&v, "Status"),
            ports: jstr(&v, "Ports"),
            // 用绝对时间而非 `RunningFor`（"3 hours ago"）：后者对已退出容器语义不明确
            created: jstr(&v, "CreatedAt"),
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
        let c = LinuxContainers { engine: ContainerEngine::None, reachable: false };
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
        let c = LinuxContainers { engine: ContainerEngine::Docker, reachable: false };
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
}
