//! 面板编排（Compose stack）的存储与渲染。
//!
//! ## 设计核心：面板"生成"文件，而不是"解析"文件
//!
//! 磁盘上两份文件：
//! - `.forkpanel-compose.json` —— **单一事实源**，面板只读写它（serde_json 已有依赖）；
//! - `compose.yaml` —— 渲染产物，给人看、给 `docker compose` 用。
//!
//! 为什么不是反过来（让用户直接编辑 YAML、面板去解析）：本 crate 的依赖预算
//! 是 38/38 已满，加不了 YAML 解析器；更要紧的是，允许自由 YAML 就等于允许
//! `privileged: true` / 挂载 `/` / 挂 `docker.sock`——那正是
//! `validate_create` 一直在拦的东西。用**类型白名单**（见 `ComposeStackService`）
//! 让危险字段在生成阶段就不可能出现，比"解析后黑名单过滤"可证明得多。
//!
//! ## 外部修改怎么处理
//!
//! 用户在 CLI 里手改 `compose.yaml` 是合法行为，面板不能装作没发生。
//! 检测方式是**重新渲染一遍再逐字节比对**（不需要哈希依赖）：
//! 一致 ⇒ 面板管的；不一致 ⇒ `externally_modified = true`，且**拒绝覆盖保存**，
//! 由用户决定是放弃面板管理还是删掉这边的元数据。

use crate::linux::containers::{
    image_is_safe, mem_limit_is_safe, port_mapping_is_safe, sensitive_host_mount,
    validate_compose_project,
};
use crate::traits::{ComposeStack, ComposeStackSpec};
use panel_core::{PanelError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 元数据文件名（单一事实源）。点开头避免与用户的 compose 文件混淆。
pub const STACK_META_FILE: &str = ".forkpanel-compose.json";
/// 渲染产物文件名。刻意用 `compose.yaml`（compose 默认查找名），
/// 这样用户在 stack 目录里直接 `docker compose up` 也能跑。
pub const STACK_YAML_FILE: &str = "compose.yaml";

/// 面板管理的所有 stack 的根目录（`<data_dir>/compose-stacks`）。
pub fn stacks_root(data_dir: &Path) -> PathBuf {
    data_dir.join("compose-stacks")
}

/// 单个 stack 的目录。`project` 已过 [`validate_compose_project`]（禁 `/`、禁 `..`），
/// 因此这里的 `join` 不会越界——**调用方必须先校验**，本函数不做二次防护。
pub fn stack_dir(root: &Path, project: &str) -> PathBuf {
    root.join(project)
}

/// 校验一次编排提交。**在写任何文件之前**调用，任一项不合法就整体拒绝。
///
/// 复用的是容器创建那套校验器（同一份实现，不另写一份）——
/// 两份实现会随时间分叉，而这类分叉就是"面板拦得住 create、拦不住 stack"的来源。
pub fn validate_stack_spec(spec: &ComposeStackSpec) -> Result<()> {
    validate_compose_project(&spec.project)?;

    if spec.services.is_empty() {
        return Err(PanelError::Validation {
            field: "services",
            reason: "至少需要一个服务".into(),
        });
    }

    let mut seen: Vec<&str> = Vec::new();
    for s in spec.services.iter() {
        if s.name.trim().is_empty() {
            return Err(PanelError::Validation {
                field: "services",
                reason: "服务名不能为空".into(),
            });
        }
        if !panel_core::rules::is_valid_container_ref(&s.name) {
            return Err(PanelError::Validation {
                field: "services",
                reason: "服务名只能包含字母、数字与 . _ -，且不得以 - 开头".into(),
            });
        }
        if seen.contains(&s.name.as_str()) {
            return Err(PanelError::Validation {
                field: "services",
                reason: format!("服务名重复：{}", s.name),
            });
        }
        seen.push(&s.name);

        if s.image.trim().is_empty() {
            return Err(PanelError::Validation {
                field: "services",
                reason: "镜像不能为空".into(),
            });
        }
        if !image_is_safe(&s.image) {
            return Err(PanelError::Validation {
                field: "services",
                reason: "镜像名含非法字符（空白或 shell 元字符）".into(),
            });
        }

        for p in &s.ports {
            if !port_mapping_is_safe(p) {
                return Err(PanelError::Validation {
                    field: "services",
                    reason: format!("端口映射格式非法（应为 host:container[/proto]）：{p}"),
                });
            }
        }

        for v in &s.volumes {
            if let Some(bad) = sensitive_host_mount(v) {
                return Err(PanelError::Validation {
                    field: "services",
                    reason: format!("禁止挂载宿主敏感路径：{bad}"),
                });
            }
        }

        if let Some(m) = &s.mem_limit {
            if !mem_limit_is_safe(m) {
                return Err(PanelError::Validation {
                    field: "services",
                    reason: "内存上限格式非法（如 512m / 2g）".into(),
                });
            }
        }

        if let Some(r) = &s.restart {
            if !matches!(r.as_str(), "no" | "on-failure" | "always" | "unless-stopped") {
                return Err(PanelError::Validation {
                    field: "services",
                    reason: "未知重启策略（no / on-failure / always / unless-stopped）".into(),
                });
            }
        }

        for e in &s.env {
            validate_env_entry(e).map_err(|reason| PanelError::Validation {
                field: "services",
                reason,
            })?;
        }

        for c in &s.command {
            // NUL 会让 argv（以及 YAML 转义）出现难以排查的截断；换行在同一条
            // 命令参数里没有语义。两者都直接拒掉，而不是转义后"看起来能跑"。
            if c.contains('\0') || c.contains('\n') {
                return Err(PanelError::Validation {
                    field: "services",
                    reason: "命令参数不得包含 NUL 或换行".into(),
                });
            }
        }
    }
    Ok(())
}

/// 环境变量必须是 `KEY=VALUE`，KEY 遵循 shell 标识符规则。
fn validate_env_entry(entry: &str) -> std::result::Result<(), String> {
    let Some((k, _)) = entry.split_once('=') else {
        return Err(format!("环境变量必须是 KEY=VALUE 形式：{entry}"));
    };
    if k.is_empty() {
        return Err("环境变量名不能为空".into());
    }
    let mut chars = k.chars();
    let first = chars.next().unwrap_or(' ');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!("环境变量名必须以字母或下划线开头：{k}"));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("环境变量名只能包含字母、数字与下划线：{k}"));
    }
    Ok(())
}

/// 渲染 `compose.yaml`。
///
/// 生成物是**确定性**的（同一 spec 永远得到同一份字节），
/// 外部修改检测正是依赖这一点：重新渲染后逐字节比对。
///
/// ⚠⚠ **所有标量一律加双引号，不做任何"裸写"**。这条是真机踩出来的：
/// 最初 `command` 用裸写，`["sleep", "300"]` 渲染成 `command: [sleep, 300]`，
/// compose 直接拒绝——`services.web.command.1 must be a string`
/// （YAML 把 `300` 解析成整数，而 compose 要求 command 的每个元素都是字符串）。
/// 同类风险遍布全文件：`mem_limit: 1024`、`image: 300`、`restart: no`
/// （`no` 在 YAML 1.1 是布尔 false）都会被类型推断吃掉。
///
/// 与其逐个列"哪些要引号"（漏一个就是一个线上 bug），不如全部引号：
/// 生成器不该给解析器留任何推断空间。可读性损失很小，正确性可证明。
pub fn render_compose_yaml(spec: &ComposeStackSpec) -> String {
    let mut out = String::new();
    out.push_str("# 本文件由 ForkPanel 生成，请勿手工编辑。\n");
    out.push_str("# 面板以同目录的 .forkpanel-compose.json 为准；\n");
    out.push_str("# 在面板外改动本文件会让面板拒绝再编辑它（避免覆盖你的修改）。\n");
    out.push_str("services:\n");

    for s in &spec.services {
        out.push_str(&format!("  {}:\n", s.name));
        out.push_str(&format!("    image: {}\n", yaml_quoted(&s.image)));
        if !s.command.is_empty() {
            out.push_str(&format!("    command: {}\n", yaml_seq(&s.command)));
        }
        if !s.ports.is_empty() {
            // 端口尤其危险：YAML 1.1 把 `22:22` 当六进制数（base-60 = 1342）
            out.push_str(&format!("    ports: {}\n", yaml_seq(&s.ports)));
        }
        if !s.env.is_empty() {
            // 值里可能有空格、`#`、引号
            out.push_str(&format!("    environment: {}\n", yaml_seq(&s.env)));
        }
        if !s.volumes.is_empty() {
            out.push_str(&format!("    volumes: {}\n", yaml_seq(&s.volumes)));
        }
        if let Some(r) = &s.restart {
            out.push_str(&format!("    restart: {}\n", yaml_quoted(r)));
        }
        if let Some(m) = &s.mem_limit {
            out.push_str(&format!("    mem_limit: {}\n", yaml_quoted(m)));
        }
    }

    // ⚠⚠ 顶层 `volumes:` 声明是 compose 的**语义要求**，不是可选项。
    // 真机踩到：服务里写 `probe-data:/data` 而顶层没声明，compose 直接报
    // `service "web" refers to undefined volume probe-data: invalid compose project`。
    // 只声明**具名卷**（源不以 `/` 或 `.` 开头）：绑定挂载（`/srv/x:/x`）
    // 与匿名卷（只写容器内路径）都不需要也不能出现在顶层。
    let named = named_volumes(spec);
    if !named.is_empty() {
        out.push_str("volumes:\n");
        for v in named {
            // 空映射 `{}`：让 compose 用默认 driver 自动创建
            out.push_str(&format!("  {}: {{}}\n", v));
        }
    }
    out
}

/// 收集所有服务里用到的**具名卷**（去重、按字母序保证确定性）。
fn named_volumes(spec: &ComposeStackSpec) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    for s in &spec.services {
        for v in &s.volumes {
            if let Some(src) = named_volume_source(v) {
                set.insert(src.to_string());
            }
        }
    }
    set.into_iter().collect()
}

/// 从一条挂载串里取出具名卷名；绑定挂载 / 匿名卷返回 None。
///
/// 判据与 `sensitive_host_mount` 同源：源部分以 `/` 开头是宿主绝对路径，
/// 以 `.` 开头是相对路径（都是绑定挂载），其余才是具名卷。
fn named_volume_source(spec: &str) -> Option<&str> {
    let src = spec.split(':').next()?.trim();
    if src.is_empty() || src.starts_with('/') || src.starts_with('.') {
        return None;
    }
    Some(src)
}

/// 渲染一个 YAML 序列（流式）。元素**一律**加双引号（理由见 `render_compose_yaml`）。
fn yaml_seq(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| yaml_quoted(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// 双引号形式。**借 `serde_json` 的字符串转义**：YAML 1.2 的双引号转义规则是
/// JSON 的超集，所以 JSON 的转义结果在 YAML 里同样合法——不必手写一套转义
/// （手写转义是这类生成器最常见的出错点）。
fn yaml_quoted(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s.replace('"', "\\\"")))
}

/// 元数据文件的实际结构（`.forkpanel-compose.json` 的内容）。
///
/// ⚠ 为什么不直接序列化 `ComposeStackSpec`：外部修改检测需要知道
/// **"面板当初写下的 yaml 是什么"**。如果改用"按当前渲染器重新渲染再比对"，
/// 那么渲染器一升级（比如从裸写改成全引号），所有既有文件都会被误判成
/// "被外部修改"从而**拒绝保存**——一次正常的版本升级就把用户的编排锁死。
///
/// 存快照后，判据变成"磁盘上的 yaml 是否还等于我们当初写的那份"，与渲染器版本无关。
/// 代价是元数据里多存一份 yaml 全文（几 KB），值得。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StackMeta {
    /// 元数据格式版本，便于将来迁移
    version: u32,
    /// 生成时 `compose.yaml` 的完整内容快照
    yaml: String,
    spec: ComposeStackSpec,
}

const META_VERSION: u32 = 1;

/// 从磁盘读一个 stack。`project` 必须是合法的项目名（调用方先校验）。
pub fn load_stack(root: &Path, project: &str) -> Result<ComposeStack> {
    let dir = stack_dir(root, project);
    let meta_path = dir.join(STACK_META_FILE);
    let raw = std::fs::read_to_string(&meta_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PanelError::NotFound(format!("编排项目不存在: {project}"))
        } else {
            PanelError::Io(format!("读取编排元数据失败: {e}"))
        }
    })?;
    let meta: StackMeta = serde_json::from_str(&raw)
        .map_err(|e| PanelError::Internal(format!("编排元数据损坏（不是合法 JSON）: {e}")))?;
    let spec = meta.spec;

    // 元数据里的 project 必须与目录名一致，否则说明有人手工改过 JSON：
    // 这种不一致会让"面板显示的项目"与"实际 -p 的项目"分叉，直接报错更安全。
    if spec.project != project {
        return Err(PanelError::Internal(format!(
            "编排元数据与目录不一致（元数据 project={}，目录={project}）",
            spec.project
        )));
    }

    let yaml_path = dir.join(STACK_YAML_FILE);
    // 外部修改判据：磁盘 yaml 是否还等于**当初写下的那份**。
    // 文件被删除也算（随后再保存会重建它，不算冲突——见 save_stack）。
    let disk = std::fs::read_to_string(&yaml_path).ok();
    let externally_modified = match disk {
        Some(d) => d != meta.yaml,
        None => false,
    };

    Ok(ComposeStack {
        project: spec.project,
        dir: dir.to_string_lossy().to_string(),
        config_file: yaml_path.to_string_lossy().to_string(),
        services: spec.services,
        externally_modified,
    })
}

/// 列出所有面板管理的 stack。目录不存在 → 空表（不是错误）。
pub fn list_stacks(root: &Path) -> Result<Vec<ComposeStack>> {
    let rd = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PanelError::Io(format!("读取编排目录失败: {e}"))),
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        // 只认带元数据的目录：用户在 compose-stacks 下随手放的其他目录一律无视
        if !entry.path().join(STACK_META_FILE).is_file() {
            continue;
        }
        // 单个 stack 损坏不应让整个列表失败：跳过并继续（列表页要能打开）
        if let Ok(st) = load_stack(root, &name) {
            out.push(st);
        }
    }
    out.sort_by(|a, b| a.project.cmp(&b.project));
    Ok(out)
}

/// 保存（创建或更新）。返回落盘后的实际状态。
///
/// 拒绝条件：已存在且 `compose.yaml` 被外部改过——这时覆盖会**静默丢掉用户的修改**。
pub fn save_stack(root: &Path, spec: &ComposeStackSpec) -> Result<ComposeStack> {
    validate_stack_spec(spec)?;

    let dir = stack_dir(root, &spec.project);
    let meta = dir.join(STACK_META_FILE);

    if meta.exists() {
        let existing = load_stack(root, &spec.project)?;
        if existing.externally_modified {
            return Err(PanelError::Conflict(format!(
                "编排项目 {} 的 compose.yaml 已被外部修改，面板不会覆盖它；\
                 请先在面板外确认该文件的改动，或删除 {} 后重新创建",
                spec.project, existing.dir
            )));
        }
    }

    std::fs::create_dir_all(&dir).map_err(|e| PanelError::Io(format!("创建编排目录失败: {e}")))?;

    // 先渲染一次，yaml 内容同时用于落盘和写进元数据快照（保证两者逐字节一致）
    let yaml = render_compose_yaml(spec);

    // 先写 YAML 再写元数据：万一中途失败，磁盘上留下的是"有 yaml 无元数据"，
    // 列表页会忽略它（只认带元数据的目录），不会显示一个半成品项目。
    atomic_write(&dir.join(STACK_YAML_FILE), yaml.as_bytes())?;
    let meta = StackMeta {
        version: META_VERSION,
        yaml,
        spec: spec.clone(),
    };
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| PanelError::Internal(format!("序列化编排元数据失败: {e}")))?;
    atomic_write(&dir.join(STACK_META_FILE), meta_json.as_bytes())?;

    load_stack(root, &spec.project)
}

/// 原子写：临时文件 + fsync + rename。与 `linux/files.rs` 的写入同口径，
/// 避免"写到一半断电留下半截 compose.yaml"。
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| PanelError::Io("路径没有父目录".into()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "f".into());
    let tmp = dir.join(format!(".panel-tmp-{}.{}", std::process::id(), name));
    std::fs::write(&tmp, data).map_err(|e| PanelError::Io(format!("write tmp: {e}")))?;
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        PanelError::Io(format!("rename: {e}"))
    })?;
    Ok(())
}

/// 便于调用方构造目录：`<data_dir>/compose-stacks/<project>`
pub fn stack_working_dir(root: &Path, project: &str) -> String {
    stack_dir(root, project).to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ComposeStackService;

    fn svc(name: &str) -> ComposeStackService {
        ComposeStackService {
            name: name.into(),
            image: "nginx:1.27-alpine".into(),
            ..Default::default()
        }
    }

    fn spec(project: &str, services: Vec<ComposeStackService>) -> ComposeStackSpec {
        ComposeStackSpec { project: project.into(), services }
    }

    // ── 渲染 ──

    /// ⭐ YAML 1.1 把 `22:22` 当六进制数（base-60 = 1342）。端口必须加引号，
    /// 否则 compose 在某些版本下会拿到 1342 这种荒唐端口。
    #[test]
    fn render_quotes_ports_to_avoid_sexagesimal() {
        let s = ComposeStackSpec {
            project: "p".into(),
            services: vec![ComposeStackService {
                ports: vec!["22:22".into()],
                ..svc("web")
            }],
        };
        let y = render_compose_yaml(&s);
        assert!(
            y.contains("ports: [\"22:22\"]"),
            "端口必须带引号，否则 YAML 1.1 会解析成六进制数：\n{y}"
        );
    }

    #[test]
    fn render_emits_no_privileged_field_ever() {
        // 类型白名单的结构性证明：无论怎么填，输出里都不可能出现这些字段。
        // （它们不在 ComposeStackService 里，所以"想填也没地方填"——本测试钉住
        // 的是"渲染器不会自己发明字段"。）
        let s = ComposeStackSpec {
            project: "p".into(),
            services: vec![ComposeStackService {
                command: vec!["sh".into(), "-c".into(), "echo privileged: true".into()],
                ..svc("web")
            }],
        };
        let y = render_compose_yaml(&s);
        // 命令内容里出现 `privileged: true` 只是字符串值，不能成为键
        for forbidden in ["privileged:", "cap_add:", "pid:", "network_mode:", "user:", "devices:"] {
            assert!(
                !y.lines().any(|l| l.trim_start().starts_with(forbidden)),
                "渲染结果不得出现字段 {forbidden}：\n{y}"
            );
        }
    }

    #[test]
    fn render_is_deterministic() {
        // 外部修改检测依赖「同一 spec 渲染出同一字节」，这条必须成立
        let s = spec("p", vec![svc("a"), svc("b")]);
        assert_eq!(render_compose_yaml(&s), render_compose_yaml(&s));
    }

    /// ⭐⭐ **真机抓到的 bug**：`command: [sleep, 300]` 被 compose 拒绝
    /// （`services.web.command.1 must be a string`），因为 `300` 被 YAML 解析成整数。
    ///
    /// 这条测试钉住"命令参数即使是纯数字也必须带引号"。
    /// 只用字符串断言是不够的——真正的判据是 `docker compose config` 接受它，
    /// 那一步在真机验证里做（本测试守的是最容易回退的那一点）。
    #[test]
    fn render_quotes_numeric_command_args() {
        let s = ComposeStackSpec {
            project: "p".into(),
            services: vec![ComposeStackService {
                command: vec!["sleep".into(), "300".into()],
                ..svc("web")
            }],
        };
        let y = render_compose_yaml(&s);
        assert!(
            y.contains("command: [\"sleep\", \"300\"]"),
            "数字形态的命令参数必须加引号，否则 compose 报 must be a string：\n{y}"
        );
    }

    /// 全部标量都带引号：不给 YAML 类型推断留任何空间。
    /// 这条是上一条的推广——逐个字段列"哪些要引号"必然漏，索性全引号。
    #[test]
    fn render_quotes_every_scalar() {
        let s = ComposeStackSpec {
            project: "p".into(),
            services: vec![ComposeStackService {
                restart: Some("no".into()),
                mem_limit: Some("1024".into()),
                ..svc("web")
            }],
        };
        let y = render_compose_yaml(&s);
        // `no` 在 YAML 1.1 是布尔 false；`1024` 是整数。都必须被引号保护。
        assert!(y.contains("restart: \"no\""), "{y}");
        assert!(y.contains("mem_limit: \"1024\""), "{y}");
        assert!(y.contains("image: \"nginx:1.27-alpine\""), "{y}");
    }

    #[test]
    fn render_quotes_value_that_would_break_yaml() {
        let s = ComposeStackSpec {
            project: "p".into(),
            services: vec![ComposeStackService {
                env: vec!["MSG=hello: world # not a comment".into()],
                ..svc("web")
            }],
        };
        let y = render_compose_yaml(&s);
        assert!(y.contains("environment: [\"MSG=hello: world # not a comment\"]"), "{y}");
    }

    // ── 校验 ──

    #[test]
    fn validate_rejects_empty_services() {
        assert!(validate_stack_spec(&spec("p", vec![])).is_err());
    }

    #[test]
    fn validate_rejects_duplicate_service_names() {
        let s = spec("p", vec![svc("web"), svc("web")]);
        let e = validate_stack_spec(&s).unwrap_err().to_string();
        assert!(e.contains("重复"), "{e}");
    }

    #[test]
    fn validate_rejects_sensitive_volume_mount() {
        // 与容器创建同一套规则：挂宿主 / 或 docker.sock 一律拒
        for bad in ["/:/host", "/etc:/etc", "/var/run/docker.sock:/s"] {
            let s = ComposeStackSpec {
                project: "p".into(),
                services: vec![ComposeStackService {
                    volumes: vec![bad.into()],
                    ..svc("web")
                }],
            };
            assert!(validate_stack_spec(&s).is_err(), "`{bad}` 必须被拒");
        }
    }

    #[test]
    fn validate_accepts_named_volume_and_safe_path() {
        for ok in ["data:/data", "/srv/app:/app"] {
            let s = ComposeStackSpec {
                project: "p".into(),
                services: vec![ComposeStackService {
                    volumes: vec![ok.into()],
                    ..svc("web")
                }],
            };
            assert!(validate_stack_spec(&s).is_ok(), "`{ok}` 应被接受");
        }
    }

    #[test]
    fn validate_rejects_bad_env() {
        for bad in ["NOEQ", "=v", "1ABC=v", "A-B=v"] {
            let s = ComposeStackSpec {
                project: "p".into(),
                services: vec![ComposeStackService {
                    env: vec![bad.into()],
                    ..svc("web")
                }],
            };
            assert!(validate_stack_spec(&s).is_err(), "`{bad}` 应被拒");
        }
        let good = ComposeStackSpec {
            project: "p".into(),
            services: vec![ComposeStackService {
                env: vec!["FOO=bar".into(), "_X=1".into()],
                ..svc("web")
            }],
        };
        assert!(validate_stack_spec(&good).is_ok());
    }

    #[test]
    fn validate_rejects_bad_project_name() {
        for bad in ["-p", "a b", "a/b", "../x"] {
            let s = spec(bad, vec![svc("web")]);
            assert!(validate_stack_spec(&s).is_err(), "`{bad}` 应被拒");
        }
    }

    /// ⭐⭐ **具名卷必须在顶层 `volumes:` 声明**——真机踩到：
    /// 服务里写 `probe-data:/data` 而顶层没声明时，compose 报
    /// `service "web" refers to undefined volume probe-data: invalid compose project`。
    ///
    /// 只声明具名卷；绑定挂载与匿名卷不能出现在顶层（会变成"未使用的卷"）。
    #[test]
    fn render_declares_named_volumes_at_top_level() {
        let s = ComposeStackSpec {
            project: "p".into(),
            services: vec![
                ComposeStackService {
                    name: "a".into(),
                    image: "i".into(),
                    volumes: vec!["shared:/data".into(), "only-a:/a".into()],
                    ..Default::default()
                },
                ComposeStackService {
                    name: "b".into(),
                    image: "i".into(),
                    // 与 a 共用 shared（只应声明一次）；绑定挂载不应进顶层
                    volumes: vec!["shared:/data".into(), "/srv/host:/h".into()],
                    ..Default::default()
                },
            ],
        };
        let y = render_compose_yaml(&s);
        let top: Vec<&str> = y
            .lines()
            .skip_while(|l| !l.starts_with("volumes:"))
            .skip(1)
            .filter(|l| l.starts_with("  "))
            .collect();
        assert_eq!(
            top,
            vec!["  only-a: {}", "  shared: {}"],
            "顶层应只声明去重后的具名卷（按字母序），绑定挂载不得进顶层：\n{y}"
        );
    }

    #[test]
    fn named_volume_source_distinguishes_kinds() {
        assert_eq!(named_volume_source("data:/data"), Some("data"));
        assert_eq!(named_volume_source("/srv/x:/x"), None);
        assert_eq!(named_volume_source("./rel:/r"), None);
        assert_eq!(named_volume_source("/anon"), None, "只有容器内路径是匿名卷");
        assert_eq!(named_volume_source(""), None);
    }

    #[test]
    fn validate_rejects_unknown_restart() {
        let s = ComposeStackSpec {
            project: "p".into(),
            services: vec![ComposeStackService {
                restart: Some("sometimes".into()),
                ..svc("web")
            }],
        };
        assert!(validate_stack_spec(&s).is_err());
    }

    // ── 磁盘往返 / 外部修改检测（真写文件）──

    /// 每个测试一个唯一目录，避免并行测试互相踩。
    fn tmp_root(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "forkpanel-stack-{}-{tag}-{n}",
            std::process::id()
        ))
    }

    #[test]
    fn save_then_load_roundtrip() {
        let root = tmp_root("roundtrip");
        let s = spec("proj1", vec![svc("web")]);
        let saved = save_stack(&root, &s).expect("保存应成功");
        assert!(!saved.externally_modified);
        assert!(Path::new(&saved.config_file).is_file(), "compose.yaml 必须真的写出来");

        let loaded = load_stack(&root, "proj1").expect("读取应成功");
        assert_eq!(loaded.services.len(), 1);
        assert_eq!(loaded.services[0].name, "web");
        assert!(!loaded.externally_modified);

        let list = list_stacks(&root).expect("列举应成功");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].project, "proj1");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn external_edit_is_detected_and_refused_on_save() {
        let root = tmp_root("extedit");
        let s = spec("proj2", vec![svc("web")]);
        let saved = save_stack(&root, &s).expect("保存应成功");

        // 模拟用户在 CLI 手改 compose.yaml
        std::fs::write(&saved.config_file, "services:\n  evil:\n    image: x\n").unwrap();

        let loaded = load_stack(&root, "proj2").unwrap();
        assert!(loaded.externally_modified, "手改后必须被标记为外部修改");

        // 关键：面板不能静默覆盖
        let err = save_stack(&root, &s).unwrap_err();
        assert!(
            err.to_string().contains("外部修改") || matches!(err, PanelError::Conflict(_)),
            "被外部改过时必须拒绝覆盖，实际: {err}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// ⭐⭐ **渲染器升级不得把既有文件判成"外部修改"**。
    ///
    /// 复现方式：保存后用当前渲染器重新渲染，把结果写进元数据快照——模拟
    /// "文件是旧版本渲染器生成的"。因为快照与磁盘仍然一致，`externally_modified`
    /// 必须为 false，保存也必须成功。
    ///
    /// 这条守的是一个真实设计缺陷：最初用"按当前渲染器重新渲染再比对"，
    /// 渲染规则一改（裸写 → 全引号），所有既有编排都会被判成外部修改而**再也存不进去**。
    #[test]
    fn renderer_upgrade_does_not_look_like_external_edit() {
        let root = tmp_root("upgrade");
        let s = spec("proj3", vec![svc("web")]);
        let saved = save_stack(&root, &s).expect("保存应成功");

        // 手工把快照改成"另一种渲染结果"，但磁盘 yaml 保持不变 ——
        // 等价于"这份文件由旧渲染器写出，快照记的也是旧内容"。
        let meta_path = Path::new(&saved.dir).join(STACK_META_FILE);
        let raw = std::fs::read_to_string(&meta_path).unwrap();
        let mut meta: StackMeta = serde_json::from_str(&raw).unwrap();
        meta.yaml = "# 旧版本渲染器的输出\nservices:\n  web:\n    image: nginx:1.27-alpine\n".into();
        std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
        // 让磁盘 yaml 与（被改过的）快照一致，模拟"旧版本写下的两个文件"
        std::fs::write(&saved.config_file, &meta.yaml).unwrap();

        let loaded = load_stack(&root, "proj3").unwrap();
        assert!(
            !loaded.externally_modified,
            "快照与磁盘一致就不是外部修改（哪怕内容不是当前渲染器的输出）"
        );

        // 保存应成功，并把快照刷新成当前渲染结果
        let again = save_stack(&root, &s).expect("渲染器升级后仍必须能保存");
        assert!(!again.externally_modified);
        let refreshed = std::fs::read_to_string(Path::new(&again.dir).join(STACK_META_FILE)).unwrap();
        let m: StackMeta = serde_json::from_str(&refreshed).unwrap();
        assert_eq!(m.yaml, render_compose_yaml(&s), "保存后快照应更新为当前渲染结果");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn deleted_yaml_is_not_external_edit() {
        let root = tmp_root("delyaml");
        let s = spec("proj4", vec![svc("web")]);
        let saved = save_stack(&root, &s).unwrap();
        std::fs::remove_file(&saved.config_file).unwrap();

        let loaded = load_stack(&root, "proj4").unwrap();
        assert!(!loaded.externally_modified, "文件被删不算外部修改（保存会重建）");
        assert!(save_stack(&root, &s).is_ok(), "应能重新生成");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_ignores_dirs_without_meta() {
        let root = tmp_root("ignore");
        std::fs::create_dir_all(root.join("handwritten")).unwrap();
        std::fs::write(root.join("handwritten").join("compose.yaml"), "services: {}\n").unwrap();
        // 用户手写的项目（没有元数据）不应出现在面板的列表里
        assert!(list_stacks(&root).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_root_lists_empty_not_error() {
        let root = tmp_root("noroot");
        assert!(list_stacks(&root).unwrap().is_empty());
    }
}
