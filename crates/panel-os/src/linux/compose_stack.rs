//! 面板编排（Compose stack）的存储与渲染。
//!
//! ## 设计核心：面板"生成"文件，而不是"解析"文件
//!
//! 磁盘上两份文件：
//! - `.forkpanel-compose.json` —— **单一事实源**，面板只读写它（serde_json 已有依赖）；
//! - `compose.yaml` —— 渲染产物，给人看、给 `docker compose` 用。
//!
//! 为什么不是反过来（让用户直接编辑 YAML、面板去解析）：本 crate 的依赖预算
//! 上限 38（去重后第三方直接依赖现约 22），不轻易加 YAML 解析器；更要紧的是，允许自由 YAML 就等于允许
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
//!
//! ## 「安全导入助手」：解析外部 YAML，但只抽取白名单子集
//!
//! 为了让用户能从别的来源粘贴 `docker-compose.yml` + `.env` 一键部署，我们**破例**
//! 引入 `serde_yaml` 解析器（仅此一处）。但这是"导入"而非"放开原始 YAML"：
//! 解析出的 `serde_yaml::Value` 树只被用来**读取白名单键**构造 `ComposeStackSpec`，
//! 未知字段一律落入 `dropped` 列表（只报告、绝不写回）。因此危险字段
//! （`privileged` / 挂 `/` / 挂 `docker.sock` / `network_mode`）在"抽取"这一步就
//! 已被类型白名单挡掉——这与"生成阶段不可能出现特权字段"的安全模型完全兼容，
//! 不依赖运行时黑名单。见 [`parse_compose_import`]。

use crate::linux::containers::{
    image_is_safe, mem_limit_is_safe, port_mapping_is_safe, sensitive_host_mount,
    validate_compose_project,
};
use crate::traits::{
    ComposeImportDropped, ComposeImportPreview, ComposeStack, ComposeStackService, ComposeStackSpec,
};
use panel_core::{PanelError, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
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
    validate_stack_services(&spec.services)
}

/// 只校验服务列表（不含项目名）。导入预览用：外部 compose 常常没有顶层 `name`，
/// 项目名由用户在导入弹窗里另填；这里若连带校验项目名，预览会永久报"项目名不能为空"，
/// 而前端把 `errors` 当阻断条件 ⇒「确认导入」永远点不动（真机 bug）。
fn validate_stack_services(services: &[ComposeStackService]) -> Result<()> {
    if services.is_empty() {
        return Err(PanelError::Validation {
            field: "services",
            reason: "至少需要一个服务".into(),
        });
    }

    let mut seen: Vec<&str> = Vec::new();
    for s in services.iter() {
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
    // 同步落盘，避免 rename 后数据仍在页缓存（断电丢失）。两层 `let _ =` 会让
    // "已保存"谎报 durability（打开/fsync 失败都无声）——与 files.rs 的写入同口径，
    // 失败必须可见（rename 仍照常提交，不会误导成"保存失败"）。
    match std::fs::File::open(&tmp) {
        Ok(f) => {
            if let Err(sync_err) = f.sync_all() {
                tracing::warn!("compose.yaml 落盘 sync_all 失败（断电可能丢失）{tmp:?}: {sync_err}");
            }
        }
        Err(open_err) => {
            tracing::warn!("落盘前打开临时文件失败，无法 sync {tmp:?}: {open_err}");
        }
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

// ─────────────── 安全导入助手（解析外部 compose YAML） ───────────────

/// 导入时允许的最大 YAML 体积，防 DoS（`serde_yaml` 解析大文档有成本）。
const IMPORT_MAX_BYTES: usize = 256 * 1024;

/// 服务级白名单键：只有这些会被抽取进 `ComposeStackSpec`。
/// `deploy` 单列是因为我们只从它里面取 `resources.limits.memory`（内存上限）。
/// 其余一切（build / depends_on / networks / healthcheck / env_file / privileged …）都进 `dropped`。
const SERVICE_WHITELIST: &[&str] = &[
    "image", "command", "ports", "environment", "volumes", "restart", "mem_limit", "deploy",
];

/// 解析**外部提供的** compose YAML，只抽取白名单子集，未知字段全部进 `dropped`。
///
/// 这是"导入"而非"放开原始 YAML"：我们从不把解析出的 `Value` 树回写成文件，
/// 只读取白名单键构造受类型约束的 `ComposeStackSpec`，因此特权字段在抽取阶段就被挡掉。
/// `env_text`（可选 `.env` 文件内容）里的 `KEY=VALUE` 会合并到所有服务的环境变量。
pub fn parse_compose_import(yaml: &str, env_text: Option<&str>) -> Result<ComposeImportPreview> {
    if yaml.len() > IMPORT_MAX_BYTES {
        return Err(PanelError::Validation {
            field: "yaml",
            reason: format!("compose 内容过大（上限 {}KB）", IMPORT_MAX_BYTES / 1024),
        });
    }

    // 多文档合并 + `<<` 合并键展开，见 parse_yaml_root 的注释。
    let (root_map, mut warnings) = parse_yaml_root(yaml)?;

    // 项目名：优先用 compose 顶层 `name`；可能不合法，交给后续校验报错。
    let project = val_str(&root_map, "name").unwrap_or_default();

    for k in root_keys(&root_map) {
        // `x-` 是 compose 官方约定的自定义扩展段（`x-common: &common` 就靠它做锚点），
        // 真 compose 会静默忽略，这里也不该报"不在支持范围"的假警报。
        if k.starts_with("x-") {
            continue;
        }
        if !matches!(k.as_str(), "name" | "version" | "services" | "service") {
            // 顶层 `volumes` 几乎每份真 compose 都有。服务引用的具名卷会被自动声明，
            // 只有 `name:` / `driver:` 这类自定义选项被忽略——别让用户以为卷丢了。
            if k == "volumes" {
                warnings.push(
                    "顶层 volumes 的 name/driver 等自定义选项已忽略；服务引用的具名卷会按 \
                     `<项目>_<卷名>` 自动声明"
                        .to_string(),
                );
            } else {
                warnings.push(format!(
                    "顶层字段 `{k}` 不在面板支持范围，已忽略（如 networks / secrets / configs）"
                ));
            }
        }
    }

    let services_val = val_at(&root_map, "services").or_else(|| val_at(&root_map, "service"));
    let Some(services_map) = services_val.and_then(|v| match v {
        Value::Mapping(m) => Some(m),
        _ => None,
    }) else {
        return Err(PanelError::Validation {
            field: "yaml",
            reason: "未找到 services 定义".into(),
        });
    };

    let mut services = Vec::new();
    let mut dropped: Vec<ComposeImportDropped> = Vec::new();
    // 敏感宿主挂载在抽取阶段就剔除（绝不进 spec），同时记下来变成阻断错误。
    let mut blocked_volumes: Vec<String> = Vec::new();
    // 抽取阶段就能判定"导不进来"的硬错误（如只有 build: 没有 image）。
    let mut hard_errors: Vec<String> = Vec::new();

    for (name_val, svc_val) in services_map.iter() {
        let Value::String(name) = name_val else { continue };
        let svc_map = match svc_val {
            Value::Mapping(m) => m,
            _ => {
                dropped.push(ComposeImportDropped {
                    service: name.clone(),
                    field: "(服务定义不是映射)".into(),
                });
                continue;
            }
        };

        let mut svc = ComposeStackService {
            name: name.clone(),
            ..Default::default()
        };

        if let Some(v) = val_at(svc_map, "image") {
            svc.image = yaml_scalar(v).unwrap_or_default();
        }
        if let Some(v) = val_at(svc_map, "command") {
            svc.command = yaml_string_list_loose(v);
        }
        if let Some(v) = val_at(svc_map, "ports") {
            svc.ports = yaml_ports(v);
        }
        if let Some(v) = val_at(svc_map, "environment") {
            svc.env = yaml_environment(v);
        }
        if let Some(v) = val_at(svc_map, "volumes") {
            // ⚠ 敏感宿主路径必须在**抽取阶段**剔除，不能只靠后面的
            // validate_stack_services：预览返回的 spec 也不允许带上 `/`、`/etc`、
            // docker.sock 这类挂载（前端会把它当"将创建的内容"展示出来）。
            for vol in yaml_volumes(v) {
                if let Some(bad) = sensitive_host_mount(&vol) {
                    blocked_volumes.push(format!("服务 {name} 的卷 `{vol}` 命中宿主敏感路径 {bad}"));
                } else {
                    svc.volumes.push(vol);
                }
            }
        }
        if let Some(v) = val_at(svc_map, "restart") {
            svc.restart = yaml_scalar(v);
        }
        // 内存上限：顶层 `mem_limit` 优先；否则 `deploy.resources.limits.memory`。
        let mut mem = val_at(svc_map, "mem_limit").and_then(yaml_scalar);
        if mem.is_none() {
            if let Some(Value::Mapping(deploy)) = val_at(svc_map, "deploy") {
                if let Some(Value::Mapping(res)) = val_at(deploy, "resources") {
                    if let Some(Value::Mapping(lim)) = val_at(res, "limits") {
                        mem = val_at(lim, "memory").and_then(yaml_scalar);
                    }
                }
            }
        }
        svc.mem_limit = mem;

        // 报告白名单之外的服务级字段
        for k in root_keys(svc_map) {
            if !SERVICE_WHITELIST.contains(&k.as_str()) {
                dropped.push(ComposeImportDropped {
                    service: name.clone(),
                    field: k.clone(),
                });
            }
        }

        // 真 compose 里最常见的两个"导不进来"原因，直接给可操作的提示，
        // 而不是只在 dropped 里留个字段名（用户看到 `build` 三个字母不知道下一步做什么）。
        if val_at(svc_map, "build").is_some() && svc.image.is_empty() {
            hard_errors.push(format!(
                "服务 {name} 只有 build: 定义，面板不执行本地构建——请先构建出镜像，再在 compose 里补 image"
            ));
        }
        if let Some(v) = val_at(svc_map, "env_file") {
            let files = yaml_string_list_loose(v).join("、");
            warnings.push(format!(
                "服务 {name} 的 env_file（{files}）不会被读取：请把该文件内容粘贴到下方 .env 输入框"
            ));
        }

        services.push(svc);
    }

    // `.env` 文件合并到所有服务
    if let Some(text) = env_text {
        let (entries, parse_warn) = parse_dotenv(text);
        if !entries.is_empty() {
            for s in services.iter_mut() {
                for e in &entries {
                    let key = e.split_once('=').map(|(k, _)| k.to_string()).unwrap_or_default();
                    let dup = s
                        .env
                        .iter()
                        .any(|x| x.split_once('=').map(|(k, _)| k == key).unwrap_or(false));
                    if !dup {
                        s.env.push(e.clone());
                    }
                }
            }
            warnings.push(format!("env 文件中的 {} 个变量已合并到所有服务", entries.len()));
        }
        warnings.extend(parse_warn);
    }

    let spec = ComposeStackSpec { project, services };

    let mut errors: Vec<String> = blocked_volumes
        .into_iter()
        .map(|v| format!("已拒绝：{v}"))
        .collect();
    errors.extend(hard_errors);
    // 只校验服务；项目名要等用户在导入弹窗里填写（见 validate_stack_services 注释）。
    if let Err(e) = validate_stack_services(&spec.services) {
        errors.push(e.to_string());
    }
    // 顶层 `name` 只是预填提示：不合法不阻断，改成警告，用户改名即可。
    if !spec.project.is_empty() {
        if let Err(e) = validate_compose_project(&spec.project) {
            warnings.push(format!(
                "compose 顶层 name `{}` 不可用（{e}），请在导入时另填项目名",
                spec.project
            ));
        }
    }

    Ok(ComposeImportPreview {
        spec,
        dropped,
        warnings,
        errors,
    })
}

/// YAML 1.1 合并键（`<<: *common`）。
const MERGE_KEY: &str = "<<";

/// 把整份 YAML 解析成**一个**顶层映射，并返回解析期间产生的提示。
///
/// 这里踩过两个真机坑，都是"外部 compose 明明合法却导不进来"：
///
/// 1. **多文档**：`serde_yaml::from_str` 只吃单文档，碰到第二个 `---` 就报
///    “deserializing from YAML containing more than one document is not supported”。
///    而 docker compose 自己是**支持**的——实测 Compose v5.7.0 会把同一文件里的
///    多个文档深合并（映射按键递归合并、序列拼接、标量后者覆盖，见 [`merge_yaml`]）。
///    所以这里照 compose 的语义合并，**不能只取第一个文档**：那会静默丢掉后续文档
///    里的服务，用户看到"导入成功但少了一半服务"。空文档（多余的 `---`，从文档里
///    复制粘贴时极常见）docker 会直接报错，这里跳过并提示，不阻断导入。
/// 2. **合并键 `<<`**：`x-common: &common` + `<<: *common` 是 compose 最常用的复用写法，
///    但 `serde_yaml` 0.9 未实现 YAML 1.1 的合并键语义——`<<` 会原样留成一个键，值就是
///    锚点内容。不展开的话继承来的 `image` / `ports` 会**静默丢失**（服务只剩自己显式
///    写的那几个字段），所以解析后必须走一遍 [`expand_merge_keys`]。
fn parse_yaml_root(yaml: &str) -> Result<(serde_yaml::Mapping, Vec<String>)> {
    let mut warnings: Vec<String> = Vec::new();
    let mut docs = 0usize;
    let mut blanks = 0usize;
    let mut merged: Option<Value> = None;

    for doc in serde_yaml::Deserializer::from_str(yaml) {
        let v = Value::deserialize(doc).map_err(|e| PanelError::Validation {
            field: "yaml",
            reason: format!("YAML 解析失败：{e}"),
        })?;
        if v.is_null() {
            blanks += 1;
            continue;
        }
        if !v.is_mapping() {
            return Err(PanelError::Validation {
                field: "yaml",
                reason: "compose 顶层必须是映射（services: ...）".into(),
            });
        }
        docs += 1;
        match merged.as_mut() {
            Some(base) => merge_yaml(base, v),
            None => merged = Some(v),
        }
    }

    if docs > 1 {
        warnings.push(format!(
            "文件含 {docs} 个 YAML 文档，已按 docker compose 的规则合并为一份（映射深合并、列表拼接）"
        ));
    }
    if blanks > 0 && docs > 0 {
        warnings.push(format!(
            "已忽略 {blanks} 个空的 YAML 文档（多余的 `---` 分隔符）"
        ));
    }

    let Some(mut root) = merged else {
        return Err(PanelError::Validation {
            field: "yaml",
            reason: "compose 内容为空".into(),
        });
    };
    expand_merge_keys(&mut root);

    let Value::Mapping(m) = root else {
        // 顶层类型在上面已逐个文档校验过，这里只是把类型收窄。
        return Err(PanelError::Validation {
            field: "yaml",
            reason: "compose 顶层必须是映射（services: ...）".into(),
        });
    };
    Ok((m, warnings))
}

/// 按 docker compose 的规则合并两个文档（实测 Compose v5.7.0）：
/// 映射按键递归合并；序列**拼接**（`ports` 在两份文档里都写会得到两条映射）；
/// 其余标量后者覆盖前者。
fn merge_yaml(base: &mut Value, over: Value) {
    match (base, over) {
        (Value::Mapping(b), Value::Mapping(o)) => {
            for (k, v) in o {
                if let Some(slot) = b.get_mut(k.clone()) {
                    merge_yaml(slot, v);
                } else {
                    b.insert(k, v);
                }
            }
        }
        (Value::Sequence(b), Value::Sequence(mut o)) => b.append(&mut o),
        (slot, v) => *slot = v,
    }
}

/// 递归展开 YAML 1.1 合并键 `<<`（值可以是单个映射，也可以是映射序列）。
/// 映射里显式写出的键优先；多个来源之间**靠前的优先**（YAML 1.1 规定）。
fn expand_merge_keys(v: &mut Value) {
    match v {
        Value::Mapping(m) => {
            for (_, val) in m.iter_mut() {
                expand_merge_keys(val);
            }
            let Some(src) = m.remove(Value::String(MERGE_KEY.to_string())) else {
                return;
            };
            let mut sources = match src {
                Value::Sequence(seq) => seq,
                other => vec![other],
            };
            // 先把要补的键全部算出来再插入：中途插入会让后来来源的同名键被
            // `contains_key` 挡掉，语义就反转成"后者覆盖"了。
            let mut inherited: Vec<(Value, Value)> = Vec::new();
            for s in sources.iter_mut() {
                expand_merge_keys(s);
                let Value::Mapping(sm) = s else { continue };
                for (k, val) in sm.iter() {
                    let already = m.contains_key(k.clone())
                        || inherited.iter().any(|(ik, _)| ik == k);
                    if !already {
                        inherited.push((k.clone(), val.clone()));
                    }
                }
            }
            for (k, val) in inherited {
                m.insert(k, val);
            }
        }
        Value::Sequence(seq) => {
            for e in seq.iter_mut() {
                expand_merge_keys(e);
            }
        }
        _ => {}
    }
}

/// 取映射里的字符串值（`name` / `restart` 这类）。
fn val_str(m: &serde_yaml::Mapping, key: &str) -> Option<String> {
    val_at(m, key).and_then(yaml_scalar)
}

/// 取映射里的值（按字符串键）。
fn val_at<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    m.get(Value::String(key.to_string()))
}

/// 映射的所有字符串键。
fn root_keys(m: &serde_yaml::Mapping) -> Vec<String> {
    m.keys()
        .filter_map(|k| match k {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

/// 标量转字符串（字符串/布尔/数字；Null 返回 None）。
fn yaml_scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => n
            .as_i64()
            .map(|v| v.to_string())
            .or_else(|| n.as_u64().map(|v| v.to_string()))
            .or_else(|| n.as_f64().map(|v| v.to_string())),
        Value::Null => None,
        _ => None,
    }
}

/// 列表类字段：序列逐元素转字符串；单个字符串按空白切分（compose 的 command 常见写法）。
fn yaml_string_list_loose(v: &Value) -> Vec<String> {
    match v {
        Value::Sequence(seq) => seq.iter().filter_map(yaml_scalar).collect(),
        Value::String(s) => s.split_whitespace().map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

/// 端口：兼容 `['8080:80']` 与 `{target, published, protocol}` 两种写法，
/// 统一成面板用的 `host:container[/proto]`。
fn yaml_ports(v: &Value) -> Vec<String> {
    match v {
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|e| match e {
                Value::String(s) => Some(s.clone()),
                Value::Mapping(m) => {
                    let target = val_str(m, "target").unwrap_or_default();
                    let published = val_str(m, "published");
                    if target.is_empty() {
                        None
                    } else if let Some(p) = published {
                        let proto = val_str(m, "protocol");
                        Some(match proto {
                            Some(pr) => format!("{p}:{target}/{pr}"),
                            None => format!("{p}:{target}"),
                        })
                    } else {
                        // 只有 target、没有 published：视作容器端口暴露
                        Some(target)
                    }
                }
                _ => None,
            })
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// 环境变量：兼容映射 `{KEY: value}` 与序列 `['KEY=value']`（序列里也允许 `{KEY: value}`）。
fn yaml_environment(v: &Value) -> Vec<String> {
    match v {
        Value::Mapping(m) => m
            .iter()
            .filter_map(|(k, val)| match k {
                Value::String(key) => {
                    let vstr = yaml_scalar(val).unwrap_or_default();
                    Some(format!("{key}={vstr}"))
                }
                _ => None,
            })
            .collect(),
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|e| match e {
                Value::String(s) => Some(s.clone()),
                Value::Mapping(m) => {
                    let (k, v) = m.iter().next()?;
                    if let Value::String(key) = k {
                        let vstr = yaml_scalar(v).unwrap_or_default();
                        Some(format!("{key}={vstr}"))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// 卷：兼容字符串 `data:/data` 与映射 `{source, target, ...}`。
fn yaml_volumes(v: &Value) -> Vec<String> {
    match v {
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|e| match e {
                Value::String(s) => Some(s.clone()),
                Value::Mapping(m) => {
                    let source = val_str(m, "source").unwrap_or_default();
                    let target = val_str(m, "target").unwrap_or_default();
                    if source.is_empty() || target.is_empty() {
                        None
                    } else {
                        Some(format!("{source}:{target}"))
                    }
                }
                _ => None,
            })
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// 解析 `.env` 文件内容：`KEY=VALUE` 行，跳过空白与 `#` 注释，剥离 `export ` 前缀。
/// 返回条目与解析提示（如某行缺少 `=`）。
fn parse_dotenv(text: &str) -> (Vec<String>, Vec<String>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        match line.split_once('=') {
            Some((k, v)) => entries.push(format!("{}={}", k.trim(), v.trim())),
            None => warnings.push(format!("env 文件忽略无法解析的行：{line}")),
        }
    }
    (entries, warnings)
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

    // ── 安全导入（parse_compose_import）──

    /// ⭐ 核心：白名单字段正确抽取，env 映射（含数字值）正确拼成 KEY=VALUE。
    #[test]
    fn import_extracts_whitelist_subset() {
        let yaml = r#"
name: myapp
services:
  web:
    image: nginx:1.27-alpine
    ports:
      - "8080:80"
    environment:
      TZ: Asia/Shanghai
      NGINX_PORT: "80"
    volumes:
      - data:/data
    restart: unless-stopped
    mem_limit: 512m
"#;
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        assert!(p.errors.is_empty(), "合法导入不应有错误：{:?}", p.errors);
        assert_eq!(p.spec.project, "myapp");
        assert_eq!(p.spec.services.len(), 1);
        let s = &p.spec.services[0];
        assert_eq!(s.image, "nginx:1.27-alpine");
        assert_eq!(s.ports, vec!["8080:80".to_string()]);
        assert_eq!(
            s.env,
            vec!["TZ=Asia/Shanghai".to_string(), "NGINX_PORT=80".to_string()]
        );
        assert_eq!(s.volumes, vec!["data:/data".to_string()]);
        assert_eq!(s.restart.as_deref(), Some("unless-stopped"));
        assert_eq!(s.mem_limit.as_deref(), Some("512m"));
    }

    /// ⭐⭐ **负向对照的判据必须真红**：如果白名单抽取"漏掉"了报告逻辑，
    /// 外部 compose 里的 build/depends_on 等会被静默吞掉——这条钉住"被忽略字段必被报告"。
    #[test]
    fn import_reports_dropped_fields() {
        let yaml = r#"
services:
  web:
    image: nginx
    build:
      context: .
    depends_on:
      - db
    networks:
      - frontend
    healthcheck:
      test: curl
"#;
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        let dropped_fields: Vec<&str> = p
            .dropped
            .iter()
            .filter(|d| d.service == "web")
            .map(|d| d.field.as_str())
            .collect();
        for f in ["build", "depends_on", "networks", "healthcheck"] {
            assert!(
                dropped_fields.contains(&f),
                "应报告被忽略字段 {f}：{dropped_fields:?}"
            );
        }
    }

    /// ⭐⭐ 安全底线：危险字段只能进 dropped，绝不通传到 spec。
    #[test]
    fn import_never_passthrough_privileged() {
        let yaml = r#"
services:
  evil:
    image: nginx
    privileged: true
    volumes:
      - /:/host
"#;
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        // 特权字段必须被报告为"忽略"
        assert!(
            p.dropped.iter().any(|d| d.field == "privileged"),
            "privileged 应被报告为忽略"
        );
        let s = &p.spec.services[0];
        // 敏感挂载既不能进 spec，也必须触发校验错误（绝不静默放行）
        assert!(
            !s.volumes.iter().any(|v| v == "/:/host"),
            "敏感挂载绝不能进 spec"
        );
        assert!(!p.errors.is_empty(), "敏感挂载应触发校验错误");
    }

    #[test]
    fn import_merges_dotenv_into_all_services() {
        let yaml = r#"
services:
  a:
    image: nginx
  b:
    image: redis
"#;
        let env = "TZ=Asia/Shanghai\n# comment\nBADLINE\nFOO=bar";
        let p = parse_compose_import(yaml, Some(env)).expect("解析应成功");
        assert_eq!(p.spec.services.len(), 2);
        for s in &p.spec.services {
            assert!(
                s.env.contains(&"TZ=Asia/Shanghai".to_string()),
                "env 应合并到每个服务"
            );
            assert!(s.env.contains(&"FOO=bar".to_string()));
        }
        assert!(
            p.warnings
                .iter()
                .any(|w| w.contains("忽略") || w.contains("BADLINE")),
            "无法解析的 env 行应被提示"
        );
    }

    #[test]
    fn import_rejects_invalid_yaml() {
        assert!(
            parse_compose_import("services: [unclosed", None).is_err(),
            "非法 YAML 必须报错"
        );
    }

    /// compose 常见写法：内存上限在 `deploy.resources.limits.memory`。
    #[test]
    fn import_handles_deploy_memory_limit() {
        let yaml = r#"
services:
  web:
    image: nginx
    deploy:
      resources:
        limits:
          memory: 1g
"#;
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        assert_eq!(p.spec.services[0].mem_limit.as_deref(), Some("1g"));
        // deploy 自身不应被当成"被忽略字段"报告（我们只取 memory）
        assert!(
            !p.dropped.iter().any(|d| d.field == "deploy"),
            "deploy 不应出现在 dropped"
        );
    }

    #[test]
    fn import_rejects_oversized_yaml() {
        let big = format!("services:\n  web:\n    image: {}\n", "x".repeat(300 * 1024));
        assert!(
            parse_compose_import(&big, None).is_err(),
            "超过 256KB 的 YAML 必须被拒"
        );
    }

    /// ⭐⭐ 回归：外部 compose 常常没有顶层 `name`。项目名由导入弹窗另填，
    /// 预览绝不能因此产生阻断性 errors——否则前端「确认导入」永久禁用（真机 bug）。
    #[test]
    fn import_without_name_has_no_blocking_errors() {
        let yaml = r#"
services:
  web:
    image: nginx:1.27-alpine
"#;
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        assert!(
            p.errors.is_empty(),
            "缺顶层 name 不应阻断导入（项目名另填）：{:?}",
            p.errors
        );
        assert_eq!(p.spec.project, "");
    }

    /// 顶层 name 非法时只给警告、不阻断——用户可在导入弹窗里改名。
    #[test]
    fn import_invalid_name_is_warning_not_error() {
        let yaml = "name: \"my stack\"\nservices:\n  web:\n    image: nginx\n";
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        assert!(
            p.errors.is_empty(),
            "非法 name 不应阻断导入：{:?}",
            p.errors
        );
        assert!(
            p.warnings.iter().any(|w| w.contains("name")),
            "应提示顶层 name 不可用：{:?}",
            p.warnings
        );
    }

    /// ⭐⭐ 回归（真机报错原文）：从文档/聊天里复制来的 compose 常带多个 `---` 文档，
    /// `serde_yaml::from_str` 只吃单文档，直接报
    /// “deserializing from YAML containing more than one document is not supported”。
    /// docker compose 自己是支持的：多文档深合并、列表拼接、标量后者覆盖（Compose v5.7.0 实测）。
    #[test]
    fn import_merges_multiple_documents() {
        let yaml = r#"
services:
  web:
    image: nginx:1.27-alpine
    ports:
      - "8080:80"
    environment:
      A: "1"
---
services:
  web:
    ports:
      - "9090:90"
    environment:
      B: "2"
  db:
    image: postgres:16-alpine
"#;
        let p = parse_compose_import(yaml, None).expect("多文档 YAML 必须能解析");
        assert!(p.errors.is_empty(), "不应有阻断错误：{:?}", p.errors);
        assert_eq!(p.spec.services.len(), 2, "两份文档里的服务都要在");
        let web = p.spec.services.iter().find(|s| s.name == "web").unwrap();
        assert_eq!(
            web.image, "nginx:1.27-alpine",
            "前一份文档的 image 不能被后一份覆盖掉"
        );
        assert_eq!(
            web.ports,
            vec!["8080:80".to_string(), "9090:90".to_string()],
            "列表按 docker compose 语义拼接"
        );
        assert_eq!(web.env, vec!["A=1".to_string(), "B=2".to_string()]);
        assert!(
            p.spec.services.iter().any(|s| s.name == "db"),
            "第二份文档里的服务不能被静默丢掉"
        );
        assert!(
            p.warnings.iter().any(|w| w.contains("2 个 YAML 文档")),
            "应提示已合并：{:?}",
            p.warnings
        );
    }

    /// 尾部多余的 `---`（粘贴时最常见）会产出一个空文档。docker compose 直接报
    /// “top-level object must be a mapping”，这里跳过并提示——否则用户得手工删掉一个
    /// 看不见的分隔符才能导入。
    #[test]
    fn import_skips_empty_trailing_document() {
        let yaml = "services:\n  web:\n    image: nginx\n---\n";
        let p = parse_compose_import(yaml, None).expect("尾部 --- 不应导致失败");
        assert!(p.errors.is_empty(), "{:?}", p.errors);
        assert_eq!(p.spec.services.len(), 1);
        assert!(
            p.warnings.iter().any(|w| w.contains("空的 YAML 文档")),
            "应提示跳过了空文档：{:?}",
            p.warnings
        );
    }

    /// ⭐⭐ 回归：`x-common: &common` + `<<: *common` 是 compose 最常见的复用写法，但
    /// `serde_yaml` 0.9 不实现 YAML 1.1 合并键语义——`<<` 会原样留成一个键。不展开就会
    /// **静默丢掉**继承来的 image/restart，服务镜像为空，最后报一个看不懂的"镜像不能为空"。
    #[test]
    fn import_expands_merge_key_anchor() {
        let yaml = r#"
x-common: &common
  image: nginx:1.27-alpine
  restart: unless-stopped
  environment:
    TZ: Asia/Shanghai
services:
  web:
    <<: *common
    ports:
      - "8080:80"
"#;
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        assert!(p.errors.is_empty(), "合并键必须展开：{:?}", p.errors);
        let s = &p.spec.services[0];
        assert_eq!(s.image, "nginx:1.27-alpine", "image 应继承自锚点");
        assert_eq!(s.restart.as_deref(), Some("unless-stopped"));
        assert_eq!(s.env, vec!["TZ=Asia/Shanghai".to_string()]);
        assert_eq!(s.ports, vec!["8080:80".to_string()]);
        assert!(
            !p.dropped.iter().any(|d| d.field == MERGE_KEY),
            "`<<` 已展开，不该出现在 dropped：{:?}",
            p.dropped
        );
        assert!(
            !p.warnings.iter().any(|w| w.contains("x-common")),
            "`x-` 扩展段是 compose 官方约定，不该报「不在支持范围」：{:?}",
            p.warnings
        );
    }

    /// 合并键优先级：显式键 > 靠前的来源 > 靠后的来源（YAML 1.1）。
    #[test]
    fn import_merge_key_priority() {
        let yaml = r#"
x-a: &a
  image: from-a
  restart: always
x-b: &b
  image: from-b
  mem_limit: 256m
services:
  web:
    <<: [*a, *b]
    image: explicit
"#;
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        let s = &p.spec.services[0];
        assert_eq!(s.image, "explicit", "显式键优先于合并键");
        assert_eq!(s.restart.as_deref(), Some("always"), "来源 a 优先于来源 b");
        assert_eq!(s.mem_limit.as_deref(), Some("256m"), "来源 b 独有的键仍要继承");
    }

    /// 只有 `build:` 没有 `image:` 的服务必须给可操作错误，而不是笼统的"镜像不能为空"。
    #[test]
    fn import_build_only_service_reports_actionable_error() {
        let yaml = "services:\n  web:\n    build: .\n";
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        assert!(
            p.errors.iter().any(|e| e.contains("build")),
            "应给出 build 相关的可操作错误：{:?}",
            p.errors
        );
    }

    /// `env_file` 不会被读取（面板不读外部文件），必须提示用户把内容粘到 .env 输入框。
    #[test]
    fn import_env_file_is_reported_with_hint() {
        let yaml = "services:\n  web:\n    image: nginx\n    env_file: .env\n";
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        assert!(
            p.warnings
                .iter()
                .any(|w| w.contains("env_file") && w.contains(".env")),
            "应提示 env_file 未读取并指向 .env 输入框：{:?}",
            p.warnings
        );
        assert!(
            p.dropped.iter().any(|d| d.field == "env_file"),
            "env_file 仍应出现在 dropped"
        );
    }

    /// 顶层 `volumes` 是每份真 compose 都有的一段：不能报成"不在面板支持范围"
    /// （那会让用户以为具名卷丢了），但 `name:`/`driver:` 确实不生效，要说明。
    #[test]
    fn import_top_level_volumes_gets_accurate_warning() {
        let yaml = r#"
services:
  db:
    image: postgres:16-alpine
    volumes:
      - data:/var/lib/postgresql/data
volumes:
  data:
    name: my-pgdata
"#;
        let p = parse_compose_import(yaml, None).expect("解析应成功");
        assert!(p.errors.is_empty(), "{:?}", p.errors);
        let w = p.warnings.join(" | ");
        assert!(w.contains("具名卷"), "应说明具名卷会自动声明：{w}");
        assert!(
            !w.contains("顶层字段 `volumes`"),
            "顶层 volumes 不该报成「不支持」：{w}"
        );
    }
}
