//! `panel upgrade`：下载签名发行包 → 验签 → 解包 → 调用发行包内 `install.sh` →
//! 失败回滚旧二进制。
//!
//! 安全边界（与 `deploy/get-panel.sh` 同口径）：
//! 1. **先验签再解包**：用内嵌 ed25519 公钥（`deploy/release-pubkey.pub`，与安装器
//!    内嵌的那把由 `ci/check-docs-consistency.sh` 钉住一致）校验 tarball 的 `.sig`；
//!    验不过立即中止，绝不执行包内任何文件。
//! 2. **不信任下载源**：`--base-url` 只影响「从哪拿」，不影响「信谁」——镜像被投毒
//!    也过不了签名。`--pubkey-file` 仅供自建分发 / E2E，官方安装不要用。
//! 3. **失败回滚**：安装前把旧二进制复制为 `panel.bak`；`install.sh` 非 0，或装完
//!    `systemctl is-active panel` 不为 active，都把旧二进制换回去并重启。
//!    `install.sh` 的退出码**不能**单独作为判据：单元是 Type=simple，起来又立刻
//!    退出时它仍可能返回 0（安装脚本自己的注释也写了这一点）。
//! 4. 只支持 systemd 安装形态；非 systemd 环境由 `install.sh` 明确报错，本命令回滚。

use panel_core::{PanelError, Result};
use panel_os::cmd::{run as cmd_run, CmdOpt, CmdOutput};
use panel_os::Bin;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_BASE: &str = "https://github.com/crudguy/forkpanel-backend/releases/download";
const API_LATEST: &str = "https://api.github.com/repos/crudguy/forkpanel-backend/releases/latest";
/// 与 `deploy/get-panel.sh` 内嵌的 RELEASE_PUBKEY 是同一把；由文档一致性门禁比对。
const EMBEDDED_PUBKEY: &str = include_str!("../../../deploy/release-pubkey.pub");

pub struct Opts {
    pub check: bool,
    pub dry_run: bool,
    pub version: Option<String>,
    pub base_url: Option<String>,
    pub pubkey: Option<PathBuf>,
    pub data_dir: PathBuf,
}

pub fn run(opts: Opts) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PanelError::Internal(format!("tokio runtime: {e}")))?;
    rt.block_on(run_async(opts))
}

/// 临时目录守卫：无论成功失败都清掉（含半截 tarball / 解包产物）。
struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cmd_err(label: &str, out: &CmdOutput) -> PanelError {
    let detail = if out.stderr.trim().is_empty() {
        format!("exit={:?}", out.code)
    } else {
        out.stderr.trim().chars().take(300).collect::<String>()
    };
    PanelError::Command { bin: label.to_string(), detail }
}

async fn fetch_latest() -> Result<(String, bool, Option<String>)> {
    let out = cmd_run(
        Bin::Curl,
        &[
            "--silent", "--show-error", "--fail", "--max-time", "10",
            "-H", "Accept: application/vnd.github+json",
            "-H", "User-Agent: forkpanel-upgrade/0.1",
            API_LATEST,
        ],
        CmdOpt { timeout: Duration::from_secs(12), ..Default::default() },
    )
    .await?;
    // run() 对非 0 退出码仍返回 Ok（curl --fail 在 4xx 时是「非 0 + 空 stdout」），
    // 必须先看 code，否则会把 403 误报成 JSON 解析失败。
    if out.code != Some(0) {
        return Err(cmd_err("curl(latest)", &out));
    }
    let v: Value = serde_json::from_str(&out.stdout)
        .map_err(|e| PanelError::Internal(format!("发行信息不是合法 JSON：{e}")))?;
    let tag = v.get("tag_name").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if tag.is_empty() {
        return Err(PanelError::Internal("发行信息缺少 tag_name（API 形态可能已变）".into()));
    }
    let pre = v.get("prerelease").and_then(|x| x.as_bool()).unwrap_or(false);
    let at = v.get("published_at").and_then(|x| x.as_str()).map(str::to_string);
    Ok((tag, pre, at))
}

async fn download(url: &str, dest: &Path) -> Result<()> {
    let dest_s = dest.to_string_lossy().to_string();
    let out = cmd_run(
        Bin::Curl,
        &[
            "--silent", "--show-error", "--fail", "--location",
            "--max-time", "120", "-o", &dest_s, url,
        ],
        CmdOpt { timeout: Duration::from_secs(130), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Err(cmd_err("curl(download)", &out));
    }
    let size = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Err(PanelError::Internal(format!("下载得到空文件：{url}")));
    }
    Ok(())
}

fn normalize_tag(v: &str) -> String {
    let t = v.trim();
    if t.starts_with('v') { t.to_string() } else { format!("v{t}") }
}

async fn rollback(bin: &Path, bak: &Path) {
    if !bak.exists() {
        eprintln!("  ⚠ 没有可回滚的备份（{}），请手动检查", bak.display());
        return;
    }
    let tmp = bin.with_file_name("panel.rollback");
    if std::fs::copy(bak, &tmp).is_ok() {
        let _ = panel_os::fs::set_mode(&tmp, 0o755);
        match std::fs::rename(&tmp, bin) {
            Ok(()) => eprintln!("  ✓ 已回滚到旧二进制 {}", bin.display()),
            Err(e) => eprintln!("  ✗ 回滚失败：{e}（备份仍在 {}）", bak.display()),
        }
    }
    // 尽力把服务拉回旧版本；失败也不掩盖上面的错误。
    let _ = cmd_run(
        Bin::Systemctl,
        &["--no-block", "restart", "panel"],
        CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
    )
    .await;
}

async fn run_async(opts: Opts) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let arch = panel_os::release::arch_slug()
        .ok_or(PanelError::Unsupported("upgrade: 当前架构没有官方发行包"))?;

    // ── 只检查 ──
    if opts.check {
        let (tag, pre, at) = fetch_latest().await?;
        println!("当前版本：{current}");
        println!("最新版本：{tag}{}（{}）",
                 if pre { " · 预发布" } else { "" },
                 at.as_deref().unwrap_or("发布时间未知"));
        println!("可升级：{}", if panel_os::release::is_newer(&tag, current) { "是" } else { "否" });
        return Ok(());
    }

    // ── 目标版本 ──
    let tag = match opts.version.as_deref() {
        Some(v) => normalize_tag(v),
        None => fetch_latest().await?.0,
    };
    let base = opts.base_url.as_deref().unwrap_or(DEFAULT_BASE).trim_end_matches('/');
    let tarball = panel_os::release::tarball_name(arch);
    let url = format!("{base}/{tag}/{tarball}");
    println!("==> 当前 {current} → 目标 {tag}（{arch}）");
    println!("==> 下载 {url}");

    // ── 临时目录（0700，Drop 清理） ──
    let root = opts.data_dir.join("tmp");
    std::fs::create_dir_all(&root)
        .map_err(|e| PanelError::Internal(format!("create {}: {e}", root.display())))?;
    let work = root.join(format!("upgrade-{}", std::process::id()));
    std::fs::create_dir_all(&work)
        .map_err(|e| PanelError::Internal(format!("create {}: {e}", work.display())))?;
    let _ = panel_os::fs::set_mode(&work, 0o700);
    let _guard = TempDir(work.clone());

    let tar_path = work.join(&tarball);
    download(&url, &tar_path).await?;
    let sig_path = work.join(format!("{tarball}.sig"));
    download(&format!("{url}.sig"), &sig_path).await?;
    println!("    ✓ 下载完成（{} 字节）", std::fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0));

    // ── 验签 ──
    let pubkey = match opts.pubkey.as_deref() {
        Some(p) => {
            if !p.is_file() {
                return Err(PanelError::Validation {
                    field: "pubkey",
                    reason: format!("公钥文件不存在：{}", p.display()),
                });
            }
            p.to_path_buf()
        }
        None => {
            let p = work.join("pubkey.pem");
            std::fs::write(&p, EMBEDDED_PUBKEY)
                .map_err(|e| PanelError::Internal(format!("write pubkey: {e}")))?;
            p
        }
    };
    println!("==> 验签（ed25519）");
    let pk_s = pubkey.to_string_lossy().to_string();
    let sig_s = sig_path.to_string_lossy().to_string();
    let tar_s = tar_path.to_string_lossy().to_string();
    let out = cmd_run(
        Bin::OpenSsl,
        &["dgst", "-verify", &pk_s, "-signature", &sig_s, &tar_s],
        CmdOpt { timeout: Duration::from_secs(30), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Err(PanelError::Validation {
            field: "signature",
            reason: format!("发行包验签失败，已中止（{}）", out.stderr.trim()),
        });
    }
    println!("    ✓ 签名有效");

    // ── 解包 ──
    println!("==> 解包");
    let work_s = work.to_string_lossy().to_string();
    let out = cmd_run(
        Bin::Tar,
        &["-xzf", &tar_s, "-C", &work_s],
        CmdOpt { timeout: Duration::from_secs(60), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Err(cmd_err("tar", &out));
    }
    let new_bin = work.join("panel");
    let install_sh = work.join("install.sh");
    for f in [&new_bin, &install_sh] {
        if !f.is_file() {
            return Err(PanelError::Internal(format!(
                "发行包缺少 {}（包结构异常）", f.display()
            )));
        }
    }
    println!("    ✓ 已解出 panel / install.sh");

    if opts.dry_run {
        println!("--dry-run：下载、验签、解包均通过，未安装。");
        return Ok(());
    }
    if !panel_os::fs::is_root() {
        return Err(PanelError::Internal("upgrade: 安装需要 root 权限".into()));
    }

    // ── 备份 → 安装 → 判活（失败回滚） ──
    let bin = panel_os::paths::panel_bin_install_path();
    let bak = bin.with_extension("bak");
    if bin.exists() {
        std::fs::copy(&bin, &bak)
            .map_err(|e| PanelError::Internal(format!("备份 {}: {e}", bin.display())))?;
        println!("==> 已备份旧二进制 → {}", bak.display());
    }

    println!("==> 安装（调用发行包内 install.sh；配置与数据保留）");
    let ish_s = install_sh.to_string_lossy().to_string();
    let nb_s = new_bin.to_string_lossy().to_string();
    let out = cmd_run(
        Bin::Bash,
        &[&ish_s, &nb_s],
        CmdOpt {
            timeout: Duration::from_secs(180),
            working_dir: Some(work.clone()),
            ..Default::default()
        },
    )
    .await;
    let install_ok = matches!(&out, Ok(o) if o.code == Some(0));
    if !install_ok {
        let detail = match &out {
            Ok(o) => o.stderr.trim().chars().take(300).collect::<String>(),
            Err(e) => e.to_string(),
        };
        eprintln!("  ✗ install.sh 失败：{detail}");
        rollback(&bin, &bak).await;
        return Err(PanelError::Command {
            bin: "install.sh".into(),
            detail: format!("升级失败并已回滚：{detail}"),
        });
    }

    // install.sh 的 0 退出码不代表服务活着（Type=simple）⇒ 必须再判 active。
    let active = cmd_run(
        Bin::Systemctl,
        &["is-active", "panel"],
        CmdOpt { timeout: Duration::from_secs(15), ..Default::default() },
    )
    .await?;
    if active.code != Some(0) {
        eprintln!("  ✗ 升级后 panel 未处于 active（systemctl is-active != 0）");
        rollback(&bin, &bak).await;
        return Err(PanelError::Internal(
            "升级后服务未启动，已回滚旧版本；请查 journalctl -u panel -n 50".into(),
        ));
    }

    println!("    ✓ 服务已启动（systemd active）");
    println!("升级完成：{current} → {tag}（备份保留在 {}）", bak.display());
    Ok(())
}
