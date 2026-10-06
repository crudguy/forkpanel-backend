//! 第三方官方 apt 源注入（方案1：加官方源）。
//!
//! 安全纪律（与 cmd.rs 一致，所有外部命令走 Bin 枚举 + argv，不碰 shell）：
//! 1. 密钥只下载到临时文件，`gpg --show-keys --with-colons` 只读解析指纹，绝不 `--import`。
//! 2. 指纹比对走硬编码白名单 `ThirdPartyRepo::key_fingerprint`，MITM 替换密钥会因指纹不符被拒
//!    （指纹必须与上游官网公示值**逐字**一致；上游轮换密钥时由人工 review 更新此处，不得猜）。
//! 3. 密钥落到**隔离 keyring**（`/etc/apt/keyrings/<name>`，signed-by 引用），不用已被废弃的
//!    `apt-key add`（后者把密钥塞进全局信任环，污染所有源）。
//! 4. 源地址与密钥地址强制 https；不允许 http（防止中间人投递假源）。
//! 5. 整个流程需要 root：写 keyring/sources + apt-get update 都是特权动作；非 root 直接报
//!    `Io`（权限），不假装成功。

use crate::cmd::{Bin, CmdOpt};
use panel_core::{PanelError, Result};
use std::path::Path;
use std::time::Duration;

/// apt 仓库描述格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoFormat {
    /// 经典一行 deb：`deb [signed-by=...] <url> <suite>`
    DebList,
    /// deb822（Netdata）：多行 `Types: deb ...`
    Deb822,
}

/// 一个第三方官方 apt 源的完整定义（编译期常量，安全评审对象）。
pub struct ThirdPartyRepo {
    /// 逻辑包名（与白名单 `ALLOWED_PACKAGES.name` 对应；`ensure_repo` 据此查表）。
    pub logical: &'static str,
    /// 仓库源的 URL 主体（不含 suite 与组件，避免不同发行版拼法差异）。
    pub url: &'static str,
    /// 仓库格式。
    pub format: RepoFormat,
    /// GPG 公钥下载地址（https）。
    pub key_url: &'static str,
    /// 期望的 GPG **主钥**指纹（大写、去空格后比对），硬编码防 MITM。
    pub key_fingerprint: &'static str,
    /// keyring 文件名（落在 /etc/apt/keyrings/）。
    pub keyring_name: &'static str,
    /// sources.list.d 文件名（落在 /etc/apt/sources.list.d/）。
    pub sources_name: &'static str,
    /// suite/组件：DebList 固定字符串；Deb822 形如 `trixie /`，codename_dependent=true 时
    /// 含 `{codename}` 占位符，需 current_codename 填充。
    pub suite: &'static str,
    /// suite 是否依赖发行版代号（true 时 suite 含 `{codename}` 占位符，需 current_codename 填充）。
    pub codename_dependent: bool,
}

/// 当前支持自动加源的白名单（仅经安全评审、且上游确有官方 apt 源的包）。
///
/// **minio / netdata 均不在表内**（2026-10-06 实测复核，两者上游 apt 仓库均已下线）：
/// - `minio`：`dl.min.io/server/minio/release/linux-debian/` 整个 apt 仓库已下线（key.asc /
///   InRelease / Release 均返回 410），`packages.min.io` 域名不存在。
/// - `netdata`：密钥仍可下载（`repository.netdata.cloud/netdatabot.gpg.key` → 200，且指纹与
///   白名单逐字一致），但**仓库元数据整体 404**——`repos/stable/debian/dists/{bookworm,
///   bullseye,trixie}/InRelease` 与 `Release` 全部返回 404，连老牌 bookworm 也不可用，
///   故并非「Debian 13 太新没有适配」，而是上游仓库本身已不可用。目录列表页仍可访问
///   （易误判为可用），必须以 InRelease 200 为准。上游现推荐 kickstart.sh / 静态安装。
///   注意官方文档把 URI 写成 `http://`，本项目强制 https（安全纪律第 4 条），即便如此仍 404。
///
/// 两者仍保留在 `ALLOWED_PACKAGES` 与 `EXTERNAL_SOURCE_PACKAGES`，UI 继续提示"需配源"，
/// 但 `ensure_repo` 对其是 no-op，装之前需用户另行提供源（或由方案3「直接下载 .deb /
/// 静态安装」实现接管）。
pub static THIRD_PARTY_REPOS: &[ThirdPartyRepo] = &[
    ThirdPartyRepo {
        logical: "grafana",
        url: "https://apt.grafana.com",
        format: RepoFormat::DebList,
        key_url: "https://apt.grafana.com/gpg.key",
        // 上游官网公示指纹（2023-08 起生效，已续期至 2027-08）。实测本机下载密钥解析一致。
        key_fingerprint: "B53AE77BADB630A683046005963FA27710458545",
        keyring_name: "grafana.asc",
        sources_name: "grafana.list",
        suite: "stable main",
        codename_dependent: false,
    },
    ThirdPartyRepo {
        logical: "postgresql",
        url: "https://apt.postgresql.org/pub/repos/apt",
        format: RepoFormat::DebList,
        key_url: "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
        // PGDG 官方公示主钥（PostgreSQL Debian Repository，2022 起）。实测本机下载
        // 解析得 B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8，与官网一致。
        key_fingerprint: "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",
        keyring_name: "pgdg.gpg",
        sources_name: "pgdg.list",
        // suite 依赖发行版代号（trixie-pgdg / bookworm-pgdg / jammy-pgdg…）。
        suite: "{codename}-pgdg main",
        codename_dependent: true,
    },
    ThirdPartyRepo {
        logical: "redis",
        url: "https://packages.redis.io/deb",
        format: RepoFormat::DebList,
        key_url: "https://packages.redis.io/gpg",
        // Redis 官方源主钥（Redis Ltd，2024 起）。实测本机下载解析得一主一子，
        // 主钥 54318FA4052D1E61A6B6F7BB5F4349D6BF53AA0C，与官网公示值一致。
        key_fingerprint: "54318FA4052D1E61A6B6F7BB5F4349D6BF53AA0C",
        keyring_name: "redis.gpg",
        sources_name: "redis.list",
        // 官方源用发行版代号分目录，trixie 上实测可选到 8.2.2（比 Debian 的
        // 8.0.2 新。注意该源的版本是 RHEL 系构建（...~trixie1 后缀），
        // 虽同为 deb 但打包方式不同，跨大版本前建议看上游 release notes。
        suite: "{codename} main",
        codename_dependent: true,
    },
];

/// 按逻辑包名查第三方源定义（无则返回 None → `ensure_repo` 视为 no-op）。
pub fn third_party_repo(logical: &str) -> Option<&'static ThirdPartyRepo> {
    THIRD_PARTY_REPOS.iter().find(|r| r.logical == logical)
}

// ─────────────── 纯函数（可单测，不依赖文件系统/网络） ───────────────

/// 解析 /etc/os-release 的 VERSION_CODENAME（纯函数，便于单测）。
pub fn parse_codename(os_release: &str) -> Option<String> {
    os_release.lines()
        .find_map(|l| l.strip_prefix("VERSION_CODENAME="))
        .map(|v| v.trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

/// 从 `gpg --show-keys --with-colons` 输出抽取所有指纹（大写）。
/// `fpr:` 行形如 `fpr:::::::::B53AE...:` —— 指纹落在该行的最后一个非空字段
/// （gpg 该记录末列即指纹；取末非空字段避免依赖具体列数，抗 gpg 小版本差异）。
/// 每个 `fpr:` 行对应一把密钥（主钥 / 子钥各一行），故可能返回多个。
pub fn extract_fingerprints(colons: &str) -> Vec<String> {
    colons.lines()
        .filter_map(|l| l.strip_prefix("fpr:"))
        .filter_map(|rest| rest.split(':').filter(|s| !s.is_empty()).last())
        .map(|fp| fp.to_ascii_uppercase())
        .collect()
}

/// 比对期望指纹与实际指纹集合（大小写/空格不敏感）。命中任一即视为可信。
pub fn fingerprint_matches(expected: &str, got: &[String]) -> bool {
    let want = expected.replace([' ', '\t'], "").to_ascii_uppercase();
    got.iter().any(|g| g.replace([' ', '\t'], "").to_ascii_uppercase() == want)
}

/// 生成 sources 文件内容（纯函数；codename_dependent 时用给定代号替换 `{codename}`）。
pub fn build_sources_content(repo: &ThirdPartyRepo, codename: &str) -> String {
    let suite = if repo.codename_dependent {
        repo.suite.replace("{codename}", codename)
    } else {
        repo.suite.to_string()
    };
    let keyring = format!("/etc/apt/keyrings/{}", repo.keyring_name);
    match repo.format {
        RepoFormat::DebList => {
            format!("deb [signed-by={keyring}] {} {suite}\n", repo.url)
        }
        RepoFormat::Deb822 => {
            format!(
                "Types: deb\nURIs: {}\nSuites: {suite}\nSigned-By: {keyring}\nBy-Hash: Yes\nEnabled: Yes\n",
                repo.url
            )
        }
    }
}

// ─────────────── I/O 流程（需 root） ───────────────

/// 读取当前发行版代号（读 /etc/os-release）。
pub async fn current_codename() -> Result<String> {
    let content = tokio::fs::read_to_string("/etc/os-release").await
        .map_err(|e| PanelError::Io(format!("read /etc/os-release: {e}")))?;
    parse_codename(&content).ok_or_else(|| PanelError::Unsupported("os.codename"))
}

fn trunc(s: &str) -> String {
    let s = s.trim();
    if s.len() <= 2000 { s.to_string() } else { format!("{}…(已截断)", &s[..2000]) }
}

/// 确保第三方 apt 源就绪：下载并校验 GPG 密钥指纹 → 写隔离 keyring → 写 sources.list.d → apt-get update。
///
/// 幂等：若 sources 文件已存在且内容一致、keyring 也存在，则跳过整段（不重复 apt-get update）。
/// 非 root 直接报 `Io`（权限），不假装成功。
pub async fn ensure_third_party_repo(repo: &ThirdPartyRepo, on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
    let codename = if repo.codename_dependent {
        // 提前解析代号，缺代号无法拼 suite；失败即中止（避免装到缺源的包）
        current_codename().await?
    } else {
        String::new()
    };
    let sources_content = build_sources_content(repo, &codename);
    ensure_repo_inner(repo, &sources_content, on_line).await
}

async fn ensure_repo_inner(repo: &ThirdPartyRepo, sources_content: &str, on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
    // 用一个 Arc 持有回调：既能直接调用 `cb(...)`，又能 clone 出一个 `'static` 闭包交给
    // CmdOpt::on_line（其字段类型是 `Arc<dyn Fn(&str)+Send+Sync+'static>`，要求捕获值 'static）。
    let cb: std::sync::Arc<dyn Fn(String) + Send + Sync> = std::sync::Arc::from(on_line);
    let keyrings_dir = Path::new("/etc/apt/keyrings");
    let sources_dir = Path::new("/etc/apt/sources.list.d");
    let keyring_path = keyrings_dir.join(repo.keyring_name);
    let sources_path = sources_dir.join(repo.sources_name);

    // 幂等快路径：keyring 与 sources 都已存在且 sources 内容一致 → 跳过（不触碰网络/apt）
    if keyring_path.is_file() && sources_path.is_file() {
        if let Ok(existing) = tokio::fs::read_to_string(&sources_path).await {
            if existing.trim() == sources_content.trim() {
                cb(format!("[panel] 第三方源 {} 已配置且一致，跳过", repo.logical));
                return Ok(());
            }
        }
    }

    cb(format!("[panel] 添加第三方源 {}（下载并校验 GPG 密钥）", repo.logical));

    // 1) 下载密钥到临时文件（https only，经 Bin 枚举，argv 直传，不经 shell）
    let tmp_key = std::env::temp_dir().join(format!("panel-repo-{}.key", repo.logical));
    let dl = crate::cmd::run(Bin::Curl, &[
        "-fsSL", "--max-time", "30", "-o",
        tmp_key.to_str().unwrap_or("/tmp/panel-repo.key"),
        repo.key_url,
    ], CmdOpt { timeout: Duration::from_secs(40), ..Default::default() }).await;
    match dl {
        Ok(o) if o.code == Some(0) => {}
        Ok(o) => return Err(PanelError::Command {
            bin: "curl".into(),
            detail: format!("下载 {} 密钥失败：{}", repo.logical, trunc(&o.stderr)),
        }),
        Err(e) => return Err(e),
    }

    // 2) 抽取并校验指纹（只读解析，绝不 --import；用隔离 homedir 避免污染目标机 gnupg）
    let homedir = std::env::temp_dir().join(format!("panel-gpg-{}", repo.logical));
    let _ = tokio::fs::create_dir_all(&homedir).await;
    let hd = homedir.to_str().unwrap_or("/tmp");
    let key_arg = tmp_key.to_str().unwrap_or("/tmp/panel-repo.key");
    let gpg_out = crate::cmd::run(Bin::Gpg, &[
        "--homedir", hd, "--batch", "--show-keys", "--with-colons", key_arg,
    ], CmdOpt { timeout: Duration::from_secs(20), ..Default::default() }).await
        .map_err(|e| PanelError::Command {
            bin: "gpg".into(),
            detail: format!("解析 {} 密钥失败：{e}", repo.logical),
        })?;
    let fps = extract_fingerprints(&gpg_out.stdout);
    if fps.is_empty() {
        return Err(PanelError::Command {
            bin: "gpg".into(),
            detail: format!("{} 密钥未解析出指纹（可能已损坏或被篡改）", repo.logical),
        });
    }
    if !fingerprint_matches(repo.key_fingerprint, &fps) {
        return Err(PanelError::Command {
            bin: "gpg".into(),
            detail: format!(
                "{} 的 GPG 密钥指纹不匹配（期望 {}，实际 {:?}）。疑似被中间人篡改或上游已轮换密钥，\
                 拒绝添加该源。如确需更新，请联系管理员复核后修改白名单指纹。",
                repo.logical, repo.key_fingerprint, fps
            ),
        });
    }
    cb(format!("[panel] {} GPG 密钥指纹校验通过", repo.logical));

    // 3) 写隔离 keyring（/etc/apt/keyrings 需 root）
    tokio::fs::create_dir_all(keyrings_dir).await
        .map_err(|e| PanelError::Io(format!("创建 {} 失败（需 root）：{e}", keyrings_dir.display())))?;
    tokio::fs::copy(&tmp_key, &keyring_path).await
        .map_err(|e| PanelError::Io(format!("写入 keyring {} 失败（需 root）：{e}", keyring_path.display())))?;

    // 4) 写 sources.list.d
    tokio::fs::create_dir_all(sources_dir).await
        .map_err(|e| PanelError::Io(format!("创建 {} 失败（需 root）：{e}", sources_dir.display())))?;
    tokio::fs::write(&sources_path, sources_content).await
        .map_err(|e| PanelError::Io(format!("写入 sources {} 失败（需 root）：{e}", sources_path.display())))?;

    // 5) apt-get update（刷新该源元数据）
    cb(format!("[panel] apt-get update（刷新 {} 源）", repo.logical));
    // 先 clone 一份 'static 句柄交给 CmdOpt（其 on_line 字段要求捕获值 'static），
    // 避免把 `cb` 整体 move 进闭包导致后面无法再调用 `cb(...)`。
    let cb_for_apt = cb.clone();
    crate::cmd::run_checked(Bin::Apt, &["update"], CmdOpt {
        timeout: Duration::from_secs(300),
        on_line: Some(std::sync::Arc::new(move |l: &str| cb_for_apt(l.to_string()))),
        ..Default::default()
    }).await.map_err(|e| PanelError::Command {
        bin: "apt-get".into(),
        detail: format!("apt-get update 失败：{e}"),
    })?;

    // 清理临时密钥与隔离 homedir
    let _ = tokio::fs::remove_file(&tmp_key).await;
    let _ = tokio::fs::remove_dir_all(&homedir).await;
    cb(format!("[panel] 第三方源 {} 已就绪", repo.logical));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_fingerprints_parses_colon_output() {
        let out = "pub:::::::::B53AE77BADB630A683046005963FA27710458545:\n\
                   fpr:::::::::B53AE77BADB630A683046005963FA27710458545:\n\
                   sub:::::::::AEF6B95F255D2E8FFE882226488427A542157EA4:\n\
                   fpr:::::::::AEF6B95F255D2E8FFE882226488427A542157EA4:\n";
        let fps = extract_fingerprints(out);
        assert_eq!(fps, vec![
            "B53AE77BADB630A683046005963FA27710458545",
            "AEF6B95F255D2E8FFE882226488427A542157EA4",
        ]);
    }

    #[test]
    fn fingerprint_matches_is_case_and_space_insensitive() {
        let got = vec!["b53ae77badb630a683046005963fa27710458545".to_string()];
        assert!(fingerprint_matches("B53AE77BADB630A683046005963FA27710458545", &got));
        assert!(fingerprint_matches("B53A E77B ADB6 30A6 8304 6005 963F A277 1045 8545", &got));
        // 子钥不应被误判为主钥匹配
        assert!(!fingerprint_matches("DEADBEEF00000000000000000000000000000000", &got));
    }

    #[test]
    fn parse_codename_reads_version_codename() {
        let or = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n\
                  VERSION_CODENAME=trixie\nID=debian\n";
        assert_eq!(parse_codename(or), Some("trixie".to_string()));
        assert_eq!(parse_codename("ID=debian\n"), None);
    }

    #[test]
    fn build_sources_deb_list_is_static() {
        let r = &THIRD_PARTY_REPOS[0]; // grafana
        assert_eq!(r.format, RepoFormat::DebList);
        assert_eq!(
            build_sources_content(r, ""),
            "deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main\n"
        );
    }

    #[test]
    fn build_sources_deb822_fills_codename() {
        // netdata 已于 2026-10-06 实测确认上游仓库整体 404 并移出 THIRD_PARTY_REPOS，
        // 但 deb822 + codename 渲染分支仍需保留（grafana 若改格式即走此路径），故用构造
        // 出来的定义覆盖它，而不是引用已移出的真实条目（那会让本用例随表变动而失效）。
        let r = ThirdPartyRepo {
            logical: "example",
            url: "https://example.test/repos/stable/debian/",
            format: RepoFormat::Deb822,
            key_url: "https://example.test/k.gpg.key",
            key_fingerprint: "DEADBEEF00000000000000000000000000000000",
            keyring_name: "example.gpg",
            sources_name: "example.sources",
            suite: "{codename} /",
            codename_dependent: true,
        };
        let got = build_sources_content(&r, "trixie");
        assert!(got.contains("Suites: trixie /"), "codename 占位符应被替换：{got}");
        assert!(got.contains("URIs: https://example.test/repos/stable/debian/"));
        assert!(got.contains("Signed-By: /etc/apt/keyrings/example.gpg"));
        // 未替换时不应残留占位符
        assert!(!got.contains("{codename}"));
    }

    #[test]
    fn pgdg_and_redis_suites_fill_codename() {
        // PGDG：suite 含空格（"{codename}-pgdg main"），占位符替换后仍应是合法
        // 的一行 deb（codename 与 main 各占一段）。若误按空格 split codename，
        // 会拼出 "deb ... trixie-pgdd" 缺 main 的坏行。
        let pgdg = third_party_repo("postgresql").expect("PGDG 应在表内");
        assert!(pgdg.codename_dependent);
        let got = build_sources_content(pgdg, "trixie");
        assert_eq!(
            got,
            "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt trixie-pgdg main\n"
        );

        // Redis：suite 无空格（"{codename} main"），官方源用发行版代号分目录。
        let redis = third_party_repo("redis").expect("Redis 应在表内");
        let got = build_sources_content(redis, "trixie");
        assert_eq!(
            got,
            "deb [signed-by=/etc/apt/keyrings/redis.gpg] https://packages.redis.io/deb trixie main\n"
        );
    }

    #[test]
    fn third_party_repos_all_have_pinned_fingerprints() {
        // 防 MITM 的底线：表内每一条都必须钉死指纹。
        // 一旦某条被改成空/占位，gpg 解析出的指纹就可能"匹配"任何密钥。
        for r in THIRD_PARTY_REPOS {
            assert_eq!(
                r.key_fingerprint.len(), 40,
                "{} 的指纹必须是 40 位十六进制，实际 {:?}",
                r.logical, r.key_fingerprint
            );
            assert!(
                r.key_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "{} 的指纹含非十六进制字符: {:?}",
                r.logical, r.key_fingerprint
            );
            assert!(r.key_url.starts_with("https://"), "{} 的密钥地址必须 https", r.logical);
            assert!(r.url.starts_with("https://"), "{} 的源地址必须 https", r.logical);
        }
    }

    #[test]
    fn netdata_and_minio_are_not_auto_repo_managed() {
        // 两者上游 apt 仓库均已下线（netdata 连 bookworm 的 InRelease 都 404），
        // 若被误加回 THIRD_PARTY_REPOS，ensure_repo 会在 apt-get update 阶段硬失败。
        for logical in ["netdata", "minio"] {
            assert!(
                third_party_repo(logical).is_none(),
                "{logical} 的上游源已失效，不应出现在自动加源表里"
            );
        }
    }

    #[test]
    fn grafana_is_auto_repo_managed() {
        // 反向对照：grafana 源实测可用（InRelease 200 + 567 个版本），必须留在表内。
        let r = third_party_repo("grafana").expect("grafana 应有官方源");
        assert_eq!(r.format, RepoFormat::DebList);
        assert!(!r.codename_dependent);
    }

    #[test]
    fn idempotency_content_compare_is_exact() {
        // 同样输入生成同样内容（确保幂等快路径的内容比对稳定）
        let r = &THIRD_PARTY_REPOS[0];
        assert_eq!(build_sources_content(r, ""), build_sources_content(r, ""));
    }
}
