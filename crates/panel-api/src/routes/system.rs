//! 系统与监控 handler。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{Auth, Shared},
};
use axum::{extract::{Query, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize)]
pub struct VersionResp {
    pub api: &'static str,
    pub app: String,
    pub build: String,
    /// 前端构建时锁定 API 版本，不匹配则提示升级面板（防前后端错配产生诡异 bug）
    pub min_web: &'static str,
}

pub async fn version() -> Json<serde_json::Value> {
    ok(VersionResp {
        api: "1.0",
        app: env!("CARGO_PKG_VERSION").to_string(),
        build: option_env!("PANEL_BUILD").unwrap_or("dev").to_string(),
        min_web: "1.0",
    })
}

/// 能力矩阵。**前端菜单/按钮的唯一开关来源**（设计方案 §0.3.4）。
pub async fn capabilities(State(state): State<Shared>, _: Auth) -> Json<serde_json::Value> {
    // `limits`：高危操作的并发上限（P2-5）。前端读它而不是自己硬编码一份——
    // 两端各写一个 4，改一端忘另一端就是「面板说能开、实际 503」。
    ok(serde_json::json!({
        "platform": state.os.platform(),
        "features": state.capabilities,
        "limits": {
            "terminal_max_sessions": crate::routes::terminal::TERMINAL_MAX_SESSIONS,
        },
    }))
}

#[derive(Debug, Serialize)]
pub struct OverviewResp {
    pub ts: i64,
    pub uptime_sec: u64,
    pub cpu_pct: f32,
    pub mem_used_kib: u64,
    pub mem_total_kib: u64,
    pub load1: f32,
    pub disks: usize,
    /// 本地磁盘（排除网络文件系统）已用字节
    pub disk_used_bytes: u64,
    /// 本地磁盘（排除网络文件系统）总字节
    pub disk_total_bytes: u64,
    /// 入站速率（排除回环接口），字节/秒
    pub net_in_bps: u64,
    /// 出站速率（排除回环接口），字节/秒
    pub net_out_bps: u64,
    pub tier: &'static str,
    /// 采样是否已被降频（低配保护，UI 需提示）
    pub degraded: bool,
}

/// 一次性快照（仪表盘卡片数据）。
pub async fn overview(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    // 只读采集循环缓存的快照，不自己触发采样：CPU 是区间值，谁调 snapshot() 谁重置
    // panel-os 的共享采样基准，既拿到被截断的抖动值、又截短采集循环的下一次窗口
    // （详见 AppState::cached_snapshot 的注释）。缓存尚未产出（首启 1 秒内）才兜底。
    // 用全限定 Arc 以免为此在 WIP 文件里多加一处 use。
    let snap = match state.cached_snapshot().await {
        Some(s) => s,
        None => std::sync::Arc::new(state.os.metrics().snapshot().await?),
    };
    Ok(ok(OverviewResp {
        ts: snap.ts_unix,
        uptime_sec: snap.uptime_sec,
        cpu_pct: snap.cpu.total_pct,
        mem_used_kib: snap.mem.used_kib,
        mem_total_kib: snap.mem.total_kib,
        load1: snap.cpu.load1,
        disks: snap.disks.len(),
        disk_used_bytes: snap.disks.iter().filter(|d| !d.is_network_fs).map(|d| d.used_bytes).sum(),
        disk_total_bytes: snap.disks.iter().filter(|d| !d.is_network_fs).map(|d| d.total_bytes).sum(),
        net_in_bps: snap.nets.iter().filter(|n| n.iface != "lo").map(|n| n.rx_rate_bps).sum(),
        net_out_bps: snap.nets.iter().filter(|n| n.iface != "lo").map(|n| n.tx_rate_bps).sum(),
        tier: match state.tier {
            panel_core::Tier::Nano => "nano",
            panel_core::Tier::Small => "small",
            panel_core::Tier::Standard => "standard",
        },
        degraded: matches!(state.tier, panel_core::Tier::Nano),
    }))
}

/// 实时指标：直接读内存环形缓冲，不查库（低配机器上这是关键路径）。
#[derive(Debug, serde::Deserialize)]
pub struct RealtimeQ { pub since: Option<usize> }

pub async fn realtime(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<RealtimeQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let n = q.since.unwrap_or(60).clamp(1, 3600);   // 上限保护：防止一次拉取全部缓冲
    let samples: Vec<_> = {
        let g = state.metrics.lock().unwrap_or_else(|e| e.into_inner());
        g.ring().last_n(n).iter().map(|s| serde_json::json!({
            "ts": s.ts, "cpu": s.cpu_pct, "mem_used_kib": s.mem_used_kib,
            "mem_total_kib": s.mem_total_kib, "load1": s.load1,
            // 与 SSE 推送口径一致：补充磁盘/网络实时字段，供前端画实时趋势
            "disk_used_bytes": s.disk_used_bytes,
            "disk_total_bytes": s.disk_total_bytes,
            "net_in_bps": s.net_in_bps,
            "net_out_bps": s.net_out_bps,
        })).collect()
    };
    Ok(ok(serde_json::json!({
        "interval_ms": state.tier.sampling_interval_ms(),
        "samples": samples,
    })))
}

/// 历史指标：查聚合表。**nano 档位不落盘**，需明确告知前端。
#[derive(Debug, serde::Deserialize)]
pub struct HistoryQ {
    pub range: Option<String>,   // "1h" | "24h" | "7d"
    pub gran: Option<String>,    // "1m" | "1h"
}

pub async fn history(
    State(state): State<Shared>,
    Auth(s): Auth,
    Query(q): Query<HistoryQ>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let gran = q.gran.unwrap_or_else(|| "1m".into());
    if !matches!(gran.as_str(), "1m" | "1h") {
        return Err(ApiError::bad_request("gran", "must be 1m or 1h"));
    }
    // 表名来自枚举映射，**绝不接受用户输入拼接**（SQL 注入红线）
    let table = match gran.as_str() { "1m" => "metrics_1m", _ => "metrics_1h" };
    if !state.tier.persist_history() {
        return Ok(ok(serde_json::json!({
            "granularity": gran,
            "samples": [],
            "unavailable": "nano tier does not persist history to disk",
        })));
    }
    let rows = state.pool.with(move |conn| {
        // 表名是编译期常量映射的结果，此处用 match 生成两条常量 SQL，避免 format!
        let sql = match table {
            "metrics_1m" => "SELECT ts, cpu_pct, mem_used_kib, load1 FROM metrics_1m
                             ORDER BY ts DESC LIMIT 1440",
            _ => "SELECT ts, cpu_pct, mem_used_kib, load1 FROM metrics_1h
                  ORDER BY ts DESC LIMIT 720",
        };
        let mut st = conn.prepare(sql)
            .map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        let it = st.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?,
                r.get::<_, i64>(2)?, r.get::<_, f64>(3)?))
        }).map_err(|e| panel_core::PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| panel_core::PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;
    Ok(ok(serde_json::json!({ "granularity": gran, "samples": rows })))
}

/// 完整系统快照（专业监控页）：暴露 SystemSnapshot 的全部细节字段
/// （CPU 总体 + per-core、load1/5/15、内存 + swap 明细、每挂载点磁盘、每网卡吞吐、进程数）。
pub async fn snapshot(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let snap = state.os.metrics().snapshot().await?;
    Ok(ok(snap))
}

/// 枚举本机系统账户（只读 `/etc/passwd`），供「运行用户」下拉等选择入口使用。
///
/// 权限用 `SERVICE_VIEW`：与应用（apps）列表同级——运行用户选择本就是应用创建/编辑
/// 表单的辅助信息，应用页可见即可见本列表；它只读不写，不会扩大攻击面。
pub async fn users(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SERVICE_VIEW)?;
    let list = state.os.users().list().await?;
    Ok(ok(list))
}

/// 目录与文件位置：面板自身、数据、日志、Web 服务器（系统自带）、前端（内嵌）。
///
/// 用途：让终端用户在管理页面一眼看清"装到了哪、数据在哪、日志在哪、软件哪来的"，
/// 不必去翻服务器或文档。所有路径来自 PathLayout（配置感知），与运行时实际落点一致。
pub async fn directories(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let p = state.os.paths();
    let data = p.data_dir();
    let bin = std::env::current_exe()
        .map(|x| x.display().to_string())
        .unwrap_or_default();
    let ws_name = state.os.webserver().name();
    let item = |label: &str, path: String, desc: Option<&str>| {
        json!({ "label": label, "path": path, "desc": desc })
    };
    let groups = json!([
        {
            "key": "panel",
            "title": "面板自身（二进制与目录）",
            "items": [
                item("二进制文件", bin.clone(), Some("单文件静态二进制，前端已内嵌其中")),
                item("配置目录", p.config_dir().display().to_string(), None),
                item("数据根目录", data.display().to_string(), None),
                item("日志目录", p.log_dir().display().to_string(), None),
                item("站点根目录", p.site_root().display().to_string(), None),
                item("服务单元目录", p.service_dir().display().to_string(), Some("systemd 单元所在")),
            ]
        },
        {
            "key": "data",
            "title": "数据存放",
            "items": [
                item("主数据库", p.sqlite_path().display().to_string(), Some("SQLite（WAL 模式）")),
                item("主密钥", data.join("master.key").display().to_string(), Some("加密 SSL 私钥/凭据；不进任何备份")),
                item("证书与 CA", data.join("ssl").display().to_string(), None),
                item("备份产物", data.join("backups").display().to_string(), None),
                item("配置自动备份", data.join("conf-backups").display().to_string(), None),
                item("计划任务脚本", data.join("scripts").display().to_string(), Some("受限目录")),
                item("缓存 / 临时", format!("{} / {}", data.join("cache").display(), data.join("tmp").display()), None),
            ]
        },
        {
            "key": "log",
            "title": "日志存放",
            "items": [
                item("面板日志", p.log_dir().display().to_string(), None),
                item("站点访问日志", p.web_log_dir().display().to_string(), None),
            ]
        },
        {
            "key": "web",
            "title": "Web 服务器（系统自带，非面板安装）",
            "items": [
                item("Web 服务器", ws_name.to_string(), Some("由发行版包管理器安装，面板只写配置")),
                item("站点配置 drop-in", p.web_conf_dir().display().to_string(), None),
                item("站点访问日志", p.web_log_dir().display().to_string(), None),
            ]
        },
        {
            "key": "frontend",
            "title": "前端文件",
            "items": [
                item("说明", format!("已内嵌于二进制 {}，无独立目录", bin), None),
            ]
        }
    ]);
    Ok(ok(json!({
        "binary": bin,
        "frontend_embedded": true,
        "groups": groups,
    })))
}


/// 重启面板（owner-only）。
///
/// 为什么用 `--no-block`：本 handler 就跑在**即将被 systemd 停掉的那个进程**里。
/// `systemctl restart` 默认等待 job 完成 ⇒ handler 会在等待中被一起杀掉，浏览器
/// 连响应都收不到；`--no-block` 把 job 交给 PID 1 后立即返回，响应才发得出去。
/// 前端仍把「请求失败」视作已发起（重启瞬间断连是预期），靠轮询 `/version` 判定恢复。
///
/// 权限：`system.manage` + owner。admin 可以改设置，但重启服务是可用性操作，
/// 影响所有在线用户，故比普通设置更严一档。
pub async fn restart(
    State(_state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    if s.role != "owner" {
        return Err(ApiError::new(
            10003,
            StatusCode::FORBIDDEN,
            "仅 owner 可重启面板（admin 可改设置，但不能重启服务）",
        ));
    }
    panel_os::run_sync(panel_os::Bin::Systemctl, &["--no-block", "restart", "panel"])?;
    Ok((StatusCode::ACCEPTED, ok(json!({ "accepted": true }))))
}


// ───────────────────────── 检查更新（只读） ─────────────────────────

/// GitHub Releases API（**编译期常量**，不接受任何用户输入 ⇒ 无 SSRF 面）。
const RELEASE_URL: &str =
    "https://api.github.com/repos/crudguy/forkpanel-backend/releases/latest";


#[derive(Debug, Serialize)]
pub struct UpgradeCheckResp {
    pub current: &'static str,
    pub latest: Option<String>,
    pub latest_tag: Option<String>,
    pub available: bool,
    pub prerelease: bool,
    pub published_at: Option<String>,
    pub source: &'static str,
    pub supported: bool,
    pub checked_at: i64,
    pub error: Option<String>,
}

/// 检查是否有新版本。**只读**：不下载、不写盘、不重启。
///
/// 为什么走 `Bin::Curl`：项目硬纪律是「子进程唯一出口在 panel-os::cmd」，且直接
/// 依赖有预算上限；curl 已在白名单内（webhook 同款），零新增依赖。URL 固定，
/// 用户无法指定目标。
///
/// 网络失败返回 **200 + `error`**，不是 5xx：对页面而言「检查失败」是正常状态，
/// 应该显示原因（DNS/超时/被墙），而不是把整张卡片渲染成服务器错误。
pub async fn upgrade_check(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    crate::ratelimit::check_read(&state, &s.username, "system.upgrade_check")?;

    let mut resp = UpgradeCheckResp {
        current: env!("CARGO_PKG_VERSION"),
        latest: None,
        latest_tag: None,
        available: false,
        prerelease: false,
        published_at: None,
        source: "github",
        supported: panel_os::Bin::Curl.available(),
        checked_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        error: None,
    };
    if !resp.supported {
        resp.error = Some("curl 不可用，无法检查更新（可从发行页手动下载）".into());
        return Ok(ok(resp));
    }

    let out = panel_os::cmd::run(
        panel_os::Bin::Curl,
        &[
            "--silent", "--show-error", "--fail", "--max-time", "5",
            "-H", "Accept: application/vnd.github+json",
            "-H", "User-Agent: forkpanel-upgrade-check/0.1",
            RELEASE_URL,
        ],
        panel_os::cmd::CmdOpt {
            timeout: std::time::Duration::from_secs(7),
            ..Default::default()
        },
    )
    .await;

    match out {
        // `run()` 对**非 0 退出码仍返回 Ok**（它只把 spawn/超时当 Err）。若不看 code，
        // curl `--fail` 在 4xx/5xx 时恰好是「非 0 + 空 stdout」，会被误报成
        // 「JSON 为空」——把真正的 403/断网原因吞掉。判据必须是 code 先行。
        Ok(o) if o.code != Some(0) => {
            let detail = if o.stderr.trim().is_empty() {
                format!("curl 退出码 {:?}", o.code)
            } else {
                o.stderr.trim().chars().take(200).collect::<String>()
            };
            resp.error = Some(format!("检查失败：{detail}"));
        }
        Ok(o) if o.stdout.trim().is_empty() => {
            resp.error = Some("检查失败：发行接口返回空响应（网络被代理/防火墙拦截？）".into());
        }
        Ok(o) => match serde_json::from_str::<serde_json::Value>(&o.stdout) {
            Ok(v) => {
                let tag = v.get("tag_name").and_then(|x| x.as_str()).unwrap_or("");
                if tag.is_empty() {
                    resp.error = Some("发行信息缺少 tag_name（API 形态可能已变）".into());
                } else {
                    resp.latest = Some(tag.trim_start_matches('v').to_string());
                    resp.latest_tag = Some(tag.to_string());
                    resp.prerelease = v.get("prerelease").and_then(|x| x.as_bool()).unwrap_or(false);
                    resp.published_at = v.get("published_at").and_then(|x| x.as_str()).map(str::to_string);
                    resp.available = panel_os::release::is_newer(tag, resp.current);
                }
            }
            Err(e) => resp.error = Some(format!("发行信息不是合法 JSON：{e}")),
        },
        Err(e) => {
            // 截断：curl 的报错可能带很长的链路信息，页面只需要原因。
            let msg: String = e.to_string().chars().take(200).collect();
            resp.error = Some(format!("检查失败：{msg}"));
        }
    }
    Ok(ok(resp))
}


#[derive(Debug, Deserialize)]
pub struct UpgradeReq {
    /// 目标版本（带不带 v 均可）；省略 = 最新
    #[serde(default)]
    pub version: Option<String>,
}

/// 触发 Web 升级（**默认关闭**）。
///
/// 三道门：`[danger] allow_web_upgrade` + owner + `systemd-run` 可用。
///
/// 为什么必须 `systemd-run`：升级会重启面板。直接 spawn 的子进程留在当前 service
/// 的 cgroup 里，systemd 重启时会把它一起杀掉，升级半途而废（二进制已替换、
/// install.sh 没跑完）。瞬时单元在独立 cgroup 执行，面板重启不影响它；页面靠
/// 轮询 `/version` 判断恢复，失败由 CLI 自动回滚。
///
/// 版本号只做**字符白名单**校验并作为单个 argv 传入（不经 shell）；`--unit` 固定，
/// 不允许调用方指定，避免覆盖别的 systemd 单元。
pub async fn upgrade(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<UpgradeReq>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    if s.role != "owner" {
        return Err(ApiError::new(10003, StatusCode::FORBIDDEN, "仅 owner 可执行升级"));
    }
    if !state.allow_web_upgrade {
        return Err(ApiError::unsupported(
            "Web 升级未开启：在 config.toml 设 [danger] allow_web_upgrade = true 并重启（命令行 sudo panel upgrade 不受限）",
        ));
    }
    if !panel_os::Bin::SystemdRun.available() {
        return Err(ApiError::unsupported("缺少 systemd-run，无法脱离当前进程执行升级"));
    }
    let version = match req.version.as_deref() {
        None => None,
        Some(v) => {
            let v = v.trim();
            if v.is_empty()
                || v.len() > 32
                || v.starts_with('-')
                || !v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            {
                return Err(ApiError::bad_request(
                    "version",
                    "版本号只允许字母/数字/./_/-，长度 1-32 且不能以 - 开头",
                ));
            }
            Some(v.to_string())
        }
    };
    crate::ratelimit::check_heavy(&state, &s.username, "system.upgrade")?;

    let bin = panel_os::paths::panel_bin_install_path();
    if !bin.is_file() {
        return Err(ApiError::unsupported(format!(
            "找不到已安装的二进制 {}（Web 升级只支持标准安装；开发实例请用 CLI）",
            bin.display()
        )));
    }
    let mut args: Vec<String> = vec![
        "--unit=panel-upgrade".into(),
        "--collect".into(),
        "--description=ForkPanel upgrade".into(),
        bin.display().to_string(),
        "upgrade".into(),
    ];
    if let Some(v) = &version {
        args.push("--version".into());
        args.push(v.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = panel_os::cmd::run(
        panel_os::Bin::SystemdRun,
        &refs,
        panel_os::cmd::CmdOpt {
            timeout: std::time::Duration::from_secs(15),
            ..Default::default()
        },
    )
    .await?;
    if out.code != Some(0) {
        let detail: String = out.stderr.trim().chars().take(300).collect();
        return Err(ApiError::new(
            30000,
            StatusCode::BAD_GATEWAY,
            format!("systemd-run 启动失败：{detail}"),
        ));
    }

    let target = version.as_deref().unwrap_or("latest").to_string();
    crate::routes::audit(&state, &s, "system.upgrade", &target, "ok").await;
    Ok((
        StatusCode::ACCEPTED,
        ok(json!({ "accepted": true, "unit": "panel-upgrade", "version": version })),
    ))
}
