//! 系统与监控 handler。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{Auth, Shared},
};
use axum::{extract::{Query, State}, Json};
use serde::Serialize;
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
