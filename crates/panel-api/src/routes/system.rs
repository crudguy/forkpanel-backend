//! 系统与监控 handler。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{Auth, Shared},
};
use axum::{extract::{Query, State}, Json};
use panel_core::cap_keys;
use serde::Serialize;

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
    ok(serde_json::json!({
        "platform": state.os.platform(),
        "features": state.capabilities,
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
    pub tier: &'static str,
    /// 采样是否已被降频（低配保护，UI 需提示）
    pub degraded: bool,
}

/// 一次性快照（仪表盘卡片数据）。
pub async fn overview(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let snap = state.os.metrics().snapshot().await?;
    Ok(ok(OverviewResp {
        ts: snap.ts_unix,
        uptime_sec: snap.uptime_sec,
        cpu_pct: snap.cpu.total_pct,
        mem_used_kib: snap.mem.used_kib,
        mem_total_kib: snap.mem.total_kib,
        load1: snap.cpu.load1,
        disks: snap.disks.len(),
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

#[allow(dead_code)]
fn _cap_keys_used() -> &'static str { cap_keys::METRICS_READ }
