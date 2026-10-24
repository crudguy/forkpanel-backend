//! WAF 拦截告警（028）。
//!
//! 配合 027 的 block_events：采集后按「近 `window_min` 分钟内每站拦截数 > `threshold`」
//! 推送一条站内通知（`notifications` 表，source=security）。配置为**单例**（id 恒 1）——
//! 告警是全局一处策略，不为每站各配一套。
//!
//! 去重：**冷却制为主**——该站近 `window_min` 分钟内已报过则跳过（查 notifications 表，
//! 无需新表），保证每站每窗至多一条；`dedup_key` 时间桶作二级兜底（INSERT OR IGNORE）。
//! 滑动计数窗跨固定桶边界时不会重复报（纯时间桶会）。
//!
//! `check_block_alerts` **永不中断采集**：读配置/计数失败即跳过，通知失败由 push 内部吞掉。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{extract::State, Json};
use panel_core::PanelError;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use crate::extract::PanelJson;

const THRESHOLD_DEFAULT: i64 = 50;
const WINDOW_DEFAULT: i64 = 5;
const THRESHOLD_MAX: i64 = 100_000;
const WINDOW_MAX: i64 = 1440; // 24h

/// 告警级别：命中达 3× 阈值升 crit，否则 warn。
fn alert_level(count: i64, threshold: i64) -> &'static str {
    if count >= threshold.saturating_mul(3) {
        "crit"
    } else {
        "warn"
    }
}

/// 读配置（enabled, threshold, window_min）；无行（理论上迁移已种）回落默认。
async fn load_cfg(state: &Shared) -> Result<(i64, i64, i64), PanelError> {
    state
        .pool
        .with(|conn| {
            conn.query_row(
                "SELECT enabled, threshold, window_min FROM waf_alert_cfg WHERE id = 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            )
            .optional()
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
        .map(|opt| opt.unwrap_or((1, THRESHOLD_DEFAULT, WINDOW_DEFAULT)))
}

/// 读告警配置（读需 `site.view`）。
pub async fn get_alert(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let (enabled, threshold, window_min) = load_cfg(&state).await?;
    Ok(ok(serde_json::json!({
        "enabled": enabled != 0,
        "threshold": threshold,
        "window_min": window_min,
    })))
}

#[derive(Debug, Deserialize)]
pub struct AlertCfgReq {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub threshold: Option<i64>,
    #[serde(default)]
    pub window_min: Option<i64>,
}

/// 更新告警配置（写需 `site.manage`；缺省字段保留现值）。阈值/窗宽越界 → 400。
pub async fn put_alert(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<AlertCfgReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let cur = load_cfg(&state).await?;
    let enabled = req.enabled.unwrap_or(cur.0 != 0);
    let threshold = req.threshold.unwrap_or(cur.1);
    let window_min = req.window_min.unwrap_or(cur.2);
    if !(1..=THRESHOLD_MAX).contains(&threshold) {
        return Err(ApiError::bad_request("threshold", format!("阈值需在 1 ~ {THRESHOLD_MAX} 之间")));
    }
    if !(1..=WINDOW_MAX).contains(&window_min) {
        return Err(ApiError::bad_request("window_min", format!("时间窗需在 1 ~ {WINDOW_MAX} 分钟之间")));
    }
    let now = crate::now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO waf_alert_cfg(id, enabled, threshold, window_min, updated_at) VALUES(1, ?1, ?2, ?3, ?4) \
                 ON CONFLICT(id) DO UPDATE SET enabled = ?1, threshold = ?2, window_min = ?3, updated_at = ?4",
                rusqlite::params![enabled as i64, threshold, window_min, now],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "waf_alert.update", "self", "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 阈值检查：由采集任务（`waf.collect`）在采集后调用。近窗内每站拦截数超阈值即推一条通知。
///
/// **永不中断采集**：配置读取/计数失败只记日志后跳过，不向上传播（告警是旁路，
/// 不该让采集中断）。⚠ 但"不中断"不等于"不吭声"——失败原因必须落到日志，
/// 否则告警长期不响而无人知晓（曾只有计数分支打日志、配置分支静默 return）。
pub async fn check_block_alerts(state: &Shared) {
    let (enabled, threshold, window_min) = match load_cfg(state).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[panel] 告警检查读取配置失败：{e}");
            return;
        }
    };
    if enabled == 0 || threshold < 1 || window_min < 1 {
        return;
    }
    let now = crate::now_unix();
    let since = now - window_min * 60;
    let counts: Vec<(String, i64)> = match state
        .pool
        .with(move |conn| {
            let mut stmt = conn
                .prepare("SELECT site, COUNT(*) FROM block_events WHERE ts >= ?1 GROUP BY site")
                .map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .map_err(|e| PanelError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[panel] 告警检查读取失败：{e}");
            return;
        }
    };

    let bucket = now / (window_min * 60);
    let cooldown_since = now - window_min * 60;
    for (site, count) in counts {
        if count <= threshold {
            continue;
        }
        let title = format!("WAF 拦截告警：{site}");
        // 冷却：该站近 window 内已报过则跳过。比固定时间桶更稳——滑动的计数窗跨桶边界时
        // （同一批事件在相邻两个 5min 点都 > 阈值）不会重复报；时间桶 dedup_key 保留作二级兜底。
        let recent: bool = {
            let t = title.clone();
            state
                .pool
                .with(move |conn| {
                    conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM notifications WHERE source = 'security' AND title = ?1 AND ts >= ?2)",
                        rusqlite::params![t, cooldown_since],
                        |r| r.get(0),
                    )
                    .map_err(|e| PanelError::Database(e.to_string()))
                })
                .await
                .unwrap_or_default()
        };
        if recent {
            continue;
        }
        let level = alert_level(count, threshold);
        let body = format!("近 {window_min} 分钟 {count} 次拦截（阈值 {threshold}）");
        crate::routes::notifications::push(
            &state.db,
            crate::routes::notifications::NewNotification {
                level,
                source: "security",
                title,
                body: Some(body),
                dedup_key: Some(format!("waf_alert:{site}:{bucket}")),
            },
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐⭐ 接线守卫：`check_block_alerts` 是**旁路**（失败不能中断采集），所以它的
    /// 失败根本不会冒泡到响应里——删掉那行 eprintln 之后，行为测试全绿、界面无感，
    /// 只有"告警该响的时候不响"这一个用户可见后果，且无人知晓。只能源码级钉住。
    /// 判据取**生产段**（剔注释 + 剥本测试模块）：守卫自身的 needle 就在测试段里。
    #[test]
    fn alert_check_never_swallows_errors_silently() {
        let prod = crate::test_support::production_source(include_str!("waf_alert.rs"));
        // ① 禁止 `Err(_)` 这类把原因丢掉的 catch-all（想忽略就写明原因并记日志）
        assert!(
            !prod.contains("Err(_)"),
            "告警检查不得用 Err(_) 吞掉错误原因：旁路失败不冒泡，静默 = 告警长期不响而无人知晓"
        );
        // ② 两处错误出口都必须打日志（按函数名定位到本函数体，避免全文件误命中）
        let body_at = prod
            .find("pub async fn check_block_alerts")
            .expect("check_block_alerts 必须存在");
        let body = &prod[body_at..];
        for (needle, what) in [
            ("告警检查读取配置失败", "读配置失败"),
            ("告警检查读取失败", "读拦截计数失败"),
        ] {
            assert!(
                body.contains(needle),
                "check_block_alerts 的{what}分支必须记日志（当前静默 return）：缺 {needle}"
            );
        }
    }

    #[test]
    fn alert_level_escalates_at_triple() {
        // 达 3× 阈值升 crit，之间 warn，等于阈值 warn
        assert_eq!(alert_level(50, 50), "warn");
        assert_eq!(alert_level(149, 50), "warn");
        assert_eq!(alert_level(150, 50), "crit"); // 3×
        assert_eq!(alert_level(500, 50), "crit");
    }

    #[test]
    fn cfg_bounds() {
        // 阈值/窗宽边界（与 put_alert 的校验同口径）
        assert!((1..=THRESHOLD_MAX).contains(&1));
        assert!((1..=THRESHOLD_MAX).contains(&THRESHOLD_MAX));
        assert!(!(1..=THRESHOLD_MAX).contains(&0));
        assert!(!(1..=THRESHOLD_MAX).contains(&(THRESHOLD_MAX + 1)));
        assert!((1..=WINDOW_MAX).contains(&1));
        assert!(!(1..=WINDOW_MAX).contains(&0));
        assert!(!(1..=WINDOW_MAX).contains(&(WINDOW_MAX + 1)));
    }

    #[test]
    fn dedup_bucket_is_window_scoped() {
        // 同一窗内 bucket 相同（去重），跨窗不同（再报）。t0 取窗宽整数倍以对齐边界。
        let window = 5i64;
        let t0 = window * 60 * 6; // 对齐到窗边界
        let in_window = t0 + window * 60 - 1;
        let next_window = t0 + window * 60;
        assert_eq!(t0 / (window * 60), in_window / (window * 60), "同窗同 bucket");
        assert_ne!(t0 / (window * 60), next_window / (window * 60), "跨窗不同 bucket");
    }
}
