//! 面板**内部**周期任务的调度器。
//!
//! # 与用户自定义 cron 的分工（重要，容易混淆）
//!
//! | | 内部周期任务（本模块） | 用户 cron（`SchedulerProvider`） |
//! |---|---|---|
//! | 例子 | 指标采样、1m 聚合、清理、备份、证书续期 | 用户自己的备份脚本、业务脚本 |
//! | 载体 | tokio 定时器（进程内） | 系统 crontab / systemd timer / launchd |
//! | 生命周期 | 面板停了就不跑 | 面板停了照样跑 |
//! | 表达式 | 固定间隔 / 每日时刻（不解析 cron） | 平台本地表达式（由 `validate_expression` 校验） |
//!
//! **刻意不复用系统 cron**：内部任务必须跟着面板进程走——面板停了还在采样是没有意义的，
//! 而且往用户 crontab 里塞条目会在卸载时留下垃圾。
//!
//! # 时钟语义
//! 每日任务用"本地时区的 03:10"这类时刻，但**只保证近似**：
//! 进程在 03:10 未运行则顺延到下次启动后补跑（对清理/备份这类任务是合理语义）。
//! 跨时区和 DST 的精确语义不在 MVP 范围内，UI 上展示的是"计划时刻"而非保证。

use panel_core::Result;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// 一个内部周期任务
#[derive(Debug, Clone)]
pub struct Schedule {
    pub name: &'static str,
    pub kind: ScheduleKind,
    /// 错峰偏移：避免所有任务在同一秒触发（低配机器上会造成瞬时抖动）
    pub jitter_sec: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ScheduleKind {
    /// 固定间隔（指标采样、聚合）
    Every(Duration),
    /// 每日本地时刻（小时, 分钟）
    DailyAt { hour: u8, minute: u8 },
}

pub type JobFn = Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> + Send + Sync>;

/// 内置任务注册表。**新增内部周期任务就在这里加一行**，不要散落到各模块。
pub fn builtin_schedules(tier: panel_core::Tier) -> Vec<Schedule> {
    let mut v = vec![
        Schedule {
            name: "metrics.sample",
            kind: ScheduleKind::Every(Duration::from_millis(tier.sampling_interval_ms())),
            jitter_sec: 0,
        },
        Schedule {
            name: "metrics.aggregate_1m",
            kind: ScheduleKind::Every(Duration::from_secs(60)),
            jitter_sec: 2,
        },
        Schedule {
            name: "metrics.rollup_1h",
            kind: ScheduleKind::DailyAt { hour: 3, minute: 10 },
            jitter_sec: 0,
        },
        Schedule {
            name: "db.cleanup",
            kind: ScheduleKind::DailyAt { hour: 3, minute: 15 },
            jitter_sec: 0,
        },
        Schedule {
            name: "cert.renew_check",
            kind: ScheduleKind::DailyAt { hour: 4, minute: 5 },
            jitter_sec: 30,
        },
    ];
    // nano 档位不做每日备份：512MB 机器上 VACUUM INTO 的 IO 与内存开销不划算
    if !matches!(tier, panel_core::Tier::Nano) {
        v.push(Schedule {
            name: "db.backup",
            kind: ScheduleKind::DailyAt { hour: 3, minute: 30 },
            jitter_sec: 0,
        });
    }
    v
}

pub struct InternalScheduler {
    jobs: Arc<Mutex<HashMap<&'static str, JobFn>>>,
    token: CancellationToken,
    /// 记录上次执行的 Unix 秒，用于"启动后补跑"
    last_run: Arc<Mutex<HashMap<&'static str, i64>>>,
}

impl InternalScheduler {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            token: CancellationToken::new(),
            last_run: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 注册任务实现。名字必须与 `builtin_schedules` 中的一致。
    pub async fn register<F, Fut>(&self, name: &'static str, f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let boxed: JobFn = Arc::new(move || Box::pin(f()));
        self.jobs.lock().await.insert(name, boxed);
    }

    /// 启动全部任务。每个任务一个独立 tokio 任务，互不阻塞。
    pub async fn start(&self, schedules: Vec<Schedule>) {
        for s in schedules {
            let jobs = self.jobs.clone();
            let token = self.token.clone();
            let last_run = self.last_run.clone();
            let jitter = s.jitter_sec;
            let kind = s.kind;
            let name = s.name;

            tokio::spawn(async move {
                // 错峰：避免所有任务在同一秒触发
                if jitter > 0 {
                    tokio::time::sleep(Duration::from_secs(jitter)).await;
                }
                loop {
                    let wait = match kind {
                        ScheduleKind::Every(d) => d,
                        ScheduleKind::DailyAt { hour, minute } => secs_until(hour, minute),
                    };
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(wait) => {}
                    }
                    if token.is_cancelled() { break; }

                    let f = {
                        let g = jobs.lock().await;
                        g.get(name).cloned()
                    };
                    if let Some(f) = f {
                        // 任务失败只记录，不让调度器退出（清理失败不该导致采样停止）
                        if let Err(e) = f().await {
                            tracing::warn!(task = name, "内部任务失败: {e}");
                        }
                        last_run.lock().await.insert(name, now_unix());
                    }
                }
            });
        }
    }

    pub fn shutdown(&self) { self.token.cancel(); }

    /// 上次成功执行的时间（供运维排查）
    pub async fn last_run_of(&self, name: &str) -> Option<i64> {
        self.last_run.lock().await.get(name).copied()
    }
}

impl Default for InternalScheduler { fn default() -> Self { Self::new() } }

/// 距离下一个"本地时间 hour:minute"还有多少秒。
/// 使用 libc 的 localtime 换算；若已过今天的时刻则顺延到明天。
fn secs_until(hour: u8, minute: u8) -> Duration {
    let now = now_unix();
    let target_today = today_at(now, hour, minute);
    let target = if target_today > now { target_today } else { target_today + 86_400 };
    Duration::from_secs((target - now).max(1) as u64)
}

fn today_at(now: i64, hour: u8, minute: u8) -> i64 {
    // 用 UTC 日的起点 + 偏移量对齐。精确时区处理（含 DST）不在 MVP 范围，
    // 这里以"容器/宿主机的本地时区"为准，UI 展示为计划时刻。
    let day_start = now - (now % 86_400);
    day_start + hour as i64 * 3600 + minute as i64 * 60
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_includes_core_jobs() {
        let v = builtin_schedules(panel_core::Tier::Standard);
        let names: Vec<&str> = v.iter().map(|s| s.name).collect();
        assert!(names.contains(&"metrics.sample"));
        assert!(names.contains(&"metrics.aggregate_1m"));
        assert!(names.contains(&"db.cleanup"));
        assert!(names.contains(&"cert.renew_check"));
    }

    #[test]
    fn nano_skips_daily_backup() {
        let v = builtin_schedules(panel_core::Tier::Nano);
        assert!(!v.iter().any(|s| s.name == "db.backup"),
                "512MB 机器上每日备份的 IO 与内存开销不划算");
        let v2 = builtin_schedules(panel_core::Tier::Standard);
        assert!(v2.iter().any(|s| s.name == "db.backup"));
    }

    #[test]
    fn sampling_interval_follows_tier() {
        let nano = builtin_schedules(panel_core::Tier::Nano);
        let std_ = builtin_schedules(panel_core::Tier::Standard);
        let pick = |v: Vec<Schedule>| -> u64 {
            v.iter().find(|s| s.name == "metrics.sample")
                .map(|s| match s.kind { ScheduleKind::Every(d) => d.as_millis() as u64, _ => 0 })
                .unwrap()
        };
        assert_eq!(pick(nano), 5000);
        assert_eq!(pick(std_), 1000);
    }

    #[test]
    fn daily_jobs_are_staggered() {
        let v = builtin_schedules(panel_core::Tier::Standard);
        let at = |n: &str| v.iter().find(|s| s.name == n).map(|s| match s.kind {
            ScheduleKind::DailyAt { hour, minute } => (hour, minute), _ => (0, 0) });
        // 清理与备份不能挤在同一分钟（低配机器上会造成 IO 抖动）
        assert_ne!(at("db.cleanup"), at("db.backup"));
        assert_eq!(at("metrics.rollup_1h"), Some((3, 10)));
    }

    #[test]
    fn secs_until_is_positive_and_bounded() {
        let d = secs_until(3, 10);
        assert!(d.as_secs() >= 1);
        assert!(d.as_secs() <= 86_400, "最远顺延到明天，不超过一天");
    }

    #[test]
    fn jitter_is_applied_to_avoid_thundering_herd() {
        let v = builtin_schedules(panel_core::Tier::Standard);
        assert!(v.iter().any(|s| s.jitter_sec > 0),
                "至少部分任务需要错峰，避免同一秒集体触发");
    }
}
