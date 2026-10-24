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
        Schedule {
            name: "waf.collect",
            kind: ScheduleKind::Every(Duration::from_secs(60)),
            jitter_sec: 10,
        },
        // 分片上传残包清理（P2-1）。TTL 24h，1h 扫一次有 24 倍冗余——扫频再高只是
        // 白扫目录，再低则残包多留一会儿。此前它只在 `init` 开新上传时顺手做，
        // 没人上传就永不清理。
        Schedule {
            name: "uploads.sweep",
            kind: ScheduleKind::Every(Duration::from_secs(3600)),
            jitter_sec: 120,
        },
        // 备份计划的 cron 扫描。**每分钟一次**：备份粒度最细到分钟，
        // 扫得更勤只是空转（一次查询只读两列），更懒则会让"3:00 的备份"
        // 拖到 3:05。真正的到期判断在 `backups::plan_sweep`（按表达式算触发点）。
        Schedule {
            name: "backup.sweep",
            kind: ScheduleKind::Every(Duration::from_secs(60)),
            jitter_sec: 20,
        },
        // 会话过期回收（P1-9）：sessions 内存 map 与 sessions 表此前单调增长——
        // `SessionCache::sweep()` 已实现却从未被调用。挂上唯一消费者：每 5 分钟
        // 清理一次过期会话（按 expires_at 判，与登录/访问续期口径一致）。
        Schedule {
            name: "session.sweep",
            kind: ScheduleKind::Every(Duration::from_secs(300)),
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
                        // 任务失败只记录，不让调度器退出（清理失败不该导致采样停止）；
                        // 同时用超时包裹，避免任一 job 挂住导致该 schedule 永久停摆（P1-10）。
                        if let Err(e) = run_job_with_timeout(name, &f, INTERNAL_JOB_TIMEOUT).await {
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

/// 内部任务单次执行的最长时限（P1-10）。任一 job 卡住（不返回、不报错）原本会让该
/// schedule 永久停摆——定时备份/清理从此不再执行，界面与 stderr 都看不出异常。
/// 超时即中断该次执行并记录 error，调度循环继续，下一周期再试。
/// 10 分钟对指标采样/清理/扫描绰绰有余；对耗时的每日备份（VACUUM INTO）也是合理上限，
/// 真卡住时能在可接受窗口内释放，而不是永远挂着。
const INTERNAL_JOB_TIMEOUT: Duration = Duration::from_secs(600);

/// 带超时的单次任务执行（P1-10 核心）。返回 job 自身的结果；超时则返回错误。
async fn run_job_with_timeout(name: &str, f: &JobFn, timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, f()).await {
        Ok(r) => r,
        Err(_) => {
            tracing::error!(
                task = name,
                timeout_secs = timeout.as_secs(),
                "内部任务超时（可能被挂住），已中断并继续调度"
            );
            Err(panel_core::PanelError::Internal(format!("internal job {name} timed out")))
        }
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
    // 以**本地时区**的今天 00:00 为基准，而不是 UTC 日的起点。
    // 此前 `now - (now % 86_400)` 算的是 UTC 日 00:00：东八区下 UI 上写的
    // 「03:10 执行」会到本地 11:10 才触发，与展示时刻整整差一个时区。
    // 偏移换算复用 panel-os 里已有的 libc localtime_r 实现，不另引依赖。
    let off = panel_os::local_utc_offset_secs_at(now);
    let local = now + off;                 // 本地时刻（纪元秒口径）
    let day_start = (local - local % 86_400) - off;  // 本地 00:00 对应的 UTC 纪元秒
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
    fn today_at_is_local_time_not_utc() {
        // 钉死「每日任务是本地时间语义」：把结果换算回本地时刻，必须正好等于请求的
        // 时:分。此前按 UTC 日起点计算，东八区会把 UI 上的 03:10 推到 11:10 才触发。
        // 用"换算回本地再比对"而不是写死绝对时刻，测试就不依赖运行机器的时区。
        let now = 1_700_000_000i64;
        let off = panel_os::local_utc_offset_secs_at(now);
        let t = today_at(now, 3, 10);
        assert_eq!((t + off).rem_euclid(86_400), 3 * 3600 + 10 * 60);
    }

    #[test]
    fn builtin_includes_core_jobs() {
        let v = builtin_schedules(panel_core::Tier::Standard);
        let names: Vec<&str> = v.iter().map(|s| s.name).collect();
        assert!(names.contains(&"metrics.sample"));
        assert!(names.contains(&"metrics.aggregate_1m"));
        assert!(names.contains(&"db.cleanup"));
        assert!(names.contains(&"cert.renew_check"));
        assert!(names.contains(&"uploads.sweep"),
            "分片残包清理必须挂在内置调度上，否则闲置面板永不回收（P2-1）");
    }

    /// 残包清理的周期必须明显短于会话 TTL（24h）——否则等于没扫。
    #[test]
    fn uploads_sweep_runs_well_within_session_ttl() {
        let v = builtin_schedules(panel_core::Tier::Standard);
        let d = v.iter().find(|s| s.name == "uploads.sweep")
            .map(|s| match s.kind { ScheduleKind::Every(d) => d.as_secs(), _ => 0 })
            .unwrap_or(0);
        assert!(d > 0 && d <= 6 * 3600,
            "uploads.sweep 周期应 <= 6h（会话 TTL 24h），实际 {d}s");
    }

    /// 备份计划的 cron 扫描必须挂在内置调度上：否则 `cron_expr` / `enabled`
    /// 又回到"只存不读"——页面上配了定时，实际永远不跑。
    #[test]
    fn builtin_includes_backup_cron_sweep() {
        let v = builtin_schedules(panel_core::Tier::Standard);
        let d = v
            .iter()
            .find(|s| s.name == "backup.sweep")
            .map(|s| match s.kind {
                ScheduleKind::Every(d) => d.as_secs(),
                _ => 0,
            })
            .unwrap_or(0);
        assert!(d > 0 && d <= 60, "backup.sweep 应每分钟扫一次，实际 {d}s");
        // 所有档位都要有：备份与内存大小无关（nano 只是跳过每日库备份）
        assert!(builtin_schedules(panel_core::Tier::Nano)
            .iter().any(|s| s.name == "backup.sweep"));
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

    /// 会话过期回收必须挂在内置调度上：否则 `SessionCache::sweep()` 已实现却永不被调用，
    /// 会话内存 map 与 sessions 表单调增长（P1-9）。
    #[test]
    fn session_sweep_is_in_builtin() {
        let v = builtin_schedules(panel_core::Tier::Standard);
        assert!(v.iter().any(|s| s.name == "session.sweep"),
            "session.sweep 必须在 builtin_schedules 中声明");
        let d = v.iter().find(|s| s.name == "session.sweep")
            .map(|s| match s.kind { ScheduleKind::Every(d) => d.as_secs(), _ => 0 })
            .unwrap_or(0);
        assert!(d > 0 && d <= 600, "session.sweep 周期应 <= 10min，实际 {d}s");
        // 所有档位都要有（会话回收与内存大小无关）
        assert!(builtin_schedules(panel_core::Tier::Nano)
            .iter().any(|s| s.name == "session.sweep"));
    }

    /// 超时包裹必须真的中断挂住的 job（P1-10 核心）。用极短超时验证分支。
    #[tokio::test]
    async fn run_job_times_out_hung_future() {
        let f: JobFn =
            std::sync::Arc::new(|| Box::pin(std::future::pending::<panel_core::Result<()>>()));
        let r = run_job_with_timeout("hung", &f, Duration::from_millis(1)).await;
        assert!(r.is_err(), "挂住的 job 必须被超时中断（不能永久停摆）");
    }

    #[tokio::test]
    async fn run_job_runs_fast_future_ok() {
        let f: JobFn = std::sync::Arc::new(|| Box::pin(async { Ok(()) }));
        let r = run_job_with_timeout("ok", &f, Duration::from_secs(10)).await;
        assert!(r.is_ok(), "正常完成的 job 不应被超时");
    }
}
