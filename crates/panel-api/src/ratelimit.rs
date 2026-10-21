//! 通用动作限流（登录之外的重活）。
//!
//! ## 为什么需要它
//! 登录防暴力已有 `auth::LoginGuard`（失败计数 + 递增退避 + 15 分钟锁定），但
//! **其他端点一个都没有**。安装软件包、拉镜像、跑备份、跑定时任务这类操作：
//! - 成本高（下载 / 编译 / 全量复制 / 长时间持锁）；
//! - 单机面板尤其怕并发写 SQLite；
//! - 一个泄露的会话或脚本化误操作就能把宿主压满。
//!
//! 这不是"没做安全"，而是"假设操作者永远理性"——对 root 权限的面板不合适。
//!
//! ## 与 LoginGuard 的刻意差异
//! | | LoginGuard | ActionLimiter |
//! |---|---|---|
//! | 计数对象 | **失败**次数 | **每次**调用（成功也计） |
//! | 被自身拦下的请求 | 也计数（防"卡在下界"的软限速，见 P2-11） | **不计数** |
//! | 超限后果 | 阶梯退避 → 锁定 15 分钟 | 只回 429 + retry_after |
//!
//! 被拒的请求不计数是有意的：这里的调用方是**已认证用户**，不是猜口令的攻击者。
//! 若拒绝也计数，用户连点两下就会把自己越锁越久（LoginGuard 那套是为对抗
//! 无限次口令尝试才必须的）。
//!
//! ## 为什么 key 是 (user, action)
//! 面板可能多用户。按用户分桶才不会让 A 的批量安装把 B 的操作挤掉；按动作分桶
//! 才不会"拉了一个镜像就把备份额度用掉"。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 每个 (user, action) 在窗口内允许的次数。
///
/// 定这个值的依据：正常人一分钟内连点安装/拉取/备份不会超过 10 次（连点两下、
/// 批量选 3~5 个包都远低于此）；而脚本化空转/误连打会被立刻按住。
const LIMIT: usize = 10;
const WINDOW: Duration = Duration::from_secs(60);

/// key 数硬上限（同 LoginGuard 的 `MAX_KEYS` 思路）：防止被构造出无限多 key。
/// 真实场景 = 用户数 × 动作数，10k 足够。
const MAX_KEYS: usize = 10_000;

pub struct ActionLimiter {
    /// key = `"{user}\u{1f}{action}"`
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
    limit: usize,
    window: Duration,
}

impl ActionLimiter {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self { hits: Mutex::new(HashMap::new()), limit, window }
    }

    /// 默认档位（10 次 / 60 秒）
    pub fn heavy() -> Self {
        Self::new(LIMIT, WINDOW)
    }

    /// 放行返回 `Ok(())` 并记账；超限返回 `Err(retry_after_secs)`（**不记账**）。
    ///
    /// `now` 参数只为可测：单测注入受控时间，生产调用传 `Instant::now()`。
    pub fn check_at(&self, user: &str, action: &str, now: Instant) -> Result<(), u64> {
        let key = format!("{user}\u{1f}{action}");
        let mut map = panel_core::sync::lock_recover(&self.hits);

        // 顺手清掉本 key 里过期的记录（滑窗）
        if let Some(q) = map.get_mut(&key) {
            while let Some(front) = q.front() {
                if now.duration_since(*front) >= self.window {
                    q.pop_front();
                } else {
                    break;
                }
            }
        }

        let len = map.get(&key).map(|q| q.len()).unwrap_or(0);
        if len >= self.limit {
            // 最早一条滑出窗口还要多久
            let oldest = map.get(&key).and_then(|q| q.front().copied());
            let wait = oldest
                .map(|t| self.window.saturating_sub(now.duration_since(t)).as_secs().max(1))
                .unwrap_or(1);
            return Err(wait);
        }

        // 容量保护：只有在插入新 key 时才需要检查（避免无限增长）
        if len == 0 && map.len() >= MAX_KEYS {
            // 满了：先做一次粗清理（丢空队列），仍满则不再接受新 key（宁可误拒）
            map.retain(|_, q| !q.is_empty());
            if map.len() >= MAX_KEYS {
                return Err(1);
            }
        }
        map.entry(key).or_default().push_back(now);
        Ok(())
    }

    pub fn check(&self, user: &str, action: &str) -> Result<(), u64> {
        self.check_at(user, action, Instant::now())
    }
}

impl Default for ActionLimiter {
    fn default() -> Self {
        Self::heavy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let l = ActionLimiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        for i in 0..3 {
            assert!(l.check_at("alice", "pkg.install", at(t0, i)).is_ok(), "第 {i} 次应放行");
        }
        let err = l.check_at("alice", "pkg.install", at(t0, 3)).unwrap_err();
        assert!(err >= 1 && err <= 60, "retry_after 应落在窗口内，实际 {err}");
    }

    #[test]
    fn window_slides() {
        let l = ActionLimiter::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(l.check_at("a", "pull", at(t0, 0)).is_ok());
        assert!(l.check_at("a", "pull", at(t0, 1)).is_ok());
        assert!(l.check_at("a", "pull", at(t0, 2)).is_err());
        // 窗口滑过第一条后，可以再进一条
        assert!(l.check_at("a", "pull", at(t0, 61)).is_ok());
    }

    #[test]
    fn rejected_calls_do_not_count() {
        // 这是与 LoginGuard 的关键差异：被拒不该把用户越锁越久
        let l = ActionLimiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(l.check_at("a", "x", at(t0, 0)).is_ok());
        for i in 1..=20 {
            assert!(l.check_at("a", "x", at(t0, i)).is_err());
        }
        // 满窗口后应恢复（若被拒也计数，这里会继续被拒）
        assert!(l.check_at("a", "x", at(t0, 61)).is_ok(), "被拒的调用不得累加计数");
    }

    /// ⭐⭐ **接线守卫**：handler 里那一行删掉，**没有任何行为测试会变红**
    /// （限流只是少了一层保护，功能照常工作）——这正是项目里「守卫自持实现」
    /// 教训的同类：只能源码级断言。写法参照 auth.rs 的 LoginGuard 接线守卫。
    #[test]
    fn heavy_handlers_are_actually_wired() {
        let cases: [(&str, &str, &str); 6] = [
            (include_str!("routes/services.rs"), "pkg.install", "services::install"),
            (include_str!("routes/services.rs"), "pkg.upgrade", "services::package_upgrade"),
            (include_str!("routes/services.rs"), "pkg.remove", "services::package_remove"),
            (include_str!("routes/containers.rs"), "image.pull", "containers::pull"),
            (include_str!("routes/backups.rs"), "backup.run", "backups::run"),
            (include_str!("routes/cron.rs"), "cron.run", "cron::run"),
        ];
        for (src, action, who) in cases {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let needle = format!("check_heavy(&state, &s.username, \"{action}\")");
            assert!(
                code.contains(&needle),
                "{who} 缺少限流接线（应当有 `{needle}?;`）。删掉它不会让任何行为测试变红，\
                 所以这条断言是唯一防线。"
            );
        }
    }

    #[test]
    fn users_and_actions_are_isolated() {
        let l = ActionLimiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(l.check_at("alice", "pull", at(t0, 0)).is_ok());
        assert!(l.check_at("alice", "pull", at(t0, 1)).is_err());
        // 换个用户同一动作：不受影响
        assert!(l.check_at("bob", "pull", at(t0, 1)).is_ok());
        // 同一用户换个动作：不受影响
        assert!(l.check_at("alice", "backup", at(t0, 1)).is_ok());
    }
}

/// handler 里的一行式入口：超限转成 429（`retry_after` 秒），并带上动作名便于排障。
///
/// 用法（放在权限校验之后、真正干活之前）：
/// ```ignore
/// crate::ratelimit::check_heavy(&state, &s.username, "pkg.install")?;
/// ```
pub fn check_heavy(state: &crate::routes::Shared, user: &str, action: &str) -> crate::error::ApiResult<()> {
    state.limits.check(user, action).map_err(|wait| {
        crate::error::ApiError::too_many_requests(wait)
    })
}
