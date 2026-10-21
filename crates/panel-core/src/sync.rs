//! 互斥锁的**中毒恢复**入口。
//!
//! ## 为什么需要它
//! `std::sync::Mutex::lock()` 在持锁线程 panic 后会返回 `Err(PoisonError)`。
//! 若调用方一律 `.unwrap()`，一次 panic 会让**此后每一次**持锁请求继续 panic——
//! 对长驻的面板进程来说，等于"一个 handler 的边界 bug 演变成整个功能永久 500，
//! 直到重启进程"。而这类 bug 恰恰最不该被放大。
//!
//! ## 为什么可以安全地恢复
//! 本项目里这些锁保护的都是**可重建的运行时状态**：流式输出缓冲（日志/进度）、
//! mock 适配器状态、"已 ensure 过的源"缓存集合。它们不是需要严格不变式的账本，
//! 中毒后继续用最坏是丢一小段缓冲，远比让面板永久 500 好。
//!
//! ⚠ 反例（不要滥用）：若将来有用 Mutex 保护**必须始终自洽**的数据（如余额、
//! 状态机推进），中毒意味着不变量可能已破坏，那时应当返回 500 并要求重启，
//! 而不是恢复。**恢复的前提是"坏了也能重建"**。
//!
//! ## 守卫
//! `ci/check_lock_unwrap.py`（已接 `make guards`）禁止生产代码里出现
//! `lock().unwrap()` —— 新增的锁一律走这里。

/// 取锁；遇到中毒（曾有持锁线程 panic）时恢复内部值继续用。
///
/// 用法与 `lock().unwrap()` 一致，返回的 guard 可直接 `Deref`/`DerefMut`：
/// ```ignore
/// let mut buf = panel_core::sync::lock_recover(&buf);
/// ```
pub fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_after_poison() {
        let m = std::sync::Arc::new(std::sync::Mutex::new(7));
        let m2 = m.clone();
        // 让另一个线程持锁时 panic，制造中毒
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("poison it");
        })
        .join();
        assert!(m.lock().is_err(), "前提：此时锁应处于中毒状态");
        // 未恢复的调用会 panic；lock_recover 必须能拿到值
        assert_eq!(*lock_recover(&m), 7);
    }

    #[test]
    fn works_on_healthy_lock() {
        let m = std::sync::Mutex::new(String::from("ok"));
        assert_eq!(lock_recover(&m).as_str(), "ok");
    }
}
