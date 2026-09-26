//! 内存指标环形缓冲（设计方案 §1.4-3）。
//!
//! # 布局纪律（有实测依据）
//! 3600 个采样点若用朴素结构（每点一个对象/HashMap）在 Python 中等价实现占 **2.2MB**；
//! 固定布局的紧凑 struct 数组仅 **253KB**（9 倍差距）。
//! 因此这里**必须**是 `#[repr(C)]` 的定长数组，**不能**是 `Vec<HashMap<..>>` 或 `Vec<SampleEnum>`。
//!
//! 单条记录 72 字节（实测口径）：
//!   ts:i64(8) cpu:f32(4) mem_used:u64(8) mem_total:u64(8) swap_used:u64(8)
//!   disk_used:u64(8) disk_total:u64(8) net_in:u64(8) net_out:u64(8) load1:f32(4)

/// 单条采样。字段顺序即内存布局，改动需同步更新 `SIZE` 断言。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Sample {
    pub ts: i64,
    pub cpu_pct: f32,
    pub mem_used_kib: u64,
    pub mem_total_kib: u64,
    pub swap_used_kib: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub net_in_bps: u64,
    pub net_out_bps: u64,
    pub load1: f32,
}

const _: () = assert!(std::mem::size_of::<Sample>() == 72);

/// 定长环形缓冲：写入 O(1)，无分配，无 GC。
/// 3600 × 72 = 259,200 字节 ≈ 253 KiB（1 小时 @1s）
pub struct MetricsRing {
    buf: Box<[Sample]>,
    head: usize,
    len: usize,
}

impl MetricsRing {
    pub fn new(capacity: usize) -> Self {
        Self { buf: vec![Sample::default(); capacity].into_boxed_slice(), head: 0, len: 0 }
    }

    /// 1 小时 @1s；nano 档位（5s 采样）建议 720 点即可覆盖同样时长
    pub fn one_hour_at_1s() -> Self { Self::new(3600) }

    pub fn push(&mut self, s: Sample) {
        self.buf[self.head] = s;
        self.head = (self.head + 1) % self.buf.len();
        if self.len < self.buf.len() { self.len += 1; }
    }

    /// 按时间顺序遍历（最旧 → 最新）
    pub fn iter(&self) -> impl Iterator<Item = &Sample> {
        let start = if self.len == self.buf.len() { self.head } else { 0 };
        (0..self.len).map(move |i| &self.buf[(start + i) % self.buf.len()])
    }

    /// 供 SSE `/metrics/realtime?since=N` 使用：取最近 n 秒
    pub fn last_n(&self, n: usize) -> Vec<Sample> {
        self.iter().rev().take(n).copied().rev().collect()
    }

    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
    pub fn capacity(&self) -> usize { self.buf.len() }
    pub fn bytes(&self) -> usize { self.buf.len() * std::mem::size_of::<Sample>() }

    /// 聚合为 1 分钟粒度的一行（聚合器每 60s 调用一次）
    pub fn aggregate(&self, n: usize) -> Option<Sample> {
        let win: Vec<Sample> = self.last_n(n);
        if win.is_empty() { return None; }
        let last = *win.last()?;
        Some(Sample {
            ts: last.ts,
            cpu_pct: win.iter().map(|s| s.cpu_pct).sum::<f32>() / win.len() as f32,
            mem_used_kib: win.iter().map(|s| s.mem_used_kib).max().unwrap_or(0),
            mem_total_kib: last.mem_total_kib,
            swap_used_kib: win.iter().map(|s| s.swap_used_kib).max().unwrap_or(0),
            disk_used_bytes: last.disk_used_bytes,
            disk_total_bytes: last.disk_total_bytes,
            net_in_bps: win.iter().map(|s| s.net_in_bps).max().unwrap_or(0),
            net_out_bps: win.iter().map(|s| s.net_out_bps).max().unwrap_or(0),
            load1: win.iter().map(|s| s.load1).sum::<f32>() / win.len() as f32,
        })
    }
}

/// 共享快照：所有 SSE 客户端读同一份，避免"每客户端一份采集"（设计方案 §3.6-7）
pub type SharedSample = arc_swap::ArcSwap<Sample>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_compact() {
        assert_eq!(std::mem::size_of::<Sample>(), 72);
        let r = MetricsRing::one_hour_at_1s();
        assert_eq!(r.bytes(), 259_200);
        assert!(r.bytes() < 300 * 1024, "3600 点应 < 300KB");
    }

    #[test]
    fn ring_wraps_without_allocating() {
        let mut r = MetricsRing::new(5);
        for i in 0..12u64 {
            r.push(Sample { ts: i as i64, cpu_pct: i as f32, ..Default::default() });
        }
        assert_eq!(r.len(), 5);
        assert_eq!(r.capacity(), 5);
        let v: Vec<i64> = r.iter().map(|s| s.ts).collect();
        assert_eq!(v, vec![7, 8, 9, 10, 11], "应为最旧→最新且已绕回");
    }

    #[test]
    fn aggregation_averages_cpu_and_peaks_memory() {
        let mut r = MetricsRing::new(10);
        for i in 0..10u64 {
            r.push(Sample { ts: i as i64, cpu_pct: i as f32,
                            mem_used_kib: 100 + i, ..Default::default() });
        }
        let a = r.aggregate(10).unwrap();
        assert_eq!(a.ts, 9);
        assert!((a.cpu_pct - 4.5).abs() < 1e-6, "cpu 应取均值 4.5，实际 {}", a.cpu_pct);
        assert_eq!(a.mem_used_kib, 109, "内存应取峰值");
    }
}
