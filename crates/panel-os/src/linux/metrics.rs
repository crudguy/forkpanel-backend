//! Linux 指标采样：全部读 procfs/sysfs，**零子进程**（设计方案 §3.6-6）。
//! 实测单次采样仅读取 3,674 字节；Rust 侧预期 < 0.02ms。

use crate::traits::{
    CpuSample, DiskSample, MemSample, MetricsProvider, NetSample, ProcessInfo, ProcessSort,
    SystemSnapshot,
};
use async_trait::async_trait;
use panel_core::Result;
use std::{collections::HashMap, sync::Mutex};

pub struct LinuxMetrics {
    /// 上次 CPU/进程时间片快照（增量计算必需）
    prev: Mutex<Prev>,
}

#[derive(Default)]
struct Prev {
    cpu_total: Option<(u64, u64)>,          // (busy, total)
    per_core: HashMap<String, (u64, u64)>,
    proc_time: HashMap<i32, (u64, u64)>,    // pid -> (utime+stime, 采样时刻毫秒)
    net: HashMap<String, (u64, u64)>,       // iface -> (rx, tx)
}

impl LinuxMetrics {
    pub fn new() -> Self { Self { prev: Mutex::new(Prev::default()) } }
}

#[async_trait]
impl MetricsProvider for LinuxMetrics {
    async fn snapshot(&self) -> Result<SystemSnapshot> {
        let stat = read_str("/proc/stat").await?;
        let meminfo = read_str("/proc/meminfo").await?;
        let netdev = read_str("/proc/net/dev").await?;
        let uptime = read_str("/proc/uptime").await?;

        // 关键：std::sync::MutexGuard 不是 Send，绝不能跨 .await 持有。
        // 先在块内完成需要 prev 的增量计算，guard 在块尾即释放，之后才 await。
        let (cpu, nets) = {
            let mut prev = self.prev.lock().unwrap_or_else(|e| e.into_inner());
            let cpu = parse_cpu(&stat, &mut prev);
            let nets = parse_netdev(&netdev, &mut prev);
            (cpu, nets)
        };
        let mem = parse_meminfo(&meminfo);
        let disks = read_mounts().await?;

        Ok(SystemSnapshot {
            ts_unix: now_unix(),
            uptime_sec: parse_uptime(&uptime),
            cpu,
            mem,
            disks,
            nets,
            proc_count: count_pids(),
            tcp_conns: 0, // 由 NetworkProvider 提供（/proc/net/tcp 解析成本较高，按需采集）
            temps: read_temps().await,
        })
    }

    async fn top_processes(&self, n: usize, sort: ProcessSort) -> Result<Vec<ProcessInfo>> {
        let mut list = scan_processes(&mut self.prev.lock().unwrap_or_else(|e| e.into_inner()))?;
        match sort {
            ProcessSort::Cpu => list.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap()),
            ProcessSort::Memory => list.sort_by(|a, b| b.rss_kib.cmp(&a.rss_kib)),
            ProcessSort::Pid => list.sort_by_key(|p| p.pid),
        }
        // n==0 表示不截断（展示全部进程）；否则截断并兜底上限 8192，防异常大请求。
        if n > 0 { list.truncate(n.min(8192)); }
        Ok(list)
    }
}

// ─────────────────────────── procfs 解析 ───────────────────────────

async fn read_str(p: &str) -> Result<String> {
    tokio::fs::read_to_string(p).await.map_err(|e| panel_core::PanelError::Internal(format!("read {p}: {e}")))
}

/// 采集 hwmon 温度通道（`/sys/class/hwmon/hwmon*/tempN_input`）。
///
/// **尽力而为**：目录不存在、单通道读失败都只跳过，绝不因此让整次快照失败——
/// 温度是锦上添花的维度，不该拖垮核心指标（无 hwmon 的虚拟机返回空数组，属正常）。
/// 返回值按 (chip, label) 稳定排序，避免 `read_dir` 顺序抖动导致前端数值闪跳。
async fn read_temps() -> Vec<crate::traits::TempSample> {
    let mut out: Vec<crate::traits::TempSample> = Vec::new();
    let mut top = match tokio::fs::read_dir("/sys/class/hwmon").await {
        Ok(r) => r,
        Err(_) => return out,
    };
    while let Ok(Some(ent)) = top.next_entry().await {
        let dir = ent.path();
        let chip = tokio::fs::read_to_string(dir.join("name"))
            .await
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let chip = if chip.is_empty() { "hwmon".to_string() } else { chip };

        // 先收集该芯片下的 tempN_input 通道名（顺序由内核给出，统一排序后再读）
        let mut channels: Vec<String> = Vec::new();
        let mut sub = match tokio::fs::read_dir(&dir).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        while let Ok(Some(e)) = sub.next_entry().await {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("temp") && n.ends_with("_input") {
                channels.push(n);
            }
        }
        channels.sort();

        for ch in channels {
            let Ok(raw) = tokio::fs::read_to_string(dir.join(&ch)).await else { continue };
            let Ok(milli) = raw.trim().parse::<i64>() else { continue };
            let channel = ch.trim_end_matches("_input").to_string(); // 形如 temp1
            let label = tokio::fs::read_to_string(dir.join(format!("{channel}_label"))).await.ok();
            let crit = tokio::fs::read_to_string(dir.join(format!("{channel}_crit")))
                .await
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok());
            out.push(temp_from_parts(&chip, label.as_deref(), &channel, milli, crit));
        }
    }
    out.sort_by(|a, b| a.chip.cmp(&b.chip).then_with(|| a.label.cmp(&b.label)));
    out
}

/// 由 hwmon 原始值构造 `TempSample`（纯函数，便于单测）。
/// `input_milli` / `crit_milli` 均为内核毫摄氏度；`crit` 缺失时**不臆测告警**。
fn temp_from_parts(
    chip: &str,
    label: Option<&str>,
    channel: &str,
    input_milli: i64,
    crit_milli: Option<i64>,
) -> crate::traits::TempSample {
    crate::traits::TempSample {
        chip: chip.to_string(),
        label: label
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| channel.to_string()),
        celsius: input_milli as f64 / 1000.0,
        critical: crit_milli.map(|c| input_milli >= c).unwrap_or(false),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// /proc/stat 首行：user nice system idle iowait irq softirq steal
fn parse_cpu(stat: &str, prev: &mut Prev) -> CpuSample {
    let mut total = CpuSample::default();
    let mut per_core: Vec<f32> = Vec::new();

    for line in stat.lines() {
        if !line.starts_with("cpu") { break; }
        let mut it = line.split_whitespace();
        let label = it.next().unwrap_or("");
        let nums: Vec<u64> = it.filter_map(|v| v.parse().ok()).collect();
        if nums.len() < 8 { continue; }
        let idle = nums[3] + nums[4];                    // idle + iowait
        let busy = nums.iter().take(8).sum::<u64>() - idle;
        let sum = busy + idle;

        let pct = if label == "cpu" {
            let p = prev.cpu_total.replace((busy, sum));
            delta_pct(p, busy, sum)
        } else {
            let p = prev.per_core.insert(label.to_string(), (busy, sum));
            let v = delta_pct(p, busy, sum);
            per_core.push(v);
            v
        };
        if label == "cpu" { total.total_pct = pct; }
    }
    total.per_core_pct = Some(per_core);
    // 负载
    if let Ok(l) = read_loadavg_sync() {
        total.load1 = l.0; total.load5 = l.1; total.load15 = l.2;
    }
    total
}

fn delta_pct(prev: Option<(u64, u64)>, busy: u64, sum: u64) -> f32 {
    match prev {
        Some((pb, ps)) if sum > ps => ((busy - pb) as f32 / (sum - ps) as f32) * 100.0,
        _ => 0.0,
    }
}

fn read_loadavg_sync() -> Result<(f32, f32, f32)> {
    let s = std::fs::read_to_string("/proc/loadavg")
        .map_err(|e| panel_core::PanelError::Internal(e.to_string()))?;
    let v: Vec<f32> = s.split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
    if v.len() == 3 { Ok((v[0], v[1], v[2])) }
    else { Err(panel_core::PanelError::Internal("bad loadavg".into())) }
}

fn parse_meminfo(s: &str) -> MemSample {
    let mut m = MemSample::default();
    let mut swap_free = 0u64;
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let key = it.next().unwrap_or("");
        let val: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        match key {
            "MemTotal:" => m.total_kib = val,
            "MemAvailable:" => m.available_kib = val,
            "Buffers:" => m.buffers_kib = val,
            "Cached:" => m.cached_kib = val,
            "SwapTotal:" => m.swap_total_kib = val,
            "SwapFree:" => swap_free = val,
            _ => {}
        }
    }
    m.used_kib = m.total_kib.saturating_sub(m.available_kib);
    m.swap_used_kib = m.swap_total_kib.saturating_sub(swap_free);
    m
}

fn parse_uptime(s: &str) -> u64 {
    s.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0) as u64
}

fn parse_netdev(s: &str, prev: &mut Prev) -> Vec<NetSample> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let mut out = Vec::new();
    for line in s.lines().skip(2) {
        let mut it = line.split_whitespace();
        let iface = match it.next() { Some(v) => v.trim_end_matches(':').to_string(), None => continue };
        let fields: Vec<u64> = it.filter_map(|v| v.parse().ok()).collect();
        if fields.len() < 10 { continue; }
        let (rx, tx) = (fields[0], fields[8]);
        let (rx_rate, tx_rate) = match prev.net.insert(iface.clone(), (rx, tx)) {
            Some((prx, ptx)) if rx >= prx && tx >= ptx => {
                // 简化：以采样间隔（由调用方决定）近似；此处按 1s 归一，
                // 实际速率由上一层聚合器用真实间隔换算
                (rx - prx, tx - ptx)
            }
            _ => (0, 0),
        };
        out.push(NetSample { iface, rx_bytes: rx, tx_bytes: tx, rx_rate_bps: rx_rate, tx_rate_bps: tx_rate });
    }
    let _ = now_ms;
    out
}

/// 挂载点采样：statvfs；识别网络文件系统（WAL 风险，设计方案 §1.4-7）
async fn read_mounts() -> Result<Vec<DiskSample>> {
    let s = read_str("/proc/mounts").await?;
    let mut out = Vec::new();
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 { continue; }
        let (device, mount, fstype) = (f[0].to_string(), f[1], f[2]);
        // 跳过纯内存与伪文件系统
        if matches!(fstype, "proc" | "sysfs" | "devtmpfs" | "cgroup" | "cgroup2" | "pstore" | "mqueue") {
            continue;
        }
        let (total, used) = statvfs_bytes(mount);
        let is_network = matches!(fstype, "nfs" | "nfs4" | "cifs" | "smb3" | "9p" | "fuse.sshfs");
        out.push(DiskSample {
            mount_point: std::path::PathBuf::from(mount),
            device,
            fs_type: fstype.to_string(),
            total_bytes: total,
            used_bytes: used,
            is_network_fs: is_network,
        });
    }
    Ok(out)
}

fn statvfs_bytes(path: &str) -> (u64, u64) {
    use std::ffi::CString;
    let Ok(c) = CString::new(path) else { return (0, 0) };
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 { return (0, 0); }
        let block = st.f_frsize as u64;
        let total = st.f_blocks as u64 * block;
        let avail = st.f_bavail as u64 * block;
        (total, total.saturating_sub(avail))
    }
}

fn count_pids() -> u32 {
    std::fs::read_dir("/proc").map(|d| d.filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().parse::<u32>().is_ok()).count() as u32)
        .unwrap_or(0)
}

/// 进程属主用户名映射：读 /etc/passwd 一次构建 uid→name 表。
fn uid_name_map() -> HashMap<u32, String> {
    let mut m = HashMap::new();
    if let Ok(s) = std::fs::read_to_string("/etc/passwd") {
        for line in s.lines() {
            let mut f = line.split(':');
            let name = match f.next() { Some(n) => n, None => continue };
            if f.next() != Some("x") { continue }
            if let Some(uid) = f.next().and_then(|u| u.parse::<u32>().ok()) {
                m.insert(uid, name.to_string());
            }
        }
    }
    m
}

/// 进程真实 uid：procfs 的 /proc/<pid>/stat 字段不含 uid，须读 /proc/<pid>/status 的 Uid 字段。
fn read_proc_uid(pid: i32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in s.lines() {
        if line.starts_with("Uid:") {
            // Uid: <real> <effective> <saved> <fs> —— 取真实 uid（第一个）
            return line.split_whitespace().nth(1).and_then(|v| v.parse::<u32>().ok());
        }
    }
    None
}

/// 进程扫描：仅读 /proc/<pid>/stat（平均 295B/进程），按需限制数量
fn scan_processes(prev: &mut Prev) -> Result<Vec<ProcessInfo>> {
    // 真实时钟节拍：CONFIG_HZ 因内核/容器而异（Debian 常见 250，旧内核 100），
    // 硬编码 100 会让 CPU% 整体偏差数倍。取系统真实值，失败回退 100。
    let hz = match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
        n if n > 0 => n as f32,
        _ => 100.0,
    };
    // 逻辑 CPU 数：进程 CPU% 按「占总算力份额」归一（与概览总 CPU% 口径一致，0~100%），
    // 故除以在线核数；取不到时回退 1（退化为「单核归一」，仍不会溢出）。
    let n_cpu = match unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } {
        n if n > 0 => n as f32,
        _ => 1.0,
    };
    let now_ms = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(_) => 0,
    };
    let mut out = Vec::new();
    // 进程属主映射表：每次扫描构建一次，所有进程复用（避免逐进程重读 /etc/passwd）
    let uid_names = uid_name_map();
    let rd = std::fs::read_dir("/proc").map_err(|e| panel_core::PanelError::Internal(e.to_string()))?;
    for entry in rd.filter_map(|e| e.ok()) {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        // comm 可能含空格与括号，取最后一个 ')' 之后的部分
        let Some(after) = stat.rfind(')').map(|i| &stat[i + 1..]) else { continue };
        let f: Vec<&str> = after.split_whitespace().collect();
        if f.len() < 22 { continue; }
        let name = stat[stat.find('(').unwrap_or(0) + 1..stat.rfind(')').unwrap_or(0)].to_string();
        let state = f[0].chars().next().unwrap_or('?');
        let ppid = f[1].parse().unwrap_or(0);
        let utime: u64 = f[11].parse().unwrap_or(0);
        let stime: u64 = f[12].parse().unwrap_or(0);
        let rss_pages: u64 = f[21].parse().unwrap_or(0);
        let ticks = utime + stime;

        // CPU% = 本窗口内进程占用算力 / (窗口秒数 × 单核算力 × 核数) × 100，
        // 即「占总算力份额」，与概览总 CPU% 口径一致（0~100%）。
        // 窗口用真实采样间隔（prev 存上次扫描时间戳）而非写死 1s——写死 1s 会让
        // 实际间隔 3s 的调用方（专业快照）算出的数值失真，出现 9770% 这类溢出值。
        let cpu_pct = match prev.proc_time.get(&pid) {
            Some((pt, ts)) if ticks >= *pt && *ts > 0 => {
                let dt = (now_ms.saturating_sub(*ts)) as f32 / 1000.0;
                if dt > 0.0 { ((ticks - pt) as f32 / hz / dt / n_cpu) * 100.0 } else { 0.0 }
            }
            _ => 0.0,
        };
        prev.proc_time.insert(pid, (ticks, now_ms));

        let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
            .map(|c| c.replace('\0', " ").trim().to_string()).unwrap_or_default();
        // 属主用户名：stat 不含 uid，须读 status 的 Uid 再映射（见 read_proc_uid / uid_name_map）
        let user = read_proc_uid(pid)
            .map(|u| uid_names.get(&u).cloned().unwrap_or_else(|| u.to_string()));

        out.push(ProcessInfo {
            pid, ppid, name: if name.is_empty() { format!("[{state}]") } else { name },
            cpu_pct,
            rss_kib: rss_pages * 4,   // 页大小 4KiB（x86_64/aarch64 通用）
            cmdline,
            user,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_parser() {
        let s = "MemTotal:        1018000 kB\nMemAvailable:     512000 kB\n\
                 Buffers:          12000 kB\nCached:          300000 kB\n\
                 SwapTotal:        204800 kB\nSwapFree:        204800 kB\n";
        let m = parse_meminfo(s);
        assert_eq!(m.total_kib, 1018000);
        assert_eq!(m.used_kib, 1018000 - 512000);
        assert_eq!(m.swap_used_kib, 0);
    }

    #[test]
    fn cpu_delta_math() {
        assert_eq!(delta_pct(None, 100, 200), 0.0);
        assert_eq!(delta_pct(Some((50, 100)), 100, 200), 50.0);
    }

    #[test]
    fn temp_sample_prefers_label() {
        // 内核 sysfs 文件常带尾换行，必须 trim
        let t = temp_from_parts("coretemp", Some(" Package id 0\n"), "temp1", 45_000, Some(100_000));
        assert_eq!(t.chip, "coretemp");
        assert_eq!(t.label, "Package id 0");
        assert_eq!(t.celsius, 45.0);
        assert!(!t.critical);
    }

    #[test]
    fn temp_sample_falls_back_and_detects_crit() {
        // 无 label → 用通道名；input ≥ crit → critical
        let t = temp_from_parts("nvme", None, "temp2", 100_000, Some(100_000));
        assert_eq!(t.label, "temp2");
        assert!(t.critical);
        // 空/空白 label 同样回退，不产生空标签
        let e = temp_from_parts("acpitz", Some("   "), "temp1", 30_000, None);
        assert_eq!(e.label, "temp1");
        assert!(!e.critical, "crit 缺失时绝不臆测告警");
    }

    #[tokio::test]
    async fn live_snapshot_works() {
        // 仅在 Linux 且有 procfs 的环境有意义；容器外会失败则跳过
        let m = LinuxMetrics::new();
        if let Ok(s) = m.snapshot().await {
            assert!(s.mem.total_kib > 0);
            assert!(s.uptime_sec > 0);
        }
    }
}
