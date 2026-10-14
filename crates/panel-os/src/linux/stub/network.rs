use super::*;


#[derive(Default)]
pub struct LinuxNetwork;

#[async_trait]
impl NetworkProvider for LinuxNetwork {
    async fn interfaces(&self) -> Result<Vec<NetSample>> {
        let s = tokio::fs::read_to_string("/proc/net/dev").await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        let mut out = Vec::new();
        for line in s.lines().skip(2) {
            let mut it = line.split_whitespace();
            let iface = match it.next() { Some(v) => v.trim_end_matches(':').to_string(), None => continue };
            let f: Vec<u64> = it.filter_map(|v| v.parse().ok()).collect();
            if f.len() < 10 { continue; }
            out.push(NetSample { iface, rx_bytes: f[0], tx_bytes: f[8], rx_rate_bps: 0, tx_rate_bps: 0 });
        }
        Ok(out)
    }

    /// 监听端口：M5 实现（解析 /proc/net/tcp + inode→pid 映射成本较高）
    async fn listening(&self) -> Result<Vec<ListeningPort>> { unsupported!("network.listening (M5)") }
}

