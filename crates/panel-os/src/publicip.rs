//! 公网出口 IP 探测（**唯一实现**，`panel init` 与 Web 端「核准 IP」共用）。
//!
//! 为什么在 panel-os：探测走 curl 子进程，而子进程唯一出口就在本 crate 的
//! `cmd`（Bin 白名单 + 安全 PATH + 强制超时）。init 与 panel-api 各写一份
//! 必然漂移成两套判据，故收成一处。
//!
//! 隐私边界：只在**部署者主动触发**时外呼一次（init 或设置页「核准 IP」），
//! 面板运行期绝不定期外呼——不把出口 IP 变成对外心跳。

use panel_core::public_ip::parse_public_ip;

/// 同步探测公网**出口** IP。任何失败都返回 None——探测是锦上添花的展示信息，
/// 绝不让 init / 核准因无外网而失败（离线机器、防火墙、回显服务不可达都是
/// 正常部署形态，由调用方提示并保留旧值）。`--fail` 把 HTTP 错误当失败；
/// `--max-time 10` 早于 `run_sync` 的 30s 上限先到（实测 DNS 抖动可到 3s+，
/// 5s 曾撞线误报跳过）。
///
/// ⚠ async 上下文不得直接调用本函数（同步阻塞最长 10s）：必须进
/// `spawn_blocking`（panel-api 侧已如此）。
pub fn probe_sync() -> Option<String> {
    let out = crate::cmd::run_sync(
        crate::cmd::Bin::Curl,
        &["-s", "--fail", "--max-time", "10", "https://api.ipify.org"],
    ).ok()?;
    parse_public_ip(&out.stdout).map(|ip| ip.to_string())
}
