//! 启动自检。每一条都对应一个**实测或已发生过**的故障模式。
//!
//! 设计意图：`panel doctor` 是"部署能不能上"的唯一判据，输出可直接粘到 issue 里。

use panel_core::{cap_keys, Tier};
use panel_os::{OsAdapter, PathLayout};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level { Ok, Warn, Fail }

#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub message: String,
    /// 出现问题时的修复建议（可执行的命令或明确的动作）
    pub fix: Option<String>,
}

pub fn run(os: &dyn OsAdapter, layout: &dyn PathLayout, db_path: &Path, tier: Tier, synchronous: &str) -> Vec<Check> {
    let mut v = Vec::new();

    // 1. 数据目录文件系统：网络文件系统上 WAL 不可靠（设计方案 §1.4-7 硬约束）
    let data = layout.data_dir();
    match panel_os::fs::check_data_dir(&data) {
        Ok((fs, is_network)) if is_network => v.push(Check {
            name: "data_fs",
            level: Level::Fail,
            message: format!("数据目录位于网络文件系统（{fs}），SQLite WAL 在此不可靠"),
            fix: Some(format!("把 [paths].data 改到本地文件系统（当前 {}）", data.display())),
        }),
        Ok((fs, _)) => v.push(Check {
            name: "data_fs",
            level: Level::Ok,
            message: format!("数据目录文件系统 {fs}"),
            fix: None,
        }),
        Err(e) => v.push(Check {
            name: "data_fs", level: Level::Warn,
            message: format!("无法探测文件系统：{e}"), fix: None,
        }),
    }

    // 2. 目录可写
    match std::fs::create_dir_all(&data)
        .and_then(|_| std::fs::write(data.join(".wtest"), b"x"))
        .and_then(|_| std::fs::remove_file(data.join(".wtest"))) {
        Ok(()) => v.push(Check { name: "data_writable", level: Level::Ok,
            message: format!("{} 可写", data.display()), fix: None }),
        Err(e) => v.push(Check { name: "data_writable", level: Level::Fail,
            message: format!("{} 不可写：{e}", data.display()),
            fix: Some(format!("chown -R root:root {} && chmod 700 {}", data.display(), data.display())) }),
    }

    // 3. 权限：面板需要 root 才能管理服务/防火墙
    v.push(if panel_os::fs::is_root() {
        Check { name: "euid", level: Level::Ok,
            message: "以特权用户运行（可管理服务/防火墙）".into(), fix: None }
    } else {
        Check { name: "euid", level: Level::Warn,
            message: "非特权运行：服务与防火墙相关能力将不可用".into(),
            fix: Some("以 root 启动（或在 systemd 单元中保持默认用户）".into()) }
    });

    // 4. 主密钥权限
    let key = data.join("master.key");
    if key.exists() {
        match panel_os::fs::mode_of(&key) {
            Some(m) if m & 0o777 == 0o600 => v.push(Check { name: "master_key", level: Level::Ok,
                message: "主密钥权限 0600".into(), fix: None }),
            Some(m) => v.push(Check { name: "master_key", level: Level::Fail,
                message: format!("主密钥权限过宽（{:o}）", m & 0o777),
                fix: Some(format!("chmod 600 {}", key.display())) }),
            // 非 POSIX 平台无法用权限位表达，降级为提示
            None => v.push(Check { name: "master_key", level: Level::Warn,
                message: "当前平台不提供 POSIX 权限位，无法校验主密钥保护".into(), fix: None }),
        }
    } else {
        v.push(Check { name: "master_key", level: Level::Warn,
            message: "主密钥不存在（未初始化）".into(),
            fix: Some("执行 panel init".into()) });
    }

    // 5. WAL 文件大小（实测：关闭 autocheckpoint 后无界增长）
    let mut wal = db_path.to_path_buf();
    wal.set_extension("db-wal");
    if let Ok(m) = std::fs::metadata(&wal) {
        let mb = m.len() as f64 / 1048576.0;
        v.push(if mb > 16.0 {
            Check { name: "wal_size", level: Level::Warn,
                message: format!("WAL 文件 {:.1} MB（超过 16MB 阈值）", mb),
                fix: Some("检查 wal_autocheckpoint 是否为 512；可执行 panel vacuum".into()) }
        } else {
            Check { name: "wal_size", level: Level::Ok,
                message: format!("WAL 文件 {:.2} MB", mb), fix: None }
        });
    }

    // 6. 数据库完整性
    if db_path.exists() {
        match panel_db::open(db_path, tier, synchronous) {
            Ok(c) => match panel_db::integrity_check(&c) {
                Ok(s) if s == "ok" => v.push(Check { name: "db_integrity", level: Level::Ok,
                    message: "数据库完整性检查通过".into(), fix: None }),
                Ok(s) => v.push(Check { name: "db_integrity", level: Level::Fail,
                    message: format!("完整性检查未通过：{s}"),
                    fix: Some("从最近的备份恢复：panel restore <file>".into()) }),
                Err(e) => v.push(Check { name: "db_integrity", level: Level::Warn,
                    message: format!("完整性检查失败：{e}"), fix: None }),
            },
            Err(e) => v.push(Check { name: "db_integrity", level: Level::Fail,
                message: format!("无法打开数据库：{e}"), fix: None }),
        }
    }

    // 7. 能力矩阵摘要：让用户一眼看到哪些功能不可用及原因
    let caps = os.capabilities();
    let missing: Vec<String> = caps.iter()
        .filter(|(_, c)| !c.supported)
        .map(|(k, c)| format!("{k}({})", c.reason.as_deref().unwrap_or("?")))
        .collect();
    v.push(if missing.is_empty() {
        Check { name: "capabilities", level: Level::Ok,
            message: "全部能力可用".into(), fix: None }
    } else {
        Check { name: "capabilities", level: Level::Warn,
            message: format!("{} 项能力不可用：{}", missing.len(), missing.join(", ")),
            fix: None }
    });

    // 8. 防火墙能力缺失时提醒"面板不会自动改你的规则"
    if !caps.get(cap_keys::FIREWALL_MANAGE).map(|c| c.supported).unwrap_or(false) {
        v.push(Check { name: "firewall", level: Level::Warn,
            message: "未检测到受支持的防火墙后端，防火墙页将不可用".into(),
            fix: Some("安装 nftables 或 iptables；面板不会自行创建防火墙规则".into()) });
    }

    // 9. 档位与采样降频提示
    v.push(match tier {
        Tier::Nano => Check { name: "tier", level: Level::Warn,
            message: "nano 档位：采样 5s、不落盘历史、SSE 上限 3 客户端".into(),
            fix: Some("这是 512MB 机器的预期行为，非故障".into()) },
        t => Check { name: "tier", level: Level::Ok,
            message: format!("档位 {:?}，采样 {}ms", t, t.sampling_interval_ms()), fix: None },
    });

    v
}

pub fn has_fail(v: &[Check]) -> bool { v.iter().any(|c| c.level == Level::Fail) }

pub fn render(v: &[Check]) -> String {
    let mut out = String::new();
    for c in v {
        let mark = match c.level { Level::Ok => "✓", Level::Warn => "!", Level::Fail => "✗" };
        out.push_str(&format!("{} {:<14} {}\n", mark, c.name, c.message));
        if let Some(f) = &c.fix { out.push_str(&format!("    → 修复：{}\n", f)); }
    }
    out
}
