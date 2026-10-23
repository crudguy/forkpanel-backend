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

    // 7. 迁移校验和漂移：迁移文件在应用到本库之后又被改过（热补丁 / 二进制与库不同构建）
    if let Some(c) = migration_checksum_check(db_path, tier, synchronous) {
        v.push(c);
    }

    // 8. 能力矩阵摘要：让用户一眼看到哪些功能不可用及原因
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

    // 9. 防火墙能力缺失时提醒"面板不会自动改你的规则"
    if !caps.get(cap_keys::FIREWALL_MANAGE).map(|c| c.supported).unwrap_or(false) {
        v.push(Check { name: "firewall", level: Level::Warn,
            message: "未检测到受支持的防火墙后端，防火墙页将不可用".into(),
            fix: Some("安装 nftables 或 iptables；面板不会自行创建防火墙规则".into()) });
    }

    // 10. 档位与采样降频提示
    v.push(match tier {
        Tier::Nano => Check { name: "tier", level: Level::Warn,
            message: "nano 档位：采样 5s、不落盘历史、SSE 上限 3 客户端".into(),
            fix: Some("这是 512MB 机器的预期行为，非故障".into()) },
        t => Check { name: "tier", level: Level::Ok,
            message: format!("档位 {:?}，采样 {}ms", t, t.sampling_interval_ms()), fix: None },
    });

    v
}

/// 迁移校验和核对。独立成函数：三态（一致 / 漂移 / 库不存在）各自可单测，
/// 且 run() 里只是一行 push——逻辑不藏在闭包段落里。
///
/// 库不存在 ⇒ `None`（不出 row）：与 db_integrity 口径一致——都没库可查，
/// 不重复报警。库打不开同样不出 row：db_integrity 已经 Fail 过了。
fn migration_checksum_check(db_path: &Path, tier: Tier, synchronous: &str) -> Option<Check> {
    if !db_path.exists() {
        return None;
    }
    let conn = panel_db::open(db_path, tier, synchronous).ok()?;
    match panel_db::migrate::checksum_drift(&conn) {
        Ok(drift) if drift.is_empty() => Some(Check {
            name: "migration_checksum",
            level: Level::Ok,
            message: "迁移校验和一致（无文件漂移）".into(),
            fix: None,
        }),
        Ok(drift) => {
            let items: Vec<String> = drift
                .iter()
                .map(|d| match &d.embedded {
                    Some(cur) => format!(
                        "v{}（库内 {} → 当前 {}",
                        d.version,
                        d.stored.get(..8).unwrap_or(&d.stored),
                        cur.get(..8).unwrap_or(cur)
                    ),
                    None => format!(
                        "v{}（库内 {}，当前二进制无此迁移文件）",
                        d.version,
                        d.stored.get(..8).unwrap_or(&d.stored)
                    ),
                })
                .collect();
            Some(Check {
                name: "migration_checksum",
                level: Level::Warn,
                message: format!("{} 个迁移版本校验和漂移：{}", drift.len(), items.join("，")),
                fix: Some(
                    "这些迁移文件在应用到本库之后又被修改过。核对改动是否有意：有意的 schema 变更应新增迁移版本（而非改旧文件）并评估库内现状差异；无意的请恢复文件。面板按库内现状继续运行，不会自动改写库存校验和（那会抹掉漂移证据）"
                        .into(),
                ),
            })
        }
        Err(e) => Some(Check {
            name: "migration_checksum",
            level: Level::Warn,
            message: format!("校验和核对失败：{e}"),
            fix: None,
        }),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 真机临时库：带 pid 防并行互踩，先 remove 三件套（db/-wal/-shm）。
    fn temp_db(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("panel-doctor-mc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("db-wal"));
        let _ = std::fs::remove_file(p.with_extension("db-shm"));
        p
    }

    #[test]
    fn migration_checksum_check_ok_on_consistent_db() {
        let p = temp_db("ok");
        {
            let mut c = panel_db::open(&p, Tier::Nano, "NORMAL").unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
        }
        let chk = migration_checksum_check(&p, Tier::Nano, "NORMAL").expect("库存在应出 row");
        assert_eq!(chk.name, "migration_checksum");
        assert_eq!(chk.level, Level::Ok);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn migration_checksum_check_warns_on_drift() {
        let p = temp_db("drift");
        {
            let mut c = panel_db::open(&p, Tier::Nano, "NORMAL").unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
            c.execute(
                "UPDATE schema_migrations SET checksum='deadbeefdeadbeef' WHERE version=1",
                [],
            )
            .unwrap();
        }
        let chk = migration_checksum_check(&p, Tier::Nano, "NORMAL").expect("库存在应出 row");
        assert_eq!(chk.level, Level::Warn, "漂移必须 Warn 而非静默 Ok");
        assert!(chk.message.contains("v1"), "告警应点名版本：{}", chk.message);
        let fix = chk.fix.expect("Warn 必须带修复建议");
        assert!(fix.contains("新增迁移版本"), "修复建议要说清正确做法：{fix}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn migration_checksum_check_absent_when_db_missing() {
        let p = temp_db("missing");
        assert!(
            migration_checksum_check(&p, Tier::Nano, "NORMAL").is_none(),
            "库不存在时不出 row（与 db_integrity 口径一致：都没库可查）"
        );
    }

    #[test]
    fn run_surfaces_drift_row_end_to_end() {
        // run() 的接线与 render() 也要真跑：只测独立函数会漏「忘了 push」
        let p = temp_db("run");
        {
            let mut c = panel_db::open(&p, Tier::Nano, "NORMAL").unwrap();
            panel_db::migrate::apply(&mut c).unwrap();
            c.execute(
                "UPDATE schema_migrations SET checksum='deadbeefdeadbeef' WHERE version=2",
                [],
            )
            .unwrap();
        }
        let os = panel_os::mock::MockOsAdapter::new();
        let layout = panel_os::mock::MockPathLayout;
        let checks = run(&os, &layout, &p, Tier::Nano, "NORMAL");
        let row = checks
            .iter()
            .find(|c| c.name == "migration_checksum")
            .expect("run() 必须产出 migration_checksum row");
        assert_eq!(row.level, Level::Warn);
        assert!(row.message.contains("v2"));
        // render 也要能吐出来（mark 映射 Warn → "!"），不能只在结构体里正确
        let out = render(&checks);
        assert!(out.contains("migration_checksum"), "render 输出应含该检查");
        assert!(out.contains('!'), "Warn 行应有 ! 标记");
        let _ = std::fs::remove_file(&p);
    }
}
