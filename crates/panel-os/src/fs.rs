//! 同步文件系统 / 权限 / 终端原语。
//!
//! # 为什么这些看似琐碎的函数要在 OS 层
//! `chmod`、`getuid`、关闭终端回显都是**平台专有**的。若散落在 CLI 里，
//! 就会出现 `#[cfg(unix)]` 长在业务层的情况 —— 这正是 CI 门禁禁止的形态。
//! 集中到这里之后，平台专有逻辑只有一处出口，业务层不必长 `#[cfg]`。
//! **本面板只支持 Linux**（见 `panel-core` 平台枚举注释）：非 POSIX 的降级分支
//! 一律删掉，而不是留着"看起来以后能接"。

use panel_core::{PanelError, Result};
use std::path::Path;

/// 是否以特权用户运行（POSIX: uid 0）
pub fn is_root() -> bool { unsafe { libc::geteuid() == 0 } }

/// 设置文件/目录权限位（POSIX mode）。
pub fn set_mode(p: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .map_err(|e| PanelError::Internal(format!("chmod {}: {e}", p.display())))
}

/// 读取权限位（POSIX）。
pub fn mode_of(p: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).ok().map(|m| m.permissions().mode())
}

/// 创建目录（递归）并设置权限
pub fn ensure_dir(p: &Path, mode: u32) -> Result<()> {
    std::fs::create_dir_all(p)
        .map_err(|e| PanelError::Internal(format!("mkdir {}: {e}", p.display())))?;
    set_mode(p, mode)
}

/// 写入文件并设置权限（主密钥等敏感文件用 0600）
pub fn write_private(p: &Path, data: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = p.parent() { std::fs::create_dir_all(parent).ok(); }
    std::fs::write(p, data)
        .map_err(|e| PanelError::Internal(format!("write {}: {e}", p.display())))?;
    set_mode(p, mode)
}

/// 检查数据目录所在文件系统，返回 `(文件系统名, 是否为网络文件系统)`。
///
/// 为什么必须走这里：SQLite 的 WAL 依赖共享内存与可靠的 fsync 语义，
/// 在 NFS / SMB / 9p 上会静默损坏。启动期必须**拒绝**而非警告。
/// statfs 魔数判定在 Linux 实现内，业务层只看到布尔值。
pub fn check_data_dir(dir: &Path) -> Result<(String, bool)> {
    crate::linux::check_data_dir_fs(dir)
}

/// 从终端读取一行且**不回显**（口令输入）。
/// 无论读取成功与否都恢复终端回显，避免失败后终端"卡住"。
/// 保留目录里**最近** `keep` 个文件名以 `prefix` 开头的普通文件，删除更旧的。
///
/// 用途：带时间戳/自增 id 的备份与日志（如 `sshd.conf.panel.bak-<ts>`、
/// `panel-task-<id>.log`）每次生成新文件、从不复用，不清理会无限增长。
///
/// 排序依据**修改时间而非文件名**——文件名里的时间戳格式可能变，mtime 才可靠。
///
/// 失败一律静默（返回已删除个数）：清理是附带的收尾动作，
/// 不该因为它失败就让"保存配置""写任务日志"这类主操作报错。
pub fn prune_keep_newest(dir: &Path, prefix: &str, keep: usize) -> usize {
    if keep == 0 { return 0; }
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf)> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(prefix))
                    .unwrap_or(false)
        })
        .filter_map(|p| {
            std::fs::metadata(&p).ok().and_then(|m| m.modified().ok()).map(|t| (t, p))
        })
        .collect();
    // 新的在前：mtime 降序
    entries.sort_by_key(|a| std::cmp::Reverse(a.0));
    let mut removed = 0;
    for (_, p) in entries.iter().skip(keep) {
        if std::fs::remove_file(p).is_ok() { removed += 1; }
    }
    removed
}

pub fn read_password(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    read_hidden_unix()
}

fn read_hidden_unix() -> Result<String> {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            return read_plain();
        }
        let original = term;
        term.c_lflag &= !libc::ECHO;
        if libc::tcsetattr(fd, libc::TCSANOW, &term) != 0 {
            return read_plain();
        }
        let mut s = String::new();
        let r = std::io::stdin().read_line(&mut s);
        libc::tcsetattr(fd, libc::TCSANOW, &original);   // 必须恢复
        eprintln!();
        match r {
            Ok(_) => Ok(s.trim().to_string()),
            Err(e) => Err(PanelError::Internal(e.to_string())),
        }
    }
}

fn read_plain() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)
        .map_err(|e| PanelError::Internal(format!("read stdin: {e}")))?;
    Ok(s.trim().to_string())
}

// ═════════════════════════════ 端口占用 ═════════════════════════════

/// 一个正在监听的端口（够面板判断「能不能用」的信息量）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortInUse {
    pub port: u16,
    /// 监听地址（`0.0.0.0` / `127.0.0.1` / `::` …）
    pub addr: String,
    /// TCP / UDP
    pub tcp: bool,
}

/// 读 `/proc/net/tcp{,6}` 判断某端口是否已被监听。
///
/// 为什么直接读 proc 而不是 `ss -ltn`：**零子进程**（面板每次保存都会问），
/// 且 `/proc/net/tcp` 在所有 Linux 上格式稳定。代价是 UDP 另读 `/proc/net/udp`、
/// 拿不到占用进程名——那部分对「能不能用」这个判断不重要。
///
/// 只看 **LISTEN（0A）** 状态：TIME_WAIT / ESTABLISHED 的连接占的是**本地临时端口**，
/// 不等于「有人在这个端口上服务」，不该据此判定端口被占。
///
/// 返回 `None` 表示**无法判定**（proc 不可读、无该文件）——调用方须放行，
/// 不能因为「读不到」就拒绝用户的应用（那是把预检当成了强制约束）。
pub fn port_in_use(port: u16) -> Option<PortInUse> {
    // /proc/net/tcp 的 local_address 是 `0100007F:1F90` 形式：小端 hex 的 IP:PORT
    let want = format!("{port:04X}");
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(file) else { continue };
        for line in text.lines().skip(1) {
            // 列序是 `sl: local_address rem_address st …`——**首列是行号、st 是第 4 列**。
            // 两处都曾写错（把 sl 当 local、把 rem_address 当 st），症状都是
            // 「bind 成功后仍报未占用」，因为永远匹配不到端口。
            let mut it = line.split_whitespace();
            it.next(); // sl（行号，非地址）
            let local = it.next()?;
            it.next(); // rem_address（对端，与占用判定无关）
            let st = it.next()?; // st：0A = LISTEN
            // **只看 0A = LISTEN**：TIME_WAIT / ESTABLISHED 占的是本地临时端口，
            // 不等于「有人在这个端口上服务」，据此拒绝会误伤一大片。
            if !st.eq("0A") {
                continue;
            }
            let Some((addr_hex, port_hex)) = local.split_once(':') else { continue };
            if port_hex.eq_ignore_ascii_case(&want) {
                return Some(PortInUse { port, addr: decode_proc_addr(addr_hex), tcp: true });
            }
        }
    }
    None
}

/// `/proc/net/*` 里的地址是小端 hex（`0100007F` = 127.0.0.1、`00000000` = 0.0.0.0）。
fn decode_proc_addr(hex: &str) -> String {
    if hex.len() == 8 {
        let b = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0);
        let v = u32::from_le_bytes([b(0), b(2), b(4), b(6)]);
        format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
    } else {
        // IPv6：统一显示为 ::（面板只需知道「不是只绑 127.0.0.1」）
        "[::]".into()
    }
}

#[cfg(test)]
mod port_tests {
    use super::*;

    /// 占用检测的**核心**语义：不可判定时必须返回 None（放行），
    /// 而不是「当成被占」把用户的应用全拒掉。
    #[test]
    fn unjudgeable_returns_none_and_does_not_block() {
        // 0 端口永远不可能有进程在监听（Linux 会拒绝 bind 0）
        assert_eq!(port_in_use(0), None);
    }

    /// 占用判定必须**真的看 proc**：本机必然有 nginx 之类在监听 80 的话会命中，
    /// 至少要能区分「已占」与「未占」两种结果（不能恒返回 None）。
    #[test]
    fn reads_proc_net_tcp_and_is_not_always_none() {
        // 起一个真实的监听端口，再断言能被查到 —— 恒 None 的检测等于没有检测
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().unwrap().port();
        let hit = port_in_use(port);
        assert!(hit.is_some(), "本机刚bind 的 {port} 端口必须被检测到占用");
        let h = hit.unwrap();
        assert_eq!(h.port, port);
        assert!(h.addr.contains("127.0.0.1"), "应解出监听地址，实际 = {}", h.addr);
        // 极少被占用的高位端口必须判为「未占用」，防止「任何端口都返回已占」
        let free = (45000..46000).find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok());
        if let Some(p) = free {
            // 这个端口已被上面那行 bind 占住了；换一个再判
            if let Some(q) = (46000..47000).find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok()) {
                assert_eq!(port_in_use(p), None, "未被监听的 {p} 不该判为占用");
                assert_eq!(port_in_use(q), None, "未被监听的 {q} 不该判为占用");
            }
        }
    }

    #[test]
    fn decodes_proc_addr_little_endian() {
        assert_eq!(decode_proc_addr("0100007F"), "127.0.0.1");
        assert_eq!(decode_proc_addr("00000000"), "0.0.0.0");
        assert_eq!(decode_proc_addr("0101A8C0"), "192.168.1.1");
        // IPv6 一律归成 ::（面板只关心「不是只绑回环」）
        assert_eq!(decode_proc_addr("00000000000000000000000001000000"), "[::]");
    }
}

// ═════════════════════════════ ELF 架构预检 ═════════════════════════════

/// 一个 ELF 可执行文件的架构信息（只取判断「能不能在这台机器上跑」所需的最小字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfArch {
    /// 32 位 / 64 位
    pub is_64: bool,
    /// `e_machine` 的可读名，如 `x86-64` / `aarch64` / `riscv` / `arm`
    pub machine: &'static str,
}

/// ELF 魔数（`\x7fELF`）。
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// 本机架构（编译期确定，与 `uname -m` 语义一致但更精确）。
pub const fn host_machine() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    { "x86-64" }
    #[cfg(target_arch = "aarch64")]
    { "aarch64" }
    #[cfg(target_arch = "arm")]
    { "arm" }
    #[cfg(target_arch = "riscv64")]
    { "riscv" }
    #[cfg(target_arch = "x86")]
    { "x86" }
    #[cfg(target_arch = "loongarch64")]
    { "loongarch" }
    #[cfg(target_arch = "mips64")]
    { "mips64" }
    #[cfg(not(any(
        target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm",
        target_arch = "riscv64", target_arch = "x86", target_arch = "loongarch64",
        target_arch = "mips64",
    )))]
    { "unknown" }
}

/// `e_machine` 码 → 可读名。只列面板可能遇到的（引自 Linux `ELF_MACHINE_*`）。
fn machine_name(code: u16) -> &'static str {
    match code {
        0x03 => "x86",
        0x08 => "mips",
        0x28 => "arm",
        0x3E => "x86-64",
        0xB7 => "aarch64",
        0xF3 => "riscv",
        0x102 => "loongarch",
        _ => "unknown",
    }
}

/// 读取 ELF 头，判断该可执行文件的架构。
///
/// **只在文件真的是 ELF 时才返回 `Some`**：脚本（`#!/bin/sh`）、`node`（本机装了
/// 对应架构）、解释器启动的应用都会走 `None` —— 那不属于「架构不匹配」，
/// 不该拦用户。只有**确凿是 ELF 且架构与本机不符**时，调用方才该拒绝。
///
/// 只读前 20 字节（`e_ident` + `e_machine`），不引入 goblin 之类的依赖——
/// 需求就是这一个判断，为此拉一个解析库不划算。
pub fn elf_arch_of(p: &Path) -> Option<ElfArch> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).ok()?;
    // 20 = e_ident(16) + e_machine(2)
    let mut head = [0u8; 20];
    f.read_exact(&mut head).ok()?;
    if head[..4] != ELF_MAGIC {
        return None;
    }
    // EI_CLASS: 1 = 32 位, 2 = 64 位；其它值（含 OS/ABI 位）一律不看架构。
    let is_64 = match head[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    // e_machine 在偏移 18（32/64 位 ELF 的这个字段位置相同）
    let code = u16::from_le_bytes([head[18], head[19]]);
    Some(ElfArch { is_64, machine: machine_name(code) })
}

/// `ExecStart` 指向的可执行文件是否**架构不匹配**。
///
/// 返回值语义刻意做成三态：
/// - `Ok(None)`：文件不存在 / 不是 ELF / 架构对得上 → **不该拦**；
/// - `Ok(Some(msg))`：确凿是 ELF 且架构不符 → `msg` 是给用户看的原因；
/// - 读文件出错也归到 `Ok(None)`（预检是**辅助**，不该因读不到就拦住创建）。
pub fn exec_arch_mismatch(workdir: &Path, exec: &str) -> Option<String> {
    let first = exec.split_whitespace().next()?;
    // 相对路径按 systemd 语义：WorkingDirectory + 相对路径（`./app` 已被
    // `exec_start_is_valid` 挡掉，这里只会拿到纯命令名或绝对路径）
    let path = if first.starts_with('/') {
        std::path::PathBuf::from(first)
    } else {
        workdir.join(first)
    };
    let arch = elf_arch_of(&path)?;
    let host = host_machine();
    if arch.machine == host {
        return None;
    }
    // 32/64 位也要对上：x86 与 x86-64 同族但不能互相执行
    let host64 = host != "x86" && host != "arm" && host != "mips64";
    if arch.machine == "x86" && host == "x86-64" && !arch.is_64 {
        // 32 位 x86 在 64 位内核上通常能跑（若装了兼容层），不当成硬错误
        return None;
    }
    let _ = host64;
    Some(format!(
        "「{}」是 {} 位 {} 产物，而本机是 {} —— 换成本机架构重新编译（交叉编译需指定 GOOS/GOARCH、CARGO_BUILD_TARGET 等）",
        path.display(),
        if arch.is_64 { "64" } else { "32" },
        arch.machine,
        host,
    ))
}

#[cfg(test)]
mod elf_tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("panel-elf-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 造一个最小 ELF 头：magic + EI_CLASS + e_machine。
    fn write_elf(path: &Path, is_64: bool, machine: u16) {
        let mut b = vec![0u8; 20];
        b[..4].copy_from_slice(&ELF_MAGIC);
        b[4] = if is_64 { 2 } else { 1 };
        b[18..20].copy_from_slice(&machine.to_le_bytes());
        std::fs::write(path, b).unwrap();
    }

    #[test]
    fn detects_elf_arch() {
        let d = tmpdir("detect");
        let p = d.join("app");
        write_elf(&p, true, 0x3E); // EM_X86_64
        assert_eq!(elf_arch_of(&p), Some(ElfArch { is_64: true, machine: "x86-64" }));
        write_elf(&p, true, 0xB7); // EM_AARCH64
        assert_eq!(elf_arch_of(&p), Some(ElfArch { is_64: true, machine: "aarch64" }));
        write_elf(&p, false, 0x03); // EM_386
        assert_eq!(elf_arch_of(&p), Some(ElfArch { is_64: false, machine: "x86" }));
        std::fs::remove_dir_all(&d).ok();
    }

    /// 非 ELF（脚本 / 文本 / 空文件）必须返回 None —— 那不是「架构不匹配」，
    /// 拦下它等于把 `#!/bin/sh ./run.sh` 这种正常用法全禁掉。
    #[test]
    fn non_elf_returns_none() {
        let d = tmpdir("nonelf");
        let sh = d.join("run.sh");
        std::fs::write(&sh, b"#!/bin/sh\necho hi\n").unwrap();
        assert_eq!(elf_arch_of(&sh), None, "shell 脚本不该被当成 ELF");
        assert_eq!(exec_arch_mismatch(&d, "run.sh"), None, "脚本必须放行");

        let txt = d.join("app.js");
        std::fs::write(&txt, b"console.log(1)").unwrap();
        assert_eq!(elf_arch_of(&txt), None);

        // 文件不存在
        assert_eq!(elf_arch_of(&d.join("nope")), None);
        assert_eq!(exec_arch_mismatch(&d, "nope"), None);
        // 空文件（读不满 20 字节）
        let e = d.join("empty");
        std::fs::write(&e, b"").unwrap();
        assert_eq!(elf_arch_of(&e), None);
        // 魔数对但 EI_CLASS 非法
        let bad = d.join("badclass");
        let mut b = vec![0u8; 20];
        b[..4].copy_from_slice(&ELF_MAGIC);
        b[4] = 9;
        std::fs::write(&bad, b).unwrap();
        assert_eq!(elf_arch_of(&bad), None);
        std::fs::remove_dir_all(&d).ok();
    }

    /// 架构不符必须给出**具体**原因（能直接告诉用户「这是 aarch64 产物、机器是 x86-64」）。
    #[test]
    fn mismatch_reports_both_architectures() {
        let d = tmpdir("mismatch");
        let p = d.join("app");
        // 挑一个**必然不是本机**的架构来测（编译期确定，不猜）
        let foreign = if host_machine() == "aarch64" { 0x3E } else { 0xB7 };
        write_elf(&p, true, foreign);
        let msg = exec_arch_mismatch(&d, "app").expect("架构不符必须报出原因");
        assert!(msg.contains(host_machine()), "原因里应含本机架构: {msg}");
        assert!(msg.contains(if foreign == 0x3E { "x86-64" } else { "aarch64" }),
            "原因里应含产物架构: {msg}");
        // 绝对路径写法同样能检出（注意：只用**首个 token** 定位可执行文件，
        // `app --flag` 里的 flag 不会被当成路径）
        assert!(
            exec_arch_mismatch(&d, &format!("{} --serve --port 3000", p.display())).is_some(),
            "绝对路径 + 启动参数 应同样检出"
        );
        // 参数里的路径**不被**误当成可执行文件：首 token `app` 解析到
        // workdir/app（外来架构）→ 仍报不匹配，说明 `/bin/true` 没被拿去做检查
        assert!(
            exec_arch_mismatch(&d, "app --config /bin/true").is_some(),
            "只有首个 token 决定可执行文件，参数里的路径不应参与"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    /// 架构一致 → 放行（别把正常应用拦了）。
    #[test]
    fn matching_arch_is_allowed() {
        let d = tmpdir("match");
        let p = d.join("app");
        write_elf(&p, true, match host_machine() {
            "x86-64" => 0x3E,
            "aarch64" => 0xB7,
            "riscv" => 0xF3,
            "arm" => 0x28,
            "x86" => 0x03,
            "loongarch" => 0x102,
            _ => 0x3E,
        });
        assert_eq!(exec_arch_mismatch(&d, "app"), None, "本机架构的产物必须放行");
        std::fs::remove_dir_all(&d).ok();
    }

    /// 相对路径按 WorkingDirectory 解析（systemd 的 `WorkingDirectory=` 语义）。
    #[test]
    fn relative_path_resolved_against_workdir() {
        let d = tmpdir("rel");
        let sub = d.join("bin");
        std::fs::create_dir_all(&sub).unwrap();
        write_elf(&sub.join("app"), true, if host_machine() == "aarch64" { 0x3E } else { 0xB7 });
        assert!(exec_arch_mismatch(&d, "bin/app").is_some(), "相对路径应相对 workdir 解析");
        std::fs::remove_dir_all(&d).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_file_is_0600() {
        let d = std::env::temp_dir().join(format!("panel-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_dir(&d, 0o700).unwrap();
        let f = d.join("k.bin");
        write_private(&f, b"secret", 0o600).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"secret");
        #[cfg(unix)]
        assert_eq!(mode_of(&f).unwrap() & 0o777, 0o600);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn mode_of_missing_file_is_none() {
        assert!(mode_of(Path::new("/definitely/not/here")).is_none());
    }

    #[test]
    fn prune_keeps_newest_and_only_touches_matching_prefix() {
        let d = std::env::temp_dir().join(format!("panel-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_dir(&d, 0o700).unwrap();

        // 三份同名前缀的备份，mtime 依次变旧（0 最新、2 最旧）
        let base = std::time::SystemTime::now();
        for i in 0..3 {
            let f = d.join(format!("sshd.conf.panel.bak-{i}"));
            std::fs::write(&f, b"x").unwrap();
            std::fs::File::options().write(true).open(&f).unwrap()
                .set_modified(base - std::time::Duration::from_secs(i * 10)).unwrap();
        }
        // 同目录但**前缀不同**的文件：绝不能被误删
        let other = d.join("sshd.conf.keepme");
        std::fs::write(&other, b"x").unwrap();

        assert_eq!(prune_keep_newest(&d, "sshd.conf.panel.bak-", 1), 2,
            "保留 1 份 → 应删掉其余 2 份");
        assert!(d.join("sshd.conf.panel.bak-0").exists(), "最新的一份必须留下");
        assert!(!d.join("sshd.conf.panel.bak-1").exists());
        assert!(!d.join("sshd.conf.panel.bak-2").exists());
        assert!(other.exists(), "非本前缀的文件被误删了（前缀匹配失效）");

        // 边界：目录不存在、前缀无匹配，都静默返回 0（清理失败不该打断主操作）
        assert_eq!(prune_keep_newest(Path::new("/definitely/not/here"), "x-", 1), 0);
        assert_eq!(prune_keep_newest(&d, "no-such-prefix-", 1), 0);
        // keep=0 表示"不保留"应视为无效参数，直接不动任何文件
        assert_eq!(prune_keep_newest(&d, "sshd.conf.panel.bak-", 0), 0);

        std::fs::remove_dir_all(&d).ok();
    }
}
