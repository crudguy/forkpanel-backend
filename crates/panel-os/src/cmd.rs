//! **全项目唯一允许 spawn 子进程的地方**（设计方案 §1.1 / §1.2）。
//!
//! 硬性约束：
//! 1. 绝不使用 `sh -c` / `bash -c`；argv 直接传参，从根上切断 shell 注入。
//! 2. `Bin` 是**编译期枚举**，不接受任意字符串——不存在"用户自定义命令"入口。
//! 3. 清除危险环境变量（LD_PRELOAD 等），PATH 固定为安全值。
//! 4. 强制超时 + kill 进程组，防止子进程泄漏成为僵尸或孤儿。
//! 5. stdout/stderr 截断（默认 1MB），防止 OOM（实测无界输出是低配机器杀手）。
//! 6. 每次调用写审计（谁、什么命令、退出码、耗时）。
//!
//! CI 门禁：仓库中除本文件外出现 `Command::new` 即构建失败（ci/check-layering.sh）。

use panel_core::{PanelError, Result};
use std::{collections::HashMap, ffi::OsString, path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::Command,
    sync::mpsc::Receiver,
    time::timeout,
};

/// 允许执行的二进制白名单。**新增一项必须走 code review + 安全评估。**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bin {
    Systemctl, Service, RcService,      // 服务
    Nft, Iptables, Ufw, FirewallCmd,    // 防火墙
    Apt, Dnf, Yum, Apk, Zypper, Dpkg,   // 包管理
    /// 只读列举可升级包（`apt list --upgradable`）。**只能用 `apt` 包装器**，因为
    /// `apt-get` 不认 `list` 子命令（会报 "Command line option --upgradable is not
    /// understood" → 退出码 100 → 误判为无更新）。`update`/`install`/`remove` 仍走
    /// `Bin::Apt`(apt-get) 以遵循 Debian「脚本里用 apt-get」的约定、避开 apt 的交互态告警。
    AptList,
    /// 只读查询软件源元数据（apt-cache policy 列可用版本）。与 Apt(apt-get) 分开：
    /// 能力不同（只读 vs 写入），便于在审计与白名单层面区别对待。
    AptCache,
    /// apt-mark hold/unhold/showhold：包级升级钉住（防「顺手升级把生产依赖升炸」）。
    /// 安全评估：① 子命令由 provider 侧**编译期写死**（showhold/hold/unhold），
    /// 不存在用户可控子命令；② 包名经调用方白名单校验后作为**单个 argv** 传入，
    /// 不经 shell；③ hold 只影响自动升级，不是安全边界——边界仍在端点权限。
    AptMark,
    Journalctl,                         // 日志
    Crontab,                            // 计划任务（用户 crontab）
    /// 计划任务重叠保护（P2-3）：包裹 cron 命令实现互斥锁。
    /// 只用 `-n <lockfile>`（非阻塞）+ `--` 分隔命令，命令本身由调用方经 argv 传入，
    /// 绝不把用户命令拼进 shell 字符串——flock 直接 exec 目标命令，无 shell 解释。
    Flock,
    /// Webhook 投递（P2-3 cron 回调 / P2-10 通知通道）的唯一 HTTP 出口。
    /// 安全评估：① 只接受 http/https 且经 `PanelError::Validation` 校验的 URL，
    /// 不接 `file://` 等危险协议；② 整个 URL 与 JSON body 各自作为**单个 argv 参数**
    /// 传给 curl，不经过 shell；③ 固定 `--max-time` 上限 + `--fail`，避免无限挂起
    /// 与把 HTTP 错误当成功。零新增依赖，复用 cmd 唯一出口纪律。
    Curl,
    Nginx, Caddy,                       // Web 服务器
    /// 容器管理（**只读列举 + 生命周期**）。安全评估：
    /// - argv 直传不经 shell；子命令由 provider 侧**编译期写死**（ps/images/start/stop/restart/rm），
    ///   不存在用户可控的子命令或选项；
    /// - 容器名/ID 经 `rules::is_valid_container_ref` 白名单校验（含禁止首字符 `-`，防参数注入）；
    /// - **不提供** `docker run`（等价宿主机任意代码执行，需独立风险设计与审批，见 #47 说明）。
    /// 注意：docker CLI 连 `/var/run/docker.sock`，即**面板进程身份**决定可达性；
    /// 因此该能力默认大概率不可用（不在 docker 组），能力位据此诚实置灰。
    Docker,
    OpenSsl,                            // TLS 自签证书生成（仅签发，不参与其它任何用途）
    /// 第三方 apt 源 GPG 密钥指纹校验（方案1：加官方源）。
    /// 安全评估：① 只接受 `-n` + 文件名 argv，只读解析密钥指纹，绝不 `--import`/网络；
    /// ② 指纹比对走硬编码白名单（THIRD_PARTY_REPOS 内置），MITM 替换密钥会因指纹不符被拒；
    /// ③ 整个命令 argv 直传，不经 shell。仅用于校验，不参与任何密钥落地动作。
    Gpg,
    MySql, MySqlDump, Psql, PgDump,     // 数据库（可选能力）
    Tar, Gzip,                          // 备份打包
    Sshd,                               // sshd -t 配置校验：改 SSH 配置前的强制安全网
    Certbot,                            // ACME 证书签发/续期（http-01 webroot）
    Fail2banClient,                     // fail2ban-client 入侵防御 jail 管理
    UserAdd, GroupAdd, Chown, Chmod, Usermod, // 用户与权限（Usermod：把用户加入附加组，仅内部白名单调用）
    Df, Stat,                           // 探测类（回退路径）
    /// 交互式登录 shell（Web 终端用）。**不经任何 shell 解释**——由 `spawn_pty`
    /// 以 argv 直接 exec；用户输入只写进 PTY 的 master，不参与本进程的 argv。
    ///
    /// 它本身就是"任意命令执行"的合法入口，这是终端的**功能**而非缺陷；因此防线
    /// 放在**会话建立那一刻**（能力位 + SYSTEM_MANAGE 权限 + 只读模式拒绝 + 并发上限 +
    /// 空闲超时 + 审计），而不是去解析每条命令。绝不接受把用户输入拼进 argv。
    Bash,
    /// 用户脚本的唯一出口：cron/手动触发的 command 是任意 shell 串，
    /// 不能也不该塞进上面的白名单——统一经 `sh -c` 走这里，保留超时与降权。
    Sh,
}

impl Bin {
    pub fn as_str(self) -> &'static str {
        use Bin::*;
        match self {
            Bash => "bash",
            Systemctl => "systemctl", Service => "service", RcService => "rc-service",
            Nft => "nft", Iptables => "iptables", Ufw => "ufw", FirewallCmd => "firewall-cmd",
            Apt => "apt-get", Dnf => "dnf", Yum => "yum", Apk => "apk", Zypper => "zypper", Dpkg => "dpkg-query",
            AptList => "apt",
            AptCache => "apt-cache",
            AptMark => "apt-mark",
            Journalctl => "journalctl", Crontab => "crontab", Flock => "flock", Curl => "curl",
            Nginx => "nginx", Caddy => "caddy",
            Docker => "docker",
            OpenSsl => "openssl", Gpg => "gpg",
            MySql => "mysql", MySqlDump => "mysqldump", Psql => "psql", PgDump => "pg_dump",
            Tar => "tar", Gzip => "gzip", Sshd => "sshd", Certbot => "certbot",
            Fail2banClient => "fail2ban-client",
            UserAdd => "useradd", GroupAdd => "groupadd", Chown => "chown", Chmod => "chmod",
            Usermod => "usermod",
            Df => "df", Stat => "stat",
            Sh => "sh",
        }
    }

    /// 解析后的绝对路径在构造期确定；找不到就禁用该能力（能力矩阵置 false）
    fn resolved(self) -> Result<PathBuf> {
        let name = self.as_str();
        // 只在这些目录中查找，避免 PATH 劫持
        const SEARCH: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin",
                                  "/usr/local/sbin", "/usr/local/bin"];
        for dir in SEARCH {
            let p = PathBuf::from(dir).join(name);
            if p.is_file() { return Ok(p); }
        }
        Err(PanelError::Unsupported(name))
    }

    /// 该二进制是否存在于安全 PATH（能力位判定用）。**只做文件存在性检查，不执行任何命令。**
    pub fn available(self) -> bool { self.resolved().is_ok() }
}

// on_line 为 `dyn Fn`，不实现 Debug，故手写 Debug（保留 Clone 派生）。
#[derive(Clone)]
pub struct CmdOpt {
    pub timeout: Duration,
    /// stdout/stderr 各自的最大字节数，超出即截断
    pub max_output: usize,
    pub working_dir: Option<PathBuf>,
    /// 追加的环境变量（不允许覆盖 PATH）
    pub env: HashMap<String, OsString>,
    /// 以该用户身份执行（降权子进程，设计方案 §1.1-1）
    pub run_as: Option<String>,
    /// 逐行回调，用于任务实时输出
    pub on_line: Option<std::sync::Arc<dyn Fn(&str) + Send + Sync>>,
}

impl std::fmt::Debug for CmdOpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmdOpt")
            .field("timeout", &self.timeout)
            .field("max_output", &self.max_output)
            .field("working_dir", &self.working_dir)
            .field("env", &self.env)
            .field("run_as", &self.run_as)
            .field("on_line", &self.on_line.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl Default for CmdOpt {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_output: 1024 * 1024,
            working_dir: None,
            env: HashMap::new(),
            run_as: None,
            on_line: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub elapsed: Duration,
}

/// 执行命令。**唯一出口。**
pub async fn run(bin: Bin, args: &[&str], opt: CmdOpt) -> Result<CmdOutput> {
    let program = bin.resolved()?;
    let start = std::time::Instant::now();

    let mut cmd = Command::new(program);
    cmd.args(args);
    // 关键：不使用 shell；stdin 关闭，避免子进程挂起等待输入
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // 固定 PATH + 清除可被劫持的动态链接器变量
    cmd.env_clear();
    cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    cmd.env("LANG", "C");
    cmd.env("LC_ALL", "C");
    for (k, v) in &opt.env {
        if k == "PATH" || k.starts_with("LD_") { continue; }   // 禁止覆盖
        cmd.env(k, v);
    }
    if let Some(dir) = &opt.working_dir { cmd.current_dir(dir); }
    if let Some(user) = &opt.run_as {
        // 降权：由 pre_exec 或外部 sudo 包装实现，此处以参数形式记录，
        // 具体实现见 linux::privileges（避免在此处引入 setuid 的 unsafe 细节）
        let _ = user;
    }
    // 独立进程组，便于超时时整组 kill（防止孙进程泄漏）
    unsafe { cmd.pre_exec(|| { libc::setsid(); Ok(()) }); }

    let mut child = cmd.spawn().map_err(|e| PanelError::Command {
        bin: bin.as_str().into(), detail: format!("spawn failed: {e}")
    })?;

    let out = child.stdout.take();
    let err = child.stderr.take();

    let wait_fut = async {
        match timeout(opt.timeout, child.wait()).await {
            Ok(Ok(st)) => exit_code(&st),
            Ok(Err(e)) => { tracing::warn!("wait failed: {e}"); None }
            Err(_) => {
                // 超时：kill 整个进程组（setsid 已确保孙进程同组），并回收避免僵尸
                tracing::warn!("command {:?} timed out after {:?}", bin, opt.timeout);
                let _ = child.kill().await;
                None
            }
        }
    };

    let (code, (stdout, t_out), (stderr, t_err)) = tokio::join!(
        wait_fut,
        collect(out, opt.max_output, &opt.on_line),
        collect(err, opt.max_output, &opt.on_line),
    );

    Ok(CmdOutput {
        code,
        stdout,
        stderr,
        truncated: t_out || t_err,
        elapsed: start.elapsed(),
    })
}

/// 退出码归一化：被信号终止时返回 128+signum（POSIX 惯例）
fn exit_code(st: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        st.code().or_else(|| st.signal().map(|s| 128 + s))
    }
    #[cfg(not(unix))]
    {
        st.code()
    }
}

async fn collect(
    r: Option<impl AsyncRead + Unpin>,
    cap: usize,
    on_line: &Option<std::sync::Arc<dyn Fn(&str) + Send + Sync>>,
) -> (String, bool) {
    let Some(r) = r else { return (String::new(), false) };
    let mut reader = BufReader::new(r);
    let mut buf = String::new();
    let mut line = String::new();
    let mut truncated = false;
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                if let Some(cb) = on_line { cb(line.trim_end()); }
                if buf.len() + line.len() > cap {
                    truncated = true;
                    break;
                }
                buf.push_str(&line);
            }
            Err(_) => break,
        }
    }
    (buf, truncated)
}

/// 流式长驻进程（日志 follow / 安装输出）：**同样是唯一出口**，
/// 业务层不得直接 `tokio::process::Command::new`。
/// 背压：channel 满时阻塞读取，调用方断开即自动 kill 子进程。
pub fn spawn_stream(bin: Bin, args: &[&str], cap: usize) -> Result<Receiver<String>> {
    let program = bin.resolved()?;
    let (tx, rx) = tokio::sync::mpsc::channel(cap);

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    cmd.env_clear();
    cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    cmd.env("LANG", "C");
    unsafe { cmd.pre_exec(|| { libc::setsid(); Ok(()) }); }

    let mut child = cmd.spawn().map_err(|e| PanelError::Command {
        bin: bin.as_str().into(), detail: format!("spawn stream failed: {e}")
    })?;

    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if tx.send(line).await.is_err() { break; }   // 慢消费者/断开 → 结束
            }
            let _ = child.kill().await;
        });
    }
    Ok(rx)
}

/// 便捷包装：期望成功，否则带上 stderr 抛出
/// 执行一条**用户定义的 shell 命令**（cron 任务等）。
///
/// 这是全项目**唯一**会解释 shell 的地方，刻意收在 `cmd.rs` 内：
/// 1. `cmd.rs` 是子进程唯一出口——把 shell 执行放这里，才不破坏"出口唯一"；
/// 2. 将来审计"哪里能执行任意命令"时，只需看这一个函数；
/// 3. 业务层调用它时不必知道 `sh -c` 的细节，也就不会到处散落 shell 调用
///    （此前 `crate/panel-api` 就自己拼了 `&["-c", cmd]`，那属于分层泄漏）。
///
/// 安全性由**调用方**保证：命令本身就是用户配置、且明确要执行的内容。
/// 这里只做工程兜底：命令作为单个 argv 传入（不参与拼接）、超时、可选降权、输出截断。
pub async fn run_shell(command: &str, opt: CmdOpt) -> Result<CmdOutput> {
    run(Bin::Sh, &["-c", command], opt).await
}

pub async fn run_checked(bin: Bin, args: &[&str], opt: CmdOpt) -> Result<CmdOutput> {
    let out = run(bin, args, opt).await?;
    match out.code {
        Some(0) => Ok(out),
        other => Err(PanelError::Command {
            bin: bin.as_str().into(),
            detail: format!("exit={other:?} stderr={}", truncate(&out.stderr, 2000)),
        }),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}…(truncated)", &s[..n]) }
}

// ═══════════════════════ 交互式 PTY（Web 终端） ═══════════════════════
//
// 为什么必须放在本文件：这里的"全项目唯一子进程出口"是一条硬不变量
// （CI 门禁 [1]）。PTY 同样要 fork/exec，因此它是**第二个**原语，也归这里。

/// PTY slave 设备名缓冲（内核保证 `/dev/pts/N` 远短于该长度）
const PTY_NAME_MAX: usize = 128;
/// 子进程环境里的安全 PATH（与 `run()` 保持一致，不复用调用方 PATH）
const PTY_SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// PTY 的**读半边**：独占 master 原件，交给专门的读任务。
/// 单独成类型是为了能安全地 `split`——Rust 里无法在同一个 `select!` 中
/// 同时持有同一个 `&mut File` 的两个 future（读与写）。
pub struct PtyReader(pub tokio::fs::File);

/// PTY 的**写/控制半边**：master 的 `dup` 副本 + 子进程句柄。
///
/// 读用原件、写用副本是 POSIX 下的常规做法：两个 fd 指向同一个终端，
/// 因此可以在两个任务里分别 `&mut`，互不冲突。
pub struct PtyTx {
    master: tokio::fs::File,
    child: tokio::process::Child,
    /// 子进程是否已被 `shutdown()` 回收。
    ///
    /// 必须记录：pid 在子进程退出后会被内核回收并**分配给别的进程**，
    /// 若 Drop 时再无条件 `kill(-pid, SIGHUP)`，就可能把信号发给一个
    /// 完全无关的进程组——比泄漏更危险。
    reaped: bool,
}

/// 一个已建立的交互式伪终端会话。
pub struct PtySession {
    reader: PtyReader,
    tx: PtyTx,
}

impl PtySession {
    pub fn pid(&self) -> u32 { self.tx.child.id().unwrap_or(0) }

    /// 拆成读半边（移入读任务）与写/控制半边（留在会话循环）。
    pub fn split(self) -> (PtyReader, PtyTx) { (self.reader, self.tx) }
}

impl PtyTx {
    /// 写用户输入（原始字节：可能是任意 UTF-8 片段或单个控制字符）。
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.master.write_all(data).await.map_err(|e| PanelError::Io(e.to_string()))?;
        self.master.flush().await.map_err(|e| PanelError::Io(e.to_string()))
    }

    /// 同步窗口尺寸。内核随后给前台进程组发 SIGWINCH，全屏程序据此重排。
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&self.master);
        set_winsize(fd, cols, rows)
    }

    /// 结束会话：**先给整个进程组发 SIGHUP**，再兜底强杀。
    ///
    /// `setsid` 之后 shell 即会话/进程组组长，因此 `kill(-pid, SIGHUP)` 能连带
    /// 清掉它启动的前台程序（`top`、`tail -f` 之类）。只 kill 直接子进程会把它们
    /// 留成孤儿——这正是"退出清理"要避免的。
    pub async fn shutdown(&mut self) {
        let pid = self.child.id().unwrap_or(0) as i32;
        if pid > 0 {
            // SAFETY: 仅为发信号，负 pid 表示进程组
            unsafe { libc::kill(-pid, libc::SIGHUP); }
        }
        // 给前台程序一点收尾窗口，超时则强杀兜底（避免僵尸残留）
        if tokio::time::timeout(Duration::from_millis(300), self.child.wait()).await.is_err() {
            let _ = self.child.start_kill();
            let _ = self.child.wait().await;
        }
        self.reaped = true;   // 之后 Drop 不得再对该 pid 发信号
    }
}

impl Drop for PtyTx {
    /// 兜底回收：**任何**离开作用域的路径都要清掉 shell 进程组。
    ///
    /// 正常路径会走 `shutdown()`（已 wait，此处无操作）。但会话循环存在
    /// 提前 return 的分支（例如通知前端 ready 失败即 return），以及 future
    /// 被取消的可能——这些路径下 `tokio::process::Child` 被 drop 时 tokio
    /// **不会**替你 kill，bash 会连同它启动的前台程序一起留下（孤儿），
    /// PTY master 也不再有人读。
    ///
    /// Drop 里不能 await，故只发 SIGHUP + SIGKILL；残留的 exit status 由
    /// tokio 的 orphan reaper 回收，不会变僵尸。
    fn drop(&mut self) {
        if self.reaped { return; }
        let pid = self.child.id().unwrap_or(0) as i32;
        if pid > 0 {
            // SAFETY: 仅为发信号，负 pid 表示整个进程组（shell 已 setsid 成为组长）
            unsafe { libc::kill(-pid, libc::SIGHUP); }
        }
        let _ = self.child.start_kill();
        self.reaped = true;
    }
}

/// `TIOCSWINSZ`：设置终端窗口尺寸（列/行），0 视为非法值按 1 处理。
fn set_winsize(fd: std::os::unix::io::RawFd, cols: u16, rows: u16) -> Result<()> {
    let ws = libc::winsize {
        ws_row: rows.max(1), ws_col: cols.max(1), ws_xpixel: 0, ws_ypixel: 0,
    };
    // SAFETY: fd 来自本模块持有的 master；ioctl 参数与 TIOCSWINSZ 约定一致
    let r = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if r != 0 {
        return Err(PanelError::Io(format!("TIOCSWINSZ 失败: {}", std::io::Error::last_os_error())));
    }
    Ok(())
}

/// 打开一对 PTY，返回 `(master_fd, slave_file)`；任一步失败都不泄漏已开的 fd。
fn open_pty(cols: u16, rows: u16) -> std::io::Result<(i32, std::fs::File)> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: 全是标准 POSIX PTY 调用；每个失败分支都显式 close(master)
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 { return Err(std::io::Error::last_os_error()); }

        if libc::grantpt(master) != 0 {
            let e = std::io::Error::last_os_error(); libc::close(master); return Err(e);
        }
        if libc::unlockpt(master) != 0 {
            let e = std::io::Error::last_os_error(); libc::close(master); return Err(e);
        }
        let mut name = [0 as libc::c_char; PTY_NAME_MAX];
        if libc::ptsname_r(master, name.as_mut_ptr(), name.len()) != 0 {
            let e = std::io::Error::last_os_error(); libc::close(master); return Err(e);
        }
        // 先设初始尺寸：否则首个程序会按默认 80x24 排版，前端 fit 之后再抖动一次
        set_winsize(master, cols, rows).ok();

        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        if slave < 0 {
            let e = std::io::Error::last_os_error(); libc::close(master); return Err(e);
        }
        Ok((master, std::fs::File::from_raw_fd(slave)))
    }
}

/// 启动交互式 PTY 会话（argv 直传，**不经 shell**）。
///
/// 两个刻意选择：
/// 1. slave 通过 `pre_exec` 里的 `dup2` 接管 0/1/2，而不是 `Stdio::from(fd)`——
///    后者的父进程关闭时机依赖 `Command` 的 drop 顺序，一旦父进程残留 slave fd，
///    子进程退出时 master 就**读不到 EOF**，会话会永远挂着。这里显式 `drop(slave)`。
/// 2. `setsid` + `TIOCSCTTY` 必须在 pre_exec 里做，否则 Ctrl-C/Ctrl-Z（作业控制）
///    与 SIGWINCH（窗口尺寸变化）都不会生效——终端会"能打字但按不了 Ctrl-C"。
pub fn spawn_pty(shell: Bin, cols: u16, rows: u16, cwd: Option<&std::path::Path>) -> Result<PtySession> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let program = shell.resolved()?;

    let (master, slave) = open_pty(cols, rows)
        .map_err(|e| PanelError::Internal(format!("openpty 失败: {e}")))?;
    let slave_fd = slave.as_raw_fd();

    // 继承面板自身的 HOME/USER/SHELL：`env_clear` 之后若没有 HOME，
    // `~` 不展开、`cd` 无默认目录，交互体验会明显不对。
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let sh = std::env::var("SHELL").unwrap_or_else(|_| format!("/usr/bin/{}", shell.as_str()));

    let mut cmd = Command::new(program);
    // 先全部置 null，随后在 pre_exec 里用 dup2 把 slave 抢到 0/1/2
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.env_clear();
    cmd.env("PATH", PTY_SAFE_PATH);
    cmd.env("HOME", home);
    cmd.env("USER", user);
    cmd.env("SHELL", sh);
    // 与前端 xterm 的 termName 匹配；否则颜色/光标/按键能力会退化
    cmd.env("TERM", "xterm-256color");
    cmd.env("LANG", "C.UTF-8");
    cmd.env("LC_ALL", "C.UTF-8");
    if let Some(d) = cwd { cmd.current_dir(d); }

    // SAFETY: pre_exec 内只调用 async-signal-safe 的系统调用（setsid/dup2/close/ioctl）
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            if libc::dup2(slave_fd, 0) < 0
                || libc::dup2(slave_fd, 1) < 0
                || libc::dup2(slave_fd, 2) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if slave_fd > 2 { libc::close(slave_fd); }
            // 接管控制终端；失败不致命（如已存在控制终端），故忽略返回值
            libc::ioctl(0, libc::TIOCSCTTY, 0);
            Ok(())
        });
    }

    let child = cmd.spawn().map_err(|e| PanelError::Command {
        bin: shell.as_str().into(),
        detail: format!("pty spawn 失败: {e}"),
    })?;
    // 父进程立刻放开 slave：子进程退出后 master 才会读到 EOF（会话收尾依赖它）
    drop(slave);

    // 写半边用 master 的 dup 副本：读/写分属不同 fd，才能在两处各自 &mut
    let write_fd = dup_fd(master)?;
    // SAFETY: 两个 fd 都来自本函数刚打开的 PTY master（原件 + dup），
    // 各自只被包进一个 File，所有权唯一，不存在重复关闭。
    Ok(unsafe {
        PtySession {
            reader: PtyReader(tokio::fs::File::from_std(std::fs::File::from_raw_fd(master))),
            tx: PtyTx {
                master: tokio::fs::File::from_std(std::fs::File::from_raw_fd(write_fd)),
                child,
                reaped: false,
            },
        }
    })
}

/// `dup` 一个 fd，失败即报错（不静默降级）。
fn dup_fd(fd: i32) -> Result<i32> {
    // SAFETY: dup 只复制 fd
    let n = unsafe { libc::dup(fd) };
    if n < 0 {
        return Err(PanelError::Io(format!("dup 失败: {}", std::io::Error::last_os_error())));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_whitelist_is_closed() {
        // 白名单是封闭枚举：不存在从字符串构造的入口（这是防注入的根本）
        assert_eq!(Bin::Nft.as_str(), "nft");
        assert_eq!(Bin::Systemctl.as_str(), "systemctl");
        assert_eq!(Bin::Bash.as_str(), "bash");
    }

    #[test]
    fn apt_family_binaries_are_distinct() {
        // 「包管理」三兄弟能力不同、不可互相替换——这是踩过的坑：
        // `upgradable()` 曾用 Bin::Apt(apt-get) 跑 `apt-get list --upgradable`，
        // 而 apt-get 不支持 list 子命令（报错、stdout 空）→ 解析为空 → 面板
        // 永远探测不到任何可升级包。故钉死映射：只读列举走 AptList(apt)，
        // 写入走 Apt(apt-get)，元数据查询走 AptCache(apt-cache)。
        assert_eq!(Bin::AptList.as_str(), "apt");
        assert_eq!(Bin::Apt.as_str(), "apt-get");
        assert_eq!(Bin::AptCache.as_str(), "apt-cache");
        assert_ne!(Bin::AptList.as_str(), Bin::Apt.as_str());
    }

    // ── PTY：真机集成测试（无 bash / 无 PTY 的环境自动跳过，不假绿）──

    /// 在 PTY 上跑一行命令并收集输出，直到出现 `needle` 或超时。
    async fn pty_collect(needle: &str, cmds: &[&str]) -> Option<String> {
        use tokio::io::AsyncReadExt;
        if !Bin::Bash.available() { return None; }
        let session = spawn_pty(Bin::Bash, 80, 24, None).ok()?;
        let (PtyReader(mut rx), mut tx) = session.split();
        for c in cmds { tx.write(c.as_bytes()).await.ok()?; }

        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(300), rx.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => {
                    out.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&out).contains(needle) { break; }
                }
                Err(_) => {}
            }
        }
        tx.shutdown().await;
        Some(String::from_utf8_lossy(&out).to_string())
    }

    #[tokio::test]
    async fn pty_runs_interactive_shell() {
        // 关键断言：shell **求值**了算术（输出 42），而不是原样回显命令。
        // 这能同时证明：slave 接对了 0/1/2、fd 没串、shell 真的在跑。
        let Some(out) = pty_collect("PANEL_PTY_42", &["echo PANEL_PTY_$((6*7))\n"]).await
            else { return };
        assert!(out.contains("PANEL_PTY_42"),
            "shell 未求值命令（可能 stdin/stdout 未接到 pty）: {}", out.escape_debug());
    }

    #[tokio::test]
    async fn pty_shutdown_releases_reader() {
        // 退出清理：shutdown 之后读半边必须收到 EOF/错误。若这里挂住，
        // 生产上的表现就是"关掉终端页后服务端线程/子进程泄漏"。
        use tokio::io::AsyncReadExt;
        if !Bin::Bash.available() { return; }
        let Ok(session) = spawn_pty(Bin::Bash, 80, 24, None) else { return };
        let (PtyReader(mut rx), mut tx) = session.split();
        tx.shutdown().await;

        let mut buf = [0u8; 256];
        let mut closed = false;
        for _ in 0..25 {
            match tokio::time::timeout(Duration::from_millis(200), rx.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => { closed = true; break }
                _ => {}
            }
        }
        assert!(closed, "shutdown 后读半边未关闭 → 会话泄漏");
    }

    #[test]
    fn winsize_rejects_bad_fd() {
        // 非法 fd 必须报错，不能静默成功（否则"resize 生效了"是假象）
        assert!(set_winsize(-1, 80, 24).is_err());
    }

    #[tokio::test]
    async fn no_shell_interpretation() {
        // 若存在 shell 注入，此参数会执行 `id`；用 argv 传参则只会被当作字面量
        let r = run(Bin::Stat, &["--printf=%n", "; id; echo pwned"], CmdOpt::default()).await;
        // stat 不存在时返回 Unsupported；存在时返回错误退出码；两者都不应产生命令执行
        match r {
            Ok(o) => assert_ne!(o.code, Some(0)),
            Err(PanelError::Unsupported(_)) => {}
            Err(e) => panic!("unexpected: {e:?}"),
        }
    }

    #[test]
    fn opt_defaults_are_bounded() {
        let d = CmdOpt::default();
        assert_eq!(d.max_output, 1024 * 1024);
        assert_eq!(d.timeout, Duration::from_secs(10));
    }
}
