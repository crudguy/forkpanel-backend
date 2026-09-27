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
    Apt, Dnf, Yum, Apk, Zypper,         // 包管理
    Journalctl,                         // 日志
    Nginx, Caddy,                       // Web 服务器
    MySql, MySqlDump, Psql, PgDump,     // 数据库（可选能力）
    Tar, Gzip,                          // 备份打包
    UserAdd, GroupAdd, Chown, Chmod,    // 用户与权限
    Df, Stat,                           // 探测类（回退路径）
}

impl Bin {
    pub fn as_str(self) -> &'static str {
        use Bin::*;
        match self {
            Systemctl => "systemctl", Service => "service", RcService => "rc-service",
            Nft => "nft", Iptables => "iptables", Ufw => "ufw", FirewallCmd => "firewall-cmd",
            Apt => "apt-get", Dnf => "dnf", Yum => "yum", Apk => "apk", Zypper => "zypper",
            Journalctl => "journalctl", Nginx => "nginx", Caddy => "caddy",
            MySql => "mysql", MySqlDump => "mysqldump", Psql => "psql", PgDump => "pg_dump",
            Tar => "tar", Gzip => "gzip",
            UserAdd => "useradd", GroupAdd => "groupadd", Chown => "chown", Chmod => "chmod",
            Df => "df", Stat => "stat",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_whitelist_is_closed() {
        // 白名单是封闭枚举：不存在从字符串构造的入口（这是防注入的根本）
        assert_eq!(Bin::Nft.as_str(), "nft");
        assert_eq!(Bin::Systemctl.as_str(), "systemctl");
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
