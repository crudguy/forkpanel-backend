use super::*;


#[derive(Default)]
pub struct LinuxUsers;

#[async_trait]
impl UserProvider for LinuxUsers {
    async fn exists(&self, name: &str) -> Result<bool> {
        // 读 /etc/passwd 而非 spawn getent：零子进程
        let s = tokio::fs::read_to_string("/etc/passwd").await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        Ok(s.lines().any(|l| l.split(':').next() == Some(name)))
    }

    /// 确保用户存在（不存在则创建）。**幂等**：已存在直接返回 Ok。
    ///
    /// 参数语义刻意做成显式布尔而非一串选项字符串——调用方在这里能一眼看出
    /// 自己是不是在创建一个「能登录的人」（服务账号应为 `system=true` +
    /// `shell_nologin=true`，否则会给系统开出一个能 SSH 进去的账号）。
    ///
    /// `useradd` 的参数选择：
    /// - `--system`：分配系统 uid（不占用 1000+ 的「真人」区间，也不在 useradd
    ///   默认创建 mail spool / 家目录 —— 服务账号要目录由面板 chown 就够）；
    /// - `--no-create-home`：同上，避免为每个应用在家目录里堆一个空壳目录；
    /// - `--shell /usr/sbin/nologin`：禁止登录。这是**安全底线**：服务账号
    ///   一旦能被 SSH 登录，等于给攻击者留了一个 shell 落点。
    async fn ensure(&self, name: &str, system: bool, shell_nologin: bool) -> Result<()> {
        if self.exists(name).await? {
            return Ok(());
        }
        // 名合法性由业务层 `rules::is_valid_system_user` 保证；这里再挡一道
        // `--` 开头（会被 useradd 当选项）与含空白，防止参数注入。
        if name.is_empty() || name.starts_with('-') || name.contains(char::is_whitespace) {
            return Err(PanelError::Validation { field: "user", reason: format!("非法用户名：{name:?}") });
        }
        // ⚠ **不要传 `--`**：实测 `useradd -- --system …` 直接打 Usage 失败
        //   （useradd 不认「选项结束符」这种 GNU 惯例）。防注入靠上面的名字校验：
        //   名字已过 `is_valid_system_user` 白名单（小写字母数字 _ -，字母/下划线开头），
        //   不可能以 `-` 开头，故不可能被解释成选项。
        let mut args: Vec<String> = Vec::new();
        if system {
            args.push("--system".into());
        }
        args.push("--no-create-home".into());
        if shell_nologin {
            // 发行版的 nologin 路径不同，逐个存在性探测而不是硬编码
            let nologin = ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"]
                .into_iter()
                .find(|p| Path::new(p).exists())
                .unwrap_or("/bin/false");
            args.push("--shell".into());
            args.push(nologin.into());
        }
        args.push(name.into());
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        crate::cmd::run_checked(
            Bin::UserAdd,
            &argv,
            CmdOpt { timeout: Duration::from_secs(20), ..Default::default() },
        ).await.map_err(|e| PanelError::Command {
            bin: "useradd".into(), detail: format!("创建系统用户 {name}: {e}"),
        })?;
        Ok(())
    }

    /// 查 uid/gid。**只读**：读 `/etc/passwd` / `/etc/group`，不 spawn 子进程。
    async fn uid_gid(&self, name: &str) -> Result<(u32, u32)> {
        let passwd = tokio::fs::read_to_string("/etc/passwd").await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        let uid = passwd
            .lines()
            .find_map(|l| {
                let mut f = l.split(':');
                (f.next()? == name).then(|| f.nth(1)?.parse::<u32>().ok())?
            })
            .ok_or_else(|| PanelError::Validation { field: "user", reason: format!("用户不存在：{name}") })?;
        let group = tokio::fs::read_to_string("/etc/group").await.unwrap_or_default();
        // 优先取同名主组（useradd --system 默认建同名组）；找不到再从 gecos 字段
        // 里的主组号兜底（Debian 的 passwd 第 4 列）。
        let gid = group
            .lines()
            .find_map(|l| {
                let mut f = l.split(':');
                (f.next()? == name).then(|| f.nth(2)?.parse::<u32>().ok())?
            })
            .or_else(|| {
                passwd
                    .lines()
                    .find(|l| l.split(':').next() == Some(name))
                    .and_then(|l| l.split(':').nth(3))
                    .and_then(|s| s.parse::<u32>().ok())
            })
            .ok_or_else(|| PanelError::Validation { field: "user", reason: format!("找不到用户 {name} 的组") })?;
        Ok((uid, gid))
    }

    /// 枚举本机全部账户。**只读**：直接解析 `/etc/passwd`（零子进程）。
    ///
    /// 过滤掉破损行（字段不足 7 列 / uid·gid 非数字 / 空名），不让脏数据污染下拉。
    /// 结果按 uid 升序，便于 UI 稳定展示。
    async fn list(&self) -> Result<Vec<SystemUser>> {
        const NOLOGIN: &[&str] = &[
            "/usr/sbin/nologin", "/sbin/nologin",
            "/bin/false", "/usr/bin/false", "/dev/null",
        ];
        let s = tokio::fs::read_to_string("/etc/passwd").await
            .map_err(|e| PanelError::Internal(e.to_string()))?;
        let mut users = Vec::new();
        for line in s.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 { continue; }
            let name = f[0];
            if name.is_empty() { continue; }
            let uid: u32 = match f[2].parse() { Ok(u) => u, Err(_) => continue };
            let gid: u32 = match f[3].parse() { Ok(g) => g, Err(_) => continue };
            let shell = f[6].to_string();
            let login_allowed = !NOLOGIN.contains(&shell.as_str());
            users.push(SystemUser { name: name.to_string(), uid, gid, shell, login_allowed });
        }
        users.sort_by_key(|a| a.uid);
        Ok(users)
    }
}

// 未在 stub 中使用的导入显式标记，避免 dead_code 警告干扰评审
#[allow(dead_code)]
fn _assert_types(_: Option<UnitName>) {}


#[cfg(test)]
mod user_provider_tests {
    use super::*;

    /// 枚举本机账户：读真实 /etc/passwd（测试数据 = 线上形态），验证解析与 login_allowed 判定。
    #[tokio::test]
    async fn linux_users_list_parses_passwd() {
        let users = LinuxUsers.list().await.expect("list 不应失败");
        assert!(!users.is_empty(), "本机应至少枚举到 root 等账户");

        let root = users.iter().find(|u| u.name == "root").expect("应有 root 账户");
        assert_eq!(root.uid, 0);
        assert!(root.login_allowed, "root 属可登录 shell，login_allowed 应为 true");

        // 服务账号（如 www-data）应为 nologin/false，login_allowed 必须 false
        if let Some(www) = users.iter().find(|u| u.name == "www-data") {
            assert!(!www.login_allowed, "www-data 是服务账号，login_allowed 应为 false");
        }

        // 结果按 uid 升序，UI 展示稳定
        for w in users.windows(2) {
            assert!(w[0].uid <= w[1].uid, "应按 uid 升序");
        }

        // 每个条目字段都该填满，不存在空名
        for u in &users {
            assert!(!u.name.is_empty(), "账户名不应为空");
        }
    }

    /// A8 回归：文件源的 level 筛选必须生效（此前 ReadQ.level 一路传到 provider 却被丢弃）。
    /// 数据与断言刻意让「文本含 error」的行只有一条——若筛选被绕过，条数立刻对不上。
    #[test]
    fn read_file_tail_applies_level_filter() {
        let d = std::env::temp_dir().join(format!("panel-loglvl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("app.log");
        std::fs::write(&f, "started ok\nconnection failed\nserved request\nwarn: disk low\nboom panic\n").unwrap();

        let base = LogQuery { lines: 100, grep: None, level: None, follow: false, since_unix: None };

        // 不筛：5 行全在
        assert_eq!(read_file_tail(&f, 100, None, &base).len(), 5);

        // level=error：只有 "connection failed" 与 "boom panic"（文本兜底口径）
        let errs = read_file_tail(&f, 100, None,
            &LogQuery { level: Some("error".into()), ..base.clone() });
        assert_eq!(errs.len(), 2, "error 档应命中 2 行：{errs:?}");
        assert!(errs.iter().all(|l| l.text.contains("failed") || l.text.contains("panic")));

        // level=warn：仅 "warn: disk low"
        let warns = read_file_tail(&f, 100, None,
            &LogQuery { level: Some("warn".into()), ..base.clone() });
        assert_eq!(warns.len(), 1, "warn 档应命中 1 行：{warns:?}");

        // level=info：不匹配任何行（"started ok"/"served request" 归 other）
        assert_eq!(read_file_tail(&f, 100, None,
            &LogQuery { level: Some("info".into()), ..base.clone() }).len(), 0);

        // level 与 grep 叠加：先文本子串再档位
        let both = read_file_tail(&f, 100, Some("disk"),
            &LogQuery { level: Some("warn".into()), ..base.clone() });
        assert_eq!(both.len(), 1);

        // 文件源行无时间戳：since 命中不了任何行（诚实语义，前端按数据禁用该控件）
        let since = read_file_tail(&f, 100, None,
            &LogQuery { since_unix: Some(1), ..base.clone() });
        assert!(since.is_empty(), "无时间戳的源 + since 应返回空，而非静默忽略筛选");

        std::fs::remove_dir_all(&d).ok();
    }
}
