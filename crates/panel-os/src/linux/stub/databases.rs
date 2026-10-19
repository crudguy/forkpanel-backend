use super::*;


/// 内建 SQLite 浏览：**只读**打开 `.db` 文件 → 列库/表/行。
///
/// 边界（诚实声明，不撒谎）：
/// - SQLite 为内建引擎（浏览 + 只读 SQL 控制台均已实装，无需外部客户端）；
/// - PostgreSQL 浏览与只读 SQL 控制台均已实装，但都经 `psql` 外部客户端，
///   且**只读靠 `PGOPTIONS=default_transaction_read_only=on` 会话护栏**
///   （见 `PG_READONLY_ENV` 的残余风险记录）；
/// - MySQL 浏览已实装（经 `mysql` 客户端），但**只读 SQL 控制台未实装**——
///   没有服务端物理只读护栏可用，见 `query()` 的 MySql 分支；
/// - 一律以 `SQLITE_OPEN_READ_ONLY` 打开（浏览不该改库）；
/// - 表名等不可参数化处一律双引号转义（`quote_ident`），LIMIT/OFFSET 走参数绑定；
/// - rusqlite 是同步阻塞 API，全部经 `spawn_blocking` 执行，绝不阻塞 async 运行时。
#[derive(Default)]
pub struct LinuxDatabases;

impl LinuxDatabases {
    /// 用外部客户端执行一条**只读** SQL，按 TAB 分列返回结果行。
    ///
    /// **凭据经环境变量传递**（`MYSQL_PWD` / `PGPASSWORD`），绝不放 argv——
    /// argv 会被同机任意用户的 `ps` 看到，等于直接泄露数据库口令。
    /// 用于浏览路径（库/表/行数/列名）与 PG 只读控制台（后者另走
    /// `sql_query_console`，要拿列名）。MySQL 的连接不是只读的，故不接控制台。
    pub(crate) async fn sql_query(t: &DbTarget, sql: &str) -> Result<Vec<Vec<String>>> {
        Self::sql_query_env(t, sql, &[]).await
    }

    /// [`LinuxDatabases::sql_query`] 的可注入环境变量变体。
    ///
    /// 存在的唯一理由：PG 只读控制台要靠 `PGOPTIONS` 把**会话**设成只读
    /// （见 `PG_READONLY_ENV`）。浏览路径一律传空切片，行为与从前逐字节一致。
    pub(crate) async fn sql_query_env(
        t: &DbTarget,
        sql: &str,
        extra_env: &[(&str, &str)],
    ) -> Result<Vec<Vec<String>>> {
        let mut env: std::collections::HashMap<String, std::ffi::OsString> =
            std::collections::HashMap::new();
        let (bin, args): (crate::cmd::Bin, Vec<String>) = match t.engine {
            DbEngine::MySql => {
                let mut a = vec![
                    "--batch".into(),
                    "--raw".into(),
                    "--skip-column-names".into(),
                    "-h".into(),
                    t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                ];
                if let Some(p) = t.port { a.push("-P".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-u".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-D".into()); a.push(d.clone()); }
                a.push("-e".into());
                a.push(sql.to_string());
                if let Some(p) = &t.password {
                    env.insert("MYSQL_PWD".into(), std::ffi::OsString::from(p));
                }
                (crate::cmd::Bin::MySql, a)
            }
            DbEngine::Postgres => {
                let mut a = vec![
                    "--no-psqlrc".into(),
                    "--tuples-only".into(),
                    "--no-align".into(),
                    "--field-separator".into(),
                    "\t".into(),
                    "-h".into(),
                    t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                ];
                if let Some(p) = t.port { a.push("-p".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-U".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-d".into()); a.push(d.clone()); }
                a.push("-c".into()); // ci-allow-layering[2]: 这是 `psql -c <sql>` 的客户端参数，与 shell 无关
                a.push(sql.to_string());
                if let Some(p) = &t.password {
                    env.insert("PGPASSWORD".into(), std::ffi::OsString::from(p));
                }
                (crate::cmd::Bin::Psql, a)
            }
            DbEngine::Sqlite => {
                return Err(panel_core::PanelError::Internal("SQLite 不走外部客户端".into()))
            }
        };
        // extra_env 放在凭据之后：调用方传的护栏变量优先（当前只有 PGOPTIONS 一处）
        for (k, v) in extra_env {
            env.insert((*k).into(), std::ffi::OsString::from(v));
        }

        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = crate::cmd::run(
            bin,
            &args_ref,
            crate::cmd::CmdOpt {
                timeout: std::time::Duration::from_secs(20),
                env,
                ..Default::default()
            },
        )
        .await?;
        if out.code != Some(0) {
            return Err(panel_core::PanelError::Command {
                bin: "mysql/psql".into(),
                detail: out.stderr,
            });
        }
        Ok(out
            .stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.split('\t').map(|c| c.to_string()).collect::<Vec<_>>())
            .collect())
    }

    /// PG 只读控制台专用：执行一条 SQL，**连列名一起取回**。
    ///
    /// 与 `sql_query` 的差别只有一处——不带 `--tuples-only`。psql 只有在
    /// 非 tuples-only 模式下才打印表头，而表头正是列名的唯一来源
    /// （`sql_query` 拿不到列名，浏览路径靠 `SHOW COLUMNS` 之类另查）。
    ///
    /// ⚠️ **不要为了省事加第二个 `-c "\echo 哨兵"`**：实测 psql 有多个 `-c` 时，
    /// 前一条失败也照样 exit 0（最后一条 `\echo` 成功就把退出码洗干净了），
    /// 错误只留在 stderr。单 `-c` 时退出码是可靠的（失败 → 非 0），
    /// 所以这里只用一条，靠「末行是命令状态行」剥离，见 `is_pg_status_tag`。
    pub(crate) async fn sql_query_console(
        t: &DbTarget,
        sql: &str,
        extra_env: &[(&str, &str)],
    ) -> Result<(Vec<String>, Vec<Vec<String>>)> {
        let mut env: std::collections::HashMap<String, std::ffi::OsString> =
            std::collections::HashMap::new();
        if let Some(p) = &t.password {
            env.insert("PGPASSWORD".into(), std::ffi::OsString::from(p));
        }
        for (k, v) in extra_env {
            env.insert((*k).into(), std::ffi::OsString::from(v));
        }
        let mut a: Vec<String> = vec![
            "--no-psqlrc".into(),
            "--no-align".into(),
            "--field-separator".into(),
            "\t".into(),
            "-h".into(),
            t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
        ];
        if let Some(p) = t.port { a.push("-p".into()); a.push(p.to_string()); }
        if let Some(u) = &t.user { a.push("-U".into()); a.push(u.clone()); }
        if let Some(d) = &t.database { a.push("-d".into()); a.push(d.clone()); }
        a.push("-c".into()); // ci-allow-layering[2]: 这是 `psql -c <sql>` 的客户端参数，与 shell 无关
        a.push(sql.to_string());
        let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
        let out = crate::cmd::run(
            crate::cmd::Bin::Psql,
            &args,
            crate::cmd::CmdOpt {
                timeout: std::time::Duration::from_secs(20),
                // 控制台的 limit 最大 2000 行，宽行可能到几 MB；默认 1MB 会被
                // 无声截断（`truncated` 只置位、不报错），那等于悄悄少给数据。
                max_output: PG_CONSOLE_MAX_OUTPUT,
                env,
                ..Default::default()
            },
        )
        .await?;
        if out.code != Some(0) {
            return Err(panel_core::PanelError::Command { bin: "psql".into(), detail: out.stderr });
        }
        if out.truncated {
            return Err(panel_core::PanelError::Command {
                bin: "psql".into(),
                detail: format!(
                    "结果超过 {PG_CONSOLE_MAX_OUTPUT} 字节上限而中断（可能少给了数据）。\
                     请加 WHERE 条件或调小返回行数上限。"
                ),
            });
        }
        // 解析：第 1 行 = 列名；其后 = 数据行；最后一行 = 命令状态行 `(N rows)`。
        // 状态行的文案随 locale 变（中文环境下是 `(3 行)`），不能按内容识别，
        // 但 `cmd::run` 固定了 LC_ALL=C，且它**恒在**——用 `is_pg_status_tag`
        // 校验后再剥。对不上就**当数据留着**：宁可多留一行，也不能吃掉真实数据。
        let lines: Vec<&str> = out.stdout.lines().collect();
        let Some((header, rest)) = lines.split_first() else {
            return Err(panel_core::PanelError::Command {
                bin: "psql".into(),
                detail: "psql 无任何输出（既无列名行也无状态行）".into(),
            });
        };
        let columns: Vec<String> = header.split('\t').map(|c| c.to_string()).collect();
        let data = match rest.split_last() {
            // 末行是状态行 → 剥掉
            Some((last, head)) if is_pg_status_tag(last) => head,
            // 没有状态行（不该发生）→ 全部当数据，不猜
            _ => rest,
        };
        Ok((
            columns,
            data.iter()
                .map(|l| l.split('\t').map(|c| c.to_string()).collect::<Vec<_>>())
                .collect(),
        ))
    }

    /// 打开目标 SQLite 文件（只读）。SQLite 的“连接”就是一个文件路径（`database` 字段）。
    fn open_sqlite(t: &DbTarget) -> Result<rusqlite::Connection> {
        use rusqlite::OpenFlags;
        let path = t.database.as_deref().ok_or_else(|| PanelError::Validation {
            field: "database".into(),
            reason: "SQLite 连接需在“库名”中填写 .db 文件路径".into(),
        })?;
        if !std::path::Path::new(path).is_file() {
            return Err(PanelError::NotFound(format!("sqlite 文件: {path}")));
        }
        rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(db_err)
    }
}

pub(super) fn db_err(e: rusqlite::Error) -> PanelError { PanelError::Database(e.to_string()) }

pub(super) fn join_err(e: tokio::task::JoinError) -> PanelError {
    PanelError::Internal(format!("db task join: {e}"))
}

/// PG 只读控制台的**会话护栏**：把默认事务设成只读。
///
/// 与 SQLite 的 `SQLITE_OPEN_READ_ONLY` 同性质——**服务端物理层面**拒绝写，
/// 不依赖任何关键字名单。实测（PostgreSQL 18.6，本机 woaiyoulin 库）：
/// - `CREATE TABLE` → 「不能在一个只读模式的事务中执行CREATE TABLE」
/// - `UPDATE` → 同上（UPDATE）
/// - `SELECT id INTO zz FROM app_user`（伪装成查询的建表）→ 同上（SELECT INTO）
///
/// ⚠️ **残余风险，诚实记录，不假装全拦**：超级用户函数照样执行——
/// `SELECT pg_reload_conf()` 实测返回 `t`。它不写用户表，
/// `default_transaction_read_only` 管不到这种"配置类"函数。要彻底封死需要
/// `SET ROLE` 到非超级用户，那是账号侧决策，属后续工作（不是本功能的静默缺口）。
///
/// ⚠️ 经 `cmd::run` 注入（`env_clear()` 之后叠加），无法被 `PATH`/`LD_*` 覆盖。
/// 但**别用 `sudo` 传它**：sudo 默认 `env_reset` 会把 PGOPTIONS 剥掉，
/// 手动复验时已踩过一次（护栏看似失效，其实是变量没到 psql）。
const PG_READONLY_ENV: &[(&str, &str)] = &[("PGOPTIONS", "-c default_transaction_read_only=on")];

/// PG 控制台结果体积上限（字节）。
///
/// 必须显著大于 `cmd::run` 默认的 1MB：2000 行 × 宽行很容易超，而超限时
/// `collect` 只是**无声截断**（置 `truncated`、不报错）——那等于悄悄少给数据。
/// 放大上限 + 显式检查 `truncated` 报错，才是"要么给全、要么明说"。
const PG_CONSOLE_MAX_OUTPUT: usize = 8 * 1024 * 1024;

/// 把用户 SQL 包成「返回行数有界」的查询。
///
/// **为什么必须包**：不限行数的 `SELECT * FROM 大表` 会在面板截断之前
/// 就产出几十 MB stdout，把面板内存吃穿。包一层 LIMIT 让**服务端**就停下。
///
/// 三个实测过的坑，少处理一个就是故障：
/// 1. **结尾分号必须剥掉**：`SELECT * FROM (SELECT 1;) AS x` 在 PG 是语法错误；
/// 2. **EXPLAIN 不能包**：`SELECT * FROM (EXPLAIN …)` 同样是语法错误
///    （EXPLAIN 不是表子查询）。它不返回数据行，包它没有意义，直接放行；
/// 3. **右括号前必须补换行**：用户 SQL 若以 `-- 注释` 收尾，不补换行的话
///    `--` 会把包裹用的 `) AS … LIMIT …` 一起吃到行尾（实测过）。
///
/// **已知边界（诚实记录）**：`SELECT 1; -- 尾注释` 这种「分号后跟行注释」的写法
/// 仍会因括号里残留分号而报 PG 语法错误。修它需要在 OS 层重写一份注释剥离，
/// 与 panel-api 的 `scrub_sql` 重复——两处漂移比这一种罕见写法更危险。
/// 后果是**可见的语法错误**，不是静默错数据，故记为已知边界而非缺陷。
pub(super) fn pg_wrap_readonly(sql: &str, limit: usize) -> String {
    let body = sql.trim().trim_end_matches(';').trim_end();
    let first = body.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();
    if first == "explain" {
        return body.to_string();
    }
    format!("SELECT * FROM ({body}\n) AS __panel_readonly LIMIT {limit}")
}

/// 是否 psql 的「命令状态行」——形如 `(3 rows)` / `(0 rows)` / `(1 row)`。
///
/// 只认这一种形态，且**不匹配就当它是数据**：宁可少剥一行，也绝不能把
/// 真实数据行当状态行吃掉（后者是静默丢数据，比多留一行严重得多）。
/// `cmd::run` 固定 `LC_ALL=C`，故英文形态是确定的；但即使 locale 漂了，
/// 后果也只是多留一行无害文本，不会吃数据。
pub(super) fn is_pg_status_tag(line: &str) -> bool {
    let t = line.trim();
    if !(t.starts_with('(') && t.ends_with(')') && t.len() >= 2) {
        return false;
    }
    let inner = &t[1..t.len() - 1];
    let mut p = inner.split_whitespace();
    let n_ok = matches!(p.next(), Some(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    let unit_ok = matches!(p.next(), Some("row") | Some("rows"));
    n_ok && unit_ok && p.next().is_none()
}

/// 标识符安全加引号（表名等不可参数化的位置）。双引号翻倍转义，杜绝注入。
pub(super) fn quote_ident(s: &str) -> String { format!("\"{}\"", s.replace('"', "\"\"")) }

/// SQLite 值 → 可选字符串（NULL → None），保持引擎无关的预览口径。
#[allow(deprecated)]
pub(super) fn value_to_string(v: rusqlite::types::ValueRef<'_>) -> Option<String> {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Text(t) => Some(String::from_utf8_lossy(t).to_string()),
        ValueRef::Blob(b) => Some(format!("<blob {} bytes>", b.len())),
    }
}

#[async_trait]
impl DatabaseProvider for LinuxDatabases {
    fn engine(&self) -> DbEngine { DbEngine::Sqlite }
    async fn available(&self) -> Result<bool> { Ok(true) }   // SQLite 内建，始终可用
    /// 引擎可用性：SQLite 内建恒可用；mysql/pg **看客户端二进制是否存在**。
    /// 客户端缺失就诚实报不可用——否则 UI 会给用户"能点但一点必失败"的假按钮。
    fn supports(&self, e: DbEngine) -> bool {
        match e {
            DbEngine::Sqlite => true,
            DbEngine::MySql => crate::cmd::Bin::MySql.available(),
            DbEngine::Postgres => crate::cmd::Bin::Psql.available(),
        }
    }

    /// 只读 SQL 控制台开放判定。**判据必须是服务端只读护栏，不是客户端在不在**：
    /// SQLite 有只读连接兜底；PG 有 `default_transaction_read_only` 会话护栏
    /// （但出口是 psql，客户端不在仍开不了，故与 `supports()` 相与）；
    /// MySQL 两者都没有 → 恒关。
    ///
    /// 判定矩阵本身在 `crate::traits::db_console_open`，两边共用同一份——
    /// 这里只负责把「客户端在位性」这个环境输入喂进去。
    fn readonly_sql(&self, e: DbEngine) -> bool {
        crate::traits::db_console_open(e, self.supports(e))
    }

    async fn databases(&self, t: &DbTarget) -> Result<Vec<String>> {
        match t.engine {
            DbEngine::Sqlite => {}
            DbEngine::MySql => {
                // 系统库不展示：它们不是"用户的业务库"，列出来只会干扰
                let rows = LinuxDatabases::sql_query(t, "SHOW DATABASES").await?;
                return Ok(rows
                    .into_iter()
                    .filter_map(|r| r.into_iter().next())
                    .filter(|n| {
                        !matches!(n.as_str(), "information_schema" | "performance_schema" | "sys" | "mysql")
                    })
                    .collect());
            }
            DbEngine::Postgres => {
                let rows = LinuxDatabases::sql_query(
                    t,
                    "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname",
                )
                .await?;
                return Ok(rows.into_iter().filter_map(|r| r.into_iter().next()).collect());
            }
        }
        let t = t.clone();
        tokio::task::spawn_blocking(move || {
            let conn = LinuxDatabases::open_sqlite(&t)?;
            let mut st = conn.prepare("PRAGMA database_list").map_err(db_err)?;
            let names = st
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(db_err)?
                .filter_map(|x| x.ok())
                .filter(|n| n != "temp")
                .collect::<Vec<_>>();
            Ok(names)
        })
        .await
        .map_err(join_err)?
    }

    async fn schemas(&self, t: &DbTarget, db: &str) -> Result<Vec<DbNode>> {
        match t.engine {
            // MySQL：库的下一级直接就是表（`SHOW TABLES` 已带库名），没有 schema 层。
            // 返回空 = 「没有更下一层」，前端据此跳过这一层，不把它当成「空目录」。
            DbEngine::MySql => Ok(Vec::new()),
            DbEngine::Postgres => {
                // `previewable` 的依据是**当前 tables() 的实现**：它写死 `table_schema='public'`。
                // 所以除 public 外的 schema 点进去一定列不出东西——这必须在数据里说清楚，
                // 而不是让用户点进去看一句「无表」。将来 tables() 支持 schema 参数时，
                // 这里要同步改成恒 true（否则前端会继续误标「不可预览」）。
                let lit = db.replace('\'', "''");
                let rows = LinuxDatabases::sql_query(
                    t,
                    &format!(
                        "SELECT nspname FROM pg_namespace \
                         WHERE nspname NOT IN ('pg_catalog','information_schema') \
                           AND nspname NOT LIKE 'pg\\_toast%' AND nspname NOT LIKE 'pg\\_temp%' \
                         ORDER BY nspname"
                    ),
                )
                .await;
                // 查不出来（老版本 PG / 权限）时**不谎报空**：退回「只有一个 public」
                let rows = match rows {
                    Ok(r) => r,
                    Err(_) => return Ok(vec![DbNode {
                        name: "public".into(),
                        previewable: lit == "public",
                    }]),
                };
                Ok(rows
                    .into_iter()
                    .filter_map(|r| r.into_iter().next())
                    .map(|n| {
                        let previewable = n == "public";
                        DbNode { name: n, previewable }
                    })
                    .collect())
            }
            DbEngine::Sqlite => {
                // SQLite 没有 schema 这一级；`PRAGMA database_list` 返回的是 **catalog**
                // （main / temp / 以及 ATTACH 进来的别名），面板连的是单个只读文件，
                // 正常情况下就只有 main。这里如实返回它，而不是凭空造一个 schema 层。
                let t = t.clone();
                tokio::task::spawn_blocking(move || {
                    let conn = LinuxDatabases::open_sqlite(&t)?;
                    let mut st = conn.prepare("PRAGMA database_list").map_err(db_err)?;
                    // query_map 必须绑定到 let 再 collect（否则临时迭代器晚于 st 析构 → E0597）
                    let names: Vec<String> = st
                        .query_map([], |r| r.get::<_, String>(1))
                        .map_err(db_err)?
                        .filter_map(|x| x.ok())
                        .filter(|n| n != "temp")
                        .collect();
                    Ok(names
                        .into_iter()
                        .map(|n| DbNode { name: n, previewable: true })
                        .collect())
                })
                .await
                .map_err(join_err)?
            }
        }
    }

    async fn tables(&self, t: &DbTarget) -> Result<Vec<DbTable>> {
        match t.engine {
            DbEngine::Sqlite => {}
            DbEngine::MySql => {
                let db = t.database.clone().unwrap_or_default();
                let names: Vec<String> = LinuxDatabases::sql_query(t, "SHOW TABLES")
                    .await?
                    .into_iter()
                    .filter_map(|r| r.into_iter().next())
                    .collect();
                let mut out = Vec::with_capacity(names.len());
                for n in names {
                    let q = format!("SELECT COUNT(*) FROM `{}.`{}``", db.replace('`', "``"), n.replace('`', "``"));
                    let rows = LinuxDatabases::sql_query(t, &q)
                        .await
                        .ok()
                        .and_then(|r| r.into_iter().next())
                        .and_then(|r| r.into_iter().next())
                        .and_then(|s| s.trim().parse::<i64>().ok())
                        .unwrap_or(-1); // 取不到行数诚实给 -1，不伪造成 0
                    out.push(DbTable { name: n, rows, kind: TableKind::Table });
                }
                return Ok(out);
            }
            DbEngine::Postgres => {
                let names: Vec<String> = LinuxDatabases::sql_query(
                    t,
                    "SELECT table_name FROM information_schema.tables \
                     WHERE table_schema = 'public' ORDER BY table_name",
                )
                .await?
                .into_iter()
                .filter_map(|r| r.into_iter().next())
                .collect();
                let mut out = Vec::with_capacity(names.len());
                for n in names {
                    let q = format!("SELECT COUNT(*) FROM public.\"{}\"", n.replace('"', "\"\""));
                    let rows = LinuxDatabases::sql_query(t, &q)
                        .await
                        .ok()
                        .and_then(|r| r.into_iter().next())
                        .and_then(|r| r.into_iter().next())
                        .and_then(|s| s.trim().parse::<i64>().ok())
                        .unwrap_or(-1);
                    out.push(DbTable { name: n, rows, kind: TableKind::Table });
                }
                return Ok(out);
            }
        }
        let t = t.clone();
        tokio::task::spawn_blocking(move || {
            let conn = LinuxDatabases::open_sqlite(&t)?;
            // 注意：`query_map` 必须绑到 let 语句再 collect —— 若作为块尾表达式，
            // 其临时迭代器会晚于 `st` 析构，触发 E0597（rusqlite 经典借用陷阱）。
            let mut st = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' \
                          AND name NOT LIKE 'sqlite_%' ORDER BY name")
                .map_err(db_err)?;
            let names: Vec<String> = st
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(db_err)?
                .filter_map(|x| x.ok())
                .collect();
            drop(st);
            let mut out = Vec::with_capacity(names.len());
            for name in names {
                // 行数取不到时诚实给 -1（不伪造成 0）
                let rows: i64 = conn
                    .query_row(&format!("SELECT COUNT(*) FROM {}", quote_ident(&name)), [], |r| r.get(0))
                    .unwrap_or(-1);
                out.push(DbTable { name, rows, kind: TableKind::Table });
            }
            Ok(out)
        })
        .await
        .map_err(join_err)?
    }

    async fn rows(&self, t: &DbTarget, table: &str, limit: usize, offset: usize) -> Result<DbRows> {
        match t.engine {
            DbEngine::Sqlite => {}
            DbEngine::MySql => {
                let esc = table.replace('`', "``");
                let total = LinuxDatabases::sql_query(t, &format!("SELECT COUNT(*) FROM `{esc}`"))
                    .await
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .and_then(|r| r.into_iter().next())
                    .and_then(|s| s.trim().parse::<i64>().ok())
                    .unwrap_or(-1);
                // 列名单独取：`--skip-column-names` 模式下结果不含表头
                let columns: Vec<String> =
                    LinuxDatabases::sql_query(t, &format!("SHOW COLUMNS FROM `{esc}`"))
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|r| r.into_iter().next())
                        .collect();
                let rows = LinuxDatabases::sql_query(
                    t,
                    &format!("SELECT * FROM `{esc}` LIMIT {limit} OFFSET {offset}"),
                )
                .await?;
                // 客户端模式下 NULL 与空串/字符串 "NULL" 无法可靠区分，
                // 故一律按文本返回（**不伪造 NULL 语义**）——比错误映射更诚实。
                return Ok(DbRows {
                    columns,
                    rows: rows.into_iter().map(|r| r.into_iter().map(Some).collect()).collect(),
                    total,
                });
            }
            DbEngine::Postgres => {
                let esc = table.replace('"', "\"\"");
                let total = LinuxDatabases::sql_query(
                    t,
                    &format!("SELECT COUNT(*) FROM public.\"{esc}\""),
                )
                .await
                .ok()
                .and_then(|r| r.into_iter().next())
                .and_then(|r| r.into_iter().next())
                .and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or(-1);
                let lit = table.replace('\'', "''");
                let columns: Vec<String> = LinuxDatabases::sql_query(
                    t,
                    &format!(
                        "SELECT column_name FROM information_schema.columns \
                         WHERE table_schema = 'public' AND table_name = '{lit}' ORDER BY ordinal_position"
                    ),
                )
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|r| r.into_iter().next())
                .collect();
                let rows = LinuxDatabases::sql_query(
                    t,
                    &format!("SELECT * FROM public.\"{esc}\" LIMIT {limit} OFFSET {offset}"),
                )
                .await?;
                // 客户端模式下 NULL 与空串/字符串 "NULL" 无法可靠区分，
                // 故一律按文本返回（**不伪造 NULL 语义**）——比错误映射更诚实。
                return Ok(DbRows {
                    columns,
                    rows: rows.into_iter().map(|r| r.into_iter().map(Some).collect()).collect(),
                    total,
                });
            }
        }
        let t = t.clone();
        let table = table.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = LinuxDatabases::open_sqlite(&t)?;
            // 表名不可参数化：经 quote_ident 安全转义后拼接；行数据全走绑定参数
            let total: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {}", quote_ident(&table)), [], |r| r.get(0))
                .map_err(db_err)?;
            let mut st = conn
                .prepare(&format!("SELECT * FROM {} LIMIT ?1 OFFSET ?2", quote_ident(&table)))
                .map_err(db_err)?;
            let columns: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
            let ncol = columns.len();
            let mut out = Vec::new();
            let mut qr = st
                .query(rusqlite::params![limit as i64, offset as i64])
                .map_err(db_err)?;
            while let Some(row) = qr.next().map_err(db_err)? {
                let mut vals = Vec::with_capacity(ncol);
                for i in 0..ncol {
                    vals.push(value_to_string(row.get_ref(i).map_err(db_err)?));
                }
                out.push(vals);
            }
            Ok(DbRows { columns, rows: out, total })
        })
        .await
        .map_err(join_err)?
    }

    async fn query(&self, t: &DbTarget, sql: &str, limit: usize) -> Result<DbQueryResult> {
        match t.engine {
            DbEngine::Sqlite => {}
            DbEngine::Postgres => {
                // 三道防线，逐层递进（任一层被绕过，下一层还在）：
                // 1. API 层 `validate_read_only_sql`：首关键词白名单 + 写关键字黑名单，
                //    尽早给出可读错误；
                // 2. 这里的 `pg_wrap_readonly`：让**返回行数有界**（服务端就停下，
                //    不会先把几十 MB stdout 产出来再被面板截断）；
                // 3. `PG_READONLY_ENV`：会话级只读，写语句在服务端**物理失败**
                //    （实测 CREATE TABLE / UPDATE / SELECT INTO 全被拦）。
                //
                // 与 SQLite 的差别只在于兜底手段（只读连接 vs 只读会话），
                // 安全性质相同：都不依赖关键字名单。
                let wrapped = pg_wrap_readonly(sql, limit + 1);
                let (columns, rows) =
                    LinuxDatabases::sql_query_console(t, &wrapped, PG_READONLY_ENV).await?;
                // 多取一行只为判截断：真有第 limit+1 行才说明"还有更多"。
                // EXPLAIN 未包裹（没有服务端 LIMIT），同样靠这个客户端判定兜住。
                let truncated = rows.len() > limit;
                let mut rows = rows;
                if truncated { rows.truncate(limit); }
                return Ok(DbQueryResult {
                    columns,
                    rows: rows.into_iter().map(|r| r.into_iter().map(Some).collect()).collect(),
                    truncated,
                });
            }
            DbEngine::MySql => {
                // MySQL 仍不开放，且理由与从前不同了（从前是"都没实现"）：
                // 白名单与包裹都只是**关键字层**防护，PG 有
                // `default_transaction_read_only` 这种服务端物理护栏，MySQL 客户端
                // 没有等价物——只读账号是账号侧配置，不是面板能替用户做的决定。
                // 本机也没有 mysql 客户端可验证，不写未测代码。
                return unsupported!(
                    "dbms.query: MySQL 未实装只读控制台（无服务端只读护栏可用；\
                     PostgreSQL 与 SQLite 已开放）"
                );
            }
        }
        let t = t.clone();
        let sql = sql.to_string();
        tokio::task::spawn_blocking(move || {
            // open_sqlite 固定 SQLITE_OPEN_READ_ONLY：即便上层白名单被绕过，
            // 写语句在这里也会**物理失败**（纵深防御，不依赖单点校验）。
            let conn = LinuxDatabases::open_sqlite(&t)?;
            let mut st = conn.prepare(&sql).map_err(db_err)?;
            let columns: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
            let ncol = columns.len();
            let mut out: Vec<Vec<Option<String>>> = Vec::new();
            let mut truncated = false;
            let mut qr = st.query([]).map_err(db_err)?;
            while let Some(row) = qr.next().map_err(db_err)? {
                // 先判上限再取值：多出来的行不取，避免无谓的值转换开销
                if out.len() >= limit {
                    truncated = true;
                    break;
                }
                let mut vals = Vec::with_capacity(ncol);
                for i in 0..ncol {
                    vals.push(value_to_string(row.get_ref(i).map_err(db_err)?));
                }
                out.push(vals);
            }
            Ok(DbQueryResult { columns, rows: out, truncated })
        })
        .await
        .map_err(join_err)?
    }

    async fn backup(&self, t: &DbTarget, o: &SafePath, on_line: Box<dyn Fn(String) + Send + Sync>) -> Result<()> {
        match t.engine {
            DbEngine::Sqlite => {
                let src = t.database.as_deref().ok_or_else(|| PanelError::Validation {
                    field: "database",
                    reason: "SQLite 连接需在「库名」中填写 .db 文件路径".into(),
                })?;
                if !std::path::Path::new(src).is_file() {
                    return Err(PanelError::NotFound(format!("sqlite 文件: {src}")));
                }
                // 在线文件复制：SQLite 文件在面板自身库上就是直接 cp（与 DbRestoreTask 同源口径）。
                // 大库一致性由备份任务在库空闲期执行保证，这里不引入 rusqlite 在线热备依赖。
                std::fs::copy(src, o.as_path()).map_err(|e| PanelError::Io(e.to_string()))?;
                on_line("SQLite 文件已复制".into());
                Ok(())
            }
            DbEngine::MySql => {
                let mut env: std::collections::HashMap<String, std::ffi::OsString> = std::collections::HashMap::new();
                if let Some(p) = &t.password { env.insert("MYSQL_PWD".into(), std::ffi::OsString::from(p)); }
                let mut a: Vec<String> = vec![
                    "--result-file".into(), o.as_path().to_string_lossy().into(),
                    "--single-transaction".into(), "--routines".into(), "--triggers".into(),
                    "--events".into(), "--skip-lock-tables".into(),
                    "-h".into(), t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                ];
                if let Some(p) = t.port { a.push("-P".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-u".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-D".into()); a.push(d.clone()); }
                let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
                on_line("mysqldump 导出中…".into());
                // 凭据走 MYSQL_PWD 环境变量（绝不进 argv，ps 可见 = 泄露口令）；
                // --result-file 直接落盘，stdout 为空，避免大库撑爆内存捕获。
                crate::cmd::run_checked(
                    crate::cmd::Bin::MySqlDump, &args,
                    crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), env, ..Default::default() },
                ).await?;
                on_line("MySQL 备份完成".into());
                Ok(())
            }
            DbEngine::Postgres => {
                let mut env: std::collections::HashMap<String, std::ffi::OsString> = std::collections::HashMap::new();
                if let Some(p) = &t.password { env.insert("PGPASSWORD".into(), std::ffi::OsString::from(p)); }
                let mut a: Vec<String> = vec![
                    "-f".into(), o.as_path().to_string_lossy().into(),
                    "-h".into(), t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                ];
                if let Some(p) = t.port { a.push("-p".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-U".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-d".into()); a.push(d.clone()); }
                let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
                on_line("pg_dump 导出中…".into());
                crate::cmd::run_checked(
                    crate::cmd::Bin::PgDump, &args,
                    crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), env, ..Default::default() },
                ).await?;
                on_line("PostgreSQL 备份完成".into());
                Ok(())
            }
        }
    }

    async fn restore(&self, t: &DbTarget, from: &SafePath) -> Result<()> {
        match t.engine {
            DbEngine::Sqlite => {
                let dst = t.database.as_deref().ok_or_else(|| PanelError::Validation {
                    field: "database",
                    reason: "SQLite 连接需在「库名」中填写 .db 文件路径".into(),
                })?;
                // 覆盖前先留快照（与 DbRestoreTask 同源安全网）：出问题可据此回滚
                if std::path::Path::new(dst).is_file() {
                    let bak = format!(
                        "{}.bak-{}", dst,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    );
                    std::fs::copy(dst, &bak).map_err(|e| PanelError::Io(e.to_string()))?;
                }
                std::fs::copy(from.as_path(), dst).map_err(|e| PanelError::Io(e.to_string()))?;
                Ok(())
            }
            DbEngine::MySql => {
                let mut env: std::collections::HashMap<String, std::ffi::OsString> = std::collections::HashMap::new();
                if let Some(p) = &t.password { env.insert("MYSQL_PWD".into(), std::ffi::OsString::from(p)); }
                let mut a: Vec<String> = vec!["-h".into(), t.host.clone().unwrap_or_else(|| "127.0.0.1".into())];
                if let Some(p) = t.port { a.push("-P".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-u".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-D".into()); a.push(d.clone()); }
                a.push("-e".into());
                a.push(format!("source {}", from.as_path().to_string_lossy()));
                let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
                crate::cmd::run_checked(
                    crate::cmd::Bin::MySql, &args,
                    crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), env, ..Default::default() },
                ).await?;
                Ok(())
            }
            DbEngine::Postgres => {
                let mut env: std::collections::HashMap<String, std::ffi::OsString> = std::collections::HashMap::new();
                if let Some(p) = &t.password { env.insert("PGPASSWORD".into(), std::ffi::OsString::from(p)); }
                let mut a: Vec<String> = vec![
                    "-h".into(), t.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                    "-f".into(), from.as_path().to_string_lossy().into(),
                ];
                if let Some(p) = t.port { a.push("-p".into()); a.push(p.to_string()); }
                if let Some(u) = &t.user { a.push("-U".into()); a.push(u.clone()); }
                if let Some(d) = &t.database { a.push("-d".into()); a.push(d.clone()); }
                let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
                crate::cmd::run_checked(
                    crate::cmd::Bin::Psql, &args,
                    crate::cmd::CmdOpt { timeout: std::time::Duration::from_secs(600), env, ..Default::default() },
                ).await?;
                Ok(())
            }
        }
    }
}

