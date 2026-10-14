use super::*;


/// 内建 SQLite 浏览：**只读**打开 `.db` 文件 → 列库/表/行。
///
/// 边界（诚实声明，不撒谎）：
/// - 仅实装 SQLite（内建引擎，无需外部客户端）；mysql/postgres 需外部客户端，`supports()=false`；
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
    /// 只用于只读浏览；面板不提供在线 SQL 编辑器（设计 §2.4 列为 M4 且默认关）。
    pub(crate) async fn sql_query(t: &DbTarget, sql: &str) -> Result<Vec<Vec<String>>> {
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
                    out.push(DbTable { name: n, rows });
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
                    out.push(DbTable { name: n, rows });
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
                out.push(DbTable { name, rows });
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
        if !matches!(t.engine, DbEngine::Sqlite) {
            // 刻意不实装 mysql/pg：它们的客户端连接**不是只读的**，白名单一旦被绕过
            // （例如 `WITH x AS (...) DELETE ...` 这类以 WITH 开头的写语句），
            // 语句会真的落到库里。SQLite 有只读连接兜底，这两个没有——
            // 与其开一个"看起来能用"的口子，不如诚实拒绝。
            return unsupported!("dbms.query: 仅 SQLite 已实装（mysql/pg 需只读账号支持）");
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

