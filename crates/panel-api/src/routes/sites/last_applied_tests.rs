//! 背景事故形状：`tls_count` 子查询列曾把 SITE_SELECT 后续列整体后移一位，
//! 编译 + 单测全绿、实机 `apply` 才报 `Invalid column type`。故本组测试全部
//! 走**真实迁移 + 真实 SITE_SELECT + 生产 to_out**，把列序钉死在测试里。

    use super::*;

    fn insert_site(c: &rusqlite::Connection, name: &str) -> i64 {
        c.execute(
            "INSERT INTO sites(name, domains, root, kind, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, r#"["a.example.com"]"#, "/var/www/x", "static", 1_700_000_000],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    fn read_applied(c: &rusqlite::Connection, id: i64) -> Option<i64> {
        let sql = format!("SELECT {SITE_SELECT} FROM sites s WHERE s.id = ?1");
        c.query_row(&sql, rusqlite::params![id], |r| r.get(44)).unwrap()
    }

    /// 列序回归：SITE_SELECT 第 44 列必须是 last_applied_at（索引错位时这里
    /// 要么类型错、要么把 remark 读成时间戳——两种都会挂）。
    #[test]
    fn site_select_column_44_is_last_applied_at_and_defaults_null() {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        panel_db::migrate::apply(&mut c).unwrap();
        let id = insert_site(&c, "fresh-site");
        assert_eq!(
            read_applied(&c, id),
            None,
            "从未下发过的站点必须是 NULL；若是 0 会被格式化成 1970-01-01 谎报下发时间"
        );
        // 同行前后列也必须读得动：证明 44 之前没有整体错位
        let sql = format!("SELECT {SITE_SELECT} FROM sites s WHERE s.id = ?1");
        let (remark, conf_path): (String, Option<String>) = c
            .query_row(&sql, rusqlite::params![id], |r| Ok((r.get(43)?, r.get(17)?)))
            .unwrap();
        assert_eq!(remark, "");
        assert_eq!(conf_path, None);
    }

    /// touch SQL 语义：只更新目标行；同值可重入（幂等）；不存在的 id 静默 0 行。
    #[test]
    fn touch_applied_sql_updates_only_the_target_row() {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        panel_db::migrate::apply(&mut c).unwrap();
        let a = insert_site(&c, "site-a");
        let b = insert_site(&c, "site-b");

        let n = c
            .execute(TOUCH_APPLIED_SQL, rusqlite::params![1_772_000_000i64, a])
            .unwrap();
        assert_eq!(n, 1, "只应命中一行");
        assert_eq!(read_applied(&c, a), Some(1_772_000_000));
        assert_eq!(read_applied(&c, b), None, "不得波及其他站点");

        // 重入（重复 apply 同一站点）：覆盖为新值，不报错
        c.execute(TOUCH_APPLIED_SQL, rusqlite::params![1_772_000_999i64, a]).unwrap();
        assert_eq!(read_applied(&c, a), Some(1_772_000_999));
        // 幽灵 id：0 行、不报错（调用方只 eprintln，不中断下发）
        assert_eq!(c.execute(TOUCH_APPLIED_SQL, rusqlite::params![1i64, 999_999]).unwrap(), 0);
    }
