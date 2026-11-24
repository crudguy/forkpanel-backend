//! 计划任务模板（v37 `cron_templates`）。
//!
//! # 模板是什么、不是什么
//! 模板只承载**新建任务的表单预填值**：用户选一个模板，字段被填进「新建任务」
//! 卡片，之后可以任意修改再提交。它：
//! - **不是**任务的父对象：与 `cron_jobs` 无外键，删模板不影响已建出来的任务；
//! - **不是**调度实体：模板本身不进 crontab，只有被用来建任务时才产生副作用；
//! - **不存 enabled**：启用与否是任务实例的属性，新建任务一律默认启用。
//!
//! # 校验口径
//! 模板字段的校验**复用** `cron::validate_job_fields` 与 `cron::check_timeout_value`，
//! 与「创建任务」完全同一份实现。这不是为了省代码，而是保证一条不变式：
//! **模板里存得下的值，一定建得出任务**。若各写一份，就可能出现「模板保存成功、
//! 套用后被 400 打回」——用户会以为是模板坏了。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{cron, audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    Json,
};
use panel_core::{cap_keys, PanelError};
use serde::Deserialize;

/// 模板名的长度上限。模板名要显示在下拉框与列表里，过长会把行撑破；
/// 与任务名不同，模板名**不进 crontab**，所以不要求 path-segment 那么严格，
/// 但同样不许空。
const MAX_TEMPLATE_NAME: usize = 64;
/// 描述长度上限（一行副标题，不是长文档）。
const MAX_TEMPLATE_DESC: usize = 200;

#[derive(Debug, Deserialize)]
pub struct TemplateReq {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub expr: String,
    pub command: String,
    pub user: Option<String>,
    pub timeout_sec: Option<i64>,
    pub webhook_url: Option<String>,
}

/// 校验后的模板字段（DB 写入用）。
struct ValidTemplate {
    name: String,
    description: String,
    expr: String,
    command: String,
    user: String,
    timeout_sec: i64,
    webhook_url: Option<String>,
}

/// 模板字段的公共校验 + 归一化（create / update 共用）。
///
/// 抽出来是为了让「新建」与「编辑」用同一套规则——两条路径各写一份时，
/// 最常见的退化是「编辑能存进去、新建不认」，而用户会认为是两套逻辑。
fn validate_template(state: &Shared, req: &TemplateReq) -> ApiResult<ValidTemplate> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("name", "模板名不能为空"));
    }
    if name.chars().count() > MAX_TEMPLATE_NAME {
        return Err(ApiError::bad_request(
            "name",
            format!("模板名不能超过 {MAX_TEMPLATE_NAME} 个字符"),
        ));
    }
    let description = req.description.trim().to_string();
    if description.chars().count() > MAX_TEMPLATE_DESC {
        return Err(ApiError::bad_request(
            "description",
            format!("描述不能超过 {MAX_TEMPLATE_DESC} 个字符"),
        ));
    }

    let user = req.user.clone().unwrap_or_else(|| "root".to_string());
    // ⭐ 与「创建任务」同一份校验：模板能存 ⇒ 一定能用来建任务
    cron::validate_job_fields(state, &req.expr, &req.command, &user)?;
    let timeout_sec = cron::check_timeout_value(req.timeout_sec.unwrap_or(1800))?;

    // Webhook：空串等价于未设置（与创建任务同口径，不要存成空串）
    let webhook_url = req.webhook_url.as_deref().map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    if let Some(u) = webhook_url.as_deref() {
        crate::webhook::validate_url(u)
            .map_err(|e| ApiError::bad_request("webhook_url", e.to_string()))?;
    }

    Ok(ValidTemplate {
        name,
        description,
        expr: req.expr.clone(),
        command: req.command.clone(),
        user,
        timeout_sec,
        webhook_url,
    })
}

#[derive(Debug, serde::Serialize)]
pub struct TemplateDto {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub expr: String,
    pub command: String,
    pub user: String,
    pub timeout_sec: i64,
    pub webhook_url: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

fn row_to_dto(r: &rusqlite::Row) -> rusqlite::Result<TemplateDto> {
    Ok(TemplateDto {
        id: r.get(0)?,
        name: r.get(1)?,
        description: r.get(2)?,
        expr: r.get(3)?,
        command: r.get(4)?,
        user: r.get(5)?,
        timeout_sec: r.get(6)?,
        webhook_url: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
    })
}

const COLS: &str = "id, name, description, expr, command, user, timeout_sec, webhook_url, \
                    created_at, updated_at";

/// 列表：按 id 升序（先建的在前，模板通常数量很少，稳定顺序比"最近改的在前"更好找）。
pub async fn list(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    // 读用 CRON_VIEW：能在页面上看到「计划任务」就该能看到模板下拉。
    // 若要求 CRON_MANAGE 才能读，只读账号会看到一个空下拉，误以为"没模板"。
    crate::auth::require(&s, perm::CRON_VIEW)?;
    let rows: Vec<TemplateDto> = state.pool.with(|conn| {
        let sql = format!("SELECT {COLS} FROM cron_templates ORDER BY id ASC");
        let mut st = conn.prepare(&sql).map_err(|e| PanelError::Database(e.to_string()))?;
        let it = st.query_map([], row_to_dto).map_err(|e| PanelError::Database(e.to_string()))?;
        let mut v = Vec::new();
        for x in it { v.push(x.map_err(|e| PanelError::Database(e.to_string()))?); }
        Ok(v)
    }).await?;
    Ok(ok(rows))
}

pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    crate::extract::PanelJson(req): crate::extract::PanelJson<TemplateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }
    let v = validate_template(&state, &req)?;

    let now = crate::now_unix();
    let name_for_dup = v.name.clone();
    let audit_label = v.name.clone();
    state.db.exec(move |conn| {
        // UNIQUE(name) 由表约束兜底，但先查一次能给出**可读的** 409，
        // 而不是把 SQLite 的 "UNIQUE constraint failed" 原样甩给用户。
        // 用 EXISTS 而不是 SELECT 1 + ?1：单条语句避免两次往返。
        let dup: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM cron_templates WHERE name = ?1)",
            rusqlite::params![name_for_dup], |r| r.get(0),
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        if dup {
            return Err(PanelError::Conflict(format!("模板「{name_for_dup}」已存在")));
        }
        conn.execute(
            "INSERT INTO cron_templates(name, description, expr, command, user, timeout_sec, \
             webhook_url, created_at, updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)",
            rusqlite::params![
                v.name, v.description, v.expr, v.command, v.user,
                v.timeout_sec, v.webhook_url, now
            ],
        ).map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                PanelError::Conflict("同名模板已存在".to_string()),
            other => PanelError::Database(other.to_string()),
        })?;
        Ok(panel_db::WriteAck { rows_changed: 1 })
    }).await?;

    audit(&state, &s, "cron_template.create", &audit_label, "ok").await;
    Ok(ok(serde_json::json!({ "name": audit_label })))
}

pub async fn update(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    crate::extract::PanelJson(req): crate::extract::PanelJson<TemplateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    if !state.capabilities.get(cap_keys::SCHEDULER_MANAGE).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("scheduler.manage"));
    }
    let v = validate_template(&state, &req)?;
    let now = crate::now_unix();
    let audit_label = v.name.clone();

    let updated = state.db.exec(move |conn| {
        // 改名撞到已有模板：仍给出 409（排除自己）
        let dup: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM cron_templates WHERE name = ?1 AND id <> ?2)",
            rusqlite::params![v.name, id], |r| r.get(0),
        ).map_err(|e| PanelError::Database(e.to_string()))?;
        if dup {
            return Err(PanelError::Conflict(format!("模板「{}」已存在", v.name)));
        }
        let n = conn.execute(
            "UPDATE cron_templates SET name=?2, description=?3, expr=?4, command=?5, user=?6, \
             timeout_sec=?7, webhook_url=?8, updated_at=?9 WHERE id=?1",
            rusqlite::params![
                id, v.name, v.description, v.expr, v.command, v.user,
                v.timeout_sec, v.webhook_url, now
            ],
        ).map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                PanelError::Conflict("同名模板已存在".to_string()),
            other => PanelError::Database(other.to_string()),
        })?;
        Ok(panel_db::WriteAck { rows_changed: n })
    }).await?;

    // 0 行受影响 = 这个 id 不存在。必须显式 404：否则前端会以为"改成功了"。
    if updated.rows_changed == 0 {
        return Err(ApiError::not_found(format!("cron template {id}")));
    }
    audit(&state, &s, "cron_template.update", &audit_label, "ok").await;
    Ok(ok(serde_json::json!({ "id": id, "name": audit_label })))
}

pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::CRON_MANAGE)?;
    // 审计要记「删了哪个模板」，所以名字必须在闭包外也拿到。
    // 闭包只能返回 WriteAck（db.exec 的签名），故用 Rc<RefCell> 带出来。
    let label_cell: std::sync::Arc<std::sync::Mutex<Option<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let label_out = label_cell.clone();
    let ack = state.db.exec(move |conn| {
        // 先读名字用于审计，再删；两者同在一个闭包里，避免"删完查不到名字"。
        let name: Option<String> = conn.query_row(
            "SELECT name FROM cron_templates WHERE id = ?1",
            rusqlite::params![id], |r| r.get(0),
        ).ok();
        *panel_core::sync::lock_recover(&label_out) = name;
        let n = conn.execute("DELETE FROM cron_templates WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| PanelError::Database(e.to_string()))?;
        Ok(panel_db::WriteAck { rows_changed: n })
    }).await?;

    if ack.rows_changed == 0 {
        return Err(ApiError::not_found(format!("cron template {id}")));
    }
    let label = panel_core::sync::lock_recover(&label_cell).clone().unwrap_or_else(|| id.to_string());
    audit(&state, &s, "cron_template.delete", &label, "ok").await;
    Ok(ok(serde_json::json!({ "id": id, "deleted": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// 用**真正的迁移 037** 建内存库，而不是手抄一份建表语句。
    ///
    /// 手抄夹具会与迁移漂移（加列/改约束后测试仍绿，因为测的是那份过时副本），
    /// 而漂移的症状是「生产缺列、测试全过」。直接 include_str! 迁移文件，
    /// 迁移一改测试立刻跟着变。
    fn seed() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../../migrations/037_cron_templates.sql"))
            .unwrap();
        conn
    }

    fn insert(conn: &Connection, name: &str) {
        conn.execute(
            "INSERT INTO cron_templates(name, description, expr, command, user, timeout_sec,
             webhook_url, created_at, updated_at) VALUES(?1,'d','0 3 * * *','/bin/true','root',1800,NULL,1,1)",
            rusqlite::params![name],
        ).unwrap();
    }

    #[test]
    fn name_is_unique() {
        let conn = seed();
        insert(&conn, "daily-backup");
        let dup = conn.execute(
            "INSERT INTO cron_templates(name, description, expr, command, user, timeout_sec,
             webhook_url, created_at, updated_at) VALUES('daily-backup','','0 3 * * *','/bin/true','root',1800,NULL,1,1)",
            [],
        );
        assert!(dup.is_err(), "同名模板必须被表约束挡住（否则下拉里会出现两个一样的）");
    }

    /// 删模板**不得**影响任何已建出来的任务——模板与 cron_jobs 没有外键。
    /// 这条守住「有人后来给 cron_templates 加外键指向 cron_jobs」这种回归：
    /// 那样删模板会连带删任务，属于不可逆的数据丢失。
    #[test]
    fn deleting_template_does_not_touch_jobs() {
        let conn = seed();
        conn.execute_batch(
            "CREATE TABLE cron_jobs(
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, expr TEXT NOT NULL,
                kind TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1, timeout_sec INTEGER NOT NULL DEFAULT 1800);
             INSERT INTO cron_jobs(name, expr, kind) VALUES('daily-backup','0 3 * * *','script');",
        ).unwrap();
        insert(&conn, "t1");
        conn.execute("DELETE FROM cron_templates WHERE name='t1'", []).unwrap();
        let left: i64 = conn.query_row("SELECT COUNT(*) FROM cron_jobs", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 1, "删模板把任务一起删了——模板必须是脚手架，不是父对象");

        // 反过来：外键若被加上，SQLite 会在 INSERT 时就报错（fails fast）。
        let fk = conn.prepare("PRAGMA foreign_key_list(cron_templates)").unwrap()
            .query_map([], |r| r.get::<_, String>(2)).unwrap().count();
        assert_eq!(fk, 0, "cron_templates 不应有任何外键");
    }

    #[test]
    fn list_is_ordered_by_id() {
        let conn = seed();
        insert(&conn, "b");
        insert(&conn, "a");
        let sql = format!("SELECT {COLS} FROM cron_templates ORDER BY id ASC");
        let mut st = conn.prepare(&sql).unwrap();
        let names: Vec<String> = st.query_map([], row_to_dto).unwrap()
            .map(|x| x.unwrap().name).collect();
        assert_eq!(names, vec!["b".to_string(), "a".to_string()], "按创建顺序，不是按名字");
    }

    /// 空串 Webhook 必须归一化成 NULL：存成空串会让前端下拉/详情里出现一个
    /// "看起来配置了但其实是空"的回调地址。
    #[test]
    fn empty_webhook_normalizes_to_none() {
        let f = |s: Option<&str>| s.map(str::trim).filter(|x| !x.is_empty()).map(|x| x.to_string());
        assert_eq!(f(Some("")), None);
        assert_eq!(f(Some("   ")), None);
        assert_eq!(f(None), None);
        assert_eq!(f(Some(" https://a/b ")), Some("https://a/b".to_string()));
    }

    /// 预置模板（迁移 038）必须**本身可通过新建任务的校验**。
    ///
    /// 只断言「迁移跑得通」是不够的：模板若带非法表达式/超长命令/越界超时，
    /// 用户从下拉里选了它、点创建，会在提交时才吃 400——而模板是我们塞进去的，
    /// 相当于我们给了用户一个用不了的起点。
    #[test]
    fn seeded_templates_pass_creation_validation() {
        let conn = seed();
        conn.execute_batch(include_str!("../../../../migrations/038_default_cron_templates.sql"))
            .unwrap();
        let sql = format!("SELECT {COLS} FROM cron_templates ORDER BY id ASC");
        let mut st = conn.prepare(&sql).unwrap();
        let rows: Vec<TemplateDto> = st.query_map([], row_to_dto).unwrap()
            .map(|x| x.unwrap()).collect();
        assert_eq!(rows.len(), 5, "默认模板条数与迁移不一致（改了迁移就要改这里）");

        // 表达式合法性用**真实实现的解析器**，而不是 mock（mock 只数段数，
        // 五段垃圾也会通过）或"看起来像五段"。
        // 必须经 `default_adapter()` 这个跨平台入口拿调度器：直接
        // `panel_os::linux::scheduler::LinuxScheduler` 会让业务层绑死平台，
        // 被架构守卫 [4c] 拦下（且 force-mock 下测的就不是真实解析器了）。
        let adapter = panel_os::default_adapter();
        let sched = adapter.scheduler();
        for r in &rows {
            assert!(sched.validate_expression(&r.expr).is_ok(),
                "默认模板「{}」的表达式非法：{}", r.name, r.expr);
            assert!(panel_core::rules::is_valid_system_user(&r.user),
                "默认模板「{}」的执行用户非法：{}", r.name, r.user);
            assert!(!r.command.trim().is_empty() && r.command.len() <= 4096,
                "默认模板「{}」的命令长度越界", r.name);
            assert!(crate::routes::cron::check_timeout_value(r.timeout_sec).is_ok(),
                "默认模板「{}」的超时越界：{}", r.name, r.timeout_sec);
            assert!(r.name.chars().count() <= MAX_TEMPLATE_NAME,
                "默认模板名超长：{}", r.name);
            assert!(r.description.chars().count() <= MAX_TEMPLATE_DESC,
                "默认模板说明超长：{}", r.name);
            // Webhook 一律留空：预填会让所有实例都往同一个地址 POST
            assert!(r.webhook_url.is_none(), "默认模板不应预填 Webhook：{}", r.name);
        }
    }

    /// 预置模板必须**幂等**：老库升级时若用户已经手建了同名模板，
    /// 迁移要静默跳过、**不覆盖用户的内容**，也不能因 UNIQUE 约束而让整个迁移失败
    /// （迁移跑挂 = 面板起不来）。
    #[test]
    fn seeding_is_idempotent_and_never_overwrites_user_templates() {
        let conn = seed();
        // 用户先手建了一条同名模板，命令与默认值不同
        conn.execute(
            "INSERT INTO cron_templates(name, description, expr, command, user, timeout_sec, \
             webhook_url, created_at, updated_at) VALUES('每日备份数据库','我自己的','0 1 * * *',\
             '/my/own.sh','root',60,NULL,1,1)",
            [],
        ).unwrap();

        // 迁移 038 应用两次：第二次不得报错、不得改变任何行
        conn.execute_batch(include_str!("../../../../migrations/038_default_cron_templates.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../../../../migrations/038_default_cron_templates.sql"))
            .unwrap();

        let cmd: String = conn.query_row(
            "SELECT command FROM cron_templates WHERE name = '每日备份数据库'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(cmd, "/my/own.sh", "用户的同名模板被默认模板覆盖了");

        let n: i64 = conn.query_row("SELECT COUNT(*) FROM cron_templates", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 5, "重复应用迁移不得插入重复行（用户 1 条 + 其余默认 4 条）");
    }
}
