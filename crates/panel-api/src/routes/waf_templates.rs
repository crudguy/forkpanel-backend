//! WAF 策略模板（026）。
//!
//! 站点 WAF + 访问控制本是 `sites` 表列（waf_enabled / waf_profile / waf_rate /
//! waf_burst / ip_allow / ip_deny）。模板把「一套 WAF + 访问控制预设」存成可复用
//! 单元：套用到某站即把该站的这些列设成模板值。
//!
//! **套用动作不在本模块**：由前端读取模板（GET 返回 profile/rate/burst/ip_allow/
//! ip_deny）后，经既有 `POST /api/v1/sites/apply` 逐站下发——刻意不在后端重复站点
//! 的部署管线（渲染→validate→deploy→指纹同步），那套逻辑单一事实源在 sites 模块，
//! 此处再写一遍必漂移，且 N 站 render/reload 的失败语义更复杂。
//!
//! 校验**完全复用** `sites::{build_waf, parse_ip_list}`：档位白名单 / rate≤1000 /
//! burst≤10000 / burst 仅在限速时有效 / IP 仅 IPv4·CIDR——与站点 apply 同源，
//! 避免两处约束漂移（这也是把这两个函数放宽到 `pub(crate)` 的原因）。
//!
//! 权限：读需 `site.view`，写需 `site.manage`（与站点 WAF 配置同权，不新增权限点）。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
    routes::sites::{build_waf, parse_ip_list, WafReq},
};
use axum::{
    extract::{Path as AxPath, State},
    Json,
};
use panel_core::PanelError;
use panel_os::WafProfile;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use crate::extract::PanelJson;

/// 模板名长度上限（与便签 500 不同：模板名是下拉/列表里的短标识）
const NAME_MAX: usize = 64;
/// 模板数量上限：防误操作把下拉塞满
const MAX_TEMPLATES: usize = 50;

/// 列表 / 详情 SQL（列固定，禁 format! 拼 SQL——分层门禁）
const SQL_LIST: &str = "SELECT id, name, waf_profile, rate_per_sec, burst, ip_allow, ip_deny, created_at, updated_at \
     FROM waf_templates ORDER BY id ASC";
const SQL_ONE: &str = "SELECT id, name, waf_profile, rate_per_sec, burst, ip_allow, ip_deny, created_at, updated_at \
     FROM waf_templates WHERE id = ?1";

/// 模板 DTO。ip_allow / ip_deny 以数组返回（落库是逗号拼接，与 Site 类型一致）。
#[derive(Debug, Serialize)]
pub struct TplDto {
    pub id: i64,
    pub name: String,
    pub waf_profile: String,
    pub rate_per_sec: i64,
    pub burst: i64,
    pub ip_allow: Vec<String>,
    pub ip_deny: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

fn split_ips(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn row_dto(r: &rusqlite::Row<'_>) -> rusqlite::Result<TplDto> {
    let allow: String = r.get(5)?;
    let deny: String = r.get(6)?;
    Ok(TplDto {
        id: r.get(0)?,
        name: r.get(1)?,
        waf_profile: r.get(2)?,
        rate_per_sec: r.get(3)?,
        burst: r.get(4)?,
        ip_allow: split_ips(&allow),
        ip_deny: split_ips(&deny),
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
    })
}

/// 写请求体（新建 / 更新共用）。字段多为可选：缺省走站点 apply 同款默认
/// （profile=basic、rate/burst=0=不限速、ip 空=不设）。
#[derive(Debug, Deserialize)]
pub struct TplReq {
    pub name: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub rate_per_sec: Option<u32>,
    #[serde(default)]
    pub burst: Option<u32>,
    #[serde(default)]
    pub ip_allow: Option<String>,
    #[serde(default)]
    pub ip_deny: Option<String>,
}

/// 归一化后的落库值。
struct Norm {
    name: String,
    profile: String,
    rate: i64,
    burst: i64,
    ip_allow: String,
    ip_deny: String,
}

/// 校验 + 归一。WAF 段复用 `build_waf`（enabled 恒 true：模板即"一套生效的 WAF 预设"），
/// IP 段复用 `parse_ip_list`。任一不符即 400，与站点 apply 的拒绝口径一致。
fn normalize(req: &TplReq) -> Result<Norm, ApiError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("name", "模板名不能为空"));
    }
    if name.chars().count() > NAME_MAX {
        return Err(ApiError::bad_request("name", format!("模板名最多 {NAME_MAX} 字")));
    }
    let spec = build_waf(
        Some(&WafReq {
            enabled: true,
            profile: req.profile.clone(),
            rate_per_sec: req.rate_per_sec,
            burst: req.burst,
        }),
        None,
    )?
    .ok_or_else(|| ApiError::bad_request("waf", "WAF 配置无效"))?;
    let profile = match spec.profile {
        WafProfile::Basic => "basic",
        WafProfile::Strict => "strict",
    }
    .to_string();
    let allow = parse_ip_list(req.ip_allow.as_deref().unwrap_or(""))?.join(",");
    let deny = parse_ip_list(req.ip_deny.as_deref().unwrap_or(""))?.join(",");
    Ok(Norm {
        name,
        profile,
        rate: spec.rate_per_sec.unwrap_or(0) as i64,
        burst: spec.burst as i64,
        ip_allow: allow,
        ip_deny: deny,
    })
}

/// 模板列表（读需 `site.view`）。
pub async fn list(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let items: Vec<TplDto> = state
        .pool
        .with(|conn| {
            let mut stmt = conn.prepare(SQL_LIST).map_err(|e| PanelError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], row_dto)
                .map_err(|e| PanelError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await?;
    Ok(ok(items))
}

/// 模板详情（读需 `site.view`；id 不存在 → 404）。
pub async fn get(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let dto = fetch_one(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("模板不存在"))?;
    Ok(ok(dto))
}

/// 新建模板（写需 `site.manage`；重名 → 409；超量 → 400）。
/// 不返回 id（db.exec 只回 WriteAck）：前端保存后 reload 列表取全量，与便签一致。
pub async fn create(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<TplReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let n = normalize(&req)?;
    if name_taken(&state, &n.name, None).await? {
        return Err(ApiError::conflict("模板名已存在"));
    }
    let count: i64 = state
        .pool
        .with(|conn| {
            conn.query_row("SELECT COUNT(*) FROM waf_templates", [], |r| r.get(0))
                .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    if count as usize >= MAX_TEMPLATES {
        return Err(ApiError::bad_request(
            "name",
            format!("模板最多 {MAX_TEMPLATES} 个，请先删除再添加"),
        ));
    }
    let now = now_unix();
    let Norm { name, profile, rate, burst, ip_allow, ip_deny } = n;
    let audit_name = name.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO waf_templates(name, waf_profile, rate_per_sec, burst, ip_allow, ip_deny, created_at, updated_at) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                rusqlite::params![name, profile, rate, burst, ip_allow, ip_deny, now],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "waf_template.create", &audit_name, "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 更新模板（写需 `site.manage`；可改名；id 不存在 → 404；重名 → 409）。
pub async fn update(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<TplReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    let n = normalize(&req)?;
    ensure_exists(&state, id).await?;
    if name_taken(&state, &n.name, Some(id)).await? {
        return Err(ApiError::conflict("模板名已存在"));
    }
    let now = now_unix();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE waf_templates SET name = ?1, waf_profile = ?2, rate_per_sec = ?3, burst = ?4, \
                 ip_allow = ?5, ip_deny = ?6, updated_at = ?7 WHERE id = ?8",
                rusqlite::params![n.name, n.profile, n.rate, n.burst, n.ip_allow, n.ip_deny, now, id],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "waf_template.update", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 删除模板（写需 `site.manage`；id 不存在 → 404）。
pub async fn delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_MANAGE)?;
    ensure_exists(&state, id).await?;
    state
        .db
        .exec(move |conn| {
            conn.execute("DELETE FROM waf_templates WHERE id = ?1", rusqlite::params![id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "waf_template.delete", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({ "ok": true })))
}

/// 先读后判：name 是否已被占用（exclude 用于更新时排除自身）。
/// 唯一冲突**不能**依赖 UNIQUE 兜底——db.exec 会把闭包错误一律包成 500，
/// 故这里先读后判，命中即 409（与 sites/crud.rs 同纪律）。
async fn name_taken(state: &Shared, name: &str, exclude_id: Option<i64>) -> Result<bool, ApiError> {
    let name = name.to_string();
    state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM waf_templates WHERE name = ?1 AND (?2 IS NULL OR id != ?2))",
                rusqlite::params![name, exclude_id],
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
        .map_err(Into::into)
}

async fn fetch_one(state: &Shared, id: i64) -> Result<Option<TplDto>, ApiError> {
    state
        .pool
        .with(move |conn| {
            conn.query_row(SQL_ONE, rusqlite::params![id], row_dto)
                .optional()
                .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await
        .map_err(Into::into)
}

/// 先读后写：id 不存在 → 404（「缺失即 404、非法即 400」）。
async fn ensure_exists(state: &Shared, id: i64) -> Result<(), ApiError> {
    let found: bool = state
        .pool
        .with(move |conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM waf_templates WHERE id = ?1)",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;
    if !found {
        return Err(ApiError::not_found("模板不存在"));
    }
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn mem_db() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        panel_db::migrate::apply(&mut c).unwrap();
        c
    }

    /// 026 迁移后的表形状：列齐全、可读写
    #[test]
    fn schema_after_migration_026() {
        let c = mem_db();
        // 空库无行（QueryReturnedNoRows）而非结构错
        let e = c
            .query_row(SQL_ONE, [1], |_| Ok(()))
            .unwrap_err();
        assert!(matches!(e, rusqlite::Error::QueryReturnedNoRows), "空库应无行而非结构错: {e:?}");
    }

    /// CRUD 往返 + updated_at 刷新 + 只动目标行
    #[test]
    fn create_update_delete_roundtrip() {
        let c = mem_db();
        c.execute(
            "INSERT INTO waf_templates(name, waf_profile, rate_per_sec, burst, ip_allow, ip_deny, created_at, updated_at) \
             VALUES('基线', 'basic', 0, 0, '', '', 100, 100)",
            [],
        )
        .unwrap();
        let id1 = c.last_insert_rowid();
        c.execute(
            "INSERT INTO waf_templates(name, waf_profile, rate_per_sec, burst, ip_allow, ip_deny, created_at, updated_at) \
             VALUES('严格', 'strict', 50, 100, '10.0.0.0/24', '', 100, 100)",
            [],
        )
        .unwrap();
        let id2 = c.last_insert_rowid();

        // 读回 id2：档位/限速/IP 正确落库
        let dto = c.query_row(SQL_ONE, [id2], row_dto).unwrap();
        assert_eq!(dto.name, "严格");
        assert_eq!(dto.waf_profile, "strict");
        assert_eq!((dto.rate_per_sec, dto.burst), (50, 100));
        assert_eq!(dto.ip_allow, vec!["10.0.0.0/24".to_string()]);

        // update 只动目标行且刷新 updated_at
        c.execute(
            "UPDATE waf_templates SET name='严格改', updated_at=200 WHERE id=?1",
            [id1],
        )
        .unwrap();
        let u2: i64 = c.query_row("SELECT updated_at FROM waf_templates WHERE id=?1", [id2], |r| r.get(0)).unwrap();
        assert_eq!(u2, 100, "update 不得波及邻行");
        let n1: String = c.query_row("SELECT name FROM waf_templates WHERE id=?1", [id1], |r| r.get(0)).unwrap();
        assert_eq!(n1, "严格改");

        // delete 只删目标行
        c.execute("DELETE FROM waf_templates WHERE id=?1", [id1]).unwrap();
        let left: i64 = c.query_row("SELECT COUNT(*) FROM waf_templates", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 1);
    }

    fn req(name: &str) -> TplReq {
        TplReq { name: name.to_string(), profile: None, rate_per_sec: None, burst: None, ip_allow: None, ip_deny: None }
    }

    /// 归一：默认 basic、rate 0=不限速；复用 build_waf 的约束
    #[test]
    fn normalize_defaults_and_constraints() {
        // 全缺省 → basic / 0 / 0
        let n = normalize(&req("默认")).unwrap();
        assert_eq!((n.profile.as_str(), n.rate, n.burst), ("basic", 0, 0));

        // 限速时 burst 缺省 → rate×2（build_waf 语义）
        let n = normalize(&TplReq { rate_per_sec: Some(50), ..req("限速") }).unwrap();
        assert_eq!((n.rate, n.burst), (50, 100));

        // 边界值本身必须放过
        let n = normalize(&TplReq { profile: Some("strict".into()), rate_per_sec: Some(1000), burst: Some(10000), ..req("边界") }).unwrap();
        assert_eq!((n.profile.as_str(), n.rate, n.burst), ("strict", 1000, 10000));
    }

    /// 归一负向：空名/超长名/坏档位/越界/burst 无 rate/坏 IP 全部拒绝
    #[test]
    fn normalize_rejects_invalid() {
        assert!(normalize(&req("   ")).is_err(), "空名应拒");
        assert!(normalize(&req(&"x".repeat(NAME_MAX + 1))).is_err(), "超长名应拒");
        assert!(normalize(&TplReq { profile: Some("paranoid".into()), ..req("p") }).is_err(), "未知档位应拒");
        assert!(normalize(&TplReq { rate_per_sec: Some(1001), ..req("r") }).is_err(), "rate 越界应拒");
        assert!(normalize(&TplReq { burst: Some(10001), ..req("b") }).is_err(), "burst 越界应拒");
        assert!(normalize(&TplReq { burst: Some(5), ..req("bnr") }).is_err(), "不限速却带 burst 应拒");
        assert!(normalize(&TplReq { ip_allow: Some("10.0.0.300".into()), ..req("ip") }).is_err(), "坏 IP 应拒");
        assert!(normalize(&TplReq { ip_allow: Some("2001:db8::1".into()), ..req("ip6") }).is_err(), "IPv6 应拒");
        // 合法 CIDR + 多值放行
        let n = normalize(&TplReq { ip_allow: Some("192.168.1.10, 10.0.0.0/24".into()), ..req("ok") }).unwrap();
        assert_eq!(n.ip_allow, "192.168.1.10,10.0.0.0/24");
    }
}
