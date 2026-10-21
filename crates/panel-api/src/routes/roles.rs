//! 角色管理（RBAC 自定义角色）。
//!
//! ## 设计取舍
//! 1. **内置四角色由代码定义**（[`crate::auth::permissions_for_role`]），不落库——
//!    两处定义必然漂移，而权限判断出错是安全事故，不能有两份"事实"。
//! 2. 本模块只管**自定义**角色；名字不得与内置角色重名（同名两套权限定义最难排查）。
//! 3. **防提权**：创建/修改角色时，权限集合必须是**调用者自身权限的子集**。
//!    没有这一条，拥有 `user.manage` 的人就能造出比 owner 更大的角色再把自己升上去。
//! 4. **不开放改名**：`users.role` 存的是名字，改名会让引用悬空。要换名字就删了重建。
//! 5. **仍被用户引用的角色不允许删除**：删掉会让那些账号在下次登录解析出零权限
//!    （默认拒绝），表现是"突然什么都干不了"——排查这种故障极费时间。
//!
//! ## 生效时机（已知边界，如实写出）
//! 会话里的权限是**登录时**解析并缓存的。因此角色权限变更对**已登录会话**
//! 不会立即生效，需重新登录。这是刻意取舍：每次请求都查库解权限，代价与收益
//! 不成比例。但必须说明清楚，否则会被当成"改了没反应"的 bug。

use crate::{
    auth::{perm, permissions_for_role, BUILTIN_ROLES},
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    Json,
};
use panel_core::PanelError;
use serde::{Deserialize, Serialize};
use crate::extract::PanelJson;

const COLS: &str = "name, permissions, created_at";
const ROLE_NAME_MIN: usize = 2;
const ROLE_NAME_MAX: usize = 32;
const ROLE_PERMS_MAX: usize = 64;

#[derive(Debug, Serialize)]
pub struct RoleDto {
    pub name: String,
    pub permissions: Vec<String>,
    /// 内置角色（不可改、不可删）
    pub builtin: bool,
    /// 自定义角色的创建时间；内置为 `None`
    pub created_at: Option<i64>,
}

fn db_err(e: rusqlite::Error) -> PanelError {
    PanelError::Database(e.to_string())
}

/// 角色名规则：小写字母开头，后接小写字母/数字/`_`/`-`，长度 2~32。
///
/// 收紧字符集是为了**可用性与安全**：名字会出现在界面与审计记录里，
/// 允许任意字符就会带来同形字冒充（例如用西里尔字母 `а` 拼出的 `аdmin`）。
pub fn valid_role_name(n: &str) -> bool {
    let b = n.as_bytes();
    if b.len() < ROLE_NAME_MIN || b.len() > ROLE_NAME_MAX {
        return false;
    }
    if !b[0].is_ascii_lowercase() {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// 校验并规范化权限集合。`granted` 是调用者自身的权限（子集约束的依据）。
fn check_permissions(requested: &[String], granted: &[String]) -> ApiResult<Vec<String>> {
    if requested.is_empty() {
        return Err(ApiError::bad_request("permissions", "至少要选择一项权限"));
    }
    if requested.len() > ROLE_PERMS_MAX {
        return Err(ApiError::bad_request("permissions", "权限项过多"));
    }
    let known = crate::auth::all_permissions();
    let mut out: Vec<String> = Vec::new();
    for p in requested {
        if !known.contains(&p.as_str()) {
            return Err(ApiError::bad_request("permissions", format!("未知权限：{p}")));
        }
        // **防提权**：不能授予自己没有的权限
        if !granted.iter().any(|g| g == p) {
            return Err(ApiError::bad_request(
                "permissions",
                format!("不能授予自己不具备的权限：{p}"),
            ));
        }
        if !out.contains(p) {
            out.push(p.clone());
        }
    }
    Ok(out)
}

/// 读一条自定义角色。JSON 损坏时返回 `None`（视作不存在，由调用方决定语义）——
/// 但 `list` 里会把它显示出来，不能让一条坏数据把整个角色列表打空。
async fn fetch_role(state: &Shared, name: &str) -> ApiResult<Option<Vec<String>>> {
    let n = name.to_string();
    let raw = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT permissions FROM roles WHERE name = ?1")
                .map_err(db_err)?;
            let mut it = st
                .query_map([n], |r| r.get::<_, String>(0))
                .map_err(db_err)?;
            let row: Option<String> = it.next().transpose().map_err(db_err)?;
            Ok(row)
        })
        .await?;
    Ok(raw.map(|js| serde_json::from_str::<Vec<String>>(&js).unwrap_or_default()))
}

/// 列出全部角色：内置（`builtin=true`，权限来自代码）+ 自定义（按名排序）。
pub async fn list(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    let custom = state
        .pool
        .with(|conn| {
            let sql = format!("SELECT {COLS} FROM roles ORDER BY name");
            let mut st = conn.prepare(&sql).map_err(db_err)?;
            let it = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .map_err(db_err)?;
            let mut out: Vec<RoleDto> = Vec::new();
            for row in it {
                let (name, js, ts) = row.map_err(db_err)?;
                // 坏 JSON 显示为空权限而不是跳过：跳过会让这个角色在界面上"消失"，
                // 而它其实还挂在某些用户身上。
                let permissions: Vec<String> = serde_json::from_str(&js).unwrap_or_default();
                out.push(RoleDto { name, permissions, builtin: false, created_at: Some(ts) });
            }
            Ok(out)
        })
        .await?;

    let mut all: Vec<RoleDto> = BUILTIN_ROLES
        .iter()
        .map(|r| RoleDto {
            name: (*r).to_string(),
            permissions: permissions_for_role(r),
            builtin: true,
            created_at: None,
        })
        .collect();
    all.extend(custom);
    Ok(ok(serde_json::json!({
        "roles": all,
        "known_permissions": crate::auth::all_permissions(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleReq {
    pub name: String,
    pub permissions: Vec<String>,
}

pub async fn create(
    State(state): State<Shared>, Auth(s): Auth, PanelJson(req): PanelJson<CreateRoleReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    let name = req.name.trim().to_lowercase();
    if !valid_role_name(&name) {
        return Err(ApiError::bad_request(
            "name",
            "角色名需 2~32 位、小写字母开头，只含小写字母/数字/下划线/连字符",
        ));
    }
    if BUILTIN_ROLES.contains(&name.as_str()) {
        return Err(ApiError::bad_request("name", format!("`{name}` 是内置角色名，不可占用")));
    }
    let perms = check_permissions(&req.permissions, &s.permissions)?;
    let json = serde_json::to_string(&perms)
        .map_err(|e| ApiError::from(PanelError::Internal(format!("序列化权限失败: {e}"))))?;
    let now = crate::now_unix();
    let name_c = name.clone();
    let res = state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO roles(name, permissions, created_at) VALUES(?1, ?2, ?3)",
                rusqlite::params![name_c, json, now],
            )
            .map(|_| panel_db::WriteAck { rows_changed: 1 })
            .map_err(db_err)
        })
        .await;
    match res {
        Ok(_) => {}
        Err(e) if e.to_string().contains("UNIQUE") || e.to_string().contains("PRIMARY") => {
            return Err(ApiError::bad_request("name", format!("角色 `{name}` 已存在")));
        }
        Err(e) => return Err(ApiError::from(e)),
    }
    audit(&state, &s, "role.create", &name, "ok").await;
    Ok(ok(serde_json::json!({ "name": name })))
}

#[derive(Debug, Deserialize)]
pub struct RolePermsReq {
    pub permissions: Vec<String>,
}

/// 修改自定义角色的权限（不开放改名，理由见模块头）。
pub async fn patch(
    State(state): State<Shared>, Auth(s): Auth,
    AxPath(name): AxPath<String>, PanelJson(req): PanelJson<RolePermsReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    if BUILTIN_ROLES.contains(&name.as_str()) {
        return Err(ApiError::bad_request("name", format!("`{name}` 是内置角色，不可修改")));
    }
    if fetch_role(&state, &name).await?.is_none() {
        return Err(ApiError::from(PanelError::NotFound(format!("角色 {name}"))));
    }
    let perms = check_permissions(&req.permissions, &s.permissions)?;
    let json = serde_json::to_string(&perms)
        .map_err(|e| ApiError::from(PanelError::Internal(format!("序列化权限失败: {e}"))))?;
    let name_c = name.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE roles SET permissions = ?1 WHERE name = ?2",
                rusqlite::params![json, name_c],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(db_err)
        })
        .await?;
    audit(&state, &s, "role.patch", &name, "ok").await;
    Ok(ok(serde_json::json!({ "name": name, "updated": true })))
}

/// 删除自定义角色（内置拒绝；仍被用户引用也拒绝，理由见模块头）。
pub async fn remove(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::USER_MANAGE)?;
    if BUILTIN_ROLES.contains(&name.as_str()) {
        return Err(ApiError::bad_request("name", format!("`{name}` 是内置角色，不可删除")));
    }
    if fetch_role(&state, &name).await?.is_none() {
        return Err(ApiError::from(PanelError::NotFound(format!("角色 {name}"))));
    }
    let n = name.clone();
    let in_use: i64 = state
        .pool
        .with(move |conn| {
            conn.query_row("SELECT COUNT(*) FROM users WHERE role = ?1", [n], |r| r.get(0))
                .map_err(db_err)
        })
        .await?;
    if in_use > 0 {
        return Err(ApiError::bad_request(
            "name",
            format!("仍有 {in_use} 个用户使用该角色，请先把他们改到别的角色"),
        ));
    }
    let n2 = name.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute("DELETE FROM roles WHERE name = ?1", [n2])
                .map(|c| panel_db::WriteAck { rows_changed: c })
                .map_err(db_err)
        })
        .await?;
    audit(&state, &s, "role.delete", &name, "ok").await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_name_rules_reject_confusables_and_bad_shapes() {
        for ok_name in ["ops-readonly", "site_admin", "db2viewer"] {
            assert!(valid_role_name(ok_name), "应接受: {ok_name}");
        }
        for bad in ["Owner", "a", "1ops", "ops.read", "运维", "", &"x".repeat(33)] {
            assert!(!valid_role_name(bad), "应拒绝: {bad:?}");
        }
    }

    #[test]
    fn permissions_must_be_known_and_subset_of_caller() {
        let mine = vec!["site.view".to_string(), "site.manage".to_string()];
        assert!(check_permissions(&["site.view".to_string()], &mine).is_ok());
        // 未知权限
        assert!(check_permissions(&["site.fly".to_string()], &mine).is_err());
        // **提权**：授予自己没有的权限必须拒绝
        assert!(check_permissions(&["user.manage".to_string()], &mine).is_err());
        // 空集合没有意义
        assert!(check_permissions(&[], &mine).is_err());
    }

    #[test]
    fn builtin_role_names_are_reserved() {
        for r in BUILTIN_ROLES {
            assert!(valid_role_name(r), "内置名应自身合法: {r}");
        }
    }
}
