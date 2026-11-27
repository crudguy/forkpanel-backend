//! DNS 提供商凭据管理（P2-10）。
//!
//! 凭据**密文入库**（AES-GCM + 主密钥，`enc:<hex>` 形态），与私钥 / 数据库口令 /
//! LLM api_key 同一套纪律。列表接口**只回显掩码**——前端拿到完整 token 就等于
//! 任何人都能从浏览器里抄走 DNS 控制权。
//!
//! 更新时 `secret` 留空 = **保持原值不变**。这不是"偷懒"，是必须的：掩码回显意味着
//! 前端拿不到原文，若留空被当成"清空 token"，用户每次只想改个 label 都会把凭据删掉。

use super::*;
use crate::extract::PanelJson;

/// 目前只支持 Cloudflare。留成常量而非枚举，是因为"支持哪些家"是产品决策，
/// 而落库的 provider 值必须与前端选项、开关文案三处一致——单一常量最容易对齐。
pub const PROVIDER_CLOUDFLARE: &str = "cloudflare";

fn supported_providers() -> &'static [&'static str] {
    &[PROVIDER_CLOUDFLARE]
}

fn provider_label(p: &str) -> &'static str {
    match p {
        PROVIDER_CLOUDFLARE => "Cloudflare",
        _ => "未知提供商",
    }
}

/// 掩码：只露前 4 后 4，中间固定 6 个星号（不按真实长度伸缩——那会泄露长度信息）。
///
/// 短于 12 字符的凭据整串打码：露前 4 后 4 会把大半内容显示出来。
pub fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    if n < 12 {
        return "*".repeat(8);
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}******{tail}")
}

/// 校验 provider 名。未知值直接拒——静默接受会让库里躺一条谁也用不上的记录。
pub fn validate_provider(p: &str) -> Result<&'static str> {
    supported_providers()
        .iter()
        .find(|x| **x == p)
        .copied()
        .ok_or_else(|| {
            let all: Vec<&str> = supported_providers().to_vec();
            PanelError::Validation {
                field: "provider",
                reason: format!("不支持的 DNS 提供商 `{p}`；当前支持：{}", all.join(", ")),
            }
        })
}

/// 库里的 `enc:<hex>` → 明文。解不开返回 None（而不是报错）：
/// 调用方要看的是"凭据还能不能用"，主密钥换了导致解不开也必须能如实报告，
/// 不能让整个列表接口 500。
fn decrypt_secret(state: &Shared, enc: &str) -> Option<String> {
    let hex = enc.strip_prefix("enc:")?;
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    let blob: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .ok()?;
    let master = state.require_secret_key().ok()?;
    master.decrypt(&blob).ok().and_then(|b| String::from_utf8(b).ok())
}

fn encrypt_secret(state: &Shared, plain: &str) -> ApiResult<String> {
    let master = state.require_secret_key()?;
    let blob = master.encrypt(plain.as_bytes()).map_err(ApiError::from)?;
    let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("enc:{hex}"))
}

/// 取出某 provider 的明文 token + 用户填的默认 zone（供签发任务在提交时带入）。
///
/// 与列表接口刻意分开：`list_dns_creds` 永远只给掩码，明文只在这一条内部路径上
/// 出现一次，且立即交给任务对象、随任务析构消失。
/// `zone_hint` 必须一起取：它是用户可见的配置项，签发时不用就是「假控制」。
#[derive(Debug, Clone)]
pub struct DnsSecret {
    pub token: String,
    pub zone_hint: String,
}

pub async fn credentials_for(state: &Shared, provider: &str) -> Result<DnsSecret> {
    let p = provider.to_string();
    let row = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT secret_enc, zone_hint FROM dns_credentials WHERE provider = ?1")
                .map_err(db_err)?;
            let mut it = st
                .query_map([p], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(db_err)?;
            it.next().transpose().map_err(db_err)
        })
        .await?
        .ok_or_else(|| PanelError::Validation {
            field: "dns_provider",
            reason: format!("未找到 `{provider}` 的 DNS 凭据"),
        })?;
    let (enc, zone_hint) = row;
    let token = decrypt_secret(state, &enc).ok_or_else(|| PanelError::Validation {
        field: "secret",
        reason: "已存 DNS 凭据无法解密（主密钥可能已更换），请重新填写 API Token".into(),
    })?;
    Ok(DnsSecret { token, zone_hint })
}

#[derive(Debug, Serialize)]
pub struct DnsCredDto {
    pub id: i64,
    pub provider: String,
    pub provider_label: String,
    pub label: String,
    /// 掩码后的凭据（**永不返回明文**）
    pub secret_masked: String,
    pub zone_hint: String,
    /// 凭据能否解密。/ `false` 通常意味着主密钥换过——要明确告诉用户去重填，
    /// 而不是让他在签发时撞一个看不懂的错。
    pub usable: bool,
    pub last_check_at: i64,
    pub last_check_ok: bool,
    pub last_check_msg: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 列出全部凭据（掩码）。
pub async fn list_dns_creds(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    let rows = state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, provider, label, secret_enc, zone_hint, last_check_at, last_check_ok, last_check_msg, created_at, updated_at \
                     FROM dns_credentials ORDER BY id",
                )
                .map_err(db_err)?;
            let it = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, i64>(8)?,
                        r.get::<_, i64>(9)?,
                    ))
                })
                .map_err(db_err)?;
            it.collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)
        })
        .await?;
    let out: Vec<DnsCredDto> = rows
        .into_iter()
        .map(|(id, provider, label, enc, zh, lca, lco, lcm, ca, ua)| {
            let plain = decrypt_secret(&state, &enc);
            DnsCredDto {
                provider_label: provider_label(&provider).to_string(),
                provider,
                id,
                label,
                secret_masked: plain.as_deref().map(mask_secret).unwrap_or_else(|| "（无法解密）".into()),
                zone_hint: zh,
                usable: plain.is_some(),
                last_check_at: lca,
                last_check_ok: lco != 0,
                last_check_msg: lcm,
                created_at: ca,
                updated_at: ua,
            }
        })
        .collect();
    Ok(ok(serde_json::json!({ "items": out })))
}

#[derive(Debug, Deserialize)]
pub struct DnsCredReq {
    pub provider: String,
    #[serde(default)]
    pub label: String,
    /// 新建必填；更新时留空 = 保持原值
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub zone_hint: String,
}

/// 新建或更新凭据（按 provider 唯一 ⇒ 同一 provider 再提交就是更新）。
///
/// 刻意做成 upsert 而不是 PUT /{id}：前端一个 provider 只该有一份凭据，
/// 让用户去关心"记录 id"纯属把内部实现泄漏到界面上。
pub async fn save_dns_cred(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<DnsCredReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "dns.cred.save")?;
    let provider = validate_provider(req.provider.trim())?.to_string();
    let secret = req.secret.trim();
    let label = req.label.trim();
    let zone_hint = req.zone_hint.trim();

    // 现有记录（决定"留空是否保留原值"）
    let existing = state
        .pool
        .with({
            let p = provider.clone();
            move |conn| {
                let mut st = conn
                    .prepare("SELECT id, secret_enc FROM dns_credentials WHERE provider = ?1")
                    .map_err(db_err)?;
                let mut it = st.query_map([p], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))).map_err(db_err)?;
                it.next().transpose().map_err(db_err)
            }
        })
        .await?;

    let enc = if secret.is_empty() {
        match &existing {
            // 留空 + 已有记录 = 保持原值
            Some((_, old)) => old.clone(),
            // 留空 + 没有记录 = 没法凭空造一个凭据
            None => {
                return Err(ApiError::bad_request(
                    "secret",
                    format!("首次添加 {} 必须填写 API Token", provider_label(&provider)),
                ))
            }
        }
    } else {
        // 先验再存：存一个已吊销的 token，用户要到签发时才撞错，且错因指向"域名配置"
        // 而不是凭据本身，极难自查。
        if provider == PROVIDER_CLOUDFLARE {
            let chk = cloudflare::check_token(secret).await?;
            if chk.zone_count == 0 {
                return Err(ApiError::bad_request(
                    "secret",
                    "Token 有效但看不到任何 zone。请确认该 Token 至少拥有 Zone:Read 权限，\
                     且账号下确有域名（只有 Zone.DNS:Edit 而无 Zone:Read 时也会是 0）",
                ));
            }
        }
        encrypt_secret(&state, secret)?
    };

    let now = crate::now_unix();
    let (p, lab, enc2, zh) = (provider.clone(), label.to_string(), enc, zone_hint.to_string());
    let id = state
        .db
        .exec(move |conn| {
            conn.execute(
                "INSERT INTO dns_credentials(provider, label, secret_enc, zone_hint, created_at, updated_at) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?5) \
                 ON CONFLICT(provider) DO UPDATE SET \
                   label = excluded.label, secret_enc = excluded.secret_enc, \
                   zone_hint = excluded.zone_hint, updated_at = excluded.updated_at",
                rusqlite::params![p, lab, enc2, zh, now],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    let _ = id;
    // 重新取 id（upsert 后自增 id 可能不是新值）
    let new_id = state
        .pool
        .with({
            let p = provider.clone();
            move |conn| {
                let mut st = conn
                    .prepare("SELECT id FROM dns_credentials WHERE provider = ?1")
                    .map_err(db_err)?;
                let mut it = st.query_map([p], |r| r.get::<_, i64>(0)).map_err(db_err)?;
                it.next().transpose().map_err(db_err)
            }
        })
        .await?
        .ok_or_else(|| ApiError::not_found("dns_credential"))?;
    // 改了凭据就把上次校验结果作废：否则界面会继续显示"上次校验通过"，
    // 而那说的是旧 token 的事——典型的状态与实体不同步。
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE dns_credentials SET last_check_at = 0, last_check_ok = 0, last_check_msg = '' WHERE id = ?1",
                [new_id],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "dns.cred.save", &provider, "ok").await;
    Ok(ok(serde_json::json!({ "id": new_id, "provider": provider })))
}

/// 删除凭据（按 provider）。
pub async fn delete_dns_cred(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(provider): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    let p = validate_provider(provider.trim())?.to_string();
    let p2 = p.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute("DELETE FROM dns_credentials WHERE provider = ?1", [p2])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "dns.cred.delete", &p, "ok").await;
    Ok(ok(serde_json::json!({ "deleted": true })))
}

/// 重新校验已存凭据（不要求用户重填 token）。
///
/// 用途：DNS 凭据会在使用方单方面失效（token 过期、权限被撤、zone 转出）。
/// 只让用户"重填一遍才知对错"会把排查成本全压给他。
pub async fn check_dns_cred(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(provider): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    crate::ratelimit::check_heavy(&state, &s.username, "dns.cred.check")?;
    let p = validate_provider(provider.trim())?.to_string();
    let enc = state
        .pool
        .with({
            let p = p.clone();
            move |conn| {
                let mut st = conn
                    .prepare("SELECT secret_enc FROM dns_credentials WHERE provider = ?1")
                    .map_err(db_err)?;
                let mut it = st.query_map([p], |r| r.get::<_, String>(0)).map_err(db_err)?;
                it.next().transpose().map_err(db_err)
            }
        })
        .await?
        .ok_or_else(|| ApiError::not_found("dns_credential"))?;
    let plain = decrypt_secret(&state, &enc).ok_or_else(|| {
        ApiError::bad_request(
            "secret",
            "已存凭据无法解密（主密钥可能已更换）。请重新填写 API Token",
        )
    })?;
    let now = crate::now_unix();
    let (ok_flag, msg, zones) = match cloudflare::check_token(&plain).await {
        Ok(c) => (true, format!("可见 {} 个 zone：{}", c.zone_count, c.zones.join(", ")), c.zones),
        Err(e) => (false, format!("{e}"), Vec::new()),
    };
    // 无论校验成败都落库：用户点"重新校验"就是为了看到真实结果，
    // 失败不记等于下次进来还是旧结论。
    let m2 = msg.clone();
    let p2 = p.clone();
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE dns_credentials SET last_check_at = ?1, last_check_ok = ?2, last_check_msg = ?3 WHERE provider = ?4",
                rusqlite::params![now, ok_flag as i64, m2, p2],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;
    audit(&state, &s, "dns.cred.check", &p, if ok_flag { "ok" } else { "fail" }).await;
    Ok(ok(serde_json::json!({
        "ok": ok_flag,
        "message": msg,
        "zones": zones,
        "checked_at": now,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_hides_most_of_long_secret() {
        let m = mask_secret("abcdefghijklmnopqrstuvwxyz");
        assert!(m.starts_with("abcd"), "{m}");
        assert!(m.ends_with("wxyz"), "{m}");
        assert!(!m.contains("efghijkl"), "中间段不应泄漏：{m}");
    }

    #[test]
    fn mask_hides_entirely_when_short() {
        // 12 字符以下露前 4 后 4 会把大半内容显示出来
        for s in ["abc", "abcdefghijk"] {
            let m = mask_secret(s);
            assert_eq!(m, "*".repeat(8), "`{s}` 应整串打码，实际 {m}");
            for ch in s.chars() {
                assert!(!m.contains(ch), "短凭据任何字符都不该出现：{m}");
            }
        }
    }

    #[test]
    fn mask_length_does_not_leak_real_length() {
        // 两个长度差很多的凭据，掩码后中间星号数必须一样（否则泄露长度）
        let a = mask_secret("abcdefghijkl");       // 12
        let b = mask_secret("abcdefghijklmnopqrstuvwxyz0123456789");
        let stars = |s: &str| s.chars().filter(|c| *c == '*').count();
        assert_eq!(stars(&a), stars(&b), "星号数量不应随真实长度变化");
    }

    #[test]
    fn unknown_provider_is_rejected() {
        assert!(validate_provider("cloudflare").is_ok());
        for bad in ["", "aliyun", "dnspod", "route53", "Cloudflare"] {
            assert!(validate_provider(bad).is_err(), "应拒绝 `{bad}`");
        }
    }
}
