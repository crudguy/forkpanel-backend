use super::*;
use crate::extract::PanelJson;

/// 自签证书有效期（天）。825 天对齐主流浏览器对单张证书的最长信任上限。
const SELF_SIGNED_DAYS: u32 = 825;

/// 面板托管的证书落盘目录（nginx 从这里读取 cert/key）。
fn ssl_dir(state: &Shared) -> PathBuf {
    state.os.paths().data_dir().join("ssl")
}

/// 面板本地根 CA 目录（签发/验证自签 leaf 用；浏览器只需下载 `ca.crt`）。
fn ca_dir(state: &Shared) -> PathBuf {
    ssl_dir(state).join("ca")
}

/// 由首个域名派生该站点证书的 (crt, key) 落盘路径（与 provider 配置文件名同源命名）。
pub(super) fn cert_paths_for(state: &Shared, domains: &[String]) -> (PathBuf, PathBuf) {
    let stem = slug(domains.first().map(|s| s.as_str()).unwrap_or("site"));
    let dir = ssl_dir(state);
    (dir.join(format!("{stem}.crt")), dir.join(format!("{stem}.key")))
}

/// 写证书/私钥到磁盘：crt 0644、key 0600（私钥绝不可被他人读取）。
fn write_cert_files(crt: &Path, key: &Path, cert_pem: &str, key_pem: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = crt.parent().ok_or_else(|| PanelError::Internal("bad cert path".into()))?;
    std::fs::create_dir_all(dir).map_err(|e| PanelError::Internal(e.to_string()))?;
    std::fs::write(crt, cert_pem).map_err(|e| PanelError::Internal(e.to_string()))?;
    std::fs::write(key, key_pem).map_err(|e| PanelError::Internal(e.to_string()))?;
    let _ = std::fs::set_permissions(crt, std::fs::Permissions::from_mode(0o644));
    let _ = std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// 该站点最近一张证书覆盖的域名（apply 注入 tls / delete 清理文件都用它）。
pub(super) async fn cert_domains_for_site(state: &Shared, site_id: i64) -> Result<Option<Vec<String>>> {
    state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains FROM ssl_certs WHERE site_id = ?1 ORDER BY id DESC LIMIT 1")
                .map_err(db_err)?;
            let mut it = st.query_map([site_id], |r| r.get::<_, String>(0)).map_err(db_err)?;
            match it.next().transpose().map_err(db_err)? {
                Some(js) => Ok(Some(serde_json::from_str(&js).unwrap_or_default())),
                None => Ok(None),
            }
        })
        .await
}

// ─────────────── SSL 证书 ───────────────

#[derive(Debug, Serialize)]
pub struct CertDto {
    pub id: i64,
    pub domain: String,
    pub issuer: Option<String>,
    pub not_after: Option<i64>,
    /// 剩余天数（UI 据此标黄/标红）
    pub days_left: Option<i64>,
    pub auto_renew: bool,
    /// idle | pending | ok | failed
    pub renew_state: String,
    /// acme | self-signed | manual（UI 据此决定自动续期开关是否可用）
    pub source: String,
}

pub async fn certs(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let rows = state
        .pool
        .with(|conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, domains, issuer, not_after, renew_state, auto_renew, source \
                     FROM ssl_certs ORDER BY not_after",
                )
                .map_err(db_err)?;
            let it = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5).unwrap_or(0),
                        r.get::<_, String>(6)?,
                    ))
                })
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(db_err)?);
            }
            Ok(v)
        })
        .await?;

    let now = crate::now_unix();
    let dtos: Vec<CertDto> = rows
        .into_iter()
        .map(|(id, domains_json, issuer, not_after, renew, auto_renew, source)| {
            // 证书覆盖多个域名（JSON 数组）；UI 单域名列展示主域名（首个）
            let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
            let primary = domains.into_iter().next().unwrap_or_default();
            CertDto {
                id,
                domain: primary,
                issuer,
                days_left: not_after.map(|t| (t - now) / 86_400),
                not_after,
                // 真实开关（v10 起有 auto_renew 列）。注意它只表示"用户已允许自动续期"，
                // 真正能否续还取决于 ssl.acme 能力位（certbot 是否可用）——
                // UI 需结合能力位判断，别把"开关关着"和"根本用不了"混为一谈。
                auto_renew: auto_renew != 0,
                renew_state: renew,
                source,
            }
        })
        .collect();
    Ok(ok(dtos))
}

/// 证书自动续期扫描的最近运行状态（前端"上次/下次扫描"展示用）。
///
/// 由内部调度器每日 4:05 触发的 `auto_renew_sweep` 写入 `cert_sweep_state`；
/// 本端点只读取，不参与调度。未运行过时整表为空 → 返回 `last_at=0`，
/// 前端据此显示"尚未运行"。
pub async fn cert_renew_sweep_state(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let row: Option<(i64, i64)> = state
        .pool
        .with(|conn| {
            match conn.query_row(
                "SELECT last_at, last_queued FROM cert_sweep_state WHERE id = 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            ) {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await?;
    let (last_at, last_queued) = row.unwrap_or((0, 0));
    // 调度为每日一次，下次 ≈ 上次 + 24h；从未运行则 0（前端显示"尚未运行"）
    let next_at = if last_at > 0 { last_at + 86_400 } else { 0 };
    Ok(ok(serde_json::json!({
        "last_at": last_at,
        "last_queued": last_queued,
        "next_at": next_at,
    })))
}

#[derive(Debug, Deserialize)]
pub struct SslApplyReq {
    /// 留空则沿用站点现有域名
    #[serde(default)]
    pub domains: Vec<String>,
    /// `self-signed`（缺省）| `http-01` | `dns-01`
    pub method: Option<String>,
    #[allow(dead_code)]
    pub email: Option<String>,
}

/// 申请证书。按 `method` 分流：
/// - `self-signed`：面板自签（**同步**完成，需 `ssl.selfsigned` + 主密钥，离线可用）；
/// - `http-01`/`dns-01`：ACME，`ssl.acme` 门控，未接入时诚实 501（#61）。
pub async fn ssl_apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<SslApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    // 无 Web 服务器底座时拒发证书：证书没有进程可加载，只会制造
    // "已配置"却永远不生效的假象（与 create/apply 同一守卫，防绕过 UI）。
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }
    let site = fetch_one(&state, id).await?.ok_or_else(|| ApiError::not_found("site"))?;

    // 域名：请求覆盖 或 沿用站点现有域名
    let domains: Vec<String> = if req.domains.is_empty() {
        serde_json::from_str(&site.domains).unwrap_or_default()
    } else {
        let mut out = Vec::with_capacity(req.domains.len());
        for d in &req.domains {
            let dom = domain(d.trim())
                .map_err(|_| ApiError::bad_request("domains", format!("invalid domain: {d}")))?;
            out.push(dom.as_str().to_string());
        }
        out
    };
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "no domain to certify"));
    }

    let method = req.method.clone().unwrap_or_else(|| "self-signed".into());
    match method.as_str() {
        "self-signed" => {}
        "http-01" => {
            if !state.capabilities.get(cap_keys::SSL_ACME).map(|c| c.supported).unwrap_or(false) {
                return Err(ApiError::unsupported("ssl.acme"));
            }
            // ACME 需要真实账户邮箱（CA 用它发到期/异常通知）——没有就明确报错，
            // 绝不静默填一个假地址（那会让用户收不到任何到期提醒）。
            let email = req
                .email
                .as_deref()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| ApiError::bad_request("email", "http-01 签发需要账户邮箱"))?
                .to_string();
            // 注：certbot 回退路线目前只签**主域名**（多域名 SAN 待扩展）
            let webroot = resolve_site_root(&state, &site.root, &site.name)?
                .as_path()
                .to_path_buf();
            let (crt_p, key_p) = cert_paths_for(&state, &domains);
            let job = AcmeTask {
                mode: AcmeMode::Issue,
                site_id: id,
                domains: domains.clone(),
                email,
                webroot,
                crt_p,
                key_p,
                master: state.require_secret_key()?,
                db: state.db.clone(),
            };
            let (tid, _) = state
                .tasks
                .submit(
                    panel_task::TaskRequest {
                        idempotency_key: format!("cert:{id}:{}", domains.join(",")),
                        kind: panel_task::TaskKind::CertIssue,
                        label: format!("ACME 签发证书（{}）", domains.join(", ")),
                        timeout: std::time::Duration::from_secs(900),
                    },
                    job,
                )
                .await
                .map_err(ApiError::from)?;
            audit(&state, &s, "ssl.apply", &id.to_string(), "queued").await;
            return Ok(ok(serde_json::json!({ "task_id": tid, "source": "acme" })));
        }
        "dns-01" => {
            return Err(ApiError::unsupported(
                "dns-01 需 DNS 提供商 API（设计 §2.4 列为 M5）；certbot 回退路线当前仅实现 http-01",
            ))
        }
        other => return Err(ApiError::bad_request("method", format!("unsupported method: {other}"))),
    }

    if !state.capabilities.get(cap_keys::SSL_SELFSIGNED).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("ssl.selfsigned"));
    }
    // 无主密钥则拒绝：私钥必须加密落库，绝不明文（对齐 databases.rs 的纪律）
    let master = state.require_secret_key()?;

    let tmp = state.os.paths().tmp_dir();
    // 改为由面板本地根 CA 签发 leaf（而非裸自签）：装上根证书后浏览器即信任，
    // HTTPS 不再报「非私密连接」。SAN 自动含 localhost/127.0.0.1/::1，本地任意访问方式都匹配。
    let (cert_pem, key_pem) =
        tls::issue_leaf_signed_by_ca(&ca_dir(&state), &tmp, &domains, SELF_SIGNED_DAYS).await?;
    let key_enc = master.encrypt(key_pem.as_bytes()).map_err(ApiError::from)?;

    // 落盘（nginx 读取）；私钥明文只存在于 0600 文件，库内为密文
    let (crt_p, key_p) = cert_paths_for(&state, &domains);
    write_cert_files(&crt_p, &key_p, &cert_pem, &key_pem)?;

    let now = crate::now_unix();
    let not_after = now + (SELF_SIGNED_DAYS as i64) * 86_400;
    // 签发者必须与真实签发者一致：leaf 由面板本地根 CA 签发，写成「Self-Signed」
    // 会让用户在证书列表/浏览器里看到的名字与实际签发者对不上。
    let issuer = tls::CA_CN.to_string();
    let domains_json = serde_json::to_string(&domains).unwrap_or_else(|_| "[]".into());
    let site_id = id;
    let (dj, iss, cert) = (domains_json.clone(), issuer.clone(), cert_pem);
    state
        .db
        .exec(move |conn| {
            // 同站点自签只保留一张：先清旧行再插入
            conn.execute("DELETE FROM ssl_certs WHERE site_id = ?1", [site_id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            conn.execute(
                "INSERT INTO ssl_certs(site_id, domains, issuer, not_after, source, key_enc, cert, renew_state, created_at)
                 VALUES(?1, ?2, ?3, ?4, 'selfsigned', ?5, ?6, 'ok', ?7)",
                rusqlite::params![site_id, dj, iss, not_after, key_enc, cert, now],
            )
            .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: 1 })
        })
        .await?;

    audit(&state, &s, "ssl.apply", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({
        "site_id": id,
        "domains": domains,
        "source": "selfsigned",
        "issuer": issuer,
        "not_after": not_after,
        "days_left": SELF_SIGNED_DAYS,
        "cert_path": crt_p.display().to_string(),
    })))
}

/// 下载面板本地根证书（`ca.crt`）。
///
/// 自签 leaf **全部**由这张根 CA 签发，而浏览器只信任「已安装的根 CA」——
/// 所以「自签证书没法在本地用」的解法不是换证书，而是让用户把根证书装一次。
/// 本端点即分发入口：返回 PEM 包装的 X.509，可被系统/浏览器信任库直接导入。
///
/// **只返回证书、绝不返回私钥**：`ca.key` 始终留在服务器（0600），浏览器不需要它。
pub async fn ssl_ca_download(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Response> {
    // 只读信息，站点查看权限即可——根证书不含私钥，泄露风险为零。
    crate::auth::require(&s, perm::SITE_VIEW)?;
    let tmp = state.os.paths().tmp_dir();
    // 幂等：根 CA 尚未生成（用户还没申请过任何自签证书）时按需创建一张，
    // 保证「先下载根证书、后申请站点证书」的顺序也能拿到同源的根。
    tls::ensure_root_ca(&ca_dir(&state), &tmp).await?;
    let pem = tls::root_ca_pem(&ca_dir(&state))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-x509-ca-cert"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"forkpanel-local-ca.crt\""),
    );
    Ok((headers, pem).into_response())
}

// ─────────────── ACME 任务体（签发 / 续期） ───────────────

/// certbot 默认有效期（天），用于写 `not_after` 供到期提醒与续期判定。
/// **未从 PEM 解析**——那要引入 X.509 解析依赖（预算不允）；certbot 默认即 90 天。
const ACME_DAYS: i64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeMode {
    Issue,
    Renew,
}

/// ACME 证书任务：调 certbot → 落盘 → **私钥加密入库**。
///
/// 与自签走同一条纪律：私钥**绝不明文入库**（库泄露 ≠ 私钥泄露）。
pub struct AcmeTask {
    pub mode: AcmeMode,
    pub site_id: i64,
    pub domains: Vec<String>,
    /// 账户邮箱（仅 Issue 使用；Renew 沿用 certbot 已有账户）
    pub email: String,
    /// http-01 校验目录（站点根目录）
    pub webroot: std::path::PathBuf,
    pub crt_p: std::path::PathBuf,
    pub key_p: std::path::PathBuf,
    pub master: crate::MasterKey,
    pub db: std::sync::Arc<panel_db::WriterActor>,
}

#[async_trait::async_trait]
impl panel_task::TaskBody for AcmeTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        progress.set(10, "调用 certbot").await;
        // 注：certbot 回退路线目前只签**主域名**（多域名 SAN 待扩展）
        let primary = self
            .domains
            .first()
            .cloned()
            .ok_or_else(|| PanelError::Internal("证书域名为空".into()))?;
        let (cert_pem, key_pem) = match self.mode {
            AcmeMode::Issue => tls::issue_acme(&primary, &self.email, &self.webroot).await?,
            AcmeMode::Renew => tls::renew_acme(&primary).await?,
        };

        progress.set(70, "落盘与入库").await;
        write_cert_files(&self.crt_p, &self.key_p, &cert_pem, &key_pem)?;
        let key_enc = self
            .master
            .encrypt(key_pem.as_bytes())
            .map_err(|e| PanelError::Internal(format!("加密私钥失败：{e}")))?;

        let now = crate::now_unix();
        let not_after = now + ACME_DAYS * 86_400;
        let site_id = self.site_id;
        let dj = serde_json::to_string(&self.domains).unwrap_or_else(|_| "[]".into());
        let issuer = "ACME (certbot)".to_string();
        let cert = cert_pem;
        self.db
            .exec(move |conn| {
                conn.execute("DELETE FROM ssl_certs WHERE site_id = ?1", [site_id])
                    .map_err(|e| PanelError::Database(e.to_string()))?;
                conn.execute(
                    // ACME 证书默认开启自动续期（有效期仅 90 天，靠人工点续期必然会漏）。
                    // 用户可在证书列表关掉；selfsigned / manual 恒为 0（无法自动续）。
                    "INSERT INTO ssl_certs(site_id, domains, issuer, not_after, source, key_enc, cert, renew_state, created_at, auto_renew) \
                     VALUES(?1, ?2, ?3, ?4, 'acme', ?5, ?6, 'ok', ?7, 1)",
                    rusqlite::params![site_id, dj, issuer, not_after, key_enc, cert, now],
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
                Ok(panel_db::WriteAck { rows_changed: 1 })
            })
            .await?;

        progress.set(100, "完成").await;
        Ok(panel_task::TaskOutcome {
            state: panel_task::TaskState::Ok,
            exit_code: Some(0),
            output_path: Some(self.crt_p.clone()),
        })
    }
}

/// 手动续期：自签证书重新生成并覆盖；ACME 证书走 `ssl.acme`（未接入时诚实 501）。
pub async fn cert_renew(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    // 续期同样是"签发一张证书"，无底座时一并拒绝——否则旧证书可被续成一个
    // 永远不生效的新证书，把"已配置"的假象重新造出来。
    if !state
        .capabilities
        .get(cap_keys::WEBSERVER_MANAGE)
        .map(|c| c.supported)
        .unwrap_or(false)
    {
        return Err(ApiError::unsupported("webserver.manage"));
    }

    let row = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains, source FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st
                .query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await?
        .ok_or_else(|| ApiError::not_found("cert"))?;
    let (domains_json, source) = row;

    if source != "selfsigned" {
        if !state.capabilities.get(cap_keys::SSL_ACME).map(|c| c.supported).unwrap_or(false) {
            return Err(ApiError::unsupported("ssl.acme"));
        }
        // ACME 续期同样走任务：certbot 可能耗时，且 CA 有限流（LE 5 次/小时/域名）
        let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
        let (crt_p, key_p) = cert_paths_for(&state, &domains);
        let job = AcmeTask {
            mode: AcmeMode::Renew,
            site_id: id,
            domains,
            // renew 沿用 certbot 既有账户，无需邮箱与 webroot
            email: String::new(),
            webroot: std::path::PathBuf::new(),
            crt_p,
            key_p,
            master: state.require_secret_key()?,
            db: state.db.clone(),
        };
        let (tid, _) = state
            .tasks
            .submit(
                panel_task::TaskRequest {
                    // 幂等键按小时：同一小时内重复提交返回同一任务，天然规避 CA 限流
                    idempotency_key: format!("cert-renew:{id}:{}", crate::now_unix() / 3600),
                    kind: panel_task::TaskKind::CertIssue,
                    label: format!("ACME 续期证书（站点 #{id}）"),
                    timeout: std::time::Duration::from_secs(900),
                },
                job,
            )
            .await
            .map_err(ApiError::from)?;
        audit(&state, &s, "ssl.renew", &id.to_string(), "queued").await;
        return Ok(ok(serde_json::json!({ "task_id": tid, "source": "acme" })));
    }
    if !state.capabilities.get(cap_keys::SSL_SELFSIGNED).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("ssl.selfsigned"));
    }
    let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
    if domains.is_empty() {
        return Err(ApiError::bad_request("domains", "cert has no domains"));
    }

    let master = state.require_secret_key()?;
    let tmp = state.os.paths().tmp_dir();
    // 改为由面板本地根 CA 签发 leaf（而非裸自签）：装上根证书后浏览器即信任，
    // HTTPS 不再报「非私密连接」。SAN 自动含 localhost/127.0.0.1/::1，本地任意访问方式都匹配。
    let (cert_pem, key_pem) =
        tls::issue_leaf_signed_by_ca(&ca_dir(&state), &tmp, &domains, SELF_SIGNED_DAYS).await?;
    let key_enc = master.encrypt(key_pem.as_bytes()).map_err(ApiError::from)?;
    let (crt_p, key_p) = cert_paths_for(&state, &domains);
    write_cert_files(&crt_p, &key_p, &cert_pem, &key_pem)?;

    let now = crate::now_unix();
    let not_after = now + (SELF_SIGNED_DAYS as i64) * 86_400;
    // 签发者必须与真实签发者一致：leaf 由面板本地根 CA 签发，写成「Self-Signed」
    // 会让用户在证书列表/浏览器里看到的名字与实际签发者对不上。
    let issuer = tls::CA_CN.to_string();
    let iss2 = issuer.clone();
    let cert2 = cert_pem;
    state
        .db
        .exec(move |conn| {
            conn.execute(
                "UPDATE ssl_certs SET cert = ?1, key_enc = ?2, not_after = ?3, issuer = ?4,
                        renew_state = 'ok', last_error = NULL WHERE id = ?5",
                rusqlite::params![cert2, key_enc, not_after, iss2, id],
            )
            .map(|n| panel_db::WriteAck { rows_changed: n })
            .map_err(|e| PanelError::Database(e.to_string()))
        })
        .await?;

    audit(&state, &s, "cert.renew", &id.to_string(), "ok").await;
    Ok(ok(serde_json::json!({
        "id": id,
        "source": "selfsigned",
        "issuer": issuer,
        "not_after": not_after,
        "days_left": SELF_SIGNED_DAYS,
    })))
}

/// 自动续期的提前量（天）：到期前多久开始尝试续期。
///
/// 取 30 天而非贴着过期线（如 7 天）：续期可能因 CA 限流、http-01 校验失败而失败，
/// 留足窗口才能重试；Let's Encrypt 有效期 90 天，30 天意味着约有 2 个月的重试余量。
const RENEW_WINDOW_DAYS: i64 = 30;

/// 证书自动续期扫描——内部周期任务 `cert.renew_check` 的任务体。
///
/// 每天执行一次：找出 **30 天内到期** 且 `auto_renew=1` 的 **ACME** 证书，逐个
/// 提交 `AcmeTask{Renew}`。刻意**不**在这里直接调 certbot：走任务队列才能被审计、
/// 可看进度，并复用按小时幂等键天然规避 CA 限流（LE 5 次/小时/域名）。
///
/// 返回成功入队条数。能力位缺失（certbot 不在）或主密钥不可用时返回 **0 而不报错**——
/// 周期任务失败不该拖垮面板，也不该每天刷同一条错误日志。
pub async fn auto_renew_sweep(state: Shared) -> panel_core::Result<usize> {
    // 没有 certbot 就没有可交互的 CA，提交必然失败，直接跳过
    let acme_ok = state
        .capabilities
        .get(cap_keys::SSL_ACME)
        .map(|c| c.supported)
        .unwrap_or(false);
    if !acme_ok {
        return Ok(0);
    }
    let Ok(master) = state.require_secret_key() else {
        return Ok(0);
    };

    let now = crate::now_unix();
    let due_before = now + RENEW_WINDOW_DAYS * 86_400;

    let rows: Vec<(i64, String)> = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare(
                    "SELECT id, domains FROM ssl_certs \
                     WHERE source='acme' AND auto_renew=1 \
                       AND not_after IS NOT NULL AND not_after <= ?1",
                )
                .map_err(db_err)?;
            let it = st
                .query_map(rusqlite::params![due_before], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(db_err)?;
            let mut v = Vec::new();
            for x in it {
                v.push(x.map_err(db_err)?);
            }
            Ok(v)
        })
        .await?;

    let mut queued = 0usize;
    for (id, domains_json) in rows {
        let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
        if domains.is_empty() {
            continue;
        }
        let (crt_p, key_p) = cert_paths_for(&state, &domains);
        let job = AcmeTask {
            mode: AcmeMode::Renew,
            site_id: id,
            domains: domains.clone(),
            // Renew 沿用 certbot 既有账户，无需邮箱与 webroot
            email: String::new(),
            webroot: std::path::PathBuf::new(),
            crt_p,
            key_p,
            master,
            db: state.db.clone(),
        };
        // 幂等键按小时：同一小时内重复触发返回同一任务，规避 CA 限流
        let idem = format!("cert-renew:{id}:{}", now / 3600);
        if state
            .tasks
            .submit(
                panel_task::TaskRequest {
                    idempotency_key: idem,
                    kind: panel_task::TaskKind::CertIssue,
                    label: format!("ACME 自动续期证书（#{id}）"),
                    timeout: std::time::Duration::from_secs(900),
                },
                job,
            )
            .await
            .is_ok()
        {
            queued += 1;
            // 系统发起的续期也写操作日志：actor 固定 "system"，
            // 否则自动续期在 UI 审计轨迹里完全不可见（仅服务端 info 日志有）。
            audit_system(
                &state,
                "cert.auto_renew",
                &format!("#{id} {}", domains.join(",")),
                "queued",
            )
            .await;
        }
        // 单条失败不影响其余证书，也不惊动周期任务（失败原因由任务自身记录）
    }

    // 记录扫描时间（供前端展示"上次/下次扫描"）。即便本次入队 0 也写入——
    // 说明扫描确实跑过、只是没有到期证书，而非"从未运行"。
    let sweep_now = now;
    let sweep_queued = queued as i64;
    state
        .pool
        .with(move |conn| {
            conn.execute(
                "INSERT INTO cert_sweep_state(id, last_at, last_queued) VALUES(1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET last_at=excluded.last_at, last_queued=excluded.last_queued",
                rusqlite::params![sweep_now, sweep_queued],
            )
            .map_err(db_err)?;
            Ok(())
        })
        .await?;

    Ok(queued)
}

#[derive(Debug, Deserialize)]
pub struct AutoRenewReq {
    pub enabled: bool,
}

/// 开关证书自动续期。**仅 ACME 证书可开**。
///
/// selfsigned / manual 没有可交互的 CA，给它们开关就是"能点但必失败"的假按钮，
/// 故 SQL 里直接带 `source='acme'` 过滤（顺带避免先读后写的竞态）。
/// 开启前还会校验 `ssl.acme` 能力位——否则用户开了开关却永远不会续，
/// 那是最坏的失败方式（UI 显示"已开启"，实际持续过期）。
pub async fn cert_auto_renew(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
    PanelJson(req): PanelJson<AutoRenewReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    if req.enabled
        && !state
            .capabilities
            .get(cap_keys::SSL_ACME)
            .map(|c| c.supported)
            .unwrap_or(false)
    {
        return Err(ApiError::unsupported("ssl.acme"));
    }
    // 先读后写：校验必须在**读路径**上返回 400/404。若把校验放进 db.exec 闭包，
    // 写通道会把任何 Err 统一包装成 Database 错误 → 用户看到 500（实测踩过）。
    let source: Option<String> = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT source FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st
                .query_map(rusqlite::params![id], |r| r.get::<_, String>(0))
                .map_err(db_err)?;
            match it.next() {
                Some(x) => Ok(Some(x.map_err(db_err)?)),
                None => Ok(None),
            }
        })
        .await?;
    let Some(source) = source else {
        return Err(ApiError::not_found("cert"));
    };
    if source != "acme" {
        return Err(ApiError::bad_request(
            "id",
            "仅 ACME 证书支持自动续期：自签 / 手动证书没有可交互的 CA，给了开关也是点不动的",
        ));
    }

    let enabled_i = if req.enabled { 1 } else { 0 };
    state
        .db
        .exec(move |conn| {
            let n = conn
                .execute(
                    "UPDATE ssl_certs SET auto_renew=?1 WHERE id=?2 AND source='acme'",
                    rusqlite::params![enabled_i, id],
                )
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;
    audit(
        &state,
        &s,
        "ssl.auto_renew",
        &id.to_string(),
        if req.enabled { "on" } else { "off" },
    )
    .await;
    Ok(ok(serde_json::json!({ "id": id, "auto_renew": req.enabled })))
}

/// 删除证书（DB + 磁盘 cert/key 一并清理）。
pub async fn cert_delete(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(id): AxPath<i64>,
) -> ApiResult<StatusCode> {
    crate::auth::require(&s, perm::SSL_MANAGE)?;
    // 先取域名，删除后才能定位要清理的磁盘文件
    let domains_json = state
        .pool
        .with(move |conn| {
            let mut st = conn
                .prepare("SELECT domains FROM ssl_certs WHERE id = ?1")
                .map_err(db_err)?;
            let mut it = st.query_map([id], |r| r.get::<_, String>(0)).map_err(db_err)?;
            Ok(it.next().transpose().map_err(db_err)?)
        })
        .await?;

    let n = state
        .db
        .exec(move |conn| {
            let n = conn
                .execute("DELETE FROM ssl_certs WHERE id = ?1", [id])
                .map_err(|e| PanelError::Database(e.to_string()))?;
            Ok(panel_db::WriteAck { rows_changed: n })
        })
        .await?;
    if n.rows_changed == 0 {
        return Err(ApiError::not_found("cert"));
    }

    if let Some(js) = domains_json {
        let ds: Vec<String> = serde_json::from_str(&js).unwrap_or_default();
        let (crt, key) = cert_paths_for(&state, &ds);
        let _ = std::fs::remove_file(&crt);
        let _ = std::fs::remove_file(&key);
    }

    audit(&state, &s, "cert.delete", &id.to_string(), "ok").await;
    Ok(StatusCode::NO_CONTENT)
}


