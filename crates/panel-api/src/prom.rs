//! Prometheus 抓取端点（`/metrics`，配置项开启 + Bearer token 鉴权）。
//!
//! 为什么不在 /api/v1 下、也不走会话鉴权：Prometheus 抓取器不支持
//! cookie+CSRF 登录流，标准做法是独立 token；而会话层（登录态/CSRF/
//! 权限位）全挂在 /api/v1 的 authed 路由组上，/metrics 若挂进去反而
//! 接不进监控栈。它与 /healthz 同属运维面：由 cmd/serve.rs 在
//! build_router 之后挂载（避开 authed 分层），自带鉴权。
//!
//! 默认**关闭**：config.toml `[metrics] scrape_token` 留空/缺省 ⇒
//! serve.rs 根本不注册 /metrics（不是注册了返回 404——关掉就要彻底不占面）。
//!
//! 鉴权是常数时间比较的 Bearer token（防逐字节时序侧信道）。token 猜解
//! 不做独立限流（面板自身默认只绑回环；公网暴露由 expose 流程管理），
//! 部署侧可用反代加限速——如实写进 deployment.md。

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::OnceLock;

/// 面板进程启动时刻（首次访问 /metrics 时懒初始化；够用——抓取器上线
/// 必然晚于面板启动，误差是抓取间隔级，不影响告警语义）
static START: OnceLock<std::time::Instant> = OnceLock::new();

/// /metrics 的依赖注入（只读，与 /healthz 同口径：读池 + 数据目录）
#[derive(Clone)]
pub struct PromState {
    pub pool: std::sync::Arc<crate::ReadPool>,
    pub data_dir: std::path::PathBuf,
    pub token: String,
}

/// 采集快照（render 的唯一输入；与 IO 解耦，单测不碰数据库）
#[derive(Debug, Default)]
pub struct Snapshot {
    pub uptime_secs: f64,
    pub sse_connections: usize,
    pub db_size_bytes: i64,
    pub audit_log_rows: i64,
    pub disk_available_bytes: Option<u64>,
    /// `None` = 从未成功备份过（render 成 -1，告警规则用 `> 86400` 即可同时覆盖）
    pub backup_last_success_age_secs: Option<f64>,
    /// `(域名串, 距到期天数)`；只含有 not_after 的证书
    pub certs: Vec<(String, f64)>,
}

/// 常数时间字符串比较。长度不同直接 false（长度本身不是秘密；
/// 长度相同则无论第几位不同都走完全程，不泄露前缀匹配度）。
pub fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 从 Authorization 头取 Bearer token；缺失/格式错返回 None。
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// 处理 /metrics：鉴权失败 401（不进采集），成功输出 exposition 文本。
pub async fn metrics(st: PromState, headers: HeaderMap) -> Response {
    match bearer_token(&headers) {
        Some(t) if token_eq(t, &st.token) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                "unauthorized: /metrics requires Authorization: Bearer <scrape_token>\n",
            )
                .into_response()
        }
    }
    let snap = gather(&st).await;
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render(&snap),
    )
        .into_response()
}

async fn gather(st: &PromState) -> Snapshot {
    let now = panel_core::now_unix() as f64;
    let start = START.get_or_init(std::time::Instant::now);
    let mut s = Snapshot {
        uptime_secs: start.elapsed().as_secs_f64(),
        sse_connections: crate::sse::SSE_CONNS.load(std::sync::atomic::Ordering::Relaxed),
        disk_available_bytes: panel_os::paths::available_bytes(&st.data_dir),
        ..Snapshot::default()
    };
    // 单次只读连接拿全部 DB 指标；任何一条失败都按「该项未知」降级，
    // 不让整份抓取 500（Prometheus 侧用 absent()/阈值告警兜底）。
    // 注意 with 的闭包可能被延迟到读线程执行，不能借用外部局部——
    // 结果打包返回，await 之后才合并进快照。
    struct DbStats {
        audit_log_rows: i64,
        backup_last_success_age_secs: Option<f64>,
        db_size_bytes: i64,
        certs: Vec<(String, f64)>,
    }
    impl Default for DbStats {
        fn default() -> Self {
            Self { audit_log_rows: -1, backup_last_success_age_secs: None, db_size_bytes: -1, certs: Vec::new() }
        }
    }
    let db = st
        .pool
        .with(move |conn| {
            let audit_log_rows = conn
                .query_row("SELECT count(*) FROM audit_log", [], |r| r.get::<_, i64>(0))
                .unwrap_or(-1);
            let backup_last_success_age_secs = conn
                .query_row(
                    "SELECT MAX(finished_at) FROM task_runs WHERE kind='backup' AND state='ok'",
                    [],
                    |r| r.get::<_, Option<i64>>(0),
                )
                .ok()
                .flatten()
                .map(|f| now - f as f64);
            let db_size_bytes = conn
                .query_row(
                    "SELECT (SELECT page_count FROM pragma_page_count) * (SELECT page_size FROM pragma_page_size)",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(-1);
            let mut certs = Vec::new();
            if let Ok(mut stmt) =
                conn.prepare("SELECT domains, not_after FROM ssl_certs WHERE not_after IS NOT NULL")
            {
                if let Ok(rows) = stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        certs.push((row.0, (row.1 as f64 - now) / 86_400.0));
                    }
                }
            }
            Ok::<_, panel_core::PanelError>(DbStats {
                audit_log_rows,
                backup_last_success_age_secs,
                db_size_bytes,
                certs,
            })
        })
        .await
        .unwrap_or_default();
    s.audit_log_rows = db.audit_log_rows;
    s.backup_last_success_age_secs = db.backup_last_success_age_secs;
    s.db_size_bytes = db.db_size_bytes;
    s.certs = db.certs;
    s
}

/// 标签值转义（Prometheus 文本格式：`\` `"` `\n`）
fn esc(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// 渲染 Prometheus exposition 文本（纯函数，行为由单测钉死）。
pub fn render(s: &Snapshot) -> String {
    let mut o = String::with_capacity(1024);
    o.push_str("# HELP forkpanel_up Whether the panel process is serving (1).\n");
    o.push_str("# TYPE forkpanel_up gauge\nforkpanel_up 1\n");
    o.push_str("# HELP forkpanel_uptime_seconds Seconds since the panel process started.\n");
    o.push_str("# TYPE forkpanel_uptime_seconds gauge\n");
    o.push_str(&format!("forkpanel_uptime_seconds {}\n", s.uptime_secs));
    o.push_str("# HELP forkpanel_build_info Panel version as labels.\n");
    o.push_str("# TYPE forkpanel_build_info gauge\n");
    o.push_str(&format!(
        "forkpanel_build_info{{version=\"{}\"}} 1\n",
        esc(env!("CARGO_PKG_VERSION"))
    ));
    o.push_str("# HELP forkpanel_sse_connections Current SSE stream connections.\n");
    o.push_str("# TYPE forkpanel_sse_connections gauge\n");
    o.push_str(&format!("forkpanel_sse_connections {}\n", s.sse_connections));
    o.push_str("# HELP forkpanel_db_size_bytes SQLite database size in bytes (-1 unknown).\n");
    o.push_str("# TYPE forkpanel_db_size_bytes gauge\n");
    o.push_str(&format!("forkpanel_db_size_bytes {}\n", s.db_size_bytes));
    o.push_str("# HELP forkpanel_audit_log_rows Audit log rows (-1 unknown).\n");
    o.push_str("# TYPE forkpanel_audit_log_rows gauge\n");
    o.push_str(&format!("forkpanel_audit_log_rows {}\n", s.audit_log_rows));
    o.push_str("# HELP forkpanel_disk_available_bytes Available bytes on the data directory filesystem (-1 unknown).\n");
    o.push_str("# TYPE forkpanel_disk_available_bytes gauge\n");
    o.push_str(&format!(
        "forkpanel_disk_available_bytes {}\n",
        s.disk_available_bytes.map(|v| v as i64).unwrap_or(-1)
    ));
    o.push_str("# HELP forkpanel_backup_last_success_age_seconds Seconds since last successful backup (-1 = never succeeded).\n");
    o.push_str("# TYPE forkpanel_backup_last_success_age_seconds gauge\n");
    o.push_str(&format!(
        "forkpanel_backup_last_success_age_seconds {}\n",
        s.backup_last_success_age_secs.unwrap_or(-1.0)
    ));
    o.push_str("# HELP forkpanel_cert_days_to_expiry Days until the certificate expires, per domain set.\n");
    o.push_str("# TYPE forkpanel_cert_days_to_expiry gauge\n");
    for (domains, days) in &s.certs {
        o.push_str(&format!(
            "forkpanel_cert_days_to_expiry{{domains=\"{}\"}} {}\n",
            esc(domains),
            days
        ));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_eq_is_exact_and_constant_shape() {
        assert!(token_eq("s3cret-token-0123", "s3cret-token-0123"));
        assert!(!token_eq("s3cret-token-0123", "s3cret-token-0124"));
        assert!(!token_eq("short", "short-but-longer"), "长度不同必须 false");
        assert!(!token_eq("", "x"));
    }

    #[test]
    fn render_has_required_exposition_lines() {
        let s = Snapshot {
            uptime_secs: 12.5,
            sse_connections: 3,
            db_size_bytes: 4096,
            audit_log_rows: 42,
            disk_available_bytes: Some(1000),
            backup_last_success_age_secs: None,
            certs: vec![("a.com,b.com".into(), 15.5)],
        };
        let out = render(&s);
        // 每个 gauge 必须带 HELP+TYPE（缺 TYPE 会被严格模式的解析器拒收）
        for m in [
            "forkpanel_up",
            "forkpanel_uptime_seconds",
            "forkpanel_build_info",
            "forkpanel_sse_connections",
            "forkpanel_db_size_bytes",
            "forkpanel_audit_log_rows",
            "forkpanel_disk_available_bytes",
            "forkpanel_backup_last_success_age_seconds",
            "forkpanel_cert_days_to_expiry",
        ] {
            assert!(out.contains(&format!("# HELP {m} ")), "缺 HELP {m}");
            assert!(out.contains(&format!("# TYPE {m} gauge")), "缺 TYPE {m}");
        }
        assert!(out.contains("forkpanel_uptime_seconds 12.5"));
        assert!(out.contains("forkpanel_sse_connections 3"));
        assert!(out.contains("forkpanel_db_size_bytes 4096"));
        assert!(out.contains("forkpanel_audit_log_rows 42"));
        assert!(out.contains("forkpanel_disk_available_bytes 1000"));
        // 从未成功备份 = -1（告警规则 `> 86400` 同时覆盖 never）
        assert!(out.contains("forkpanel_backup_last_success_age_seconds -1"));
        assert!(
            out.contains("forkpanel_cert_days_to_expiry{domains=\"a.com,b.com\"} 15.5"),
            "{out}"
        );
    }

    #[test]
    fn render_escapes_label_values() {
        let s = Snapshot {
            certs: vec![("we\"ird\\\\name".into(), 1.0)],
            ..Snapshot::default()
        };
        let out = render(&s);
        assert!(
            out.contains("domains=\"we\\\"ird\\\\\\\\name\""),
            "标签值必须转义引号与反斜杠：{out}"
        );
    }

    #[test]
    fn disk_unknown_renders_minus_one() {
        let s = Snapshot { disk_available_bytes: None, ..Snapshot::default() };
        assert!(render(&s).contains("forkpanel_disk_available_bytes -1"));
    }

    #[test]
    fn bearer_header_parsing() {
        let mut h = HeaderMap::new();
        assert!(bearer_token(&h).is_none());
        h.insert(axum::http::header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(bearer_token(&h).is_none(), "非 Bearer 方案必须拒绝");
        h.insert(axum::http::header::AUTHORIZATION, "Bearer t0k".parse().unwrap());
        assert_eq!(bearer_token(&h), Some("t0k"));
    }
}
