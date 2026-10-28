//! 公网暴露向导的 API（域名反代 + 防火墙白名单 + TLS）。
//!
//! ## 为什么需要这组端点
//!
//! 面板默认只监听 `127.0.0.1`（零暴露默认）。要让小白用户"免命令行地开公网"，
//! 只能把 `deploy/expose-public.sh` 的能力搬到网页上——但**绝不重写**它的
//! fail-closed 逻辑（拒 `0.0.0.0/0`、拒已裸奔时再装反代、端口探测不可信即拒）。
//! 本模块是**薄壳**：校验入参 → 拼 argv → 经 `panel_os::run_sync(Bin::Bash)` 调脚本。
//!
//! ## 状态从哪来
//!
//! 脚本不写状态文件，状态就体现在它落的两个文件上：
//! - `/etc/nginx/conf.d/forkpanel-public-access.conf` 存在 = 正在对外暴露；
//! - `panel.service.d/panel-tls.conf` 存在 = 启用了 HTTPS 终结。
//!
//! 故 `status` 直接探测两者（经 `panel_os::paths` 抽象，业务层不硬编码路径），
//! 刻意**不改脚本去额外写状态文件**——那会让 `ci/e2e-expose-public.sh` 的
//! 逐条断言面跟着变，收益不抵风险。
//!
//! ## 安全要点
//!
//! ① 能力门：`EXPOSE_MANAGE` 不支持即 501（前端据此置灰，三处口径一致）；
//! ② 权限：`system.manage`（开启公网暴露等同于系统级运维动作）；
//! ③ 写操作自动经 `guard_write` 的 CSRF 校验（挂在 `authed` 路由链上）；
//! ④ **只读模式拒绝**：`read_only_guard` 已覆盖 POST，无需重复判断；
//! ⑤ 审计：apply / remove 都留痕（who / 什么域名 / 成功与否）。

use crate::{
    auth::perm,
    error::{ok, ApiError, ApiResult},
    routes::{audit, Auth, Shared},
};
use axum::{extract::State, Json};
use panel_core::cap_keys;
use serde::{Deserialize, Serialize};

/// 脚本落盘的 nginx 配置路径（经 paths 抽象，见 `panel_os::paths`）。
fn nginx_conf_path() -> std::path::PathBuf {
    panel_os::paths::expose_nginx_conf_path()
}

/// 启用 TLS 时脚本落的 systemd drop-in（存在即有 HTTPS 终结）。
fn tls_dropin_path() -> std::path::PathBuf {
    panel_os::paths::expose_tls_dropin_path()
}

/// 能力门：不支持时 501，并把「为什么不支持」透给前端（前端置灰时展示同一句）。
fn ensure_supported(state: &Shared) -> ApiResult<()> {
    match state.capabilities.get(cap_keys::EXPOSE_MANAGE) {
        Some(c) if c.supported => Ok(()),
        _ => {
            let reason = state
                .capabilities
                .get(cap_keys::EXPOSE_MANAGE)
                .and_then(|c| c.reason.clone())
                .unwrap_or_else(|| "unsupported".into());
            Err(ApiError::unsupported(format!("expose: {reason}")))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ExposeStatus {
    /// 是否正在对外暴露（nginx 反代配置存在）
    pub exposed: bool,
    /// 是否启用了 HTTPS 终结
    pub tls: bool,
    /// 暴露脚本是否已安装（缺失时 apply 必然失败，前端据此提示重装）
    pub script_installed: bool,
    /// 能力位是否支持（false 时 apply/remove 均 501）
    pub supported: bool,
    /// 不支持的原因（supported=false 时有值）
    pub unsupported_reason: Option<String>,
}

/// GET /api/v1/system/expose/status
///
/// 只读：探测文件存在性，不触达脚本、不改任何东西。权限用 `system.view`
/// ——状态本身不是秘密，能看见系统概览的人就能看见"是否已对外暴露"。
pub async fn status(State(state): State<Shared>, Auth(s): Auth) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_VIEW)?;
    let cap = state.capabilities.get(cap_keys::EXPOSE_MANAGE);
    let supported = cap.map(|c| c.supported).unwrap_or(false);
    Ok(ok(ExposeStatus {
        exposed: nginx_conf_path().exists(),
        tls: tls_dropin_path().exists(),
        script_installed: panel_os::paths::panel_expose_script_path().exists(),
        supported,
        unsupported_reason: if supported {
            None
        } else {
            cap.and_then(|c| c.reason.clone())
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct ApplyReq {
    /// 对外域名（至少两级，顶级域不能是数字）
    pub domain: String,
    /// 允许访问的来源网段，至少一个；掩码 0 被拒
    pub allow: Vec<String>,
    /// true = 现场生成自签证书（浏览器会告警，仅临时/内网自用）
    #[serde(default)]
    pub self_signed: bool,
    /// 已有证书链（与 key 成对，给则走该证书，优先于 self_signed）
    pub fullchain: Option<String>,
    /// 证书私钥
    pub key: Option<String>,
    /// 不自动放行防火墙端口
    #[serde(default)]
    pub no_firewall: bool,
}

#[derive(Debug, Serialize)]
pub struct ApplyResp {
    pub domain: String,
    /// 脚本的 stdout（含它自己打印的逐步结果），原样给前端展示
    pub output: String,
}

/// POST /api/v1/system/expose/apply
///
/// 校验 → 调脚本 → 审计。**校验一律走 `panel_core::expose`**（与 CLI 同一份），
/// 脚本侧另有同名校验做纵深防御；两边都不通过时，用户看到的是同一条中文原因。
pub async fn apply(
    State(state): State<Shared>,
    Auth(s): Auth,
    Json(req): Json<ApplyReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    ensure_supported(&state)?;

    // ── 入参校验（共享规则，见 panel_core::expose）──
    panel_core::expose::validate_domain(&req.domain)
        .map_err(|e| ApiError::bad_request("domain", e))?;
    if req.allow.is_empty() {
        return Err(ApiError::bad_request(
            "allow",
            "至少要给一个来源网段（否则等于把 root 面板开放给全网）",
        ));
    }
    for c in &req.allow {
        panel_core::expose::validate_cidr(c).map_err(|e| ApiError::bad_request("allow", e))?;
    }
    // 证书参数成对：给了一个就必须给另一个，否则脚本会静默回退成自签
    match (&req.fullchain, &req.key) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(ApiError::bad_request(
                "fullchain",
                "证书链与私钥必须成对提供（或都不给以使用自签）",
            ));
        }
        _ => {}
    }

    // ── 拼 argv（脚本参数的唯一构造点）──
    let mut args: Vec<String> = vec!["-d".into(), req.domain.clone()];
    for c in &req.allow {
        args.push("-a".into());
        args.push(c.clone());
    }
    if let (Some(fc), Some(k)) = (&req.fullchain, &req.key) {
        args.push("--fullchain".into());
        args.push(fc.clone());
        args.push("--key".into());
        args.push(k.clone());
    } else if req.self_signed {
        args.push("--self-signed".into());
    }
    if req.no_firewall {
        args.push("--no-firewall".into());
    }

    let domain = req.domain.clone();
    // run_sync 是同步阻塞的（等脚本跑完 nginx/防火墙），必须挪出 async worker，
    // 否则一个慢操作会卡住整个 runtime 的其他请求（见 panel-api/lib.rs 顶部的纪律）。
    let out = tokio::task::spawn_blocking(move || invoke_script(&args))
        .await
        .map_err(|e| ApiError::new(10999, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                   format!("expose 任务失败：{e}")))?;

    match out {
        Ok(output) => {
            audit(&state, &s, "expose.apply", &domain, "ok").await;
            Ok(ok(ApplyResp { domain, output }))
        }
        Err(msg) => {
            // 失败也要留痕：失败原因（如脚本的 fail-closed 拒绝）是事后排查的唯一线索
            audit(&state, &s, "expose.apply", &domain, "fail").await;
            Err(ApiError::new(
                10013,
                axum::http::StatusCode::BAD_REQUEST,
                msg,
            ))
        }
    }
}

/// POST /api/v1/system/expose/remove
///
/// 撤销暴露（等于脚本的 `--uninstall`）。面板仍绑回环，ssh 隧道照常可用。
pub async fn remove(
    State(state): State<Shared>,
    Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::SYSTEM_MANAGE)?;
    ensure_supported(&state)?;

    let out = tokio::task::spawn_blocking(|| invoke_script(&["--uninstall".to_string()]))
        .await
        .map_err(|e| ApiError::new(10999, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                   format!("expose 任务失败：{e}")))?;

    match out {
        Ok(output) => {
            audit(&state, &s, "expose.remove", "-", "ok").await;
            Ok(ok(serde_json::json!({ "output": output })))
        }
        Err(msg) => {
            audit(&state, &s, "expose.remove", "-", "fail").await;
            Err(ApiError::new(10013, axum::http::StatusCode::BAD_REQUEST, msg))
        }
    }
}

/// 调 `expose-public.sh`。**与 CLI 的 `invoke_expose` 同款语义**：
/// 脚本不存在给明确提示（而非让 bash exec 不存在的路径得到 127）；非零退出
/// 视为失败并把脚本输出原样带回（那是用户唯一能看到的失败原因）。
fn invoke_script(script_args: &[String]) -> std::result::Result<String, String> {
    let script = panel_os::paths::panel_expose_script_path();
    let script_s = script
        .to_str()
        .ok_or_else(|| format!("expose 脚本路径非 UTF-8：{}", script.display()))?;
    if !script.exists() {
        return Err(format!(
            "找不到 expose 脚本 {}（是否漏装？重新跑 install.sh 或手动部署 deploy/expose-public.sh）",
            script.display()
        ));
    }
    let mut argv: Vec<&str> = Vec::with_capacity(script_args.len() + 1);
    argv.push(script_s);
    for a in script_args {
        argv.push(a.as_str());
    }
    let out = panel_os::run_sync(panel_os::Bin::Bash, &argv)
        .map_err(|e| format!("调用 expose 脚本失败：{e}"))?;
    if out.code != Some(0) {
        return Err(format!(
            "expose-public.sh 失败（退出码 {:?}）：\n{}{}",
            out.code, out.stdout, out.stderr
        ));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    /// ⭐ **接线守卫**：apply / remove 必须真的经 `Bin::Bash` 调脚本。
    ///
    /// 只测"参数校验会对坏输入报错"是不够的——把 `invoke_script` 的调用删掉、
    /// 让 handler 直接返回成功，所有校验测试依然全绿，而用户点"开启"毫无效果。
    /// 这类"收下参数却不做事"只能源码级断言（同 CLI 的 `expose_arm_invokes_script_via_bash`）。
    #[test]
    fn handlers_actually_invoke_the_script() {
        let prod = panel_testutil::production_source(include_str!("expose.rs"));
        assert!(
            prod.contains("panel_os::run_sync(panel_os::Bin::Bash"),
            "必须经 Bin::Bash argv 直传调脚本（不得 shell 拼字符串、不得直接 spawn）"
        );
        assert!(
            prod.contains("panel_os::paths::panel_expose_script_path()"),
            "脚本路径必须走 panel_os::paths（业务层不硬编码 /usr/local/share/...）"
        );
        // apply 与 remove 两条臂都要真调（少一条就是某个按钮点了没反应）。
        // ⚠ 两个 needle 不能互为前缀：`invoke_script(&` 会同时命中 `invoke_script(&args)`
        //   ⇒ 相加恒为 3，永远是假绿。故精确到各自的 argv 表达式。
        assert_eq!(
            prod.matches("invoke_script(&args)").count(),
            1,
            "apply 必须调 invoke_script(&args)"
        );
        assert_eq!(
            prod.matches("invoke_script(&[\"--uninstall\".to_string()])").count(),
            1,
            "remove 必须调 invoke_script 且传 --uninstall"
        );
        assert!(
            prod.contains("--uninstall"),
            "remove 必须走脚本的 --uninstall 分支，而不是自己 rm 配置"
        );
    }

    /// 能力门必须存在且返回 501：删掉 `ensure_supported` 会让"不支持也照做"。
    #[test]
    fn capability_gate_is_wired_in_both_write_handlers() {
        let prod = panel_testutil::production_source(include_str!("expose.rs"));
        assert_eq!(
            prod.matches("ensure_supported(&state)?").count(),
            2,
            "apply / remove 各需一道能力门"
        );
        assert!(
            prod.contains("ApiError::unsupported"),
            "能力不满足必须返回 501（10009），不能静默照做"
        );
    }

    /// 阻塞调用必须挪出 async worker：直接调 run_sync 会卡住整个 runtime。
    #[test]
    fn blocking_script_calls_are_offloaded() {
        let prod = panel_testutil::production_source(include_str!("expose.rs"));
        assert_eq!(
            prod.matches("tokio::task::spawn_blocking").count(),
            2,
            "apply / remove 的脚本调用都要 spawn_blocking"
        );
    }

    /// 证书参数成对校验：只给 fullchain 不给 key（或反之）必须拒绝，
    /// 否则脚本会静默回退成自签——用户以为装了真证书，实际浏览器告警。
    #[test]
    fn cert_pairing_is_validated() {
        let prod = panel_testutil::production_source(include_str!("expose.rs"));
        assert!(
            prod.contains("证书链与私钥必须成对提供"),
            "缺少成对校验会让半套证书静默回退自签"
        );
    }
}
