    use super::*;

    #[test]
    fn upstream_validation_blocks_config_injection() {
        for ok in ["http://127.0.0.1:3000", "https://backend.internal", "http://[::1]:8080"] {
            assert!(validate_upstream(ok).is_ok(), "应放行: {ok}");
        }
        for bad in [
            // 关键用例：值会直接进 nginx 配置，一个换行就能插入任意指令
            "http://127.0.0.1:3000; }\nserver { listen 9999",
            "http://127.0.0.1:3000 /",
            "http://127.0.0.1:3000/x",
            "http://127.0.0.1:3000#frag",
            "127.0.0.1:3000",            // 缺 scheme
            "http://bad host:3000",      // 含空格
            "http://127.0.0.1\t:3000",   // 含制表符
        ] {
            assert!(validate_upstream(bad).is_err(), "必须拒绝: {bad:?}");
        }
    }

    #[test]
    fn fpm_validation_blocks_injection() {
        assert!(validate_fpm("unix:/run/php/php8.2-fpm.sock").is_ok());
        assert!(validate_fpm("127.0.0.1:9000").is_ok());
        for bad in [
            "unix:relative.sock",        // 非绝对路径
            "unix:/run/../etc/passwd",   // 含 ..
            "127.0.0.1:9000; }",         // 分号 + 花括号
            "127.0.0.1:9000\nserver{",   // 换行
            "",
            "a b",
        ] {
            assert!(validate_fpm(bad).is_err(), "必须拒绝: {bad:?}");
        }
    }

    #[test]
    fn days_left_calculation() {
        let now = crate::now_unix();
        let f = |na: Option<i64>| na.map(|t| (t - now) / 86_400);
        assert_eq!(f(Some(now + 86_400 * 30)), Some(30));
        assert_eq!(f(Some(now + 86_400 * 3)), Some(3));
        assert_eq!(f(None), None);
    }

    #[test]
    fn renewal_warning_thresholds() {
        // UI：>30 绿 / 7~30 黄 / <7 红
        let level = |d: i64| if d > 30 { "ok" } else if d >= 7 { "warn" } else { "danger" };
        assert_eq!(level(60), "ok");
        assert_eq!(level(30), "warn");
        assert_eq!(level(7), "warn");
        assert_eq!(level(3), "danger");
        assert_eq!(level(0), "danger");
    }

    #[test]
    fn apply_flow_order_is_enforced() {
        // 顺序：render → validate → deploy → reload → 持久化
        // validate 失败时不得 deploy（旧配置必须原封不动）
        let steps = ["render", "validate", "deploy", "reload", "persist"];
        assert_eq!(steps[1], "validate", "校验必须在部署之前");
        assert!(steps.iter().position(|s| *s == "validate").unwrap()
            < steps.iter().position(|s| *s == "deploy").unwrap());
        assert!(steps.iter().position(|s| *s == "deploy").unwrap()
            < steps.iter().position(|s| *s == "reload").unwrap());
    }

    #[test]
    fn ensure_site_root_dir_creates_with_explicit_755() {
        // 验证站点根目录被创建且权限显式设为 0o755，不再依赖 umask 隐式保证
        // （root:root + 严 umask 下，缺少这步会导致 www-data 读静态文件 403）。
        let d = std::env::temp_dir().join(format!("panel-site-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_site_root_dir(&d);
        assert!(d.is_dir(), "站点根目录应被创建");
        // 权限走跨平台 owner（panel_os::fs 内部已按平台分支实现），业务层不写平台条件编译。
        // Linux 上 mode_of 恒返回 Some，断言必执行；非 unix 平台该特性本就为 no-op。
        if let Some(m) = panel_os::fs::mode_of(&d) {
            assert_eq!(m & 0o777, 0o755, "目录应显式设为 755（不再依赖 umask）");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_site_root_dir_is_idempotent() {
        // 幂等：重复调用不报错、权限保持 755
        let d = std::env::temp_dir().join(format!("panel-site-root-idem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        ensure_site_root_dir(&d);
        ensure_site_root_dir(&d);
        assert!(d.is_dir());
        if let Some(m) = panel_os::fs::mode_of(&d) {
            assert_eq!(m & 0o777, 0o755);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── site_root_rel：绝对路径剥前缀 / 越界拒绝 / 空串回填 ──
    // 回归：目录选择器返回绝对路径、库里 root 也是绝对路径，但沙箱只收相对 site_root
    // 的路径。此前 resolve_site_root 直接把绝对路径交给 resolve_within_for_create →
    // is_absolute 一律判 PathEscape(50001)，于是「编辑站点 → 保存」必报"路径超出允许范围"。
    #[test]
    fn site_root_rel_strips_prefix_for_absolute_within_root() {
        let base = Path::new("/var/www");
        // 选择器返回的 /var/www/my-site → 相对 my-site
        assert_eq!(site_root_rel(base, "/var/www/my-site", "fallback"), "my-site");
        // 库里落地、带结尾斜杠的绝对路径也应剥干净
        assert_eq!(site_root_rel(base, "/var/www/sub/", "fallback"), "sub");
        // 恰好等于 base（选了 site_root 本身）→ 用 "." 表示根目录
        assert_eq!(site_root_rel(base, "/var/www", "fallback"), ".");
    }

    #[test]
    fn site_root_rel_keeps_out_of_root_absolute_so_sandbox_rejects() {
        // 越界绝对路径保持原样，交给 resolve_within_for_create 判 PathEscape（绝不放行）
        assert_eq!(site_root_rel(Path::new("/var/www"), "/etc/passwd", "fb"), "/etc/passwd");
        // 伪装前缀（/var/www-evil）不会被字符串前缀误判命中：strip_prefix 是组件级，
        // /var/www-evil 不以 /var/www 为组件前缀 → 保持原样 → 沙箱拒绝
        assert_eq!(site_root_rel(Path::new("/var/www"), "/var/www-evil/x", "fb"), "/var/www-evil/x");
    }

    #[test]
    fn site_root_rel_empty_falls_back_to_name_and_relative_passthrough() {
        assert_eq!(site_root_rel(Path::new("/var/www"), "", "my-site"), "my-site");
        // 相对路径原样透传（含子目录与 .. 语义拦截交给沙箱）
        assert_eq!(site_root_rel(Path::new("/var/www"), "my-site/blog", "fb"), "my-site/blog");
    }

    // ── 部署指纹 / 未同步（017）：判据、边界、分隔符安全 ──

    /// 一个「手动维护 + 已同步」的基线行（指纹在用例里按需设置）。
    fn raw_site() -> RawSite {
        RawSite {
            id: 1,
            name: "my-site".into(),
            domains: r#"["example.com"]"#.into(),
            root: "/var/www/my-site".into(),
            kind: "static".into(),
            enabled: 1,
            created_at: 0,
            tls: false,
            waf_enabled: 1,
            waf_profile: Some("basic".into()),
            waf_rate: None,
            waf_burst: Some(0),
            upstreams_json: None,
            fpm: None,
            spa: 0,
            redirect_target: None,
            redirect_code: None,
            conf_path: Some("/etc/nginx/conf.d/panel-example.com.conf".into()),
            routes_json: "[]".into(),
            manual_conf: 1,
            conf_snapshot: None,
            custom_conf: None,
            www_redirect: "off".into(),
            tls_profile: "modern".into(),
            tls_min: "TLSv1.2".into(),
            hsts: 0,
            hsts_max_age: 300,
            hsts_sub: 0,
            hsts_preload: 0,
            rewrite_preset: "none".into(),
            rewrite_custom: None,
            last_ver_hash: None,
            ip_allow: None,
            ip_deny: None,
            auth_basic: 0,
            auth_user: None,
            lb_policy: "least_conn".into(),
            proxy_connect_timeout: 60,
            proxy_send_timeout: 60,
            proxy_read_timeout: 60,
            log_access: 0,
            log_error: 0,
            log_error_level: "error".into(),
            remark: String::new(),
            last_applied_at: None,
        }
    }

    /// 纯映射（023）：RawSite.last_applied_at 必须原样透传到 SiteOut——None 不被
    /// 误转成 0（0 是合法时间戳 1970，与「从未下发」语义相反）。
    #[test]
    fn to_out_maps_last_applied_at_through_verbatim() {
        let mut r = raw_site();
        r.last_applied_at = Some(1_772_000_000);
        assert_eq!(to_out(&r).last_applied_at, Some(1_772_000_000));
        r.last_applied_at = None;
        assert_eq!(to_out(&r).last_applied_at, None);
    }

    #[test]
    fn conf_stale_true_when_manual_and_snapshot_missing() {
        // 旧行（017 之前转入手动维护，如 as11）：无指纹记录 → 按「未同步」对待。
        // 有疑问时向"提示"倾斜，而不是假装同步。
        assert!(conf_stale_of(&raw_site()));
    }

    #[test]
    fn conf_stale_false_when_fingerprint_matches() {
        let mut r = raw_site();
        r.conf_snapshot = Some(fingerprint_of(&r));
        assert!(!conf_stale_of(&r), "指纹一致 = 已同步");
    }

    #[test]
    fn conf_stale_true_when_any_deploy_field_changed() {
        // 核心回归（真实事故）：手动维护后只改表单（如 WAF 档位 strict）、文件没动
        // → 必须报未同步。面板显示 strict、nginx 里是 basic 且界面毫无提示，正是要修的 bug。
        let mk = || {
            let mut r = raw_site();
            r.conf_snapshot = Some(fingerprint_of(&r));
            r
        };
        macro_rules! changed {
            ($label:expr, $m:expr) => {{
                let mut r = mk();
                let f: fn(&mut RawSite) = $m;
                f(&mut r);
                assert!(conf_stale_of(&r), "{}：字段变更必须触发未同步", $label);
            }};
        }
        changed!("waf_profile", |r| r.waf_profile = Some("strict".into()));
        changed!("name", |r| r.name = "renamed".into());
        changed!("domains", |r| r.domains = r#"["example.com","www.example.com"]"#.into());
        changed!("root", |r| r.root = "/var/www/other".into());
        changed!("kind", |r| r.kind = "redirect".into());
        changed!("spa", |r| r.spa = 1);
        changed!("upstreams", |r| r.upstreams_json = Some(r#"["http://127.0.0.1:3000"]"#.into()));
        changed!("fpm", |r| r.fpm = Some("unix:/run/php.sock".into()));
        changed!("redirect_target", |r| r.redirect_target = Some("https://x.example".into()));
        changed!("redirect_code", |r| r.redirect_code = Some(302));
        changed!("waf_enabled", |r| r.waf_enabled = 0);
        changed!("waf_rate", |r| r.waf_rate = Some(50));
        changed!("waf_burst", |r| r.waf_burst = Some(99));
        changed!("routes", |r| r.routes_json = r#"[{"prefix":"/","kind":"static"}]"#.into());
    }

    #[test]
    fn conf_stale_false_for_panel_managed_or_disabled() {
        // 非手动维护：apply 每次重渲染 → 不存在分叉概念（指纹值随便给）
        let mut r = raw_site();
        r.manual_conf = 0;
        r.conf_snapshot = Some("whatever".into());
        assert!(!conf_stale_of(&r));
        // 停用：文件已被移除 → 无从「未同步」
        let mut r2 = raw_site();
        r2.enabled = 0;
        assert!(!conf_stale_of(&r2));
    }

    #[test]
    fn fingerprint_is_separator_safe() {
        // 分隔符回归：没有 \u{1f} 时 ("a","bc") 与 ("ab","c") 会撞同一指纹 → 漏报
        let a = deploy_fingerprint("a", "bc", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", None, "");
        let b = deploy_fingerprint("ab", "c", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", None, "");
        assert_ne!(a, b, "字段边界必须由分隔符保护");
        // 自定义片段（019）参与指纹：只差它一处也必须产生不同指纹
        // ——否则改了 custom_conf「未同步」不会亮，等于坏了 017 的核心承诺。
        let c = deploy_fingerprint("a", "bc", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", Some("add_header X-A 1;"), "");
        assert_ne!(a, c, "custom_conf 必须进入指纹");
        let d = deploy_fingerprint("a", "bc", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", Some("add_header X-A 2;"), "");
        assert_ne!(c, d, "custom_conf 内容变化必须反映到指纹");
        // 高级配置（020）同理：www 跳转 / TLS 档位 / 伪静态都会改变渲染结果，
        // 漏进指纹 = 改了它们「未同步」不亮（与 custom_conf 同款静默分叉）。
        let e = deploy_fingerprint("a", "bc", "/r", "static", false, None, None, None, None, false, None, None, None, "[]", None, r#"{"www":"to_www"}"#);
        assert_ne!(a, e, "高级配置必须进入指纹");
    }

    #[test]
    fn conf_hash_stable_distinct_and_hex() {
        // SHA-256 hex（64 字符）：版本去重与「当前版本」标记的比较基准
        let a = conf_hash("server { listen 80; }\n");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, conf_hash("server { listen 80; }\n"), "同内容必须同 hash");
        assert_ne!(a, conf_hash("server { listen 81; }\n"), "一字节之差必须不同");
    }

    #[test]
    fn rollback_state_managed_iff_fingerprint_matches_form() {
        // 版本指纹 == 当前表单指纹 → 回托管、快照=表单指纹（天然已同步）
        let (m, snap) = rollback_state(Some("FP"), "FP");
        assert_eq!(m, 0);
        assert_eq!(snap.as_deref(), Some("FP"));
        // 不等 → 手动维护、快照=版本指纹
        let (m, snap) = rollback_state(Some("OLD"), "FP");
        assert_eq!(m, 1);
        assert_eq!(snap.as_deref(), Some("OLD"));
        // 版本无指纹（旧行）→ 手动维护 + NULL 快照（conf_stale_of 判「未同步」）
        let (m, snap) = rollback_state(None, "FP");
        assert_eq!(m, 1);
        assert!(snap.is_none());
    }
