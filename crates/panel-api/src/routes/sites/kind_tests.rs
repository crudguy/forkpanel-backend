    use super::*;

    /// 两个换算必须互为逆（在各自定义域上）。之前这里断链：`apply` 写死
    /// `'static'`，`to_out` 又只认 `reverse_proxy`，于是**任何**站点读出来都是
    /// 静态站——反代站被编辑后一点"应用"就被改坏。
    #[test]
    fn kind_maps_round_trip_and_unknown_falls_back_to_static() {
        for (db, api) in [
            ("static", "static"),
            ("reverse_proxy", "proxy"),
            ("php", "php"),
            ("redirect", "redirect"),
            ("routed", "routed"),
        ] {
            assert_eq!(kind_to_api(db), api, "库口径 {db} 应呈现为 {api}");
        }
        assert_eq!(kind_to_db(&panel_os::SiteKind::Static), "static");
        assert_eq!(
            kind_to_db(&panel_os::SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] }),
            "reverse_proxy"
        );
        assert_eq!(kind_to_db(&panel_os::SiteKind::Php { fpm: "unix:/run/php.sock".into() }), "php");
        assert_eq!(
            kind_to_db(&panel_os::SiteKind::Redirect { target: "https://new.example.com".into(), code: 301 }),
            "redirect"
        );
        // 未知值必须降级成 static：认成 proxy 会让人按错误前提去改配置
        assert_eq!(kind_to_api("something_else"), "static");
        assert_eq!(kind_to_api(""), "static");
    }

    fn route(prefix: &str, kind: &str) -> RouteOut {
        RouteOut {
            prefix: prefix.to_string(),
            kind: kind.to_string(),
            upstreams: Vec::new(),
            spa: false,
            fpm: None,
            front_controller: None,
            root: None,
        }
    }

    #[test]
    fn routes_validation_normalizes_and_accepts() {
        let mut rs = vec![route("/", "static"), route("/api/", "proxy")];
        rs[1].upstreams = vec!["  http://127.0.0.1:3000  ".into()];
        let out = validate_routes(&rs).expect("合法路由表应通过");
        // 末尾多余的 / 必须被归一化（/api/ ≡ /api），否则同一前缀能存成两条
        assert_eq!(out.routes[1].prefix, "/api");
        assert_eq!(out.routes[1].kind, panel_os::RouteKind::Proxy {
            upstreams: vec!["http://127.0.0.1:3000".into()],
        });
        // 归一化后两条不再重复（若不归一化，第二条就与首条同前缀而报重复）
        assert_eq!(out.routes.len(), 2);
        assert!(out.fallback().is_some());
    }

    /// `prefix` 会**直接进 nginx 配置文本**，带 `;` / `{` / 换行就是配置注入
    /// （可借此写出任意指令，如 `location / { } return 200 "ok"; }`）。
    /// 这类输入必须在校验层挡住——渲染层不设防。
    #[test]
    fn routes_validation_blocks_config_injection() {
        for bad in [
            "/api; return 200 'pwned'",
            "/api { }",
            "/api\n    }\n    location / { deny all;",
            "/api /api2",   // 空白
            "/api/$(id)",
            "/api`id`",
            "/api\u{0}",
        ] {
            let rs = vec![route("/", "static"), route(bad, "static")];
            assert!(
                validate_routes(&rs).is_err(),
                "必须拒绝含注入字符的前缀：{bad:?}"
            );
        }
        // 合法但需归一化的边界
        let rs = vec![route("/", "static"), route("/api/v1.0~beta-2_x", "static")];
        assert!(validate_routes(&rs).is_ok(), "点/波浪/下划线/连字符应放行");
    }

    #[test]
    fn routes_validation_requires_exactly_one_fallback() {
        // 没有兜底 → 必须报错（漏掉的路径会落到别的站点去）
        let rs = vec![route("/api", "static")];
        let e = validate_routes(&rs).expect_err("缺兜底必须报错");
        assert!(format!("{e:?}").contains("兜底"), "{e:?}");
        // 两个兜底 → 必须报错（谁生效取决于书写顺序）
        let rs = vec![route("/", "static"), route("/", "proxy")];
        assert!(validate_routes(&rs).is_err(), "重复的 / 必须报错");
        // 空表
        assert!(validate_routes(&[]).is_err(), "空路由表必须报错");
    }

    #[test]
    fn routes_validation_rejects_duplicate_prefix() {
        let rs = vec![route("/", "static"), route("/api", "static"), route("/api", "static")];
        let e = validate_routes(&rs).expect_err("重复前缀必须报错");
        assert!(format!("{e:?}").contains("重复"), "{e:?}");
    }

    #[test]
    fn routes_validation_checks_per_kind_required_fields() {
        // 反代缺后端
        let mut proxy = route("/api", "proxy");
        proxy.upstreams = vec!["   ".into()];
        let rs = vec![route("/", "static"), proxy];
        assert!(validate_routes(&rs).is_err(), "反代必须有后端");

        // PHP 缺 fpm / 缺 front_controller
        let rs = vec![route("/", "static"), route("/app", "php")];
        assert!(validate_routes(&rs).is_err(), "PHP 缺 fpm 必须报错");
        let mut php = route("/app", "php");
        php.fpm = Some("unix:/run/php.sock".into());
        let rs = vec![route("/", "static"), php.clone()];
        assert!(validate_routes(&rs).is_err(), "PHP 缺 front_controller 必须报错");
        // 补齐后应通过
        let mut ok = php.clone();
        ok.front_controller = Some("/app/public/index.php".into());
        let rs = vec![route("/", "static"), ok];
        assert!(validate_routes(&rs).is_ok());

        // front_controller 必须以 / 开头且不含注入字符
        let mut bad = php.clone();
        bad.front_controller = Some("app/index.php".into());
        let rs = vec![route("/", "static"), bad];
        assert!(validate_routes(&rs).is_err(), "front_controller 须以 / 开头");

        // 未知 kind
        let rs = vec![route("/", "static"), route("/x", "cobol")];
        assert!(validate_routes(&rs).is_err(), "未知 kind 必须报错");

        // 非 / 前缀
        let rs = vec![route("/", "static"), route("api", "static")];
        assert!(validate_routes(&rs).is_err(), "前缀须以 / 开头");
    }
