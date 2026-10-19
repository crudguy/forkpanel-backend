use super::*;

    use crate::traits::DatabaseProvider;

    #[test]
    fn service_unit_from_dpkg_list_picks_primary_unit() {
        // nginx 同时 shipping nginx.service 与 nginx-debug.service：必须选主单元 nginx.service，
        // 而非排在前面（dpkg -L 顺序）或名字更长的 nginx-debug.service。
        let nginx = "/usr/lib/systemd/system/nginx-debug.service\n/usr/lib/systemd/system/nginx.service\n/usr/share/doc/nginx/copyright\n";
        assert_eq!(service_unit_from_dpkg_list(nginx, "nginx").as_deref(), Some("nginx.service"));
        // redis 真实包名是 redis-server，单元名与之同 stem
        let redis = "/lib/systemd/system/redis-server.service\n";
        assert_eq!(service_unit_from_dpkg_list(redis, "redis-server").as_deref(), Some("redis-server.service"));
    }

    #[test]
    fn service_unit_from_dpkg_list_skips_template_and_absent() {
        // 仅模板单元 → 不关联（避免把 postgresql@.service 当具体单元）
        let pg = "/usr/lib/systemd/system/postgresql@.service\n";
        assert_eq!(service_unit_from_dpkg_list(pg, "postgresql"), None);
        // 包装里没有 .service（certbot/ufw 之类）→ 不关联
        assert_eq!(service_unit_from_dpkg_list("no service file here\n", "certbot"), None);
    }

    /// dpkg 状态判据：第二位（当前状态）== 'i' 即算已安装。
    ///
    /// `hi `（apt-mark hold 钉住）是本测试的核心——hold 功能上线时的实机回归：
    /// 旧判据只认 `ii`，hold nginx 后该包从「已安装软件」整条消失。
    #[test]
    fn dpkg_status_installed_accepts_hold_variant() {
        assert!(dpkg_status_installed("ii "), "普通已安装");
        assert!(dpkg_status_installed("hi "), "hold 钉住的已安装（期望动作 h，文件在盘上）");
        assert!(dpkg_status_installed("ii"), "无尾随空格的紧凑输出");
        assert!(!dpkg_status_installed("rc "), "删剩配置：文件已不在");
        assert!(!dpkg_status_installed("un "), "未安装（dpkg-query 对没装过的包也输出一行）");
        assert!(!dpkg_status_installed("iF"), "半配置：坏了，不算可用");
        assert!(!dpkg_status_installed("iU"), "半解包：坏了，不算可用");
        assert!(!dpkg_status_installed(""), "空串保守排除");
        assert!(!dpkg_status_installed("i"), "只有一位：无当前状态位，保守排除");
    }

    fn nginx_server() -> LinuxWebServer {
        LinuxWebServer { name: Some("nginx"), paths: Arc::new(LinuxPathLayout::default()) }
    }

    fn spec_static() -> SiteSpec {
        SiteSpec {
            server_names: vec!["example.com".into(), "www.example.com".into()],
            root: PathBuf::from("/var/www/example"),
            listen: vec![80, 443],
            kind: SiteKind::Static,
            access_log: None,
            error_log: None,
            tls_cert: None,
            tls_key: None,
            force_https: false,
            spa_fallback: false,
            waf: None,
            routes: None,
            custom_conf: None,
            www_redirect: None,
            tls_profile: None,
            tls_min: None,
            hsts: false,
            hsts_max_age: 0,
            hsts_include_sub: false,
            hsts_preload: false,
            rewrite_preset: None,
            rewrite_custom: None,
            ip_allow: None,
            ip_deny: None,
            auth_basic: false,
            auth_user: None,
            auth_file: None,
            lb_policy: None,
            proxy_connect_timeout: 60,
            proxy_send_timeout: 60,
            proxy_read_timeout: 60,
            error_log_level: None,
        }
    }

    /// 多路由测试用的 spec：`/` 静态兜底 + `/api` 反代。
    fn spec_routed() -> SiteSpec {
        let mut s = spec_static();
        s.kind = SiteKind::Routed {
            routes: SiteRoutes {
                routes: vec![
                    SiteRoute { prefix: "/".into(), kind: RouteKind::Static { spa: true, root: None } },
                    SiteRoute {
                        prefix: "/api".into(),
                        kind: RouteKind::Proxy {
                            upstreams: vec!["http://127.0.0.1:3000".into()],
                        },
                    },
                ],
            },
        };
        s.routes = match &s.kind { SiteKind::Routed { routes } => Some(routes.clone()), _ => None };
        s
    }

    fn spec_waf(profile: WafProfile, rate: Option<u32>, burst: u32) -> SiteSpec {
        let mut s = spec_static();
        s.waf = Some(WafSpec { profile, rate_per_sec: rate, burst });
        s
    }

    /// 规则集必须遵守的硬约束：不含空白 / `;` / `{` / `}` / 反斜杠 / 引号。
    /// 前四者会破坏 nginx 的词法结构（正则里的 `{8,}` 量词因此不可用）；
    /// 反斜杠的转义语义在引号内外不一致——**不依赖它**才不用赌具体实现。
    #[test]
    fn pkg_install_target_formats_version_per_manager() {
        // apt 用等号语法；dnf/yum/apk/zypper 用连字符；无版本原样返回包名。
        assert_eq!(pkg_install_target("apt", "nginx", Some("1.22.1-9")), "nginx=1.22.1-9");
        assert_eq!(pkg_install_target("dnf", "nginx", Some("1.22.1")), "nginx-1.22.1");
        assert_eq!(pkg_install_target("yum", "redis", Some("5.0.2")), "redis-5.0.2");
        assert_eq!(pkg_install_target("apt", "nginx", None), "nginx");
        assert_eq!(pkg_install_target("dnf", "nginx", None), "nginx");
    }

    #[test]
    fn parse_apt_policy_versions_picks_only_version_rows() {
        // 样本取自本机 LC_ALL=C apt-cache policy nginx 的真实形态
        let out = "nginx:\n  Installed: (none)\n  Candidate: 1.26.3-3+deb13u9\n  Version table:\n\
                   1.26.3-3+deb13u9 500\n    500 http://security.debian.org/debian-security amd64 Packages\n\
                   1.26.3-3+deb13u7 500\n    500 http://deb.debian.org/debian amd64 Packages\n";
        let v = parse_apt_policy_versions(out);
        assert_eq!(v, vec!["1.26.3-3+deb13u9".to_string(), "1.26.3-3+deb13u7".to_string()]);

        // 来源行（"500 http://..."）绝不能被当成版本——它以数字开头，极易误提
        for got in &v {
            assert!(!got.starts_with("500"), "来源行的优先级被误当版本：{got}");
            assert!(!got.starts_with("http"), "来源 URL 被误当版本：{got}");
        }

        // 已安装的包：当前版本行带 "***" 前缀（本机 redis-server 真实形态）。
        // 不剥掉该标记就会漏掉正在使用的版本——这是实测才暴露的 bug，钉住它。
        let installed = "redis-server:\n  Installed: 5:8.0.2-3+deb13u3\n  Version table:\n\
                         *** 5:8.0.2-3+deb13u3 500\n     500 http://security.debian.org amd64 Packages\n\
                         5:8.0.2-3+deb13u2 500\n     500 http://deb.debian.org amd64 Packages\n";
        assert_eq!(
            parse_apt_policy_versions(installed),
            vec!["5:8.0.2-3+deb13u3".to_string(), "5:8.0.2-3+deb13u2".to_string()],
            "*** 标记的已安装版本必须被抽出"
        );
        assert_eq!(parse_apt_policy_installed(installed), Some("5:8.0.2-3+deb13u3".to_string()));

        // 未安装：apt 写 "Installed: (none)"，必须返回 None 而不是把 "(none)" 当版本号
        let not_installed = "nginx:\n  Installed: (none)\n  Candidate: 1.26.3-3+deb13u9\n  Version table:\n\
                             1.26.3-3+deb13u9 500\n";
        assert_eq!(parse_apt_policy_installed(not_installed), None);

        // 没有 Version table（如包不存在）→ 空列表，调用方退回"装最新版"
        assert!(parse_apt_policy_versions("N: Unable to locate package foo\n").is_empty());
        // 中文 locale 下标题不同，解析器只看英文标题，故必须靠调用方传 LC_ALL=C
        assert!(parse_apt_policy_versions("版本列表：\n     1.0 500\n").is_empty());
    }

    #[test]
    fn waf_rule_sets_stay_token_safe() {
        for pat in [
            WAF_UA_BASIC, WAF_UA_STRICT_EXTRA,
            WAF_SQLI_BASIC, WAF_SQLI_STRICT_EXTRA,
            WAF_XSS_BASIC, WAF_XSS_STRICT_EXTRA,
            WAF_TRAV_BASIC, WAF_TRAV_STRICT_EXTRA,
        ] {
            assert!(!pat.is_empty(), "规则集不该为空");
            for bad in [' ', '\t', '\n', ';', '{', '}', '\\', '"', '\''] {
                assert!(
                    !pat.contains(bad),
                    "规则集含非法字符 {bad:?}，会破坏 nginx 词法：{pat}"
                );
            }
        }
    }

    /// 分层只能是"加规则"，不能是"换一套规则"——否则打开严格档反而可能放松某项防护。
    #[test]
    fn strict_profile_only_adds_rules() {
        for (b, s) in [
            (waf_ua(WafProfile::Basic), waf_ua(WafProfile::Strict)),
            (waf_sqli(WafProfile::Basic), waf_sqli(WafProfile::Strict)),
            (waf_xss(WafProfile::Basic), waf_xss(WafProfile::Strict)),
            (waf_trav(WafProfile::Basic), waf_trav(WafProfile::Strict)),
        ] {
            assert!(s.starts_with(&b), "严格档必须包含基础档的全部备选：\n基础: {b}\n严格: {s}");
        }
        // 高误报备选不得出现在默认档
        assert!(!waf_sqli(WafProfile::Basic).contains("1[[:space:]]*=1"));
        assert!(!waf_xss(WafProfile::Basic).contains("eval[(]"));
    }

    #[test]
    fn waf_http_directives_precede_the_server_block() {
        let out = render_nginx(&spec_waf(WafProfile::Basic, Some(10), 20));
        let zone = out.find("limit_req_zone").expect("限速开启时应有 limit_req_zone");
        let map = out.find("map $http_user_agent").expect("应有 UA map");
        let srv = out.find("server {").expect("应有 server 块");
        assert!(zone < srv, "limit_req_zone 是 http 级指令，必须排在 server 之前：\n{out}");
        assert!(map < srv, "map 是 http 级指令，必须排在 server 之前：\n{out}");
        assert!(out.contains("rate=10r/s"), "{out}");
        assert!(out.contains("burst=20 nodelay"), "{out}");
        assert!(out.contains("limit_req_status 429"), "超限应 429（503 会被监控误判成服务挂了）：\n{out}");
    }

    #[test]
    fn waf_basic_vs_strict_differences() {
        let basic = render_nginx(&spec_waf(WafProfile::Basic, None, 0));
        assert!(basic.contains("if ($panel_example_com_ua)   { return 403; }"), "{basic}");
        assert!(basic.contains("if ($panel_example_com_sqli) { return 403; }"), "{basic}");
        assert!(basic.contains("if ($panel_example_com_xss)  { return 403; }"), "{basic}");
        assert!(basic.contains("if ($panel_example_com_trav) { return 403; }"), "{basic}");
        assert!(!basic.contains("_method"), "基础档不该限制请求方法：\n{basic}");
        assert!(!basic.contains("_noua"), "基础档不该拦空 UA：\n{basic}");
        assert!(!basic.contains("limit_req zone="), "未配置限速就不该出现 limit_req：\n{basic}");

        let strict = render_nginx(&spec_waf(WafProfile::Strict, None, 0));
        assert!(strict.contains("_noua)   { return 403; }"), "{strict}");
        assert!(strict.contains("_method) { return 405; }"), "非白名单方法应 405 而非 403：\n{strict}");
        // 敏感文件拒绝已**默认生效**（不再随 WAF 档位变化）：两档都该有
        // 隐藏文件 + 版本库 + 备份/残留三类 deny。
        for (name, out) in [("basic", &basic), ("strict", &strict)] {
            assert!(out.contains(r#"if ($uri ~* "/[.](git|svn|hg)(/|$)") { return 403; }"#), "{name} 缺版本库目录拒绝：\n{out}");
            assert!(out.contains("swp|save|tar"), "{name} 缺备份 / 残留文件拒绝：\n{out}");
        }
        // 严格档专有：目录类规则（匹配面大、误杀风险更高，故不默认开）
        assert!(!basic.contains("logs?|backup"), "基础档不该有目录类拒绝（误杀风险高）：\n{basic}");
        assert!(strict.contains("logs?|backup"), "严格档应额外拦配置 / 日志 / 备份目录：\n{strict}");
    }

    #[test]
    fn well_known_is_exempt_from_the_dotfile_deny() {
        let out = render_nginx(&spec_waf(WafProfile::Basic, None, 0));
        assert!(
            out.contains(r#"if ($uri ~ "/[.](?!well-known/)") { return 403; }"#),
            "隐藏文件规则必须放行 /.well-known —— ACME http-01 挑战文件就落在那里，\
             一刀切会把证书续期打死：\n{out}"
        );
    }

    #[test]
    fn no_waf_means_no_waf_directives() {
        let out = render_nginx(&spec_static());
        // ⚠ 清单里**刻意不含 "well-known"**：ACME 挑战 location 与敏感文件拒绝
        // 已改为默认生效（不再依附 WAF），它们出现是正确行为而非 WAF 泄漏。
        for bad in ["map $", "limit_req", "WAF", "limit_req_zone"] {
            assert!(!out.contains(bad), "未启用 WAF 时不该出现 {bad:?}：\n{out}");
        }
        // 反过来确认：默认生效的两项**确实在**（否则本测试就成了「什么都没查」的恒绿）
        assert!(out.contains("location ^~ /.well-known/acme-challenge/"), "默认应含 ACME 挑战路径：\n{out}");
        assert!(out.contains("return 403; }"), "默认应含敏感文件拒绝：\n{out}");
    }

    /// 真机语法校验：把渲染结果交给**真实的** `nginx -t`。
    ///
    /// 上面那些断言只能证明"生成的东西符合我以为的 nginx 语法"——那正是最容易错的
    /// 地方（`map` 的上下文、`if` 在 server 级是否合法、PCRE 前瞻、`limit_req` 参数、
    /// 引号内反斜杠的转义）。只有真解析器说了算。
    ///
    /// 本机没有 nginx 时**跳过并打印原因**，绝不假装通过。可用 `PANEL_NGINX_BIN`
    /// 指定任意二进制（例如从 .deb 里 `dpkg-deb -x` 解出来的，无需安装）。
    #[tokio::test]
    async fn rendered_config_passes_real_nginx_syntax_check() {
        let bin = std::path::PathBuf::from(
            std::env::var("PANEL_NGINX_BIN").unwrap_or_else(|_| "/usr/sbin/nginx".into()),
        );
        if !bin.is_file() {
            eprintln!(
                "跳过：未找到 nginx 二进制（{} 不存在；可用 PANEL_NGINX_BIN 指定）",
                bin.display()
            );
            return;
        }
        // 相对 include 的源目录。本机没装 nginx 时，可以指向从 .deb 里解出来的
        // `etc/nginx`（那里有 fastcgi_params 等发行版文件）。
        let conf_src = std::path::PathBuf::from(
            std::env::var("PANEL_NGINX_CONF_DIR").unwrap_or_else(|_| "/etc/nginx".into()),
        );
        if !conf_src.is_dir() {
            eprintln!(
                "跳过：未找到 nginx 配置目录（{} 不存在；可用 PANEL_NGINX_CONF_DIR 指定）",
                conf_src.display()
            );
            return;
        }

        // 组合覆盖全部渲染分支：3 种站点类型 × 2 个 WAF 档位 × 限速开关，外加无 WAF 基线
        let mut specs: Vec<SiteSpec> = Vec::new();
        for kind in [
            SiteKind::Static,
            SiteKind::ReverseProxy {
                upstreams: vec!["http://127.0.0.1:3000".into(), "http://127.0.0.1:3001".into()],
            },
            SiteKind::Php { fpm: "unix:/run/php/php8.2-fpm.sock".into() },
        ] {
            for profile in [WafProfile::Basic, WafProfile::Strict] {
                for rate in [None, Some(10u32)] {
                    let mut s = spec_static();
                    s.kind = kind.clone();
                    // 非特权环境下 :80/:443 会被内核拒绝 bind —— **`nginx -t` 会真的去
                    // bind**（它靠端口冲突来检测配置里的重复 `listen`），于是校验会因
                    // 权限失败，而这与配置内容无关。测试改用高位端口：WAF 片段与端口
                    // 无关，结论不受影响。
                    s.listen = vec![18080, 18443];
                    s.waf = Some(WafSpec { profile, rate_per_sec: rate, burst: 20 });
                    specs.push(s);
                }
            }
        }
        let mut baseline = spec_static();
        baseline.listen = vec![18080, 18443];
        specs.push(baseline);

        let base = std::env::temp_dir()
            .join(format!("panel-nginx-t-{}-{}", std::process::id(), uniq_counter()));
        std::fs::create_dir_all(base.join("conf")).unwrap();
        std::fs::create_dir_all(base.join("logs")).unwrap();

        for (i, s) in specs.iter().enumerate() {
            let frag = base.join("site.conf");
            let rendered = render_nginx(s);
            std::fs::write(&frag, &rendered).unwrap();
            // **复用生产那三份实现**（wrapper / argv / include 搬运），不另抄一份：
            // 抄一份必然漂移，而漂移的方向恰恰是"测试通过了、生产那套没通过"。
            stage_relative_includes(&rendered, &conf_src, &base.join("conf"))
                .await
                .unwrap();
            std::fs::write(base.join("conf/nginx.conf"), validate_wrapper(&base, &frag)).unwrap();

            let out = std::process::Command::new(&bin)
                .args(nginx_test_argv(&base))
                .output()
                .expect("启动 nginx 失败");
            assert!(
                out.status.success(),
                "第 {i} 份配置未通过真实 nginx 语法校验（kind={:?}）：\n{}\n--- 渲染结果 ---\n{}",
                s.kind,
                String::from_utf8_lossy(&out.stderr),
                render_nginx(s)
            );
        }

        // ── 阴性对照：喂一份**故意非法**的片段，必须被判失败 ──
        // 这一条才是真正钉住本次修复的断言。旧实现只给 `-p`，而 Debian 的 nginx
        // 把 `--conf-path` 编成了绝对路径 → `-p` 不生效 → 无论片段多离谱，测的
        // 都是系统的 /etc/nginx/nginx.conf：系统里没装 nginx 时它报"文件不存在"，
        // 装了 nginx 之后它又**恒为通过**。两种表现都不指向真正的问题，
        // 而生成片段里的语法错误会一路部署到线上（reload 失败留下坏配置，
        // 下次 nginx 重启直接起不来）。
        let bad = base.join("bad.conf");
        std::fs::write(&bad, "this_is_not_an_nginx_directive 1;\n").unwrap();
        std::fs::write(base.join("conf/nginx.conf"), validate_wrapper(&base, &bad)).unwrap();
        let out = std::process::Command::new(&bin)
            .args(nginx_test_argv(&base))
            .output()
            .expect("启动 nginx 失败");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "非法片段必须被判失败，否则说明校验根本没读到它");
        assert!(
            err.contains("bad.conf"),
            "报错应当指向我们自己生成的片段文件（证明真的读到了它），实际是：{err}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn render_static_contains_core_directives() {
        let out = render_nginx(&spec_static());
        assert!(out.contains("listen 80;"), "{out}");
        // 无证书时**不得**监听 443（详见 render_nginx 里的说明：裸 `listen 443` 会让
        // 同机任一 `listen 443 ssl` 站点把**整份** nginx 配置拖成 emerg）。
        assert!(!out.contains("listen 443"), "无证书时不应监听 443: {out}");
        assert!(!out.contains("ssl;"), "无证书时不应出现 ssl: {out}");
        assert!(out.contains("server_name example.com www.example.com;"), "{out}");
        assert!(out.contains("root /var/www/example;"), "{out}");
        assert!(out.contains("try_files $uri $uri/ =404;"), "{out}");
    }

    /// 回归防护：无证书站点与「有证书 + 443 ssl」的站点同机共存时，前者不得裸监听
    /// 443 —— 那会让 nginx 直接 emerg，**整份**配置（含其它正常站点）全部加载失败。
    /// 修好前此断言为 1（存在裸 `listen 443;`），修好后为 0。
    #[test]
    fn render_no_tls_site_never_bare_listens_443_beside_ssl_site() {
        let no_tls = spec_static(); // listen=[80,443]，tls_cert/tls_key 均为 None
        let mut with_tls = spec_static();
        with_tls.server_names = vec!["secure.example".into()];
        with_tls.tls_cert = Some(PathBuf::from("/tmp/secure.example.crt"));
        with_tls.tls_key = Some(PathBuf::from("/tmp/secure.example.key"));

        let combined = format!("{}{}", render_nginx(&no_tls), render_nginx(&with_tls));
        assert!(combined.contains("listen 443 ssl;"), "有证书站点应 ssl 监听 443: {combined}");
        assert_eq!(
            combined.matches("listen 443;").count(),
            0,
            "无证书站点不得裸监听 443（会让整份 nginx 配置 emerg）: {combined}"
        );
        // 无证书站点仍须保留明文 80，别把站点一起修没了
        assert!(combined.contains("listen 80;"), "{combined}");
    }

    #[test]
    fn render_force_https_with_tls_adds_redirect_and_ssl() {
        let mut s = spec_static();
        s.force_https = true;
        s.tls_cert = Some(PathBuf::from("/etc/panel/ssl/example.com.crt"));
        s.tls_key = Some(PathBuf::from("/etc/panel/ssl/example.com.key"));
        let out = render_nginx(&s);
        assert!(out.contains("return 301 https://$host$request_uri;"), "{out}");
        assert!(out.contains("listen 443 ssl;"), "{out}");
        assert!(out.contains("ssl_certificate     /etc/panel/ssl/example.com.crt;"), "{out}");
        assert!(out.contains("ssl_certificate_key /etc/panel/ssl/example.com.key;"), "{out}");
        // 80 只应出现在重定向块一次，主块不再监听 80
        assert_eq!(out.matches("listen 80;").count(), 1, "{out}");
    }

    #[test]
    fn render_reverse_proxy_sets_headers() {
        let mut s = spec_static();
        s.kind = SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] };
        let out = render_nginx(&s);
        assert!(out.contains("proxy_pass http://127.0.0.1:3000;"), "{out}");
        assert!(out.contains("proxy_set_header Host $host;"), "{out}");
        assert!(out.contains("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"), "{out}");
        // ⚠ 断言必须**只看主 location 块**：反代站点另有 ACME 挑战 location
        // （合法地含 try_files），全文查 try_files 会误伤那条。
        let main = out
            .split("location / {")
            .nth(1)
            .and_then(|t| t.split('}').next())
            .expect("应有主 location 块");
        assert!(!main.contains("try_files"), "反代的主 location 不该用 try_files: {main}");
        assert!(!main.contains("root "), "反代的主 location 不该自带 root（用 server 级 root）: {main}");
        // 单后端不该建 upstream 块：多一层间接没有收益
        assert!(!out.contains("upstream "), "单后端不应生成 upstream 块: {out}");
    }

    #[test]
    fn render_multi_upstream_puts_block_at_http_level() {
        let mut s = spec_static();
        s.kind = SiteKind::ReverseProxy {
            upstreams: vec!["http://127.0.0.1:3000".into(), "http://127.0.0.1:3001".into()],
        };
        let out = render_nginx(&s);
        // upstream 是 http 级指令：必须排在 server 之前，否则 nginx -t 会整份拒绝
        let up = out.find("upstream ").expect("应生成 upstream 块");
        let srv = out.find("server {").expect("应有 server 块");
        assert!(up < srv, "upstream 块必须在 server 之前: {out}");
        // server 指令只接受 host:port
        assert!(out.contains("server 127.0.0.1:3000;"), "{out}");
        assert!(!out.contains("server http://"), "upstream 内不得出现 scheme: {out}");
        assert!(out.contains("proxy_pass http://panel_"), "proxy_pass 应指向 upstream 名: {out}");
    }

    #[test]
    fn render_php_passes_to_fpm() {
        let mut s = spec_static();
        s.kind = SiteKind::Php { fpm: "unix:/run/php/php8.2-fpm.sock".into() };
        let out = render_nginx(&s);
        assert!(out.contains("fastcgi_pass unix:/run/php/php8.2-fpm.sock;"), "{out}");
        assert!(out.contains("SCRIPT_FILENAME $document_root$fastcgi_script_name;"), "{out}");
        assert!(out.contains("location ~ \\.php$"), "{out}");
    }

    #[test]
    fn render_reverse_proxy_supports_websocket() {
        let mut s = spec_static();
        s.kind = SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] };
        let out = render_nginx(&s);
        // 升级头 + HTTP/1.1 长连接：WebSocket 握手才能成功
        assert!(out.contains("proxy_http_version 1.1;"), "{out}");
        assert!(out.contains("proxy_set_header Upgrade $http_upgrade;"), "{out}");
        // map 动态决定 Connection（普通请求 keep-alive、WS 升级），变量名每站唯一
        let ws_var = format!("${}_ws", upstream_name(&s.server_names));
        assert!(out.contains(&format!("map $http_upgrade {ws_var} {{")), "{out}");
        assert!(out.contains(&format!("proxy_set_header Connection {ws_var};")), "{out}");
        // 单后端仍不该建 upstream 块
        assert!(!out.contains("upstream "), "单后端不应生成 upstream 块: {out}");
    }

    #[test]
    fn render_spa_fallback_uses_index_html() {
        let mut s = spec_static();
        s.spa_fallback = true;
        let out = render_nginx(&s);
        assert!(out.contains("try_files $uri $uri/ /index.html;"), "{out}");
        // 同上：ACME 挑战 location 合法地含 =404，只能查主 location 块
        let main = out
            .split("location / {")
            .nth(1)
            .and_then(|t| t.split('}').next())
            .expect("应有主 location 块");
        assert!(!main.contains("=404"), "SPA 的主 location 不该回 404: {main}");
        // 非 SPA 仍是 =404（避免把未知路径当成 index 引发漏洞）
        let mut plain = spec_static();
        plain.spa_fallback = false;
        assert!(render_nginx(&plain).contains("try_files $uri $uri/ =404;"), "{plain:?}");
    }

    /// 多路由核心：`/` 静态 + `/api` 反代，各生成一条 `location ^~`。
    ///
    /// 这正是「Vue dist + Go/Node API」这一最高频形态——此前必须拆成两个站点。
    #[test]
    fn routed_site_renders_one_caret_prefix_location_per_route() {
        let out = render_nginx(&spec_routed());
        assert!(out.contains("location ^~ / {"), "缺兜底路由：\n{out}");
        assert!(out.contains("location ^~ /api {"), "缺 /api 路由：\n{out}");
        assert!(out.contains("proxy_pass http://127.0.0.1:3000;"), "反代目标错：\n{out}");
        // / 是 SPA 静态 → 回退 index.html
        assert!(out.contains("try_files $uri $uri/ /index.html;"), "/ 应为 SPA 静态：\n{out}");
    }

    /// #2 的核心约束：**多路由下必须全部用 `^~` 前缀，一条正则都不用**。
    ///
    /// 理由：nginx 里`^~` 前缀命中后**永不再走正则**，这让「用户写的 prefix」
    /// 与「deny/WAF 的正则 location」的优先级变得确定。反之若用普通前缀，
    /// 谁先命中就取决于配置里的书写顺序——多站点 conf 拼进同一 http 上下文时
    /// 这种顺序依赖极难排查。
    #[test]
    fn routed_sites_use_no_regex_locations() {
        let out = render_nginx(&spec_routed());
        // ⚠ 断言只针对**路由表段**（`# ── 多路由` 到下一个段标/结尾）。
        // deny 与 ACME 那几条**必须仍是正则**——它们要拦的是「任意路径下的
        // 敏感文件」（`/api/.env`、`/admin/.git/config`），换成前缀就漏了。
        // 「路由表不用正则」与「防护规则用正则」是两件事，别混为一谈。
        let routed_section = out
            .split("── 多路由")
            .nth(1)
            .expect("应有多路由段");
        for line in routed_section.lines().filter(|l| l.contains("location ")) {
            assert!(
                line.contains("location ^~ "),
                "路由表只允许 ^~ 前缀（禁正则），发现：{line}\n{routed_section}"
            );
        }
        // 反向确认：防护规则确实还在（且是正则形态）
        assert!(out.contains(r#"if ($uri ~ "/[.](?!well-known/)") { return 403; }"#), "{out}");
        // 反代请求头一行不能少（Host/真实 IP 是反代的 basics）
        assert!(out.contains("proxy_set_header Host $host;"), "{out}");
        assert!(out.contains("proxy_set_header X-Real-IP $remote_addr;"), "{out}");
    }

    /// 排序必须按前缀长度降序——`/api/admin` 要先于 `/api` 先于 `/`。
    /// 即便 nginx 前缀匹配本身挑最长，显式降序也让「配置文本顺序 = 生效顺序」。
    #[test]
    fn routed_routes_render_in_longest_prefix_first_order() {
        let mut s = spec_static();
        let routes = SiteRoutes {
            routes: vec![
                SiteRoute { prefix: "/".into(), kind: RouteKind::Static { spa: false, root: None } },
                SiteRoute { prefix: "/api".into(), kind: RouteKind::Static { spa: false, root: None } },
                SiteRoute {
                    prefix: "/api/admin".into(),
                    kind: RouteKind::Proxy { upstreams: vec!["http://127.0.0.1:9000".into()] },
                },
            ],
        };
        s.kind = SiteKind::Routed { routes: routes.clone() };
        let out = render_nginx(&s);
        let admin = out.find("location ^~ /api/admin {").expect("应有 /api/admin");
        let api = out.find("location ^~ /api {").expect("应有 /api");
        let root = out.find("location ^~ / {").expect("应有 /");
        assert!(admin < api && api < root, "顺序应按前缀长度降序：\n{out}");
        // 顺带验证 sorted() 与 fallback()
        assert_eq!(routes.fallback().map(|r| r.prefix.as_str()), Some("/"));
    }

    /// 多路由下两条反代路由各有多个后端 → upstream 块名**必须不同**。
    /// 撞名会让 nginx 以 `duplicate upstream` 拒绝加载**整份配置**
    /// （不止这个站点，全机 nginx 起不来）。
    #[test]
    fn routed_multi_upstream_blocks_have_unique_names() {
        let mut s = spec_static();
        s.kind = SiteKind::Routed {
            routes: SiteRoutes {
                routes: vec![
                    SiteRoute { prefix: "/".into(), kind: RouteKind::Static { spa: false, root: None } },
                    SiteRoute {
                        prefix: "/api".into(),
                        kind: RouteKind::Proxy {
                            upstreams: vec!["http://127.0.0.1:3000".into(), "http://127.0.0.1:3001".into()],
                        },
                    },
                    SiteRoute {
                        prefix: "/ws".into(),
                        kind: RouteKind::Proxy {
                            upstreams: vec!["http://127.0.0.1:4000".into(), "http://127.0.0.1:4001".into()],
                        },
                    },
                ],
            },
        };
        let out = render_nginx(&s);
        assert!(out.contains("upstream panel_example_com_api {"), "{out}");
        assert!(out.contains("upstream panel_example_com_ws {"), "{out}");
        // 两个 map 变量也不能重名
        assert!(out.contains("map $http_upgrade $panel_example_com_api_ws {"), "{out}");
        assert!(out.contains("map $http_upgrade $panel_example_com_ws_ws {"), "{out}");
        // 单后端路由不该建 upstream 块（少一层间接）
        let single = render_nginx(&spec_routed());
        assert!(!single.contains("upstream "), "单后端不该建 upstream 块：\n{single}");
    }

    /// 自定义配置片段：原样插入主 server 块**尾部**（闭合 `}` 之前）。
    /// 三个必须保住的语义：① 内容逐行原样（不重排缩进——写坏由 nginx -t 拦）；
    /// ② 空/仅空白片段不产生任何输出；③ 片段在 server 块内（`}` 之前）。
    #[test]
    fn custom_conf_inserted_before_server_close_brace() {
        let mut s = spec_static();
        s.custom_conf = Some("add_header X-Custom \"1\";\nlocation = /health { return 200; }".into());
        let out = render_nginx(&s);
        // ① 内容逐行原样
        assert!(out.contains("add_header X-Custom \"1\";"), "{out}");
        assert!(out.contains("location = /health { return 200; }"), "{out}");
        // ③ 片段位于 server 块的闭合 `}` 之前（不能掉到块外——那会改变指令作用域）
        let seg = out.find("add_header X-Custom").expect("片段应在输出中");
        let tail = &out[seg..];
        assert!(
            tail.contains("\n}\n"),
            "片段之后必须有 server 块的闭合花括号：\n{tail}"
        );
        // ② 空片段（None / 空白）不产生片段段标
        s.custom_conf = Some("   \n\t\n".into());
        assert!(
            !render_nginx(&s).contains("自定义配置片段"),
            "空白片段不应渲染任何内容"
        );
        s.custom_conf = None;
        assert!(!render_nginx(&s).contains("自定义配置片段"), "{out}");
    }

    /// www ↔ 非 www 跳转（020）：独立 server 块 + return 301，且**主块必须剔除来源
    /// 域名**——两块同名会让 nginx 报 conflicting server name 并按先声明者命中，
    /// 跳转直接失效（这是独立块方案唯一容易写错的地方，故用断言钉住）。
    #[test]
    fn www_redirect_emits_standalone_server_and_drops_source_name() {
        // server_names = [example.com, www.example.com]
        let mut s = spec_static();
        s.www_redirect = Some("to_bare".into());
        let out = render_nginx(&s);
        assert!(out.contains("return 301 $scheme://example.com$request_uri;"), "{out}");
        assert!(out.contains("    server_name www.example.com;\n"), "跳转块只命中来源域名：{out}");
        assert!(out.contains("    server_name example.com;\n"), "主块保留目标域名：{out}");
        assert_eq!(out.matches("    server_name ").count(), 2, "跳转块与主块各一条：{out}");
        // 反向：裸域 → www
        s.www_redirect = Some("to_www".into());
        assert!(render_nginx(&s).contains("return 301 $scheme://www.example.com$request_uri;"), "{s:?}");
        // off（默认）不生成任何跳转块
        s.www_redirect = Some("off".into());
        assert!(!render_nginx(&s).contains("$scheme://"), "off 不应生成跳转：{s:?}");
    }

    /// TLS 强化（020）：协议下限按档位**展开**、套件取预设、HSTS 仅在开启时输出。
    #[test]
    fn tls_hardening_emits_protocols_ciphers_and_hsts_only_when_enabled() {
        let mut s = spec_static();
        s.tls_cert = Some(PathBuf::from("/etc/panel/ssl/example.com.crt"));
        s.tls_key = Some(PathBuf::from("/etc/panel/ssl/example.com.key"));
        s.tls_min = Some("TLSv1.3".into());
        s.tls_profile = Some("strict".into());
        let out = render_nginx(&s);
        assert!(out.contains("ssl_protocols TLSv1.3;"), "{out}");
        // strict 档仍必须是 OpenSSL 套件名（TLSv1.3 套件名会让 nginx emerg，见 tls_ciphers）
        assert!(out.contains("ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384"), "{out}");
        assert!(out.contains("ssl_session_cache shared:"), "{out}");
        assert!(!out.contains("Strict-Transport-Security"), "HSTS 默认不开：{out}");
        // 开启后按 max-age / includeSubDomains / preload 逐项拼装
        s.hsts = true;
        s.hsts_max_age = 300;
        s.hsts_include_sub = true;
        let out2 = render_nginx(&s);
        assert!(out2.contains("Strict-Transport-Security \"max-age=300; includeSubDomains\" always;"), "{out2}");
        s.hsts_preload = true;
        assert!(render_nginx(&s).contains("max-age=300; includeSubDomains; preload"), "{s:?}");
        // 下限展开：TLSv1.2 → `TLSv1.2 TLSv1.3`
        s.tls_min = Some("TLSv1.2".into());
        assert!(render_nginx(&s).contains("ssl_protocols TLSv1.2 TLSv1.3;"), "{s:?}");
    }

    /// 伪静态（020）：预置模板替换默认 `=404` 兜底；custom 时原样输出用户文本。
    #[test]
    fn php_rewrite_preset_replaces_try_files() {
        let mut s = spec_static();
        s.kind = SiteKind::Php { fpm: "unix:/run/php/php8.2-fpm.sock".into() };
        assert!(render_nginx(&s).contains("try_files $uri $uri/ =404;"), "默认无伪静态：{s:?}");
        s.rewrite_preset = Some("wordpress".into());
        assert!(render_nginx(&s).contains("try_files $uri $uri/ /index.php?$args;"), "{s:?}");
        s.rewrite_preset = Some("laravel".into());
        assert!(render_nginx(&s).contains("try_files $uri $uri/ /index.php?$query_string;"), "{s:?}");
        // ThinkPHP 的差别在 php location 里拆 PATH_INFO
        s.rewrite_preset = Some("thinkphp".into());
        assert!(render_nginx(&s).contains("fastcgi_split_path_info"), "ThinkPHP 需拆 PATH_INFO：{s:?}");
        s.rewrite_preset = Some("custom".into());
        s.rewrite_custom = Some("try_files $uri $uri/ /custom.php?$args;".into());
        assert!(render_nginx(&s).contains("try_files $uri $uri/ /custom.php?$args;"), "{s:?}");
    }

    /// 多路由的 PHP 必须用 front controller 形式，**不能**用 `location ~ \.php$`。
    ///
    /// 这是 #2+#4 必须一起做的原因：`^~` 会屏蔽同级正则，若沿用单路由那套正则写法，
    /// PHP 请求会落到静态处理（源码被当文本下载，或直接 404）——一个更隐蔽的坏法。
    #[test]
    fn routed_php_uses_front_controller_not_regex() {
        let mut s = spec_static();
        s.kind = SiteKind::Routed {
            routes: SiteRoutes {
                routes: vec![
                    SiteRoute { prefix: "/".into(), kind: RouteKind::Static { spa: false, root: None } },
                    SiteRoute {
                        prefix: "/app".into(),
                        kind: RouteKind::Php {
                            fpm: "unix:/run/php/php8.2-fpm.sock".into(),
                            front_controller: "/app/public/index.php".into(),
                        },
                    },
                ],
            },
        };
        let out = render_nginx(&s);
        assert!(out.contains("location ^~ /app {"), "{out}");
        assert!(out.contains("fastcgi_pass unix:/run/php/php8.2-fpm.sock;"), "{out}");
        assert!(
            out.contains("fastcgi_param SCRIPT_FILENAME $document_root/app/public/index.php;"),
            "应把 SCRIPT_FILENAME 固定到 front controller：\n{out}"
        );
        // 关键：**路由表段内**不得出现正则 location（deny/ACME 的正则不在此段）
        let routed_section = out.split("── 多路由").nth(1).expect("应有多路由段");
        assert!(!routed_section.contains("location ~"), "路由表不得用正则 location：\n{routed_section}");
    }

    /// 多路由站点的 ACME 挑战路径与敏感文件 deny **仍然生效**——
    /// 它们是 server 级的，与路由表共存（这也是把两件事分开实现的原因）。
    #[test]
    fn routed_site_keeps_acme_and_deny_guards() {
        let out = render_nginx(&spec_routed());
        assert!(out.contains("location ^~ /.well-known/acme-challenge/"), "{out}");
        assert!(out.contains(r#"if ($uri ~ "/[.](?!well-known/)") { return 403; }"#), "{out}");
    }

    /// 修复 #1：反代站点的 ACME http-01 挑战路径。
    ///
    /// 此前反代站点只有 `location / { proxy_pass … }`，certbot 的挑战请求会被
    /// **转发给后端** → 拉不到 token → 签发静默失败。判据是「配置里必须有一条
    /// 从磁盘 root 取挑战文件的 location，且优先级高于任何正则」。
    #[test]
    fn acme_challenge_path_survives_reverse_proxy() {
        let mut s = spec_static();
        s.kind = SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] };
        let out = render_nginx(&s);
        assert!(
            out.contains("location ^~ /.well-known/acme-challenge/ {"),
            "反代站点必须有 ACME 挑战 location，否则挑战请求会被转发给后端：\n{out}"
        );
        assert!(out.contains("root /var/www/example;"), "挑战 location 应复用站点 root：\n{out}");
        // `^~` 是关键：命中后不再走正则，deny 规则抢不走挑战路径
        let acme = out
            .split("location ^~ /.well-known/acme-challenge/ {")
            .nth(1)
            .and_then(|t| t.split('}').next())
            .expect("应能切出 ACME location 块");
        assert!(acme.contains("try_files $uri =404;"), "挑战文件不存在应 404（不能当索引）：\n{acme}");
        // 挑战 location 必须排在 proxy 的主 location **之前**（可读性/可维护性，
        // 且让「挑战优先」在配置文本上就是显然的）
        let acme_at = out.find("location ^~ /.well-known/acme-challenge/").unwrap();
        let proxy_at = out.find("proxy_pass ").unwrap();
        assert!(acme_at < proxy_at, "ACME location 应排在 proxy_pass 之前：\n{out}");
    }

    /// 修复 #1 的覆盖广度：三种「有 root」的类型都要有挑战路径，
    /// 只有整站重定向（不输出 root）例外。
    #[test]
    fn acme_challenge_path_covers_all_root_bearing_kinds() {
        let mut proxy = spec_static();
        proxy.kind = SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] };
        let mut php = spec_static();
        php.kind = SiteKind::Php { fpm: "unix:/run/php/php8.2-fpm.sock".into() };

        for (name, spec) in [
            ("static", spec_static()),
            ("proxy", proxy),
            ("php", php),
        ] {
            let out = render_nginx(&spec);
            assert!(
                out.contains("location ^~ /.well-known/acme-challenge/ {"),
                "{name} 站点缺 ACME 挑战 location：\n{out}"
            );
        }

        // 重定向站不输出 root，挑战路径对它无意义（证书由目标站负责）
        let mut rd = spec_static();
        rd.kind = SiteKind::Redirect { target: "https://x.example.com".into(), code: 301 };
        let out = render_nginx(&rd);
        assert!(!out.contains("acme-challenge"), "重定向站不该输出挑战 location：\n{out}");
    }

    /// 修复 #3：敏感文件拒绝**默认生效**（不依赖 WAF）。
    ///
    /// 此前 deny 只在 `waf: Some(..)` 时才生成 —— 不开 WAF 的站点连 `.git` 都能下载。
    #[test]
    fn sensitive_files_are_denied_without_waf() {
        let out = render_nginx(&spec_static());
        assert!(out.contains("return 403; }"), "默认站点就该有 deny 规则：\n{out}");
        // 隐藏文件（放行 .well-known）
        assert!(out.contains(r#"if ($uri ~ "/[.](?!well-known/)") { return 403; }"#), "缺隐藏文件拒绝：\n{out}");
        // 版本库目录
        assert!(out.contains(r#"if ($uri ~* "/[.](git|svn|hg)(/|$)") { return 403; }"#), "缺版本库目录拒绝：\n{out}");
        // 备份与编辑器残留
        assert!(out.contains("swp|save|tar"), "缺备份 / 残留文件拒绝：\n{out}");
        // 目录类规则误杀面大，**只**在严格档
        assert!(!out.contains("logs?|backup"), "默认档不该有目录类 deny：\n{out}");
    }

    /// 回归：多路由上线后实测 `/.env` 返回 **200 + 文件内容**（源码直接被下载走）。
    ///
    /// 根因是 `location ^~` 会**屏蔽同级正则 location** —— deny 原先是
    /// `location ~ …`，被 `location ^~ /` 抢先命中后整条规则不执行。
    /// 因此 deny 必须落在 **server 级 `if`**（rewrite 阶段，早于 location 匹配）。
    ///
    /// 这条断言锁住「deny 是 `if` 而非 `location`」——形态改回去就会红。
    #[test]
    fn deny_rules_must_be_server_level_if_not_location() {
        let out = render_nginx(&spec_routed());
        assert!(
            out.contains(r#"if ($uri ~ "/[.](?!well-known/)") { return 403; }"#),
            "敏感文件拒绝必须是 server 级 if（rewrite 阶段），否则被 ^~ 屏蔽：\n{out}"
        );
        // 反向断言：deny **不得**再以正则 location 形态出现
        assert!(
            !out.contains("location ~ /[.]") && !out.contains("location ~* /[.]"),
            "deny 不许用正则 location（^~ 会屏蔽它）：\n{out}"
        );
        // 所有 return 403 都必须在 server 块内（缩进 4 空格），不依赖任何 location
        for line in out.lines().filter(|l| l.trim_start().starts_with("if ($uri")) {
            assert!(
                line.starts_with("    if ($uri"),
                "deny 的 if 必须在 server 块内：{line}\n{out}"
            );
        }
    }

    /// deny 必须覆盖**任意层级**的隐藏文件，不只是顶层。
    ///
    /// 实测：`^/[.]`（带锚点）时 `/admin/.env` 与 `/api/.env` 全部漏过——
    /// 多路由让站点有了子路径，这个漏洞才暴露。去掉 `^` 后 `/[.]` 匹配任意位置，
    /// 而 `/a.b.c` 这类正常名不受影响（`.` 前面是字母而非 `/`）。
    ///
    /// 同时锁住 `.well-known` 的放行不能被这个"放宽"误伤。
    #[test]
    fn deny_covers_nested_paths_but_still_exempts_well_known() {
        let out = render_nginx(&spec_routed());
        // 不能有 `^` 锚点
        assert!(
            !out.contains(r#"if ($uri ~ "^/[.]"#),
            "隐藏文件规则不能锚定 ^（否则 /admin/.env 漏过）：\n{out}"
        );
        assert!(!out.contains(r#"~* "^/[.](git|svn|hg)"#), "版本库规则同样不能锚定 ^：\n{out}");
        // 但放行 .well-known 的前瞻必须仍在
        assert!(out.contains(r#"/[.](?!well-known/)"#), "必须保留 .well-known 放行：\n{out}");
        assert!(
            out.contains(r#"location ^~ /.well-known/acme-challenge/"#),
            "挑战路径必须仍在：\n{out}"
        );
    }

    /// deny 放行 `/.well-known` 是硬要求——一刀切会把证书签发/续期打死，
    /// 且症状是「证书莫名过期」，与这条规则毫无字面关联，最难排查。
    #[test]
    fn deny_rules_exempt_well_known() {
        for (name, spec) in [
            ("no-waf", spec_static()),
            ("basic", spec_waf(WafProfile::Basic, None, 0)),
            ("strict", spec_waf(WafProfile::Strict, None, 0)),
        ] {
            let out = render_nginx(&spec);
            assert!(
                out.contains(r#"if ($uri ~ "/[.](?!well-known/)") { return 403; }"#),
                "{name}: 隐藏文件规则必须放行 /.well-known：\n{out}"
            );
            assert!(
                out.contains("location ^~ /.well-known/acme-challenge/"),
                "{name}: 必须有显式的挑战 location：\n{out}"
            );
        }
    }

    #[test]
    fn render_redirect_returns_code_and_target() {
        let mut s = spec_static();
        s.kind = SiteKind::Redirect { target: "https://new.example.com".into(), code: 301 };
        let out = render_nginx(&s);
        // 整站重定向：只发 return，不输出 root / index / location
        assert!(out.contains("return 301 https://new.example.com$request_uri;"), "{out}");
        assert!(!out.contains("root "), "重定向不应输出 root: {out}");
        assert!(!out.contains("location "), "重定向不应输出 location: {out}");
        assert!(!out.contains("try_files"), "重定向不应输出 try_files: {out}");
    }

    // ── 应用托管（systemd 单元渲染） ──

    fn app_spec() -> AppUnitSpec {
        AppUnitSpec {
            unit: app_unit_name("blog"),
            description: "ForkPanel 应用 blog".into(),
            workdir: PathBuf::from("/srv/apps/blog"),
            exec_start: "node server.js".into(),
            run_user: Some("www-data".into()),
            env: vec![("NODE_ENV".into(), "production".into())],
            port: 3000,
            auto_restart: true,
        }
    }

    #[test]
    fn render_app_unit_emits_core_directives() {
        let out = render_app_unit(&app_spec());
        for want in [
            "[Unit]", "[Service]", "[Install]",
            "WorkingDirectory=/srv/apps/blog",
            "ExecStart=node server.js",
            "User=www-data",
            "Environment=\"NODE_ENV=production\"",
            "Restart=always",
            "WantedBy=multi-user.target",
        ] {
            assert!(out.contains(want), "缺 {want}: {out}");
        }
    }

    #[test]
    fn render_app_unit_restart_toggle() {
        let mut s = app_spec();
        s.auto_restart = false;
        let out = render_app_unit(&s);
        assert!(out.contains("Restart=no"), "{out}");
        assert!(!out.contains("Restart=always"), "{out}");
    }

    #[test]
    fn render_app_unit_escapes_specifier_and_injection() {
        let mut s = app_spec();
        // `%` 必须双写成 `%%`：否则 systemd 当 specifier 展开（路径里的 % 被静默替换掉）
        s.workdir = PathBuf::from("/srv/100%/app");
        s.exec_start = "node /srv/100%/s.js".into();
        // 换行是**注入点**：不剔除会让值里的内容变成新的 systemd 指令
        s.env = vec![("A".into(), "x\nRestart=no".into())];
        let out = render_app_unit(&s);
        assert!(out.contains("WorkingDirectory=/srv/100%%/app"), "{out}");
        assert!(out.contains("ExecStart=node /srv/100%%/s.js"), "{out}");
        assert!(!out.contains("x\nRestart=no"), "换行必须被剔除（注入点）: {out}");
        assert!(out.contains("Environment=\"A=x Restart=no\""), "{out}");
        // 整个单元里只能有一条 **以 Restart= 开头的指令行** —— 值里那条必须已被折平。
        // 注意按「行首」判定：折叠后的 env 值里合法地含有 "Restart=no" 这个文本片段
        // （它在 Environment= 行内部，不是独立指令），直接 `matches("Restart=")` 会误计。
        let directive_lines = out.lines().filter(|l| l.starts_with("Restart=")).count();
        assert_eq!(directive_lines, 1, "{out}");
    }

    #[test]
    fn app_unit_name_is_valid_systemd_name() {
        // 站点名白名单**允许** `..`（如 `a..b`），而 systemd 单元名禁止 → 派生时必须折叠，
        // 否则会出现"校验通过却装不进 systemd"的死角。
        for app in ["blog", "my-app", "a.b", "a..b", "api_v2"] {
            let u = app_unit_name(app);
            assert!(!u.contains(".."), "单元名残留 `..`: {u}");
            assert!(panel_core::rules::is_valid_unit_name(&u), "派生单元名不合法: {u}");
            assert!(u.starts_with("panel-app-") && u.ends_with(".service"), "{u}");
        }
    }

    #[test]
    fn slug_sanitizes_and_defaults() {
        assert_eq!(slug("example.com"), "example.com");
        assert_eq!(slug("a/b c"), "a_b_c");
        assert_eq!(slug(""), "site");
    }

    #[test]
    fn conf_path_is_namespaced_and_derived_from_first_host() {
        let p = nginx_server().conf_path(&["foo.example".into(), "bar.example".into()]);
        assert!(p.to_string_lossy().ends_with("panel-foo.example.conf"), "{p:?}");
    }

    #[test]
    fn render_rejects_empty_server_names() {
        let mut s = spec_static();
        s.server_names.clear();
        assert!(nginx_server().render(&s).is_err());
    }

    #[test]
    fn render_rejects_when_no_webserver() {
        let ws = LinuxWebServer { name: None, paths: Arc::new(LinuxPathLayout::default()) };
        assert!(matches!(ws.render(&spec_static()), Err(PanelError::Unsupported(_))));
    }

    fn caddy_server() -> LinuxWebServer {
        LinuxWebServer { name: Some("caddy"), paths: Arc::new(LinuxPathLayout::default()) }
    }

    // ── caddy 基础样板渲染（纯函数黄金单测；validate/reload 的 CLI 沙箱无 caddy 未真机验证）──

    #[test]
    fn caddy_static_renders_http_site_with_root_and_file_server() {
        let out = render_caddy(&spec_static());
        // 无证书 → 仅 http，绝不产出 https/443（同 nginx 纪律）
        assert!(out.contains("http://example.com, http://www.example.com {"), "应 http 站点块（多域名列表）：{out}");
        assert!(!out.contains("https://"), "无证书不得出现 https：{out}");
        assert!(out.contains("root * /var/www/example"), "应声明 root：{out}");
        assert!(out.contains("file_server"), "静态站应 file_server：{out}");
    }

    #[test]
    fn caddy_spa_fallback_emits_try_files_index_html() {
        let mut s = spec_static();
        s.spa_fallback = true;
        let out = render_caddy(&s);
        assert!(out.contains("try_files {path} {path}/ /index.html"), "SPA 回退：{out}");
    }

    #[test]
    fn caddy_reverse_proxy_sets_upstream_and_client_headers() {
        let mut s = spec_static();
        s.kind = SiteKind::ReverseProxy { upstreams: vec!["http://127.0.0.1:3000".into()] };
        let out = render_caddy(&s);
        assert!(out.contains("reverse_proxy http://127.0.0.1:3000"), "应反代到后端：{out}");
        assert!(out.contains("header_up Host {host}"), "应透传 Host：{out}");
        assert!(out.contains("header_up X-Forwarded-Proto {scheme}"), "应透传 Proto：{out}");
    }

    #[test]
    fn caddy_php_normalizes_unix_socket_and_host_port() {
        // 纯函数：nginx `unix:/x` → caddy `unix//x`（双斜杠）；host:port 原样
        assert_eq!(caddy_fpm_upstream("unix:/run/php/php8.2-fpm.sock"), "unix//run/php/php8.2-fpm.sock");
        assert_eq!(caddy_fpm_upstream("127.0.0.1:9000"), "127.0.0.1:9000");
        let mut s = spec_static();
        s.kind = SiteKind::Php { fpm: "unix:/run/php/php8.2-fpm.sock".into() };
        let out = render_caddy(&s);
        assert!(out.contains("php_fastcgi unix//run/php/php8.2-fpm.sock"), "fpm 应归一化：{out}");
    }

    #[test]
    fn caddy_tls_site_uses_https_and_tls_directive() {
        let mut s = spec_static();
        s.tls_cert = Some(PathBuf::from("/etc/panel/tls/example.crt"));
        s.tls_key = Some(PathBuf::from("/etc/panel/tls/example.key"));
        let out = render_caddy(&s);
        assert!(out.contains("https://example.com, https://www.example.com {"), "有证书应 https（多域名）：{out}");
        assert!(out.contains("tls /etc/panel/tls/example.crt /etc/panel/tls/example.key"), "应 tls 指令：{out}");
    }

    #[test]
    fn caddy_force_https_with_tls_adds_http_redirect_block() {
        let mut s = spec_static();
        s.tls_cert = Some(PathBuf::from("/etc/panel/tls/example.crt"));
        s.tls_key = Some(PathBuf::from("/etc/panel/tls/example.key"));
        s.force_https = true;
        let out = render_caddy(&s);
        // 手动 tls 不会自动重定向，须显式 http 块 301 → https；{host} 占位符覆盖多域名
        assert!(out.contains("http://example.com, http://www.example.com {"), "应有独立 http 重定向块（覆盖全部域名）：{out}");
        assert!(out.contains("redir https://{host}{uri} permanent"), "应 301 跳 https：{out}");
    }

    #[test]
    fn caddy_www_redirect_to_www_emits_block_and_excludes_source() {
        let mut s = spec_static();
        s.www_redirect = Some("to_www".into());
        let out = render_caddy(&s);
        // 来源域 example.com 进跳转块、不进主块（两块争主机会让 caddy 报警）
        assert!(out.contains("http://example.com {\n\tredir {scheme}://www.example.com{uri} permanent"), "裸域→www 跳转块：{out}");
        assert!(out.contains("http://www.example.com {"), "主块只含 www 域：{out}");
    }

    #[test]
    fn caddy_www_redirect_to_bare_emits_block_and_excludes_source() {
        // spec_static 的 names 含 www.example.com；to_bare：www → 裸域
        let mut s = spec_static();
        s.www_redirect = Some("to_bare".into());
        let out = render_caddy(&s);
        assert!(out.contains("http://www.example.com {\n\tredir {scheme}://example.com{uri} permanent"), "www→裸域跳转块：{out}");
        assert!(out.contains("http://example.com {"), "主块只含裸域：{out}");
    }

    #[test]
    fn caddy_tls_protocols_and_hsts_on_tls_site() {
        let mut s = spec_static();
        s.tls_cert = Some(PathBuf::from("/etc/panel/tls/example.crt"));
        s.tls_key = Some(PathBuf::from("/etc/panel/tls/example.key"));
        s.tls_min = Some("TLSv1.2".into());
        s.hsts = true;
        s.hsts_max_age = 31536000;
        s.hsts_include_sub = true;
        let out = render_caddy(&s);
        assert!(out.contains("tls /etc/panel/tls/example.crt /etc/panel/tls/example.key {"), "tls 块：{out}");
        assert!(out.contains("protocols tls1.2 tls1.3"), "TLS 下限→protocols：{out}");
        assert!(out.contains("header Strict-Transport-Security \"max-age=31536000; includeSubDomains\""), "HSTS：{out}");
    }

    #[test]
    fn caddy_tls_min_v13_maps_to_tls13_only() {
        assert_eq!(caddy_tls_protocols(Some("TLSv1.3")), "tls1.3");
        // caddy v2 最低 tls1.2：更低下限如实回落
        assert_eq!(caddy_tls_protocols(Some("TLSv1.1")), "tls1.2 tls1.3");
        assert_eq!(caddy_tls_protocols(None), "tls1.2 tls1.3");
    }

    #[test]
    fn caddy_ip_whitelist_and_blacklist_use_matchers() {
        let mut s = spec_static();
        s.ip_allow = Some(vec!["10.0.0.0/8".into(), "192.168.1.5".into()]);
        let out = render_caddy(&s);
        assert!(out.contains("@panel_example_com_blocked not remote_ip 10.0.0.0/8 192.168.1.5"), "白名单 matcher：{out}");
        assert!(out.contains("respond @panel_example_com_blocked 403"), "名单外 403：{out}");
        // 白名单模式忽略 ip_deny（同 nginx：二者互斥、白名单优先）
        s.ip_deny = Some(vec!["1.2.3.4".into()]);
        assert!(!render_caddy(&s).contains("_denied"), "白名单优先时黑名单应被忽略");

        let mut d = spec_static();
        d.ip_deny = Some(vec!["1.2.3.4".into()]);
        let out2 = render_caddy(&d);
        assert!(out2.contains("@panel_example_com_denied remote_ip 1.2.3.4"), "黑名单 matcher：{out2}");
        assert!(out2.contains("respond @panel_example_com_denied 403"), "黑名单 403：{out2}");
    }

    #[test]
    fn caddy_multi_domain_lists_all_names_in_site_address() {
        // 无 www 跳转时两个域名都进主块地址列表（逗号分隔）
        let out = render_caddy(&spec_static());
        assert!(out.contains("http://example.com, http://www.example.com {"), "多域名逗号列表：{out}");
    }

    // ── caddy WAF（规则集与 nginx 同源；expression 语法另经真机 caddy validate 验证）──

    #[test]
    fn caddy_waf_basic_emits_matchers_and_403() {
        let out = render_caddy(&spec_waf(WafProfile::Basic, None, 0));
        assert!(out.contains("header_regexp User-Agent `sqlmap|nikto|"), "UA 规则与 nginx 同源：{out}");
        assert!(out.contains("_waf_sqli expression"), "SQLi matcher：{out}");
        assert!(out.contains("_waf_xss expression"), "XSS matcher：{out}");
        assert!(out.contains("_waf_trav expression"), "路径穿越 matcher：{out}");
        assert!(out.contains("respond @panel_example_com_waf_ua 403"), "命中即 403：{out}");
        // 基础档不出方法白名单 / 空 UA 规则
        assert!(!out.contains("_waf_method"), "基础档不应有方法白名单：{out}");
        assert!(!out.contains("_waf_noua"), "基础档不应有空 UA 规则：{out}");
    }

    #[test]
    fn caddy_waf_strict_adds_method_whitelist_and_empty_ua() {
        let out = render_caddy(&spec_waf(WafProfile::Strict, None, 0));
        assert!(out.contains("not method GET HEAD POST PUT DELETE PATCH OPTIONS"), "严格档方法白名单：{out}");
        assert!(out.contains("respond @panel_example_com_waf_method 405"), "非白名单方法 405：{out}");
        assert!(out.contains("header User-Agent \"\""), "空 UA matcher：{out}");
        assert!(out.contains("nmap|zaproxy"), "严格档 UA 应含附加备选：{out}");
    }

    #[test]
    fn caddy_waf_rate_limit_is_honestly_noted_not_silently_dropped() {
        let out = render_caddy(&spec_waf(WafProfile::Basic, Some(10), 20));
        assert!(out.contains("限速未实装"), "限速不支持必须显式说明：{out}");
        // 注释里会出现 rate_limit 这个词（说明缺的是什么），但不得出现**指令调用**。
        assert!(!out.contains("rate_limit {") && !out.contains("rate_limit{"), "标准 caddy 无 rate_limit 指令，不得输出指令调用：{out}");
    }

    /// **前端置灰 ↔ 后端未实装 的一致性守卫**。
    ///
    /// 前端 `useSiteCaps.isCaddy` 把一批字段置灰（Basic Auth / 伪静态 / lb_policy /
    /// 反代超时 / 站点日志 / custom_conf / tls_profile），理由写的是「caddy 下未实装、
    /// 填了也不会写进配置」。这条断言把**这句话钉死**：把这些字段全填上，caddy 渲染
    /// 里仍不得出现对应指令。
    ///
    /// 为什么值得一条测试：置灰是**前端单方面的承诺**，后端没有任何东西阻止某人明天
    /// 就给 caddy 加上 `basicauth`——那时前端仍置灰，用户白白用不上一个已经能用的
    /// 功能，而编译、类型、所有其它测试全绿。反之若后端悄悄丢了某项而前端没置灰，
    /// 用户点了会静默失效。两侧各改一处都会在这里变红。
    ///
    /// ⚠ 若将来真为 caddy 实装了其中某项：**同步改前端置灰与本条断言**，三者一起动。
    #[test]
    fn caddy_render_emits_none_of_the_fields_frontend_greys_out() {
        let mut s = spec_static();
        // 全部按「用户填满了」构造——置灰的承诺就是「填了也不生效」
        s.auth_basic = true;
        s.auth_user = Some("alice".into());
        s.auth_file = Some(PathBuf::from("/etc/panel/htpasswd/x"));
        s.rewrite_preset = Some("wordpress".into());
        s.rewrite_custom = Some("try_files $uri $uri/ /index.php?$args;".into());
        s.lb_policy = Some("least_conn".into());
        s.proxy_connect_timeout = 5;
        s.proxy_send_timeout = 5;
        s.proxy_read_timeout = 5;
        s.access_log = Some(PathBuf::from("/var/log/panel/x.access.log"));
        s.error_log = Some(PathBuf::from("/var/log/panel/x.error.log"));
        s.error_log_level = Some("warn".into());
        s.tls_profile = Some("strict".into());
        s.custom_conf = Some("location /static/ { expires 7d; }".into());
        let out = render_caddy(&s);
        // ⚠ 必须**剔除头部注释行**再比对：那两行「已覆盖/未覆盖」清单里本身就写着
        // `lb_policy`、`custom_conf` 等字样（它们就是用来说明缺什么的）。拿整串去
        // contains 会恒命中、断言变恒绿——先把 `#` 开头的行去掉。
        let body: String = out.lines().filter(|l| !l.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n");
        for directive in [
            "basicauth",          // Basic Auth
            "auth_basic",
            "lb_policy",          // 负载均衡策略
            "proxy_connect_timeout",
            "proxy_send_timeout",
            "proxy_read_timeout",
            "access_log",         // 站点独立日志
            "error_log",
            "log {",              // caddy 的 log 指令块
            "\nlog ",
            "expires 7d",         // custom_conf 原义（nginx 语法）
            "location /static/",
            // ── 下面三项上面已「填满」，但旧断言列表漏了——属于「注释声称钉死了、实际没钉」
            // 的恒绿缺口。caddy 渲染根本不读这些字段（见 webserver.rs 头部诚实清单），故填入的
            // 哨兵值绝不应泄漏进 Caddyfile；一旦将来有人给 caddy 接上 伪静态 / tls_profile，
            // 这里会变红提醒「前端仍置灰」的失同步。
            "wordpress",         // rewrite_preset 哨兵（caddy 不读 rewrite_preset）
            "/index.php",        // rewrite_custom 的 PHP 路由哨兵（caddy 不读 rewrite_custom；
                                 // 注意 SPA 块只产 /index.html，不会误伤）
            "strict",            // tls_profile 档位哨兵（caddy 不开放套件配置，tls_protocols 恒回落）
        ] {
            assert!(!body.contains(directive), "caddy 渲染不应产出 `{directive}`（前端据此置灰）：\n{body}");
        }
        // 反向：承诺「已实装」的项必须真的在，否则前端不置灰就是撒谎
        assert!(body.contains("file_server"), "静态站点基础形态必须仍在：{body}");
    }

    #[test]
    fn caddy_cel_regex_translates_posix_class_and_escapes_for_cel() {
        let got = caddy_cel_regex("union[[:space:]]+select");
        assert!(!got.contains("[[:space:]]"), "POSIX 类应被翻译掉：{got:?}");
        // \s 经 CEL 双写后是两个反斜杠 + s（CEL 字符串里 \\ 才解析出一个反斜杠）。
        // 注意 [[:space:]] 自带方括号，替换后不再有 []——输出 union\\s+select。
        assert_eq!(got.matches('\\').count(), 2, "反斜杠应双写：{got:?}");
        assert!(got.starts_with("union"), "前缀不动：{got:?}");
        assert!(got.ends_with("+select"), "后缀不动：{got:?}");
        // RE2 原生字符类原样保留
        assert_eq!(caddy_cel_regex("a[.]b[(]c"), "a[.]b[(]c");
        assert_eq!(caddy_cel_regex("plain"), "plain");
        // 嵌入形态：POSIX 类主体替换后仍是合法 RE2 字符类（真机 caddy validate 抓过的 bug）
        let embedded = caddy_cel_regex("union[[:space:](/*]+select");
        assert!(!embedded.contains("[:space:]"), "嵌入 POSIX 类也应被翻译：{embedded:?}");
        assert!(embedded.contains("(/*"), "类内其余字符不动：{embedded:?}");
    }

    /// 真机验证：渲染的 WAF Caddyfile 必须过 `caddy validate`。
    /// **expression matcher 的 CEL 语法只能靠真机证伪**——字符串单测看不出 caddy 认不认。
    /// 二进制缺失（CI）时跳过而非失败，与 nginx 的 `validate_roundtrip_when_nginx_present`
    /// 同模式；本地验证设 `CADDY_BIN=/path/to/caddy`。
    #[tokio::test]
    async fn caddy_waf_rendered_config_passes_real_caddy_validate() {
        let bin = std::env::var("CADDY_BIN").ok().filter(|s| !s.is_empty())
            .or_else(|| which("caddy").then(|| "caddy".to_string()));
        let Some(bin) = bin else {
            // ⚠ 静默跳过 = 假绿：这条守卫在没装 caddy 的机器上其实什么都没验。
            // 必须把"没验"喊出来，否则 CI 一片全绿里藏着一条从未跑过的断言。
            eprintln!("[skip] caddy_waf_rendered_config_passes_real_caddy_validate：无 caddy 二进制（设 CADDY_BIN= 或跑 ci/fetch-caddy.sh）");
            return;
        };
        for profile in [WafProfile::Basic, WafProfile::Strict] {
            let rendered = render_caddy(&spec_waf(profile, None, 0));
            let dir = std::env::temp_dir().join(format!("panel-caddy-waf-{}-{:?}", std::process::id(), profile));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let file = dir.join("Caddyfile");
            std::fs::write(&file, &rendered).unwrap();
            let out = std::process::Command::new(&bin)
                .args(["validate", "--adapter", "caddyfile", "--config"])
                .arg(&file)
                .output()
                .expect("spawn caddy validate");
            let _ = std::fs::remove_dir_all(&dir);
            assert!(
                out.status.success(),
                "caddy validate 拒绝 WAF 配置（{profile:?}）：\n{}\n--- rendered ---\n{rendered}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn caddy_routed_renders_handle_blocks_and_fallback() {
        let out = render_caddy(&spec_routed());
        assert!(out.contains("handle /api* {"), "反代路由应 handle：{out}");
        assert!(out.contains("reverse_proxy http://127.0.0.1:3000"), "handle 内反代：{out}");
        assert!(out.contains("handle {"), "兜底路由应无参 handle：{out}");
    }

    #[test]
    fn caddy_redirect_emits_redir_with_uri() {
        let mut s = spec_static();
        s.kind = SiteKind::Redirect { target: "https://target.com".into(), code: 301 };
        let out = render_caddy(&s);
        assert!(out.contains("redir https://target.com{uri} 301"), "整站重定向：{out}");
    }

    #[test]
    fn caddy_sites_dir_and_main_conf_are_caddy_paths() {
        assert_eq!(caddy_sites_dir(), PathBuf::from("/etc/caddy/sites"));
        assert_eq!(caddy_main_conf(), PathBuf::from("/etc/caddy/Caddyfile"));
    }

    #[test]
    fn caddy_provider_render_and_conf_path_use_caddy_layout() {
        // provider 层：caddy 的 render 走 render_caddy，conf_path 落 sites/*.caddy
        let (path, content) = caddy_server().render(&spec_static()).unwrap();
        assert!(path.to_string_lossy().ends_with("panel-example.com.caddy"), "conf_path 应落 caddy 片段：{path:?}");
        assert!(content.contains("http://example.com, http://www.example.com {"), "render 应产出 Caddyfile（多域名）：{content}");
    }

    #[test]
    fn caddy_provider_render_rejects_when_no_webserver() {
        let ws = LinuxWebServer { name: None, paths: Arc::new(LinuxPathLayout::default()) };
        assert!(matches!(ws.render(&spec_static()), Err(PanelError::Unsupported(_))));
    }

    #[tokio::test]
    async fn deploy_writes_target_without_leaving_tmp() {
        let dir = std::env::temp_dir().join(format!("panel-deploy-test-{}", uniq_counter()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("panel-x.conf");
        nginx_server().deploy(&target, "server {}\n").await.unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "server {}\n");
        let leftovers: Vec<String> = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "残留临时文件: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// provider 真机校验用的 provider 实例。**关键：data_dir 必须指向可写目录。**
    ///
    /// `validate()` 会在 `paths.tmp_dir()` 下建临时目录跑 `nginx -t` / `caddy validate`，
    /// 而 `LinuxPathLayout::default()` 的 data_dir 是 `/var/lib/panel`——**root 755**，
    /// 非 root 跑测试会在 `create_dir_all` 这一步就 `Permission denied (os error 13)`。
    /// 此前这两个真机测试在本沙箱/CI 恒红，一直被误读成"`nginx -t` 需要 root"；
    /// 实测根因是 tmp 目录不可写（wrapper 本身已把 pid / error_log / 五个 temp 路径
    /// 全部收进临时 prefix，语法校验并不需要 root）。故覆写 data_dir 到系统临时目录，
    /// 让校验只依赖"二进制在不在"。
    fn server_with_tmp_data(name: &'static str) -> LinuxWebServer {
        let dir = std::env::temp_dir().join(format!("panel-wsval-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = LinuxPathLayout::default().with_overrides(None, None, Some(dir), None);
        LinuxWebServer { name: Some(name), paths: Arc::new(paths) }
    }

    /// 需真机 nginx 的端到端校验：二进制缺失（CI）时跳过而非失败。
    #[tokio::test]
    async fn validate_roundtrip_when_nginx_present() {
        if !which("nginx") { return; }
        let srv = server_with_tmp_data("nginx");
        let ok = srv.validate(&render_nginx(&spec_static())).await;
        if let Err(e) = &ok {
            let msg = format!("{e:?}");
            // ⚠ `nginx -t` **会真的 bind 监听端口**（不是只解析语法），且早期就要打开
            // 编译期默认的 `/var/log/nginx/error.log`。非 root 必得 `Permission denied`
            // ——那是环境限制不是代码缺陷；跳过而非恒红（恒红的守卫比没守卫更危险）。
            // 实测输出：先 "syntax is ok"，随后 "bind() to 0.0.0.0:80 failed (13: Permission denied)"。
            if msg.contains("Permission denied") && (msg.contains("bind()") || msg.contains("error log file")) {
                eprintln!("[skip] validate_roundtrip_when_nginx_present：nginx -t 需 root（{msg}）");
                return;
            }
            panic!("合法 server 块应通过 nginx -t: {e:?}");
        }
        let bad = srv.validate("server { listen ; }").await;
        assert!(bad.is_err(), "非法配置应被 validate 拒绝");
    }

    /// caddy 分支的 **provider 层**真机校验——此前只验了 `render_caddy` 纯函数，
    /// `validate()` 真正 fork `caddy validate --adapter caddyfile` 这条链路没跑过。
    /// 二进制缺失（CI）时跳过，与 nginx 同模式。
    #[tokio::test]
    async fn caddy_validate_roundtrip_when_caddy_present() {
        if !crate::cmd::Bin::Caddy.available() {
            eprintln!("[skip] caddy_validate_roundtrip_when_caddy_present：无 caddy 二进制（设 CADDY_BIN= 或跑 ci/fetch-caddy.sh）");
            return;
        }
        let srv = server_with_tmp_data("caddy");
        let ok = srv.validate(&render_caddy(&spec_static())).await;
        assert!(ok.is_ok(), "合法 caddy 站点块应通过 caddy validate: {ok:?}");
        let bad = srv.validate("http://example.com {{\n").await;
        assert!(bad.is_err(), "未闭合的站点块应被 caddy validate 拒绝");
    }

    /// deploy → reload → remove 的 provider 真机闭环。**需 root 且环境已备**：
    /// ① `/etc/caddy/Caddyfile` 存在（含 `import /etc/caddy/sites/*`）
    /// ② 已有 caddy 在跑（admin 端点可达，`reload` 才会成功）
    /// ③ 显式 `PANEL_CADDY_E2E=1`
    /// 三者缺一即跳过——"环境不具备"绝不能伪装成代码缺陷（恒红的守卫比没守卫更危险）。
    #[tokio::test]
    async fn caddy_deploy_reload_remove_roundtrip_when_env_prepared() {
        if std::env::var("PANEL_CADDY_E2E").as_deref() != Ok("1") { return; }
        if !crate::cmd::Bin::Caddy.available() { return; }
        if !std::path::Path::new("/etc/caddy/Caddyfile").exists() { return; }
        let srv = server_with_tmp_data("caddy");
        // ⚠ 端口必须避开 80/443：真机上 nginx 常已占着（本机实测就是），此处只验
        // 「面板下发的片段能被主配置 import 且 reload 生效」，不抢生产端口。
        let mut spec = spec_static();
        spec.server_names = vec!["127.0.0.1:8080".into()];
        let (path, content) = srv.render(&spec).expect("render 应产出路径与内容");
        srv.validate(&content).await.expect("渲染出的配置应通过 caddy validate");
        srv.deploy(&path, &content).await.expect("deploy 应写入 /etc/caddy/sites");
        assert!(path.exists(), "deploy 后片段应在磁盘上：{path:?}");
        srv.reload().await.expect("reload 应对主 Caddyfile 生效");
        srv.remove(&path).await.expect("remove 应删除片段");
        assert!(!path.exists(), "remove 后片段不应残留：{path:?}");
    }

    // ── 数据库备份/恢复：sqlite roundtrip + mysql/pg 客户端缺失诚实 501 ──
    #[tokio::test]
    async fn sqlite_backup_and_restore_roundtrip() {
        use panel_core::SafePath;
        let dir = std::env::temp_dir().join(format!("fp_dbtest_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("app.db");
        {
            let c = rusqlite::Connection::open(&src).unwrap();
            c.execute("CREATE TABLE t(x INTEGER)", []).unwrap();
            c.execute("INSERT INTO t VALUES (42)", []).unwrap();
        }
        let bak = dir.join("app.backup.db");
        let target = DbTarget {
            engine: DbEngine::Sqlite,
            host: None, port: None, user: None, password: None,
            database: Some(src.to_string_lossy().into()),
        };
        let prov: &dyn DatabaseProvider = &LinuxDatabases::default();
        prov
            .backup(&target, unsafe { &SafePath::from_raw(bak.clone()) }, Box::new(|_| {}))
            .await
            .unwrap();
        assert!(bak.is_file(), "备份文件应生成");
        // 篡改源库，再从备份恢复
        {
            let c = rusqlite::Connection::open(&src).unwrap();
            c.execute("UPDATE t SET x = 999", []).unwrap();
        }
        prov
            .restore(&target, unsafe { &SafePath::from_raw(bak.clone()) })
            .await
            .unwrap();
        let v: i64 = rusqlite::Connection::open(&src).unwrap()
            .query_row("SELECT x FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 42, "恢复后应回到备份时的 42");
        // 还原应留覆盖前快照（自愈网）
        let snap = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("app.db.bak-"));
        assert!(snap, "还原应生成 .bak 快照");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mysql_backup_unsupported_when_client_missing() {
        // 沙箱无 mysqldump：诚实 Unsupported（前端据此置灰），而非假装成功
        if crate::cmd::Bin::MySqlDump.available() { return; }
        let target = DbTarget {
            engine: DbEngine::MySql,
            host: Some("127.0.0.1".into()), port: Some(3306),
            user: Some("u".into()), password: Some("p".into()), database: Some("db".into()),
        };
        let prov: &dyn DatabaseProvider = &LinuxDatabases::default();
        let r = prov.backup(&target, unsafe { &SafePath::from_raw(std::env::temp_dir().join("x.sql")) }, Box::new(|_| {}))
            .await;
        assert!(matches!(r, Err(panel_core::PanelError::Unsupported(_))), "缺失客户端应 Unsupported: {r:?}");
    }
    #[test]
    fn version_major_jump_detects_cross_major_and_ignores_minor() {
        // 跨主版本：PostgreSQL 17→18、Node.js 20→24
        assert!(version_major_jump("17+278", "18+293.pgdg13+1"), "PG 17→18 应判跨主版本");
        assert!(version_major_jump("20.19.0", "24.21.0"), "Node 20→24 应判跨主版本");
        // 仅次/修订版本：Redis 8.0.2→8.10.2、Nginx 1.26→1.30、Node 18.19→18.20
        assert!(!version_major_jump("5:8.0.2", "5:8.10.2"), "Redis 8.0.2→8.10.2 仅次版本");
        assert!(!version_major_jump("1.26.3-3+deb13u9", "1.30.5-1"), "Nginx 1.26→1.30 仅次版本");
        assert!(!version_major_jump("18.19.0", "18.20.0"), "Node 18→18 仅修订");
        // 带 epoch 仍正确剥除：redis 5:8.x 同主版本
        assert!(!version_major_jump("5:8.0.2", "5:8.1.0"));
    }

    #[test]
    fn version_major_jump_handles_unparseable_gracefully() {
        // 解析不出主版本号时保守返回 false（不当作跨主版本，避免误阻断常规升级）
        assert!(!version_major_jump("nightly", "1.0.0"));
        assert!(!version_major_jump("1.0.0", ""));
        assert!(!version_major_jump("", ""));
    }

    #[test]
    fn split_apt_policy_blocks_reads_real_multi_package_output() {
        // 本机实测：`LC_ALL=C apt-cache policy nginx redis-server` 的真实形态
        let out = r"nginx:
  Installed: (none)
  Candidate: 1.30.5-1~trixie
  Version table:
     1.30.5-1~trixie 500
        500 https://nginx.org/packages/debian trixie/nginx amd64 Packages
     1.26.3-3+deb13u9 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
redis-server:
  Installed: 6:8.10.2-1rl1~trixie1
  Candidate: 6:8.10.2-1rl1~trixie1
  Version table:
 *** 6:8.10.2-1rl1~trixie1 500
        500 https://packages.redis.io/deb trixie/main amd64 Packages
";
        let blocks = split_apt_policy_blocks(out);
        assert_eq!(blocks.len(), 2, "应切出两个包块：{blocks:?}");
        assert_eq!(blocks[0].0, "nginx");
        assert_eq!(blocks[1].0, "redis-server");
        // 每块正文喂给既有解析器，结果必须与单包查询一致（含 "*** " 已安装标记）
        assert_eq!(parse_apt_policy_installed(&blocks[0].1), None);
        assert_eq!(
            parse_apt_policy_versions(&blocks[0].1),
            vec!["1.30.5-1~trixie".to_string(), "1.26.3-3+deb13u9".to_string()]
        );
        assert_eq!(
            parse_apt_policy_installed(&blocks[1].1),
            Some("6:8.10.2-1rl1~trixie1".to_string())
        );
        assert_eq!(
            parse_apt_policy_versions(&blocks[1].1),
            vec!["6:8.10.2-1rl1~trixie1".to_string()]
        );
    }

    #[test]
    fn split_apt_policy_blocks_ignores_apt_error_lines() {
        // apt 把"找不到的包"写在 col 0，且以包名（而非 ':'）结尾 → 绝不能被当成块头
        let out = "N: Unable to locate package nosuchpkg\nnginx:\n  Installed: (none)\n";
        let blocks = split_apt_policy_blocks(out);
        assert_eq!(blocks.len(), 1, "错误行不该产生块：{blocks:?}");
        assert_eq!(blocks[0].0, "nginx");
    }

    /// 真实复现（2026-10-08 受控 apt 沙箱实测，逐字取自 `LC_ALL=C apt-cache policy demo-pkg`）：
    /// apt preferences 把包钉在**已安装版本**后，`Candidate` 被压低到 1.0，`apt list --upgradable`
    /// 对该包**沉默**；但版本表里仍有更高版 2.0。旧口径（Candidate）会永远漏报这种更新，
    /// 新口径必须据版本表报出「1.0 → 2.0」——这正是用户报告的「官方源有新版却总说已是最新」。
    #[test]
    fn pinned_candidate_below_installed_still_reports_update() {
        let out = r"demo-pkg:
  Installed: 1.0
  Candidate: 1.0
  Version table:
     2.0 500
        500 file:/tmp/apt-e2e/repo ./ Packages
 *** 1.0 1001
        500 file:/tmp/apt-e2e/repo ./ Packages
        100 /tmp/apt-e2e/var/lib/dpkg/status
";
        let blocks = split_apt_policy_blocks(out);
        assert_eq!(blocks.len(), 1);
        let body = &blocks[0].1;
        // 前置事实：真实输出确如所料——Installed = Candidate = 1.0（apt 自认无可升级），
        // 但版本表最高仍是 2.0。
        assert_eq!(parse_apt_policy_installed(body), Some("1.0".to_string()));
        let versions = parse_apt_policy_versions(body);
        assert_eq!(versions, vec!["2.0".to_string(), "1.0".to_string()]);
        // 新口径：取版本表最高版与已装版本比较 → 必须报出更新。
        assert_eq!(
            crate::traits::upgradable_pair(Some("1.0"), &versions),
            Some(("1.0".to_string(), "2.0".to_string())),
            "Candidate 被 pin 压低时仍应据版本表报出更新（旧口径漏报的场景）"
        );
    }
