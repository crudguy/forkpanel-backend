//! 软件包域（安装 / 升级 / 卸载 / 版本查询 / 白名单目录）。
//!
//! 从 `services.rs` 拆出：服务管理与软件包管理是两个域，共用同一个文件会让
//! "改服务动作"被迫审阅整份包白名单，也让权限/校验口径容易互相抄错。
//! 路由层通过 `pub(crate) use packages::*;` 继续用 `services::package_*` 的旧路径调用
//! ——调用点零改动（`routes.rs` 里 12 条 `.route(...)` 不需改）。

use super::*;
use crate::extract::PanelJson;

// ─────────────── 软件包（走任务队列） ───────────────

#[derive(Debug, Deserialize)]
pub struct InstallReq {
    pub name: String,
    pub version: Option<String>,
    /// 跨主版本升级的二次确认标记。仅 `package_upgrade` 使用：检测到跨主版本
    /// （如 PostgreSQL 17→18、Node.js 20→24）且为 false 时，升级接口返回 409
    /// 强制前端弹窗确认——不能只靠前端拦截（直接调 API 即可绕过警告）。
    /// `package.install` 忽略此字段（全新安装无"当前版本"可比，不触发跨主版本判定）。
    pub confirm_major: Option<bool>,
}

/// 版本号字符白名单：用户可控输入。后端以数组传参交给包管理器（不走 shell，无命令注入
/// 风险），但奇字符会让 apt/dnf 直接报错、用户困惑。只允许版本号里合法出现的字符集。
/// 抽成独立函数便于单测——内联在 handler 里的校验无法被测试覆盖（已踩过 any/静默吞错的坑）。
pub(crate) fn validate_pkg_version(v: &str) -> ApiResult<()> {
    if v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '~' | ':' | '-')) {
        Ok(())
    } else {
        Err(ApiError::bad_request("version", "版本号只能包含字母、数字及 + . ~ : - 字符"))
    }
}

/// 已支持的软件包白名单。
///
/// 为什么白名单而不是任意包名：面板以 root 运行，允许安装任意包等于
/// 给了 Web 界面一个"任意代码执行"入口。白名单把风险收敛到已知集合。
/// 白名单条目：`name` 是对外逻辑名（UI 展示、install/remove 入参、幂等键、审计都用它），
/// `label` 是给人看的品牌名——刻意不带版本后缀，避免把主版本焊死在展示上
/// （例如 `apache2` 的 "2" 只是 Debian 给 Apache 2.x 打的包名后缀，真出 Apache 3 就尴尬了）。
///
/// 后六个字段（summary/features/scenes/entry/howto/units）是**面向用户的说明**
/// 及其实例锚点，随 `/packages`
/// 的 `catalog` 一起下发，供前端软件卡片上的「说明」渲染。放在后端是为了守住
/// 「包集合 + 包的说明只有一个事实源」：前端若另维护一份 22 条文案表，后端加包
/// 或改能力（例如某软件的入口页被下线）时前端不会有任何编译错误，只会静默说谎。
///
/// `pub(crate)`：`pkg_help` 模块只做投影（不改写文案），需要能看见这个结构。
pub(crate) struct PkgDef {
    /// 对外逻辑名（UI 展示、install/remove 入参、幂等键、审计都用它）
    pub name: &'static str,
    /// 给人看的品牌名
    pub label: &'static str,
    /// 用途：一句话说清"这东西是什么"
    pub summary: &'static str,
    /// 主要功能：用户真的会用的能力
    pub features: &'static str,
    /// 适用场景：什么时候该装它（帮用户做决策）
    pub scenes: &'static str,
    /// 使用方式 / 访问入口：面板内入口 + 面板外的真实访问方式。
    /// **必须诚实**——面板没有的入口不许编，写「面板无独立页面」并给出真实路径。
    pub entry: &'static str,
    /// 怎么配：到了 `entry` 说的那个页面之后**具体填什么**（必填项 / 典型值 / 常见错法）。
    ///
    /// 为什么与 `entry` 分开而不是塞进同一段：`entry` 回答「去哪」，`howto` 回答
    /// 「填什么」。合成一段后用户在弹窗里读到的是四五句话的连续文本，找不到自己
    /// 卡住的那一步。分开后前端能分两行展示，扫一眼就知道该抄哪个值。
    ///
    /// 纪律：这里写的每个字段名与格式**必须能在前端表单里找到对应物**（只读调研过，
    /// 不是凭想象写）。面板没有的配置步骤不许编——与 `entry` 同一条诚实边界。
    /// 面板内纯自动的包（无表单可填）写清「无需填任何东西」，不要留空。
    pub howto: &'static str,
    /// 该包在 systemd 上的服务单元名（`dpkg -L` 实证所得，非按包名推导）。
    ///
    /// 为什么要单独一个字段、为什么不能在前端按包名拼：
    /// 包名与单元名**不是同一个字符串**，而且差异没有规律。实测：
    /// `mariadb-server` → `mariadb.service`、`grafana` → `grafana-server.service`、
    /// `redis`（Debian 包名 redis-server）→ `redis-server.service`、
    /// `php-fpm` → `php8.4-fpm.service`（元包本身没有单元，单元由它 Depends 的
    /// 具体版本包提供，版本号随发行版变）。前端若写 `name + '.service'` 去猜，
    /// 这四条**全部匹配失败**，表现为「服务详情页查不到软件说明」——静默、无报错。
    ///
    /// 用途：服务详情页用当前单元名在 catalog 里反查条目，**在本页**直接展开
    /// 用途/功能/场景/怎么配，而不是把用户送去「软件」页再点一次 `?`。
    ///
    /// 空数组表示「该包没有常驻服务单元」（应用运行时、纯工具链、元包），
    /// 前端据此不渲染软件说明区——与 `entry` 写「面板无独立页面」同一条诚实边界：
    /// 宁可没有，也不给一个反查永远落空的入口。
    pub units: &'static [&'static str],
}

pub(crate) const ALLOWED_PACKAGES: &[PkgDef] = &[
    PkgDef {
        name: "nginx", label: "Nginx",
        summary: "高性能 HTTP 服务器与反向代理。",
        features: "静态站点、反向代理与负载均衡、TLS、伪静态、WAF、访问日志。",
        scenes: "搭建网站、把 Node / PHP 应用挂到 80 / 443、单机托管多个站点。",
        entry: "「网站」页建站与改站点；「证书」菜单配 TLS；「WAF」菜单配防护规则；「服务」页看状态与日志。",
        howto: "「网站」页→新建站点：名称（小写字母/数字/连字符，如 my-site）与域名（逗号分隔，须已解析到本机）必填；根目录留空即用站点名。填完点「保存并应用」——保存即下发，站点立刻对外服务。HTTPS 要到「证书」页选中该站点签发，证书才会被写进配置。",
        units: &["nginx.service"],
    },
    PkgDef {
        name: "caddy", label: "Caddy",
        summary: "自带自动 HTTPS 的现代 Web 服务器。",
        features: "静态站 / 反向代理 / PHP / 多路由、自动或手动 TLS、HSTS、IP 名单、WAF（规则集）。",
        scenes: "想省掉证书申请与续期、托管轻量站点。nginx 独有的能力（Basic Auth、伪静态、TLS 套件档、WAF 限速等）在 Caddy 下不可用，界面会置灰。",
        entry: "「网站」页（探测到 Caddy 时按 Caddyfile 渲染）；「证书」菜单；「服务」页。",
        howto: "「网站」页→新建站点，字段与 nginx 完全一致（面板自动按 Caddyfile 渲染，不用手写语法）。注意 Caddy 下部分能力置灰：限速、自定义片段、加密套件档位、Basic Auth 不支持。",
        units: &["caddy.service", "caddy-api.service"],
    },
    PkgDef {
        name: "apache2", label: "Apache",
        summary: "传统 Web 服务器（虚拟主机 / .htaccess）。",
        features: "静态站点、PHP、虚拟主机、.htaccess 覆盖配置。",
        scenes: "兼容迁移过来的既有 Apache 项目。",
        entry: "面板的站点托管目前只渲染 nginx / caddy：Apache 装好后需自行维护配置。「服务」页仍可启停、看日志、改单元配置。",
        howto: "面板不代写 Apache 配置：建站请首选 nginx / caddy。若必须用 Apache，装好后到「服务」页启停、看日志，配置文件（/etc/apache2/）请通过 SSH 编辑——面板按官方 systemd 单元部署时进程受 ProtectSystem=strict 约束，/etc 只读：文件页能看不能写，终端是面板子进程、同样写不进。",
        units: &["apache2.service"],
    },
    PkgDef {
        name: "mariadb-server", label: "MariaDB",
        summary: "MySQL 兼容的关系型数据库。",
        features: "建库建账号、SQL 查询、备份与还原。",
        scenes: "WordPress 等传统 PHP 应用、需要 MySQL 兼容性的存量项目。",
        entry: "「数据库」页新建连接（需本机 mysql 客户端）→ 备份 / 还原 / 浏览；「服务」页看状态。",
        howto: "「数据库」页「新增连接」：名称（随意，如 myapp）、引擎选 MySQL（MariaDB 走这个选项）、主机 127.0.0.1、端口 3306、用户名 root、口令、库名（如 myapp）。用户名必填，空着按钮点不动。只做备份与还原，不提供写库入口。",
        units: &["mariadb.service"],
    },
    PkgDef {
        name: "postgresql", label: "PostgreSQL",
        summary: "功能完整的关系型数据库。",
        features: "关系表、JSON / JSONB、扩展插件、备份与还原。",
        scenes: "新项目起步、需要复杂查询与严格事务语义。",
        entry: "「数据库」页新建连接（需本机 psql 客户端，账号必填）；「服务」页看状态。",
        howto: "「数据库」页「新增连接」：名称随意、引擎选 PostgreSQL、主机 127.0.0.1、端口 5432、用户名 postgres、口令、库名（如 myapp）。用户名必填。客户端装上只代表本机有 psql，不代表一定连得上目标库。",
        units: &["postgresql.service"],
    },
    PkgDef {
        name: "redis", label: "Redis",
        summary: "内存键值数据库，常用作缓存。",
        features: "缓存、会话存储、消息队列、分布式锁。",
        scenes: "加速读多写少的应用、跨进程共享状态。",
        entry: "面板无独立页面；应用连 127.0.0.1:6379（默认端口，以你的配置为准）；「服务」页看状态 / 日志 / 配置。",
        howto: "无需在面板里填连接：应用连 127.0.0.1:6379。要改端口/密码请通过 SSH 编辑 /etc/redis/redis.conf，改完到「服务」页重启 redis-server——面板按官方 systemd 单元部署时 /etc 只读（ProtectSystem=strict），文件页能看不能写，终端同理。",
        units: &["redis-server.service"],
    },
    PkgDef {
        name: "memcached", label: "Memcached",
        summary: "纯内存 KV 缓存，不做持久化。",
        features: "对象缓存（重启即清空）。",
        scenes: "减轻数据库读压力，可接受缓存丢失。",
        entry: "面板无独立页面；应用连 127.0.0.1:11211（默认端口）；「服务」页看状态与日志。",
        howto: "无需填连接：应用连 127.0.0.1:11211。要调内存上限请通过 SSH 编辑 /etc/memcached.conf 后到「服务」页重启（面板按官方 systemd 单元部署时 /etc 只读，文件页写不进）。",
        units: &["memcached.service"],
    },
    // 只保留元包 php-fpm：它 Depends 当前发行版的默认 phpX.Y-fpm，任何一代
    // Debian/Ubuntu 上都必然可装。此前写死 php8.1/8.2/8.3-fpm 是想覆盖多发行版，
    // 但 Debian 每代只提供 1 个 PHP 版本（13→8.4、12→8.2、11→7.4），实测本机
    // 三条全部"仓库无此包"——即任意一台机器上最多 1 条有效，其余点了必失败。
    PkgDef {
        name: "php-fpm", label: "PHP-FPM",
        summary: "PHP 的 FastCGI 进程管理器。",
        features: "执行 PHP 站点、按进程池隔离与调优。",
        scenes: "PHP 建站（WordPress、ThinkPHP 等）。",
        entry: "「网站」页新建站点时选 PHP 运行方式；「服务」页看 php-fpm 状态与日志。",
        howto: "「网站」页建站时类型选「PHP (php-fpm)」，php-fpm 一栏填 unix:/run/php/php8.2-fpm.sock（版本号按已装的改）或 127.0.0.1:9000。路径写错站点会 502，不会给出更明确的提示。",
        units: &["php8.4-fpm.service"],
    },
    PkgDef {
        name: "certbot", label: "Certbot",
        summary: "Let's Encrypt 的 ACME 证书客户端。",
        features: "签发免费证书、自动续期、通配符证书（DNS 验证）。",
        scenes: "公网站点启用 HTTPS。",
        entry: "「证书」页签发 / 续期（依赖 ssl.acme 能力位）；「网站」页给站点绑定证书。",
        howto: "「证书」页→申请：先选站点，方式选「ACME http-01」，再填邮箱（ACME 注册用，如 ops@example.com）。用户名的域名必须公网 80 端口可达，否则签不下来。仅内网用请选「面板自签」。",
        units: &["certbot.service", "certbot.timer"],
    },
    PkgDef {
        name: "fail2ban", label: "Fail2ban",
        summary: "日志驱动的防暴力破解工具。",
        features: "监控 SSH / 服务日志，按规则自动封禁来源 IP。",
        scenes: "公网 SSH 或面板登录防护。",
        entry: "「安全」菜单的防火墙规则页（fail2ban 区；nftables 后端下恒不支持）；「服务」页看状态。",
        howto: "面板不提供 fail2ban 的 jail 表单：/etc/fail2ban/ 整目录已列入敏感路径黑名单（其 action 规则会以 root 执行命令，文件页拒绝读写），规则请通过 SSH 编辑 /etc/fail2ban/jail.local 后 systemctl reload fail2ban。nftables 后端下该能力位恒不支持，别在面板里找开关。",
        units: &["fail2ban.service"],
    },
    PkgDef {
        name: "ufw", label: "UFW",
        summary: "简易防火墙命令行前端。",
        features: "按端口放行 / 拒绝、限流、按应用配置。",
        scenes: "基础主机防护，替代手写 iptables 规则。",
        entry: "「安全」菜单的防火墙规则页（后端按 nft / iptables / ufw / firewalld 实际探测适配）；「服务」页看状态。",
        howto: "「安全」菜单→防火墙规则：端口填 80,443 或区间 8000-8100，来源留空即 0.0.0.0/0（也可填 10.0.0.0/24），备注随便写便于日后辨认。只支持放行，不支持封禁。",
        units: &["ufw.service"],
    },
    PkgDef {
        name: "minio", label: "MinIO",
        summary: "S3 协议兼容的对象存储。",
        features: "桶与对象管理、S3 API、预签名 URL。",
        scenes: "应用存图片 / 附件 / 备份，且希望用 S3 SDK 直连。",
        entry: "自带 Console（默认 :9001，S3 API 默认 :9000）——需先配好第三方源才能安装；「服务」页看状态。",
        howto: "装完先配第三方源，再用它自带 Console（默认 :9001，S3 API 走 :9000）建 bucket 与访问密钥。面板内没有对象存储页面，配好源后到「服务」页看状态。",
        units: &[],
    },
    PkgDef {
        name: "valkey-server", label: "Valkey",
        summary: "Redis 的开源分支，协议兼容。",
        features: "功能同 Redis：缓存、会话、队列、分布式锁。",
        scenes: "Redis 变更许可证后的替代选择，客户端无需改动。",
        entry: "与 Redis 相同（面板无独立页面，应用连默认端口）；注意服务名是 valkey-server。",
        howto: "无需填连接：应用连 127.0.0.1:6379（与 Redis 同端口，二选一装）。配置文件在 /etc/valkey/，请通过 SSH 编辑后到「服务」页重启（面板按官方 systemd 单元部署时 /etc 只读，文件页写不进）。",
        units: &["valkey-server.service"],
    },
    PkgDef {
        name: "prometheus", label: "Prometheus",
        summary: "指标采集与时序数据库。",
        features: "按目标抓取指标、PromQL 查询、告警规则。",
        scenes: "自建监控体系、需要长期留存历史指标。",
        entry: "面板无独立页面（「概览」的主机监控是内置采集，不依赖它）；用它自己的 Web UI（默认 :9090）看指标与告警。",
        howto: "无需在面板里配：面板的主机监控是内置采集，不读 Prometheus。要用它就到 http://<本机>:9090 打开它自己的 Web UI；抓取目标写在 /etc/prometheus/prometheus.yml，该文件请通过 SSH 编辑（面板按官方 systemd 单元部署时 /etc 只读，文件页写不进）。",
        units: &["prometheus.service"],
    },
    PkgDef {
        name: "grafana", label: "Grafana",
        summary: "可视化仪表盘与告警平台。",
        features: "仪表盘编辑器、多数据源接入、告警通知。",
        scenes: "接 Prometheus 等数据源做展示与看板。",
        entry: "面板无独立页面，也不内嵌 Grafana 面板；用它自己的 Web UI（默认 :3000）建仪表盘与配告警。",
        howto: "面板不内嵌 Grafana：装好后浏览器开 http://<本机>:3000，首次登录 admin/admin（会强制改密），数据源与仪表盘都在它自己的界面里配。",
        units: &["grafana-server.service"],
    },
    PkgDef {
        name: "netdata", label: "Netdata",
        summary: "秒级粒度的实时主机监控。",
        features: "秒级指标采集、内置告警、开箱即用的图表面板。",
        scenes: "单机快速排障、看瞬时毛刺。",
        entry: "面板无独立页面（「概览」的主机监控为内置实现）；用它自己的 Web UI（默认 :19999）看秒级图表。",
        howto: "面板不内嵌 Netdata：装好后开 http://<本机>:19999 看秒级图表。要调告警请通过 SSH 编辑 /etc/netdata/health.d/ 下的文件（面板按官方 systemd 单元部署时 /etc 只读，文件页写不进）。",
        units: &["netdata.service"],
    },
    PkgDef {
        name: "haproxy", label: "HAProxy",
        summary: "四层 / 七层负载均衡器。",
        features: "TCP 与 HTTP 反向代理、健康检查、多后端分流。",
        scenes: "多个后端实例之间分流、需要比 Web 服务器更强的转发控制。",
        entry: "面板无独立页面；「服务」页看状态 / 日志；改配置请走 SSH（/etc/haproxy/haproxy.cfg，面板按官方 systemd 单元部署时 /etc 只读）。",
        howto: "面板不代写 HAProxy 配置：/etc/haproxy/haproxy.cfg（frontend / backend / server 三段）请通过 SSH 编辑，保存后到「服务」页重启 haproxy（面板按官方 systemd 单元部署时 /etc 只读，文件页写不进）。只想给 Web 站点做反代与负载均衡，直接用「网站」页的「反向代理」类型更省事。",
        units: &["haproxy.service"],
    },
    PkgDef {
        name: "nodejs", label: "Node.js",
        summary: "JavaScript 服务端运行时。",
        features: "运行 Node 服务、执行前端构建工具链（npm / pnpm）。",
        scenes: "Node / NestJS / Next.js 等应用，或需要前端构建环境。",
        entry: "「应用」页选 Node.js 运行时（systemd 托管 + 自动反代）；未安装时应用页会提示到「软件」页装。",
        howto: "「应用」页新建：名称（如 my-blog）、运行时选 Node.js、工作目录填绝对路径且须已存在（如 /opt/blog，可用「浏览…」选）、启动命令填 node server.js --port 3000（程序名或绝对路径均可）、监听端口 3000、域名填 blog.example.com。运行用户留空则自动建 site-<应用名>。没装 Node 时页面会提示去「软件」页装。",
        units: &[],
    },
    PkgDef {
        name: "default-jdk", label: "OpenJDK",
        summary: "Java 运行时与开发工具包。",
        features: "运行 Jar、编译 Java 代码。",
        scenes: "Spring Boot 等 Java 应用、Jar 包部署。",
        entry: "「应用」页选 Java 运行时；或「终端」「文件」自行部署。",
        howto: "「应用」页新建：运行时选 Java，工作目录填 jar 所在目录（须已存在），启动命令写 java -jar app.jar，端口填应用实际监听的那个。缺 JVM 时在「软件」页装。",
        units: &[],
    },
    // Go / Rust 是元包：`golang-go` → 当前发行版的 golang-1.XX-go；`cargo` Depends
    // `rustc`（实测 apt-cache depends），装一个包即得完整工具链。二者与上面的
    // nodejs / default-jdk 同属「应用运行时」，供「应用」页的运行时安装提示联动。
    PkgDef {
        name: "golang-go", label: "Go",
        summary: "Go 语言工具链。",
        features: "编译、测试、运行 Go 程序（go build / run / test）。",
        scenes: "部署编译为单文件的 Go 二进制服务。",
        entry: "「应用」页选 Go 运行时；或「终端」「文件」自行编译部署。",
        howto: "「应用」页新建：运行时选 Go，工作目录填二进制所在目录，启动命令填二进制路径（如 /opt/app/server）。Go 只在构建时需要，机器上没装 Go 也能跑已编译好的二进制。",
        units: &[],
    },
    PkgDef {
        name: "cargo", label: "Rust",
        summary: "Rust 语言工具链（含 rustc）。",
        features: "cargo build / run / test，依赖管理与交叉编译。",
        scenes: "编译并部署 Rust 服务。",
        entry: "「应用」页选 Rust 运行时；或「终端」「文件」自行编译部署。",
        howto: "「应用」页新建：运行时选 Rust，工作目录填二进制所在目录，启动命令填cargo run --release 或直接 /opt/app/target/release/app。运行不依赖 Rust 工具链。",
        units: &[],
    },
    PkgDef {
        name: "wireguard-tools", label: "WireGuard",
        summary: "现代轻量 VPN（点对点隧道）。",
        features: "内核态加密隧道、点对点与站点互联、按密钥识别对端。",
        scenes: "远程接入内网、在多台主机之间建立私有网络。",
        entry: "面板无独立页面；配置请通过 SSH 编辑 /etc/wireguard/*.conf；「服务」页看 wg-quick@ 单元状态。",
        howto: "面板不代写 WireGuard 配置：/etc/wireguard/wg0.conf（私钥、Address、对端 PublicKey/Endpoint/AllowedIPs）请通过 SSH 编辑，再到「服务」页启停 wg-quick@wg0（面板按官方 systemd 单元部署时 /etc 只读，文件页与终端都写不进）。",
        units: &["wg-quick@.service"],
    },
];

/// 白名单里**官方仓库通常不含**的包：需先在目标机上配好第三方软件源才能装。
///
/// 为什么单独维护而不是给 PkgDef 加字段：这只是"装之前要先配源"的提示信息，
/// 与包的身份（name/label）无关，混进 PkgDef 会让白名单每条字面量都变长。
///
/// 现状（2026-10-06 实测复核，Debian 13 trixie）：
/// - 有官方 apt 源、且已在 `panel-os/src/linux/repo.rs::THIRD_PARTY_REPOS` 登记
///   （密钥 URL + 官网公示指纹硬校验）的：`grafana` / `postgresql` / `redis` /
///   `nginx` / `nodejs`。由 `ensure_repo`（方案1）自动加源（校验 GPG 指纹 → 写隔离
///   keyring + sources.list.d → apt-get update）。实测加源后候选版本明显变新：
///   postgresql `17+278`(Debian) → `18+293.pgdg13+1`(PGDG)；
///   redis-server `8.0.2`(Debian) → `8.10.2`(Redis 官方源，与官网同步)；
///   nginx `1.26.3`(Debian) → `1.30.5`(nginx.org)。
///   故标 external 仅作"需联网加源"的弱提示，装/升级时能自动就绪。
///   （nodejs 一度因 deb.nodesource.com 超时而未接；后查明是**本机 IPv6 优先才超时、
///   强制 IPv4 即通**，遂接通并钉死指纹——详见 repo.rs 该条注释。）
/// - `netdata` / `minio`：**上游 apt 仓库均已下线**，`ensure_repo` 是 no-op，不会尝试加源。
///   netdata 的密钥仍能下载（指纹也对得上），但仓库元数据整体 404——连老牌 bookworm 的
///   InRelease 都是 404，故非"Debian 13 太新"，是仓库本身不可用；目录列表页仍能打开，
///   极易误判为可用，判定必须以 InRelease 200 为准（详见 `panel-os/src/linux/repo.rs` 注释）。
///   两者需走「直接下载 .deb / 静态安装」路径（方案3），不在自动加源范围内。
///
/// 面板保留这些入口（配好源后即可安装），UI 上标注提示，避免用户白点一次。
pub(crate) const EXTERNAL_SOURCE_PACKAGES: &[&str] = &[
    // 上游 apt 仓库已下线：ensure_repo 是 no-op，保留入口 + "需配源"提示。
    "minio", "netdata",
    // 自动加源（repo.rs 表内有定义）：UI 标"需配源"作弱提示，实际装/升级会自动加。
    // 这些包在 Debian stable 源里版本明显落后官网，已接各自上游官方源
    // （Grafana / PGDG / packages.redis.io / nginx.org / NodeSource）。
    "grafana", "postgresql", "redis", "nginx", "nodejs",
];

/// 逻辑包名 → 各发行版的**真实包名**（槽位 0 = Debian 系 apt，槽位 1 = 其它/RHEL 系）。
///
/// 为什么需要：同一个软件在不同发行版叫不同名字。Debian/Ubuntu 上 Redis 的包名是
/// `redis-server`（`redis` 是 Red Hat 系的名），此前探测只认 `redis` → Debian 上永远
/// 探测不到，用户看到的是"Redis 明明装了却不显示在已安装列表里"（本机实测：
/// redis-server 5:8.0.2 状态 ii，而白名单比对的是 redis，落空）。
///
/// 约定：`ALLOWED_PACKAGES` 里的都是**逻辑名**，对外一律用它（UI 展示、install/remove
/// 入参、幂等键、审计）；只有真正要交给 apt/dnf 的那一刻才换成真实包名。
pub(crate) const PKG_NAME_ALIASES: &[(&str, [&str; 2])] = &[
    ("redis", ["redis-server", "redis"]),
    ("apache2", ["apache2", "httpd"]),
];

/// 逻辑名 → 当前包管理器对应的真实包名（无别名条目则原样返回）。
pub fn real_pkg_name(manager: Option<&str>, logical: &str) -> String {
    match PKG_NAME_ALIASES.iter().find(|a| a.0 == logical) {
        Some(a) => a.1[if manager == Some("apt") { 0 } else { 1 }].to_string(),
        None => logical.to_string(),
    }
}

/// 真实包名 → 逻辑名：探测结果回填用，保证返回给前端的始终是逻辑名
/// （否则 Debian 上会吐出 `redis-server`，前端按逻辑名渲染的卡片/安装按钮就对不上了）。
pub fn logical_pkg_name(real: &str) -> Option<&'static str> {
    PKG_NAME_ALIASES.iter()
        .find(|a| a.1.contains(&real))
        .map(|a| a.0)
}

pub async fn install(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<InstallReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    // 重活限流：10 次 / 60 秒 / 用户（见 ratelimit.rs 的设计说明）
    crate::ratelimit::check_heavy(&state, &s.username, "pkg.install")?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == req.name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary installs are refused)"));
    }
    // 版本是用户可控输入：虽然后端以数组传参交给 apt/dnf（不走 shell，无命令注入风险），
    // 但奇字符会让包管理器直接报错、用户困惑。这里只允许版本号里合法出现的字符集，
    // 把错误拦在入参阶段、给出清晰中文提示。
    if let Some(v) = &req.version {
        validate_pkg_version(v)?;
    }
    // 跨主版本升级二次确认：install 也能触发升级（已装包传最新版即等于升级），
    // 不能只在 upgrade 路径守，否则换端点即可绕过警告。未装包 current=None → 不触发，
    // 首次安装零影响。
    require_major_upgrade_confirm(&state, &req).await?;

    // 安装必须走任务队列：耗时不可预测 + 输出需流式返回
    // Debian 上 Redis 的真实包名是 redis-server —— 直接拿逻辑名去 apt install 会失败，
    // 故此处换成当前发行版的真名（幂等键与审计仍用逻辑名，见下方 clone）。
    let pkg = real_pkg_name(state.os.packages().manager(), &req.name);
    let os = state.os.clone();
    let body = PackageTask { pkg, os, op: PkgOp::Install, version: req.version.clone(), logical: req.name.clone() };
    let (id, created) = state.tasks.submit(
        panel_task::TaskRequest {
            // 幂等键：同一包在窗口期内重复提交只会执行一次（防双击 / 防重试风暴）
            idempotency_key: format!("pkg.install:{}", req.name),
            kind: panel_task::TaskKind::Package,
            label: format!("安装 {}", req.name),
            timeout: Duration::from_secs(1800),
        },
        body,
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "package.install", &req.name, "queued").await;
    Ok(ok(serde_json::json!({ "task_id": id, "created": created })))
}

/// 安装/卸载共用同一任务体：结构一致（白名单→队列→底层），仅动词不同。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PkgOp { Install, Remove }

pub(crate) struct PackageTask { pub pkg: String, pub os: std::sync::Arc<dyn panel_os::OsAdapter>, pub op: PkgOp, pub version: Option<String>,
    /// 逻辑包名（= 白名单 ALLOWED_PACKAGES.name）。第三方官方源包（grafana/netdata）据此
    /// 在 install 前查 THIRD_PARTY_REPOS 自动加源；普通包在 ensure_repo 内是 no-op。
    pub logical: String }

#[async_trait::async_trait]
impl panel_task::TaskBody for PackageTask {
    async fn run(&self, progress: panel_task::Progress) -> Result<panel_task::TaskOutcome> {
        let installing = self.op == PkgOp::Install;
        let verb = if installing { "安装" } else { "卸载" };
        progress.set(5, &format!("开始{verb} {}", self.pkg)).await;

        // 输出缓冲：任务结束后落临时文件并经 output_path 登记，
        // 任务中心的 /tasks/{id}/output 才有内容可读（失败原因不丢）。
        // 只留尾部 MAX_BUF 行：包管理器输出可达几万行，全量落盘没必要。
        const MAX_BUF: usize = 400;
        let buf: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();

        // 第三方官方源：无论安装、升级还是「换源」，都先确保源就绪。
        //
        // 为什么提到 Install 分支之外（原先只在 install 前调）：接官方源的主要目的
        // 就是给**已装**的包换源（Debian 的 postgresql 停在 17、redis 停在 8.0.2，
        // 想用 PGDG 的 18 / Redis 官方源的 8.2 就必须先加源再升级）。若只挂在 install
        // 分支，已装的包走 upgrade 路径时加不上源，恰好漏掉最需要它的场景。
        //
        // 幂等由 ensure_third_party_repo 自己保证（keyring+sources 已一致则跳过），
        // 故每次任务都调只是几次 stat，不产生额外 apt-get update。
        // 无第三方源的包（普通包 / 非 apt 发行版 / netdata / minio）在其内是 no-op。
        {
            let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = seen.clone();
            if let Err(e) = self.os.packages().ensure_repo(&self.logical, Box::new(move |line| {
                if let Ok(mut g) = sink.lock() { g.push(line); }
            })).await {
                let msg = e.to_string();
                progress.log(&format!("加源失败：{msg}")).await;
                return Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Failed, exit_code: Some(1), output_path: None,
                });
            }
        }

        let result: Option<String> = if installing {
            // 同步回调 → 异步广播的桥接。
            // 用 unbounded 但在消费端限速：包管理器输出可能几万行，
            // 全部堆进 channel 会撑爆内存。消费端每 N 行合并成一条进度。
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let consumer = {
                let progress = progress.clone();
                let buf = buf.clone();
                tokio::spawn(async move {
                    let mut n = 0usize;
                    while let Some(line) = rx.recv().await {
                        n += 1;
                        {
                            let mut b = panel_core::sync::lock_recover(&buf);
                            if b.len() >= MAX_BUF { b.remove(0); }
                            b.push(line.clone());
                        }
                        // 每 20 行上报一次进度，其余只转发日志行
                        if n.is_multiple_of(20) {
                            progress.set(percent_from_lines(n), &line).await;
                        } else {
                            progress.log(&line).await;
                        }
                        if progress.is_canceled() { break; }
                    }
                })
            };

            let tx_for_cb = tx;
            let r = self.os.packages()
                .install(&self.pkg, self.version.as_deref(), Box::new(move |line| {
                    // try_send 永不阻塞：消费者跟不上就丢弃，绝不拖慢安装本身
                    let _ = tx_for_cb.send(line);
                }))
                .await;
            // tx 已随上方回调闭包一起释放（闭包所有权在 install 内），通道关闭后
            // 消费者 recv() 返回 None 自然退出；这里只需等消费者收尾。
            let _ = consumer.await;
            r.err().map(|e| e.to_string())
        } else {
            // 卸载没有流式输出可桥接（remove 不带回调），失败原因原样落日志
            self.os.packages().remove(&self.pkg).await.err().map(|e| e.to_string())
        };

        if let Some(e) = &result {
            progress.log(&format!("失败：{e}")).await;
            let mut b = panel_core::sync::lock_recover(&buf);
            if b.len() >= MAX_BUF { b.remove(0); }
            b.push(format!("失败：{e}"));
        }

        // 缓冲落盘 → 任务中心可读
        let mut output_path = None;
        let lines_snapshot: Vec<String> = panel_core::sync::lock_recover(&buf).clone();
        if !lines_snapshot.is_empty() {
            // 日志写进专属子目录而非 temp_dir 根（与 cron 任务体一致）：id 递增
            // → 每次都是新文件，若散落在 /tmp 根既无法定向清理，也会污染临时目录；
            // 写后按前缀裁剪，避免无限增长（P1-13）。读取端按 output_path 完整路径跟随。
            let dir = std::env::temp_dir().join(panel_task::TASK_LOG_DIRNAME);
            let _ = tokio::fs::create_dir_all(&dir).await;
            let p = dir.join(format!("{}{}.log", panel_task::TASK_LOG_PREFIX, progress.id()));
            if tokio::fs::write(&p, lines_snapshot.join("\n")).await.is_ok() {
                output_path = Some(p.clone());
                // 只保留最近若干份（清理失败不影响任务结果，函数内部静默）
                panel_os::prune_keep_newest(&dir, panel_task::TASK_LOG_PREFIX, panel_task::TASK_LOG_KEEP);
            }
        }

        match result {
            None => {
                progress.set(100, &format!("{verb}完成")).await;
                Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Ok, exit_code: Some(0), output_path,
                })
            }
            Some(_) => {
                // Package 类型 max_attempts=1：**不自动重试**（半装/半卸比重跑更危险）
                Ok(panel_task::TaskOutcome {
                    state: panel_task::TaskState::Failed, exit_code: Some(1), output_path,
                })
            }
        }
    }
}

/// 依据已输出行数估算进度（包管理器不提供真实百分比）。
/// 上限 90%：真正的 100% 只在成功返回后设置，避免"看起来装完了其实没完"。
pub(crate) fn percent_from_lines(n: usize) -> u8 {
    match n {
        0..=20 => 10,
        21..=100 => 30,
        101..=300 => 55,
        301..=800 => 75,
        _ => 90,
    }
}


pub async fn packages_list(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    // 打开软件管理即确保官方源落地（进程内只一次），让安装候选版本也反映官方源。
    ensure_external_repos_once(&state).await;
    // 语义是"管理白名单内软件的安装状态"，不是通用包管理器枚举：
    // 只在白名单范围内探测，避免全量 rpm/dpkg 扫描（慢且暴露无关信息）。
    // 按当前发行版的**真实包名**去探测，再把结果回填为**逻辑名**：
    // Debian 上 Redis 要查 redis-server，但对外仍要叫 redis（前端按逻辑名渲染、
    // 卸载接口也按逻辑名校验），否则同一个软件在 UI 上会出现两个身份。
    let manager = state.os.packages().manager();
    let probe: Vec<String> = ALLOWED_PACKAGES.iter().map(|d| real_pkg_name(manager, d.name)).collect();
    let probe: Vec<&str> = probe.iter().map(|s| s.as_str()).collect();
    let pkgs = state.os.packages().detect_installed(&probe).await?;
    // hold 全集一次性查（apt-mark showhold 一次输出全部被钉包名），本地与已装包
    // 求交集——按名逐个查既慢又把「全量集」语义拆散，理由见 PackageProvider::holds。
    // 失败降级为空集 + eprintln：hold 徽标是锦上添花，不该让整页软件列表挂掉
    // （与 packages_upgradable 探测失败同口径）；apt-mark 缺失只影响徽标显示。
    let held_set: std::collections::HashSet<String> = match state.os.packages().holds().await {
        Ok(v) => v.into_iter().collect(),
        Err(e) => {
            eprintln!("[panel] 查询 apt-mark hold 失败（hold 徽标将不显示）：{e}");
            Default::default()
        }
    };
    // 软件卡片的「服务管理」入口：用 `dpkg -L` 直接问"这个包装了哪些 .service"，
    // 绕过 systemctl list-units 对 enabled-but-dead 单元的遗漏（详见 PackageProvider::service_unit）。
    // 状态取自 systemd（is-active 口径，与 /services 同源），故 dead 的服务也能正确显示入口与状态。
    let mut items: Vec<serde_json::Value> = Vec::new();
    for p in pkgs {
        // 探测到的是真实包名（Debian 上 redis 查 redis-server），先还原成逻辑名，
        // 再取对应 label；取不到（理论上不会）时退回逻辑名，保证 UI 至少有字可显示。
        let logical = logical_pkg_name(&p.name).unwrap_or(p.name.as_str());
        let (name, label) = match ALLOWED_PACKAGES.iter().find(|d| d.name == logical) {
            Some(d) => (d.name.to_string(), d.label.to_string()),
            None => (logical.to_string(), logical.to_string()),
        };
        let unit = if let Ok(Some(u)) = state.os.packages().service_unit(&p.name).await {
            let st = match panel_core::unit_name(&u) {
                Ok(un) => state.os.services().status(&un).await
                    .map(|s| format!("{s:?}").to_lowercase())
                    .unwrap_or_else(|_| "unknown".to_string()),
                Err(_) => "unknown".to_string(),
            };
            Some(serde_json::json!({ "name": u, "state": st }))
        } else { None };
        items.push(serde_json::json!({
            "name": name, "label": label, "version": p.version,
            "manager": p.manager, "unit": unit,
            // 按**真实包名**比对：apt-mark 只认真名（Debian 上 redis 的 hold 落在
            // redis-server 上），拿逻辑名去比会永远不命中，UI 显示「未钉住」的谎状态。
            "held": held_set.contains(&p.name),
        }));
    }
    // 完整白名单（name+label+说明）随清单一起下发：前端据此给「已装」和「可装」两类都
    // 渲染友好品牌名与用途说明，而不必在 CATEGORIES / 前端常量表里再维护一份
    // （单一事实源在后端）。
    let catalog: Vec<serde_json::Value> = crate::routes::pkg_help::projection(ALLOWED_PACKAGES.iter())
        .map(|d| serde_json::json!({
            "name": d.name,
            "label": d.label,
            // 提示"官方源通常不含，需先配第三方源"；配好源后装上不受影响
            "external": EXTERNAL_SOURCE_PACKAGES.contains(&d.name),
            // 说明五项：前端软件卡片「说明」直接渲染，不硬编码任何一条
            "summary": d.summary,
            "features": d.features,
            "scenes": d.scenes,
            "entry": d.entry,
            "howto": d.howto,
            // 服务单元名（可能多条）：服务详情页据此反查，在本页直接展开软件说明。
            // 必须由后端给——包名与单元名不是同一字符串（mariadb-server→mariadb、
            // grafana→grafana-server、php-fpm→php8.4-fpm），前端按包名拼一定落空。
            "units": d.units,
        }))
        .collect();
    Ok(ok(serde_json::json!({ "packages": items, "catalog": catalog })))
}

/// 查询某个白名单包在当前软件源里可供安装的版本（新→旧）。
///
/// 为什么单独成端点而不是塞进 packages_list：列包是高频调用（页面加载/轮询），
/// 而版本查询要为每个包跑一次 apt-cache——25 个包全查会明显拖慢列表。
/// 改为安装弹窗打开时才按单个包查询（懒加载）。
pub async fn package_versions(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    // 与 install 同一道围栏：只查白名单内的包，避免把本端点变成任意包元数据探针。
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary installs are refused)"));
    }
    let manager = state.os.packages().manager();
    let real = real_pkg_name(manager, &name);
    let v = state.os.packages().list_versions(&real).await?;
    // 空列表不是错误：查不到就退回"装最新版"，前端据此只显示一个选项。
    // installed 由包管理器给出，用于在下拉里标「（已安装）」。
    Ok(ok(serde_json::json!({ "name": name, "versions": v.versions, "installed": v.installed })))
}

/// 对「有官方源定义的外部包」确保源已落地（每个逻辑名进程内最多尝试一次）。
///
/// `ensure_repo` 内部对无源包（minio/netdata）是 no-op，故直接遍历白名单安全。
/// 进程内只跑一次：成功则缓存、失败也缓存（权限类失败重试无意义），不反复打 `apt-get update`。
/// 调用点：只读「可升级探测」与安装列表加载，确保「接官方源」在用户看到列表前就落地，
/// 否则只读探测只能看到发行版源的旧版，「接官方源」等于没接。
async fn ensure_external_repos_once(state: &Shared) {
    for &logical in EXTERNAL_SOURCE_PACKAGES {
        let first = panel_core::sync::lock_recover(&ENSURED_EXTERNAL_REPOS).insert(logical);
        if !first {
            continue;
        }
        if let Err(e) = state.os.packages().ensure_repo(logical, Box::new(|_| {})).await {
            eprintln!(
                "[panel] 确保官方源 {logical} 失败（升级/探测将继续，但可能只能看到发行版源版本）：{e}"
            );
        }
    }
}

/// 探测白名单内**已安装且源里有新版**的包（B1：只读，供 UI 显示「有新版」徽标）。
///
/// 为什么单独成端点：与 packages_list 分开是因为它要对白名单跑一次 `apt-cache policy`
/// （亚秒级子进程），而 packages_list 是页面/轮询高频调用；混在一起会让每次刷新都多付这个开销。
///
/// 判据是「版本表最高版本 > 已安装版本」，与安装弹窗默认选中项（versions[0]）**同源**；
/// 刻意不用 `apt list --upgradable`——其判据 apt 的 Candidate 会被 pin / 源优先级压低，
/// 一旦低于已安装版本就永不报告（详见 `PackageProvider::upgradable` 的说明）。
///
/// 权限用 PACKAGE_MANAGE（与安装同级）：升级会改动系统，viewer 不该看到可升级清单。
/// 探测失败**不报错**、返回空列表——探测是锦上添花，不该让整页软件列表挂掉。
pub async fn packages_upgradable(
    State(state): State<Shared>, Auth(s): Auth,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    // 探测可升级包要跑 apt 子进程（还要先 ensure_repo），是本仓最贵的只读端点之一
    crate::ratelimit::check_read(&state, &s.username, "pkg.upgradable")?;
    if !state.capabilities.get(cap_keys::PACKAGE_UPGRADE)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.upgrade"));
    }
    // 探测前先确保官方源已落地：否则只读探测只能看到发行版源的旧版，「接官方源」等于没接。
    // ensure_repo 进程内只跑一次（见 ensure_external_repos_once），不拖慢后续轮询。
    ensure_external_repos_once(&state).await;
    let mgr = state.os.packages().manager();
    // 只问白名单这二十来个包（按真包名探测，php-fpm ↔ php8.4-fpm 这类别名由
    // real_pkg_name 统一处理），再映射回逻辑名对外——与 install/remove 的约定一致。
    let reals: Vec<String> = ALLOWED_PACKAGES.iter().map(|p| real_pkg_name(mgr, p.name)).collect();
    let refs: Vec<&str> = reals.iter().map(|s| s.as_str()).collect();
    let up = state.os.packages().upgradable(&refs).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = ALLOWED_PACKAGES.iter().filter_map(|p| {
        let real = real_pkg_name(mgr, p.name);
        up.iter().find(|u| u.name == real).map(|u| serde_json::json!({
            "name": p.name,            // 逻辑名（前端按它匹配已安装卡片）
            "label": p.label,
            "current": u.current,
            "candidate": u.candidate,
            "major": u.major,          // 跨主版本标记：前端据此弹窗二次确认
        }))
    }).collect();
    Ok(ok(serde_json::json!({ "items": items })))
}

/// 升级某个已安装软件到指定版本（A：复用 install pkg=version 路径）。
///
/// 为什么复用 install 而不新增 PkgOp::Upgrade：apt/dnf 的 `install pkg=version` 语义上
/// **本身就是覆盖升级**（已装 1.0 时执行 install pkg=1.2.3 就是升到 1.2.3），
/// 另立一个 op 只会让底层多一份完全同构的分支。升级与安装的差别只在 UI 语义与幂等键。
///
/// version 为空时表示"升到源里的最新版"（apt install pkg，不带版本约束）。
pub async fn package_upgrade(
    State(state): State<Shared>,
    Auth(s): Auth,
    PanelJson(req): PanelJson<InstallReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    // 重活限流：10 次 / 60 秒 / 用户（见 ratelimit.rs 的设计说明）
    crate::ratelimit::check_heavy(&state, &s.username, "pkg.upgrade")?;
    if !state.capabilities.get(cap_keys::PACKAGE_UPGRADE)
        .map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.upgrade"));
    }
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == req.name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary installs are refused)"));
    }
    if let Some(v) = &req.version {
        validate_pkg_version(v)?;
    }
    let real = real_pkg_name(state.os.packages().manager(), &req.name);

    // 跨主版本升级二次确认（与 install 共用同一守卫，单一事实源）。
    require_major_upgrade_confirm(&state, &req).await?;

    let pkg = real;
    let os = state.os.clone();
    let body = PackageTask { pkg, os, op: PkgOp::Install, version: req.version.clone(), logical: req.name.clone() };
    // 幂等键与 install 刻意不同（pkg.upgrade: vs pkg.install:）：否则用户先装了新版、
    // 又点「更新到旧版本」会被 install 的窗口期幂等吞掉，任务静默不执行。
    let (id, created) = state.tasks.submit(
        panel_task::TaskRequest {
            idempotency_key: format!("pkg.upgrade:{}", req.name),
            kind: panel_task::TaskKind::Package,
            label: format!("升级 {}", req.name),
            timeout: Duration::from_secs(1800),
        },
        body,
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "package.upgrade", &req.name, "queued").await;
    Ok(ok(serde_json::json!({ "task_id": id, "created": created })))
}

/// 跨主版本升级二次确认守卫（install 与 upgrade 两路共用，单一事实源）。
///
/// 已装包升到**跨主版本**候选（PostgreSQL 17→18、Node.js 20→24 等）时，未带
/// `confirm_major=true` 则 409 拒绝——不能只靠前端拦截，否则直接调 API 即可绕过。
/// 判定与 /packages/upgradable 列表里的 `major` 标记同源：都取「版本表最高版本」作候选，
/// 再交 `version_major_jump` 判定——两处各写一份必然漂移。
///
/// 未装包：`current` 经 upgradable + apt-cache policy 都取不到 → `major=false` → 不触发，
/// 故对「首次安装」零影响；仅当包**已装且**目标跨主版本时才拦截。
async fn require_major_upgrade_confirm(
    state: &Shared,
    req: &InstallReq,
) -> ApiResult<()> {
    let real = real_pkg_name(state.os.packages().manager(), &req.name);
    let up = state.os.packages().upgradable(&[real.as_str()]).await.unwrap_or_default();
    let entry = up.iter().find(|u| u.name == real);
    // candidate：用户显式指定版本优先，否则取 upgradable 探测到的目标版本
    let candidate = req.version.clone()
        .or_else(|| entry.as_ref().map(|u| u.candidate.clone()));
    // current：upgradable 探测里的已装版本；不在探测列表里（用户显式指定旧/新版）时
    // 退回 apt-cache policy 的已装版本
    let current = match entry {
        Some(u) => Some(u.current.clone()),
        None => state.os.packages().list_versions(&real).await.ok().and_then(|v| v.installed),
    };
    let major = match (&current, &candidate) {
        (Some(c), Some(n)) => version_major_jump(c, n),
        _ => false,
    };
    if major && !req.confirm_major.unwrap_or(false) {
        return Err(ApiError::conflict("major_upgrade").with_detail(serde_json::json!({
            "kind": "major_upgrade",
            "from": current,
            "to": candidate,
            "note": "跨主版本升级可能不向后兼容，通常需要数据迁移或服务重配。例如 PostgreSQL 17→18 须先执行 pg_upgrade 或逻辑备份恢复，期间服务不可用。确认前请务必先完成数据备份。",
        })));
    }
    Ok(())
}

pub async fn package_remove(
    State(state): State<Shared>, Auth(s): Auth, AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    // 重活限流：10 次 / 60 秒 / 用户（见 ratelimit.rs 的设计说明）
    crate::ratelimit::check_heavy(&state, &s.username, "pkg.remove")?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary removes are refused)"));
    }

    // 卸载与安装同权重：走任务队列 + 幂等键（与 install 不同键，避免互相吞并）
    let pkg = real_pkg_name(state.os.packages().manager(), &name);
    let os = state.os.clone();
    let body = PackageTask { pkg, os, op: PkgOp::Remove, version: None, logical: name.clone() };
    let (id, created) = state.tasks.submit(
        panel_task::TaskRequest {
            idempotency_key: format!("pkg.remove:{}", name),
            kind: panel_task::TaskKind::Package,
            label: format!("卸载 {}", name),
            timeout: Duration::from_secs(1800),
        },
        body,
    ).await.map_err(ApiError::from)?;

    audit(&state, &s, "package.remove", &name, "queued").await;
    Ok(ok(serde_json::json!({ "task_id": id, "created": created })))
}

/// 设置/取消某个白名单包的「升级钉住」（apt-mark hold/unhold）请求体。
#[derive(Debug, Deserialize)]
pub struct HoldReq {
    /// true = 钉住（阻止自动升级）；false = 取消钉住。
    pub held: bool,
}

/// 设置/取消某个已安装白名单包的 hold 状态。
///
/// 为什么单独端点而不并进 install/remove：hold 改的是**升级通道**而非安装状态，
/// 语义独立——装卸走任务队列、有流式输出；hold 是秒级同步操作，且需要独立的
/// 「仅 apt 支持」能力判定（dnf 的 versionlock 是插件、apk 无对应概念）。
///
/// **幂等**：对已 hold 的包再 hold、对未 hold 的包再 unhold 都返回成功——
/// apt-mark 自身幂等，端点层不额外查现状，省一次子进程往返。
///
/// 语义边界（前端文案必须同步说清）：hold 只挡 `apt-get upgrade` 的**自动**升级，
/// 不挡显式 `apt-get install <pkg>=<version>`——防误升，不是安全边界。
pub async fn package_hold(
    State(state): State<Shared>,
    Auth(s): Auth,
    AxPath(name): AxPath<String>,
    PanelJson(req): PanelJson<HoldReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::auth::require(&s, perm::PACKAGE_MANAGE)?;
    if !state.capabilities.get(cap_keys::PACKAGE_INSTALL).map(|c| c.supported).unwrap_or(false) {
        return Err(ApiError::unsupported("package.install"));
    }
    // 与 install/remove 同一道围栏：面板以 root 运行，只允许动白名单内的包。
    if !ALLOWED_PACKAGES.iter().any(|p| p.name == name.as_str()) {
        return Err(ApiError::bad_request("name",
            "package not in the allowed list (panel runs as root; arbitrary holds are refused)"));
    }
    // 能力诚实：非 apt 管理器没有 hold 概念，如实 501 而不是伪造成功——
    // 能力位不能撒谎（`Capable` 对「实际能不能跑」负责）。
    if state.os.packages().manager() != Some("apt") {
        return Err(ApiError::unsupported("package.hold"));
    }
    // 钉的是**真实包名**（Debian 上 redis → redis-server）：apt-mark 只认真名，
    // 拿逻辑名去 hold 会钉到一个不存在的包（退出码 0 但不生效，静默假成功）。
    let real = real_pkg_name(state.os.packages().manager(), &name);
    state.os.packages().set_hold(&real, req.held).await?;
    audit(&state, &s, "package.hold",
        &format!("{name}:{}", if req.held { "hold" } else { "unhold" }), "ok").await;
    Ok(ok(serde_json::json!({ "name": name, "held": req.held })))
}

