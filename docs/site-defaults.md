# 站点默认加固片段

> 适用范围：nginx 后端的**站点**与**应用**（应用创建站点复用 `sites::apply`，走同一
> 渲染器）。Caddy 分支不受影响，也未套用 nginx 语义。
>
> 事实源：`deploy/site-defaults.inc`；渲染器：
> `crates/panel-os/src/linux/providers/webserver.rs` 的 `render_nginx()` /
> `site_defaults_directives()`；门禁：`ci/check_site_defaults.py`。

## 1. 生效形态：内联，不是运行时 include

用户创建站点或应用时，面板渲染 `/etc/nginx/conf.d/panel-<host>.conf`。这份文件本身
就是 nginx 主配置 `include /etc/nginx/conf.d/*.conf;` 加载的 **http 级 drop-in**，
所以「默认带上常用配置」就是把片段指令**内联写进它**，不需要第二份文件。

`deploy/site-defaults.inc` 经 `include_str!` **编译期内嵌**进二进制；渲染时
`site_defaults_directives()` 剔掉注释与空行、补上 server 级缩进后写进主
`server {}` 块。产物自包含，不生成任何 `include` 指令。

为什么不采用「生成一份 .inc 文件、在 conf 里 include 它」：

| 风险 | 后果 |
|---|---|
| 分发路径 | `build-static.sh` 只打包 `install.sh` / `config.toml` / `expose-public.sh`。新增资产要同步改打包、安装、卸载与 systemd `ReadWritePaths`；漏一处，生成的 `include` 指向不存在的文件，`nginx -t` 直接失败，**所有站点下发不了** |
| 校验耦合 | `validate()` 用 `-c/-p` 把 conf_prefix 指到临时目录，绝对路径 include 会去读宿主文件，语法校验变成在测「文件装没装」而不是配置对不对 |
| 版本链盲区 | 站点行为依赖外部文件，而 `conf_snapshot` 只记表单字段指纹、`site_conf_versions` 只存 conf 文本。外部文件一改，行为变了而面板无痕，回滚语义被破坏 |
| 架构优势 | 单文件静态二进制 + 内嵌前端的分发模型，不应为三条响应头引入一条运行时文件依赖 |

## 2. 默认三条

| 指令 | 作用 | 为什么可以默认开 |
|---|---|---|
| `server_tokens off;` | `Server` 头只回 `nginx`、不回版本号 | 无功能影响；不依赖宿主主配置是否也关掉 |
| `add_header X-Content-Type-Options "nosniff" always;` | 禁止浏览器 MIME 嗅探 | 对 MIME 配置正确的应用零影响 |
| `add_header Referrer-Policy "strict-origin-when-cross-origin" always;` | 跨站请求不带完整路径 | 与主流浏览器现行默认策略一致，几乎不改变行为 |

`always` 参数保证 4xx/5xx 与 `return` 响应同样带这些头。

## 3. 明确不默认开的常用配置

这些是同类产品常见的「一键加固」项，但**默认替用户决定会改变或破坏应用**：

| 配置 | 不默认开的原因 |
|---|---|
| CORS / `Access-Control-Allow-*` | 跨域策略属于应用；站点类型、API 形态、cookie 凭据策略各不相同，面板默认放宽同源策略等于静默改变安全边界 |
| `Content-Security-Policy` | 会直接破坏用户页面的内联脚本 / 样式 / 第三方资源，且需要按站点逐个调 nonce 或白名单 |
| `Strict-Transport-Security` | 项目已有独立 HSTS 开关（含 max-age / includeSubDomains / preload 三项），且浏览器在 max-age 内强制 HTTPS、服务端无法撤回 |
| `gzip` / `gzip_types` | 属 http 级指令；本机主配置通常已 `gzip on`，在站点里重复定义 `gzip_types` 不会报错但会**静默覆盖**系统默认值 |
| `X-Frame-Options` | 会破坏被 iframe 嵌入的后台、支付回调页、嵌入式应用 |
| `Permissions-Policy` | 禁用 geolocation / microphone / camera 会破坏扫码、地图、语音、视频类应用 |

后两项在 `deploy/site-defaults.inc` 里以**注释形式**给出可选示例（不生效）。需要时
按应用实际调整后写进站点「自定义配置片段」，或转手动维护自行接管。

## 4. 落点：必须留在主 server 块内

nginx 的 `add_header` 规则是：**当前级一旦定义了任意 `add_header`，上级的全部
`add_header` 都不再继承**。站点开启 HSTS 时，主 `server {}` 块内已经写了一条
`Strict-Transport-Security`；若把默认头放到 http 级 drop-in，它们会被**全部静默
遮蔽**（`nginx -t` 不报错，页面看着也正常，只是头没了）。

因此默认片段内联在主 `server {}` 块内、`server_name` 之后、任何 `location` 之前，
与 HSTS 同级；同级的多个 `add_header` 会累加输出。真机 A/B 验证证据见
`.workbuddy/docs/site-defaults-2026-11-14.md`。

## 5. 对既有站点与手动维护的影响

- 片段随「保存并应用 / 重新生成」重新渲染；**已落盘的站点不会自动变化**，需要用户
  重新下发一次才会带上。
- 渲染输出变化**不改变表单部署字段**，所以 `conf_snapshot` 指纹不变，手动维护站点
  不会因此误报 `conf_stale`。
- `manual_conf=1` 的站点走「普通保存跳过渲染 / 校验 / 下发」的路径，磁盘配置是唯一
  事实源，默认片段不会覆盖用户手改内容。
- 用户若不想要这几条：在面板「站点配置」区编辑并保存，转为手动维护后自行接管。

## 6. 验证门禁

| 层 | 位置 | 钉住什么 |
|---|---|---|
| 静态守卫 | `ci/check_site_defaults.py`（接在 `make guards`） | 生效指令恰好三条且逐条精确、禁止项为零、`include_str!` 恰好一处、`render_nginx` 真的调用、无运行时 include、守卫确实在跑 |
| 行为单测 | `crates/panel-os/src/linux/providers/tests.rs` 的 `site_defaults_*` | 内联位置在 server 级、HSTS 共存时仍在、Caddy 不误用、维护者注释不进产物 |
| 真机语法 | 同文件 `rendered_config_passes_real_nginx_syntax_check` | 全部渲染分支的产物过真实 `nginx -t` |
| 真机响应头 | `.workbuddy/tmp/verify-site-defaults.sh`（落地时的一次性验收） | nginx 实际发出的头、HSTS 站点不丢头、`Server` 头不含版本号 |

守卫与单测均做过负向对照（注入 CORS、删除内联调用、门禁接线短路）：改坏必真红、
字节还原必真绿。
