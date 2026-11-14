# 由 ForkPanel 编译期内嵌：站点默认加固片段（server 级，内联进 panel-<host>.conf）。
#
# 为什么是「内联」而不是运行时 include：
#   - panel-<host>.conf 本身就是 nginx 的 http 级 drop-in，默认配置写进它即为
#     「创建站点/应用时默认带上」，无需第二份文件；
#   - 外部 include 需要随安装包分发到固定绝对路径，而 build-static.sh 只打包
#     install.sh / config.toml / expose-public.sh，漏一处即 nginx -t 失败、站点全红；
#   - validate 的临时 wrapper 用 -c/-p 换 prefix，绝对路径 include 会去读宿主文件，
#     让校验依赖「文件是否已安装」而非配置本身；
#   - 站点 conf 的行为若依赖外部文件，conf_snapshot 指纹与 site_conf_versions 版本链
#     都记不下这份依赖：外部文件一改、行为变了而面板无痕，回滚语义被破坏。
#
# 落点：必须放在主 server 块内。nginx 的 add_header 在「本级有定义时」不再继承上级；
#   开启 HSTS 的站点 server 块内已有一条 add_header，http 级的头会被全部静默遮蔽。
#   放 server 级则与 HSTS 同级累加，两类头都会发出。
#
# 边界（ci/check_site_defaults.py 逐条钉住，禁止把下面这些变成生效指令）：
#   - CORS 响应头：跨域策略属于应用，面板不代用户放宽同源策略
#   - Content-Security-Policy：会直接破坏用户页面的脚本 / 样式
#   - Strict-Transport-Security：项目已有独立 HSTS 开关，且浏览器侧不可撤回
#   - gzip / gzip_types：属 http 级；本机主配置已启用 gzip，重复定义会静默覆盖默认值
#   - X-Frame-Options / Permissions-Policy：会破坏 iframe 嵌入与定位 / 摄像头 / 麦克风
#     类应用，故只作可选示例列在下方，不默认生效
#
# 用户若不需要：在面板「站点配置」区编辑并保存，转为手动维护后自行接管。

server_tokens off;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# 可选加固（默认不生效；需要时按应用实际调整后写进站点「自定义配置片段」）：
# add_header X-Frame-Options "SAMEORIGIN" always;
# add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
