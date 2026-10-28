#!/usr/bin/env bash
# 公网暴露脚本 E2E：在 user namespace 里真跑 `deploy/expose-public.sh`
#
# ## 为什么需要
# `expose-public.sh` 干的是**把 root 权限面板放到公网边缘**这种一步走错就出大事的活：
# 它会写 nginx 配置、动防火墙、重启面板。它的全部安全性建立在三条 fail-closed 之上
# （不给 allow 就拒绝 / 面板已裸奔就拒绝 / 端口探测不可信就拒绝），而这类检查最典型的
# 失效方式是**没人真的跑过它**——写的时候觉得对，某次重构顺手删掉一行，静默退化。
#
# ## 边界（诚实说明，不假装覆盖）
#  - `systemctl` / `nginx` / `ss` / `ufw` 全是 **shim**，只记录调用、**不做真事**。
#    故本脚本验的是"调了什么、生成了什么"，**不是**"nginx 真的能转发、ufw 真的放行"。
#    （真机验收见 docs/deployment.md 2.5 的清单。）
#  - 自签证书用的是**真 openssl**（不 shim），所以那条路径是真跑的。
#
# ## 用法
#   ci/e2e-expose-public.sh        # 或 make e2e-expose
# 环境不具备（无 unshare / 无 userns 权限）⇒ [skip] 且退出 2，不计为通过。
set -uo pipefail

SCRIPT_DEFAULT=./deploy/expose-public.sh
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASS=0; FAIL=0; SKIP=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
skip() { SKIP=$((SKIP+1)); say "  [skip] $1"; }
chk()     { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1  实际=[$2] 期望=[$3]"; fi; }
chk_has() { case "$2" in *"$3"*) ok "$1";; *) bad "$1  输出缺少 [$3]；实际=[$2]";; esac; }
chk_not() { case "$2" in *"$3"*) bad "$1  不该出现 [$3]；实际=[$2]";; *) ok "$1";; esac; }

if [ ! -f "$SCRIPT_DEFAULT" ]; then
  say "[skip] 找不到脚本：$SCRIPT_DEFAULT"
  exit 2
fi
if ! command -v unshare >/dev/null 2>&1; then
  say "[skip] 缺少 unshare（util-linux），无法构造隔离环境"
  exit 2
fi
if ! unshare -rmn --propagation private true >/dev/null 2>&1; then
  say "[skip] user namespace 不可用（内核/发行版禁用，或已被 seccomp 限制）"
  exit 2
fi

PORT=17524

unshare -rmn --propagation private bash -s -- "$REPO" "$PORT" <<'INNER'
set -uo pipefail
REPO="$1"; PORT="$2"; SCRIPT="$REPO/deploy/expose-public.sh"

PASS=0; FAIL=0; SKIP=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
chk()     { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1  实际=[$2] 期望=[$3]"; fi; }
chk_has() { case "$2" in *"$3"*) ok "$1";; *) bad "$1  输出缺少 [$3]；实际=[$2]";; esac; }
chk_not() { case "$2" in *"$3"*) bad "$1  不该出现 [$3]；实际=[$2]";; *) ok "$1";; esac; }

NGINX_CONF=/etc/nginx/conf.d/forkpanel-public-access.conf

# ── 1. 一次性文件系统 + 假面板 ──────────────────────────────────────────
for d in /etc /var/lib /var/www; do
  mkdir -p "$d" 2>/dev/null || { say "  ✗ 无法准备 $d"; exit 1; }
  mount -t tmpfs none "$d" 2>/dev/null || { say "  ✗ 无法挂载 tmpfs 到 $d"; exit 1; }
done
mkdir -p /etc/forkpanel /etc/nginx/conf.d /etc/systemd/system /var/lib/forkpanel
cat > /etc/forkpanel/config.toml <<EOF
[server]
bind = "127.0.0.1"
port = $PORT
localhost_only = true
EOF

# /etc/ssl 被 tmpfs 盖空了：openssl 需要一份配置文件，给它个最小可用的
mkdir -p /etc/ssl
printf '[req]\ndistinguished_name = dn\n[dn]\n' > /etc/ssl/openssl.cnf
export OPENSSL_CONF=/etc/ssl/openssl.cnf

# ── 2. shim：记录调用，不真的动系统 ────────────────────────────────────
mkdir -p /tmp/e2e-shim
: > /tmp/e2e-shim/calls.log
SS_OUT=/tmp/e2e-shim/ss.out
NX_T_FAIL=0
NX_RELOAD_FAIL=0
SYS_RELOAD_FAIL=0
export NX_T_FAIL NX_RELOAD_FAIL SYS_RELOAD_FAIL SS_OUT

cat > /tmp/e2e-shim/systemctl <<'SH'
#!/bin/bash
echo "systemctl $*" >> /tmp/e2e-shim/calls.log
case "$1 $2" in
  "reload nginx") [ "${SYS_RELOAD_FAIL:-0}" = "1" ] && exit 1; exit 0 ;;
esac
exit 0
SH
cat > /tmp/e2e-shim/nginx <<'SH'
#!/bin/bash
echo "nginx $*" >> /tmp/e2e-shim/calls.log
case "$1" in
  -t) [ "${NX_T_FAIL:-0}" = "1" ] && exit 1; exit 0 ;;
  -s) [ "${NX_RELOAD_FAIL:-0}" = "1" ] && exit 1; exit 0 ;;
  *)  exit 0 ;;
esac
SH
cat > /tmp/e2e-shim/ss <<'SH'
#!/bin/bash
cat "${SS_OUT:-/dev/null}"
SH
cat > /tmp/e2e-shim/ufw <<'SH'
#!/bin/bash
echo "ufw $*" >> /tmp/e2e-shim/calls.log
case "$1" in
  status) echo "Status: active" ;;
esac
exit 0
SH
chmod +x /tmp/e2e-shim/systemctl /tmp/e2e-shim/nginx /tmp/e2e-shim/ss /tmp/e2e-shim/ufw
export PATH=/tmp/e2e-shim:$PATH

# ss 输出按用例切换：$1=状态名，其后是 ss 的真实输出行
setss() { local name="$1"; shift; printf '%s\n' "$@" > "$SS_OUT"; }
reset_log() { : > /tmp/e2e-shim/calls.log; }

# ── 3. 参数校验都必须拒绝（fail-closed）────────────────────────────────
say '== 3. 参数不合法时一律拒绝（不接受“先装上再说”）=='
setss normal "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port" \
             "LISTEN  0       128     127.0.0.1:$PORT    0.0.0.0:*"

out=$(bash "$SCRIPT" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok "不带任何参数被拒" || bad "不带任何参数竟通过了"

# ⚠ 这一条是本脚本存在的核心理由：没有来源限制的反代 = 把 root 面板开放公网
out=$(bash "$SCRIPT" -d panel.example.com 2>&1); rc=$?
chk "缺 -a/--allow 必须拒绝" "$rc" "1"
chk_has "拒绝原因说明来源限制" "$out" "allow"

out=$(bash "$SCRIPT" -d example -a 203.0.113.0/24 2>&1); rc=$?
chk "单段域名被拒" "$rc" "1"
out=$(bash "$SCRIPT" -d panel.123 -a 203.0.113.0/24 2>&1); rc=$?
chk "顶级域含数字被拒（panel.123）" "$rc" "1"
out=$(bash "$SCRIPT" -d panel.example.com -a 300.1.1.1/24 2>&1); rc=$?
chk "非法 CIDR（300.1.1.1/24）被拒" "$rc" "1"
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/33 2>&1); rc=$?
chk "掩码越界（/33）被拒" "$rc" "1"
# ⚠ 掩码 0（0.0.0.0/0）形式上"按要求给了 allow"，实质等于不设限制——
#   放行它就等于上面那条检查白做。必须单独挡。
out=$(bash "$SCRIPT" -d panel.example.com -a 0.0.0.0/0 2>&1); rc=$?
chk "掩码 0（0.0.0.0/0，等于不设限制）被拒" "$rc" "1"
chk_has "指出它等于不设限制" "$out" "等于不设限制"
out=$(bash "$SCRIPT" -d panel.example.com -a 10.0.0.0/0 2>&1); rc=$?
chk "掩码 0 的其它写法（10.0.0.0/0）也被拒" "$rc" "1"
# ⚠ 前导零变体：早期实现在调用点用 glob `*/0|*/00|*/000` 拦掩码 0，
#   而 `/0000`、`/00000` 在 `10#` 十进制解析下**同样等于 0** 却能整条绕过。
#   现改为在 validate_cidr 内按解析值判定，这里逐条钉死防回退。
for m in 0000 00000 0000000000; do
  out=$(bash "$SCRIPT" -d panel.example.com -a "203.0.113.0/$m" 2>&1); rc=$?
  chk "掩码前导零变体 /$m 必须拒绝（glob 守卫的历史漏洞）" "$rc" "1"
done
# bash 算术按 2^64 回绕：`$((10#18446744073709551616))` 得 0，不加位数上限就能骗过 -le 32
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/18446744073709551616 2>&1); rc=$?
chk "超长数字掩码（回绕成 0）必须拒绝" "$rc" "1"
# 反向确认守卫没有误伤：合法掩码必须仍然通过参数校验这一关。
# 判据=输出里不出现「掩码 0」类拒绝文案（后续环节是否失败与本守卫无关，故只查本关）。
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1)
chk_not "合法 /24 不得被掩码守卫误伤" "$out" "掩码 0"

# IPv6 本版明确不支持：必须**明确拒绝**而不是假装通过
out=$(bash "$SCRIPT" -d panel.example.com -a 2001:db8::/32 2>&1); rc=$?
chk "IPv6 来源被拒（不支持却装懂最危险）" "$rc" "1"

# ── 4. 端口探测：不可信 / 不在跑 / 已裸奔，都必须拒绝 ──────────────────
say "== 4. 端口探测的三类拒绝（判据不可信时一律不放行）=="
# ⓵ 连表头都没有 = 探测根本没跑起来；此时"没检测到"不能当成"只在本地"
setss broken "LISTEN  0  128  127.0.0.1:$PORT  0.0.0.0:*"
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "ss 输出缺表头必须拒绝" "$rc" "1"
chk_has "提示探测不可信" "$out" "不可信"

# ⓶ 面板压根没在跑
setss nobody "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port"
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "面板未监听必须拒绝" "$rc" "1"

# ⓷ 面板已经自己裸奔 —— 此时装反代不但没用，还会掩盖真实风险
setss naked "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port" \
            "LISTEN  0       128     0.0.0.0:$PORT     0.0.0.0:*"
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "面板已监听 0.0.0.0 必须拒绝" "$rc" "1"
chk_has "指出已经暴露在外" "$out" "已经自己暴露"

# ── 5. 正常路径：生成什么必须逐条核对 ──────────────────────────────────
say "== 5. 正常路径生成的 nginx 配置 =="
setss normal "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port" \
             "LISTEN  0       128     127.0.0.1:$PORT    0.0.0.0:*"
reset_log
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 -a 198.51.100.7/32 2>&1); rc=$?
chk "正常路径退出码 0" "$rc" "0"
if [ "$rc" -ne 0 ]; then say "--------- 输出 ---------"; say "$out"; say "------------------------"; fi

if [ -f "$NGINX_CONF" ]; then
  ok "nginx 配置已生成：$NGINX_CONF"
  conf=$(cat "$NGINX_CONF")
  # ⚠ 没有 deny all 就意味着"名单内放行、名单外也放行"——这条是整个脚本的安全底线
  chk_has "配置含 deny all（fail-closed 底线）" "$conf" "deny all;"
  chk_has "allow 网段 1"  "$conf" "allow 203.0.113.0/24;"
  chk_has "allow 网段 2"  "$conf" "allow 198.51.100.7/32;"
  chk_has "反代指向面板回环端口" "$conf" "proxy_pass http://127.0.0.1:$PORT;"
  chk_has "转发真实来源 IP"    "$conf" "X-Real-IP"
  chk_has "转发 X-Forwarded-Proto" "$conf" "X-Forwarded-Proto"
  chk_has "证书链已写入"       "$conf" "ssl_certificate "
  chk_has "ACME 续期路径放行"  "$conf" ".well-known/acme-challenge/"
  chk_has "强制 HTTPS 跳转"    "$conf" "return 301 https://"
  # WS：必须 map 动态决定，写死 Connection "upgrade" 会让**所有**请求都带升级头
  chk_has "WS 升级用带前缀的 map 变量（防与其它 map 冲突）" "$conf" "map \$http_upgrade \$forkpanel_panel_ws {"
  # SSE（日志流）：开了缓冲事件会攒着不发，默认 60s 读超时会把长流掐断
  chk_has "SSE 不被缓冲"           "$conf" "proxy_buffering off;"
  chk_has "长流读超时已放宽"       "$conf" "proxy_read_timeout 3600s;"
  # 文件管理器要传文件，nginx 默认 1m 会让稍大一点的上传直接 413
  chk_has "放开上传体积"           "$conf" "client_max_body_size 0;"
  # HTTP/2 刻意不启用：跨版本不兼容会让 nginx -t 失败、脚本每次回滚。
  # ⚠ 断言要指向**指令行**，不能在整份文件里搜 "http2" 这个词：注释里解释
  #   "为何不用 http2" 时必然出现该词（这条断言就因此误红过一次——是断言写宽了，
  #   不是配置写错了）。判据先剔注释行，再确认剔完仍有配置体，防止两边都空 ⇒ 恒绿。
  nocmt=$(printf '%s\n' "$conf" | grep -v '^[[:space:]]*#' || true)
  chk_has "剔注释后仍有配置体（防恒绿）" "$nocmt" "server {"
  chk_not "指令行里没有 http2（版本兼容）" "$nocmt" "http2"
  # 放在 nocmt 定义**之后**：上面那条用到的 "$nocmt" 若早于此取值会是空串，
  # 断言就成了恒绿（本项目踩过：看着在测、实际什么都没测到）。
  chk_not "不写死 Connection \"upgrade\"" "$nocmt" 'Connection "upgrade"'
  say "  ---- 生成的 server 块（前 40 行）----"
  head -40 "$NGINX_CONF" | sed 's/^/    /'
else
  bad "nginx 配置未生成"
fi

# 自签证书必须是真的（openssl 不 shim）
CERT_DIR=/var/lib/forkpanel/ssl/public-access
if [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]; then
  ok "自签证书已生成"
  subj=$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -subject 2>/dev/null || true)
  chk_has "证书 CN 是指定域名" "$subj" "panel.example.com"
else
  bad "自签证书未生成"
fi

say '== 5c. 证书：CN 没变就复用（不许每次重生成 / 悄悄替回自签）=='
serial() { openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -serial 2>/dev/null || true; }
before=$(serial)
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "同域名重跑退出码 0" "$rc" "0"
chk "证书序列号未变（确认没被重生成）" "$(serial)" "$before"
chk_has "如实说明复用了已有证书" "$out" "复用已有证书"

# 反面：换域名必须重建。若复用旧 CN 的证书，用户握手时会看到域名不匹配，
# 而"脚本说成功了"——这是最容易被忽略的假成功。
out=$(bash "$SCRIPT" -d other.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "换域名后退出码 0" "$rc" "0"
if [ "$(serial)" != "$before" ]; then ok "换域名后重建了证书"; else bad "换域名后证书没重建（会带着旧 CN 对外）"; fi
chk_has "新证书 CN 是新域名" "$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -subject 2>/dev/null || true)" "other.example.com"

# 顺序断言：不许还没 -t 就去 reload
calls=$(cat /tmp/e2e-shim/calls.log 2>/dev/null)
i_t=$(printf '%s\n' "$calls" | grep -n '^nginx -t' | head -1 | cut -d: -f1)
i_reload=$(printf '%s\n' "$calls" | grep -n 'reload' | head -1 | cut -d: -f1)
if [ -n "$i_t" ] && [ -n "$i_reload" ] && [ "$i_t" -lt "$i_reload" ]; then
  ok "nginx -t 在 reload 之前（不在滚动的基础上重载）"
else
  bad "调用顺序不对：-t 应在 reload 之前；实际=[$calls]"
fi

# 80 端口的 server 块本来就是本脚本生成的（ACME HTTP-01 挑战落在 80），
# 只放行 443 的表现是"现在一切正常、三个月后续不上才炸"。
chk_has "防火墙放行 80（否则证书续期必然失败）" "$calls" "ufw allow 80/tcp"
chk_has "防火墙放行 443"                    "$calls" "ufw allow 443/tcp"

# 脚本绝不许替用户把面板改成对外绑定
chk_has "面板配置仍绑回环（脚本不得改面板绑定）" "$(cat /etc/forkpanel/config.toml)" "127.0.0.1"
chk_has "localhost_only 仍为 true" "$(cat /etc/forkpanel/config.toml)" "localhost_only = true"

say '== 5b. WEBROOT 建不出来时只警告，不许把主线活搞黄 =='
rm -rf /var/www/html
# ⚠ 用"占位文件"让它必定建不出来：本 E2E 跑在 user namespace 里**就是 root**，
#   `chmod 555` 拦不住 root（CAP_DAC_OVERRIDE）——上一版用例因此从未走进警告分支，
#   而断言写的是源码里的变量名 WEBROOT、不是脚本真实打印的那句话，两边一凑就成了
#   "看起来在测、实际什么都没测到"。现在两条都改成真的。
: > /var/www/html
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
rm -f /var/www/html
chk "WEBROOT 不可创建仍能完成反代" "$rc" "0"
# 判据指向**脚本真打出来的那句话**，别拿源码标识符当判据（它不会出现在输出里）
chk_has "如实提示 WEBROOT 不可用" "$out" "无法创建 /var/www/html"
[ -f "$NGINX_CONF" ] && ok "配置照常生成" || bad "WEBROOT 失败连带配置也没生成"
mkdir -p /var/www/html

# ── 6. nginx -t 失败必须回滚，不许留坏配置 ─────────────────────────────
# ⚠ conf.d 里一个语法错误会让**整台 nginx 起不来**，本机其它站点一起陪葬。
#   宁可回滚到"没配过"，也不能留个坏文件。
# 回滚还必须**退回上一份能用**的配置，而不是删掉文件：二次改参数失败时，
# 删文件会把用户正跑着的反代一起弄没 —— 比不做还糟。
say "== 6a. 已有旧配置时 -t 失败 → 必须还原上一份可用配置 =="
good=$(cat "$NGINX_CONF" 2>/dev/null || true)
[ -n "$good" ] && ok "前置：失败前已存在可用配置" || bad "前置失败：第 5 节未留下配置"
NX_T_FAIL=1
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok "nginx -t 失败时退出非 0" || bad "nginx -t 失败却返回 0"
chk "失败后内容还原为上一份可用配置" "$(cat "$NGINX_CONF" 2>/dev/null || true)" "$good"
chk_has "输出明确说明已还原" "$out" "还原"
NX_T_FAIL=0

say "== 6b. 此前没有配置时 -t 失败 → 不许留半截文件 =="
rm -f "$NGINX_CONF"
NX_T_FAIL=1
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
[ -f "$NGINX_CONF" ] && bad "首次失败却留下了配置文件" || ok "首次失败已删除未通过校验的文件"
NX_T_FAIL=0

# D 的守卫：以前 `|| true` 会把 reload 失败吞掉却仍打印"已重载"——这是文案撒谎，
# 必须钉住"失败要说出来"。
say "== 6c. reload 失败必须说出来（不许被 || true 吞掉）=="
# 两条重载路径都要失败（systemctl reload 与 nginx -s reload），
# 否则在装了 systemd 的机器上永远命中 systemctl 那条、测不到警告。
SYS_RELOAD_FAIL=1
NX_RELOAD_FAIL=1
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "reload 失败时脚本仍如实退出 0（配置已落盘）" "$rc" "0"
chk_has "明确提示重载失败" "$out" "重载失败"
SYS_RELOAD_FAIL=0
NX_RELOAD_FAIL=0

# ── 7. 卸载必须清干净 ──────────────────────────────────────────────────
say "== 7. --uninstall 必须撤得干净（且不动面板绑定）=="
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
[ -f "$NGINX_CONF" ] && ok "卸载前配置存在（前置）" || bad "前置失败：配置没生成"
out=$(bash "$SCRIPT" --uninstall 2>&1); rc=$?
chk "卸载退出码 0" "$rc" "0"
[ -f "$NGINX_CONF" ] && bad "卸载后 nginx 配置仍在" || ok "nginx 配置已移除"
[ -f /etc/systemd/system/panel.service.d/panel-tls.conf ] \
  && bad "卸载后 PANEL_TLS drop-in 仍在" || ok "PANEL_TLS drop-in 已移除"
chk_has "面板配置仍绑回环" "$(cat /etc/forkpanel/config.toml)" "127.0.0.1"

# ── 8. TOML 取值：只看 [server] 表 ────────────────────────────────────
# 以前是全文件 grep 第一个 `^port` 再 head -1：配置一缩进就读不到（误判"面板没配"），
# 而别的表先出现 port 时又会拿错表的值 —— 拿错端口的下游后果是 WS / SSE 全都连错。
say '== 8. [server] 端口取值：缩进 / 别的表在前 / 行尾注释都要读对 =='
CFG=/etc/forkpanel/config.toml
cp -a "$CFG" /tmp/e2e-shim/config.toml.bak
SS_HDR="State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port"
probe() { printf '%s\n' "$1" > "$CFG"; setss probe "$SS_HDR" "LISTEN  0  128  127.0.0.1:$PORT  0.0.0.0:*"; }

probe "[db]
port = 5432

  [server]
    bind = \"127.0.0.1\"
    port = $PORT   # 面板端口
    localhost_only = true
"
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "缩进+别表在前+行尾注释仍能读对" "$rc" "0"
chk_has "取到的是 [server] 的 $PORT 而非 [db] 的 5432" "$out" "127.0.0.1:$PORT"

probe "[server]
bind = \"127.0.0.1\"
localhost_only = true
"
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "[server] 里没配 port 必须拒绝" "$rc" "1"
chk_has "拒绝原因指向 [server] 表" "$out" "[server]"

probe "[db]
port = 5432
"
out=$(bash "$SCRIPT" -d panel.example.com -a 203.0.113.0/24 2>&1); rc=$?
chk "连 [server] 表都没有必须拒绝" "$rc" "1"

cp -a /tmp/e2e-shim/config.toml.bak "$CFG"

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP ────────"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
INNER
rc=$?

if [ "$rc" -eq 0 ]; then
  say ""
  say "PASS：公网暴露脚本的三条 fail-closed、坏配置回滚与卸载均已钉住"
fi
exit "$rc"
