#!/usr/bin/env bash
# 防火墙（firewall）E2E：对**运行中的 dev 后端**打真实请求，
# 覆盖能力位门禁 + 只读端点 + apply 校验闸门（含 SSH 失联保护）+ fail2ban 诚实 501。
#
# ## 为什么需要
# 防火墙是**最高风险模块**（三条硬约束：改前快照 / 只管自己写的规则 / SSH 端口保护）。
# 规则解析（ports / CIDR / action）与 SSH 失联保护是安全面，单测覆盖了纯函数，
# 但覆盖不到「路由注册 + 能力位门禁 + 校验在 snapshot() 之前挡回」这条端到端链路。
#
# ## ⚠️ 刻意不做什么（安全纪律，比其它 E2E 更硬）
#  dev 主机防火墙后端**真实在场**（firewall.manage=True，iptables/nft 在 /usr/sbin，
#  交互 PATH 没有 ⇒ `which` 会误判缺失）。因此本脚本**绝不**：
#   · 提交**合法**规则（会真的写 iptables/nft）；
#   · 带 allow_lockout_risk=true 的封端口规则（会真的封端口）；
#   · 调 set_enabled / set_active / delete_rule（会真的改防火墙状态/删规则）。
#  只测：能力位、只读端点、以及**全部在 snapshot() 之前返回**的拒绝分支（零残留）。
#  每条拒绝分支都钉死**具体 code**（不用 chk_ne）——否则 URL 写错命中 404 会假绿。
#
# ## 用法
#   ci/e2e-firewall.sh [base_url]   默认 http://127.0.0.1:2083
#   凭据走环境变量：PANEL_E2E_USER / PANEL_E2E_PASS（默认 admin / DevPreview2026x）
#
# ## 依赖
#   curl、python3（解析 JSON；不依赖 jq）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
CJ=$(mktemp)
PASS=0; FAIL=0

cleanup() { rm -f "$CJ" 2>/dev/null; }
trap cleanup EXIT

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }
chk_bool() { if [ "$2" = "True" ] || [ "$2" = "False" ]; then PASS=$((PASS+1)); say "  ✓ $1 ($2)"
            else FAIL=$((FAIL+1)); say "  ✗ $1  期望布尔 实际=[$2]"; fi; }

jcode() { python3 -c 'import sys,json;print(json.load(sys.stdin).get("code"))'; }
jget() { python3 -c 'import sys,json
d=json.load(sys.stdin)
if isinstance(d,dict) and "data" in d: d=d["data"]
p=sys.argv[1].split(".")
for k in p:
    if d is None: break
    d = d[int(k)] if isinstance(d,list) else d.get(k)
print("" if d is None else d)' "$1"; }

post() { curl -s -b "$CJ" -X POST "$B/api/v1$1" -H 'Content-Type: application/json' \
           -H "x-csrf-token: $CSRF" -d "$2"; }
get()  { curl -s -b "$CJ" "$B/api/v1$1"; }

# ── 0. 探活 + 登录 ──
if ! curl -s -m 3 "$B/api/v1/version" > /dev/null; then
  say "[skip] 后端不可达：$B —— 本脚本未验证任何东西（请先启动 dev 服务）"
  exit 0
fi
say "=== 0. 登录 $B ==="
curl -s -c "$CJ" -X POST "$B/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}" > /dev/null
CSRF=$(awk '$6=="panel_csrf"{print $7}' "$CJ")
if [ -z "$CSRF" ]; then say "  ✗ 登录失败或拿不到 panel_csrf"; exit 1; fi
say "  ✓ 已登录（csrf=${CSRF:0:8}…）"

say "=== 1. 能力位门禁（firewall.manage / fail2ban.manage）==="
CAPF=$(mktemp); get /system/capabilities > "$CAPF"
fw_sup=$(python3 -c 'import sys,json;f=json.load(open(sys.argv[1]))["data"]["features"].get("firewall.manage") or {};print("True" if f.get("supported") else "False")' "$CAPF")
f2b_sup=$(python3 -c 'import sys,json;f=json.load(open(sys.argv[1]))["data"]["features"].get("fail2ban.manage") or {};print("True" if f.get("supported") else "False")' "$CAPF")
f2b_reason=$(python3 -c 'import sys,json;f=json.load(open(sys.argv[1]))["data"]["features"].get("fail2ban.manage") or {};print(f.get("reason") or "")' "$CAPF")
rm -f "$CAPF"
chk_bool "capabilities.features.firewall.manage.supported 是布尔" "$fw_sup"
chk_bool "capabilities.features.fail2ban.manage.supported 是布尔" "$f2b_sup"
say "  · firewall.manage=$fw_sup  fail2ban.manage=$f2b_sup (reason=${f2b_reason:-<none>})"

# firewall.manage 不可用：读/写端点一律诚实 501。到此为止，不恒绿。
if [ "$fw_sup" != "True" ]; then
  say "  [warn] firewall.manage 不支持 —— 只验证 501 诚实闸门"
  chk "GET /firewall/status 诚实 501" "$(get /firewall/status | jcode)" "10009"
  chk "GET /firewall/rules 诚实 501" "$(get /firewall/rules | jcode)" "10009"
  chk "POST /firewall/rules 诚实 501" "$(post /firewall/rules '{"rules":[{"ports":"80"}]}' | jcode)" "10009"
  say ""
  say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
  [ "$FAIL" -eq 0 ] || exit 1
  exit 0
fi

say "=== 2. 只读端点（状态 / 规则清单）==="
r=$(get /firewall/status); chk "GET /firewall/status code=0" "$(echo "$r" | jcode)" "0"
chk_bool "status.active 是布尔" "$(echo "$r" | python3 -c 'import sys,json;print(str(json.load(sys.stdin)["data"].get("active")))')"
be=$(echo "$r" | jget backend)
case "$be" in
  nftables|iptables|ufw|firewalld|wf|pf|none) PASS=$((PASS+1)); say "  ✓ status.backend 已知（$be）";;
  *) FAIL=$((FAIL+1)); say "  ✗ status.backend 非预期：$be";;
esac
r=$(get /firewall/rules); chk "GET /firewall/rules code=0" "$(echo "$r" | jcode)" "0"
chk "rules 响应含 backend/active/rules" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
print("ok" if isinstance(d.get("backend"),str) and isinstance(d.get("active"),bool) and isinstance(d.get("rules"),list) else "bad")')" "ok"

say "=== 3. apply 校验闸门（拒绝分支，全部在 snapshot() 之前挡回，零残留）==="
# 端口非法：越界 / 区间倒挂
r=$(post /firewall/rules '{"rules":[{"ports":"99999"}]}');    chk "非法端口（越界）→ 10001" "$(echo "$r" | jcode)" "10001"
r=$(post /firewall/rules '{"rules":[{"ports":"80-70"}]}');    chk "非法端口（区间倒挂）→ 10001" "$(echo "$r" | jcode)" "10001"
# 源地址非法：非 IP / 前缀越界
r=$(post /firewall/rules '{"rules":[{"ports":"80","source":"999.999.999.999"}]}'); chk "非法 CIDR（非 IP）→ 10001" "$(echo "$r" | jcode)" "10001"
r=$(post /firewall/rules '{"rules":[{"ports":"80","source":"1.2.3.4/99"}]}');       chk "非法 CIDR（前缀越界）→ 10001" "$(echo "$r" | jcode)" "10001"
# 动作非法
r=$(post /firewall/rules '{"rules":[{"ports":"80","action":"drop"}]}');             chk "未知动作 → 10001" "$(echo "$r" | jcode)" "10001"
# SSH 失联保护：封 22 且未显式 allow_lockout_risk ⇒ 冲突（10005），不碰防火墙
r=$(post /firewall/rules '{"rules":[{"ports":"22","action":"deny"}]}');             chk "封 SSH(22) 未确认 → 冲突 10005" "$(echo "$r" | jcode)" "10005"
r=$(post /firewall/rules '{"rules":[{"ports":"1-65535","action":"reject"}]}');      chk "封全端口未确认 → 冲突 10005" "$(echo "$r" | jcode)" "10005"

say "=== 4. fail2ban 诚实闸门 ==="
if [ "$f2b_sup" = "True" ]; then
  # 有 fail2ban：只读 status 安全；jail/unban 是写，不调
  r=$(get /firewall/fail2ban); chk "GET /firewall/fail2ban code=0" "$(echo "$r" | jcode)" "0"
else
  chk "GET /firewall/fail2ban 诚实 501（binary_missing）" "$(get /firewall/fail2ban | jcode)" "10009"
  chk "POST fail2ban/jail 诚实 501" "$(post /firewall/fail2ban/jail '{"name":"sshd","enabled":true}' | jcode)" "10009"
  chk "POST fail2ban/unban 诚实 501" "$(post /firewall/fail2ban/unban '{"jail":"sshd","ip":"1.2.3.4"}' | jcode)" "10009"
fi

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
