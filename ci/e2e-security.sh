#!/usr/bin/env bash
# 安全域 E2E（WAF 模板 / 拦截事件 / 告警配置 + 安全中心基线 / 在线会话）：
# 对**运行中的 dev 后端**打真实请求。
#
# ## 为什么需要
# 这四块都是安全面，且单测只覆盖纯逻辑：
#  - WAF 模板是"一套生效的 WAF 预设"，保存后被站点 apply 引用；模板校验（profile /
#    限速上限 / IP 列表）错放行，等于把坏配置带进 nginx。
#  - 拦截事件是审计证据，过滤条件写错会让"看起来没有攻击"。
#  - 告警阈值/窗宽越界会让告警永不触发或刷屏。
#  - 安全中心：基线修复会**写回系统 sshd 配置**，会话吊销会**踢人下线**——这两处
#    的闸门（确认词 / 404）必须在真机验过。
#
# ## ⚠️ 刻意不做什么
#  - **绝不**用正确确认词调 `POST /security/baseline/apply`（会写回 sshd 配置，高危）。
#    只验"错误确认词 → 10001"这道闸门。
#  - 告警 PUT 只**原值回写**（幂等，无净变更），不做会改变 dev 配置的写入。
#  - 会话吊销只吊销**本次自己新建的第二个会话**（先算差集，绝不碰别人的会话）。
#
# ## 用法
#   ci/e2e-security.sh [base_url]   默认 http://127.0.0.1:2083
#   凭据：PANEL_E2E_USER / PANEL_E2E_PASS（默认 admin / DevPreview2026x）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
CJ=$(mktemp); CJ2=$(mktemp)
PASS=0; FAIL=0
CSRF=""; CSRF2=""
MARK="$$$(date +%s)"
TPL="e2e_tpl_${MARK}"          # ≤64 字
TPL2="e2e_tpl_${MARK}_r"
TPL_ID=""; NEW_SID=""

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }

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
put_cmd() { curl -s -b "$CJ" -X PUT "$B/api/v1$1" -H 'Content-Type: application/json' \
           -H "x-csrf-token: $CSRF" -d "$2"; }
patch_cmd() { curl -s -b "$CJ" -X PATCH "$B/api/v1$1" -H 'Content-Type: application/json' \
           -H "x-csrf-token: $CSRF" -d "$2"; }
del_body() { curl -s -b "$CJ" -X DELETE "$B/api/v1$1" -H "x-csrf-token: $CSRF"; }
get()  { curl -s -b "$CJ" "$B/api/v1$1"; }

cleanup() {
  # 模板兜底删除（按名找 id）；会话兜底吊销（只吊销我们算出来的那个新 sid）
  if [ -n "$TPL_ID" ]; then
    curl -s -o /dev/null -b "$CJ" -X DELETE "$B/api/v1/waf/templates/$TPL_ID" -H "x-csrf-token: $CSRF" 2>/dev/null || true
  fi
  if [ -n "$NEW_SID" ]; then
    curl -s -o /dev/null -b "$CJ" -X DELETE "$B/api/v1/security/sessions/$NEW_SID" -H "x-csrf-token: $CSRF" 2>/dev/null || true
  fi
  rm -f "$CJ" "$CJ2" 2>/dev/null
}
trap cleanup EXIT

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

say "=== 1. WAF 模板：校验闸门 + CRUD ==="
chk "GET /waf/templates code=0" "$(get /waf/templates | jcode)" "0"
chk "空模板名 → 10001" "$(post /waf/templates '{"name":""}' | jcode)" "10001"
LONGN=$(python3 -c 'print("x"*65)')
chk "模板名超长(65) → 10001" "$(post /waf/templates "{\"name\":\"$LONGN\"}" | jcode)" "10001"
chk "非法 profile → 10001" "$(post /waf/templates "{\"name\":\"$TPL\",\"profile\":\"extreme\"}" | jcode)" "10001"
chk "限速超上限(1001) → 10001" "$(post /waf/templates "{\"name\":\"$TPL\",\"rate_per_sec\":1001}" | jcode)" "10001"
chk "burst 超上限(10001) → 10001" "$(post /waf/templates "{\"name\":\"$TPL\",\"burst\":10001}" | jcode)" "10001"
chk "非法 IP 列表 → 10001" "$(post /waf/templates "{\"name\":\"$TPL\",\"ip_allow\":\"not-an-ip\"}" | jcode)" "10001"
chk "创建合法模板 → code 0" "$(post /waf/templates "{\"name\":\"$TPL\",\"profile\":\"basic\",\"rate_per_sec\":10,\"burst\":20,\"ip_allow\":\"10.0.0.0/8\",\"ip_deny\":\"192.168.0.1\"}" | jcode)" "0"
TPL_ID=$(get /waf/templates | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; t=next((x for x in d if x["name"]==sys.argv[1]),None)
print(t["id"] if t else "")' "$TPL")
if [ -n "$TPL_ID" ]; then PASS=$((PASS+1)); say "  ✓ 列表含新模板 id=$TPL_ID"
else FAIL=$((FAIL+1)); say "  ✗ 列表里找不到新模板 $TPL"; fi
chk "详情字段正确（basic/10/20/ip）" "$(get "/waf/templates/$TPL_ID" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
ok = d.get("waf_profile")=="basic" and d.get("rate_per_sec")==10 and d.get("burst")==20 and d.get("ip_allow")==["10.0.0.0/8"] and d.get("ip_deny")==["192.168.0.1"]
print("ok" if ok else "bad")')" "ok"
chk "重名创建 → 409" "$(post /waf/templates "{\"name\":\"$TPL\"}" | jcode)" "10005"
chk "PATCH 改名+改档 → code 0" "$(patch_cmd "/waf/templates/$TPL_ID" "{\"name\":\"$TPL2\",\"profile\":\"strict\",\"rate_per_sec\":5,\"burst\":5}" | jcode)" "0"
chk "PATCH 生效（strict/5）" "$(get "/waf/templates/$TPL_ID" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("ok" if d.get("name")==sys.argv[1] and d.get("waf_profile")=="strict" and d.get("rate_per_sec")==5 else "bad")' "$TPL2")" "ok"
chk "PATCH 不存在 → 404" "$(patch_cmd /waf/templates/99999999 '{"name":"x"}' | jcode)" "10004"
chk "GET 不存在 → 404" "$(get /waf/templates/99999999 | jcode)" "10004"
chk "DELETE 不存在 → 404" "$(del_body /waf/templates/99999999 | jcode)" "10004"
chk "DELETE 模板 → code 0" "$(del_body "/waf/templates/$TPL_ID" | jcode)" "0"
TPL_ID=""
chk "删除后列表不含该模板" "$(get /waf/templates | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];print("no" if any(x["name"]==sys.argv[1] for x in d) else "yes")' "$TPL2")" "yes"

say "=== 2. WAF 拦截事件（只读 + 过滤）==="
r=$(get /waf/events); chk "GET /waf/events code=0" "$(echo "$r" | jcode)" "0"
chk "events 返回数组" "$(echo "$r" | python3 -c 'import sys,json;print("yes" if isinstance(json.load(sys.stdin)["data"],list) else "no")')" "yes"
chk "按不存在的站点过滤 → 空数组" "$(get "/waf/events?site=__no_such_site__" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["data"]))')" "0"
chk "limit=1 生效" "$(get "/waf/events?limit=1" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["data"]) <= 1)')" "True"

say "=== 3. WAF 告警配置（越界拒绝 + 原值回写）==="
r=$(get /waf/alert); chk "GET /waf/alert code=0" "$(echo "$r" | jcode)" "0"
chk "含 enabled/threshold/window_min" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];print("ok" if all(k in d for k in ("enabled","threshold","window_min")) else "bad")')" "ok"
chk "threshold=0 越界 → 10001" "$(put_cmd /waf/alert '{"threshold":0}' | jcode)" "10001"
chk "threshold=100001 越界 → 10001" "$(put_cmd /waf/alert '{"threshold":100001}' | jcode)" "10001"
chk "window_min=0 越界 → 10001" "$(put_cmd /waf/alert '{"window_min":0}' | jcode)" "10001"
chk "window_min=1441 越界 → 10001" "$(put_cmd /waf/alert '{"window_min":1441}' | jcode)" "10001"
# 原值回写（幂等，无净变更）
ALERT_SAME=$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
print(json.dumps({"enabled": d["enabled"], "threshold": d["threshold"], "window_min": d["window_min"]}))')
chk "原值回写 → code 0" "$(put_cmd /waf/alert "$ALERT_SAME" | jcode)" "0"
chk "回写后值未变" "$(get /waf/alert | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
print(json.dumps({"enabled": d["enabled"], "threshold": d["threshold"], "window_min": d["window_min"]}, sort_keys=True))')" "$(printf '%s' "$ALERT_SAME" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin), sort_keys=True))')"

say "=== 4. 安全基线（只读 + 确认词闸门）==="
r=$(get /security/baseline); chk "GET /security/baseline code=0" "$(echo "$r" | jcode)" "0"
chk "baseline 返回数组且条目含 key/ok" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
print("ok" if isinstance(d,list) and (not d or ("key" in d[0] and "ok" in d[0])) else "bad")')" "ok"
chk "错误确认词调修复 → 10001（不触达 sshd）" "$(post /security/baseline/apply '{"key":"ssh.permit_root_login","confirm_token":"确认"}' | jcode)" "10001"
chk "缺确认词 → 10001" "$(post /security/baseline/apply '{"key":"ssh.permit_root_login","confirm_token":""}' | jcode)" "10001"

say "=== 5. 在线会话（读 + 只吊销自己新建的会话）==="
r=$(get /security/sessions); chk "GET /security/sessions code=0" "$(echo "$r" | jcode)" "0"
chk "sessions 形状 + 恰一个 current" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; s=d.get("sessions") or []
print("ok" if isinstance(s,list) and sum(1 for x in s if x.get("current"))==1 and "total" in d else "bad")')" "ok"
chk "吊销不存在会话 → 404" "$(del_body /security/sessions/__no_such_sid__ | jcode)" "10004"
BEFORE=$(get /security/sessions | python3 -c 'import sys,json
print("\n".join(x["id"] for x in json.load(sys.stdin)["data"]["sessions"]))')
# 第二个会话（同一账号）；登录会新建一个 sid
curl -s -c "$CJ2" -X POST "$B/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}" > /dev/null
AFTER=$(get /security/sessions | python3 -c 'import sys,json
print("\n".join(x["id"] for x in json.load(sys.stdin)["data"]["sessions"]))')
NEW_SID=$(python3 -c '
import sys
before=set(sys.argv[1].split())
after=sys.argv[2].split()
new=[x for x in after if x not in before]
print(new[0] if new else "")' "$BEFORE" "$AFTER")
if [ -n "$NEW_SID" ]; then PASS=$((PASS+1)); say "  ✓ 第二个会话已建立（差集识别）"
else FAIL=$((FAIL+1)); say "  ✗ 无法识别新增会话（不吊销任何会话以免误伤）"; fi
if [ -n "$NEW_SID" ]; then
  chk "吊销新会话 → 204" "$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X DELETE "$B/api/v1/security/sessions/$NEW_SID" -H "x-csrf-token: $CSRF")" "204"
  chk "吊销后不再出现" "$(get /security/sessions | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]["sessions"];print("yes" if any(x["id"]==sys.argv[1] for x in d) else "no")' "$NEW_SID")" "no"
  NEW_SID=""
fi

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
