#!/usr/bin/env bash
# 可观测与轻管理面 E2E（系统概览 / 指标 / 日志 / 通知 / 便签 / 任务中心）：
# 对**运行中的 dev 后端**打真实请求。补上九域 E2E 未覆盖的最后一组路由域。
#
# ## 为什么需要
# 剩下这五个域（system / logs / notifications / notes / tasks）此前**没有任何端到端
# 覆盖**，而它们恰好是"面板自己的门面"：概览数字、日志源、通知未读数、便签、任务中心。
# 这类面最容易出现两种病：①**能力位/权限位没接对**（读得到但没数据、或越权可读）；
# ②**诚实降级被当成真实数据**（比如日志源读失败却返回空列表，看起来像"没有日志"）。
#
# ## 纪律
#  - **只读为主**：只有"本机便签"走完整生命周期（本地数据，结尾删净）。
#    明确**不做**：通知 read-all（会把所有通知标已读，破坏用户可见状态）、
#    任务 cancel（会打断真实任务）、日志 download（落文件）。
#  - 涉及"不存在 id"的写端点（标已读 / 删除 / 取消）**只打不存在的 id**：
#    既验证 404，又绝不碰到真实对象。
#  - 每条断言钉死**具体 code**，不用"期望非 0"（404 会冒充业务拒绝码）。
#
# ## 用法
#   ci/e2e-observe.sh [base_url]   默认 http://127.0.0.1:2083
#   凭据：PANEL_E2E_USER / PANEL_E2E_PASS（默认 admin / DevPreview2026x）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
CJ=$(mktemp)
PASS=0; FAIL=0
CSRF=""
MARK="$$$(date +%s)"
NOTE_CONTENT="e2e note ${MARK}"
NOTE_ID=""

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
patch_cmd() { curl -s -b "$CJ" -X PATCH "$B/api/v1$1" -H 'Content-Type: application/json' \
           -H "x-csrf-token: $CSRF" -d "$2"; }
del_body() { curl -s -b "$CJ" -X DELETE "$B/api/v1$1" -H "x-csrf-token: $CSRF"; }
get()  { curl -s -b "$CJ" "$B/api/v1$1"; }

cleanup() {
  # 便签兜底删除（只删本次自己建的那条）
  if [ -n "$NOTE_ID" ]; then
    curl -s -o /dev/null -b "$CJ" -X DELETE "$B/api/v1/server/notes/$NOTE_ID" -H "x-csrf-token: $CSRF" 2>/dev/null || true
  fi
  rm -f "$CJ" 2>/dev/null
}
trap cleanup EXIT

if ! curl -s -m 3 "$B/api/v1/version" > /dev/null; then
  say "[skip] 后端不可达：$B —— 本脚本未验证任何东西（请先启动 dev 服务）"
  exit 0
fi
# 能力位是否可用（1=可用）。能力位 key 是**字面量带点**（如 "logs.read"），不是嵌套
# 结构 ⇒ 不能用点号路径取。
cap_supported() { # $1 = 能力位 key
  get /system/capabilities | python3 -c '
import sys,json
f=(json.load(sys.stdin)["data"]["features"].get(sys.argv[1]) or {})
print("1" if f.get("supported") else "0")' "$1"
}
cap_reason() { # $1 = 能力位 key
  get /system/capabilities | python3 -c '
import sys,json
f=(json.load(sys.stdin)["data"]["features"].get(sys.argv[1]) or {})
print(f.get("reason") or "")' "$1"
}

say "=== 0. 登录 $B ==="
curl -s -c "$CJ" -X POST "$B/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}" > /dev/null
CSRF=$(awk '$6=="panel_csrf"{print $7}' "$CJ")
if [ -z "$CSRF" ]; then say "  ✗ 登录失败或拿不到 panel_csrf"; exit 1; fi
say "  ✓ 已登录（csrf=${CSRF:0:8}…）"

say "=== 1. 系统概览与指标（只读）==="
r=$(get /system/overview); chk "GET /system/overview code=0" "$(echo "$r" | jcode)" "0"
chk "overview 字段齐全（cpu/内存/磁盘/档位/运行时长）" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
need=["cpu_pct","mem_used_kib","mem_total_kib","disk_total_bytes","tier","uptime_sec","ts"]
print("ok" if all(k in d for k in need) and isinstance(d["tier"],str) else "bad")')" "ok"
r=$(get /system/capabilities); chk "GET /system/capabilities code=0" "$(echo "$r" | jcode)" "0"
chk "capabilities 含 features 与 limits" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("ok" if isinstance(d.get("features"),dict) and isinstance(d.get("limits"),dict) else "bad")')" "ok"
r=$(get /metrics/realtime); chk "GET /metrics/realtime code=0" "$(echo "$r" | jcode)" "0"
chk "realtime 含 interval_ms + samples" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("ok" if isinstance(d.get("interval_ms"),int) and isinstance(d.get("samples"),list) else "bad")')" "ok"
r=$(get "/metrics/history?gran=1m"); chk "history gran=1m code=0" "$(echo "$r" | jcode)" "0"
chk "history granularity 回显 1m" "$(echo "$r" | jget granularity)" "1m"
r=$(get "/metrics/history?gran=1h"); chk "history gran=1h granularity 回显" "$(echo "$r" | jget granularity)" "1h"
chk "history gran 非法 → 10001" "$(get "/metrics/history?gran=bogus" | jcode)" "10001"
r=$(get /system/directories); chk "GET /system/directories code=0" "$(echo "$r" | jcode)" "0"
chk "directories 含 frontend_embedded 布尔" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("ok" if isinstance(d.get("frontend_embedded"),bool) and isinstance(d.get("groups"),list) else "bad")')" "ok"
chk "GET /system/users code=0" "$(get /system/users | jcode)" "0"

say "=== 2. 日志源与日志读取（只读 + 拒绝分支）==="
CAP_LOGS=$(cap_supported "logs.read")
LOGS_REASON=$(cap_reason "logs.read")
if [ "$CAP_LOGS" = "1" ]; then
r=$(get /logs/sources); chk "GET /logs/sources code=0" "$(echo "$r" | jcode)" "0"
chk "sources 含 backend + 源列表（id/kind/label）" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; s=d.get("sources") or []
print("ok" if d.get("backend") and s and all(("id" in x and "kind" in x and "label" in x) for x in s) else "bad")')" "ok"
r=$(get "/logs/system?lines=3"); chk "GET /logs/system code=0" "$(echo "$r" | jcode)" "0"
chk "日志行含 ts/level/text + capped 布尔" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; l=d.get("lines")
print("ok" if isinstance(l,list) and isinstance(d.get("capped"),bool) and (not l or all(("ts" in x and "level" in x and "text" in x) for x in l)) else "bad")')" "ok"
r=$(get "/logs/system/stats"); chk "GET /logs/system/stats code=0" "$(echo "$r" | jcode)" "0"
chk "stats 含 histogram 数组" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("ok" if isinstance(d.get("histogram"),list) else "bad")')" "ok"
chk "未知日志源 → 404" "$(get /logs/no_such_source | jcode)" "10004"
GREP300=$(python3 -c 'print("x"*300)')
chk "grep 超长(300>256) → 10001" "$(get "/logs/system?grep=$GREP300" | jcode)" "10001"

else
  # 能力位缺失（CI runner 常无 journald）：**只验诚实 501**，并显式标记本段
  # 「降级」——不让 CI 绿得让人误以为日志读面也验过了。
  r=$(get /logs/sources)
  chk "无日志能力位时 /logs/sources 诚实 501" "$(echo "$r" | jcode)" "10009"
  say "  [降级] 可观测域·日志段：能力位 logs.read 不可用（reason=${LOGS_REASON:-<none>}）——**日志读面未覆盖**"
fi
say "=== 3. 通知（只读 + 只碰不存在的 id）==="
r=$(get /notifications); chk "GET /notifications code=0" "$(echo "$r" | jcode)" "0"
chk "通知条目含 id/level/read/title" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
print("ok" if isinstance(d,list) and (not d or all(("id" in x and "level" in x and "read" in x and "title" in x) for x in d)) else "bad")')" "ok"
r=$(get /notifications/unread-count); chk "GET /notifications/unread-count code=0" "$(echo "$r" | jcode)" "0"
chk "unread count 是非负整数" "$(echo "$r" | python3 -c 'import sys,json
c=json.load(sys.stdin)["data"]["count"]; print("ok" if isinstance(c,int) and c>=0 else "bad")')" "ok"
chk "标记不存在的通知已读 → 404" "$(post /notifications/999999/read '{}' | jcode)" "10004"
chk "删除不存在的通知 → 404" "$(del_body /notifications/999999 | jcode)" "10004"

say "=== 4. 本机便签（完整生命周期，结尾删净）==="
r=$(get /server/notes); chk "GET /server/notes code=0" "$(echo "$r" | jcode)" "0"
chk "便签条目含 id/content/updated_at" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("ok" if isinstance(d,list) and (not d or all(("id" in x and "content" in x and "updated_at" in x) for x in d)) else "bad")')" "ok"
chk "空内容 → 10001" "$(post /server/notes '{"content":"  "}' | jcode)" "10001"
LONG500=$(python3 -c 'print("x"*501)')
chk "内容超 500 字 → 10001" "$(post /server/notes "{\"content\":\"$LONG500\"}" | jcode)" "10001"
chk "创建便签 → code 0" "$(post /server/notes "{\"content\":\"$NOTE_CONTENT\"}" | jcode)" "0"
NOTE_ID=$(get /server/notes | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print(next((x["id"] for x in d if x["content"]==sys.argv[1]), ""))' "$NOTE_CONTENT")
if [ -n "$NOTE_ID" ]; then PASS=$((PASS+1)); say "  ✓ 列表含新便签 id=$NOTE_ID"
else FAIL=$((FAIL+1)); say "  ✗ 列表里找不到新便签"; fi
chk "PATCH 便签 → code 0" "$(patch_cmd "/server/notes/$NOTE_ID" "{\"content\":\"$NOTE_CONTENT v2\"}" | jcode)" "0"
chk "便签内容已更新" "$(get /server/notes | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("yes" if any(x["content"]==sys.argv[1] for x in d) else "no")' "$NOTE_CONTENT v2")" "yes"
chk "删除不存在的便签 → 404" "$(del_body /server/notes/999999 | jcode)" "10004"
chk "删除便签 → code 0" "$(del_body "/server/notes/$NOTE_ID" | jcode)" "0"
NOTE_ID=""
chk "删除后列表不再含它" "$(get /server/notes | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("no" if any(x["content"].startswith(sys.argv[1]) for x in d) else "yes")' "$NOTE_CONTENT")" "yes"

say "=== 5. 任务中心（只读）==="
r=$(get /tasks); chk "GET /tasks code=0" "$(echo "$r" | jcode)" "0"
chk "任务条目含 id/state/kind/key" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("ok" if isinstance(d,list) and (not d or all(("id" in x and "state" in x and "kind" in x and "key" in x) for x in d)) else "bad")')" "ok"
TID=$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print(d[0]["id"] if d else "")')
if [ -n "$TID" ]; then
  chk "GET /tasks/{id} code=0" "$(get "/tasks/$TID" | jcode)" "0"
  chk "任务详情含 id/state" "$(get "/tasks/$TID" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; print("ok" if "id" in d and "state" in d else "bad")')" "ok"
  chk "GET /tasks/{id}/output code=0" "$(get "/tasks/$TID/output" | jcode)" "0"
else
  say "  · 任务队列为空，跳过单任务详情断言"
fi
chk "GET /tasks/99999999 → 404" "$(get /tasks/99999999 | jcode)" "10004"
chk "GET /tasks/99999999/output → 404" "$(get /tasks/99999999/output | jcode)" "10004"
chk "取消不存在的任务 → 404（不碰真实任务）" "$(post /tasks/99999999/cancel '{}' | jcode)" "10004"

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
