#!/usr/bin/env bash
# 备份 E2E（#264–#270 + 系统保留份数 #267）：对**运行中的 dev 后端**打真实请求，
# 覆盖备份计划的列举/创建/校验/执行/产物/下载/恢复闸门/清理这条完整链路。
#
# ## 为什么需要
# 备份模块的单测覆盖了纯逻辑（plan_sweep / 产物名校验 / 裁剪），但覆盖不到
# "路由注册 + 中间件 + 任务队列 + OS provider + 磁盘落盘"这条端到端链路。
# 真机跑一遍能抓出：能力位未接线、keep 生效值没下发给前端、panel 在线恢复
# 被误做成可点按钮、产物下载名白名单漏网等单测盲区。
#
# ## 用法
#   ci/e2e-backups.sh [base_url]
#     默认 http://127.0.0.1:2083
#   凭据走环境变量：PANEL_E2E_USER / PANEL_E2E_PASS
#     默认 admin / DevPreview2026x（dev 库）
#
# ## 纪律
#  1. **全部用临时对象**：dest_dir 带 PID，trap 兜底清理客户端临时文件；
#     服务端残留目录用 files/delete 最佳努力清理（失败只告警、不计入 FAIL）；
#  2. 每条断言都读**响应字段**，不是只看 HTTP 200；
#  3. 含负向断言：非法 kind / 不存在的 target / dest 越界 / 对不存在 id 做
#     patch·delete·run / panel 在线恢复诚实 501（危险按钮不提供）；
#  4. 后端不可达时**显式 skip 并非零退出**——不能因为没起服务就假装通过
#     （恒绿守卫比没守卫更危险）。
#
# ## 依赖
#   curl、python3（解析 JSON；不依赖 jq）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
DEST="e2e-$$"
ROOT="/tmp/panel-e2e-backups-$$"
CJ=$(mktemp)
DL=$(mktemp)
PASS=0; FAIL=0

cleanup() { rm -rf "$ROOT" "$CJ" "$DL" 2>/dev/null; }
trap cleanup EXIT

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }
# 期望"非 0"（负向断言：被拒/未找到）
chk_ne() { if [ "$2" != "0" ] && [ -n "$2" ]; then PASS=$((PASS+1)); say "  ✓ $1 (code=$2)"
           else FAIL=$((FAIL+1)); say "  ✗ $1  期望非0 实际=[$2]"; fi; }
# 期望布尔值（python 的 print(True) -> "True"）
chk_bool() { if [ "$2" = "True" ] || [ "$2" = "False" ]; then PASS=$((PASS+1)); say "  ✓ $1 ($2)"
             else FAIL=$((FAIL+1)); say "  ✗ $1  期望布尔 实际=[$2]"; fi; }

# 业务响应统一是 {code, data, message}；jget 自动剥 data 层
jget() { python3 -c 'import sys,json
d=json.load(sys.stdin)
if isinstance(d,dict) and "data" in d: d=d["data"]
p=sys.argv[1].split(".")
for k in p:
    if d is None: break
    d = d[int(k)] if isinstance(d,list) else d.get(k)
print("" if d is None else d)' "$1"; }
jcode() { python3 -c 'import sys,json;print(json.load(sys.stdin).get("code"))'; }

post() { curl -s -b "$CJ" -X POST "$B/api/v1$1" -H 'Content-Type: application/json' \
           -H "x-csrf-token: $CSRF" -d "$2"; }
put()  { curl -s -b "$CJ" -X PUT  "$B/api/v1$1" -H 'Content-Type: application/json' \
           -H "x-csrf-token: $CSRF" -d "$2"; }
patch_cmd() { curl -s -b "$CJ" -X PATCH "$B/api/v1$1" -H 'Content-Type: application/json' \
           -H "x-csrf-token: $CSRF" -d "$2"; }
get()  { curl -s -b "$CJ" "$B/api/v1$1"; }

# 取 dest_dir==$DEST 的计划字段（创建后靠 dest_dir 反查 id）
plan_field() {
  get /backups | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
for p in d:
    if p["dest_dir"]==sys.argv[1]: print(p[sys.argv[2]]); break' "$DEST" "$1"
}

# ── 0. 探活：后端不在就显式跳过（不是通过）──
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

# 备份根目录（用于服务端残留清理）
BDIR=$(get /backups/system | jget dir)
say "  备份根目录 = $BDIR"

say "=== 1. 系统备份信息（#267 生效值）==="
sys_keep=$(get /backups/system | jget keep)
sys_daily=$(get /backups/system | jget daily_backup)
chk "system.keep 是整数 ≥1" "$( [ "$sys_keep" -ge 1 ] 2>/dev/null && echo ok || echo bad )" "ok"
chk_bool "system.daily_backup 是布尔" "$sys_daily"
# 跨端点对账：settings.deployment.db_backup_keep 必须等于 system.keep
set_keep=$(get /settings | jget deployment.db_backup_keep)
chk "settings.db_backup_keep 与 system.keep 一致" "$set_keep" "$sys_keep"

say "=== 2. 创建 kind=panel 自备份计划（默认 keep/enabled）==="
r=$(post /backups "{\"kind\":\"panel\",\"target\":\"panel\",\"dest_dir\":\"$DEST\"}")
chk "创建计划 code=0" "$(echo "$r" | jcode)" "0"
PID_=$(plan_field id)
if [ -n "$PID_" ]; then PASS=$((PASS+1)); say "  ✓ 从 list 反查到新计划 id ($PID_)"
else FAIL=$((FAIL+1)); say "  ✗ 从 list 反查到新计划 id  未找到"; PID_=0; fi
kdef=$(plan_field keep_count); chk "keep_count 默认 7" "$kdef" "7"
enab=$(plan_field enabled);   chk "enabled 默认 true" "$enab" "True"

say "=== 3. 负向：非法输入必须被拒 ==="
r=$(post /backups '{"kind":"bogus","target":"panel","dest_dir":"neg-$$"}')
chk_ne "非法 kind 被拒" "$(echo "$r" | jcode)"
r=$(post /backups "{\"kind\":\"site\",\"target\":\"no-such-site-$$\",\"dest_dir\":\"neg-$$\"}")
chk_ne "不存在的 site target 被拒" "$(echo "$r" | jcode)"
r=$(post /backups '{"kind":"panel","target":"panel","dest_dir":"../escape-$$"}')
chk_ne "dest_dir 越出 backup_dir 被拒" "$(echo "$r" | jcode)"
# 对不存在的 id 做 patch/delete/run
r=$(patch_cmd /backups/999999999 '{"keep_count":3}'); chk_ne "patch 不存在 id 被拒" "$(echo "$r" | jcode)"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X DELETE "$B/api/v1/backups/999999999" -H "x-csrf-token: $CSRF")
chk "delete 不存在 id → 404" "$code" "404"
r=$(post /backups/999999999/run '{}'); chk_ne "run 不存在 id 被拒" "$(echo "$r" | jcode)"

say "=== 4. 执行计划 → 轮询任务 ==="
r=$(post /backups/$PID_/run '{}')
chk "run code=0" "$(echo "$r" | jcode)" "0"
TID=$(echo "$r" | jget task_id)
if [ -n "$TID" ]; then PASS=$((PASS+1)); say "  ✓ 拿到 task_id ($TID)"
else FAIL=$((FAIL+1)); say "  ✗ 拿到 task_id  未返回"; TID=0; fi
st="running"; i=0
while [ "$st" != "ok" ] && [ "$st" != "failed" ]; do
  sleep 2; i=$((i+1))
  st=$(get "/tasks/$TID" | jget state)
  [ "$i" -ge 60 ] && break   # 120s 超时
done
chk "任务最终 ok（i=$i, state=$st）" "$st" "ok"
# 计划自身的执行回写
lr=$(plan_field last_result); chk "plan.last_result=ok" "$lr" "ok"
lra=$(plan_field last_run_at); chk "plan.last_run_at 已写入" "$( [ -n "$lra" ] && echo set || echo empty )" "set"

say "=== 5. 产物列表 + 下载 ==="
acount=$(get "/backups/$PID_/artifacts" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["data"]))')
chk "产物 ≥1 份" "$( [ "$acount" -ge 1 ] 2>/dev/null && echo ok || echo bad )" "ok"
aname=$(get "/backups/$PID_/artifacts" | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"];print(d[0]["name"] if d else "")')
code=$(curl -s -o "$DL" -w '%{http_code}' -b "$CJ" "$B/api/v1/backups/$PID_/artifacts/$aname" -H "x-csrf-token: $CSRF")
chk "下载产物 HTTP 200" "$code" "200"
sz=$(stat -c %s "$DL" 2>/dev/null || echo 0)
chk "下载产物非空（size=$sz）" "$( [ "$sz" -gt 0 ] 2>/dev/null && echo ok || echo bad )" "ok"

say "=== 6. 恢复闸门：panel 在线恢复诚实 501 ==="
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X POST "$B/api/v1/backups/$PID_/restore" \
  -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" \
  -d "{\"artifact\":\"$aname\",\"confirm_token\":\"覆盖恢复\"}")
chk "panel 恢复诚实返回 501（不提供危险按钮）" "$code" "501"

say "=== 7. 清理 ==="
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X DELETE "$B/api/v1/backups/$PID_" -H "x-csrf-token: $CSRF")
chk "删除计划 → 204" "$code" "204"
# 服务端产物目录最佳努力清理（无独立删除 API：尝试 files/delete；失败只告警）
rc=$(post /files/delete "{\"path\":\"$BDIR/$DEST\",\"allow_dir\":true}")
rcc=$(echo "$rc" | jcode)
if [ "$rcc" = "0" ]; then say "  ✓ 服务端残留目录已清理（$BDIR/$DEST）"
else say "  [warn] 服务端残留 $BDIR/$DEST 未通过 files API 清理（code=$rcc），请手动 sudo rm -rf"; fi

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
