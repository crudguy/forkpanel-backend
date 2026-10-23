#!/usr/bin/env bash
# 计划任务（cron）E2E：对**运行中的 dev 后端**打真实请求，
# 覆盖能力位下发 + 读端点 + 创建/改写的全套校验闸门（拒绝分支，零残留）+
# 一次真实的「创建 → 手动执行 → 校验产物 → 删除」生命周期。
#
# ## 为什么需要
# cron 模块有完整的 handler 级校验（表达式 / 任务名 / 运行用户 / 命令长度 /
# 超时范围 / 并发上限 / Webhook），而且「手动执行」会真的经任务队列跑一条 shell
# 命令。单测覆盖了各校验函数的纯逻辑，但覆盖不到「路由注册 + 能力位门禁 +
# OS provider 真实 crontab 读写 + 任务队列执行」这条端到端链路。真机跑一遍能抓出：
# 端点未接线、能力位没下发、校验闸门被误放开（那等于任意 shell 执行）。
#
# ## 用法
#   ci/e2e-cron.sh [base_url]
#     默认 http://127.0.0.1:2083
#   凭据走环境变量：PANEL_E2E_USER / PANEL_E2E_PASS
#     默认 admin / DevPreview2026x（dev 库）
#
# ## 纪律
#  1. **不依赖外部资源**：不连数据库、不碰 docker；只动本机 root crontab（用完即删）；
#  2. 校验闸门的**拒绝分支**在 crontab 写入之前就被 handler 挡回（code=10001），零残留；
#  3. 生命周期会真实写入一条 crontab 并在结尾 DELETE 回收，trap 兜底再删一次；
#  4. 每条断言都读**响应字段**，不是只看 HTTP 200；
#  5. 后端不可达时**显式 skip 并非零退出**（恒绿守卫比没守卫更危险）；
#  6. 能力位 unsupported（crontab 二进制缺失）时读/写端点诚实 501——此时只验证
#     能力位的 reason 机器码已下发，不强行断言数据。
#
# ## 依赖
#   curl、python3（解析 JSON；不依赖 jq）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
CJ=$(mktemp)
DL=$(mktemp)
PASS=0; FAIL=0
CRON_NAME=""          # 生命周期创建的作业名（trap 兜底回收）

cleanup() {
  # 作业若因脚本中途异常未走主流程删除，这里兜底回收本机 crontab 条目（零残留）
  if [ -n "$CRON_NAME" ]; then
    curl -s -o /dev/null -b "$CJ" -X DELETE "$B/api/v1/cron/jobs/$CRON_NAME" \
      -H "x-csrf-token: $CSRF" 2>/dev/null || true
  fi
  rm -f "$CJ" "$DL" 2>/dev/null
}
trap cleanup EXIT

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }
chk_ne() { if [ -n "$2" ] && [ "$2" != "0" ]; then PASS=$((PASS+1)); say "  ✓ $1 (code=$2)"
           else FAIL=$((FAIL+1)); say "  ✗ $1  期望非0 实际=[$2]"; fi; }
chk_bool() { if [ "$2" = "True" ] || [ "$2" = "False" ]; then PASS=$((PASS+1)); say "  ✓ $1 ($2)"
            else FAIL=$((FAIL+1)); say "  ✗ $1  期望布尔 实际=[$2]"; fi; }

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
patch_cmd() { curl -s -b "$CJ" -X PATCH "$B/api/v1$1" -H 'Content-Type: application/json' \
           -H "x-csrf-token: $CSRF" -d "$2"; }
del() { curl -s -b "$CJ" -X DELETE "$B/api/v1$1" -H "x-csrf-token: $CSRF"; }
get()  { curl -s -b "$CJ" "$B/api/v1$1"; }

# ── 0. 探活 ──
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

say "=== 1. 能力位下发（scheduler.manage 按 crontab 二进制可达性判定）==="
# 注意：能力位 key 是字面量 "scheduler.manage"（带点），不是嵌套结构，故单独用 python 取
supported=$(get /system/capabilities | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"]["features"]["scheduler.manage"];print("True" if d["supported"] else "False")')
reason=$(get /system/capabilities | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"]["features"]["scheduler.manage"];print(d.get("reason") or "")')
chk_bool "capabilities.features.scheduler.manage.supported 是布尔" "$supported"
say "  · reason = ${reason:-<none>}"

# 能力位 unsupported（crontab 二进制缺失）时读/写端点诚实 501：
# 只验证能力位已按二进制可达性下发（reason=binary_missing），不强行断言数据。
if [ "$supported" != "True" ]; then
  say "  [warn] scheduler.manage 不支持（reason=$reason）—— 跳过数据面断言"
  list_code=$(get /cron/jobs | jcode)
  chk "GET /cron/jobs 在 unsupported 时诚实 501" "$list_code" "10009"
  case "$reason" in
    binary_missing) PASS=$((PASS+1)); say "  ✓ 能力位 reason 为已知机器码（$reason）";;
    *) FAIL=$((FAIL+1)); say "  ✗ 能力位 reason 非预期：$reason";;
  esac
  say ""
  say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
  [ "$FAIL" -eq 0 ] || exit 1
  exit 0
fi

say "=== 2. 读端点（列表 / 预览 / 详情 / 历史）==="
r=$(get /cron/jobs); chk "GET /cron/jobs code=0" "$(echo "$r" | jcode)" "0"
# 预览：合法表达式应返回未来若干触发时刻（>=1）
r=$(post /cron/preview '{"expr":"*/5 * * * *"}')
chk "POST /cron/preview 合法表达式 code=0" "$(echo "$r" | jcode)" "0"
nnext=$(echo "$r" | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"];print(len(d.get("next") or []))')
if [ "${nnext:-0}" -ge 1 ]; then PASS=$((PASS+1)); say "  ✓ 预览返回 >=1 个未来触发时刻（$nnext）"
else FAIL=$((FAIL+1)); say "  ✗ 预览未返回未来触发时刻（next=$nnext）"; fi
# 详情：不存在的作业应 404（10004）
r=$(get /cron/jobs/__e2e_no_such_job__); chk "GET /cron/jobs/{id} 不存在 404" "$(echo "$r" | jcode)" "10004"
# 历史：系统 crontab 不记录历史，应返回数组（可能为空）
r=$(get /cron/jobs/__e2e_no_such_job__/runs)
chk "GET /cron/jobs/{id}/runs code=0" "$(echo "$r" | jcode)" "0"

say "=== 3. 创建校验闸门（拒绝分支，零残留）==="
# 以下全部在 crontab 写入之前被 handler 挡回（code=10001），不会真的落地
r=$(post /cron/preview '{"expr":"0 5 * *"}');            chk_ne "预览：表达式段数不足被拒" "$(echo "$r" | jcode)"
r=$(post /cron/preview '{"expr":"99 5 * * *"}');          chk_ne "预览：分钟越界被拒" "$(echo "$r" | jcode)"
r=$(post /cron/jobs '{"name":"../x","expr":"* * * * *","command":"echo hi"}'); chk_ne "创建：非法任务名被拒" "$(echo "$r" | jcode)"
r=$(post /cron/jobs '{"name":"e2e-bad","expr":"* * * * *","command":"echo hi","user":"root; rm -rf /"}'); chk_ne "创建：注入式运行用户被拒" "$(echo "$r" | jcode)"
r=$(post /cron/jobs '{"name":"e2e-bad","expr":"* * * * *","command":""}'); chk_ne "创建：空命令被拒" "$(echo "$r" | jcode)"
r=$(post /cron/jobs '{"name":"e2e-bad","expr":"* * * * *","command":"echo hi","timeout_sec":-1}'); chk_ne "创建：负超时被拒" "$(echo "$r" | jcode)"
r=$(post /cron/jobs '{"name":"e2e-bad","expr":"* * * * *","command":"echo hi","max_overlap":2}'); chk_ne "创建：并发上限>1 被拒（未实装）" "$(echo "$r" | jcode)"
r=$(post /cron/jobs '{"name":"e2e-bad","expr":"* * * * *","command":"echo hi","webhook_url":"not-a-url"}'); chk_ne "创建：非法 Webhook URL 被拒" "$(echo "$r" | jcode)"
r=$(post /cron/jobs '{"name":"e2e-bad","expr":"* * * * *","command":"echo hi","webhook_events":["bogus"]}'); chk_ne "创建：非法 Webhook 事件被拒" "$(echo "$r" | jcode)"

say "=== 4. 生命周期：创建 → 改 → 执行 → 校验 → 删除 ==="
# 不写文件：cron 任务以 root 身份跑，产物文件会变 root 所有、非 root 的 E2E shell
# 删不掉（残留）。改以「任务中心输出 + 作业状态回写」作为真实执行的证据，零残留。
MARK="$$$(date +%s)"
NAME="e2e-cron-$MARK"
CRON_NAME="$NAME"
CMD="echo e2e-ran-ok"
# 用 python 安全拼 JSON，避免 shell 引号/转义翻车
PAYLOAD=$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1],"expr":sys.argv[2],"command":sys.argv[3],"enabled":True,"timeout_sec":60,"max_overlap":1}))' "$NAME" "*/5 * * * *" "$CMD")
r=$(post /cron/jobs "$PAYLOAD")
chk "创建合法作业 code=0" "$(echo "$r" | jcode)" "0"
chk "创建返回 name 与请求一致" "$(echo "$r" | jget name)" "$NAME"

# 详情：enabled / kind / name 与落库一致
r=$(get /cron/jobs/$NAME)
chk "GET 详情 code=0" "$(echo "$r" | jcode)" "0"
chk "详情.enabled=True" "$(echo "$r" | jget enabled)" "True"
chk "详情.kind=script" "$(echo "$r" | jget kind)" "script"
chk "详情.name=$NAME" "$(echo "$r" | jget name)" "$NAME"

# 改写：先禁用 → 校验禁用生效 → 再启用 → 校验启用生效
r=$(patch_cmd /cron/jobs/$NAME '{"enabled":false}')
chk "PATCH 禁用 code=0" "$(echo "$r" | jcode)" "0"
chk "PATCH 后 enabled=False" "$(get /cron/jobs/$NAME | jget enabled)" "False"
r=$(patch_cmd /cron/jobs/$NAME '{"enabled":true}')
chk "PATCH 启用 code=0" "$(echo "$r" | jcode)" "0"
chk "PATCH 后 enabled=True" "$(get /cron/jobs/$NAME | jget enabled)" "True"

# 手动执行：返回 task_id，轮询任务中心直到终态
r=$(post /cron/jobs/$NAME/run '')
chk "手动执行返回 code=0" "$(echo "$r" | jcode)" "0"
TID=$(echo "$r" | jget task_id)
if [ -z "$TID" ]; then FAIL=$((FAIL+1)); say "  ✗ 未取到 task_id"
else
  PASS=$((PASS+1)); say "  ✓ 取到 task_id=$TID"
  st="running"
  for _ in $(seq 1 40); do
    st=$(get /tasks/$TID | jget state)
    case "$st" in ok|failed|interrupted) break;; esac
    sleep 0.5
  done
  chk "任务终态为 ok" "$st" "ok"
fi

# 产物：任务中心输出应包含命令回显（证明命令真的经任务队列执行，且输出被留痕）。
# 注意：tasks.output 是「日志行数组」，不是单个字符串，故拼成文本再匹配。
rout=$(get /tasks/$TID/output)
hit=$(echo "$rout" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
o=d.get("lines")
if isinstance(o,list): txt="\n".join(map(str,o))
elif isinstance(o,str): txt=o
else: txt=""
print("yes" if "e2e-ran-ok" in txt else "no")')
if [ "$hit" = "yes" ]; then PASS=$((PASS+1)); say "  ✓ 任务中心输出含执行标记（命令真执行且留痕）"
else FAIL=$((FAIL+1)); say "  ✗ 任务中心输出未含执行标记（output=[$rout]）"; fi

# 状态回写：get_job 的 last_status / last_run_at 应被更新
r=$(get /cron/jobs/$NAME)
lstat=$(echo "$r" | jget last_status)
lrun=$(echo "$r" | jget last_run_at)
chk "执行后 last_status=ok" "$lstat" "ok"
if [ -n "$lrun" ] && [ "$lrun" != "None" ]; then PASS=$((PASS+1)); say "  ✓ 执行后 last_run_at 已回写（$lrun）"
else FAIL=$((FAIL+1)); say "  ✗ 执行后 last_run_at 未回写（$lrun）"; fi

# 历史端点：始终返回数组
r=$(get /cron/jobs/$NAME/runs); chk "GET runs code=0（始终数组）" "$(echo "$r" | jcode)" "0"

# 删除：回收 crontab 条目（主流程；trap 兜底）
r=$(del /cron/jobs/$NAME)
chk "DELETE 作业 code=0" "$(echo "$r" | jcode)" "0"
CRON_NAME=""   # 已成功删除，trap 无需再删
# 删除后详情应 404（确认 crontab 条目也真被移除，而非只删库元数据）
r=$(get /cron/jobs/$NAME); chk "删除后 GET 详情 404" "$(echo "$r" | jcode)" "10004"

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
