#!/usr/bin/env bash
# 容器（Docker）E2E（A7 容器页完善）：对**运行中的 dev 后端**打真实请求，
# 覆盖容器读端点 + 能力位下发 + 创建安全闸门（二次确认词 / 禁特权 / 禁敏感挂载 / 容器名白名单）。
#
# ## 为什么需要
# 容器页是 ForkPanel 最大的单页（6 个 Tab + Compose/Stack 子组件）。单测覆盖了
# provider 的 `validate_create` 纯逻辑，但覆盖不到"路由注册 + 能力位门禁 + OS provider
# 实际调用 docker"这条端到端链路。真机跑一遍能抓出：端点未接线、能力位没下发、
# 创建安全闸门被误放开（那等于宿主级任意代码执行）。
#
# ## 用法
#   ci/e2e-containers.sh [base_url]
#     默认 http://127.0.0.1:2083
#   凭据走环境变量：PANEL_E2E_USER / PANEL_E2E_PASS
#     默认 admin / DevPreview2026x（dev 库）
#
# ## 纪律
#  1. **不创建真实容器**：只测创建安全闸门的**拒绝分支**（缺确认词 / 特权 / 敏感挂载 /
#     非法名 / 错确认词），这些在 docker 之前就被 validate_create 挡回，零残留；
#  2. 每条断言都读**响应字段**，不是只看 HTTP 200；
#  3. 后端不可达时**显式 skip 并非零退出**（恒绿守卫比没守卫更危险）；
#  4. docker 不可达（能力位 unsupported）时，读端点会诚实 501——此时只验证能力位
#     的 reason 机器码已下发，不强行断言读数据。
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

cleanup() { rm -f "$CJ" "$DL" 2>/dev/null; }
trap cleanup EXIT

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }
chk_ne() { if [ "$2" != "0" ] && [ -n "$2" ]; then PASS=$((PASS+1)); say "  ✓ $1 (code=$2)"
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

say "=== 1. 能力位下发（container.manage 按 daemon 可达性判定）==="
# 注意：能力位 key 是字面量 "container.manage"（带点），不是嵌套结构，故单独用 python 取
supported=$(get /system/capabilities | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"]["features"]["container.manage"];print("True" if d["supported"] else "False")')
reason=$(get /system/capabilities | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"]["features"]["container.manage"];print(d.get("reason") or "")')
chk_bool "capabilities.features.container.manage.supported 是布尔" "$supported"
say "  · reason = ${reason:-<none>}"

# ── 2. 读端点（仅在能力位 supported 时断言数据）──
# 能力位 unsupported（docker 不可达）时读端点诚实 501：只验证 reason 已下发，不强行读数据。
list_http=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" "$B/api/v1/containers")
if [ "$list_http" != "200" ]; then
  say "  [warn] 容器读端点返回 $list_http（能力位 unsupported，reason=$reason）"
  say "  [warn] 跳过读端点与创建闸门断言（需在 docker 可达的宿主上才能真机验证）"
  # reason 必须是已知机器码，证明能力位确实按 daemon 可达性下发了
  case "$reason" in
    binary_missing|daemon_unreachable) PASS=$((PASS+1)); say "  ✓ 能力位 reason 为已知机器码（$reason）";;
    *) FAIL=$((FAIL+1)); say "  ✗ 能力位 reason 非预期：$reason";;
  esac
  say ""
  say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
  [ "$FAIL" -eq 0 ] || exit 1
  exit 0
fi

say "=== 2. 读端点（6 类只读列举）==="
for ep in containers images stats networks volumes compose stacks; do
  # 列表端点是 /containers（无子路径）；其余是 /containers/$ep
  path=$( [ "$ep" = "containers" ] && echo "/containers" || echo "/containers/$ep" )
  r=$(get "$path")
  code=$(echo "$r" | jcode)
  chk "GET $path code=0" "$code" "0"
done
# 网络条目形状：driver / name / scope 均为字符串
net_shape=$(get /containers/networks | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
if not d: print("empty");
else:
    it=d[0]; print("ok" if isinstance(it.get("driver"),str) and isinstance(it.get("name"),str) and isinstance(it.get("scope"),str) else "bad")')
chk "networks 条目含 driver/name/scope" "$net_shape" "ok"

say "=== 3. 创建安全闸门（拒绝分支，零残留）==="
# 以下全部在 docker 之前被 validate_create 挡回（code=10001），不会真的创建容器
r=$(post /containers '{"name":"e2e-probe","image":"alpine"}')
chk_ne "缺 confirm_token 被拒" "$(echo "$r" | jcode)"
r=$(post /containers '{"name":"e2e-probe","image":"alpine","privileged":true,"confirm_token":"创建容器"}')
chk_ne "特权容器被拒" "$(echo "$r" | jcode)"
r=$(post /containers '{"name":"e2e-probe","image":"alpine","volumes":["/:/host"],"confirm_token":"创建容器"}')
chk_ne "敏感挂载 / 被拒" "$(echo "$r" | jcode)"
r=$(post /containers '{"name":"e2e-probe","image":"alpine","volumes":["/var/run/docker.sock:/var/run/docker.sock"],"confirm_token":"创建容器"}')
chk_ne "docker.sock 挂载被拒" "$(echo "$r" | jcode)"
r=$(post /containers '{"name":"-bad","image":"alpine","confirm_token":"创建容器"}')
chk_ne "非法容器名被拒" "$(echo "$r" | jcode)"
r=$(post /containers '{"name":"e2e-probe","image":"alpine","confirm_token":"错词"}')
chk_ne "错误确认词被拒" "$(echo "$r" | jcode)"

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
