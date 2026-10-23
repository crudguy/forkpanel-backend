#!/usr/bin/env bash
# 权限与设置 E2E（用户 / 角色 / RBAC 防提权 / 设置 / 审计）：对**运行中的 dev 后端**
# 打真实请求。这是整个面板权限最高的面，此前没有任何端到端覆盖。
#
# ## 为什么需要
# users/roles 的守卫（owner 不可经 API 操作、自锁防护、防提权子集约束、内置角色保留、
# 被引用角色不可删、部署级设置拒绝 PATCH）都有单测，但「路由注册 + 权限点 + 真库 +
# 两个会话之间的权限差」这条端到端链路没跑过。RBAC 一旦回归就是安全事故。
#
# ## 覆盖
#  1. 只读：/users、/roles（4 内置 + 27 权限）、/settings（deployment/reserved）、/audit
#  2. 用户创建校验拒绝（用户名/口令策略/owner 不可分配/角色不存在），零残留
#  3. 用户生命周期：创建→改角色→禁用→启用→删除→重复删 404
#  4. 自锁与 owner 守卫：改/删 owner(=当前登录) → 403；不存在 → 404
#  5. 角色生命周期 + 内置保留 + 未知权限 + 空权限 + 被引用不可删
#  6. **防提权**：造一个仅 `user.manage` 的用户并**另开会话**，验证它不能授予自己没有的
#     权限（且该角色未落库），但能授予自己有的权限（证明不是"一律拒绝"）
#  7. 设置：部署级键/未知键/空 patch 一律 10001
#  8. 审计闭环：user.create / role.create 真写入且可按 action 过滤查到
#
# ## 纪律
#  - 只创建**临时**用户/角色，名字带 pid+时间戳；trap 兜底删除（先用户后角色）。
#  - 拒绝分支全部在写库之前返回（10001），零残留。
#  - 每条拒绝分支钉死具体 code，不用"期望非 0"（404 会冒充业务拒绝码）。
#
# ## 用法
#   ci/e2e-rbac.sh [base_url]   默认 http://127.0.0.1:2083
#   凭据：PANEL_E2E_USER / PANEL_E2E_PASS（默认 admin / DevPreview2026x，dev 上的 owner）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
CJ=$(mktemp); CJ2=$(mktemp)
PASS=0; FAIL=0
CSRF=""; CSRF2=""
MARK="$$$(date +%s)"
U_NAME="e2e_user_${MARK}"       # validate_username 只查非空/≤64
U2_NAME="e2e_umuser_${MARK}"
R_NAME="e2e_role_${MARK}"       # valid_role_name: 小写开头 + [a-z0-9_-] 2~32
R_UM="e2e_um_${MARK}"
R_OK="e2e_ok_${MARK}"
R_ESC="e2e_esc_${MARK}"
PW="E2ePass!2345"               # ≥10、4 类字符、不含弱口令子串
USERS_TO_DEL=" $U_NAME $U2_NAME "
ROLES_TO_DEL=" $R_NAME $R_UM $R_OK "

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }
chk_ge() { if [ -n "$2" ] && [ "$2" -ge "$3" ] 2>/dev/null; then PASS=$((PASS+1)); say "  ✓ $1 ($2 ≥ $3)"
           else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望 ≥$3"; fi; }

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
patch_http() { curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X PATCH "$B/api/v1$1" \
           -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d "$2"; }
del_http() { curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X DELETE "$B/api/v1$1" -H "x-csrf-token: $CSRF"; }
del_body() { curl -s -b "$CJ" -X DELETE "$B/api/v1$1" -H "x-csrf-token: $CSRF"; }
get()  { curl -s -b "$CJ" "$B/api/v1$1"; }
# 第二会话（防提权用）
get2()  { curl -s -b "$CJ2" "$B/api/v1$1"; }
post2() { curl -s -b "$CJ2" -X POST "$B/api/v1$1" -H 'Content-Type: application/json' \
            -H "x-csrf-token: $CSRF2" -d "$2"; }
user_id() { get /users | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
print(next((u["id"] for u in d if u["username"]==sys.argv[1]), ""))' "$1"; }

cleanup() {
  # 先删用户、再删角色：角色被用户引用时删不掉（这是产品的真实约束）
  for n in $USERS_TO_DEL; do
    id=$(user_id "$n" 2>/dev/null || true)
    [ -n "${id:-}" ] && curl -s -o /dev/null -b "$CJ" -X DELETE "$B/api/v1/users/$id" \
      -H "x-csrf-token: $CSRF" 2>/dev/null || true
  done
  for n in $ROLES_TO_DEL; do
    curl -s -o /dev/null -b "$CJ" -X DELETE "$B/api/v1/roles/$n" \
      -H "x-csrf-token: $CSRF" 2>/dev/null || true
  done
  rm -f "$CJ" "$CJ2" 2>/dev/null
}
trap cleanup EXIT

# ── 0. 探活 + 登录（owner）──
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

say "=== 1. 只读端点（users / roles / settings / audit）==="
r=$(get /users); chk "GET /users code=0" "$(echo "$r" | jcode)" "0"
chk "admin 是 owner（owner 守卫的前提）" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];print(next((u["role"] for u in d if u["username"]=="admin"),""))')" "owner"
r=$(get /roles); chk "GET /roles code=0" "$(echo "$r" | jcode)" "0"
chk "内置角色 4 个" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]["roles"];print(sum(1 for x in d if x.get("builtin")))')" "4"
chk_ge "known_permissions 数量" "$(echo "$r" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["data"].get("known_permissions") or []))')" 20
r=$(get /settings); chk "GET /settings code=0" "$(echo "$r" | jcode)" "0"
chk "deployment 含 localhost_only/db_backup_keep + reserved" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; dep=d.get("deployment") or {}
print("ok" if "localhost_only" in dep and "db_backup_keep" in dep and isinstance(d.get("reserved"),dict) else "bad")')" "ok"
r=$(get /audit); chk "GET /audit code=0" "$(echo "$r" | jcode)" "0"
chk "audit 返回 {items,total}" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];print("ok" if isinstance(d.get("items"),list) and "total" in d else "bad")')" "ok"

say "=== 2. 用户创建校验闸门（拒绝分支，零残留）==="
r=$(post /users '{"username":"","password":"E2ePass!2345","role":"viewer"}'); chk "空用户名 → 10001" "$(echo "$r" | jcode)" "10001"
LONGU=$(python3 -c 'print("x"*65)')
r=$(post /users "{\"username\":\"$LONGU\",\"password\":\"E2ePass!2345\",\"role\":\"viewer\"}"); chk "用户名超长(65) → 10001" "$(echo "$r" | jcode)" "10001"
r=$(post /users '{"username":"e2e_bad","password":"short","role":"viewer"}'); chk "口令过短 → 10001" "$(echo "$r" | jcode)" "10001"
r=$(post /users '{"username":"e2e_bad","password":"aaaaaaaaaa","role":"viewer"}'); chk "口令单一字符类 → 10001" "$(echo "$r" | jcode)" "10001"
r=$(post /users '{"username":"e2e_bad","password":"password123","role":"viewer"}'); chk "口令命中弱口令 → 10001" "$(echo "$r" | jcode)" "10001"
r=$(post /users "{\"username\":\"e2e_bad\",\"password\":\"$PW\",\"role\":\"owner\"}"); chk "role=owner 不可经 API 分配 → 10001" "$(echo "$r" | jcode)" "10001"
r=$(post /users "{\"username\":\"e2e_bad\",\"password\":\"$PW\",\"role\":\"no_such_role\"}"); chk "role 不存在 → 10001" "$(echo "$r" | jcode)" "10001"

say "=== 3. 用户生命周期（建→改角色→禁用→启用→删→重复删）==="
r=$(post /users "{\"username\":\"$U_NAME\",\"password\":\"$PW\",\"role\":\"viewer\"}")
chk "创建用户 code=0" "$(echo "$r" | jcode)" "0"
ID=$(user_id "$U_NAME")
if [ -n "$ID" ]; then PASS=$((PASS+1)); say "  ✓ 新用户出现在列表 id=$ID"
else FAIL=$((FAIL+1)); say "  ✗ 列表里找不到新建用户 $U_NAME"; fi
chk "初始角色 viewer" "$(get /users | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];u=next((x for x in d if x["username"]==sys.argv[1]),None);print(u["role"] if u else "")' "$U_NAME")" "viewer"
chk "PATCH 改角色 → 204" "$(patch_http "/users/$ID" '{"role":"operator"}')" "204"
chk "列表 role=operator" "$(get /users | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];u=next((x for x in d if x["username"]==sys.argv[1]),None);print(u["role"] if u else "")' "$U_NAME")" "operator"
chk "PATCH 禁用 → 204" "$(patch_http "/users/$ID" '{"disabled":true}')" "204"
chk "列表 disabled=true" "$(get /users | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];u=next((x for x in d if x["username"]==sys.argv[1]),None);print(str(u["disabled"]) if u else "")' "$U_NAME")" "True"
chk "PATCH 启用 → 204" "$(patch_http "/users/$ID" '{"disabled":false}')" "204"
chk "DELETE 用户 → 204" "$(del_http "/users/$ID")" "204"
chk "删除后列表不再含该用户" "$(get /users | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];print("yes" if any(x["username"]==sys.argv[1] for x in d) else "no")' "$U_NAME")" "no"
chk "重复删除 → 404" "$(del_body "/users/$ID" | jcode)" "10004"

say "=== 4. 自锁与 owner 守卫 ==="
OWNER_ID=$(get /users | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"];print(next((u["id"] for u in d if u["role"]=="owner"),""))')
chk "PATCH owner(=当前登录) → 403" "$(patch_http "/users/$OWNER_ID" '{"disabled":true}')" "403"
chk "DELETE owner(=当前登录) → 403" "$(del_http "/users/$OWNER_ID")" "403"
chk "PATCH 不存在用户 → 404" "$(patch_cmd /users/99999999 '{"role":"viewer"}' | jcode)" "10004"
chk "DELETE 不存在用户 → 404" "$(del_body /users/99999999 | jcode)" "10004"

say "=== 5. 角色生命周期 + 内置保留 + 未知/空权限 ==="
r=$(post /roles "{\"name\":\"$R_NAME\",\"permissions\":[\"site.view\"]}")
chk "创建自定义角色 code=0" "$(echo "$r" | jcode)" "0"
chk "列表含该角色且 builtin=false、权限正确" "$(get /roles | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]["roles"];r=next((x for x in d if x["name"]==sys.argv[1]),None)
print("ok" if r and r["builtin"] is False and r["permissions"]==["site.view"] else "bad")' "$R_NAME")" "ok"
chk "重名创建 → 10001" "$(post /roles "{\"name\":\"$R_NAME\",\"permissions\":[\"site.view\"]}" | jcode)" "10001"
chk "占用内置名 admin → 10001" "$(post /roles '{"name":"admin","permissions":["site.view"]}' | jcode)" "10001"
chk "非法角色名(数字开头) → 10001" "$(post /roles '{"name":"1bad","permissions":["site.view"]}' | jcode)" "10001"
chk "未知权限 → 10001" "$(post /roles "{\"name\":\"$R_NAME\",\"permissions\":[\"site.fly\"]}" | jcode)" "10001"
chk "空权限集合 → 10001" "$(post /roles "{\"name\":\"$R_NAME\",\"permissions\":[]}" | jcode)" "10001"
chk "PATCH 角色权限 code=0" "$(patch_cmd "/roles/$R_NAME" '{"permissions":["site.view","site.manage"]}' | jcode)" "0"
chk "权限已更新" "$(get /roles | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]["roles"];r=next((x for x in d if x["name"]==sys.argv[1]),None)
print("ok" if r and set(r["permissions"])=={"site.view","site.manage"} else "bad")' "$R_NAME")" "ok"
chk "PATCH 内置角色 → 10001" "$(patch_cmd /roles/admin '{"permissions":["site.view"]}' | jcode)" "10001"
chk "DELETE 内置角色 → 10001" "$(del_body /roles/admin | jcode)" "10001"
chk "DELETE 不存在角色 → 404" "$(del_body /roles/no_such_role_xyz | jcode)" "10004"

say "=== 6. 防提权（第二会话：仅 user.manage 的用户）==="
chk "创建仅 user.manage 的角色" "$(post /roles "{\"name\":\"$R_UM\",\"permissions\":[\"user.manage\"]}" | jcode)" "0"
chk "创建该角色下的用户" "$(post /users "{\"username\":\"$U2_NAME\",\"password\":\"$PW\",\"role\":\"$R_UM\"}" | jcode)" "0"
curl -s -c "$CJ2" -X POST "$B/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U2_NAME\",\"password\":\"$PW\"}" > /dev/null
CSRF2=$(awk '$6=="panel_csrf"{print $7}' "$CJ2")
if [ -n "$CSRF2" ]; then PASS=$((PASS+1)); say "  ✓ 第二会话登录成功"
else FAIL=$((FAIL+1)); say "  ✗ 第二会话登录失败（防提权无法验证）"; fi
chk "user.manage 用户可读角色" "$(get2 /roles | jcode)" "0"
chk "授予自己没有的权限 → 10001" "$(post2 /roles "{\"name\":\"$R_ESC\",\"permissions\":[\"site.manage\"]}" | jcode)" "10001"
chk "越权角色未落库" "$(get /roles | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]["roles"];print("no" if any(x["name"]==sys.argv[1] for x in d) else "yes")' "$R_ESC")" "yes"
chk "授予自己有的权限 → 0（防提权不是一律拒绝）" "$(post2 /roles "{\"name\":\"$R_OK\",\"permissions\":[\"user.manage\"]}" | jcode)" "0"
chk "删除仍被引用的角色 → 10001" "$(del_body "/roles/$R_UM" | jcode)" "10001"
ID2=$(user_id "$U2_NAME")
chk "删除该用户 → 204" "$(del_http "/users/$ID2")" "204"
chk "用户删后角色可删 → 204" "$(del_http "/roles/$R_UM")" "204"

say "=== 7. 设置：部署级/未知/空 patch 一律拒绝 ==="
chk "空 patch → 10001" "$(patch_cmd /settings '{"settings":{}}' | jcode)" "10001"
r=$(patch_cmd /settings '{"settings":{"localhost_only":true}}')
chk "部署级 localhost_only → 10001" "$(echo "$r" | jcode)" "10001"
chk "拒绝理由点明「部署级」" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin); print("yes" if "部署级" in str(d.get("message",""))+str(d.get("detail","")) else "no")')" "yes"
chk "部署级 db_backup_keep → 10001" "$(patch_cmd /settings '{"settings":{"db_backup_keep":3}}' | jcode)" "10001"
chk "未知键 → 10001" "$(patch_cmd /settings '{"settings":{"no_such_key":"x"}}' | jcode)" "10001"

say "=== 8. 审计闭环（user.create / role.create 真写入）==="
items=$(get "/audit?action=user.create&page_size=50")
chk "审计可按 action 过滤读" "$(echo "$items" | jcode)" "0"
chk "审计含 user.create(target=$U_NAME)" "$(echo "$items" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]["items"];print("yes" if any(x.get("target")==sys.argv[1] for x in d) else "no")' "$U_NAME")" "yes"
items2=$(get "/audit?action=role.create&page_size=50")
chk "审计含 role.create(target=$R_NAME)" "$(echo "$items2" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]["items"];print("yes" if any(x.get("target")==sys.argv[1] for x in d) else "no")' "$R_NAME")" "yes"

# 收尾：删掉剩余临时对象（trap 也会兜底，这里显式做以证明「零残留」）
chk "删除防提权正例角色 → 204" "$(del_http "/roles/$R_OK")" "204"
chk "删除主测试角色 → 204" "$(del_http "/roles/$R_NAME")" "204"

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
