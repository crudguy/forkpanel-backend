#!/usr/bin/env bash
# 站点（sites）E2E：对**运行中的 dev 后端**打真实请求，
# 覆盖能力位门禁 + 只读端点 + 创建校验闸门 + 一条纯 DB 生命周期 + SSL 诚实 501 闸门。
#
# ## 为什么需要
# 站点是"配置变更必须先校验后生效"的典范：create/patch/delete 只写库，
# apply/reload 才真正渲染 → nginx -t → 原子替换 → reload。单测覆盖了各校验
# 纯逻辑，但覆盖不到「路由注册 + 能力位门禁（webserver.manage / ssl.acme）+
# 站点名/域名强校验 + 纯 DB CRUD」这条端到端链路。
#
# ## ⚠️ 刻意不做什么（安全纪律）
#  dev 主机 nginx 真实在场（webserver.manage=True）。因此本脚本**绝不**调用
#  apply / reload / conf_put / 停用（enabled 翻转）——那会渲染并 reload **真实**
#  nginx，属破坏性操作；也绝不用 method=self-signed 申请证书（会真的签出证书落盘）。
#  只测：能力位下发、只读端点、创建/SSL 的**拒绝分支**（零残留）、以及一条
#  **从不 apply、从不翻转 enabled** 的纯 DB 生命周期。
#
# ## 用法
#   ci/e2e-sites.sh [base_url]   默认 http://127.0.0.1:2083
#   凭据走环境变量：PANEL_E2E_USER / PANEL_E2E_PASS（默认 admin / DevPreview2026x）
#
# ## 依赖
#   curl、python3（解析 JSON；不依赖 jq）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
CJ=$(mktemp)
PASS=0; FAIL=0; SKIP=0
SITE_ID=""          # trap 兜底回收的站点 id
SITE_DIR=""         # trap 兜底清理的站点根目录（create 自愈式 mkdir，空目录）

cleanup() {
  # 站点登记兜底删除（纯 DB；本脚本从不 apply，conf_path 恒空，不碰 nginx）
  if [ -n "$SITE_ID" ]; then
    curl -s -o /dev/null -b "$CJ" -X DELETE "$B/api/v1/sites/$SITE_ID" -H "x-csrf-token: $CSRF" 2>/dev/null || true
  fi
  # 站点根目录：create 自愈式建的**空**目录，父目录归 agent 所有 ⇒ 可删（零残留）
  [ -n "$SITE_DIR" ] && rm -rf "$SITE_DIR" 2>/dev/null || true
  rm -f "$CJ" 2>/dev/null
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

say "=== 1. 能力位门禁（webserver.manage / ssl.acme）==="
CAPF=$(mktemp); get /system/capabilities > "$CAPF"
web_sup=$(python3 -c 'import sys,json;f=json.load(open(sys.argv[1]))["data"]["features"].get("webserver.manage") or {};print("True" if f.get("supported") else "False")' "$CAPF")
ssl_sup=$(python3 -c 'import sys,json;f=json.load(open(sys.argv[1]))["data"]["features"].get("ssl.acme") or {};print("True" if f.get("supported") else "False")' "$CAPF")
ssl_reason=$(python3 -c 'import sys,json;f=json.load(open(sys.argv[1]))["data"]["features"].get("ssl.acme") or {};print(f.get("reason") or "")' "$CAPF")
rm -f "$CAPF"
chk_bool "capabilities.features.webserver.manage.supported 是布尔" "$web_sup"
chk_bool "capabilities.features.ssl.acme.supported 是布尔" "$ssl_sup"
say "  · webserver.manage=$web_sup  ssl.acme=$ssl_sup (reason=${ssl_reason:-<none>})"

say "=== 2. 只读端点（site.view，与能力位无关）==="
r=$(get /sites); chk "GET /sites code=0" "$(echo "$r" | jcode)" "0"
chk "GET /sites 返回数组" "$(echo "$r" | python3 -c 'import sys,json;print("yes" if isinstance(json.load(sys.stdin)["data"],list) else "no")')" "yes"
r=$(get /sites/root); chk "GET /sites/root code=0" "$(echo "$r" | jcode)" "0"
chk "sites/root 返回非空 site_root" "$(echo "$r" | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"].get("site_root") or "";print("yes" if d.startswith("/") else "no")')" "yes"
r=$(get /certs); chk "GET /certs code=0" "$(echo "$r" | jcode)" "0"
cert_shape=$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
if not isinstance(d,list): print("bad"); raise SystemExit
if not d: print("empty"); raise SystemExit
it=d[0]
need=["domain","issuer","source","days_left","auto_renew"]
print("ok" if all(k in it for k in need) else "bad")')
case "$cert_shape" in
  ok|empty) PASS=$((PASS+1)); say "  ✓ certs 条目形状合法（$cert_shape）";;
  *) FAIL=$((FAIL+1)); say "  ✗ certs 条目形状异常：$cert_shape";;
esac
r=$(get /sites/99999999); chk "GET /sites/{不存在} → 404" "$(echo "$r" | jcode)" "10004"

# webserver.manage 不可用：建站/SSL 一律诚实 501，读端点仍可用。到此为止，不恒绿。
if [ "$web_sup" != "True" ]; then
  say "  [warn] webserver.manage 不支持（reason 见上）—— 只验证 501 诚实闸门"
  say "  [降级] 站点：能力位 webserver.manage 不可用——**站点数据面未覆盖**（只验了诚实 501）"
  r=$(post /sites '{"name":"e2e_site","domains":["a.example.com"]}')
  chk "create 在无 web 底座时诚实 501" "$(echo "$r" | jcode)" "10009"
  r=$(post /sites/99999999/ssl/apply '{"method":"http-01"}')
  chk "ssl_apply 在无 web 底座时诚实 501" "$(echo "$r" | jcode)" "10009"
  say ""
  say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
  [ "$FAIL" -eq 0 ] || exit 1
  exit 0
fi

say "=== 3. 创建校验闸门（拒绝分支，全部在 mkdir 之前挡回，零残留）==="
# name / domains 校验在 resolve_site_root 之前；root 逃逸在 mkdir 之前 ⇒ 均不落目录
r=$(post /sites '{"name":"a b","domains":["a.example.com"]}');            chk_ne "非法站点名（空格）被拒" "$(echo "$r" | jcode)"
r=$(post /sites '{"name":"a/b","domains":["a.example.com"]}');            chk_ne "非法站点名（斜杠）被拒" "$(echo "$r" | jcode)"
r=$(post /sites '{"name":".hidden","domains":["a.example.com"]}');        chk_ne "非法站点名（点开头）被拒" "$(echo "$r" | jcode)"
r=$(post /sites '{"name":"e2e_bad","domains":[]}');                        chk_ne "空域名列表被拒" "$(echo "$r" | jcode)"
r=$(post /sites '{"name":"e2e_bad","domains":["not_a_domain"]}');         chk_ne "非法域名（无点）被拒" "$(echo "$r" | jcode)"
r=$(post /sites '{"name":"e2e_bad","domains":["http://x"]}');             chk_ne "非法域名（含协议/特殊字符）被拒" "$(echo "$r" | jcode)"
# root 逃逸 site_root：PathEscape → 50001，且在 mkdir 之前
r=$(post /sites "$(python3 -c 'import json,sys;print(json.dumps({"name":"e2e_bad","domains":["a.example.com"],"root":sys.argv[1]}))' "../../../../tmp/e2e-escape")")
chk "root 逃逸 site_root 被拒" "$(echo "$r" | jcode)" "50001"

say "=== 4. 纯 DB 生命周期（创建→详情→改名→备注→SSL 501→删除，从不 apply）==="
MARK="$$$(date +%s)"
NAME="e2e_site_${MARK}"                        # is_valid_site_name：字母数字开头 + . _ -，≤63
DOMAIN="e2e-${MARK}.example.com"               # TLD=com 在白名单内
r=$(post /sites "$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1],"domains":[sys.argv[2]],"enabled":True}))' "$NAME" "$DOMAIN")")
chk "创建合法站点 code=0" "$(echo "$r" | jcode)" "0"
SITE_ID=$(echo "$r" | jget id)
SITE_DIR=$(echo "$r" | jget root)              # 绝对路径；trap 兜底清理
if [ -n "$SITE_ID" ]; then PASS=$((PASS+1)); say "  ✓ 站点 id=$SITE_ID root=$SITE_DIR"
else FAIL=$((FAIL+1)); say "  ✗ 未取到站点 id"; fi
chk "创建返回 name 与请求一致" "$(echo "$r" | jget name)" "$NAME"
chk "创建返回 enabled=True" "$(echo "$r" | jget enabled)" "True"
chk "创建返回 deployed=False（从未 apply）" "$(echo "$r" | jget deployed)" "False"
chk "创建返回 tls=False（无证书）" "$(echo "$r" | jget tls)" "False"

r=$(get /sites/$SITE_ID); chk "GET 详情 code=0" "$(echo "$r" | jcode)" "0"
chk "详情.name 一致" "$(echo "$r" | jget name)" "$NAME"
chk "列表含新建站点" "$(get /sites | python3 -c "import sys,json
d=json.load(sys.stdin)['data']; print('yes' if any(x['id']==int(sys.argv[1]) for x in d) else 'no')" "$SITE_ID")" "yes"

# 改名（不翻 enabled ⇒ 不触达 nginx，纯 DB）
NEWNAME="${NAME}_renamed"
r=$(patch_cmd /sites/$SITE_ID "$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1]}))' "$NEWNAME")")
chk "PATCH 改名 code=0" "$(echo "$r" | jcode)" "0"
chk "改名后详情.name 更新" "$(get /sites/$SITE_ID | jget name)" "$NEWNAME"

# 备注（204）
rc=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X PATCH "$B/api/v1/sites/$SITE_ID/remark" \
     -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d '{"remark":"e2e 测试站点"}')
chk "PATCH remark → 204" "$rc" "204"
chk "备注已回写" "$(get /sites/$SITE_ID | jget remark)" "e2e 测试站点"

# SSL 诚实闸门（在签发任何证书之前返回，零残留）
r=$(post /sites/$SITE_ID/ssl/apply '{"method":"http-01"}');  chk "ssl_apply http-01 → 501（ssl.acme 未接入）" "$(echo "$r" | jcode)" "10009"
r=$(post /sites/$SITE_ID/ssl/apply '{"method":"dns-01"}');   chk "ssl_apply dns-01 → 501（未实装）" "$(echo "$r" | jcode)" "10009"
r=$(post /sites/$SITE_ID/ssl/apply '{"method":"bogus"}');    chk "ssl_apply 非法 method → 10001" "$(echo "$r" | jcode)" "10001"

# 删除（conf_path 恒空 ⇒ 不碰 nginx，纯 DB）→ 204
http=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X DELETE "$B/api/v1/sites/$SITE_ID" -H "x-csrf-token: $CSRF")
chk "DELETE 站点 → 204" "$http" "204"
# 删除后：详情应 404；重复删除应 404（均在清空 SITE_ID 供 trap 之前验）
r=$(get /sites/$SITE_ID); chk "删除后 GET 详情 → 404" "$(echo "$r" | jcode)" "10004"
r=$(curl -s -b "$CJ" -X DELETE "$B/api/v1/sites/$SITE_ID" -H "x-csrf-token: $CSRF"); chk "重复删除 → 404" "$(echo "$r" | jcode)" "10004"
SITE_ID=""                                        # 已删，trap 无需再删

# 站点根目录残留清理（create 自愈式 mkdir 的空目录）。
# ⚠ 站点根在 /var/www 下、由 **root 后端**创建 ⇒ 权限 root:root 755，普通用户的
# rm -rf 必然失败。此前这里用裸 `rm -rf`，于是**每次运行都固定报红**——那不是抓到
# 产品缺陷，而是脚本自己缺 sudo（恒红和恒绿一样有害，都会让人不再看结果）。
# 现在：优先 sudo（本机已授权），实在删不掉才 skip 并说清原因，不再计入 FAIL。
if [ -n "$SITE_DIR" ] && [ -d "$SITE_DIR" ]; then
  rm -rf "$SITE_DIR" 2>/dev/null
  if [ -d "$SITE_DIR" ] && echo 'a' | sudo -S -p '' rm -rf "$SITE_DIR" 2>/dev/null; then :; fi
  if [ -d "$SITE_DIR" ]; then
    SKIP=$((SKIP+1)); say "  [skip] 站点根目录删不掉（需 root）：$SITE_DIR"
  else
    PASS=$((PASS+1)); say "  ✓ 站点根目录已清理（零残留）"
  fi
  SITE_DIR=""
fi

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP ────────"
[ "$FAIL" -eq 0 ] || exit 1
