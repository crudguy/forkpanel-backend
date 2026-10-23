#!/usr/bin/env bash
# 数据库（db）E2E：对**运行中的 dev 后端**打真实请求，
# 覆盖连接创建校验闸门 + SQLite 只读浏览全链路 + 只读 SQL 控制台闸门 + 连接生命周期。
#
# ## 为什么需要
# db 模块的校验（连接名 / 引擎白名单 / mysql·pg 必填账号 / sqlite 路径沙箱 /
# 只读 SQL 白名单）与「浏览 provider（rusqlite 只读连接 → 库/表/行）」在单测里
# 各有覆盖，但覆盖不到「路由注册 + 权限点 + OS provider 真实打开 .db 文件 +
# read_only 连接」这条端到端链路。真机跑一遍能抓出：端点未接线、能力位撒谎、
# 校验闸门被误放开、SQLite 文件路径沙箱被绕过（那等于读任意系统文件）。
#
# ## 用法
#   ci/e2e-databases.sh [base_url]
#     默认 http://127.0.0.1:2083
#   凭据走环境变量：PANEL_E2E_USER / PANEL_E2E_PASS
#     默认 admin / DevPreview2026x（dev 库）
#
# ## 纪律
#  1. **只用 SQLite**：内建只读 rusqlite，无需外部客户端/守护进程，dev 上零依赖可跑；
#     不碰 mysql/pg（需真实远端，会引入外部依赖与脆弱性）。
#  2. 连接创建/浏览都在沙箱内：`.db` 文件放 /tmp 专属子目录（agent 所有，可删）；
#     浏览以只读连接打开，不写目标库，零残留。
#  3. 每条断言读**响应字段**，不是只看 HTTP 200；
#  4. 后端不可达时**显式 skip 并非零退出**（恒绿守卫比没守卫更危险）。
#
# ## 依赖
#   curl、python3（含 sqlite3，解析 JSON）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
CJ=$(mktemp); DL=$(mktemp); HDRF=$(mktemp)
PASS=0; FAIL=0
MARK="$$$(date +%s)"
TMPD="/tmp/forkpanel-e2e-db-$MARK"      # .db 夹具目录（agent 所有）
DBFILE="$TMPD/sample.db"
NAME_A="e2e_db_${MARK}"                 # ⚠ is_valid_db_name 仅允许 [A-Za-z0-9_]，禁连字符
NAME_B="e2e_db_${MARK}_b"
CONN_IDS=""                             # trap 兜底回收的连接 id

cleanup() {
  # 中途异常时兜底回收连接登记 + .db 夹具（零残留）
  for id in $CONN_IDS; do
    [ -n "$id" ] && curl -s -o /dev/null -b "$CJ" -X DELETE "$B/api/v1/db/connections/$id" \
      -H "x-csrf-token: $CSRF" 2>/dev/null || true
  done
  rm -rf "$TMPD" 2>/dev/null || true
  rm -f "$CJ" "$DL" "$HDRF" 2>/dev/null
}
trap cleanup EXIT

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }
chk_ne() { if [ -n "$2" ] && [ "$2" != "0" ]; then PASS=$((PASS+1)); say "  ✓ $1 (code=$2)"
           else FAIL=$((FAIL+1)); say "  ✗ $1  期望非0 实际=[$2]"; fi; }

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
# 按连接名在列表里取 id（浏览/改/删端点只吃数字 id）
conn_id() { get /db/connections | python3 -c "import sys,json
name=sys.argv[1]; d=json.load(sys.stdin)['data']
print(next((c['id'] for c in d if c['name']==name), ''))" "$1"; }

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

say "=== 1. 连接创建校验闸门（拒绝分支，零残留）==="
# 以下全部在建行之前被 handler 挡回（code=10001），不落 db_connections
r=$(post /db/connections '{"name":"bad name","engine":"sqlite","default_db":"/tmp/x.db"}'); chk_ne "非法连接名（空格）被拒" "$(echo "$r" | jcode)"
r=$(post /db/connections '{"name":"e2e_bad","engine":"oracle"}'); chk_ne "未知引擎被拒" "$(echo "$r" | jcode)"
r=$(post /db/connections '{"name":"e2e_bad","engine":"mysql"}'); chk_ne "mysql 缺账号被拒" "$(echo "$r" | jcode)"
r=$(post /db/connections "$(python3 -c 'import json,sys;print(json.dumps({"name":"e2e_bad","engine":"sqlite","default_db":sys.argv[1]}))' "/tmp/forkpanel-e2e-nope-$MARK.db")"); chk_ne "sqlite 文件不存在被拒" "$(echo "$r" | jcode)"
r=$(post /db/connections '{"name":"e2e_bad","engine":"sqlite","default_db":"/etc/passwd"}'); chk_ne "sqlite 敏感路径被拒" "$(echo "$r" | jcode)"
r=$(post /db/connections '{"name":"e2e_bad","engine":"mysql","user":"root","default_db":"bad;db"}'); chk_ne "非 sqlite 非法库名被拒" "$(echo "$r" | jcode)"

say "=== 2. 造 SQLite 夹具 + 建连接 ==="
mkdir -p "$TMPD"
python3 - "$DBFILE" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE e2e_items(id INTEGER PRIMARY KEY, name TEXT, update_time INTEGER, note TEXT)")
c.execute("INSERT INTO e2e_items(name,update_time,note) VALUES('alpha',100,NULL)")
c.execute("INSERT INTO e2e_items(name,update_time,note) VALUES('beta',200,'hello')")
c.commit(); c.close()
PY
if [ ! -f "$DBFILE" ]; then say "  ✗ 夹具 .db 创建失败：$DBFILE"; exit 1; fi
say "  ✓ 夹具已建：$DBFILE"

r=$(post /db/connections "$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1],"engine":"sqlite","default_db":sys.argv[2]}))' "$NAME_A" "$DBFILE")")
chk "创建 sqlite 连接 code=0" "$(echo "$r" | jcode)" "0"
ID_A=$(conn_id "$NAME_A")
if [ -n "$ID_A" ]; then PASS=$((PASS+1)); say "  ✓ 连接 id=$ID_A"; CONN_IDS="$CONN_IDS $ID_A"
else FAIL=$((FAIL+1)); say "  ✗ 列表里找不到新建连接 $NAME_A"; fi

# 列表字段：engine=sqlite / client_ready / readonly_sql / has_password（只读 SQL 对 sqlite 开放）
flags=$(get /db/connections | python3 -c "import sys,json
name=sys.argv[1]; d=json.load(sys.stdin)['data']
c=next((x for x in d if x['name']==name), None)
ok = c and c['engine']=='sqlite' and c['client_ready'] is True and c['readonly_sql'] is True and c['has_password'] is False
print('ok' if ok else 'bad:%r'%(c,))" "$NAME_A")
chk "列表字段：sqlite/客户端就绪/只读控制台开放/无口令" "$flags" "ok"

say "=== 3. SQLite 只读浏览全链路（连接→库→schema→表→行→导出）==="
r=$(get /db/$ID_A/databases); chk "databases code=0" "$(echo "$r" | jcode)" "0"
chk "databases 含 main" "$(echo "$r" | python3 -c 'import sys,json;print("yes" if "main" in json.load(sys.stdin)["data"] else "no")')" "yes"

r=$(get /db/$ID_A/main/schemas); chk "schemas code=0" "$(echo "$r" | jcode)" "0"
chk "schemas 含 main 且可预览" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; m=next((x for x in d if x["name"]=="main"), None)
print("ok" if m and m.get("previewable") is True else "bad:%r"%(m,))')" "ok"

r=$(get /db/$ID_A/main/tables); chk "tables code=0" "$(echo "$r" | jcode)" "0"
chk "tables 含 e2e_items(kind=table,rows=2)" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; t=next((x for x in d if x["name"]=="e2e_items"), None)
print("ok" if t and t.get("kind")=="table" and t.get("rows")==2 else "bad:%r"%(t,))')" "ok"

r=$(get /db/$ID_A/main/e2e_items/rows); chk "rows code=0" "$(echo "$r" | jcode)" "0"
chk "rows 结构（total=2,列含 id/name/update_time/note）" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; c=d.get("columns") or []
ok = d.get("total")==2 and len(d.get("rows") or [])==2 and {"id","name","update_time","note"} <= set(c)
print("ok" if ok else "bad:%r"%(d,))')" "ok"
chk "rows NULL 保留 + 文本值正确" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; c=d["columns"]; i=c.index("note"); rows=d["rows"]
print("ok" if rows[0][i] is None and rows[1][i]=="hello" else "bad:%r"%(rows,))')" "ok"

# 导出：HTTP 200 + text/csv + 内容含列名与数据值（带 UTF-8 BOM）
http=$(curl -s -D "$HDRF" -o "$DL" -w '%{http_code}' -b "$CJ" "$B/api/v1/db/$ID_A/main/e2e_items/export")
chk "export HTTP 200" "$http" "200"
chk "export Content-Type 为 text/csv" "$(grep -i '^content-type:' "$HDRF" | tr -d '\r' | awk '{print $2}' | cut -d';' -f1)" "text/csv"
csvchk=$(python3 -c 'import sys
b=open(sys.argv[1],"rb").read()
print("ok" if (b.startswith(b"\xef\xbb\xbf") and b"update_time" in b and b"alpha" in b and b"\r\n" in b) else "bad")' "$DL")
chk "export 内容：BOM + 列名 + 数据 + CRLF" "$csvchk" "ok"

say "=== 4. 只读 SQL 控制台（能力 + 正例 + 拒绝分支）==="
r=$(get /db/$ID_A/sql-meta); chk "sql-meta code=0" "$(echo "$r" | jcode)" "0"
chk "sql-meta：sqlite/只读开放/默认语句/示例" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
ok = d.get("engine")=="sqlite" and d.get("readonly_sql") is True and bool(d.get("default_sql")) and len(d.get("samples") or [])>=1 and bool(d.get("note"))
print("ok" if ok else "bad")')" "ok"

qsel=$(python3 -c 'import json,sys;print(json.dumps({"sql":sys.argv[1]}))' "SELECT id, name FROM e2e_items ORDER BY id")
r=$(post /db/$ID_A/query "$qsel"); chk "query SELECT code=0" "$(echo "$r" | jcode)" "0"
chk "query 返回 2 行且值正确" "$(echo "$r" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]; rows=d.get("rows") or []
ok = d.get("columns")==["id","name"] and [x[0] for x in rows]==["1","2"] and [x[1] for x in rows]==["alpha","beta"]
print("ok" if ok else "bad:%r"%(d,))')" "ok"
# 列名含 update_time（内有写关键字 "update"）：完整词边界不得误判，且能跑出值
qupd=$(python3 -c 'import json,sys;print(json.dumps({"sql":sys.argv[1]}))' "SELECT update_time FROM e2e_items WHERE id = 1")
r=$(post /db/$ID_A/query "$qupd"); chk "query update_time 列不被写关键字误判" "$(echo "$r" | jcode)" "0"
chk "query update_time 值=100" "$(echo "$r" | jget rows.0.0)" "100"
# 拒绝分支（全部 10001，在 provider 之前被 validate_read_only_sql 挡回）
for bad in "DROP TABLE e2e_items" "CREATE TABLE x(a)" "DELETE FROM e2e_items" "UPDATE e2e_items SET name='x'" "SELECT 1; DROP TABLE e2e_items"; do
  qp=$(python3 -c 'import json,sys;print(json.dumps({"sql":sys.argv[1]}))' "$bad")
  chk_ne "query 拒绝写/多语句：${bad:0:22}" "$(post /db/$ID_A/query "$qp" | jcode)"
done

say "=== 5. 连接生命周期（改名 / 改名撞车 409 / 备注 / 删除）==="
r=$(patch_cmd /db/connections/$ID_A "$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1]}))' "${NAME_A}_renamed")")
chk "PATCH 改名 code=0" "$(echo "$r" | jcode)" "0"
chk "改名后 id 不变" "$(conn_id "${NAME_A}_renamed")" "$ID_A"

r=$(post /db/connections "$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1],"engine":"sqlite","default_db":sys.argv[2]}))' "$NAME_B" "$DBFILE")")
chk "创建 B code=0" "$(echo "$r" | jcode)" "0"
ID_B=$(conn_id "$NAME_B"); [ -n "$ID_B" ] && CONN_IDS="$CONN_IDS $ID_B"
r=$(patch_cmd /db/connections/$ID_A "$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1]}))' "$NAME_B")")
chk "改名撞已存在 → 409" "$(echo "$r" | jcode)" "10005"

rc=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X PATCH "$B/api/v1/db/$ID_A/remark" \
     -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" -d '{"remark":"e2e 测试连接"}')
chk "PATCH remark → 204" "$rc" "204"
chk "备注已回写" "$(get /db/connections | python3 -c "import sys,json
d=json.load(sys.stdin)['data']; c=next((x for x in d if x['id']==int(sys.argv[1])), None)
print(c.get('remark') if c else 'none')" "$ID_A")" "e2e 测试连接"

r=$(del /db/connections/$ID_A); chk "DELETE A code=0" "$(echo "$r" | jcode)" "0"
CONN_IDS=$(echo "$CONN_IDS" | sed "s/ $ID_A//")     # 已删，trap 无需再删
r=$(get /db/$ID_A/databases); chk "删除后浏览 → 404" "$(echo "$r" | jcode)" "10004"
r=$(del /db/connections/999999); chk "删除不存在 → 404" "$(echo "$r" | jcode)" "10004"
r=$(del /db/connections/$ID_B); chk "DELETE B code=0" "$(echo "$r" | jcode)" "0"
CONN_IDS=$(echo "$CONN_IDS" | sed "s/ $ID_B//")

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
