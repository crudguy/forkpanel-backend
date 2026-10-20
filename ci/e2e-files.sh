#!/usr/bin/env bash
# 文件管理器 E2E（A7）：对**运行中的 dev 后端**打真实请求，覆盖全部 18 条路由。
#
# ## 为什么需要
# 单测覆盖不到"路由注册 + 中间件 + 沙箱 + OS provider"这条完整链路。事实已证明：
#  - `write` 误用 `resolve` ⇒ 写新文件 100% NotFound，而所有单测都绿；
#  - `stat.mode` 带文件类型位 ⇒ 与 list 语义不一致，单测也绿（直到本脚本抓出）。
# 两者都是"编译/单测全绿、真机一用就错"的典型。
#
# ## 用法
#   ci/e2e-files.sh [base_url]
#     默认 http://127.0.0.1:2083
#   凭据走环境变量：PANEL_E2E_USER / PANEL_E2E_PASS
#     默认 admin / DevPreview2026x（dev 库）
#
# ## 纪律
#  1. **全部用临时对象**：临时目录名带 PID，trap 兜底清理，宿主机不留残留；
#  2. 每条断言都读**响应字段**，不是只看 HTTP 200；
#  3. 含负向断言：缺片 complete、分片大小不符、chmod recursive、action 空 paths /
#     非法 op、删目录未声明 allow_dir、回收站条目重复恢复；
#  4. 后端不可达时**显式 skip 并非零退出**——不能因为没起服务就假装通过
#     （恒绿守卫比没守卫更危险）。
#
# ## 依赖
#   curl、python3（解析 JSON；不依赖 jq）
set -uo pipefail

B="${1:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
ROOT="/tmp/panel-e2e-files-$$"
CJ=$(mktemp)
DL=$(mktemp)
PASS=0; FAIL=0

cleanup() { rm -rf "$ROOT" "$CJ" "$DL" 2>/dev/null; }
trap cleanup EXIT

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }
chk_has() { case "$2" in *"$3"*) PASS=$((PASS+1)); say "  ✓ $1";;
            *) FAIL=$((FAIL+1)); say "  ✗ $1  未包含[$3] 实际=[$2]";; esac; }

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
get()  { curl -s -b "$CJ" "$B/api/v1$1"; }

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

say "=== 1. mkdir + 写基线文件 ==="
for d in "$ROOT" "$ROOT/sub" "$ROOT/dest"; do
  r=$(post /files/mkdir "{\"path\":\"$d\"}"); chk "mkdir ${d##*/}" "$(echo "$r" | jcode)" "0"
done
r=$(put /files/write "{\"path\":\"$ROOT/a.txt\",\"content\":\"alpha\\n\"}"); chk "写 a.txt" "$(echo "$r" | jcode)" "0"

say "=== 2. rename ==="
r=$(post /files/rename "{\"from\":\"$ROOT/a.txt\",\"to\":\"$ROOT/b.txt\"}"); chk "rename" "$(echo "$r" | jcode)" "0"
r=$(get "/files/stat?path=$ROOT/b.txt"); chk "新名存在" "$(echo "$r" | jcode)" "0"
r=$(get "/files/stat?path=$ROOT/a.txt"); chk "旧名已不在" "$(echo "$r" | jcode)" "10004"

say "=== 3. copy（rename?copy=true）==="
r=$(post /files/rename "{\"from\":\"$ROOT/b.txt\",\"to\":\"$ROOT/c.txt\",\"copy\":true}"); chk "copy" "$(echo "$r" | jcode)" "0"
r=$(get "/files/stat?path=$ROOT/b.txt"); chk "源仍在" "$(echo "$r" | jcode)" "0"
r=$(get "/files/read?path=$ROOT/c.txt"); chk_has "副本内容一致" "$(echo "$r" | jget content)" "alpha"

say "=== 4. chmod ==="
r=$(post /files/chmod "{\"path\":\"$ROOT/c.txt\",\"mode\":\"600\"}"); chk "chmod" "$(echo "$r" | jcode)" "0"
chk "chmod 回显" "$(echo "$r" | jget mode)" "600"
# stat 与 list 必须同一口径：只取权限位（不带 S_IFREG 的 100xxx）
r=$(get "/files/stat?path=$ROOT/c.txt"); chk "stat.mode 只有权限位" "$(echo "$r" | jget mode)" "600"
# 按**文件名**取条目，不能取 entries.0（目录排序在前，会拿到别的条目）
lmode=$(get "/files/list?path=$ROOT" | python3 -c 'import sys,json
for e in json.load(sys.stdin)["data"]["entries"]:
    if e["name"]=="c.txt": print(e["mode"])')
chk "list.mode 同口径" "$lmode" "600"
r=$(post /files/chmod "{\"path\":\"$ROOT/c.txt\",\"mode\":\"600\",\"recursive\":true}")
chk "recursive 显式拒绝(10001)" "$(echo "$r" | jcode)" "10001"
r=$(post /files/chmod "{\"path\":\"$ROOT/c.txt\",\"mode\":\"4755\"}")
chk "setuid 越界拒绝(10001)" "$(echo "$r" | jcode)" "10001"

say "=== 5. upload ==="
BODY="multipart-upload-payload"
r=$(curl -s -b "$CJ" -X PUT "$B/api/v1/files/upload?path=$ROOT/up.bin" -H "x-csrf-token: $CSRF" \
      -H 'Content-Type: application/octet-stream' --data-binary "$BODY")
chk "upload" "$(echo "$r" | jcode)" "0"
chk "upload 字节数" "$(echo "$r" | jget size)" "${#BODY}"
r=$(get "/files/read?path=$ROOT/up.bin"); chk_has "upload 内容一致" "$(echo "$r" | jget content)" "$BODY"

say "=== 6. download ==="
hdr=$(curl -s -D - -o "$DL" -b "$CJ" "$B/api/v1/files/download?path=$ROOT/up.bin")
chk_has "attachment 头" "$hdr" "attachment; filename="
chk_has "RFC5987 filename*" "$hdr" "filename*=UTF-8''"
chk "下载字节一致" "$(cat "$DL")" "$BODY"

say "=== 7. action 批量 ==="
r=$(post /files/action "{\"op\":\"copy\",\"paths\":[\"$ROOT/b.txt\"],\"dest\":\"$ROOT/dest\"}")
chk "copy ok_count" "$(echo "$r" | jget ok_count)" "1"
r=$(get "/files/stat?path=$ROOT/dest/b.txt"); chk "copy 落点" "$(echo "$r" | jcode)" "0"
r=$(post /files/action "{\"op\":\"copy\",\"paths\":[\"$ROOT/b.txt\"],\"dest\":\"$ROOT/dest\"}")
chk "重复 copy 必须失败" "$(echo "$r" | jget fail_count)" "1"
chk_has "错误点名 target exists" "$(echo "$r" | jget results.0.error)" "target exists"
r=$(post /files/action "{\"op\":\"move\",\"paths\":[\"$ROOT/c.txt\"],\"dest\":\"$ROOT/sub\"}")
chk "move ok_count" "$(echo "$r" | jget ok_count)" "1"
r=$(get "/files/stat?path=$ROOT/sub/c.txt"); chk "move 落点" "$(echo "$r" | jcode)" "0"
r=$(get "/files/stat?path=$ROOT/c.txt"); chk "move 源已不在" "$(echo "$r" | jcode)" "10004"
r=$(post /files/action "{\"op\":\"chmod\",\"paths\":[\"$ROOT/sub/c.txt\"],\"mode\":\"640\"}")
chk "批量 chmod" "$(echo "$r" | jget ok_count)" "1"
r=$(get "/files/stat?path=$ROOT/sub/c.txt"); chk "批量 chmod 生效" "$(echo "$r" | jget mode)" "640"
r=$(post /files/action '{"op":"move","paths":[]}'); chk "空 paths 整体 400" "$(echo "$r" | jcode)" "10001"
r=$(post /files/action "{\"op\":\"rm-rf\",\"paths\":[\"$ROOT/b.txt\"]}"); chk "非法 op 整体 400" "$(echo "$r" | jcode)" "10001"

say "=== 8. 软删除 → restore ==="
r=$(post /files/trash "{\"path\":\"$ROOT/b.txt\"}"); chk "trash" "$(echo "$r" | jcode)" "0"
TID=$(echo "$r" | jget id)
chk_has "记录原始路径" "$(echo "$r" | jget original_path)" "$ROOT/b.txt"
r=$(get "/files/stat?path=$ROOT/b.txt"); chk "软删后原位置空" "$(echo "$r" | jcode)" "10004"
ids=$(get /files/trash | python3 -c 'import sys,json;print(",".join(i["id"] for i in json.load(sys.stdin)["data"]["items"]))')
chk_has "回收站列表含该条目" "$ids" "$TID"
r=$(post /files/trash/restore "{\"id\":\"$TID\"}"); chk "restore" "$(echo "$r" | jcode)" "0"
r=$(get "/files/stat?path=$ROOT/b.txt"); chk "文件已回来" "$(echo "$r" | jcode)" "0"
r=$(post /files/trash/restore "{\"id\":\"$TID\"}"); chk "重复 restore 必失败(10004)" "$(echo "$r" | jcode)" "10004"

say "=== 9. purge ==="
r=$(post /files/trash "{\"path\":\"$ROOT/dest/b.txt\"}"); chk "再软删一条" "$(echo "$r" | jcode)" "0"
TID2=$(echo "$r" | jget id)
r=$(post /files/trash/purge "{\"id\":\"$TID2\"}"); chk "purge 单条" "$(echo "$r" | jget purged)" "1"
r=$(post /files/trash/purge "{}"); chk "purge 全部(幂等)" "$(echo "$r" | jcode)" "0"

say "=== 10. multipart 分片上传 ==="
MP="chunked-payload-0123456789"; N=${#MP}
r=$(post /files/multipart/init "{\"path\":\"$ROOT/mp.bin\",\"size\":$N}"); chk "init" "$(echo "$r" | jcode)" "0"
UID_=$(echo "$r" | jget upload_id)
chk "total_chunks" "$(echo "$r" | jget total_chunks)" "1"
chk "chunk_size 服务端定档" "$(echo "$r" | jget chunk_size)" "4194304"
r=$(post /files/multipart/init "{\"path\":\"$ROOT/x.bin\",\"size\":0}"); chk "size=0 拒绝(10001)" "$(echo "$r" | jcode)" "10001"
r=$(post "/files/multipart/$UID_/complete" '{}'); chk "缺片 complete 失败(10001)" "$(echo "$r" | jcode)" "10001"
r=$(get "/files/multipart/$UID_"); chk "缺片后会话保留" "$(echo "$r" | jcode)" "0"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X PUT \
  "$B/api/v1/files/multipart/chunk?upload_id=$UID_&index=0" -H "x-csrf-token: $CSRF" \
  -H 'Content-Type: application/octet-stream' --data-binary "short")
chk "分片大小不符 → 400" "$code" "400"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X PUT \
  "$B/api/v1/files/multipart/chunk?upload_id=$UID_&index=0" -H "x-csrf-token: $CSRF" \
  -H 'Content-Type: application/octet-stream' --data-binary "$MP")
chk "chunk → 204" "$code" "204"
r=$(get "/files/multipart/$UID_"); chk "status received[0]" "$(echo "$r" | jget received.0)" "0"
r=$(post "/files/multipart/$UID_/complete" '{}'); chk "complete" "$(echo "$r" | jcode)" "0"
chk "合并字节数相符" "$(echo "$r" | jget size)" "$N"
r=$(get "/files/read?path=$ROOT/mp.bin"); chk_has "合并内容正确" "$(echo "$r" | jget content)" "$MP"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -X DELETE \
  "$B/api/v1/files/multipart/$UID_" -H "x-csrf-token: $CSRF")
chk "abort 已完成会话幂等 → 204" "$code" "204"

say "=== 11. 删除语义 ==="
r=$(post /files/delete "{\"path\":\"$ROOT/sub\",\"allow_dir\":false}")
chk "删目录未声明 allow_dir → 失败" "$(echo "$r" | jcode)" "10001"
r=$(post /files/delete "{\"path\":\"$ROOT/sub\",\"allow_dir\":true}"); chk "allow_dir=true 可删" "$(echo "$r" | jcode)" "0"

say "=== 12. 清理 ==="
r=$(post /files/delete "{\"path\":\"$ROOT\",\"allow_dir\":true}"); chk "删临时根目录" "$(echo "$r" | jcode)" "0"
r=$(get "/files/stat?path=$ROOT"); chk "临时目录已消失" "$(echo "$r" | jcode)" "10004"
n=$(get /files/trash | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["data"]["items"]))')
chk "回收站残留 0 条" "$n" "0"

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
