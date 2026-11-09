#!/usr/bin/env bash
# 主密钥与备份的三方恢复演练（G12）。
#
# ## 这份脚本验收的是什么
# `docs/production-readiness-2026-11-07.md` §4.2 G12 的三条判据，逐条落成断言：
#   ① 备份 `encrypt` **默认开启**，产物 **0600**；
#   ② `master.key` 的异地离线副本能导出、能校验、**真能开锁**；
#   ③ `panel.db` + `master.key` + 备份**三方恢复**走通，且「丢密钥 / 换密钥」
#      两条应急路径的行为都被钉死。
#
# ## 为什么必须真跑，而不是单测
# 这四条只有把进程停掉、把库删掉、把密钥删掉之后才会暴露：
#   - 恢复时若偷偷**新生成**一把主密钥，`aes-gcm decrypt` 失败会被误判成"产物损坏"（实测踩过）；
#   - 加密产物的临时文件名若与明文临时文件撞名，会边读边写同一个文件，产物无限增长
#     （实测一次跑出 438MB 的 `.part` 才停）；
#   - 换钥后旧产物是否真解不开、旧副本是否真失效，只能拿**真密钥**试。
#
# ## 纪律
#  1. 只杀自己的进程：按端口精确取 pid（`ss -tlnp | grep :PORT`），**绝不 `pgrep -x panel`**
#     ——那会匹配到用户正在用的 dev 实例。
#  2. 每条断言钉死具体退出码 / 具体文案，不用"期望非 0"（URL 写错命中 404 也会非 0）。
#     注意 `$?` 必须直接取；`cmd | head` 拿到的是 head 的退出码。
#  3. 环境不具备（无二进制 / 无特权 / 端口被占）显式 `[skip]` 并**非零退出**，不假装通过。
#  4. 正负对照成对出现：只测正向时，把闸门整个删掉也能全绿。
#
# ## 用法
#   ci/e2e-key-drill.sh [panel_binary]
#     默认 ./target/debug/panel；端口默认 2102（PANEL_E2E_KEY_PORT 覆盖）
#
# ## 依赖
#   curl、python3、ss、tar

set -uo pipefail

BIN="${1:-./target/debug/panel}"
PORT="${PANEL_E2E_KEY_PORT:-2102}"
BASE="http://127.0.0.1:$PORT"
OWNER="admin"
OWNERPASS="KeyDrill2026x"

ROOT=""
PASS=0
FAIL=0
SKIP=0

say() { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
skip() { SKIP=$((SKIP+1)); say "  [skip] $1"; }

chk() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1  实际=[$2] 期望=[$3]"; fi; }
chk_rc() { if [ "$2" = "$3" ]; then ok "$1 (rc=$2)"; else bad "$1  rc 实际=[$2] 期望=[$3]"; fi; }
chk_has() { case "$2" in *"$3"*) ok "$1";; *) bad "$1  输出缺少 [$3]；实际=[$2]";; esac; }

# ── 进程控制：只按端口精确匹配 ─────────────────────────────────────────
port_pid() {
  echo 'a' | sudo -S -p '' ss -tlnp 2>/dev/null \
    | grep ":$PORT " | grep -oE 'pid=[0-9]+' | cut -d= -f2 | head -1
}
wait_port_free() {
  for _ in $(seq 1 20); do
    ss -tln 2>/dev/null | grep -q ":$PORT " || return 0
    sleep 0.3
  done
  return 1
}
stop_own_server() {
  local pid; pid=$(port_pid)
  [ -z "$pid" ] && return 0
  echo 'a' | sudo -S -p '' kill "$pid" 2>/dev/null
  # ⚠ 端口先释放 **不等于** 进程已退出：优雅关闭会先摘掉 listener、再走完收尾，
  #   而实例锁是按「pid 是否存活」判定的。只等端口就重启，新进程会撞锁：
  #   「已有 panel 实例持有 data/panel.lock（锁文件记录 pid=…）」（实测踩过）。
  #   故这里等 /proc/<pid> 消失——它对属主/权限不敏感，僵尸被回收后也会消失。
  for _ in $(seq 1 40); do
    [ -d "/proc/$pid" ] || break
    sleep 0.2
  done
  wait_port_free
}
# 等端口就绪（最多 ~6s）：固定 sleep 3 在慢机器上会偶发假红
wait_serving() {
  for _ in $(seq 1 20); do
    ss -tln 2>/dev/null | grep -q ":$PORT " && return 0
    sleep 0.3
  done
  return 1
}
# 起不来时把日志尾巴打出来：只报「起不来」等于让下一个人重跑一遍
show_serve_log() {
  say "    ── $1 最后 8 行 ──"
  tail -8 "$1" 2>/dev/null | sed 's/^/    /'
}
cleanup() {
  stop_own_server >/dev/null 2>&1
  [ -n "$ROOT" ] && rm -rf "$ROOT"
}
trap cleanup EXIT

# ── 0. 前置检查 ───────────────────────────────────────────────────────
if [ ! -x "$BIN" ]; then
  say "[skip] 找不到可执行文件：$BIN（先 cargo build --bin panel）"
  exit 2
fi
if [ "$(id -u)" -ne 0 ] && ! echo 'a' | sudo -S -p '' true 2>/dev/null; then
  say "[skip] 既非 root 也无 sudo：serve 需要特权才能建数据目录"
  exit 2
fi
if ss -tln 2>/dev/null | grep -q ":$PORT "; then
  say "[skip] 端口 $PORT 已被占用（可能是你正在用的实例），换 PANEL_E2E_KEY_PORT 再跑"
  exit 2
fi

ROOT=$(mktemp -d "/tmp/panel-e2e-key-$$-XXXX")
CFG="$ROOT/panel.toml"
OFFSITE="$ROOT/offsite"     # 模拟"异地离线介质"
mkdir -p "$OFFSITE"
cat > "$CFG" <<EOF
[server]
bind = "127.0.0.1"
port = $PORT
[paths]
config = "$ROOT/config"
data = "$ROOT/data"
log = "$ROOT/logs"
site_root = "$ROOT/sites"
EOF

say "== 0. 初始化隔离实例（$ROOT） =="
out=$("$BIN" init --config "$CFG" --owner "$OWNER" --owner-pass "$OWNERPASS" 2>&1)
chk_rc "init 成功" "$?" "0"
DB="$ROOT/data/panel.db"
KEY="$ROOT/data/master.key"
[ -f "$DB" ] && ok "panel.db 已创建" || bad "panel.db 不存在"
if [ -f "$KEY" ]; then
  chk "主密钥权限 0600" "$(stat -c %a "$KEY")" "600"
else
  bad "master.key 未生成"
fi

# ── 1. 判据②前半：备份默认加密 + 产物 0600 ─────────────────────────────
say "== 1. CLI 备份默认加密，产物 0600，且不留明文 =="
out=$("$BIN" backup --config "$CFG" 2>&1); rc=$?
chk_rc "panel backup 成功" "$rc" "0"
chk_has "产物是加密容器（.db.enc）" "$out" ".db.enc"
ART=$(ls "$ROOT"/data/backups/panel-*.db.enc 2>/dev/null | head -1)
if [ -n "$ART" ] && [ -s "$ART" ]; then ok "加密产物存在且非空：$(basename "$ART")"
else bad "未产出 .db.enc 产物"; fi
if [ -n "$ART" ]; then
  chk "产物权限 0600" "$(stat -c %a "$ART")" "600"
  # 同目录下不能有同名明文：有的话等于没加密
  if ls "$ROOT"/data/backups/panel-*.db >/dev/null 2>&1; then
    bad "加密产物旁边留下了明文 .db（等于没加密）"
  else ok "没有残留明文 .db"; fi
fi
# 明文模式仍要可用（负向对照的另一半）：产物必须是 0600 的 .db
out=$("$BIN" backup --config "$CFG" --out "$ROOT/plain.db" --no-encrypt 2>&1); rc=$?
chk_rc "--no-encrypt 可用" "$rc" "0"
if [ -f "$ROOT/plain.db" ]; then chk "明文产物也是 0600" "$(stat -c %a "$ROOT/plain.db")" "600"
else bad "--no-encrypt 未产出 .db"; fi

# ── 2. 起服务，验 API 侧默认加密 + 造一条真密文 ─────────────────────────
say "== 2. 起隔离实例并造真实密文（API） =="
echo 'a' | sudo -S -p '' setsid nohup "$BIN" serve --config "$CFG" \
  > "$ROOT/serve.log" 2>&1 < /dev/null &
if ! wait_serving; then
  bad "隔离实例未能启动（见 $ROOT/serve.log）；后续 API 断言无法进行"
  show_serve_log "$ROOT/serve.log"
  say ""
  say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP ────────"
  exit 1
fi
ok "隔离实例已起（:$PORT）"

CK="$ROOT/ck"
code=$(curl -s -c "$CK" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' -d "{\"username\":\"$OWNER\",\"password\":\"$OWNERPASS\"}")
chk "owner 登录 204" "$code" "204"
CSRF=$(grep panel_csrf "$CK" 2>/dev/null | awk '{print $7}')

say "== 3. 判据②：备份计划 encrypt 默认开启（请求里不带该字段） =="
code=$(curl -s -b "$CK" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/backups" \
  -H "x-csrf-token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"kind":"panel","target":"panel","dest_dir":"sched"}')
chk "创建计划 200" "$code" "200"
enc=$(curl -s -b "$CK" "$BASE/api/v1/backups" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d[0]["encrypt"] if d else "none")')
chk "省略 encrypt ⇒ 落库为 true" "$enc" "True"
# 反向：显式 false 必须被尊重（否则"默认开启"变成"无法关闭"）
code=$(curl -s -b "$CK" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/backups" \
  -H "x-csrf-token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"kind":"panel","target":"panel","dest_dir":"sched2","encrypt":false}')
chk "创建（显式 false）200" "$code" "200"
enc=$(curl -s -b "$CK" "$BASE/api/v1/backups" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print([x["encrypt"] for x in d if x["dest_dir"]=="sched2"][0])')
chk "显式 encrypt=false 必须是 false（不能强制加密）" "$enc" "False"

say "== 4. 造一条真密文：数据库连接口令 =="
code=$(curl -s -b "$CK" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/db/connections" \
  -H "x-csrf-token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"name":"drill","engine":"mysql","host":"127.0.0.1","port":3306,"user":"root","password":"P@ssw0rd-drill","default_db":"app"}')
chk "建 db 连接 200" "$code" "200"

# ── 5. 判据②：离线副本的导出与校验 ─────────────────────────────────────
say "== 5. key show / export / check =="
out=$("$BIN" key show --config "$CFG" 2>&1); rc=$?
chk_rc "key show 成功" "$rc" "0"
chk_has "show 打印 0600 权限" "$out" "0600"
chk_has "show 不打印密钥本体（只给指纹）" "$out" "指纹："
FP_OLD=$(printf '%s' "$out" | sed -n 's/^指纹：//p' | head -1)
if [ ${#FP_OLD} -eq 16 ]; then ok "指纹 16 位十六进制（$FP_OLD）"
else bad "指纹长度异常：[$FP_OLD]"; fi

out=$("$BIN" key export --config "$CFG" --out "$OFFSITE/master.key" 2>&1); rc=$?
chk_rc "导出离线副本成功" "$rc" "0"
chk "副本权限 0600" "$(stat -c %a "$OFFSITE/master.key")" "600"
chk "副本 32 字节" "$(stat -c %s "$OFFSITE/master.key")" "32"

out=$("$BIN" key export --config "$CFG" --out "$ROOT/data/master.key.bak" 2>&1); rc=$?
chk_rc "导出到数据目录必须被拒" "$rc" "1"
chk_has "拒绝原因是「同盘等于没备份」" "$out" "同盘等于没备份"

out=$("$BIN" key export --config "$CFG" --out "$OFFSITE/master.key" 2>&1); rc=$?
chk_rc "覆盖已存在副本必须被拒" "$rc" "1"

head -c 16 /dev/urandom > "$ROOT/short.key"
out=$("$BIN" key check --config "$CFG" "$ROOT/short.key" 2>&1); rc=$?
chk_rc "16 字节文件被拒" "$rc" "1"
chk_has "拒因点名字节数" "$out" "16 字节"

head -c 32 /dev/urandom > "$ROOT/wrong.key"
out=$("$BIN" key check --config "$CFG" "$ROOT/wrong.key" 2>&1); rc=$?
chk_rc "另一把 32 字节密钥被拒" "$rc" "1"
chk_has "拒因是「指纹不一致」" "$out" "指纹不一致"

out=$("$BIN" key check --config "$CFG" "$OFFSITE/master.key" 2>&1); rc=$?
chk_rc "正确副本 check 通过" "$rc" "0"
chk_has "check 真拿副本解开了库里的密文" "$out" "已用副本解开一条真实密文"
chk_has "命中的是数据库口令那一列" "$out" "password_enc"

# ── 6. 换密钥：三道闸门 + 真换 ────────────────────────────────────────
say "== 6. key rotate 的三道闸门 =="
out=$("$BIN" key rotate --config "$CFG" --yes 2>&1); rc=$?
chk_rc "服务在跑时换钥必须被拒" "$rc" "1"
chk_has "拒因是服务仍在运行" "$out" "服务仍在运行"

if stop_own_server; then ok "隔离实例已停（:$PORT 已释放）"
else bad "隔离实例停不掉，换钥会改到活动库"; fi

out=$("$BIN" key rotate --config "$CFG" --yes 2>&1); rc=$?
chk_rc "有旧密钥加密产物时换钥必须被拒" "$rc" "1"
chk_has "拒因是旧产物换钥后不可解" "$out" "旧密钥加密"
chk_has "并且给了 --force 这条出路" "$out" "--force"

out=$("$BIN" key rotate --config "$CFG" --force 2>&1); rc=$?
chk_rc "缺 --yes 必须被拒" "$rc" "1"
chk_has "拒因是未确认（--yes）" "$out" "--yes"

say "== 7. 真换钥 =="
out=$("$BIN" key rotate --config "$CFG" --force --yes 2>&1); rc=$?
chk_rc "换钥成功" "$rc" "0"
chk_has "报告各作用域行数" "$out" "重加密完成"
chk_has "命中数据库连接口令 1 行" "$out" "数据库连接口令 1"
if ls "$ROOT"/data/master.key.bak-* >/dev/null 2>&1; then ok "旧密钥留了 .bak-<ts>"
else bad "旧密钥没有留档——换错了无法回退"; fi
BAK=$(ls "$ROOT"/data/master.key.bak-* 2>/dev/null | head -1)
[ -n "$BAK" ] && chk "旧密钥备份权限 0600" "$(stat -c %a "$BAK")" "600"
FP_NEW=$("$BIN" key show --config "$CFG" 2>&1 | sed -n 's/^指纹：//p' | head -1)
if [ -n "$FP_NEW" ] && [ "$FP_NEW" != "$FP_OLD" ]; then ok "指纹已变（$FP_OLD → $FP_NEW）"
else bad "换钥后指纹没变（$FP_NEW）"; fi

say "== 8. 换钥后的三条行为（旧副本失效 / 新钥能开锁 / 旧产物解不开） =="
out=$("$BIN" key check --config "$CFG" "$OFFSITE/master.key" 2>&1); rc=$?
chk_rc "旧副本必须失效" "$rc" "1"
chk_has "拒因是「指纹不一致」" "$out" "指纹不一致"

out=$("$BIN" key check --config "$CFG" "$KEY" 2>&1); rc=$?
chk_rc "新密钥能开库里的密文" "$rc" "0"
chk_has "确实解开了密文（重加密没写坏）" "$out" "已用副本解开一条真实密文"

out=$("$BIN" verify-backup --config "$CFG" "$ART" 2>&1); rc=$?
chk_rc "旧密钥加密的产物必须解不开" "$rc" "1"
chk_has "报错给出了「上一代密钥」这条出路" "$out" "上一代主密钥"

# ── 9. 判据③：「丢密钥」分支 ───────────────────────────────────────────
say "== 9. 三方恢复：先用新钥造产物，再制造灾难 =="
out=$("$BIN" backup --config "$CFG" --out "$ROOT/data/backups/drill.db" 2>&1); rc=$?
chk_rc "用新钥造备份成功" "$rc" "0"
FRESH="$ROOT/data/backups/drill.db.enc"
[ -f "$FRESH" ] && ok "新产物：$(basename "$FRESH")" || bad "未产出 drill.db.enc"

out=$("$BIN" key export --config "$CFG" --out "$OFFSITE/new.key" 2>&1); rc=$?
chk_rc "导出新钥副本成功" "$rc" "0"

# 灾难：库没了、密钥没了，只剩备份与异地副本
rm -f "$DB" "$DB-wal" "$DB-shm" "$KEY"
if [ ! -f "$DB" ] && [ ! -f "$KEY" ]; then ok "已删除 panel.db 与 master.key（模拟整机损毁）"
else bad "灾难模拟失败：库或密钥仍在"; fi

out=$("$BIN" restore-db --config "$CFG" "$FRESH" 2>&1); rc=$?
chk_rc "丢密钥时恢复加密产物必须被拒" "$rc" "1"
chk_has "拒因是「没有它无法恢复」而不是 aead 报错" "$out" "没有它无法恢复"
chk_has "给了「找回离线副本」这条出路" "$out" "异地离线副本"
# 关键：拒绝时**不能**顺手生成一把新密钥——否则"丢密钥"被伪装成"产物损坏"
if [ -f "$KEY" ]; then bad "被拒时静默新建了 master.key（丢密钥会被误判成产物损坏）"
else ok "被拒时没有静默新建 master.key"; fi
if [ -f "$DB" ]; then bad "被拒后 panel.db 被创建了（不该动任何东西）"
else ok "被拒后没有创建 panel.db"; fi

say "== 10. 三方恢复：副本 → 密钥 → 库 → 服务 =="
cp "$OFFSITE/new.key" "$KEY" && chmod 600 "$KEY"
[ -f "$KEY" ] && ok "异地副本已放回 master.key" || bad "放回副本失败"
out=$("$BIN" key check --config "$CFG" "$OFFSITE/new.key" 2>&1); rc=$?
chk_rc "副本与在用密钥一致" "$rc" "0"

out=$("$BIN" restore-db --config "$CFG" "$FRESH" 2>&1); rc=$?
chk_rc "恢复成功" "$rc" "0"
chk_has "产物通过 integrity_check" "$out" "integrity_check=ok"
chk_has "输出确认已恢复" "$out" "已恢复"
if ls "$ROOT"/data/backups/pre-restore-*.db >/dev/null 2>&1; then ok "留了 pre-restore 快照"
else skip "没有 pre-restore 快照（库原本不存在，属预期）"; fi

echo 'a' | sudo -S -p '' setsid nohup "$BIN" serve --config "$CFG" \
  > "$ROOT/serve2.log" 2>&1 < /dev/null &
if ! wait_serving; then
  bad "恢复后实例起不来（恢复出来的库可能不可用）"
  show_serve_log "$ROOT/serve2.log"
else
  ok "恢复后实例已起"
  CK2="$ROOT/ck2"
  code=$(curl -s -c "$CK2" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/login" \
    -H 'Content-Type: application/json' -d "{\"username\":\"$OWNER\",\"password\":\"$OWNERPASS\"}")
  chk "恢复后 owner 能登录" "$code" "204"
  body=$(curl -s -b "$CK2" "$BASE/api/v1/db/connections")
  chk_has "恢复后数据回来了（drill 连接在）" "$body" "\"name\":\"drill\""
  chk_has "口令标记仍在（has_password）" "$body" "\"has_password\":true"
  out=$("$BIN" key check --config "$CFG" "$OFFSITE/new.key" 2>&1); rc=$?
  chk_rc "恢复后密文仍能被副本解开（三方闭环）" "$rc" "0"
  chk_has "确实解开了密文" "$out" "已用副本解开一条真实密文"
fi

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP ────────"
if [ "$FAIL" -gt 0 ]; then
  say "FAIL：主密钥/备份恢复链路存在缺陷"
  exit 1
fi
say "PASS：三方恢复 + 丢密钥 + 换密钥全部通过"
exit 0
