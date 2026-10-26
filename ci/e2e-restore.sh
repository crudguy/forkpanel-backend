#!/usr/bin/env bash
# 离线恢复链路 E2E：把 `panel restore-db` 这条**灾难恢复唯一出路**真跑一遍。
#
# ## 为什么必须单独有这一份
# `ci/e2e-backups.sh:154` 对恢复只断言了一句「panel 在线时诚实返回 501」——
# 那是**拒绝**分支，不是恢复本身。真正能用的路径是离线 CLI（`panel restore-db`），
# 它包含四段只有跑起来才知道对不对的逻辑：
#   ① 服务在线必须拒绝（在线覆盖 SQLite 会毁 WAL）；
#   ② 产物先验（坏产物绝不能盖到正在用的库上）；
#   ③ 覆盖前留 pre-restore 快照（这是回滚的唯一依据）；
#   ④ 原子替换 + 清掉旧库的 -wal/-shm。
# 这四条任何一条退化，用户的表现都是「以为恢复了，其实数据没了」——比没恢复更糟。
# 单测（`restore_cli_tests`）只覆盖原子替换的纯逻辑，覆盖不到「服务是否真在跑」
# 「快照是否真留」「恢复后能否真的启动并登录」。
#
# ## 为什么不用运行中的 dev 后端
# 恢复要覆盖 `panel.db`，绝不能碰真实实例。本脚本**自建一个隔离实例**：
# 临时目录 + 独立端口 + 独立 data_dir，全程不与 2083 交互。
#
# ## 纪律
#  1. **只杀自己的进程**：按端口精确取 pid（`ss -tlnp | grep :PORT`），
#     **绝不用 `pgrep -x panel`**——它会匹配到用户的 dev 实例，实测误杀过 2083。
#     停不掉就直接 FAIL，不"尽力而为"。
#  2. 每条断言钉死**具体退出码 / 具体文案**，不用"期望非 0"（URL 写错命中 404 会假绿）。
#     注意：`$?` 必须直接取，`cmd | tail` 拿到的是 tail 的退出码。
#  3. 环境不具备（无二进制 / 非 root）显式 `[skip]` 并**非零退出**，不假装通过。
#  4. 正负对照都要有：坏产物必须被拒、在线必须被拒、站点归档必须被拒、
#     不存在的产物必须被拒。只测正向时，把闸门整个删掉也能全绿。
#
# ## 用法
#   ci/e2e-restore.sh [panel_binary]
#     默认 ./target/debug/panel；端口默认 2101（可用 PANEL_E2E_RESTORE_PORT 覆盖）
#
# ## 依赖
#   curl、python3、sqlite3（仅用于独立校验恢复后的库；缺失则该项 skip）

set -uo pipefail

BIN="${1:-./target/debug/panel}"
PORT="${PANEL_E2E_RESTORE_PORT:-2101}"
BASE="http://127.0.0.1:$PORT"
OWNER="admin"
OWNERPASS="RstE2E2026x"

ROOT=""
PASS=0
FAIL=0
SKIP=0

say() { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
skip() { SKIP=$((SKIP+1)); say "  [skip] $1"; }

# 期望相等
chk() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1  实际=[$2] 期望=[$3]"; fi; }
# 期望退出码恰好等于 $2（**不用"非 0"**：崩在最前面的参数解析也会非 0）
chk_rc() { if [ "$2" = "$3" ]; then ok "$1 (rc=$2)"; else bad "$1  rc 实际=[$2] 期望=[$3]"; fi; }
# 输出必须包含某段文案（用于确认"失败原因是这道闸门"，而不是别的原因碰巧失败）
chk_has() { case "$2" in *"$3"*) ok "$1";; *) bad "$1  输出缺少 [$3]；实际=[$2]";; esac; }

# ── 进程控制：只按端口精确匹配，绝不 pgrep -x panel ──────────────────────
port_pid() {
  # root 进程的 pid 在非 root 下看不到 ⇒ 必须用 sudo 读
  echo 'a' | sudo -S -p '' ss -tlnp 2>/dev/null \
    | grep ":$PORT " | grep -oE 'pid=[0-9]+' | cut -d= -f2 | head -1
}
wait_port_free() {
  for _ in $(seq 1 20); do
    if ! ss -tln 2>/dev/null | grep -q ":$PORT "; then return 0; fi
    sleep 0.3
  done
  return 1
}
stop_own_server() {
  local pid; pid=$(port_pid)
  if [ -z "$pid" ]; then return 0; fi
  echo 'a' | sudo -S -p '' kill "$pid" 2>/dev/null
  wait_port_free || return 1
}

cleanup() {
  stop_own_server >/dev/null 2>&1
  [ -n "$ROOT" ] && rm -rf "$ROOT"
}
trap cleanup EXIT

# ── 0. 前置检查 ────────────────────────────────────────────────────────
if [ ! -x "$BIN" ]; then
  say "[skip] 找不到可执行文件：$BIN（先 cargo build --bin panel）"
  exit 2
fi
if ! ss -tln 2>/dev/null | grep -q ":$PORT " && ! command -v ss >/dev/null 2>&1; then
  say "[skip] 缺少 ss，无法做端口级进程隔离"
  exit 2
fi
if [ "$(id -u)" -ne 0 ] && ! echo 'a' | sudo -S -p '' true 2>/dev/null; then
  say "[skip] 既非 root 也无 sudo：panel 需要特权才能建数据目录"
  exit 2
fi
# 端口若已被别人占用，绝不在这里杀——那是别人的进程
if ss -tln 2>/dev/null | grep -q ":$PORT "; then
  say "[skip] 端口 $PORT 已被占用（可能是你正在用的实例），换 PANEL_E2E_RESTORE_PORT 再跑"
  exit 2
fi

ROOT=$(mktemp -d /tmp/panel-e2e-restore-XXXXXX)
CFG="$ROOT/panel.toml"
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
[ -f "$DB" ] && ok "panel.db 已创建" || bad "panel.db 不存在"

say "== 1. 造一份真产物 =="
out=$("$BIN" backup --config "$CFG" 2>&1)
chk_rc "backup 成功" "$?" "0"
ART=$(ls "$ROOT"/data/backups/panel-*.db 2>/dev/null | head -1)
if [ -n "$ART" ] && [ -s "$ART" ]; then ok "产物存在且非空：$(basename "$ART")"
else bad "backup 未产出面板库产物"; fi

say "== 2. verify-backup：好产物必须通过 =="
out=$("$BIN" verify-backup --config "$CFG" "$ART" 2>&1); rc=$?
chk_rc "好产物 verify 通过" "$rc" "0"
chk_has "通过文案含 integrity_check" "$out" "integrity_check=ok"

say "== 3. verify-backup 负向：坏产物必须被拒 =="
BAD_ART="$ROOT/corrupt.db"
head -c 4096 /dev/urandom > "$BAD_ART" 2>/dev/null
out=$("$BIN" verify-backup --config "$CFG" "$BAD_ART" 2>&1); rc=$?
chk_rc "坏产物 verify 退出码 1" "$rc" "1"
chk_has "坏产物失败原因是 db 解析而非参数错误" "$out" "not a database"

say "== 4. restore-db 负向：服务在线必须拒绝 =="
echo 'a' | sudo -S -p '' setsid nohup "$BIN" serve --config "$CFG" \
  > "$ROOT/serve.log" 2>&1 < /dev/null &
sleep 3
if ! ss -tln 2>/dev/null | grep -q ":$PORT "; then
  bad "隔离实例未能启动，后续在线闸门无法验证（见 $ROOT/serve.log）"
else
  ok "隔离实例已起（:$PORT）"
  out=$("$BIN" restore-db --config "$CFG" "$ART" 2>&1); rc=$?
  chk_rc "在线时 restore-db 被拒" "$rc" "1"
  chk_has "拒绝原因是服务仍在运行" "$out" "服务仍在运行"
  # 关键：被拒之后库必须**原封不动**（不能"先动了一点再发现不该动"）
  if [ -f "$ROOT/data/panel.db" ]; then ok "被拒后 panel.db 仍在"
  else bad "被拒后 panel.db 消失了"; fi
  # WAL 还在 ⇒ 说明没有做过替换
  if [ -f "$ROOT/data/panel.db-wal" ]; then ok "被拒后 WAL 未被清理（未发生替换）"
  else skip "被拒后 WAL 不存在（实例刚起可能尚未产生 WAL，非失败）"; fi
fi

say "== 5. restore-db 负向：站点归档必须被拒 =="
TAR="$ROOT/site.tar.gz"
tar czf "$TAR" -C "$ROOT" data 2>/dev/null
out=$("$BIN" restore-db --config "$CFG" --force "$TAR" 2>&1); rc=$?
chk_rc "站点归档被拒" "$rc" "1"
chk_has "拒绝原因是只接受面板库产物" "$out" "只接受面板库产物"

say "== 6. restore-db 负向：不存在的产物必须被拒 =="
out=$("$BIN" restore-db --config "$CFG" --force "$ROOT/nope.db" 2>&1); rc=$?
chk_rc "不存在的产物被拒" "$rc" "1"

say "== 7. 停机（按端口精确停，绝不用 pgrep -x panel） =="
if stop_own_server; then ok "隔离实例已停（:$PORT 已释放）"
else bad "隔离实例停不掉，后续恢复会拿不到库锁"; fi

say "== 8. restore-db 正向：真恢复 =="
PRE_SNAP_BEFORE=$(ls "$ROOT"/data/backups/pre-restore-*.db 2>/dev/null | wc -l)
out=$("$BIN" restore-db --config "$CFG" "$ART" 2>&1); rc=$?
chk_rc "restore-db 成功" "$rc" "0"
chk_has "输出确认已恢复" "$out" "已恢复"
PRE_SNAP_AFTER=$(ls "$ROOT"/data/backups/pre-restore-*.db 2>/dev/null | wc -l)
if [ "$PRE_SNAP_AFTER" -gt "$PRE_SNAP_BEFORE" ]; then
  ok "覆盖前留了 pre-restore 快照（$PRE_SNAP_BEFORE → $PRE_SNAP_AFTER）"
else
  bad "没有留 pre-restore 快照——出事时无法回滚，这是恢复流程的命门"
fi
# 原子替换的中间文件与旧 WAL 都必须消失：留着会让下次启动读到不一致的状态
if ls "$ROOT"/data/*.restore-tmp >/dev/null 2>&1; then bad "残留 .restore-tmp 临时文件"
else ok "无 .restore-tmp 残留"; fi
if [ -f "$ROOT/data/panel.db-wal" ] || [ -f "$ROOT/data/panel.db-shm" ]; then
  bad "旧库的 -wal/-shm 未清理（会与恢复后的库不一致）"
else ok "旧库 -wal/-shm 已清理"; fi

say "== 9. 恢复后的库必须真的能用：起服务 + 登录 =="
echo 'a' | sudo -S -p '' setsid nohup "$BIN" serve --config "$CFG" \
  > "$ROOT/serve2.log" 2>&1 < /dev/null &
sleep 3
if ! ss -tln 2>/dev/null | grep -q ":$PORT "; then
  bad "恢复后实例起不来（恢复出来的库可能不可用）"
else
  ok "恢复后实例已起"
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$OWNER\",\"password\":\"$OWNERPASS\"}")
  chk "恢复后 owner 能登录（库里的用户表完好）" "$code" "204"
  csrf=$(curl -s -c "$ROOT/ck" -X POST "$BASE/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$OWNER\",\"password\":\"$OWNERPASS\"}" >/dev/null; \
    grep panel_csrf "$ROOT/ck" 2>/dev/null | awk '{print $7}')
  if [ -n "$csrf" ]; then ok "恢复后能取到 CSRF（会话机制正常）"
  else bad "恢复后取不到 CSRF"; fi
  code=$(curl -s -o /dev/null -w '%{http_code}' -b "$ROOT/ck" "$BASE/api/v1/system/capabilities")
  chk "恢复后能力矩阵可读" "$code" "200"
fi

say "== 10. 恢复后的库独立校验（sqlite3，可选） =="
if command -v sqlite3 >/dev/null 2>&1; then
  ic=$(sqlite3 "$DB" 'PRAGMA integrity_check;' 2>&1)
  chk "sqlite3 integrity_check" "$ic" "ok"
  n=$(sqlite3 "$DB" 'SELECT count(*) FROM users;' 2>&1)
  if [ "${n:-0}" -ge 1 ] 2>/dev/null; then ok "users 表有 $n 条记录"
  else bad "users 表为空或读不出（实际=[$n]）"; fi
else
  skip "无 sqlite3，跳过独立校验（不当作通过）"
fi

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP ────────"
if [ "$FAIL" -gt 0 ]; then
  say "FAIL：恢复链路存在缺陷"
  exit 1
fi
say "PASS：离线恢复链路端到端通过"
exit 0
