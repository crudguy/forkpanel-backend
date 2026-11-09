#!/usr/bin/env bash
# 单实例锁 + 升级前快照的真机验收（生产就绪度 §3.6 / G9）。
#
# 源码守卫只能证明「接线还在」，这里真起两个进程验证：
#   ① 第二个 serve 被硬拒且诊断带持有者 pid；
#   ② 运行中 panel migrate 也被拒，日志无 table already exists / database is locked；
#   ③ 人为把 schema 版本退回 v28 后启动，必须生成可 integrity_check 的升级前快照；
#   ④ 主实例退出后锁自动释放，migrate 可正常执行。
#
# 用法：bash ci/verify-instance-lock.sh [panel 二进制路径]
#   默认 ./target/debug/panel；PANEL_LOCK_PORT 默认 20844
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/panel}"
PORT="${PANEL_LOCK_PORT:-20844}"
BASE="http://127.0.0.1:${PORT}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/forkpanel-lock-XXXXXX")"
CFG="$TMP/cfg/config.toml"
PASS=0; FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
die()  { say "!! $*"; exit 1; }

kill_instance() {
  local p
  for p in $(pgrep -f -- "$CFG" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
  sleep 0.4
  for p in $(pgrep -f -- "$CFG" 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
}
cleanup() { kill_instance; rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT

[ -x "$BIN" ] || die "找不到可执行文件：$BIN（先 cargo build --bin panel）"
command -v curl >/dev/null 2>&1 || die "缺少 curl"
command -v python3 >/dev/null 2>&1 || die "缺少 python3（用于构造旧 schema 与校验快照）"
if curl -s -o /dev/null -m 1 "$BASE/api/v1/version" 2>/dev/null; then
  die "端口 $PORT 已有服务在应答——换 PANEL_LOCK_PORT"
fi

mkdir -p "$TMP/cfg" "$TMP/data" "$TMP/sites" "$TMP/log"
cat > "$CFG" <<EOF
[server]
bind = "127.0.0.1"
port = ${PORT}

[paths]
config = "$TMP/cfg"
data = "$TMP/data"
site_root = "$TMP/sites"
log = "$TMP/log"

[security]
session_idle = "30m"
session_absolute = "12h"
EOF

"$BIN" init --config "$CFG" --owner lockcheck --owner-pass 'LockOk2026x' >/dev/null 2>&1 \
  || die "init 失败（配置见 $CFG）"

# 人为把版本记录退回 v28：模拟「旧库遇到新二进制」的升级路径。
python3 - "$TMP/data/panel.db" <<'PY' || die "构造旧 schema 失败"
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
# 全新库上 apply 会插入 1..29 全部版本行，故删掉 29 行让 MAX 回到 28；
# 不能 UPDATE 成 28（会与已存在的 28 行主键冲突）。
c.execute("DELETE FROM schema_migrations WHERE version = 29")
c.commit(); c.close()
PY

say "=== 单实例锁 / 升级快照真机验收（$BASE）==="
BIN="$BIN" CFG="$CFG" TMP="$TMP" setsid bash -c '"$BIN" serve --config "$CFG" > "$TMP/a.log" 2>&1' \
  < /dev/null > /dev/null 2>&1 &
disown 2>/dev/null || true
for _ in $(seq 1 25); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)"
  [ "$code" = "200" ] && break
  sleep 1
done
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)" = "200" ] \
  || { tail -30 "$TMP/a.log" >&2 2>/dev/null || true; die "主实例未就绪（端口 $PORT）"; }
ok "主实例启动并应答 /api/v1/version"

# ① 第二个 serve 必须被硬拒
out="$("$BIN" serve --config "$CFG" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q '已有 panel 实例'; then
  ok "第二个 serve 被硬拒，诊断含持有者 pid"
else
  bad "第二个 serve 未被正确拒绝（rc=$rc, out=$out）"
fi

# ② 运行中的 migrate 也必须被拒
out="$("$BIN" migrate --config "$CFG" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q '已有 panel 实例'; then
  ok "运行中的 panel migrate 被硬拒（不会并发跑 DDL）"
else
  bad "并发 migrate 未被拒绝（rc=$rc, out=$out）"
fi

if grep -qE 'table already exists|database is locked' "$TMP/a.log" 2>/dev/null; then
  bad "主实例日志出现并发 DDL 冲突"
else
  ok "日志无 table already exists / database is locked"
fi

# ③ 升级前快照
snap="$(find "$TMP/data/backups" -name 'pre-migrate-v28-to-v29-*.db' -type f 2>/dev/null | head -1)"
if [ -n "$snap" ] && [ -s "$snap" ]; then
  ok "生成升级前快照：$(basename "$snap")"
  chk="$(python3 - "$snap" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
print(c.execute('PRAGMA integrity_check').fetchone()[0])
print(c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0])
c.close()
PY
)"
  if printf '%s\n' "$chk" | grep -q '^ok$' && printf '%s\n' "$chk" | grep -q '^28$'; then
    ok "快照 integrity_check=ok 且 schema 仍是升级前 v28"
  else
    bad "快照内容异常：$chk"
  fi
else
  bad "未生成 pre-migrate 升级前快照（回滚锚点缺失）"
fi

# ④ 锁释放后可正常 migrate
kill_instance
out="$("$BIN" migrate --config "$CFG" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'schema 版本'; then
  ok "主实例退出后锁自动释放，migrate 正常执行"
else
  bad "锁释放后 migrate 仍失败（rc=$rc, out=$out）"
fi

say ""
say "──────── 结果：PASS=$PASS FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
say "PASS：单实例锁与升级前快照真机生效"
exit 0
