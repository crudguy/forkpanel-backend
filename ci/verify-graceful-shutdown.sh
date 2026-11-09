#!/usr/bin/env bash
# 真机 SIGTERM 优雅关闭验收（生产就绪度 P1 / G6 的行为判据）。
#
# 只断言源码接线抓不到「信号根本没接上」或「接了但进程没干净退出」：
# 这里起独立实例 → 发 SIGTERM → 检查退出码、日志标记与端口释放。
#
# 用法：bash ci/verify-graceful-shutdown.sh [panel 二进制路径]
#   默认 ./target/debug/panel（先 cargo build --bin panel）
#   PANEL_SHUT_PORT 可改端口（默认 20842，避开 dev 2083 / e2e 20840 / hdr 20841）
# 环境不具备（无二进制 / curl / 端口被占）⇒ 非零退出，不冒充通过。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/panel}"
PORT="${PANEL_SHUT_PORT:-20842}"
BASE="http://127.0.0.1:${PORT}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/forkpanel-shut-XXXXXX")"
CFG="$TMP/cfg/config.toml"
PASS=0; FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
die()  { say "!! $*"; exit 1; }

kill_instance() {
  local p
  for p in $(pgrep -f -- "$CFG" 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
}
cleanup() { kill_instance; rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT

[ -x "$BIN" ] || die "找不到可执行文件：$BIN（先 cargo build --bin panel）"
command -v curl >/dev/null 2>&1 || die "缺少 curl"
if curl -s -o /dev/null -m 1 "$BASE/api/v1/version" 2>/dev/null; then
  die "端口 $PORT 已有服务在应答——换 PANEL_SHUT_PORT，避免误测到别人的实例"
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

"$BIN" init --config "$CFG" --owner shutcheck --owner-pass 'ShutAccept2026x' >/dev/null 2>&1 \
  || die "init 失败（配置见 $CFG）"

# wrapper 记录真实退出码：SIGTERM 若被进程直接终止，这里会是 143 而不是 0。
BIN="$BIN" CFG="$CFG" TMP="$TMP" setsid bash -c \
  '"$BIN" serve --config "$CFG" > "$TMP/panel.log" 2>&1; printf "PANEL_EXIT=%s\n" "$?" >> "$TMP/panel.log"' \
  < /dev/null > /dev/null 2>&1 &
disown 2>/dev/null || true
for _ in $(seq 1 25); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)"
  [ "$code" = "200" ] && break
  sleep 1
done
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)" = "200" ] \
  || { tail -30 "$TMP/panel.log" >&2 2>/dev/null || true; die "实例未就绪（端口 $PORT）"; }

# 精确找 panel 进程（不能用 pgrep -x panel：会连开发实例一起杀）。
PANEL_PID=""
for p in $(pgrep -f -- "$CFG" 2>/dev/null); do
  [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "panel" ] && PANEL_PID="$p"
done
[ -n "$PANEL_PID" ] || die "找不到本次实例的 panel 进程"

say "=== SIGTERM 优雅关闭真机验收（pid=$PANEL_PID, $BASE）==="
kill -TERM "$PANEL_PID"
for _ in $(seq 1 30); do
  [ ! -d "/proc/$PANEL_PID" ] && break
  sleep 0.5
done
if [ -d "/proc/$PANEL_PID" ]; then
  bad "SIGTERM 后 15s 内进程仍未退出（信号没接上或关闭流程挂住）"
else
  ok "SIGTERM 后进程在 15s 内退出"
fi

LOG="$(cat "$TMP/panel.log" 2>/dev/null || true)"
case "$LOG" in
  *"收到 SIGTERM，开始优雅关闭"*) ok "日志有优雅关闭标记（信号确实被处理）" ;;
  *) bad "日志没有优雅关闭标记——SIGTERM 可能被默认动作直接终止，没走 graceful shutdown" ;;
esac
case "$LOG" in
  *"PANEL_EXIT=0"*) ok "退出码 0（不是 143 的默认 SIGTERM 终止）" ;;
  *) bad "没有 PANEL_EXIT=0（见日志尾部）" ;;
esac
case "$LOG" in
  *"panicked at"*|*"Aborted"*) bad "关闭过程出现 panic / abort" ;;
  *) ok "关闭过程无 panic / abort" ;;
esac
if curl -s -o /dev/null -m 1 "$BASE/api/v1/version" 2>/dev/null; then
  bad "关闭后端口仍可应答（服务没退干净）"
else
  ok "关闭后端口已释放"
fi

say ""
say "──────── 结果：PASS=$PASS FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
say "PASS：SIGTERM 走优雅关闭，进程以 0 退出且端口释放"
exit 0
