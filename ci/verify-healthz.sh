#!/usr/bin/env bash
# 就绪探针 /healthz 的真机行为判据（生产就绪度 P1 / G8）。
#
# 只断言「源码里写了检查」抓不到接线退化，也抓不到旧实现（恒返回 plain "ok"）。
# 本脚本在临时目录起独立实例，验 200 响应是 JSON、带 no-store、不泄露路径，
# 并确认 systemd 探活依赖的 /api/v1/version 仍可用。
# 503 分支不在真机模拟（不把盘写满），由 embed.rs 的 evaluate_health 四态单测
# 与 ci/check_healthz.py 源码守卫覆盖 —— 如实说明边界，不假装全覆盖。
#
# 用法：bash ci/verify-healthz.sh [panel 二进制路径]
#   默认 ./target/debug/panel；PANEL_HEALTH_PORT 默认 20843
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/panel}"
PORT="${PANEL_HEALTH_PORT:-20843}"
BASE="http://127.0.0.1:${PORT}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/forkpanel-health-XXXXXX")"
CFG="$TMP/cfg/config.toml"
PASS=0; FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
die()  { say "!! $*"; exit 1; }

kill_instance() {
  local p
  for p in $(pgrep -f -- "$CFG" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
  sleep 0.3
  for p in $(pgrep -f -- "$CFG" 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
}
cleanup() { kill_instance; rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT

[ -x "$BIN" ] || die "找不到可执行文件：$BIN（先 cargo build --bin panel）"
command -v curl >/dev/null 2>&1 || die "缺少 curl"
if curl -s -o /dev/null -m 1 "$BASE/api/v1/version" 2>/dev/null; then
  die "端口 $PORT 已有服务在应答——换 PANEL_HEALTH_PORT，避免误测到别人的实例"
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

"$BIN" init --config "$CFG" --owner healthcheck --owner-pass 'HealthOk2026x' >/dev/null 2>&1 \
  || die "init 失败（配置见 $CFG）"

BIN="$BIN" CFG="$CFG" TMP="$TMP" setsid bash -c '"$BIN" serve --config "$CFG" > "$TMP/panel.log" 2>&1' \
  < /dev/null > /dev/null 2>&1 &
disown 2>/dev/null || true
for _ in $(seq 1 25); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)"
  [ "$code" = "200" ] && break
  sleep 1
done
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)" = "200" ] \
  || { tail -30 "$TMP/panel.log" >&2 2>/dev/null || true; die "实例未就绪（端口 $PORT）"; }

say "=== 就绪探针真机验收（$BASE）==="
raw="$(curl -sS -i "$BASE/healthz" 2>/dev/null)"
head_line="$(printf '%s\n' "$raw" | head -1)"
case "$head_line" in *" 200 "*) ok "GET /healthz 返回 200" ;; *) bad "GET /healthz 状态异常：$head_line" ;; esac
case "$raw" in *'"status":"ok"'*) ok "响应是 JSON 且 status=ok（不是旧的 plain \"ok\"）" ;; *) bad "响应缺 status=ok：$raw" ;; esac
case "$raw" in *'no-store'*) ok "带 Cache-Control: no-store" ;; *) bad "缺 no-store（LB 可能缓存旧健康状态）" ;; esac
body="$(printf '%s\n' "$raw" | tail -1)"
case "$body" in
  *'/var/'*|*'/tmp/'*|*"$TMP"*) bad "响应泄露内部路径：$body" ;;
  *) ok "响应不含内部路径 / 错误详情" ;;
esac

code="$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)"
[ "$code" = "200" ] && ok "systemd 探活判据 /api/v1/version 仍 200" \
  || bad "探活判据 /api/v1/version 异常：$code"

say ""
say "──────── 结果：PASS=$PASS FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
say "PASS：/healthz 真机返回结构化健康状态（503 分支由四态单测 + 源码守卫覆盖）"
exit 0
