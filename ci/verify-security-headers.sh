#!/usr/bin/env bash
# 真机安全响应头验收（生产就绪度 P1-2 / G5 的行为判据）。
#
# 为什么必须真机：只断言「源码挂了 layer」抓不到 axum 的 `.fallback()` 语义坑——
# build_router 内的 layer 不包裹之后新增的 /healthz 与替换后的 SPA fallback，
# 编译、类型、单测、静态守卫可以全绿而登录页一个安全头都没有。
# 本脚本在临时目录拉起独立实例，对 7 类响应逐条用 curl 检查响应头。
#
# 用法：bash ci/verify-security-headers.sh [panel 二进制路径]
#   默认 ./target/debug/panel（先 cargo build --bin panel）
#   PANEL_HDR_PORT 可改端口（默认 20841，避开 dev 2083 / e2e 20840）
# 环境不具备（无二进制 / curl / 端口被占）⇒ 非零退出，不冒充通过。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/panel}"
PORT="${PANEL_HDR_PORT:-20841}"
BASE="http://127.0.0.1:${PORT}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/forkpanel-hdr-XXXXXX")"
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
  die "端口 $PORT 已有服务在应答——换 PANEL_HDR_PORT，避免误测到别人的实例"
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

"$BIN" init --config "$CFG" --owner hdrcheck --owner-pass 'HdrAccept2026x' >/dev/null 2>&1 \
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

ASSET="$(grep -oE '/assets/index\.[A-Za-z0-9_-]+\.js' "$ROOT/web/dist/index.html" 2>/dev/null | head -1)"
[ -n "$ASSET" ] || die "从 web/dist/index.html 提取不到入口 JS（先同步前端产物）"

PATHS=( "/" "$ASSET" "/healthz" "/api/v1/version" "/some/spa/route" "/api/v1/does-not-exist" "/assets/no-such-file.js" )
HEADERS=( x-frame-options content-security-policy referrer-policy permissions-policy x-content-type-options )

say "=== 安全响应头真机验收（$BASE）==="
for p in "${PATHS[@]}"; do
  hdr="$(curl -sS -D - -o /dev/null "$BASE$p" 2>/dev/null)"
  [ -n "$hdr" ] || { bad "$p 无响应"; continue; }
  missing=0
  for h in "${HEADERS[@]}"; do
    cnt="$(printf '%s\n' "$hdr" | grep -ci "^${h}:")"
    if [ "$cnt" -ne 1 ]; then
      bad "$p 的 $h 出现 $cnt 次（应为 1：0=漏挂，>1=双挂）"
      missing=1
    fi
  done
  csp="$(printf '%s\n' "$hdr" | grep -i '^content-security-policy:' | head -1)"
  case "$csp" in
    *"frame-ancestors 'none'"*) ;;
    *) bad "$p 的 CSP 缺 frame-ancestors 'none'"; missing=1 ;;
  esac
  [ "$missing" -eq 0 ] && ok "$p 五类安全头齐全且各一次"
done

say ""
say "──────── 结果：PASS=$PASS FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
say "PASS：SPA/静态资源/healthz/API/SPA 回退/404 均带安全响应头且无重复"
exit 0
