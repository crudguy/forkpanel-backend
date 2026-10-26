#!/usr/bin/env bash
# CI 真机 E2E runner：**自包含**——在临时目录拉起一个独立 panel 实例，跑十域 E2E，收尾清理。
# 任何 CI（GitHub Actions / GitLab CI / 本地 shell）都能直接调用：
#   bash ci/run-e2e-ci.sh
#
# ## 为什么要自包含
# E2E 需要一个**真的在跑的 panel**（有库、有 owner、能写）。复用开发机上的 dev 实例会：
# ① 状态不干净（上一轮残留会干扰断言）；② 无法在 CI 里复现；③ 写操作污染开发环境。
# 这里在临时目录里拉起**独立实例**：配置 / 数据 / 站点根 / 日志全部重定向到临时目录，
# **不碰 /etc 与 /var/lib，不需要 root**。
#
# ## 关键机制
# ① `panel init --config <cfg>` 在**配置文件已存在**时会复用它，并按 `[paths]` 覆盖建目录
#    ⇒ 先手写一份带 `[paths]` 的最小配置再 init ⇒ 全程零系统目录、零 sudo。
# ② 实例必须**脱离本会话**（setsid + disown）：否则 bash 退出会**等后台任务**，
#    脚本永远挂住（实测：bash -c 'sleep 30 &' 真的等了 30 秒）。
# ③ 进程 pid 用**唯一配置路径**反查（`pgrep -f "$CFG"`），不靠 `$!`——setsid 可能 fork，
#    `$!` 未必是最终 pid；且绝不能用 `pgrep -x panel`（会连开发实例一起杀）。
#
# ## 环境变量
#   PANEL_E2E_PORT       实例端口（默认 20840，避开开发实例 2083）
#   PANEL_E2E_USER/PASS  登录账号（默认 admin / CI 专用口令；**不用**开发口令）
#   PANEL_E2E_TIMEOUT    E2E 阶段超时秒数（默认 900）
#   PANEL_E2E_KEEP=1     保留临时目录与日志（排查用）
#   PANEL_E2E_RELEASE=1  用 release 构建（默认 debug，构建更快）
#   PANEL_E2E_SKIP_BUILD=1 跳过构建（复用已有二进制）
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PANEL_E2E_PORT:-20840}"
EUSER="${PANEL_E2E_USER:-admin}"
EPASS="${PANEL_E2E_PASS:-CiPreview2026x}"
BASE="http://127.0.0.1:${PORT}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/forkpanel-ci-XXXXXX")"
CFG="$TMP/cfg/config.toml"
BIN="$ROOT/target/debug/panel"

say() { printf '%s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

# 只杀**用本次配置路径**启动的进程（路径唯一 ⇒ 绝不误伤开发实例）。
kill_instance() {
  local p
  for p in $(pgrep -f -- "$CFG" 2>/dev/null); do
    kill "$p" 2>/dev/null || true
  done
  sleep 0.5
  for p in $(pgrep -f -- "$CFG" 2>/dev/null); do
    kill -9 "$p" 2>/dev/null || true
  done
}

cleanup() {
  # ⚠ 顺序：**先杀进程、再删目录**。反了会留下"日志已删但进程还在"的孤儿实例。
  kill_instance
  if [ "${PANEL_E2E_KEEP:-0}" = "1" ]; then
    say "（PANEL_E2E_KEEP=1：临时目录保留在 $TMP）"
  else
    rm -rf "$TMP" 2>/dev/null || true
  fi
}
trap cleanup EXIT

say "=== CI E2E：临时实例 $TMP（端口 $PORT）==="

# ── 1. 构建 ──
if [ "${PANEL_E2E_SKIP_BUILD:-0}" != "1" ]; then
  say "  · 构建 panel（${PANEL_E2E_RELEASE:+release}）…"
  if [ "${PANEL_E2E_RELEASE:-0}" = "1" ]; then
    ( cd "$ROOT" && cargo build --release --bin panel ) || die "构建失败"
    BIN="$ROOT/target/release/panel"
  else
    ( cd "$ROOT" && cargo build --bin panel ) || die "构建失败"
  fi
fi
[ -x "$BIN" ] || die "找不到可执行文件：$BIN"

# ── 2. 最小配置（[paths] 全指向临时目录 ⇒ 不写系统目录、不需要 root）──
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

# ── 3. 初始化（建目录 + 主密钥 + 库 + owner）──
say "  · 初始化实例（owner=$EUSER）…"
"$BIN" init --config "$CFG" --owner "$EUSER" --owner-pass "$EPASS" \
  || die "init 失败（配置见 $CFG）"

# ── 4. 起服务（脱离本会话 + disown：否则脚本退出时会等它，永远挂住）──
say "  · 启动服务…"
# 用一层薄 wrapper 记录**退出码**：CI 里实例若静默死亡（SIGKILL=137 / SIGSEGV=139 /
# panic=101 / 正常=0），日志里能直接看到，不必再复现一遍猜。
# ⚠ 三件事必须一起做，否则实例根本起不来而脚本还以为起来了：
# ① `bash -c '...'` 用单引号 ⇒ 里面的 `$BIN`/`$CFG`/`$TMP` 由**子 shell**展开，
#    而子 shell **不继承未 export 的变量** ⇒ 展开成空串，命令变成
#    `"" serve --config "" > "/panel.log"`（重定向到根目录 ⇒ 权限不足）。
#    所以先 export（或在 wrapper 里现取）。实测症状：日志永远是空的、
#    「实例未就绪」、而 `tail` 什么都打不出来。
# ② `< /dev/null` + `disown`：不脱离本会话的话 bash 退出会**等**这个后台任务而挂死。
# ③ `die` 必须真退出非 0（见下）。
BIN="$BIN" CFG="$CFG" TMP="$TMP" setsid bash -c '"$BIN" serve --config "$CFG" > "$TMP/panel.log" 2>&1; \
  printf "PANEL_EXIT=%s\n" "$?" >> "$TMP/panel.log"' < /dev/null > /dev/null 2>&1 &
disown 2>/dev/null || true
for _ in $(seq 1 25); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)"
  [ "$code" = "200" ] && break
  sleep 1
done
if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$BASE/api/v1/version" 2>/dev/null || echo 000)" != "200" ]; then
  say "—— 服务未就绪，panel 日志尾部 ——"
  tail -40 "$TMP/panel.log" >&2 2>/dev/null || true
  die "实例未就绪（端口 $PORT）"
fi
say "  ✓ 实例就绪：$BASE"

# ── 5. 跑十域 E2E（带超时：某个域卡住不能把 CI 拖死）──
say "  · 跑 E2E 十域…"
export PANEL_E2E_USER="$EUSER" PANEL_E2E_PASS="$EPASS"
rc=0
( cd "$ROOT" && timeout "${PANEL_E2E_TIMEOUT:-900}" bash ci/e2e-all.sh "$BASE" ) || rc=$?
if [ "$rc" -ne 0 ]; then
  say "—— E2E 失败（rc=$rc），panel 日志尾部 ——"
  tail -60 "$TMP/panel.log" >&2 2>/dev/null || true
  say "—— 临时目录：$TMP（PANEL_E2E_KEEP=1 可保留）——"
fi
exit $rc
