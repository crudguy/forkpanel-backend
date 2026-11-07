#!/usr/bin/env bash
# release panic 策略 ↔ CatchPanicLayer 兜底能力 的兼容性守卫（上线阻断项 P0）。
#
# 背景：CatchPanicLayer 基于 std::panic::catch_unwind；[profile.release] 设成
# panic="abort" 时 panic 不展开，兜底层完全失效，任一请求 panic 都会让以 root
# 运行的面板整进程 abort。而 panic_guard.rs 的端到端单测跑在默认 dev profile
# （unwind）下，改坏 release profile 照样恒绿 —— 这类跨 profile 的接线只能用
# 源码级守卫钉住，且必须真的接进 make guards 才算在跑。
#
# 恒绿纪律：
#   ① 提取前提先断言（段存在 / panic 键恰好 1 处 / 兜底层恰好 1 处），
#      提取塌成 0 一律判红，绝不「0 个文件均在限额内」式通过；
#   ② 断言前剔注释，注释里写了 "unwind" 不算数；
#   ③ 判据直接盯被检查的那份文件（Cargo.toml / routes.rs / panic_guard.rs），
#      不靠别的脚本转述，也不靠测试自己持有的实现。
#
# 负向对照：把 Cargo.toml 的 panic 改回 "abort"，本脚本必须判红；改回
# "unwind" 必须转绿。删掉 [profile.release] 段或 routes.rs 的 layer 同样判红。
#
# 用法：./ci/check-release-panic.sh [仓库根目录]
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

FAIL=0
fail() { echo "  ✗ $1"; FAIL=1; }
pass() { echo "  ✓ $1"; }

CARGO="Cargo.toml"
ROUTES="crates/panel-api/src/routes.rs"
GUARD="crates/panel-api/src/panic_guard.rs"

for f in "$CARGO" "$ROUTES" "$GUARD"; do
  [ -s "$f" ] || fail "$f 不存在或为空——提取前提不成立，绝不能当作通过"
done
if [ "$FAIL" -ne 0 ]; then
  echo "✗ $(basename "$0")：前提不成立"
  exit 1
fi

# 只在 [profile.release] 段内取值：遇到下一个 [xxx] 段即停，并剔掉行内注释。
REL=$(awk '/^\[profile\.release\]/ {f=1; next} f && /^\[/ {exit} f {print}' "$CARGO" | sed 's/#.*//')

echo "== [1] release 段存在且 panic 键恰好一处 =="
PANIC_CNT=$(printf '%s\n' "$REL" | grep -cE '^[[:space:]]*panic[[:space:]]*=')
if [ "$PANIC_CNT" -eq 1 ]; then
  pass "[profile.release] 内 panic 键恰好 1 处"
else
  fail "[profile.release] 内 panic 键应恰好 1 处，实得 $PANIC_CNT（段被删/被搬/写重了都会恒绿）"
fi

echo "== [2] release 的 panic 策略必须是 unwind =="
if [ "$PANIC_CNT" -eq 1 ] && printf '%s\n' "$REL" | grep -qE '^[[:space:]]*panic[[:space:]]*=[[:space:]]*"unwind"[[:space:]]*$'; then
  pass "release panic=unwind，CatchPanicLayer 能真正捕获 handler panic"
else
  fail "release panic 不是 unwind（abort 会让整个 root 面板进程终止，且 dev 单测恒绿）"
fi

echo "== [3] 生产路由确实挂了 panic 兜底层 =="
WIRED=$(grep -vE '^[[:space:]]*//' "$ROUTES" | grep -c 'CatchPanicLayer::custom(crate::panic_guard::handle_panic)')
if [ "$WIRED" -eq 1 ]; then
  pass "build_router 内 CatchPanicLayer 恰好 1 处（已剔注释）"
else
  fail "build_router 内 CatchPanicLayer 应恰好 1 处，实得 $WIRED"
fi

echo "== [4] 端到端 panic→500 用例仍在（防止只剩静态断言） =="
if grep -q 'panicking_handler_becomes_structured_500' "$GUARD"; then
  pass "panic_guard 的端到端用例存在（cargo test --release 可复跑）"
else
  fail "panic_guard 的端到端用例被删，行为证据消失"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "✗ $(basename "$0")：release panic 兜底守卫未通过"
  exit 1
fi
echo "PASS：release panic 策略与 CatchPanicLayer 兼容"
exit 0
