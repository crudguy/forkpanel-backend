#!/usr/bin/env bash
# 资源预算门禁：把"极低资源占用"变成构建期检查（设计方案 §3.7）
#
# 用法：./ci/check-budgets.sh [仓库根目录]
# 未构建产物时对应项自动跳过（骨架阶段不会误报失败）。
# 退出码：0 = 通过 / 跳过；1 = 超预算

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"
BUDGETS="ci/budgets.json"

command -v python3 >/dev/null 2>&1 || { echo "需要 python3"; exit 1; }

get() { python3 -c "import json,sys;print(json.load(open('$BUDGETS'))['$1'])" 2>/dev/null; }

FAIL=0
fail() { echo "  ✗ $1"; FAIL=1; }
pass() { echo "  ✓ $1"; }
skip() { echo "  · $1（跳过）"; }

echo "== [1] 二进制体积 =="
LIMIT=$(get binary_bytes)
BIN="target/release/panel"
if [ -f "$BIN" ]; then
  SZ=$(stat -c%s "$BIN")
  echo "  · 实际 $((SZ/1024/1024)) MB / 预算 $((LIMIT/1024/1024)) MB"
  [ "$SZ" -gt "$LIMIT" ] && fail "二进制超出预算" || pass "二进制体积达标"
else
  skip "未找到 $BIN（需先 cargo build --release）"
fi

echo "== [2] 前端体积 =="
if [ -d web/dist/assets ] && [ -f "$BUDGETS" ]; then
  ( cd web && node scripts/size-report.mjs ) && pass "前端体积达标" || fail "前端体积超出预算"
else
  skip "未找到 web/dist（需先 pnpm build）"
fi

echo "== [3] 直接依赖数量 =="
LIMIT=$(get direct_deps)
if command -v cargo >/dev/null 2>&1; then
  N=$(cargo tree --depth 1 2>/dev/null | grep -cE "^[├└]")
  echo "  · 实际 ${N} / 预算 ${LIMIT}"
  [ "$N" -gt "$LIMIT" ] && fail "依赖数量超出预算" || pass "依赖数量达标"
else
  skip "未检测到 cargo"
fi

echo "== [4] SQLite 体积预算一致性（schema 注释检查） =="
LIMIT=$(get db_size_mb)
if [ -f migrations/001_init.sql ]; then
  if grep -q "≤ 8 MB" migrations/001_init.sql; then
    pass "schema 注释与预算一致（${LIMIT} MB）"
  else
    fail "schema 注释中的体积预算与 budgets.json 不一致"
  fi
else
  skip "未找到 migrations"
fi

echo "== [5] 指标落盘密度硬约束 =="
LIMIT=$(get metrics_samples_persisted_per_day)
# 聚合器每分钟 1 行 = 1440 行/天；任何"每秒落盘"的实现都是违规
if grep -rqE "INTO metrics_1m" crates/panel-db/src/aggregator.rs; then
  pass "指标走 1m 聚合（${LIMIT} 行/天）"
else
  fail "未找到 1m 聚合写入路径"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "PASS：资源预算检查通过"
  exit 0
else
  echo "FAIL：存在超预算项"
  exit 1
fi
