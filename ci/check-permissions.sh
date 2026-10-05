#!/usr/bin/env bash
# 前端权限点合法性检查
#
# 目的：抓"权限点字符串写错"——前端 auth.enabled(cap, perm) / can(perm) 的第二个
# 参数是**权限点**，必须与后端 auth::perm 模块里的常量值对得上。
#
# 为什么需要门禁：这是纯字符串参数，TypeScript 与 cargo 都**不会**报错（两边都是
# 字面量，跨仓更是无从校验），写错了只会静默生效。已踩实例：ServicesView 曾传
# 'package.install'（那是**能力位名**），而权限集合里只有 'package.manage'
# → `enabled = supported && can` 的 can 恒为 false → owner 的可安装按钮被自己
# disable，而能力位 supported 明明是 true。表现是"功能莫名不可用"，根因却在一个
# 字符串上，靠肉眼审查极难发现。
#
# 注意区分两类名字（极易混用）：
#   · 能力位（capabilities）：package.install / service.manage —— 描述"本机能不能跑"
#   · 权限点（permissions）：package.manage / service.manage —— 描述"这个角色能不能操作"
# 两者命名经常撞车（service.manage 两边都有），这正是 bug 温床。
#
# 检查项：
#   A. 源文件存在性（缺失即失败，绝不恒绿）
#   B. 提取非空且规模合理（正则失效多半表现为数量骤降）
#   C. 前端权限点必须是后端常量的子集（差集为空）
#
# 用法：./ci/check-permissions.sh [后端仓根] [前端仓根]
#   前端仓根默认 ../forkpanel-frontend；也可用 PANEL_FRONTEND_ROOT 覆盖。

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
FE_ROOT="${2:-${PANEL_FRONTEND_ROOT:-$ROOT/../forkpanel-frontend}}"
cd "$ROOT"

FAIL=0
fail() { echo "  ✗ $1"; FAIL=1; }
pass() { echo "  ✓ $1"; }

BE_SRC="crates/panel-api/src/auth.rs"
FE_DIR="$FE_ROOT/src"

echo "== [A] 源文件存在性 =="
for f in "$BE_SRC" "$FE_DIR"; do
  if [ ! -e "$f" ]; then
    fail "找不到：$f"
    echo "      提取失败必须判失败——否则差集恒为空，门禁永远绿（恒绿门禁比没门禁更危险）"
    exit 1
  fi
done
pass "后端 $BE_SRC / 前端 $FE_DIR 均存在"

# ── 抽取后端权限常量：pub mod perm { ... } 块内的字符串值 ──
BE=$(awk '/^pub mod perm \{/,/^\}/' "$BE_SRC" 2>/dev/null \
  | grep -oE '"[a-z]+\.[a-z]+"' | tr -d '"' | sort -u)

# ── 抽取前端用到的权限点：只认 enabled(cap, perm) 与 can(perm) 两处调用 ──
# 不从整个 src 里捞 '[a-z]+.[a-z]+'，那会把路由名/i18n key 之类一并误提。
FE=$( { grep -rhoE "enabled\([^)]*\)" "$FE_DIR" 2>/dev/null
        grep -rhoE "\bcan\('[a-z]+\.[a-z]+'\)" "$FE_DIR" 2>/dev/null; } \
  | grep -oE "'[a-z]+\.[a-z]+'" | tr -d "'" | sort -u)

count() { [ -n "$1" ] && printf '%s\n' "$1" | wc -l | tr -d ' ' || echo 0; }
BE_N=$(count "$BE")
FE_N=$(count "$FE")

echo
echo "== [B] 提取结果非空且规模合理 =="
if [ "$BE_N" -eq 0 ]; then
  fail "未从后端提取到权限常量（$BE_SRC）——perm 模块改名/改结构了？需同步更新本脚本"
else
  pass "后端权限常量 $BE_N 项"
fi
if [ "$FE_N" -eq 0 ]; then
  fail "未从前端提取到任何权限点（$FE_DIR）——enabled()/can() 调用形式变了？需同步更新提取规则"
else
  pass "前端引用权限点 $FE_N 项"
fi
# 权限点是成体系的一组（view/manage 成对），正常应远多于 10 项；过少多半是提取失败
MIN=10
if [ "$BE_N" -lt "$MIN" ]; then
  fail "后端权限常量仅 $BE_N 项（少于阈值 $MIN）：更可能是提取正则失效，而非真的删到这么少"
fi

echo
echo "== [C] 前端权限点必须是后端常量的子集 =="
if [ "$BE_N" -eq 0 ] || [ "$FE_N" -eq 0 ]; then
  fail "跳过差集比较：上方提取为空（此处若放行就会恒绿）"
else
  UNKNOWN=$(comm -23 <(printf '%s\n' "$FE") <(printf '%s\n' "$BE"))
  if [ -n "$UNKNOWN" ]; then
    fail "前端引用了后端不存在的权限点（按钮会被静默 disable 或操作被 403 拒绝）："
    printf '%s\n' "$UNKNOWN" | sed 's/^/      /'
    echo "      提示：确认是权限点还是能力位——两者命名常撞车（如 service.manage）"
  else
    pass "前端引用的 $FE_N 个权限点后端全部存在"
  fi
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "PASS：前端权限点均合法"; exit 0; else echo "FAIL：存在越界权限点"; exit 1; fi
