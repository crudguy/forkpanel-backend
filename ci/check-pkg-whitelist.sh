#!/usr/bin/env bash
# 软件包白名单一致性检查
#
# 目的：抓"两处白名单漂移"——后端 ALLOWED_PACKAGES（真正放行安装的那个）与
# 前端 CATEGORIES.pkgs（渲染安装/卸载入口的那个）必须逐项一致。
#
# 漂移的两种后果都是用户可见缺陷，且方向相反：
#   · 后端有、前端没有 → 这个包在面板里永远装不上（入口压根不存在）
#   · 前端有、后端没有 → 按钮能点、点了必被 400 拒绝（"能点但必失败"最伤）
#
# 为什么需要门禁：这是同一条约束落在两条路径上的典型场景（后端签发、
# 前端渲染），靠"注释里写请保持同步"必然漂移——cron 创建接口的 timeout_sec
# 校验就是同一模式漏配过的（一处校验、一处不校验）。
#
# 检查项：
#   A. 提取非空（缺失文件/正则失效即失败，绝不恒绿）
#   B. 规模合理（数量过少多半是正则失效，而非真的删到这么少）
#   C. 双向差集为空
#   D. 前端不得再出现第二份 WHITELIST 常量（单一事实源防倒退）
#
# 用法：./ci/check-pkg-whitelist.sh [后端仓根] [前端仓根]
#   前端仓根默认 ../forkpanel-frontend；也可用 PANEL_FRONTEND_ROOT 覆盖。

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
FE_ROOT="${2:-${PANEL_FRONTEND_ROOT:-$ROOT/../forkpanel-frontend}}"
cd "$ROOT"

FAIL=0
fail() { echo "  ✗ $1"; FAIL=1; }
pass() { echo "  ✓ $1"; }

# ── CI 无前端仓时的诚实跳过（与 check-embed-fresh.sh / check_openapi.py 同纪律）──
# GitHub Actions 只 checkout 后端仓；前端是私有独立仓，未配 token 时拉不到。
# **跳过不是通过**：必须把「没验」喊出来；但恒红同样有害（会淹没真失败），
# 故只在 CI 里跳过。本地开发两仓都在，仍走下面的硬失败，绝不静默放行。
ci_skip_no_frontend() {
  [ -n "${CI:-}" ] || return 1
  echo "[skip] $(basename "$0")：找不到前端仓库（$1）——CI 只 checkout 后端仓，本轮跳过（非通过）" >&2
  echo "       如需在 CI 真检查：把前端仓 checkout 到该路径，或设 PANEL_FRONTEND_ROOT" >&2
  exit 0
}

BE_SRC="crates/panel-api/src/routes/services/packages.rs"   # 拆域后白名单在 packages.rs（2026-10-21）
FE_SRC="$FE_ROOT/src/views/ServicesView.vue"

echo "== [A] 源文件存在性 =="
for f in "$BE_SRC" "$FE_SRC"; do
  if [ ! -f "$f" ]; then
    if [ "$f" = "$FE_SRC" ]; then ci_skip_no_frontend "$FE_ROOT"; fi
    fail "找不到源文件：$f"
    echo "      提取失败必须判失败——否则差集恒为空，门禁永远绿（恒绿门禁比没门禁更危险）"
    echo "      前端已拆为独立仓，请传第二个参数或设 PANEL_FRONTEND_ROOT 指向它"
    exit 1
  fi
done
pass "后端 $BE_SRC / 前端 $FE_SRC 均存在"

# ── 抽取后端白名单：const ALLOWED_PACKAGES ... ]; 之间的字符串 ──
# 只取 `name:` 行上的名字，**不能**对整个块无差别抓字符串：
# `PkgDef` 里还有 `units: &["nginx.service"]` 这类系统单元名，它们同样是
# 小写 + 点号，会被同一条正则抓进来，于是每个包都变成「后端允许但前端无入口」，
# 门禁直接误报 18 条（本轮实际踩到）。判据必须锚在**包名字段**上，而不是
# "看起来像包名的字符串"——单元名不是包名，两者格式完全重叠，只能靠位置区分。
# 不锚 `^const`：拆域后该常量带可见性前缀（`pub(crate) const`）。
# 仍保留"提取不到就判失败"的判据（见下方 BE_N 检查）。
BE=$(awk '/const ALLOWED_PACKAGES/,/^\];/' "$BE_SRC" 2>/dev/null \
  | grep -oE 'name: "[a-z0-9][a-z0-9.+-]*"' | grep -oE '"[a-z0-9][a-z0-9.+-]*"' \
  | tr -d '"' | sort -u)

# ── 抽取前端 CATEGORIES 的 pkgs 并集 ──
# 只取 pkgs 数组，避免把 key/label 的中文标签也算进来
FE=$(grep -oE "pkgs: \[[^]]*\]" "$FE_SRC" 2>/dev/null \
  | grep -oE "'[a-z0-9][a-z0-9.+-]*'" | tr -d "'" | sort -u)

count() { [ -n "$1" ] && printf '%s\n' "$1" | wc -l | tr -d ' ' || echo 0; }
BE_N=$(count "$BE")
FE_N=$(count "$FE")

echo
echo "== [B] 提取结果非空且规模合理 =="
if [ "$BE_N" -eq 0 ]; then
  fail "未从后端提取到任何包名（$BE_SRC）——正则失效还是白名单被清空？"
else
  pass "后端白名单 $BE_N 项"
fi
if [ "$FE_N" -eq 0 ]; then
  fail "未从前端提取到任何包名（$FE_SRC）——CATEGORIES 格式变了？需同步更新本脚本提取规则"
else
  pass "前端分类集合 $FE_N 项"
fi
# 白名单是刻意收敛的安全边界，正常不应小于 8 项；过少几乎一定是提取失败
MIN=8
if [ "$BE_N" -lt "$MIN" ]; then
  fail "后端白名单仅 $BE_N 项（少于阈值 $MIN）：更可能是提取正则失效，而非真的收敛到这么少"
fi

echo
echo "== [C] 双向差集必须为空 =="
if [ "$BE_N" -eq 0 ] || [ "$FE_N" -eq 0 ]; then
  fail "跳过差集比较：上方提取为空（此处若放行就会恒绿）"
else
  ONLY_BE=$(comm -23 <(printf '%s\n' "$BE") <(printf '%s\n' "$FE"))
  ONLY_FE=$(comm -13 <(printf '%s\n' "$BE") <(printf '%s\n' "$FE"))
  if [ -n "$ONLY_BE" ]; then
    fail "后端允许安装但前端无入口（用户永远装不上）："
    printf '%s\n' "$ONLY_BE" | sed 's/^/      /'
  else
    pass "后端白名单全部有前端入口"
  fi
  if [ -n "$ONLY_FE" ]; then
    fail "前端有入口但后端会拒绝（点了必被 400 拒绝）："
    printf '%s\n' "$ONLY_FE" | sed 's/^/      /'
  else
    pass "前端入口全部在后端白名单内"
  fi
fi

echo
echo "== [D] 前端单一事实源（防倒退）=="
# 历史形态：ServicesView 曾同时有 WHITELIST 数组与 CATEGORIES，
# 两份要想着同步，必然漂移。现在包集合的唯一事实源必须是 CATEGORIES.pkgs。
if grep -nE '^[[:space:]]*(const|let|var)[[:space:]]+WHITELIST' "$FE_SRC" 2>/dev/null; then
  fail "前端出现第二份 WHITELIST 常量：请删除它，包集合只保留 CATEGORIES 一处"
else
  pass "前端无第二份 WHITELIST（CATEGORIES 为唯一事实源）"
fi

echo
echo "== [E] AppRuntime.runtime_pkg 必须落在白名单内 =="
# 防"能力位撒谎"：面板若声称某运行时可从「软件」页安装（runtime_pkg: Some("x")），
# 那个 x 就必须真在白名单里——否则界面永远显示「未装」且无处可点。这类漏配
# **不会编译报错**（match 已穷尽），只在运行时暴露，故必须靠脚本把守。
# 该约束跨 crate（panel-os 不依赖 panel-api），无法写成 Rust 单测。
TRAITS_SRC="crates/panel-os/src/traits.rs"
if [ ! -f "$TRAITS_SRC" ]; then
  fail "找不到 $TRAITS_SRC"
else
  # 必须**收窄到 fn runtime_pkg 的函数体**：traits.rs 里还有别的 Some("…")
  # （版本号解析工具），全文件 grep 会把 "1.0" / "17+278" 这类误当包名。
  RP=$(awk '/fn runtime_pkg/,/^    }/' "$TRAITS_SRC" 2>/dev/null \
    | grep -oE 'Some\("[a-z0-9][a-z0-9.+-]*"\)' | grep -oE '"[a-z0-9][a-z0-9.+-]*"' \
    | tr -d '"' | sort -u)
  RP_N=$(count "$RP")
  if [ "$RP_N" -eq 0 ]; then
    fail "未提取到任何 runtime_pkg（正则失效，还是全改成 None 了？）"
  else
    pass "runtime_pkg 提取到 $RP_N 项：$(printf '%s' "$RP" | tr '\n' ' ')"
    if [ "$BE_N" -eq 0 ]; then
      fail "跳过 [E] 差集：上方后端白名单为空"
    else
      MISS=$(comm -23 <(printf '%s\n' "$RP") <(printf '%s\n' "$BE"))
      if [ -n "$MISS" ]; then
        fail "以下 runtime_pkg 不在 ALLOWED_PACKAGES 内（界面会永远显示「未装」且无处可装）："
        printf '%s\n' "$MISS" | sed 's/^/      /'
      else
        pass "runtime_pkg 全部在白名单内"
      fi
    fi
  fi
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "PASS：软件包白名单前后端一致"; exit 0; else echo "FAIL：白名单不一致"; exit 1; fi
