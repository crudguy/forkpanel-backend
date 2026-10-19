#!/usr/bin/env bash
# 前后端 API 契约一致性检查
#
# 目的：抓"路径漂移"——后端改了路由而前端没改（或反之）。这类 bug 在运行期
# 表现为 404 或静默失败，靠手测很难覆盖全。
#
# 检查项：
#   A. 前端调用的每个 /api/v1/* 路径，后端必须存在
#   B. 后端声明的每个写路径（POST/PUT/PATCH/DELETE），前端调用处必须带 CSRF 头
#      （由 api/client.ts 统一附加，因此只需确认前端没有绕过 client 直接 fetch）
#   E. 契约文件自身结构 + 前后端副本一致（转交 ci/check_openapi.py）
#   F. 带路径参数的模板化端点（后端 {param} / 前端 ${expr}）归一化成 # 占位后，
#      前端每个模板化路径必须在后端有对应路由——[A] 的字符类不含 {}，这类端点原先全部漏查
#
# 用法：./ci/check-api-contract.sh [仓库根目录] [前端仓根目录]
#   前端仓根目录默认 ../forkpanel-frontend；也可用环境变量 PANEL_FRONTEND_ROOT 覆盖。

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

# ── 定位前端源码目录 ──
# 历史坑：本脚本早期硬编码 `web/src`（前后端未拆仓时的布局）。拆仓后前端移到
# ../forkpanel-frontend，`web/` 只剩构建产物 dist，于是 grep 静默返回空 →
# MISSING 为空 → 报"✓ 全部一致"。**恒绿的门禁比没有门禁更危险**，因此这里
# 必须先确认目录真实存在，缺失即失败。
FE_SRC=""
for cand in "$FE_ROOT/src" "$ROOT/web/src"; do
  if [ -d "$cand" ]; then FE_SRC="$cand"; break; fi
done
if [ -z "$FE_SRC" ]; then
  ci_skip_no_frontend "$FE_ROOT"
  fail "找不到前端源码目录（试过 $FE_ROOT/src 与 $ROOT/web/src）"
  echo "      前端已拆为独立仓，请传第二个参数或设 PANEL_FRONTEND_ROOT 指向它"
  echo "      —— 绝不能在此静默通过：grep 抓不到文件会让 A/B/D 三项全部恒绿"
  exit 1
fi
echo "== 前端源码目录：$FE_SRC =="

# ── 抽取后端路由（形如 .route("/api/v1/xxx", get(...))）──
BACKEND=$(grep -rhoE '"/api/v1/[a-zA-Z0-9/_-]+"' crates/panel-api/src/ 2>/dev/null | tr -d '"' | sort -u)
if [ -z "$BACKEND" ]; then
  echo "  · 未从后端提取到路由"; exit 0
fi
echo "== 后端已声明路由 =="
echo "$BACKEND" | sed 's/^/      /'

# ── 抽取前端调用路径 ──
FRONTEND=$(grep -rhoE "'/api/v1/[a-zA-Z0-9/_-]+'" "$FE_SRC" 2>/dev/null | tr -d "'" | sort -u)
if [ -z "$FRONTEND" ]; then
  fail "未从前端提取到任何 /api/v1/* 调用路径（$FE_SRC）"
  echo "      提取为空说明 grep 目标不对或前端改用其它调用方式——不能当作通过"
else
  echo
  echo "== 前端调用路径 =="
  echo "$FRONTEND" | sed 's/^/      /'
fi

echo
echo "== [A] 前端路径必须在后端存在 =="
MISSING=""
for p in $FRONTEND; do
  if ! echo "$BACKEND" | grep -qxF "$p"; then
    MISSING="$MISSING $p"
  fi
done
if [ -n "$MISSING" ]; then
  fail "前端调用了后端不存在的路径：$MISSING"
else
  pass "全部前端调用路径均已在后端声明"
fi

echo "== [B] 前端不得绕过统一 client 直接 fetch =="
# 排除统一客户端本身：$FE_SRC 已是绝对路径，不能用 "src/api/client.ts" 这种
# 相对片段去 grep -v（否则排除失效，客户端自身的 fetch 会被误报）。
RAW=$(grep -rnE '(^|[^.a-zA-Z])fetch\(' "$FE_SRC" --include="*.ts" --include="*.vue" 2>/dev/null \
  | grep -v "api/client\.ts")
if [ -n "$RAW" ]; then
  fail "发现绕过 api/client.ts 的直接 fetch（会漏掉 CSRF 头与 401 处理）："
  echo "$RAW" | sed 's/^/      /'
else
  pass "全部请求都经过 api/client.ts（自动附加 CSRF、处理 401）"
fi

echo "== [C] 写接口必须受 CSRF 守卫 =="
# guard_write 中间件必须挂载在写路由之上
if grep -q "guard_write" crates/panel-api/src/routes.rs; then
  pass "写操作已挂载 guard_write（CSRF + Origin 校验）"
else
  fail "未找到 guard_write 挂载点"
fi

echo "== [D] 版本协商常量一致 =="
BE_VER=$(grep -rhoE 'api: "1\.0"' crates/panel-api/src/ | head -1)
FE_VER=$(grep -rhoE "v\.api !== '[0-9.]+'" "$FE_SRC/main.ts" 2>/dev/null | head -1)
if [ -n "$BE_VER" ] && [ -n "$FE_VER" ]; then
  pass "后端 $BE_VER / 前端校验 $FE_VER"
else
  echo "  · 版本常量未同时检测到（骨架阶段可忽略）"
fi

echo
echo "== [E] 契约结构与前后端副本一致 =="
if [ -f ci/check_openapi.py ]; then
  if PANEL_FRONTEND_OPENAPI="${PANEL_FRONTEND_OPENAPI:-$FE_ROOT/src/api/openapi.yaml}" \
     python3 ci/check_openapi.py "$ROOT"; then
    pass "契约结构合法且前后端副本一致"
  else
    fail "契约结构或副本一致性检查未通过（详见上方 [E1]~[E4]）"
  fi
else
  fail "缺少 ci/check_openapi.py"
fi

echo
echo "== [F] 模板化路由（{param} / \${expr}）两端形状一致 =="
# 背景：[A] 的正则字符类 [a-zA-Z0-9/_-] 不含 {}，带路径参数的端点两端都不是
#   静态字面量——后端 .route("/api/v1/sites/{id}/conf")、前端模板串
#   `.../sites/${id}/conf`——这类端点 [A] 全部漏查：后端改名或前端拼错路径
#   只会在运行期 404，静态路由检查与 openapi 结构检查都发现不了。
# 做法：两端各自归一化成「# 占位符」形状再比对——
#   后端 {param} -> #；前端 ${expr} -> #，并截断查询串 / 条件模板尾巴
#   （${q ? ...} 这类是查询后缀而非路径参数，含 ? 的 ${} 一律截断）。
# 前提断言：归一化后两端模板形状各需达到一定数量，扫不到即失败——
#   「恒绿的门禁比没有门禁更危险」，提取塌成 0 绝不能算通过。
BE_TPL=$(grep -rhoE '"/api/v1/[^"]*"' crates/panel-api/src/ 2>/dev/null \
  | tr -d '"' | sed -E 's/\{[^}]*\}/#/g' | grep '#' | sort -u)
FE_TPL=$(grep -rhoE '`/api/v1/[^`]*`' "$FE_SRC" 2>/dev/null \
  | tr -d '`' | sed -E 's/\$\{[^}?]*\}/#/g' | sed -E 's/(\$\{|\?).*//' | grep '#' | sort -u)
BE_TPL_N=$(printf '%s\n' "$BE_TPL" | grep -c .)
FE_TPL_N=$(printf '%s\n' "$FE_TPL" | grep -c .)
if [ "$BE_TPL_N" -lt 20 ] || [ "$FE_TPL_N" -lt 20 ]; then
  fail "模板化路由提取异常：后端 ${BE_TPL_N} 个、前端 ${FE_TPL_N} 个（应各 ≥20）——解析前提不成立"
  echo "      修法：确认书写风格未变（后端换 :id 语法 / 前端改非模板字面量），同步升级本段归一化规则"
else
  TPL_MISS=""
  for p in $FE_TPL; do
    printf '%s\n' "$BE_TPL" | grep -qxF "$p" || TPL_MISS="$TPL_MISS $p"
  done
  if [ -n "$TPL_MISS" ]; then
    fail "前端调用的模板化路径在后端无对应路由（归一化后）：$TPL_MISS"
    echo "      修法：后端补齐/改名对齐，或修正前端路径（{param} 与 \${expr} 的段数、字面量须一致）"
  else
    pass "全部 ${FE_TPL_N} 个前端模板化路径均在后端有对应路由（共 ${BE_TPL_N} 个后端模板路由）"
  fi
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "PASS：前后端契约一致"; exit 0; else echo "FAIL：契约不一致"; exit 1; fi
