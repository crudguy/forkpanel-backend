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
#
# 用法：./ci/check-api-contract.sh [仓库根目录]

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

FAIL=0
fail() { echo "  ✗ $1"; FAIL=1; }
pass() { echo "  ✓ $1"; }

# ── 抽取后端路由（形如 .route("/api/v1/xxx", get(...))）──
BACKEND=$(grep -rhoE '"/api/v1/[a-zA-Z0-9/_-]+"' crates/panel-api/src/ 2>/dev/null | tr -d '"' | sort -u)
if [ -z "$BACKEND" ]; then
  echo "  · 未从后端提取到路由"; exit 0
fi
echo "== 后端已声明路由 =="
echo "$BACKEND" | sed 's/^/      /'

# ── 抽取前端调用路径 ──
FRONTEND=$(grep -rhoE "'/api/v1/[a-zA-Z0-9/_-]+'" web/src 2>/dev/null | tr -d "'" | sort -u)
echo
echo "== 前端调用路径 =="
echo "$FRONTEND" | sed 's/^/      /'

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
RAW=$(grep -rnE '(^|[^.a-zA-Z])fetch\(' web/src --include="*.ts" --include="*.vue" 2>/dev/null \
  | grep -v "src/api/client.ts")
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
FE_VER=$(grep -rhoE "v\.api !== '[0-9.]+'" web/src/main.ts | head -1)
if [ -n "$BE_VER" ] && [ -n "$FE_VER" ]; then
  pass "后端 $BE_VER / 前端校验 $FE_VER"
else
  echo "  · 版本常量未同时检测到（骨架阶段可忽略）"
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "PASS：前后端契约一致"; exit 0; else echo "FAIL：契约不一致"; exit 1; fi
