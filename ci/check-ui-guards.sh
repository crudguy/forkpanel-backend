#!/usr/bin/env bash
# 前端 UI 守卫（forkpanel-frontend/scripts/check-*.mjs，共 18 个）的后端侧入口。
#
# 为什么需要这一层：这 18 个守卫此前**只有**前端仓 `package.json` 的 `check:ui`
# 这个手动入口，`make check`（CI 实际跑的）从不执行它们 —— 包括为修 F/P 级问题
# 专门加的 `check-nav-policy` / `check-bulk-scope` / `check-component-imports`。
# 与 `check-bootstrap-token.sh` 是同一类问题：写好了、没人调，而「守卫存在」
# 很容易被当成「守卫在跑」。
#
# ⚠ 更糟的是 `run-ui-guards.mjs` 头部注释当时写着「Makefile 与 package.json 都
#   转发到本文件」—— 注释先于实现写成，于是这个缺口连"文档对不上"都算不上，
#   它被一句不存在的事实盖住了。本脚本补上 Makefile 那一半。
#
# 18 个守卫只依赖 node 内置模块（node:fs / node:path / node:url），无 npm 依赖，
# 因此 CI 自带 node 即可执行，不需要 pnpm install。
set -uo pipefail

FE="${PANEL_FRONTEND_ROOT:-../forkpanel-frontend}"

# 与 check-api-contract.sh 同口径：**前端仓缺失判红，不是跳过**。
# 「18 个守卫一个都没跑」被当成通过，正是本脚本存在的理由——它的缺失分支
# 没有资格再犯同一个错。
if [ ! -f "$FE/scripts/run-ui-guards.mjs" ]; then
  echo "✗ 找不到前端 UI 守卫入口（$FE/scripts/run-ui-guards.mjs）"
  echo "  前端已拆为独立仓：请设 PANEL_FRONTEND_ROOT 指向它"
  echo "  —— 绝不能在此跳过：18 个守卫不跑＝这一层完全没有覆盖"
  exit 1
fi

# node 是跑 .mjs 的前提，缺了同样判红（判成"通过"会把整层静默掉）
if ! command -v node >/dev/null 2>&1; then
  echo "✗ 找不到 node，无法执行前端 UI 守卫（18 个）"
  exit 1
fi

cd "$FE" || { echo "✗ 进不去前端目录：$FE"; exit 1; }

node scripts/run-ui-guards.mjs
