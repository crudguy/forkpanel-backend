#!/usr/bin/env bash
# 内嵌前端新鲜度门禁：确保 `web/dist` 与前端源码构建产物一致。
#
# 为什么需要它：后端二进制通过 `embed.rs` 的 `#[folder="../../web/dist"]` 把前端
# 静态资源**编译进 Rust 二进制**。改完前端只跑 `cargo build` 不会重新 embed——
# 必须 ① vite build → ② rm -rf web/dist/* → ③ cp -a 前端 dist/ → ④ touch embed.rs
# → ⑤ cargo build。漏任何一步都会**发出旧前端**，而编译、类型、测试全绿。
#
# 本脚本不重新构建（太慢），只做「一致性对账」：
#   - 前端源码 dist/index.html 引用的每个 asset，都必须存在于 web/dist/ 下；
#   - 反向也查：web/dist 里不得残留源码 dist 中已不存在的**同名前缀**文件
#     （只 cp 不 rm 会留下旧 hash 的僵尸 chunk，久而久之 web/dist 无限膨胀）。
#
# 用法：bash ci/check-embed-fresh.sh   （在 forkpanel-backend/ 下执行）
# 退出码：0 = 一致；1 = 不一致（附差异清单）
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
FE_DIST="${FE_DIST:-$HERE/../forkpanel-frontend/dist}"
BE_DIST="$HERE/web/dist"

fail() { echo "check-embed-fresh: $1" >&2; exit 1; }

# ── 环境判定：CI 只 checkout 后端，没有前端仓库 ──
# 前端产物缺失时**显式跳过并喊出来**，不判失败：CI 上没有 forkpanel-frontend/，
# 判失败等于恒红（比没门禁更糟——会淹没真失败）。本地两个仓库都在，才是真检查。
if [ ! -d "$FE_DIST" ]; then
  echo "[skip] check-embed-fresh：找不到 $FE_DIST（CI 环境未 checkout 前端仓库，跳过）" >&2
  exit 0
fi
[ -d "$BE_DIST" ] || fail "找不到内嵌目录 $BE_DIST"
# ⚠ P1-7：原只判 web/dist 目录存在，不判 index.html / assets 数量。若只 `rm -rf
#   web/dist/*` 没 cp，index.html 缺失、assets 全空，三个比对集合全空 ⇒ 仍 PASS（恒绿）。
#   必须断言 index.html 存在、且至少引用了若干 asset。
[ -f "$BE_DIST/index.html" ] || fail "内嵌目录 $BE_DIST 缺少 index.html：可能只 rm 没 cp，请按 embed 五步重做"
ASSETS=$(grep -oE '/assets/[A-Za-z0-9_.-]+\.(js|css)' "$BE_DIST/index.html" | sort -u)
[ -n "$ASSETS" ] || fail "内嵌 index.html 未引用任何 /assets/*（异常：构建产物形态不符，或 index.html 损坏）"
# ── 1) 内嵌 index.html 引用的 asset 必须在 web/dist 里存在 ──
# ⚠ 必须读**内嵌的** `$BE_DIST/index.html`，不能读前端源码那份：两边都读源码等于
# 自己跟自己比，恒绿。负向对照实测过——只把内嵌 index.html 换回旧引用时，读源码
# 的版本 PASS（漏判），读内嵌的版本才 FAIL（抓住）。这正是本项目反复踩的
# 「断言目标错了」类恒绿陷阱。
# 只查 index.html 直接引用的（入口/vendor/css）；路由懒加载 chunk 由 import()
# 动态拉取，无法从静态 HTML 推全，故不做全量清单比对。
missing=0
while IFS= read -r a; do
  [ -n "$a" ] || continue
  rel="${a#/}"
  if [ ! -f "$BE_DIST/$rel" ]; then
    echo "  ❌ 内嵌 index.html 引用 $a，但 web/dist 里没有这个文件" >&2
    missing=1
  fi
done < <(echo "$ASSETS")

[ $missing -eq 0 ] || fail "内嵌 index.html 引用了不存在的 asset。很可能是只换了 index.html 没同步 asset，或漏了 cp：请按 ①pnpm build → ②rm -rf web/dist/* → ③cp -a 前端dist/ → ④touch crates/panel-cli/src/embed.rs → ⑤cargo build 重做。"

# ── 2) 内容一致：内嵌 index.html 引用的文件必须与源码 dist 逐字节相同 ──
# 抓「文件名对上了但内容是旧的」——cp 了 index.html 却没更新 asset，或 embed 时
# cargo 复用了缓存的旧 folder。
diffcnt=0
while IFS= read -r a; do
  [ -n "$a" ] || continue
  rel="${a#/}"
  if [ ! -f "$FE_DIST/$rel" ]; then
    echo "  ❌ $rel 在源码 dist 中不存在（内嵌的是来历不明的文件）" >&2
    diffcnt=1
  elif ! cmp -s "$FE_DIST/$rel" "$BE_DIST/$rel"; then
    echo "  ❌ $rel 内容不一致（内嵌的是旧版本）" >&2
    diffcnt=1
  fi
done < <(grep -oE '/assets/[A-Za-z0-9_.-]+\.(js|css)' "$BE_DIST/index.html" | sort -u)

[ $diffcnt -eq 0 ] || fail "内嵌目录里躺着旧文件。同上，按五步重做 embed。"

# ── 3) 僵尸 chunk：web/dist 里多出源码 dist 没有的文件 ──
# 「只 cp 不 rm」的典型症状：web/dist/assets/Foo.a1b2c3.js 与源码 Foo.d4e5f6.js
# 并存，旧的那个再也不会被引用，但会永久占着二进制体积。
#
# ⚠ 不能用「同名 stem 是否存在」判断：源码里只要还有 Foo.*，旧 hash 的
# Foo.DEADBEEF.js 就会被判合法（负向对照实测漏判）。必须逐个文件名精确比对。
zombie=0
for f in "$BE_DIST"/assets/*; do
  [ -e "$f" ] || continue
  b="$(basename "$f")"
  [ -f "$FE_DIST/assets/$b" ] || { echo "  ❌ 僵尸 chunk：$b（源码 dist 中没有同名文件）" >&2; zombie=1; }
done
[ $zombie -eq 0 ] || fail "web/dist 残留旧构建产物。清空重拷：rm -rf web/dist/* && cp -a ../forkpanel-frontend/dist/. web/dist/"

echo "check-embed-fresh: PASS（内嵌前端与源码构建产物一致）"
