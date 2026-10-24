#!/usr/bin/env bash
# 前端单文件行数门禁
#
# 目的：挡住「一个 .vue 涨到两三千行」这类膨胀。大视图的代价不是"不好看"，而是
# 项目里已经踩过的三类具体故障：
#   ① **纯逻辑住在 .vue 里没法单测**——vitest 只收 `src/**/*.test.ts` 且无 vue 插件，
#      必须先抽成 .ts 才能测（不抽就只能靠手点，回归全看人）；
#   ② **分支互相吞内容**——卡片/浮层插进 v-if 链中间会静默不渲染，文件越大越容易插错；
#   ③ 改一处要读完整个文件，回归面不可控。
#
# 阈值是**当前最大值 + 余量**，不是理想值：一接就红的门禁等于恒红，比没有门禁更糟
# （恒红会淹没真失败）。收紧的正确姿势是拆完组件后**把这两个常数调小**——
# 只涨不降的上限等于没上限。
#
# 用法：./ci/check-frontend-loc.sh [后端仓根] [前端仓根]
#   前端仓根默认 ../forkpanel-frontend；也可用 PANEL_FRONTEND_ROOT 覆盖。

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
FE_ROOT="${2:-${PANEL_FRONTEND_ROOT:-$ROOT/../forkpanel-frontend}}"
cd "$ROOT"

# ── 定位前端源码目录（与 check-api-contract.sh 同款探测）──
# 历史坑：拆仓前前端在 web/src，拆仓后移到 ../forkpanel-frontend/src。硬编码旧路径
# 会让 find 静默返回空 ⇒ "0 个文件、全部通过"——恒绿的门禁比没有门禁更危险。
FE_SRC=""
for cand in "$FE_ROOT/src" "$ROOT/web/src"; do
  if [ -d "$cand" ]; then FE_SRC="$cand"; break; fi
done
if [ -z "$FE_SRC" ]; then
  if [ -n "${CI:-}" ]; then
    echo "[skip] $(basename "$0")：找不到前端源码（试过 $FE_ROOT/src 与 $ROOT/web/src）——本轮跳过（非通过）" >&2
    exit 0
  fi
  echo "✗ $(basename "$0")：找不到前端源码（试过 $FE_ROOT/src 与 $ROOT/web/src）" >&2
  echo "  本地两仓应并列存放；也可设 PANEL_FRONTEND_ROOT 指定。" >&2
  exit 1
fi

# 当前实际最大值：.vue 1617（SiteFormDialog.vue）、.ts 382（useSiteForm.ts，types.ts 已豁免）
VUE_MAX=1700
TS_MAX=500

# 豁免：契约生成物，行数随 openapi.yaml 增长，不代表手写复杂度。
# ⚠ 路径是**相对 $FE_SRC（即 src/）**的，不是相对仓根——写错会静默不生效，
#    表现为"明明豁免了还在报错"（或更糟：看起来通过其实根本没匹配到）。
# ⚠ 新增豁免必须写明原因——「豁免清单越来越长」本身就是这条门禁正在失效的信号。
EXEMPT=("api/types.ts")

list_files() {
  find "$FE_SRC" -type f \( -name '*.vue' -o -name '*.ts' \) -not -path '*/node_modules/*'
}

over=()
while IFS= read -r f; do
  [ -z "$f" ] && continue
  rel="${f#"$FE_SRC"/}"
  skip=0
  for e in "${EXEMPT[@]}"; do [ "$rel" = "$e" ] && skip=1 && break; done
  [ "$skip" -eq 1 ] && continue
  n=$(wc -l < "$f" | tr -d ' ')
  case "$f" in
    *.vue) max=$VUE_MAX ;;
    *)     max=$TS_MAX ;;
  esac
  if [ "$n" -gt "$max" ]; then
    over+=("$rel|$n|$max")
  fi
done < <(list_files)

if [ "${#over[@]}" -gt 0 ]; then
  echo "✗ 前端单文件行数超限（.vue ≤ $VUE_MAX，.ts ≤ $TS_MAX）："
  for it in "${over[@]}"; do
    IFS='|' read -r rel n max <<< "$it"
    echo "    $rel：$n 行（上限 $max，超 $((n - max)) 行）"
  done
  echo
  echo "  拆法：先把纯逻辑抽到 src/composables/*.ts（这样它才可单测），再把视图拆成子组件。"
  echo "  拆完之后请回来**调小 VUE_MAX / TS_MAX**——上限只涨不降，这条门禁就白写了。"
  exit 1
fi

cnt=$(list_files | grep -c .)
if [ "$cnt" -eq 0 ]; then
  # ⚠ P1-8：本轮新加门禁自带洞——扫到 0 个文件仍报「0 个文件均在限额内」PASS。
  #   目录结构一变 / list_files 异常 ⇒ 恒绿。门禁无法得出结论时绝不能算通过。
  if [ -n "${CI:-}" ]; then
    echo "[skip] $(basename "$0")：扫描到 0 个前端文件，门禁无法得出结论（非通过）" >&2
    exit 0
  fi
  echo "✗ $(basename "$0")：扫描到 0 个前端文件——路径探测或 list_files 异常，门禁不能当作通过" >&2
  echo "   FE_SRC=$FE_SRC；检查前端仓是否并列存放或设 PANEL_FRONTEND_ROOT" >&2
  exit 1
fi
echo "PASS：${cnt} 个前端文件均在限额内（.vue ≤ $VUE_MAX，.ts ≤ $TS_MAX；豁免：${EXEMPT[*]}）"
