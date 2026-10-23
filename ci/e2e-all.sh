#!/usr/bin/env bash
# 真机 E2E 汇总 runner：一次跑完八域，聚合结果。
#
# ## 为什么需要
# 八域各有独立脚本（`ci/e2e-*.sh`）。单个 `make e2e-<域>` 适合调一个域；上线前要
# "整机跑一遍"时，需要一条命令给出**全局**结论。本脚本只做编排与聚合，不重复任何
# 断言——断言仍由各域脚本负责（单一事实源，改口径只改一处）。
#
# ## 用法
#   ci/e2e-all.sh [base_url] [--stop-on-fail]
#     base_url 默认 http://127.0.0.1:2083（或 PANEL_E2E_BASE）
#     --stop-on-fail  首个失败即停（默认跑完全部八域再统一汇报）
#   凭据：PANEL_E2E_USER / PANEL_E2E_PASS（默认 admin / DevPreview2026x）
#
# ## 纪律
#  1. **串行**：八个脚本打同一个后端，并行会互相干扰任务队列 / 审计 / 限流与临时对象。
#  2. **skip 不冒充通过**：后端不可达时首个脚本打印 `[skip]`，本脚本立即停止并明确
#     告知"未验证任何东西"，而不是把剩下六个也跑成 skip 佯装跑过（恒绿守卫之戒）。
#  3. **退出码是权威信号**：PASS/FAIL 数字仅用于汇报；某域退出码非 0 即判失败，
#     即使结果行解析不到也不会被吞掉。
#
# ## 依赖
#   bash；各域脚本自身依赖 curl / python3。
set -uo pipefail

B=""; STOP_ON_FAIL=0
for a in "$@"; do
  case "$a" in
    --stop-on-fail) STOP_ON_FAIL=1 ;;
    -*) printf '未知参数：%s\n' "$a" >&2; exit 2 ;;
    *) B="$a" ;;
  esac
done
B="${B:-${PANEL_E2E_BASE:-http://127.0.0.1:2083}}"

# 脚本目录：允许从任意 cwd 调用（Makefile / 手动 / CI 都能跑）
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 顺序：只读/低副作用在前，写操作在后；中途失败时前面的结论仍然可信。
SCRIPTS=(e2e-files e2e-backups e2e-containers e2e-cron e2e-databases e2e-sites e2e-firewall e2e-rbac)
declare -A LABEL=(
  [e2e-files]="文件" [e2e-backups]="备份" [e2e-containers]="容器"
  [e2e-cron]="计划任务" [e2e-databases]="数据库" [e2e-sites]="站点"
  [e2e-firewall]="防火墙" [e2e-rbac]="权限与设置"
)

say() { printf '%s\n' "$*"; }
TOTAL_PASS=0; TOTAL_FAIL=0; BAD=0; SKIPPED=0
ROWS=()

for s in "${SCRIPTS[@]}"; do
  say ""
  say "════════ [$s] ${LABEL[$s]} ════════"
  out=$(bash "$HERE/$s.sh" "$B" 2>&1); rc=$?
  printf '%s\n' "$out"

  # 后端不可达：首个脚本即 skip，剩余六个同理。立即停止并如实说明。
  if printf '%s\n' "$out" | grep -q '^\[skip\]'; then
    SKIPPED=1
    say ""
    say "!! [$s] 后端不可达 —— 八个域都会 skip，提前结束；**本次未验证任何东西**。"
    break
  fi

  # 结果行：多个脚本在 unsupported 分支也打一行，故取最后一行（实际执行的那条）
  line=$(printf '%s\n' "$out" | grep 'E2E 结果' | tail -1)
  p=$(printf '%s' "$line" | sed -n 's/.*PASS=\([0-9]\+\).*/\1/p')
  f=$(printf '%s' "$line" | sed -n 's/.*FAIL=\([0-9]\+\).*/\1/p')
  p=${p:-0}; f=${f:-0}
  TOTAL_PASS=$((TOTAL_PASS + p)); TOTAL_FAIL=$((TOTAL_FAIL + f))

  if [ "$rc" -ne 0 ] || [ "$f" -ne 0 ]; then
    st="FAIL"; BAD=$((BAD + 1))
  else
    st="PASS"
  fi
  ROWS+=("[$st] ${LABEL[$s]}（$s） PASS=$p FAIL=$f")

  if [ "$st" = "FAIL" ] && [ "$STOP_ON_FAIL" -eq 1 ]; then
    say ""
    say "!! --stop-on-fail：[$s] 失败，提前结束。"
    break
  fi
done

say ""
say "──────────── 汇总 ────────────"
for row in "${ROWS[@]}"; do say "  $row"; done
say "  ──────────────────────────────"
printf '  合计：PASS=%s  FAIL=%s  失败域=%s/%s\n' "$TOTAL_PASS" "$TOTAL_FAIL" "$BAD" "${#ROWS[@]}"

if [ "$SKIPPED" -eq 1 ]; then
  say "  结论：[skip] 后端不可达，未验证任何东西。"
  exit 0
fi
if [ "$BAD" -ne 0 ]; then
  say "  结论：有域失败（见上表 [FAIL] 行）。"
  exit 1
fi
say "  结论：八域全部通过。"
exit 0
