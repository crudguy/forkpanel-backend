#!/usr/bin/env bash
# 真机 E2E 汇总 runner：一次跑完全部域，聚合结果。
#
# ## 为什么需要
# 各域各有独立脚本（`ci/e2e-*.sh`）。单个 `make e2e-<域>` 适合调一个域；上线前要
# "整机跑一遍"时，需要一条命令给出**全局**结论。本脚本只做编排与聚合，不重复任何
# 断言——断言仍由各域脚本负责（单一事实源，改口径只改一处）。
#
# ## 用法
#   ci/e2e-all.sh [base_url] [--stop-on-fail]
#     base_url 默认 http://127.0.0.1:2083（或 PANEL_E2E_BASE）
#     --stop-on-fail  首个失败即停（默认跑完全部域再统一汇报）
#   凭据：PANEL_E2E_USER / PANEL_E2E_PASS（默认 admin / DevPreview2026x）
#
# ## 纪律
#  1. **串行**：十个脚本打同一个后端，并行会互相干扰任务队列 / 审计 / 限流与临时对象。
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
# e2e-restore 放最后：它是唯一**不起 HTTP**的域（自己在隔离目录 init/backup/restore），
# 参数是 panel 二进制而非 base_url，且会临时独占一个端口。放在末尾既不影响前置域，
# 也保证它失败时前面的结论仍然可信。
SCRIPTS=(e2e-files e2e-backups e2e-containers e2e-cron e2e-databases e2e-sites e2e-firewall e2e-rbac e2e-security e2e-observe e2e-restore)
declare -A LABEL=(
  [e2e-files]="文件" [e2e-backups]="备份" [e2e-containers]="容器"
  [e2e-cron]="计划任务" [e2e-databases]="数据库" [e2e-sites]="站点"
  [e2e-firewall]="防火墙" [e2e-rbac]="权限与设置" [e2e-security]="WAF 与安全" [e2e-observe]="可观测"
  [e2e-restore]="恢复链路(CLI)"
)
# 参数形态：绝大多数域吃 base_url，e2e-restore 吃 panel 二进制路径（缺省 debug 产物）。
RESTORE_BIN="${PANEL_E2E_BIN:-./target/debug/panel}"

say() { printf '%s\n' "$*"; }
TOTAL_PASS=0; TOTAL_FAIL=0; BAD=0; SKIPPED=0
ROWS=()
DEGRADED=0; DEG_LIST=""   # 降级域：能力位缺失，只验了诚实 501，数据面未覆盖

for s in "${SCRIPTS[@]}"; do
  say ""
  say "════════ [$s] ${LABEL[$s]} ════════"
  if [ "$s" = "e2e-restore" ]; then
    out=$(bash "$HERE/$s.sh" "$RESTORE_BIN" 2>&1); rc=$?
  else
    out=$(bash "$HERE/$s.sh" "$B" 2>&1); rc=$?
  fi
  printf '%s\n' "$out"

  # skip ≠ 通过：某域明确告知"环境不具备"，本脚本立即停止并说清"未验证任何东西"，
  # 而不是把剩下的也跑成 skip 佯装跑过（恒绿守卫之戒）。
  if printf '%s\n' "$out" | grep -q '^\[skip\]'; then
    SKIPPED=1
    say ""
    say "!! [$s] 环境不具备（后端不可达 / 缺少二进制或权限）——剩余域都会 skip，提前结束；"
    say "!! **本次未验证任何东西**。"
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
  # 能力位缺失导致的数据面未覆盖：**单独统计**，别让它混进"全绿"里
  if printf '%s' "$out" | grep -q '\[降级\]'; then
    DEGRADED=$((DEGRADED + 1)); DEG_LIST="$DEG_LIST $s"
  fi

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
printf '  合计：PASS=%s  FAIL=%s  失败域=%s/%s  降级域=%s\n' "$TOTAL_PASS" "$TOTAL_FAIL" "$BAD" "${#ROWS[@]}" "$DEGRADED"
if [ "$DEGRADED" -gt 0 ]; then
  printf '  ⚠ 降级域（能力位缺失，只验了诚实 501，**数据面未覆盖**）：%s\n' "$DEG_LIST"
fi

if [ "$SKIPPED" -eq 1 ]; then
  # ⚠ 必须**非零**退出：skip 不是通过（"跳过不是通过"）。曾写成 exit 0，于是
  # 实例在跑到一半时挂掉、后续域全部 skip，CI 照样绿——什么都没验证却报成功。
  say "  结论：[skip] 环境不具备，**未验证任何东西**（非零退出＝门禁失败，不是通过）。"
  exit 1
fi
if [ "$BAD" -ne 0 ]; then
  say "  结论：有域失败（见上表 [FAIL] 行）。"
  exit 1
fi
if [ "$DEGRADED" -gt 0 ]; then
  say "  结论：全部域无失败；其中 ${DEGRADED} 域**降级**（能力位缺失，数据面未覆盖）。"
else
  say "  结论：全部 ${#ROWS[@]} 域通过（无降级）。"
fi
exit 0
