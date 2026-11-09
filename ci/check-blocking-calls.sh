#!/usr/bin/env bash
# Q-01：阻塞子进程调用必须走唯一出口。
#
# 背景：`panel_os::run_sync` 是**同步**的（`std::process::Command` + `wait()`）。
# 在 async handler 里直接调它会把 tokio worker 钉住到子进程结束——systemd /
# D-Bus 卡顿时一次 `systemctl is-active` 就能让整个 API 短时无响应，而这类查询
# 还会被前端轮询放大。
#
# 为什么用「出口唯一性」而不是「逐点检查有没有包 spawn_blocking」：
# 后者要么写半个 Rust 解析器，要么退化成靠字符距离的启发式——误判方向还是
# **放行**（本项目已被这类恒绿守卫坑过多次）。把出口收成 `crate::blocking`
# 之后，判据变成「其它文件里 0 次出现」，简单且不可能误绿。
#
# 本脚本自带三条活性自检，防止判据本身失效后静默放行：
#   ① 出口文件存在且真的转发 run_sync；
#   ② 业务侧确实有 4 处调用（出口没被架空）；
#   ③ 主判据的 grep 确实扫到了文件（不是空集恒真）。
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FAIL=0
fail() { echo "  ✗ $1"; FAIL=1; }
pass() { echo "  ✓ $1"; }

SRC="crates/panel-api/src"
OUTLET="$SRC/blocking.rs"

echo "== [Q-01] 阻塞子进程调用出口唯一性 =="

# ① 出口本体：存在 + 真的转发（改成空实现后「其它文件 0 处」会变成恒绿）
#
# ⚠ 必须只看**生产段**：出口文件的 cfg(test) 里有
# `prod.contains("panel_os::run_sync(bin, args)")` 这条断言字符串，用整文件 grep
# 会让活性自检被测试自身喂饱——出口改成空实现也照样绿。负向对照实测过，
# 属「判据指向错」类（与「空集恒真」同源）。
OUTLET_PROD=$(awk '/#\[cfg\(test\)\]/{exit} {print}' "$OUTLET" 2>/dev/null || true)
if [ ! -f "$OUTLET" ]; then
  fail "唯一出口 $OUTLET 不存在——判据前提不成立"
elif ! printf '%s\n' "$OUTLET_PROD" | grep -q 'panel_os::run_sync(bin, args)'; then
  fail "唯一出口里没有真实转发 `panel_os::run_sync(bin, args)`——改成空实现会让本判据恒绿"
else
  pass "唯一出口存在且确实转发 run_sync"
fi

# ③ 扫描面自检：确认整棵源码树确实被扫到（文件数与调用点都不会是 0）
N_RS=$(find "$SRC" -name '*.rs' -type f | wc -l | tr -d ' ')
N_OUTLET_CALLS=$(printf '%s\n' "$OUTLET_PROD" | grep -c 'run_sync_in_blocking(' || true)
if [ "$N_RS" -lt 50 ]; then
  fail "只扫到 $N_RS 个 .rs 文件（预期 ≥50）——扫描路径变了？"
elif [ "${N_OUTLET_CALLS:-0}" -lt 1 ]; then
  fail "出口文件里没找到 run_sync_in_blocking 定义/调用——判据可能失效"
else
  pass "扫描面正常（$N_RS 个 .rs，出口含 $N_OUTLET_CALLS 处 run_sync_in_blocking）"
fi

# ② 业务侧调用点数：出口被架空（有人绕回裸调）或没接上，都会让这条数字变化
CALLS=$(grep -rn 'blocking::run_sync_in_blocking(' "$SRC" --include='*.rs' \
  | grep -v "^$OUTLET:" \
  | grep -vE ':[0-9]+:[[:space:]]*(//|/\*|\*)' || true)
N_CALLS=$(printf '%s\n' "$CALLS" | grep -c 'run_sync_in_blocking' || true)
if [ "${N_CALLS:-0}" -lt 4 ]; then
  fail "业务侧只有 $N_CALLS 处调用唯一出口（预期 ≥4）——有调用点绕回了裸调，或出口没接上"
else
  pass "业务侧 $N_CALLS 处阻塞调用均经唯一出口"
fi

# 主判据：除出口文件外，任何地方直接调 run_sync 都是裸调
LEAK=$(grep -rn 'panel_os::run_sync' "$SRC" --include='*.rs' \
  | grep -v "^$OUTLET:" \
  | grep -vE ':[0-9]+:[[:space:]]*(//|/\*|\*)' || true)
if [ -n "$LEAK" ]; then
  fail "以下位置绕过唯一出口直接调 panel_os::run_sync（同步调用会钉住 tokio worker）："
  printf '%s\n' "$LEAK" | sed 's/^/      /'
  echo "      改法：用 crate::blocking::run_sync_in_blocking()；async handler 里还要确保它在 spawn_blocking 闭包内。"
else
  pass "除唯一出口外无直接 run_sync 调用"
fi

# ④ 出口自己必须带超时（Q-01 的第二半）
#    只保证「走唯一出口」不够：出口若先 read_to_string 等 EOF 再 wait()，
#    孙进程继承 stdout 就会永久钉住 spawn_blocking 线程。判据指向 cmd.rs
#    生产段（剔 cfg(test) 之后的测试字符串），不靠别处转述。
echo
echo "== [Q-01b] 同步出口必须自带超时与进程组回收 =="
CMD_SRC="crates/panel-os/src/cmd.rs"
if [ ! -s "$CMD_SRC" ]; then
  fail "$CMD_SRC 不存在——超时判据前提不成立"
else
  CMD_PROD=$(awk '/#\[cfg\(test\)\]/{exit} {print}' "$CMD_SRC" 2>/dev/null || true)
  MISS=0
  for needle in 'RUN_SYNC_TIMEOUT' 'run_sync_with_timeout' 'try_wait()' 'libc::SIGKILL' 'recv_timeout'; do
    # ⚠ 用 `case` 而不是 `printf | grep -q`：`grep -q` 命中即退出，printf 随即收到
    # SIGPIPE，在 `set -o pipefail` 下整条管道返回 141 ⇒ **偶发假失败**
    # （实测连跑 5 次红 2 次，而手动 `grep -c` 每次都过）。假失败的守卫比没有守卫
    # 更糟：它会训练所有人"红了就重跑"，真失败迟早被一起忽略。
    case "$CMD_PROD" in
      *"$needle"*) ;;
      *)
        fail "cmd.rs 生产段缺 $needle（同步出口没有超时 / 进程组 kill / 读线程上限）"
        MISS=1
        ;;
    esac
  done
  [ "$MISS" -eq 0 ] && pass "同步出口含超时、进程组 kill 与读线程上限"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "PASS：阻塞调用出口唯一且自带超时"
  exit 0
else
  echo "FAIL：存在裸调"
  exit 1
fi
