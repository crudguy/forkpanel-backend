#!/usr/bin/env bash
# 分层与可移植性门禁（设计方案 §0.3.4 / §1.1 / §1.2）
#
# 目的：把"架构纪律"变成 CI 里跑得出来的检查，而不是口头约定。
# 用法：./ci/check-layering.sh [仓库根目录]
# 退出码：0 = 通过；1 = 存在违规

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

FAIL=0
note_fail() { echo "  ✗ $1"; FAIL=1; }
note_ok()   { echo "  ✓ $1"; }

# 过滤掉注释行（形如 path:N:// 注释 或 path:N: * 注释），避免把规则说明当成违规
strip_comments() { grep -vE ':[0-9]+:[[:space:]]*(//|\*|/\*)' || true; }

echo "== [1] 子进程出口唯一性 =="
# 除 panel-os/src/cmd.rs 外，任何 crate 都不得直接 spawn 进程
SPAWN_HITS=$(grep -rn --include="*.rs" -E "Command::new|tokio::process|std::process::Command" \
  crates/ 2>/dev/null | grep -v "crates/panel-os/src/cmd.rs" | grep -v "^crates/panel-os/src/cmd.rs")
if [ -n "$SPAWN_HITS" ]; then
  note_fail "发现 cmd.rs 之外的进程调用："
  echo "$SPAWN_HITS" | sed 's/^/      /'
else
  note_ok "全部进程调用收敛在 panel-os/src/cmd.rs"
fi

echo "== [2] 禁止 shell 解释 =="
SHELL_HITS=$(python3 ci/strip_tests.py 'sh -c|bash -c|/bin/sh|"-c"' 2>/dev/null \
  | grep -v "crates/panel-os/src/cmd.rs" | strip_comments)
if [ -n "$SHELL_HITS" ]; then
  note_fail "存在 shell 调用（命令注入高危）："
  echo "$SHELL_HITS" | sed 's/^/      /'
else
  note_ok "无 sh -c / bash -c"
fi

echo "== [3] OS 路径硬编码 =="
# 业务层（panel-core 及未来的 panel-service / panel-api）不得出现 Linux 绝对路径
# panel-os/src/linux/** 是平台实现本身，允许；paths.rs 是布局定义，允许
# 豁免整个 panel-os：敏感路径黑名单、平台默认目录、平台实现本身都属于平台知识。
PATH_HITS=$(python3 ci/strip_tests.py '"/(etc|var|proc|usr|run|sys|opt|home|root)/' 2>/dev/null \
  | grep -v "crates/panel-os/")
if [ -n "$PATH_HITS" ]; then
  note_fail "业务层出现硬编码路径（mock 与 tests 已豁免）："
  echo "$PATH_HITS" | sed 's/^/      /'
else
  note_ok "业务层无硬编码 Linux 路径"
fi

echo "== [4] 平台条件编译位置 =="
# cfg(target_os=...) 只允许出现在 OS 抽象层内部
CFG_HITS=$(grep -rn --include="*.rs" -E 'cfg\(target_os|cfg\(target_family|cfg\(windows\)|cfg\(unix\)' crates/ 2>/dev/null \
  | grep -v "crates/panel-os/")
if [ -n "$CFG_HITS" ]; then
  note_fail "业务层出现平台条件编译（应通过 trait 抽象）："
  echo "$CFG_HITS" | sed 's/^/      /'
else
  note_ok "平台条件编译仅在 OS 抽象层内"
fi

echo "== [4c] 平台模块直接引用 =="
# 业务层直接写 panel_os::linux::xxx 会让代码绑死在 Linux 上，
# 且非 Linux 目标编译不过。平台能力必须经 OsAdapter / fs 等跨平台入口。
PLAT_HITS=$(grep -rn --include="*.rs" -E 'panel_os::(linux|win|macos)::' crates/ 2>/dev/null \
  | grep -v "crates/panel-os/src/")
if [ -n "$PLAT_HITS" ]; then
  note_fail "业务层直接引用平台模块（应通过跨平台入口）："
  echo "$PLAT_HITS" | sed 's/^/      /'
else
  note_ok "平台模块引用仅在 OS 抽象层内部"
fi

echo "== [4b] procfs 直接访问位置 =="
# 业务层直接读 /proc 会让"平台专有知识"泄漏出去（应走 MetricsProvider / host_profile）
# 豁免：panel-os/src 下所有平台实现目录与 mock。
# 敏感路径黑名单（/proc/ /sys/ /dev/ ...）本就是平台专有知识，必须定义在平台实现内。
PROC_HITS=$(grep -rn --include="*.rs" -E '"/proc/' crates/ 2>/dev/null \
  | grep -v "crates/panel-os/" \
  | grep -v "^crates/panel-core/")
if [ -n "$PROC_HITS" ]; then
  note_fail "业务层直接访问 procfs（应通过 OsAdapter）："
  echo "$PROC_HITS" | sed 's/^/      /'
else
  note_ok "procfs 访问仅在 Linux 平台实现内"
fi

echo "== [5] SQL 拼接 =="
SQL_HITS=$(grep -rn --include="*.rs" -E 'execute\(&format!|prepare\(&format!|query_row\(&format!' crates/ 2>/dev/null)
if [ -n "$SQL_HITS" ]; then
  note_fail "存在 SQL 字符串拼接（必须使用绑定参数）："
  echo "$SQL_HITS" | sed 's/^/      /'
else
  note_ok "无 SQL 拼接"
fi

echo "== [6] 强类型构造点审计 =="
# from_raw 是 unsafe 构造，只允许出现在校验器/沙箱内部
# 合法构造点：panel-core（强类型定义 + 校验器）、paths.rs（路径沙箱）、mock.rs（桩数据）。
# 其余一律违规。测试块由 strip_tests.py 剥离（测试构造 fixture 合法）。
RAW_HITS=$(python3 ci/strip_tests.py crates 2>/dev/null \
  | grep -v "crates/panel-core/src/lib.rs" \
  | grep -v "crates/panel-os/src/paths.rs" \
  | grep -v "crates/panel-os/src/mock.rs")
if [ -n "$RAW_HITS" ]; then
  note_fail "from_raw 出现在校验器之外："
  echo "$RAW_HITS" | sed 's/^/      /'
else
  note_ok "强类型构造点受控"
fi

echo "== [7] 前端可移植性与 XSS =="
if [ -d web/src ]; then
  # 过滤纯注释行（以 * 或 // 开头）：纪律说明里会提到这些词本身，不能算违规
  FE_HITS=$(grep -rn -E "v-html|isLinux|navigator\.platform|target_os" web/src 2>/dev/null \
    | grep -vE ':[0-9]+:[[:space:]]*(\*|//)')
  if [ -n "$FE_HITS" ]; then
    note_fail "前端存在平台硬编码或 v-html："
    echo "$FE_HITS" | sed 's/^/      /'
  else
    note_ok "前端无平台判断与 v-html"
  fi
else
  echo "  · web/src 不存在（骨架阶段跳过）"
fi

echo "== [8] 依赖数量预算 =="
if command -v cargo >/dev/null 2>&1; then
  N=$(cargo tree --depth 1 2>/dev/null | grep -c "^[├└]")
  echo "  · 直接依赖约 ${N} 个（预算 ≤ 38）"
  [ "$N" -gt 38 ] && note_fail "直接依赖超出预算" || note_ok "依赖数量在预算内"
else
  echo "  · 未检测到 cargo（跳过）"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "PASS：全部架构门禁通过"
  exit 0
else
  echo "FAIL：存在架构违规，请修正后再提交"
  exit 1
fi
