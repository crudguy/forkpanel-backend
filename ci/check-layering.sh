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

# 行内豁免：在违规行**行尾**写 `ci-allow-layering[规则号]: 理由`，该行即被跳过。
#
# 为什么需要这个机制：有些规则会撞上真实需求（例如"禁止 shell 解释"遇上 cron——
# cron 的本职就是执行用户定义的命令），或者出现静态检测分辨不了的误报
# （例如拼接的是编译期常量、而非用户输入）。没有豁免出口时门禁会永远红着，
# 而"永远红"= 没人再看它 = 门禁失效。豁免把这类冲突**显式化**：
# 理由就写在违规点旁边，将来审计时一眼能看到"这里为什么可以例外"。
#
# **必须带理由**：冒号后没有实际内容（`ci-allow-layering[5]:` 后面空空如也）
# 不算豁免，该行照旧报错——空理由的豁免等于沉默，比不豁免更糟。
allow_filter() {
  grep -vE "ci-allow-layering\[$1\]: .+" || true
}

# ───────────────────────────────────────────────────────────────
# P1-5 前提断言：strip_tests.py 工具链必须可用且能真正执行。
# 规则 [1][2][3][6] 依赖它提取生产代码中的违规点；若 python3 缺失、
# 脚本不存在或执行抛异常，四条规则会"空命中=恒绿"，虚假保证比没有门禁更危险。
# 这里集中探测一次：工具不可用 ⇒ 本地强制失败 / CI 跳过（非通过），
# 绝不把"提取器没跑"误当成"无违规"。
# ───────────────────────────────────────────────────────────────
STRIP_ERR=""
if ! command -v python3 >/dev/null 2>&1; then
  STRIP_ERR="python3 不可用"
elif [ ! -x "ci/strip_tests.py" ]; then
  STRIP_ERR="ci/strip_tests.py 不存在或不可执行"
elif ! python3 ci/strip_tests.py 'NEVER_MATCH_PATTERN_XYZ_12345' >/dev/null 2>&1; then
  # 冒烟测试：用一个必不匹配的模式跑一次完整扫描，确认脚本能真正执行
  # （imports / 正则编译 / 目录遍历都正常），而非静默异常退出。
  STRIP_ERR="ci/strip_tests.py 执行异常（exit=$?）"
fi
SKIP_STRIP_RULES=""
if [ -n "$STRIP_ERR" ]; then
  SKIP_STRIP_RULES=1
  if [ -n "${CI:-}" ]; then
    echo "  [skip] 规则[1][2][3][6]：strip_tests.py 工具链不可用（$STRIP_ERR）——CI 跳过（非通过）" >&2
  else
    echo "  ✗ 规则[1][2][3][6]：$STRIP_ERR ——本地强制失败（门禁不可用=不通过）"
    FAIL=1
  fi
fi

echo "== [1] 子进程出口唯一性 =="
# 除 panel-os/src/cmd.rs 外，任何 crate 都不得直接 spawn 进程。
# 走 strip_tests.py：本规则管的是**生产代码**，测试里直接跑外部二进制
# （例如用真实 nginx 校验渲染结果）不属于违规。与 [2] 共用同一套剥离逻辑——
# 各条规则各自 grep、各自加 -v 绕过，正是把豁免面散开的开始。
if [ -z "${SKIP_STRIP_RULES:-}" ]; then
  SPAWN_HITS=$(python3 ci/strip_tests.py 'Command::new|tokio\.process|std::process::Command' 2>/dev/null \
    | grep -v "crates/panel-os/src/cmd.rs" | allow_filter 1 || true)
  if [ -n "$SPAWN_HITS" ]; then
    note_fail "发现 cmd.rs 之外的进程调用："
    echo "$SPAWN_HITS" | sed 's/^/      /'
  else
    note_ok "全部进程调用收敛在 panel-os/src/cmd.rs"
  fi
fi

echo "== [2] 禁止 shell 解释 =="
if [ -z "${SKIP_STRIP_RULES:-}" ]; then
  SHELL_HITS=$(python3 ci/strip_tests.py 'sh -c|bash -c|/bin/sh|"-c"' 2>/dev/null \
    | grep -v "crates/panel-os/src/cmd.rs" | strip_comments | allow_filter 2)
  if [ -n "$SHELL_HITS" ]; then
    note_fail "存在 shell 调用（命令注入高危）："
    echo "$SHELL_HITS" | sed 's/^/      /'
  else
    note_ok "无 sh -c / bash -c"
  fi
fi

echo "== [3] OS 路径硬编码 =="
# 业务层（panel-core 及未来的 panel-service / panel-api）不得出现 Linux 绝对路径
# panel-os/src/linux/** 是平台实现本身，允许；paths.rs 是布局定义，允许
# 豁免整个 panel-os：敏感路径黑名单、平台默认目录、平台实现本身都属于平台知识。
if [ -z "${SKIP_STRIP_RULES:-}" ]; then
  PATH_HITS=$(python3 ci/strip_tests.py '"/(etc|var|proc|usr|run|sys|opt|home|root)/' 2>/dev/null \
    | grep -v "crates/panel-os/")
  if [ -n "$PATH_HITS" ]; then
    note_fail "业务层出现硬编码路径（mock 与 tests 已豁免）："
    echo "$PATH_HITS" | sed 's/^/      /'
  else
    note_ok "业务层无硬编码 Linux 路径"
  fi
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
  | grep -v "crates/panel-os/src/" | strip_comments | allow_filter 4c)
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
# 规则：值必须走绑定参数。**例外**：表名/库名等 SQL 标识符无法参数化，
# 只能经专门的转义函数（`quote_ident`，双引号翻倍）拼接 —— 这类安全用法豁免。
SQL_HITS=$(grep -rn --include="*.rs" -E 'execute\(&format!|prepare\(&format!|query_row\(&format!' crates/ 2>/dev/null \
  | grep -v 'quote_ident' | strip_comments | allow_filter 5 || true)
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
if [ -z "${SKIP_STRIP_RULES:-}" ]; then
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
fi

echo "== [7] 前端可移植性与 XSS =="
# ⚠ P1-4：前端已拆为独立仓（../forkpanel-frontend/src），硬编码 `web/src` 永远为假，
#   规则[7] 永不执行、只打「骨架阶段跳过」——不是 [skip]、不判失败。改为与
#   check-api-contract.sh 同款目录探测：先前端仓 src，再兜底旧 web/src。
FE_DIR="${FE_DIR:-$ROOT/../forkpanel-frontend}"
FE_SRC=""
for cand in "$FE_DIR/src" "$ROOT/web/src"; do
  if [ -d "$cand" ]; then FE_SRC="$cand"; break; fi
done
if [ -z "$FE_SRC" ]; then
  if [ -n "${CI:-}" ]; then
    echo "  [skip] 规则[7]：找不到前端源码（试过 $FE_DIR/src 与 $ROOT/web/src）——CI 跳过（非通过）" >&2
  else
    echo "  · 未找到前端源码目录（试过 $FE_DIR/src 与 $ROOT/web/src），规则[7]跳过；本地应并列存放 forkpanel-frontend"
  fi
else
  # 过滤纯注释行（以 * 或 // 开头）：纪律说明里会提到这些词本身，不能算违规；
  # 接入 allow_filter 7 以便对可信 v-html（如渲染内部 SVG 图标集）加行内豁免。
  # Icon.vue 的 v-html 渲染**内部可信 SVG 图标集**（ICONS 为前端常量，非用户内容，
  # 无 XSS 风险），属已知安全用法，按文件路径豁免——Vue 模板自闭合标签内无法放行内
  # 注释豁免，故在此排除其路径；其余位置的 v-html 仍受规则[7]约束。
  FE_HITS=$(grep -rn -E "v-html|isLinux|navigator\.platform|target_os" "$FE_SRC" 2>/dev/null \
    | grep -vE ':[0-9]+:[[:space:]]*(\*|//)' | allow_filter 7 \
    | grep -v "components/Icon.vue")
  if [ -n "$FE_HITS" ]; then
    note_fail "前端存在平台硬编码或 v-html："
    echo "$FE_HITS" | sed 's/^/      /'
  else
    note_ok "前端无平台判断与 v-html"
  fi
fi

echo "== [8] 依赖数量预算 =="
if command -v cargo >/dev/null 2>&1; then
  # P1-6 前提断言：cargo tree 必须真正执行成功，否则不得把 N=0 当成"在预算内"。
  # 断网 / workspace 损坏 / 依赖未下载等都会导致 cargo tree 失败，
  # 旧写法 2>/dev/null 吞掉错误，N=0 ⇒ 静默放行——恒绿洞。
  TREE_OUT=$(cargo tree --edges normal --depth 1 2>/tmp/cargo_tree.err)
  TREE_RC=$?
  if [ "$TREE_RC" -ne 0 ]; then
    if [ -n "${CI:-}" ]; then
      echo "  [skip] 规则[8]：cargo tree 执行失败（exit=$TREE_RC）——CI 跳过（非通过）" >&2
    else
      echo "  ✗ 规则[8]：cargo tree 执行失败（exit=$TREE_RC）——本地强制失败（门禁不可用=不通过）"
      FAIL=1
    fi
    cat /tmp/cargo_tree.err 2>/dev/null | sed 's/^/      /' || true
  else
    # 统计**去重后**的第三方直接依赖：
    #  - `--edges normal` 排除 dev/build 依赖（测试工具不应占用生产依赖预算）；
    #  - `grep -v '^panel-'` 排除内部 workspace crate（它们是第一方代码，不是"依赖"）；
    #  - 按成员去重——`cargo tree --depth 1` 会为每个 member 重复列出同一依赖，
    #    不清重会把"被多个 crate 共用的依赖"翻倍计数，虚高到顶格、误导"预算已满"。
    # 口径对应 docs 里的"直接依赖预算 ≤ 38"（第三方、去重、生产）。
    N=$(printf '%s\n' "$TREE_OUT" | grep '^[├└]' | sed 's/^[├└]── //' | sed 's/ v[0-9].*//' \
          | grep -v '^panel-' | sort -u | wc -l)
    echo "  · 第三方直接依赖（去重、生产）约 ${N} 个（预算 ≤ 38）"
    [ "$N" -gt 38 ] && note_fail "直接依赖超出预算" || note_ok "依赖数量在预算内"
  fi
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
