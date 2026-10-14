#!/usr/bin/env bash
# 依赖安全审计门禁：cargo audit 扫 Cargo.lock 的已知漏洞（RustSec advisory-db）。
#
# 与 ci/check-layering.sh / check-api-contract.sh 等并列的**手动门禁**（本项目无自动
# CI 流水线，由开发者/编排者运行）。用法：./ci/check-audit.sh [仓库根目录]
#
# 恒绿纪律（与 check-api-contract.sh 同范式）：cargo-audit **找不到就失败**，绝不静默
# 跳过——「恒绿的门禁比没有门禁更危险」。缺失时给出可操作的安装提示。
#
# 网络鲁棒性：advisory-db 托管在 github，本机网络会抖动。故**先试联网拉新库拿最新事实，
# 仅当失败是网络类（fetch/IO/git/dns/tcp）时回退本地缓存 --no-fetch 重判**——绝不因
# 网络抖动把结果判错。本地缓存由首次 `cargo audit`（或 `cargo audit fetch`）生成，
# 建议定期联网刷新以纳入新公布 advisory。
#
# 退出语义：发现**漏洞**→ 非零（门禁红）；仅有 unmaintained 等 warning 不拦（cargo audit
# 默认行为，warning 不改变退出码）。需连 warning 一起拒可加 -D warnings。
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

# ── 定位 cargo-audit：PATH → ~/.cargo/bin → 本机 managed 工具目录 ──
# command -v 对裸名查 PATH、对绝对路径查可执行，两者都覆盖。
AUDIT_BIN=""
for cand in cargo-audit "$HOME/.cargo/bin/cargo-audit" \
            /home/a/.workbuddy/binaries/cargo-tools/bin/cargo-audit; do
  p="$(command -v "$cand" 2>/dev/null)" && { AUDIT_BIN="$p"; break; }
done

if [ -z "$AUDIT_BIN" ]; then
  echo "  ✗ 未找到 cargo-audit——依赖安全审计门禁无法运行"
  echo "      修复：cargo install cargo-audit"
  echo "      —— 找不到审计工具即判失败，绝不静默跳过（恒绿比没门禁更危险）"
  exit 1
fi

echo "== 依赖安全审计（cargo audit / RustSec advisory-db） =="
echo "  使用：$AUDIT_BIN"

# 先联网拉新库；仅网络类失败才回退本地缓存（--no-fetch）。
out="$("$AUDIT_BIN" audit 2>&1)"; rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qiE 'fetch|network|IO error|git operation|dns|tcp|connection'; then
  echo "  · 联网更新 advisory-db 失败，回退本地缓存（--no-fetch）重判"
  out="$("$AUDIT_BIN" audit --no-fetch 2>&1)"; rc=$?
fi
printf '%s\n' "$out"

if [ $rc -eq 0 ]; then
  echo "PASS：Cargo.lock 无已知漏洞"
  exit 0
else
  echo "FAIL：cargo audit 退出码 $rc——可能有漏洞，或无本地 advisory-db（先联网跑一次 cargo audit fetch），详见上方"
  exit 1
fi
