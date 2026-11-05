#!/usr/bin/env bash
# 无终端初始化：引导令牌「仅 localhost 可取」+ bootstrap 后文件即删 的**源码级守卫**。
#
# 恒绿纪律（与 check-api-contract.sh / check-audit.sh 同范式）：行为测试若只驱动函数自身，
# 删掉接线（端点不校验回环 / bootstrap 不删文件）仍会绿——故本门禁直接盯住源码接线，
# 且断言前**剔除注释行**（多文件 grep 前缀是 `文件名:行号:`，按 `^[^:]+:[0-9]+:` 过滤会
# 误伤；这里用 `^[0-9]+:[[:space:]]` 只针对单文件路径的 grep -n 输出）。
#
# 用法：./ci/check-bootstrap-token.sh [仓库根目录]
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

FAIL=0
fail() { echo "  ✗ $1"; FAIL=1; }
pass() { echo "  ✓ $1"; }

AUTH="crates/panel-api/src/routes/auth.rs"
MAIN="crates/panel-cli/src/main.rs"
# `axum::serve` 的启动装配住在 cmd/serve.rs（Q-07 第 1 刀 add6824 从 main.rs 搬走）。
# ⚠ 判据**不再盯死某个文件名**：那次搬迁没同步本脚本，[3] 就一直红，而它当时
# 没接进 make guards，于是谁都没发现。现在扫整个 panel-cli/src，文件再搬也不会瞎。
CLI_SRC="crates/panel-cli/src"

# 前提断言：文件必须存在且非空，否则下面 grep / awk 塌成 0 会恒绿（与 check-api-contract.sh 同教训）
[ -s "$AUTH" ] || fail "$AUTH 不存在或为空——提取前提不成立，绝不能当作通过"
[ -s "$MAIN" ] || fail "$MAIN 不存在或为空——提取前提不成立，绝不能当作通过"

# 剔注释行：单文件 grep -n 前缀是 `行号:`，按此过滤；注释里的 `forbidden`/`is_loopback`
# 不得让门禁误判为已接线（否则删掉真实代码仍报「✓」）。
nz() { grep -vE '^[0-9]+:[[:space:]]*//' "$1" | grep -c .; }

echo "== [1] 端点对回环地址做硬拒（非 loopback → 403）=="
# 处理函数必须存在、调用回环判定、且在非回环分支返回 forbidden。
if awk '/^pub async fn bootstrap_token\(/{f=1} f&&/is_loopback|ip\(\)\.is_loopback\(\)/{a=1} f&&/forbidden\(/{b=1} f&&/^}/{print (a&&b)?"1":"0"; exit}' "$AUTH" | grep -q 1; then
  pass "bootstrap_token 在回环判定后于非回环分支返回 403"
else
  fail "bootstrap_token 未在非回环分支以 403 拒绝（远程攻击者可取到令牌）"
fi

echo "== [2] bootstrap 成功后删除磁盘明文令牌文件 =="
# 必须是在 `fn bootstrap` 函数体内调用清理（而非只在别处定义）。
if awk '/^pub async fn bootstrap\(/{f=1} f&&/clear_bootstrap_token_file\(/{c=1} f&&/^}/{print (c)?"1":"0"; exit}' "$AUTH" | grep -q 1; then
  pass "bootstrap 处理函数体内调用了令牌文件清理"
else
  fail "bootstrap 成功后未删除 bootstrap.token（初始化后明文令牌残留磁盘）"
fi

echo "== [3] serve 真正把 ConnectInfo 接进连接（否则回环判定永远读不到真实 peer）=="
# 判据形态（与 check-api-contract.sh 的「定义处恰好 N 处」同范式）：
#   ① 先剔注释行（递归 grep 的前缀是 `文件:行号:`，故按 `:[0-9]+:\s*//` 过滤，
#      不能照抄单文件版的 `^[0-9]+:`——那对递归输出恒不命中，等于没剔）；
#   ② 再断言**恰好 1 处**：0 处=没接线（真漏洞）；多出来=有人又开了一条连接入口，
#      也该看一眼。只判 `>0` 时，注释里写着这个词也会假绿。
CC_N=$(grep -rnE 'into_make_service_with_connect_info' "$CLI_SRC" --include='*.rs' \
        | grep -vE ':[0-9]+:[[:space:]]*//' | grep -c . || true)
if [ "$CC_N" = "1" ]; then
  pass "serve 已接线 into_make_service_with_connect_info（panel-cli/src 下恰好 1 处）"
elif [ "$CC_N" = "0" ]; then
  fail "serve 未接线 ConnectInfo：bootstrap_token 的回环判定取不到真实来源地址，判定形同虚设"
else
  fail "into_make_service_with_connect_info 出现 $CC_N 处（期望恰好 1 处）——新增连接入口须同步复核该判据"
fi

echo "== [4] 令牌文件权限收紧到 0600（非属主 / 非 root 读不到）=="
if grep -nE '0o600|from_mode\(0o600\)' "$MAIN" | grep -vE '^[0-9]+:[[:space:]]*//' | grep -q .; then
  pass "令牌文件以 0600 写入"
else
  fail "令牌文件未设 0600 权限（同机非 root 进程可读到明文令牌）"
fi

if [ "$FAIL" -eq 0 ]; then echo "PASS：引导令牌无终端初始化安全接线齐全"; exit 0; else echo "FAIL：引导令牌安全接线缺失"; exit 1; fi
