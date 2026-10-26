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
if grep -nE 'into_make_service_with_connect_info' "$MAIN" | grep -vE '^[0-9]+:[[:space:]]*//' | grep -q .; then
  pass "serve 已接线 into_make_service_with_connect_info"
else
  fail "serve 未接线 ConnectInfo：bootstrap_token 的回环判定取不到真实来源地址，判定形同虚设"
fi

echo "== [4] 令牌文件权限收紧到 0600（非属主 / 非 root 读不到）=="
if grep -nE '0o600|from_mode\(0o600\)' "$MAIN" | grep -vE '^[0-9]+:[[:space:]]*//' | grep -q .; then
  pass "令牌文件以 0600 写入"
else
  fail "令牌文件未设 0600 权限（同机非 root 进程可读到明文令牌）"
fi

if [ "$FAIL" -eq 0 ]; then echo "PASS：引导令牌无终端初始化安全接线齐全"; exit 0; else echo "FAIL：引导令牌安全接线缺失"; exit 1; fi
