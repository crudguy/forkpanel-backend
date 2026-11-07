#!/usr/bin/env bash
# 发版产物回验：用**安装器内嵌的那把公钥**验证 dist/ 里的 tarball、签名与 SHA256SUMS。
#
# ## 为什么不能用「私钥导出公钥」自验
# 那是自己跟自己比：secret 私钥与仓库内嵌公钥不匹配时照样绿，而用户侧
# get-panel.sh / panel upgrade 会验不过 —— 本仓反复踩过「判据指向错」这类恒绿。
# 唯一有意义的判据是「用户拿到的那把钥匙能不能验过」，故公钥直接从
# deploy/get-panel.sh 的 RELEASE_PUBKEY 块提取（与 check-docs-consistency.sh 同款提法）。
#
# ## 为什么必须在上传 Release 之前
# 一旦资产上传，用户就能下载；此时再发现密钥错配只能删 Release。放在发版流水线里
# 当场判红，把「靠人确认密钥身份」变成「机器每次发版自动证明」。
#
# ## 用法
#   bash ci/verify-release-assets.sh [仓库根] [dist 目录]
# 默认：仓库根 = 脚本上一级，dist 目录 = <仓库根>/dist
# 返回：0 = 全部通过；1 = 有失败（**不要发布**）
# 注：脚本只读，不生成任何密钥、不改动仓库文件。ROOT 参数供离线负向对照用。
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
DIST="${2:-$ROOT/dist}"

FAIL=0
fail() { echo "  ✗ $1"; FAIL=1; }
pass() { echo "  ✓ $1"; }

INSTALLER="$ROOT/deploy/get-panel.sh"
KEYFILE="$ROOT/deploy/release-pubkey.pub"
[ -s "$INSTALLER" ] || { fail "找不到安装器 $INSTALLER（提取前提不成立）"; exit 1; }
[ -s "$KEYFILE" ] || { fail "找不到 $KEYFILE（升级链验签公钥）"; exit 1; }
[ -d "$DIST" ] || { fail "找不到产物目录 $DIST"; exit 1; }
command -v openssl >/dev/null 2>&1 || { fail "缺少 openssl（验签必需）"; exit 1; }

PUB="$(mktemp)"
trap 'rm -f "$PUB"' EXIT

# 与 ci/check-docs-consistency.sh:97 同一提取口径：取 BEGIN 后的那行 base64。
B64="$(grep -A1 'BEGIN PUBLIC KEY' "$INSTALLER" | tail -1 | tr -d " \t'")"
FILE_B64="$(grep -v -e 'BEGIN PUBLIC KEY' -e 'END PUBLIC KEY' "$KEYFILE" | tr -d ' \n\r')"
if [ -z "$B64" ] || [ -z "$FILE_B64" ]; then
  fail "公钥提取为空（正则失效，判据不可信，绝不当作通过）"
  exit 1
fi
if [ "$B64" != "$FILE_B64" ]; then
  fail "安装器内嵌公钥与 deploy/release-pubkey.pub 不一致（升级链会验不过）"
else
  pass "安装器内嵌公钥 == release-pubkey.pub（单一信任根）"
fi
{
  printf '%s\n' '-----BEGIN PUBLIC KEY-----'
  printf '%s\n' "$B64"
  printf '%s\n' '-----END PUBLIC KEY-----'
} > "$PUB"

echo "== [1] 双架构 tarball + .sig，用用户侧公钥验签 =="
for arch in amd64 arm64; do
  t="$DIST/panel-linux-$arch.tar.gz"
  s="$t.sig"
  if [ ! -s "$t" ]; then fail "缺产物 $t（双架构必须齐全）"; continue; fi
  if [ ! -s "$s" ]; then fail "缺签名 $s"; continue; fi
  # 与 deploy/get-panel.sh:248 完全同一条命令，保证「用户能验过」而不是自验自话。
  if openssl dgst -verify "$PUB" -signature "$s" "$t" >/dev/null 2>&1; then
    pass "$arch：签名有效"
  else
    fail "$arch：验签失败 —— secret 私钥与内嵌公钥不匹配，或产物被篡改"
  fi
done

echo "== [2] SHA256SUMS 覆盖双架构且逐项校验通过 =="
SUMS="$DIST/SHA256SUMS"
if [ ! -s "$SUMS" ]; then
  fail "缺 $SUMS"
else
  for arch in amd64 arm64; do
    if grep -q "panel-linux-$arch.tar.gz" "$SUMS"; then
      pass "SHA256SUMS 覆盖 $arch"
    else
      fail "SHA256SUMS 未覆盖 $arch（发布资产会少一半）"
    fi
  done
  if ( cd "$DIST" && sha256sum -c SHA256SUMS --quiet ) >/dev/null 2>&1; then
    pass "SHA256SUMS 逐项校验通过"
  else
    fail "SHA256SUMS 与实际产物不符"
  fi
fi

if [ "$FAIL" -ne 0 ]; then
  echo "✗ 发版产物回验失败：**不要发布**（用户侧会验不过，或资产不全）"
  exit 1
fi
echo "PASS：发版产物用安装器内嵌公钥回验通过（双架构 + 签名 + SHA256SUMS）"
exit 0
