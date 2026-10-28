#!/usr/bin/env bash
# E2E for deploy/mirror-sync.sh（离线、不依赖真实 GitHub）：
#   - 好源：同步 latest，两架构 tarball+sig 落盘、验签通过
#   - 坏源（攻击者私钥签名）：同步必须拒绝，且绝不落盘任何文件
#
# 用本地 python http.server 冒充"官方 Release 源"，用自签 ed25519 测试密钥验签。
set -uo pipefail

MS="$(cd "$(dirname "$0")/.." && pwd)/deploy/mirror-sync.sh"
[ -f "$MS" ] || { echo "找不到 $MS" >&2; exit 1; }

ROOT="$(mktemp -d)"
trap 'kill "$HP" 2>/dev/null; rm -rf "$ROOT"' EXIT

openssl genpkey -algorithm ed25519 -out "$ROOT/test.key" 2>/dev/null
openssl pkey -in "$ROOT/test.key" -pubout -out "$ROOT/test.pub.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$ROOT/rogue.key" 2>/dev/null   # 攻击者密钥

# 把两架构 tarball+sig 用指定 key 签好放进 dir
build() {
  local dir="$1" key="$2"
  mkdir -p "$dir"
  for arch in amd64 arm64; do
    mkdir -p "$ROOT/payload"
    printf '#!/bin/sh\necho p\n' > "$ROOT/payload/panel"
    printf '#!/bin/sh\necho i\n' > "$ROOT/payload/install.sh"
    printf '[server]\nport=2083\n' > "$ROOT/payload/config.toml"
    tar -C "$ROOT/payload" --owner=0 --group=0 -czf "$dir/panel-linux-$arch.tar.gz" panel install.sh config.toml
    openssl pkeyutl -sign -inkey "$key" -rawin -in "$dir/panel-linux-$arch.tar.gz" -out "$dir/panel-linux-$arch.tar.gz.sig"
  done
}
build "$ROOT/good" "$ROOT/test.key"   # 好源：测试私钥签（与 --pubkey 匹配）
build "$ROOT/bad"  "$ROOT/rogue.key"  # 坏源：攻击者私钥签（客户端测试公钥验不过）

PORT=8732
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$ROOT" >/dev/null 2>&1 &
HP=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PORT/good/panel-linux-amd64.tar.gz.sig" >/dev/null 2>&1 && break
  sleep 0.1
done

pass=0; fail=0
check() { if eval "$2"; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1"; fail=$((fail+1)); fi; }

echo "==> 场景 A：从好源同步 latest，应落盘两架构并验签通过"
DEST="$ROOT/mirror"
OUT="$(PANEL_RELEASE_BASE="http://127.0.0.1:$PORT/good" bash "$MS" --version latest --dest "$DEST" --pubkey "$ROOT/test.pub.pem" 2>&1)"; RC=$?
check "同步成功（exit0）" '[ "$RC" -eq 0 ]'
check "两架构 tarball 落盘 latest/" \
  '[ -f "$DEST/latest/panel-linux-amd64.tar.gz" ] && [ -f "$DEST/latest/panel-linux-arm64.tar.gz" ]'
check "两架构 sig 落盘" \
  '[ -f "$DEST/latest/panel-linux-amd64.tar.gz.sig" ] && [ -f "$DEST/latest/panel-linux-arm64.tar.gz.sig" ]'
check "输出含『验签 OK』与『已镜像到』" \
  'printf "%s" "$OUT" | grep -q "验签 OK" && printf "%s" "$OUT" | grep -q "已镜像到"'

echo "==> 场景 B：坏源（攻击者签名）同步必须拒绝且不落盘"
DEST2="$ROOT/mirror2"
OUT2="$(PANEL_RELEASE_BASE="http://127.0.0.1:$PORT/bad" bash "$MS" --version latest --dest "$DEST2" --pubkey "$ROOT/test.pub.pem" 2>&1)"; RC2=$?
check "坏源同步退出非0（拒绝镜像）" '[ "$RC2" -ne 0 ]'
check "坏源未落盘任何文件" \
  '[ ! -d "$DEST2/latest" ] || [ -z "$(ls -A "$DEST2/latest" 2>/dev/null)" ]'

echo
echo "=========================================="
echo "PASS=$pass  FAIL=$fail"
echo "=========================================="
[ "$fail" -eq 0 ]
