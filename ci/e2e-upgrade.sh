#!/usr/bin/env bash
# 升级链路 E2E（离线；在 user namespace 的 tmpfs 里真跑）
#
# 覆盖三条：
#   1) 正常升级：本地 http 源 + 测试密钥签名 → 下载 → 验签 → 解包 → install.sh
#   2) 篡改 tarball：验签必须失败，且**绝不执行**包内 install.sh
#   3) install.sh 失败：必须回滚旧二进制
#
# 需要：user namespace、openssl、python3、release 二进制（install.sh 会执行它）。
# 不具备时 [skip] 退出 2（不冒充通过）。
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="${1:-$HERE/target/release/panel}"

say() { printf '%s\n' "$*"; }
if [ ! -f "$BIN_SRC" ]; then
  say "[skip] 找不到二进制：$BIN_SRC（先 cargo build --release --bin panel）"
  exit 2
fi
BIN_SRC="$(cd "$(dirname "$BIN_SRC")" && pwd)/$(basename "$BIN_SRC")"
for b in unshare openssl python3 curl; do
  command -v "$b" >/dev/null 2>&1 || { say "[skip] 缺少 $b"; exit 2; }
done
if ! unshare -rmn --propagation private true >/dev/null 2>&1; then
  say "[skip] user namespace 不可用"
  exit 2
fi

say "== 0. 构造一次性环境（tmpfs + shim + 本地发行源）=="
unshare -rmn --propagation private bash -s -- "$BIN_SRC" "$HERE" <<'INNER'
set -uo pipefail
BIN_SRC="$1"; REPO="$2"
PASS=0; FAIL=0; SKIP=0
ok()  { PASS=$((PASS+1)); say "  ✓ $1"; }
bad() { FAIL=$((FAIL+1)); say "  ✗ $1"; }
skip(){ SKIP=$((SKIP+1)); say "  [skip] $1"; }
chk()    { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 实际=[$2] 期望=[$3]"; fi; }
chk_rc() { if [ "$2" = "$3" ]; then ok "$1 (rc=$2)"; else bad "$1 rc 实际=[$2] 期望=[$3]"; fi; }
chk_has(){ case "$2" in *"$3"*) ok "$1";; *) bad "$1 缺少 [$3]；实际=[$(printf '%s' "$2" | tail -3 | tr '\n' ' ')]";; esac; }
say() { printf '%s\n' "$*"; }

ip link set lo up 2>/dev/null || { say "  ✗ 无法启用 lo"; exit 1; }
for d in /usr/local /etc /var /run/systemd/system; do
  mkdir -p "$d" 2>/dev/null || { say "  ✗ 无法准备 $d"; exit 1; }
  mount -t tmpfs none "$d" 2>/dev/null || { say "  ✗ 无法挂载 tmpfs 到 $d"; exit 1; }
done
mkdir -p /usr/local/bin /usr/local/share/forkpanel /etc/forkpanel /etc/systemd/system \
         /var/lib/forkpanel /var/log/forkpanel /var/www \
         /tmp/up-srv/v0.1.0 /tmp/up-srv/v0.2.0 /tmp/up-srv/stage-good /tmp/up-srv/stage-bad /tmp/up-shim
ok "一次性文件系统就绪"

# 旧二进制（升级前）
cp "$BIN_SRC" /usr/local/bin/panel && chmod 0755 /usr/local/bin/panel
SHA_OLD=$(sha256sum /usr/local/bin/panel | cut -d' ' -f1)

cat > /etc/forkpanel/config.toml <<'EOF'
tier = "auto"
[server]
bind = "127.0.0.1"
port = 2099
localhost_only = true
[paths]
config = "/etc/forkpanel"
data = "/var/lib/forkpanel"
log = "/var/log/forkpanel"
site_root = "/var/www"
[db]
synchronous = "NORMAL"
daily_backup = false
[security]
session_idle = "30m"
session_absolute = "12h"
max_login_attempts = 5
read_only = false
[audit]
retention_days = 90
max_rows = 50000
EOF

# systemctl / ss shim。⚠ panel-os 的 Bin::resolved() **不读 PATH**（防劫持），
# 所以 systemctl 必须 bind-mount 到它实际搜索的路径，光放 PATH 是无效的。
cat > /tmp/up-shim/systemctl <<'SH'
#!/bin/bash
echo "systemctl $*" >> /tmp/up-shim/calls.log
exit 0
SH
cat > /tmp/up-shim/ss <<'SH'
#!/bin/bash
printf 'State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'
printf 'LISTEN 0 128 127.0.0.1:2099 0.0.0.0:*\n'
SH
chmod +x /tmp/up-shim/systemctl /tmp/up-shim/ss
: > /tmp/up-shim/calls.log
export PATH=/tmp/up-shim:$PATH

BOUND=0
for p in /usr/sbin/systemctl /usr/bin/systemctl; do
  if [ -e "$p" ] && mount --bind /tmp/up-shim/systemctl "$p" 2>/dev/null; then BOUND=1; fi
done
if [ "$BOUND" -ne 1 ]; then
  say "  [skip] 无法把 systemctl shim bind 到 /usr/{s,}bin（会调用真实 systemd），跳过"
  exit 2
fi
systemctl is-active panel >/dev/null 2>&1
grep -q "is-active panel" /tmp/up-shim/calls.log || { say "  ✗ shim 未生效"; exit 1; }
ok "systemctl shim 生效（bind mount）"

# 测试密钥
openssl genpkey -algorithm ed25519 -out /tmp/up.key 2>/dev/null
openssl pkey -in /tmp/up.key -pubout -out /tmp/up.pub 2>/dev/null
[ -s /tmp/up.pub ] || { say "  ✗ 测试密钥生成失败"; exit 1; }

make_pkg() { # $1=stage $2=install.sh 路径 $3=输出 tar
  local stage="$1" ins="$2" tar="$3"
  cp "$BIN_SRC" "$stage/panel" && chmod 0755 "$stage/panel"
  cp "$ins" "$stage/install.sh" && chmod 0755 "$stage/install.sh"
  cp "$REPO/deploy/config.toml" "$stage/config.toml"
  cp "$REPO/deploy/forkpanel-config.sh" "$stage/forkpanel-config.sh"
  tar -C "$stage" -czf "$tar" panel install.sh config.toml forkpanel-config.sh || return 1
  openssl pkeyutl -sign -inkey /tmp/up.key -rawin -in "$tar" -out "$tar.sig" || return 1
  [ -s "$tar" ] && [ -s "$tar.sig" ]
}

make_pkg /tmp/up-srv/stage-good "$REPO/deploy/install.sh" /tmp/up-srv/v0.1.0/panel-linux-amd64.tar.gz \
  || { say "  ✗ 正常包生成失败"; exit 1; }
printf '#!/bin/bash\nexit 1\n' > /tmp/up-srv/stage-bad-install.sh
chmod 0755 /tmp/up-srv/stage-bad-install.sh
make_pkg /tmp/up-srv/stage-bad /tmp/up-srv/stage-bad-install.sh /tmp/up-srv/v0.2.0/panel-linux-amd64.tar.gz \
  || { say "  ✗ 失败包生成失败"; exit 1; }
ok "已生成 v0.1.0（正常）与 v0.2.0（install.sh 必失败）两套签名包"

python3 -m http.server 18080 --bind 127.0.0.1 --directory /tmp/up-srv >/tmp/up-http.log 2>&1 &
HTTP_PID=$!
trap 'kill $HTTP_PID 2>/dev/null' EXIT
for _ in $(seq 1 30); do
  curl -sf -o /dev/null http://127.0.0.1:18080/v0.1.0/panel-linux-amd64.tar.gz && break
  sleep 0.2
done
curl -sf -o /dev/null http://127.0.0.1:18080/v0.1.0/panel-linux-amd64.tar.gz \
  || { say "  ✗ 本地源未就绪"; exit 1; }
ok "本地发行源就绪（127.0.0.1:18080）"

up() { "$BIN_SRC" --config /etc/forkpanel/config.toml upgrade "$@" 2>&1; }
BASE="--base-url http://127.0.0.1:18080 --pubkey-file /tmp/up.pub"

say "== 1. dry-run：下载 + 验签 + 解包 =="
out=$(up --version 0.1.0 $BASE --dry-run); rc=$?
chk_rc "dry-run 退出码" "$rc" "0"
chk_has "dry-run 验签通过" "$out" "签名有效"
chk_has "dry-run 未安装" "$out" "未安装"
[ -e /usr/local/bin/panel.bak ] && bad "dry-run 不应写备份" || ok "dry-run 未落盘"

say "== 2. 篡改 tarball：必须验签失败且不执行包内文件 =="
cp /tmp/up-srv/v0.1.0/panel-linux-amd64.tar.gz /tmp/good.tar
printf 'X' >> /tmp/up-srv/v0.1.0/panel-linux-amd64.tar.gz
out=$(up --version 0.1.0 $BASE --dry-run); rc=$?
[ "$rc" -ne 0 ] && ok "篡改包被拒（rc=$rc）" || bad "篡改包竟然通过"
chk_has "拒绝原因是验签失败" "$out" "验签失败"
grep -q "start panel" /tmp/up-shim/calls.log \
  && bad "篡改包竟触发了 install.sh（start panel 已被调用）" || ok "包内 install.sh 未被执行"
cp /tmp/good.tar /tmp/up-srv/v0.1.0/panel-linux-amd64.tar.gz

say "== 3. 正常升级：install.sh 成功 =="
out=$(up --version 0.1.0 $BASE); rc=$?
chk_rc "升级退出码" "$rc" "0"
chk_has "升级完成" "$out" "升级完成"
[ -f /usr/local/bin/panel.bak ] && ok "旧二进制已备份为 panel.bak" || bad "缺少 panel.bak"
chk "备份内容 == 升级前二进制" \
  "$(sha256sum /usr/local/bin/panel.bak | cut -d' ' -f1)" "$SHA_OLD"
grep -q "start panel" /tmp/up-shim/calls.log && ok "install.sh 已拉起服务" || bad "install.sh 未拉起服务"

say "== 4. install.sh 失败：必须回滚 =="
# 先把当前二进制换成一个**不同内容**的标记文件：否则新旧都是同一个 release 二进制，
# 回滚断言会因为「回滚前后哈希本来就相同」而恒真（假绿）。
printf 'marker-old-binary\n' > /usr/local/bin/panel && chmod 0755 /usr/local/bin/panel
SHA_MARK=$(sha256sum /usr/local/bin/panel | cut -d' ' -f1)
out=$(up --version 0.2.0 $BASE); rc=$?
[ "$rc" -ne 0 ] && ok "失败退出码非 0（rc=$rc）" || bad "install.sh 失败却返回 0"
chk_has "提示已回滚" "$out" "已回滚"
chk "回滚后二进制 == 失败前标记" \
  "$(sha256sum /usr/local/bin/panel | cut -d' ' -f1)" "$SHA_MARK"

say ""
say "──────── 升级 E2E：PASS=$PASS FAIL=$FAIL SKIP=$SKIP ────────"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
INNER
rc=$?
if [ "$rc" -eq 0 ]; then
  say ""
  say "PASS：升级链路（验签 / 安装 / 回滚）按预期工作"
fi
exit "$rc"
