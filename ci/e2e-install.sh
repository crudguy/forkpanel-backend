#!/usr/bin/env bash
# 安装脚本 E2E：在 user namespace 里真跑 `deploy/install.sh`，逐条核对
# `docs/install-footprint.md` 声称的文件、权限与 systemd 加固。
#
# ## 为什么需要
# 部署文档写得很细（装哪些文件、权限 0700/0750、单元带 ProtectSystem=strict、
# ReadWritePaths 跟随 [paths]），但**这些说法从未被脚本验证过**。文档与脚本一旦漂移，
# 用户看到的是"按文档装完服务起不来"，而我们的门禁全绿——因为门禁里没有一个用例
# 真的跑过安装脚本。
#
# ## 为什么能用 user namespace 而不污染本机
# `install.sh` 的路径全是硬编码绝对路径（/usr/local/bin、/etc/forkpanel、
# /var/lib/forkpanel …），靠环境变量挪不走。`unshare -rmn` 里我们是 uid 0，
# 先把这些目录用 tmpfs **盖住**，安装就只写进内存；进程一退，tmpfs 随之消失，
# 本机 /etc、/var/lib、/usr/local 一个字节都没动。
#
# ## 边界（诚实说明，不假装覆盖）
#  - 无 system bus ⇒ `systemctl` 用 shim 记录调用而**不真的动 init**。故本脚本验证
#    的是"install.sh 调了哪些 systemctl 命令"，不是"服务真的开机自启了"。
#    （真实 systemd 行为只能上真机验，见 docs/deployment.md 的人工清单。）
#  - 同理 `panel systemd-unit --install` 会写 /etc/systemd/system，那部分只验落盘内容。
#
# ## 用法
#   ci/e2e-install.sh [bin_path]      # 缺省 target/release/panel
# 环境不具备（无 unshare / 无 userns 权限）⇒ [skip] 且退出 2，不计为通过。
set -uo pipefail

BIN_SRC="${1:-${PANEL_E2E_INSTALL_BIN:-./target/release/panel}}"

PASS=0; FAIL=0; SKIP=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
skip() { SKIP=$((SKIP+1)); say "  [skip] $1"; }
chk()     { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1  实际=[$2] 期望=[$3]"; fi; }
chk_has() { case "$2" in *"$3"*) ok "$1";; *) bad "$1  输出缺少 [$3]；实际=[$2]";; esac; }
chk_rc()  { if [ "$2" = "$3" ]; then ok "$1 (rc=$2)"; else bad "$1  rc 实际=[$2] 期望=[$3]"; fi; }

# ── 0. 前置：二进制 + user namespace 能力 ────────────────────────────────
if [ ! -f "$BIN_SRC" ]; then
  say "[skip] 找不到二进制：$BIN_SRC（先 cargo build --release --bin panel）"
  exit 2
fi
BIN_SRC="$(cd "$(dirname "$BIN_SRC")" && pwd)/$(basename "$BIN_SRC")"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v unshare >/dev/null 2>&1; then
  say "[skip] 缺少 unshare（util-linux），无法构造隔离安装环境"
  exit 2
fi
if ! unshare -rmn --propagation private true >/dev/null 2>&1; then
  say "[skip] user namespace 不可用（内核/发行版禁用，或已被 seccomp 限制）"
  say "       本脚本靠 userns 把 /etc、/var/lib 变成一次性 tmpfs，没有它就会写到本机"
  exit 2
fi

say "== 0. 在 user namespace 内构造一次性安装环境 =="
say "  二进制：$BIN_SRC"
say "  脚本：  $REPO/deploy/install.sh"

# 所有逻辑都在 ns 内跑；用单引号 heredoc 传入，外层不展开
unshare -rmn --propagation private bash -s -- "$BIN_SRC" "$REPO" <<'INNER'
set -uo pipefail
BIN_SRC="$1"; REPO="$2"

PASS=0; FAIL=0; SKIP=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
skip() { SKIP=$((SKIP+1)); say "  [skip] $1"; }
chk()     { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1  实际=[$2] 期望=[$3]"; fi; }
chk_has() { case "$2" in *"$3"*) ok "$1";; *) bad "$1  输出缺少 [$3]；实际=[$2]";; esac; }
chk_rc()  { if [ "$2" = "$3" ]; then ok "$1 (rc=$2)"; else bad "$1  rc 实际=[$2] 期望=[$3]"; fi; }

# ── 1. 覆盖安装路径 ──────────────────────────────────────────────────────
# 注意：必须在盖住 /etc **之后**重建 /etc/alternatives/awk。awk 是
# /usr/bin/awk -> /etc/alternatives/awk 的符号链接，/etc 一旦变成空 tmpfs，
# 链接就断了，`awk` 会"凭空消失"（这正是本脚本第一次跑时踩到的坑，也是
# install.sh 里 pick_random_port 加固的直接来由）。
# ⚠ netns 里 lo 默认是 DOWN：服务 bind 127.0.0.1 能成功（bind 不需要接口 up），
# 但 TCP 连接全部超时 ⇒ curl 拿到 000。这个坑的表现极具误导性——"端口在监听"
# 却"连不上"，会让人怀疑后端，实际是网络命名空间没配回环。必须先 lo up。
ip link set lo up 2>/dev/null || { say "  ✗ 无法启用 lo（需 iproute2 与 CAP_NET_ADMIN）"; exit 1; }

for d in /usr/local /etc /var/lib /var/log /var/www /run/systemd/system; do
  mkdir -p "$d" 2>/dev/null || { say "  ✗ 无法准备 $d"; exit 1; }
  mount -t tmpfs none "$d" 2>/dev/null || { say "  ✗ 无法挂载 tmpfs 到 $d"; exit 1; }
done
mkdir -p /usr/local/bin /etc/alternatives
ln -sf /usr/bin/mawk /etc/alternatives/awk 2>/dev/null || \
  ln -sf "$(command -v gawk 2>/dev/null || echo /usr/bin/awk)" /etc/alternatives/awk 2>/dev/null || true
if echo "a b" | awk '{print $1}' >/dev/null 2>&1; then :; else
  say "  ✗ 环境自检失败：覆盖 /etc 后 awk 不可用，无法继续（这本身是个有效信号，但先修环境）"
  exit 1
fi
ok "一次性文件系统就绪（/etc /var/lib /var/log /var/www /usr/local /run/systemd/system）"

# systemctl shim：记录调用，不真的动 init
mkdir -p /tmp/e2e-shim
cat > /tmp/e2e-shim/systemctl <<'SH'
#!/bin/bash
echo "systemctl $*" >> /tmp/e2e-shim/calls.log
exit 0
SH
chmod +x /tmp/e2e-shim/systemctl
: > /tmp/e2e-shim/calls.log
export PATH=/tmp/e2e-shim:$PATH

# ── 2. 非 root 必须被拒 ──────────────────────────────────────────────────
say "== 2. 安装脚本必须拒绝非 root =="
# ⚠ userns 默认只映射一个 uid（/proc/self/uid_map 里 0 → 宿主 uid），因此
# `setpriv --reuid=65534` 会报 "setresuid failed: 无效的参数"——降到未映射的 uid
# 在内核层就不允许。这不是 install.sh 的缺陷，是隔离环境的边界，必须诚实 skip。
# 要真验这条只能上真机用普通用户跑（见 docs/deployment.md 的人工清单）。
if command -v setpriv >/dev/null 2>&1 && \
   setpriv --reuid=65534 --regid=65534 --clear-groups true >/dev/null 2>&1; then
  out=$(setpriv --reuid=65534 --regid=65534 --clear-groups bash "$REPO/deploy/install.sh" "$BIN_SRC" 2>&1); rc=$?
  chk_rc "非 root 调用被拒" "$rc" "1"
  chk_has "拒绝原因是需要 root" "$out" "需要 root"
else
  skip "userns 只映射了单个 uid，无法降权验证『非 root 被拒』（需真机普通用户）"
fi

# ── 3. 二进制不存在必须被拒 ──────────────────────────────────────────────
say "== 3. 不存在的二进制必须被拒 =="
out=$(bash "$REPO/deploy/install.sh" /nonexistent/panel 2>&1); rc=$?
chk_rc "不存在的二进制被拒" "$rc" "1"
chk_has "拒绝原因指向二进制路径" "$out" "找不到二进制"

# ── 4. 正式安装 ──────────────────────────────────────────────────────────
say "== 4. 正式安装（install.sh）=="
: > /tmp/e2e-shim/calls.log
out=$(bash "$REPO/deploy/install.sh" "$BIN_SRC" 2>&1); rc=$?
chk_rc "install.sh 退出码 0" "$rc" "0"
if [ "$rc" -ne 0 ]; then
  say "--------- 安装输出 ---------"
  say "$out"
  say "---------------------------"
fi

INSTALLED_PORT=$(grep -oE '监听端口随机分配为 [0-9]+' <<< "$out" | grep -oE '[0-9]+' | head -1)
if [ -n "$INSTALLED_PORT" ]; then ok "分配了随机端口：$INSTALLED_PORT"
else bad "安装输出里没有『监听端口随机分配为 N』"; fi

# ── 5. 逐条核对 install-footprint.md 的声明 ──────────────────────────────
say "== 5. 核对文件与权限（对照 docs/install-footprint.md）=="

chk "二进制权限 0755"        "$(stat -c '%a' /usr/local/bin/panel 2>/dev/null)" "755"
chk "/etc/forkpanel 权限 0750"  "$(stat -c '%a' /etc/forkpanel 2>/dev/null)" "750"
chk "/var/lib/forkpanel 权限 0700" "$(stat -c '%a' /var/lib/forkpanel 2>/dev/null)" "700"
chk "/var/log/forkpanel 权限 0750" "$(stat -c '%a' /var/log/forkpanel 2>/dev/null)" "750"
chk "/var/www 权限 0755"     "$(stat -c '%a' /var/www 2>/dev/null)" "755"
chk "config.toml 权限 0640"  "$(stat -c '%a' /etc/forkpanel/config.toml 2>/dev/null)" "640"

# 配置文件内容：端口必须被真的替换成随机值，且不再是模板里的 2083
if [ -f /etc/forkpanel/config.toml ]; then
  cfport=$(grep -oE '^port = [0-9]+' /etc/forkpanel/config.toml | grep -oE '[0-9]+')
  chk "config.toml 里的 port 与提示一致" "$cfport" "$INSTALLED_PORT"
  case "$cfport" in
    2083) bad "端口仍是模板默认 2083——随机化没有生效" ;;
    *) if [ "$cfport" -ge 10000 ] 2>/dev/null; then ok "端口落在 ≥10000 区间（$cfport）"
       else bad "端口 $cfport 不在随机区间（应 ≥10000）"; fi ;;
  esac
  # 默认只监听回环：这是安全默认值，改动等于把面板暴露到公网
  grep -qE '^bind = "127\.0\.0\.1"' /etc/forkpanel/config.toml \
    && ok "默认只绑定回环 127.0.0.1" || bad "默认 bind 不是 127.0.0.1"
else
  bad "config.toml 未生成"
fi

# ── 6. systemd 单元：加固项与 ReadWritePaths 必须与 [paths] 对齐 ─────────
say "== 6. systemd 单元加固（ProtectSystem / ReadWritePaths）=="
UNIT=/etc/systemd/system/panel.service
if [ -f "$UNIT" ]; then
  ok "panel.service 已落盘"
  grep -q 'ProtectSystem=strict' "$UNIT" && ok "单元启用 ProtectSystem=strict" \
    || bad "单元缺少 ProtectSystem=strict（面板可写全盘）"
  rwp=$(grep -oE '^ReadWritePaths=.*' "$UNIT" | head -1)
  if [ -n "$rwp" ]; then
    ok "单元声明了 ReadWritePaths"
    for p in /var/lib/forkpanel /var/log/forkpanel /var/www /etc/forkpanel; do
      chk_has "ReadWritePaths 含 $p" "$rwp" "$p"
    done
  else
    bad "单元缺少 ReadWritePaths——ProtectSystem=strict 下面板将无法写数据目录"
  fi
else
  bad "panel.service 未生成"
fi

# 探活单元（install.sh 会装 timer 并 enable）
for f in panel-healthcheck.service panel-healthcheck.timer; do
  [ -f "/etc/systemd/system/$f" ] && ok "探活单元已落盘：$f" || bad "缺少探活单元：$f"
done

# ── 7. install.sh 调用了哪些 systemctl（shim 记录） ──────────────────────
say "== 7. 安装过程调用了哪些 systemctl =="
calls=$(cat /tmp/e2e-shim/calls.log 2>/dev/null)
[ -n "$calls" ] && ok "捕获到 systemctl 调用" || bad "安装过程一次 systemctl 都没调用"
chk_has "调用了 daemon-reload" "$calls" "daemon-reload"
chk_has "enable 了 panel 服务" "$calls" "enable panel"
chk_has "enable 了探活 timer" "$calls" "enable --now panel-healthcheck.timer"

# ── 8. 真数据面：装的这个二进制能不能跑起来 + 初始化 + 登录 ─────────────
# 前面验的都是"文件摆对了"，这里验"装出来的东西真的能用"——两者常不一致
# （权限对了但动态库缺失、二进制架构不符，都会在这里暴露）。
say "== 8. 装出来的二进制真的能服务（起进程 + 初始化 + 登录）=="
CONF=/etc/forkpanel/config.toml
if [ ! -x /usr/local/bin/panel ]; then
  bad "装出来的二进制不可执行，跳过运行时验证"
else
  initout=$(/usr/local/bin/panel --config "$CONF" init --owner admin --owner-pass 'E2eInstall2026x' 2>&1); irc=$?
  chk_rc "用安装后的配置初始化成功" "$irc" "0"
  if [ "$irc" -ne 0 ]; then say "    init 输出：$initout"; fi

  setsid nohup /usr/local/bin/panel --config "$CONF" serve \
    > /tmp/e2e-install-serve.log 2>&1 < /dev/null &
  sleep 3
  if ss -tln 2>/dev/null | grep -q ":$INSTALLED_PORT "; then
    ok "服务在安装配置的端口 $INSTALLED_PORT 上监听"
    # ⚠ --noproxy '*' 必须带：本机若有 http_proxy/https_proxy，curl 会把回环请求
    # 也发给代理，于是"服务在监听"却拿到 000（连不上）。这类假阴性极难排查——
    # 现象像后端挂了，实际是 curl 走错了路。
    http=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -m 5 \
      -X POST "http://127.0.0.1:$INSTALLED_PORT/api/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d '{"username":"admin","password":"E2eInstall2026x"}')
    chk "owner 能登录（204）" "$http" "204"
  else
    bad "服务没在 $INSTALLED_PORT 上监听（见 /tmp/e2e-install-serve.log）"
    say "--------- serve 日志尾部 ---------"
    tail -20 /tmp/e2e-install-serve.log 2>/dev/null
  fi
  pid=$(ss -tlnp 2>/dev/null | grep ":$INSTALLED_PORT " | grep -oE 'pid=[0-9]+' | cut -d= -f2 | head -1)
  [ -n "$pid" ] && kill "$pid" 2>/dev/null
fi

# ── 9. 幂等：重跑不得覆盖已有配置 ────────────────────────────────────────
say "== 9. 重跑 install.sh 必须保留既有配置（升级不覆盖）=="
if [ -f "$CONF" ]; then
  before=$(grep -oE '^port = [0-9]+' "$CONF")
  out2=$(bash "$REPO/deploy/install.sh" "$BIN_SRC" 2>&1); rc2=$?
  chk_rc "重跑退出码 0" "$rc2" "0"
  chk_has "重跑明确提示保留配置" "$out2" "保留"
  after=$(grep -oE '^port = [0-9]+' "$CONF")
  chk "重跑后端口未被改动" "$after" "$before"
else
  bad "配置不存在，幂等性无法验证"
fi

# ── 10. 卸载：必须移除二进制与单元，且保留数据 ──────────────────────────
say "== 10. uninstall.sh：删程序、留数据 =="
mkdir -p /var/lib/forkpanel && echo keep > /var/lib/forkpanel/panel.db
out3=$(bash "$REPO/deploy/uninstall.sh" 2>&1); rc3=$?
chk_rc "uninstall.sh 退出码 0" "$rc3" "0"
[ -e /usr/local/bin/panel ] && bad "卸载后二进制仍在" || ok "二进制已移除"
[ -e "$UNIT" ] && bad "卸载后 panel.service 仍在" || ok "systemd 单元已移除"
[ -f /var/lib/forkpanel/panel.db ] && ok "数据目录被保留（不自动删账号与数据）" \
  || bad "数据目录被删除了——卸载脚本绝不应删数据"
[ -f "$CONF" ] && ok "配置文件被保留" || bad "配置文件被删除"
chk_has "卸载提示保留目录" "$out3" "保留"

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP ────────"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
INNER
rc=$?

if [ "$rc" -eq 0 ]; then
  say ""
  say "PASS：安装脚本与部署文档一致，装出来的二进制真能服务"
fi
exit "$rc"
