#!/usr/bin/env bash
# ForkPanel 安装脚本：二进制 → 目录 → 默认配置 → systemd 单元 → 自动拉起服务
#
# 用法（需 root）：
#   ./deploy/install.sh [二进制路径]        # 缺省 ./target/release/panel
#
# 该脚本只做"安装"，不建账号。首个 owner 由 Web 首启向导创建：
# 服务被自动拉起后，从日志取一次性引导令牌，在浏览器里完成初始化。
#
# ★ 改动本脚本前请看 `ci/e2e-install.sh`：它在 user namespace 里把 /usr/local、
#   /etc、/var/lib、/var/log、/var/www 换成一次性 tmpfs 后**真跑一遍本脚本**，
#   逐条核对 `docs/install-footprint.md` 声称的路径与权限（`make e2e-install`）。
#   加了新落盘位置或改了权限，记得同步文档与那条 E2E，否则门禁会红。
set -euo pipefail

BIN_SRC="${1:-./target/release/panel}"
PREFIX="${PREFIX:-/usr/local}"
BIN_DST="$PREFIX/bin/panel"

CONF_DIR=/etc/forkpanel
CONF_FILE="$CONF_DIR/config.toml"
DATA_DIR=/var/lib/forkpanel
LOG_DIR=/var/log/forkpanel
SITE_ROOT=/var/www

die() { echo "install: $1" >&2; exit 1; }

# 发行版端口随机分配 ≥10000，避免固定 2083 被扫描
# ⚠ 探测工具必须显式检查：`ss | awk` 里 awk 若不可用（精简镜像、路径被覆盖、
#   alternatives 链断裂），管道**照样 exit 0**（退出码来自 awk，而 awk 根本没跑起来
#   时 bash 报 "awk: command not found" 却仍以 0 结束管道）⇒ 于是"没有任何端口被占"，
#   随手挑一个。装完服务起不来，原因还离现场很远。宁可不随机，也不要随机到错的。
pick_random_port() {
  local p
  if ! command -v ss >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then
    echo "install: 缺少 ss/awk，无法检测端口占用，退回默认端口 2083" >&2
    echo 2083; return 0
  fi
  # 一次性取到所有监听端口，避免循环里反复 fork。
  # ⚠ 判据不能是"used 为空"——一台全新机器可能真的一个监听都没有，那是合法状态。
  #   要判的是**探测本身有没有跑起来**：ss 头部固定有 "State Recv-Q ..." 这行，
  #   连头部都没有才说明 ss 输出异常（无权限、命令坏了）。
  local raw; raw=$(ss -ltn 2>/dev/null)
  local used; used=$(printf '%s\n' "$raw" | awk 'NR>1{print $4}')
  if ! printf '%s\n' "$raw" | grep -q '^State'; then
    echo "install: ss 输出异常（缺少表头），无法检测端口占用，退回默认端口 2083" >&2
    echo 2083; return 0
  fi
  for _ in $(seq 1 30); do
    p=$(( 10000 + (RANDOM * 32768 + RANDOM) % 55536 ))
    if ! printf '%s\n' "$used" | grep -qE "[:.]${p}\$"; then
      echo "$p"; return 0
    fi
  done
  echo "install: 30 次随机都没找到空闲端口，退回默认端口 2083" >&2
  echo 2083; return 0
}

# 等某个端口真的进入 LISTEN（最多 15 秒）。
# ⚠ 这个函数不能省：单元是 **Type=simple**（crates/panel-cli/src/bootstrap.rs），
#   systemd 在进程 fork 之后就判定"启动成功"——端口被占 / 配置有误导致"起来又立刻
#   退出"时，`systemctl start` 常常早就返回 0 了。也就是说，**systemctl 的退出码
#   不足以证明服务活着**。判据必须是"内核里真的有东西在 listen"。
wait_port_up() {
  local port="$1" i
  command -v ss >/dev/null 2>&1 || return 1
  command -v awk >/dev/null 2>&1 || return 1
  for i in $(seq 1 15); do
    if ss -ltn 2>/dev/null | awk 'NR>1{print $4}' | grep -qE "[:.]${port}\$"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

[ "$(id -u)" -eq 0 ] || die "需要 root 权限（面板要管理系统服务/防火墙）"
[ -f "$BIN_SRC" ]   || die "找不到二进制：$BIN_SRC（先 cargo build --release，或显式传入路径）"
command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd（请用 --config 直接运行 serve，或自行接入进程管理器）"

install -m 0755 "$BIN_SRC" "$BIN_DST"
echo "· 二进制 → $BIN_DST"

# 公网暴露脚本（面板仍绑回环，由它做 nginx 反代 + 防火墙白名单，绝不裸奔到公网）
SHARE_DIR="${PREFIX}/share/forkpanel"
EXPOSE_SRC="$(dirname "$0")/expose-public.sh"
EXPOSE_DST="$SHARE_DIR/expose-public.sh"
if [ -f "$EXPOSE_SRC" ]; then
  install -d -m 0755 "$SHARE_DIR"
  install -m 0755 "$EXPOSE_SRC" "$EXPOSE_DST"
  echo "· 公网暴露脚本 → $EXPOSE_DST"
else
  echo "· ⚠ 未找到 $EXPOSE_SRC，跳过安装 expose 脚本（panel expose 将不可用）" >&2
fi

install -d -m 0750 "$CONF_DIR"
install -d -m 0700 "$DATA_DIR"
install -d -m 0750 "$LOG_DIR"
install -d -m 0755 "$SITE_ROOT"
echo "· 目录已就绪（数据 0700 / 配置·日志 0750）"

if [ -f "$CONF_FILE" ]; then
  echo "· 配置已存在，保留 $CONF_FILE（升级不覆盖）"
  PORT=$(grep -oE '^port = [0-9]+' "$CONF_FILE" | grep -oE '[0-9]+' || echo 2083)
else
  PORT=$(pick_random_port)
  install -m 0640 "$(dirname "$0")/config.toml" "$CONF_FILE"
  sed -i -E "s/^port = [0-9]+/port = $PORT/" "$CONF_FILE"
  echo "· 默认配置 → $CONF_FILE（监听端口随机分配为 $PORT）"
fi

"$BIN_DST" --config "$CONF_FILE" systemd-unit --install >/dev/null
systemctl daemon-reload
systemctl enable panel >/dev/null
echo "· systemd 单元已安装并设为开机自启"

# ── 装完直接把服务拉起来 ────────────────────────────────────────────────
# 用户不该还得自己敲 `systemctl start panel`。但这里的诚实性要求有两条，别为省事省掉：
#
# 1) **不能只看 systemctl 的退出码**就宣布"已启动"：单元是 Type=simple（见
#    wait_port_up 的注释），端口冲突等情形下进程会 fork 之后立刻退出，
#    而那时 systemctl 早已返回 0。⇒ 必须真探端口，否则我们输出的"已启动"是句谎话。
#
# 2) **启动失败也不许带崩整条 set -e**：走到这里时二进制 / 目录 / 配置 / 单元都已落盘，
#    把它判成"安装失败"是错的——真实状态是"已安装、这一次没起来"。用户的退出码语义是
#    "安装是否成功"，所以本脚本仍以 0 退出，同时给一条能直接看到真实报错的诊断。
RUN_STATE="up"
if ! systemctl start panel 2>/dev/null; then
  RUN_STATE="failed"
  echo "· ⚠ 服务已安装，但本次自动启动失败。看真实原因（常见：端口 $PORT 被占用 / 配置有误）：" >&2
  echo "      journalctl -u panel -n 50 --no-pager" >&2
  echo "      systemctl status panel --no-pager" >&2
elif wait_port_up "$PORT"; then
  echo "· 服务已自动启动（端口 $PORT 已在监听）"
else
  # start 说自己成功了，端口却没 listen —— 正是 Type=simple 的假阴性，必须照实说
  RUN_STATE="unknown"
  echo "· 服务已安装、启动命令已下发，但端口 $PORT 尚未进入监听。" >&2
  echo "  （Type=simple 单元 fork 即算成功，起来又立刻退出的情况未必反映到退出码里。）" >&2
  echo "  请按下面第 1 步确认实际状态：" >&2
  echo "      systemctl status panel --no-pager" >&2
  echo "      journalctl -u panel -n 50 --no-pager" >&2
fi

# 外部探活：Restart=on-failure 只覆盖「进程死了」，不覆盖「活着但不服务」
# （事件循环卡死、监听 socket 丢失但主线程没退）。每分钟探一次 /api/v1/version，
# 连续两次失败才重启——给瞬时抖动留机会，避免误把好服务重启掉。
# 不需要可删掉这两行 + 执行 panel healthcheck --uninstall。
"$BIN_DST" --config "$CONF_FILE" healthcheck --install >/dev/null
systemctl daemon-reload
systemctl enable --now panel-healthcheck.timer >/dev/null
echo "· 外部探活已安装（每分钟一次，连续两次失败才重启）"

case "$RUN_STATE" in
  up)      STEP1="服务已自动启动并在端口 $PORT 监听（systemctl status panel 看详情）" ;;
  unknown) STEP1="启动命令已下发但端口未确认监听，先跑 systemctl status panel 确认状态" ;;
  *)       STEP1="本次自动启动失败：先 journalctl -u panel -n 50 看原因，修好后 systemctl start panel" ;;
esac

cat <<EOF

══════════════════════════════════════════════════════════════════
⚠ 重要：面板默认【只监听本机 127.0.0.1】，公网用「服务器IP:端口」连不上！
══════════════════════════════════════════════════════════════════

  这是刻意的安全默认值（面板以 root 运行、且本构建没有内置 HTTPS）。
  它和集中式面板不一样：这类面板默认直接绑 0.0.0.0 让你 IP:端口 就能进；
  ForkPanel 默认谁也进不来，需要你显式「开门」——避免把 root 面板裸奔到公网。

  1) 本机访问（最简单，推荐先这样验收）
       打开 http://127.0.0.1:$PORT
      （面板以 root 运行、无 HTTPS，绝不要把它直接绑到公网）

  2) 临时远程访问（SSH 端口转发，最安全）
        ssh -L $PORT:127.0.0.1:$PORT <user>@<server>
        然后在本机浏览器打开 http://127.0.0.1:$PORT

  3) 长期对外（别人也要访问）
        sudo panel expose -d 你的域名 -a 你的出口IP/32
      （脚本会做：nginx 反代终结 TLS + 防火墙白名单；面板本身仍只绑回环，
       不会把 root 面板裸奔到公网；用完撤销：sudo panel expose --uninstall）
      ⚠ 不给来源网段、或给 0.0.0.0/0，脚本会直接拒绝——那等于没有限制。

  你的公网 IP 大概是：$(curl -s --max-time 3 ifconfig.me 2>/dev/null || echo '（探测失败，自行用 curl ifconfig.me 查）')

  取出一次性引导令牌（首次启动且无 owner 时打印，30 分钟内有效）：
      journalctl -u panel -n 50 --no-pager

  备用路径（无浏览器/自动化场景）：
      panel --config $CONF_FILE init --owner admin      # 交互式；脚本里可用 --owner-pass
  忘记口令：
      panel --config $CONF_FILE passwd <user>

  卸载： ./deploy/uninstall.sh（保留数据与配置）
EOF
