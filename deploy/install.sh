#!/usr/bin/env bash
# ForkPanel 安装脚本：二进制 → 目录 → 默认配置 → systemd 单元
#
# 用法（需 root）：
#   ./deploy/install.sh [二进制路径]        # 缺省 ./target/release/panel
#
# 该脚本只做"安装"，不建账号。首个 owner 由 Web 首启向导创建：
# 启动服务后从日志取一次性引导令牌，在浏览器里完成初始化。
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

# 发行版端口随机分配 ≥10000，避免固定 2083 被扫描（参考宝塔面板）
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

[ "$(id -u)" -eq 0 ] || die "需要 root 权限（面板要管理系统服务/防火墙）"
[ -f "$BIN_SRC" ]   || die "找不到二进制：$BIN_SRC（先 cargo build --release，或显式传入路径）"
command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd（请用 --config 直接运行 serve，或自行接入进程管理器）"

install -m 0755 "$BIN_SRC" "$BIN_DST"
echo "· 二进制 → $BIN_DST"

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

# 外部探活：Restart=on-failure 只覆盖「进程死了」，不覆盖「活着但不服务」
# （事件循环卡死、监听 socket 丢失但主线程没退）。每分钟探一次 /api/v1/version，
# 连续两次失败才重启——给瞬时抖动留机会，避免误把好服务重启掉。
# 不需要可删掉这两行 + 执行 panel healthcheck --uninstall。
"$BIN_DST" --config "$CONF_FILE" healthcheck --install >/dev/null
systemctl daemon-reload
systemctl enable --now panel-healthcheck.timer >/dev/null
echo "· 外部探活已安装（每分钟一次，连续两次失败才重启）"

cat <<EOF

安装完成。下一步：

  1. 启动服务
       systemctl start panel

  2. 取出一次性引导令牌（首次启动且无 owner 时打印，30 分钟内有效）
       journalctl -u panel -n 50 --no-pager

  3. 打开面板并完成初始化
       本机： http://127.0.0.1:$PORT
       远程： ssh -L $PORT:127.0.0.1:$PORT <user>@<server>   然后访问 http://127.0.0.1:$PORT
       页面会自动显示"初始化面板"向导，填入令牌 + 账号 + 口令即可。

  备用路径（无浏览器/自动化场景）：
       panel --config $CONF_FILE init --owner admin      # 交互式；脚本里可用 --owner-pass
  忘记口令：
       panel --config $CONF_FILE passwd <user>

  卸载： ./deploy/uninstall.sh（保留数据与配置）
EOF
