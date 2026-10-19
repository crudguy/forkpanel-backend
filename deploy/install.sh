#!/usr/bin/env bash
# ForkPanel 安装脚本：二进制 → 目录 → 默认配置 → systemd 单元
#
# 用法（需 root）：
#   ./deploy/install.sh [二进制路径]        # 缺省 ./target/release/panel
#
# 该脚本只做"安装"，不建账号。首个 owner 由 Web 首启向导创建：
# 启动服务后从日志取一次性引导令牌，在浏览器里完成初始化。
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
else
  install -m 0640 "$(dirname "$0")/config.toml" "$CONF_FILE"
  echo "· 默认配置 → $CONF_FILE"
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
       本机： http://127.0.0.1:2083
       远程： ssh -L 2083:127.0.0.1:2083 <user>@<server>   然后访问 http://127.0.0.1:2083
       页面会自动显示"初始化面板"向导，填入令牌 + 账号 + 口令即可。

  备用路径（无浏览器/自动化场景）：
       panel --config $CONF_FILE init --owner admin      # 交互式；脚本里可用 --owner-pass
  忘记口令：
       panel --config $CONF_FILE passwd <user>

  卸载： ./deploy/uninstall.sh（保留数据与配置）
EOF
