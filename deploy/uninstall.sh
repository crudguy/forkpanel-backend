#!/usr/bin/env bash
# ForkPanel 卸载（源码树 / 兼容入口）
#
# 真正的实现在已安装二进制的 `panel uninstall` 里（单一事实源）：它清 panel.service、
# 探活 service/timer、探活脚本、panel/forkpanel/fp 三个命令入口与公网暴露脚本，
# **保留数据与配置**。本脚本只是源码树里的入口，避免两处清单漂移。
#
# 推荐用法：sudo panel uninstall
# 本脚本：  sudo ./deploy/uninstall.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "uninstall: 需要 root 权限" >&2; exit 1; }

BIN=/usr/local/bin/panel
if [ -x "$BIN" ]; then
  cfg="${FORKPANEL_CONFIG:-/etc/forkpanel/config.toml}"
  if [ -f "$cfg" ]; then
    exec "$BIN" --config "$cfg" uninstall
  fi
  exec "$BIN" uninstall
fi

# ── 兜底：二进制已不在（半装 / 被手动删）时按同一份清单做最小清除 ──────────
# 注意仍**不删** /var/lib、/etc、/var/log 与 /var/www：账号、数据、配置、
# 站点文件都可能还要保留。
systemctl disable --now panel-healthcheck.timer 2>/dev/null || true
systemctl stop panel 2>/dev/null || true
systemctl disable panel 2>/dev/null || true
rm -f /etc/systemd/system/panel.service \
      /etc/systemd/system/panel-healthcheck.service \
      /etc/systemd/system/panel-healthcheck.timer
rm -f /var/lib/forkpanel/scripts/healthcheck.sh
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/bin/panel /usr/local/bin/forkpanel /usr/local/bin/fp
rm -f /usr/local/share/forkpanel/expose-public.sh
rmdir /usr/local/share/forkpanel 2>/dev/null || true

cat <<'EOF'

已卸载 ForkPanel（二进制不存在，已按清单做兜底清除）。
以下目录被保留（含账号与数据，未自动删除）：
  /var/lib/forkpanel    数据库、主密钥、备份
  /etc/forkpanel        配置
  /var/log/forkpanel    日志
  /var/www              站点根目录

确认不再需要后自行删除：
  rm -rf /var/lib/forkpanel /etc/forkpanel /var/log/forkpanel
EOF
