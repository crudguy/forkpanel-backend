#!/usr/bin/env bash
# ForkPanel 卸载脚本：停服务 → 移除单元 → 移除二进制
#
# ★ 数据与配置默认保留（账号、站点、审计、备份都在里面）。
#   确认无需保留后再自行删除：
#     rm -rf /var/lib/forkpanel /etc/forkpanel /var/log/forkpanel
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "uninstall: 需要 root 权限" >&2; exit 1; }

systemctl stop panel 2>/dev/null || true
systemctl disable panel 2>/dev/null || true
rm -f /etc/systemd/system/panel.service
systemctl daemon-reload 2>/dev/null || true
echo "· 服务已停止，systemd 单元已移除"

rm -f /usr/local/bin/panel
echo "· 二进制已移除"

# 公网暴露脚本（panel expose 调用，面板仍绑回环）
EXPOSE=/usr/local/share/forkpanel/expose-public.sh
if [ -f "$EXPOSE" ]; then
  rm -f "$EXPOSE"
  rmdir /usr/local/share/forkpanel 2>/dev/null || true
  echo "· 公网暴露脚本已移除"
fi

cat <<'EOF'

已卸载。以下目录被保留（含账号与数据，未自动删除）：
  /var/lib/forkpanel    数据库、主密钥、备份
  /etc/forkpanel        配置
  /var/log/forkpanel    日志
  /var/www              站点根目录

确认不再需要后自行删除：
  rm -rf /var/lib/forkpanel /etc/forkpanel /var/log/forkpanel
EOF
