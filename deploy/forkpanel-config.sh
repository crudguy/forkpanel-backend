#!/usr/bin/env bash
# ForkPanel 交互式配置入口（安装为 /usr/local/bin/forkpanel，并创建短别名 fp）
#
# 为什么需要它：端口、监听地址、口令、暴露/升级/卸载散落在 config.toml 与一堆
# 子命令里，新用户记不住；`panel` 本身又是纯子命令式（裸跑只会打印帮助）。
# 这里提供一个「进去就能改」的菜单，同时保留非交互开关，便于脚本与 E2E 验证：
#
#   forkpanel                     # 交互菜单（需要 TTY）
#   forkpanel --status            # 只打印当前状态（不需要 root）
#   forkpanel --set-port 12083    # 改端口（需要 root）
#   forkpanel --set-bind 127.0.0.1
#   forkpanel --set-bind 0.0.0.0 --yes   # 非回环必须显式 --yes
#
# 所有写操作只改 config.toml 的 [server] 段，然后按需重启服务；数据与站点不动。
set -euo pipefail

CONF="${FORKPANEL_CONFIG:-/etc/forkpanel/config.toml}"
BIN="${FORKPANEL_BIN:-/usr/local/bin/panel}"
ACTION=""
NEW_PORT=""
NEW_BIND=""
ASSUME_YES=0
NO_RESTART=0

usage() {
  cat <<'EOF'
用法：forkpanel [选项]

  （无参数）              进入交互式配置菜单（需要 TTY）
  --status                打印配置、服务与安装路径
  --set-port N            修改监听端口（1-65535）
  --set-bind ADDR         修改监听地址；非回环地址需加 --yes
  --config PATH           指定 config.toml（默认 /etc/forkpanel/config.toml）
  --no-restart            写完配置不重启服务
  -y, --yes               跳过「非回环地址」的二次确认
  -h, --help              显示本帮助

改端口/地址需要 root；--status 不需要。
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --config)     CONF="${2:?--config 需要路径}"; shift 2 ;;
    --status)     ACTION=status; shift ;;
    --set-port)   ACTION=port; NEW_PORT="${2:?--set-port 需要端口}"; shift 2 ;;
    --set-bind)   ACTION=bind; NEW_BIND="${2:?--set-bind 需要地址}"; shift 2 ;;
    --no-restart) NO_RESTART=1; shift ;;
    -y|--yes)     ASSUME_YES=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "forkpanel: 未知参数 $1" >&2; usage >&2; exit 2 ;;
  esac
done

is_root() { [ "$(id -u)" -eq 0 ]; }
need_root() { is_root || { echo "需要 root：请用 sudo forkpanel" >&2; exit 1; }; }

# 取某个段里的键值（去掉引号与空白）；默认 [server]，可传第二参数指定段名。
get_kv() {
  local key="$1" sec="${2:-server}"
  [ -f "$CONF" ] || return 1
  awk -v k="$key" -v sec="$sec" '
    $0 == "[" sec "]" {s=1; next}
    /^\[/{s=0}
    s && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
      sub(/^[^=]*=[[:space:]]*/, ""); gsub(/["[:space:]]/, ""); print; exit
    }
  ' "$CONF"
}

# 只替换 [server] 段里的键，保留注释与其它段；写回用 cat 保持 inode/权限不变。
set_kv() {
  local key="$1" val="$2" tmp
  tmp=$(mktemp) || { echo "无法创建临时文件" >&2; return 1; }
  if ! awk -v k="$key" -v v="$val" '
      /^\[server\]/{s=1; print; next}
      /^\[/{s=0}
      s && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { print k " = " v; done=1; next }
      { print }
      END{ if (!done) exit 3 }
    ' "$CONF" > "$tmp"; then
    rm -f "$tmp"
    echo "写入失败：$CONF 的 [server] 段缺少 $key" >&2
    return 1
  fi
  cat "$tmp" > "$CONF"
  rm -f "$tmp"
}

svc_state() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet panel 2>/dev/null; then
    echo "active"
  else
    echo "inactive / 未安装"
  fi
}

restart_svc() {
  [ "$NO_RESTART" -eq 1 ] && { echo "· 已跳过重启（--no-restart）"; return 0; }
  if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet panel 2>/dev/null; then
    if systemctl restart panel 2>/dev/null; then
      echo "· 已重启 panel（端口 $(get_kv port)）"
    else
      echo "· ⚠ 重启失败：journalctl -u panel -n 50 --no-pager" >&2
    fi
  else
    echo "· 未检测到 panel 的 systemd 单元，改动将在下次启动生效"
  fi
}

show_status() {
  echo "ForkPanel 状态"
  echo "  配置文件   $CONF"
  if [ ! -f "$CONF" ]; then
    echo "  （配置文件不存在：面板可能尚未安装）"
    return 0
  fi
  echo "  监听       $(get_kv bind 2>/dev/null || echo '?'):$(get_kv port 2>/dev/null || echo '?')"
  echo "  仅本机     $(get_kv localhost_only 2>/dev/null || echo '?')  （true 时覆盖 bind）"
  echo "  服务       $(svc_state)"
  if [ -x "$BIN" ]; then
    echo "  版本       $("$BIN" --version 2>/dev/null || echo '未知')"
  else
    echo "  二进制     $BIN（不存在）"
  fi
  echo "  数据目录   $(get_kv data paths 2>/dev/null || echo '?')"
}

set_port() {
  need_root
  local p="$1"
  case "$p" in ''|*[!0-9]*) echo "端口必须是数字：$p" >&2; return 1 ;; esac
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "端口超出范围 1-65535：$p" >&2; return 1
  fi
  [ -f "$CONF" ] || { echo "找不到配置文件 $CONF" >&2; return 1; }
  set_kv port "$p"
  echo "· 端口已改为 $p"
  restart_svc
}

set_bind() {
  need_root
  local b="$1"
  [ -f "$CONF" ] || { echo "找不到配置文件 $CONF" >&2; return 1; }
  case "$b" in
    127.0.0.1|::1)
      set_kv bind "\"$b\""
      set_kv localhost_only true
      echo "· 监听地址已改为 $b（localhost_only=true）"
      ;;
    *)
      if [ "$ASSUME_YES" -ne 1 ]; then
        cat >&2 <<EOF
拒绝直接改到非回环地址：$b
  面板以 root 运行且本构建无内置 HTTPS，直接绑出去等于把 root 面板暴露到网络。
  确需公网访问，优先用：sudo panel expose -d <域名> -a <出口IP>/32
  仍要直接改，请显式加 --yes（会同时设置 localhost_only=false，否则 bind 不生效）。
EOF
        return 2
      fi
      set_kv bind "\"$b\""
      set_kv localhost_only false
      echo "· 监听地址已改为 $b，并设置 localhost_only=false"
      echo "  ⚠ 已把 root 面板暴露到网络；强烈建议改用 panel expose 接 TLS。"
      ;;
  esac
  restart_svc
}

do_uninstall() {
  need_root
  echo "⚠ 将停止服务、删除程序与 systemd 单元；数据与配置保留。"
  if [ "$ASSUME_YES" -ne 1 ]; then
    printf "输入 uninstall 确认："
    read -r ok || return 1
    [ "$ok" = "uninstall" ] || { echo "已取消"; return 0; }
  fi
  if [ ! -x "$BIN" ]; then
    echo "找不到 $BIN；若已半装，请用源码树里的 deploy/uninstall.sh 兜底" >&2
    return 1
  fi
  "$BIN" uninstall
}

expose_help() {
  cat <<'EOF'
公网暴露（脚本做 nginx 反代 + 防火墙白名单，面板本身仍只绑回环）：
  sudo panel expose -d <域名> -a <出口IP>/32
撤销：
  sudo panel expose --uninstall
EOF
}

upgrade_help() {
  cat <<'EOF'
升级（下载签名二进制 → 验签 → 替换并重启；配置与数据保留）：
  wget -O get-panel.sh https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh
  sudo sh get-panel.sh
注：PANEL_VERSION 不带 v 前缀（脚本自己拼 /v<版本>）。
EOF
}

menu() {
  while true; do
    echo
    echo "==== ForkPanel 配置 ===="
    echo "  1) 查看状态"
    echo "  2) 修改监听端口"
    echo "  3) 修改监听地址（含公网风险确认）"
    echo "  4) 重置用户口令"
    echo "  5) 公网暴露（引导命令）"
    echo "  6) 升级面板"
    echo "  7) 卸载面板"
    echo "  8) 查看全部命令"
    echo "  0) 退出"
    printf "选择 [0-8]："
    read -r choice || exit 0
    case "$choice" in
      1) show_status ;;
      2) printf "新端口 [1-65535]："; read -r p || continue
         set_port "$p" || true ;;
      3) echo "当前：$(get_kv bind 2>/dev/null || echo '?')"
         echo "  1) 127.0.0.1（推荐：仅本机）"
         echo "  2) 自定义地址"
         printf "选择 [1-2]："; read -r c || continue
         case "$c" in
           1) set_bind 127.0.0.1 || true ;;
           2) printf "地址："; read -r b || continue
              set_bind "$b" || true ;;
           *) echo "无效选择" ;;
         esac ;;
      4) printf "用户名："; read -r u || continue
         if [ -x "$BIN" ] && [ -f "$CONF" ]; then
           "$BIN" --config "$CONF" passwd "$u" || true
         else
           echo "找不到二进制或配置，无法改口令" >&2
         fi ;;
      5) expose_help ;;
      6) upgrade_help ;;
      7) do_uninstall || true ;;
      8) if [ -x "$BIN" ]; then "$BIN" --help; else echo "找不到 $BIN" >&2; fi ;;
      0|q|Q) exit 0 ;;
      *) echo "无效选择：$choice" ;;
    esac
  done
}

case "$ACTION" in
  status) show_status ;;
  port)   set_port "$NEW_PORT" ;;
  bind)   set_bind "$NEW_BIND" ;;
  "")
    if [ ! -t 0 ]; then
      echo "forkpanel: 非交互环境请用 --status / --set-port / --set-bind" >&2
      usage >&2
      exit 2
    fi
    menu
    ;;
esac
