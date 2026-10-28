#!/usr/bin/env bash
# ForkPanel 镜像同步工具：从官方 Release（或 PANEL_RELEASE_BASE）拉取签名 tarball → 先验签 → 落本地 / 推 rclone。
#
# 安全：只镜像"验签通过的真货"。验签失败（被篡改 / 来源不可信）立即中止，绝不写入任何文件，
#       从源头杜绝镜像被投毒后客户端又放行。客户端 get-panel.sh 仍会二次验签，双重保险。
#
# 用法：
#   ./deploy/mirror-sync.sh                                  # 同步 latest（amd64 + arm64）
#   ./deploy/mirror-sync.sh --version v0.1.0                 # 同步指定版本
#   ./deploy/mirror-sync.sh --dest /srv/mirror               # 落到本地目录（默认 ./mirror）
#   ./deploy/mirror-sync.sh --rclone myremote:/forkpanel     # 同时推到 rclone remote
#   ./deploy/mirror-sync.sh --public-base https://mirror.example.com/forkpanel
#                                                              # 打印客户端该填的 PANEL_MIRRORS
#
# 产出布局（dest 根下）：
#   latest/panel-linux-{amd64,arm64}.tar.gz(.sig)
#   <tag>/panel-linux-{amd64,arm64}.tar.gz(.sig)               （指定版本时）
# 客户端 PANEL_MIRRORS 基址 = <public-base>/latest  或  <public-base>/<tag>
set -euo pipefail

VERSION="latest"
DEST="./mirror"
RCLONE=""
PUBLIC_BASE=""
PUBKEY_FILE=""

need_val() {  # need_val <flag> <value>
  [ -n "$2" ] || { echo "选项 $1 需要一个值" >&2; exit 1; }
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)      need_val "$1" "${2:-}"; VERSION="$2"; shift 2 ;;
    --dest)         need_val "$1" "${2:-}"; DEST="$2"; shift 2 ;;
    --rclone)       need_val "$1" "${2:-}"; RCLONE="$2"; shift 2 ;;
    --public-base)  need_val "$1" "${2:-}"; PUBLIC_BASE="$2"; shift 2 ;;
    --pubkey)       need_val "$1" "${2:-}"; PUBKEY_FILE="$2"; shift 2 ;;
    -h|--help)      sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "未知参数：$1（用 -h 看用法）" >&2; exit 1 ;;
  esac
done

# 源基址（与 get-panel.sh 保持一致）
if [ "$VERSION" = "latest" ]; then
  SRC_BASE="${PANEL_RELEASE_BASE:-https://github.com/crudguy/forkpanel-backend/releases/latest/download}"
else
  SRC_BASE="${PANEL_RELEASE_BASE:-https://github.com/crudguy/forkpanel-backend/releases/download/$VERSION}"
fi

# 验签公钥：优先 --pubkey，否则内嵌发布公钥（与 get-panel.sh 同一把）
if [ -n "$PUBKEY_FILE" ]; then
  [ -f "$PUBKEY_FILE" ] || { echo "公钥文件不存在：$PUBKEY_FILE" >&2; exit 1; }
  USE_PUBKEY="$PUBKEY_FILE"
else
  USE_PUBKEY="$(mktemp)"; TMP_PUBKEY="$USE_PUBKEY"
  cat > "$USE_PUBKEY" <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcw1u+sjeBdzxlMwz88QBli5DCBTi705rQcIdIIPRKGU=
-----END PUBLIC KEY-----
EOF
fi

command -v openssl >/dev/null 2>&1 || { echo "缺少 openssl（验签必需）" >&2; exit 1; }

WORK="$(mktemp -d)"
if [ -n "${TMP_PUBKEY:-}" ]; then
  trap 'rm -rf "$WORK" "$TMP_PUBKEY"' EXIT
else
  trap 'rm -rf "$WORK"' EXIT
fi

# 稳健下载（与 get-panel.sh 同款预算 normal）
dl() {  # dl <url> <out>
  local url="$1" out="$2" rc=0
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 5 --retry-delay 2 --connect-timeout 15 --max-time 600 -C - "$url" -o "$out" || rc=$?
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=5 --timeout=60 -c "$url" -O "$out" || rc=$?
  else
    echo "缺少 curl / wget，无法下载。" >&2; exit 1
  fi
  return $rc
}

echo "==> 同步版本：$VERSION （源：$SRC_BASE）"

# 阶段1：下载并验签全部架构（任一失败则整体中止，不落盘）
for arch in amd64 arm64; do
  tb="panel-linux-$arch.tar.gz"
  dl "$SRC_BASE/$tb" "$WORK/$tb" || { echo "下载失败：$SRC_BASE/$tb" >&2; exit 1; }
  dl "$SRC_BASE/$tb.sig" "$WORK/$tb.sig" || { echo "下载签名失败：$SRC_BASE/$tb.sig" >&2; exit 1; }
  if ! openssl dgst -verify "$USE_PUBKEY" -signature "$WORK/$tb.sig" "$WORK/$tb" >/dev/null 2>&1; then
    echo "签名校验失败，拒绝镜像（未写入任何文件）：$tb" >&2; exit 1
  fi
  echo "    验签 OK：$tb"
done

# 阶段2：落盘（latest 写 latest/，指定版本写 <tag>/）
if [ "$VERSION" = "latest" ]; then SUB="$DEST/latest"; else SUB="$DEST/$VERSION"; fi
mkdir -p "$SUB"
for arch in amd64 arm64; do
  tb="panel-linux-$arch.tar.gz"
  cp -a "$WORK/$tb" "$SUB/$tb"
  cp -a "$WORK/$tb.sig" "$SUB/$tb.sig"
done
echo "已镜像到：$SUB/"

# 可选：推送到 rclone remote
if [ -n "$RCLONE" ]; then
  command -v rclone >/dev/null 2>&1 || { echo "未安装 rclone，无法推送 $RCLONE" >&2; exit 1; }
  if [ "$VERSION" = "latest" ]; then RSUB="$RCLONE/latest"; else RSUB="$RCLONE/$VERSION"; fi
  rclone copy "$SUB" "$RSUB"
  echo "已推送到：$RSUB"
fi

# 打印客户端该填的 PANEL_MIRRORS 基址
base="${PUBLIC_BASE%/}"
if [ -n "$PUBLIC_BASE" ]; then
  if [ "$VERSION" = "latest" ]; then
    echo "客户端可用：PANEL_MIRRORS=$base/latest"
  else
    echo "客户端可用：PANEL_MIRRORS=$base/$VERSION"
  fi
else
  echo "提示：把上面这份目录通过 Web 服务器 / rclone 对外暴露后，客户端设"
  echo "      PANEL_MIRRORS=<对外基址>/latest （latest 模式）或 <对外基址>/$VERSION （指定版本）。"
fi
