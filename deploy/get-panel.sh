#!/usr/bin/env bash
# ForkPanel 一键安装（分发版）：下载签名 tarball → 验签 → 解包 → 安装
#
# 用法（小白复制这一行即可）：
#   curl -fsSL https://get.forkpanel.dev | sh
#
# 安全设计：
#   - 仅支持 Linux（面板 OS 抽象层当前只有 Linux 实现；其他系统适配中）
#   - 按 uname -m 选 amd64 / arm64
#   - 用「内嵌 ed25519 公钥 + openssl」验证 tarball 签名；签不过立即中止，绝不运行未验文件
#   - 解包后执行 tarball 内的 install.sh（建目录 / 配置随机端口 / 系统单元 / 探活）
#
# 覆盖项：PANEL_RELEASE_BASE=... 切换下载源；--no-install 仅下载验签不解装（调试 / 测试）
# 注意：下方 RELEASE_PUBKEY 为「演示公钥」。正式发版前请用您自己的 ed25519 私钥重签，
#       并替换此处公钥（否则任何人都能用演示私钥伪造签名）。
set -euo pipefail

# 默认分发源：GitHub Releases（latest = 最新非预发布）。
#   - 指定版本：releases/download/v<版本>/panel-linux-<arch>.tar.gz
#   - 最新稳定：releases/latest/download/panel-linux-<arch>.tar.gz（GitHub 自动 302 到最新）
# 想切到自建源（如 releases.forkpanel.dev）或镜像：PANEL_RELEASE_BASE=https://... ./get-panel.sh
PANEL_VERSION="${PANEL_VERSION:-latest}"
if [ "$PANEL_VERSION" = "latest" ]; then
  RELEASE_BASE="${PANEL_RELEASE_BASE:-https://github.com/crudguy/forkpanel-backend/releases/latest/download}"
else
  RELEASE_BASE="${PANEL_RELEASE_BASE:-https://github.com/crudguy/forkpanel-backend/releases/download/v$PANEL_VERSION}"
fi
RELEASE_PUBKEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcw1u+sjeBdzxlMwz88QBli5DCBTi705rQcIdIIPRKGU=
-----END PUBLIC KEY-----'

NO_INSTALL=0
for a in "$@"; do case "$a" in --no-install) NO_INSTALL=1;; esac; done

# 仅支持 Linux
case "$(uname -s)" in Linux) ;; *) echo "仅支持 Linux（其他系统适配中）" >&2; exit 1;; esac

# 架构识别
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "不支持的架构：$(uname -m)" >&2; exit 1 ;;
esac

# 需要 root
[ "$(id -u)" -eq 0 ] || { echo "需要 root 权限（面板要管理系统服务/防火墙）。请 sudo 或 root 执行。" >&2; exit 1; }

# openssl 必需（验签）；缺失则尝试装
if ! command -v openssl >/dev/null 2>&1; then
  echo "缺少 openssl（验签必需），尝试安装…" >&2
  if command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y openssl;
  elif command -v dnf >/dev/null 2>&1; then dnf install -y openssl;
  elif command -v apk >/dev/null 2>&1; then apk add openssl;
  elif command -v yum >/dev/null 2>&1; then yum install -y openssl;
  else echo "请先安装 openssl 再运行。" >&2; exit 1; fi
fi

TARBALL="panel-linux-$ARCH.tar.gz"
URL="$RELEASE_BASE/$TARBALL"
SIGURL="$RELEASE_BASE/$TARBALL.sig"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

dl() {  # dl <url> <out>
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2";
  elif command -v wget >/dev/null 2>&1; then wget -q "$1" -O "$2";
  else echo "缺少 curl / wget" >&2; exit 1; fi
}

echo "==> 下载 $URL"
dl "$URL" "$WORK/$TARBALL" || { echo "下载失败：$URL" >&2; exit 1; }
dl "$SIGURL" "$WORK/$TARBALL.sig" || { echo "下载签名失败：$SIGURL" >&2; exit 1; }

echo "==> 校验签名（内嵌公钥，openssl ed25519）"
printf '%s\n' "$RELEASE_PUBKEY" > "$WORK/pubkey.pem"
if ! openssl dgst -verify "$WORK/pubkey.pem" -signature "$WORK/$TARBALL.sig" "$WORK/$TARBALL" >/dev/null 2>&1; then
  echo "签名校验失败！tarball 可能被篡改或来源不可信，已中止（未执行任何文件）。" >&2
  exit 1
fi
echo "    签名 OK"

echo "==> 解包"
tar -C "$WORK" -xzf "$WORK/$TARBALL"

if [ "$NO_INSTALL" -eq 1 ]; then
  echo "（--no-install）已下载并验签；产物："
  echo "    $WORK/panel"
  echo "    $WORK/install.sh"
  echo "    $WORK/config.toml"
  exit 0
fi

echo "==> 安装（执行 tarball 内的 install.sh）"
( cd "$WORK" && sh ./install.sh ./panel )

echo "完成。面板已安装并启动；按 install.sh 输出里的随机端口与引导令牌完成初始化。"
