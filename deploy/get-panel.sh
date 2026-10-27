#!/usr/bin/env bash
# ForkPanel 一键安装（分发版）：下载签名 tarball → 验签 → 解包 → 安装
#
# 用法（三选一）：
#   1) 官方一键脚本域名（规划中，尚未部署，请勿使用）：
#        curl -fsSL https://get.forkpanel.dev | sh
#   2) 已 clone 仓库 / 已有本脚本：
#        sudo bash deploy/get-panel.sh
#   3) 中国大陆网络（GitHub Release 资产 CDN 直连不稳，详见下方"网络问题"）：
#        https_proxy=http://<代理>:port sudo -E bash deploy/get-panel.sh
#        PANEL_RELEASE_BASE=https://<国内镜像基址>/... sudo -E bash deploy/get-panel.sh
#
# 安全设计：
#   - 仅支持 Linux（面板 OS 抽象层当前只有 Linux 实现；其他系统适配中）
#   - 按 uname -m 选 amd64 / arm64
#   - 用「内嵌 ed25519 公钥 + openssl」验证 tarball 签名；签不过立即中止，绝不运行未验文件
#   - 解包后执行 tarball 内的 install.sh（建目录 / 配置随机端口 / 系统单元 / 探活）
#
# 覆盖项：PANEL_RELEASE_BASE=... 切换下载源（国内镜像 / 自建源）；
#        PANEL_VERSION=... 指定版本（默认 latest）；--no-install 仅下载验签不解装。
#
# 网络问题（中国大陆用户最常见）：
#   脚本默认从 GitHub Releases 下载，资产实际落在 release-assets.githubusercontent.com
#   （Azure CDN），该域名在国内常直连超时或被重置，表现就是"一直下载不了安装文件"。
#   解决：① 走代理（https_proxy，注意用 sudo -E 透传环境变量）；
#        ② 把 PANEL_RELEASE_BASE 指到国内可达镜像；③ 手动下载后本地装（见下方失败提示）。
#
# 注意：下方 RELEASE_PUBKEY 即为发布私钥 /home/a/release.key 对应的 ed25519 公钥
#       （base64 已与 release.key 对齐，并非占位演示密钥）。若将来更换签名密钥，
#       须用新私钥重签，并用 `openssl pkey -in <新私钥> -pubout` 同步更新此处。
set -euo pipefail

# 默认分发源：GitHub Releases（latest = 最新非预发布）。
#   - 指定版本：releases/download/v<版本>/panel-linux-<arch>.tar.gz
#   - 最新稳定：releases/latest/download/panel-linux-<arch>.tar.gz（GitHub 自动 302 到最新）
# 想切到自建源（如 releases.forkpanel.dev）或国内镜像：
#   PANEL_RELEASE_BASE=https://... sudo -E bash get-panel.sh
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

# 稳健下载：重试 + 断点续传 + 长超时，扛住 GitHub CDN 的瞬时抖动。
#   curl：--retry 只在连接/超时/5xx 时重试（404 等硬错立即失败，交给我们给诊断）；
#         -C - 支持 Range 续传；--max-time 600 给慢速链路留足时间。
#   wget：-c 续传，--tries/--timeout 对应重试。
dl() {  # dl <url> <out>
  local url="$1" out="$2" rc=0
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 5 --retry-delay 2 \
          --connect-timeout 15 --max-time 600 -C - "$url" -o "$out" || rc=$?
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=5 --timeout=60 -c "$url" -O "$out" || rc=$?
  else
    echo "缺少 curl / wget，无法下载。" >&2; exit 1
  fi
  return $rc
}

# 下载失败的统一诊断：区分"版本/URL 错（404）"与"网络被墙/超时（连接失败）"
diagnose_fetch_fail() {
  local what="$1" url="$2"
  echo "$what 失败：$url" >&2
  echo "  常见原因与对策：" >&2
  echo "  1) 网络（中国大陆最常见）：GitHub Release 资产走 release-assets.githubusercontent.com，" >&2
  echo "     CDN 直连常超时/被重置。请走代理并以 sudo -E 透传环境变量：" >&2
  echo "       https_proxy=http://<代理>:port sudo -E bash get-panel.sh" >&2
  echo "  2) 改用国内可达镜像源：PANEL_RELEASE_BASE=https://<镜像基址>/... sudo -E bash get-panel.sh" >&2
  echo "  3) 手动下载后本地安装（绕过脚本下载）：" >&2
  echo "       在能访问 GitHub 的机器下载 panel-linux-$ARCH.tar.gz 与 .sig，" >&2
  echo "       scp 到本机后：tar xzf panel-linux-$ARCH.tar.gz && sudo sh ./install.sh ./panel" >&2
  echo "  4) 若提示 404：检查 PANEL_VERSION（默认 latest）或 PANEL_RELEASE_BASE 是否拼写错误。" >&2
  exit 1
}

echo "==> 下载 $URL"
dl "$URL" "$WORK/$TARBALL" || diagnose_fetch_fail "下载" "$URL"
dl "$SIGURL" "$WORK/$TARBALL.sig" || diagnose_fetch_fail "下载签名" "$SIGURL"

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
