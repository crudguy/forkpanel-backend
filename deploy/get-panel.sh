#!/usr/bin/env bash
# ForkPanel 一键安装（分发版）：下载签名 tarball → 验签 → 解包 → 安装
#
# 用法（三选一）：
#   1) 官方一键脚本域名（规划中，尚未部署，请勿使用）：
#        curl -fsSL https://get.forkpanel.dev | sh
#   2) 已 clone 仓库 / 已有本脚本：
#        sudo bash deploy/get-panel.sh
#   3) 中国大陆网络（GitHub Release 资产 CDN 直连不稳）：
#        https_proxy=http://<代理>:port sudo -E bash deploy/get-panel.sh
#
# 下载源（按序回退，见下方"多源回退"）：
#   - PANEL_RELEASE_BASE：钉死单源（自建源 / 指定镜像），设置后不再回退到其它源。
#   - PANEL_MIRRORS：逗号分隔的备用源（通常是国内可达镜像），逐个尝试，死源快速跳过。
#   - 兜底：官方 GitHub Releases（latest 自动 302 到最新非预发布）。
#   镜像源同样走验签，不会被"投毒"放行（见下方"安全设计"）。
#
# 覆盖项：
#   PANEL_VERSION=...      指定版本（默认 latest）
#   PANEL_RELEASE_BASE=... 钉死单一下载源（国内镜像 / 自建源），不再回退
#   PANEL_MIRRORS=...      逗号分隔的备用源基址，按顺序回退
#   PANEL_PUBKEY_FILE=...  用外部公钥文件覆盖内嵌公钥（密钥轮换 / E2E 自签测试）
#   --no-install           仅下载验签不解装
#
# 安全设计：
#   - 仅支持 Linux（面板 OS 抽象层当前只有 Linux 实现；其他系统适配中）
#   - 按 uname -m 选 amd64 / arm64
#   - 用「内嵌（或外部）ed25519 公钥 + openssl」验证 tarball 签名；签不过立即中止，绝不运行未验文件。
#     不论 tarball 来自 GitHub 还是任何镜像，都必须通过同一把公钥验签，镜像被污染也不会被放行。
#   - 解包后执行 tarball 内的 install.sh（建目录 / 配置随机端口 / 系统单元 / 探活）
#
# 多源回退：
#   默认顺序为 PANEL_RELEASE_BASE（若设置）→ PANEL_MIRRORS（若设置）→ 官方 GitHub。
#   每个"源"是一个目录基址，脚本在其后拼接 /panel-linux-<arch>.tar.gz 与 .sig。
#   镜像链（PANEL_MIRRORS 各项）用更紧的下载预算（连接 8s / 上限 120s / 重试 2）快速跳过死源；
#   钉死源与 GitHub 兜底用原韧性参数（连接 15s / 上限 600s / 重试 5）。
#   mirror-sync.sh 会把可用的源基址直接打印出来，粘进 PANEL_MIRRORS 即可。
#
# 网络问题（中国大陆用户最常见）：
#   脚本默认从 GitHub Releases 下载，资产实际落在 release-assets.githubusercontent.com
#   （Azure CDN），该域名在国内常直连超时或被重置，表现就是"一直下载不了安装文件"。
#   解决：① 走代理（https_proxy，注意用 sudo -E 透传环境变量）；
#        ② 把 PANEL_MIRRORS / PANEL_RELEASE_BASE 指到国内可达镜像；
#        ③ 手动下载后本地装（见下方失败提示）。
#
# 注意：下方 RELEASE_PUBKEY 即为发布私钥 /home/a/release.key 对应的 ed25519 公钥
#       （base64 已与 release.key 对齐，并非占位演示密钥）。若将来更换签名密钥，
#       须用新私钥重签，并用 `openssl pkey -in <新私钥> -pubout` 同步更新此处（或改用 PANEL_PUBKEY_FILE）。
set -euo pipefail

# 目标版本
PANEL_VERSION="${PANEL_VERSION:-latest}"

# 参数解析（--no-install 仅下载验签不解装）
NO_INSTALL=0
for a in "$@"; do case "$a" in --no-install) NO_INSTALL=1;; esac; done

# 官方 GitHub 兜底源（latest = 最新非预发布；指定版本走 releases/download/v<版本>）。
if [ "$PANEL_VERSION" = "latest" ]; then
  GITHUB_BASE="https://github.com/crudguy/forkpanel-backend/releases/latest/download"
else
  GITHUB_BASE="https://github.com/crudguy/forkpanel-backend/releases/download/v$PANEL_VERSION"
fi

# 候选下载源（按序回退）。
#   - 显式 PANEL_RELEASE_BASE：用户钉死单源，不再回退（避免"自以为切了源其实被兜底覆盖"）。
#   - 否则 PANEL_MIRRORS（逗号分隔）+ 官方 GitHub 兜底。
sources=()
pinned=0
if [ -n "${PANEL_RELEASE_BASE:-}" ]; then
  sources=("$PANEL_RELEASE_BASE")
  pinned=1
else
  IFS=',' read -ra mirrors <<< "${PANEL_MIRRORS:-}"
  for m in "${mirrors[@]}"; do
    m="${m// /}"              # 去掉镜像基址里的空格（URL 不应含空格）
    [ -n "$m" ] && sources+=("$m")
  done
  sources+=("$GITHUB_BASE")   # 兜底
fi

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

# 稳健下载：重试 + 断点续传 + 长超时，扛住 GitHub CDN 的瞬时抖动。
#   budget=tight：连接 8s / 上限 120s / 重试 2（镜像链快速跳过死源）
#   budget=normal：连接 15s / 上限 600s / 重试 5（钉死源 / GitHub 兜底的原韧性参数）
#   curl：--retry 只在连接/超时/5xx 时重试（404 等硬错立即失败，交给上层诊断）；
#         -C - 支持 Range 续传。
#   wget：-c 续传，--timeout 对应连接+读取超时。
dl() {  # dl <url> <out> <budget: tight|normal>
  local url="$1" out="$2" budget="${3:-normal}" rc=0
  local cto=15 max=600 retries=5
  if [ "$budget" = "tight" ]; then cto=8; max=120; retries=2; fi
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry "$retries" --retry-delay 2 \
          --connect-timeout "$cto" --max-time "$max" -C - "$url" -o "$out" || rc=$?
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries="$retries" --timeout="$cto" -c "$url" -O "$out" || rc=$?
  else
    echo "缺少 curl / wget，无法下载。" >&2; exit 1
  fi
  return $rc
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 验签公钥：优先 PANEL_PUBKEY_FILE（密钥轮换 / E2E 自签测试），否则内嵌。
if [ -n "${PANEL_PUBKEY_FILE:-}" ]; then
  [ -f "$PANEL_PUBKEY_FILE" ] || { echo "PANEL_PUBKEY_FILE 指向的文件不存在：$PANEL_PUBKEY_FILE" >&2; exit 1; }
  PUBKEY_FILE="$PANEL_PUBKEY_FILE"
  echo "==> 使用外部公钥：$PUBKEY_FILE"
else
  RELEASE_PUBKEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcw1u+sjeBdzxlMwz88QBli5DCBTi705rQcIdIIPRKGU=
-----END PUBLIC KEY-----'
  printf '%s\n' "$RELEASE_PUBKEY" > "$WORK/pubkey.pem"
  PUBKEY_FILE="$WORK/pubkey.pem"
fi

# 下载失败的统一诊断：列出所有候选源 + 区分网络/404 对策
diagnose_fetch_fail() {
  echo "所有候选下载源均失败。按尝试顺序：" >&2
  for s in "${sources[@]}"; do echo "  - ${s%/}/$TARBALL" >&2; done
  echo "  常见原因与对策：" >&2
  echo "  1) 网络（中国大陆最常见）：GitHub Release 资产走 release-assets.githubusercontent.com，" >&2
  echo "     CDN 直连常超时/被重置。请走代理并以 sudo -E 透传环境变量：" >&2
  echo "       https_proxy=http://<代理>:port sudo -E bash get-panel.sh" >&2
  echo "  2) 若已设 PANEL_MIRRORS / PANEL_RELEASE_BASE 仍失败，确认镜像基址可达且含 $TARBALL 与 .sig；" >&2
  echo "  3) 手动下载后本地安装（绕过脚本下载）：" >&2
  echo "       在能访问 GitHub 的机器下载 panel-linux-$ARCH.tar.gz 与 .sig，" >&2
  echo "       scp 到本机后：tar xzf panel-linux-$ARCH.tar.gz && sudo sh ./install.sh ./panel" >&2
  echo "  4) 若脚本打印具体源的 404：检查 PANEL_VERSION（默认 latest）或源基址是否拼写错误。" >&2
  exit 1
}

# 按序尝试每个源；tarball 与签名都下载成功才算该源可用。
TARBALL_OK=0
for i in "${!sources[@]}"; do
  base="${sources[$i]}"
  base="${base%/}"                       # 去掉尾部斜杠，避免 //
  url="$base/$TARBALL"
  sigurl="$base/$TARBALL.sig"
  # 预算：钉死源 / GitHub 兜底用 normal；镜像链用 tight 快速跳过死源。
  if [ "$pinned" -eq 1 ] || [ "$i" -eq $(( ${#sources[@]} - 1 )) ]; then
    budget=normal
  else
    budget=tight
  fi
  echo "==> [源 $((i+1))/${#sources[@]}] $base （预算：$budget）"
  if dl "$url" "$WORK/$TARBALL" "$budget" && dl "$sigurl" "$WORK/$TARBALL.sig" "$budget"; then
    TARBALL_OK=1
    echo "    已选用该源"
    break
  fi
  echo "    该源不可用，尝试下一个…" >&2
  # 清理可能残存的半成品，避免拿到部分文件误判
  rm -f "$WORK/$TARBALL" "$WORK/$TARBALL.sig"
done

[ "$TARBALL_OK" -eq 1 ] || diagnose_fetch_fail

echo "==> 校验签名（openssl ed25519，公钥：$PUBKEY_FILE）"
if ! openssl dgst -verify "$PUBKEY_FILE" -signature "$WORK/$TARBALL.sig" "$WORK/$TARBALL" >/dev/null 2>&1; then
  echo "签名校验失败！tarball 可能被篡改或来源不可信，已中止（未执行任何文件）。" >&2
  exit 1
fi
echo "    签名 OK"

echo "==> 解包"
tar -C "$WORK" -xzf "$WORK/$TARBALL"

if [ "${NO_INSTALL:-0}" -eq 1 ]; then
  echo "（--no-install）已下载并验签；产物："
  echo "    $WORK/panel"
  echo "    $WORK/install.sh"
  echo "    $WORK/config.toml"
  exit 0
fi

echo "==> 安装（执行 tarball 内的 install.sh）"
( cd "$WORK" && sh ./install.sh ./panel )

echo "完成。面板已安装（并已尝试自动启动，实际状态见上面 install.sh 打出的『服务状态』行）；按其中的随机端口与引导令牌完成初始化。"
