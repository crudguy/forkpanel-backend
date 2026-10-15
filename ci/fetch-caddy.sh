#!/usr/bin/env bash
# 取并安装 caddy 二进制，让"真机 caddy"那几条测试真的跑起来，而不是静默跳过。
#
# 为什么需要：panel-os 里有两类 caddy 断言只在**真机有 caddy**时才执行——
#   · caddy_waf_rendered_config_passes_real_caddy_validate（渲染产物过 `caddy validate`）
#   · caddy_validate_roundtrip_when_caddy_present（provider 层 `validate()` 真 fork）
# 没装 caddy 时它们会打印 [skip] 后跳过——**跳过不是通过**。CI 想覆盖 caddy
# 渲染/校验链路，就得先把二进制弄到手。
#
# ⚠ 装到哪：`panel_os::cmd::Bin::Caddy` **不看 PATH**，只认固定搜索目录
#   /usr/sbin /sbin /usr/bin /bin /usr/local/sbin /usr/local/bin（与 cmd.rs 解析目录一致）。
#   所以必须落到其中之一，否则测试依旧跳过——本脚本默认装到 /usr/local/bin。
#
# 用法：
#   sudo ./ci/fetch-caddy.sh && cargo test -p panel-os --lib
#   CADDY_INSTALL_DIR=$HOME/.local/bin ./ci/fetch-caddy.sh   # 无 root 时（需在搜索目录内）
#
# 幂等：目标已存在且 `caddy version` 跑得通就直接复用，不重复下载。
set -euo pipefail

VER="${CADDY_VERSION:-2.11.7}"
DEST_DIR="${CADDY_INSTALL_DIR:-/usr/local/bin}"
DEST="$DEST_DIR/caddy"
CACHE_DIR="${CADDY_OUT_DIR:-$(cd "$(dirname "$0")/.." && pwd)/target/caddy}"

have_caddy() { [[ -x "$1" ]] && "$1" version >/dev/null 2>&1; }

# ① 已在搜索目录里 —— 直接复用
for d in /usr/sbin /sbin /usr/bin /bin /usr/local/sbin /usr/local/bin; do
  if have_caddy "$d/caddy"; then
    echo "fetch-caddy: 已存在 $d/caddy（$("$d/caddy" version | head -1)）" >&2
    echo "$d/caddy"; exit 0
  fi
done

OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "fetch-caddy: 不支持的系统 $OS（请自装 caddy 到搜索目录后重试）" >&2; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "fetch-caddy: 不支持的架构 $ARCH（请自装 caddy 到搜索目录后重试）" >&2; exit 1 ;;
esac

TARBALL="caddy_${VER}_${os}_${arch}.tar.gz"
# GitHub 直连在部分网络下会被限速（本机实测 ~20KB/s，一个包要十几分钟）。
# 允许换源覆盖：CADDY_URL=https://<镜像>/caddy_2.11.7_linux_amd64.tar.gz
URL="${CADDY_URL:-https://github.com/caddyserver/caddy/releases/download/v${VER}/${TARBALL}}"

mkdir -p "$CACHE_DIR"
STAGE="$CACHE_DIR/caddy.stage"
TARBALL_PATH="$CACHE_DIR/$TARBALL"
PART="$TARBALL_PATH.part"

if [[ ! -f "$TARBALL_PATH" ]]; then
  echo "fetch-caddy: 下载 $URL" >&2
  # ⚠ 必须下到 `.part` 再改名：直接写到目标路径时，**中断留下的半成品会被下一轮
  # 当成"已下载"直接复用**，于是 `tar` 解压失败且报错与真实原因（网络中断）无关。
  # 失败即报错退出——**不静默降级**（静默降级会让 CI 以为覆盖到了 caddy，实际又变回跳过）。
  curl -fL --retry 5 --retry-delay 3 --retry-all-errors -C - -o "$PART" "$URL"
  mv -f "$PART" "$TARBALL_PATH"
fi

tar -xzf "$TARBALL_PATH" -C "$CACHE_DIR" caddy
rm -f "$STAGE"; mv -f "$CACHE_DIR/caddy" "$STAGE"
chmod +x "$STAGE"

if have_caddy "$STAGE"; then :; else
  echo "fetch-caddy: 下载物不可执行，请检查 $STAGE" >&2; exit 1
fi

# ② 落到搜索目录（可能需 root）
if [[ -w "$DEST_DIR" ]]; then
  mv -f "$STAGE" "$DEST"
else
  # 非交互（CI / 无 tty）时必须用 `sudo -n`：裸 `sudo` 会卡在读口令，
  # 表现为"流水线挂住不报错"。口令没缓存就直接失败并给出可执行的下一步。
  if [[ -t 0 ]]; then
    echo "fetch-caddy: $DEST_DIR 不可写，尝试 sudo 安装" >&2
    sudo install -m 0755 "$STAGE" "$DEST"
  else
    echo "fetch-caddy: $DEST_DIR 不可写，尝试 sudo -n 安装" >&2
    sudo -n install -m 0755 "$STAGE" "$DEST" || {
      echo "fetch-caddy: 无免密 sudo。请改用：sudo $0，或 CADDY_INSTALL_DIR=<你有写权限的搜索目录> $0" >&2
      exit 1
    }
  fi
  rm -f "$STAGE"
fi

echo "fetch-caddy: $("$DEST" version | head -1) -> $DEST" >&2
echo "$DEST"
