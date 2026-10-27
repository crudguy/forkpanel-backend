#!/usr/bin/env bash
# ForkPanel 静态分发构建：musl 静态二进制 + 签名 tarball
#
# 前提（在 CI / 有网环境执行）：
#   cargo install cargo-zigbuild     # 只是 cargo 子命令，**不会**自动下载 zig 本体
#   zig（0.13+）                     # ⚠ 必须单独安装，否则报 Failed to find zig 直接挂
#                                     #   CI 见 release.yml 的 mlugg/setup-zig@v2
#   openssl                         # ed25519 签名
#   openssl genpkey -algorithm ed25519 -out "$KEY"   # 生成您的签名私钥（妥善保管，勿入库）
#
# 用法：
#   ./deploy/build-static.sh [版本号] [签名私钥路径]
#
# 产出 dist/panel-linux-{amd64,arm64}.tar.gz(+.sig)
#   tarball 内含：panel（静态二进制）、install.sh（安装逻辑）、config.toml（默认配置）
set -euo pipefail

cd "$(dirname "$0")/.."   # 切到仓库根
VERSION="${1:-0.0.0-dev}"
SIGN_KEY="${2:-${PANEL_RELEASE_KEY:-$HOME/.forkpanel-release.key}}"
OUT="dist"
mkdir -p "$OUT"

[ -f "$SIGN_KEY" ] || { echo "缺少签名私钥：$SIGN_KEY（见文件头注释生成方式）" >&2; exit 1; }
command -v cargo-zigbuild >/dev/null 2>&1 || { echo "缺少 cargo-zigbuild：cargo install cargo-zigbuild" >&2; exit 1; }
# zig 是 cargo-zigbuild 的 linker 后端，缺失时它只会报含糊的 "Failed to find zig"。
# 在这里提前拦住并说清病因，省去下一次「看不出为什么」的 CI 红。
command -v zig >/dev/null 2>&1 || {
  echo "缺少 zig 编译器（cargo-zigbuild 依赖它，且不会自动下载）：" >&2
  echo "  Debian/Ubuntu：下载官方 tarball 解压后加进 PATH；CI 见 release.yml 的 mlugg/setup-zig@v2" >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || { echo "缺少 openssl" >&2; exit 1; }

# 把安装三件套打进 tarball（install.sh 单源来自 deploy/，避免漂移）
pack() {
  local target="$1" arch="$2"
  echo "==> 构建 $target"
  cargo zigbuild --release --target "$target"
  local bin="target/$target/release/panel"
  [ -f "$bin" ] || { echo "构建失败：$bin" >&2; exit 1; }
  local tmp; tmp="$(mktemp -d)"
  cp "$bin" "$tmp/panel"
  cp deploy/install.sh "$tmp/install.sh"
  cp deploy/config.toml "$tmp/config.toml"
  chmod 0755 "$tmp/panel"
  local tarball="$OUT/panel-linux-$arch.tar.gz"
  tar -C "$tmp" -czf "$tarball" panel install.sh config.toml
  openssl dgst -sign "$SIGN_KEY" -out "$tarball.sig" "$tarball"
  echo "    产出 $tarball ($(du -h "$tarball" | cut -f1)) + .sig"
  rm -rf "$tmp"
}

pack x86_64-unknown-linux-musl amd64
pack aarch64-unknown-linux-musl arm64

echo "完成：$OUT/panel-linux-{amd64,arm64}.tar.gz(.sig) 上传到 RELEASE_BASE（见 deploy/get-panel.sh）。"
