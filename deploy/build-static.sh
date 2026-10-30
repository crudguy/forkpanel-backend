#!/usr/bin/env bash
# ForkPanel 静态分发构建：musl 静态二进制 + 签名 tarball
#
# 前提（在 CI / 有网环境执行）：
#   cargo install cargo-zigbuild     # 只是 cargo 子命令，**不会**自动下载 zig 本体
#   zig（0.13+）                     # ⚠ 必须单独安装，否则报 Failed to find zig 直接挂
#                                     #   CI 见 release.yml 的 mlugg/setup-zig@v2
#   openssl（1.1.1+）                # ed25519 签名，签用 pkeyutl -sign -rawin
#                                     #   ⚠ 不能用 dgst -sign：官方文档明确不支持 Ed25519
#   openssl genpkey -algorithm ed25519 -out "$KEY"   # 生成您的签名私钥（妥善保管，勿入库）
#
# 用法：
#   ./deploy/build-static.sh [版本号] [签名私钥路径]
#
# 产出 dist/panel-linux-{amd64,arm64}.tar.gz(+.sig)
#   tarball 内含：panel（静态二进制）、install.sh（安装逻辑）、config.toml（默认配置）、
#                forkpanel-config.sh（交互式配置入口，装为 forkpanel / fp）、
#                expose-public.sh（公网暴露脚本，install.sh 同目录查找，漏打包会导致 panel expose 不可用）
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
  cp deploy/forkpanel-config.sh "$tmp/forkpanel-config.sh"
  cp deploy/config.toml "$tmp/config.toml"
  cp deploy/expose-public.sh "$tmp/expose-public.sh"
  chmod 0755 "$tmp/panel"
  local tarball="$OUT/panel-linux-$arch.tar.gz"
  tar -C "$tmp" -czf "$tarball" panel install.sh forkpanel-config.sh config.toml expose-public.sh
  # ⚠ 必须用 pkeyutl -rawin，**不能**用 `dgst -sign`：openssl 官方文档写明
  #   `dgst -sign` 不支持 Ed25519/Ed448（"Use the pkeyutl command instead"）。
  #   旧版 openssl（如 ubuntu-24.04 自带的 3.0.x）会直接拒绝：
  #     Key type not supported for this operation
  #   本机 openssl 3.5+ 恰好能过 ⇒ 又一类「本地绿 / CI 红」，别被本地骗了。
  #   ed25519 无预哈希（pure Ed25519），-rawin 让 pkeyutl 把整份消息交给算法。
  #   两种方式产出的签名完全互验（已实测），故验签侧 get-panel.sh 的
  #   `dgst -verify` 无需改动。
  openssl pkeyutl -sign -inkey "$SIGN_KEY" -rawin -in "$tarball" -out "$tarball.sig"
  echo "    产出 $tarball ($(du -h "$tarball" | cut -f1)) + .sig"
  rm -rf "$tmp"
  # 打包完整性守卫：解包校验 tarball 必含这些文件，漏打任何一个立即失败，
  # 避免发布残缺 tarball（曾漏 expose-public.sh → 安装报「未找到 ./expose-public.sh」）。
  # 清单须与上方 cp + tar 列表保持一致；新增安装依赖文件时三处同步改。
  local expected=( panel install.sh forkpanel-config.sh config.toml expose-public.sh )
  local listing; listing="$(tar -tzf "$tarball")"
  local miss=0
  for f in "${expected[@]}"; do
    if ! printf '%s\n' "$listing" | grep -qx "$f"; then
      echo "    打包残缺：tarball 缺少 $f（检查上方 cp 与 tar 列表）" >&2
      miss=1
    fi
  done
  if [ "$miss" -ne 0 ]; then
    rm -f "$tarball" "$tarball.sig"
    echo "    已删除残缺产物：$tarball" >&2
    exit 1
  fi
}

pack x86_64-unknown-linux-musl amd64
pack aarch64-unknown-linux-musl arm64

echo "完成：$OUT/panel-linux-{amd64,arm64}.tar.gz(.sig) 上传到 RELEASE_BASE（见 deploy/get-panel.sh）。"
