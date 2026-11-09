#!/usr/bin/env bash
# 发布后冒烟：把**刚上传的资产下载回来**再校验一遍（报告 §3.10 P1 / §4.2 G11）
#
# 为什么必须「下载回来」：release.yml 里 `ci/verify-release-assets.sh` 验的是
# **准备上传的文件**。上传环节仍可能出错且它看不见：
#   - `files:` 列表漏写某一项 ⇒ Release 上只有 3 个资产，用户下不到 arm64；
#   - 上传中断 ⇒ 0 字节资产，用户侧验签报「Verification failure」；
#   - 资产名被改 ⇒ get-panel.sh 拼出的 URL 404。
# 本地验完就发，只证明「我打算发什么」，不证明「用户能下到什么」。
#
# 判据：
#   [1] Release 上恰好这 5 个资产（两个 tarball + 两个 .sig + SHA256SUMS），多一个少一个都算异常
#   [2] 下载回来 `sha256sum -c` 通过（对照 Release 里的 SHA256SUMS）
#   [3] 用**仓库内嵌公钥**验两个 .sig，命令与用户侧 get-panel.sh 完全相同（dgst -verify）
#   [4] amd64 包解出来的二进制**真能跑**，且 `panel --version` 的版本号 == tag
#   [5] 两个二进制架构正确（x86-64 / aarch64）且静态链接（musl 的核心承诺）
#
# 用法：bash ci/release-smoke.sh <owner/repo> <tag>
#
# 离线自验：设 `RELEASE_SMOKE_LOCAL_DIR=<目录>` 时跳过 gh，把该目录当作「下载结果」。
#   这是为了让本脚本的每条判据都能被负向对照真跑到（否则它只能在真发版时首次执行，
#   「写好了但没跑过」——正是本报告反复点名的形态）。生产路径永远走 gh。
set -uo pipefail

REPO="${1:-}"
TAG="${2:-}"
if [ -z "$REPO" ] || [ -z "$TAG" ]; then
  echo "用法：bash ci/release-smoke.sh <owner/repo> <tag>" >&2
  exit 2
fi
VER="${TAG#v}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# 默认用仓库内嵌公钥（与用户侧 get-panel.sh 完全同一把）。
# `RELEASE_SMOKE_PUBKEY` 只给离线自验（ci/verify-release-smoke.sh）用——
# 本地样本通常是用临时密钥打的包，不覆盖就会在 [3] 假红。CI 里永远不设这个变量。
PUBKEY="${RELEASE_SMOKE_PUBKEY:-$ROOT/deploy/release-pubkey.pub}"
if [ ! -f "$PUBKEY" ]; then
  echo "✗ 缺少发布公钥 $PUBKEY（验签信任根不成立）" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
bad() { echo "  ✗ $1" >&2; fail=1; }
ok()  { echo "  ✓ $1"; }

EXPECTED=(
  panel-linux-amd64.tar.gz
  panel-linux-amd64.tar.gz.sig
  panel-linux-arm64.tar.gz
  panel-linux-arm64.tar.gz.sig
  SHA256SUMS
)

if [ -n "${RELEASE_SMOKE_LOCAL_DIR:-}" ]; then
  DL="$RELEASE_SMOKE_LOCAL_DIR"
  [ -d "$DL" ] || { echo "✗ RELEASE_SMOKE_LOCAL_DIR 不存在：$DL" >&2; exit 1; }
  echo "== 离线模式：把 $DL 当作已下载资产（不走 gh）=="
  ASSETS="$(cd "$DL" && ls -1 | sort)"
else
  command -v gh >/dev/null 2>&1 || { echo "✗ 缺少 gh CLI（CI 由 GitHub runner 自带）" >&2; exit 1; }
  echo "== [0] 列举 Release $TAG 的资产 =="
  if ! gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name' | sort > "$WORK/assets.txt"; then
    echo "✗ 取不到 Release $TAG 的资产清单（Release 不存在或无权限）" >&2
    exit 1
  fi
  ASSETS="$(cat "$WORK/assets.txt")"
  DL="$WORK/dl"
  mkdir -p "$DL"
  echo "== [0b] 下载资产 =="
  if ! gh release download "$TAG" --repo "$REPO" --dir "$DL"; then
    echo "✗ 资产下载失败" >&2
    exit 1
  fi
fi

echo "== [1] 资产清单恰好 5 项 =="
printf '%s\n' "${EXPECTED[@]}" | sort > "$WORK/want.txt"
printf '%s\n' "$ASSETS" | grep -v '^$' | sort > "$WORK/got.txt" || true
if diff -u "$WORK/want.txt" "$WORK/got.txt" > "$WORK/diff.txt" 2>&1; then
  ok "5 个资产齐全且无多余项"
else
  # 展示具体缺/多，而不是只说「不一致」——排障时最想知道的就是这一条
  bad "资产清单不符（左=期望 右=实际）："
  sed 's/^/      /' "$WORK/diff.txt"
fi

echo "== [2] SHA256SUMS 逐行真校验 =="
if [ -f "$DL/SHA256SUMS" ]; then
  if ( cd "$DL" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ); then
    ok "下载回来的产物与 SHA256SUMS 一致"
  else
    bad "SHA256SUMS 校验失败（上传损坏或被替换）"
    ( cd "$DL" && sha256sum -c SHA256SUMS 2>&1 | grep -v ': OK$' | sed 's/^/      /' ) || true
  fi
else
  bad "Release 上没有 SHA256SUMS"
fi

echo "== [3] 用仓库内嵌公钥验签（与用户侧同一条命令） =="
for arch in amd64 arm64; do
  t="$DL/panel-linux-$arch.tar.gz"; s="$t.sig"
  if [ ! -f "$t" ] || [ ! -f "$s" ]; then bad "$arch 的 tarball 或 .sig 缺失，跳过验签"; continue; fi
  if openssl dgst -verify "$PUBKEY" -signature "$s" "$t" >/dev/null 2>&1; then
    ok "$arch 签名验证通过"
  else
    bad "$arch 签名验证失败（私钥与仓库公钥不匹配，或产物被篡改）"
  fi
done

echo "== [4] amd64 二进制真能跑，且版本号 == tag =="
if [ -f "$DL/panel-linux-amd64.tar.gz" ]; then
  mkdir -p "$WORK/amd64"
  if tar -C "$WORK/amd64" -xzf "$DL/panel-linux-amd64.tar.gz" 2>/dev/null; then
    if [ -x "$WORK/amd64/panel" ]; then
      # 用 `--version` 而不是 `--help`：后者只证明二进制能加载，不证明版本对
      got="$("$WORK/amd64/panel" --version 2>&1 | head -1 || true)"
      if [ "$got" = "panel $VER" ]; then ok "panel --version = panel $VER"
      else bad "版本号不符：期望「panel $VER」，实得「$got」（Cargo.toml 未对齐 tag？）"; fi
    else
      bad "解包后 panel 不可执行（权限位丢了？）"
    fi
  else
    bad "amd64 tarball 无法解包"
  fi
else
  bad "缺少 amd64 tarball，跳过运行验证"
fi

echo "== [5] 两个二进制架构正确且静态链接 =="
for arch in amd64 arm64; do
  t="$DL/panel-linux-$arch.tar.gz"
  [ -f "$t" ] || { bad "缺少 $arch tarball"; continue; }
  d="$WORK/$arch"; mkdir -p "$d"
  tar -C "$d" -xzf "$t" 2>/dev/null || { bad "$arch tarball 无法解包"; continue; }
  [ -f "$d/panel" ] || { bad "$arch 包内没有 panel"; continue; }
  desc="$(file -b "$d/panel")"
  want_arch=$([ "$arch" = amd64 ] && echo "x86-64" || echo "aarch64")
  case "$desc" in
    *"$want_arch"*) ok "$arch 架构为 $want_arch" ;;
    *) bad "$arch 包内二进制架构不符：期望含 $want_arch，实得「$desc」" ;;
  esac
  # musl 静态构建的意义就是「不依赖宿主 glibc」。这里不用 ldd（static-pie 时它的
  # 输出因发行版而异），直接看 file 的描述里有没有 static/dynamic 标记。
  case "$desc" in
    *"statically linked"*|*"static-pie"*) ok "$arch 为静态链接" ;;
    *"dynamically linked"*) bad "$arch 是动态链接（musl 静态构建失败，用户机上会缺 glibc）" ;;
    *) bad "$arch 静态性无法判定：「$desc」" ;;
  esac
  # 打包清单：少任何一个都会在用户机器上才炸。
  # ⚠ 必须先把清单取进变量再 grep。写成 `tar -tzf "$t" | grep -qx "$f"` 时，
  #   `set -o pipefail` 会把「grep -q 命中后提前退出 ⇒ tar 收到 SIGPIPE(141)」
  #   当成管道失败 ⇒ **每个文件都被判缺失**，正向样本直接假红。
  #   同族坑：`a | tail` 吃掉退出码。
  listing="$(tar -tzf "$t" 2>/dev/null)"
  miss=""
  for f in panel install.sh config.toml expose-public.sh; do
    printf '%s\n' "$listing" | grep -qx "$f" || miss="$miss $f"
  done
  if [ -z "$miss" ]; then ok "$arch 包内四件齐全"
  else bad "$arch 包内缺:$miss"; fi
done

if [ "$fail" -ne 0 ]; then
  echo "✗ 发布后冒烟未通过：Release $TAG 不应转为正式发布" >&2
  exit 1
fi
echo "PASS：Release $TAG 的资产可下载、可验签、可运行、架构与版本均正确"
