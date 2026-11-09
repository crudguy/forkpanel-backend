#!/usr/bin/env bash
# 发布产物完整性门禁（报告 §3.10 P2 / §4.2 G11）
#
# 为什么需要：`deploy/build-static.sh` 的 `OUT="dist"` 让产物落在**仓库根下的 `dist/`**。
# 评审实测 `deploy/dist/` 里躺着一个停在 11-01、**只有 amd64、没有 SHA256SUMS** 的包
# ——陈旧且残缺的产物放在那儿，谁顺手拿它去装就会装到半个月前的代码，而没有任何东西
# 会提醒。更糟的是根 `dist/` 此前**根本没进 .gitignore**（`git status` 一直显示
# `?? dist/`，一次 `git add -A` 就会把 5.8MB 二进制提交进仓库）。
# 发版侧有 `ci/verify-release-assets.sh` 兜底，但那只在 release.yml 里跑；本地这堆
# 文件此前完全没有守卫。
#
# 判据（DIST 存在时全部要满足）：
#   [1] amd64 / arm64 两个 tarball 都在
#   [2] 各自 .sig 都在且非空（ed25519 签名固定 64 字节，截断的 .sig 验签必失败）
#   [3] SHA256SUMS 在，且 `sha256sum -c` **逐行真校验**——只判文件存在等于没校验
#   [4] SHA256SUMS 恰好覆盖两个包（少了＝漏包，多了＝混入无关产物）
#   [5] 每个 tarball 内含四个安装依赖文件（panel/install.sh/config.toml/expose-public.sh）
#       —— 打包残缺时 install.sh 要到用户机器上才报错（曾漏 expose-public.sh）
#   [6] 给了 PANEL_DIST_PUBKEY 时，用该公钥验两个 .sig（可选：本地测试常用临时密钥，
#       强制用仓库公钥验会把「用自己的密钥试打包」判红）
#
# DIST 不存在 → [skip] 非通过。这是本地常态：发布走 CI，干净 checkout 没有这个目录，
# 硬判红会让人克隆后第一次 `make check` 就红，然后被 `|| true` 掉（那才是真恒绿）。
#
# 用法：bash ci/check_release_artifacts.sh [dist目录]
#   DIST=/path bash ci/check_release_artifacts.sh /path
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# ⚠ 默认是**仓库根下的 dist/**：`deploy/build-static.sh` 的 `OUT="dist"` 就是这个。
#   评审报告里写的 `deploy/dist` 是更早的输出位置（现已废弃），那里的残留包
#   正是「比源码旧 5 天」的来源。两者都要能查 —— 用参数或 DIST= 覆盖即可。
DIST="${1:-${DIST:-$ROOT/dist}}"

fail=0
bad() { echo "  ✗ $1" >&2; fail=1; }
ok()  { echo "  ✓ $1"; }

case "$DIST" in
  /*) ;;
  *) DIST="$ROOT/$DIST" ;;
esac

if [ ! -d "$DIST" ]; then
  echo "[skip] $(basename "$0")：$DIST 不存在（本地产物未构建，本门禁未执行——非通过）" >&2
  echo "  需要时：PATH=\$HOME/.local/opt/zig:\$PATH ./deploy/build-static.sh <版本> <私钥>" >&2
  exit 0
fi
# 目录存在但**一个 tarball 都没有**：视为「尚未构建」，同样跳过。
# 判据要区分「没开始」与「做了一半」——`build-static.sh` 会先 `mkdir -p dist`，
# 若把空目录判红，构建中途失败留下的空壳会让 `make check` 永久红。
# 但只要目录里出现了任何一个 tarball，就说明构建已经开始过，此后必须完整（见下方判据）。
if ! ls "$DIST"/panel-linux-*.tar.gz >/dev/null 2>&1; then
  echo "[skip] $(basename "$0")：$DIST 里还没有任何 panel-linux-*.tar.gz（未构建，非通过）" >&2
  exit 0
fi

echo "== [1] 双架构 tarball =="
for arch in amd64 arm64; do
  t="$DIST/panel-linux-$arch.tar.gz"
  if [ -f "$t" ]; then ok "存在 panel-linux-$arch.tar.gz（$(du -h "$t" | cut -f1)）"
  else bad "缺少 panel-linux-$arch.tar.gz（早期产物只有 amd64，这条就是为它加的）"; fi
done

echo "== [2] 签名文件非空 =="
# ed25519 签名恒为 64 字节。0 字节或截断的 .sig 在用户侧才暴露，且报错是
# 「Verification failure」这种看不出病因的文案。
for arch in amd64 arm64; do
  s="$DIST/panel-linux-$arch.tar.gz.sig"
  if [ ! -f "$s" ]; then bad "缺少 panel-linux-$arch.tar.gz.sig"; continue; fi
  n=$(wc -c < "$s" | tr -d ' ')
  if [ "$n" -eq 64 ]; then ok "panel-linux-$arch.tar.gz.sig 为 64 字节（ed25519 定长）"
  else bad "panel-linux-$arch.tar.gz.sig 是 $n 字节（ed25519 应为 64）"; fi
done

echo "== [3] SHA256SUMS 逐行真校验 =="
if [ ! -f "$DIST/SHA256SUMS" ]; then
  bad "缺少 SHA256SUMS（旧产物就没有它）"
else
  # ⚠ 必须真的 `-c`：只判「文件存在」或「行数对」挡不住内容写错一个字符，
  #   那种情况下用户侧会静默装到坏包（get-panel.sh 的 hash 校验才会拦）。
  if ( cd "$DIST" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ); then
    ok "SHA256SUMS 与实际产物逐行一致"
  else
    bad "SHA256SUMS 校验失败（内容与实际产物不符，或列了不存在的文件）"
    ( cd "$DIST" && sha256sum -c SHA256SUMS 2>&1 | grep -v ': OK$' | sed 's/^/      /' ) || true
  fi
fi

echo "== [4] SHA256SUMS 恰好覆盖两个包 =="
if [ -f "$DIST/SHA256SUMS" ]; then
  cnt=$(grep -c . "$DIST/SHA256SUMS" || true)
  if [ "$cnt" -eq 2 ]; then ok "共 2 条"
  else bad "应恰好 2 条（amd64 / arm64），实得 $cnt"; fi
  for want in panel-linux-amd64.tar.gz panel-linux-arm64.tar.gz; do
    if grep -qE "^[0-9a-f]{64}  $want$" "$DIST/SHA256SUMS"; then ok "覆盖 $want"
    else bad "未覆盖 $want（或该行格式不是「<64位hash>␣␣<文件名>」）"; fi
  done
fi

echo "== [5] tarball 内含四个安装依赖文件 =="
for arch in amd64 arm64; do
  t="$DIST/panel-linux-$arch.tar.gz"
  [ -f "$t" ] || continue
  listing=$(tar -tzf "$t" 2>/dev/null) || { bad "$arch tarball 无法解包"; continue; }
  miss=""
  for f in panel install.sh config.toml expose-public.sh; do
    printf '%s\n' "$listing" | grep -qx "$f" || miss="$miss $f"
  done
  if [ -z "$miss" ]; then ok "$arch tarball 四件齐全"
  else bad "$arch tarball 缺:$miss"; fi
done

echo "== [6] 可选：用指定公钥验签 =="
if [ -z "${PANEL_DIST_PUBKEY:-}" ]; then
  ok "未设 PANEL_DIST_PUBKEY，跳过验签（本地试用临时密钥属正常）"
elif [ ! -f "$PANEL_DIST_PUBKEY" ]; then
  bad "PANEL_DIST_PUBKEY 指向的文件不存在：$PANEL_DIST_PUBKEY"
else
  # 与用户侧同一条命令（get-panel.sh 用 dgst -verify）——不同命令验签会让
  # 「本地过 / 用户侧不过」成为可能。
  for arch in amd64 arm64; do
    t="$DIST/panel-linux-$arch.tar.gz"; s="$t.sig"
    [ -f "$t" ] && [ -f "$s" ] || continue
    if openssl dgst -verify "$PANEL_DIST_PUBKEY" -signature "$s" "$t" >/dev/null 2>&1; then
      ok "$arch 签名验证通过"
    else
      bad "$arch 签名验证失败（私钥与公钥不匹配，或产物被替换）"
    fi
  done
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ 发布产物不完整：见上方 ✗ 项。重建：" >&2
  echo "  ./deploy/build-static.sh <版本> <私钥> && ( cd dist && sha256sum panel-linux-*.tar.gz > SHA256SUMS )" >&2
  exit 1
fi
echo "PASS：发布产物齐全（双架构 + .sig + SHA256SUMS + 打包清单）"
