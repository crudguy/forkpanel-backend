#!/usr/bin/env bash
# release-smoke.sh 的离线自验 + 负向对照（报告 §4.2 G11）
#
# 为什么需要：`ci/release-smoke.sh` 的正常路径要访问 GitHub Release，本地跑不了。
# 不验就等于「写好了但没跑过」——本报告反复点名的形态。这里用 `RELEASE_SMOKE_LOCAL_DIR`
# 把 `deploy/dist` 的真产物当作「下载结果」，再用派生样本逐条打红。
#
# 前提：`deploy/dist` 里有完整产物（双架构 + .sig + SHA256SUMS）。没有则 [skip] 非通过。
#
# 判据：正向样本必须 PASS；6 组负向必须转红且**命中对应编号段**（防止「改坏了 A 却让
# B 红」凑数，也防止某条判据其实从没生效）。
#
# 用法：bash ci/verify-release-smoke.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# 与 ci/check_release_artifacts.sh 同口径：产物在**仓库根下的 dist/**
# （build-static.sh 的 OUT="dist"；deploy/dist 是废弃的旧位置）
DIST="${PANEL_DIST_DIR:-$ROOT/dist}"
SMOKE="$ROOT/ci/release-smoke.sh"
TAG="v0.1.0"
VER="0.1.0"

if [ ! -d "$DIST" ]; then
  echo "[skip] $(basename "$0")：$DIST 不存在——先跑 deploy/build-static.sh，本脚本未验证任何东西" >&2
  exit 2
fi
[ -x "$SMOKE" ] || [ -f "$SMOKE" ] || { echo "✗ 找不到 $SMOKE" >&2; exit 1; }
for f in panel-linux-amd64.tar.gz panel-linux-arm64.tar.gz SHA256SUMS; do
  [ -f "$DIST/$f" ] || { echo "[skip] $(basename "$0")：$DIST 缺 $f，样本不完整" >&2; exit 2; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

P=0; F=0
chk() { # chk <名称> <实际> <期望>
  if [ "$2" = "$3" ]; then P=$((P+1)); echo "  PASS $1"
  else F=$((F+1)); echo "  FAIL $1  实际=[$2] 期望=[$3]"; fi
}
chk_has() { # chk_has <名称> <文本> <子串>
  case "$2" in *"$3"*) P=$((P+1)); echo "  PASS $1";;
    *) F=$((F+1)); echo "  FAIL $1  未命中[$3]";; esac
}

# 造一份独立副本（cp -a 保留 mtime/权限，避免样本自身引入差异）
prep() {
  local d="$TMP/$1"
  mkdir -p "$d"
  cp -a "$DIST"/. "$d"/
  printf '%s' "$d"
}

# 本地样本都是用**临时密钥**打的包，故把公钥一并指过去；CI 里不需要这层覆盖。
TPUB="${PANEL_TEST_PUBKEY:-/tmp/g11-release.pub}"
run() { # run <目录> → 输出到 stdout，返回码透传
  RELEASE_SMOKE_LOCAL_DIR="$1" RELEASE_SMOKE_PUBKEY="$TPUB" \
    bash "$SMOKE" "local/sandbox" "$TAG" 2>&1
}

# 段内是否出现 ✗：只认对应编号段，避免别的判据红了被当成命中
seg_cross() { # seg_cross <输出> <编号>
  printf '%s\n' "$1" | awk -v n="[${2}]" '
    index($0, "== " n) == 1 { inside = 1; next }
    inside && index($0, "== [") == 1 { inside = 0 }
    inside && index($0, "✗") > 0 { found = 1 }
    END { exit(found ? 0 : 1) }'
}

echo "== 正向：完整样本必须 PASS =="
d=$(prep ok)
out=$(run "$d"); rc=$?
# 版本号断言依赖 tag 与产物真实版本一致：build-static.sh 用 0.1.0 打的包
chk "完整样本退出码" "$rc" "0"
chk_has "输出含 PASS" "$out" "PASS：Release $TAG"
chk "输出无 ✗" "$(printf '%s' "$out" | grep -c '✗' || true)" "0"

echo "== 负向 1：删掉 arm64 包（早期产物只有 amd64 的原形） =="
d=$(prep no-arm64); rm -f "$d/panel-linux-arm64.tar.gz" "$d/panel-linux-arm64.tar.gz.sig"
out=$(run "$d"); rc=$?
chk "退出码非 0" "$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"
chk "命中 [1] 段" "$(seg_cross "$out" 1 && echo yes || echo no)" "yes"

echo "== 负向 2：篡改 tarball（上传损坏 / 被替换） =="
d=$(prep tampered)
printf 'x' >> "$d/panel-linux-amd64.tar.gz"
out=$(run "$d"); rc=$?
chk "退出码非 0" "$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"
chk "命中 [2] 段（SHA256 不符）" "$(seg_cross "$out" 2 && echo yes || echo no)" "yes"
chk "命中 [3] 段（签名失效）" "$(seg_cross "$out" 3 && echo yes || echo no)" "yes"

echo "== 负向 3：SHA256SUMS 写错一个字符 =="
d=$(prep bad-sums)
python3 - "$d/SHA256SUMS" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()
# 只改第一行的第一个十六进制字符，保持行数/文件名为「看起来正常」的形态
if lines:
    h, name = lines[0].split("  ", 1)
    h = ("0" if h[0] != "0" else "1") + h[1:]
    lines[0] = f"{h}  {name}"
open(p, "w").write("\n".join(lines) + "\n")
PY
out=$(run "$d"); rc=$?
chk "退出码非 0" "$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"
chk "命中 [2] 段（逐行校验，不是只看文件在不在）" "$(seg_cross "$out" 2 && echo yes || echo no)" "yes"

echo "== 负向 4：两个包的架构被互换（amd64 包冒充 arm64） =="
d=$(prep swapped)
cp -a "$d/panel-linux-amd64.tar.gz" "$d/panel-linux-arm64.tar.gz"
# 重新算 SHA256SUMS + 重签，让 [2][3] 保持绿——只让架构判据单独说话
( cd "$d" && sha256sum panel-linux-*.tar.gz > SHA256SUMS )
openssl pkeyutl -sign -inkey "${PANEL_TEST_KEY:-/tmp/g11-release.key}" -rawin \
  -in "$d/panel-linux-arm64.tar.gz" -out "$d/panel-linux-arm64.tar.gz.sig" 2>/dev/null
out=$(run "$d"); rc=$?
chk "退出码非 0" "$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"
chk "命中 [5] 段（架构不符）" "$(seg_cross "$out" 5 && echo yes || echo no)" "yes"

echo "== 负向 5：版本号不符（Cargo.toml 未对齐 tag） =="
d=$(prep wrong-ver)
# 造一个只会打印错版本号的假 panel，重新打包成 amd64 包
work="$TMP/wrong-ver-src"; mkdir -p "$work"
printf '#!/bin/sh\necho "panel 9.9.9"\n' > "$work/panel"; chmod 0755 "$work/panel"
for f in install.sh config.toml expose-public.sh; do
  tar -xzf "$DIST/panel-linux-amd64.tar.gz" -C "$work" "$f" 2>/dev/null || cp "$ROOT/deploy/$f" "$work/$f"
done
tar -C "$work" -czf "$d/panel-linux-amd64.tar.gz" panel install.sh config.toml expose-public.sh
( cd "$d" && sha256sum panel-linux-*.tar.gz > SHA256SUMS )
openssl pkeyutl -sign -inkey "${PANEL_TEST_KEY:-/tmp/g11-release.key}" -rawin \
  -in "$d/panel-linux-amd64.tar.gz" -out "$d/panel-linux-amd64.tar.gz.sig" 2>/dev/null
out=$(run "$d"); rc=$?
chk "退出码非 0" "$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"
chk "命中 [4] 段（版本号不符）" "$(seg_cross "$out" 4 && echo yes || echo no)" "yes"

echo "== 负向 6：多放一个无关资产 =="
d=$(prep extra); : > "$d/panel-linux-riscv64.tar.gz"
out=$(run "$d"); rc=$?
chk "退出码非 0" "$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"
chk "命中 [1] 段（清单必须恰好 5 项）" "$(seg_cross "$out" 1 && echo yes || echo no)" "yes"

echo "────────────────────────────────────────"
echo "PASS=$P FAIL=$F"
if [ "$F" -ne 0 ]; then
  echo "✗ 发布冒烟自验未通过" >&2
  exit 1
fi
echo "PASS：release-smoke 的正向与 6 组负向均符合预期"
