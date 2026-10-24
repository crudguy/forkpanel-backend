#!/usr/bin/env bash
# 文档 ↔ 代码一致性守卫：把**文档里对代码事实的断言**双向钉住。
#
# # 为什么需要
# 本项目反复踩过"文档/注释与代码漂移"：注释说实现了、代码没实现；或代码删了、
# 文档仍把它当可用项。典型的一次是 `--features tls`：占位特性**从未接线**，却让
# 配置模板宣传"启用它就能开 HTTPS"——用户照做，得到的却是同端口明文。
#
# 纯靠人记着更新文档不可靠 ⇒ 这里把**具体事实**双向钉住：
#   · 文档说"已删除 / 已收敛"的 → 代码里必须真的没有；
#   · 文档说"由 X 下发 / 单一真值"的 → X 必须还在；
#   · 文档侧的"待办/待拍板"条目里不得再出现**已删除的选项**（否则活清单会误导）。
#
# ⚠ 断言一律**剔注释行**再比对：`.rs`/`.toml` 里的说明文字（"历史上有过 axum-server"
#   这类）不是声明，比对时必须排除，否则门禁被自己的注释绊倒。
#
# # 用法
#   bash ci/check-docs-consistency.sh（在 forkpanel-backend 下执行）
#   前端仓不在时，前端侧断言显式 [skip]（不判失败——恒红比没门禁更糟）。
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
FE="${FE_DIR:-$HERE/../forkpanel-frontend}"
CRATES="$HERE/crates"
ALL_RS="$(find "$CRATES" -name '*.rs' -type f)"
ALL_TOML="$(find "$CRATES" -name 'Cargo.toml' -type f)"
fail=0
ok()  { printf '  ✓ %s\n' "$1"; }
bad() { printf '  ✗ %s\n' "$1" >&2; fail=1; }

# 在若干文件里找**非注释行**的匹配（`.rs`/`.toml` 都用 `#` 起注释）。
# ⚠ 多文件时 grep 的输出前缀是 `文件名:行号:`，故过滤式要带上文件名段
#   （写成 `^[0-9]+:` 会在多文件时完全失效——注释行滤不掉，门禁被自己的注释绊倒）。
active_match() { # $1=ERE 模式, 其余=文件
  local pat="$1"; shift
  # shellcheck disable=SC2086
  # ⚠ P1-3：注释过滤式必须区分 Rust 属性 `#[...]` 与真实注释。原 `^...:#` 会把
  #   `#[cfg(feature = "tls")]` 这类属性行当注释剔掉，导致该检查恒绿（永远找不到
  #   ⇒ 误报"无 tls 代码"）。改为：剔 `//` 注释（含 ///）和 `#` 注释，但保留 `#[`（属性）。
  grep -nE "$pat" "$@" 2>/dev/null | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(//|#[^\[])' | grep -q .
}

echo "== 文档 ↔ 代码一致性 =="

# 1) `--features tls` 已删除（docs/audit-*.md 写了"已删除"，`[server].tls` 已拒绝启动）
if active_match '^tls = \[' $ALL_TOML; then
  bad "仍有 crate 声明 tls 特性——文档已写明它被删除（99437e5）"
else ok "无 crate 声明 tls 特性（与文档一致）"; fi
if active_match 'cfg\(feature = "tls"\)' $ALL_RS; then
  bad '仍有 #[cfg(feature = "tls")] 代码——文档说该特性从未接线'
else ok '无 #[cfg(feature = "tls")] 代码（与文档一致）'; fi

# 2) 面板本体不终结 TLS ⇒ 不该再依赖 axum-server（serve 只有 http）
if active_match 'axum-server' $ALL_TOML; then
  bad "Cargo.toml 又出现 axum-server 依赖——文档说面板自身 HTTPS 未实现"
else ok "无 axum-server 依赖（与文档一致）"; fi

# 3) 终端并发上限已是单一真值（env.md 的说法）：后端 capabilities 必须仍在下发
if active_match 'terminal_max_sessions' "$CRATES/panel-api/src/routes/system.rs"; then
  ok "capabilities 仍下发 terminal_max_sessions"
else bad "capabilities 不再下发 terminal_max_sessions——env.md 的说法已过期"; fi
if [ -d "$FE/src" ]; then
  FE_FILES="$(find "$FE/src" -type f \( -name '*.ts' -o -name '*.vue' \))"
  if active_match 'MAX_TABS' $FE_FILES; then
    bad "前端又出现 MAX_TABS——env.md 说它已删除、改读 auth.terminalMax"
  else ok "前端无 MAX_TABS（与文档一致）"; fi
else
  printf '  [skip] 前端仓不在 %s，跳过前端侧断言\n' "$FE"
fi

# 4) 主密钥只来自文件，不读环境变量（env.md 的说法）
if active_match 'env::var\([^)]*PANEL_MASTER_KEY' $ALL_RS; then
  bad "代码开始读 PANEL_MASTER_KEY 环境变量了——env.md 说它不存在"
else ok "未读取 PANEL_MASTER_KEY（与文档一致）"; fi

# 5) 文档侧：**活清单**里不得再挂着已删除的选项
for d in "$HERE/docs/audit-2026-10-17.md" "$HERE/docs/audit-2026-10-17-summary.md"; do
  [ -f "$d" ] || continue
  if grep -n '待拍板' "$d" | grep -q 'features tls'; then
    bad "$(basename "$d")：仍有'待拍板 + --features tls'——该选项已删除（99437e5）"
  else ok "$(basename "$d")：活清单里没有已删除的 tls 选项"; fi
done
if grep -q '属审计 P2-5 待办' "$HERE/docs/env.md" 2>/dev/null; then
  bad "env.md 仍写 P2-5 是待办——它已完成（23050e9/16b67d9）"
else ok "env.md：P2-5 不再是待办"; fi

[ $fail -eq 0 ] || exit 1
echo "PASS：文档 ↔ 代码一致性通过"
