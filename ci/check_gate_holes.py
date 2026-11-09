#!/usr/bin/env python3
"""G10「3 个门禁洞」的接线守卫（报告 §3.9 / §4.2）。

三个洞的共同形态都是**守卫存在但不在跑**，而且每一处都有「注释写了、退出码没写」：
  ① `check-embed-fresh.sh` 在 CI 里必然 `[skip] exit 0` —— ci.yml 不构建前端，
     `FE_DIST` 指向被 .gitignore 的目录。后果：这条挡住「改了前端却发出旧前端」
     的唯一门禁，在 CI 上从没执行过（只有 release.yml 单点兜底）。
  ② `check-frontend-loc.sh` 两处 CI 分支都 `exit 0`。报告点的是「扫到 0 个文件」
     那一处（原 :89），但 CI 里真正命中的是「找不到前端源码」那处 ——
     只改报告点名的那行，默认路径上依然恒绿。
  ③ 前端 `check:contract` 是孤儿守卫：package.json 有入口，Makefile 与前端 CI
     都不调用。

本守卫钉住**接线**，行为由「负向对照矩阵 + 真跑脚本」负责：
  [1] ci.yml 的 check job 真的构建前端并同步 web/dist（否则 ① 的 FE_DIST 不会存在）
  [2] 构建步骤带 `if: steps.<id>.outcome == 'success'`，占位兜底带 `!= 'success'`
      （占位若无条件执行会覆盖真产物，让 ① 退回假红/失配）
  [3] check-embed-fresh.sh：CI 分支判红，`exit 0` 只剩本地跳过那一处
  [4] check-frontend-loc.sh：全文不再有 `exit 0`
  [5] 前端 Makefile：`check:` 的依赖列表含 contract，且 contract 目标跑同一个脚本
  [6] 前端 package.json 的 `check:contract` 与 Makefile 同源（防两处漂移）

恒绿纪律：判据一律剔注释（本项目注释里大量出现 `exit 0` / `[skip]` 字样，
直接 grep 会让注释冒充实现）；提取为空即判红，绝不当通过。

用法：python3 ci/check_gate_holes.py [仓库根目录]
"""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
# 与 check-frontend-loc.sh / check-ui-guards.sh 同口径：本地两仓并列，CI 由
# PANEL_FRONTEND_ROOT 指定（ci.yml 里指向 $GITHUB_WORKSPACE/forkpanel-frontend）。
FE = Path(os.environ.get("PANEL_FRONTEND_ROOT") or (ROOT.parent / "forkpanel-frontend"))
fail = 0


def ok(msg):
    print(f"  ✓ {msg}")


def bad(msg):
    global fail
    print(f"  ✗ {msg}")
    fail = 1


def read(p):
    if not p.is_file() or p.stat().st_size == 0:
        bad(f"{p} 不存在或为空——提取前提不成立，绝不能当作通过")
        return ""
    return p.read_text()


def strip_comments(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


wf = read(ROOT / ".github/workflows/ci.yml")
ef = read(ROOT / "ci/check-embed-fresh.sh")
loc = read(ROOT / "ci/check-frontend-loc.sh")
fe_mk = read(FE / "Makefile")
fe_pkg = read(FE / "package.json")
if fail:
    print("✗ check_gate_holes：前提不成立（有文件读不到）")
    sys.exit(1)

wf_code = strip_comments(wf)
ef_code = strip_comments(ef)
loc_code = strip_comments(loc)

# ───────────────────────────────────────────────────────────────────────────
print("== [1] ci.yml 的 check job 真的构建前端并同步 web/dist ==")
# 没有这一段，`FE_DIST` 永远不存在 ⇒ check-embed-fresh.sh 在 CI 里不是判红就是跳过，
# 两种都不算「验证过」。
if "id: frontend" in wf_code:
    ok("前端 checkout 步骤带 id（供后续 if 引用）")
else:
    bad("前端 checkout 步骤缺 `id:`——`steps.<id>.outcome` 引用会失效，构建步骤将被静默跳过")

for needle, desc in [
    ("corepack pnpm@9 build", "真的执行前端构建（不是只 install）"),
    ("cp -a forkpanel-frontend/dist/. web/dist/", "把构建产物同步进 web/dist"),
    ("touch crates/panel-cli/src/embed.rs", "touch embed.rs 迫使 RustEmbed 重嵌（否则命中缓存嵌旧包）"),
]:
    if needle in wf_code:
        ok(desc)
    else:
        bad(f"ci.yml 缺接线：{desc}（找不到 `{needle}`）")

if re.search(r"rm\s+-rf\s+web/dist", wf_code):
    ok("同步前清空 web/dist（只 cp 只增不删，会留僵尸 chunk）")
else:
    bad("同步前没有 rm -rf web/dist：旧 hash 的 chunk 会残留，embed-fresh 的僵尸检查失去意义")

# ───────────────────────────────────────────────────────────────────────────
print("== [2] 构建步骤有 if 门、占位兜底也有 if 门 ==")
m_build = re.search(r"if:\s*steps\.frontend\.outcome\s*==\s*'success'", wf_code)
if m_build:
    ok("构建步骤限定在前端检出成功时执行")
else:
    bad("构建步骤没有 `if: steps.frontend.outcome == 'success'`（前端未检出时会硬失败，或写法漂移）")

# 占位步骤必须带否定条件：无条件跑会用占位 index.html 覆盖刚同步的真产物，
# 于是 embed-fresh 要么报「内容不一致」的假红，要么彻底失去检查意义。
m_ph = re.search(r"if:\s*steps\.frontend\.outcome\s*!=\s*'success'", wf_code)
if m_ph:
    ok("占位 web/dist 只在前端不可用时兜底")
else:
    bad("占位 web/dist 没有 `if: steps.frontend.outcome != 'success'`：会覆盖真产物")

ph_if_n = len(re.findall(r"if:\s*steps\.frontend\.outcome\s*!=\s*'success'", wf_code))
if ph_if_n == 1:
    ok("占位步骤的 if 恰好 1 处")
else:
    bad(f"占位条件应恰好 1 处，实得 {ph_if_n}（重复或缺失都算异常）")

# ───────────────────────────────────────────────────────────────────────────
print("== [3] check-embed-fresh.sh：CI 下缺产物必须判红 ==")
# 剔注释后 `exit 0` 只允许剩本地跳过那一处，且必须**排在 CI 判红之后**。
# ⚠ 不要用「exit 0 前面 N 行内不含 ${CI:-}」这种窗口判据：CI 判定与本地跳过
#   本来就在同一个 if 块里相邻，窗口开小了抓不到 [skip]、开大了必然含 CI 标记，
#   两种写法都会误判。位置关系（先判红、后兜底）才是这段代码的真实语义。
lines_ef = ef_code.splitlines()
ci_pos = next((i for i, l in enumerate(lines_ef) if "${CI:-}" in l), -1)
e1_pos = next(
    (i for i, l in enumerate(lines_ef) if i > ci_pos >= 0 and re.match(r"^\s*exit\s+1\s*$", l)),
    -1,
)
if ci_pos < 0:
    bad("找不到 CI 判定（`${CI:-}`）——报告要求的「缺失判红」分支不存在")
elif e1_pos < 0:
    bad("CI 判定之后没有 exit 1——「缺失判红」没落到实处")
else:
    ok("CI 判定分支内判红（exit 1）")

exit0_lines = [
    (i, l) for i, l in enumerate(lines_ef) if re.match(r"^\s*exit\s+0\s*$", l)
]
if not exit0_lines:
    ok("没有 exit 0（更严格：任何缺失都判红）")
elif len(exit0_lines) > 1:
    bad(f"仍有 {len(exit0_lines)} 处 exit 0：除本地跳过外，CI 分支不得静默通过")
else:
    i, _ = exit0_lines[0]
    near = "\n".join(lines_ef[max(0, i - 4) : i + 1])
    if "[skip]" not in near:
        bad("唯一的 exit 0 附近没有 [skip] 提示：静默通过与显式跳过必须能区分")
    elif not (0 <= ci_pos < e1_pos < i):
        bad("唯一的 exit 0 不在 CI 判红之后：说明它仍可能是 CI 路径的静默通过")
    else:
        ok("唯一的 exit 0 是「本地未构建前端」的显式跳过，且排在 CI 判红之后")

# ───────────────────────────────────────────────────────────────────────────
print("== [4] check-frontend-loc.sh：不再有 CI 静默通过 ==")
loc_exit0 = re.findall(r"^\s*exit\s+0\s*$", loc_code, re.M)
if not loc_exit0:
    ok("全文无 exit 0（正常路径靠脚本末尾隐式 0，异常路径一律 exit 1）")
else:
    bad(f"仍有 {len(loc_exit0)} 处 exit 0：报告 §3.9 点名的恒绿洞回来了")

# 两处判红都要在：找不到前端源码、扫到 0 个文件。只留一处＝另一条路径仍恒绿。
n_src_guard = len(re.findall(r"\[ -z \"\$FE_SRC\" \]", loc_code))
if n_src_guard == 1:
    ok("「找不到前端源码」分支仍在（且无 CI 例外）")
else:
    bad(f"`[ -z \"$FE_SRC\" ]` 应恰好 1 处，实得 {n_src_guard}")
if re.search(r"if\s*\[\s*\"\$cnt\"\s+-eq\s+0\s*\]", loc_code):
    ok("「扫到 0 个文件」分支仍在")
else:
    bad("找不到 `if [ \"$cnt\" -eq 0 ]` 判据：空集检查被删了")

# ───────────────────────────────────────────────────────────────────────────
print("== [5] 前端 Makefile：contract 已挂进 check 链 ==")
m_check = re.search(r"^check:\s*(.+)$", fe_mk, re.M)
if not m_check:
    bad("前端 Makefile 找不到 `check:` 目标")
else:
    deps = m_check.group(1).split()
    if "contract" in deps:
        ok(f"check 依赖含 contract（当前：{' '.join(deps)}）")
    else:
        bad(f"check 依赖缺 contract（当前：{' '.join(deps)}）——契约检查又成孤儿")

m_tgt = re.search(r"^contract:\s*$", fe_mk, re.M)
if not m_tgt:
    bad("前端 Makefile 没有 `contract:` 目标")
else:
    body = fe_mk[m_tgt.end() :].split("\n\n")[0]
    if "ci/check-contract.sh" in body:
        ok("contract 目标跑的就是 ci/check-contract.sh")
    else:
        bad("contract 目标没调用 ci/check-contract.sh（指向了别的东西）")

# ───────────────────────────────────────────────────────────────────────────
print("== [6] package.json 与 Makefile 同源 ==")
try:
    pkg = json.loads(fe_pkg)
    script = pkg.get("scripts", {}).get("check:contract", "")
except json.JSONDecodeError as e:
    bad(f"package.json 解析失败：{e}")
    script = ""
if "ci/check-contract.sh" in script:
    ok("package.json 的 check:contract 与 Makefile 指向同一脚本")
else:
    bad(f"package.json 的 check:contract 与 Makefile 漂移（实得：{script!r}）")

if fail:
    print("✗ check_gate_holes：门禁接线未通过")
    sys.exit(1)
print("PASS：3 个门禁洞的接线均已在位（行为由负向对照矩阵与真跑脚本覆盖）")
sys.exit(0)
