#!/usr/bin/env python3
"""E2E 接线守卫：确保零 root 聚合脚本真的被 CI 调用，且「跳过 ≠ 通过」。

背景：18 个 ci/e2e-*.sh 与自称「任何 CI 可直接调用、零 root」的 run-e2e-ci.sh
长期不进 make check / workflow —— 唯一覆盖「路由注册 + 能力位 + OS provider 真实落盘」
的一层在每次 PR 与发版前从不被自动执行。接线之后还要防两类退化：
  ① workflow 里那行被删 / 改成注释 / 加 continue-on-error ⇒ 又变成「有脚本没在跑」；
  ② 任一域 [skip] 时退出 0，或聚合器把 skip 当通过 ⇒ 恒绿门禁。

恒绿纪律：判据剔注释、提取先断言非空（SCRIPTS 提取塌成 0 一律判红）、
直接盯被检查的那份文件。

用法：python3 ci/check_e2e_wired.py [仓库根目录]
"""
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
fail = 0


def ok(msg):
    print(f"  ✓ {msg}")


def bad(msg):
    global fail
    print(f"  ✗ {msg}")
    fail = 1


def read(rel):
    p = ROOT / rel
    if not p.is_file() or p.stat().st_size == 0:
        bad(f"{rel} 不存在或为空——提取前提不成立，绝不能当作通过")
        return ""
    return p.read_text()


def strip_comments(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


wf = read(".github/workflows/ci.yml")
runner = read("ci/run-e2e-ci.sh")
agg = read("ci/e2e-all.sh")
if fail:
    print("✗ check_e2e_wired：前提不成立")
    sys.exit(1)

print("== [1] workflow 里真的调用 run-e2e-ci.sh（剔注释后恰好 1 处） ==")
wf_code = strip_comments(wf)
n = len(re.findall(r"^\s*run:\s*bash ci/run-e2e-ci\.sh\s*$", wf_code, re.M))
if n == 1:
    ok("ci.yml 有且仅有 1 条 run: bash ci/run-e2e-ci.sh 步骤")
else:
    bad(f"ci.yml 的 E2E 调用应恰好 1 处，实得 {n}（删了/写进注释/重复都算异常）")
if re.search(r"continue-on-error", wf_code) and re.search(r"run-e2e-ci", wf_code):
    # 仅提示：其它 job 也可能合法使用 continue-on-error（私有前端仓 checkout），
    # 故这里只在 E2E 步骤所在行附近精确判断。
    m = re.search(r"run:\s*bash ci/run-e2e-ci\.sh[\s\S]{0,200}", wf_code)
    if m and "continue-on-error" in m.group(0):
        bad("E2E 步骤附近出现 continue-on-error（失败会被吞掉）")

print("== [2] runner 确实调用聚合器（没改成别的不完整入口） ==")
if re.search(r"bash ci/e2e-all\.sh", strip_comments(runner)):
    ok("run-e2e-ci.sh 调用 ci/e2e-all.sh 汇总十域")
else:
    bad("run-e2e-ci.sh 不再调用 e2e-all.sh，聚合结论可能缺失")

print("== [3] 聚合器把 [skip] 判为失败（跳过 ≠ 通过） ==")
m = re.search(r'if \[ "\$SKIPPED" -eq 1 \]; then([\s\S]*?)\nfi', agg)
if not m:
    bad("提取不到 SKIPPED 汇总分支（判据塌成空）")
elif re.search(r"^\s*exit 1\s*$", m.group(1), re.M):
    ok("SKIPPED 分支非零退出")
else:
    bad("SKIPPED 分支没有 exit 1（曾写成 exit 0，实例挂掉后 CI 照样绿）")

print("== [4] 各域「整域 skip」不得 exit 0（单独挂进 CI 也不能恒绿） ==")
m = re.search(r"SCRIPTS=\(([^)]*)\)", agg, re.S)
if not m:
    bad("提取不到 SCRIPTS 数组")
    names = []
else:
    names = [x for x in re.split(r"\s+", m.group(1).strip()) if x]
if len(names) < 8:
    bad(f"从 SCRIPTS 只提取到 {len(names)} 个域（扫描塌成空，绝不能当作通过）")
else:
    ok(f"从 SCRIPTS 提取到 {len(names)} 个域")

checked = 0
for name in names:
    t = read(f"ci/{name}.sh")
    if not t:
        continue
    for sm in re.finditer(r'say "\[skip\][^\n]*\n((?:.*\n){0,3})', t):
        # ⚠ 必须先剔注释：说明性注释里常写「exit 0 会恒绿」这类反例文字，
        #   不剔就会把它当成真实指令误判（本仓同款教训：判据指向注释 = 假红/假绿）。
        block = "\n".join(
            l for l in sm.group(0).splitlines() if not l.lstrip().startswith("#")
        )
        em = re.search(r"\bexit\s+(\d+)", block)
        if not em:
            bad(f"{name}: [skip] 后 3 行内没有 exit（可能落回默认 0）")
        elif em.group(1) == "0":
            bad(f"{name}: 整域 [skip] 仍 exit 0 ⇒ 恒绿")
        else:
            checked += 1
if checked:
    ok(f"{checked} 处整域 [skip] 均为非零退出")
else:
    bad("没有提取到任何整域 [skip] 判据（扫描塌成空）")

if fail:
    print("✗ check_e2e_wired：E2E 接线或 skip 语义未通过")
    sys.exit(1)
print("PASS：零 root E2E 已接入 CI，且跳过不会被当作通过")
sys.exit(0)
