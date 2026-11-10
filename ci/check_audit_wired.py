#!/usr/bin/env python3
"""依赖安全审计的 CI 接线守卫（生产就绪度 P1 §8-11）。

背景：后端早有 `make audit` + 独立 audit job，但**从没真的跑过**（本机缺
cargo-audit）；前端 CI 连 audit job 都没有。装上工具后第一次真扫就抓到
`libsqlite3-sys` 的 CVE。修完漏洞还要防三类「看起来有、实际没在跑」：

  ① workflow 里删掉 `run: make audit` / 改成注释 / 加 `continue-on-error`
     ⇒ 失败被吞；加 `needs: check` ⇒ 主门禁红时审计被整条跳过；
  ② 命令里加 `--ignore` / `--audit-level` / `--prod` / `-D` /
     `--ignore-registry-errors` ⇒ 缩小范围或把网络错误判绿（恒绿）；
  ③ `ci/check-audit.sh` 在「找不到 cargo-audit」时不再 `exit 1`
     ⇒ 工具缺失被当成通过（跳过 ≠ 通过）。

恒绿纪律：剔整行注释、按 YAML 缩进精确提取 `audit:` job 块（提取为空即红）、
判据指向被检查的那两份 workflow / Makefile，并钉死本守卫自身已接进 guards。

用法：python3 ci/check_audit_wired.py [后端仓根目录] [前端仓根目录]
     前端仓缺省取 $PANEL_FRONTEND_ROOT 或 ../forkpanel-frontend；缺失判红。
"""
import os
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
FE = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(
    os.environ.get("PANEL_FRONTEND_ROOT", str(ROOT.parent / "forkpanel-frontend"))
)
fail = 0


def ok(msg):
    print(f"  ✓ {msg}")


def bad(msg):
    global fail
    print(f"  ✗ {msg}")
    fail = 1


def read(p: Path, label: str) -> str:
    if not p.is_file() or p.stat().st_size == 0:
        bad(f"{label} 不存在或为空（{p}）——提取前提不成立，绝不能当作通过")
        return ""
    return p.read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def job_block(text: str, name: str) -> str:
    """按 YAML 缩进提取 `  <name>:` 到下一个同级 job 之间的整块。"""
    lines = text.splitlines()
    start = next(
        (i for i, l in enumerate(lines) if re.match(rf"^  {re.escape(name)}:\s*$", l)),
        None,
    )
    if start is None:
        return ""
    end = next(
        (j for j in range(start + 1, len(lines))
         if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[j])),
        len(lines),
    )
    return "\n".join(lines[start:end])


def target_body(text: str, name: str) -> str:
    """提取 Makefile 目标的命令行（到下一个空行/目标为止）。"""
    m = re.search(rf"^{re.escape(name)}:[ \t]*[^\n]*\n((?:[ \t]+[^\n]*\n?)*)", text, re.M)
    return m.group(1) if m else ""


be_wf = strip_comments(read(ROOT / ".github/workflows/ci.yml", "后端 ci.yml"))
fe_wf = strip_comments(read(FE / ".github/workflows/ci.yml", "前端 ci.yml"))
be_mk = strip_comments(read(ROOT / "Makefile", "后端 Makefile"))
fe_mk = strip_comments(read(FE / "Makefile", "前端 Makefile"))
auditor = read(ROOT / "ci/check-audit.sh", "ci/check-audit.sh")
if fail:
    print("✗ check_audit_wired：前提不成立")
    sys.exit(1)

print("== [1] 两个仓库的 audit job 真的调用 make audit ==")
blocks = {}
for label, wf in [("后端", be_wf), ("前端", fe_wf)]:
    b = job_block(wf, "audit")
    if not b.strip():
        bad(f"{label} ci.yml 提取不到 audit job（判据不能塌空）")
        blocks[label] = ""
        continue
    blocks[label] = b
    n = len(re.findall(r"^\s*run:\s*make audit\s*$", b, re.M))
    if n == 1:
        ok(f"{label} audit job 恰好 1 条 `run: make audit`")
    else:
        bad(f"{label} audit job 的 `run: make audit` 应恰好 1 条，实得 {n}")

print("== [2] 失败不得被吞、审计不得被跳过、范围不得被缩小 ==")
forbidden = [
    ("continue-on-error", "continue-on-error（失败被吞）"),
    ("|| true", "|| true（失败被吞）"),
    ("needs:", "needs:（主门禁红时整条被跳过）"),
    ("if: false", "if: false"),
    ("--ignore", "--ignore / --ignore-registry-errors（放过漏洞或网络错误）"),
    ("--audit-level", "--audit-level（抬高阈值等于放过中低危）"),
    ("--no-fetch", "--no-fetch（不刷 advisory-db，用过期事实判绿）"),
    ("--prod", "--prod（只扫生产依赖）"),
    (" -D", " -D（只扫 devDependencies）"),
]
for label, b in blocks.items():
    if not b:
        continue
    hits = [desc for needle, desc in forbidden if needle in b]
    if hits:
        bad(f"{label} audit job 出现禁用写法：{', '.join(hits)}")
    else:
        ok(f"{label} audit job 无「吞失败 / 跳过 / 缩范围」写法")

print("== [3] 两端 Makefile 的 audit 目标接的是真门禁 ==")
be_target = target_body(be_mk, "audit")
fe_target = target_body(fe_mk, "audit")
if "bash ci/check-audit.sh" in be_target:
    ok("后端 make audit → ci/check-audit.sh")
else:
    bad(f"后端 audit 目标没调 ci/check-audit.sh：{be_target!r}")
if "pnpm audit" in fe_target and "corepack pnpm@10 audit" in fe_target:
    ok("前端 make audit 双路径齐全（CI 用 pnpm / 本机用 corepack）")
else:
    bad(f"前端 audit 目标缺 pnpm audit 或 corepack 兜底：{fe_target!r}")
# if/else 必须把失败码透传：不能出现 || true / exit 0 之类的兜底
if "|| true" in fe_target or "exit 0" in fe_target:
    bad("前端 audit 目标存在吞失败的兜底写法")
else:
    ok("前端 audit 目标不吞失败码")
# 网络隔离：audit 不并进主门禁（registry/advisory-db 抖动不该拖红 check）
for label, mk in [("后端", be_mk), ("前端", fe_mk)]:
    m = re.search(r"^check:\s*([^\n]*)$", mk, re.M)
    if m and "audit" in m.group(1):
        bad(f"{label} `check` 目标含 audit——网络抖动会连带拖红主门禁")
    elif m:
        ok(f"{label} audit 未并进 check（网络隔离）")
    else:
        bad(f"{label} Makefile 提取不到 check 目标（判据塌空）")

print("== [4] 工具缺失必须判红（跳过 ≠ 通过） ==")
m = re.search(r'if \[ -z "\$AUDIT_BIN" \]; then([\s\S]*?)\nfi', auditor)
if not m:
    bad("提取不到「找不到 cargo-audit」分支（判据塌空）")
elif re.search(r"^\s*exit 1\s*$", m.group(1), re.M):
    ok("找不到 cargo-audit 时 exit 1")
else:
    bad("找不到 cargo-audit 时没 exit 1——工具缺失会伪装成通过")
if re.search(r'out="\$\("\$AUDIT_BIN" audit 2>&1\)"', auditor):
    ok("主路径先联网刷新 advisory-db（不是一上来就 --no-fetch）")
else:
    bad("主路径不再先联网刷新（用过期 advisory 判绿）")

print("== [5] 守卫自身必须在跑 ==")
if "ci/check_audit_wired.py" in be_mk:
    ok("后端 Makefile guards 已接线")
else:
    bad("后端 Makefile guards 未调用本守卫（守卫存在≠在跑）")

if fail:
    print("✗ check_audit_wired：依赖审计 CI 接线未通过")
    sys.exit(1)
print("PASS：前后端 audit job / make audit / 工具缺失判红，接线完整且无恒绿旁路")
sys.exit(0)
