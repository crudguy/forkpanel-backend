#!/usr/bin/env python3
"""发布流水线的接线守卫（报告 §3.10 P1 / §4.2 G11）。

背景：`release.yml` 此前**没有**灰度、没有发布后冒烟、没有回滚路径（评审原文：
全文 grep `rollback|smoke|canary|灰度` 0 命中）。发版是一次性全量：本地验完就上传，
上传完就可见。上传环节出错（漏传资产 / 0 字节 / 改名）只能等用户 `get-panel.sh`
验签失败才发现，而那时资产已经对所有人可见。

本守卫钉住四件事的**接线**（行为由 `ci/verify-release-smoke.sh` 的负向对照覆盖）：
  [1] 上传先落 draft（用户不可见），且存在唯一的 `--draft=false` 转正动作
  [2] 发布后冒烟排在上传**之后**、转正**之前**（顺序错了两头都白做）
  [3] 失败时把 Release 按回 draft（自动回滚），且这条带 `if: failure()`
  [4] 产物新鲜度判据排在上传之前（防「构建失败但 dist 里残留上一轮包」）
  [5] 冒烟脚本与用户侧同源：`dgst -verify` + 仓库公钥，不是本地 dist 自验
  [6] `deploy/dist` 必须在 .gitignore 里（产物是构建输出，不该入库）
  [7] 产物完整性门禁真的挂在 `make guards` 上

恒绿纪律：判据剔注释（release.yml 的注释里就写着 draft/smoke/回滚这些词，
不剔会让注释冒充实现）；顺序判据一律用 `find` 出 -1 即判红，不做「找到了就过」。

用法：python3 ci/check_release_pipeline.py [仓库根目录]
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


wf = read(".github/workflows/release.yml")
smoke = read("ci/release-smoke.sh")
mk = read("Makefile")
gi = read(".gitignore")
if fail:
    print("✗ check_release_pipeline：前提不成立（有文件读不到）")
    sys.exit(1)

wf_code = strip_comments(wf)
smoke_code = strip_comments(smoke)

p_draft = wf_code.find("draft: true")
p_smoke = wf_code.find("ci/release-smoke.sh")
p_promote = wf_code.find("--draft=false")
p_rollback = wf_code.find("--draft=true")
p_fresh = wf_code.find("产物新鲜度")
p_failure = wf_code.find("if: failure()")

print("== [1] 上传先落 draft，且只有一个转正动作 ==")
if p_draft < 0:
    bad("没有 `draft: true`：Release 一上传就对用户可见，冒烟再失败也来不及")
else:
    ok("上传步骤带 draft: true")
n_promote = len(re.findall(r"--draft=false", wf_code))
if n_promote == 1:
    ok("转正动作恰好 1 处（--draft=false）")
elif n_promote == 0:
    bad("没有转正动作：Release 永远是草稿，用户下不到")
else:
    bad(f"转正动作有 {n_promote} 处，应恰好 1 处（多处会让回滚语义不清）")

print("== [2] 冒烟排在上传之后、转正之前 ==")
if p_smoke < 0:
    bad("找不到 ci/release-smoke.sh 的调用")
elif p_draft < 0 or p_promote < 0:
    bad("上传或转正步骤缺失，顺序判据无法得出结论")
elif p_draft < p_smoke < p_promote:
    ok("顺序正确：draft 上传 → 冒烟 → 转正")
else:
    bad(f"顺序错误（draft@{p_draft} smoke@{p_smoke} promote@{p_promote}）："
        "冒烟必须夹在上传与转正之间")

print("== [3] 失败时把 Release 按回 draft（自动回滚） ==")
if p_rollback < 0:
    bad("没有 `--draft=true` 回滚动作：冒烟失败后坏包仍对用户可见")
elif p_failure < 0:
    bad("回滚步骤没有 `if: failure()`：正常路径也会执行，等于每次发版都撤销")
elif p_failure < p_rollback:
    ok("回滚动作在 `if: failure()` 步骤内")
else:
    bad("`if: failure()` 出现在回滚动作之后，说明它们不在同一步骤")

print("== [4] 产物新鲜度判据在上传之前 ==")
if p_fresh < 0:
    bad("没有「产物新鲜度」步骤：dist 里的上一轮残留会被当成本次产物发出去")
elif p_draft >= 0 and p_fresh > p_draft:
    bad("新鲜度检查排在上传之后：包已经可见了才判红，没有意义")
else:
    ok("新鲜度检查在上传之前")
if p_fresh >= 0 and "stat -c %Y" not in wf_code:
    bad("新鲜度判据没用 mtime（找不到 `stat -c %Y`）：可能只判了文件存在")
elif p_fresh >= 0:
    ok("用 mtime 比对，而非只判存在")

print("== [5] 冒烟脚本与用户侧同源 ==")
for needle, desc in [
    ("openssl dgst -verify", "验签命令与 get-panel.sh 完全相同（dgst -verify）"),
    ("deploy/release-pubkey.pub", "用仓库内嵌公钥，而不是本地 dist 自验"),
    ("sha256sum -c SHA256SUMS", "逐行校验摘要，不是只判文件在不在"),
    ("panel --version", "真的跑二进制并比对版本号"),
    ("file -b", "判定二进制架构"),
]:
    if needle in smoke_code:
        ok(desc)
    else:
        bad(f"冒烟脚本缺判据：{desc}（找不到 `{needle}`）")
# 负向保护：冒烟不能变成「拿本地 dist 自验」——那与上传环节无关，等于没验发布结果
if "sha256sum -c dist/" in smoke_code or "openssl dgst -verify \"$ROOT/deploy/release-pubkey.pub\" -signature dist/" in smoke_code:
    bad("冒烟脚本在校验本地 dist：那样验的是「我打算发什么」，不是「用户能下到什么」")
else:
    ok("冒烟对象是下载回来的资产，不是本地 dist")

print("== [6] deploy/dist 不入库 ==")
# 产物是 4.7MB×2 的二进制，入库会永久拖大仓库且无法 diff。.gitignore 里漏了它，
# 某次 `git add -A` 就会把它们提交进去。
if re.search(r"^\s*/?deploy/dist/?\s*$", gi, re.M):
    ok(".gitignore 忽略了 deploy/dist")
else:
    bad(".gitignore 未忽略 deploy/dist（产物可能被 git add -A 提交进仓库）")

print("== [7] 产物完整性门禁挂在 make guards 上 ==")
m_guards = re.search(r"^guards:\n((?:\t.*\n|\n)*)", mk, re.M)
if not m_guards:
    bad("Makefile 找不到 guards 目标")
else:
    body = m_guards.group(1)
    if "check_release_artifacts.sh" in body:
        ok("guards 里调用了 ci/check_release_artifacts.sh")
    else:
        bad("guards 未调用 ci/check_release_artifacts.sh —— 门禁写好也不会跑")

if fail:
    print("✗ check_release_pipeline：发布流水线接线未通过")
    sys.exit(1)
print("PASS：draft 上传 → 冒烟 → 转正 → 失败回滚 的接线完备，且产物门禁在跑")
