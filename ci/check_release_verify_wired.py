#!/usr/bin/env python3
"""发版签名回验的接线守卫（上线阻断项 B3 的工程部分）。

背景：验签是安装 / 升级 / 镜像三条链路的唯一信任根。仓库曾对「内嵌公钥是演示
密钥还是正式密钥」自相矛盾，且已存在用其签名的可安装资产；靠人判断不可靠。
工程侧的解法不是替维护者断言密钥身份，而是让**每次发版都用用户侧那把公钥回验**，
密钥错配 / 篡改 / 资产缺失当场判红。守卫负责钉住这条接线不退化：
  ① release.yml 剔注释后恰好 1 处调用 ci/verify-release-assets.sh；
  ② 该调用在上传 Release **之前**（发布后再验已经晚了）；
  ③ 回验脚本与用户侧同源（dgst -verify + 安装器内嵌公钥），不是私钥导出公钥自验；
  ④ 宣发口径全仓钉死版本 tag：任何文件都不许宣传从 main 实时取脚本 URL
     （含两步法 wget -O；脚本里内嵌公钥，取脚本即取信任根），同时保留
     $TAG 取脚本样板，防止「删光安装指引也恒绿」。

恒绿纪律：判据剔注释、提取先断言非空、直接盯被检查的那份文件。

用法：python3 ci/check_release_verify_wired.py [仓库根目录]
"""
import os
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
vs = read("ci/verify-release-assets.sh")
if fail:
    print("✗ check_release_verify_wired：前提不成立")
    sys.exit(1)

wf_code = strip_comments(wf)
vs_code = strip_comments(vs)

print("== [1] release.yml 真的调用回验脚本（剔注释后恰好 1 处） ==")
hits = re.findall(r"^\s*run:\s*bash ci/verify-release-assets\.sh", wf_code, re.M)
if len(hits) == 1:
    ok("发版流水线有且仅有 1 条回验步骤")
else:
    bad(f"回验步骤应恰好 1 处，实得 {len(hits)}（删了/写进注释/重复都算异常）")

print("== [2] 回验必须排在上传 Release 之前 ==")
p_call = wf_code.find("run: bash ci/verify-release-assets.sh")
p_upload = wf_code.find("softprops/action-gh-release")
if p_call < 0 or p_upload < 0:
    bad("找不到回验调用或上传步骤，顺序判据无法得出结论")
elif p_call < p_upload:
    ok("回验步骤在 softprops/action-gh-release 之前")
else:
    bad("回验排在上传之后（资产已可被下载，验出问题也来不及）")

print("== [3] 回验脚本与用户侧同源，不是「私钥导出公钥」自验 ==")
for needle, desc in [
    ("openssl dgst -verify", "使用与 get-panel.sh 相同的 dgst -verify"),
    ("deploy/get-panel.sh", "公钥取自安装器内嵌的 RELEASE_PUBKEY"),
    ("release-pubkey.pub", "同时核对升级链的公钥"),
    ("SHA256SUMS", "校验摘要清单"),
]:
    if needle in vs_code:
        ok(desc)
    else:
        bad(f"回验脚本缺判据：{desc}（{needle}）")
if "-pubout" in vs_code or "pkey -in" in vs_code:
    bad("回验脚本出现从私钥导出公钥（自己跟自己比 ⇒ 密钥错配时恒绿）")
else:
    ok("没有从私钥导出公钥的自验路径")
if "amd64" in vs_code and "arm64" in vs_code:
    ok("双架构都有判据")
else:
    bad("双架构判据不完整")

print("== [4] 宣发口径：全仓零 main 分支实时 URL，且保留钉死 tag 的取脚本方式 ==")
# ⚠ 这条**必须读原始 wf（含注释）**：release.yml 的用户侧安装说明本来就写在
#   文件头注释里，若沿用 wf_code（已剔注释），判据永远看不到目标 ⇒ 恒绿。
#   「断言前剔注释」是为了防注释里的假调用冒充真指令，不是所有判据都该剔。
if re.search(r"main/deploy/get-panel\.sh\s*\|\s*sh", wf):
    bad("release.yml 仍在宣传 curl | sh 从 main 取脚本（取脚本即取内嵌公钥）")
else:
    ok("release.yml 没有 curl | sh 从 main 取脚本")

# 4b) 两步法同样不能从 main 取：脚本内嵌公钥，取脚本即取信任根。
#     全仓扫描（排除构建产物 / 版本库 / 会话工作区里的负向对照快照），
#     新增任何文件漏写这条 URL 都会当场判红，不靠人工维护文件清单。
BAD_URL = "raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh"
SKIP_DIRS = {".git", "target", "node_modules", "dist", "coverage", ".workbuddy", ".idea", "web"}
SELF = "ci/check_release_verify_wired.py"  # 本文件含 BAD_URL 作判据，跳过自身
leaks = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        rel = (Path(dirpath) / fn).relative_to(ROOT).as_posix()
        if rel == SELF:
            continue
        try:
            text = (ROOT / rel).read_text()
        except (UnicodeDecodeError, OSError):
            continue
        if BAD_URL in text:
            leaks.append(rel)
if leaks:
    bad(f"仍有 {len(leaks)} 个文件宣传 main 分支实时 URL：{', '.join(sorted(leaks))}（须钉死版本 tag）")
else:
    ok("全仓无 main 分支实时取脚本 URL")

# 4c) 正向断言：钉死 tag 的取脚本样板必须还在，防止「把安装指引删光也绿」。
#     判据认 $TAG 变量而非具体版本号——以后发新版不必改守卫。
for rel in [".github/workflows/release.yml", "README.md", "docs/distribution.md",
            "docs/deployment.md", "deploy/get-panel.sh", "crates/panel-cli/src/main.rs"]:
    t = read(rel)
    if "$TAG/deploy/get-panel.sh" in t:
        ok(f"{rel} 保留钉死 tag（$TAG）取脚本 URL")
    else:
        bad(f"{rel} 缺 $TAG 取脚本 URL——删光安装指引也会让 4b 恒绿")

if fail:
    print("✗ check_release_verify_wired：发版签名回验接线未通过")
    sys.exit(1)
print("PASS：发版前用用户侧公钥回验已接线，且排在上传之前")
sys.exit(0)
