#!/usr/bin/env python3
"""首启引导窗口的「脚本前置检查 + nginx 层 deny」双保险源码守卫（上线阻断项 P0）。

背景：官方安装不建 owner，首个 owner 走 Web 首启向导；而 bootstrap-token 端点
只校验 TCP peer 是否 loopback。官方公网暴露脚本从 127.0.0.1 反代 ⇒ 到达面板的
peer 恒为回环，公网请求会被当成「本机可信」。若先开反代再首启，白名单网段内
任何人都能取到一次性令牌并抢注 owner（面板以 root 运行，内置终端等价 root shell）。

两层防护缺一不可，且行为 E2E 只在 userns 里手工跑（不进 make check），故必须
用源码级守卫钉住接线：
  ① expose-public.sh 在写任何配置前探测 /api/v1/auth/status，且 fail-closed；
  ② 生成的 nginx 配置对 /api/v1/auth/bootstrap* 加 deny all（不依赖运行时状态）。

恒绿纪律：先断言提取块非空再判内容；剔注释；判据指向被检查的那份文件；
E2E 与文档的对应场景也在判据内，删掉任一环都判红。

用法：python3 ci/check_expose_bootstrap.py [仓库根目录]
"""
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
EXPOSE = "deploy/expose-public.sh"
E2E = "ci/e2e-expose-public.sh"
DOC = "docs/deployment.md"

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


def between(text, start, end):
    i = text.find(start)
    if i < 0:
        return ""
    j = text.find(end, i + len(start))
    return text[i:j] if j >= 0 else ""


s = read(EXPOSE)
e = read(E2E)
d = read(DOC)
if fail:
    print("✗ check_expose_bootstrap：前提不成立")
    sys.exit(1)

print("== [1] 探测块存在且非空（结构精确包裹，防「整份文件搜关键词」恒绿） ==")
blk = between(s, "# ── ②' 首启初始化状态", "# ── ③ 证书")
if blk.strip():
    code = strip_comments(blk)
    ok("能提取「首启状态探测」到「证书」之间的独立代码块")
else:
    code = ""
    bad("提取不到首启状态探测块（被删/被改名/标记行变了都会让判据塌成空）")

print("== [2] 探测必须打真实状态端点，且判据不可信时 fail-closed ==")
if code.count("/api/v1/auth/status") >= 1 and "need_cmd curl" in code:
    ok("块内向 /api/v1/auth/status 发 curl 且显式要求 curl 存在")
else:
    bad("块内缺少对 /api/v1/auth/status 的 curl 探测或 need_cmd curl")
if 'case "$STATUS_COMPACT" in' in code and 'needs_bootstrap":false' in code and "*) die" in code:
    ok("只有拿到明确的 needs_bootstrap:false 才放行，其余一律 die")
else:
    bad("缺少 case 判据或 *) die 兜底（放行未初始化 = 抢注 root 面板）")

print("== [3] nginx 模板必须封死两条引导端点（块内判据） ==")
i = s.find("    location ^~ /api/v1/auth/bootstrap {")
j = s.find("    }", i) if i >= 0 else -1
nginx_blk = s[i:j] if i >= 0 and j >= 0 else ""
if nginx_blk.strip():
    ng_code = strip_comments(nginx_blk)
    ok("能提取引导端点 location 块")
else:
    ng_code = ""
    bad("提取不到引导端点 location 块")
if "deny all;" in ng_code:
    ok("引导端点块内确有 deny all（不是命中 server 级白名单那条）")
else:
    bad("引导端点块内没有 deny all")

print("== [4] E2E 必须有能区分两种实现的负向场景 ==")
for needle, desc in [
    ('"needs_bootstrap":true', "未初始化必须拒绝"),
    ("CURL_FAIL=1", "状态探测失败必须拒绝"),
    ("boot_block", "块级断言（不能只搜整份文件的 deny all）"),
    ("引导端点块内必须 deny all", "nginx 块内 deny 断言"),
]:
    if needle in e:
        ok(f"E2E 含场景：{desc}")
    else:
        bad(f"E2E 缺少场景：{desc}（{needle}）")

print("== [5] 部署文档同步（手写 nginx 示例同样要带 deny） ==")
if "needs_bootstrap=false" in d and "location ^~ /api/v1/auth/bootstrap" in d:
    ok("deployment.md 写明前置条件与手写示例的 deny 块")
else:
    bad("deployment.md 缺前置条件或手写示例的 deny 块，运维照抄会漏")

if fail:
    print("✗ check_expose_bootstrap：首启窗口双保险接线未通过")
    sys.exit(1)
print("PASS：首启引导窗口的脚本前置检查与 nginx deny 均已接线")
sys.exit(0)
