#!/usr/bin/env python3
"""SPA / 静态资源安全响应头的接线守卫（生产就绪度 P1-2 / G5）。

背景：axum 的 `.layer()` 只包裹调用时已存在的路由与 fallback。安全头原先挂在
build_router 内，而生产链在 build_router 之后又加 `/healthz` 并用
`.fallback(embed::static_handler)` **替换**了 fallback ⇒ 登录页、JS/CSS、SPA 回退、
404、healthz 全部绕过安全头，形成「接口有防护、页面没防护」的错配；CatchPanic
转出的 500 同样漏掉。修法是把 security_headers 挪到 cmd/serve.rs 生产链的
`.fallback()` 之后、request_log 之内层（request_log 仍是最外层，唯一挂点守卫不变）。

恒绿纪律：判据剔注释（三份文件都有大段解释性注释，不剔会把说明文字当成挂点）、
提取前提先断言、顺序用源码出现下标比较（builder 调用顺序即层序）。

用法：python3 ci/check_security_headers.py [仓库根目录]
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
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("//", "///")))


serve = read("crates/panel-cli/src/cmd/serve.rs")
routes = read("crates/panel-api/src/routes.rs")
mid = read("crates/panel-api/src/middleware.rs")
if fail:
    print("✗ check_security_headers：前提不成立")
    sys.exit(1)

serve_code = strip_comments(serve)
routes_code = strip_comments(routes)
mid_code = strip_comments(mid)

print("== [1] 生产链恰好一个安全头挂点（防双挂 / 防漏挂） ==")
n = len(re.findall(r"from_fn\(\s*panel_api::middleware::security_headers", serve_code))
if n == 1:
    ok("cmd/serve.rs 内 security_headers 恰好 1 处（from_fn 包裹）")
else:
    bad(f"cmd/serve.rs 的安全头挂点应恰好 1 处，实得 {n}")
if "security_headers" in routes_code:
    bad("build_router 仍挂 security_headers ⇒ 双挂（且 SPA/healthz 依旧绕过）")
else:
    ok("build_router 生产段不再挂 security_headers（单一挂点）")

print("== [2] 挂点顺序：fallback 之后、request_log 之前 ==")
p_fb = serve_code.find(".fallback(embed::static_handler)")
p_sec = serve_code.find("panel_api::middleware::security_headers")
p_log = serve_code.find("panel_api::middleware::request_log")
if min(p_fb, p_sec, p_log) < 0:
    bad("三个锚点有缺失，顺序判据无法得出结论")
elif p_fb < p_sec < p_log:
    ok("fallback < security_headers < request_log（覆盖全部响应且日志仍最外层）")
else:
    bad(f"层序错误：fallback={p_fb} security_headers={p_sec} request_log={p_log}")

print("== [3] 安全头内容完整，且注释与实现一致 ==")
for needle, desc in [
    ('X_FRAME_OPTIONS', "X-Frame-Options"),
    ('REFERRER_POLICY', "Referrer-Policy"),
    ('Permissions-Policy', "Permissions-Policy"),
    ("frame-ancestors 'none'", "CSP 禁止被 iframe 嵌套"),
    ("script-src 'self'", "CSP 限同源脚本"),
    ('X_CONTENT_TYPE_OPTIONS', "nosniff"),
]:
    if needle in mid_code:
        ok(f"含 {desc}")
    else:
        bad(f"安全头实现缺 {desc}（{needle}）")
if "CSP 使用 nonce" in mid or "nonce 在渲染" in mid:
    bad("middleware.rs 仍有「nonce」不实注释（实现是静态 script-src 'self'）")
else:
    ok("CSP 注释与静态策略实现一致")

if fail:
    print("✗ check_security_headers：安全响应头接线未通过")
    sys.exit(1)
print("PASS：安全响应头挂在 fallback 之后且全链唯一，SPA/静态/healthz/404 均覆盖")
sys.exit(0)
