#!/usr/bin/env python3
"""站点默认加固片段（`deploy/site-defaults.inc`）的边界与接线守卫。

背景：`render_nginx` 把一组常用配置内联进 `conf.d/panel-<host>.conf` 的主
server 块。这个片段有两条容易静默退化的路径：

  ① 改成运行时 `include <外部文件>` —— build-static.sh 只打包三件脚本，漏拷贝
     就会让 nginx -t 失败、所有站点下发不了；且站点行为依赖外部文件后，
     conf_snapshot 指纹与 site_conf_versions 版本链都记不下这份依赖。
  ② 往默认集合里「顺手加一条」—— CORS / CSP / HSTS / gzip / X-Frame-Options /
     Permissions-Policy 都会改变或破坏用户应用，不能由面板替用户默认决定。

恒绿纪律：判据先剔注释（.inc 里有大段取舍说明与注释掉的可选示例，直接全文
grep 既会误伤也会漏判）；先断言「生效指令恰好三条且逐条精确」，再断言禁止项
在生效指令里为 0；接线三处一起钉（include_str! / render_nginx 调用 / Makefile
本守卫在跑），避免「守卫存在但不在跑」。

用法：python3 ci/check_site_defaults.py [仓库根目录]
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


def strip_hash_comments(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def strip_slash_comments(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))


inc = read("deploy/site-defaults.inc")
src = read("crates/panel-os/src/linux/providers/webserver.rs")
mk = read("Makefile")
if fail:
    print("✗ check_site_defaults：前提不成立")
    sys.exit(1)

inc_code = strip_hash_comments(inc)
src_code = strip_slash_comments(src)
mk_code = strip_hash_comments(mk)

EXPECTED = [
    "server_tokens off;",
    'add_header X-Content-Type-Options "nosniff" always;',
    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
]
FORBIDDEN = [
    "Access-Control-Allow", "Content-Security-Policy", "Strict-Transport-Security",
    "gzip", "X-Frame-Options", "Permissions-Policy", "include ",
]

print("== [1] 生效指令恰好三条，且逐条精确（新增前须评估兼容性） ==")
directives = [l.strip() for l in inc_code.splitlines() if l.strip()]
if directives == EXPECTED:
    ok("默认集合逐条精确：server_tokens / nosniff / Referrer-Policy")
else:
    bad(f"生效指令集合不符，实得 {directives!r}")

print("== [2] 禁止项不得以生效指令出现（注释里的说明与可选示例不算） ==")
for f in FORBIDDEN:
    hits = [d for d in directives if f.lower() in d.lower()]
    if hits:
        bad(f"默认片段含禁止项 {f!r}：{hits}")
    else:
        ok(f"不含 {f}")

print("== [3] 渲染器编译期内嵌 .inc（单一事实源，恰好一处） ==")
n = len(re.findall(r'include_str!\(\s*"[^"]*site-defaults\.inc"\s*\)', src_code))
if n == 1:
    ok("include_str! 指向 deploy/site-defaults.inc 恰好 1 处")
else:
    bad(f"include_str! 应恰好 1 处，实得 {n}")

print("== [4] render_nginx 真的调用 site_defaults_directives() ==")
start = src_code.find("pub(super) fn render_nginx")
end = src_code.find("pub(super) fn render_ws_map")
body = src_code[start:end] if start >= 0 and end > start else ""
if not body:
    bad("render_nginx 函数体提取前提不成立")
elif body.count("site_defaults_directives()") == 1:
    ok("render_nginx 内恰好 1 处调用")
else:
    bad(f"render_nginx 内调用次数应恰好 1，实得 {body.count('site_defaults_directives()')}")
n_all = src_code.count("site_defaults_directives()")
if n_all == 2:
    ok("全文件恰好 2 处（1 定义 + 1 调用），无第二份实现")
else:
    bad(f"全文件 site_defaults_directives() 应恰好 2 处，实得 {n_all}")

print("== [5] 绝不生成运行时 include（外部文件 = 分发依赖 + 版本链盲区） ==")
if re.search(r"include\s+[^\n]*site-defaults", src_code):
    bad("渲染器拼出了运行时 include 指令")
else:
    ok("渲染器没有 include site-defaults 指令")
if src_code.count("site-defaults.inc") == 1:
    ok("site-defaults.inc 在代码里只出现在 include_str! 那一处")
else:
    bad(f"site-defaults.inc 在剔注释后的代码里出现 {src_code.count('site-defaults.inc')} 次，应恰好 1")

print("== [6] 本守卫接进 Makefile guards（守卫存在 ≠ 守卫在跑） ==")
if "python3 ci/check_site_defaults.py" in mk_code:
    ok("Makefile guards 真的调用本守卫")
else:
    bad("Makefile 未调用 ci/check_site_defaults.py")

if fail:
    print("✗ check_site_defaults：站点默认加固边界/接线未通过")
    sys.exit(1)
print("PASS：默认三条内联于 server 块、无运行时 include、禁止项为零、守卫在跑")
sys.exit(0)
