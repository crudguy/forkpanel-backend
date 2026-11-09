#!/usr/bin/env python3
"""就绪探针 /healthz 的接线守卫（生产就绪度 P1 / G8）。

背景：/healthz 原先恒返回 "ok"（进程活着就 200），DB 写不进、盘满、调度器
停摆时仍报健康 ⇒ 前置 LB / 编排不会摘流量。现在它是依赖型就绪探针：
DB 可读 + 数据目录余量 ≥ 32 MiB 才 200，否则 503 且只回原因码。

两个容易回退的点，守卫必须钉住：
  ① serve 链必须注入 HealthState（否则又变回无依赖的恒 ok）；
  ② systemd 探活**必须继续打 /api/v1/version**：盘满重启解决不了问题，
     拿依赖型探针触发重启会退化成重启循环。

恒绿纪律：判据剔注释、提取前提先断言、探活判据只盯 URL 赋值行（源码里
测试断言本身含 "/healthz" 字样，全文扫会误判）。

用法：python3 ci/check_healthz.py [仓库根目录]
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
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("//", "///", "//!")))


embed = read("crates/panel-cli/src/embed.rs")
serve = read("crates/panel-cli/src/cmd/serve.rs")
boot = read("crates/panel-cli/src/bootstrap.rs")
doc = read("docs/deployment.md")
if fail:
    print("✗ check_healthz：前提不成立")
    sys.exit(1)

embed_code = strip_comments(embed)
serve_code = strip_comments(serve)

print("== [1] /healthz 做真实依赖检查，恒 ok 已删除 ==")
for needle, desc in [
    ("pub struct HealthState", "只读依赖注入结构"),
    ("pub fn evaluate_health(", "纯判定函数"),
    ("MIN_FREE_BYTES", "磁盘余量阈值"),
    ("SELECT 1", "DB 可读探测"),
    ("available_bytes(", "磁盘余量探测"),
    ("SERVICE_UNAVAILABLE", "异常返回 503"),
    ("no-store", "禁用缓存"),
]:
    if needle in embed_code:
        ok(f"含 {desc}")
    else:
        bad(f"embed.rs 缺 {desc}（{needle}）")
if '-> &\'static str { "ok" }' in embed_code:
    bad("embed.rs 仍存在恒 ok 的 healthz 实现（进程活着就 200）")
else:
    ok("恒 ok 实现已删除")

print("== [2] serve 链确实注入了 HealthState ==")
for needle, desc in [
    ("embed::HealthState {", "构造 HealthState"),
    ("pool: state.pool.clone()", "注入读连接池"),
    ("data_dir: health_data_dir", "注入数据目录"),
    ("embed::healthz(hs.clone())", "调用带状态的探针"),
]:
    if needle in serve_code:
        ok(desc)
    else:
        bad(f"serve.rs 缺 {desc}（{needle}）")
if 'axum::routing::get(embed::healthz)' in serve_code:
    bad("serve.rs 仍把无参 healthz 直接注册（没注入依赖）")
else:
    ok("不再直接注册无参 healthz")

print("== [3] systemd 探活仍打 /api/v1/version（防重启循环） ==")
i = boot.find("pub fn healthcheck_script(")
j = boot.find("/// 生成探活的 systemd", i)
body = boot[i:j] if i >= 0 and j > i else ""
if not body.strip():
    bad("提取不到探活脚本函数体（判据塌成空）")
else:
    url_lines = [l for l in body.splitlines() if "URL=" in l and "/api/" in l]
    if len(url_lines) == 1 and "/api/v1/version" in url_lines[0] and "healthz" not in url_lines[0]:
        ok("探活 URL = /api/v1/version（依赖型探针不用于触发重启）")
    else:
        bad(f"探活 URL 被改动或提取异常：{url_lines}")

print("== [4] 四态判定有单测，文档说明了用途边界 ==")
# ⚠ 必须只扫 #[cfg(test)] 之后的测试段：这四个符号在 healthz 实现里也出现，
#   全文 grep 会让「删掉整段单测」照样 PASS（判据指向错 ⇒ 恒绿）。
test_at = embed.find("#[cfg(test)]")
test_code = embed[test_at:] if test_at >= 0 else ""
if not test_code.strip():
    bad("提取不到 embed.rs 测试段（单测判据塌成空）")
else:
    for needle in ["HealthVerdict::DiskLow", "HealthVerdict::DiskUnknown",
                   "HealthVerdict::DbUnavailable", "HealthVerdict::Healthy"]:
        if needle in test_code:
            ok(f"单测覆盖 {needle.split('::')[-1]}")
        else:
            bad(f"embed.rs 测试段缺 {needle}")
# ⚠ 不能只搜「就绪探针」这个词：文档多处出现，删掉整个小节仍会命中 ⇒ 恒绿。
#   判据钉住小节标题与表格里独有的两行。
for needle, desc in [
    ("### 5.2.1 就绪探针", "就绪探针小节"),
    ("Cache-Control: no-store", "缓存策略说明"),
    ("db_unavailable", "503 原因码说明"),
    ("重启循环", "不用于 systemd 探活的理由"),
]:
    if needle in doc:
        ok(f"deployment.md 含 {desc}")
    else:
        bad(f"deployment.md 缺 {desc}（{needle}）——运维照旧配置会踩坑")

if fail:
    print("✗ check_healthz：就绪探针接线未通过")
    sys.exit(1)
print("PASS：/healthz 做真实就绪检查，systemd 探活保持 HTTP 活性判据")
sys.exit(0)
