#!/usr/bin/env python3
"""站点配置下发「失败自动回滚」的接线守卫（生产就绪度 §3.3 S4 / G7）。

背景：旧链路 deploy（已落盘）→ prune 旧配置 → reload → 落库，reload 失败或
落库失败时直接返回，磁盘 / nginx 内存 / DB 三方分叉；下次 nginx 重启才突然
加载那份「失败」的配置。修法是在 deploy 前抓 `DeploySnapshot`，任一后续
步骤失败都 `rollback_after_failure`（恢复文件 + best-effort reload）。

恒绿纪律：判据剔注释、按文件精确计数（apply 必须恰好 2 处回滚：reload 失败
与落库失败；少一处就是漏了一条失败路径）、直接盯被检查的那份文件。

用法：python3 ci/check_site_rollback.py [仓库根目录]
      PANEL_FRONTEND_ROOT 可覆盖前端仓路径（默认 ../forkpanel-frontend）
"""
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
FE = Path(os.environ.get("PANEL_FRONTEND_ROOT") or (ROOT.parent / "forkpanel-frontend"))
fail = 0


def ok(msg):
    print(f"  ✓ {msg}")


def bad(msg):
    global fail
    print(f"  ✗ {msg}")
    fail = 1


def read(p: Path, label: str) -> str:
    if not p.is_file() or p.stat().st_size == 0:
        bad(f"{label} 不存在或为空——提取前提不成立，绝不能当作通过")
        return ""
    return p.read_text()


def strip_comments(text):
    return "\n".join(l for l in text.splitlines()
                     if not l.lstrip().startswith(("//", "///", "//!", "#")))


sites = read(ROOT / "crates/panel-api/src/routes/sites.rs", "sites.rs")
rb = read(ROOT / "crates/panel-api/src/routes/sites/rollback.rs", "rollback.rs")
apply = read(ROOT / "crates/panel-api/src/routes/sites/apply.rs", "apply.rs")
conf = read(ROOT / "crates/panel-api/src/routes/sites/conf.rs", "conf.rs")
client = read(FE / "src/api/client.ts", "client.ts")
client_test = read(FE / "src/api/client.test.ts", "client.test.ts")
if fail:
    print("✗ check_site_rollback：前提不成立")
    sys.exit(1)

apply_code = strip_comments(apply)
conf_code = strip_comments(conf)
rb_code = strip_comments(rb)

print("== [1] 回滚模块已声明并实现完整 ==")
if "mod rollback;" in strip_comments(sites):
    ok("sites.rs 声明了 mod rollback")
else:
    bad("sites.rs 未声明 mod rollback（回滚模块不会被编译）")
for needle, desc in [
    ("pub struct DeploySnapshot", "快照结构"),
    ("pub async fn capture(", "下发前抓取"),
    ("pub async fn restore(", "文件恢复"),
    ("pub async fn rollback_after_failure(", "统一收尾"),
    ("state.os.webserver().reload()", "恢复后 best-effort reload"),
]:
    if needle in rb_code:
        ok(f"rollback.rs 含 {desc}")
    else:
        bad(f"rollback.rs 缺 {desc}（{needle}）")

print("== [2] apply 的两条失败路径都回滚（恰好 2 处） ==")
for needle, desc, expect in [
    ("DeploySnapshot::capture(", "下发前抓快照", 1),
    ("rollback_after_failure(", "失败回滚调用", 2),
    # 定义 / deploy 分支赋值 / 落库失败读取 = 3 处；少一处说明快照没跨步骤传下去
    ("rollback_snapshot", "快照跨 deploy/落库传递", 3),
    ("db_result", "落库结果被接住", 2),
]:
    n = apply_code.count(needle)
    if n == expect:
        ok(f"apply.rs 的 {desc} 出现 {n} 处")
    else:
        bad(f"apply.rs 的 {desc} 应出现 {expect} 处，实得 {n}（漏一条失败路径也会恒绿）")

print("== [3] conf_put 三步骤包在同一个 outcome 里 ==")
for needle, desc, expect in [
    ("DeploySnapshot::capture(", "下发前抓快照", 1),
    ("rollback_after_failure(", "失败回滚调用", 1),
    ("let outcome:", "统一 outcome", 1),
]:
    n = conf_code.count(needle)
    if n == expect:
        ok(f"conf.rs 的 {desc} 出现 {n} 处")
    else:
        bad(f"conf.rs 的 {desc} 应出现 {expect} 处，实得 {n}")

print("== [4] 前端文案与测试断言同步 ==")
if "已自动回滚" in client or "已自动回滚" in client_test:
    bad("前端仍宣称「已自动回滚」（40002 实际是校验失败、根本没写盘）")
else:
    ok("前端不再谎报自动回滚")
if "未写入磁盘" in client and "未写入磁盘" in client_test:
    ok("client.ts 与 client.test.ts 文案同源")
else:
    bad("前端文案与测试断言不同步")

print("== [5] 回滚逻辑有真行为单测 ==")
t = rb.find("#[cfg(test)]")
test_code = rb[t:] if t >= 0 else ""
n = test_code.count("#[tokio::test]")
if n >= 3:
    ok(f"rollback.rs 测试段有 {n} 个 tokio 行为用例")
else:
    bad(f"rollback.rs 测试段只有 {n} 个 tokio 用例（旧内容/新文件/旧配置恢复三态未覆盖）")

if fail:
    print("✗ check_site_rollback：下发回滚接线未通过")
    sys.exit(1)
print("PASS：apply / conf_put 的失败路径均自动回滚，前端文案与实现一致")
sys.exit(0)
