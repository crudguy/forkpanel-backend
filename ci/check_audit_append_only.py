#!/usr/bin/env python3
"""审计日志 append-only 的接线守卫（production-readiness §3.5 P1，030 迁移）。

## 防什么
audit_log 此前没有任何强制机制：注释自称 append-only，但任何代码路径都能
UPDATE/DELETE 无痕改写（production-readiness §3.5 实测）。030 引入触发器 +
单行令牌表：UPDATE 全禁；DELETE 只放行 prune_audit 持 `_audit_permit` 令牌
的保留期修剪。

## 判据（三类恒绿防护）
1. 迁移文件、MIGRATIONS 注册、LATEST=30、触发器/令牌表 DDL 各自精确命中——
   少一环就是「守卫存在但防线没接线」；
2. prune_audit 必须持令牌（INSERT _audit_permit）且 RAII 回收
   （DELETE _audit_permit 在 Drop 里）；
3. 生产代码里 `DELETE FROM audit_log` / `UPDATE audit_log` 只允许出现在
   cleanup.rs 且钉死计数——别的文件出现即违例，cleanup.rs 里多一条也撞红；
4. doctor 必须有 audit_append_only 在位检查（触发器被 DROP 的唯一留痕点）。

判据剔注释、剥测试模块（ci/strip_tests.py 同约定）。
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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
    return p.read_text(encoding="utf-8")


def strip_comments_and_tests(text: str) -> str:
    lines = text.splitlines()
    cut = len(lines)
    for i, l in enumerate(lines):
        if l.strip().startswith("#[cfg(test)]"):
            cut = i
            break
    out = []
    for l in lines[:cut]:
        s = l.strip()
        if s.startswith(("//", "///", "//!")):
            continue
        out.append(l)
    return "\n".join(out)


def expect(text: str, needle: str, desc: str, count: int = 1):
    n = text.count(needle)
    if n == count:
        ok(f"{desc}（恰好 {count} 处）")
    else:
        bad(f"{desc}：期望 {count} 处、实际 {n} 处（{needle[:50]!r}）")


print("== [1] 030 迁移内容 ==")
mig = read("migrations/030_audit_append_only.sql")
if mig:
    expect(mig, "CREATE TABLE _audit_permit(permit INTEGER PRIMARY KEY)", "令牌表")
    expect(mig, "CREATE TRIGGER audit_append_only_no_update", "UPDATE 全禁触发器")
    expect(mig, "CREATE TRIGGER audit_append_only_no_delete", "DELETE 令牌门触发器")
    expect(mig, "WHEN NOT EXISTS (SELECT 1 FROM _audit_permit)", "DELETE 门只看令牌表")
    if mig.count("RAISE(ABORT") != 2:
        bad(f"两个触发器都必须 RAISE(ABORT)，实际 {mig.count('RAISE(ABORT')} 处")
    else:
        ok("两个触发器都 RAISE(ABORT)")

print("== [2] 迁移注册 ==")
migrs = read("crates/panel-db/src/migrate.rs")
if migrs:
    expect(migrs, 'include_str!("../../../migrations/030_audit_append_only.sql")', "030 已注册进 MIGRATIONS")
    expect(migrs, "pub const LATEST: u32 = 30;", "LATEST=30")

print("== [3] prune_audit 持令牌 ==")
clean = strip_comments_and_tests(read("crates/panel-db/src/cleanup.rs"))
if clean:
    expect(clean, "let _permit = PrunePermit::acquire(conn)?;", "prune_audit 持令牌")
    expect(clean, "INSERT INTO _audit_permit(permit) VALUES (1)", "令牌获取=INSERT 单行")
    expect(clean, "DELETE FROM _audit_permit WHERE permit = 1", "令牌回收在 Drop 里")

print("== [4] 生产代码里 audit_log 的删改只在 cleanup.rs ==")
crates = ROOT / "crates"
offenders = []
cleanup_deletes = 0
for p in sorted(crates.rglob("*.rs")):
    if "target" in p.parts or p.stem == "tests" or p.stem.endswith("_tests"):
        continue
    prod = strip_comments_and_tests(p.read_text(encoding="utf-8"))
    n_del = prod.count("DELETE FROM audit_log")
    n_upd = prod.count("UPDATE audit_log")
    if p.name == "cleanup.rs":
        cleanup_deletes = n_del
        if n_upd:
            offenders.append(f"{p.relative_to(ROOT)}: UPDATE audit_log x{n_upd}")
    elif n_del or n_upd:
        offenders.append(f"{p.relative_to(ROOT)}: DELETE x{n_del} UPDATE x{n_upd}")
if cleanup_deletes == 2:
    ok("cleanup.rs 恰好 2 处 DELETE FROM audit_log（按时间 + 按行数上限）")
else:
    bad(f"cleanup.rs 的 DELETE FROM audit_log 期望 2 处、实际 {cleanup_deletes} 处")
if offenders:
    for o in offenders:
        bad(f"越权删改：{o}")
else:
    ok("其他文件 0 处 audit_log 删改")

print("== [5] doctor 留痕检查 ==")
doc = strip_comments_and_tests(read("crates/panel-cli/src/doctor.rs"))
if doc:
    expect(doc, 'name: "audit_append_only"', "doctor 有 audit_append_only 检查", 3)
    expect(doc, "audit_append_only_no_update", "检查点名两个触发器")

if fail:
    print("✗ check_audit_append_only：审计 append-only 接线未通过")
    sys.exit(1)
print("PASS：审计 append-only（030 触发器 + 修剪令牌 + doctor 留痕）接线完整")
sys.exit(0)
