#!/usr/bin/env python3
"""迁移回滚 / 跨进程锁 / 单实例护栏的接线守卫（生产就绪度 §3.6 / G9）。

三类事故：① 启动期 migrate 早于端口 bind，两个进程各自跑 DDL 会撞
`table already exists`；② 后台周期任务进程内计时，双实例重复备份/续期；
③ 025/029 是破坏性变更且没有 down migration，升级后旧二进制读不了新库。

修法：serve / migrate / init 共用 flock 单实例锁；真实升级前 VACUUM INTO
留一致快照作为回退锚点；文档写明「回滚 = 整库还原 + 换回旧二进制」。

恒绿纪律：判据剔注释、三处接线各自精确计数、直接盯被检查的那份文件。

用法：python3 ci/check_migrate_safety.py [仓库根目录]
"""
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
    return "\n".join(l for l in text.splitlines()
                     if not l.lstrip().startswith(("//", "///", "//!", "#")))


os_lib = read("crates/panel-os/src/lib.rs")
lock = read("crates/panel-os/src/instance_lock.rs")
main = read("crates/panel-cli/src/main.rs")
snap = read("crates/panel-cli/src/migrate_snapshot.rs")
serve = read("crates/panel-cli/src/cmd/serve.rs")
db = read("crates/panel-cli/src/cmd/db.rs")
init = read("crates/panel-cli/src/cmd/init.rs")
doc = read("docs/deployment.md")
if fail:
    print("✗ check_migrate_safety：前提不成立")
    sys.exit(1)

lock_code = strip_comments(lock)
snap_code = strip_comments(snap)

print("== [1] flock 单实例锁实现完整 ==")
if "pub mod instance_lock;" in strip_comments(os_lib):
    ok("panel-os/lib.rs 声明了 instance_lock 模块")
else:
    bad("panel-os/lib.rs 未声明 instance_lock（锁不会被编译）")
for needle, desc in [
    ("libc::LOCK_EX | libc::LOCK_NB", "非阻塞独占锁"),
    ("libc::EWOULDBLOCK", "冲突诊断"),
    ("libc::LOCK_UN", "释放/进程退出兜底"),
    ("impl Drop for InstanceLock", "RAII 显式解锁"),
]:
    if needle in lock_code:
        ok(f"含 {desc}")
    else:
        bad(f"instance_lock.rs 缺 {desc}（{needle}）")

print("== [2] 三条入口都接线（各恰好 1 处） ==")
if "mod migrate_snapshot;" in strip_comments(main):
    ok("main.rs 声明了 migrate_snapshot 模块")
else:
    bad("main.rs 未声明 migrate_snapshot（升级快照不会被编译）")
for label, src in [("serve.rs", serve), ("cmd/db.rs migrate", db), ("cmd/init.rs init", init)]:
    code = strip_comments(src)
    for needle, desc in [
        ("instance_lock::acquire(", "实例锁"),
        ("snapshot_before_migrate(", "升级前快照"),
    ]:
        n = code.count(needle)
        if n == 1:
            ok(f"{label} 接了 {desc}")
        else:
            bad(f"{label} 的 {desc} 应恰好 1 处，实得 {n}（漏一路就是并发/无锚点升级）")

print("== [3] 快照只在真实升级时生成且可裁剪 ==")
for needle, desc in [
    ("current == 0 || current >= latest", "新库/已最新跳过"),
    ("panel_db::backup_file(", "VACUUM INTO 一致快照"),
    ("prune_keep_newest(", "保留上限"),
    ("SNAPSHOT_KEEP: usize = 5", "保留 5 份"),
]:
    if needle in snap_code:
        ok(f"migrate_snapshot.rs 含 {desc}")
    else:
        bad(f"migrate_snapshot.rs 缺 {desc}（{needle}）")

print("== [4] 兼容矩阵与回滚 runbook 已写明 ==")
for needle, desc in [
    ("## 7. schema 升级与回滚", "章节"),
    ("没有 down migration", "前向迁移事实"),
    ("025_server_notes.sql", "破坏性变更 025"),
    ("029_drop_api_tokens.sql", "破坏性变更 029"),
    ("030_audit_append_only.sql", "后向不兼容变更 030（旧码 prune_audit 无令牌会被触发器拒）"),
    ("panel restore-db", "整库还原步骤"),
    ("旧二进制", "旧码不能读新库"),
]:
    if needle in doc:
        ok(f"deployment.md 含 {desc}")
    else:
        bad(f"deployment.md 缺 {desc}（{needle}）")

print("== [5] 锁与快照都有真行为单测 ==")
for label, src, expect in [("instance_lock.rs", lock, 2), ("migrate_snapshot.rs", snap, 2)]:
    t = src.find("#[cfg(test)]")
    test_code = src[t:] if t >= 0 else ""
    n = test_code.count("#[test]")
    if n >= expect:
        ok(f"{label} 测试段有 {n} 个用例")
    else:
        bad(f"{label} 测试段只有 {n} 个用例（互斥/快照验证不足）")

if fail:
    print("✗ check_migrate_safety：迁移安全接线未通过")
    sys.exit(1)
print("PASS：单实例锁、升级前快照与回滚 runbook 均已接线")
sys.exit(0)
