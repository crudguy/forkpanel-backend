#!/usr/bin/env python3
"""同步重 IO 不得留在 async 上下文（生产就绪度 P1 §8-10）。

背景：`std::fs::copy` 整个 SQLite 库、递归删/遍历解压目录这类操作耗时随数据量
增长，写在 `async fn` 里会钉住 tokio worker；更隐蔽的是 `tokio::time::timeout`
对一个不 yield 的 future **根本不会触发**，`panel-task` 的任务超时会变成假象。

#10 把这类 IO 收进 `panel_os::fs::blocking` / `tokio::task::spawn_blocking`。
本守卫钉住三件事：
  ① 服务进程的生产段里，async fn 内的内容类/递归类 `std::fs` 必须位于
     阻塞闭包内（按**括号配对**取调用区间，覆盖 `move || {}` 与 `move || expr`）；
  ② 微 IO（元数据级快操作）只允许白名单方法，且总数钉死 —— 新增一处必须
     回来复审并更新计数，不能悄悄长出来；
  ③ 出口本体、真行为超时测试、文档约定、本守卫接线都必须在位。

恒绿纪律：
  · 生产段用**括号配对剥 `#[cfg(test)]` 模块**（fs.rs 有 3 个中段测试模块，
    `split("#[cfg(test)]")` 会把后面半份生产代码一起砍掉 ⇒ 判据塌空恒绿）；
  · 注释与字符串内容先按位置抹成空格（保留偏移），哨兵字样不会误命中；
  · 扫描面自检：文件数 / async fn 数 / std::fs 总数低于阈值一律判红；
  · 未知方法 fail-closed（不在 HEAVY 也不在 MICRO ⇒ 违规）。

豁免面（写死在代码里，不靠人记）：
  · `crates/panel-cli/**`：CLI 与 `panel upgrade` 自带 runtime；Web 升级经
    systemd-run 拉**独立进程**，都不占用服务进程的 tokio worker；
  · 测试专用文件 `*/tests.rs` 与 `#[cfg(test)]` 模块。

用法：python3 ci/check_sync_io.py [仓库根目录]
"""
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
fail = 0

# 内容类 / 递归类：耗时随数据量增长 ⇒ 必须进 blocking 池
HEAVY = {
    "read", "write", "copy", "read_to_string", "remove_dir_all",
    "OpenOptions", "read_link", "canonicalize", "rename",
}
# 元数据级快操作：不读内容、不递归，包一层 blocking 只是多一次线程切换
MICRO = {
    "create_dir_all", "remove_file", "metadata", "read_dir", "set_permissions",
    "Permissions", "symlink_metadata",
}
MICRO_PIN = 26  # 2026-11-10 审定值；新增微 IO 须复审后同步改这里

SCAN_DIRS = ["crates/panel-api/src", "crates/panel-os/src",
             "crates/panel-task/src", "crates/panel-db/src",
             "crates/panel-core/src"]
BLOCKING_RE = re.compile(r"(?:spawn_blocking|(?:crate|panel_os)::fs::blocking)\s*\(")
ASYNC_FN_RE = re.compile(r"\basync\s+fn\s+(\w+)")
FS_RE = re.compile(r"std::fs::(\w+)")


def ok(msg):
    print(f"  ✓ {msg}")


def bad(msg):
    global fail
    print(f"  ✗ {msg}")
    fail = 1


def blank_non_code(s: str) -> str:
    """注释与字符串内容按位置抹成空格（保留换行与偏移）。"""
    out = list(s)
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            j = s.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and s[i + 1] == "*":
            j = s.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == '"':
            j = i + 1
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def match_brace(code: str, brace_at: int) -> int:
    depth = 0
    for i in range(brace_at, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(code) - 1


def production_segment(raw: str) -> str:
    """剥注释/字符串 + 按括号配对剥所有 `#[cfg(test)]` 模块。"""
    code = blank_non_code(raw)
    # 从后往前删，避免删掉前面的块后偏移失效
    starts = [m.start() for m in re.finditer(r"#\[cfg\(test\)\]", code)]
    for st in reversed(starts):
        brace = code.find("{", st)
        if brace < 0:
            continue
        end = match_brace(code, brace) + 1
        code = code[:st] + (" " * (end - st)) + code[end:]
    return code


def paren_spans(code: str) -> list[tuple[int, int]]:
    """阻塞调用的整段区间（覆盖 move || {} 与 move || expr 两种闭包）。"""
    spans = []
    for m in BLOCKING_RE.finditer(code):
        start = m.end() - 1
        depth = 0
        for i in range(start, len(code)):
            if code[i] == "(":
                depth += 1
            elif code[i] == ")":
                depth -= 1
                if depth == 0:
                    spans.append((start, i + 1))
                    break
    return spans


def async_fn_spans(code: str) -> list[tuple[int, int, str]]:
    spans = []
    for m in ASYNC_FN_RE.finditer(code):
        brace = code.find("{", m.end())
        if brace < 0:
            continue
        spans.append((brace, match_brace(code, brace) + 1, m.group(1)))
    return spans


def inside(pos: int, spans) -> bool:
    return any(a <= pos < b for a, b, *_ in spans)


# ── 扫描 ────────────────────────────────────────────────────────────────────
files: list[Path] = []
for d in SCAN_DIRS:
    files.extend(sorted((ROOT / d).rglob("*.rs")))
files = [f for f in files if f.is_file() and not f.name.endswith("tests.rs")]

violations: list[str] = []
micro_calls = 0
n_async_fn = 0
n_fs_total = 0
n_blocking = 0

for f in files:
    code = production_segment(f.read_text(encoding="utf-8"))
    if "std::fs::" not in code:
        continue
    fns = async_fn_spans(code)
    blocks = paren_spans(code)
    n_async_fn += len(fns)
    n_blocking += len(blocks)
    rel = str(f.relative_to(ROOT))
    for m in FS_RE.finditer(code):
        n_fs_total += 1
        pos = m.start()
        if not inside(pos, fns):
            continue  # 同步函数 / 已在阻塞池的辅助函数：不在本判据范围
        if inside(pos, blocks):
            continue  # 已在 spawn_blocking / fs::blocking 闭包内：合规
        meth = m.group(1)
        line = code.count("\n", 0, pos) + 1
        owner = next((name for a, b, name in fns if a <= pos < b), "?")
        if meth in HEAVY:
            violations.append(f"{rel}:{line} [{owner}] std::fs::{meth} —— 重 IO 必须进 blocking 池")
        elif meth in MICRO:
            micro_calls += 1
        else:
            violations.append(f"{rel}:{line} [{owner}] std::fs::{meth} —— 未登记方法（fail-closed）")

print("== [1] 扫描面自检（空集恒真防护） ==")
if len(files) < 50:
    bad(f"只扫到 {len(files)} 个 .rs（预期 ≥50）——扫描路径变了？")
else:
    ok(f"扫描 {len(files)} 个生产 .rs 文件")
if n_async_fn < 50:
    bad(f"只提取到 {n_async_fn} 个 async fn（预期 ≥50）——提取塌空")
else:
    ok(f"提取 {n_async_fn} 个 async fn、{n_blocking} 个阻塞闭包")
if n_fs_total < 100:
    bad(f"生产段只扫到 {n_fs_total} 处 std::fs（预期 ≥100）——判据可能失效")
else:
    ok(f"生产段共 {n_fs_total} 处 std::fs 调用纳入判定")

print("== [2] async 上下文不得直调重 IO ==")
if violations:
    for v in violations:
        bad(v)
    print("      改法：包进 `panel_os::fs::blocking(move || ...)` 或 `spawn_blocking`，")
    print("            见 crates/panel-os/src/fs.rs 的出口文档与 panel-api 的同步 IO 约定。")
else:
    ok("重 IO 全部位于 blocking 池（内容类 / 递归类 0 处裸调）")

print("== [3] 微 IO 白名单与计数钉死 ==")
if micro_calls == MICRO_PIN:
    ok(f"微 IO 恰好 {MICRO_PIN} 处，均为白名单方法（元数据级快操作）")
else:
    bad(f"微 IO 实得 {micro_calls} 处，钉死值 {MICRO_PIN}——新增/删除都要回来复审并同步 MICRO_PIN")

print("== [4] 出口 / 行为判据 / 文档 / 接线 ==")
outlet = ROOT / "crates/panel-os/src/fs.rs"
if outlet.is_file():
    prod = production_segment(outlet.read_text(encoding="utf-8"))
    if "pub async fn blocking" in prod and "tokio::task::spawn_blocking(f)" in prod:
        ok("出口 panel_os::fs::blocking 真的转发 spawn_blocking（不是空壳）")
    else:
        bad("出口缺 `pub async fn blocking` 或没转发 spawn_blocking——改成空实现会恒绿")
else:
    bad("出口文件不存在")

task_lib = ROOT / "crates/panel-task/src/lib.rs"
if task_lib.is_file() and "timeout_fires_when_heavy_io_is_offloaded" in task_lib.read_text(encoding="utf-8"):
    ok("panel-task 的超时真行为测试仍在（重 IO 让出 worker 后计时器必须触发）")
else:
    bad("缺 timeout_fires_when_heavy_io_is_offloaded（超时假象没有行为判据）")

lib_doc = ROOT / "crates/panel-api/src/lib.rs"
if lib_doc.is_file() and "ci/check_sync_io.py" in lib_doc.read_text(encoding="utf-8"):
    ok("crate 根同步 IO 约定已指向本机器判据")
else:
    bad("crate 根文档没写清判据来源（散文约定没有门禁兜底）")

mk = ROOT / "Makefile"
if mk.is_file() and "ci/check_sync_io.py" in mk.read_text(encoding="utf-8"):
    ok("make guards 已接线（守卫存在≠在跑）")
else:
    bad("make guards 未调用本守卫")

if fail:
    print("✗ check_sync_io：同步重 IO 门禁未通过")
    sys.exit(1)
print("PASS：async 上下文重 IO 全部卸载、微 IO 已登记、出口与超时行为判据齐全")
sys.exit(0)
