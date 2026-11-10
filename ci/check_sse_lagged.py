#!/usr/bin/env python3
"""SSE 任务流 `RecvError::Lagged` 不关流的接线守卫（生产就绪度 P1 §8-6）。

背景：`while let Ok(ev) = bus_rx.recv().await` 会把慢消费者的 `Lagged`
当成流结束——客户端静默失联、任务终态事件丢失，只能靠 EventSource 自动重连。
修复分三层，守卫必须逐层钉住，否则极易退化成恒绿：

  ① 分类：`RecvError::Lagged(n)` → `TaskRecvStep::Lagged(n)`（不是 Closed）；
  ② **循环**：Lagged 分支必须 `continue` + 响亮记日志，绝不能 `break`；
     只测纯分类函数挡不住有人把 loop 里的分支改回 break —— 那是恒绿判据；
  ③ **接线**：`task_stream` 必须真的调用可测的 `task_event_stream`，
     且行为测试用真实小容量 broadcast 通道跑流（不是源码字符串镜像）。

恒绿纪律：判据剔注释、切生产段前断言 `#[cfg(test)]` 恰好 1 处、
函数体用括号配对提取（不用「下一个 fn」巧合锚点）、提取为空即判红。

用法：python3 ci/check_sse_lagged.py [仓库根目录]
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


def strip_comments(line: str) -> str:
    """剥离行尾 // 注释（引号感知，避免误截字符串里的 //）。"""
    quote = ""
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            return line[:i]
        i += 1
    return line


def extract_block(text: str, brace_at: int) -> str:
    """从 `{` 位置做括号配对，返回整块文本（含首尾括号）。"""
    depth = 0
    for i in range(brace_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_at:i + 1]
    return ""  # 不配平 ⇒ 判据塌空，必须判红（语法错误 cargo 也会先拦）


def fn_body(text: str, signature: str) -> str:
    i = text.find(signature)
    if i < 0:
        return ""
    j = text.find("{", i)
    return extract_block(text, j) if j >= 0 else ""


p = ROOT / "crates/panel-api/src/sse.rs"
if not p.is_file() or p.stat().st_size == 0:
    print("✗ check_sse_lagged：sse.rs 不存在或为空——提取前提不成立")
    sys.exit(1)
raw = p.read_text(encoding="utf-8")
makefile = ROOT / "Makefile"
mk = makefile.read_text(encoding="utf-8") if makefile.is_file() else ""

# ⚠ 切生产段的前提：全文件恰好一个尾部测试模块。
#   计数必须只认「行首独立成行」的属性：测试里既有注释也有
#   `src.split("#[cfg(test)]")` 字符串字面量，全文 count 会数出 3 个 ⇒ 恒红。
#   真加第二个测试模块（同样行首）仍会判红，不会退化成恒绿。
lines = raw.splitlines()
mod_lines = [i for i, l in enumerate(lines) if l.strip() == "#[cfg(test)]"]
if len(mod_lines) != 1:
    bad(f"sse.rs 行首 #[cfg(test)] 出现 {len(mod_lines)} 次（应为 1）——生产段提取前提不成立")
    sys.exit(1)
cut = mod_lines[0]
prod = "\n".join(strip_comments(l) for l in lines[:cut])
tests = "\n".join(lines[cut:])
if not prod.strip():
    bad("生产段为空——所有源码判据都会恒绿，必须判红")
    sys.exit(1)
ok("生产段提取成立（剔注释、尾部单测试模块）")

print("== [1] 分类：Lagged 不是流结束 ==")
body = fn_body(prod, "fn classify_task_recv(")
if not body:
    bad("提取不到 classify_task_recv 函数体")
else:
    for needle, desc in [
        ("Err(RecvError::Lagged(n)) => TaskRecvStep::Lagged(n)", "Lagged → Lagged(n)"),
        ("Err(RecvError::Closed) => TaskRecvStep::Closed", "Closed → Closed"),
        ("Ok(ev) => TaskRecvStep::Event(ev)", "Ok → Event"),
    ]:
        if needle in body:
            ok(desc)
        else:
            bad(f"classify 缺 {desc}（{needle}）")
    if "Lagged(n)" in body and "Lagged(n)) => TaskRecvStep::Closed" in body:
        bad("Lagged 被映射成 Closed——旧 bug 复活")
    else:
        ok("Lagged 未被误判为 Closed")

print("== [2] 接收循环：Lagged 分支 continue + 响亮留痕 ==")
body = fn_body(prod, "fn task_event_stream(")
if not body:
    bad("提取不到 task_event_stream 函数体（可测流不存在）")
else:
    if "classify_task_recv(bus_rx.recv().await)" in body:
        ok("循环走统一分类函数")
    else:
        bad("循环没调用 classify_task_recv（可能又写回 while let Ok）")
    if "while let Ok(" in body:
        bad("旧 `while let Ok(..) = recv()` 写法复活（吞 Lagged、关流）")
    else:
        ok("旧 while let Ok 写法已删除")
    if "yield Ok::<_, Infallible>" in body:
        ok("事件仍推送为 SSE 帧")
    else:
        bad("循环不再 yield 事件")
    if "TaskRecvStep::Closed => break" in body:
        ok("Closed 正常结束流")
    else:
        bad("缺 Closed => break（总线关闭会无限循环）")
    # 精确提取 Lagged 分支块：只看这一支，别被其它 continue 蒙混过关
    k = body.find("TaskRecvStep::Lagged(n) => {")
    arm = extract_block(body, body.find("{", k)) if k >= 0 else ""
    if not arm:
        bad("提取不到 Lagged 分支块（判据不能塌空）")
    else:
        if "continue" in arm:
            ok("Lagged 分支 continue（SSE 流保持存活）")
        else:
            bad("Lagged 分支没有 continue——等价于关流，#6 回归")
        if "break" in arm:
            bad("Lagged 分支出现 break——等价于关流，#6 回归")
        else:
            ok("Lagged 分支无 break")
        if "eprintln!" in arm and "{n}" in arm:
            ok("落后条数响亮记日志（不静默吞掉）")
        else:
            bad("Lagged 分支缺带条数的告警日志")

print("== [3] task_stream 接线：用的是抽出的可测流 ==")
body = fn_body(prod, "pub async fn task_stream(")
if not body:
    bad("提取不到 task_stream 函数体")
else:
    if "task_event_stream(bus_rx)" in body:
        ok("task_stream 调用 task_event_stream（行为测试测的就是生产这条流）")
    else:
        bad("task_stream 没接可测流——测试测的是另一份实现，恒绿")
    if "let _guard = conn;" in body and "inner.next().await" in body:
        ok("SseConnGuard 仍随 SSE body 流转移（客户端断开不泄漏计数）")
    else:
        bad("连接守卫接线丢失——计数只增不减会触发档位上限死锁")
n_calls = prod.count("classify_task_recv(bus_rx.recv().await)")
n_defs = prod.count("fn classify_task_recv(")
if n_calls == 1 and n_defs == 1:
    ok("生产段分类调用恰好 1 处、定义 1 处（无旁路内联副本）")
else:
    bad(f"生产段分类调用 {n_calls} 处 / 定义 {n_defs} 处（应各为 1）")
if "while let Ok(" in prod:
    bad("sse.rs 生产段仍有 `while let Ok(`（吞 Lagged 的旧写法）")
else:
    ok("sse.rs 生产段全无 `while let Ok(`")

print("== [4] 真行为判据：小容量真实通道 + 跑流 ==")
for needle, desc in [
    ("#[tokio::test]", "异步行为测试（不是纯文本断言）"),
    ("fn task_event_stream_survives_lagged", "Lagged 存活测试"),
    ("broadcast::channel::<panel_task::TaskEvent>(2)", "真实小容量 broadcast 通道"),
    ("s.next()", "真的 poll 流"),
    ("Lagged 之后流不得关闭", "落后后仍收到 SSE 帧"),
    ("Lagged 之后补发的事件必须仍被送达", "落后后补发事件仍送达"),
    ("drop(tx)", "总线关闭路径"),
    ("fn classify_task_recv_keeps_stream_alive_on_lagged", "分类测试"),
]:
    if needle in tests:
        ok(f"测试段含 {desc}")
    else:
        bad(f"测试段缺 {desc}（{needle}）——行为判据被删会恒绿")

print("== [5] 守卫自身必须在跑 ==")
if "ci/check_sse_lagged.py" in mk:
    ok("Makefile guards 已接线")
else:
    bad("Makefile guards 未调用本守卫（守卫存在≠在跑）")

if fail:
    print("✗ check_sse_lagged：SSE Lagged 接线未通过")
    sys.exit(1)
print("PASS：Lagged 不关流（分类 / 循环 / 接线 / 真行为测试四层齐全）")
sys.exit(0)
