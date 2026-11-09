#!/usr/bin/env python3
"""优雅关闭 + 同步出口超时的接线守卫（生产就绪度 P1 / G6）。

两类缺陷都是「代码写了但永远不生效 / 永远不返回」：
  ① serve 无 signal 处理，`sched.shutdown()` 写在 axum::serve().await 之后 ⇒
     正常运行期间永远执行不到；SIGTERM 直接杀进程，备份 / 站点下发 / SSE 硬断。
  ② panel_os::run_sync 同步 `read_to_string` 等 EOF 再 wait()，孙进程继承 stdout
     时永久钉住 spawn_blocking 线程，阻塞池耗尽后面板整体无响应。

恒绿纪律：判据剔注释、提取前提先断言、层序 / 代码顺序用下标比较，
直接盯被检查的那份文件（不在全仓 grep 到就算过）。

用法：python3 ci/check_graceful_shutdown.py [仓库根目录]
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
        bad(f"{rel} 不存在或为空——提取前提不成立")
        return ""
    return p.read_text()


def strip_comments(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("//", "///", "//!")))


cargo = read("Cargo.toml")
serve = read("crates/panel-cli/src/cmd/serve.rs")
sched = read("crates/panel-task/src/scheduler.rs")
cmd = read("crates/panel-os/src/cmd.rs")
if fail:
    print("✗ check_graceful_shutdown：前提不成立")
    sys.exit(1)

serve_code = strip_comments(serve)
sched_code = strip_comments(sched)
cmd_code = strip_comments(cmd)

print("== [1] tokio 启用 signal feature（否则信号层编译不过 / 被 cfg 掉） ==")
tokio_line = next((l for l in strip_comments(cargo).splitlines() if l.strip().startswith("tokio")), "")
if '"signal"' in tokio_line:
    ok("workspace tokio features 含 signal")
else:
    bad("Cargo.toml 的 tokio features 缺 signal（SIGTERM/SIGINT 无从接入）")

print("== [2] serve 链真的接了 graceful shutdown，且关闭动作排在其后 ==")
n = serve_code.count(".with_graceful_shutdown(shutdown_signal())")
if n == 1:
    ok("axum::serve 恰好一处 with_graceful_shutdown(shutdown_signal())")
else:
    bad(f"with_graceful_shutdown 应恰好 1 处，实得 {n}")
p_shut = serve_code.find(".with_graceful_shutdown(shutdown_signal())")
p_cancel = serve_code.find("sched_in.shutdown();")
p_drain = serve_code.find("sched_in.drain(")
if min(p_shut, p_cancel, p_drain) < 0:
    bad("关闭动作锚点缺失，顺序判据无法得出结论")
elif p_shut < p_cancel < p_drain:
    ok("serve 返回后才 cancel 调度器并 drain（顺序正确）")
else:
    bad(f"关闭顺序错误：shutdown={p_cancel} drain={p_drain} graceful={p_shut}")
for needle, desc in [
    ("SignalKind::terminate()", "SIGTERM handler"),
    ("tokio::signal::ctrl_c()", "SIGINT / Ctrl-C"),
    ("async fn shutdown_signal()", "信号等待函数定义"),
]:
    if needle in serve_code:
        ok(f"含 {desc}")
    else:
        bad(f"serve.rs 缺 {desc}（{needle}）")

print("== [3] 调度器保存 JoinHandle 并支持带上限的 drain ==")
for needle, desc in [
    ("pub async fn drain(", "drain 入口"),
    ("JoinHandle<()>", "任务句柄集合"),
    ("tokio::time::timeout(limit, join)", "drain 上限（不无限等后台 job）"),
]:
    if needle in sched_code:
        ok(f"含 {desc}")
    else:
        bad(f"scheduler.rs 缺 {desc}（{needle}）")

print("== [4] 同步出口自带超时、进程组 kill 与读线程上限 ==")
# 函数体提取用括号配对，不用「下一个函数名」当锚点——后者是巧合锚点：
# 锚点函数被删/改名/挪位时判据塌成空（truncate 被删时真实塌过一次）。
i = cmd_code.find("pub fn run_sync_with_timeout(")
if i < 0:
    body = ""
else:
    brace = cmd_code.find("{", i)
    depth = 0
    j = brace
    while j < len(cmd_code):
        if cmd_code[j] == "{":
            depth += 1
        elif cmd_code[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    # 注释已剥离；format! 的 {:?} 花括号成对，不干扰配对
    body = cmd_code[i:j + 1] if depth == 0 else ""
if not body.strip():
    bad("提取不到 run_sync_with_timeout 函数体（判据塌成空）")
else:
    ok("能提取同步出口函数体")
# 默认超时转发在 run_sync() 里，位于本函数体**之前**，不能放进 body 判据。
if "run_sync_with_timeout(bin, args, RUN_SYNC_TIMEOUT)" in cmd_code:
    ok("含 默认超时转发")
else:
    bad("缺 默认超时转发（run_sync 必须走带超时的实现）")
for needle, desc in [
    ("try_wait()", "非阻塞轮询"),
    ("libc::SIGKILL", "进程组 kill"),
    ("recv_timeout(", "读线程等待上限"),
    ("std::thread::spawn", "管道读取移出主线程"),
]:
    if needle in body:
        ok(f"含 {desc}")
    else:
        bad(f"同步出口缺 {desc}（{needle}）")
p_spawn = body.find("std::thread::spawn")
p_read = body.find("read_to_string")
if p_spawn >= 0 and p_read >= 0 and p_spawn < p_read:
    ok("read_to_string 在子线程内（主线程只按超时决策）")
else:
    bad(f"读线程顺序错误：spawn={p_spawn} read_to_string={p_read}")

if fail:
    print("✗ check_graceful_shutdown：优雅关闭 / 超时接线未通过")
    sys.exit(1)
print("PASS：SIGTERM 优雅关闭与 run_sync 超时均已接线")
sys.exit(0)
