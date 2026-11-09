#!/usr/bin/env python3
"""外部告警接线守卫（报告 §3.5 / §4.2 G8）。

背景：告警是**最容易做成摆设**的一类功能——字段/文件/常量全都"在"，但没有一个
消费者。本次实现前实测到的现状正是如此：

  - 安装器生成了 `/etc/forkpanel/alert-webhook` 与 `panel-failure-notify.service`，
    `panel.service` 里也有 `OnFailure=` —— **崩溃**这一环是真的；
  - 但**业务事件**（备份失败 / 证书续期失败 / 内部周期任务失败）一个都没接：
    `webhook::fire` 全仓只有 cron 两处调用，失败只落 journald 与站内通知表。
    运维不看面板就永远不知道「备份已经连续失败一周」。

本守卫钉住**接线**，行为由单测（`alert::tests`）与 `ci/e2e-alert.sh` 真跑覆盖：

  [1] `serve` 启动链必须读配置（`AlertSink::load`）、必须给 **两条**主干接钩子
      （`TaskRunner` 任务失败 / `InternalScheduler` 周期任务失败），且把 sink
      注入 `AppState`（否则业务 handler 拿不到）
  [2] 失败事件名按任务种类**分别映射**（backup / cert_issue / 其它），
      不许全塞一个 `job.failed`——那样告警只说"有东西坏了"
  [3] 三个事件常量都必须有**定义处之外的引用**（防"先定义着备用"的死常量）
  [4] 钩子必须**真的被调用**，不是只被存起来：调度器在失败分支、
      runner 在终态失败分支各调一次
  [5] `backup.sweep` 的 Err 分支**不许吞**成 `Ok(())`：吞掉之后「每分钟扫描一直失败」
      完全静默，页面上的定时备份永远不触发却没有任何信号
  [6] shell 侧（崩溃告警）与 Rust 侧必须指向**同一个文件名**：两处各写一份
      路径，改名时必然只改一处

恒绿纪律（与 `check_key_hygiene.py` 同）：
  - 生产段一律剔注释 + 按大括号配对剥 `#[cfg(test)]`；
  - 提取为空 ⇒ 直接判红（空集会让"每处都满足"恒真）；
  - 匹配用 `re.escape` 后的字面量，避免正则元字符（`::`、`<`）带来的静默空转。

用法：python3 ci/check_alert_wiring.py [仓库根目录]
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


def strip_rust_comments(src: str) -> str:
    """剔掉 `//` 行注释与 `/* */` 块注释（保留字符串里的内容不动，本项目够用）。"""
    out = []
    for line in src.splitlines():
        out.append(re.sub(r"\s*//.*$", "", line))
    return re.sub(r"/\*.*?\*/", "", "\n".join(out), flags=re.S)


def strip_cfg_test_blocks(src: str) -> str:
    """按大括号配对整体剥掉 `#[cfg(test)]` 修饰的模块/函数。

    ⚠ 不能用 `rfind` 一刀切：一个文件里有多个测试模块时，最后一个之前的所有
    测试代码都会留在"生产段"里，于是判据匹配到的是测试夹具（实测踩过）。
    """
    while True:
        m = re.search(r"#\[cfg\(test\)\]", src)
        if not m:
            return src
        brace = src.find("{", m.end())
        semi = src.find(";", m.end())
        if semi != -1 and (brace == -1 or semi < brace):
            src = src[: m.start()] + src[semi + 1 :]
            continue
        if brace == -1:
            return src[: m.start()]
        depth = 0
        for j in range(brace, len(src)):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    src = src[: m.start()] + src[j + 1 :]
                    break
        else:
            return src[: m.start()]


def production(rel: str) -> str:
    p = ROOT / rel
    if not p.exists():
        bad(f"缺少文件 {rel}")
        return ""
    return strip_cfg_test_blocks(strip_rust_comments(p.read_text()))


def count(hay: str, needle: str) -> int:
    return hay.count(needle)


print("[1] serve 启动链：读配置 + 两条主干都接钩子 + 注入 AppState")
serve = production("crates/panel-cli/src/cmd/serve.rs")
if not serve.strip():
    bad("serve.rs 生产段提取为空（判据会恒真，按红处理）")
else:
    if count(serve, "alert::AlertSink::load(") < 1:
        bad("serve 没有调用 `AlertSink::load` —— /etc/forkpanel/alert-webhook 配了也没人读")
    else:
        ok("serve 读取告警配置")
    hooks = count(serve, "set_failure_hook(")
    if hooks < 2:
        bad(f"`set_failure_hook` 只出现 {hooks} 次，应为 2（TaskRunner + InternalScheduler）")
    else:
        ok(f"两条主干的失败钩子都已接（{hooks} 处）")
    # 注入 AppState：构造函数最后多一个 alert 实参（判据只认 `alert` 出现在 new(...) 里）
    m = re.search(r"AppState::new\((.*?)\)\)\s*;", serve, re.S)
    if not m:
        bad("找不到 `AppState::new(...)` 调用")
    elif "alert" not in m.group(1):
        bad("`AppState::new` 没收到 alert 参数 —— 业务 handler 拿不到通道")
    else:
        ok("告警通道已注入 AppState")

print("[2] 事件名按任务种类分别映射")
for const in ("BACKUP_FAILED", "CERT_FAILED", "JOB_FAILED"):
    if f"events::{const}" not in serve:
        bad(f"serve 未使用 `events::{const}` —— 事件分类退化")
    else:
        ok(f"事件 `{const}` 已接线")

print("[3] 事件常量必须有定义处之外的引用（防死常量）")
alert_rs = production("crates/panel-api/src/alert.rs")
if not alert_rs.strip():
    bad("alert.rs 生产段提取为空")
else:
    all_src = ""
    for rel in ("crates/panel-cli/src/cmd/serve.rs", "crates/panel-cli/src/cmd/alert.rs"):
        all_src += production(rel)
    for const in ("BACKUP_FAILED", "CERT_FAILED", "JOB_FAILED"):
        pat = rf'\bpub const {const}: &str = "([a-z0-9.]+)";'
        m = re.search(pat, alert_rs)
        if not m:
            bad(f"alert.rs 里找不到 `pub const {const}`")
            continue
        if const in all_src:
            ok(f"`{const}` = {m.group(1)!r} 有消费者")
        else:
            bad(f"`{const}` 定义了但没人用（死常量）")

print("[4] 钩子必须真的被调用（不是只被存起来）")
sched = production("crates/panel-task/src/scheduler.rs")
if "h(name, e.to_string())" not in sched:
    bad("scheduler.rs 保存了钩子却没在失败分支调用 —— 任务失败照样静默")
else:
    ok("调度器失败分支已调用钩子")
runner = production("crates/panel-task/src/lib.rs")
if "if outcome.state == TaskState::Failed" not in runner:
    bad("runner 没有按 `state == Failed` 判定 —— `Ok(TaskOutcome{Failed})` 型失败会漏")
elif not re.search(r"h\(id, rkind\.as_str\(\), detail\)", runner):
    bad("runner 判定失败但没调用钩子")
else:
    ok("任务终态失败已调用钩子")

print("[5] backup.sweep 不得把 Err 吞成 Ok")
m = re.search(r"sweep_due\(&state\)\.await\s*\{(.*?)\n                \}", serve, re.S)
if not m:
    bad("找不到 `sweep_due` 的 match 块（判据失锚，按红处理）")
else:
    block = m.group(1)
    idx = block.find("Err(e)")
    if idx == -1:
        bad("`sweep_due` 的 match 里看不到 Err 分支")
    else:
        # `Err` 是最后一个分支 ⇒ 从它截到块尾即可。**不要**写成
        # `Err\(e\)\s*=>\s*\{[^}]*Ok\(\(\)\)`：分支体里有 `format!("…{e}")`，
        # 那个 `}` 会让 `[^}]*` 提前断掉，判据于是永远匹配不到 —— 实测恒绿。
        tail = block[idx:]
        if "Ok(())" in tail:
            bad("`backup.sweep` 的 Err 分支返回 `Ok(())` —— 扫描一直失败也完全静默")
        else:
            ok("`backup.sweep` 保留 Err 上抛")

print("[6] shell 与 Rust 指向同一个配置文件")
alert_const = re.search(r'pub const WEBHOOK_FILE: &str = "([^"]+)";', alert_rs)
install = (ROOT / "deploy/install.sh")
if not alert_const:
    bad("alert.rs 里找不到 `WEBHOOK_FILE` 常量")
elif not install.exists():
    bad("缺少 deploy/install.sh")
else:
    shell_name = alert_const.group(1)
    body = install.read_text()
    m = re.search(r"^WH=(.+)$", body, re.M)
    if not m:
        bad("install.sh 里找不到 `WH=` 定义（崩溃告警锚点丢失）")
    elif Path(m.group(1).strip()).name != shell_name:
        bad(f"shell 用 {Path(m.group(1).strip()).name!r}，Rust 用 {shell_name!r} —— 改名只改一处")
    else:
        ok(f"两侧一致：{shell_name}")
    # OnFailure 接线：单元模板里必须真的引用 notifier，否则崩溃告警根本不触发
    boot = production("crates/panel-cli/src/bootstrap.rs")
    if "OnFailure=panel-failure-notify.service" not in boot:
        bad("panel.service 模板里没有 `OnFailure=` —— 崩溃告警单元永远不会被拉起")
    else:
        ok("panel.service 已挂 OnFailure")

print("[7] `panel alert` 两条子命令都必须走同一个 load（不许靠文件存在性猜）")
cli_alert = production("crates/panel-cli/src/cmd/alert.rs")
if not cli_alert.strip():
    bad("cmd/alert.rs 生产段提取为空")
else:
    # status 与 test **各要一次**：只判"至少一次"时，把 status 换成 exists()
    # 仍然绿——而 status 恰恰是最容易被写成"看文件在不在"的那一个。
    n = count(cli_alert, "AlertSink::load(")
    if n < 2:
        bad(f"`cmd/alert.rs` 里 `AlertSink::load` 只有 {n} 处，status 与 test 应各一处")
    else:
        ok("CLI 与运行时共用同一个加载路径（2 处）")

print()
if fail:
    print("FAIL: 外部告警接线不完整（见上面 ✗）")
    sys.exit(1)
print("PASS: 外部告警接线完整")
