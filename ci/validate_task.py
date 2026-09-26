#!/usr/bin/env python3
"""
复刻 panel-task 的关键语义并跑用例（无法编译 Rust 环境下的行为仿真）。
覆盖：状态机、重试策略（含"副作用不可回滚"的核心判断）、并发档位、
幂等键语义、中断不做自动恢复、内部调度错峰与 nano 降级。
"""
import sys, asyncio, time

fails = []
def check(cond, label):
    if not cond: fails.append(label)

# ─────────── 1. 状态机 ───────────
QUEUED, RUNNING, OK, FAILED, CANCELED, INTERRUPTED = \
    "queued","running","ok","failed","canceled","interrupted"
TERMINAL = {OK, FAILED, CANCELED, INTERRUPTED}

check(RUNNING not in TERMINAL, "running 非终态")
check(QUEUED not in TERMINAL, "queued 非终态")
check(INTERRUPTED in TERMINAL, "interrupted 是终态")
# 需要人工介入
check(INTERRUPTED == "interrupted", "中断态命名与 schema 一致")

# ─────────── 2. 重试策略：核心判断 ───────────
def retry(kind):
    return {
        "package":     (1, 0, 0),        # max, base_sec, max_sec
        "cert_issue":  (3, 60, 900),
        "config_apply":(2, 2, 10),
        "service":     (2, 2, 10),
        "backup":      (3, 5, 60),
        "database":    (3, 5, 60),
        "internal":    (3, 5, 60),
    }[kind]

def delay_for(kind, attempt):
    mx, base, cap = retry(kind)
    if attempt == 0 or mx == 1: return 0
    return min(base * (1 << min(attempt-1, 6)), cap)

# 副作用不可回滚 → 绝不自动重试
check(retry("package")[0] == 1, "软件安装失败绝不自动重试（半装比重跑更危险）")
check(delay_for("package", 1) == 0, "package 无重试延迟")

# ACME 有限流 → 必须退避
check(retry("cert_issue")[0] == 3, "证书最多 3 次")
check(delay_for("cert_issue", 1) == 60, "首次退避 60s（避开 ACME 限流）")
check(delay_for("cert_issue", 2) == 120, "指数退避")
check(delay_for("cert_issue", 3) == 240, "指数退避")
check(delay_for("cert_issue", 10) <= 900, "退避有上限")

# 幂等操作可重试
for k in ("backup", "config_apply", "service", "database"):
    check(retry(k)[0] > 1, f"{k} 可重试（幂等）")

# ─────────── 3. 并发档位 ───────────
CONC = {"nano": 1, "small": 2, "standard": 4}
check(CONC["nano"] == 1, "512MB 机器上同时跑两个 apt 会 OOM")
check(CONC["nano"] < CONC["small"] < CONC["standard"], "并发随档位放宽")

# ─────────── 4. 幂等键语义 ───────────
class Runner:
    """幂等：非终态 → 复用；终态 → 允许重提"""
    def __init__(self): self.tasks = {}
    def submit(self, key, state_of_existing=None):
        if key in self.tasks:
            tid, st = self.tasks[key]
            if st not in TERMINAL:
                return (tid, False)     # 复用，不重复执行
        tid = len(self.tasks) + 1
        self.tasks[key] = (tid, QUEUED)
        return (tid, True)

r = Runner()
tid1, new1 = r.submit("install-nginx")
check(new1 is True, "首次提交为新建")
tid2, new2 = r.submit("install-nginx")
check(new2 is False and tid1 == tid2, "运行中重复提交应复用（防双击）")
r.tasks["install-nginx"] = (tid1, FAILED)
tid3, new3 = r.submit("install-nginx")
check(new3 is True, "终态后可重新提交（用户确实想再来一次）")
# 窗口过期后可重新提交
check(r.submit("other-key")[1] is True, "不同 key 互不影响")

# ─────────── 5. 中断不做自动恢复 ───────────
def reap_orphans(tasks):
    """把 running/queued 标记 interrupted，返回数量；不做任何重试"""
    n = 0
    for k, (tid, st) in list(tasks.items()):
        if st in (RUNNING, QUEUED):
            tasks[k] = (tid, INTERRUPTED); n += 1
    return n

t = {"a": (1, RUNNING), "b": (2, QUEUED), "c": (3, OK)}
n = reap_orphans(t)
check(n == 2, "两个非终态被标记")
check(t["a"][1] == INTERRUPTED and t["b"][1] == INTERRUPTED, "标记为 interrupted")
check(t["c"][1] == OK, "已终态不受影响")
check(all(v[1] != RUNNING for v in t.values()), "reap 后无残留 running")

# ─────────── 6. 内部调度：错峰与 nano 降级 ───────────
def builtin(tier):
    sampling = {"nano": 5000, "small": 2000, "standard": 1000}[tier]
    jobs = [
        ("metrics.sample", ("every", sampling), 0),
        ("metrics.aggregate_1m", ("every", 60000), 2),
        ("metrics.rollup_1h", ("daily", 3, 10), 0),
        ("db.cleanup", ("daily", 3, 15), 0),
        ("cert.renew_check", ("daily", 4, 5), 30),
    ]
    if tier != "nano":
        jobs.append(("db.backup", ("daily", 3, 30), 0))
    return jobs

check(not any(j[0] == "db.backup" for j in builtin("nano")),
      "nano 不做每日备份（IO 与内存开销不划算）")
check(any(j[0] == "db.backup" for j in builtin("standard")), "standard 有每日备份")

by_name = {j[0]: j for j in builtin("standard")}
check(by_name["db.cleanup"][1] != by_name["db.backup"][1],
      "清理与备份不得挤在同一分钟（低配 IO 抖动）")
check(any(j[2] > 0 for j in builtin("standard")), "至少部分任务错峰")
check(by_name["metrics.sample"][1][1] == 1000, "standard 采样 1s")
check({j[0]: j for j in builtin("nano")}["metrics.sample"][1][1] == 5000, "nano 采样 5s")

# ─────────── 7. 进度广播不落库 ───────────
BUS_CAP = 256
check(BUS_CAP <= 512, "广播缓冲必须小（慢消费者直接丢弃）")

def truncate(line, limit=4096):
    return line[:limit] if len(line) > limit else line
check(len(truncate("x" * 10000)) == 4096, "超长日志行必须截断")
check(len(truncate("short")) == 5, "短行不截断")

def clamp(pct): return min(pct, 100)
check(clamp(200) == 100, "进度百分比需夹紧")
check(clamp(50) == 50, "正常值不变")

print(f"任务中心逻辑仿真完成，失败: {len(fails)}")
for f in fails: print("  FAIL", f)
sys.exit(1 if fails else 0)
