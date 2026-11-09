#!/usr/bin/env python3
"""日志去向 / 保留策略 / 崩溃告警的接线守卫（生产就绪度 P1 / G8）。

背景：文档与 Rust 注释长期声称「serve 启动时 stderr 已重定向进日志文件」，
实际全仓零实现，`/var/log/forkpanel` 一直是空目录；journald 也没有保留上限，
无人值守机器上可能撑爆磁盘。崩溃只有 `Restart=on-failure` 拉起，没有任何
外部可见的记录。本轮把日志真实去向明确为 journald 并加保留策略，同时用
systemd OnFailure 挂一个崩溃通知单元（默认写 journal，可选 webhook）。

恒绿纪律：判据剔注释、提取前提先断言、对「不实注释是否回退」用精确原文串
（历史说明里也会引用该句子，全文关键词会被误伤）。

用法：python3 ci/check_logging.py [仓库根目录]
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
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("//", "///", "//!", "#")))


install = read("deploy/install.sh")
boot = read("crates/panel-cli/src/bootstrap.rs")
mid = read("crates/panel-api/src/middleware.rs")
routes = read("crates/panel-api/src/routes.rs")
foot = read("docs/install-footprint.md")
dep = read("docs/deployment.md")
e2e = read("ci/e2e-install.sh")
if fail:
    print("✗ check_logging：前提不成立")
    sys.exit(1)

install_code = strip_comments(install)

print("== [1] 安装器给 journald 配了保留上限 ==")
# ⚠ 两个配置项在 echo 提示行里也会出现；只扫 drop-in 的 heredoc 正文，
#   否则删掉配置内容后提示行仍能让判据假绿（负向对照实测抓到过）。
# ⚠ 不能用 find("EOF", i)：第一个 EOF 就在起始行的 <<'EOF' 里，会把正文截空。
m = re.search(r"cat > \"\$JOURNALD_DROPIN\" <<'EOF'\n([\s\S]*?)\nEOF", install_code)
jd_body = m.group(1) if m else ""
if not jd_body.strip():
    bad("提取不到 journald drop-in 的 heredoc 正文（判据塌成空）")
else:
    for needle, desc in [("SystemMaxUse=200M", "磁盘上限"),
                         ("MaxRetentionSec=14day", "保留期")]:
        if needle in jd_body:
            ok(f"drop-in 正文含 {desc}")
        else:
            bad(f"drop-in 正文缺 {desc}（{needle}）")
for needle, desc in [
    ("JOURNALD_DROPIN=/etc/systemd/journald.conf.d/forkpanel.conf", "drop-in 路径"),
    ("systemctl restart systemd-journald", "改动生效"),
]:
    if needle in install_code:
        ok(f"含 {desc}")
    else:
        bad(f"install.sh 缺 {desc}（{needle}）")

print("== [2] 安装器生成崩溃通知单元与脚本 ==")
for needle, desc in [
    ("panel-failure-notify.service", "通知单元"),
    ("notify-failure.sh", "通知脚本"),
    ("/etc/forkpanel/alert-webhook", "可选 webhook 配置"),
    ("logger -t forkpanel", "本地 journal 兜底"),
    ("curl -fsS --max-time 5", "外发带超时"),
]:
    if needle in install_code:
        ok(f"含 {desc}")
    else:
        bad(f"install.sh 缺 {desc}（{needle}）")

print("== [3] 主单元确实挂了 OnFailure ==")
i = boot.find("pub fn systemd_unit(")
j = boot.find("\n}\n", i)
body = boot[i:j] if i >= 0 and j > i else ""
if not body.strip():
    bad("提取不到 systemd_unit 函数体（判据塌成空）")
elif "OnFailure=panel-failure-notify.service" in body:
    ok("panel.service 的 OnFailure 指向崩溃通知单元")
else:
    bad("systemd_unit 缺 OnFailure=panel-failure-notify.service")

print("== [4] 不实注释已修正，文档如实说明无文件日志 ==")
legacy = ["stderr 已重定向进日志文件；systemd 部署下进 journald",
          "serve 启动时 stderr 已重定向进日志文件，不会打到终端"]
for src, name in [(mid, "middleware.rs"), (routes, "routes.rs")]:
    hit = [s for s in legacy if s in src]
    if hit:
        bad(f"{name} 仍残留不实注释：{hit[0]}")
    elif "journalctl -u panel" in src:
        ok(f"{name} 已改为 journald 真实去向")
    else:
        bad(f"{name} 既没写真实去向也没写不实注释（判据异常）")
if "不落文件日志" in foot and "已废止" in foot:
    ok("install-footprint.md 如实说明无文件日志并废止 logrotate 说法")
else:
    bad("install-footprint.md 仍在宣称 logrotate 认 /var/log")

print("== [5] 部署文档与安装 E2E 同步 ==")
for needle, desc in [
    ("### 5.2.2 日志去向与保留", "日志章节"),
    ("### 5.2.3 外部告警通道", "告警章节"),
    # 标题之外再钉两个**只可能来自真实实现**的锚点：`panel alert test` 是 CLI
    # 真命令，`backup.failed` 是代码里的事件名。只判标题的话，正文删空仍然绿。
    ("panel alert test", "告警自检命令"),
    ("backup.failed", "业务失败事件名"),
]:
    if needle in dep:
        ok(f"deployment.md 含 {desc}")
    else:
        bad(f"deployment.md 缺 {desc}（{needle}）")
for needle, desc in [
    ("6b. journald", "E2E 日志断言段"),
    ("OnFailure=panel-failure-notify.service", "E2E OnFailure 断言"),
    ("alert-webhook", "E2E webhook 钩子断言"),
]:
    if needle in e2e:
        ok(f"e2e-install.sh 含 {desc}")
    else:
        bad(f"e2e-install.sh 缺 {desc}（{needle}）")

if fail:
    print("✗ check_logging：日志 / 告警接线未通过")
    sys.exit(1)
print("PASS：日志去向与保留已明确，崩溃告警已挂 OnFailure，不实注释已修正")
sys.exit(0)
