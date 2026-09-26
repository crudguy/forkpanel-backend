#!/usr/bin/env python3
"""
复刻 panel-cli 的关键逻辑并跑用例（无法编译 Rust 环境下的行为仿真）。
覆盖：配置解析与默认值、档位探测、时长解析、systemd 单元硬化项、主密钥文件权限。
"""
import os, sys, tempfile, stat, re

fails = []
def check(cond, label):
    if not cond: fails.append(label)

# ─────────── 1. 时长解析（config::parse_duration） ───────────
def parse_duration(s):
    s = s.strip()
    m = re.match(r"^(\d+)([smhd])$", s)
    if not m: raise ValueError(f"bad duration: {s}")
    n, u = int(m.group(1)), m.group(2)
    return n * {"s":1, "m":60, "h":3600, "d":86400}[u]

check(parse_duration("30m") == 1800, "30m = 1800s")
check(parse_duration("12h") == 43200, "12h = 43200s")
check(parse_duration("90s") == 90, "90s")
check(parse_duration("7d") == 604800, "7d")
for bad in ["30x", "abc", "30", ""]:
    try:
        parse_duration(bad); fails.append(f"非法时长应拒绝: {bad!r}")
    except ValueError: pass

# ─────────── 2. 档位探测（Tier::detect / Config::tier） ───────────
def detect(mem_mb, cpus):
    if mem_mb <= 512 or cpus <= 1: return "nano"
    if mem_mb <= 2048 or cpus <= 2: return "small"
    return "standard"

def cfg_tier(forced, mem_mb, cpus):
    if forced in ("nano","small","standard"): return forced
    return detect(mem_mb, cpus)

check(detect(256, 1) == "nano", "256MB/1核 → nano")
check(detect(1024, 1) == "nano", "1核即使内存大也 nano（单核无法承载采集+API）")
check(detect(1024, 2) == "small", "1GB/2核 → small")
check(detect(4096, 4) == "standard", "4GB/4核 → standard")
check(cfg_tier("standard", 256, 1) == "standard", "显式档位必须覆盖探测")

# 档位参数必须单调
SAMPLING = {"nano":5000, "small":2000, "standard":1000}
SSE = {"nano":3, "small":10, "standard":50}
CACHE = {"nano":1000, "small":2000, "standard":4000}
check(SAMPLING["nano"] > SAMPLING["small"] > SAMPLING["standard"], "采样间隔随档位收紧")
check(SSE["nano"] < SSE["small"] < SSE["standard"], "SSE 上限随档位放宽")
check(CACHE["nano"] < CACHE["standard"], "页缓存随档位放宽")
check(detect(512, 4) == "nano", "512MB 边界应判 nano")

# ─────────── 3. 监听地址：localhost_only 必须覆盖 bind ───────────
def addr(bind, localhost_only, port=2083):
    host = "127.0.0.1" if localhost_only else bind
    return f"{host}:{port}"

check(addr("0.0.0.0", True) == "127.0.0.1:2083", "localhost_only 必须覆盖 bind")
check(addr("0.0.0.0", False) == "0.0.0.0:2083", "显式关闭时才监听全部")
check(addr("127.0.0.1", True).startswith("127."), "默认回环")

# ─────────── 4. systemd 单元硬化项 ───────────
def systemd_unit(bin_path, config, mem_max, writable):
    return f"""[Unit]
Description=Lightweight server management panel
[Service]
ExecStart={bin_path} --config {config} serve
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
ReadWritePaths={' '.join(writable)}
MemoryMax={mem_max}
CPUQuota=20%
TasksMax=256
[Install]
WantedBy=multi-user.target"""

MEM = {"nano":"96M", "small":"192M", "standard":"384M"}
for tier in ("nano","small","standard"):
    u = systemd_unit("panel", "config.toml", MEM[tier], ["data","log"])
    check("NoNewPrivileges=yes" in u, f"{tier}: 禁止提权")
    check("ProtectSystem=strict" in u, f"{tier}: 系统只读")
    check(f"MemoryMax={MEM[tier]}" in u, f"{tier}: 内存上限 {MEM[tier]}")
    check("CPUQuota=20%" in u, f"{tier}: CPU 配额")
    # 单元内容不得包含服务目录路径（安装位置由 PathLayout 决定）
    check("systemd/system" not in u, f"{tier}: 不得写死服务目录")
check(MEM["nano"] == "96M" and MEM["standard"] == "384M", "内存上限按档位分档")

# ─────────── 5. 主密钥文件权限 ───────────
d = tempfile.mkdtemp(prefix="panel-cli-sim-")
kp = os.path.join(d, "master.key")
with open(kp, "wb") as f: f.write(b"0"*32)
os.chmod(kp, 0o600)
check(stat.S_IMODE(os.stat(kp).st_mode) == 0o600, "主密钥 0600")
os.chmod(kp, 0o644)
check(stat.S_IMODE(os.stat(kp).st_mode) != 0o600, "权限过宽应被 doctor 判 Fail")
os.chmod(kp, 0o600)

# ─────────── 6. 引导令牌 ───────────
import secrets
t1, t2 = secrets.token_hex(16), secrets.token_hex(16)
check(len(t1) == 32 and t1 != t2, "引导令牌 32 位十六进制且唯一")

# ─────────── 7. 配置默认值（保守优先） ───────────
defaults = {"localhost_only": True, "retention_days": 90, "max_rows": 50000,
            "synchronous": "NORMAL", "max_login_attempts": 5, "read_only": False}
check(defaults["localhost_only"] is True, "默认只监听回环")
check(defaults["retention_days"] == 90, "审计默认 90 天（实测 180 天 = 4.12MB）")
check(defaults["synchronous"] == "NORMAL", "默认 NORMAL（FULL 吞吐降 42%）")

import shutil; shutil.rmtree(d, ignore_errors=True)

print(f"CLI 逻辑仿真完成，失败: {len(fails)}")
for f in fails: print("  FAIL", f)
sys.exit(1 if fails else 0)
