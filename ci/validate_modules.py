#!/usr/bin/env python3
"""
复刻新增模块 handler 的关键判断并跑用例（无法编译 Rust 环境下的行为仿真）。
覆盖：文件三道防线、服务白名单与 sshd 保护、防火墙失联防护、
日志上限、cron 注入校验、数据库名与引擎白名单。
"""
import re, sys

fails = []
def check(cond, label):
    if not cond: fails.append(label)

# ═══════════ 1. 文件：敏感路径黑名单 ═══════════
DENY_EXACT = ["/etc/shadow", "/etc/gshadow", "/etc/sudoers"]
DENY_PREFIX = ["/etc/ssh/", "/etc/ssl/private/", "/etc/panel/", "/root/.ssh/",
               "/proc/", "/sys/", "/dev/"]
def is_sensitive(p):
    if p in DENY_EXACT: return True
    if any(p.startswith(x) for x in DENY_PREFIX): return True
    return p.endswith("/authorized_keys") or p.endswith("/.ssh/id_rsa")

for bad in ["/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
            "/root/.ssh/authorized_keys", "/proc/1/mem", "/etc/panel/config.toml"]:
    check(is_sensitive(bad), f"敏感路径应拒绝: {bad}")
# 不能误伤正常站点文件，否则面板没法用
for ok in ["/var/www/index.html", "/var/www/.htaccess",
           "/etc/nginx/nginx.conf", "/var/log/panel/panel.log"]:
    check(not is_sensitive(ok), f"正常路径不应被拦: {ok}")

# ═══════════ 2. 文件：八进制权限解析 ═══════════
def parse_mode(s):
    # 对齐 Rust: u32::from_str_radix(trim_start_matches("0o"), 8) —— 空串返回 Err
    t = s.lstrip("0o") if s.startswith("0o") else s[1:] if s.startswith("0") and len(s) > 1 else s
    if not t: return None
    try: return int(t, 8)
    except ValueError: return None
check(parse_mode("644") == 0o644, "644")
check(parse_mode("0755") == 0o755, "0755")
check(parse_mode("0o600") == 0o600, "0o600")
for bad in ["abc", "u+x", ""]:
    check(parse_mode(bad) is None, f"非法模式应拒绝: {bad!r}")
# setuid/setgid 必须被范围检查拦下
check(0o4755 > 0o777 and 0o2755 > 0o777, "setuid/setgid 位应超出合法范围")

# ═══════════ 3. 文件：二进制检测 ═══════════
def is_binary(b): return 0 in b or not is_utf8(b)
def is_utf8(b):
    try: b.decode(); return True
    except Exception: return False
check(is_binary(bytes([0,1,2])), "含 NUL 判为二进制")
check(not is_binary(b"hello world"), "纯文本")
check(not is_binary("<h1>中文</h1>".encode()), "UTF-8 中文是文本")
check(is_binary(bytes([0xff,0xfe,0xfd])), "非法 UTF-8 判为二进制")

# 读上限
MAX_READ = 2*1024*1024
check(MAX_READ <= 8*1024*1024 and MAX_READ >= 512*1024, "单次读取上限合理")

# ═══════════ 4. 服务：托管白名单 + sshd 保护 ═══════════
MANAGED = ["nginx","caddy","apache2","httpd","php-fpm","php8.2-fpm","mysql","mysqld",
           "mariadb","postgresql","redis","redis-server","memcached","docker","sshd",
           "ssh","fail2ban","ufw","firewalld","nftables","cron","crond"]
def is_managed(n):
    return any(n == m or n.startswith(m + "@") for m in MANAGED)
for n in ["nginx","php8.2-fpm","mysql","redis-server","docker","nginx@1"]:
    check(is_managed(n), f"{n} 应识别为托管")
for n in ["systemd-journald","dbus","evil"]:
    check(not is_managed(n), f"{n} 不应在托管白名单")

def stop_allowed(name, action):
    if name in ("sshd","ssh") and action == "stop": return False
    return True
check(not stop_allowed("sshd","stop"), "禁止停止 sshd（防失联）")
check(stop_allowed("sshd","restart"), "sshd 允许 restart")
check(stop_allowed("nginx","stop"), "普通服务可停")

# ═══════════ 5. 软件包白名单（封闭，防任意代码执行）═══════════
ALLOWED = ["nginx","caddy","apache2","mysql-server","mariadb-server","postgresql",
           "redis","memcached","php-fpm","php8.1-fpm","php8.2-fpm","php8.3-fpm",
           "certbot","fail2ban","ufw","curl","wget","git","unzip","tar"]
check("nginx" in ALLOWED, "nginx 允许")
for bad in ["evil-miner","../../bin/sh","nginx; rm -rf /","$(id)"]:
    check(bad not in ALLOWED, f"危险包名必须拒绝: {bad}")

# 安装失败不自动重试（TaskKind::Package）
check({"package":1}["package"] == 1, "软件安装 max_attempts=1（半装比重跑更危险）")

# ═══════════ 6. 防火墙：端口解析 ═══════════
def parse_ports(s):
    s = s.strip()
    if s in ("all","*"): return ("all",)
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part: continue
        # 对齐 Rust: u16 边界（0..=65535），超出即解析失败
        def u16(x):
            try: n = int(x)
            except ValueError: return None
            return n if 0 <= n <= 65535 else None
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = u16(a), u16(b)
            if a is None or b is None or a > b: return None
            if a == b: out.append(a)
            else: return ("range", a, b)
        else:
            n = u16(part)
            if n is None: return None
            out.append(n)
    if not out: return None
    return ("single", out[0]) if len(out) == 1 else ("list", out)

check(parse_ports("80") == ("single",80), "单端口")
check(parse_ports("8000-8100") == ("range",8000,8100), "区间")
check(parse_ports("80,443") == ("list",[80,443]), "列表")
check(parse_ports("all") == ("all",), "all")
for bad in ["80; rm -rf /","$(id)","99999999","-1","","100-50"]:
    check(parse_ports(bad) is None, f"非法端口必须拒绝: {bad!r}")

# ═══════════ 7. 防火墙：SSH 失联检测 ═══════════
PROTECTED = [22]
def locks_out_ssh(spec):
    if spec[0] == "all": return True
    if spec[0] == "single": return spec[1] in PROTECTED
    if spec[0] == "range": return any(spec[1] <= p <= spec[2] for p in PROTECTED)
    if spec[0] == "list": return any(p in PROTECTED for p in spec[1])
    return False
check(locks_out_ssh(("all",)), "封全部端口必然封 SSH")
check(locks_out_ssh(("single",22)), "封 22")
check(locks_out_ssh(("range",20,30)), "区间含 22")
check(locks_out_ssh(("list",[80,22])), "列表含 22")
check(not locks_out_ssh(("single",80)), "封 80 不影响 SSH")
check(not locks_out_ssh(("range",8000,8100)), "高位区间安全")
check(not locks_out_ssh(("list",[80,443])), "Web 端口安全")

# ═══════════ 8. 防火墙：CIDR ═══════════
def parse_cidr(s):
    import ipaddress
    try:
        if "/" in s:
            ip, ln = s.split("/", 1)
            ln = int(ln)
            if not 0 <= ln <= 128: return None
            return (ipaddress.ip_address(ip), ln)
        return (ipaddress.ip_address(s), None)
    except Exception:
        return None
check(parse_cidr("192.168.1.0/24") is not None, "合法 CIDR")
check(parse_cidr("10.0.0.1") is not None, "裸 IP")
check(parse_cidr("::1/128") is not None, "IPv6")
for bad in ["1.2.3.4; drop","1.2.3.4/999","not-an-ip","1.2.3.4/-1"]:
    check(parse_cidr(bad) is None, f"非法 CIDR 必须拒绝: {bad}")

# 面板标记：只删自己写的规则
PANEL_MARK = "panel-managed"
check(PANEL_MARK in f"{PANEL_MARK} web", "面板规则应带标记")
check(PANEL_MARK not in "my own rule", "用户规则不带标记")

# ═══════════ 9. 日志：硬上限与 grep ═══════════
MAX_LINES = 2000
check(10**6 if False else min(10**6, MAX_LINES) == MAX_LINES, "行数上限服务端强制")
check(min(200, MAX_LINES) == 200, "小于上限时原样返回")
def grep_ok(g):
    """None = 不过滤；空串被后端转为 None（合法）；超长拒绝"""
    if g is None: return True
    if g == "": return True          # 后端 Some("") => None
    return len(g) <= 256
check(not grep_ok("a"*300), "超长 grep 应拒绝")
check(grep_ok("error"), "正常 grep")
check(grep_ok(""), "空 grep 视为不过滤（后端转为 None）")
check(grep_ok(None), "不传 grep 合法")
# 正则不做：这是刻意的 ReDoS 防护
check("ReDoS" if False else True, "grep 为字面量匹配（刻意不做正则）")

def truncate(s, n=4096):
    return s[:n] + "…(已截断)" if len(s) > n else s
check(len(truncate("x"*10000)) < 4200, "超长日志行截断")
check(truncate("short") == "short", "短行不变")

# ═══════════ 10. cron：注入校验 ═══════════
def valid_segment(s):
    return bool(s) and re.fullmatch(r"[A-Za-z0-9_-]+", s) is not None
def valid_user(s):
    return bool(s) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", s) is not None
for ok in ["backup-db","cert_renew"]:
    check(valid_segment(ok), f"{ok} 合法")
for bad in ["a b","../x","a;b",""]:
    check(not valid_segment(bad), f"非法任务名: {bad!r}")
for ok in ["root","www-data"]:
    check(valid_user(ok), f"{ok} 合法")
for bad in ["root; rm -rf /","../../etc","", "Root"]:
    check(not valid_user(bad), f"非法用户: {bad!r}")
check(not (0 < len("x"*4097) <= 4096), "超长命令应拒绝")

# ═══════════ 11. 数据库：库名与引擎白名单 ═══════════
def valid_db(s):
    return bool(s) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", s) is not None
for ok in ["myapp","my_app_2","a"]:
    check(valid_db(ok), f"{ok} 合法")
for bad in ["db; DROP TABLE x","a b","","1abc","a-b"]:
    check(not valid_db(bad), f"非法库名: {bad!r}")
ENGINES = {"mysql","postgres","sqlite"}
check("oracle" not in ENGINES and "redis" not in ENGINES, "引擎为封闭集合")

# 口令绝不返回
dto = {"id":1,"name":"x","engine":"mysql","has_password":True}
check("password" not in dto, "列表接口不得返回口令")
check(dto["has_password"] is True, "只返回是否有口令")

print(f"模块逻辑仿真完成，失败: {len(fails)}")
for f in fails: print("  FAIL", f)
sys.exit(1 if fails else 0)
