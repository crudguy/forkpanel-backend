#!/usr/bin/env python3
"""
复刻 panel-api::auth 的关键语义并跑安全用例集。
目的：在无法编译 Rust 的环境下，仍能验证鉴权逻辑的不变量（不是形式验证，是行为仿真）。
覆盖：口令策略、argon2 参数分档、会话轮换与过期、防暴力锁定、RBAC 默认拒绝、CSRF 时序安全。
"""
import json, sys, time, hashlib, hmac, secrets

# ─────────── 复刻 auth.rs 语义 ───────────

def check_password_policy(pwd: str):
    if len(pwd) < 10: return "min length is 10"
    if len(pwd) > 256: return "too long"
    WEAK = ["password", "123456789", "qwertyuiop", "admin1234", "iloveyou", "letmein"]
    low = pwd.lower()
    if any(w in low for w in WEAK): return "too common"
    classes = sum([any(c.isascii() and c.islower() for c in pwd),
                   any(c.isascii() and c.isupper() for c in pwd),
                   any(c.isdigit() for c in pwd),
                   any(not c.isalnum() for c in pwd)])
    if classes < 2: return "needs 2 character classes"
    return None

def hash_params(tier):
    return {"nano": 8*1024, "small": 16*1024, "standard": 19*1024}[tier]

ROLE_PERMS = {
    "viewer": ["system.view","service.view","site.view","file.read","db.view",
               "firewall.view","cron.view","log.view","task.view","audit.view"],
    "operator": None,  # 下面拼
    "admin": None,
    "owner": None,
}
_VIEW = ROLE_PERMS["viewer"]
_MANAGE = ["system.manage","service.manage","package.manage","site.manage","ssl.manage",
           "file.write","db.manage","firewall.manage","security.manage","cron.manage",
           "settings.manage","user.manage"]
ROLE_PERMS["owner"] = _VIEW + _MANAGE
ROLE_PERMS["admin"] = _VIEW + _MANAGE
ROLE_PERMS["operator"] = _VIEW + ["service.manage","site.manage","ssl.manage","cron.manage","file.write"]

def permissions_for_role(role):
    return ROLE_PERMS.get(role, [])

def require(perms, p):
    return p in perms

class SessionCache:
    def __init__(self, idle=1800, absolute=43200):
        self.m = {}; self.idle = idle; self.absolute = absolute
    def insert(self, sid, s):
        now = int(time.time()); s = dict(s)
        s["created_at"] = now; s["last_seen"] = now; s["expires_at"] = now + self.idle
        self.m[sid] = s
    def get(self, sid):
        now = int(time.time())
        s = self.m.get(sid)
        if not s: return None
        if s["expires_at"] <= now or now - s["created_at"] >= self.absolute:
            del self.m[sid]; return None
        s["last_seen"] = now; s["expires_at"] = now + self.idle
        return s
    def rotate(self, old):
        s = self.m.pop(old, None)
        if s is None: return None
        new = secrets.token_hex(32)
        self.insert(new, s)
        return new, s
    def remove(self, sid): self.m.pop(sid, None)

class LoginGuard:
    """滑动窗口 + 指数退避 + 锁定（复刻 auth.rs）"""
    def __init__(self, max_attempts=5, lock_after=15, lock_duration=900, window=900):
        self.m = {}; self.max_attempts = max_attempts
        self.lock_after = lock_after; self.lock_duration = lock_duration; self.window = window
    def check(self, key):
        now = time.time()
        v = [t for t in self.m.get(key, []) if now - t < self.window]
        self.m[key] = v
        n = len(v)
        if n >= self.lock_after:
            last = v[-1] if v else now
            return max(0, int(self.lock_duration - (now - last)))
        if n >= self.max_attempts:
            backoff = 1 << min(n - self.max_attempts, 6)
            last = v[-1] if v else now
            elapsed = now - last
            if elapsed < backoff: return int(backoff - elapsed)
        return None
    def record_failure(self, key): self.m.setdefault(key, []).append(time.time())
    def reset(self, key): self.m.pop(key, None)

def csrf_ok(a, b):
    if not a or not b or len(a) != len(b): return False
    acc = 0
    for x, y in zip(a.encode(), b.encode()): acc |= x ^ y
    return acc == 0

# ─────────── 用例 ───────────

fails = []
def check(cond, label):
    if not cond: fails.append(label)

# 1) 口令策略
for bad in ["short1!A", "password12345", "aaaaaaaaaaaa", "1234567890", ""]:
    check(check_password_policy(bad) is not None, f"弱口令应拒绝: {bad!r}")
for good in ["Tr0ub4dor&3xy", "correct-horse-battery"]:
    check(check_password_policy(good) is None, f"强口令应接受: {good!r}")

# 2) argon2 分档
check(hash_params("nano") == 8*1024, "nano argon2 m=8MiB")
check(hash_params("standard") == 19*1024, "standard argon2 m=19MiB")
check(hash_params("nano") < hash_params("standard"), "低配必须更小")

# 3) RBAC 默认拒绝
check(permissions_for_role("nobody") == [], "未知角色零权限")
check(permissions_for_role("") == [], "空角色零权限")
check(not require(permissions_for_role("viewer"), "site.manage"), "viewer 不能改站点")
check(not require(permissions_for_role("viewer"), "firewall.manage"), "viewer 不能改防火墙")
check(require(permissions_for_role("viewer"), "system.view"), "viewer 可读")
check(not require(permissions_for_role("operator"), "firewall.manage"), "operator 不能改防火墙")
check(require(permissions_for_role("operator"), "site.manage"), "operator 可改站点")
check(require(permissions_for_role("admin"), "user.manage"), "admin 可管用户")

# 4) 会话轮换与过期
c = SessionCache(idle=1, absolute=3600)
s = {"user_id": 1, "username": "a", "role": "admin", "permissions": [], "allowed_roots": []}
sid = secrets.token_hex(32); c.insert(sid, s)
check(c.get(sid) is not None, "会话应可取")
new, _ = c.rotate(sid)
check(new != sid, "轮换后 sid 必须不同")
check(c.get(sid) is None, "旧 sid 必须立即失效")
check(c.get(new) is not None, "新 sid 必须可用")
c2 = SessionCache(idle=0, absolute=3600)
sid2 = secrets.token_hex(32); c2.insert(sid2, dict(s))
check(c2.get(sid2) is None, "过期会话必须失效")

# 5) 防暴力
g = LoginGuard()
for _ in range(15): g.record_failure("1.2.3.4:admin")
check(g.check("1.2.3.4:admin") is not None, "15 次后应锁定")
g.reset("1.2.3.4:admin")
check(g.check("1.2.3.4:admin") is None, "reset 后应放行")
for _ in range(6): g.record_failure("1.2.3.4:bob")
check(g.check("1.2.3.4:bob") is not None, "超过 5 次进入退避")
check(g.check("9.9.9.9:bob") is None, "不同 key 互不影响")

# 6) CSRF
tok = secrets.token_hex(24)
check(csrf_ok(tok, tok), "相同 token 应通过")
check(not csrf_ok(tok, tok[:-1] + ("0" if tok[-1] != "0" else "1")), "不同 token 应拒绝")
check(not csrf_ok(None, tok), "缺失 cookie token 应拒绝")
check(not csrf_ok("", ""), "空 token 应拒绝")
check(not csrf_ok(tok, tok + "x"), "长度不同应拒绝")

print(f"鉴权不变量检查完成，失败: {len(fails)}")
for f in fails: print("  FAIL", f)
sys.exit(1 if fails else 0)
