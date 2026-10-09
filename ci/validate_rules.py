#!/usr/bin/env python3
"""
复刻 panel-core::rules 的校验规则并跑注入用例集。
目的：在无法编译 Rust 的环境下，仍可验证"规则本身能挡住注入"。
输出的 cases JSON 可直接被 Rust 单测导入（保持单一事实来源）。
"""
import json, re, sys, os

# ── 与 crates/panel-core/src/lib.rs::rules 保持一致 ──

# TLD 白名单：与 Rust 侧共用同一份数据文件（单一事实来源）。缺失或规模异常即
# fail fast —— 绝不静默放行，否则镜像与 Rust 脱节还报绿，比没有校验更危险。
_TLD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "crates", "panel-core", "src", "data", "tlds.txt")
_TLD_EXTRA = {"local", "lan", "internal", "home", "test", "example", "invalid", "localhost", "onion"}

def _load_tld_allowlist():
    if not os.path.exists(_TLD_FILE):
        raise SystemExit(f"TLD 白名单数据缺失: {_TLD_FILE}")
    with open(_TLD_FILE, encoding="utf-8") as fp:
        tlds = {ln.strip().lower() for ln in fp if ln.strip() and not ln.startswith("#")}
    if len(tlds) < 1000:
        raise SystemExit(f"TLD 白名单规模异常（仅 {len(tlds)} 条），疑似读取不全")
    return tlds | _TLD_EXTRA

TLD_ALLOWLIST = _load_tld_allowlist()

def is_valid_unit_name(s: str) -> bool:
    if not s or len(s) > 256: return False
    if s.startswith('-') or ".." in s: return False
    return all(c.isascii() and (c.isalnum() or c in "_ . @ -".replace(" ", "")) for c in s)

def is_valid_domain(s: str) -> bool:
    if not s or len(s) > 253: return False
    if s.startswith('.') or s.endswith('.'): return False
    labels = s.split('.')
    # 必须至少两级（含 '.'）：单词级如 random/localhost/as 一律拒绝
    if len(labels) < 2: return False
    for label in labels:
        n = len(label)
        if not (1 <= n <= 63): return False
        if not all(c.isascii() and (c.isalnum() or c == '-') for c in label): return False
        if label.startswith('-') or label.endswith('-'): return False
    # 纯数字（形似 IPv4）：只接受 4 段且每段 0~255，挡掉 999.999.999.999
    if all(label.isdigit() for label in labels):
        return len(labels) == 4 and all(int(label) <= 255 for label in labels)
    # TLD 必须真实存在（大小写不敏感）
    return labels[-1].lower() in TLD_ALLOWLIST

def is_valid_system_user(s: str) -> bool:
    if not s or len(s) > 32: return False
    if not (s[0].isascii() and (s[0].islower() or s[0] == '_')): return False
    return all(c.isascii() and (c.islower() or c.isdigit() or c in "_-") for c in s[1:])

def is_valid_db_name(s: str) -> bool:
    if not s or len(s) > 64: return False
    return all(c.isascii() and (c.isalnum() or c == '_') for c in s)

def is_valid_path_segment(s: str) -> bool:
    # 与 Rust 一致：**白名单**（字母数字 + . _ -），并拒 . / ..
    # 旧实现只排除 \0 / \ 及 . ..，会放行空格与 ; $ ` " 等注入字符（与 Rust 脱节）。
    if not s or len(s) > 255: return False
    if s in ('.', '..'): return False
    return all(c.isascii() and (c.isalnum() or c in "-_.") for c in s)

CASES = {
    "unit_name": {
        "valid":   ["nginx.service", "panel@1.service", "sshd", "mysql_1.service", "a.b-c@d"],
        "invalid": ["nginx; rm -rf /", "../../etc/passwd", "$(id)", "`id`", "-bad", "a..b", "",
                    "x" * 300, "nginx|cat /etc/shadow", "nginx\nrm -rf /", "unit&id"],
    },
    "domain": {
        "valid":   ["example.com", "a.b.c.example.org", "s1.example.com", "1.2.3.4",
                    "host.lan", "myapp.local", "svc.internal", "example.xn--fiqs8s"],
        "invalid": ["-a.com", "a-.com", ".com", "exa mple.com", "a" * 254, "", "a..b",
                    "example.com;rm -rf /", "example.com\nSet-Cookie:x", "$(id).com",
                    "random", "test123", "localhost", "as", "a",
                    # TLD 真实性：编造顶级域 / 伪 IP / 段数不足
                    "asdf.qwer", "host.zzz", "example.notreal",
                    "999.999.999.999", "256.1.1.1", "1.2.3"],
    },
    "system_user": {
        "valid":   ["www-data", "_apps", "nginx1"],
        "invalid": ["-root", "root;id", "", "Root", "user name", "u" * 40, "user$(id)"],
    },
    "db_name": {
        "valid":   ["wp_db1", "Panel", "a"],
        "invalid": ["wp-db", "db;drop table", "db'or 1=1--", "", "db`x", "d" * 65],
    },
    "path_segment": {
        "valid":   ["site-a", "index.html"],
        "invalid": ["..", ".", "a/b", "a\0b", "a\\b", "", "s" * 256, "a b", "a;b"],
    },
}

FUNCS = {
    "unit_name": is_valid_unit_name,
    "domain": is_valid_domain,
    "system_user": is_valid_system_user,
    "db_name": is_valid_db_name,
    "path_segment": is_valid_path_segment,
}

if __name__ == "__main__":
    failures, total = [], 0
    for kind, groups in CASES.items():
        fn = FUNCS[kind]
        for want, items in (("accept", groups["valid"]), ("reject", groups["invalid"])):
            for item in items:
                total += 1
                got = fn(item)
                ok = (got is True) if want == "accept" else (got is False)
                if not ok:
                    failures.append({"rule": kind, "input": repr(item), "expected": want,
                                     "actual": "accept" if got else "reject"})
    print(f"用例总数: {total}  失败: {len(failures)}")
    for f in failures:
        print("  FAIL", f)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "validation_cases.json")
    with open(out, "w") as fp:
        json.dump(CASES, fp, indent=2, ensure_ascii=False)
    print(f"用例集已写入 {out}（供 Rust 单测导入）")
    sys.exit(1 if failures else 0)
