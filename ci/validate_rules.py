#!/usr/bin/env python3
"""
复刻 panel-core::rules 的校验规则并跑注入用例集。
目的：在无法编译 Rust 的环境下，仍可验证"规则本身能挡住注入"。
输出的 cases JSON 可直接被 Rust 单测导入（保持单一事实来源）。
"""
import json, re, sys

# ── 与 crates/panel-core/src/lib.rs::rules 保持一致 ──
def is_valid_unit_name(s: str) -> bool:
    if not s or len(s) > 256: return False
    if s.startswith('-') or ".." in s: return False
    return all(c.isascii() and (c.isalnum() or c in "_ . @ -".replace(" ", "")) for c in s)

def is_valid_domain(s: str) -> bool:
    if not s or len(s) > 253: return False
    if s.startswith('.') or s.endswith('.'): return False
    for label in s.split('.'):
        n = len(label)
        if not (1 <= n <= 63): return False
        if not all(c.isascii() and (c.isalnum() or c == '-') for c in label): return False
        if label.startswith('-') or label.endswith('-'): return False
    return True

def is_valid_system_user(s: str) -> bool:
    if not s or len(s) > 32: return False
    if not (s[0].isascii() and (s[0].islower() or s[0] == '_')): return False
    return all(c.isascii() and (c.islower() or c.isdigit() or c in "_-") for c in s[1:])

def is_valid_db_name(s: str) -> bool:
    if not s or len(s) > 64: return False
    return all(c.isascii() and (c.isalnum() or c == '_') for c in s)

def is_valid_path_segment(s: str) -> bool:
    if not s or len(s) > 255: return False
    if '\0' in s or '/' in s or '\\' in s: return False
    return s not in ('.', '..')

CASES = {
    "unit_name": {
        "valid":   ["nginx.service", "panel@1.service", "sshd", "mysql_1.service", "a.b-c@d"],
        "invalid": ["nginx; rm -rf /", "../../etc/passwd", "$(id)", "`id`", "-bad", "a..b", "",
                    "x" * 300, "nginx|cat /etc/shadow", "nginx\nrm -rf /", "unit&id"],
    },
    "domain": {
        "valid":   ["example.com", "a.b.c.example.org", "xn--fiqs8s", "s1.example.com", "1.2.3.4"],
        "invalid": ["-a.com", "a-.com", ".com", "exa mple.com", "a" * 254, "", "a..b",
                    "example.com;rm -rf /", "example.com\nSet-Cookie:x", "$(id).com"],
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
        "valid":   ["site-a", "index.html", "a b"],
        "invalid": ["..", ".", "a/b", "a\0b", "a\\b", "", "s" * 256],
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
    with open("/data/workspace/panel-skeleton/tests-fixtures/validation_cases.json", "w") as fp:
        json.dump(CASES, fp, indent=2, ensure_ascii=False)
    print("用例集已写入 tests-fixtures/validation_cases.json（供 Rust 单测导入）")
    sys.exit(1 if failures else 0)
