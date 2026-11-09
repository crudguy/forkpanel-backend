#!/usr/bin/env python3
"""外部命令输出回显前必须过 panel_core::sanitize（production-readiness §3.3 P1）。

## 为什么
`PanelError::Command` / `ConfigInvalid` 的 detail 同时经两条路回到 API 客户端：
`Display` 拼进 message、error.rs 拼进 detail.stderr/detail.output。nginx -t /
certbot / tar / psql 的 stderr 会携带面板校验临时目录、ACME 账户邮箱与账户 ID。
脱敏只能发生在**构造侧**（到 API 边界时 message 已拼好），所以钉构造点。

## 判据（三类恒绿防护）
1. 生产代码里 `PanelError::Command {` / `ConfigInvalid {` 构造块总数 == TOTAL_PIN
   ——正则写错/目录挪走会静默空转，靠计数兜底；新增构造点会撞红，提醒接线。
2. 构造块内引用 `stderr`/`stdout` 的，必须同块调用 `sanitize` ——违例数 == 0。
3. `panel_core::sanitize` 调用数 == SANITIZE_PIN ——函数被改名/移走会判红而非假绿。

## 构造块识别
从关键字后的第一个 `{` 做括号配对提取块文本。match 模式（`{ bin, detail }`）
不含 `detail:` 字段赋值，天然不计为构造点。测试模块按 strip_tests 约定剥离；
注释按行剥离（说明文字提到 stderr 是正常的）。
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"

# 钉死值（2026-11-09 实测）：改构造点/接线会撞红，需有意识地更新
TOTAL_PIN = 66
SANITIZE_PIN = 34

HEAD = re.compile(r"(?:PanelError::)?(Command|ConfigInvalid)\s*\{")
FIELD = re.compile(r"\bdetail\s*:")
EXTERNAL = re.compile(r"\b(stderr|stdout)\b")
SANITIZED = re.compile(r"\bsanitize::(stderr|external_output)\b")


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


def prod_text(path: Path) -> str:
    """生产段：剥注释 + 砍 #[cfg(test)] 起的整段（与 ci/strip_tests.py 同约定）。"""
    lines = path.read_text(encoding="utf-8").splitlines()
    cut = len(lines)
    for i, l in enumerate(lines):
        if l.strip().startswith("#[cfg(test)]"):
            cut = i
            break
    return "\n".join(strip_comments(l) for l in lines[:cut])


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
    return text[brace_at:]  # 不配平（语法错误会被 cargo 先拦住）


def main() -> int:
    if not CRATES.is_dir():
        print(f"FAIL：找不到 {CRATES}（不能静默跳过）")
        return 1

    files = sorted(
        p for p in CRATES.rglob("*.rs")
        if "target" not in p.parts and p.stem != "tests" and not p.stem.endswith("_tests")
    )
    if len(files) < 20:
        print(f"FAIL：只扫到 {len(files)} 个 .rs——疑似扫错目录")
        return 1

    total = 0
    sanitize_calls = 0
    violations = []
    for p in files:
        text = prod_text(p)
        sanitize_calls += len(SANITIZED.findall(text))
        for m in HEAD.finditer(text):
            brace = text.index("{", m.start())
            block = extract_block(text, brace)
            if not FIELD.search(block):
                continue  # match 模式 / 非构造
            total += 1
            if EXTERNAL.search(block) and not SANITIZED.search(block):
                line = text[: m.start()].count("\n") + 1
                violations.append(f"{p.relative_to(ROOT)}:{line}")

    if total != TOTAL_PIN:
        print(f"FAIL：构造点总数 {total} != 钉死值 {TOTAL_PIN}。"
              "新增了构造点（请接线 sanitize 并更新钉值）或扫描失效（正则/目录变了）")
        return 1
    if sanitize_calls != SANITIZE_PIN:
        print(f"FAIL：sanitize 调用数 {sanitize_calls} != 钉死值 {SANITIZE_PIN}。"
              "sanitize 被改名/移走/漏接线")
        return 1
    if violations:
        print("FAIL：以下构造点携带外部 stderr/stdout 但未过 panel_core::sanitize：")
        for v in violations:
            print(f"  {v}")
        return 1

    print(f"PASS：{total} 个构造点、{sanitize_calls} 处 sanitize 调用、0 违例")
    return 0


if __name__ == "__main__":
    sys.exit(main())
