#!/usr/bin/env python3
"""禁止生产代码里出现裸的 `lock().unwrap()` / `lock().expect(`。

## 为什么
`std::sync::Mutex::lock()` 在持锁线程 panic 后返回 `Err(PoisonError)`。裸 unwrap
会让**此后每一次**持锁请求继续 panic——一个 handler 的边界 bug 演变成整个功能
永久 500，直到重启进程。统一走 `panel_core::sync::lock_recover`（中毒时恢复内部
值继续用；本项目这些锁保护的都是可重建的运行时状态）。

## 判据（三类恒绿防护）
1. 扫到的 .rs 文件数低于阈值 ⇒ 认为扫错目录，判失败（不是"没问题"）。
2. 全文一次都没见到 `lock_recover(` ⇒ 说明检查的对象已不存在（重命名/移走），
   判失败，避免"规则还在、代码已不按它写"的假覆盖。
3. **测试模块与注释不算**：生产文件末尾的 `#[cfg(test)] mod tests` 整段跳过
   （里面刻意制造中毒是合法的）；注释（整行或行尾）跳过——说明文字里提到
   `lock().unwrap()` 是正常的。行尾注释用**引号感知**的剥离，避免把字符串里的
   `//` 当注释（那会造成漏检）。

## 例外
`crates/panel-core/src/sync.rs` 是恢复函数本身的实现与测试，整体豁免。
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"
# 实现与自测都在这个文件里（它必须能写裸 lock().unwrap() 来"制造中毒"）
ALLOW_FILES = {"panel-core/src/sync.rs"}
MIN_FILES = 20  # 低于此数视为扫错目录

BAD = re.compile(r"lock\(\)\s*\.\s*(unwrap|expect)\s*\(")


def code_part(line: str) -> str:
    """去掉行尾注释，保留引号内的内容。

    朴素地 `line.split("//")` 会把 `"a//b"` 这类字符串截断，进而漏检它后面的代码；
    这里用一个极小的状态机（只认 `"` `'` 与反斜杠转义）跟踪是否在字符串里。
    Rust 的原始字符串 `r#"..."#` 在本仓的锁调用处并不出现，不做处理。
    """
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


def strip_test_module(text: str) -> str:
    """砍掉第一个顶格 `#[cfg(test)]` + `mod tests` 起的整段。

    约定：测试模块放文件末尾且顶格书写（全仓现状如此）。这样既不用做括号配对，
    也不会误伤写在某个函数上的 `#[cfg(test)]`。
    """
    m = re.search(r"^#\[cfg\(test\)\]\s*\n\s*mod\s+\w+\s*\{", text, re.M)
    return text[: m.start()] if m else text


def main() -> int:
    if not CRATES.is_dir():
        print(f"FAIL：找不到 {CRATES}（不能静默跳过）")
        return 1

    files = sorted(CRATES.rglob("*.rs"))
    files = [f for f in files if "target" not in f.parts]
    if len(files) < MIN_FILES:
        print(f"FAIL：只扫到 {len(files)} 个 .rs（阈值 {MIN_FILES}）——疑似扫错目录")
        return 1

    hits = []
    saw_recover = False
    for f in files:
        rel = f.relative_to(CRATES).as_posix()
        text = f.read_text(encoding="utf-8", errors="replace")
        if "lock_recover(" in text:
            saw_recover = True
        if rel in ALLOW_FILES:
            continue
        body = strip_test_module(text)
        for i, line in enumerate(body.splitlines(), 1):
            code = code_part(line)
            if not code.strip():
                continue
            if BAD.search(code):
                hits.append((rel, i, line.strip()))

    print(f"== 锁中毒恢复守卫 ==（扫过 {len(files)} 个 .rs）")

    if not saw_recover:
        print("FAIL：全仓没有一处 `lock_recover(` —— 检查对象已不存在，本守卫失去意义")
        return 1

    if hits:
        print(f"  ✗ 发现 {len(hits)} 处裸 lock().unwrap()/expect()（应用 lock_recover）：")
        for rel, ln, src in hits[:20]:
            print(f"    crates/{rel}:{ln}: {src}")
        if len(hits) > 20:
            print(f"    …… 其余 {len(hits) - 20} 处省略")
        return 1

    print("  ✓ 生产代码无裸 lock().unwrap()/expect()")
    return 0


if __name__ == "__main__":
    sys.exit(main())
