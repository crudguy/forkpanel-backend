#!/usr/bin/env python3
"""
在**生产代码**中搜索模式（剥离文件末尾的 #[cfg(test)] 测试模块）。

用法：
  python3 ci/strip_tests.py <pattern> [--root crates] [--ext .rs]

为什么需要它：
测试里会出现 "nginx; rm -rf /" 这类注入样本、/etc/shadow 这类路径字面量，
它们是**被测数据**而非违规。直接 grep 会误报，导致团队养成"加 grep -v 绕过"的坏习惯。
统一在这里剥离，豁免面集中可控。

另输出（无参数时）：from_raw 的调用点，供「强类型构造点审计」使用。
"""
import os, re, sys

def prod_files(root, ext):
    for dirpath, dirs, files in os.walk(root):
        # tests/ 目录整体豁免（集成测试的 fixture 也是数据）
        dirs[:] = [d for d in dirs if d != "tests"]
        for fn in files:
            if not fn.endswith(ext):
                continue
            # 单元测试子模块文件（tests.rs / <name>_tests.rs）整体豁免——与行内
            # #[cfg(test)] mod 同等：里面是测试 fixture / 注入样本 / 路径字面量，
            # 是被测数据而非生产违规。这类文件的 cfg(test) 在父模块的 `mod X;`
            # 声明上、文件自身无 #[cfg(test)] 行，prod_lines 切不断，故按命名约定在此豁免。
            base = fn[: -len(ext)]
            if base == "tests" or base.endswith("_tests"):
                continue
            yield os.path.join(dirpath, fn)

def prod_lines(path):
    """返回 (行号, 内容) 的生产代码行"""
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except Exception:
        return
    cut = len(lines)
    for i, l in enumerate(lines):
        if l.strip().startswith("#[cfg(test)]"):
            cut = i
            break
    for i, l in enumerate(lines[:cut], 1):
        yield i, l

def main():
    args = [a for a in sys.argv[1:]]
    root = "crates"
    ext = ".rs"
    if "--root" in args:
        root = args[args.index("--root") + 1]
        args = [a for a in args if a != "--root" and a != root]
    if "--ext" in args:
        ext = args[args.index("--ext") + 1]
        args = [a for a in args if a != "--ext" and a != ext]
    pattern = args[0] if args else "from_raw"

    rx = re.compile(pattern)
    for p in prod_files(root, ext):
        for i, l in prod_lines(p):
            if rx.search(l):
                print(f"{p}:{i}: {l.strip()}")

if __name__ == "__main__":
    main()
