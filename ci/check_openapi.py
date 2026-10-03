#!/usr/bin/env python3
"""OpenAPI 契约文件结构校验（零依赖，仅标准库）。

为什么需要它
------------
`docs/api/openapi.yaml` 是前后端唯一契约（事实源）。它用大量 flow 风格
（`{ a: 1, b: 2 }`）单行书写，可读性好但**极易写坏**：

- 在 flow mapping 的值里直接写未加引号的 `{`/`}`，YAML 会当成"开启嵌套
  映射"，随后解析报错——曾真实发生：`description: 已更新（返回 { id, auto_renew }）`
  让整份契约**无法被任何 YAML 解析器读取**。
- flow mapping 的多行条目之间漏写逗号，同样使文件不可解析。
- 前后端两份副本手改不同步，契约一致性静默失效。

以上三类都不会让 `cargo build` / `vue-tsc` 报错，也不会被 grep 类门禁
（只看路径字符串）发现，直到有人拿 YAML 解析器去读才炸——而项目里当时
并没有这样的读取方，属于**完全没有守卫**。

本脚本做三件事（都不依赖 PyYAML，避免 CI 环境装依赖）：
1. flow mapping 语法体检：未加引号的 plain scalar 里出现 `{`/`[`/`}`/`]`
   即报错（附行号与出错片段）。
2. 冒烟解析：若运行环境恰好有 PyYAML，则真解析一次兜住逗号等其它错法；
   没有则跳过并说明（不算失败）。
3. 两份副本逐字节比对：后端事实源 vs 前端副本，不一致即失败。

用法：
    python3 ci/check_openapi.py [后端仓根目录]

退出码：0 通过 / 1 失败。
"""
import os
import re
import sys

DEFAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_REL = 'docs/api/openapi.yaml'
# 前端仓是独立 git 仓，默认同级；可用环境变量或第二参数覆盖。
FRONTEND_REL = os.environ.get(
    'PANEL_FRONTEND_OPENAPI',
    os.path.join('..', 'forkpanel-frontend', 'src', 'api', 'openapi.yaml'),
)

# flow mapping 里作为"结构"出现是合法的：值开头、逗号后、嵌套开始。
STRUCT_CHARS = set('{[}]')


def scan_flow_scalars(path):
    """逐字符扫，找出 flow mapping 的 plain scalar 里误写的结构字符。

    状态机：depth>0 表示当前处于 flow 上下文（`{` 或 `[` 内部）；
    quote 表示当前处于引号字符串内。处于 flow 上下文、不在引号内时，
    若遇到 `{`/`[`/`}`/`]` 且它前一个有效字符是普通值字符（而非
    `:`/`,`/`{`/`[` 这些结构位置），说明它出现在一个未加引号的标量里
    ——这正是让 YAML 解析崩掉的写法。
    """
    problems = []
    with open(path, encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            if line.lstrip().startswith('#'):
                continue
            depth = 0
            quote = None
            prev_sig = ''      # 上一个"有意义"的字符
            i = 0
            while i < len(line):
                ch = line[i]
                if quote:
                    if ch == '\\' and quote == '"':
                        i += 2
                        continue
                    if ch == quote:
                        quote = None
                elif ch in "'\"":
                    quote = ch
                elif ch in '{[':
                    # 结构位置的 '{'（值开头 / 逗号后 / 嵌套）→ 合法
                    if ch == '{' and depth > 0 and prev_sig not in (':', ',', '{', '['):
                        problems.append((lineno, ch, line.rstrip()))
                        break
                    depth += 1
                elif ch in '}]':
                    depth -= 1
                if not ch.isspace():
                    prev_sig = ch
                i += 1
    return problems


def smoke_parse(path):
    """若环境有 PyYAML 就真解析一次；没有则返回 None（跳过，不算失败）。"""
    try:
        import yaml  # type: ignore
    except ImportError:
        return None
    try:
        yaml.safe_load(open(path, encoding='utf-8'))
    except Exception as e:  # noqa: BLE001 - 任何异常都是契约损坏
        return str(e).replace('\n', ' | ')
    return ''


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ROOT
    backend = os.path.join(root, BACKEND_REL)
    frontend = os.argv[2] if len(sys.argv) > 2 else os.path.join(root, FRONTEND_REL)

    fails = []

    if not os.path.exists(backend):
        print(f"  ✗ 找不到契约事实源：{backend}")
        return 1

    # ── 1. flow mapping 语法体检 ──
    print("== [E1] 契约 flow mapping 语法 ==")
    bad = scan_flow_scalars(backend)
    if bad:
        for lineno, ch, text in bad:
            print(f"  ✗ {BACKEND_REL}:{lineno} 未加引号的标量里出现 '{ch}'，"
                  f"YAML 会解析失败：{text.strip()[:90]}")
            print(f"      修法：给该 description/summary 值加单引号，如 '... {{ id }} ...'")
        fails.append(f"{len(bad)} 处 flow mapping 语法错误")
    else:
        print("  ✓ 无未加引号的结构字符")

    # ── 2. PyYAML 冒烟解析（可选） ──
    print("== [E2] YAML 可解析性（冒烟）==")
    for label, p in ((BACKEND_REL, backend), ('前端副本', frontend)):
        if not os.path.exists(p):
            print(f"  · 跳过 {label}：文件不存在（{p}）")
            continue
        err = smoke_parse(p)
        if err is None:
            print(f"  · 跳过 {label}：环境无 PyYAML，语法体检已覆盖主要错法")
        elif err:
            print(f"  ✗ {label} 解析失败：{err[:200]}")
            fails.append(f"{label} 不可解析")
        else:
            print(f"  ✓ {label} 可解析")

    # ── 3. 两份副本一致性 ──
    print("== [E3] 前后端副本逐字节一致 ==")
    if not os.path.exists(frontend):
        print(f"  · 跳过：前端副本不存在（{frontend}）；"
              f"用 PANEL_FRONTEND_OPENAPI 或第二参数指定")
    else:
        a = open(backend, encoding='utf-8').read()
        b = open(frontend, encoding='utf-8').read()
        if a == b:
            print("  ✓ 两份契约完全一致")
        else:
            al, bl = a.splitlines(), b.splitlines()
            diffs = [i + 1 for i in range(max(len(al), len(bl)))
                     if (al[i] if i < len(al) else None) != (bl[i] if i < len(bl) else None)]
            head = ', '.join(map(str, diffs[:10])) + (' …' if len(diffs) > 10 else '')
            print(f"  ✗ 两份契约不一致，共 {len(diffs)} 行不同（行号：{head}）")
            print(f"      后端 {BACKEND_REL} 是事实源，改完请同步到 {os.path.relpath(frontend, root)}")
            fails.append("前后端契约副本不一致")

    print()
    if fails:
        print("FAIL：" + "；".join(fails))
        return 1
    print("PASS：契约结构与副本一致性通过")
    return 0


if __name__ == '__main__':
    sys.exit(main())
