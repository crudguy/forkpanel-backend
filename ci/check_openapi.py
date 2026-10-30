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

以上各类都不会让 `cargo build` / `vue-tsc` 报错，也不会被 grep 类门禁
（只看路径字符串）发现，直到有人拿 YAML 解析器去读才炸——而项目里当时
并没有这样的读取方，属于**完全没有守卫**。结构错位（第 4 项）更隐蔽：
PyYAML 都能"解析成功"，只有按语义消费契约的读取方才拿得到错误结构。

本脚本做六件事（都不依赖 PyYAML，避免 CI 环境装依赖）：
1. flow mapping 语法体检：未加引号的 plain scalar 里出现 `{`/`[`/`}`/`]`
   即报错（附行号与出错片段）。
2. 冒烟解析：若运行环境恰好有 PyYAML，则真解析一次兜住逗号等其它错法；
   没有则跳过并说明（不算失败）。
3. 两份副本逐字节比对：后端事实源 vs 前端副本，不一致即失败。
4. 结构体检（[E4]，零依赖）：同级重复键 / `$ref` 目标存在性 / schemas
   直系缩进 / **路径键落点**——缩进错位的定义块（曾真实发生：`SiteRoute:`
   多缩进 4 格、`App:` 顶格）不会让第 1/2 项报错，只在语义上把 schema
   顶替或丢失；路径键掉出 `paths:` 块（曾真实发生：`join-docker-group`
   顶格写成顶层键，其后一批路径全被错位吞掉，PyYAML 一读即 ParserError，
   无 PyYAML 的门禁环境里 [E1]/[E3]/[E4]/[E5] 却全绿）同属静默结构错位。
5. 行级括号平衡（[E5]，零依赖）：行尾多/少一个 `}`（曾真实发生：
   system/users 响应 schema 行 10 开 11 闭，整份文件从该行起不可解析）
   ——第 1 项只看非法位置的开括号，PyYAML 缺席时第 2 项跳过，第 3/4 项
   不依赖括号闭合，全靠本项兜住。

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
                    # 只有结构位置的 '{'/'['（行首 / 冒号后 / 逗号后 / 嵌套 / 块序列 '-' 后）
                    # 才是真正的 flow 上下文入口；其它位置是 plain scalar 内容——在 block
                    # 上下文（如 description: | 的说明文字）合法，在 flow 上下文非法。
                    structural = (prev_sig == '') or (prev_sig in (':', ',', '{', '[', '-'))
                    if not structural and depth > 0:
                        problems.append((lineno, ch, line.rstrip()))
                        break
                    if structural:
                        depth += 1
                elif ch in '}]':
                    if depth > 0:
                        depth -= 1
                if not ch.isspace():
                    prev_sig = ch
                i += 1
    return problems


def scan_bracket_balance(path):
    """逐行检查 `{}` / `[]` 括号平衡（引号感知，跳过注释与块标量内容）。

    为什么需要
    ----------
    [E1] 只查「标量里多了结构字符」（非法位置的开括号），查不出**行尾多一个
    闭括号**：`... login_allowed: { type: boolean } } } } } } }`（10 开 11 闭）
    里每一段流映射单看都合法，只有数总账才发现多一个 `}`——而它让整份文件
    **从该行起无法被任何 YAML 解析器读取**。PyYAML 缺席时 [E2] 跳过，[E3]
    副本比对、[E4] 结构体检（它们不依赖括号闭合）也都会报绿，属于治理盲区。
    曾真实发生：该行横跨 3 个提交未被发现，本次手工数括号才定位。

    与书写风格的耦合：flow 结构不跨行（本文件约定）——若未来出现跨行 flow，
    本函数需按「括号计数跨行结转」升级。

    返回 (problems, stats)：
    - problems: [(行号, 类型, 净深度, 行文本)]，类型 ∈ extra-close /
      unbalanced / unterminated-quote；
    - stats: {'lines': 总行数, 'brace_lines': 含括号的行数}（供前提断言）。
    """
    problems = []
    lines = open(path, encoding='utf-8').read().splitlines()
    brace_lines = 0
    skip_to = -1
    for i, line in enumerate(lines):
        lineno = i + 1
        if i < skip_to or line.lstrip().startswith('#'):
            continue
        ind = len(line) - len(line.lstrip())
        if re.search(r':\s*[|>][-+0-9]*\s*$', line):
            j = i + 1
            while j < len(lines) and (not lines[j].strip()
                                      or (len(lines[j]) - len(lines[j].lstrip())) > ind):
                j += 1
            skip_to = j
            continue
        if not any(c in line for c in '{[}]'):
            continue
        brace_lines += 1
        depth = 0
        quote = None
        k = 0
        problem = None
        while k < len(line):
            ch = line[k]
            if quote:
                if quote == '"' and ch == '\\':
                    k += 2
                    continue
                if quote == "'" and ch == "'" and k + 1 < len(line) and line[k + 1] == "'":
                    k += 2          # YAML 单引号内两个 '' 表示一个字面 '
                    continue
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == '#' and (k == 0 or line[k - 1] in ' \t'):
                break               # 行内注释：其后不再计入
            elif ch in '{[':
                depth += 1
            elif ch in '}]':
                depth -= 1
                if depth < 0:
                    problem = ('extra-close', depth)
                    break
            k += 1
        if problem is None and quote:
            problem = ('unterminated-quote', depth)
        if problem is None and depth != 0:
            problem = ('unbalanced', depth)
        if problem:
            problems.append((lineno, problem[0], problem[1], line))
    return problems, {'lines': len(lines), 'brace_lines': brace_lines}


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


def is_misplaced_path(key: str, container: str, ind: int) -> bool:
    """API 路径键（`/api/v1/...` 形态）必须是顶层 `paths:` 的直属子级（缩进 2）。

    为什么需要
    ----------
    曾真实发生：`/api/v1/containers/join-docker-group:` 顶格（0 缩进）写成了
    顶层键，从它下一行起所有路径都被错位吞进它的块内——PyYAML 直接
    ParserError（整份契约不可读），而 [E1] 括号/标量体检、[E3] 副本比对、
    [E4] 原三项、[E5] 行级括号平衡**全部报绿**（[E2] 冒烟解析在无 PyYAML
    的环境跳过）。零依赖环境下唯一能抓住它的就是本条按缩进的落点断言。
    """
    return key.startswith('/') and not (container == 'paths' and ind == 2)


def scan_structure(path):
    """按缩进解析键路径，做四项结构体检（零依赖，不用 YAML 解析器）。

    为什么需要
    ----------
    缩进错位的定义块不会让 [E1] 报错：把 `    SiteRoute:` 误写成 8 空格后，它成了
    上层 properties 下的「空值键」，后面跟着的 `type/properties` 与上层重名——PyYAML
    对重复键「取后者」，解析**成功**但语义已坏（Site 的 properties 被顶替、
    SiteRoute 从 components.schemas 里消失）。曾真实发生：`SiteRoute:` 多缩进 4 格 +
    `App:` 顶格，横跨 3 个提交无人发现——唯一可靠信号就是这份结构体检。

    返回 (dups, paths, bad_schema_children, misplaced_paths, ok_paths)：
    - dups: [(行号, 键, 容器路径)] 同级重复键——YAML 语义上不允许，出现即结构错位；
    - paths: 所有键的完整路径集合（供 $ref 目标存在性检查）；
    - bad_schema_children: components/schemas 直系子级中缩进非 4 空格的行；
    - misplaced_paths: [(行号, 键, 容器, 缩进)] 长得像 API 路径（`/` 开头）却不在
      顶层 `paths:` 直属子级（缩进 2）上的键——掉出 paths 块的结构错位；
    - ok_paths: 正确挂在 paths 直属子级上的路径键（供前提断言数「真提取到了」）。

    与书写风格的耦合（改风格须同步升级本函数）：
    - 块标量（`|` / `>`）内容按缩进跳过，否则描述文本里的 `xx:` 会被当成键；
    - 列表项行 `- `：块状项（`- key: v`）自建唯一容器 `#item@行号` 隔离同级重复
      （servers 这类「多项各带续行」写法因此不误报）；flow 项（`- {…}` / `- $ref`）
      视为不透明；
    - 描述值均单行内联、flow 不跨行——若未来出现跨行 flow，需扩展本解析。
    """
    lines = open(path, encoding='utf-8').read().splitlines()
    dups, paths, bad, misplaced, ok_paths = [], set(), [], [], []
    stack = []              # [(indent, path)] 键路径栈
    seen = {}               # (container_path, indent) -> set(keys) 同级键去重表
    skip_to = -1            # 块标量内容的跳过终止行
    i, n = 0, len(lines)
    while i < n:
        l = lines[i]
        if i < skip_to or not l.strip() or l.lstrip().startswith('#'):
            i += 1
            continue
        s = l.lstrip()
        m_item = re.match(r'^(\s*)- (.*)$', l)
        if m_item:
            ind = len(m_item.group(1))
            rest = m_item.group(2)
            while stack and stack[-1][0] >= ind:
                stack.pop()
            container = stack[-1][1] if stack else ''
            item_id = f'{container}/#item@{i + 1}'
            if rest.startswith(('{', '[')):
                stack.append((ind, item_id))
            else:
                m_k = re.match(r'^([^\s#][^:]*):(\s|$)', rest)
                if m_k:
                    key = m_k.group(1).strip()
                    full = item_id + '/' + key
                    paths.add(full)
                    if is_misplaced_path(key, item_id, ind):
                        misplaced.append((i + 1, key, item_id, ind))
                    bucket = seen.setdefault((item_id, ind + 2), set())
                    if key in bucket:
                        dups.append((i + 1, key, item_id))
                    bucket.add(key)
                    stack.append((ind, item_id))
                    stack.append((ind + 2, full))
                else:
                    stack.append((ind, item_id))
            i += 1
            continue
        m = re.match(r'^([^\s#][^:]*):(\s|$)', s)
        if not m:
            i += 1
            continue
        key = m.group(1).strip()
        ind = len(l) - len(s)
        while stack and stack[-1][0] >= ind:
            stack.pop()
        container = stack[-1][1] if stack else ''
        full = (container + '/' + key) if container else key
        paths.add(full)
        if is_misplaced_path(key, container, ind):
            misplaced.append((i + 1, key, container, ind))
        elif key.startswith('/'):
            ok_paths.append(key)
        bucket = seen.setdefault((container, ind), set())
        if key in bucket:
            dups.append((i + 1, key, container or '<root>'))
        bucket.add(key)
        if container == 'components/schemas' and ind != 4:
            bad.append((i + 1, ind, s))
        stack.append((ind, full))
        if re.search(r':\s*[|>][-+0-9]*\s*$', l):
            j = i + 1
            while j < n and (not lines[j].strip()
                             or (len(lines[j]) - len(lines[j].lstrip())) > ind):
                j += 1
            skip_to = j
        i += 1
    return dups, paths, bad, misplaced, ok_paths


def collect_refs(text):
    """抽取全部 `$ref: '#/components/…'` 目标路径（兼容两种引号）。"""
    return (set(re.findall(r"\$ref:\s*'#/([^']+)'", text))
            | set(re.findall(r'\$ref:\s*"#/([^"]+)"', text)))


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ROOT
    backend = os.path.join(root, BACKEND_REL)
    frontend = sys.argv[2] if len(sys.argv) > 2 else os.path.join(root, FRONTEND_REL)

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

    # ── 4. 结构体检：同级重复键 / $ref 目标存在 / schemas 直系缩进 ──
    print("== [E4] 契约结构（同级重复键 / $ref 目标存在 / 路径键落点）==")
    dups, paths, bad_children, misplaced, ok_paths = scan_structure(backend)
    refs = collect_refs(open(backend, encoding='utf-8').read())
    # 前提断言：提取结果异常少 = 解析器自己失效（或文件被大改）。
    # 绝不能因为「没扫到东西」而报绿——恒绿的门禁比没有门禁更危险。
    if len(paths) < 100 or len(refs) < 5:
        print(f"  ✗ 提取异常：键路径 {len(paths)} 个、$ref {len(refs)} 个——解析前提不成立")
        print("      修法：先确认契约文件未被截断/换书写风格；若是风格变化，需同步升级 scan_structure")
        fails.append("结构解析前提不成立（检查器需维护）")
    else:
        if dups:
            for lineno, key, container in dups[:10]:
                print(f"  ✗ {BACKEND_REL}:{lineno} 同级重复键 '{key}'"
                      f"（容器：{container}）")
            print("      修法：YAML 不允许同级重复键；多为缩进错位——把该块挪回正确层级"
                  "（典型：schema 名多缩进而把上一个块的尾部写成了重复键）")
            fails.append(f"{len(dups)} 处同级重复键")
        else:
            print("  ✓ 无同级重复键")
        missing = sorted(r for r in refs if r not in paths)
        if missing:
            for r in missing[:10]:
                print(f"  ✗ $ref 目标不存在：#/{r}")
            print("      修法：补上缺失的 schema/parameter 定义，或修正其缩进"
                  "（定义写错层级时，按引用路径找不到它）")
            fails.append(f"{len(missing)} 个 $ref 目标缺失")
        else:
            print(f"  ✓ {len(refs)} 个 $ref 目标全部存在")
        if bad_children:
            for lineno, ind, text in bad_children[:10]:
                print(f"  ✗ {BACKEND_REL}:{lineno} schemas 直系子级缩进 {ind}"
                      f"（应为 4）：{text.strip()[:60]}")
            fails.append(f"{len(bad_children)} 处 schemas 子级缩进异常")
        # 路径键落点：API 路径键必须全部是 paths 的直属子级（缩进 2）。
        # 前提断言同上面两项——扫到的 paths 子级路径键过少 = 解析器失效，
        # 绝不因「没扫到」而报绿。
        if len(ok_paths) < 50:
            print(f"  ✗ 提取异常：paths 下仅扫到 {len(ok_paths)} 个路径键——解析前提不成立")
            print("      修法：先确认契约文件未被截断；若 paths 数量合法地降到 50 以下，"
                  "同步调整本阈值")
            fails.append("paths 提取前提不成立（检查器需维护）")
        elif misplaced:
            for lineno, key, container, ind in misplaced[:10]:
                print(f"  ✗ {BACKEND_REL}:{lineno} 路径键 '{key}' 不在 paths 块内"
                      f"（所在容器：{container or '<root>'}，缩进 {ind}，应为 paths 下 2）")
            print("      修法：paths 直属子级统一 2 空格缩进；顶格/多缩进都会让路径"
                  "掉出 paths 块——文件随即无法被任何 YAML 解析器读取")
            fails.append(f"{len(misplaced)} 个路径键掉出 paths 块")
        else:
            print(f"  ✓ {len(ok_paths)} 个路径键全部挂在 paths 块内（缩进 2）")

    # ── 5. 行内括号平衡（零依赖，兜住「行尾多/少一个闭括号」）──
    print("== [E5] flow 括号平衡（行级）==")
    problems, stats = scan_bracket_balance(backend)
    # 前提断言：本文件应含大量流式括号行；扫到的太少 = 检查器失效，绝不报绿
    if stats['brace_lines'] < 50:
        print(f"  ✗ 提取异常：仅 {stats['brace_lines']} 行含括号（共 {stats['lines']} 行）"
              "——解析前提不成立")
        fails.append("括号检查前提不成立（检查器需维护）")
    elif problems:
        kinds = {'extra-close': '多一个闭括号',
                 'unbalanced': '括号未闭合（开多于闭）',
                 'unterminated-quote': '引号未闭合'}
        for lineno, kind, depth, text in problems[:10]:
            extra = f"（净深度 {depth}）" if kind == 'unbalanced' else ''
            print(f"  ✗ {BACKEND_REL}:{lineno} {kinds.get(kind, kind)}{extra}："
                  f"{text.strip()[:90]}")
        print("      修法：flow 结构不跨行；数该行 {} [] 开闭总数是否相等"
              "（引号内与注释里的不计）")
        fails.append(f"{len(problems)} 处括号不平衡")
    else:
        print(f"  ✓ {stats['brace_lines']} 个括号行全部平衡（共 {stats['lines']} 行）")

    print()
    if fails:
        print("FAIL：" + "；".join(fails))
        return 1
    print("PASS：契约结构与副本一致性通过")
    return 0


if __name__ == '__main__':
    sys.exit(main())
