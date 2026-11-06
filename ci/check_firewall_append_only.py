#!/usr/bin/env python3
"""F-20 接线守卫：两个真实后端的 apply 只能是「追加/确保存在」语义。

行为测试（rule_plan_append.rs）能证明公共判据正确，但挡不住某个后端自己又写回
「过期清理」。这里直接钉住 ufw / nft 两份 apply 的函数体：必须用同一份
plan_additions、removed 恒 0、且不含任何删除调用。

⚠ 扫描式守卫先证明「真的抓到了东西」（活性自检），再做集合/包含断言，
否则正则一旦失效就是「空集恒真」的假绿。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPLS = {
    'ufw': ROOT / 'crates/panel-os/src/linux/firewall.rs',
    'nft': ROOT / 'crates/panel-os/src/linux/firewall_nft.rs',
}
TRAITS = ROOT / 'crates/panel-os/src/traits.rs'
ROUTES = ROOT / 'crates/panel-api/src/routes/firewall.rs'

errors = []


def code_lines(src: str) -> str:
    """剔注释行与行尾注释；块注释按行配对剥除。"""
    out = []
    in_block = False
    for line in src.splitlines():
        if in_block:
            if '*/' in line:
                line = line.split('*/', 1)[1]
                in_block = False
            else:
                continue
        if '/*' in line:
            line = line.split('/*', 1)[0]
            in_block = True
        out.append(line.split('//', 1)[0])
    return '\n'.join(out)


def apply_body(src: str):
    """按花括号配对截出第一个 `async fn apply` 的完整函数体（原文，未剔注释）。"""
    m = re.search(r'^\s*async fn apply\(', src, re.M)
    if not m:
        return None
    i = src.find('{', m.start())
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(src)):
        if src[j] == '{':
            depth += 1
        elif src[j] == '}':
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return None


# ── 活性自检：扫描确实抓到了被检查的那份代码 ──
traits_code = code_lines(TRAITS.read_text())
if traits_code.count('pub fn plan_additions(') != 1:
    errors.append('traits.rs 里 pub fn plan_additions 定义必须恰好 1 处（扫描失效不得算过）')
if 'pub fn user_comment(' not in traits_code:
    errors.append('traits.rs 里找不到 pub fn user_comment')

routes_code = code_lines(ROUTES.read_text())
if 'panel_os::user_comment(' not in routes_code:
    errors.append('routes/firewall.rs 未把 comment 洗成用户备注')
if 'RulePlan { rules }' not in routes_code:
    errors.append('routes/firewall.rs 未构造追加语义的 RulePlan')

# 旧字段是「配置项假控制」（没有任何实现读它），删掉后不允许再出现在代码行里
for label, path in [('traits.rs', TRAITS), ('routes/firewall.rs', ROUTES), *IMPLS.items()]:
    # ⚠ 每条扫描路径都要有活性自检：路径失效若直接 read_text() 会抛 FileNotFoundError，
    #   那是「崩溃」而不是可识别的红，CI 里同样会淹没真失败。
    if not path.is_file():
        errors.append(f'{label}: 找不到实现文件 {path.name}（扫描失效，绝不能算通过）')
        continue
    if 'replace_panel_managed_only' in code_lines(path.read_text()):
        errors.append(f'{label} 代码里又出现了已删除的 replace_panel_managed_only 字段')

# ── 两个实现的 apply 函数体 ──
BANNED = ('delete_number(', '"delete", "rule"', 'delete_rule(', 'stale', 'removed += 1')
for name, path in IMPLS.items():
    if not path.is_file():
        errors.append(f'{name}: 找不到实现文件 {path.name}（扫描失效，绝不能算通过）')
        continue
    src = path.read_text()
    body = apply_body(src)
    if not body or 'Ok(ApplyReport' not in body:
        errors.append(f'{name}: 没抓到完整的 apply 函数体（扫描失效，绝不能算通过）')
        continue
    body = code_lines(body)
    if 'plan_additions(' not in body:
        errors.append(f'{name}: apply 未调用公共判据 plan_additions')
    if 'let removed = 0;' not in body:
        errors.append(f'{name}: apply 的 removed 不是恒定 0（又在删既有规则？）')
    if 'unchanged' not in body:
        errors.append(f'{name}: apply 没有幂等计数 unchanged')
    for bad in BANNED:
        if bad in body:
            errors.append(f'{name}: apply 里出现了删除/过期清理代码 {bad!r}')

if errors:
    print('FAIL：F-20 追加语义守卫')
    for e in errors:
        print(f'  ✗ {e}')
    sys.exit(1)

print(f'✓ F-20：{len(IMPLS)} 个真实后端 apply 均为追加语义（0 删除调用，共用 plan_additions）')
