#!/usr/bin/env python3
"""F-02① 接线守卫：LLM 测试连接必须「锁 Endpoint + 绝不携带已存密钥」。

为什么需要源码级守卫：
- 纯函数单测只能证明 `resolve_probe_endpoint` / `llmTestBlockReason` 输出正确，
  证明不了 handler 与视图真的调用了它；
- 「把已存密钥读回来」这类改动不会让任何行为测试变红（功能照常，只是密钥
  又被带出去了）。只能钉住 `test_llm` 函数体里不出现取密钥的调用。

活性自检：所有被扫文件必须存在，`test_llm` 函数体必须截取成功且含哨兵点，
纯函数定义处必须恰好 1 处。路径或正则一失效就判红，绝不让空集算通过。
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
FE = ROOT.parent / 'forkpanel-frontend'
FILES = {
    'settings.rs': ROOT / 'crates/panel-api/src/routes/settings.rs',
    'SettingsView.vue': FE / 'src/views/SettingsView.vue',
    'llmTestGate.ts': FE / 'src/utils/llmTestGate.ts',
    'openapi(后端)': ROOT / 'docs/api/openapi.yaml',
    'openapi(前端)': FE / 'src/api/openapi.yaml',
}

errors = []
for label, p in FILES.items():
    if not p.is_file():
        errors.append(f'{label}: 找不到 {p}（扫描失效，绝不能算通过）')
if errors:
    print('F-02① 守卫失败：\n  - ' + '\n  - '.join(errors))
    sys.exit(1)

settings = FILES['settings.rs'].read_text(encoding='utf-8')
view = FILES['SettingsView.vue'].read_text(encoding='utf-8')
gate = FILES['llmTestGate.ts'].read_text(encoding='utf-8')
openapi = FILES['openapi(后端)'].read_text(encoding='utf-8')


def code_lines(src):
    """剔整行注释（Rust `//` / `///`、块注释行）。不切行尾注释，避免误伤 URL。"""
    return [l for l in src.splitlines()
            if not l.lstrip().startswith(('//', '/*', '*'))]


def fn_body(src, needle):
    """按花括号配对截取函数体；截不到返回 None（调用方必须判红）。"""
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines) if needle in l), None)
    if start is None:
        return None
    depth, began, body = 0, False, []
    for line in lines[start:]:
        body.append(line)
        for ch in line:
            if ch == '{':
                depth += 1
                began = True
            elif ch == '}':
                depth -= 1
        if began and depth == 0:
            return '\n'.join(body)
    return None


# ── 1. 定义处活性自检 ──
if settings.count('fn resolve_probe_endpoint(') != 1:
    errors.append('settings.rs: `fn resolve_probe_endpoint(` 定义处应恰好 1 处')
if gate.count('export function llmTestBlockReason(') != 1:
    errors.append('llmTestGate.ts: `export function llmTestBlockReason(` 定义处应恰好 1 处')

# ── 2. handler 函数体：只锁已保存 Endpoint、只读本次输入的密钥 ──
body = fn_body(settings, 'pub async fn test_llm(')
if body is None or 'load_table(' not in body:
    errors.append('settings.rs: test_llm 函数体截取失败或缺哨兵点（扫描失效）')
else:
    code = '\n'.join(code_lines(body))
    for needle in ('resolve_probe_endpoint(', 'saved_endpoint', 'req.api_key.as_deref()'):
        if needle not in code:
            errors.append(f'test_llm 缺少 `{needle}`（Endpoint 锁定/本次密钥接线丢了）')
    for banned in ('plain_api_key(', 'K_LLM_API_KEY'):
        if banned in code:
            errors.append(f'test_llm 又出现了 `{banned}`（已存密钥禁止参与测试）')

# ── 3. 前端提交前拦：比较基准必须是「已保存值」快照，且 load/save 都更新 ──
if 'llmTestBlockReason(' not in view:
    errors.append('SettingsView.vue: 未调用 llmTestBlockReason（前端提前拦丢了）')
if view.count('savedLlmEndpoint.value = report.value.runtime.endpoint') < 2:
    errors.append('SettingsView.vue: savedLlmEndpoint 快照未在 load 与 save 同时更新')

# ── 4. 契约与副本 ──
for needle in ('绝不回退到库里已存值', '目标 Endpoint 锁定为库里已保存的值'):
    if needle not in openapi:
        errors.append(f'openapi 缺少收紧说明 `{needle}`')
if FILES['openapi(后端)'].read_bytes() != FILES['openapi(前端)'].read_bytes():
    errors.append('前后端 openapi 副本不一致')

if errors:
    print('F-02① 守卫失败：\n  - ' + '\n  - '.join(errors))
    sys.exit(1)
print('✓ F-02①：测试连接锁已保存 Endpoint、不携带已存密钥，前后端与契约三处同步')
