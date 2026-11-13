#!/usr/bin/env python3
"""F-02① 接线守卫：LLM 测试连接必须「锁 Endpoint + 密钥只经 resolve_probe_key」。

口径变更（2026-11-13，随 251b0ea）：原规则「绝不读取已存 api_key」被**有界放宽**——
框留空时允许回退库里已存（解密后）的密钥，修 Agnes 类服务对 /chat/completions
强制鉴权导致的 401 误报。放宽的前提是 `resolve_probe_endpoint` 仍把探测目标
**锁定为已保存值**：回退的密钥只会发到管理员自己的端点，原规则要防的
「把密钥导向攻击者主机」已不成立。

为什么仍需要源码级守卫：
- 纯函数单测只能证明 `resolve_probe_endpoint` / `llmTestBlockReason` 输出正确，
  证明不了 handler 与视图真的调用了它；
- 风险面从「读回已存密钥」变成「绕过 Endpoint 锁 / 绕过 resolve_probe_key /
  把密钥直接发给请求体指定的主机」——这类改动功能照常，行为测试不会变红。
  故判据**不是删掉 banned 让它变绿**，而是换成：
    ✅ 目标仍由 `let endpoint = match resolve_probe_endpoint(&saved_endpoint, …)` 锁定；
    ✅ 密钥只经 `let api_key = resolve_probe_key(…)`，回退来源是 table.get(K_LLM_API_KEY)；
    ❌ 禁止 `test_llm` 体内直接 `plain_api_key(`（绕过统一解密出口）。
  Endpoint 锁或 resolve_probe_key 任一被拆，上面的 needle 就会消失 ⇒ 判红。
- 契约（openapi）必须写明新口径，前后端副本逐字节一致。

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
if settings.count('fn resolve_probe_key(') != 1:
    errors.append('settings.rs: `fn resolve_probe_key(` 定义处应恰好 1 处（留空回退已存密钥的唯一出口）')
if gate.count('export function llmTestBlockReason(') != 1:
    errors.append('llmTestGate.ts: `export function llmTestBlockReason(` 定义处应恰好 1 处')

# ── 2. handler 函数体：锁已保存 Endpoint + 密钥只经 resolve_probe_key ──
# 新口径：允许回退已存密钥，但必须 ① 目标由 resolve_probe_endpoint 锁定为
# 已保存值；② 密钥只经 resolve_probe_key 取得（填了优先 / 留空回退已存）。
# ⚠ 判据要能区分「安全实现」与「把密钥发到任意主机」：拆掉 Endpoint 锁、
#   绕过 resolve_probe_key、或直接在 handler 里解密，下面的 needle/banned 必判红。
body = fn_body(settings, 'pub async fn test_llm(')
if body is None or 'load_table(' not in body:
    errors.append('settings.rs: test_llm 函数体截取失败或缺哨兵点（扫描失效）')
else:
    code = '\n'.join(code_lines(body))
    for needle in (
        'let endpoint = match resolve_probe_endpoint(',
        'saved_endpoint',
        'valid_endpoint(&endpoint)',
        'let api_key = resolve_probe_key(',
        'table.get(K_LLM_API_KEY)',
        'req.api_key.as_deref()',
    ):
        if needle not in code:
            errors.append(f'test_llm 缺少 `{needle}`（Endpoint 锁定 / 密钥统一出口接线丢了）')
    for banned in ('plain_api_key(',):
        if banned in code:
            errors.append(f'test_llm 又出现了 `{banned}`（禁止绕过 resolve_probe_key 直接解密）')

# ── 3. 前端提交前拦：比较基准必须是「已保存值」快照，且 load/save 都更新 ──
if 'llmTestBlockReason(' not in view:
    errors.append('SettingsView.vue: 未调用 llmTestBlockReason（前端提前拦丢了）')
if view.count('savedLlmEndpoint.value = report.value.runtime.endpoint') < 2:
    errors.append('SettingsView.vue: savedLlmEndpoint 快照未在 load 与 save 同时更新')

# ── 4. 契约与副本 ──
# 契约口径随 251b0ea 更新：不再写「绝不回退」，改为写清回退前提与 Endpoint 锁。
for needle in ('回退到库里已存的密钥', '目标 Endpoint 锁定为库里已保存的值'):
    if needle not in openapi:
        errors.append(f'openapi 缺少收紧说明 `{needle}`')
if FILES['openapi(后端)'].read_bytes() != FILES['openapi(前端)'].read_bytes():
    errors.append('前后端 openapi 副本不一致')

if errors:
    print('F-02① 守卫失败：\n  - ' + '\n  - '.join(errors))
    sys.exit(1)
print('✓ F-02①：测试连接锁已保存 Endpoint、密钥只经 resolve_probe_key（留空回退已存），前后端与契约三处同步')
