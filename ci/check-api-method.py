#!/usr/bin/env python3
"""守卫：前端调用方法与 openapi 契约必须一致。

## 为什么需要这条守卫

`2026-11-09` 真机发现 `/files/write` 在浏览器里恒 405：前端写 `api.post(...)`，
契约与后端只注册了 `PUT`。后果是**「在线编辑并保存」这个核心功能整整一版不可用**，
而文案只显示「请求失败，请稍后重试」。

为什么别的门禁没抓到：
- `check-api-contract.sh` 比对的是**路径集合**（180 = 180），方法不参与；
- `ci/e2e-files.sh` 用 `put /files/write` **直接打后端**，后端侧全绿；
- 单测不生效真实 HTTP；`vue-tsc` 只认类型 —— `api.post` 与 `api.put` 签名相同。

即「路径对、方法错」是一类**任何现有门禁都看不见**的接线错误，只能靠比对
「调用点的 HTTP 方法」与「契约里该 path 允许的方法」。

## 判据

1. 自检：契约 ≥100 条、endpoints ≥50 条、调用点 ≥100 处 —— 解析器失灵时直接判红，
   不允许「扫到 0 处 ⇒ 通过」这种静默空转；
2. 每个调用点：前端方法必须 ∈ 契约该 path 允许的方法集合；
3. 前端用到契约里没有的 path ⇒ 判红（路径拼错同样是静默 404）。

负向对照：把 FilesView 的 `api.put(API.files.write())` 改回 `api.post` ⇒ 本条判红。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / 'docs/api/openapi.yaml'
ENDPOINTS = ROOT.parent / 'forkpanel-frontend/src/api/endpoints.ts'
FE_SRC = ROOT.parent / 'forkpanel-frontend/src'

# 调用写法 → 真实 HTTP 方法
VERB = {
    'get': 'GET',
    'post': 'POST',
    'put': 'PUT',
    'patch': 'PATCH',
    'del': 'DELETE',
    'putRaw': 'PUT',
    'postRaw': 'POST',
}

# 至少要解析出这么多，否则视为解析器失灵
MIN_PATHS = 100
MIN_ENDPOINTS = 50
MIN_CALLS = 100

fails = []


def fail(msg):
    fails.append(msg)
    print(f'  ✗ {msg}')


def normalize(t: str) -> str:
    """把契约的 {id} 与前端的 ${enc(id)} 归一到同一个占位符。

    连续占位符合并成一个 `*`：`/containers/${id}${force ? '?force=true' : ''}`
    归一后是 `/containers/*`，而契约 `/containers/{id}` 也是 `/containers/*` ——
    不合并会得到 `**` 与 `*` 两种写法，互相认不出。
    """
    t = re.sub(r'\$\{[^}]*\}', '*', t)
    t = re.sub(r'\{[^}]*\}', '*', t)
    t = t.split('?')[0]
    t = re.sub(r'\*+', '*', t)
    return t.rstrip('/')


def load_contract():
    """path -> {方法}。逐行状态机：`  /api/v1/x:` 开路径，`    get:` 记方法。"""
    out = {}
    cur = None
    for line in CONTRACT.read_text().splitlines():
        m = re.match(r'^  (/api/v1/\S+):\s*$', line)
        if m:
            cur = normalize(m.group(1))
            out.setdefault(cur, set())
            continue
        if cur is None:
            continue
        m = re.match(r'^    (get|post|put|patch|delete):\s*$', line)
        if m:
            out[cur].add(m.group(1).upper())
        elif re.match(r'^  \S', line):   # 回到顶层键 ⇒ 当前路径结束
            cur = None
    return out


def load_endpoints():
    """(group, name) -> 路径模板。

    条目可能跨行（长 URL 或参数多），所以按「缩进 4 的 key 行」切片后再找第一个
    字符串字面量，而不是只看 key 所在那一行 —— 首版按单行解析时漏了 8 个多行条目。
    """
    out = {}
    group = None
    name = None
    buf = []

    def flush():
        if group and name:
            # 剔除注释行再找路径字面量：endpoints.ts 的文档注释里大量出现
            # `` `docker create` `` / `` `docker rmi` `` 这类反引号片段，不剔的话
            # 会被当成该条目的路径（实测把 list 解析成 "docker create"）。
            code = [ln for ln in buf
                    if not ln.strip().startswith(('//', '*', '/*'))]
            text = ' '.join(code)
            # 先认模板字符串（带路径参数的端点一律用反引号），再退回单引号字面量。
            m = re.search(r'`([^`]*)`', text) or re.search(r"'([^']*)'", text)
            if m:
                out[(group, name)] = m.group(1)

    for line in ENDPOINTS.read_text().splitlines():
        if re.match(r'^  \w+:\s*\{\s*$', line):
            flush()
            name, buf = None, []
            group = re.match(r'^  (\w+):', line).group(1)
            continue
        if re.match(r'^  \}', line):
            flush()
            name, buf = None, []
            group = None
            continue
        m = re.match(r'^    (\w+):', line)
        if m and group:
            flush()
            name, buf = m.group(1), [line]
            continue
        if name:
            buf.append(line)
    flush()
    return out


def load_calls():
    """[(file, line, 方法, group, name)]"""
    calls = []
    pat = re.compile(
        r'api\.(get|post|put|patch|del|putRaw|postRaw)\s*(?:<[^>]*>)?\s*\(\s*API\.(\w+)\.(\w+)\s*\(')
    files = list(FE_SRC.rglob('*.vue')) + list(FE_SRC.rglob('*.ts'))
    for f in files:
        if '.test.' in f.name:
            continue
        for i, line in enumerate(f.read_text(errors='replace').splitlines(), 1):
            # 跳过注释行：useAsync.ts 的用法示例里写着 `api.get(API.x.list())`，
            # 那是文档不是调用，算进来会变成一条假红。
            if line.lstrip().startswith(('//', '*', '/*')):
                continue
            for m in pat.finditer(line):
                calls.append((str(f.relative_to(ROOT.parent)), i,
                              VERB[m.group(1)], m.group(2), m.group(3)))
    return calls


def main():
    if not CONTRACT.exists():
        print(f'[api-method] 契约不存在: {CONTRACT}')
        return 1
    if not ENDPOINTS.exists():
        print(f'[api-method] endpoints.ts 不存在: {ENDPOINTS}')
        return 1

    contract = load_contract()
    endpoints = load_endpoints()
    calls = load_calls()

    print(f'[api-method] 契约路径 {len(contract)} / endpoints {len(endpoints)} / 调用点 {len(calls)}')

    # ① 解析器自检：数量不足说明格式变了或正则失效，绝不能当成「没问题」
    if len(contract) < MIN_PATHS:
        fail(f'契约只解析出 {len(contract)} 条路径（应 ≥{MIN_PATHS}）—— 解析器可能失效')
    if len(endpoints) < MIN_ENDPOINTS:
        fail(f'endpoints.ts 只解析出 {len(endpoints)} 条（应 ≥{MIN_ENDPOINTS}）—— 解析器可能失效')
    if len(calls) < MIN_CALLS:
        fail(f'只找到 {len(calls)} 处调用（应 ≥{MIN_CALLS}）—— 解析器可能失效')

    # ② 逐个调用点比对方法
    unknown_ep = {}
    path_miss = []
    mismatch = []
    for f, ln, verb, group, name in calls:
        tpl = endpoints.get((group, name))
        if tpl is None:
            unknown_ep[(group, name)] = unknown_ep.get((group, name), 0) + 1
            continue
        norm = normalize(tpl)
        if norm not in contract:
            path_miss.append((f, ln, verb, norm))
            continue
        if verb not in contract[norm]:
            mismatch.append((f, ln, verb, norm, sorted(contract[norm])))

    if unknown_ep:
        # 解析不到的调用名不直接判红（可能是解构/变量间接调用），但要亮出来让人看到
        print('  [i] endpoints.ts 里没解析到这些调用名（请人工确认是否间接调用）:')
        for (g, n), c in sorted(unknown_ep.items()):
            print(f'      API.{g}.{n}  ×{c}')

    for f, ln, verb, norm in path_miss:
        fail(f'{f}:{ln} 用了契约里没有的路径：{verb} {norm}')

    for f, ln, verb, norm, allowed in mismatch:
        fail(f'{f}:{ln} 前端发 {verb}，契约 {norm} 只允许 {"/".join(allowed)}')

    if fails:
        print(f'[api-method] 失败 {len(fails)} 项')
        return 1
    print(f'[api-method] PASS —— {len(calls)} 处调用的方法与契约一致')
    return 0


if __name__ == '__main__':
    sys.exit(main())
