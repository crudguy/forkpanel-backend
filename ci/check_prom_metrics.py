#!/usr/bin/env python3
"""Prometheus 抓取端点 /metrics 的接线守卫（生产就绪度 P1 §8-9）。

背景：监控采集原先完全没有入口——面板活着没有只有进程级的 `up`。
现在 /metrics 由 config.toml `[metrics] scrape_token` 开关 + Bearer token 鉴权。
本守卫钉住四个容易回退的点：

  ① **假控制**：`scrape_token` 字段在 config.rs 里、serve.rs 却没人读
     ⇒ 配了 token 也永远不注册（比"没做"更危险：伪装成已做）；
  ② **无条件注册**：token 留白时仍注册 /metrics（要么裸奔、要么 404 占面）——
     路由注册必须整个包在 `Some(t) if !t.is_empty()` 分支里；
  ③ **鉴权短路**：handler 先采集后鉴权（或把常数时间比较换回 `==`）；
  ④ **删单测恒绿**：exposition 格式 / token 比较的行为判据只扫测试段。

恒绿纪律：判据剔注释、提取前提先断言、钉死「/metrics 在 serve.rs 全文恰好一处」
（防止有人在 build_router 里再挂一个绕过条件分支的注册点）。

用法：python3 ci/check_prom_metrics.py [仓库根目录]
"""
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
fail = 0


def ok(msg):
    print(f"  ✓ {msg}")


def bad(msg):
    global fail
    print(f"  ✗ {msg}")
    fail = 1


def read(rel):
    p = ROOT / rel
    if not p.is_file() or p.stat().st_size == 0:
        bad(f"{rel} 不存在或为空——提取前提不成立，绝不能当作通过")
        return ""
    return p.read_text(encoding="utf-8")


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


def prod_and_test(text: str):
    """返回 (生产段, 测试段)。生产段 = 剥注释 + 砍 #[cfg(test)] 起的整段。"""
    lines = text.splitlines()
    cut = len(lines)
    for i, l in enumerate(lines):
        if l.strip().startswith("#[cfg(test)]"):
            cut = i
            break
    prod = "\n".join(strip_comments(l) for l in lines[:cut])
    return prod, "\n".join(lines[cut:])


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


prom_raw = read("crates/panel-api/src/prom.rs")
serve_raw = read("crates/panel-cli/src/cmd/serve.rs")
config_raw = read("crates/panel-cli/src/config.rs")
doc = read("docs/deployment.md")
tmpl = read("deploy/config.toml")
if fail:
    print("✗ check_prom_metrics：前提不成立")
    sys.exit(1)

prom, prom_tests = prod_and_test(prom_raw)
serve, _ = prod_and_test(serve_raw)
config, _ = prod_and_test(config_raw)

print("== [1] prom.rs：鉴权在采集之前，token 比较常数时间 ==")
i = prom.find("pub async fn metrics(")
if i < 0:
    bad("prom.rs 缺 metrics handler（pub async fn metrics）")
    body = ""
else:
    brace = prom.index("{", i)
    body = extract_block(prod_and_test(prom_raw)[0], brace)
if body:
    j_auth = body.find("UNAUTHORIZED")
    j_gather = body.find("gather(")
    if j_auth < 0:
        bad("handler 无 401 分支——鉴权被删")
    elif j_gather >= 0 and j_gather < j_auth:
        bad("先采集后鉴权：未授权请求也在消耗 DB 查询")
    else:
        ok("鉴权失败 401 先于采集")
    if "token_eq(" in body:
        ok("鉴权用常数时间比较 token_eq")
    else:
        bad("handler 未调用 token_eq（可能被换回 ==，泄露前缀匹配度）")
    if "bearer_token(" in body:
        ok("从 Authorization 头解析 Bearer")
    else:
        bad("handler 未解析 Authorization 头")
if "version=0.0.4" in prom:
    ok("exposition content-type 带 version=0.0.4")
else:
    bad("缺标准 content-type（text/plain; version=0.0.4）")

print("== [2] serve.rs：条件注册（留白不占面）+ 反假控制 ==")
if "cfg.metrics.scrape_token" in serve:
    ok("serve.rs 真实读取 cfg.metrics.scrape_token（不是假控制）")
else:
    bad("serve.rs 不读 scrape_token ⇒ [metrics] 配置项是假控制（配了也永远不注册）")
k = serve.find("match cfg.metrics.scrape_token")
if k < 0:
    bad("serve.rs 缺 token 条件分支（match cfg.metrics.scrape_token）")
    match_block = ""
else:
    brace = serve.index("{", k)
    match_block = extract_block(prod_and_test(serve_raw)[0], brace)
if match_block:
    if '"/metrics"' in match_block:
        ok('"/metrics" 注册包在 token 非空分支内')
    else:
        bad('"/metrics" 不在 token 条件分支内——留白也会注册')
    if "!t.is_empty()" in match_block:
        ok("留白 token（空白串）也不注册")
    else:
        bad("条件只判 Some 不判空白串——scrape_token = \" \" 会裸奔")
n_metrics = serve.count('"/metrics"')
if n_metrics == 1:
    ok('serve.rs 全文 "/metrics" 恰好 1 处（无第二个绕过条件的注册点）')
else:
    bad(f'serve.rs "/metrics" 出现 {n_metrics} 次（应为 1：只允许条件分支内这一处）')
if "panel_api::prom::PromState" in serve:
    ok("注入真实 PromState（读池 + 数据目录 + token）")
else:
    bad("serve.rs 未构造 PromState（handler 拿不到依赖）")

print("== [3] config.rs：Metrics 结构与 Config 接线 ==")
for needle, desc in [
    ("pub struct Metrics", "Metrics 结构"),
    ("pub metrics: Metrics", "Config.metrics 字段"),
    ("scrape_token", "scrape_token 字段"),
]:
    if needle in config:
        ok(f"config.rs 含 {desc}")
    else:
        bad(f"config.rs 缺 {desc}（{needle}）")
i = config.find("pub struct Metrics")
if i >= 0:
    # serde 属性在 struct 声明上方，判据窗口取「前 300 字符 + 花括号块」
    block = config[max(0, i - 300):i] + extract_block(config, config.index("{", i))
    if "deny_unknown_fields" in block:
        ok("Metrics 拒绝未知字段（配置拼错不会被静默忽略）")
    else:
        bad("Metrics 缺 #[serde(deny_unknown_fields)]")
i = config.find("impl Default for Config")
if i >= 0:
    block = extract_block(config, config.index("{", i))
    if "Metrics::default()" in block:
        ok("Config::default() 含 metrics（默认关闭）")
    else:
        bad("Config::default() 漏 metrics 字段")
else:
    bad("提取不到 impl Default for Config（判据塌成空）")

print("== [4] 行为判据有单测（只扫测试段，防删测试恒绿） ==")
for needle, desc in [
    ("token_eq_is_exact_and_constant_shape", "token 比较行为"),
    ("render_has_required_exposition_lines", "每个指标 HELP+TYPE"),
    ("render_escapes_label_values", "标签值转义"),
    ("bearer_header_parsing", "Authorization 头解析"),
]:
    if needle in prom_tests:
        ok(f"单测覆盖 {desc}")
    else:
        bad(f"prom.rs 测试段缺 {needle}（{desc} 无行为判据）")

print("== [5] 文档与配置模板同步 ==")
for needle, desc in [
    ("### 5.2.4 Prometheus 抓取端点", "/metrics 小节"),
    ("scrape_token", "配置项说明"),
    ("> 86400", "备份告警规则（never = -1 的配套写法）"),
    ("常数时间", "token 比较的安全边界说明"),
]:
    if needle in doc:
        ok(f"deployment.md 含 {desc}")
    else:
        bad(f"deployment.md 缺 {desc}（{needle}）——运维照旧配置会踩坑")
if "[metrics]" in tmpl and "scrape_token" in tmpl:
    ok("deploy/config.toml 模板含 [metrics] 注释块")
else:
    bad("deploy/config.toml 模板缺 [metrics] 说明（部署者不知道有这个开关）")

if fail:
    print("✗ check_prom_metrics：/metrics 接线未通过")
    sys.exit(1)
print("PASS：/metrics 条件注册 + Bearer 鉴权 + exposition 格式，接线完整")
sys.exit(0)
