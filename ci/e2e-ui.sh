#!/usr/bin/env bash
# 浏览器级 UI 渲染冒烟（**前端**真机验收）：用 agent-browser 驱动真实浏览器，
# 断言关键页面**真的渲染出了内容**——而不是"编译绿就以为页面是好的"。
#
# ## 为什么需要（这是后端 E2E 覆盖不到的那一层）
# 九个后端 E2E 全部打在 API 上；前端 74 个 UI 文件（32 views + 42 components）里
# **没有任何一个渲染测试**（vitest 只收 `src/**/*.test.ts` 且无 vue 插件）。
# 而本项目踩过的最深一坑正是这一类：**新增子组件忘了 import ⇒ 静默不渲染**
# （Vue 把未知标签当普通元素渲染空内容，只有 console warning；vue-tsc / build /
# 单测全绿）。这类 bug 后端 E2E 永远抓不到，只有拿浏览器看 DOM 才能发现。
# 本脚本把"人拿浏览器看一眼"固化成可重复执行的门禁。
#
# ## 覆盖
#   1. 登录页 → 登录 → 应用外壳（侧边栏导航数量）
#   2. 概览：标题 + **数据驱动**卡片（"共 N 个"）+ 顶栏 CPU 实时值（证明前端真取到后端数据）
#   3. 容器页：6 个 Tab 齐全 + 逐个 Tab 的**边界引导 banner**真实渲染（镜像/网络/卷/Compose/容器）
#      —— 这正是"忘 import ⇒ 静默不渲染"最容易发生的地方
#   4. 用户 / 设置 / 备份 / 文件 / 日志 / 数据库：各页主区非空且有可辨认内容
#
# ## 纪律
#  - **只读浏览**：不点任何写操作按钮（不建/删资源），不触发破坏性路径。
#  - 断言一律用 **DOM 文本/元素**，不看 HTTP 200（200 只说明路由通了）。
#  - 每一处"页面非空"都用**可辨认的内容**（标题/表头/数据串），不用"元素个数 > 0"
#    这种判别力弱的写法。
#
# ## 依赖
#   agent-browser（浏览器自动化 CLI）；前端 dev server（默认 5173，代理 /api→2083）；
#   curl、python3（拼 JS 用，不依赖 jq）。
#
# ## 用法
#   ci/e2e-ui.sh
#   PANEL_E2E_FE=http://127.0.0.1:5173 ci/e2e-ui.sh     # 指定前端地址
set -uo pipefail

FE="${PANEL_E2E_FE:-http://127.0.0.1:5173}"
API="${PANEL_E2E_BASE:-http://127.0.0.1:2083}"
U="${PANEL_E2E_USER:-admin}"
P="${PANEL_E2E_PASS:-DevPreview2026x}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"                       # forkpanel-backend
FE_DIR="${PANEL_E2E_FE_DIR:-$(cd "$REPO/.." && pwd)/forkpanel-frontend}"
PASS=0; FAIL=0
STARTED_FE=0

say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "  ✓ $1"
        else FAIL=$((FAIL+1)); say "  ✗ $1  实际=[$2] 期望=[$3]"; fi; }

# ── 定位 agent-browser ──
AB=""
for c in "${AGENT_BROWSER:-}" "$HOME/.workbuddy/binaries/node/workspace/node_modules/.bin/agent-browser" \
         "$(command -v agent-browser 2>/dev/null || true)"; do
  [ -n "$c" ] && [ -x "$c" ] && { AB="$c"; break; }
done

cleanup() {
  "$AB" close --all >/dev/null 2>&1 || true
  # 只关我们自己起的 dev server，绝不碰别人已在跑的
  if [ "$STARTED_FE" -eq 1 ] && [ -n "${FE_PID:-}" ]; then
    kill "$FE_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ -z "$AB" ]; then
  say "[skip] 找不到 agent-browser（可用 AGENT_BROWSER=/path/to/agent-browser 指定）—— 本脚本未验证任何东西"
  exit 0
fi
if ! curl -s -m 3 "$API/api/v1/version" > /dev/null; then
  say "[skip] 后端不可达：$API —— 本脚本未验证任何东西（前端 dev 的 /api 代理也指向它）"
  exit 0
fi

# 前端 dev server：没有就起一个（起了才由我们负责关）
if ! curl -s -m 3 "$FE/" > /dev/null; then
  say "  · 前端 dev 未在 $FE，尝试启动…"
  if [ -d "$FE_DIR" ]; then
    ( cd "$FE_DIR" && setsid nohup corepack pnpm exec vite --host 127.0.0.1 --port 5173 \
        > /tmp/forkpanel-e2e-ui-vite.log 2>&1 < /dev/null & echo $! > /tmp/forkpanel-e2e-ui-vite.pid )
    FE_PID="$(cat /tmp/forkpanel-e2e-ui-vite.pid 2>/dev/null || true)"
    STARTED_FE=1
    for _ in $(seq 1 30); do
      curl -s -m 2 "$FE/" > /dev/null && break
      sleep 1
    done
  fi
  if ! curl -s -m 3 "$FE/" > /dev/null; then
    say "[skip] 前端 dev 起不来（$FE）—— 请手动起 vite 后重跑；日志 /tmp/forkpanel-e2e-ui-vite.log"
    exit 0
  fi
fi
say "=== 0. 环境就绪（前端 $FE → 后端 $API）==="

# ── agent-browser 封装 ──
# eval 结果：数字是裸 1/0，字符串会被 JSON 加引号 ⇒ 一律让 JS 返回 Number(...)
ui_probe() {
  local b64 out
  b64=$(printf '%s' "$1" | base64 -w0)
  out=$("$AB" eval --base64 "$b64" 2>/dev/null | tr -d '\r' | tail -1)
  printf '%s' "$out"
}
# 文本包含（用 python 做 JSON 转义，避免引号/反斜杠把 shell 与 JS 一起带沟里）
# ⚠ 必须包 Number()：布尔结果 agent-browser 打印的是 true/false，shell 里比 "1" 永远不等。
ui_has_text() {
  ui_probe "$(python3 -c 'import json,sys;print("Number(document.body.innerText.includes(%s))" % json.dumps(sys.argv[1]))' "$1")"
}
# 正则命中
ui_has_re() {
  ui_probe "$(python3 -c 'import json,sys;print("Number((new RegExp(%s)).test(document.body.innerText))" % json.dumps(sys.argv[1]))' "$1")"
}
# 轮询等待某个布尔条件成立（ SPA 挂载 + 取数需要时间）
ui_wait() {
  local expr="$1" t="${2:-15}" i=0
  while [ "$i" -lt $((t * 3)) ]; do
    [ "$(ui_probe "Number($expr)")" = "1" ] && return 0
    sleep 0.33; i=$((i + 1))
  done
  return 1
}
# 点一个 role=tab 的 Tab（容器页 6 个）
ui_click_tab() {
  ui_probe "$(python3 -c 'import json,sys
label=json.dumps(sys.argv[1])
print("(function(){const t=[...document.querySelectorAll(\"[role=tab]\")].find(x=>x.innerText.trim()===%s);if(!t)return 0;t.click();return 1;})()" % label)' "$1")"
}
# 打开路由并等主区挂载
ui_goto() {
  "$AB" open "$FE$1" > /dev/null 2>&1
  ui_wait 'document.querySelector("main") && document.querySelector("main").innerText.trim().length > 8' 20
}

say "=== 1. 登录 ==="
# 先清会话：否则复用到上一次的登录态，登录页根本没输入框，登录那段就测不到。
"$AB" close --all > /dev/null 2>&1 || true
"$AB" open "$FE/" > /dev/null 2>&1
ui_wait 'document.querySelectorAll("input").length >= 2' 15
chk "登录页有用户名/密码输入框" "$(ui_probe 'Number(document.querySelectorAll("input").length >= 2)')" "1"
LOGIN_JS="$(python3 -c 'import json,sys
u=json.dumps(sys.argv[1]); p=json.dumps(sys.argv[2])
print("""(function(){
 const setVal=(el,v)=>{const proto=el instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
 Object.getOwnPropertyDescriptor(proto,"value").set.call(el,v);el.dispatchEvent(new Event("input",{bubbles:true}));};
 const user=document.querySelector("input:not([type=password])");const pass=document.querySelector("input[type=password]");
 if(!user||!pass)return 0;setVal(user,%s);setVal(pass,%s);
 const btn=[...document.querySelectorAll("button")].find(b=>b.innerText.trim()==="登录");
 if(!btn)return 0;btn.click();return 1;})()""" % (u,p))' "$U" "$P")"
chk "提交登录（原生 setter + input 事件）" "$(ui_probe "$LOGIN_JS")" "1"
ui_wait 'location.pathname !== "/login"' 20
chk "登录后离开 /login" "$(ui_probe 'Number(location.pathname !== "/login")')" "1"
chk "侧边栏导航链接 ≥ 15" "$(ui_probe 'Number(document.querySelectorAll("a[href]").length >= 15)')" "1"

say "=== 2. 概览：标题 + 数据驱动内容（证明前端真取到后端数据）==="
ui_goto "/"
chk "概览标题" "$(ui_has_text '概览')" "1"
# 概览的卡片与顶栏 CPU 是**异步取数**后才有 ⇒ 先等再断言，否则测的是"还没加载完"。
# ⚠ 正则只写**单反斜杠**：shell 单引号里 `\\s` 会原样进 JS，变成"字面反斜杠+s"。
ui_wait '/共\s*\d+\s*个/.test(document.body.innerText)' 25 || true
chk "概览含数据驱动卡片（共 N 个）" "$(ui_has_re '共\s*\d+\s*个')" "1"
ui_wait '/CPU\s*[\d.]+\s*%/.test(document.body.innerText)' 25 || true
chk "顶栏含 CPU 实时值" "$(ui_has_re 'CPU\s*[\d.]+\s*%')" "1"

say "=== 3. 容器页：6 个 Tab + 各 Tab 边界引导真实渲染 ==="
ui_goto "/containers"
chk "6 个 Tab 齐全（集合判定，不依赖排序）" "$(ui_probe 'Number(["容器","镜像","资源","网络","卷","Compose"].every(x=>[...document.querySelectorAll("[role=tab]")].some(t=>t.innerText.trim()===x)))')" "1"
chk "容器 Tab：docker exec 引导在 DOM 里" "$(ui_has_text 'docker exec')" "1"
chk "镜像 Tab：点击后「删除镜像」引导在 DOM 里" "$(ui_click_tab '镜像' >/dev/null; ui_wait 'document.body.innerText.includes("删除镜像")' 10 && ui_has_text '删除镜像')" "1"
chk "网络 Tab：点击后「创建 / 删除网络」引导在 DOM 里" "$(ui_click_tab '网络' >/dev/null; ui_wait 'document.body.innerText.includes("创建 / 删除网络")' 10 && ui_has_text '创建 / 删除网络')" "1"
chk "卷 Tab：点击后「创建 / 删除卷」引导在 DOM 里" "$(ui_click_tab '卷' >/dev/null; ui_wait 'document.body.innerText.includes("创建 / 删除卷")' 10 && ui_has_text '创建 / 删除卷')" "1"
chk "Compose Tab：点击后「项目级日志」引导在 DOM 里" "$(ui_click_tab 'Compose' >/dev/null; ui_wait 'document.body.innerText.includes("项目级日志")' 10 && ui_has_text '项目级日志')" "1"
chk "资源 Tab：点击后主区非空" "$(ui_click_tab '资源' >/dev/null; ui_wait 'document.querySelector("main").innerText.trim().length > 20' 10 && ui_probe 'Number(document.querySelector("main").innerText.trim().length > 20)')" "1"

say "=== 4. 其它关键页面：主区真实渲染 ==="
ui_goto "/users"
chk "用户页含「用户名」表头" "$(ui_has_text '用户名')" "1"
ui_goto "/settings"
chk "设置页含部署级说明" "$(ui_has_re '部署级|localhost_only')" "1"
ui_goto "/backups"
chk "备份页有内容" "$(ui_has_re '备份')" "1"
ui_goto "/files"
chk "文件页主区非空" "$(ui_probe 'Number(document.querySelector("main").innerText.trim().length > 20)')" "1"
ui_goto "/logs"
chk "日志页有内容" "$(ui_has_re '日志')" "1"
ui_goto "/databases"
chk "数据库页有内容" "$(ui_has_re '数据库')" "1"

say ""
say "──────── E2E 结果：PASS=$PASS  FAIL=$FAIL ────────"
[ "$FAIL" -eq 0 ] || exit 1
