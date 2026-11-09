#!/usr/bin/env bash
# 外部告警通道 E2E（G8）。
#
# ## 这份脚本验收的是什么
# `docs/production-readiness-2026-11-07.md` §4.2 G8 的判据是「崩溃 / 备份失败 /
# 证书续期失败**各触发一次外部通知**」。三者的共同出口只有一处：
# `<config_dir>/alert-webhook`（与崩溃告警 `notify-failure.sh` 共用）。
# 本脚本把这条出口的**两种调用方**都真跑一遍：
#   - Rust 侧：`panel alert test` → 假接收器收到 `event=test`；
#   - shell 侧：从 install.sh 抽出的 `notify-failure.sh` → 收到 `event=crash`。
#
# ## 为什么必须真跑，而不是只靠单测
# 单测能证明 `AlertSink::fire` 组包正确、节流生效，但证明不了这三件事：
#   ① 配置文件的**路径**对不对（`config_dir` 与安装器的 `/etc/forkpanel` 是两处）；
#   ② `curl` 出口在本机真的可用（`Bin::Curl.available()` 为假时 fire 直接 Unsupported）；
#   ③ 发不出去时**退出码非 0**（否则运维看到"已投递"却什么也没收到）。
# 第 ③ 条尤其重要：只测成功路径的实现，把 URL 硬编码成返回值也能全绿。
#
# ## 纪律
#  1. 零 root：不需要启动服务、不写 `/etc`，配置目录用 `[paths] config` 覆盖到临时目录。
#  2. 断言钉死具体文案 / 退出码；`$?` 直接取（`cmd | head` 拿到的是 head 的码）。
#  3. 环境不具备（无二进制 / 无 curl / 端口被占）显式 `[skip]`，不假装通过。
#  4. 正负对照成对：每条"能发出去"的断言都配一条"发不出去必须报错"。
#
# ## 用法
#   ci/e2e-alert.sh [panel_binary]
#     默认 ./target/debug/panel；接收器端口 PANEL_E2E_ALERT_PORT（默认 2103）
#
# ## 依赖
#   curl、python3

set -uo pipefail

BIN="${1:-./target/debug/panel}"
PORT="${PANEL_E2E_ALERT_PORT:-2103}"

ROOT=""
RECV_PID=""
PASS=0
FAIL=0
SKIP=0

say() { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $1"; }
skip() { SKIP=$((SKIP+1)); say "  [skip] $1"; }
chk()      { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1  实际=[$2] 期望=[$3]"; fi; }
chk_rc()   { if [ "$2" = "$3" ]; then ok "$1 (rc=$2)"; else bad "$1  rc 实际=[$2] 期望=[$3]"; fi; }
chk_has()  { case "$2" in *"$3"*) ok "$1";; *) bad "$1  输出缺少 [$3]；实际=[$2]";; esac; }
chk_hasnt(){ case "$2" in *"$3"*) bad "$1  不应包含 [$3]；实际=[$2]";; *) ok "$1";; esac; }

cleanup() {
  [ -n "$RECV_PID" ] && kill "$RECV_PID" 2>/dev/null
  [ -n "$ROOT" ] && rm -rf "$ROOT"
}
trap cleanup EXIT

# ── 前置检查 ────────────────────────────────────────────────────────────
if [ ! -x "$BIN" ]; then
  skip "找不到可执行文件 $BIN（先 cargo build --bin panel）"
  say "SKIP=$SKIP FAIL=$FAIL"
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  # 本面板经 curl 投递（见 panel-api/src/webhook.rs）：没 curl 则告警必然发不出，
  # 这是**部署缺依赖**而不是"测试环境不具备"，但本脚本不负责装包，显式跳过。
  skip "本机没有 curl —— 面板的告警投递依赖 curl，装上再跑"
  say "SKIP=$SKIP FAIL=$FAIL"
  exit 2
fi
if ss -tln 2>/dev/null | grep -q ":$PORT "; then
  skip "端口 $PORT 已被占用，换 PANEL_E2E_ALERT_PORT 再跑"
  say "SKIP=$SKIP FAIL=$FAIL"
  exit 2
fi

ROOT=$(mktemp -d "/tmp/panel-e2e-alert-$$-XXXX")
CFG="$ROOT/panel.toml"
CONF_DIR="$ROOT/config"
mkdir -p "$CONF_DIR"
HITS="$ROOT/hits.jsonl"
: > "$HITS"
cat > "$CFG" <<EOF
[server]
bind = "127.0.0.1"
port = $PORT
[paths]
config = "$CONF_DIR"
data = "$ROOT/data"
log = "$ROOT/logs"
site_root = "$ROOT/sites"
EOF

# ── 假接收器：收 POST 落 jsonl ──────────────────────────────────────────
cat > "$ROOT/recv.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
out, port = sys.argv[1], int(sys.argv[2])

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        with open(out, "a", encoding="utf-8") as f:
            f.write(body.replace("\n", " ") + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
python3 "$ROOT/recv.py" "$HITS" "$PORT" &
RECV_PID=$!
for _ in $(seq 1 50); do
  ss -tln 2>/dev/null | grep -q ":$PORT " && break
  sleep 0.1
done
if ! ss -tln 2>/dev/null | grep -q ":$PORT "; then
  bad "假接收器未能监听 $PORT"
  say "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
  exit 1
fi
ok "假接收器已监听 127.0.0.1:$PORT"

say "== 1. 未配置：诚实说"没有"，且 test 必须响亮失败 =="
out=$("$BIN" alert status --config "$CFG" 2>&1)
chk_rc "status 未配置时正常运行" "$?" "0"
chk_has "status 明说未配置" "$out" "未配置"
chk_has "status 给出可复制的修复命令" "$out" "alert-webhook"
chk_hasnt "status 绝不谎报已配置" "$out" "已配置"

out=$("$BIN" alert test --config "$CFG" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then ok "未配置时 test 退码非 0 (rc=$rc)"
else bad "未配置时 test 竟然成功 —— 假成功比没有更危险"; fi
chk_has "test 失败时说明缺什么" "$out" "未配置"

say "== 2. 非法 URL：加载阶段就拒绝，不退化成"能发" =="
printf 'ftp://example.com/hook\n' > "$CONF_DIR/alert-webhook"
out=$("$BIN" alert status --config "$CFG" 2>&1)
chk_has "ftp:// 被拒（仍报未配置）" "$out" "未配置"
out=$("$BIN" alert test --config "$CFG" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then ok "非法 URL 时 test 退码非 0 (rc=$rc)"
else bad "ftp:// 竟然能发 —— URL 校验没生效"; fi

say "== 3. 配好之后：test 真发出去，字段与接收方约定一致 =="
printf 'http://127.0.0.1:%s/hook\n' "$PORT" > "$CONF_DIR/alert-webhook"
out=$("$BIN" alert status --config "$CFG" 2>&1)
chk_has "status 报已配置" "$out" "已配置"
chk_hasnt "status 不回显 URL（它常带 token）" "$out" "127.0.0.1:$PORT"
: > "$HITS"
out=$("$BIN" alert test --config "$CFG" 2>&1); rc=$?
chk_rc "test 投递成功" "$rc" "0"
sleep 0.2
if [ -s "$HITS" ]; then ok "接收器收到 1 条 POST"; else bad "接收器没收到任何 POST"; fi
body=$(head -1 "$HITS")
chk_has "事件名是 test" "$body" '"event":"test"'
chk_has "带 panel 标识" "$body" '"panel":"forkpanel"'
chk_has "带 unit 字段" "$body" '"unit":"panel.service"'
# ts 是数字而不是字符串：接收方按数值比较时间，字符串会静默比较失败
case "$body" in
  *'"ts":'[0-9]*) ok "ts 为纪元秒（数值）";;
  *) bad "ts 不是数值：$body";;
esac

say "== 4. 发不出去必须报错（否则"已投递"是谎话） =="
printf 'http://127.0.0.1:1/never\n' > "$CONF_DIR/alert-webhook"
out=$("$BIN" alert test --config "$CFG" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then ok "对端不可达时 test 退码非 0 (rc=$rc)"
else bad "对端不可达竟然报成功"; fi
chk_has "失败时给出排查方向" "$out" "curl"

say "== 5. 崩溃告警（shell 侧）：与 Rust 侧同一份配置、同一套字段 =="
# 从 install.sh 里抽出真实的 notify-failure.sh 生成块，只把硬编码的 /etc 路径
# 换成本次临时目录——**不改逻辑**，验的是即将装到机器上的那段脚本。
NOTIFY_SRC="$ROOT/notify-failure.sh"
awk '/^cat > "\$NOTIFY_SCRIPT" <<.EOF.$/{flag=1;next} /^EOF$/{if(flag){exit}} flag' \
  deploy/install.sh > "$NOTIFY_SRC"
if [ -s "$NOTIFY_SRC" ]; then
  ok "从 install.sh 抽出 notify-failure.sh（$(wc -l < "$NOTIFY_SRC") 行）"
else
  bad "没能从 install.sh 抽出通知脚本 —— 锚点变了"
fi
sed -i.bak "s#^WH=/etc/forkpanel/alert-webhook#WH=$CONF_DIR/alert-webhook#" "$NOTIFY_SRC"
chmod +x "$NOTIFY_SRC"
printf 'http://127.0.0.1:%s/hook\n' "$PORT" > "$CONF_DIR/alert-webhook"
: > "$HITS"
out=$("$NOTIFY_SRC" 2>&1); rc=$?
chk_rc "通知脚本退出 0（投递失败也不影响服务恢复）" "$rc" "0"
sleep 0.2
if [ -s "$HITS" ]; then ok "接收器收到崩溃告警"; else bad "崩溃告警没发出去"; fi
body=$(head -1 "$HITS")
chk_has "崩溃事件名是 crash" "$body" '"event":"crash"'
chk_has "崩溃包的 panel 字段与 Rust 侧一致" "$body" '"panel":"forkpanel"'
chk_has "崩溃包带 ts" "$body" '"ts":'
chk_has "崩溃包带 detail（人类可读时间在这里）" "$body" '"detail":'

say "== 6. 通知脚本在未配置时也不得报错 =="
rm -f "$CONF_DIR/alert-webhook"
out=$("$NOTIFY_SRC" 2>&1); rc=$?
chk_rc "无配置时通知脚本仍退出 0" "$rc" "0"

say ""
say "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
