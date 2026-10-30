#!/usr/bin/env bash
# E2E for deploy/get-panel.sh（离线、不依赖真实 GitHub）：
#   - 死源 → 好源 按序回退并成功
#   - 镜像源坏签名 / 篡改 tarball 被验签拒绝（防投毒）
#   - PANEL_RELEASE_BASE 钉死单源（成功 / 死源无兜底→诊断退出）
#   - 内嵌公钥与测试公钥互不通用（密钥隔离）
#   - 断点续传：预置半成品 + Range 服务器，断言确实续传（206）且产物完整验签通过
#
# 用本地 python http.server 冒充多个"下载源"目录；用自签 ed25519 测试密钥验签。
#
# ★ 本文件的 Range 服务器模板已抽成可复用 agent skill `bash-installer-progress-resume`
#   （SKILL.md / references/range-server.md 可粘贴 heredoc / assets/range-server.py）。
#   改这段 Range 逻辑时，请把改动反向同步进该 skill，避免两处漂移。
set -uo pipefail

GP="$(cd "$(dirname "$0")/.." && pwd)/deploy/get-panel.sh"
[ -f "$GP" ] || { echo "找不到 $GP" >&2; exit 1; }

ROOT="$(mktemp -d)"
trap 'kill "$HTTP_PID" "$RANGE_PID" 2>/dev/null; rm -rf "$ROOT"' EXIT

# ---- 测试密钥 ----
openssl genpkey -algorithm ed25519 -out "$ROOT/test.key" 2>/dev/null
openssl pkey -in "$ROOT/test.key" -pubout -out "$ROOT/test.pub.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$ROOT/rogue.key" 2>/dev/null   # 攻击者密钥

# ---- 构造 tarball 内容 + 各源目录 ----
mkdir -p "$ROOT/payload" "$ROOT/good" "$ROOT/dead" "$ROOT/rogue" "$ROOT/tampered"
printf '#!/bin/sh\necho panel-test\n' > "$ROOT/payload/panel"
printf '#!/bin/sh\necho install\n'     > "$ROOT/payload/install.sh"
printf '[server]\nport = 2083\n'        > "$ROOT/payload/config.toml"
# --owner=0 --group=0：让归档记录 uid 0，避免 unshare 伪 root 下 tar 还原外域 uid 报错
# （真实环境 root 解包到数字 uid 不会失败；此处仅为 E2E 可复现）。
tar -C "$ROOT/payload" --owner=0 --group=0 -czf "$ROOT/good/panel-linux-amd64.tar.gz" panel install.sh config.toml
# 好签名（测试私钥）
openssl pkeyutl -sign -inkey "$ROOT/test.key" -rawin \
  -in "$ROOT/good/panel-linux-amd64.tar.gz" -out "$ROOT/good/panel-linux-amd64.tar.gz.sig"
# 死源：目录里没有 tarball（curl 命中 404）

# 坏签名：rogue 源用攻击者私钥签同一份 tarball（客户端公钥仍是 test.pub.pem → 验不过）
cp "$ROOT/good/panel-linux-amd64.tar.gz" "$ROOT/rogue/"
openssl pkeyutl -sign -inkey "$ROOT/rogue.key" -rawin \
  -in "$ROOT/rogue/panel-linux-amd64.tar.gz" -out "$ROOT/rogue/panel-linux-amd64.tar.gz.sig"

# 篡改：先拷好版 tarball + 好签名，再篡改 tarball（不重签）→ 签名失配 → 验不过
cp "$ROOT/good/panel-linux-amd64.tar.gz"     "$ROOT/tampered/"
cp "$ROOT/good/panel-linux-amd64.tar.gz.sig" "$ROOT/tampered/"
printf 'x' >> "$ROOT/tampered/panel-linux-amd64.tar.gz"

# ---- 起本地 http 源 ----
PORT=8731
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$ROOT" >/dev/null 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PORT/good/panel-linux-amd64.tar.gz.sig" >/dev/null 2>&1 && break
  sleep 0.1
done

# ---- 运行器：在伪 root 下跑 get-panel.sh（--no-install），捕获输出与退出码 ----
# 统一把 PANEL_CACHE_DIR 关进 $ROOT/cache，避免 E2E 触碰真实 /var/cache 或 $HOME。
run_gp() {  # run_gp <env 赋值...>
  OUT="$(unshare -r env "$@" PANEL_CACHE_DIR="$ROOT/cache" bash "$GP" --no-install 2>&1)"; RC=$?
}

pass=0; fail=0
check() {  # check <名称> <表达式>
  if eval "$2"; then echo "  PASS  $1"; pass=$((pass+1));
  else echo "  FAIL  $1"; fail=$((fail+1)); fi
}

echo "==> 场景 1+2：死源 → 好源 回退并成功（同一次运行，覆盖两源都尝试）"
run_gp "PANEL_MIRRORS=http://127.0.0.1:$PORT/dead,http://127.0.0.1:$PORT/good" "PANEL_PUBKEY_FILE=$ROOT/test.pub.pem"
check "回退后成功（exit0 + 签名OK + 已选用该源）" \
  '[ "$RC" -eq 0 ] && printf "%s" "$OUT" | grep -q "签名 OK" && printf "%s" "$OUT" | grep -q "已选用该源"'
check "确实先试死源失败再试好源成功，且未落到 GitHub 兜底" \
  'printf "%s" "$OUT" | grep -q "源 1/" && printf "%s" "$OUT" | grep -q "该源不可用" && printf "%s" "$OUT" | grep -q "已选用该源" && ! printf "%s" "$OUT" | grep -q "github.com"'

echo "==> 场景 3：镜像源坏签名被拒（防投毒）"
run_gp "PANEL_RELEASE_BASE=http://127.0.0.1:$PORT/rogue" "PANEL_PUBKEY_FILE=$ROOT/test.pub.pem"
check "坏签名源退出非0且不打印签名OK" \
  '[ "$RC" -ne 0 ] && ! printf "%s" "$OUT" | grep -q "签名 OK"'

echo "==> 场景 4：篡改 tarball 被验签拦下"
run_gp "PANEL_RELEASE_BASE=http://127.0.0.1:$PORT/tampered" "PANEL_PUBKEY_FILE=$ROOT/test.pub.pem"
check "篡改 tarball 退出非0" \
  '[ "$RC" -ne 0 ] && ! printf "%s" "$OUT" | grep -q "签名 OK"'

echo "==> 场景 5：PANEL_RELEASE_BASE 钉死单源（好源）成功"
run_gp "PANEL_RELEASE_BASE=http://127.0.0.1:$PORT/good" "PANEL_PUBKEY_FILE=$ROOT/test.pub.pem"
check "钉死好源成功" \
  '[ "$RC" -eq 0 ] && printf "%s" "$OUT" | grep -q "已选用该源"'

echo "==> 场景 6：PANEL_RELEASE_BASE 钉死死源无兜底 → 诊断退出"
run_gp "PANEL_RELEASE_BASE=http://127.0.0.1:$PORT/dead" "PANEL_PUBKEY_FILE=$ROOT/test.pub.pem"
check "钉死死源→打印『所有候选下载源均失败』并退出非0" \
  '[ "$RC" -ne 0 ] && printf "%s" "$OUT" | grep -q "所有候选下载源均失败"'

echo "==> 场景 7：内嵌公钥拒绝测试签名（密钥隔离，证明内嵌路径生效）"
run_gp "PANEL_RELEASE_BASE=http://127.0.0.1:$PORT/good"   # 不设 PUBKEY_FILE → 用内嵌公钥
check "内嵌公钥与测试私钥不匹配→退出非0" \
  '[ "$RC" -ne 0 ]'

echo "==> 场景 8：断点续传（预置半成品 + Range 服务器，断言确实续传且产物完整验签）"
# Range 服务器：对 tarball 支持 bytes Range（返回 206），并在日志里记录是否收到 Range 请求。
RANGE_PORT=8732
RANGE_LOG="$ROOT/range.log"
rm -f "$RANGE_LOG"
cat > "$ROOT/range_server.py" <<'PY'
import http.server, socketserver, os
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        # SimpleHTTPRequestHandler.__init__ 会用 os.getcwd() 覆盖类属性 directory，
        # 故必须从构造参数显式传入，否则服务的是脚本所在目录而非 $ROOT/good。
        super().__init__(*a, directory=os.environ['RANGE_DIR'], **kw)
    def do_GET(self):
        p = self.translate_path(self.path)
        rng = self.headers.get('Range')
        with open(os.environ['RANGE_LOG'], 'a') as f:
            f.write(('1' if rng else '0') + '\n')
        if not os.path.isfile(p):
            self.send_error(404); return
        data = open(p, 'rb').read()
        total = len(data)
        if rng and rng.startswith('bytes='):
            start_s = rng[len('bytes='):].split('-')[0]
            start = int(start_s) if start_s.strip() else 0
            end = total - 1
            chunk = data[start:end + 1]
            self.send_response(206)
            self.send_header('Content-Range', 'bytes %d-%d/%d' % (start, end, total))
            self.send_header('Content-Length', str(len(chunk)))
            self.send_header('Accept-Ranges', 'bytes')
            self.end_headers(); self.wfile.write(chunk)
        else:
            self.send_response(200)
            self.send_header('Content-Length', str(total))
            self.send_header('Accept-Ranges', 'bytes')
            self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('127.0.0.1', int(os.environ['RANGE_PORT'])), H).serve_forever()
PY
RANGE_PORT="$RANGE_PORT" RANGE_LOG="$RANGE_LOG" RANGE_DIR="$ROOT/good" python3 "$ROOT/range_server.py" &
RANGE_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$RANGE_PORT/panel-linux-amd64.tar.gz.sig" >/dev/null 2>&1 && break
  sleep 0.1
done

# 预置半成品：截取好 tarball 前 64 字节，落进 get-panel.sh 会用的「同 URL 缓存键」路径。
# 非 latest（=0.0.0）才允许续传；latest 会强制全新下载、清掉半成品。
TARBALL="panel-linux-amd64.tar.gz"
RANGE_URL="http://127.0.0.1:$RANGE_PORT/$TARBALL"
SAFE="$(printf '%s' "$RANGE_URL" | sha256sum | cut -c1-16)"
mkdir -p "$ROOT/cache"
head -c 64 "$ROOT/good/$TARBALL" > "$ROOT/cache/$SAFE.tar.gz"

run_gp "PANEL_VERSION=0.0.0" "PANEL_RELEASE_BASE=http://127.0.0.1:$RANGE_PORT" "PANEL_PUBKEY_FILE=$ROOT/test.pub.pem"
check "续传后成功（exit0 + 签名OK）" \
  '[ "$RC" -eq 0 ] && printf "%s" "$OUT" | grep -q "签名 OK"'
check "确实触发了续传（Range 服务器收到带 Range 的请求）" \
  'grep -q "1" "$RANGE_LOG"'
# 产物完整由上面的「签名 OK」保证（openssl 对整份 tarball 验签，残缺/错位必失败）；
# 缓存文件在 --no-install 退出时已被清理，故不再比对磁盘大小。

echo
echo "=========================================="
echo "PASS=$pass  FAIL=$fail"
echo "=========================================="
[ "$fail" -eq 0 ]
