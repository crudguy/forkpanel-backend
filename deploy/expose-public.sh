#!/usr/bin/env bash
# ForkPanel 公网暴露：nginx 反代终结 TLS + 来源白名单
#
# ## 先看这段（定位）
# 面板本体**不提供 HTTPS**（serve 恒为明文 axum::serve），且以 root 运行 ⇒
# 绝不许把它直接绑到 0.0.0.0。本脚本走项目已定案的唯一受支持路径：
# **面板继续绑回环，由 nginx 反代终结 TLS**，面板自身的外网暴露面恒为 0。
# 副产品：即便 nginx 挂了、或白名单把自己锁在外面，
# `ssh -L <端口>:127.0.0.1:<端口>` 这条应急后门永远可用。
#
# ## 用法（需 root）
#   ./deploy/expose-public.sh -d panel.example.com -a 203.0.113.0/24 [-a 1.2.3.4/32]
#                             [--fullchain F --key K | --self-signed] [--no-firewall]
#   ./deploy/expose-public.sh --uninstall
#
# ## 三条 fail-closed（宁可不做，也不留敞开的大门）
#   1) 不给 -a/--allow 直接拒绝：没有来源限制的反代 = 把 root 面板开放到公网任人触达；
#   2) 面板本身已在非回环监听（已经裸奔）→ 拒绝：此时装反代不但没用，还会让人误以为
#      “装了就安全”，反而掩盖真实风险；
#   3) 端口探测跑不起来（ss 输出连表头都没有）→ 拒绝：判据不可信时不能放行，
#      否则“没检测到 = 没监听”会一路放行会把裸奔判成安全。
#
# ★ 改动本脚本前请看 `ci/e2e-expose-public.sh`：它在 user namespace 里把 /etc、
#   /var/lib 换成一次性 tmpfs，用 systemctl / nginx / ss / ufw 的 shim 真跑一遍本脚本，
#   逐条钉住上述三条与生成的 nginx 配置（`make e2e-expose`）。
set -euo pipefail

CONF_FILE=/etc/forkpanel/config.toml
NGINX_CONF=/etc/nginx/conf.d/forkpanel-public-access.conf
CERT_DIR=/var/lib/forkpanel/ssl/public-access
# 本脚本自签时留个记号：下次才知道这份证书是自己签的、可以替换（见 ③）
MARKER="$CERT_DIR/.self-signed-by-forkpanel"
TLS_DROPIN_DIR=/etc/systemd/system/panel.service.d
TLS_DROPIN="$TLS_DROPIN_DIR/panel-tls.conf"
WEBROOT=/var/www/html

DOMAIN=""; UNINSTALL=0; NO_FIREWALL=0; SELF_SIGNED=0
FULLCHAIN=""; KEY=""
ALLOW=()

die()  { echo "expose-public: $*" >&2; exit 1; }
note() { echo "  · $*"; }

usage() {
  cat <<'EOF'
用法（需 root）：
  ./deploy/expose-public.sh -d <域名> -a <CIDR> [-a <CIDR>...] [选项]

必填：
  -d, --domain <域名>      对外域名，如 panel.example.com（至少两级，顶级域不能是数字）
  -a, --allow <CIDR>       允许访问的来源网段，可重复给出。至少给一个；
                           名单外一律拒绝。填自己的出口网段（curl ifconfig.me 查）

证书（二选一，都不给则默认 --self-signed）：
      --fullchain <文件>   已有证书链
      --key <文件>         证书私钥
      --self-signed        现场生成自签证书（浏览器会告警，仅临时 / 内网自用）

其他：
      --no-firewall        不自动放行防火墙端口
      --uninstall          撤下反代并还原（面板仍绑回环，ssh 隧道照常可用）
  -h, --help               看这份说明

注意：
  -a 必须填**具体的**出口网段：不给就拒绝；给掩码 0（如 0.0.0.0/0）等于不设限制，
    同样拒绝（查自己的出口 IP：curl -s ifconfig.me，再按 /32 填）。
  本机需要有 nginx；脚本会连带放行防火墙的 **80 与 443**（80 留给证书续期挑战）。
  生产环境更推荐用面板 UI 自建反代站点（站点→新建→反向代理），那样证书由面板签发
  并随 010_cert_auto_renew 自动续期；本脚本是不走面板站点模型时的轻量路径。
EOF
}

if [ $# -eq 0 ]; then
  usage; exit 1;
fi

# ⚠ 取值前必须先确认"后面还有个值"：像 `-d` 少给值这种情况，`shift 2` 会越界，
#   而 bash 的越界报错在 set -e 下表现为**一句话不说就退出 1**（实测过）——
#   用户看到的是"命令好像没跑"，属于最难自己诊断的那一类失败。
need_val() { [ "$1" -ge 2 ] && [ -n "${2:-}" ] || die "$3 需要一个值（用 --help 看用法）"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -d|--domain)   need_val $# "${2:-}" "-d/--domain"; DOMAIN="$2";    shift 2 ;;
    -a|--allow)    need_val $# "${2:-}" "-a/--allow";  ALLOW+=("$2");  shift 2 ;;
    --fullchain)   need_val $# "${2:-}" "--fullchain"; FULLCHAIN="$2"; shift 2 ;;
    --key)         need_val $# "${2:-}" "--key";       KEY="$2";       shift 2 ;;
    --self-signed) SELF_SIGNED=1;     shift ;;
    --no-firewall) NO_FIREWALL=1;     shift ;;
    --uninstall)   UNINSTALL=1;       shift ;;
    -h|--help)     usage; exit 0 ;;
    *) die "未知参数：$1（用 --help 看用法）" ;;
  esac
done

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }

# ── 域名校验 ────────────────────────────────────────────────────────────
# 与面板前端的域名规则保持一致：至少两级、每段只允许字母数字连字符、
# 段首段尾不能是连字符、顶级域不得含数字（这条挡住 1.2.3.4 被当域名使）。
validate_domain() {
  local d="$1" parts tld p
  [ "${#d}" -le 253 ] || return 1
  # ⚠ 尾点必须显式拒：bash 的 `read -ra` 分词会**丢掉末尾空字段**
  #   （`"example.com."` → parts=2、tld="com"），于是尾点域名在这里一路通过，
  #   而 Rust `panel_core::expose` 用 `split('.')` 会得到空段并拒绝——
  #   同一个域名在 CLI/UI 被拒、直接跑脚本却放行，且写出的
  #   `server_name example.com.;` 几乎不可能匹配到 Host 头，
  #   表现为「脚本说完成了但打不开」，而 nginx -t 并不报错。故按 Rust 口径统一。
  case "$d" in ''|*.) return 1 ;; esac
  IFS='.' read -ra parts <<< "$d"
  [ "${#parts[@]}" -ge 2 ] || return 1
  tld="${parts[${#parts[@]}-1]}"
  for p in "${parts[@]}"; do
    [ -n "$p" ] || return 1
    case "$p" in *[!a-zA-Z0-9-]*) return 1 ;; esac
    case "$p" in -*|*-) return 1 ;; esac
  done
  case "$tld" in *[0-9]*) return 1 ;; esac
  return 0
}

# ── CIDR 校验（本版只认 IPv4，IPv6 诚实拒绝让人工处理）────────────────
validate_cidr() {
  local c="$1" ip mask o
  case "$c" in
    *:*) return 1 ;;                       # IPv6：本脚本不校验，别假装通过
    */*) ip="${c%/*}"; mask="${c#*/}" ;;
    *)   ip="$c";     mask=32 ;;
  esac
  case "$mask" in ''|*[!0-9]*) return 1 ;; esac
  # 位数上限：bash 算术按 2^64 回绕，`10#` 后跟 20 位数字会绕回 0
  # （实测 `$((10#18446744073709551616))` = 0），不设限就能骗过下面的 `-le 32`。
  [ "${#mask}" -le 3 ] || return 1
  # 10# 强制十进制：否则 08 / 09 会被当八进制，bash 抛 "value too great for base"
  [ "$((10#$mask))" -le 32 ] || return 1
  # ⚠ 掩码 0 必须按**数值**挡：0.0.0.0/0 形式上"按要求给了 allow"，实质等于不设
  #   限制，正是 fail-closed 要防的那扇门。此前用 glob `*/0|*/00|*/000` 只在调用点挡，
  #   而 `/0000`、`/00000` 在十进制解析下同样为 0 却能穿过（可直接绕过整条检查）。
  #   故收进本函数——它是「段/掩码合法性」的唯一事实源，与 Rust `panel_core::expose` 同口径。
  [ "$((10#$mask))" -ge 1 ] || return 1
  [ "${#ip}" -le 15 ] || return 1
  local IFS='.'; read -ra o <<< "$ip" 2>/dev/null || return 1
  [ "${#o[@]}" -eq 4 ] || return 1
  for n in "${o[@]}"; do
    case "$n" in ''|*[!0-9]*) return 1 ;; esac
    [ "$((10#$n))" -le 255 ] || return 1
  done
  return 0
}

# ── 卸载：撤下反代，面板保持绑回环 ─────────────────────────────────────
if [ "$UNINSTALL" -eq 1 ]; then
  [ "$(id -u)" -eq 0 ] || die "需要 root 权限"
  # ⚠ 不无条件声称"已删除"：`rm -f` 对不存在的文件同样返回 0，于是本就未暴露时
  #   卸载也会打印"已删除"，上游 remove 遂一律审计成 ok——审计日志里出现无从分辨的
  #   「撤销成功」，运维无法据此判断到底有没有真的撤销过暴露。
  if [ -e "$NGINX_CONF" ]; then
    rm -f "$NGINX_CONF" && echo "· 已删除 $NGINX_CONF"
  else
    echo "· $NGINX_CONF 不存在（本就未对外暴露，无需撤销）"
  fi
  if command -v nginx >/dev/null 2>&1; then nginx -t >/dev/null 2>&1 && nginx -s reload >/dev/null 2>&1 || true; fi
  rm -f "$TLS_DROPIN"
  # ⚠ 必须**重启** panel，且不能只 `daemon-reload`：PANEL_TLS 是进程启动时
  #   读取的环境变量（panel-api routes/auth.rs 据此给会话 cookie 加 Secure），
  #   daemon-reload 只让 systemd 重读单元文件，改变不了已在跑的进程环境。
  #   不重启则「磁盘已撤销 / 进程仍在 TLS 模式」的不一致会一直挂着，
  #   且从外面看不出来，直到有人手动重启。
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl restart panel >/dev/null 2>&1; then
      echo "· 已移除 PANEL_TLS=1 并重启面板（当前会话会断开，重登即可）"
    else
      echo "· 已移除 PANEL_TLS=1 的 systemd 配置，但重启 panel 失败（请手动 systemctl restart panel，否则进程仍在 TLS 模式）"
    fi
  else
    echo "· 已移除 PANEL_TLS=1 的 systemd 配置（无 systemd，请自行重启面板进程）"
  fi
  echo
  echo "反代已撤下。面板仍只绑回环 ⇒ 本机访问请用："
  echo "    ssh -L <端口>:127.0.0.1:<端口> <user>@<server>"
  echo
  # 防火墙是唯一刻意不自动回退的一步：443 上可能有别的站点，自动删除容易误伤，
  # 与其"聪明地删错"，不如明确告诉用户该执行什么。
  echo "⚠ 防火墙放行没有被自动撤销（避免误伤同样用 443 的其它服务）。若要一并去掉："
  echo "      ufw delete allow 80/tcp; ufw delete allow 443/tcp"
  echo "      # 或 firewalld：firewall-cmd --permanent --remove-service=http --remove-service=https && firewall-cmd --reload"
  exit 0
fi

# ── 前置：root / nginx ──────────────────────────────────────────────────
# ⚠ 刻意**不在这里**要求 openssl：用户若自带证书（--fullchain/--key）根本用不到它，
#   提前要求等于把"明明能做成的事"也拒掉。挪到自签分支里按需检查。
[ "$(id -u)" -eq 0 ] || die "需要 root 权限（要写 /etc/nginx 与 systemd 单元）"
need_cmd nginx
[ -f "$CONF_FILE" ] || die "找不到面板配置 $CONF_FILE（面板装了吗？）"

# ── ① 参数校验（fail-closed 第 1 条）───────────────────────────────────
[ -n "$DOMAIN" ] || die "必须用 -d/--domain 指定对外域名（如 panel.example.com）"
validate_domain "$DOMAIN" || die "域名 [$DOMAIN] 不合法：需至少两级、每段字母数字连字符、顶级域不能含数字"

if [ "${#ALLOW[@]}" -eq 0 ]; then
  echo "expose-public: 拒绝执行 —— 没有 -a/--allow 就不给开反代。" >&2
  echo "  没有来源限制的反代，等于把 root 权限的面板放到公网任人触达。" >&2
  echo "  请填你自己的出口网段，例如：-a \$(curl -s ifconfig.me)/32" >&2
  exit 1
fi
# ⚠ 掩码 0 的拦截**不放这里**：上一版在此用 glob `*/0|*/00|*/000` 挡，
#   但 `/0000`、`/00000` 在 `10#` 十进制解析下同样为 0，能整条绕过。
#   已收进 `validate_cidr`（按解析后的数值判定），此处只做一次调用即可。
for c in "${ALLOW[@]}"; do
  validate_cidr "$c" || die "来源网段 [$c] 不合法（本版只支持 IPv4 CIDR；掩码 0 覆盖整个 IPv4 空间、等于不设限制，已拒绝；IPv6 请在生成的 nginx 配置里自行加 allow）"
done

if [ -n "$FULLCHAIN" ] || [ -n "$KEY" ]; then
  [ -n "$FULLCHAIN" ] && [ -n "$KEY" ] || die "--fullchain 与 --key 必须成对给出"
  [ -f "$FULLCHAIN" ] || die "证书链不存在：$FULLCHAIN"
  [ -f "$KEY" ]       || die "私钥不存在：$KEY"
else
  SELF_SIGNED=1
fi

# ── ② 读取面板端口 + 真实监听地址（fail-closed 第 2、3 条）─────────────
# ── TOML 取值：只认 [server] 表内的 port ───────────────────────────────
# 两种写法都刻意避开：`grep port | head -1` 会把别的表的端口当成本服务的
# （配置里将来完全可能出现 [db] port）；而 `^port` 那种写法要求配置顶格写，
# 用户一缩进就取不到、直接判定"面板没配"。这里先定位表，再在表内取键。
server_key() {
  local key="$1" in_server=0 line head lhs rhs tbl
  while IFS= read -r line || [ -n "$line" ]; do
    head="${line#"${line%%[![:space:]]*}"}"          # 去行首空白
    case "$head" in
      '['*)                                          # [table] 行：切换当前表
        tbl="${head#[}"; tbl="${tbl%%]*}"
        tbl="${tbl%"${tbl##*[![:space:]]}"}"
        if [ "$tbl" = "server" ]; then in_server=1; else in_server=0; fi
        continue ;;
      ''|'#'*) continue ;;                           # 空行 / 注释行
    esac
    [ "$in_server" -eq 1 ] || continue
    case "$head" in *=*) ;; *) continue ;; esac      # 不是键值对
    lhs="${head%%=*}"; rhs="${head#*=}"
    lhs="${lhs%"${lhs##*[![:space:]]}"}"             # 去首尾空白
    lhs="${lhs#"${lhs%%[![:space:]]*}"}"
    rhs="${rhs%%#*}"                                 # 去行尾注释
    rhs="${rhs#"${rhs%%[![:space:]]*}"}"
    rhs="${rhs%"${rhs##*[![:space:]]}"}"
    [ "$lhs" = "$key" ] || continue
    printf '%s' "$rhs"
    return 0
  done < "$CONF_FILE"
  return 1
}

PORT="$(server_key port || true)"
case "$PORT" in
  ''|*[!0-9]*) die "未能从 $CONF_FILE 的 [server] 表读出监听端口" ;;
esac

# 判据刻意取**真实监听**而不是配置文件里的 bind：
# 配置可能被改了却没重启，而“内核里到底监听在哪”才是决定暴露面的事实。
need_cmd ss
RAW=$(ss -ltn 2>/dev/null)
if ! printf '%s\n' "$RAW" | grep -q '^State'; then
  die "ss 输出没有表头，端口探测不可信（可能无权限或命令异常）。\
判据不可信时不放行——否则“检测不到”会被当成“只在本地”，把裸奔判成安全。"
fi

# 取第 4 列（Local Address:Port），挑出本地端口恰为 $PORT 的行。
# ⚠ 刻意不用 awk：awk 通常是 /usr/bin/awk -> /etc/alternatives/awk 的软链，
#   在精简镜像 / alternatives 链断裂 / /etc 被临时替换时会“凭空消失”——
#   install.sh 的 pick_random_port 就为此专门加固过。这里只是取一列，
#   bash 内建的 read -ra 足够，顺带少一个外部依赖。
HITS=""
while IFS= read -r line; do
  if [ -z "$line" ]; then continue; fi
  read -ra f <<< "$line"
  if [ "${f[0]:-}" = "State" ]; then continue; fi
  la="${f[3]:-}"
  if [ -z "$la" ]; then continue; fi
  case "$la" in
    *:"$PORT") HITS+="$la"$'\n' ;;
  esac
done <<< "$RAW"
[ -n "$HITS" ] || die "没检测到面板在端口 $PORT 上监听（先确认 systemctl start panel）"

while IFS= read -r addr; do
  [ -n "$addr" ] || continue
  case "$addr" in
    127.0.0.1:*|\[::1\]:*) ;;
    *) die "面板当前监听在 $addr（非回环）——已经自己暴露在外了。\
本脚本的唯一前提是「面板本体零暴露面」，请先把 $CONF_FILE 里 localhost_only 改回 true 并重启，再重跑。" ;;
  esac
done <<< "$HITS"
echo "· 面板正在 127.0.0.1:$PORT 监听（本体未对外暴露，符合前提）"

# ── ③ 证书 ──────────────────────────────────────────────────────────────
if [ "$SELF_SIGNED" -eq 1 ]; then
  need_cmd openssl
  mkdir -p "$CERT_DIR"
  chmod 0700 "$CERT_DIR"
  FULLCHAIN="$CERT_DIR/fullchain.pem"
  KEY="$CERT_DIR/privkey.pem"
  # ⚠ 已存在且 CN 与本次域名一致 ⇒ 复用，不重建。两个理由：
  #   1) 每次重建自签证书会换指纹，浏览器**再次**告警，用户以为是坏了；
  #   2) 更要命的：用户后来把受信任证书放到同一路径，重跑时会被悄悄换回自签——
  #      那是静默降级（HTTPS 还在，只是变成了"有 HTTPS 的裸奔"）。
  #
  # 归属怎么判断：看 MARKER —— 本脚本自签时留下的记号。
  #   · 有记号 ⇒ 自己签的：CN 对得上就复用，对不上（含读不出 CN）就重建；
  #   · 没记号 ⇒ 别人放的：一律不动。
  # ⚠ "读不出 CN 就一律复用"这种兜底不能用（E2E 已钉住）：openssl 的输出写法随版本
  #   变（本机实测是 subject=CN=panel.example.com，等号两边**没有**空格），
  #   一旦漏掉某种写法，就会退化成"永远不换证书"——带着旧 CN 对外却报成功。
  REUSE=0
  if [ -f "$FULLCHAIN" ] && [ -f "$KEY" ]; then
    if [ ! -f "$MARKER" ]; then
      note "已有证书不是本脚本签发的（缺 $MARKER），按原样复用、不擅自替换"
      REUSE=1
    else
      subj="$(openssl x509 -in "$FULLCHAIN" -noout -subject 2>/dev/null || true)"
      rest="${subj#subject=}"; rest="${rest#/}"
      case "$rest" in
        'CN ='*) cert_cn="${rest#*=}" ;;             # OpenSSL 3.x：subject=CN = x
        CN=*)    cert_cn="${rest#CN=}" ;;            # 另有实现：subject=CN=x
        *)       cert_cn="" ;;
      esac
      case "$cert_cn" in */*) cert_cn="${cert_cn%%/*}" ;; esac    # 后面还跟着别的字段
      cert_cn="${cert_cn#"${cert_cn%%[![:space:]]*}"}"            # 去首尾空白
      cert_cn="${cert_cn%"${cert_cn##*[![:space:]]}"}"
      if [ "$cert_cn" = "$DOMAIN" ]; then
        REUSE=1
        note "复用已有证书 $FULLCHAIN（CN=$DOMAIN）"
      elif [ -n "$cert_cn" ]; then
        note "已有证书 CN=[$cert_cn] 与本次域名不符，将重建"
      else
        note "读不出证书 CN（[$subj]），按域名不符处理，免得带着错证书对外"
      fi
    fi
  fi
  if [ "$REUSE" -eq 0 ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -keyout "$KEY" -out "$FULLCHAIN" -subj "/CN=$DOMAIN" \
      -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1 \
      || die "生成自签证书失败（openssl 报错见上）"
    chmod 0600 "$KEY"; chmod 0644 "$FULLCHAIN"
    : > "$MARKER"
    note "已生成自签证书（浏览器会告警），建议尽快换成受信任证书"
  fi
fi

# ── ④ 生成 nginx 配置 ───────────────────────────────────────────────────
# 时间戳刻意用 strftime 通用格式：本机 busybox 的 `date -I` 恰好可用，但那是
# 编译期开关（FEATURE_DATE_ISO8601），换个精简实现（部分 Alpine 镜像）就会直接报错。
mkdir -p "$(dirname "$NGINX_CONF")"
# WEBROOT 是 ACME 续期挑战的落点：不建的话平时一切正常，等证书到期续不上才发现，
# 属于"延迟爆炸"那类坑，这里顺手保证它存在。
# ⚠ 但它**不是这次反代能不能用的前提**，所以创建失败只警告、不中止——
#   别让一个"将来才有用"的目录把主线活搞黄（这句针对的是 chmod 受限、
#   或 root 权限被容器裁剪掉的环境）。
if ! mkdir -p "$WEBROOT" 2>/dev/null; then
  note "无法创建 $WEBROOT：将来用 webroot 方式续期证书会失败（本次反代不受影响）"
fi

# 本脚本允许"改参数重跑"。万一这版没通过 nginx -t，必须能退回**上一份还能用的**
# 配置；只 rm 掉文件的话，会把用户正跑着的反代一并弄没 —— 比不做还糟。
PREV="$(mktemp 2>/dev/null || true)"
HAVE_PREV=0
if [ -f "$NGINX_CONF" ] && [ -n "$PREV" ]; then
  cp -a "$NGINX_CONF" "$PREV" && HAVE_PREV=1
fi

{
  cat <<NGINX
# 由 deploy/expose-public.sh 于 $(date '+%Y-%m-%dT%H:%M:%S%z') 生成
# 改参数请重跑脚本，**不要手改本文件**（重跑会整体覆盖）。
#
# 安全前提：面板本体始终只绑 127.0.0.1（面板端口 $PORT），外网只到这里。
# 万一 nginx 挂了 / 白名单把自己锁外面，仍可用 ssh -L $PORT:127.0.0.1:$PORT 进面板。

# WebSocket 升级映射（http 级指令，必须排在 server 之前）：
# 按请求动态决定 Connection——有 Upgrade 头才 upgrade，否则 close。
# 变量名刻意带 forkpanel_panel_ 前缀：本项目自己的站点渲染器也会生成同类 map，
# 同名变量会让 nginx -t 报 duplicate map，这里主动错开。
map \$http_upgrade \$forkpanel_panel_ws {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name $DOMAIN;

    # 续期挑战路径必须放行：否则下面的白名单会把 ACME 验证请求挡在门外，
    # 证书到期时无法自动续期。
    location /.well-known/acme-challenge/ {
        root $WEBROOT;
        try_files \$uri =404;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    # 刻意不启用 HTTP/2：http2 on 指令需要 nginx >= 1.25.1，而旧写法
    # listen 443 ssl http2 又在 1.25+ 报弃用告警，两者都无法通吃所有版本。
    # 这里宁可用 HTTP/1.1 —— HTTPS 的安全性来自 TLS，不来自 HTTP/2。
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate     $FULLCHAIN;
    ssl_certificate_key $KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;

    # ── 来源白名单（fail-closed：名单外一律拒绝）──
NGINX
  for c in "${ALLOW[@]}"; do printf '    allow %s;\n' "$c"; done
  cat <<NGINX
    deny all;

    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # WebSocket（内置 Web 终端走 WS）：必须按请求动态决定。写死
        # Connection "upgrade" 会让**所有**请求都带升级头、把后端连接复用搞坏
        # ——这一条本项目 Rust 侧渲染器的注释里早就写明，这里保持一致。
        proxy_set_header Upgrade    \$http_upgrade;
        proxy_set_header Connection \$forkpanel_panel_ws;

        # SSE（日志流）：开了缓冲事件会被攒着不发、看起来像"卡住"；
        # 默认 60s 读超时也会把长连接掐断，故放宽到 1h。
        proxy_buffering off;
        proxy_connect_timeout 10s;
        proxy_read_timeout 3600s;

        # 面板要传文件（文件管理器），nginx 默认 1m 会让稍大一点的上传直接 413。
        # 来源已由上面的白名单限定，这里不再自设上限。
        client_max_body_size 0;
    }
}
NGINX
} > "$NGINX_CONF"
chmod 0644 "$NGINX_CONF"
echo "· nginx 配置 → $NGINX_CONF"

# ── ⑤ 先 nginx -t 通过才 reload；失败必须回滚 ──────────────────────────
# ⚠ 不能留坏配置：conf.d 里一个语法错误会让**整台 nginx 起不来**，
#   连本机其它站点一起陪葬。宁可回滚到"没配过"的状态。
if ! nginx -t >/dev/null 2>&1; then
  if [ "$HAVE_PREV" -eq 1 ]; then
    cp -a "$PREV" "$NGINX_CONF"
    echo "· 已还原上一份可用的 nginx 配置（没把正在跑的反代一起删掉）" >&2
  else
    rm -f "$NGINX_CONF"
    echo "· 首次配置即失败，已删除未通过校验的文件" >&2
  fi
  die "生成的配置未通过 nginx -t，已回滚（本机 nginx 未受影响）。详见 nginx -t 输出。"
fi
[ -n "$PREV" ] && rm -f "$PREV"

# D：reload 结果**不能被吞掉**。以前 `|| true` 会让脚本在 reload 失败时也打印
#    "已重载"，用户以为改完了，实际 nginx 还在跑旧配置。
reloaded=0
if command -v systemctl >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1; then
  reloaded=1
fi
if [ "$reloaded" -eq 0 ] && nginx -s reload >/dev/null 2>&1; then
  reloaded=1
fi
if [ "$reloaded" -eq 1 ]; then
  echo "· nginx -t 通过并已重载"
else
  echo "· ⚠ nginx -t 已通过，但**重载失败**（nginx 没在运行？）—— 配置已落盘，需你手动生效：" >&2
  echo "      nginx -s reload    # 或 systemctl reload nginx" >&2
fi

# ── ⑥ 防火墙：只在检测到活跃防火墙时才动 ───────────────────────────────
if [ "$NO_FIREWALL" -eq 1 ]; then
  note "已跳过防火墙放行（--no-firewall）：请自行确认 443 可达"
else
  # 云厂商安全组是另一层，脚本碰不到 ⇒ 必须显式提醒，别让人以为"跑完就通了"
  # 80 也必须放行：上面生成的 80 server 块里就有 HTTP-01 续期挑战的路径。
  # 只开 443 的表现是"一切正常"，等三个月后证书续不上才炸——延迟爆炸型故障。
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 80/tcp >/dev/null 2>&1 && ufw allow 443/tcp >/dev/null 2>&1 \
      && echo "· ufw 已放行 80/tcp 与 443/tcp" \
      || note "ufw 放行失败，请手动执行：ufw allow 80/tcp && ufw allow 443/tcp"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1 \
      && firewall-cmd --permanent --add-service=https >/dev/null 2>&1 \
      && firewall-cmd --reload >/dev/null 2>&1 && echo "· firewalld 已放行 http 与 https" \
      || note "firewalld 放行失败，请手动执行：firewall-cmd --permanent --add-service=http --add-service=https && firewall-cmd --reload"
  else
    note "未检测到活跃防火墙，443 是否可达取决于你的云厂商安全组 —— 请去控制台确认"
  fi
fi

# ── ⑦ 告诉 panel 它跑在 HTTPS 后面（否则 cookie 不带 Secure）────────────
# panel-api/src/routes/auth.rs 读 PANEL_TLS 环境变量决定是否给会话 cookie 加 Secure。
# 页面走 https 而 cookie 没 Secure ⇒ 降级的第一块骨牌，必须补。
mkdir -p "$TLS_DROPIN_DIR"
printf '[Service]\nEnvironment=PANEL_TLS=1\n' > "$TLS_DROPIN"
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart panel >/dev/null 2>&1 \
    && echo "· 已设置 PANEL_TLS=1 并重启面板（当前会话会断开，重登即可）" \
    || note "PANEL_TLS=1 已写入 $TLS_DROPIN，但重启 panel 失败（请手动 systemctl restart panel）"
else
  note "PANEL_TLS=1 已写入 $TLS_DROPIN（无 systemd，请自行重启面板进程）"
fi

cat <<EOF

完成。验收清单（逐条确认，别只看"跑完了"）：

  1. DNS：$DOMAIN 必须解析到本机           dig +short $DOMAIN
  2. 本地可达（先绕开外网）                curl -k https://127.0.0.1/ --resolve $DOMAIN:443:127.0.0.1
  3. 白名单内应 200、名单外应 403         换一台不在网段的机器试一下必须为 403
  4. 证书可续期                            生产建议改用面板站点 SSL（有 010_cert_auto_renew 自动续期）
  5. 云安全组放行 443                      云服务器这一层脚本碰不到，务必去控制台确认
  6. 应急后门仍在                          ssh -L $PORT:127.0.0.1:$PORT <user>@<server>

  浏览器打开： https://$DOMAIN
  撤下反代：   ./deploy/expose-public.sh --uninstall
EOF
