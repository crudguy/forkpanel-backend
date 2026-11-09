# ForkPanel 部署与账号初始化

面向**把面板装到别人服务器上**的场景。核心问题：面板没有注册页，第一个 owner 账号怎么来。

结论：**一次性引导令牌 + Web 首启向导**。不做开放注册，不做无口令 setup 窗口。

---

## 1. 为什么没有注册页

面板账号 = 服务器管理员，不是社区用户。若开放"任何人可注册/无口令创建 owner"，监听回环的服务等于给同机任意本地进程留后门。

因此建号能力必须等价于**"看过服务器终端输出"**这一信任前提，三条路径都满足它：

| 路径 | 适用场景 | 做法 | 信任前提 |
|---|---|---|---|
| **① 引导令牌（推荐）** | 有人值守的常规部署 | 首启打印一次性令牌，浏览器里建号 | 能读服务日志 |
| **② CLI init** | 自动化 / 无人值守 / 无浏览器 | `panel init --owner admin` | 有服务器终端 |
| **③ install.sh 随机口令** | 批量脚本部署 | 脚本生成强口令传给 `init --owner-pass` | 能读脚本输出 |

被否决的方案：**无口令首启 setup 窗口**（首启 N 分钟内回环可直接建号）。弱点与"开放注册"同源——同机进程无需任何凭据即可创建 owner。

---

## 2. 推荐路径：引导令牌

### 2.1 安装

```bash
cargo build --release
sudo ./deploy/install.sh                 # 缺省取 ./target/release/panel
```

`install.sh` 会：装二进制到 `/usr/local/bin/panel`、建目录（数据 0700 / 配置·日志 0750）、写入 `/etc/forkpanel/config.toml`（已存在则不覆盖）、安装 systemd 单元、**并在装完直接把服务拉起来**（会真探端口确认在监听后才报"已启动"）。**它不建账号。**

> **不用再手动 `systemctl start panel`**：安装脚本已代为启动，收尾输出会写明服务实际状态。
> 万一没起来，脚本不会把"安装"判失败（此时文件都已落盘），而是给出 `journalctl -u panel` 诊断。

> **端口不再固定 2083**：新安装时 `install.sh` 会在 `[10000, 65535]` 随机分配一个监听端口并写进 `config.toml`，安装输出与首启横幅都会打印实际端口（降低被扫描概率）。升级（配置已存在）沿用既有端口。dev/test 默认值仍保留 2083（见 `config.rs` 的 `default_port`），不影响开发环境。

### 2.1.1 一键安装脚本 get-panel.sh（无需 Rust 工具链）

不想自己编译的用户：官方提供一个「下载签名二进制 → 验签 → 安装」的脚本，等价于 §2.1 的
「编译 + install.sh」，但**不需要在本机装 cargo / zig**：

```bash
# 脚本自身从 main 分支取；二进制默认从 GitHub Releases 下载最新稳定版
# 两步法：先下载脚本到本地（wget 重试+续传；curl 备选见 README），再 sudo 执行
wget -O get-panel.sh https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh
sudo bash get-panel.sh

# 指定版本
# ⚠ 版本号不带 v 前缀（脚本自己拼 /releases/download/v<版本>）
PANEL_VERSION=0.1.0 sudo -E bash get-panel.sh
```

脚本按架构（amd64 / arm64）选包、用**内嵌 ed25519 公钥**验签（签不过绝不运行），
解包后执行 tarball 内的 install.sh（即 §2.1 那条安装 + 自动启动链路）。

> **安全不变**：无论 tarball 来自 GitHub 还是下面任何镜像，都必须通过同一把公钥验签，
> 镜像被污染也不会被放行。

### 2.1.2 国内镜像源（解决 GitHub CDN 下载不动）

中国大陆实机最常见的问题：GitHub Release 资产落在 `release-assets.githubusercontent.com`
（Azure CDN），直连常超时 / 被重置，表现就是"一直下载不了安装文件"。脚本支持**多源按序回退**：

```bash
# 方式一：钉死单源（自建源 / 指定镜像，设置后不再回退）
PANEL_RELEASE_BASE=https://<你的镜像基址>/releases/latest/download \
  sudo -E bash get-panel.sh

# 方式二：逗号分隔的备用镜像链，逐个尝试，死源快速跳过，最后兜底官方 GitHub
PANEL_MIRRORS=https://mirror-a.example.com/latest,https://mirror-b.example.com/latest \
  sudo -E bash get-panel.sh
```

- 每个"源"是一个**目录基址**：脚本在其后拼接 `/panel-linux-<arch>.tar.gz` 与 `.sig`。
- 镜像链用更紧的下载预算（连接 8s / 上限 120s / 重试 2）快速跳过死源；钉死源与
  官方兜底用原韧性参数（连接 15s / 上限 600s / 重试 5）。
- 想自建镜像？仓库自带 `deploy/mirror-sync.sh`，**只镜像验签通过的真货**（坏货绝不写入）：

  ```bash
  # 同步 latest（amd64 + arm64）并直接打印客户端该填的 PANEL_MIRRORS
  bash deploy/mirror-sync.sh --public-base https://mirror.example.com/forkpanel
  # 同步指定版本到本地目录
  bash deploy/mirror-sync.sh --version v0.1.0 --dest /srv/mirror
  # 同时推到 rclone remote（Cloudflare R2 / 对象存储等）
  bash deploy/mirror-sync.sh --rclone myremote:/forkpanel
  ```

  产出布局：`<dest>/latest/` 与 `<dest>/<tag>/`，各含 `panel-linux-{amd64,arm64}.tar.gz(.sig)`。
  把这份目录通过 Web 服务器 / rclone 对外暴露后，客户端设
  `PANEL_MIRRORS=<对外基址>/latest`（追最新）或 `<对外基址>/<tag>`（钉版本）。

> **密钥轮换**：换签名私钥后，用新私钥重签 Release，并用 `openssl pkey -in <新私钥> -pubout`
> 同步 `get-panel.sh` 的 `RELEASE_PUBKEY`；或分发时下发 `PANEL_PUBKEY_FILE` 覆盖内嵌公钥。
>
> **守卫自证**：两类分发脚本都有 E2E（`make e2e-get-panel` / `make e2e-mirror`），
> 把验签判否分支改坏再跑会明确变红，还原后转绿——改动后请照此自证。

### 2.2 取令牌

首次启动且库中无 owner 时，服务日志会打印醒目横幅：

```bash
journalctl -u panel -n 50 --no-pager
```

```
════════════════════════════════════════════════════════
 首次启动：尚无 owner 账号
 打开面板完成初始设置，引导令牌（一次性，30 分钟内有效）：

     <32 位十六进制令牌>

 面板地址：http://127.0.0.1:<端口>   （<端口> 即下方"监听 …"行与安装输出打印的实际端口，已随机分配）
 远程访问：ssh -L <端口>:127.0.0.1:<端口> <user>@<server>
 令牌过期/丢失：重启 panel serve 重新生成
════════════════════════════════════════════════════════
```

令牌特性：**只存 sha256 哈希于内存**、**正确即焚 / 错误不焚**、30 分钟过期、重启即换新。

### 2.3 打开面板

```bash
# 远程部署：先建隧道（不要改 localhost_only）；<端口> 为安装时随机分配的监听端口
# 不想每次开隧道、要长期公网访问：见 2.5（唯一受支持方式是前置反代终结 TLS，别直接改 bind）
ssh -L <端口>:127.0.0.1:<端口> <user>@<server>
# 本机浏览器访问 http://127.0.0.1:<端口>
```

页面自动探测 `GET /api/v1/auth/status`：无 owner 时显示**初始化面板**向导（令牌 + 用户名 + 口令 + 确认，含实时强度提示），提交成功后切回登录表单。

#### 2.3.1 为什么局域网里其他设备连不上

如果你在装面板的机器上跑 `curl http://127.0.0.1:<端口>` 能通，但同网段另一台机器访问
`http://<内网IP>:<端口>` 连不上，**这是默认行为，不是故障**：

```toml
[server]
localhost_only = true     # ← 为真时 Config::addr() 强制只监听 127.0.0.1，覆盖 bind
```

原因是面板以 root 运行（要管服务与防火墙），而本构建的 `serve` 是明文 HTTP、不提供 HTTPS。
两者叠加时，监听非回环地址等于把 root 操作入口明文放到网络上，登录口令可被嗅探。

三种放开方式，按推荐顺序：

| 方式 | 适用场景 | 怎么做 |
|---|---|---|
| **SSH 端口转发**（推荐） | 临时/日常远程 | `ssh -L <端口>:127.0.0.1:<端口> <user>@<server>`，再访问 `http://127.0.0.1:<端口>`。面板零改配置，无新增暴露面。 |
| **前置反代**（长期对外） | 需要固定域名/HTTPS | 见 2.5。面板仍绑回环，由 nginx 终结 TLS。 |
| **局域网直连**（不推荐） | 可信内网、临时调试 | 把 `localhost_only` 设为 `false`、**同时**把 `bind` 设为 `"0.0.0.0"`，再 `systemctl restart panel`。 |

> ⚠️ 局域网直连的两个坑：① **只改 `bind` 不生效**——`localhost_only` 会覆盖它，这是最高频的误判；
> ② 改完是明文 root 入口，任何同网段设备都能触达登录页，仅限可信网络临时使用，用完改回。

查看当前是否处于仅本机模式：**设置 → 部署配置（只读）→ 监听地址**；终端也会在 `serve`
启动时打印一行「仅本机访问」提示（`journalctl -u panel`）。

### 2.4 接口契约

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/auth/status` | `{ needs_bootstrap, token_active }`，公开，只暴露布尔值 |
| POST | `/api/v1/auth/bootstrap` | `{ token, username, password }` → 204；已有 owner → 409 |

错误码：`10011` 令牌无效/过期、`10005` 已完成初始化、`10001` 口令不合策略。

> 副作用顺序纪律：owner 检查 → 输入校验 → 哈希 → **最后**才消费令牌。
> 否则用户第一次提交弱口令失败却已焚毁令牌，第二次改对也进不去。

---

### 2.5 公网远程访问：前置反代是唯一受支持的方式

**先说结论：别把面板直接绑到 `0.0.0.0`。**

面板以 root 运行（它要管理系统服务、防火墙），而**本构建不提供 HTTPS**——
`serve` 永远是明文 `axum::serve`。两个事实叠加的后果是：一旦监听非回环地址，
就是把 root 权限的操作入口**明文**放到网上，登录口令可被嗅探。

> `[server].tls` 是**故意做成拒绝启动**的：历史上宣传过 `--features tls`，但代码从未接线。
> 现在配置它，启动时会直接报错并提示改走前置反代——宁可拒绝，也不留一个
> "看起来有 HTTPS、实际是明文"的假开关（见 `crates/panel-cli/src/config.rs` 的
> `validate_implemented`）。

#### 最容易踩的一处：只改 `bind` 是不生效的

```toml
[server]
bind = "0.0.0.0"          # ← 只改这个没用
localhost_only = true     # ← 它会强制覆盖 bind
```

`Config::addr()` 里是 `if localhost_only { "127.0.0.1" } else { bind }`：
`localhost_only` 为真时无论 `bind` 写什么都绑回本机，表现为"改了没生效"。
两者都改才会真的监听非回环——届时启动会打印醒目安全横幅，但**不会拒绝启动**。

#### 受支持做法：面板继续绑回环，由 nginx 反代终结 TLS

好处是**面板自身零外网暴露面**；即便 nginx 挂了或在改错白名单时把自己锁在外面，
`ssh -L` 到面板的回环端口这条**应急后门依然存在**。

**方式一（推荐，零手写配置）：在面板里给自己建一个反代站点**

面板已有完整的站点反代 + 证书签发与自动续期 + 访问控制能力，直接用即可：

1. 站点 → 新建 → 域名填 `panel.<你的域名>`，类型选**反向代理**
2. upstream 填 `http://127.0.0.1:<面板端口>`（端口见安装输出，或 `grep ^port /etc/forkpanel/config.toml`）
3. 开启 SSL（面板负责签发，**并会跑 `010_cert_auto_renew` 的到期自动续期**）
4. 访问控制：填 **IP 白名单**（只放行你自己的出口网段），建议再叠一层 Basic Auth
5. 防火墙放行 443

**方式二：用 `deploy/expose-public.sh` 生成（脚本化，推荐给自动化 / 批量场景）**

不用面板站点模型时，仓库自带一个"一次跑完"的脚本，它上面三步全包了，而且**失败就退干净**。

> ⚠ **前置硬闸：执行前必须先完成 owner 初始化**。经 SSH 隧道或本机走完首启向导
> （或 `panel init --owner/--owner-pass`），并确认
> `curl -s http://127.0.0.1:<面板端口>/api/v1/auth/status` 返回 `needs_bootstrap=false`。
> 原因：官方安装不建账号，首个 owner 由 Web 向导创建；而引导令牌端点只校验 TCP peer
> 是否回环，本反代从 `127.0.0.1` 转发会让**公网请求被当成 loopback 可信请求**。
> 若先开反代再首启，白名单网段内任何人都能取到一次性令牌并抢注 owner（面板以 root
> 运行，内置终端等价 root shell）。脚本会主动探测并拒绝，且生成的 nginx 配置对
> `/api/v1/auth/bootstrap*` 加了 `deny all` 作为不依赖运行时状态的纵深防御。

```bash
sudo ./deploy/expose-public.sh -d panel.example.com -a 203.0.113.0/24 [-a 1.2.3.4/32] \
      [--fullchain <链> --key <私钥> | --self-signed] [--no-firewall]
sudo ./deploy/expose-public.sh --uninstall          # 撤下反代，面板仍绑回环
```

它会做这些事（每一条都是过去手写时最容易漏的）：

| 步骤 | 做什么 | 漏了会怎样 |
| --- | --- | --- |
| 校验 | 不给 `-a/--allow` **直接拒绝**；域名/CIDR 不合法拒绝 | 没有来源限制的反代＝把 root 面板开放到公网任人触达 |
| 首启检查 | 向 `/api/v1/auth/status` 确认 `needs_bootstrap=false`；未初始化 / 服务不可达 / 响应异常一律拒绝；nginx 层 `deny` 两条引导端点 | 先开反代再首启＝白名单内可抢注 root 面板 |
| 探测 | 用 `ss -ltn` 看**真实监听**（而非配置文件里的 bind）：非回环即拒绝；`ss` 输出连表头都没有也拒绝 | "没检测到＝没监听"会把裸奔判成安全 |
| 证书 | 自带 `--fullchain/--key`，或 `--self-signed` 现场生成；CN 没变就**复用**（不会每次重签） | 每次重签会换指纹、也会把用户后放的受信任证书悄悄替回自签 |
| 配置 | 80 跳 HTTPS + ACME 挑战路径放行、443 终结 TLS、IP 白名单 `deny all`、WebSocket/SSE 转发、放开上传体积 | 少 SSE 那条会表现为"日志流看着卡住" |
| 生效 | 先 `nginx -t`，**不通过就回滚上一份可用配置**（首次失败则删除）；重载失败会明说 | `conf.d` 一个语法错误会让整台 nginx 起不来，本机其它站点陪葬 |
| 防火墙 | ufw / firewalld 放行 **80 与 443**（80 是续期挑战要走的） | 只开 443：跳转正常，三个月后证书续不上才炸 |
| 收尾 | 写 systemd drop-in `PANEL_TLS=1` 并重启面板（当前会话会断开，重登即可） | cookie 不带 `Secure`：HTTPS 装了也白装 |

脚本本身有 E2E（`make e2e-expose`）：在 user namespace 里用 tmpfs + systemctl/nginx/ss/ufw/curl 的 shim 真跑一遍，把上面四条拒绝与配置逐条钉住（含「未初始化必须拒绝」「引导端点块内必须 deny」的负向场景）；不具备 `unshare` 时 `[skip]` 退出 2，不冒充通过。

**方式三：纯手写 nginx（供裁剪参考）**

```nginx
# ← 注意 WebSocket 的 Connection 必须**动态决定**：写死 "upgrade" 会让所有请求
#   都带升级头、破坏后端连接复用（本项目 Rust 侧站点渲染器也是同样写法）。
map $http_upgrade $forkpanel_panel_ws {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name panel.example.com;
    # 续期挑战必须放行，否则白名单会把 ACME 验证挡在门外
    location /.well-known/acme-challenge/ { root /var/www/html; try_files $uri =404; }
    location / { return 301 https://$host$request_uri; }
}

server {
    # 刻意不写 http2：`http2 on;` 需要 nginx ≥ 1.25.1，而旧写法 `listen 443 ssl http2`
    # 又在 1.25+ 报弃用告警，两边无法通吃。HTTPS 的安全性来自 TLS，不来自 HTTP/2。
    listen 443 ssl;
    server_name panel.example.com;
    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;

    # IP 白名单：只放行自己的出口网段，其余一律拒绝（宁可收紧）
    allow 203.0.113.0/24;
    deny  all;

    # 首启引导端点：公网一律拒绝。同机反代会让端点误判为 loopback，
    # 白名单内任何人都能在 owner 创建前取到令牌抢注 root 面板。
    location ^~ /api/v1/auth/bootstrap { deny all; }

    location / {
        proxy_pass http://127.0.0.1:<面板随机端口>;   # ← 换成实际端口
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $forkpanel_panel_ws;
        # SSE（日志流）不能被缓冲，默认 60s 读超时也会把长连接掐断
        proxy_buffering off;
        proxy_read_timeout 3600s;
        # 文件管理器要传文件，nginx 默认 1m 会让稍大一点的上传直接 413
        client_max_body_size 0;
    }
}
```

```bash
nginx -t && systemctl reload nginx
ufw allow 80/tcp && ufw allow 443/tcp     # 80 也要开：ACME 续期挑战走 80
```

#### 别漏这一步：告诉 panel 它现在跑在 HTTPS 后面

反代终结 TLS 后必须设 `PANEL_TLS=1`，会话 cookie 才会带 `Secure`
（`panel-api/src/routes/auth.rs` 读这个环境变量，默认关闭）：

```bash
systemctl edit panel        # 写入下面三行后保存
# [Service]
# Environment=PANEL_TLS=1
systemctl restart panel
```

#### 开放前逐条确认

- [ ] 域名 DNS 已解析到本机
- [ ] 证书已签发，且自动续期在跑
- [ ] IP 白名单已收紧到自己的出口网段
- [ ] `/etc/forkpanel/config.toml` 里 `localhost_only` **仍为 `true`**（面板本身不对外）
- [ ] 防火墙 **80 与 443** 都已放行（80 留给 HTTP-01 续期挑战；云厂商安全组是另一层，脚本碰不到）
- [ ] `PANEL_TLS=1` 已生效（`systemctl show panel -p Environment` 可查）
- [ ] `ss -ltn | grep <端口>` 确认面板仍**只**监听 `127.0.0.1:<端口>`
- [ ] 换一台**不在白名单内**的机器访问必须是 403（不做这一步＝白名单可能压根没生效）
- [ ] 应急后门可用：`ssh -L <端口>:127.0.0.1:<端口> <user>@<server>`

---

## 3. 账号运维

```bash
# 改口令（仅改已存在用户；不是建号入口）
sudo panel --config /etc/forkpanel/config.toml passwd admin

# 自动化场景（口令会进 shell history / ps，仅脚本使用）
sudo panel --config /etc/forkpanel/config.toml passwd admin --pass '<新口令>'
```

**忘记口令**：`panel passwd <user>` 改掉即可，无需删库。

**误删 owner**：库中无 owner 时重启服务会重新打印引导令牌，走一遍向导即可。

口令策略：≥10 位且至少含两类字符（与前端强度提示同源）。

---

## 4. 三条安全红线

1. **守住 `localhost_only = true`**。远程访问走 SSH 隧道，不要改成 `0.0.0.0`。确需公网暴露时先接 TLS（M3 ACME）再改，并自行承担暴露面。
2. **`--owner-pass` / `--pass` 只用于脚本**。命令行参数会进 shell history 且 `ps` 可见；手工部署一律用交互模式（口令关回显）。
3. **不做多用户注册**。面板账号即服务器管理员。未来有团队需求应做"owner 邀请子账号"，而非注册页——主流集中式面板都是这个模型。

---

### 4.1 主密钥：异地副本 / 丢失 / 轮换

`<data_dir>/master.key`（0600，32 字节）加密着 **SSL 私钥、数据库口令、远端备份凭据、
MFA 密钥、LLM API Key**。它**不在任何备份里**——这是刻意的（密钥跟密文放一起，加密就白做了）。

于是有一条必须写进运维清单的结论：

> **`master.key` 丢了 = 备份全废。** 恢复出来的库能打开、账号能登录，
> 但所有证书私钥解不开、所有数据库连不上、远端备份也传不出去。
> 外观上"恢复成功了"，实际是个残废的面板。

从 G12 起，**备份产物默认加密**（`panel backup` 出 `.db.enc`，备份计划不传 `encrypt`
即按 `true` 处理），所以这条从"建议"升级成"没做就不能开工"。

#### 4.1.1 做一份异地离线副本

不需要 `tar`/`chmod` 手工拼命令，用面板自己的命令（它顺带拒绝两个错：写进数据目录、
覆盖已有副本）：

```bash
# 1) 看一眼当前密钥的指纹（16 位十六进制）。指纹是哈希，贴进工单/聊天不泄露密钥。
sudo panel key show
#   主密钥：/var/lib/forkpanel/master.key
#   权限：0600
#   大小：32 字节
#   指纹：bcd198f68ebc8e88

# 2) 导出到**异地介质**（U 盘 / 另一台机器 / 密码管理器附件）。
#    目标在数据目录内会被直接拒绝——同盘等于没备份。
sudo panel key export --out /mnt/usb/forkpanel-master.key

# 3) 立刻验证它真能开锁：指纹比对 + 拿副本真解一条库里的密文
sudo panel key check /mnt/usb/forkpanel-master.key
#   ✅ 已用副本解开一条真实密文（db_connections.password_enc id=1（数据库连接口令））
#      ——这份副本确实能开这把锁
```

三件事必须一起做，缺一条这份副本就只是"看着像备份"：

1. **存到与备份不同的介质**（同盘、同机、同机房都不算）；
2. **记下指纹**（写进密码管理器条目或运维台账，换钥后要能分辨"这是哪一代"）；
3. **定期复核**：换机器、换密钥、恢复演练之前，先跑一次 `panel key check`。
   指纹一致但解不开的唯一原因，就是这把钥匙不是那批密文的那把。

> `panel key check` 与 `panel verify-backup` 的区别：前者验"钥匙对不对"，
> 后者验"产物能不能恢复"。恢复出事故时两个都要跑，顺序是先钥匙后产物。

#### 4.1.2 丢密钥了怎么办

**先别做任何写操作。** 按顺序试三条出路，前一条不成立再走下一条：

| # | 处境 | 处置 |
|---|---|---|
| ① | 有异地副本 | 把它放回 `<data_dir>/master.key`（`chmod 600`），`panel key check` 确认能开锁，再走 §5.3 恢复库 |
| ② | 换过密钥 | 目录里会有 `master.key.bak-<时间戳>`；用它去解**那个年代**加密的产物。用错代次报的是 `aes-gcm decrypt` 失败，不是"文件损坏" |
| ③ | 真的全丢了 | **加密产物无救**（AES-256-GCM 无密钥即无解）。只能改用未加密的 `.db` 产物恢复，并接受库里所有密文失效：重新签发证书、重设数据库口令与远端凭据、重新绑定 MFA |

第 ③ 条的代价要提前讲清楚：恢复出来的库**能登录**，`has_password` 还是 `true`，
但每一次真正去读秘密都会失败。所以丢密钥时的正确动作是"找密钥"，不是"重装一遍"。

⚠ **不要用一把新生成的密钥顶替。** 新密钥解不开旧产物，只会让现场看起来像"产物损坏"，
把排查引到完全错误的方向。为此 `panel restore-db` / `verify-backup` 在密钥缺失时
**显式失败**并列出上面三条出路，而不是自动生成一把新的（这条有源码守卫
`ci/check_key_hygiene.py` [6] 钉着）。

#### 4.1.3 换密钥（`panel key rotate`）

需要换钥的典型场景：密钥曾随备份一起外泄、交接换人、合规要求定期轮换。

```bash
sudo systemctl stop panel                  # ① 必须先停：运行中的进程内存里还是旧密钥
sudo panel key rotate                      # ② 先干跑：只打印将发生什么
sudo panel key rotate --yes                # ③ 真换
```

它会做四件事，顺序是安全性的一部分：

1. **单事务**重加密 5 个作用域的密文（MFA 密钥 / SSL 私钥 / 数据库口令 / 远端备份凭据 /
   LLM API Key）。任何一行解不开就整体回滚——绝不留"半新半旧"的库；
2. 新密钥**先落盘**（`master.key.new`，0600）再改库：反过来的话，一旦写钥匙失败，
   库里已是新密文而盘上没有对应钥匙 = 数据当场全废；
3. 原子换名：旧 → `master.key.bak-<时间戳>`，新 → `master.key`；
4. 打印各作用域行数与新指纹。

两条硬前提（都会被命令本身拦下，不用记）：

- **服务在跑就拒绝**——否则运行中的进程会继续用旧密钥加密新秘密，库里新旧混装；
- **`backup_dir` 里还有 `.enc` 产物就拒绝**（`--force` 才继续）——那些产物换钥后永久不可解。
  先恢复到新库、或用旧密钥解一份明文 `--no-encrypt` 备份，再换。

换完立刻做的事：

```bash
sudo systemctl start panel && sudo panel doctor
sudo panel key export --out /mnt/usb/forkpanel-master-new.key   # 副本同步更新
sudo panel key check  /mnt/usb/forkpanel-master-new.key
# 确认服务与各功能都正常后，才删除 master.key.bak-<ts>
```

> 旧密钥不要急着删：它是换钥后**唯一**还能解开旧产物与旧副本的东西。
> 保留到下一次备份周期结束、并确认新副本可用之后再删。

#### 4.1.4 三方恢复演练（`panel.db` + `master.key` + 备份）

三个部件少一个都恢复不了，所以演练必须**同时**覆盖"删库"和"删密钥"：

```bash
ci/e2e-key-drill.sh            # 隔离实例 + 独立端口，不碰正在用的实例
```

它按顺序验 10 组、74 条断言（2026-11-09 实跑 `PASS=74 FAIL=0 SKIP=1`）：

| 组 | 验什么 |
|---|---|
| 1 | `panel backup` 默认出 `.db.enc` 且 0600；同目录不留明文；`--no-encrypt` 仍可用 |
| 2–3 | API 侧省略 `encrypt` ⇒ 落库 `true`；显式 `false` **必须被尊重**（默认开启 ≠ 无法关闭） |
| 4–5 | `key show/export/check` 正向；写到数据目录、覆盖已有副本、16 字节文件、另一把 32 字节密钥，四个负向全部被拒 |
| 6 | `key rotate` 三道闸门：服务在跑 / 有旧 `.enc` 产物 / 缺 `--yes` |
| 7–8 | 真换钥后：旧副本失效、新钥能开库、旧产物解不开且报"上一代密钥" |
| 9 | 删库 + 删钥后 `restore-db` 被拒、**不新建密钥**、**不创建空库** |
| 10 | 副本放回 → 恢复库 → 起服务 → 登录 → 数据在 → 密文仍能解开（三方闭环） |

> 「只演练过明文产物」等于没演练：G12 之前 `restore-db` 在密钥缺失时会**静默生成**
> 一把新密钥，于是"丢密钥"被伪装成"产物损坏"，而明文产物那条路会一路成功——
> 现场看起来一切正常，直到某天要读 SSL 私钥。这条是 2026-11-09 真跑时抓出来的。

前端备份页对加密产物已有同义的红字警告（「主密钥一旦丢失无法恢复」），
但那是**用户勾选加密时**才看得见——而密钥丢失影响的是全部备份，故在此再立一条。

### 4.2 根 CA 私钥同样必须单独备份

用了**面板自签证书**才需要管这一条（纯 ACME 用户可跳过）。

`<data_dir>/ssl/ca/` 下是面板本地根 CA：`ca.crt`（可分发的根证书）+
`ca.key`（**私钥，0600，不被 `master.key` 加密**——它保护的不是数据而是信任本身）。
它同样不在任何备份里：`panel` 备份只做 `VACUUM INTO`（纯库），不碰这个目录。

两条结论：

> **`ca.key` 丢了 = 已分发的信任作废。** 用户浏览器/系统里装的是旧根证书，
> 而新签发的站点证书会改用新根——**全部自签站点当场报警**，且毫无提示。
> 每个信任过这台面板的浏览器都要重新装一次根证书。

> **只丢一半比全丢更坑**：`ca.crt` 与 `ca.key` 必须成对。只有一张在位时，
> 面板会**拒绝重签**并返回冲突错误（重签会覆盖剩下的那张，等于静默销毁信任），
> 需要人从备份恢复整个目录。

```bash
# 与 master.key 一起、同样存到异地
sudo tar czf /root/forkpanel-ca-$(date +%F).tar.gz -C /var/lib/forkpanel ssl/ca
sudo chmod 600 /root/forkpanel-ca-*.tar.gz
```

恢复顺序：先 `master.key`（否则库里的证书私钥解不开），再 `ssl/ca/`（否则自签站点
在浏览器里报警）。换机器部署则两者都要重新生成/重新分发根证书。

## 5. systemd 硬化

`panel systemd-unit --install` 生成的单元已含：

- `NoNewPrivileges / ProtectSystem=strict / ProtectHome / ProtectKernelTunables / ProtectControlGroups / RestrictSUIDSGID`
- `CapabilityBoundingSet`（§8-12）：只保留有真实消费者的 10 个 cap——`CHOWN / DAC_OVERRIDE / DAC_READ_SEARCH / FOWNER / FSETID`（文件与站点目录管理）、`KILL`（进程信号）、`SETUID / SETGID`（cron「立即执行」的 run_as 降权）、`NET_BIND_SERVICE`（可配置直绑 80/443）、`NET_ADMIN`（nft/iptables 防火墙）。明确不含 `SYS_ADMIN`（god cap）等其余 31 个。**改这行前必须想清消费者**：砍掉 `SETUID` 会让 run_as 降权 spawn 失败，砍掉 `NET_ADMIN` 会让防火墙读写全灭（实测：`nft list` 直接 EPERM）
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`：UNIX（docker/systemctl socket）、INET/INET6（HTTP/ACME）、NETLINK（nftables 命根）
- `MemoryDenyWriteExecute=yes`：内存页不得同时可写可执行（Rust/SQLite/各子进程均不需 W^X 豁免）
- `SystemCallFilter=@system-service` + `SystemCallErrorNumber=EPERM`：收敛到服务常用 syscall 集（含 set*id 降权与 netlink），越权调用响亮失败
- `ReadWritePaths` 开放数据、日志、站点、配置四个**必填**目录（由 `PathLayout` 提供，非硬编码），外加 nginx `conf.d` / caddy `sites` 两个**可选**目录（`-` 前缀：不存在时 systemd 忽略而非拒绝启动）——站点部署要直写这两个 /etc 落点。⚠ 自定义 [paths] 时目录**不能放 /tmp 或 /var/tmp**：`PrivateTmp=yes` 会给服务一个私有的 /tmp 与 /var/tmp，单元会以 226/NAMESPACE 起不来
- `MemoryMax` 按档位（96M / 192M / 384M）、`CPUQuota=20%`、`TasksMax=256`
- `Restart=on-failure` + `RestartSec=3`：**进程崩溃 / 非零退出会自愈**

以上收敛集经真机验收（Debian 13 / systemd 254 划痕实例，2026-11-09）：启动 active、HTTP 200、登录/cron/docker/nft/systemctl/进程/总览各链路全通、journal 零 SIGSYS、`CapBnd=0x14ff` 精确等于保留集；负向（临时砍掉 NET_ADMIN）证实限制真实生效且探针可分辨。

### 5.1 崩溃自愈的边界（如实说明）

`Restart=on-failure` 覆盖的是「进程死了」。它**不覆盖**「进程活着但不服务」——
例如事件循环被某个请求卡死、或监听 socket 丢失但主线程没退。这类故障 systemd
从外部看不出来，需要下面之一：

| 方案 | 做法 | 代价 |
|---|---|---|
| **外部探活（当前最现实）** | systemd timer / cron 每分钟 `curl -fsS http://127.0.0.1:2083/api/v1/version`，连续失败则 `systemctl restart panel` | 多一个计时器单元；探活脚本要自己幂等 |
| **sd_notify watchdog** | 单元加 `WatchdogSec=60`，应用侧周期性 `sd_notify(0, "WATCHDOG=1")` | 需引 `libsystemd`（或自己实现 `sd_notify` 的 datagram 协议），依赖预算上限 38（去重后第三方直接依赖现约 22），新增仍须先决策 |
| **Type=notify** | 同上，启动完成也走 sd_notify | 同上 |

### 5.2 已提供：`panel healthcheck`（方案①的落地件）

上面三个方案里，**方案①（外部探活）已由 `panel healthcheck` 子命令落地**，
`deploy/install.sh` 默认装上：

```bash
panel healthcheck                       # 打印脚本 + 两个单元（审阅用，不安装）
panel healthcheck --install             # 安装到 script_dir 与 systemd
panel healthcheck --uninstall           # 移除
```

它每分钟打一次 `/api/v1/version`，**连续两次失败才重启**（用 marker 文件记状态）。
为什么是两次：单次失败多为瞬时抖动（重启窗口、CPU 饱和、探活自身超时），
误把好服务重启掉的代价高于漏一次报。恢复成功即清 marker，隔很久的两次失败
不会被你误判成连续失败。

两个刻意的设计选择：

- **判定打 `/api/v1/version` 而非 `/healthz`**。`GET /healthz` 现在是**依赖型就绪探针**（检查 DB 可读 + 数据目录可用余量，异常返回 503），供前置 LB / 编排摘流量；但盘满、库挂这类故障**重启解决不了**，拿它做 systemd 探活会让「连续两次失败」退化成无意义的重启循环。systemd 层只判「HTTP 是否还能回话」，依赖故障交给 `/healthz` 的 503 + 外部告警。
- **探活 service 自身 `Restart=no`**。「两次才重启」由脚本实现，systemd 若再叠
  一层 `Restart=on-failure`，会把策略变得更激进（一次失败就反复重跑）。

```bash
# 看探活是否在跑、上次结果
systemctl list-timers panel-healthcheck.timer
journalctl -u panel-healthcheck.service -n 20 --no-pager
# 手动跑一次自检（不等 timer）
/var/lib/forkpanel/scripts/healthcheck.sh
```

### 5.2.1 就绪探针 `/healthz`

| 项 | 说明 |
|---|---|
| 路径 | `GET /healthz`（免登录、只读、不写库） |
| 200 | `{"status":"ok"}` — DB 可读且数据目录可用空间 ≥ 32 MiB |
| 503 | `{"status":"degraded","reason":"db_unavailable"｜"disk_low"｜"disk_unknown"}` — 只回原因码，**不回内部路径 / 错误详情** |
| 缓存 | `Cache-Control: no-store`，避免 LB 缓存旧健康状态 |
| 用途 | 前置 LB / 编排系统的**就绪探针**：异常时摘流量并触发告警 |
| 不用于 | systemd 探活（见上：盘满重启无用，会形成重启循环） |

> 当前探针覆盖 DB 可读与磁盘余量；**调度器停摆尚未纳入**。外部告警渠道与日志轮转仍在 P1 待办（见 `production-readiness-2026-11-07.md` §3.5）。

> 脚本路径取自 `PathLayout::script_dir()`、端口取自 `Config`，均不硬编码。
> 该脚本的逻辑已真机四态验证（活着 / 挂一次 / 连续挂两次 / 恢复），
> 单测见 `bootstrap::tests::healthcheck_*`。

---

### 5.2.2 日志去向与保留

| 项 | 说明 |
|---|---|
| 唯一去向 | `journalctl -u panel`（systemd 部署）；非 systemd 部署打到启动终端 |
| 无文件日志 | `/var/log/forkpanel` **不落文件**（该目录保留给任务输出等） |
| 保留上限 | 安装器写 `/etc/systemd/journald.conf.d/forkpanel.conf`：`SystemMaxUse=200M`、`MaxRetentionSec=14day` |
| 生效 | `install.sh` 会 `systemctl restart systemd-journald`；手工改配置后同样需要重启 |

> 历史文档曾声称「serve 启动时 stderr 已重定向进日志文件」，实际从未实现，已修正代码注释与 `install-footprint.md`。若确需文件日志 + logrotate（例如采集 agent 只认文件），需把 `StandardOutput/StandardError` 改成 `append:` 并**接受 `journalctl -u panel` 不再可用**；这是另一套方案，当前未采用。

### 5.2.3 外部告警通道（崩溃 + 业务失败，共用一份配置）

告警只有一个配置点：**`/etc/forkpanel/alert-webhook`**，内容是**一行** URL（仅 `http(s)`）。
崩溃与业务失败读的是同一个文件——运维不需要在设置页再配第二个地址。

```bash
sudo sh -c 'echo "https://hooks.example.com/services/XXX" > /etc/forkpanel/alert-webhook'
sudo chmod 600 /etc/forkpanel/alert-webhook   # 该 URL 通常自带 token
sudo panel alert test                         # 立刻验证通不通，别等真出事
panel alert status                            # 是否已接 + 节流口径
```

#### 会触发什么

| 事件 | `event` 字段 | 触发点 |
|---|---|---|
| 进程崩溃 | `crash` | `panel.service` 的 `OnFailure=` → `notify-failure.sh`（不依赖面板进程还活着） |
| 备份失败 | `backup.failed` | 任务终态 `failed` 且 `kind=backup`（手动 / 计划 / 上传远端任一步） |
| 证书签发或续期失败 | `cert.failed` | 任务终态 `failed` 且 `kind=cert_issue` |
| 其它任务失败 | `job.failed` | 任务终态 `failed`（含超时） |
| 内部周期任务失败 | `job.failed` | `InternalScheduler` 任一 job 返回 Err 或超时（清理 / 采样 / 备份扫描…） |
| 通道自检 | `test` | `panel alert test` |

包体形状（shell 侧与 Rust 侧**字段一致**，接收方一套解析即可）：

```json
{"panel":"forkpanel","event":"backup.failed","host":"web-1","ts":1762000000,"unit":"panel.service","detail":"任务 #7（backup）失败：…"}
```

`ts` 是**纪元秒**（数值，不是字符串）；人类可读时间在 `detail` 里。

#### 节流（以及为什么不会把运维逼到关掉告警）

同一 `event` 在 **300 秒**内只外发一条，每小时总量上限 **30 条**。被节流的只记 journald，
外发侧静默。投递失败会**回滚**该事件的节流记录——否则「这次没送到」会占掉整个窗口，
之后 5 分钟内的真实故障全被吞掉。

#### 三条硬约束

1. **配置不存数据库**。库挂了（损坏 / 磁盘满 / 迁移卡死）恰恰是最该告警的时刻，
   把 URL 放进 `settings` 表等于「最需要它的时候读不出来」。
2. **告警失败绝不影响业务**。备份失败的原因是「磁盘满」，不该被「告警发不出去」覆盖掉；
   投递错误只记日志，业务结果不变。
3. **未配置时完全静默**：不报错、不重试、不假装发出。`panel alert status` 会明说「未配置」。

> 排查顺序（`panel alert test` 失败时）：① `curl -v -X POST -d '{}' <URL>` 看对端是否收 POST；
> ② 出站防火墙 / nft 是否放行；③ `which curl` —— 面板经 `curl` 投递，未装则必然失败。

### 5.3 停机恢复面板库（runbook，已真机演练）

**适用范围**：`kind=panel` 的备份（面板自身数据库）。

**为什么必须停机**：面板库是面板**运行中**的库。在线覆盖会损坏 SQLite WAL——
写进去的那一刻旧的 WAL 帧还在，两边一对不上就是「库能打开但数据错乱」，
比打不开更难查。所以站点文件与数据库连接可以在 Web 里在线恢复（`kind=site` /
`kind=db` 有完整实现），而面板库只能停机换文件。这不是缺功能，是 SQLite 的硬约束。

> 恢复前先确认：**主密钥 `<data_dir>/master.key` 还在**。它不在备份里（那是它
> 该在的地方），但 SSL 私钥、数据库口令、远端凭据全都靠它解密——丢了它，备份
> 恢复回来也是一堆解不开的密文。
>
> 从 G12 起默认产物是 `.db.enc`（加密容器），**没有主密钥连恢复都开始不了**：
> `restore-db` 会明确告诉你"没有它无法恢复"并列出三条出路，而不是给你一个
> `aes-gcm decrypt` 失败。顺序永远是 **先钥匙，后库**——详见 §4.1.2。

```bash
CFG=/etc/forkpanel/config.toml

# ⓪ 先确认钥匙这一半：副本与在用密钥指纹一致，且真能开锁
panel --config "$CFG" key show
panel --config "$CFG" key check /mnt/usb/forkpanel-master.key

# ① 停服务（systemd 环境下探活 timer 会连着报失败，属预期，恢复后自愈）
systemctl stop panel

# ② 一条命令完成：验产物 → 给当前库留快照 → 原子替换 → 清掉旧 WAL/SHM
panel --config "$CFG" restore-db /path/to/panel-1234567890.db.enc
#    ✅ 产物可恢复：… integrity_check=ok，含 users 表
#    当前库已留快照：/var/lib/forkpanel/backups/pre-restore-<ts>.db
#    ✅ 已恢复：/var/lib/forkpanel/panel.db

# ③ 起来，然后**验证数据真的回来了**——不只是 200
systemctl start panel
curl -fsS http://127.0.0.1:2083/api/v1/version
# 登录进面板，核对站点数 / 用户数 / 最近备份时间与备份时刻一致
# 密文这一半也要验：库里"有口令"不等于"口令解得开"
panel --config "$CFG" key check /mnt/usb/forkpanel-master.key
```

`restore-db` 的四道保护（缺一条都可能把"恢复"变成"二次事故"）：

1. **拒绝在线恢复**：先探测 `server.bind:port` 是否可连接，能连就中止；
   容器里进程名不同、或已确认停机，可加 `--force`。
2. **先验产物**：`integrity_check` + 必须含 `users` 表；坏产物当场失败，
   不会拿它覆盖正在用的库（退出码 1）。
3. **先留当前态快照**：`backups/pre-restore-<ts>.db`，恢复错了还能退回去。
4. **原子替换 + 清 WAL/SHM**：先写同目录临时文件再 `rename`；旧的 `-wal/-shm`
   属于被替换掉的那个库，留着会被回放到新库上——必须一起删。

只接受 `.db` / `.db.enc`：站点 `.tar.gz` 会被明确拒绝（把归档盖到 `panel.db`
上只会得到一个打不开的库）。

**本地盘没了**（机器挂了、盘换了）：只要计划配了远端副本，可以直接从远端取回——

```bash
panel --config "$CFG" restore-db --remote 3            # 取该计划最新的面板库产物
panel --config "$CFG" restore-db --remote 3 --artifact plan3-1700000000.db   # 指定某一版
```

约束与行为：计划必须是 `kind=panel` 且配了远端副本（否则明确报错，不会去连一个
空 URL）；只认 `.db` / `.db.enc`；拉下来的临时副本用完即删——留在临时目录会让
人误以为本地另有一份备份。服务仍在运行时会先被拦下（不会白下一个大文件）。

<details><summary>没有 <code>restore-db</code> 的旧版本（手工步骤）</summary>

```bash
DATA=/var/lib/forkpanel
# 备份当前态——哪怕它已经坏了
cp -a "$DATA/panel.db" "$DATA/panel.db.broken-$(date +%s)"
panel --config "$CFG" verify-backup /path/to/plan1-1234567890.db
# 主库 + WAL + SHM 三个一起换
rm -f "$DATA/panel.db" "$DATA/panel.db-wal" "$DATA/panel.db-shm"
cp /path/to/plan1-1234567890.db "$DATA/panel.db"
chmod 600 "$DATA/panel.db"
```

</details>

**验收标准**（恢复成功的定义）：能登录 + 站点与账号数量、内容与备份时刻一致。
只看 `/api/v1/version` 返回 200 是不够的——那只能证明进程起来了。

### 5.4 数据库连接（`kind=db`）的在线恢复

站点与数据库连接可以在 Web 里直接恢复，但**每个引擎的语义不一样**，运维时按这个表理解：

| 引擎 | 产物 | 恢复动作 | 恢复前快照 |
|---|---|---|---|
| SQLite | `.db` | 文件覆盖 | provider 内 `<库>.bak-<ts>` |
| MySQL | `.sql` | `mysql -e "source …"` | 计划产物目录 `pre-restore-mysql-<ts>.sql`（留最近 3 份） |
| PostgreSQL | `.sql` | `psql -v ON_ERROR_STOP=1 --single-transaction -f …` | 计划产物目录 `pre-restore-pg-<ts>.sql`（留最近 3 份） |

两条容易踩的坑，都是**静默失败**，看任务状态看不出来：

1. **PSQL 必须开 `ON_ERROR_STOP`**（2026-10-22 真机实证，PG 17.11）。不开时
   `psql -f` 遇错继续往下跑并以 **0** 退出：撞上「关系已存在」后整份 dump 一条都
   没生效，任务却报 `state=ok`，用户在页面上看到的是「恢复成功」，库里一行没变。
   开了之后同一条命令退出码 3、任务正确置 `failed`，并靠 `--single-transaction`
   把改动整体回滚。
2. 配套地，`pg_dump` 必须带 `--clean --if-exists`，产物才会自带"先 DROP 再建"。
   ⚠ **升级后旧产物（无 `--clean`）恢复会明确失败**——这是对的：以前它是"假装
   成功、实际什么都没做"。遇到就重跑一次备份再恢复。

MySQL 侧无需这两个参数：`mysqldump` 默认就带 `DROP TABLE IF EXISTS`，
`mysql` 客户端非 `--force` 模式下遇错即中止（等价 `ON_ERROR_STOP`）——
所以**绝不要**给它加 `--force`。

**验收标准**：恢复完成后**回到库里数一遍行**（`kind=db` 的恢复不会替你验数据）。


**真机演练记录**（2026-10-19，独立实例端口 2091，未碰 dev）：

| 步骤 | 结果 |
|---|---|
| 灌入测试站点 `dr-site` 后备份 | 产物 237,568 B，`integrity_check=ok，含 users 表` |
| 把主库覆写成 50,000 B 随机垃圾 | 服务随后无法正常读库 |
| 按上面 ①~⑤ 换库重启 | `/api/v1/version` 200 |
| 用备份里的账号登录 + 拉站点列表 | HTTP 204 登录成功，`dr-site` 完整回来（domains/root/enabled 均一致） |

> 演练用的备份与坏库都已清理。建议每次大版本升级前照此跑一遍——
> 没演练过的恢复流程，等于没有恢复流程。

## 6. 升级与卸载

```bash
# 升级（面板自带：下载 → 验签 → 失败自动回滚；保留配置与数据）
sudo panel upgrade
# 只检查是否有新版本：sudo panel upgrade --check
# 源码 / 离线：sudo sh get-panel.sh

# 卸载（二进制自带，任何目录都能跑）
sudo panel uninstall
```

> **Web 端「执行升级」默认关闭**：升级会替换 root 二进制并重启，只有 owner 才看得到按钮。
> 启用方式：`config.toml` 加 `[danger] allow_web_upgrade = true` 并重启面板；之后仍需
> owner + 输入确认词 `UPGRADE`。命令行 `panel upgrade` 不受此开关影响，也是网络中断时
> 唯一可靠的恢复路径——所以**不要**因为开了 Web 升级就关掉 SSH。

卸载保留 `/var/lib/forkpanel`、`/etc/forkpanel`、`/var/log/forkpanel`（含账号与数据），确认后自行删除。
源码树里的 `deploy/uninstall.sh` 是同一实现的薄包装（有二进制时直接 `exec panel uninstall`），仅供习惯相对路径的人使用。

---

## 7. schema 升级与回滚（单实例约束）

### 7.1 只有前向迁移，**没有 down migration**

`panel-db/migrate.rs` 的 `MIGRATIONS` 是纯前向数组（当前 `LATEST = 30`），
`schema_migrations` 只记录已应用版本与校验和。两个破坏性变更使旧二进制无法
在同一库上工作：

| 版本 | 动作 | 后果 |
|---|---|---|
| `025_server_notes.sql` | 建 `server_notes` 后 `DROP TABLE server_note` | 旧码仍按 `server_note` 查，表已不存在 |
| `029_drop_api_tokens.sql` | `DROP TABLE IF EXISTS api_tokens` | 零引用的表被删除，旧码若有引用即失败 |

另有一个**非破坏性但后向不兼容**的变更（不丢数据，但旧码的某条路径会失败）：

| 版本 | 动作 | 后果 |
|---|---|---|
| `030_audit_append_only.sql` | 建 `_audit_permit` 令牌表 + `audit_log` append-only 触发器（UPDATE 全禁，DELETE 须持令牌） | 旧二进制的 `prune_audit` 没有令牌逻辑，清理任务每次执行报 `audit_log is append-only`；其余读写正常 |

因此**回滚 = 整库还原 + 换回旧二进制**，不是「跑一条 down SQL」。项目不为已删数据
硬写反向脚本（那会造出「表结构回来了、数据没了」的假回退）。

### 7.2 升级前自动一致快照

`serve` / `panel migrate` / `panel init` 在 `migrate::apply` 之前调用
`snapshot_before_migrate`：仅当 `0 < current < LATEST` 时用 `VACUUM INTO`
写一份升级前的一致快照到 `<data_dir>/backups/pre-migrate-v<旧>-to-v<新>-<ts>.db`（版本号取自 `migrate::LATEST`，不硬编码），
保留最近 5 份。全新库与版本已最新时零额外 IO（冷启动预算不受影响）。
快照失败会**阻断升级**——没有回退锚点就不把 schema 推到不可回退的位置。

### 7.3 回滚 runbook

```bash
# 1) 停服（务必先停：否则旧二进制与新库仍在互相写）
sudo systemctl stop panel
# 2) 找到升级前快照（按时间选升级那一刻的那份）
ls -lt /var/lib/forkpanel/backups/pre-migrate-*.db
# 3) 还原（会先验产物、给当前库留 pre-restore 快照、原子替换、清 WAL/SHM）
sudo panel restore-db /var/lib/forkpanel/backups/pre-migrate-v28-to-v29-<ts>.db
# 4) 换回旧版本二进制，再起服务
sudo cp /path/to/old/panel /usr/local/bin/panel && sudo systemctl start panel
# 5) 验收：能登录 + 站点/用户数量与升级前一致 + panel doctor 的 integrity_check=ok
```

> ⚠ 回滚演练需两个真实不同版本的二进制才能完整验证「旧码 + 旧库」。当前仓库
> 只保留一个版本产物，该组合的端到端演练仍列在上线验收清单（见
> `high-risk-acceptance-runbook.md`）。已有 `panel restore-db` 的真机恢复演练可证明
> 「库能被完整换回」，但不能替代「旧二进制能读它」的验证。

### 7.4 单实例与并发迁移硬护栏

`serve` / `panel migrate` / `panel init` 启动即抢 `<data_dir>/panel.lock` 的
`flock(LOCK_EX | LOCK_NB)`，持有到进程退出；抢不到会带持有者 PID 明确报错退出。
这同时挡住三类事故：并发跑 DDL（`table already exists` / `database is locked`）、
双实例各跑一遍备份 / 证书续期 / 清理、以及内存状态各持一份。
flock 由内核持有，进程被 SIGKILL 后自动释放，不留陈旧 pid 文件。

单实例是**已知设计限制**（`docs/design-multi-node.md` 标注设计稿未实施）；
多节点方案需先引入 leader 选举与共享存储，不能靠放宽这把锁实现。

## 8. 故障排查

| 现象 | 原因与处理 |
|---|---|
| 看不到令牌横幅 | 库中已有 owner（走登录）；或横幅在更早的日志里，`journalctl -u panel --no-pager \| grep 令牌` |
| 提示令牌无效/过期 | 令牌 30 分钟有效且用过即焚：`systemctl restart panel` 重新生成 |
| 提交弱口令后进不去 | 已按次序修复（校验先行、令牌最后消费）；若仍出现请查版本 |
| 端口占用 `Address already in use` | 有残留进程：`ss -ltnp \| grep <实际端口>` 后停用旧实例 |
| 远程打不开 | 先确认隧道已建立，且访问的是本机 `127.0.0.1:2083` |
| `check_data_dir` 失败 | 数据目录不存在，先建目录再 `serve` |
