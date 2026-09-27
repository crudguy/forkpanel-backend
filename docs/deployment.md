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
sudo systemctl start panel
```

`install.sh` 会：装二进制到 `/usr/local/bin/panel`、建目录（数据 0700 / 配置·日志 0750）、写入 `/etc/forkpanel/config.toml`（已存在则不覆盖）、安装并 enable systemd 单元。**它不建账号。**

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

 面板地址：http://127.0.0.1:2083
 远程访问：ssh -L 2083:127.0.0.1:2083 <user>@<server>
 令牌过期/丢失：重启 panel serve 重新生成
════════════════════════════════════════════════════════
```

令牌特性：**只存 sha256 哈希于内存**、**正确即焚 / 错误不焚**、30 分钟过期、重启即换新。

### 2.3 打开面板

```bash
# 远程部署：先建隧道（不要改 localhost_only）
ssh -L 2083:127.0.0.1:2083 <user>@<server>
# 本机浏览器访问 http://127.0.0.1:2083
```

页面自动探测 `GET /api/v1/auth/status`：无 owner 时显示**初始化面板**向导（令牌 + 用户名 + 口令 + 确认，含实时强度提示），提交成功后切回登录表单。

### 2.4 接口契约

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/auth/status` | `{ needs_bootstrap, token_active }`，公开，只暴露布尔值 |
| POST | `/api/v1/auth/bootstrap` | `{ token, username, password }` → 204；已有 owner → 409 |

错误码：`10011` 令牌无效/过期、`10005` 已完成初始化、`10001` 口令不合策略。

> 副作用顺序纪律：owner 检查 → 输入校验 → 哈希 → **最后**才消费令牌。
> 否则用户第一次提交弱口令失败却已焚毁令牌，第二次改对也进不去。

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
3. **不做多用户注册**。面板账号即服务器管理员。未来有团队需求应做"owner 邀请子账号"，而非注册页——主流面板（宝塔 / 1Panel / CasaOS）都是这个模型。

---

## 5. systemd 硬化

`panel systemd-unit --install` 生成的单元已含：

- `NoNewPrivileges / ProtectSystem=strict / ProtectHome / ProtectKernelTunables / ProtectControlGroups / RestrictSUIDSGID`
- `ReadWritePaths` 仅开放数据、日志、站点、配置四个目录（由 `PathLayout` 提供，非硬编码）
- `MemoryMax` 按档位（96M / 192M / 384M）、`CPUQuota=20%`、`TasksMax=256`

---

## 6. 升级与卸载

```bash
# 升级：覆盖二进制后重启（配置不会被覆盖）
sudo ./deploy/install.sh ./target/release/panel
sudo systemctl restart panel

# 卸载
sudo ./deploy/uninstall.sh
```

卸载保留 `/var/lib/forkpanel`、`/etc/forkpanel`、`/var/log/forkpanel`（含账号与数据），确认后自行删除。

---

## 7. 故障排查

| 现象 | 原因与处理 |
|---|---|
| 看不到令牌横幅 | 库中已有 owner（走登录）；或横幅在更早的日志里，`journalctl -u panel --no-pager \| grep 令牌` |
| 提示令牌无效/过期 | 令牌 30 分钟有效且用过即焚：`systemctl restart panel` 重新生成 |
| 提交弱口令后进不去 | 已按次序修复（校验先行、令牌最后消费）；若仍出现请查版本 |
| 端口占用 `Address already in use` | 有残留进程：`ss -ltnp \| grep 2083` 后停用旧实例 |
| 远程打不开 | 先确认隧道已建立，且访问的是本机 `127.0.0.1:2083` |
| `check_data_dir` 失败 | 数据目录不存在，先建目录再 `serve` |
