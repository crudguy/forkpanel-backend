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

> **端口不再固定 2083**：新安装时 `install.sh` 会在 `[10000, 65535]` 随机分配一个监听端口并写进 `config.toml`，安装输出与首启横幅都会打印实际端口（参考宝塔面板，降低被扫描概率）。升级（配置已存在）沿用既有端口。dev/test 默认值仍保留 2083（见 `config.rs` 的 `default_port`），不影响开发环境。

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
ssh -L <端口>:127.0.0.1:<端口> <user>@<server>
# 本机浏览器访问 http://127.0.0.1:<端口>
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

### 4.1 主密钥必须单独备份（最容易被漏的一步）

`<data_dir>/master.key`（0600）加密着 **SSL 私钥、数据库口令、远端备份凭据**。
它**不在任何备份里**——这是刻意的（密钥跟密文放一起，加密就白做了）。

于是有一条必须写进运维清单的结论：

> **`master.key` 丢了 = 备份全废。** 恢复出来的库能打开、账号能登录，
> 但所有证书私钥解不开、所有数据库连不上、远端备份也传不出去。
> 外观上"恢复成功了"，实际是个残废的面板。

```bash
# 初始化后立刻做一次，并存到与备份**不同**的地方（同盘等于没备份）
sudo tar czf /root/forkpanel-master-$(date +%F).tar.gz -C /var/lib/forkpanel master.key
sudo chmod 600 /root/forkpanel-master-*.tar.gz
# 建议：再抄一份到密码管理器或异地；换机器时它是第一个要搬的东西
```

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
- `ReadWritePaths` 开放数据、日志、站点、配置四个**必填**目录（由 `PathLayout` 提供，非硬编码），外加 nginx `conf.d` / caddy `sites` 两个**可选**目录（`-` 前缀：不存在时 systemd 忽略而非拒绝启动）——站点部署要直写这两个 /etc 落点
- `MemoryMax` 按档位（96M / 192M / 384M）、`CPUQuota=20%`、`TasksMax=256`
- `Restart=on-failure` + `RestartSec=3`：**进程崩溃 / 非零退出会自愈**

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

- **判定打 `/api/v1/version` 而非 `/healthz`**。后者在 embed 层，进程活着就
  恒返 200，探不到「HTTP 服务已死但主线程还在」——那正是要抓的故障。
- **探活 service 自身 `Restart=no`**。「两次才重启」由脚本实现，systemd 若再叠
  一层 `Restart=on-failure`，会把策略变得更激进（一次失败就反复重跑）。

```bash
# 看探活是否在跑、上次结果
systemctl list-timers panel-healthcheck.timer
journalctl -u panel-healthcheck.service -n 20 --no-pager
# 手动跑一次自检（不等 timer）
/var/lib/forkpanel/scripts/healthcheck.sh
```

> 脚本路径取自 `PathLayout::script_dir()`、端口取自 `Config`，均不硬编码。
> 该脚本的逻辑已真机四态验证（活着 / 挂一次 / 连续挂两次 / 恢复），
> 单测见 `bootstrap::tests::healthcheck_*`。

---

### 5.3 停机恢复面板库（runbook，已真机演练）

**适用范围**：`kind=panel` 的备份（面板自身数据库）。

**为什么必须停机**：面板库是面板**运行中**的库。在线覆盖会损坏 SQLite WAL——
写进去的那一刻旧的 WAL 帧还在，两边一对不上就是「库能打开但数据错乱」，
比打不开更难查。所以站点文件与数据库连接可以在 Web 里在线恢复（`kind=site` /
`kind=db` 有完整实现），而面板库只能停机换文件。这不是缺功能，是 SQLite 的硬约束。

> 恢复前先确认：**主密钥 `<data_dir>/master.key` 还在**。它不在备份里（那是它
> 该在的地方），但 SSL 私钥、数据库口令、远端凭据全都靠它解密——丢了它，备份
> 恢复回来也是一堆解不开的密文。

```bash
CFG=/etc/forkpanel/config.toml

# ① 停服务（systemd 环境下探活 timer 会连着报失败，属预期，恢复后自愈）
systemctl stop panel

# ② 一条命令完成：验产物 → 给当前库留快照 → 原子替换 → 清掉旧 WAL/SHM
panel --config "$CFG" restore-db /path/to/plan1-1234567890.db
#    ✅ 产物可恢复：… integrity_check=ok，含 users 表
#    当前库已留快照：/var/lib/forkpanel/backups/pre-restore-<ts>.db
#    ✅ 已恢复：/var/lib/forkpanel/panel.db

# ③ 起来，然后**验证数据真的回来了**——不只是 200
systemctl start panel
curl -fsS http://127.0.0.1:2083/api/v1/version
# 登录进面板，核对站点数 / 用户数 / 最近备份时间与备份时刻一致
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
| 端口占用 `Address already in use` | 有残留进程：`ss -ltnp \| grep <实际端口>` 后停用旧实例 |
| 远程打不开 | 先确认隧道已建立，且访问的是本机 `127.0.0.1:2083` |
| `check_data_dir` 失败 | 数据目录不存在，先建目录再 `serve` |
