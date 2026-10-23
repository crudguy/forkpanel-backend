# 安装文件与目录说明（Install Footprint）

> 本文回答一个问题：**装 ForkPanel 会在我的机器上动哪些文件、哪些目录？**
> 以及它**是否像宝塔那样把所有东西塞进一个 `/www` 目录**。
>
> 结论先行：**不是**。`ForkPanel` 不采用宝塔式的 `/www` 集中式，而是遵循
> Linux 标准目录（FHS）分散布局——一个二进制 + 几个标准位置，且**不自带任何
> 服务端软件**（nginx / 数据库都是系统已有的，面板只写配置、不装软件）。
>
> 文中路径与 `deploy/install.sh`、`deploy/config.toml` 严格对应；凡带 `forkpanel`
> 后缀的是**安装脚本实际值**，带 `panel` 后缀的是**代码内默认值**（仅在你不带
> `--config` 手动跑 `panel` 时生效，不是真实安装路径）。

---

## 一、安装时创建的文件（运行 `deploy/install.sh`）

安装脚本需要 **root**（要装系统服务、写 `/usr`、`/etc`、`/var`）。它会创建：

| 路径 | 类型 | 权限 | 内容 |
|---|---|---|---|
| `/usr/local/bin/panel` | 文件 | 0755 | **单文件静态二进制**，前端产物已内嵌其中，无代码目录 |
| `/etc/forkpanel/` | 目录 | 0750 | 配置目录 |
| `/etc/forkpanel/config.toml` | 文件 | 0640 | 唯一配置文件（已存在则**保留**，升级不覆盖） |
| `/var/lib/forkpanel/` | 目录 | **0700** | 面板私有数据根（数据库 / 密钥 / 备份） |
| `/var/log/forkpanel/` | 目录 | 0750 | 日志目录 |
| `/var/www/` | 目录 | 0755 | 站点根目录（通常 nginx 已建，脚本确保存在） |
| `/etc/systemd/system/panel.service` | 文件 | — | 主服务单元（由 `panel systemd-unit --install` 生成） |
| `/etc/systemd/system/panel-healthcheck.service` | 文件 | — | 外部探活服务单元 |
| `/etc/systemd/system/panel-healthcheck.timer` | 文件 | — | 探活定时器（每分钟一次，连续两次失败才重启） |
| `/var/lib/forkpanel/scripts/healthcheck.sh` | 文件 | — | 探活脚本（写进数据目录内的受限脚本目录） |

> 安装完成后会执行 `systemctl daemon-reload && systemctl enable panel`
> 以及 `systemctl enable --now panel-healthcheck.timer`，把两个单元设为开机自启。

**`config.toml` 是唯一需要你关心的配置文件**，其 `[paths]` 节可覆盖上面 4 个根
（config / data / log / site_root），但业务代码禁止直接拼路径——一律走
`PathLayout`，CI 门禁会 grep `/etc`、`/var`、`/www` 字面量。

---

## 二、运行时生成的文件（面板启动后逐步产生）

### 2.1 面板私有数据 `/var/lib/forkpanel/`（0700）

```
panel.db            SQLite 主库（WAL 模式，伴生 panel.db-wal / panel.db-shm）
master.key          主密钥：加密 SSL 私钥 / 数据库口令 / 远端备份凭据。
                    刻意不进任何备份（丢了只能重新签发证书、重设凭据）。
ssl/
  ca/ca.crt  ca.key 本地根 CA（自签证书的信任根）
  <域名>.crt <域名>.key  站点证书（私钥落库前用 master.key 加密）
backups/            备份产物
conf-backups/       覆盖站点配置前的自动备份
htpasswd/           Basic Auth 口令文件
scripts/            计划任务脚本（受限目录，防任意命令注入）
uploads/            分片上传的临时块
tmp/  cache/  log/  临时 / 缓存 / 内部日志
```

### 2.2 站点内容与 Web 服务器（**不在面板自己的目录里**）

```
/var/www/<站点名>/                  站点文件（web 用户可读）
/etc/nginx/conf.d/panel-<slug>.conf  nginx drop-in 配置（不动系统主配置）
/var/log/forkpanel/web/<slug>.access.log 站点访问日志
```

> ⚠️ 注意两个位置：**站点文件不在 `/var/lib/forkpanel` 里**；**nginx 也不是面板装的**。
> 面板只往系统的 `nginx` 的 `conf.d` 里丢一个 drop-in 文件。所以装面板**之前**机器上
> 必须有可用的 nginx（由系统包管理器安装），否则 Web 管理能力不可用。

### 2.3 安装**不会**创建的东西

- **任何 Web 服务器**：不自带 nginx，接管系统已装的 nginx 写 drop-in
- **任何数据库服务**：用内嵌 SQLite，不装 MySQL/PostgreSQL
- **PHP / Redis / MySQL 等运行时**：那些由系统包管理器管；面板只"管理"已存在的

---

## 三、与宝塔（`/www` 集中式）对比

宝塔（Linux 版）的典型布局：

```
/www/server/panel/        面板自身：Python 代码 + 模板 + 数据
/www/server/nginx/        面板安装的 nginx
/www/server/mysql|php|redis/...   面板安装的各服务端软件
/www/wwwroot/<域名>/      所有网站文件
/www/backup/  /www/logs/  备份 / 日志
```

| 维度 | ForkPanel（FHS 分散式） | 宝塔（`/www` 集中式） |
|---|---|---|
| 面板自身 | **一个二进制，没有代码目录** | `/www/server/panel`，大量 Python 文件 + 模板 |
| Web 服务器 | 不自带，接管系统 nginx 写 drop-in | 自带 `/www/server/nginx` |
| 站点文件 | `/var/www/<站点>` | `/www/wwwroot/<域名>` |
| 数据 / 密钥 | `/var/lib/forkpanel`（**0700**） | `/www/server/panel/data` |
| 备份 / 日志 | `/var/lib/forkpanel/backups`、`/var/log/forkpanel` | `/www/backup`、`/www/logs` |
| 软件升级 | 换一个二进制即可 | 面板统一更新所有自带软件 |
| 与系统包管理器的关系 | 不冲突（nginx 归 apt） | 面板自带版本可能覆盖 apt 升级的 |

### 文件管理

- **宝塔**：一棵树看得见摸得着，`tar czf www.tgz /www` 一次全搬；但用户数据、
  面板自身、各种服务软件混居同树，备份难只挑站点不挑软件。
- **ForkPanel**：每类数据各在标准位置。`logrotate` 认 `/var/log`、备份工具认
  `/var/lib`、打成 deb 也顺理成章；代价是路径分散，新人需查本文。

### 安全性（差距最大的一项）

宝塔单根大树 + root 运行，历史上多起严重漏洞出在路径穿越 / 命令执行；站点文件与
面板数据同树，隔离只能靠目录权限。

ForkPanel 做了四层：

1. **systemd 层就锁死**：生成的单元带 `ProtectSystem=strict` +
   `ReadWritePaths=/var/lib/forkpanel /var/log/forkpanel /var/www /etc/forkpanel`——
   **进程想写这 4 个目录之外的任何位置，内核直接拒绝**（面板有漏洞也写不出去）。
   > ⚠️ 这个 `ReadWritePaths` 由 `config.toml` 的 `[paths]` 决定。历史上曾有个 bug：
   > 生成单元时用的是**代码默认路径**而非**配置实际路径**，一旦你覆盖 `[paths]`，
   > 单元会放行错误的目录，导致 `ProtectSystem=strict` 下面板写不进真实数据目录。
   > 已修复并加了回归测试（`read_write_paths_track_configured_layout`）。
2. **数据目录 0700**，主密钥单独存放且不进任何备份。
3. **敏感文件黑名单**（`panel-os::sensitive`）：账号库、sudo/PAM、`ld.so.preload`、
   cron、systemd 全部拒绝通过文件接口读写。
4. **路径不可硬编码**：业务层出现 `/etc`、`/var`、`/www` 字面量 CI 直接红。

### 可维护性

- **宝塔**统一更新体验好（一键升所有软件），但面板成巨大单点：任一环升级失败
  可能连带整棵树；且与发行版包管理器天然冲突。
- **ForkPanel**"能不装就不装"：升级 = 换一个文件；nginx/php/mysql 版本归系统包
  管理器。卸载脚本也只删单元和二进制，**刻意保留 `/var/lib/forkpanel`**
  （账号和数据不自动删，见下）。

---

## 四、卸载：保留数据

`deploy/uninstall.sh`（需 root）只做：

- `systemctl stop/disable panel`
- `rm -f /etc/systemd/system/panel.service`（及探活单元）
- `rm -f /usr/local/bin/panel`

**以下目录被保留**（含账号与数据，不自动删）：

```
/var/lib/forkpanel    数据库、主密钥、备份
/etc/forkpanel        配置
/var/log/forkpanel    日志
/var/www              站点根目录
```

确认不再需要后自行删除：

```bash
rm -rf /var/lib/forkpanel /etc/forkpanel /var/log/forkpanel
```

---

## 五、安装后如何自检

```bash
# 1) 二进制在位
ls -l /usr/local/bin/panel

# 2) 服务已起、开机自启
systemctl status panel --no-pager
systemctl is-enabled panel

# 3) 数据目录权限正确（应为 0700，属 root）
stat -c '%a %U %n' /var/lib/forkpanel

# 4) 单元 hardening 到位（ReadWritePaths 应与你 config.toml 的 [paths] 一致）
systemctl cat panel | grep -E 'ProtectSystem|ReadWritePaths'

# 5) 站点配置已落到系统 nginx（需先建站）
ls /etc/nginx/conf.d/panel-*.conf
```

> 若你改过 `config.toml` 的 `[paths]`，重跑一次
> `panel --config /etc/forkpanel/config.toml systemd-unit --install &&
>  systemctl daemon-reload` 让单元里的 `ReadWritePaths` 重新对齐。
