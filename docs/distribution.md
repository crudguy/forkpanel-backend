# ForkPanel 分发与安装

ForkPanel 以**单一静态二进制 + 一键安装器**的形式分发。用户无需安装 Rust 工具链或拿源码编译，一行命令即可装好。

## 安装（最新稳定版）

```bash
# 两步法（推荐）：先把脚本下载到本地，确认完整再执行，避免管道中途断流半执行
wget -O get-panel.sh https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh
# curl 备选：curl -fSL --retry 5 --retry-delay 2 -o get-panel.sh <同一 URL>
sudo sh get-panel.sh
```

> 若 `raw.githubusercontent.com` 持续掉线（中国大陆常见）：可用代理 `https_proxy=http://<代理>:port wget -O get-panel.sh <同 URL>` 下载，
> 或把仓库导入 Gitee 等国内镜像后从镜像拉脚本。脚本到手后，其内部二进制下载已支持 `PANEL_MIRRORS` / 代理（见下文"切换到自建 / 镜像源"），全链路即稳。

安装器会：检测架构（amd64/arm64）→ 从 GitHub Releases 下载对应 tarball → **用内嵌 ed25519 公钥验签** → 验过才解包 → 执行 `install.sh`（建目录、随机端口、systemd 单元、外部探活）。

> 需要 root（面板要管理系统服务/防火墙）。请 `sudo` 或 root 执行。

## 安装指定版本

```bash
# 两步法：先下载（版本变量只影响执行，不影响下载），再执行时指定版本
wget -O get-panel.sh https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh
PANEL_VERSION=0.1.0 sudo -E sh get-panel.sh
```

## 仅下载验签、不安装（调试 / 审计）

```bash
# 两步法：先下载，再传 --no-install 仅验签不安装
wget -O get-panel.sh https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh
sudo sh get-panel.sh --no-install
```
产物留在临时目录（脚本会打印路径），不触动系统。

## 切换到自建 / 镜像源

默认源是 GitHub Releases。若想走自建源（如 `releases.forkpanel.dev`）或镜像：

```bash
# 两步法：先下载脚本（入口用 main 分支源码版或 releases 版均可），执行时切到自建/镜像源
wget -O get-panel.sh https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh
PANEL_RELEASE_BASE=https://releases.forkpanel.dev sudo -E sh get-panel.sh
```

## 更新

重新跑一次安装器即可，会下载新版本、覆盖 `/usr/local/bin/panel`；**已有配置 `/etc/forkpanel/config.toml` 不会被覆盖**（端口等保留）。

## 卸载

```bash
sudo panel uninstall        # 等价于 /usr/local/bin/panel --config /etc/forkpanel/config.toml uninstall
# 源码树里另有 deploy/uninstall.sh：有二进制时直接 exec 上面的命令，不是第二套实现
```
卸载保留数据与配置；如需彻底清除 `/var/lib/forkpanel`、`/var/log/forkpanel`、`/etc/forkpanel` 请手动删除。

## 安全模型（务必读完）

- 每个 tarball 都用 **ed25519 私钥**签名（`.sig`），安装器**先验签后执行**，签名不过绝不会运行任何文件。

### 密钥策略：固定一对，长期复用，**不是**每次发版都换

- **生成一次，长期用**。私钥保密、公钥嵌进 `get-panel.sh` 随安装器分发到用户机器。
  如果每次发版都换密钥，用户机器上的安装器还是旧公钥，新签的包就验不过——所以密钥必须稳定。
- **只有两种情况才需要换（密钥轮转）**：
  1. **私钥泄露**（最严重）：必须立即换，并通知用户「旧公钥作废、请重新拉取安装器」；
  2. **主动定期轮转**（安全好习惯，如每年一次）。
- 正常发版**不要**换密钥，沿用同一对即可。

### 首次发布前：生成并配置正式密钥（一次性）

> ⚠ **私钥必须由维护者本地生成并自行保管，绝不能经 AI / 脚本 / 仓库传输或落盘到非私密处。**
> 下面是维护者本机执行的命令（AI 不代生成）：

1. 生成密钥对（私钥权限锁 600，绝不入库）：
   `openssl genpkey -algorithm ed25519 -out release.key && chmod 600 release.key`
2. 提取公钥：`openssl pkey -in release.key -pubout`
3. 把公钥（上一步输出）替换进 `deploy/get-panel.sh` 的 `RELEASE_PUBKEY`（那段 PEM 块）。
   公钥是公开的，可交给协助者代替换，不含秘密。
4. 私钥 `release.key` 的**全部内容**（含 `-----BEGIN/END-----` 与换行）原样粘贴为
   GitHub repo secret **`PANEL_RELEASE_KEY`**（GitHub secret 支持多行；release.yml 会还原成文件）。

### 演示密钥的用途

- 仓库里现存的 `RELEASE_PUBKEY` + `build-static.sh` 默认读的 `$HOME/.forkpanel-release.key`
  是**一对演示密钥**，专供你**本地联调**整条「签名→下载→验签→安装」链路
  （用演示私钥签的包，演示公钥能验过）。**正式发版前必须换成你自己的正式密钥对**，
  否则任何人拿演示私钥都能伪造签名。

### 密钥分配模型（用户视角）：用户不需要、也不应该生成任何密钥

- **私钥只在你（发布者）手里**：存于 GitHub secret `PANEL_RELEASE_KEY`，仅用于给每次
  发布的 tarball 签名。**用户永远拿不到、也不需要这个私钥**。
- **公钥对所有用户公开且共享**：已内嵌进 `get-panel.sh`，随安装器分发给每一个下载者。
  用户机器跑 `curl | sh` 时，脚本自动用内嵌公钥验证下载的 tarball 是否由你的私钥签出。
- **用户不生成任何密钥**：安装全程只是 `curl | sh`，验签对用户透明、无需任何操作。
- ⚠ 这与「用户登录面板的账号」是两回事：
  - ed25519 密钥 = **发布者签名 / 用户验源**，解决「软件是不是你发的、有没有被改」；
  - 面板 owner/admin 账号 = **用户身份认证**，是面板启动后由首启向导/引导令牌创建的，
    属于运行期，与分发密钥无关。
- 类比：如同软件作者的代码签名证书——作者持私钥签软件，用户用公开公钥/证书验证，
  **用户不需要自己的证书**。这里是「一方签名、多方验证」的发布模型，不是「每用户一对」模型。

## 发布流程（维护者）

1. 本地提交、push `main`；确认 CI（门禁 + 测试）全绿。
2. 确保 `get-panel.sh` 已是正式公钥（见上）。
3. 打 tag 触发发版：`git tag v0.1.0 && git push origin v0.1.0`
   ⚠ 打 tag 的 push **不会**触发 `ci.yml`（`ci.yml` 只绑 `main` 分支）。所以发版前的质量兜底完全由 `release.yml` 内置的 `make check` 承担——它必须留在发布链最前面，不能省。
4. GitHub Actions `Release` workflow 自动：先跑 **`make check`（门禁 + 全量测试）作为发布门槛** → 构建（前端 + 后端 musl 静态）→ 签名 → 上传到 `v0.1.0` Release 资产。门禁不过则中止，不会把坏代码签名发出去。
5. 在 GitHub Releases 页面复核资产（`*.tar.gz` / `*.tar.gz.sig` / `SHA256SUMS`），必要时编辑发布说明。

### 需要的 Secrets

| Secret | 用途 |
|---|---|
| `FRONTEND_REPO_TOKEN` | 拉取前端仓 `crudguy/forkpanel-frontend`（**已公开，可不配**；若改回私有则必须配 PAT） |
| `PANEL_RELEASE_KEY` | ed25519 签名私钥 PEM（发版签名用，**绝不入库**） |

**配置入口（图形界面）**：仓库页面 → `Settings`（注意是**仓库**的 Settings，不是你 GitHub 个人账户设置）→ 左侧 `Secrets and variables` → `Actions` → `New repository secret`。`FRONTEND_REPO_TOKEN` 也已在同一页面。

**配置内容注意**：`PANEL_RELEASE_KEY` 的值是私钥文件 `release.key` 的**全部内容**（含 `-----BEGIN/END PRIVATE KEY-----` 与中间 base64 行及换行），必须原样、多行粘贴。保存后 GitHub 不再显示明文，粘贴务必准确。

**更快的方式（避免多行私钥复制出错）**：本机装了 GitHub CLI 且已 `gh auth login` 后，直接在仓库目录或显式 `--repo` 执行：
```bash
gh secret set PANEL_RELEASE_KEY < release.key
```

> ⚠ 私钥由维护者本地生成并自行保管（见上文安全模型），**不要**把私钥内容贴给 AI 或他人代配；上面的 `gh` 命令是你本机对自己仓库执行。

## 资产命名约定

`build-static.sh` 产出固定名 `panel-linux-{amd64,arm64}.tar.gz(.sig)`，`get-panel.sh` 按此名下载——**两边必须保持一致**，改名需同步改两处。

## 前端如何分发：编进后端二进制，**不分开发布**

- 分发的只有**后端**产物（`panel-linux-*.tar.gz`）。**前端不单独分发**、也没有独立 release。
- 原因：前端构建产物 `web/dist/` 被 `rust-embed`（`crates/panel-cli/src/embed.rs` 的
  `#[folder = "../../web/dist"]`）**编译期内嵌**进 `panel` 二进制，`web/dist/` 本身被
  `.gitignore` 忽略、不入库。用户装一个二进制即可得到完整 UI，无需额外下载前端。
- 发版时 `release.yml` 自动完成：`检出前端仓 → pnpm build → rm -rf web/dist/* &&
  cp -a 前端dist/. → touch embed.rs → cargo 静态编译`，所以**前后端版本天然绑定**，
  打一个 tag 同时冻结两端。
- 推论：只给后端打 tag 就够；但前端仓必须先有对应提交（`release.yml` 拉的是其默认分支
  最新代码）。想发「前端某特定提交」的版本，需先把该提交合入前端默认分支。
