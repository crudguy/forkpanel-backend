# ForkPanel 分发与安装

ForkPanel 以**单一静态二进制 + 一键安装器**的形式分发。用户无需安装 Rust 工具链或拿源码编译，一行命令即可装好。

## 安装（最新稳定版）

```bash
curl -fsSL https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh | sh
```

安装器会：检测架构（amd64/arm64）→ 从 GitHub Releases 下载对应 tarball → **用内嵌 ed25519 公钥验签** → 验过才解包 → 执行 `install.sh`（建目录、随机端口、systemd 单元、外部探活）。

> 需要 root（面板要管理系统服务/防火墙）。请 `sudo` 或 root 执行。

## 安装指定版本

```bash
PANEL_VERSION=0.1.0 curl -fsSL https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh | sh
```

## 仅下载验签、不安装（调试 / 审计）

```bash
curl -fsSL https://raw.githubusercontent.com/crudguy/forkpanel-backend/main/deploy/get-panel.sh | sh -s -- --no-install
```
产物留在临时目录（脚本会打印路径），不触动系统。

## 切换到自建 / 镜像源

默认源是 GitHub Releases。若想走自建源（如 `releases.forkpanel.dev`）或镜像：

```bash
PANEL_RELEASE_BASE=https://releases.forkpanel.dev curl -fsSL <get-panel.sh 入口> | sh
```

## 更新

重新跑一次安装器即可，会下载新版本、覆盖 `/usr/local/bin/panel`；**已有配置 `/etc/forkpanel/config.toml` 不会被覆盖**（端口等保留）。

## 卸载

```bash
/usr/local/bin/panel --config /etc/forkpanel/config.toml uninstall   # 或 ./deploy/uninstall.sh
```
卸载保留数据与配置；如需彻底清除 `/var/lib/forkpanel`、`/var/log/forkpanel`、`/etc/forkpanel` 请手动删除。

## 安全模型（务必读完）

- 每个 tarball 都用 **ed25519 私钥**签名（`.sig`），安装器**先验签后执行**，签名不过绝不会运行任何文件。
- **发布前必须替换正式密钥**：`get-panel.sh` 里现存的 `RELEASE_PUBKEY` 是**演示公钥**。正式发版前请：
  1. 本地生成密钥对：`openssl genpkey -algorithm ed25519 -out release.key`
  2. 提取公钥：`openssl pkey -in release.key -pubout`
  3. 把公钥替换进 `deploy/get-panel.sh` 的 `RELEASE_PUBKEY`
  4. 私钥 `release.key` 内容存为 GitHub repo secret **`PANEL_RELEASE_KEY`**（多行 PEM 原样粘贴，**绝不入库**）
- 任何人拿到演示私钥都能伪造签名——正式发版前不换密钥等于没有验签。

## 发布流程（维护者）

1. 本地提交、push `main`；确认 CI（门禁 + 测试）全绿。
2. 确保 `get-panel.sh` 已是正式公钥（见上）。
3. 打 tag 触发发版：`git tag v0.1.0 && git push origin v0.1.0`
4. GitHub Actions `Release` workflow 自动：构建（前端 + 后端 musl 静态）→ 签名 → 上传到 `v0.1.0` Release 资产。
5. 在 GitHub Releases 页面复核资产（`*.tar.gz` / `*.tar.gz.sig` / `SHA256SUMS`），必要时编辑发布说明。

### 需要的 Secrets

| Secret | 用途 |
|---|---|
| `FRONTEND_REPO_TOKEN` | 拉取私有前端仓 `crudguy/forkpanel-frontend`（已有，CI 同用） |
| `PANEL_RELEASE_KEY` | ed25519 签名私钥 PEM（发版签名用，**绝不入库**） |

## 资产命名约定

`build-static.sh` 产出固定名 `panel-linux-{amd64,arm64}.tar.gz(.sig)`，`get-panel.sh` 按此名下载——**两边必须保持一致**，改名需同步改两处。
