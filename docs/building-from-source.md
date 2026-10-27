# 从源码构建与分发（开发者路径）

> 本文面向**想要自己编译、二次开发或搭建私有分发**的人。
> 只想安装使用面板的人请看 [distribution.md](./distribution.md)，**不需要**看本文——直接一行命令安装即可。

## 你不需要照搬维护者的机器布局

维护者本机把后端仓与前端仓**并列**放在同一父目录：

```
forkpanel/
├── forkpanel-backend/     # Rust 后端（本仓库）
└── forkpanel-frontend/    # Vue 前端（独立仓库）
```

但这不是硬性要求。所有跨仓引用都有覆盖入口，你可以放在任意位置。

## 硬约束只有一条：`web/dist` 必须在后端仓内的固定相对位置

`crates/panel-cli/src/embed.rs` 里写的是：

```rust
#[folder = "../../web/dist"]
```

该路径相对 `crates/panel-cli/src/` 解析，落到 **`<后端仓>/web/dist`**。这是 `rust-embed`
编译期宏，**必须在本后端仓的 `web/dist/` 存在真实产物**，编译器才能把前端嵌进二进制。
（`web/dist/` 被 `.gitignore` 忽略，不入库。）

所以无论前端仓放在哪，最终都要把前端构建产物同步到 `<后端仓>/web/dist/`。

## 完整构建步骤

```bash
# 1. 取代码（两个仓均已公开，可直接 clone）
git clone https://github.com/crudguy/forkpanel-backend.git
git clone https://github.com/crudguy/forkpanel-frontend.git forkpanel-frontend   # 位置随意

# 2. 构建前端
cd forkpanel-frontend
corepack enable && corepack pnpm@9 install --frozen-lockfile
corepack pnpm@9 build                          # 产出 forkpanel-frontend/dist/

# 3. 同步进后端（这一步不可省，且必须先清空再拷）
cd ../forkpanel-backend
rm -rf web/dist/* && cp -a ../forkpanel-frontend/dist/. web/dist/
touch crates/panel-cli/src/embed.rs            # 强制重新嵌入（防增量编译用旧产物）

# 4. 编译后端
cargo build --release                          # 动态链接版，本机跑
# 或静态分发版（见下）
```

## 门禁（可选但强烈建议）

`make check` 会跑门禁 + 全量测试。它默认去 `../forkpanel-frontend` 找前端，位置不同时用
环境变量覆盖：

```bash
PANEL_FRONTEND_ROOT=/path/to/forkpanel-frontend \
PANEL_FRONTEND_OPENAPI=/path/to/forkpanel-frontend/src/api/openapi.yaml \
FE_DIST=/path/to/forkpanel-frontend/dist \
make check
```

不设也不会崩：门禁脚本会显式 `[skip]`（注明"非通过"），但契约/权限点等跨仓检查会跳过。

## 做静态分发（musl + 签名）

```bash
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# 签名私钥（自己生成；想用本地联调的演示密钥也行，但对外分发必须换成自己的）
openssl genpkey -algorithm ed25519 -out release.key && chmod 600 release.key

./deploy/build-static.sh 1.0.0 ./release.key   # 产出 dist/panel-linux-{amd64,arm64}.tar.gz(.sig)
```

## 搭建自己的分发（fork 场景必读）

如果你 fork 了本项目并向自己的用户分发：

1. **换公钥**：`deploy/get-panel.sh` 里的 `RELEASE_PUBKEY` 必须换成**你自己**私钥对应的公钥
   （`openssl pkey -in release.key -pubout`）。用维护者公钥 + 自己私钥 = 签名根本验不过。
2. **换下载源**：`get-panel.sh` 里 `PANEL_RELEASE_BASE` 默认指向维护者的 GitHub 仓库，
   改成你自己的仓库地址（或设环境变量覆盖）。
3. **换 GitHub 变量**：`.github/workflows/release.yml` 里 `repository: crudguy/forkpanel-frontend`
   改成你的前端仓；`PANEL_RELEASE_KEY` secret 存你自己的私钥。
4. **换 import 路径**（仅 Rust 侧改名时）：若改了 crate 名，需同步全部 `use panel_*::`。

## 常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| 编译报 `web/dist` 不存在 / 嵌入的是旧页面 | 漏了第 3 步同步，或只 `cp -a` 未先 `rm -rf` | 清空后重拷 + `touch embed.rs` |
| 前端改了但发出去还是旧 UI | 未重新编译后端（嵌入发生在编译期） | 必须重新 `cargo build` |
| 门禁输出 `[skip]` 却显示"通过" | 前端路径没找到，跨仓检查被跳过 | 设 `PANEL_FRONTEND_ROOT` 后重跑 |
| `get-panel.sh` 验签失败 | 公钥与签名私钥不匹配（用了别人公钥） | 换成自己私钥对应的公钥 |
| 拉前端仓 403 | 仓为私有或 token 无权限 | 两仓现均公开；私有镜像场景用有权限的 token |
