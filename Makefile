# ForkPanel 后端门禁——一条命令跑完全部门禁。
#
# 背景：ci/ 下 6 个门禁脚本质量很高，但此前没有任何东西把它们与
# `cargo test --workspace` 串起来，全靠人记得逐个跑（审计 P1-3）。
# 本 Makefile 与 .github/workflows/ci.yml 共用同一份目标。
#
# 注意 ci/check-audit.sh 的纪律：找不到 cargo-audit **判失败**而非静默跳过
# （恒绿比没门禁更危险）。故 audit 单独成一个目标，CI 里单独一个 job——
# advisory-db 托管在 GitHub，网络抖动时不该连带拖红主门禁。

.PHONY: check guards audit test embed-fresh e2e-files e2e-backups e2e-containers e2e-cron e2e-databases e2e-sites e2e-firewall e2e-rbac e2e-security e2e-all e2e-ui e2e-observe

# 主门禁：静态守卫 + 全量测试（离线可跑，确定性高）
check: guards lint embed-fresh test

# ci/ 下的静态门禁（layering / 契约 / 权限点 / 包白名单 / openapi 字节一致）
# 零 lint 门禁：clippy 同时覆盖 rustc 与 clippy 的全部 lint，用 -D warnings 让它们
# 直接失败。**必须用 clippy 而不是 `cargo build | grep warning`**：cargo 命中缓存后
# 就不再复现警告 ⇒ 缓存会让"有警告"悄悄变绿；clippy 每次都重新检查。
lint:
	cargo clippy --workspace --all-targets -- -D warnings

guards:
	bash ci/check-layering.sh
	bash ci/check-api-contract.sh
	bash ci/check-permissions.sh
	bash ci/check-docs-consistency.sh
	bash ci/check-pkg-whitelist.sh
	python3 ci/check_openapi.py
	# 锁中毒恢复：禁止生产代码裸 lock().unwrap()（见 ci/check_lock_unwrap.py）
	python3 ci/check_lock_unwrap.py

# 内嵌前端新鲜度：改完前端只 cargo build **不会**重新 embed，必须
# ① vite build → ② rm -rf web/dist/* → ③ cp -a → ④ touch embed.rs → ⑤ cargo build。
# 漏任一步都会发出旧前端，而编译/类型/测试全绿。放在 guards 之后、test 之前：
# 它是纯文件对账（秒级），失败时没必要再跑几分钟的测试。
embed-fresh:
	bash ci/check-embed-fresh.sh

# 依赖安全审计（需 cargo-audit，且要联网拉 RustSec advisory-db）
audit:
	bash ci/check-audit.sh

# 文件管理器 E2E：需要**运行中的 dev 后端**（默认 127.0.0.1:2083）。
#
# 刻意**不进 `check`**：CI 里没有服务，脚本只会走 [skip] 分支——那是恒绿，
# 比没有门禁更危险（会让人以为覆盖到了）。它要求人工在真机跑，输出 61 条断言。
#   make e2e-files
#   make e2e-files BASE=http://127.0.0.1:2084
e2e-files:
	bash ci/e2e-files.sh "$(BASE)"

# 备份 E2E：需要**运行中的 dev 后端**（默认 127.0.0.1:2083）。
#
# 与 e2e-files 同理**不进 `check`**：CI 里没有服务，脚本只会走 [skip] 分支——那是恒绿，
# 比没有门禁更危险。它要求人工在真机跑，输出 23 条断言，覆盖备份计划的
# 列举/创建/校验/执行/产物/下载/恢复闸门/清理 + 系统保留份数跨端点对账。
#   make e2e-backups
#   make e2e-backups BASE=http://127.0.0.1:2084
e2e-backups:
	bash ci/e2e-backups.sh "$(BASE)"

# 容器（Docker）E2E：需要**运行中的 dev 后端**（默认 127.0.0.1:2083）且宿主 Docker
# 守护进程可达（能力位 container.manage 按 daemon socket 可达性判定，由后端进程身份决定）。
#
# 与 e2e-files / e2e-backups 同理**不进 `check`**：CI 无 docker 守护进程时读端点会诚实 501，
# 脚本只验证能力位 reason 已下发而非假装通过。人工在真机跑，输出 15 条断言，覆盖容器读端点
# （列举/镜像/资源/网络/卷/Compose/Stack）+ 能力位下发 + 创建安全闸门（缺确认词 / 特权 /
# 敏感挂载 / 非法名 / 错确认词），全部卡在 docker 之前的 validate_create，零残留。
#   make e2e-containers
#   make e2e-containers BASE=http://127.0.0.1:2084
e2e-containers:
	bash ci/e2e-containers.sh "$(BASE)"

# 计划任务 E2E：对运行中的 dev 后端打真实请求，覆盖能力位下发 + 读端点（列表/预览/详情/
# 历史）+ 创建/改写的全套校验闸门（拒绝分支，零残留）+ 一次真实的「创建 → 改 → 执行 →
# 校验产物 → 删除」生命周期（实际写本机 root crontab，结尾回收，trap 兜底）。
# 与 e2e-* 同理**不进 `check`**：CI 无 crontab 二进制时读/写端点会诚实 501，脚本只验证
# 能力位 reason 已下发而非假装通过。人工在真机跑，输出 34 条断言。
#   make e2e-cron
#   make e2e-cron BASE=http://127.0.0.1:2084
e2e-cron:
	bash ci/e2e-cron.sh "$(BASE)"

# 数据库（db）E2E：对运行中的 dev 后端打真实请求，覆盖连接创建校验闸门 + SQLite
# 只读浏览全链路（连接→库→schema→表→行→导出）+ 只读 SQL 控制台闸门 + 连接生命周期。
# 只用 SQLite（内建只读 rusqlite，dev 零外部依赖可跑），不碰 mysql/pg。
# 与 e2e-* 同理**不进 `check`**：CI 无交互、连接与 .db 夹具属真机操作。人工在真机跑，
# 输出 42 条断言。
#   make e2e-databases
#   make e2e-databases BASE=http://127.0.0.1:2084
e2e-databases:
	bash ci/e2e-databases.sh "$(BASE)"

# 站点（sites）E2E：对运行中的 dev 后端打真实请求，覆盖能力位门禁 + 只读端点 +
# 创建校验闸门 + 一条纯 DB 生命周期 + SSL 诚实 501 闸门。
# ⚠ dev 主机 nginx 真实在场，故**绝不**调用 apply/reload/conf_put/停用（会 reload 真实
# nginx，破坏性），也不用 self-signed 签证书（会落盘）。只测拒绝分支 + 纯 DB CRUD。
# 与 e2e-* 同理**不进 `check`**。人工在真机跑，输出 36 条断言。
#   make e2e-sites
#   make e2e-sites BASE=http://127.0.0.1:2084
e2e-sites:
	bash ci/e2e-sites.sh "$(BASE)"

# 防火墙（firewall）E2E：最高风险模块，故纪律最硬——dev 防火墙后端真实在场
# （firewall.manage=True，iptables/nft 在 /usr/sbin），本脚本**绝不**提交合法规则 /
# 带 allow_lockout_risk 封端口 / 调 set_enabled/delete_rule（都会真的改防火墙）。
# 只测：能力位、只读端点、以及**全部在 snapshot() 之前返回**的拒绝分支（零残留），
# 每条钉死具体 code（不用 chk_ne，防 URL 写错命中 404 假绿）。不进 `check`。
#   make e2e-firewall
#   make e2e-firewall BASE=http://127.0.0.1:2084
e2e-firewall:
	bash ci/e2e-firewall.sh "$(BASE)"

# 权限与设置 E2E（用户 / 角色 / RBAC 防提权 / 设置 / 审计）——面板权限最高的一面。
# 造临时用户/角色并另开会话验证防提权，trap 兜底清理（先用户后角色）。不进 check。
#   make e2e-rbac
e2e-rbac:
	bash ci/e2e-rbac.sh "$(BASE)"

# WAF 与安全中心 E2E（模板/事件/告警 + 基线/在线会话）。⚠ 绝不用正确确认词调
# baseline/apply（会写回 sshd）；告警只原值回写；只吊销本次新建的会话。不进 check。
#   make e2e-security
e2e-security:
	bash ci/e2e-security.sh "$(BASE)"

# 九域 E2E 汇总：一次串行跑完并聚合（上线前的整机自检）。
# 只做编排与聚合，断言仍由各域脚本负责；后端不可达时明确 [skip] 不再继续，
# 某域退出码非 0 即判失败（退出码是权威信号）。
#   make e2e-all
#   make e2e-all BASE=http://127.0.0.1:2084
e2e-all:
	bash ci/e2e-all.sh "$(BASE)"

# 浏览器级 UI 渲染冒烟（**前端**真机验收）：用 agent-browser 驱动真实浏览器，
# 断言关键页面真的渲染出了内容（"忘 import 子组件 ⇒ 静默不渲染"这类坑只有浏览器能抓）。
# 刻意**不进 e2e-all**：它需要浏览器 + 前端 dev server，与后端 API 级 E2E 是不同层，
# 混在一起会让 API 门禁依赖浏览器环境。
#   make e2e-ui
e2e-ui:
	bash ci/e2e-ui.sh

# 可观测与轻管理面 E2E（系统概览 / 指标 / 日志 / 通知 / 便签 / 任务中心）。
# 只读为主：便签走完整生命周期（结尾删净）；通知 read-all 与任务 cancel **不碰**
# （前者改用户可见状态、后者会打断真实任务）。不进 check。
#   make e2e-observe
e2e-observe:
	bash ci/e2e-observe.sh

test:
	cargo test --workspace
