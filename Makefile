# ForkPanel 后端门禁——一条命令跑完全部门禁。
#
# 背景：ci/ 下 6 个门禁脚本质量很高，但此前没有任何东西把它们与
# `cargo test --workspace` 串起来，全靠人记得逐个跑（审计 P1-3）。
# 本 Makefile 与 .github/workflows/ci.yml 共用同一份目标。
#
# 注意 ci/check-audit.sh 的纪律：找不到 cargo-audit **判失败**而非静默跳过
# （恒绿比没门禁更危险）。故 audit 单独成一个目标，CI 里单独一个 job——
# advisory-db 托管在 GitHub，网络抖动时不该连带拖红主门禁。

.PHONY: check guards audit test embed-fresh e2e-files e2e-backups e2e-containers e2e-cron

# 主门禁：静态守卫 + 全量测试（离线可跑，确定性高）
check: guards embed-fresh test

# ci/ 下的静态门禁（layering / 契约 / 权限点 / 包白名单 / openapi 字节一致）
guards:
	bash ci/check-layering.sh
	bash ci/check-api-contract.sh
	bash ci/check-permissions.sh
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

test:
	cargo test --workspace
