# ForkPanel 后端门禁——一条命令跑完全部门禁。
#
# 背景：ci/ 下 6 个门禁脚本质量很高，但此前没有任何东西把它们与
# `cargo test --workspace` 串起来，全靠人记得逐个跑（审计 P1-3）。
# 本 Makefile 与 .github/workflows/ci.yml 共用同一份目标。
#
# 注意 ci/check-audit.sh 的纪律：找不到 cargo-audit **判失败**而非静默跳过
# （恒绿比没门禁更危险）。故 audit 单独成一个目标，CI 里单独一个 job——
# advisory-db 托管在 GitHub，网络抖动时不该连带拖红主门禁。

.PHONY: check guards audit test

# 主门禁：静态守卫 + 全量测试（离线可跑，确定性高）
check: guards test

# ci/ 下的静态门禁（layering / 契约 / 权限点 / 包白名单 / openapi 字节一致）
guards:
	bash ci/check-layering.sh
	bash ci/check-api-contract.sh
	bash ci/check-permissions.sh
	bash ci/check-pkg-whitelist.sh
	python3 ci/check_openapi.py

# 依赖安全审计（需 cargo-audit，且要联网拉 RustSec advisory-db）
audit:
	bash ci/check-audit.sh

test:
	cargo test --workspace
