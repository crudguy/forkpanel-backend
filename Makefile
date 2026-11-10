# ForkPanel 后端门禁——一条命令跑完全部门禁。
#
# 背景：ci/ 下的门禁脚本质量很高，但此前没有任何东西把它们与
# `cargo test --workspace` 串起来，全靠人记得逐个跑（审计 P1-3）。
# 本 Makefile 与 .github/workflows/ci.yml 共用同一份目标。
#
# 注意 ci/check-audit.sh 的纪律：找不到 cargo-audit **判失败**而非静默跳过
# （恒绿比没门禁更危险）。故 audit 单独成一个目标，CI 里单独一个 job——
# advisory-db 托管在 GitHub，网络抖动时不该连带拖红主门禁。

.PHONY: check guards audit test embed-fresh e2e-files e2e-backups e2e-containers e2e-cron e2e-databases e2e-sites e2e-firewall e2e-rbac e2e-security e2e-all e2e-ui e2e-observe e2e-restore e2e-key-drill e2e-install e2e-upgrade e2e-expose e2e-get-panel e2e-mirror mirror-sync

# E2E 用的后端地址与二进制路径（可按需覆盖：make e2e-files BASE=http://127.0.0.1:2084）
BASE ?= http://127.0.0.1:2083
# e2e-restore 直接在进程内跑 CLI，不需要 HTTP，需要的是 panel 二进制。
# ⚠ 只用 debug 产物：`make check` 只编 test profile，**不更新** target/debug/panel，
#   故改了源码要先 `cargo build --bin panel`。
BIN ?= ./target/debug/panel
# e2e-install 装的是**生产形态**，必须用 release 产物（debug 的 rust-embed 运行期读磁盘，
# 装到别处会找不到前端；release 才是真内嵌）。
REL_BIN ?= ./target/release/panel

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
	# 前端调用方法与契约一致：`/files/write` 只注册 PUT，前端写 api.post ⇒ 浏览器 405、
	# 「在线编辑并保存」整版不可用。路径集合门禁（上面那条只比路径）与后端 e2e-files.sh
	# （用 `put` 直接打接口）都看不见「路径对、方法错」这一类，只能单独钉。
	python3 ci/check-api-method.py
	bash ci/check-permissions.sh
	bash ci/check-docs-consistency.sh
	bash ci/check-pkg-whitelist.sh
	python3 ci/check_openapi.py
	# 锁中毒恢复：禁止生产代码裸 lock().unwrap()（见 ci/check_lock_unwrap.py）
	python3 ci/check_lock_unwrap.py
	# 外部命令输出回显前必须过 panel_core::sanitize（nginx -t/certbot stderr
	# 原样回显会泄露校验临时目录与 ACME 账户信息；message 在构造侧已拼好，
	# API 边界再裁 detail 字段没用，只能钉构造点）
	python3 ci/check-error-sanitize.py
	# 审计 append-only：030 触发器 + prune 令牌 + doctor 留痕四环接线
	# （此前 append-only 只是注释自称，任何代码路径都能无痕删改）
	python3 ci/check_audit_append_only.py
	# Prometheus /metrics：条件注册（留白不占面）+ Bearer 鉴权先于采集
	# + scrape_token 消费链（防「config 有字段、serve 没人读」的假控制）
	python3 ci/check_prom_metrics.py
	# 前端单文件行数上限：挡住 .vue/.ts 无限膨胀（大视图的直接后果是"纯逻辑没法单测"）
	bash ci/check-frontend-loc.sh
	# 前端 UI 守卫（清单以 run-ui-guards.mjs 的 UI_GUARDS 为准，不在此写死数量）：
	# 此前只有前端仓 package.json 的 `check:ui` 手动入口，`make check` 从不执行
	# ⇒ 这批守卫「存在但不跑」。它们只依赖
	# node 内置模块，CI 自带 node 即可；前端仓未检出时**判红**（与 check-api-contract 同口径）。
	bash ci/check-ui-guards.sh
	# F-20：两个防火墙后端的 apply 必须只新增、不删（行为测试挡不住各写一份）
	python3 ci/check_firewall_append_only.py
	# F-02①：测试连接锁已保存 Endpoint、绝不携带已存密钥（行为测试挡不住把密钥读回来）
	python3 ci/check_llm_test_tightening.py
	# 阻塞子进程调用出口唯一性：run_sync 是同步的，裸调会钉住 tokio worker（Q-01）
	bash ci/check-blocking-calls.sh
	# 无终端初始化的引导令牌：仅 localhost 可取 + bootstrap 后即删 + 文件 0600。
	# ⚠ 此前它是**孤儿守卫**：脚本写好却没人调用，且 [3] 的判据在 Q-07 搬迁后
	#   一直指向已搬空的文件（恒红）⇒ 「守卫存在」不等于「守卫在跑」。
	bash ci/check-bootstrap-token.sh
	# release panic 策略必须与 CatchPanicLayer 兼容：panic="abort" 下兜底层整体失效，
	# 而 panic_guard 的单测跑在 dev(unwind) 下恒绿 ⇒ 只能源码级守卫钉住（本轮 P0）。
	bash ci/check-release-panic.sh
	# 首启引导窗口：expose 脚本必须先确认 needs_bootstrap=false，且生成的 nginx
	# 配置对 /api/v1/auth/bootstrap* 加 deny（同机反代会让端点误判为 loopback）。
	python3 ci/check_expose_bootstrap.py
	# 零 root E2E 必须真的接进 CI：此前 18 个 e2e-*.sh + run-e2e-ci.sh 全在门禁外，
	# 「脚本已为 CI 准备好」和「CI 会跑」是两回事；顺带钉住 [skip] 不得冒充通过。
	python3 ci/check_e2e_wired.py
	# 发版签名回验必须真的接在 release.yml 且排在上传 Release 之前：
	# 密钥错配 / 篡改 / 资产缺失要当场判红，不能等用户侧验签失败才发现（B3）。
	python3 ci/check_release_verify_wired.py
	# 安全响应头必须挂在 serve 链的 .fallback() 之后（build_router 内挂了 SPA/静态/
	# healthz/404 会整条绕过），且全链唯一。判据剔注释，防说明文字冒充挂点。
	python3 ci/check_security_headers.py
	# SIGTERM 优雅关闭（含调度器 drain）与 run_sync 超时必须真的接线：
	# 前者曾让 sched.shutdown() 永远执行不到，后者会永久钉住 spawn_blocking 线程。
	python3 ci/check_graceful_shutdown.py
	# /healthz 必须是依赖型就绪探针（DB 可读 / 磁盘余量），且 systemd 探活
	# 仍打 /api/v1/version（盘满重启无用，改用就绪探针会造成重启循环）。
	python3 ci/check_healthz.py
	# 日志真实去向（journald + 保留上限）、崩溃告警 OnFailure 与不实注释修正
	# 必须一起接线：只改注释不改安装器 = 又一轮「文档承诺但代码没有」。
	python3 ci/check_logging.py
	# 站点下发 deploy→reload→落库 任一失败都要回滚磁盘（apply 两条路径 / conf_put 一条），
	# 少一条就是「配置已写但库还是旧值」，下次 nginx 重启才爆。
	python3 ci/check_site_rollback.py
	# 单实例锁（flock）+ 升级前一致快照必须三条入口都接线：漏一路就是
	# 并发 DDL 或「升级后没有回退锚点」（025/029 是破坏性变更）。
	python3 ci/check_migrate_safety.py
	# G10：3 个「守卫存在但不在跑」的洞必须钉住接线——embed-fresh 在 CI 里
	# 必然 [skip]（ci.yml 不构建前端）、check-frontend-loc 两处 CI 分支 exit 0、
	# 前端 check:contract 是孤儿。判据一律剔注释（注释里就写着 exit 0 / [skip]）。
	python3 ci/check_gate_holes.py
	# G11：发布流水线必须是「draft 上传 → 发布后冒烟 → 转正 → 失败回滚」，
	# 且冒烟验的是**下载回来的资产**（拿本地 dist 自验等于没验发布结果）。
	python3 ci/check_release_pipeline.py
	# 发布产物完整性：dist/ 里一出现 panel-linux-*.tar.gz 就必须双架构 + .sig +
	# SHA256SUMS 逐行可验（一个都没有＝未构建，跳过；做了一半＝判红）。
	bash ci/check_release_artifacts.sh
	# G12：密钥与备份的接线——encrypt 默认开启且后端/openapi×2/前端四处一致、
	# 产物一律 0600、rekey 覆盖面与 schema 的 *_enc 列集合相等、恢复路径不得
	# 自动生成主密钥（否则「丢密钥」被伪装成「产物损坏」）。
	python3 ci/check_key_hygiene.py
	# G8：外部告警接线——serve 必须读 alert-webhook 并给任务/调度器两条主干接钩子、
	# 事件按 kind 分类、钩子必须真被调用（不是只存着）、backup.sweep 不得吞 Err、
	# shell 与 Rust 指向同一个文件名（改名只改一处＝崩溃告警静默失效）。
	python3 ci/check_alert_wiring.py

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

# 全部 E2E 域汇总：一次串行跑完并聚合（上线前的整机自检）。
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

# 备份恢复链路 E2E（`panel verify-backup` + `panel restore-db`，CLI 级、离线）。
# 与上面所有 e2e-* 都不同：它们打 HTTP，本脚本**自己在隔离目录造实例**
# （init → backup → 恢复），不依赖运行中的后端、不需要 BASE，也不碰真实库。
# 覆盖四道闸门：好产物通过 / 坏产物被拒 / 服务在线被拒 / 非面板库产物被拒；
# 以及恢复的四条命门：留 pre-restore 快照 / 无 .restore-tmp 残留 / 清旧 -wal、-shm /
# 恢复后库真能用（起服务 + owner 登录 + 会话）。
# ⚠ 端口被占时脚本 [skip] 退出 2（不冒充通过）；需要 root 或 sudo（服务绑定端口）。
#   make e2e-restore
e2e-restore:
	bash ci/e2e-restore.sh "$(BIN)"

# 主密钥三方恢复演练（G12）：`panel.db` + `master.key` + 备份同时删掉再拉回来。
# 与 e2e-restore 一样要自建实例 + 停服，故不进 `make check`（CI 的 E2E job 跑它）。
e2e-key-drill:
	bash ci/e2e-key-drill.sh "$(BIN)"

# 安装脚本 E2E（deploy/install.sh + uninstall.sh，**在 user namespace 里真跑**）。
# 又一次不同于前面所有 e2e-*：它不碰 HTTP、不碰运行中的后端，而是在 `unshare -rmn`
# 里把 /usr/local、/etc、/var/lib、/var/log、/var/www 用 tmpfs 盖住后真装一遍，
# 逐条核对 docs/install-footprint.md 的声明（权限 0700/0750、ProtectSystem=strict、
# ReadWritePaths 跟随 [paths]、升级不覆盖配置、卸载删程序留数据），最后真起进程
# 初始化并登录，证明"装出来的二进制能用"。
# ⚠ 需要 unshare + user namespace；不具备时 [skip] 退出 2。吃 release 二进制。
#   make e2e-install
e2e-install:
	bash ci/e2e-install.sh "$(REL_BIN)"

# 升级链路 E2E（离线；user namespace 内真跑）：本地 http 源 + 测试密钥签名，
# 覆盖 下载/验签/解包 → 篡改必须拒绝 → 正常安装 → install.sh 失败必须回滚。
#   make e2e-upgrade
e2e-upgrade:
	bash ci/e2e-upgrade.sh "$(REL_BIN)"

# 公网暴露脚本 E2E（deploy/expose-public.sh，在 user namespace 里真跑）。
# 和 e2e-install 同一路数：不碰 HTTP、不需要运行中的后端，用 tmpfs + systemctl /
# nginx / ss / ufw / curl 的 shim 在隔离环境里把脚本真跑一遍，逐条核对四条 fail-closed
# （不给 allow 就拒 / 面板已裸奔就拒 / 端口探测不可信就拒）、生成的 nginx 配置、
# 坏配置必须回滚上一份、以及卸载必须撤干净。
# 这是"把 root 面板放到公网边缘"的脚本，守卫必须能自证有效：改动脚本 / 断言后，
# 请把对应的那一条行为**改坏**再跑本目标，确认它真的变红，并还原后再确认转绿。
# ⚠ 需要 unshare + user namespace；不具备时 [skip] 退出 2。
#   make e2e-expose
e2e-expose:
	bash ci/e2e-expose-public.sh

# 分发脚本 E2E（deploy/get-panel.sh，离线）：用本地 http 源模拟"死源→好源回退"、
# 镜像源坏签名/篡改被验签拒绝（防投毒）、PANEL_RELEASE_BASE 钉死单源、内嵌公钥与测试
# 公钥互不通用。全程不碰真实 GitHub，跑完输出 7 条断言。
# 守卫自证：把 get-panel.sh 的 `openssl dgst -verify` 判否分支改坏（去掉 exit 1）再跑，
# 场景 3/4/7 必须变红；还原后转绿。
#   make e2e-get-panel
e2e-get-panel:
	bash ci/e2e-get-panel.sh

# 镜像同步 E2E（deploy/mirror-sync.sh，离线）：用本地 http 源冒充官方 Release，验证
# 好源两架构落盘 + 坏源（攻击者签名）被拒绝且零落盘。输出 6 条断言。
# 守卫自证：把 mirror-sync.sh 的验签 `exit 1` 去掉再跑，场景 B 必须变红；还原后转绿。
#   make e2e-mirror
e2e-mirror:
	bash ci/e2e-mirror.sh

# 镜像同步工具：从官方 Release 拉取签名 tarball → 先验签 → 落本地 / 推 rclone。
# 只镜像验签通过的真货，坏货绝不写入。详见 deploy/mirror-sync.sh 头部用法。
#   make mirror-sync                       # 同步 latest 到 ./mirror
#   make mirror-sync VERSION=v0.1.0 DEST=/srv/mirror
#   make mirror-sync RCLONE=myremote:/forkpanel PUBLIC_BASE=https://mirror.example.com/forkpanel
mirror-sync:
	bash deploy/mirror-sync.sh $(if $(VERSION),--version $(VERSION),) $(if $(DEST),--dest $(DEST),) $(if $(RCLONE),--rclone $(RCLONE),) $(if $(PUBLIC_BASE),--public-base $(PUBLIC_BASE),)

test:
	cargo test --workspace
