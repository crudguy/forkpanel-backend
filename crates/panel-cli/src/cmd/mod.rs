//! 子命令实现，按能力域分文件。
//!
//! 为什么这样分：`run()` 是一张 17 条子命令的分派表。arm 里直接写实现时，分派表
//! 被几百行启动/装配代码埋住——想知道"面板到底有哪几个命令"要翻过整段 serve 流程，
//! 想改 serve 要在一张 switch 里找边界。拆开后，`main.rs::run()` 只剩下
//! `Cmd::X => …` 一行一条，看分派关系不用跳转。
//!
//! 分文件的口径是**能力域**而非行数：同一域的命令共用同一套前置（读配置 → 建库 →
//! 建 layout），放在一起改一处就够。已迁：`serve`（187 行、独占一套启动装配）、
//! `db`（migrate/backup/vacuum/verify-backup/restore-db，五个都动同一份 panel.db）。
//! `system`（systemd-unit/healthcheck/capabilities/uninstall/upgrade，
//! 都改这台机器的面板安装）。后续 `security`
//! （passwd/expose）、`init`（init/doctor）按同样口径迁入。
//!
//! ⚠️ 迁移时有一条固定动作：`main.rs` 的 `wiring_guard_tests` 里有几条守卫靠
//! `include_str!` 扫被搬走的代码（"这条调用必须挂在 serve 启动链上"这类）。
//! 搬迁后必须把这些守卫的 `include_str!` 目标一并改到新文件——不能改成"全仓
//! grep 得到就算过"，那会把"恰好一次""在 fallback 之后"这类次序/唯一性判据
//! 退化成恒绿。详见各守卫自身的注释。

pub(crate) mod db;
pub(crate) mod serve;
pub(crate) mod system;
