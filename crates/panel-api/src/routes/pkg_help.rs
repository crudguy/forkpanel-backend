//! 白名单软件包的**面向用户的说明**（用途 / 功能 / 场景 / 入口）。
//!
//! 为什么放在后端而不是前端常量表：
//! 包集合的单一事实源是 `services::ALLOWED_PACKAGES`，前端只消费 `/packages` 下发的
//! `catalog`（`labelMap` / `externalPkgs` 都这么来）。说明文字如果另在前端维护一份，
//! 就回到「同一条约束落在两条路径」的老问题——后端加包而前端没加说明、或前端说明
//! 与后端实际能力（比如某软件根本没有面板入口）对不上，两种漂移**都不会编译报错**，
//! 用户看到的是「点开是空的」或「说明里写有入口、界面里找不到」。
//!
//! 于是这里给 `PkgDef` 加四个 `&'static str` 字段，随 `catalog` 一起下发；前端软件卡片
//! 上的「说明」按钮直接渲染，不再硬编码任何一条。
//!
//! 文案口径（写在数据里，别只写在这里）：
//! - **用途**一句话说清"这东西是什么"，不堆术语。
//! - **功能**列用户真的会用的能力，不列实现细节。
//! - **场景**给"什么时候该装它"，帮用户做决策。
//! - **入口**必须诚实：面板里没有对应页面就写「面板无独立页面」并给出真实访问方式
//!   （端口 / 配置文件 / 「文件」或「终端」），绝不编一个不存在的入口——这是本项目
//!   「能力位不撒谎」在文案上的对应纪律。
//!
//! 端口均为各软件默认值，文案里显式说明"以你的配置为准"（见前端统一脚注）。

use super::services::PkgDef;

/// 供 `catalog` 下发的说明条目形状。
pub(super) struct PkgHelp {
    pub name: &'static str,
    pub label: &'static str,
    pub summary: &'static str,
    pub features: &'static str,
    pub scenes: &'static str,
    pub entry: &'static str,
}

/// 从白名单条目投影出说明（顺序与 `ALLOWED_PACKAGES` 一致，不另排序）。
pub(super) fn projection<'a>(
    defs: impl Iterator<Item = &'a PkgDef> + 'a,
) -> impl Iterator<Item = PkgHelp> + 'a {
    defs.map(|d| PkgHelp {
        name: d.name,
        label: d.label,
        summary: d.summary,
        features: d.features,
        scenes: d.scenes,
        entry: d.entry,
    })
}
