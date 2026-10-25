#![cfg(test)]
//! 校验规则判据的**唯一事实源**：`tests-fixtures/validation_cases.json`。
//!
//! 为什么判据不放进测试代码里：
//! 这些样本（尤其是 invalid 那一组）是"哪些输入必须被拒"的规格，将来脚本、
//! 契约测试、其他语言的消费者都要按同一份清单验证。此前它被手抄进
//! `lib.rs` 的测试数组里，而 JSON 那份**零引用**——两份已经漂移：JSON 的
//! `domain.valid` 缺 `host.lan`/`app.local` 等私有后缀例外，invalid 只有
//! Rust 侧的一半。手抄的必然结局就是这样：改一处、漏一处，且无人察觉。
//!
//! 现在测试只读取这份 JSON，改判据只改 JSON 一处；`lib.rs` 的
//! `validation_cases_fixture_has_a_consumer` 守卫反过来钉住"这份文件真被读了"。
//!
//! ⚠ 全文件 `#![cfg(test)]`：仅测试期编译，不进生产构建。

use std::collections::BTreeMap;

/// 判据文件路径（相对本文件：`crates/panel-core/src/` → 仓库根）
pub const CASES_JSON: &str = include_str!("../../../tests-fixtures/validation_cases.json");

#[derive(serde::Deserialize, Clone)]
pub struct Cases {
    pub valid: Vec<String>,
    pub invalid: Vec<String>,
}

/// 取某个规则分组的判据。**分组缺失/结构不对直接 panic**——判据为空时测试会
/// 遍历空数组而"通过"，那是最危险的假绿（等价于把判据删了）。
pub fn cases(group: &str) -> Cases {
    let all: BTreeMap<String, Cases> = serde_json::from_str(CASES_JSON)
        .expect("tests-fixtures/validation_cases.json 必须是 {group:{valid,invalid}} 结构");
    all.get(group)
        .unwrap_or_else(|| panic!("判据文件缺少分组 `{group}`：删分组 = 该规则从此零覆盖"))
        .clone()
}
