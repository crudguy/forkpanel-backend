//! 测试期共享工具：**源码守卫的「生产段」提取器**。
//!
//! 为什么单独立一个 crate：`panel-cli` 的接线守卫写在 `src/main.rs` 的
//! `#[cfg(test)]` 模块里，而 `panel-api` 的同款守卫写在 `crates/panel-api`
//! 里——前者是 binary crate，够不到后者的 `pub(crate) mod test_support`。
//! 两边各留一份「剔注释 + 剥 cfg(test)」的解析器，必然漂移成两份语义不同的
//! 判据（一份挡得住、一份挡不住），那比只留一份还糟。故提为共享实现。
//!
//! ⚠ 只允许作为 `[dev-dependencies]` 引用，且本 crate 不得引入第三方依赖。

/// 源码守卫取「**生产段**」：剔注释行 + 剔 `#[cfg(test)]` 包裹的块。
///
/// 为什么不能只 `split("#[cfg(test)]").next()`：
/// `routes/backups.rs` 的**第一个测试模块之后仍有生产函数**（`prune_daily_db`
/// 等，:2508 起）——一刀切会把生产代码一起切掉 ⇒ 守卫恒红（项目已踩过一次）。
/// 这里按**花括号配对精确剥离测试块**，只丢块本身。
///
/// 为什么必须同时剔注释行：实现被整块注释掉、而 needle 留在注释里时，只看
/// 生产段的守卫照样绿——「判据指向错」那类恒绿守卫。实测过这个骗法：把
/// `sched.register("backup.sweep", …)` 整块注释掉并在注释里留同名 needle，
/// 只 split 不剔注释的守卫**依然全绿**（定时备份静默不跑，门禁一声不吭）。
///
/// ⚠ 活性自检：产出为空说明剥离/过滤写坏了，直接 panic 说明原因，
/// 而不是让所有守卫以「没找到 needle」的模糊形态红。
pub fn production_source(src: &str) -> String {
    let lines: Vec<&str> = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with('*')
        })
        .collect();
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]") {
            i += 1;
            // 跳过紧随其后的其它属性行（`#[cfg(test)]` 与 `#[allow(...)]` 同注一个项）
            while i < lines.len() && lines[i].trim_start().starts_with("#[") {
                i += 1;
            }
            let is_block = i < lines.len() && {
                let t = lines[i].trim_start();
                t.starts_with("mod ") || t.starts_with("fn ") || t.contains('{')
            };
            if !is_block {
                // 无块形态（`#[cfg(test)]` + `use foo;`）：必须**连被注解的那一行
                // 一起丢**——只丢属性行的话，`use super::*;` 这类测试专属 import
                // 会被当成生产代码留下（本 crate 自测抓到的真 bug，见下方用例）。
                i += 1;
                continue;
            }
            if !lines[i].contains('{') {
                // `mod x` 与 `{` 分行写的极端写法：别静默漏掉整个块
                i += 1;
                if i >= lines.len() || !lines[i].trim_start().starts_with('{') {
                    continue;
                }
            }
            let mut depth = 0usize;
            while i < lines.len() {
                depth += lines[i].chars().filter(|c| *c == '{').count();
                depth = depth.saturating_sub(lines[i].chars().filter(|c| *c == '}').count());
                i += 1;
                if depth == 0 {
                    break;
                }
            }
            continue;
        }
        out.push(lines[i]);
        i += 1;
    }
    if out.is_empty() && !src.is_empty() {
        panic!("production_source 产出为空——测试块剥离或注释过滤写坏了（守卫判据整体失效）");
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::production_source;

    /// 骗法一：实现被整块注释掉，needle 只留在注释里。
    /// 不剔注释的守卫会拿注释当实现 ⇒ 恒绿。
    #[test]
    fn comment_only_needle_is_not_production() {
        let src = "\
fn serve() {
    // sched.register(\"backup.sweep\", move || {});
    run();
}";
        let prod = production_source(src);
        assert!(
            !prod.contains("sched.register"),
            "注释里的 needle 绝不能被当成生产实现（注释掉注册后守卫必须转红）"
        );
        assert!(prod.contains("run();"), "真正的生产代码不能被误剔");
    }

    /// 骗法二：needle 只出现在测试模块里（守卫自引用的那一类）。
    #[test]
    fn test_module_needle_is_not_production() {
        let src = "\
fn serve() {
    run();
}

#[cfg(test)]
mod wiring {
    #[test]
    fn t() {
        let s = \"sched.register(\\\"backup.sweep\\\"\";
        assert!(s.contains(\"sched.register\"));
    }
}";
        let prod = production_source(src);
        assert!(
            !prod.contains("sched.register"),
            "测试体里的 needle 绝不能被计入生产段（判据必须指向生产那一份）"
        );
        assert!(prod.contains("run();"));
    }

    /// 关键反例：`backups.rs` 这种「测试模块之后还有生产函数」的文件，
    /// 一刀切 split 会把生产代码切掉 ⇒ 守卫恒红。必须精确剥离。
    #[test]
    fn production_after_mid_file_test_module_is_kept() {
        let src = "\
fn before() {}

#[cfg(test)]
mod tests {
    #[test]
    fn t() { assert!(true); }
}

fn prune_daily_db() {}
";
        let prod = production_source(src);
        assert!(prod.contains("fn before()"), "测试模块之前的生产代码必须保留");
        assert!(
            prod.contains("fn prune_daily_db()"),
            "测试模块**之后**的生产代码必须保留（split 一刀切会把它切掉 ⇒ 守卫恒红）"
        );
        assert!(!prod.contains("fn t()"), "测试块本身必须剥掉");
    }

    /// 无块形态（`#[cfg(test)] use ...;`）只丢一行，不能把后面的生产代码吞掉。
    #[test]
    fn bare_cfg_test_item_only_drops_its_own_line() {
        let src = "\
#[cfg(test)]
use super::*;
fn prod_fn() {}
";
        let prod = production_source(src);
        assert!(prod.contains("fn prod_fn()"), "无块 cfg(test) 项后面的生产代码必须保留");
        assert!(!prod.contains("use super::*"));
    }

    /// 属性叠加形态：`#[cfg(test)]` 与 `#[allow(...)]` 同注一个块。
    #[test]
    fn stacked_attributes_are_skipped_before_block_scan() {
        let src = "\
#[cfg(test)]
#[allow(dead_code)]
mod t {
    fn inner() {}
}
fn prod_fn() {}
";
        let prod = production_source(src);
        assert!(prod.contains("fn prod_fn()"), "属性叠加的测试块之后的生产代码必须保留");
        assert!(!prod.contains("fn inner()"), "测试块内容必须剥掉");
    }

    /// 活性自检：剥离逻辑写坏时宁可panic，也不要让所有守卫「没找到」而静默放行。
    #[test]
    #[should_panic(expected = "production_source 产出为空")]
    fn empty_result_panics_instead_of_silently_passing() {
        let _ = production_source("// 全是注释\n/* 也全是注释 */");
    }

    /// 空输入是真空（守卫自己的 include_str! 不会为空，这里只保证不误 panic）。
    #[test]
    fn empty_input_is_allowed() {
        assert_eq!(production_source(""), "");
    }
}
