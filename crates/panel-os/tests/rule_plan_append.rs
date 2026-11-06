//! F-20 回归：防火墙 apply 的**追加语义**。
//!
//! 真机 ufw / nft 的 apply 需要 CAP_NET_ADMIN，CI 里只能 skip；因此把「要不要删」
//! 的决策抽成 `panel_os::plan_additions` 在这里直接钉死，再由
//! `ci/check_firewall_append_only.py` 钉住两个真实实现确实只调用了它。

use panel_os::mock::MockOsAdapter;
use panel_os::*;

fn rule(port: u16, id: &str, comment: Option<&str>) -> FirewallRule {
    FirewallRule {
        id: id.into(),
        ports: PortSpec::Single(port),
        protocol: Protocol::Tcp,
        action: Action::Allow,
        direction: Direction::Inbound,
        source_cidr: None,
        comment: comment.map(str::to_string),
        panel_managed: true,
    }
}

/// F-20 主回归：已放行 8080，第二次只提交 9090 ⇒ 只新增 9090，8080 不许被删。
#[test]
fn second_apply_only_adds_the_new_port() {
    let existing = vec![rule(8080, "p1", Some("panel-managed p1 web"))];
    let wanted = vec![rule(9090, "p2", Some("panel-managed p2 api"))];

    assert_eq!(plan_additions(&existing, &wanted), vec![0]);
    // 判据只读 existing、不消费也不修改：8080 必须原样还在。
    assert_eq!(existing.len(), 1, "existing 不应被删减");
    assert_eq!(existing[0].ports, PortSpec::Single(8080));
}

#[test]
fn reapplying_an_existing_rule_is_unchanged_not_a_second_add() {
    let existing = vec![rule(8080, "p1", Some("panel-managed p1 web"))];
    let wanted = vec![rule(8080, "another-id", None)];
    assert_eq!(plan_additions(&existing, &wanted), Vec::<usize>::new());
}

#[test]
fn functional_equality_ignores_id_and_comment_but_not_source_or_protocol() {
    let a = rule(8080, "p1", Some("web"));
    let b = rule(8080, "different-id", None);
    assert!(rules_functionally_eq(&a, &b), "id / comment 不代表规则语义");

    let mut with_source = b.clone();
    with_source.source_cidr = Some("10.0.0.0/8".into());
    assert!(!rules_functionally_eq(&a, &with_source));
    assert_eq!(plan_additions(std::slice::from_ref(&a), &[with_source]), vec![0]);

    let mut udp = b.clone();
    udp.protocol = Protocol::Udp;
    assert!(!rules_functionally_eq(&a, &udp));
}

#[test]
fn empty_existing_adds_every_rule_and_missing_ones_only() {
    let wanted = vec![rule(80, "a", None), rule(443, "b", None)];
    assert_eq!(plan_additions(&[], &wanted), vec![0, 1]);

    let existing = vec![rule(80, "a", None)];
    let wanted = vec![rule(80, "a2", None), rule(443, "b", None)];
    assert_eq!(plan_additions(&existing, &wanted), vec![1]);
}

#[test]
fn user_comment_strips_marks_including_legacy_double_prefix() {
    assert_eq!(user_comment(Some("panel-managed p18f3ab web")), Some("web".into()));
    // 路由层与实现层历史上各拼过一次标记，已落盘的数据要能洗干净。
    assert_eq!(
        user_comment(Some("panel-managed g1 panel-managed r1 api")),
        Some("api".into())
    );
    assert_eq!(user_comment(Some("panel-managed p2")), None, "无备注应显示为空");
    assert_eq!(user_comment(Some("my own rule")), Some("my own rule".into()));
    assert_eq!(user_comment(None), None);
}

/// mock 适配器天然是追加语义：用它跑一遍完整 apply → list 链路，无需 root。
#[tokio::test]
async fn apply_twice_keeps_both_ports() {
    let os = MockOsAdapter::new();
    let fw = os.firewall();

    let first = fw.apply(RulePlan { rules: vec![rule(8080, "p1", Some("web"))] }).await.unwrap();
    assert_eq!((first.added, first.removed), (1, 0));

    let second = fw.apply(RulePlan { rules: vec![rule(9090, "p2", Some("api"))] }).await.unwrap();
    assert_eq!(second.added, 1);
    assert_eq!(second.removed, 0, "apply 不许删除任何既有规则");

    let list = fw.list_rules().await.unwrap();
    assert_eq!(list.len(), 2, "8080 与 9090 必须同时存在");
    let mut ports: Vec<u16> = list.iter()
        .filter_map(|r| match r.ports { PortSpec::Single(p) => Some(p), _ => None })
        .collect();
    ports.sort_unstable();
    assert_eq!(ports, vec![8080, 9090]);
}
