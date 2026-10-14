    use super::*;

    fn req(enabled: bool, profile: Option<&str>, rate: Option<u32>, burst: Option<u32>) -> WafReq {
        WafReq { enabled, profile: profile.map(str::to_string), rate_per_sec: rate, burst }
    }

    fn spec(profile: panel_os::WafProfile, rate: Option<u32>, burst: u32) -> panel_os::WafSpec {
        panel_os::WafSpec { profile, rate_per_sec: rate, burst }
    }

    /// 缺省必须**保留**而不是关闭：否则任何不知道 `waf` 字段的调用方
    /// 一次 apply 就会把防护静默关掉，而且没有任何提示。
    #[test]
    fn omitted_waf_keeps_the_stored_config() {
        let cur = spec(panel_os::WafProfile::Strict, Some(5), 10);
        assert_eq!(build_waf(None, Some(&cur)).unwrap(), Some(cur));
        assert_eq!(build_waf(None, None).unwrap(), None);
    }

    #[test]
    fn explicit_disable_turns_it_off_even_if_currently_on() {
        let cur = spec(panel_os::WafProfile::Basic, Some(5), 10);
        assert_eq!(build_waf(Some(&req(false, None, None, None)), Some(&cur)).unwrap(), None);
    }

    #[test]
    fn burst_defaults_to_twice_the_rate_and_profile_defaults_to_basic() {
        let g = build_waf(Some(&req(true, Some("basic"), Some(10), None)), None).unwrap().unwrap();
        assert_eq!(g.burst, 20);
        assert_eq!(g.profile, panel_os::WafProfile::Basic);
        // 不给档位 → 基础档（默认值应当"够用且不误伤"）
        let g2 = build_waf(Some(&req(true, None, None, None)), None).unwrap().unwrap();
        assert_eq!(g2.profile, panel_os::WafProfile::Basic);
        assert_eq!(g2.rate_per_sec, None);
    }

    /// `rate=0` 若原样下发，nginx 会拒绝加载整份配置——必须解释成"不限速"。
    #[test]
    fn rate_zero_means_unlimited_rather_than_going_into_the_config() {
        let g = build_waf(Some(&req(true, None, Some(0), None)), None).unwrap().unwrap();
        assert_eq!(g.rate_per_sec, None);
        assert_eq!(g.burst, 0);
        // 不限速却给了 burst = 用户以为限速生效了，直接拒绝
        assert!(build_waf(Some(&req(true, None, None, Some(50))), None).is_err());
    }

    #[test]
    fn unknown_profile_and_out_of_range_numbers_are_rejected() {
        assert!(build_waf(Some(&req(true, Some("yolo"), None, None)), None).is_err());
        assert!(build_waf(Some(&req(true, None, Some(WAF_RATE_MAX + 1), None)), None).is_err());
        assert!(build_waf(Some(&req(true, None, Some(1), Some(WAF_BURST_MAX + 1))), None).is_err());
        // 边界值本身必须放过：不然"上限"就成了一句空话
        let ok = build_waf(Some(&req(true, None, Some(WAF_RATE_MAX), None)), None).unwrap().unwrap();
        assert_eq!(ok.rate_per_sec, Some(WAF_RATE_MAX));
        assert_eq!(ok.burst, WAF_RATE_MAX * 2);
    }
