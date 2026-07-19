//! Unit tests for individual public functions and types.
//!
//! These tests exercise each public API in isolation, covering
//! normal paths, edge cases, and boundary conditions.

use truestack::fingerprints::{detect, extract_version, Rule, RuleEngine};
use truestack::html::extract_title;
use truestack::implied::expand;
use truestack::postprocess::{apply, is_spa_catch_all};
use truestack::security_headers::audit;
use truestack::{TechCategory, Technology};

// ── extract_version ──────────────────────────────────────────────────────────

#[test]
fn extract_version_standard_slash_format() {
    assert_eq!(
        extract_version("nginx/1.21.0", "nginx"),
        Some("1.21.0".to_string())
    );
}

#[test]
fn extract_version_with_parenthetical_suffix() {
    assert_eq!(
        extract_version("Apache/2.4.41 (Unix)", "apache"),
        Some("2.4.41".to_string())
    );
}

#[test]
fn extract_version_microsoft_iis() {
    assert_eq!(
        extract_version("Microsoft-IIS/10.0", "IIS"),
        Some("10.0".to_string())
    );
}

#[test]
fn extract_version_empty_header_returns_none() {
    assert_eq!(extract_version("", "nginx"), None);
}

#[test]
fn extract_version_missing_slash_returns_none() {
    assert_eq!(extract_version("nginx", "nginx"), None);
}

#[test]
fn extract_version_slash_with_no_version_returns_none() {
    assert_eq!(extract_version("nginx/", "nginx"), None);
}

#[test]
fn extract_version_whitespace_trimmed() {
    assert_eq!(
        extract_version("  foo / 1.2.3 ", "foo"),
        Some("1.2.3".to_string())
    );
}

// ── TechCategory serialization round-trip ────────────────────────────────────

#[test]
fn tech_category_serde_roundtrip() {
    let cats = [
        TechCategory::Cms,
        TechCategory::Framework,
        TechCategory::Language,
        TechCategory::Server,
        TechCategory::Cdn,
        TechCategory::Analytics,
        TechCategory::Security,
        TechCategory::Database,
        TechCategory::Os,
        TechCategory::Other,
    ];
    for cat in &cats {
        let json = serde_json::to_string(cat).expect("serialize TechCategory");
        let back: TechCategory = serde_json::from_str(&json).expect("deserialize TechCategory");
        assert_eq!(cat, &back, "roundtrip failed for {cat:?}");
    }
}

// ── Technology struct ────────────────────────────────────────────────────────

#[test]
fn technology_serde_roundtrip() {
    let tech = Technology {
        name: "nginx".into(),
        version: Some("1.21.0".into()),
        category: TechCategory::Server,
        confidence: 95,
    };
    let json = serde_json::to_string(&tech).unwrap();
    let back: Technology = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, "nginx");
    assert_eq!(back.version.as_deref(), Some("1.21.0"));
    assert_eq!(back.confidence, 95);
}

// ── detect: single-technology cases ──────────────────────────────────────────

#[test]
fn detect_returns_empty_for_no_inputs() {
    let techs = detect::<&str, &str>(&[], "");
    assert!(techs.is_empty(), "expected empty result for no inputs");
}

#[test]
fn detect_nginx_from_server_header() {
    let techs = detect(&[("Server", "nginx/1.21.0")], "");
    assert!(techs.iter().any(|t| t.name == "nginx"));
}

#[test]
fn detect_express_from_x_powered_by() {
    let techs = detect(&[("X-Powered-By", "Express")], "");
    assert!(techs.iter().any(|t| t.name == "Express"));
}

#[test]
fn detect_django_from_csrftoken_cookie() {
    let techs = detect(&[("Set-Cookie", "csrftoken=abc")], "");
    assert!(techs.iter().any(|t| t.name == "Django"));
}

#[test]
fn detect_nextjs_from_script_tag_in_body() {
    let body = r#"<script id="__NEXT_DATA__" type="application/json">{}</script>"#;
    let techs = detect::<&str, &str>(&[], body);
    assert!(techs.iter().any(|t| t.name == "Next.js"));
}

#[test]
fn detect_wordpress_from_cookie() {
    let techs = detect(&[("Set-Cookie", "wordpress_test_cookie=test")], "");
    assert!(techs.iter().any(|t| t.name == "WordPress"));
}

#[test]
fn detect_cloudflare_from_cf_ray_header() {
    let techs = detect(&[("Server", "cloudflare"), ("CF-RAY", "12345abc-SYC")], "");
    let cf = techs.iter().find(|t| t.name == "Cloudflare");
    assert!(cf.is_some(), "Cloudflare not detected");
    assert_eq!(cf.unwrap().category, TechCategory::Cdn);
}

#[test]
fn detect_header_key_is_case_insensitive() {
    // Header key normalised to lowercase
    let techs = detect(&[("SERVER", "nginx/1.21.0")], "");
    assert!(techs.iter().any(|t| t.name == "nginx"));
}

// ── is_spa_catch_all ──────────────────────────────────────────────────────────

#[test]
fn spa_catch_all_true_when_same_hash_and_200() {
    assert!(is_spa_catch_all(0xdeadbeef, 0xdeadbeef, 200));
}

#[test]
fn spa_catch_all_false_when_different_hash() {
    assert!(!is_spa_catch_all(0xdeadbeef, 0xcafebabe, 200));
}

#[test]
fn spa_catch_all_false_when_404() {
    assert!(!is_spa_catch_all(0xdeadbeef, 0xdeadbeef, 404));
}

#[test]
fn spa_catch_all_false_when_hash_is_zero() {
    assert!(!is_spa_catch_all(0, 0, 200));
}

// ── html::extract_title ───────────────────────────────────────────────────────

#[test]
fn extract_title_normal_html() {
    assert_eq!(
        extract_title("<html><head><title>Hello</title></head></html>"),
        Some("Hello".to_string())
    );
}

#[test]
fn extract_title_missing_title_tag() {
    assert_eq!(extract_title("<html><head></head></html>"), None);
}

#[test]
fn extract_title_empty_title_tag_returns_none() {
    assert_eq!(
        extract_title("<html><head><title>   </title></head></html>"),
        None
    );
}

#[test]
fn extract_title_nested_whitespace_trimmed() {
    assert_eq!(
        extract_title("<html><head><title>  My App  </title></head></html>"),
        Some("My App".to_string())
    );
}

// ── implied::expand ───────────────────────────────────────────────────────────

#[test]
fn expand_react_implies_nodejs_and_webpack() {
    let detected = vec![Technology {
        name: "React".into(),
        version: None,
        category: TechCategory::Framework,
        confidence: 90,
    }];
    let implied = expand(&detected);
    let names: Vec<&str> = implied.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"Node.js"), "React should imply Node.js");
    assert!(names.contains(&"webpack"), "React should imply webpack");
}

#[test]
fn expand_does_not_re_imply_already_detected() {
    let detected = vec![
        Technology {
            name: "React".into(),
            version: None,
            category: TechCategory::Framework,
            confidence: 90,
        },
        Technology {
            name: "Node.js".into(),
            version: None,
            category: TechCategory::Language,
            confidence: 85,
        },
    ];
    let implied = expand(&detected);
    assert!(
        !implied.iter().any(|t| t.name == "Node.js"),
        "Node.js already detected, should not appear in implied set"
    );
}

#[test]
fn expand_implied_confidence_lower_than_trigger() {
    let detected = vec![Technology {
        name: "Django".into(),
        version: None,
        category: TechCategory::Framework,
        confidence: 80,
    }];
    let implied = expand(&detected);
    let python = implied.iter().find(|t| t.name == "Python");
    assert!(python.is_some());
    assert!(
        python.unwrap().confidence < 80,
        "implied confidence must be lower than trigger"
    );
}

// ── postprocess::apply ────────────────────────────────────────────────────────

fn make_tech(name: &str, category: TechCategory, confidence: u8) -> Technology {
    Technology {
        name: name.into(),
        version: None,
        category,
        confidence,
    }
}

fn make_rule(name: &str, excludes: Vec<&str>, requires: Vec<&str>) -> Rule {
    Rule {
        name: name.into(),
        version_header: None,
        category: TechCategory::Other,
        signals: vec![],
        negative_signals: vec![],
        excludes: excludes.into_iter().map(String::from).collect(),
        requires: requires.into_iter().map(String::from).collect(),
        min_signals: 1,
    }
}

#[test]
fn postprocess_dedup_keeps_highest_confidence() {
    let techs = vec![
        make_tech("nginx", TechCategory::Server, 60),
        make_tech("nginx", TechCategory::Server, 95),
    ];
    let result = apply(techs, &[]);
    assert_eq!(
        result.iter().filter(|t| t.name == "nginx").count(),
        1,
        "dedup should produce exactly one entry"
    );
    assert_eq!(
        result
            .iter()
            .find(|t| t.name == "nginx")
            .unwrap()
            .confidence,
        95
    );
}

#[test]
fn postprocess_excludes_removes_conflicted_tech() {
    let techs = vec![
        make_tech("Cloudflare", TechCategory::Cdn, 95),
        make_tech("nginx", TechCategory::Server, 60),
    ];
    let rules = vec![
        make_rule("Cloudflare", vec!["nginx"], vec![]),
        make_rule("nginx", vec![], vec![]),
    ];
    let result = apply(techs, &rules);
    assert!(!result.iter().any(|t| t.name == "nginx"));
    assert!(result.iter().any(|t| t.name == "Cloudflare"));
}

#[test]
fn postprocess_requires_removes_orphan_plugin() {
    let techs = vec![make_tech("Yoast SEO", TechCategory::Other, 80)];
    let rules = vec![make_rule("Yoast SEO", vec![], vec!["WordPress"])];
    let result = apply(techs, &rules);
    assert!(
        result.is_empty(),
        "plugin without required dependency should be removed"
    );
}

// ── RuleEngine::compile / from_toml ──────────────────────────────────────────

#[test]
fn rule_engine_from_toml_minimal_rule() {
    let toml = r#"
[[rules]]
name = "TestLib"
category = "framework"

[[rules.signals]]
type = "header"
key = "X-TestLib"
value = "1"
"#;
    let engine = RuleEngine::from_toml(toml).expect("parse minimal TOML");
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].name, "TestLib");
}

#[test]
fn rule_engine_from_toml_bad_input_returns_error() {
    let result = RuleEngine::from_toml("this is not toml @@@@");
    assert!(result.is_err(), "invalid TOML should return an error");
}

#[test]
fn rule_engine_embedded_has_rules() {
    let engine = RuleEngine::embedded();
    assert!(
        !engine.rules.is_empty(),
        "embedded rule engine must have at least one rule"
    );
}

// ── security_headers::audit ───────────────────────────────────────────────────

#[test]
fn audit_empty_headers_produces_multiple_missing_findings() {
    let findings = audit::<&str, &str>(&[]);
    let titles: Vec<&str> = findings.iter().map(|f| f.title()).collect();
    assert!(titles.contains(&"Missing HSTS header"));
    assert!(titles.contains(&"Missing Content-Security-Policy"));
    assert!(titles.contains(&"Missing X-Frame-Options"));
    assert!(titles.contains(&"Missing X-Content-Type-Options"));
    assert!(titles.contains(&"Missing Referrer-Policy"));
    assert!(titles.contains(&"Missing Permissions-Policy"));
}

#[test]
fn audit_csp_bypass_domain_flagged() {
    let findings = audit(&[(
        "Content-Security-Policy",
        "script-src 'self' cdn.jsdelivr.net",
    )]);
    assert!(
        findings.iter().any(|f| f.title().contains("CSP bypass")),
        "jsdelivr should trigger CSP bypass finding"
    );
}

#[test]
fn audit_unsafe_inline_in_csp_flagged() {
    let findings = audit(&[(
        "Content-Security-Policy",
        "script-src 'unsafe-inline' 'self'",
    )]);
    assert!(
        findings.iter().any(|f| f.title().contains("unsafe-inline")),
        "unsafe-inline should be flagged"
    );
}

#[test]
fn audit_x_powered_by_leaks_technology() {
    let findings = audit(&[("X-Powered-By", "PHP/8.0")]);
    assert!(
        findings.iter().any(|f| f.title().contains("X-Powered-By")),
        "X-Powered-By should trigger leakage finding"
    );
}

#[test]
fn audit_server_header_with_version_flagged() {
    let findings = audit(&[("Server", "Apache/2.4.41")]);
    assert!(
        findings.iter().any(|f| f.title().contains("Server")),
        "Server header with version should be flagged"
    );
}
