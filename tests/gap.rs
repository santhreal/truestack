//! Gap tests: behaviours not covered by unit/adversarial/integration tests.
//!
//! This file targets scenarios that fall between the cracks of the other
//! test files: version_intel assessments, implied-chain chaining, waf
//! integration, and boundary conditions on the rule engine.

use truestack::fingerprints::{detect_with_engine, Rule, RuleEngine, SignalDef};
use truestack::implied::expand;
use truestack::postprocess::apply;
use truestack::security_headers::audit;
use truestack::version_intel::{assess_headers, VersionReliability};
use truestack::{TechCategory, Technology};

// ── version_intel: basic assess_headers round-trip ───────────────────────────

#[test]
fn assess_headers_on_empty_techs_returns_empty() {
    let empty: &[(&str, &str)] = &[];
    let result = assess_headers::<&str, &str>(&[], empty);
    assert!(
        result.is_empty(),
        "assess_headers on empty tech list should return empty"
    );
}

#[test]
fn assess_headers_without_os_context_records_entry() {
    let techs = vec![Technology {
        name: "nginx".into(),
        version: Some("1.21.0".into()),
        category: TechCategory::Server,
        confidence: 90,
    }];
    let empty_headers: &[(&str, &str)] = &[];
    let result = assess_headers(&techs, empty_headers);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].technology, "nginx");
    assert_eq!(result[0].reported_version.as_deref(), Some("1.21.0"));
}

#[test]
fn assess_headers_debian_context_marks_possibly_backported() {
    let techs = vec![Technology {
        name: "Apache".into(),
        version: Some("2.4.41".into()),
        category: TechCategory::Server,
        confidence: 90,
    }];
    // Debian server header hints
    let headers = &[("Server", "Apache/2.4.41 (Debian)")];
    let result = assess_headers(&techs, headers);
    assert_eq!(result.len(), 1);
    let assessment = &result[0];
    // On a backporting distro, reliability should be Unreliable or Suspect
    assert!(
        matches!(
            assessment.reliability,
            VersionReliability::Unreliable | VersionReliability::Suspect
        ),
        "Debian Apache version should be Unreliable or Suspect, got {:?}",
        assessment.reliability
    );
}

#[test]
fn assess_headers_ubuntu_in_server_header_detected() {
    let techs = vec![Technology {
        name: "nginx".into(),
        version: Some("1.18.0".into()),
        category: TechCategory::Server,
        confidence: 90,
    }];
    let headers = &[("Server", "nginx/1.18.0 (Ubuntu)")];
    let result = assess_headers(&techs, headers);
    assert_eq!(result.len(), 1);
    // Ubuntu is an aggressive backporter - reliability must not be Likely or NoVersion
    assert!(
        matches!(
            result[0].reliability,
            VersionReliability::Unreliable | VersionReliability::Suspect
        ),
        "Ubuntu nginx version should be Unreliable or Suspect, got {:?}",
        result[0].reliability
    );
}

// ── implied: chained implications ────────────────────────────────────────────

#[test]
fn nuxtjs_implies_vuejs_and_nodejs() {
    let detected = vec![Technology {
        name: "Nuxt.js".into(),
        version: None,
        category: TechCategory::Framework,
        confidence: 90,
    }];
    let implied = expand(&detected);
    let names: Vec<&str> = implied.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"Vue.js"), "Nuxt.js should imply Vue.js");
    assert!(names.contains(&"Node.js"), "Nuxt.js should imply Node.js");
}

#[test]
fn wordpress_implies_php_and_mysql() {
    let detected = vec![Technology {
        name: "WordPress".into(),
        version: None,
        category: TechCategory::Cms,
        confidence: 90,
    }];
    let implied = expand(&detected);
    let names: Vec<&str> = implied.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"PHP"), "WordPress should imply PHP");
    assert!(names.contains(&"MySQL"), "WordPress should imply MySQL");
}

#[test]
fn laravel_implies_php() {
    let detected = vec![Technology {
        name: "Laravel".into(),
        version: None,
        category: TechCategory::Framework,
        confidence: 90,
    }];
    let implied = expand(&detected);
    assert!(
        implied.iter().any(|t| t.name == "PHP"),
        "Laravel should imply PHP"
    );
}

#[test]
fn angular_implies_typescript() {
    let detected = vec![Technology {
        name: "Angular".into(),
        version: None,
        category: TechCategory::Framework,
        confidence: 85,
    }];
    let implied = expand(&detected);
    assert!(
        implied.iter().any(|t| t.name == "TypeScript"),
        "Angular should imply TypeScript"
    );
}

// ── detect_with_engine: favicon hash matching ────────────────────────────────

#[test]
fn favicon_hash_signal_triggers_rule() {
    let rule = Rule {
        name: "FaviconDetected".into(),
        version_header: None,
        category: TechCategory::Other,
        signals: vec![SignalDef::Favicon { hash: -12345678 }],
        negative_signals: vec![],
        excludes: vec![],
        requires: vec![],
        min_signals: 1,
    };
    let engine = RuleEngine::compile(vec![rule]);
    let empty_headers: &[(&str, &str)] = &[];

    let found = detect_with_engine(empty_headers, "", Some(-12345678), &engine);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "FaviconDetected");

    // Different hash should not match
    let not_found = detect_with_engine(empty_headers, "", Some(99999999), &engine);
    assert!(not_found.is_empty());
}

#[test]
fn favicon_hash_none_does_not_match() {
    let rule = Rule {
        name: "FaviconSite".into(),
        version_header: None,
        category: TechCategory::Other,
        signals: vec![SignalDef::Favicon { hash: 42 }],
        negative_signals: vec![],
        excludes: vec![],
        requires: vec![],
        min_signals: 1,
    };
    let engine = RuleEngine::compile(vec![rule]);
    let empty_headers: &[(&str, &str)] = &[];
    let result = detect_with_engine(empty_headers, "", None, &engine);
    assert!(
        result.is_empty(),
        "None favicon hash should not match any rule"
    );
}

// ── min_signals: multi-signal threshold ──────────────────────────────────────

#[test]
fn min_signals_two_requires_both_signals() {
    let rule = Rule {
        name: "StrictTech".into(),
        version_header: None,
        category: TechCategory::Framework,
        signals: vec![
            SignalDef::Header {
                key: "X-SigA".into(),
                value: "yes".into(),
            },
            SignalDef::Header {
                key: "X-SigB".into(),
                value: "yes".into(),
            },
        ],
        negative_signals: vec![],
        excludes: vec![],
        requires: vec![],
        min_signals: 2,
    };
    let engine = RuleEngine::compile(vec![rule]);

    // Only one signal present - should NOT match
    let one_signal = detect_with_engine(&[("X-SigA", "yes")], "", None, &engine);
    assert!(
        one_signal.is_empty(),
        "min_signals=2 should not fire with only 1 match"
    );

    // Both signals present - should match
    let both = detect_with_engine(&[("X-SigA", "yes"), ("X-SigB", "yes")], "", None, &engine);
    assert_eq!(both.len(), 1, "min_signals=2 should fire when both match");
}

// ── requires: plugin chain ────────────────────────────────────────────────────

#[test]
fn plugin_with_unmet_requires_is_removed_by_postprocess() {
    let techs = vec![
        Technology {
            name: "WooCommerce".into(),
            version: None,
            category: TechCategory::Other,
            confidence: 80,
        },
        // WordPress NOT present
    ];
    let rules = vec![Rule {
        name: "WooCommerce".into(),
        version_header: None,
        category: TechCategory::Other,
        signals: vec![],
        negative_signals: vec![],
        excludes: vec![],
        requires: vec!["WordPress".into()],
        min_signals: 1,
    }];
    let result = apply(techs, &rules);
    assert!(
        result.is_empty(),
        "WooCommerce without WordPress should be removed by requires check"
    );
}

// ── security_headers: CORP / COOP / COEP checks ──────────────────────────────

#[test]
fn audit_missing_corp_coop_coep_flagged() {
    let findings = audit::<&str, &str>(&[]);
    let titles: Vec<&str> = findings.iter().map(|f| f.title()).collect();
    assert!(
        titles
            .iter()
            .any(|t| t.contains("COEP") || t.contains("Cross-Origin-Embedder")),
        "Missing COEP should be flagged"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("COOP") || t.contains("Cross-Origin-Opener")),
        "Missing COOP should be flagged"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("CORP") || t.contains("Cross-Origin-Resource")),
        "Missing CORP should be flagged"
    );
}

#[test]
fn audit_csp_wildcard_script_src_flagged() {
    let findings = audit(&[("Content-Security-Policy", "script-src *")]);
    assert!(
        findings.iter().any(|f| f.title().contains("wildcard")),
        "CSP wildcard script-src should be flagged"
    );
}

#[test]
fn audit_csp_missing_base_uri_flagged() {
    let findings = audit(&[("Content-Security-Policy", "default-src 'self'")]);
    assert!(
        findings.iter().any(|f| f.title().contains("base-uri")),
        "Missing base-uri in CSP should be flagged"
    );
}

#[test]
fn audit_x_aspnet_version_leakage_flagged() {
    let findings = audit(&[("X-AspNet-Version", "4.0.30319")]);
    assert!(
        findings.iter().any(|f| f.title().contains("X-AspNet")),
        "X-AspNet-Version header should trigger leakage finding"
    );
}

// ── RuleEngine::merge ─────────────────────────────────────────────────────────

#[test]
fn rule_engine_merge_combines_rules() {
    let engine_a = RuleEngine::compile(vec![Rule {
        name: "TechA".into(),
        version_header: None,
        category: TechCategory::Other,
        signals: vec![SignalDef::Body {
            value: "marker_a".into(),
        }],
        negative_signals: vec![],
        excludes: vec![],
        requires: vec![],
        min_signals: 1,
    }]);
    let engine_b = RuleEngine::compile(vec![Rule {
        name: "TechB".into(),
        version_header: None,
        category: TechCategory::Other,
        signals: vec![SignalDef::Body {
            value: "marker_b".into(),
        }],
        negative_signals: vec![],
        excludes: vec![],
        requires: vec![],
        min_signals: 1,
    }]);

    let mut merged = engine_a;
    merged.merge(engine_b);

    assert_eq!(merged.rules.len(), 2);

    let a = detect_with_engine::<&str, &str>(&[], "marker_a", None, &merged);
    let b = detect_with_engine::<&str, &str>(&[], "marker_b", None, &merged);
    assert!(a.iter().any(|t| t.name == "TechA"));
    assert!(b.iter().any(|t| t.name == "TechB"));
}

// ── detect: version_header extraction ────────────────────────────────────────

#[test]
fn version_header_populated_from_named_header() {
    let rule = Rule {
        name: "MyServer".into(),
        version_header: Some("X-My-Version".into()),
        category: TechCategory::Server,
        signals: vec![SignalDef::Header {
            key: "X-My-Tech".into(),
            value: "yes".into(),
        }],
        negative_signals: vec![],
        excludes: vec![],
        requires: vec![],
        min_signals: 1,
    };
    let engine = RuleEngine::compile(vec![rule]);
    let headers = &[("X-My-Tech", "yes"), ("X-My-Version", "MyServer/3.2.1")];
    let result = detect_with_engine(headers, "", None, &engine);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].version.as_deref(), Some("3.2.1"));
}
