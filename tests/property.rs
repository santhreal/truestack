//! Property-based tests using `proptest`.
//!
//! These tests verify invariants that must hold for all valid inputs,
//! not just specific hand-crafted examples.

use proptest::prelude::*;
use truestack::fingerprints::{detect, extract_version, RuleEngine};
use truestack::postprocess::{apply, is_spa_catch_all};
use truestack::security_headers::audit;
use truestack::{TechCategory, Technology};

// ── helper ────────────────────────────────────────────────────────────────────

fn arb_tech_category() -> impl Strategy<Value = TechCategory> {
    prop_oneof![
        Just(TechCategory::Cms),
        Just(TechCategory::Framework),
        Just(TechCategory::Language),
        Just(TechCategory::Server),
        Just(TechCategory::Cdn),
        Just(TechCategory::Analytics),
        Just(TechCategory::Security),
        Just(TechCategory::Database),
        Just(TechCategory::Os),
        Just(TechCategory::Other),
    ]
}

fn arb_technology() -> impl Strategy<Value = Technology> {
    (
        "[a-zA-Z][a-zA-Z0-9 ./-]{0,30}",
        proptest::option::of("[0-9]{1,3}\\.[0-9]{1,3}"),
        arb_tech_category(),
        0u8..=100u8,
    )
        .prop_map(|(name, version, category, confidence)| Technology {
            name,
            version,
            category,
            confidence,
        })
}

// ── detect: never panics ──────────────────────────────────────────────────────

proptest! {
    /// `detect` must not panic for any combination of arbitrary header strings and body.
    #[test]
    fn detect_never_panics(
        headers in prop::collection::vec(
            ("[a-zA-Z0-9_-]{1,64}", "[ -~]{0,256}"),
            0..20
        ),
        body in "[ -~\t\n]{0,4096}"
    ) {
        // Should complete without panicking
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let _result = detect(&header_refs, &body);
    }
}

proptest! {
    /// Confidence of every detected technology is in 0..=100.
    #[test]
    fn detect_confidence_in_range(
        headers in prop::collection::vec(
            ("[a-zA-Z0-9_-]{1,64}", "[ -~]{0,128}"),
            0..10
        ),
        body in "[ -~\t\n]{0,1024}"
    ) {
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let techs = detect(&header_refs, &body);
        for t in &techs {
            prop_assert!(
                t.confidence <= 100,
                "confidence {} out of range for {}",
                t.confidence,
                t.name
            );
        }
    }
}

// ── extract_version: no panic ─────────────────────────────────────────────────

proptest! {
    /// `extract_version` must not panic for any inputs.
    #[test]
    fn extract_version_never_panics(
        header_val in "[ -~]{0,512}",
        tech_name in "[a-zA-Z0-9 ./-]{1,64}"
    ) {
        let _result = extract_version(&header_val, &tech_name);
    }
}

proptest! {
    /// If `extract_version` returns `Some`, the string must be non-empty.
    #[test]
    fn extract_version_some_is_non_empty(
        header_val in "[ -~]{0,512}",
        tech_name in "[a-zA-Z0-9 ./-]{1,64}"
    ) {
        if let Some(v) = extract_version(&header_val, &tech_name) {
            prop_assert!(!v.is_empty(), "extract_version returned Some(\"\")");
        }
    }
}

// ── is_spa_catch_all: symmetry ────────────────────────────────────────────────

proptest! {
    /// is_spa_catch_all(a, b, 200) == is_spa_catch_all(b, a, 200) when both > 0.
    #[test]
    fn spa_catch_all_is_symmetric(
        a in 1u64..,
        b in 1u64..
    ) {
        prop_assert_eq!(
            is_spa_catch_all(a, b, 200),
            is_spa_catch_all(b, a, 200)
        );
    }
}

proptest! {
    /// is_spa_catch_all is never true when baseline hash is zero.
    #[test]
    fn spa_catch_all_false_for_zero_baseline(probe_hash in any::<u64>()) {
        prop_assert!(!is_spa_catch_all(0, probe_hash, 200));
    }
}

// ── postprocess::apply: dedup invariant ──────────────────────────────────────

proptest! {
    /// After apply(), no two technologies share the same name.
    #[test]
    fn apply_produces_unique_names(
        techs in prop::collection::vec(arb_technology(), 0..20)
    ) {
        let result = apply(techs, &[]);
        let mut names: Vec<&str> = result.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        let unique_len = {
            let mut u = names.clone();
            u.dedup();
            u.len()
        };
        prop_assert_eq!(
            names.len(),
            unique_len,
            "duplicate names remain after apply: {:?}",
            names
        );
    }
}

proptest! {
    /// After dedup, the surviving confidence is >= all original values for that name.
    #[test]
    fn apply_dedup_keeps_max_confidence(
        base_name in "[a-zA-Z]{3,12}",
        confidences in prop::collection::vec(0u8..=100u8, 1..5),
        category in arb_tech_category()
    ) {
        let max_conf = *confidences.iter().max().unwrap();
        let techs: Vec<Technology> = confidences
            .iter()
            .map(|&c| Technology {
                name: base_name.clone(),
                version: None,
                category: category.clone(),
                confidence: c,
            })
            .collect();
        let result = apply(techs, &[]);
        let entry = result.iter().find(|t| t.name == base_name);
        prop_assert!(entry.is_some(), "tech disappeared after dedup");
        prop_assert_eq!(
            entry.unwrap().confidence,
            max_conf,
            "expected max confidence {} but got {}",
            max_conf,
            entry.unwrap().confidence
        );
    }
}

// ── audit: no panic ───────────────────────────────────────────────────────────

proptest! {
    /// `audit` must not panic for any combination of header names and values.
    #[test]
    fn audit_never_panics(
        headers in prop::collection::vec(
            ("[a-zA-Z0-9_-]{1,64}", "[ -~]{0,512}"),
            0..30
        )
    ) {
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let _findings = audit(&header_refs);
    }
}

// ── RuleEngine: compile is idempotent ────────────────────────────────────────

proptest! {
    /// Merging an empty engine into another leaves rule count unchanged.
    #[test]
    fn rule_engine_merge_empty_is_identity(
        n in 0usize..3
    ) {
        use truestack::fingerprints::Rule;
        use truestack::fingerprints::SignalDef;

        let rules: Vec<Rule> = (0..n)
            .map(|i| Rule {
                name: format!("Tech{}", i),
                version_header: None,
                category: TechCategory::Other,
                signals: vec![SignalDef::Body { value: format!("marker{}", i) }],
                negative_signals: vec![],
                excludes: vec![],
                requires: vec![],
                min_signals: 1,
            })
            .collect();

        let mut engine = RuleEngine::compile(rules);
        let count_before = engine.rules.len();
        let empty = RuleEngine::compile(vec![]);
        engine.merge(empty);
        prop_assert_eq!(engine.rules.len(), count_before);
    }
}
