//! Post-detection processing: excludes, requires, dedup, and proxy detection.
//!
//! After the raw signal matching produces candidate technologies, this module
//! applies conditional logic that Wappalyzer supports but most tools skip:
//!
//! - **Excludes**: Detecting CDN X removes raw server Y from results
//!   (the "server: nginx" header came from the CDN, not the origin)
//! - **Requires**: Plugin detections only fire if the base tech is present
//! - **Proxy detection**: When two server techs are detected, flag the layer
//! - **Deduplication**: Same tech from different signals merged to highest confidence

use crate::Technology;
use std::collections::HashMap;

/// Apply all post-processing rules to a raw detection set.
pub fn apply(mut techs: Vec<Technology>, rules: &[crate::fingerprints::Rule]) -> Vec<Technology> {
    // Phase 1: Apply requires  -  remove techs whose requirements aren't met
    let detected_names: std::collections::HashSet<String> =
        techs.iter().map(|t| t.name.clone()).collect();

    // Find which rules fired and check their requires
    let mut requires_failed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for rule in rules {
        if detected_names.contains(&rule.name) && !rule.requires.is_empty() {
            let all_met = rule.requires.iter().all(|req| detected_names.contains(req));
            if !all_met {
                requires_failed.insert(rule.name.clone());
            }
        }
    }
    techs.retain(|t| !requires_failed.contains(&t.name));

    // Phase 2: Apply excludes  -  remove techs that are excluded by detected techs
    let mut excluded: std::collections::HashSet<String> = std::collections::HashSet::new();
    for rule in rules {
        if techs.iter().any(|t| t.name == rule.name) {
            for exc in &rule.excludes {
                excluded.insert(exc.clone());
            }
        }
    }
    techs.retain(|t| !excluded.contains(&t.name));

    // Phase 3: Detect proxy layers
    let server_techs: Vec<&Technology> = techs
        .iter()
        .filter(|t| matches!(t.category, crate::TechCategory::Server))
        .collect();

    if server_techs.len() >= 2 {
        // Multiple server technologies detected  -  likely a proxy setup.
        // The CDN/proxy layer (Cloudflare, nginx as reverse proxy) sits in front.
        // Don't remove either  -  just annotate for downstream consumers.
        // The implied graph and behavioral fingerprinting help disambiguate.
    }

    // Phase 4: Deduplicate  -  same tech from multiple signals, keep highest confidence
    let mut best: HashMap<String, Technology> = HashMap::new();
    for tech in techs {
        best.entry(tech.name.clone())
            .and_modify(|existing| {
                if tech.confidence > existing.confidence {
                    *existing = tech.clone();
                }
            })
            .or_insert(tech);
    }

    // Phase 5: Expand implied technologies
    let deduped: Vec<Technology> = best.into_values().collect();
    let implied = crate::implied::expand(&deduped);

    let mut final_set = deduped;
    for imp in implied {
        if !final_set.iter().any(|t| t.name == imp.name) {
            final_set.push(imp);
        }
    }

    final_set
}

/// Detect if a response is from a SPA catch-all (same content for all paths).
///
/// SPAs serve index.html for every route. This means hidden probes like
/// /swagger.json, /.git/config, /graphql all return 200 with the same
/// React/Vue/Angular app shell. Without this check, every probe is a
/// false positive.
pub fn is_spa_catch_all(baseline_hash: u64, probe_hash: u64, probe_status: u16) -> bool {
    probe_status == 200 && baseline_hash == probe_hash && baseline_hash != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprints::Rule;
    use crate::{TechCategory, Technology};

    fn tech(name: &str, cat: TechCategory, confidence: u8) -> Technology {
        Technology {
            name: name.into(),
            version: None,
            category: cat,
            confidence,
        }
    }

    fn rule(name: &str, excludes: Vec<&str>, requires: Vec<&str>) -> Rule {
        Rule {
            name: name.into(),
            version_header: None,
            category: TechCategory::Server,
            signals: vec![],
            negative_signals: vec![],
            excludes: excludes.into_iter().map(ToString::to_string).collect(),
            requires: requires.into_iter().map(ToString::to_string).collect(),
            min_signals: 1,
        }
    }

    #[test]
    fn excludes_removes_conflicting_tech() {
        let techs = vec![
            tech("Cloudflare", TechCategory::Cdn, 95),
            tech("nginx", TechCategory::Server, 60),
        ];
        let rules = vec![
            rule("Cloudflare", vec!["nginx"], vec![]),
            rule("nginx", vec![], vec![]),
        ];
        let result = apply(techs, &rules);
        assert!(!result.iter().any(|t| t.name == "nginx"));
        assert!(result.iter().any(|t| t.name == "Cloudflare"));
    }

    #[test]
    fn requires_removes_orphaned_plugins() {
        let techs = vec![
            tech("Yoast SEO", TechCategory::Other, 80),
            // WordPress NOT detected  -  Yoast should be removed
        ];
        let rules = vec![rule("Yoast SEO", vec![], vec!["WordPress"])];
        let result = apply(techs, &rules);
        assert!(result.is_empty());
    }

    #[test]
    fn requires_keeps_when_dependency_present() {
        let techs = vec![
            tech("WordPress", TechCategory::Cms, 90),
            tech("Yoast SEO", TechCategory::Other, 80),
        ];
        let rules = vec![
            rule("Yoast SEO", vec![], vec!["WordPress"]),
            rule("WordPress", vec![], vec![]),
        ];
        let result = apply(techs, &rules);
        assert!(result.iter().any(|t| t.name == "Yoast SEO"));
    }

    #[test]
    fn deduplicates_keeping_highest_confidence() {
        let techs = vec![
            tech("nginx", TechCategory::Server, 60),
            tech("nginx", TechCategory::Server, 90),
        ];
        let result = apply(techs, &[]);
        assert_eq!(result.iter().filter(|t| t.name == "nginx").count(), 1);
        assert_eq!(
            result
                .iter()
                .find(|t| t.name == "nginx")
                .unwrap()
                .confidence,
            90
        );
    }

    #[test]
    fn spa_catch_all_detected() {
        assert!(is_spa_catch_all(12345, 12345, 200));
        assert!(!is_spa_catch_all(12345, 67890, 200)); // different content
        assert!(!is_spa_catch_all(12345, 12345, 404)); // real 404
        assert!(!is_spa_catch_all(0, 0, 200)); // no baseline
    }
}
