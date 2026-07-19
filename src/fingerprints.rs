//! YAML-driven technology fingerprinting engine.
//!
//! Detects web technologies from HTTP response headers, body content, and
//! cookies using a signal-based rule engine. Rules are embedded at compile
//! time from `rules.yaml` but the public [`detect`] function accepts raw
//! header/body data so callers can supply their own transport.

use crate::{TechCategory, Technology};
use once_cell::sync::Lazy;
use serde::Deserialize;

/// A single detection rule loaded from the YAML rule file.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// Display name for the technology.
    pub name: String,
    /// Optional header whose value contains the version string.
    pub version_header: Option<String>,
    /// Broad technology category.
    pub category: TechCategory,
    /// One or more signals  -  a match on **any** signal triggers the rule.
    pub signals: Vec<SignalDef>,
    /// Negative signals  -  if **any** of these match, the rule is disqualified.
    /// This prevents false positives from banner-spoofing or proxies.
    #[serde(default)]
    pub negative_signals: Vec<SignalDef>,
    /// Technologies that this detection EXCLUDES.
    /// If this rule fires, the named technologies are removed from results.
    /// Example: detecting "Cloudflare CDN" excludes direct "nginx" when
    /// the nginx signature comes from Cloudflare's proxy, not the origin.
    #[serde(default)]
    pub excludes: Vec<String>,
    /// Technologies that MUST also be detected for this rule to fire.
    /// Example: "WordPress SEO Plugin" requires "WordPress" to be present.
    #[serde(default)]
    pub requires: Vec<String>,
    /// Minimum number of signals that must match for this rule to fire.
    /// Default is 1 (any signal match triggers the rule).
    /// Set higher for technologies that need multiple confirmations.
    #[serde(default = "default_min_signals")]
    pub min_signals: usize,
}

fn default_min_signals() -> usize {
    1
}

/// Where to look for a signal match.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum SignalDef {
    /// Match an HTTP response header key/value pair.
    #[serde(rename = "header")]
    Header { key: String, value: String },
    /// Match a substring in the response body.
    #[serde(rename = "body")]
    Body { value: String },
    /// Match a substring in a `Set-Cookie` header.
    #[serde(rename = "cookie")]
    Cookie { value: String },
    /// Match a Shodan-compatible favicon hash.
    #[serde(rename = "favicon")]
    Favicon { hash: i32 },
}

/// Confidence weight for a matched signal source.
fn signal_confidence(sig: &SignalDef) -> u8 {
    match sig {
        SignalDef::Header { .. } => 95,
        SignalDef::Cookie { .. } => 90,
        SignalDef::Favicon { .. } => 90,
        SignalDef::Body { .. } => 70,
    }
}

/// Compute aggregate confidence from matched signals.
fn aggregate_confidence(matched: &[&SignalDef]) -> u8 {
    let base = matched
        .iter()
        .map(|s| signal_confidence(s))
        .max()
        .unwrap_or(80);
    let extra = matched.len().saturating_sub(1) as u8;
    base.saturating_add(5u8.saturating_mul(extra)).min(100)
}

/// A technology fingerprinting engine.
#[derive(Debug, Clone)]
pub struct RuleEngine {
    pub rules: Vec<Rule>,
    pub body_ac: std::sync::Arc<aho_corasick::AhoCorasick>,
    pub body_patterns: std::sync::Arc<Vec<String>>,
}

#[derive(Deserialize)]
struct RawRuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    /// Parse a RuleEngine from a TOML string.
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        let raw: RawRuleEngine =
            toml::from_str(s).map_err(|e| anyhow::anyhow!("Failed to parse rules TOML: {e}"))?;
        Ok(Self::compile(raw.rules))
    }

    /// Compile a rule engine from a list of rules
    pub fn compile(rules: Vec<Rule>) -> Self {
        let mut body_patterns = std::collections::HashSet::new();
        for rule in &rules {
            for sig in &rule.signals {
                if let SignalDef::Body { value } = sig {
                    body_patterns.insert(value.clone());
                }
            }
            for sig in &rule.negative_signals {
                if let SignalDef::Body { value } = sig {
                    body_patterns.insert(value.clone());
                }
            }
        }
        let patterns: Vec<String> = body_patterns.into_iter().collect();
        // A body-pattern Aho-Corasick build failure means the loaded rule data is
        // broken (e.g. exceeds the automaton's scale limits). Fail closed loudly:
        // substituting an empty matcher would silently make EVERY body fingerprint
        // stop matching while `body_patterns` still claims N patterns (Law 10).
        let ac = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to build the body-pattern matcher from {} rule pattern(s): {error}. Fix the rule data; truestack refuses to run with a matcher that silently matches nothing",
                    patterns.len()
                )
            });

        Self {
            rules,
            body_ac: std::sync::Arc::new(ac),
            body_patterns: std::sync::Arc::new(patterns),
        }
    }

    /// Load and merge all `.toml` rule files from a directory.
    pub fn from_directory<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let mut engine = Self::compile(Vec::new());
        if !path.as_ref().exists() {
            return Ok(engine);
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                let content = std::fs::read_to_string(&path)?;
                let ext_engine = Self::from_toml(&content)?;
                engine.merge(ext_engine);
            }
        }
        Ok(engine)
    }

    /// Merge another engine's rules into this one.
    pub fn merge(&mut self, other: Self) {
        let mut combined = self.rules.clone();
        combined.extend(other.rules);
        *self = Self::compile(combined);
    }

    /// Access the embedded rule engine.
    pub fn embedded() -> &'static Self {
        &ENGINE
    }
}

#[allow(clippy::panic)]
static ENGINE: Lazy<RuleEngine> = Lazy::new(|| {
    let toml = include_str!("rules.toml");
    RuleEngine::from_toml(toml)
        .unwrap_or_else(|e| panic!("failed to parse embedded rules.toml: {}", e))
});

/// Detect technologies from raw HTTP response data using the default engine.
///
/// `headers` is a slice of `(name, value)` pairs exactly as received.
/// `body` is the decoded response body (UTF-8 or best-effort).
///
/// Returns a [`Vec<Technology>`] with one entry per matched rule.
pub fn detect<K: AsRef<str>, V: AsRef<str>>(headers: &[(K, V)], body: &str) -> Vec<Technology> {
    detect_with_engine(headers, body, None, &ENGINE)
}

/// Detect technologies from raw HTTP response data using a specific engine.
pub fn detect_with_engine<K: AsRef<str>, V: AsRef<str>>(
    headers: &[(K, V)],
    body: &str,
    favicon_hash: Option<i32>,
    engine: &RuleEngine,
) -> Vec<Technology> {
    let cookies: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.as_ref())
        .collect();

    let body_matches: std::collections::HashSet<&str> = engine
        .body_ac
        .find_iter(body)
        .map(|mat| engine.body_patterns[mat.pattern().as_usize()].as_str())
        .collect();

    engine
        .rules
        .iter()
        .filter_map(|rule| {
            let matched: Vec<&SignalDef> = rule
                .signals
                .iter()
                .filter(|sig| matches_signal(sig, headers, &body_matches, &cookies, favicon_hash))
                .collect();

            if matched.is_empty() || matched.len() < rule.min_signals {
                return None;
            }

            // Check negative signals (Oneshot Anti-Spoofing)
            let disqualified = rule
                .negative_signals
                .iter()
                .any(|sig| matches_signal(sig, headers, &body_matches, &cookies, favicon_hash));
            if disqualified {
                return None;
            }

            let version = rule.version_header.as_ref().and_then(|vh| {
                headers
                    .iter()
                    .find(|(k, _)| k.as_ref().eq_ignore_ascii_case(vh))
                    .and_then(|(_, v)| extract_version(v.as_ref(), &rule.name))
            });

            Some(Technology {
                name: rule.name.clone(),
                version,
                category: rule.category.clone(),
                confidence: aggregate_confidence(&matched),
            })
        })
        .collect()
}

/// Zero-allocation case-insensitive substring search
pub(crate) fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let haystack_b = haystack.as_bytes();
    let needle_b = needle.as_bytes();
    if haystack_b.len() < needle_b.len() {
        return false;
    }
    for i in 0..=(haystack_b.len() - needle_b.len()) {
        if haystack_b[i..i + needle_b.len()].eq_ignore_ascii_case(needle_b) {
            return true;
        }
    }
    false
}

/// Check whether a single signal matches the given response data.
fn matches_signal<K: AsRef<str>, V: AsRef<str>>(
    sig: &SignalDef,
    headers: &[(K, V)],
    body_matches: &std::collections::HashSet<&str>,
    cookies: &[&str],
    favicon_hash: Option<i32>,
) -> bool {
    match sig {
        SignalDef::Header { key, value } => headers.iter().any(|(k, v)| {
            k.as_ref().eq_ignore_ascii_case(key)
                && (value.is_empty() || contains_ignore_case(v.as_ref(), value))
        }),
        SignalDef::Body { value } => body_matches.contains(value.as_str()),
        SignalDef::Cookie { value } => cookies.iter().any(|c| contains_ignore_case(c, value)),
        SignalDef::Favicon { hash } => favicon_hash == Some(*hash),
    }
}

/// Best-effort version string extraction from a header value.
///
/// Handles formats like `nginx/1.21.0`, `Apache/2.4.41 (Unix)`,
/// `Microsoft-IIS/10.0`.
pub fn extract_version(header_val: &str, tech_name: &str) -> Option<String> {
    let lower_val = header_val.to_lowercase();
    let lower_tech = tech_name.to_lowercase();

    // 1. Try to find specific "Tech/Version" in a multi-tech string
    if let Some(idx) = lower_val.find(&lower_tech) {
        let remainder = &header_val[idx + tech_name.len()..];
        if let Some(stripped) = remainder.strip_prefix('/') {
            let version_str = stripped
                .split_whitespace()
                .next()
                .map(|s| {
                    s.trim_matches(|c: char| !c.is_alphanumeric() && c != '.')
                        .to_string()
                })
                .filter(|s| !s.is_empty());

            if version_str.is_some() {
                return version_str;
            }
        }
    }

    // 2. Fallback to extracting the first valid version string
    header_val
        .split_whitespace()
        .find(|t| {
            t.chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        })
        .or_else(|| {
            header_val
                .split('/')
                .nth(1)
                .map(|s| s.split_whitespace().next().unwrap_or(s))
        })
        .map(|s| {
            s.trim_matches(|c: char| !c.is_alphanumeric() && c != '.')
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_engine_loads_correctly() {
        let count = ENGINE.rules.len();
        assert!(count > 0, "loaded 0 rules from yaml engine");
    }

    #[test]
    fn detect_nginx_header() {
        let headers = vec![("Server".to_string(), "nginx/1.21.0".to_string())];
        let techs = detect(&headers, "");
        assert_eq!(techs.len(), 1);
        assert_eq!(techs[0].name, "nginx");
        assert_eq!(techs[0].version.as_deref(), Some("1.21.0"));
        assert_eq!(techs[0].confidence, 95);
    }

    #[test]
    fn detect_cloudflare_cdn() {
        let headers = vec![
            ("Server".to_string(), "cloudflare".to_string()),
            ("cf-ray".to_string(), "123456789".to_string()),
        ];
        let techs = detect(&headers, "");
        let cf = techs
            .iter()
            .find(|t| t.name == "Cloudflare")
            .expect("did not detect Cloudflare");
        assert_eq!(cf.category, TechCategory::Cdn);
    }

    #[test]
    fn detect_nextjs_body() {
        let body = r#"<html><body><script id="__NEXT_DATA__" type="application/json"></script></body></html>"#;
        let empty_headers: &[(&str, &str)] = &[];
        let techs = detect(empty_headers, body);
        let next = techs
            .iter()
            .find(|t| t.name == "Next.js")
            .expect("did not detect Next.js");
        assert_eq!(next.category, TechCategory::Framework);
    }

    #[test]
    fn version_extraction() {
        assert_eq!(
            extract_version("nginx/1.21.0", "nginx"),
            Some("1.21.0".to_string())
        );
        assert_eq!(
            extract_version("Apache/2.4.41 (Unix) OpenSSL/1.1.1d", "Apache"),
            Some("2.4.41".to_string())
        );
        assert_eq!(
            extract_version("Microsoft-IIS/10.0", "IIS"),
            Some("10.0".to_string())
        );
    }

    #[test]
    fn compiled_body_matcher_matches_its_patterns() {
        // Guards against the empty-matcher fallback regression: the Aho-Corasick
        // built by `compile` must actually match the body patterns it was given,
        // and its pattern count must equal the declared `body_patterns` (no silent
        // divergence between what is claimed and what is matchable).
        let rule = Rule {
            name: "MarkerTech".into(),
            version_header: None,
            category: TechCategory::Cms,
            signals: vec![SignalDef::Body {
                value: "unique-body-marker".into(),
            }],
            negative_signals: vec![],
            excludes: vec![],
            requires: vec![],
            min_signals: 1,
        };
        let engine = RuleEngine::compile(vec![rule]);

        assert_eq!(
            engine.body_ac.patterns_len(),
            engine.body_patterns.len(),
            "matcher pattern count must equal declared body_patterns"
        );
        assert_eq!(engine.body_patterns.len(), 1, "one body pattern expected");
        assert!(
            engine.body_ac.is_match("prefix unique-body-marker suffix"),
            "compiled matcher must match its own body pattern (empty-matcher regression)"
        );

        let no_headers: Vec<(String, String)> = Vec::new();
        let techs = detect_with_engine(
            &no_headers,
            "page has a unique-body-marker inside",
            None,
            &engine,
        );
        assert_eq!(techs.len(), 1);
        assert_eq!(techs[0].name, "MarkerTech");
    }

    #[test]
    fn negative_signals_disqualify_rule() {
        let rule = Rule {
            name: "RealTech".into(),
            version_header: None,
            category: TechCategory::Cms,
            signals: vec![SignalDef::Body {
                value: "real-tech-marker".into(),
            }],
            negative_signals: vec![SignalDef::Header {
                key: "X-Spoof".into(),
                value: "true".into(),
            }],
            excludes: vec![],
            requires: vec![],
            min_signals: 1,
        };
        let engine = RuleEngine::compile(vec![rule]);

        let headers_clean = vec![("Content-Type".to_string(), "text/plain".to_string())];
        let headers_spoofed = vec![("X-Spoof".to_string(), "true".to_string())];
        let body = "real-tech-marker";

        let techs_clean = detect_with_engine(&headers_clean, body, None, &engine);
        let techs_spoofed = detect_with_engine(&headers_spoofed, body, None, &engine);

        assert_eq!(techs_clean.len(), 1);
        assert_eq!(techs_clean[0].name, "RealTech");
        assert_eq!(
            techs_spoofed.len(),
            0,
            "Negative signal should have disqualified the rule"
        );
    }

    #[test]
    fn aggregate_confidence_scales_with_signals() {
        let sigs = [
            SignalDef::Body { value: "a".into() },
            SignalDef::Body { value: "b".into() },
            SignalDef::Body { value: "c".into() },
        ];
        let refs: Vec<&SignalDef> = sigs.iter().collect();
        assert_eq!(aggregate_confidence(&refs), 80); // 70 + 5*2 = 80

        let header_sig = SignalDef::Header {
            key: "x".into(),
            value: "y".into(),
        };
        let mixed = vec![&header_sig, &sigs[0], &sigs[1]];
        assert_eq!(aggregate_confidence(&mixed), 100); // 95 + 5*1 = 100 capped
    }
}
