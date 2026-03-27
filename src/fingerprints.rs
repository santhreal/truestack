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
#[derive(Debug, Deserialize)]
struct Rule {
    /// Display name for the technology.
    name: String,
    /// Optional header whose value contains the version string.
    version_header: Option<String>,
    /// Broad technology category.
    category: TechCategory,
    /// One or more signals — a match on **any** signal triggers the rule.
    signals: Vec<SignalDef>,
}

/// Where to look for a signal match.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum SignalDef {
    /// Match an HTTP response header key/value pair.
    #[serde(rename = "header")]
    Header { key: String, value: String },
    /// Match a substring in the response body.
    #[serde(rename = "body")]
    Body { value: String },
    /// Match a substring in a `Set-Cookie` header.
    #[serde(rename = "cookie")]
    Cookie { value: String },
}

/// Top-level YAML structure wrapping the rule list.
#[derive(Debug, Deserialize)]
struct RuleEngine {
    rules: Vec<Rule>,
}

static ENGINE: Lazy<RuleEngine> = Lazy::new(|| {
    let yaml = include_str!("rules.yaml");
    serde_yaml::from_str(yaml)
        .expect("failed to parse embedded rules.yaml — this is a build-time bug")
});

/// Detect technologies from raw HTTP response data.
///
/// `headers` is a slice of `(name, value)` pairs exactly as received.
/// `body` is the decoded response body (UTF-8 or best-effort).
///
/// Returns a [`Vec<Technology>`] with one entry per matched rule.
pub fn detect<K: AsRef<str>, V: AsRef<str>>(headers: &[(K, V)], body: &str) -> Vec<Technology> {
    let body_lower = body.to_lowercase();
    let cookies: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.as_ref())
        .collect();

    ENGINE
        .rules
        .iter()
        .filter_map(|rule| {
            let hit = rule
                .signals
                .iter()
                .any(|sig| matches_signal(sig, headers, &body_lower, &cookies));
            if !hit {
                return None;
            }

            let version = rule.version_header.as_ref().and_then(|vh| {
                headers
                    .iter()
                    .find(|(k, _)| k.as_ref().eq_ignore_ascii_case(vh))
                    .and_then(|(_, v)| extract_version(v.as_ref()))
            });

            Some(Technology {
                name: rule.name.clone(),
                version,
                category: rule.category.clone(),
                confidence: 80,
            })
        })
        .collect()
}

/// Check whether a single signal matches the given response data.
fn matches_signal<K: AsRef<str>, V: AsRef<str>>(
    sig: &SignalDef,
    headers: &[(K, V)],
    body_lower: &str,
    cookies: &[&str],
) -> bool {
    match sig {
        SignalDef::Header { key, value } => headers.iter().any(|(k, v)| {
            k.as_ref().eq_ignore_ascii_case(key)
                && (value.is_empty() || v.as_ref().to_lowercase().contains(&value.to_lowercase()))
        }),
        SignalDef::Body { value } => body_lower.contains(&value.to_lowercase()),
        SignalDef::Cookie { value } => cookies
            .iter()
            .any(|c| c.to_lowercase().contains(&value.to_lowercase())),
    }
}

/// Best-effort version string extraction from a header value.
///
/// Handles formats like `nginx/1.21.0`, `Apache/2.4.41 (Unix)`,
/// `Microsoft-IIS/10.0`.
pub fn extract_version(header_val: &str) -> Option<String> {
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
        assert_eq!(extract_version("nginx/1.21.0"), Some("1.21.0".to_string()));
        assert_eq!(
            extract_version("Apache/2.4.41 (Unix) OpenSSL/1.1.1d"),
            Some("2.4.41".to_string())
        );
        assert_eq!(
            extract_version("Microsoft-IIS/10.0"),
            Some("10.0".to_string())
        );
    }
}
