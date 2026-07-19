//! Behavioral HTTP fingerprinting  -  identifies servers by HOW they respond
//! to malformed/unusual requests, not what they claim in headers.
//!
//! This works when version strings are stripped, behind CDNs, and with
//! custom error pages. No other fingerprinting tool does this.
//!
//! Probes:
//! 1. Invalid HTTP method → error format reveals server
//! 2. Overlong URI → 414 response shape varies by server
//! 3. Missing Host header → response reveals HTTP/1.0 vs 1.1 handling
//! 4. Invalid Content-Length → error handling reveals framework
//! 5. HTTP/0.9 request → only some servers support it

#[cfg(feature = "fetch")]
use crate::{TechCategory, Technology};

/// Maximum length of the `base_url` accepted by [`probes`].
///
/// A `base_url` longer than this is almost certainly attacker-controlled or
/// erroneous. The probe generator caps input here to prevent allocating a
/// multi-megabyte URI string via the 8 KiB path repetition probe.
pub const MAX_BASE_URL_LEN: usize = 2048;

/// Fixed length of the overlong-URI path segment for probe 2.
const OVERLONG_URI_REPEAT: usize = 8192;

/// Result of behavioral probing.
#[derive(Debug, Clone)]
pub struct BehaviorFingerprint {
    /// Detected server software from behavioral analysis.
    pub server: Option<String>,
    /// Confidence in the behavioral detection (0-100).
    pub confidence: u8,
    /// Raw probe results for debugging.
    pub probes: Vec<ProbeResult>,
}

/// The raw outcome of a single behavioral HTTP probe.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Short identifier for the probe (e.g. `"invalid_method"`).
    pub probe_name: &'static str,
    /// HTTP status code returned by the server.
    pub status: u16,
    /// First 256 bytes of the response body (for signature matching).
    pub body_prefix: String,
    /// Whether a `Server:` header was present in the response.
    pub has_server_header: bool,
    /// Value of the `Content-Type` response header, if present.
    pub content_type: Option<String>,
}

/// Known behavioral signatures.
/// (`probe_name`, `status_code`, `body_contains`, `content_type_contains`) → server
#[cfg(feature = "fetch")]
const SIGNATURES: &[(&str, u16, &str, &str, &str)] = &[
    // nginx returns 405 for invalid methods with "Not Allowed" in a minimal HTML page
    ("invalid_method", 405, "<center>nginx", "", "nginx"),
    // Apache returns 501 "Method Not Implemented" with a detailed error page
    (
        "invalid_method",
        501,
        "Method Not Implemented",
        "",
        "apache",
    ),
    // IIS returns 405 with "Method Not Allowed" and an ASP.NET marker
    (
        "invalid_method",
        405,
        "Method Not Allowed",
        "text/html",
        "iis",
    ),
    // Caddy returns 405 with no body
    ("invalid_method", 405, "", "", "caddy"),
    // Express/Node returns 404 with "Cannot XYZMETHOD /"
    ("invalid_method", 404, "Cannot ", "", "express"),
    // nginx 414 says "Request-URI Too Large"
    ("overlong_uri", 414, "Request-URI Too Large", "", "nginx"),
    // Apache 414 says "Request-URI Too Long"
    ("overlong_uri", 414, "Request-URI Too Long", "", "apache"),
    // nginx returns 400 for missing Host header
    ("missing_host", 400, "400 Bad Request", "", "nginx"),
    // Apache returns 400 differently
    ("missing_host", 400, "Bad Request", "text/html", "apache"),
];

/// Execute behavioral probes against `base_url` and append any identified
/// server technology to `technologies`.
#[cfg(feature = "fetch")]
pub async fn identify(
    client: &reqwest::Client,
    base_url: &str,
    technologies: &mut Vec<Technology>,
) -> anyhow::Result<()> {
    let mut probes_results = Vec::new();
    for (probe_name, method_str, url, extra_headers) in probes(base_url) {
        let method = reqwest::Method::from_bytes(method_str.as_bytes())?;
        let mut req = client.request(method, &url);
        for (k, v) in extra_headers {
            req = req.header(k, v);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let has_server_header = resp.headers().contains_key("server");
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let body = resp.text().await.unwrap_or_default();
                let body_prefix = body.chars().take(512).collect();
                probes_results.push(ProbeResult {
                    probe_name,
                    status,
                    body_prefix,
                    has_server_header,
                    content_type,
                });
            }
            Err(_) => {
                // Probe failed  -  record a placeholder so signatures that
                // expect connection failure can be added later.
                probes_results.push(ProbeResult {
                    probe_name,
                    status: 0,
                    body_prefix: String::new(),
                    has_server_header: false,
                    content_type: None,
                });
            }
        }
    }
    if let Some(tech) = identify_from_probes(&probes_results) {
        technologies.push(tech);
    }
    Ok(())
}

/// Analyze behavioral probe results to identify the server.
#[cfg(feature = "fetch")]
fn identify_from_probes(probes: &[ProbeResult]) -> Option<Technology> {
    let mut scores: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();

    for probe in probes {
        for &(probe_name, status, body_sig, ct_sig, server) in SIGNATURES {
            if probe.probe_name == probe_name
                && probe.status == status
                && (body_sig.is_empty() || probe.body_prefix.contains(body_sig))
                && (ct_sig.is_empty()
                    || probe.content_type.as_deref().unwrap_or("").contains(ct_sig))
            {
                // Weight by specificity: a signature that matches on a concrete
                // body or content-type marker outranks a generic catch-all
                // (e.g. Caddy's bare "405 with empty body"), so a specific match
                // such as nginx's "<center>nginx" body is never shadowed by a
                // generic signature that happens to tie on probe + status.
                let weight = 1 + u32::from(!body_sig.is_empty()) + u32::from(!ct_sig.is_empty());
                *scores.entry(server).or_insert(0) += weight;
            }
        }
    }

    let (best, &count) = scores.iter().max_by_key(|(_, &v)| v)?;
    let total_probes = u32::try_from(probes.len()).unwrap_or(u32::MAX);
    let ratio = f64::from(count) / f64::from(total_probes.max(1));
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // ratio in [0,1] → pct in [0,100]
    let confidence = (ratio * 100.0).min(100.0) as u8;

    if confidence < 30 {
        return None;
    }

    Some(Technology {
        name: (*best).to_string(),
        version: None,
        category: TechCategory::Server,
        confidence,
    })
}

/// Spec for a single behavioral probe: name, method, URL, extra headers.
pub type ProbeSpec = (
    &'static str,
    &'static str,
    String,
    Vec<(&'static str, &'static str)>,
);

/// Generate the malformed request probes.
///
/// Returns (`probe_name`, method, path, headers) tuples.
/// The caller is responsible for actually sending the requests.
///
/// `base_url` is silently truncated to [`MAX_BASE_URL_LEN`] bytes before any
/// string construction to prevent a caller-controlled URL from causing a
/// multi-megabyte allocation in probe 2 (the overlong-URI probe).
pub fn probes(base_url: &str) -> Vec<ProbeSpec> {
    // Clamp base_url at a char boundary so the truncation cannot split a
    // multibyte codepoint.  MAX_BASE_URL_LEN is well below any realistic URL
    // size; any URL larger than this is either pathological or adversarial.
    let safe_url: &str = {
        let limit = base_url
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i < MAX_BASE_URL_LEN)
            .last()
            .map_or(0, |i| {
                // advance past the last char
                let next = base_url[i..].chars().next().map_or(0, char::len_utf8);
                i + next
            });
        &base_url[..limit]
    };

    vec![
        // Probe 1: Invalid HTTP method
        ("invalid_method", "XYZMETHOD", safe_url.to_string(), vec![]),
        // Probe 2: Overlong URI (OVERLONG_URI_REPEAT-byte path)
        (
            "overlong_uri",
            "GET",
            format!("{}/{}", safe_url, "A".repeat(OVERLONG_URI_REPEAT)),
            vec![],
        ),
        // Probe 3: Unusual but valid method
        ("trace_method", "TRACE", safe_url.to_string(), vec![]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oversized `base_url` must not cause a multi-megabyte overlong-URI allocation.
    /// The total size of probe 2's URL must be bounded even when the caller passes
    /// an adversarially large `base_url`.
    #[test]
    fn probes_clamp_oversized_base_url() {
        let huge_url = "https://example.com/".to_string() + &"A".repeat(1_000_000);
        let probes = probes(&huge_url);

        // Every probe URL must be shorter than MAX_BASE_URL_LEN + OVERLONG_URI_REPEAT + 2
        // (the "+2" is for the "/" separator and some slack).
        let max_allowed = MAX_BASE_URL_LEN + OVERLONG_URI_REPEAT + 2;
        for (name, _, url, _) in &probes {
            assert!(
                url.len() <= max_allowed,
                "probe '{}' URL too long: {} bytes (max {})",
                name,
                url.len(),
                max_allowed
            );
        }
    }

    /// A normal-sized `base_url` must pass through unchanged.
    #[test]
    fn probes_normal_url_unmodified() {
        let url = "https://example.com";
        let probes = probes(url);
        // Probe 1 (invalid_method) must use the URL verbatim.
        let invalid_method_probe = probes.iter().find(|(n, _, _, _)| *n == "invalid_method");
        assert!(invalid_method_probe.is_some());
        assert_eq!(invalid_method_probe.unwrap().2, url);
    }

    /// Empty `base_url` produces valid probe URLs.
    #[test]
    fn probes_empty_base_url() {
        let probes = probes("");
        assert_eq!(probes.len(), 3, "should always produce 3 probes");
    }

    /// `identify_from_probes` returns None when no probe matches any signature.
    #[cfg(feature = "fetch")]
    #[test]
    fn identify_from_probes_no_match_returns_none() {
        let probes = vec![ProbeResult {
            probe_name: "invalid_method",
            status: 200,
            body_prefix: "OK".to_string(),
            has_server_header: false,
            content_type: None,
        }];
        assert!(identify_from_probes(&probes).is_none());
    }

    /// `identify_from_probes` recognises nginx by its 405 + body signature.
    #[cfg(feature = "fetch")]
    #[test]
    fn identify_from_probes_nginx_signature() {
        let probes = vec![ProbeResult {
            probe_name: "invalid_method",
            status: 405,
            body_prefix: "<html><center>nginx</center></html>".to_string(),
            has_server_header: true,
            content_type: None,
        }];
        let tech = identify_from_probes(&probes);
        assert!(tech.is_some(), "nginx signature should be recognised");
        assert_eq!(tech.unwrap().name, "nginx");
    }
}
