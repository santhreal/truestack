//! Security HTTP header auditing.
//!
//! Analyses response headers for missing or misconfigured security controls.
//! Checks include HSTS, CSP (with deep bypass analysis), X-Frame-Options,
//! X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.

use crate::fingerprints::contains_ignore_case;
use crate::{Finding, SecEvidence, Severity};

/// A check for a missing or misconfigured security header.
struct HeaderCheck {
    header: &'static str,
    missing_severity: Severity,
    missing_title: &'static str,
    missing_detail: &'static str,
    /// Optional: if the header is present, its value must contain this string.
    must_contain: Option<(&'static str, Severity, &'static str)>,
}

const CHECKS: &[HeaderCheck] = &[
    HeaderCheck {
        header: "strict-transport-security",
        missing_severity: Severity::Medium,
        missing_title: "Missing HSTS header",
        missing_detail: "Strict-Transport-Security not set  -  browsers may downgrade to HTTP.",
        must_contain: Some(("max-age", Severity::Low, "HSTS missing max-age directive")),
    },
    HeaderCheck {
        header: "content-security-policy",
        missing_severity: Severity::Medium,
        missing_title: "Missing Content-Security-Policy",
        missing_detail: "CSP not set  -  XSS attacks are unmitigated at the browser level.",
        must_contain: None,
    },
    HeaderCheck {
        header: "x-frame-options",
        missing_severity: Severity::Low,
        missing_title: "Missing X-Frame-Options",
        missing_detail: "X-Frame-Options not set  -  clickjacking attacks possible. Use CSP frame-ancestors if CSP is present.",
        must_contain: None,
    },
    HeaderCheck {
        header: "x-content-type-options",
        missing_severity: Severity::Low,
        missing_title: "Missing X-Content-Type-Options",
        missing_detail: "X-Content-Type-Options: nosniff not set  -  MIME-sniffing attacks possible.",
        must_contain: Some(("nosniff", Severity::Low, "X-Content-Type-Options value is not 'nosniff'")),
    },
    HeaderCheck {
        header: "referrer-policy",
        missing_severity: Severity::Low,
        missing_title: "Missing Referrer-Policy",
        missing_detail: "Referrer-Policy not set  -  full URL may be sent to third parties in Referer header.",
        must_contain: None,
    },
    HeaderCheck {
        header: "permissions-policy",
        missing_severity: Severity::Low,
        missing_title: "Missing Permissions-Policy",
        missing_detail: "Permissions-Policy not set  -  browser features (camera, microphone, etc.) not explicitly restricted.",
        must_contain: None,
    },
    HeaderCheck {
        header: "cross-origin-embedder-policy",
        missing_severity: Severity::Low,
        missing_title: "Missing Cross-Origin-Embedder-Policy (COEP)",
        missing_detail: "COEP not set  -  Cross-Origin XS-Leaks and Spectre attacks may be possible.",
        must_contain: None,
    },
    HeaderCheck {
        header: "cross-origin-opener-policy",
        missing_severity: Severity::Low,
        missing_title: "Missing Cross-Origin-Opener-Policy (COOP)",
        missing_detail: "COOP not set  -  Cross-Origin window reference leaks possible.",
        must_contain: None,
    },
    HeaderCheck {
        header: "cross-origin-resource-policy",
        missing_severity: Severity::Low,
        missing_title: "Missing Cross-Origin-Resource-Policy (CORP)",
        missing_detail: "CORP not set  -  Unintentional cross-origin resource sharing possible.",
        must_contain: None,
    },
    HeaderCheck {
        header: "cache-control",
        missing_severity: Severity::Low,
        missing_title: "Missing Cache-Control Header",
        missing_detail: "Cache-Control not set  -  sensitive pages might be cached downstream.",
        must_contain: None,
    },
];

/// CDN/cloud domains commonly used to bypass CSP via JSONP or script hosting.
const CSP_BYPASS_DOMAINS: &[(&str, &str)] = &[
    (
        "cdn.jsdelivr.net",
        "jsDelivr CDN  -  JSONP/arbitrary script endpoint",
    ),
    ("unpkg.com", "unpkg CDN  -  arbitrary npm package hosting"),
    ("cdnjs.cloudflare.com", "cdnjs  -  AngularJS JSONP bypass"),
    (
        "ajax.googleapis.com",
        "Google Ajax CDN  -  Angular JS CSP bypass",
    ),
    (
        "www.googleapis.com",
        "Google APIs  -  OAuth redirect bypass",
    ),
    ("accounts.google.com", "Google Accounts  -  OAuth JSONP"),
    ("apis.google.com", "Google APIs  -  JSONP bypass"),
    ("storage.googleapis.com", "GCS  -  arbitrary file hosting"),
    ("*.s3.amazonaws.com", "S3  -  attacker-writable buckets"),
    (
        "*.blob.core.windows.net",
        "Azure Blob  -  arbitrary file hosting",
    ),
    (
        "*.cloudfront.net",
        "CloudFront  -  CNAME to attacker bucket",
    ),
    ("*.github.io", "GitHub Pages  -  attacker-controlled origin"),
    ("*.vercel.app", "Vercel  -  attacker deployable"),
    ("*.netlify.app", "Netlify  -  attacker deployable"),
    ("*.pages.dev", "Cloudflare Pages  -  attacker deployable"),
];

/// Headers that leak implementation details and should be removed.
const LEAKY_HEADERS: &[(&str, &str, &str)] = &[
    (
        "x-powered-by",
        "X-Powered-By header leaks server technology",
        "X-Powered-By discloses tech stack to attackers. Remove this header.",
    ),
    (
        "server",
        "Server header leaks version info",
        "Server header may expose software version. Consider suppressing or genericising.",
    ),
    (
        "x-aspnet-version",
        "X-AspNet-Version leaks framework version",
        "X-AspNet-Version header exposes .NET version. Suppress in IIS config.",
    ),
    (
        "x-aspnetmvc-version",
        "X-AspNetMvc-Version leaks framework version",
        "X-AspNetMvc-Version header exposes MVC version. Suppress in Global.asax.",
    ),
    (
        "x-generator",
        "X-Generator leaks framework/CMS version",
        "X-Generator header exposes CMS version. Suppress to hide stack details.",
    ),
    (
        "via",
        "Via header exposes proxy chain",
        "Via header leaks internal proxy chains and names. Mask or remove.",
    ),
    (
        "x-version",
        "X-Version leaks software version",
        "X-Version header exposes exact software version to attackers. Remove this header.",
    ),
];

/// Audit HTTP response headers for security misconfigurations.
///
/// Returns a list of [`Finding`]s describing missing headers,
/// CSP bypass opportunities, and information-leaking headers.
#[allow(clippy::too_many_lines)] // Single linear audit: header checks, CSP analysis, leaky headers.
pub fn audit<K: AsRef<str>, V: AsRef<str>>(headers: &[(K, V)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // ── Missing / misconfigured security headers ─────────────────────────
    for check in CHECKS {
        let found = headers
            .iter()
            .find(|(k, _)| k.as_ref().eq_ignore_ascii_case(check.header));
        match found {
            None => {
                if let Some(f) = Finding::builder("truestack", "?", check.missing_severity)
                    .title(check.missing_title)
                    .detail(check.missing_detail)
                    .tag("headers")
                    .tag("security-headers")
                    .build_or_log()
                {
                    findings.push(f);
                }
            }
            Some((_, val)) => {
                let val_str = val.as_ref();
                if let Some((must, sev, title)) = check.must_contain {
                    if !contains_ignore_case(val_str, must) {
                        if let Some(f) = Finding::builder("truestack", "?", sev)
                            .title(title)
                            .detail(format!("{} value: '{}'", check.header, val_str))
                            .tag("headers")
                            .tag("security-headers")
                            .evidence(SecEvidence::HttpResponse {
                                status: 200,
                                headers: vec![(
                                    check.header.to_string().into(),
                                    val_str.to_string().into(),
                                )],
                                body_excerpt: None,
                            })
                            .build_or_log()
                        {
                            findings.push(f);
                        }
                    }
                }
            }
        }
    }

    // ── CSP deep analysis ────────────────────────────────────────────────
    let csp_headers = headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case("content-security-policy"));

    for (_, csp_val) in csp_headers {
        let csp_str = csp_val.as_ref();
        let csp_evidence = || SecEvidence::HttpResponse {
            status: 200,
            headers: vec![(
                "Content-Security-Policy".to_string().into(),
                csp_str.to_string().into(),
            )],
            body_excerpt: None,
        };

        // unsafe-inline in script-src
        if contains_ignore_case(csp_str, "'unsafe-inline'")
            && contains_ignore_case(csp_str, "script-src")
        {
            if let Some(f) = Finding::builder("truestack", "?", Severity::Medium)
                .title("CSP: unsafe-inline in script-src  -  XSS mitigation defeated")
                .detail(
                    "Content-Security-Policy includes 'unsafe-inline' for scripts. \
                         Inline script execution is permitted, completely negating CSP's \
                         primary XSS defence. Remove unsafe-inline and use nonces or hashes.",
                )
                .tag("headers")
                .tag("csp")
                .tag("xss")
                .evidence(csp_evidence())
                .build_or_log()
            {
                findings.push(f);
            }
        }

        // unsafe-eval
        if contains_ignore_case(csp_str, "'unsafe-eval'") {
            if let Some(f) = Finding::builder("truestack", "?", Severity::Low)
                .title("CSP: unsafe-eval in script-src")
                .detail(
                    "Content-Security-Policy includes 'unsafe-eval'. \
                         eval(), Function(), and setTimeout(string) are permitted, \
                         widening the XSS attack surface. Remove unsafe-eval.",
                )
                .tag("headers")
                .tag("csp")
                .evidence(csp_evidence())
                .build_or_log()
            {
                findings.push(f);
            }
        }

        // Wildcard in script-src / default-src
        let has_wildcard = csp_str.split(';').any(|directive| {
            let parts: Vec<_> = directive.split_whitespace().collect();
            if parts.is_empty() {
                return false;
            }
            let directive_name = parts[0];
            let is_script_src = directive_name.eq_ignore_ascii_case("script-src")
                || (directive_name.eq_ignore_ascii_case("default-src")
                    && !contains_ignore_case(csp_str, "script-src"));
            is_script_src && (parts.contains(&"*") || parts.contains(&"'*'"))
        });

        if has_wildcard {
            if let Some(f) = Finding::builder("truestack", "?", Severity::High)
                    .title("CSP: wildcard (*) in script-src  -  policy is trivially bypassable")
                    .detail(
                        "A wildcard host source in script-src allows loading scripts from any domain. \
                         CSP provides no meaningful XSS protection. Restrict to specific trusted origins.",
                    )
                    .tag("headers").tag("csp").tag("xss")
                    .evidence(csp_evidence()).build_or_log() { findings.push(f); }
        }

        // Known CSP bypass domains
        for (domain, reason) in CSP_BYPASS_DOMAINS {
            let match_domain = domain.trim_start_matches("*.");
            if contains_ignore_case(csp_str, match_domain) {
                if let Some(f) = Finding::builder("truestack", "?", Severity::Medium)
                    .title(format!("CSP bypass: {domain} in script-src"))
                    .detail(format!(
                        "CSP allows scripts from '{domain}'  -  {reason}. \
                             Attackers can load malicious scripts from this trusted origin \
                             to bypass CSP-based XSS protections.",
                    ))
                    .tag("headers")
                    .tag("csp")
                    .tag("xss")
                    .evidence(csp_evidence())
                    .build_or_log()
                {
                    findings.push(f);
                }
                break; // one bypass domain per CSP is enough
            }
        }

        // Missing base-uri
        if !contains_ignore_case(csp_str, "base-uri") {
            if let Some(f) = Finding::builder("truestack", "?", Severity::Low)
                    .title("CSP: missing base-uri directive")
                    .detail(
                        "CSP does not include a base-uri directive. If an attacker can inject a \
                         <base href> tag, all relative script/link URLs become attacker-controlled  -  \
                         bypassing script-src restrictions. Add base-uri 'self'.",
                    )
                    .tag("headers").tag("csp")
                    .evidence(csp_evidence()).build_or_log() { findings.push(f); }
        }
    }

    // ── Leaky headers ────────────────────────────────────────────────────
    for (header, title, detail) in LEAKY_HEADERS {
        if let Some((_, val)) = headers
            .iter()
            .find(|(k, _)| k.as_ref().eq_ignore_ascii_case(header))
        {
            let val_str = val.as_ref();
            if !val_str.trim().is_empty() {
                if let Some(f) = Finding::builder("truestack", "?", Severity::Info)
                    .title((*title).to_string())
                    .detail((*detail).to_string())
                    .tag("headers")
                    .tag("information-disclosure")
                    .evidence(SecEvidence::HttpResponse {
                        status: 200,
                        headers: vec![(header.to_string().into(), val_str.to_string().into())],
                        body_excerpt: None,
                    })
                    .build_or_log()
                {
                    findings.push(f);
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_hsts() {
        let empty_headers: &[(&str, &str)] = &[];
        let findings = audit(empty_headers);
        assert!(
            findings.iter().any(|f| f.title().contains("HSTS")),
            "should flag missing HSTS"
        );
    }

    #[test]
    fn unsafe_inline_csp() {
        let headers = vec![("Content-Security-Policy", "script-src 'unsafe-inline'")];
        let findings = audit(&headers);
        assert!(
            findings.iter().any(|f| f.title().contains("unsafe-inline")),
            "should flag unsafe-inline in CSP"
        );
    }

    #[test]
    fn csp_bypass_jsdelivr() {
        let headers = vec![("Content-Security-Policy", "script-src cdn.jsdelivr.net")];
        let findings = audit(&headers);
        assert!(
            findings.iter().any(|f| f.title().contains("jsdelivr")),
            "should flag jsdelivr as CSP bypass"
        );
    }
    #[test]
    fn leaky_server_header() {
        let headers = vec![("Server", "Apache/2.4.41")];
        let findings = audit(&headers);
        assert!(
            findings.iter().any(|f| f.title().contains("Server header")),
            "should flag leaky Server header"
        );
    }
}
