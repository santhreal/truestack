//! # truestack
//!
//! Security-aware technology fingerprinting for web servers.
//!
//! Unlike traditional fingerprinting tools that report what the version string
//! claims, `truestack` is designed to determine the **true** security posture
//! of a target — including detection of backported patches, behavioural
//! differential probing, and CVE correlation.
//!
//! ## Core capabilities
//!
//! - **YAML-driven rule engine** — signal-based detection from HTTP headers,
//!   response bodies, and cookies. Ship your own rules or use the embedded set.
//! - **Security header auditing** — checks for HSTS, CSP, X-Frame-Options and
//!   friends, including deep CSP bypass analysis (15 known bypass domains).
//! - **Favicon hashing** — Shodan-compatible MurmurHash3 for cross-service
//!   pivot (`http.favicon.hash:{value}`).
//! - **Version extraction** — parses `Server`, `X-Powered-By`, and other
//!   headers to extract semver-style version strings.
//!
//! ## Quick start
//!
//! ```rust
//! use truestack::fingerprints;
//!
//! let headers = vec![
//!     ("Server".to_string(), "nginx/1.21.0".to_string()),
//! ];
//! let techs = fingerprints::detect(&headers, "");
//! assert_eq!(techs[0].name, "nginx");
//! assert_eq!(techs[0].version.as_deref(), Some("1.21.0"));
//! ```

/// Local HTTP compatibility shim backed by `stealthreq`.
pub mod reqwest {
    pub use stealthreq::http::*;
}

pub mod fingerprints;
pub mod security_headers;

pub mod favicon;

pub mod html;

use serde::{Deserialize, Serialize};

// ─── Core types ──────────────────────────────────────────────────────────────

/// A detected technology fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    /// Technology name (e.g. "nginx", "Cloudflare", "Next.js").
    pub name: String,
    /// Extracted version string, if available.
    pub version: Option<String>,
    /// Broad technology category.
    pub category: TechCategory,
    /// Confidence score in the range 0–100.
    pub confidence: u8,
}

/// Broad category for a detected technology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TechCategory {
    /// Content management system (WordPress, Drupal, …).
    Cms,
    /// Web framework (Next.js, Laravel, Spring, …).
    Framework,
    /// Programming language runtime (PHP, Python, …).
    Language,
    /// HTTP server software (nginx, Apache, IIS, …).
    Server,
    /// Content-delivery network (Cloudflare, Fastly, …).
    Cdn,
    /// Analytics and tracking (Google Analytics, …).
    Analytics,
    /// Security products (WAF, anti-bot, …).
    Security,
    /// Database engines.
    Database,
    /// Operating system.
    Os,
    /// Anything that does not fit the categories above.
    Other,
}

// ─── Security header finding types ───────────────────────────────────────────

/// Severity level for a security finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational — no direct risk, but worth noting.
    Info,
    /// Low-severity — minor hardening gap.
    Low,
    /// Medium-severity — exploitable under certain conditions.
    Medium,
    /// High-severity — directly exploitable weakness.
    High,
    /// Critical — active vulnerability.
    Critical,
}

/// A security-relevant finding produced by header or configuration analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderFinding {
    /// Short human-readable title.
    pub title: String,
    /// Detailed explanation with remediation guidance.
    pub detail: String,
    /// Finding severity.
    pub severity: Severity,
    /// Tags for filtering and grouping.
    pub tags: Vec<String>,
    /// Optional evidence (header name + value, body excerpt, etc.).
    pub evidence: Option<HeaderEvidence>,
}

impl Severity {
    /// Returns the severity level as a lowercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Evidence attached to a [`HeaderFinding`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderEvidence {
    /// The relevant HTTP header name-value pair.
    pub header: Option<(String, String)>,
    /// An optional excerpt from the response body.
    pub body_excerpt: Option<String>,
}
