use serde::{Deserialize, Serialize};

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
    /// Content management system (`WordPress`, Drupal, …).
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

/// Evidence attached to a `HeaderFinding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderEvidence {
    /// The relevant HTTP header name-value pair.
    pub header: Option<(String, String)>,
    /// An optional excerpt from the response body.
    pub body_excerpt: Option<String>,
}
