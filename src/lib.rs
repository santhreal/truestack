#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

//! # truestack  -  Security-aware technology fingerprinting
//!
//! Security-aware technology fingerprinting for web servers.
//!
//! Unlike traditional fingerprinting tools that report what the version string
//! claims, `truestack` is designed to determine the **true** security posture
//! of a target  -  including detection of backported patches, behavioural
//! differential probing, and CVE correlation.
//!
//! ## Core capabilities
//!
//! - **YAML-driven rule engine**  -  signal-based detection from HTTP headers,
//!   response bodies, and cookies. Ship your own rules or use the embedded set.
//! - **Security header auditing**  -  checks for HSTS, CSP, X-Frame-Options and
//!   friends, including deep CSP bypass analysis (15 known bypass domains).
//! - **Favicon hashing**  -  Shodan-compatible `MurmurHash3` for cross-service
//!   pivot (`http.favicon.hash:{value}`).
//! - **Version extraction**  -  parses `Server`, `X-Powered-By`, and other
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
//!
//! ## Safe defaults
//!
//! - **Input size:** No hard cap is enforced on caller-supplied header slices
//!   or body strings passed to `fingerprints::detect` / `security_headers::audit`.
//!   The optional `fetch` feature caps favicon downloads at
//!   `favicon::DEFAULT_FAVICON_LIMIT` (5 MiB). The behavior probing module
//!   silently truncates `base_url` to `behavior::MAX_BASE_URL_LEN` (2048 bytes)
//!   before constructing probe URLs.
//! - **Recursion depth:** No recursive algorithms are used; the TOML rule engine
//!   and all detection passes iterate linearly over flat rule lists and header
//!   slices with no recursive descent.
//! - **Outbound network:** The library core makes no outbound network calls.
//!   Network I/O is only performed when the caller explicitly passes a
//!   `reqwest::Client` to `favicon::fetch_hash` or `behavior::probes`
//!   (both gated on the `fetch` feature).
//! - **Process spawning:** No child processes are spawned anywhere in this crate.
//! - **Filesystem writes:** This crate never writes to the filesystem. The only
//!   filesystem reads are `RuleEngine::from_directory`, which is caller-initiated
//!   and reads `.toml` files from a path supplied by the caller.
//! - **Credential exposure:** No credentials are accepted, stored, or logged.
//!   The `reqwest::Client` passed by callers may carry authentication tokens, but
//!   this crate does not inspect, log, or forward those tokens beyond the
//!   HTTP requests the caller explicitly initiates.

/// Local HTTP compatibility shim backed by reqwest..
pub mod reqwest {
    pub use reqwest::*;
}

pub mod behavior;
pub mod favicon;
pub mod fingerprints;
pub mod html;
pub mod implied;
pub mod postprocess;
pub mod security_headers;
/// Shared technology and finding types.
pub mod types;
pub mod version_intel;
pub mod waf;

/// Re-export shared security finding types.
pub use secfinding::{Evidence as SecEvidence, Finding, Severity};
pub use types::{HeaderEvidence, TechCategory, Technology};
