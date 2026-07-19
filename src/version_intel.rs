//! Version intelligence  -  backport-aware version assessment.
//!
//! Most fingerprinting tools report the version string at face value and
//! let users feed it into a CVE database.  This is **dangerously wrong**
//! for any target running a distribution that backports security patches
//! (Debian, Ubuntu, RHEL, Amazon Linux, SUSE, …).
//!
//! When Apache reports `2.4.41` on Ubuntu, the code may contain every fix
//! through `2.4.59`  -  the version string never changes but the actual
//! vulnerability surface is entirely different.
//!
//! This module provides [`assess`] which takes detected technologies and
//! raw headers, detects the underlying OS distribution, and annotates
//! each version with a [`VersionReliability`] rating so downstream
//! consumers (CVE correlation, pentest reports, gossan scanners) know
//! how much to trust the number.

use crate::Technology;
use serde::{Deserialize, Serialize};

// ─── OS context detection ────────────────────────────────────────────────────

/// Detected operating system or distribution context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsContext {
    /// Distribution name (e.g. "Ubuntu", "Debian", "RHEL").
    pub distro: Distro,
    /// Optional distribution version hint (e.g. "22.04", "bookworm").
    pub version_hint: Option<String>,
    /// Where the OS hint was found.
    pub source: OsSource,
}

/// Known Linux distributions and their patch strategies.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Distro {
    /// Debian  -  aggressive backporter, version strings frozen at upload.
    Debian,
    /// Ubuntu  -  inherits Debian backporting + own security team.
    Ubuntu,
    /// Red Hat Enterprise Linux  -  backports for 10+ year lifecycle.
    Rhel,
    /// CentOS / CentOS Stream  -  RHEL-derived, same backporting.
    CentOs,
    /// Rocky Linux  -  RHEL-compatible, same backporting.
    Rocky,
    /// AlmaLinux  -  RHEL-compatible, same backporting.
    Alma,
    /// Amazon Linux  -  AWS's RHEL-derived distro, backports aggressively.
    AmazonLinux,
    /// SUSE Linux Enterprise  -  backports for enterprise lifecycle.
    Suse,
    /// openSUSE  -  community SUSE, Tumbleweed rolls, Leap backports.
    OpenSuse,
    /// Alpine Linux  -  uses apk, generally tracks upstream closely.
    Alpine,
    /// Arch Linux  -  rolling release, versions match upstream.
    Arch,
    /// Fedora  -  upstream-first, versions generally match.
    Fedora,
    /// FreeBSD  -  ports system, mixed backporting.
    FreeBsd,
    /// Windows Server  -  patches via Windows Update, version strings unreliable.
    Windows,
    /// Generic / Unknown.
    Unknown,
}

impl Distro {
    /// Returns `true` if this distribution is known to backport security
    /// patches without bumping the upstream version number.
    #[must_use]
    pub const fn backports_patches(self) -> bool {
        matches!(
            self,
            Self::Debian
                | Self::Ubuntu
                | Self::Rhel
                | Self::CentOs
                | Self::Rocky
                | Self::Alma
                | Self::AmazonLinux
                | Self::Suse
                | Self::OpenSuse
        )
    }

    /// Returns `true` if this distribution uses rolling releases where
    /// the version number generally tracks upstream.
    #[must_use]
    pub const fn is_rolling(self) -> bool {
        matches!(self, Self::Arch | Self::Fedora | Self::Alpine)
    }
}

/// Where the OS context was inferred from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsSource {
    /// Extracted from the `Server` header parenthetical (e.g. "(Ubuntu)").
    ServerHeader,
    /// Extracted from `X-Powered-By` version suffix (e.g. "PHP/7.4.3-4ubuntu2").
    PoweredByHeader,
    /// Detected from truestack's technology fingerprinting (OS rules).
    Fingerprint,
    /// Inferred from version numbering patterns.
    VersionPattern,
}

// ─── Version assessment ──────────────────────────────────────────────────────

/// How reliable the reported version number is for CVE assessment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VersionReliability {
    /// Version number is meaningless  -  distro backports make it unreliable.
    /// **Do not use for CVE correlation without behavioral verification.**
    Unreliable,
    /// Version may be partially reliable but backports are likely.
    /// Treat CVE matches as low-confidence without further evidence.
    Suspect,
    /// Version is likely accurate  -  rolling distro or no backporting detected.
    Likely,
    /// No version was extracted  -  nothing to assess.
    NoVersion,
}

/// A single technology's version assessment with backport intelligence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionAssessment {
    /// Technology name.
    pub technology: String,
    /// The reported version string (as extracted from headers).
    pub reported_version: Option<String>,
    /// Detected OS/distribution context, if any.
    pub os_context: Option<OsContext>,
    /// Whether backported patches are likely applied.
    pub backport_likely: bool,
    /// How much to trust the version number for CVE correlation.
    pub reliability: VersionReliability,
    /// Human-readable advisory explaining the assessment.
    pub advisory: String,
}

/// Assess detected technologies for backport-aware version reliability.
///
/// Takes the technologies detected by [`crate::fingerprints::detect`] and
/// raw response headers, and produces a [`VersionAssessment`] for each
/// technology that has a version string.
///
/// Technologies without a version are included with
/// [`VersionReliability::NoVersion`] for completeness.
#[must_use]
pub fn assess_headers<K: AsRef<str>, V: AsRef<str>>(
    technologies: &[Technology],
    headers: &[(K, V)],
) -> Vec<VersionAssessment> {
    let os = detect_os(headers);

    technologies
        .iter()
        .map(|tech| {
            let version = tech.version.as_deref();
            match version {
                None => VersionAssessment {
                    technology: tech.name.clone(),
                    reported_version: None,
                    os_context: os.clone(),
                    backport_likely: false,
                    reliability: VersionReliability::NoVersion,
                    advisory: "no version extracted  -  cannot assess".to_string(),
                },
                Some(ver) => assess_single(&tech.name, ver, &os),
            }
        })
        .collect()
}

/// Mutate `technologies` in place with backport-aware confidence scoring.
pub fn assess<K: AsRef<str>, V: AsRef<str>>(
    technologies: &mut Vec<Technology>,
    headers: &[(K, V)],
) {
    let assessments = assess_headers(technologies, headers);
    for tech in technologies.iter_mut() {
        if let Some(a) = assessments.iter().find(|a| a.technology == tech.name) {
            tech.confidence = match a.reliability {
                VersionReliability::Unreliable => tech.confidence.saturating_sub(20).max(20),
                VersionReliability::Likely => (tech.confidence + 5).min(100),
                _ => tech.confidence,
            };
        }
    }
}

/// Detect the OS/distribution from response headers.
#[must_use]
pub fn detect_os<K: AsRef<str>, V: AsRef<str>>(headers: &[(K, V)]) -> Option<OsContext> {
    // 1. Check Server header parenthetical: "Apache/2.4.41 (Ubuntu)"
    if let Some(ctx) = headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case("server"))
        .find_map(|(_, v)| parse_os_from_parenthetical(v.as_ref()))
    {
        return Some(ctx);
    }

    // 2. Check X-Powered-By for distro version suffixes
    if let Some(ctx) = headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case("x-powered-by"))
        .find_map(|(_, v)| parse_os_from_version_suffix(v.as_ref()))
    {
        return Some(ctx);
    }

    // 3. Check Server header for distro-specific patterns
    if let Some(ctx) = headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case("server"))
        .find_map(|(_, v)| parse_os_from_server_string(v.as_ref()))
    {
        return Some(ctx);
    }

    None
}

/// Assess a single technology+version pair against OS context.
fn assess_single(tech_name: &str, version: &str, os: &Option<OsContext>) -> VersionAssessment {
    let (backport_likely, reliability, advisory) = match os {
        Some(ctx) if ctx.distro.backports_patches() => {
            let distro_name = format!("{:?}", ctx.distro);
            (
                true,
                VersionReliability::Unreliable,
                format!(
                    "{tech_name} {version} reported on {distro_name}  -  \
                     this distribution backports security patches without \
                     changing the upstream version number. The actual \
                     vulnerability surface may be entirely different from \
                     what CVE databases report for version {version}. \
                     Do NOT use this version for CVE correlation without \
                     behavioral verification or package-level inspection \
                     (e.g. dpkg -l, rpm -q)."
                ),
            )
        }
        Some(ctx) if ctx.distro.is_rolling() => (
            false,
            VersionReliability::Likely,
            format!(
                "{tech_name} {version} on {:?} (rolling release)  -  \
                 version number likely tracks upstream. \
                 CVE correlation is more reliable but verify with \
                 package manager.",
                ctx.distro
            ),
        ),
        Some(ctx) => {
            // Known OS but not a known backporter (FreeBSD, Windows, etc.)
            (
                false,
                VersionReliability::Suspect,
                format!(
                    "{tech_name} {version} on {:?}  -  \
                     patch strategy is uncertain for this platform. \
                     Treat CVE matches with moderate confidence.",
                    ctx.distro
                ),
            )
        }
        None => {
            // Check if the version string itself contains distro hints
            if let Some(inline_ctx) = parse_os_from_version_suffix(version) {
                if inline_ctx.distro.backports_patches() {
                    return VersionAssessment {
                        technology: tech_name.to_string(),
                        reported_version: Some(version.to_string()),
                        os_context: Some(inline_ctx.clone()),
                        backport_likely: true,
                        reliability: VersionReliability::Unreliable,
                        advisory: format!(
                            "{tech_name} {version}  -  version string contains \
                             {:?} packaging suffix, confirming backported patches. \
                             Upstream version number is meaningless for CVE assessment.",
                            inline_ctx.distro
                        ),
                    };
                }
            }

            (
                false,
                VersionReliability::Suspect,
                format!(
                    "{tech_name} {version}  -  no OS context detected. \
                     Version may be accurate or may be backported. \
                     Treat CVE matches with moderate confidence."
                ),
            )
        }
    };

    VersionAssessment {
        technology: tech_name.to_string(),
        reported_version: Some(version.to_string()),
        os_context: os.clone(),
        backport_likely,
        reliability,
        advisory,
    }
}

// ─── Parsing helpers ─────────────────────────────────────────────────────────

/// Distro patterns to search for in parenthetical server strings.
const DISTRO_PATTERNS: &[(&str, Distro)] = &[
    ("ubuntu", Distro::Ubuntu),
    ("debian", Distro::Debian),
    ("red hat", Distro::Rhel),
    ("redhat", Distro::Rhel),
    ("rhel", Distro::Rhel),
    ("centos", Distro::CentOs),
    ("rocky", Distro::Rocky),
    ("almalinux", Distro::Alma),
    ("amzn", Distro::AmazonLinux),
    ("amazon", Distro::AmazonLinux),
    ("suse", Distro::Suse),
    ("opensuse", Distro::OpenSuse),
    ("alpine", Distro::Alpine),
    ("arch", Distro::Arch),
    ("fedora", Distro::Fedora),
    ("freebsd", Distro::FreeBsd),
    ("win32", Distro::Windows),
    ("win64", Distro::Windows),
    ("windows", Distro::Windows),
    ("unix", Distro::Unknown), // "Unix" is too generic
];

/// Parse OS from "Server: Apache/2.4.41 (Ubuntu 22.04)".
fn parse_os_from_parenthetical(server: &str) -> Option<OsContext> {
    let paren_start = server.find('(')?;
    let paren_end = server.find(')')?;
    if paren_end <= paren_start {
        return None;
    }
    let content = &server[paren_start + 1..paren_end];
    let lower = content.to_ascii_lowercase();

    for &(pattern, distro) in DISTRO_PATTERNS {
        if lower.contains(pattern) && distro != Distro::Unknown {
            // Try to extract version hint
            let version_hint = extract_distro_version(content, pattern);
            return Some(OsContext {
                distro,
                version_hint,
                source: OsSource::ServerHeader,
            });
        }
    }
    None
}

/// Parse OS from version suffixes like "PHP/7.4.3-4ubuntu2.18" or
/// "7.4.3-1+deb11u1".
fn parse_os_from_version_suffix(value: &str) -> Option<OsContext> {
    let lower = value.to_ascii_lowercase();

    // Debian: "1+deb11u1", "2.4.54-1~deb12u1"
    if lower.contains("+deb") || lower.contains("~deb") || lower.contains(".deb") {
        let version_hint = extract_deb_version(&lower);
        return Some(OsContext {
            distro: Distro::Debian,
            version_hint,
            source: OsSource::PoweredByHeader,
        });
    }

    // Ubuntu: "4ubuntu2.18", "-ubuntu"
    if lower.contains("ubuntu") {
        return Some(OsContext {
            distro: Distro::Ubuntu,
            version_hint: None,
            source: OsSource::PoweredByHeader,
        });
    }

    // RHEL/CentOS: ".el7", ".el8", ".el9"
    if lower.contains(".el") {
        let version_hint = lower.find(".el").and_then(|i| {
            let rest = &lower[i + 3..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                None
            } else {
                Some(format!("EL{digits}"))
            }
        });
        return Some(OsContext {
            distro: Distro::Rhel,
            version_hint,
            source: OsSource::VersionPattern,
        });
    }

    // Amazon Linux: ".amzn2", ".amzn2023"
    if lower.contains(".amzn") || lower.contains("amzn") {
        return Some(OsContext {
            distro: Distro::AmazonLinux,
            version_hint: None,
            source: OsSource::VersionPattern,
        });
    }

    // Alpine: "-r0", "-r1" suffix pattern with "alpine" somewhere
    if lower.contains("alpine") {
        return Some(OsContext {
            distro: Distro::Alpine,
            version_hint: None,
            source: OsSource::VersionPattern,
        });
    }

    None
}

/// Parse OS from server string without parenthesizes (e.g. "Apache/2.4.41 Ubuntu").
fn parse_os_from_server_string(server: &str) -> Option<OsContext> {
    let lower = server.to_ascii_lowercase();
    for &(pattern, distro) in DISTRO_PATTERNS {
        if distro != Distro::Unknown && lower.contains(pattern) {
            return Some(OsContext {
                distro,
                version_hint: None,
                source: OsSource::ServerHeader,
            });
        }
    }
    None
}

/// Extract a numeric version hint after a distro keyword.
fn extract_distro_version(content: &str, _pattern: &str) -> Option<String> {
    // Look for version numbers after the distro name
    let mut chars = content.chars().peekable();
    let mut found_digit_start = false;
    let mut version = String::new();

    for ch in &mut chars {
        if ch.is_ascii_digit() {
            found_digit_start = true;
            version.push(ch);
        } else if found_digit_start && (ch == '.' || ch == '-') {
            version.push(ch);
        } else if found_digit_start {
            break;
        }
    }

    let trimmed = version
        .trim_end_matches(|c: char| !c.is_ascii_digit())
        .to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Extract Debian version from patterns like "+deb11u1".
fn extract_deb_version(lower: &str) -> Option<String> {
    // Find "deb" followed by digits
    if let Some(idx) = lower.find("deb") {
        let rest = &lower[idx + 3..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return Some(format!("Debian {digits}"));
        }
    }
    None
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
