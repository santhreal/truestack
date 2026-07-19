//! WAF detection via `wafrift-detect`.
//!
//! Thin integration layer that delegates WAF identification to the
//! [`wafrift_detect`] crate and converts results into truestack's
//! [`Technology`] type.

use crate::{TechCategory, Technology};

/// Detect the WAF protecting a target from response data.
///
/// Wraps [`wafrift_detect::detect`] and maps the result into a
/// [`Technology`] with the WAF's name, confidence score, and
/// `Security` category.
///
/// # Arguments
///
/// * `status`  -  HTTP response status code.
/// * `headers`  -  Response headers as `(name, value)` pairs.
/// * `body`  -  Raw response body bytes (only the first 4 KiB are inspected).
#[must_use]
pub fn detect(status: u16, headers: &[(String, String)], body: &[u8]) -> Option<Technology> {
    let detected = wafrift_detect::detect(status, headers, body)
        .into_iter()
        .next()?;

    // Guard against NaN/infinity before the cast: `as u8` on a non-finite
    // f64 is defined to produce 0, but a NaN confidence is almost certainly
    // a bug in wafrift-detect rather than "zero confidence", so clamp
    // explicitly rather than silently losing the anomaly.
    let raw = detected.confidence * 100.0;
    let confidence = if raw.is_finite() {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        // finite + clamped to [0.0, 100.0]
        {
            raw.round().clamp(0.0, 100.0) as u8
        }
    } else {
        0u8
    };

    Some(Technology {
        name: detected.name.clone(),
        version: None,
        category: TechCategory::Security,
        confidence,
    })
}

/// Returns the names of all WAFs that can be detected.
#[must_use]
pub fn supported_wafs() -> Vec<String> {
    wafrift_detect::supported_wafs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_waf_detected() {
        let headers = vec![
            ("server".to_string(), "cloudflare".to_string()),
            ("cf-ray".to_string(), "abc123".to_string()),
        ];
        let result = detect(403, &headers, b"cloudflare ray id");
        assert!(result.is_some(), "should detect Cloudflare WAF");
        let tech = result.unwrap();
        assert_eq!(tech.name, "Cloudflare");
        assert_eq!(tech.category, TechCategory::Security);
        assert!(tech.confidence > 50);
    }

    #[test]
    fn no_waf_returns_none() {
        let headers = vec![("server".to_string(), "nginx/1.21.0".to_string())];
        let result = detect(200, &headers, b"<html>hello</html>");
        assert!(result.is_none());
    }

    #[test]
    fn supported_wafs_nonempty() {
        let wafs = supported_wafs();
        assert!(
            wafs.len() >= 15,
            "should have at least 15 WAF detectors, got {}",
            wafs.len()
        );
    }

    /// Verify the confidence clamp logic in isolation.
    ///
    /// The production path calls `wafrift_detect` which we can't control here,
    /// but we can exercise the arithmetic directly to confirm the guard works
    /// for boundary values including the NaN case.
    #[test]
    fn confidence_clamp_boundary_values() {
        // Test the clamp formula mirrors what detect() uses.
        let clamp = |raw: f64| -> u8 {
            if raw.is_finite() {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                // finite + clamped to [0.0, 100.0]
                {
                    raw.round().clamp(0.0, 100.0) as u8
                }
            } else {
                0u8
            }
        };

        assert_eq!(clamp(1.0 * 100.0), 100); // max confidence
        assert_eq!(clamp(0.0 * 100.0), 0); // zero confidence
        assert_eq!(clamp(0.505 * 100.0), 51); // rounds up
        assert_eq!(clamp(f64::NAN), 0); // NaN yields 0, not garbage
        assert_eq!(clamp(f64::INFINITY), 0); // +inf yields 0
        assert_eq!(clamp(f64::NEG_INFINITY), 0); // -inf yields 0
        assert_eq!(clamp(1.5 * 100.0), 100); // clamped at 100, not 150
    }
}
