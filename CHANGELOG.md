# Changelog

All notable changes to truestack are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Initial crate structure with core fingerprinting modules.

## [0.1.0]  -  Initial release

- **Security-aware technology fingerprinting**  -  Determines true security posture vs. version string claims.
- **Backported patch detection**  -  Identifies security fixes that don't change version numbers.
- **Behavioural differential probing**  -  Analyzes server behavior patterns for fingerprinting.
- **CVE correlation**  -  Links detected technologies to known vulnerabilities.
- **YAML-driven rule engine**  -  Signal-based detection from HTTP headers, response bodies, and cookies.
- **Security header auditing**  -  HSTS, CSP, X-Frame-Options checks with deep CSP bypass analysis.
- **Favicon hashing**  -  Shodan-compatible MurmurHash3 for cross-service pivot (`http.favicon.hash:{value}`).
- **Zero-config core**  -  Fingerprinting runs on raw data without requiring a specific HTTP client.
- **Optional `fetch` feature**  -  Async fetching helpers using `reqwest`.
