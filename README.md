# truestack

[![CI](https://github.com/santhreal/truestack/actions/workflows/ci.yml/badge.svg)](https://github.com/santhreal/truestack/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Crates.io](https://img.shields.io/crates/v/truestack)](https://crates.io/crates/truestack) [![status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](https://santh.dev)

> Part of the [Santh](https://santh.dev) security research ecosystem.

## What it does

`truestack` is a security-aware technology fingerprinting library for web servers. Unlike traditional fingerprinting tools that report what the version string claims, `truestack` determines the **true** security posture of a target - including detection of backported patches, behavioural differential probing, and CVE correlation.

Core capabilities:

- **TOML-driven rule engine** - signal-based detection from HTTP headers, response bodies, and cookies. Rules are easily extensible.
- **Security header auditing** - checks for HSTS, CSP, X-Frame-Options, and more. Includes deep CSP bypass analysis (15 known bypass domains).
- **Favicon hashing** - Shodan-compatible MurmurHash3 for cross-service pivot (`http.favicon.hash:{value}`).
- **Version extraction** - parses `Server`, `X-Powered-By`, and other headers to extract semver-style version strings.
- **Backport intelligence** - detects Debian/Ubuntu/RHEL distro context and annotates version strings with reliability ratings so CVE correlation is accurate.
- **Zero-config core** - fingerprinting runs on raw `&[(K, V)]` and `&str` without requiring a specific HTTP client.

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
truestack = "0.2"
```

Detect technologies and audit headers:

```rust
use truestack::fingerprints;
use truestack::security_headers;

fn main() {
    let headers = vec![
        ("Server".to_string(), "nginx/1.21.0".to_string()),
        ("X-Powered-By".to_string(), "Express".to_string()),
    ];
    let body = "<html><body>__NEXT_DATA__</body></html>";

    let techs = fingerprints::detect(&headers, body);
    for tech in &techs {
        println!("Found: {} (version: {:?})", tech.name, tech.version);
    }

    let findings = security_headers::audit(&headers);
    for f in &findings {
        println!("[{}] {}", f.severity().as_str(), f.title());
    }
}
```

Install the CLI:

```bash
cargo install --path .
truestack https://example.com --favicon --format json
truestack https://example.com --rules-dir ./my-rules/
```

Optional `fetch` feature enables `truestack::favicon::fetch_hash` via `reqwest`.

## When to use / When not

**Use truestack when:**
- You need to fingerprint a live web target during a security assessment or red-team exercise.
- You want security-header findings (HSTS, CSP bypass, clickjacking) alongside tech detection in one pass.
- You need Shodan-compatible favicon hashes for pivot queries.
- You are running on a Debian/Ubuntu/RHEL target and need backport-aware CVE correlation rather than naive version matching.

**Do not use truestack when:**
- You need passive traffic analysis - truestack is request/response oriented.
- You need full Wappalyzer compatibility and a browser DOM - truestack works on raw HTTP, not rendered pages.
- You are targeting non-HTTP services.

## Compared to alternatives

| Tool | Backend | Backport-aware | Security headers | Favicon hash | Embeddable library |
|---|---|---|---|---|---|
| **truestack** | Raw HTTP (Rust) | Yes | Yes (15 bypass domains) | Yes (Shodan MurmurHash3) | Yes |
| Wappalyzer | Browser / Node.js | No | No | No | Node.js only |
| WhatWeb | Ruby CLI | No | Partial | No | No |
| Nmap scripts | Nmap NSE | No | No | No | No |

truestack is the only library-first option with first-class backport detection and CSP bypass analysis.

## How it fits in Santh

Within the Santh security research platform, `truestack` acts as the technology-fingerprinting layer:

- **Input**: raw HTTP response data (headers + body) collected by Santh's crawlers or passed in via the scan pipeline.
- **Output**: `Vec<Technology>` consumed by the CVE-correlation and risk-scoring modules; `Vec<Finding>` (from `secfinding`) fed into the unified finding store.
- The `waf` module bridges to `wafrift-detect` so WAF presence is surfaced alongside framework detections in a single pass.
- `version_intel::assess_headers` annotates confidence before findings reach the report renderer.

## Contributing

1. Fork the repo and create a feature branch.
2. Add tests for any new rule or behaviour - all categories (`tests/unit.rs`, `tests/adversarial.rs`, `tests/property.rs`, `tests/gap.rs`, `tests/integration.rs`) are expected to stay green.
3. New fingerprint rules go in `src/rules.toml` following the existing TOML schema.
4. Run `cargo +nightly test -p truestack` and `cargo clippy` before opening a PR.
5. Describe what signal(s) you used to detect the technology and cite a public reference.

## License

MIT - see [LICENSE-MIT](LICENSE-MIT). Dual-licensed under Apache 2.0 - see [LICENSE-APACHE](LICENSE-APACHE).
