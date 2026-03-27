# truestack

Security-aware technology fingerprinting for web servers.

Unlike traditional fingerprinting tools that report what the version string claims, `truestack` is designed to determine the **true** security posture of a target — including detection of backported patches, behavioural differential probing, and CVE correlation.

## Features

- **YAML-driven rule engine** — signal-based detection from HTTP headers, response bodies, and cookies.
- **Security header auditing** — checks for HSTS, CSP, X-Frame-Options, and more. Includes deep CSP bypass analysis.
- **Favicon hashing** — Shodan-compatible MurmurHash3 for cross-service pivot (`http.favicon.hash:{value}`).
- **Zero-config core** — fingerprinting runs on raw data `&[(K, V)]` and `&str` without requiring a specific HTTP client. Optional `fetch` feature provides async fetching helpers.

## Usage

```rust
use truestack::fingerprints;
use truestack::security_headers;

fn main() {
    // 1. Detect technologies from headers and body
    let headers = vec![
        ("Server".to_string(), "nginx/1.21.0".to_string()),
        ("X-Powered-By".to_string(), "Express".to_string()),
    ];
    let body = "<html><body>__NEXT_DATA__</body></html>";
    
    let techs = fingerprints::detect(&headers, body);
    for tech in techs {
        println!("Found: {} (version: {:?})", tech.name, tech.version);
    }
    
    // 2. Audit security headers
    let findings = security_headers::audit(&headers);
    for finding in findings {
        println!("Security Finding [{}]: {}", finding.severity.as_str(), finding.title);
        println!("  {}", finding.detail);
    }
}
```

### Optional Features

- **`fetch`**: Enables `truestack::favicon::fetch_hash` which uses `reqwest` to download a favicon and compute its Shodan hash.

## License

MIT
