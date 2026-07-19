#![cfg(feature = "fetch")]
use truestack::{fingerprints, security_headers, Severity};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_full_fingerprint_pipeline() {
    let server = MockServer::start().await;

    // Mock a WordPress site with some security issues
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("server", "nginx/1.18.0")
                .insert_header("x-powered-by", "PHP/7.4.3")
                .insert_header("set-cookie", "wordpress_test_cookie=wp_cookie")
                // Missing HSTS, CSP, etc.
                .set_body_string("<html><head><title>My Blog</title></head><body>Welcome to WordPress</body></html>")
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let resp = client.get(server.uri()).send().await.unwrap();

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.text().await.unwrap();

    // 1. Detect technologies
    let techs = fingerprints::detect(&headers, &body);

    let names: Vec<&str> = techs.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"nginx"));
    assert!(names.contains(&"PHP"));
    assert!(names.contains(&"WordPress"));

    let nginx = techs.iter().find(|t| t.name == "nginx").unwrap();
    assert_eq!(nginx.version.as_deref(), Some("1.18.0"));

    // 2. Audit security headers
    let findings = security_headers::audit(&headers);

    let titles: Vec<&str> = findings.iter().map(|f| f.title()).collect();
    assert!(titles.contains(&"Missing HSTS header"));
    assert!(titles.contains(&"Missing Content-Security-Policy"));

    // Check severity
    let hsts = findings
        .iter()
        .find(|f| f.title().contains("HSTS"))
        .unwrap();
    assert_eq!(hsts.severity(), Severity::Medium);
}

#[tokio::test]
async fn test_csp_bypass_detection_integration() {
    let server = MockServer::start().await;

    // Mock a site with a vulnerable CSP (allowing jsdelivr)
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "content-security-policy",
                    "script-src 'self' cdn.jsdelivr.net; object-src 'none';",
                )
                .set_body_string("<html><body>Vulnerable CSP</body></html>"),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let resp = client.get(server.uri()).send().await.unwrap();

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let findings = security_headers::audit(&headers);

    let bypass = findings
        .iter()
        .find(|f| f.title().contains("CSP bypass"))
        .unwrap();
    assert_eq!(bypass.severity(), Severity::Medium);
    assert!(bypass.detail().contains("cdn.jsdelivr.net"));
}
