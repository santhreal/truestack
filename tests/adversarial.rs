use truestack::fingerprints::{detect, extract_version};
use truestack::postprocess::apply;
use truestack::security_headers::audit;
use truestack::{TechCategory, Technology};

#[test]
fn test_empty_inputs() {
    let empty_headers: &[(&str, &str)] = &[];
    let techs = detect(empty_headers, "");
    assert!(techs.is_empty());

    let findings = audit(empty_headers);
    assert!(
        !findings.is_empty(),
        "Missing headers should trigger findings"
    );
}

#[test]
fn test_unicode_body() {
    let body = "<html><body>Some unicode: 🐻‍❄️ __NEXT_DATA__ 안녕하세요</body></html>";
    let empty_headers: &[(&str, &str)] = &[];
    let techs = detect(empty_headers, body);
    assert!(techs.iter().any(|t| t.name == "Next.js"));
}

#[test]
fn test_unicode_headers() {
    let headers = vec![
        ("Server", "nginx/1.21.0 🚀"),
        ("X-Powered-By", "Express 💣"),
    ];
    let techs = detect(&headers, "");
    assert!(techs.iter().any(|t| t.name == "nginx"));
    assert!(techs.iter().any(|t| t.name == "Express"));

    let nginx = techs.iter().find(|t| t.name == "nginx").unwrap();
    // extraction stops at space, so should be 1.21.0
    assert_eq!(nginx.version.as_deref(), Some("1.21.0"));
}

#[test]
fn test_malformed_html() {
    let body = "<html  <body <script id=\"__NEXT_DATA__\" >>> <//html>";
    let empty_headers: &[(&str, &str)] = &[];
    let techs = detect(empty_headers, body);
    assert!(techs.iter().any(|t| t.name == "Next.js"));
}

#[test]
fn test_case_insensitivity_headers() {
    let headers = vec![
        ("SeRvEr", "NGINX/1.21.0"),
        ("X-PoWeReD-By", "ExPrEsS"),
        ("SeT-CoOkIe", "csrftoken=12345"),
    ];
    let techs = detect(&headers, "");
    assert!(techs.iter().any(|t| t.name == "nginx"));
    assert!(techs.iter().any(|t| t.name == "Express"));
    assert!(techs.iter().any(|t| t.name == "Django"));
}

#[test]
fn test_version_extraction_edge_cases() {
    assert_eq!(extract_version("", ""), None);
    assert_eq!(extract_version("nginx/", "nginx"), None);
    assert_eq!(extract_version("Apache/", "apache"), None);
    assert_eq!(extract_version("Express", "express"), None);
    assert_eq!(
        extract_version("nginx/1.21.0", "nginx"),
        Some("1.21.0".to_string())
    );
    assert_eq!(
        extract_version("Microsoft-IIS/10.0", "iis"),
        Some("10.0".to_string())
    );
    assert_eq!(
        extract_version("Server/2.0 (Ubuntu)", "server"),
        Some("2.0".to_string())
    );
    assert_eq!(
        extract_version("  foo / 1.0 ", "foo"),
        Some("1.0".to_string())
    );
}

#[test]
fn test_multiple_set_cookie_headers() {
    let headers = vec![
        ("Set-Cookie", "session=abc"),
        ("Set-Cookie", "wordpress_test_cookie=1"),
        ("Set-Cookie", "django=test"),
    ];
    let techs = detect(&headers, "");
    assert!(techs.iter().any(|t| t.name == "WordPress"));
    assert!(techs.iter().any(|t| t.name == "Django"));
}

#[test]
fn test_csp_multiple_headers() {
    let headers = vec![
        ("Content-Security-Policy", "default-src 'self'"),
        ("Content-Security-Policy", "script-src 'unsafe-inline'"),
    ];
    let findings = audit(&headers);
    assert!(findings.iter().any(|f| f.title().contains("unsafe-inline")));
}

#[test]
fn test_csp_wildcard() {
    let headers = vec![("Content-Security-Policy", "script-src *")];
    let findings = audit(&headers);
    assert!(findings.iter().any(|f| f.title().contains("wildcard")));
}

#[test]
fn test_csp_bypass_domains() {
    let headers = vec![(
        "Content-Security-Policy",
        "script-src https://cdn.jsdelivr.net",
    )];
    let findings = audit(&headers);
    assert!(findings.iter().any(|f| f.title().contains("CSP bypass")));
}

#[test]
fn test_csp_missing_base_uri() {
    let headers = vec![("Content-Security-Policy", "default-src 'self'")];
    let findings = audit(&headers);
    assert!(findings
        .iter()
        .any(|f| f.title().contains("missing base-uri")));
}

#[test]
fn test_concurrent_usage() {
    use std::sync::Arc;
    use std::thread;

    let body = Arc::new("<html><body>__NEXT_DATA__</body></html>".to_string());
    let headers = Arc::new(vec![("Server".to_string(), "nginx/1.21.0".to_string())]);

    let mut handles = vec![];
    for _ in 0..10 {
        let b = Arc::clone(&body);
        let h = Arc::clone(&headers);
        handles.push(thread::spawn(move || {
            let techs = detect(h.as_slice(), &b);
            assert!(techs.iter().any(|t| t.name == "nginx"));
            assert!(techs.iter().any(|t| t.name == "Next.js"));

            let findings = audit(h.as_slice());
            assert!(!findings.is_empty());
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// Ensure at least 50 tests are logically tested by having a test generator or big test data.
// We will test all tech fingerprints and all header audits here.
#[test]
fn test_all_fingerprints() {
    let scenarios = vec![
        (vec![("server", "nginx")], "", "nginx"),
        (vec![("server", "apache")], "", "Apache"),
        (vec![("server", "microsoft-iis")], "", "IIS"),
        (vec![("x-powered-by", "express")], "", "Express"),
        (vec![("set-cookie", "connect.sid=123")], "", "Express"),
        (vec![("set-cookie", "csrftoken=123")], "", "Django"),
        (vec![("set-cookie", "sessionid=123")], "", "Django"),
        (vec![("set-cookie", "_session_id=123")], "", "Ruby on Rails"),
        (vec![("x-runtime", "0.123")], "", "Ruby on Rails"),
        (
            vec![("server", "cloudflare"), ("cf-ray", "123")],
            "",
            "Cloudflare",
        ),
        (vec![("x-served-by", "cache")], "", "Fastly"),
        (
            vec![("set-cookie", "wordpress_logged_in=1")],
            "",
            "WordPress",
        ),
        (vec![("x-generator", "drupal")], "", "Drupal"),
        (vec![("x-powered-by", "next.js")], "", "Next.js"),
        (vec![], "__NUXT__", "Nuxt.js"),
        (vec![("x-powered-by", "Nuxt")], "", "Nuxt.js"),
        (vec![], "react-dom", "React"),
        (vec![], "data-v-1234", "Vue.js"),
        (vec![], "ng-version", "Angular"),
        (vec![("set-cookie", "laravel_session=1")], "", "Laravel"),
        (vec![("x-powered-by", "php")], "", "PHP"),
        (vec![("set-cookie", "JSESSIONID=123")], "", "Spring"),
        (vec![], "jquery", "jQuery"),
        (vec![("x-powered-by", "asp.net")], "", "ASP.NET"),
    ];

    for (headers, body, expected) in scenarios {
        let techs = detect(&headers, body);
        assert!(
            techs.iter().any(|t| t.name == expected),
            "Failed to detect {}",
            expected
        );
    }
}

#[test]
fn test_missing_framework_signals_are_detected() {
    let django = detect(&[("Set-Cookie", "sessionid=abc123")], "");
    assert!(django.iter().any(|t| t.name == "Django"));

    let express = detect(&[("Set-Cookie", "connect.sid=s%3Aabc")], "");
    assert!(express.iter().any(|t| t.name == "Express"));

    let rails = detect(&[("X-Runtime", "0.142")], "");
    assert!(rails.iter().any(|t| t.name == "Ruby on Rails"));

    let empty_headers: &[(&str, &str)] = &[];
    let nuxt = detect(
        empty_headers,
        r#"<div id="__nuxt"></div><script>window.__NUXT__={}</script>"#,
    );
    assert!(nuxt.iter().any(|t| t.name == "Nuxt.js"));
}

#[test]
fn test_all_security_headers_missing() {
    let empty: &[(&str, &str)] = &[];
    let findings = audit(empty);
    let titles: Vec<_> = findings.iter().map(|f| f.title()).collect();

    assert!(titles.contains(&"Missing HSTS header"));
    assert!(titles.contains(&"Missing Content-Security-Policy"));
    assert!(titles.contains(&"Missing X-Frame-Options"));
    assert!(titles.contains(&"Missing X-Content-Type-Options"));
    assert!(titles.contains(&"Missing Referrer-Policy"));
    assert!(titles.contains(&"Missing Permissions-Policy"));
}

#[test]
fn test_leaky_headers() {
    let headers = vec![
        ("X-Powered-By", "PHP/8.0"),
        ("Server", "Apache"),
        ("X-AspNet-Version", "4.0.30319"),
        ("X-AspNetMvc-Version", "5.2"),
    ];
    let findings = audit(&headers);
    let titles: Vec<_> = findings.iter().map(|f| f.title()).collect();

    assert!(titles.contains(&"X-Powered-By header leaks server technology"));
    assert!(titles.contains(&"Server header leaks version info"));
    assert!(titles.contains(&"X-AspNet-Version leaks framework version"));
    assert!(titles.contains(&"X-AspNetMvc-Version leaks framework version"));
}

#[test]
fn test_large_body_does_not_panic() {
    // 3 MB body containing a framework marker  -  should scan without OOM.
    let mut body = String::with_capacity(3 * 1024 * 1024);
    body.push_str("<html><head><title>Big</title></head><body>");
    for _ in 0..(3 * 1024) {
        body.push_str(&"a".repeat(1024));
    }
    body.push_str("__NEXT_DATA__");
    body.push_str("</body></html>");

    let empty_headers: &[(&str, &str)] = &[];
    let techs = detect(empty_headers, &body);
    assert!(techs.iter().any(|t| t.name == "Next.js"));
}

#[test]
fn test_postprocess_dedup_keeps_highest_confidence() {
    let techs = vec![
        Technology {
            name: "nginx".into(),
            version: None,
            category: TechCategory::Server,
            confidence: 60,
        },
        Technology {
            name: "nginx".into(),
            version: None,
            category: TechCategory::Server,
            confidence: 95,
        },
    ];
    let result = apply(techs, &[]);
    assert_eq!(result.iter().filter(|t| t.name == "nginx").count(), 1);
    assert_eq!(
        result
            .iter()
            .find(|t| t.name == "nginx")
            .unwrap()
            .confidence,
        95
    );
}

#[test]
fn test_react_server_components_detection() {
    let body = r#"<html><body><script>__RSC</script></body></html>"#;
    let techs = detect::<&str, &str>(&[], body);
    assert!(techs.iter().any(|t| t.name == "React Server Components"));
}

#[test]
fn test_turbopack_detection() {
    let body = r#"<html><body><script>__turbopack_load()</script></body></html>"#;
    let techs = detect::<&str, &str>(&[], body);
    assert!(techs.iter().any(|t| t.name == "Turbopack"));
}
