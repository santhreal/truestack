use criterion::{criterion_group, criterion_main, Criterion};
use truestack::fingerprints::{detect_with_engine, RuleEngine};

fn bench_fingerprint_matching(c: &mut Criterion) {
    // Load real rules from the embedded set
    let engine = RuleEngine::embedded();

    // A complex mock response body
    let body = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
            <script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>
            <link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css">
        </head>
        <body>
            <div id="app">{{ message }}</div>
            <p>Powered by WordPress 6.4.1</p>
            <!-- Jira version 8.20.1 -->
        </body>
        </html>
    "#;

    let headers = [
        ("server", "nginx/1.18.0"),
        ("x-powered-by", "PHP/7.4.3"),
        ("content-type", "text/html"),
        ("set-cookie", "wp-settings-1=..."),
    ];

    c.bench_function("fingerprint_complex_response", |b| {
        b.iter(|| {
            let _ = detect_with_engine(&headers, body, None, engine);
        });
    });
}

criterion_group!(benches, bench_fingerprint_matching);
criterion_main!(benches);
