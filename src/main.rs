use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::io::Write;
use std::time::Duration;
use truestack::{favicon, fingerprints, security_headers};

#[derive(Parser)]
#[command(name = "truestack")]
#[command(about = "Security-aware technology fingerprinting")]
struct Cli {
    /// Target URL
    url: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    format: OutputFormat,

    /// Directory containing custom .toml rules
    #[arg(short, long)]
    rules_dir: Option<String>,

    /// Include favicon hash
    #[arg(long)]
    favicon: bool,

    /// Timeout in seconds
    #[arg(short, long, default_value = "10")]
    timeout: u64,

    /// Accept invalid or self-signed TLS certificates. Dangerous on untrusted networks.
    #[arg(long, default_value_t = false)]
    insecure: bool,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Json,
    Text,
}

#[derive(Serialize)]
struct Report {
    url: String,
    technologies: Vec<truestack::Technology>,
    security_headers: Vec<truestack::Finding>,
    favicon_hash: Option<i32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut client_builder =
        default_fetch_client_builder()?.timeout(Duration::from_secs(cli.timeout));
    if cli.insecure {
        writeln!(std::io::stderr().lock(), "Warning: --insecure disables TLS certificate verification - do NOT use on untrusted networks")?;
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder
        .build()
        .context("Failed to build HTTP client")?;

    let resp = client
        .get(&cli.url)
        .send()
        .await
        .context("Failed to fetch URL")?;

    let status_code = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = resp.text().await.unwrap_or_default();

    let mut favicon_hash = None;
    if cli.favicon {
        let parsed_url = reqwest::Url::parse(&cli.url)?;
        let fav_url = parsed_url.join("/favicon.ico")?;
        if let Ok(fav_resp) = client.get(fav_url).send().await {
            if fav_resp.status().is_success() {
                if let Ok(bytes) = fav_resp.bytes().await {
                    favicon_hash = Some(favicon::shodan_favicon_hash(&bytes));
                }
            }
        }
    }

    let mut engine = fingerprints::RuleEngine::embedded().clone();
    if let Some(dir) = &cli.rules_dir {
        match fingerprints::RuleEngine::from_directory(dir) {
            Ok(custom) => engine.merge(custom),
            Err(e) => writeln!(
                std::io::stderr().lock(),
                "Warning: failed to load custom rules from {}: {}",
                dir,
                e
            )?,
        }
    }

    let mut technologies = fingerprints::detect_with_engine(&headers, &body, favicon_hash, &engine);

    // WAF Detection
    if let Some(waf_tech) = truestack::waf::detect(status_code, &headers, body.as_bytes()) {
        technologies.push(waf_tech);
    }

    // Behavioral Fingerprinting
    // Sends multi-probe requests to definitively identify servers that strip/spoof their Server headers
    let _ = truestack::behavior::identify(&client, &cli.url, &mut technologies).await;

    // Apply post-processing (excludes, requires, dedup, implied technologies)
    technologies = truestack::postprocess::apply(technologies, &engine.rules);

    // Assess version strings for backport likelihood (Debian/Ubuntu/etc)
    truestack::version_intel::assess(&mut technologies, &headers);

    let security_headers = security_headers::audit(&headers);

    let report = Report {
        url: cli.url.clone(),
        technologies,
        security_headers,
        favicon_hash,
    };

    match cli.format {
        OutputFormat::Json => {
            writeln!(
                std::io::stdout().lock(),
                "{}",
                serde_json::to_string_pretty(&report)?
            )?;
        }
        OutputFormat::Text => {
            writeln!(std::io::stdout().lock(), "Target: {}", report.url)?;
            writeln!(std::io::stdout().lock(), "\nTechnologies:")?;
            if report.technologies.is_empty() {
                writeln!(std::io::stdout().lock(), "  (none detected)")?;
            }
            for t in &report.technologies {
                writeln!(
                    std::io::stdout().lock(),
                    "  - {} (Category: {:?}, Version: {})",
                    t.name,
                    t.category,
                    t.version.as_deref().unwrap_or("unknown")
                )?;
            }

            writeln!(std::io::stdout().lock(), "\nSecurity Headers Findings:")?;
            if report.security_headers.is_empty() {
                writeln!(std::io::stdout().lock(), "  (no findings)")?;
            }
            for f in &report.security_headers {
                writeln!(
                    std::io::stdout().lock(),
                    "  [{:?}] {}: {}",
                    f.severity(),
                    f.title(),
                    f.detail()
                )?;
            }

            if let Some(hash) = report.favicon_hash {
                writeln!(std::io::stdout().lock(), "\nFavicon Hash: {}", hash)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
fn default_fetch_headers() -> Result<reqwest::header::HeaderMap> {
    guise::http::default_browser_header_map_without_compression()
        .context("Failed to build shared stealth browser headers")
}

fn default_fetch_client_builder() -> Result<reqwest::ClientBuilder> {
    guise::http::default_browser_client_builder_without_compression()
        .context("Failed to build shared stealth browser client builder")
}

#[cfg(test)]
mod tests {
    use super::*;
    use guise::fingerprint::default_profile_facts;
    use reqwest::header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT};

    #[test]
    fn default_fetch_headers_match_shared_stealth_profile_without_compression() {
        let headers = default_fetch_headers().expect("shared headers");
        let facts = default_profile_facts();

        assert_eq!(
            headers
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some(facts.user_agent)
        );
        assert_eq!(
            headers.get(ACCEPT).and_then(|value| value.to_str().ok()),
            Some(facts.accept)
        );
        assert_eq!(
            headers
                .get(ACCEPT_LANGUAGE)
                .and_then(|value| value.to_str().ok()),
            Some(facts.accept_language)
        );
        assert!(headers.get(ACCEPT_ENCODING).is_none());
    }
}
