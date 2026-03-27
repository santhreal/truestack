use clap::{Parser, Subcommand};
use stealthreq::http as reqwest;
use truestack::favicon;
use truestack::fingerprints;
use truestack::html;
use truestack::security_headers;

#[derive(Debug, Parser)]
#[command(
    name = "truestack",
    version,
    about = "Security-aware technology fingerprinting CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Fetch a URL and detect technologies from the response
    Detect { url: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Detect { url } => detect(&url).await?,
    }
    Ok(())
}

async fn detect(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .user_agent(format!("truestack/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = client.get(url).send().await?;
    let status = response.status();
    let final_url = response.url().clone();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body = response.text().await?;

    println!("URL: {final_url}");
    println!("Status: {status}");

    if let Some(title) = html::extract_title(&body) {
        println!("Title: {title}");
    }

    let technologies = fingerprints::detect(&headers, &body);
    println!("Technologies:");
    if technologies.is_empty() {
        println!("  none");
    } else {
        for technology in technologies {
            match technology.version {
                Some(version) => println!(
                    "  {} [{}] confidence={} version={version}",
                    technology.name,
                    technology.category.as_ref(),
                    technology.confidence
                ),
                None => println!(
                    "  {} [{}] confidence={}",
                    technology.name,
                    technology.category.as_ref(),
                    technology.confidence
                ),
            }
        }
    }

    let findings = security_headers::audit(&headers);
    println!("Security Findings:");
    if findings.is_empty() {
        println!("  none");
    } else {
        for finding in findings {
            println!("  {} [{}]", finding.title, finding.severity.as_str());
        }
    }

    if let Some(hash) = favicon::fetch_hash(&client, final_url.as_str()).await {
        println!("Favicon Hash: {hash}");
    }

    Ok(())
}

trait CategoryLabel {
    fn as_ref(&self) -> &'static str;
}

impl CategoryLabel for truestack::TechCategory {
    fn as_ref(&self) -> &'static str {
        match self {
            Self::Cms => "cms",
            Self::Framework => "framework",
            Self::Language => "language",
            Self::Server => "server",
            Self::Cdn => "cdn",
            Self::Analytics => "analytics",
            Self::Security => "security",
            Self::Database => "database",
            Self::Os => "os",
            Self::Other => "other",
        }
    }
}
