use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Certificate transparency log entry
#[derive(Debug, Serialize, Deserialize)]
pub struct CtEntry {
    pub subdomain: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub source: String,
}

/// Output structure for JSON mode
#[derive(Debug, Serialize)]
pub struct CtOutput {
    pub target: String,
    pub timestamp: String,
    pub module: String,
    pub total_found: usize,
    pub entries: Vec<CtEntry>,
    pub mitre_techniques: Vec<String>,
}

/// Run certificate transparency log search.
/// Source: crt.sh (public log aggregator) — passive, no authentication required.
pub async fn run(target: &str, include_expired: bool, output_format: &str) -> Result<()> {
    let entries = search_ct_logs(target, include_expired).await?;

    let out = CtOutput {
        target: target.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        module: "ct".to_string(),
        total_found: entries.len(),
        entries,
        mitre_techniques: vec![
            "T1590.001".to_string(),
            "T1596.003".to_string(),
        ],
    };

    match output_format {
        "json" => println!("{}", serde_json::to_string_pretty(&out)?),
        _ => {
            println!("Target:      {}", out.target);
            println!("Timestamp:   {}", out.timestamp);
            println!("Total found: {}", out.total_found);
            println!();
            for e in &out.entries {
                println!(
                    "  [{} → {}] {} — {}",
                    e.not_before, e.not_after, e.subdomain, e.issuer
                );
            }
        }
    }

    Ok(())
}

async fn search_ct_logs(target: &str, _include_expired: bool) -> Result<Vec<CtEntry>> {
    let client = reqwest::Client::builder()
        .user_agent("threat-intel-toolkit/0.1 (security research; passive only)")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let url = format!(
        "https://crt.sh/?q={}&output=json",
        urlencoding::encode(target)
    );

    let response: Vec<serde_json::Value> = client
        .get(&url)
        .send()
        .await?
        .json()
        .await
        .unwrap_or_default();

    let entries = response
        .into_iter()
        .filter_map(|entry| {
            Some(CtEntry {
                subdomain: entry["name_value"].as_str()?.to_string(),
                issuer: entry["issuer_name"]
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string(),
                not_before: entry["not_before"].as_str().unwrap_or("").to_string(),
                not_after: entry["not_after"].as_str().unwrap_or("").to_string(),
                serial_number: entry["serial_number"].as_str().unwrap_or("").to_string(),
                source: "crt.sh".to_string(),
            })
        })
        .collect();

    Ok(entries)
}
