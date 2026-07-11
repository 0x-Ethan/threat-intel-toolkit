use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// DNS finding from passive enumeration
#[derive(Debug, Serialize, Deserialize)]
pub struct DnsFinding {
    pub subdomain: String,
    pub record_type: String,
    pub value: String,
    pub source: String,
}

/// Output structure for JSON mode
#[derive(Debug, Serialize)]
pub struct DnsOutput {
    pub target: String,
    pub timestamp: String,
    pub module: String,
    pub findings: Vec<DnsFinding>,
    pub mitre_techniques: Vec<String>,
    pub framework_refs: Vec<String>,
}

/// Run passive DNS enumeration.
/// Uses certificate transparency logs as a passive data source — no active probing.
pub async fn run(target: &str, limit: usize, output_format: &str) -> Result<()> {
    let findings = enumerate_via_ct(target, limit).await?;

    let out = DnsOutput {
        target: target.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        module: "dns".to_string(),
        findings,
        mitre_techniques: vec!["T1590.001".to_string()],
        framework_refs: vec![
            "NIST CSF DE.CM-1".to_string(),
            "NIST CSF ID.AM-3".to_string(),
        ],
    };

    match output_format {
        "json" => println!("{}", serde_json::to_string_pretty(&out)?),
        _ => {
            println!("Target:    {}", out.target);
            println!("Timestamp: {}", out.timestamp);
            println!("Findings:  {}", out.findings.len());
            println!();
            for f in &out.findings {
                println!(
                    "  {} {} → {} [{}]",
                    f.record_type, f.subdomain, f.value, f.source
                );
            }
        }
    }

    Ok(())
}

/// Enumerate subdomains using certificate transparency logs (passive only).
/// Data source: crt.sh public API — no authentication required, no active scanning.
///
/// Fix v0.1.1: crt.sh returns multiple subdomains in a single name_value field
/// separated by newlines. Each is now split into an individual finding entry.
/// Fix v0.1.1: Full deduplication across the entire result set, not just consecutive entries.
async fn enumerate_via_ct(target: &str, limit: usize) -> Result<Vec<DnsFinding>> {
    let client = reqwest::Client::builder()
        .user_agent("threat-intel-toolkit/0.1 (security research; passive only)")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let url = format!(
        "https://crt.sh/?q=%.{}&output=json",
        urlencoding::encode(target)
    );

    let response: Vec<serde_json::Value> = client
        .get(&url)
        .send()
        .await?
        .json()
        .await
        .unwrap_or_default();

    // crt.sh sometimes returns multiple subdomains in one name_value field
    // separated by newline characters. Split each entry individually.
    let mut findings: Vec<DnsFinding> = response
        .into_iter()
        .flat_map(|entry| {
            let name_value = entry["name_value"].as_str().unwrap_or("").to_string();
            let issuer = entry["issuer_name"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();

            name_value
                .split('\n')
                .filter(|n| !n.is_empty() && !n.starts_with('*'))
                .map(|n| DnsFinding {
                    subdomain: n.trim().to_string(),
                    record_type: "DNS".to_string(),
                    value: issuer.clone(),
                    source: "crt.sh".to_string(),
                })
                .collect::<Vec<_>>()
        })
        .take(limit)
        .collect();

    // Sort then dedup for full deduplication across the entire result set
    findings.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
    findings.dedup_by(|a, b| a.subdomain == b.subdomain);

    Ok(findings)
}
