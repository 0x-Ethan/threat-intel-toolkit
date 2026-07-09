use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::Serialize;

/// MITRE ATT&CK technique info
#[derive(Debug, Serialize)]
pub struct AttckTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub mitigations: Vec<String>,
    pub nist_csf_refs: Vec<String>,
    pub source: String,
}

/// Output structure
#[derive(Debug, Serialize)]
pub struct AtkOutput {
    pub queried_technique: String,
    pub timestamp: String,
    pub module: String,
    pub result: Option<AttckTechnique>,
}

/// Map a MITRE ATT&CK technique ID to its metadata.
/// Currently uses a local reference set for passive-only operation.
/// Future: integrate with MITRE ATT&CK TAXII server.
pub async fn run(technique: &str, output_format: &str) -> Result<()> {
    let result = lookup_technique(technique)?;

    let out = AtkOutput {
        queried_technique: technique.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        module: "atk".to_string(),
        result: Some(result),
    };

    match output_format {
        "json" => println!("{}", serde_json::to_string_pretty(&out)?),
        _ => {
            if let Some(t) = &out.result {
                println!("Technique:   {} — {}", t.id, t.name);
                println!("Tactic:      {}", t.tactic);
                println!("Description: {}", t.description);
                println!();
                println!("Mitigations:");
                for m in &t.mitigations {
                    println!("  · {}", m);
                }
                println!();
                println!("NIST CSF References:");
                for r in &t.nist_csf_refs {
                    println!("  · {}", r);
                }
            }
        }
    }

    Ok(())
}

/// Local reference set for key reconnaissance techniques.
/// Covers T1590.x (Gather Victim Network Information) and T1596.x (Search Open Technical Databases).
fn lookup_technique(id: &str) -> Result<AttckTechnique> {
    match id {
        "T1590" | "T1590.001" => Ok(AttckTechnique {
            id: "T1590.001".to_string(),
            name: "Gather Victim Network Information: Domain Properties".to_string(),
            tactic: "Reconnaissance".to_string(),
            description: "Adversaries gather information about victim domain properties, including registrars, IP address blocks, DNS records, and organizational contacts. This information may be used to identify targets or plan attacks.".to_string(),
            mitigations: vec![
                "M1056: Pre-compromise — Limit exposure of information via WHOIS privacy protection".to_string(),
                "M1056: Monitor for unusual queries to public domain information services".to_string(),
            ],
            nist_csf_refs: vec![
                "ID.AM-3: Organizational communication and data flows are mapped".to_string(),
                "DE.CM-1: The network is monitored to detect potential cybersecurity events".to_string(),
            ],
            source: "MITRE ATT&CK v15 (local reference)".to_string(),
        }),
        "T1596" | "T1596.003" => Ok(AttckTechnique {
            id: "T1596.003".to_string(),
            name: "Search Open Technical Databases: Digital Certificates".to_string(),
            tactic: "Reconnaissance".to_string(),
            description: "Adversaries search public certificate transparency logs to identify targets, discover subdomains, and enumerate organizational infrastructure. Certificate transparency logs are publicly accessible and contain historical certificate data.".to_string(),
            mitigations: vec![
                "M1056: Pre-compromise — Certificate issuance for internal systems should use private CAs where possible".to_string(),
                "M1056: Audit public certificates regularly for unexpected issuance".to_string(),
            ],
            nist_csf_refs: vec![
                "ID.AM-1: Physical devices and systems within the organization are inventoried".to_string(),
                "PR.IP-1: A baseline configuration of IT systems is created".to_string(),
            ],
            source: "MITRE ATT&CK v15 (local reference)".to_string(),
        }),
        _ => Err(anyhow!(
            "Technique '{}' not found in local reference set. For full ATT&CK coverage, use the MITRE ATT&CK TAXII server: https://attack.mitre.org/resources/attack-data-and-tools/",
            id
        )),
    }
}
