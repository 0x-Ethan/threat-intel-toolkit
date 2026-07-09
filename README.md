# threat-intel-toolkit

> Threat Intelligence & OSINT research toolkit. Attack surface mapping, adversary profiling, geolocation analysis, and passive reconnaissance — built in Rust.

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-FFD65A?style=for-the-badge)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.78%2B-orange?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/[USERNAME]/threat-intel-toolkit/ci.yml?style=for-the-badge&label=CI)](https://github.com/[USERNAME]/threat-intel-toolkit/actions)
[![GitHub Stars](https://img.shields.io/github/stars/[USERNAME]/threat-intel-toolkit?style=for-the-badge&color=FFD65A)](https://github.com/[USERNAME]/threat-intel-toolkit/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/[USERNAME]/threat-intel-toolkit?style=for-the-badge&color=5FD68A)](https://github.com/[USERNAME]/threat-intel-toolkit/issues)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-5FD68A?style=for-the-badge)](CONTRIBUTING.md)
[![Buy Me A Coffee](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/[BUYMEACOFFEE_USERNAME])

</div>

---

## Overview

`threat-intel-toolkit` is an open-source collection of Rust-based tools for structured threat intelligence workflows:

- **Attack surface enumeration** aligned with OWASP Amass methodology
- **Passive DNS & certificate transparency** analysis
- **Geolocation pattern matching** from open-source image indicators
- **Adversary profiling** mapped to MITRE ATT&CK techniques
- **Privacy-respecting OSINT** — no active scanning, no unauthorized access

This toolkit is built for **security researchers**, **threat intelligence analysts**, and **DFIR practitioners** who need fast, auditable, memory-safe tooling.

> **Scope:** All techniques in this toolkit operate within legal boundaries and are designed for authorized research, defensive security, and academic use only. See [DISCLAIMER.md](DISCLAIMER.md).

---

## Quick Start

**Requirements:** Rust 1.78+ · Git · Linux / macOS

```bash
# Clone
git clone https://github.com/[USERNAME]/threat-intel-toolkit.git
cd threat-intel-toolkit

# Build
cargo build --release

# Run passive DNS lookup
./target/release/tit dns --target example.com

# Run certificate transparency search
./target/release/tit ct --target example.com --output json
```

---

## Modules

| Module | Description | Status |
|--------|-------------|--------|
| `dns`  | Passive DNS enumeration via certificate transparency and public resolvers | ✅ Stable |
| `ct`   | Certificate transparency log search (crt.sh, Google CT) | ✅ Stable |
| `geo`  | Open-source geolocation indicator analysis from image metadata | 🔄 In Progress |
| `atk`  | MITRE ATT&CK technique mapper for observed TTPs | 🔄 In Progress |
| `priv` | Privacy data exposure assessment against GDPR/CCPA/HIPAA scope | 📋 Planned |

---

## Core Design Principles

**Memory safety first.** All modules are written in Rust. No unsafe blocks without explicit documentation.

**Passive only.** This toolkit does not perform active scanning. Every data source is public, passive, or explicitly authorized.

**Audit trail.** All operations produce structured JSON output suitable for DFIR chain-of-custody documentation.

**Framework alignment.** Findings map to MITRE ATT&CK, NIST CSF v2.0, and relevant privacy frameworks (GDPR, UK GDPR, CCPA).

---

## Use Cases

- **Threat Intelligence:** Map attack surface before an engagement
- **DFIR:** Reconstruct adversary infrastructure from passive indicators
- **Privacy Engineering:** Assess public data exposure for GDPR/CCPA compliance audits
- **Vulnerability Research:** Enumerate subdomains and certificate history for responsible disclosure scoping

---

## Output Format

All modules support `--output json` for structured, parseable results:

```json
{
  "target": "example.com",
  "timestamp": "2026-07-09T00:00:00Z",
  "module": "ct",
  "findings": [
    {
      "subdomain": "staging.example.com",
      "issuer": "Let's Encrypt",
      "not_before": "2025-12-01",
      "not_after": "2026-03-01",
      "source": "crt.sh"
    }
  ],
  "mitre_techniques": ["T1590.001"],
  "framework_refs": ["NIST CSF DE.CM-1"]
}
```

---

## Roadmap

- [ ] `geo` module: landmark and road sign pattern recognition from open-source image datasets
- [ ] `priv` module: DPIA-ready data exposure report generator
- [ ] MITRE ATT&CK Navigator integration (JSON layer export)
- [ ] OWASP Amass data source plugin interface (Rust FFI)
- [ ] Structured DFIR report output (PDF-ready Markdown)

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

Areas where contributions are most valuable:
- New passive data sources (public APIs, CT logs, passive DNS providers)
- MITRE ATT&CK technique mappings for new TTPs
- Privacy framework coverage (DORA, NIS2, EU AI Act additions)
- Documentation and research writeups in `/research-notes`

---

## Research Notes

The `/research-notes` directory contains published analysis, methodology notes, and responsible disclosure documentation.

See: [`research-notes/`](research-notes/)

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

**Important:** This toolkit is for authorized security research and defensive use only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. See [DISCLAIMER.md](DISCLAIMER.md).

---

## About

Maintained by **[NAME]** — Cybersecurity Researcher focused on Threat Intelligence, DFIR, and Data Protection.

Contributing to [OWASP Amass](https://github.com/owasp-amass/amass) · [MITRE ATT&CK](https://github.com/mitre-attack)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/[USERNAME])
[![Website](https://img.shields.io/badge/Website-[DOMAIN]-FFD65A?style=flat-square)](https://[DOMAIN])
