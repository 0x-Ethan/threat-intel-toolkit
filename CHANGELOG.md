# Changelog

All notable changes to `threat-intel-toolkit` are documented here.

This project follows [Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/) conventions.

---

## [Unreleased]

### Planned
- `geo` module: geolocation indicator analysis from open-source image metadata
- `priv` module: DPIA-ready data exposure report generator
- MITRE ATT&CK Navigator JSON layer export
- OWASP Amass data source plugin interface (Rust FFI)
- Structured DFIR report output (PDF-ready Markdown)

---

## [0.1.0] — 2026-07-09

### Added
- Initial release
- `dns` module: passive DNS enumeration via certificate transparency (crt.sh source)
- `ct` module: certificate transparency log search with structured JSON output
- `atk` module: MITRE ATT&CK technique mapper (T1590.x, T1596.x) with NIST CSF cross-references
- CLI interface (`tit`) with `--output json` and `--verbose` flags
- GitHub Actions CI pipeline: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo audit`
- Full documentation: README, CONTRIBUTING, DISCLAIMER, SECURITY, CODE_OF_CONDUCT
- MITRE ATT&CK technique coverage: T1590.001, T1596.003
- Framework alignment: NIST CSF v2.0, GDPR, UK GDPR, CCPA

### Design
- Passive-only architecture: no active scanning, all data sources are public
- JSON output format with MITRE technique and NIST CSF references on every result
- PGP-signed commits from first release

---

[Unreleased]: https://github.com/[USERNAME]/threat-intel-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/[USERNAME]/threat-intel-toolkit/releases/tag/v0.1.0
