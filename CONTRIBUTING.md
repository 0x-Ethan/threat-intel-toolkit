# Contributing to threat-intel-toolkit

Thank you for your interest in contributing. This project follows the contribution standards of established security research communities including OWASP and MITRE ATT&CK.

## Before You Start

- Read the [DISCLAIMER.md](DISCLAIMER.md). All contributions must fall within its defined scope.
- Review open [Issues](https://github.com/[USERNAME]/threat-intel-toolkit/issues) and [Discussions](https://github.com/[USERNAME]/threat-intel-toolkit/discussions) before starting work.
- For significant changes, open an issue first to discuss the approach.

## Types of Contributions

**Code contributions**
- New passive data source integrations
- Performance improvements to existing modules
- Bug fixes with accompanying test cases
- MITRE ATT&CK technique mappings

**Research contributions**
- Methodology documentation in `/research-notes`
- Framework mapping notes (NIST, GDPR, UK GDPR)
- Responsible disclosure write-ups (post-remediation only)

**Documentation**
- README improvements
- Usage examples
- Architecture documentation

## Contribution Process

1. **Fork** the repository
2. **Create a branch** — use descriptive names: `feat/ct-module-ipv6`, `fix/dns-timeout-handling`, `docs/mitre-t1590-mapping`
3. **Write clean Rust** — follow `rustfmt` and `clippy` standards
4. **Add tests** — all new functionality must include unit tests
5. **Commit clearly** — use [Conventional Commits](https://www.conventionalcommits.org/) format:
   - `feat: add certificate transparency IPv6 support`
   - `fix: resolve DNS timeout on slow resolvers`
   - `docs: add MITRE T1590.001 technique mapping`
6. **Sign your commits** — PGP-signed commits are strongly encouraged and required for maintainer-level contributions
7. **Open a Pull Request** — reference the related issue, describe your changes clearly

## Code Standards

```bash
# Format before committing
cargo fmt

# Lint — zero warnings policy
cargo clippy -- -D warnings

# Test — all tests must pass
cargo test
```

**No unsafe blocks** without a clear documented justification comment directly above the block.

**No active scanning** in any module — all data sources must be passive, public, or explicitly authorized.

## Security Issues

Do **not** open a public GitHub issue for security vulnerabilities in this project. Report them privately to `[EMAIL]` with subject `[SECURITY] threat-intel-toolkit`.

## Code of Conduct

This project adheres to professional standards of conduct consistent with OWASP's Code of Conduct. Contributions that are disrespectful, abusive, or harmful will not be accepted.

---

*Questions? Open a [Discussion](https://github.com/[USERNAME]/threat-intel-toolkit/discussions).*
