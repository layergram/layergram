# Security Policy

Layergram is a privacy-focused application with security-sensitive code in cryptography, local storage, app lock flows, identity exchange, and steganographic message handling.

For a complete description of what Layergram protects against, what is explicitly out of scope, and the assumptions the model relies on, see [`THREAT_MODEL.md`](THREAT_MODEL.md). Security reports are evaluated against that document.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes |
| 1.3.x   | Security fixes only |
| < 1.3.0 | No |

## Reporting a Vulnerability

Please **do not open a public issue** for security vulnerabilities.

Use [GitHub private vulnerability reporting](https://github.com/layergram/layergram/security/advisories/new) whenever possible. It provides a structured private channel for the report and any coordinated fix. If GitHub reporting is unavailable, email **security@layergram.app**.

Include as much of the following information as you can safely share:

- Affected version or commit
- Platform and OS version
- Clear reproduction steps
- Expected behavior and actual behavior
- Security impact assessment, if known
- Logs, screenshots, or proof-of-concept material that do not expose real secrets or personal data

If the issue touches cryptography, identity recovery, passphrases, deep links, or steganographic decoding, include a minimal reproducible example whenever possible.

Do not send real private keys, credentials, plaintext conversations, or personal data. If sensitive evidence is necessary, first ask through one of the private reporting channels how to transfer a minimized, redacted sample.

## Automated Security Baseline

Layergram uses complementary controls because no single scanner covers every
language and security boundary in this repository:

- CodeQL scans the languages it supports in the repository.
- The complete Flutter/Dart source is checked with fatal analyzer diagnostics
  and strict cast analysis on every pull request and default-branch update.
- Source-level security invariant tests reject direct runtime logging,
  non-secure randomness in cryptographic and encrypted-storage code,
  certificate-validation bypasses, and plaintext preference dependencies in
  the cryptographic core.
- GitHub secret scanning and push protection are complemented by a pinned,
  checksum-verified Gitleaks scan of the complete Git history and by an
  optional repository-managed local pre-commit hook.
- Dependency lockfiles are checked with OSV-Scanner.

Automated analysis reduces preventable mistakes but is not presented as a
substitute for independent cryptographic review, protocol analysis, or a
professional security audit.

## Response Expectations

Layergram will make a best effort to:

- Acknowledge receipt within 72 hours
- Confirm whether the report is in scope and reproducible
- Work on a fix or mitigation before public disclosure when appropriate
- Coordinate disclosure timing when a fix is required

The public triage, remediation, verification, and disclosure process is documented in [`SECURITY_RESPONSE.md`](SECURITY_RESPONSE.md). Active incident evidence and pre-disclosure discussion remain private.

## Scope

This policy covers vulnerabilities affecting the public Layergram repository, including:

- Encryption and key management
- Local secure storage and identity handling
- App lock and unlock flows
- Layergram Message Format (LMF) parsing and transport handling
- Steganographic encoding and decoding behavior
- Official release and distribution artifacts produced from this repository

General product questions and non-security bugs should go through the normal public repository channels.
