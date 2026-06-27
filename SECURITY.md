# Security Policy

Layergram is a privacy-focused application with security-sensitive code in cryptography, local storage, app lock flows, identity exchange, and steganographic message handling.

For a complete description of what Layergram protects against, what is explicitly out of scope, and the assumptions the model relies on, see [`THREAT_MODEL.md`](THREAT_MODEL.md). Security reports are evaluated against that document.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | Yes |
| < 1.3.0 | No |

## Reporting a Vulnerability

Please **do not open a public issue** for security vulnerabilities.

Instead, report them privately to **security@layergram.app** with as much of the following information as you can safely share:

- Affected version or commit
- Platform and OS version
- Clear reproduction steps
- Expected behavior and actual behavior
- Security impact assessment, if known
- Logs, screenshots, or proof-of-concept material that do not expose real secrets or personal data

If the issue touches cryptography, identity recovery, passphrases, deep links, or steganographic decoding, include a minimal reproducible example whenever possible.

## Response Expectations

Layergram will make a best effort to:

- Acknowledge receipt within 72 hours
- Confirm whether the report is in scope and reproducible
- Work on a fix or mitigation before public disclosure when appropriate
- Coordinate disclosure timing when a fix is required

## Scope

This policy covers vulnerabilities affecting the public Layergram repository, including:

- Encryption and key management
- Local secure storage and identity handling
- App lock and unlock flows
- Layergram Message Format (LMF) parsing and transport handling
- Steganographic encoding and decoding behavior
- Official release and distribution artifacts produced from this repository

General product questions and non-security bugs should go through the normal public repository channels once the repository is live.
