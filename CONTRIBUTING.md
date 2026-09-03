# Contributing to Layergram

Thanks for your interest in contributing to Layergram.
This document explains how to propose changes, what belongs in this public repository, and how we work together.

Layergram is a **maintainer-led** open-source project. The source is available
for inspection, use, modification, and independent forks under the project
license, while the official upstream repository remains deliberately curated.
Review capacity is limited, particularly for security-sensitive changes.

---

## 1. Governance and review capacity

Opening an issue or pull request does not create an obligation for the
maintainer to review, accept, merge, or release the proposed work. There is no
general response-time or review-time commitment for issues, feature requests,
or pull requests.

Before opening **any pull request**:

1. Open a change proposal using the repository issue form, unless the
   maintainer has invited the contribution directly.
2. Wait for an explicit written confirmation from the maintainer that the
   specific scope is accepted for implementation.
3. Keep the pull request within that approved scope.

An open issue, positive feedback, or an assignment is not by itself approval
to implement. Approval to implement also does not guarantee a
merge: the final change must still satisfy the project's technical, security,
licensing, compatibility, maintenance, and release requirements.

Unsolicited, unapproved, oversized, or substantially out-of-scope pull
requests may be closed without a complete code review. The maintainer may also
decline or defer a proposal because of roadmap fit, long-term maintenance cost,
review capacity, compatibility risk, or security risk, even when the idea or
implementation is technically reasonable.

Independent experimentation remains welcome in personal forks. Contributors
should keep unapproved implementation work in their own forks rather than
assuming that it will be reviewed or merged upstream.

---

## 2. Scope of this repository

This repository contains the official public source code of the Layergram app.
It includes:

- The Layergram Flutter application.
- The Layergram Message Format (LMF) and related public specifications.
- Core cryptographic, steganographic, storage, and privacy features needed to use the app.
- The public capability interfaces and their no-op implementations for features that are intentionally outside this repository.

This repository is **not** the place for:

- Proprietary hosted services or private backend integrations.
- Billing logic, paid feature delivery infrastructure, or closed-source premium implementations.
- Internal-only planning material or one-off maintenance scripts.
- Changes that would blur the distinction between official Layergram releases and third-party forks.

The maintainer may decline contributions that are out of scope for this
repository, even if they are technically sound.

---

## 3. Public repository boundary and future add-ons

Layergram is open source and freely compilable from this repository.
Layergram may also distribute official free binaries under the Layergram name through the Apple App Store, Google Play, and Microsoft Store.

Future optional paid add-ons may be developed separately outside this repository.
To keep the public repository clear and sustainable:

- Contributions must stand on their own inside the public codebase.
- Pull requests that depend on private services, hidden packages, or unreleased premium infrastructure are out of scope.
- Work that belongs better in a separate add-on, service, or fork may be declined or asked to be reshaped.

This does **not** prevent independent experimentation.
It simply means that not every feature is guaranteed to be merged into the official public Layergram repository.

If you are unsure whether an idea fits, open a change proposal and wait for an
explicit scope decision before investing time in implementation.

---

## 4. Ways to contribute

The most useful initial contributions do not require submitting code:

- Bug reports with clear reproduction steps.
- Narrow documentation corrections proposed through an issue.
- Reproduction cases and synthetic test vectors that contain no sensitive data.
- Focused suggestions for tests, tooling, UX, or accessibility improvements.
- Design feedback grounded in the public specifications and threat model.

Code, documentation, tests, and tooling may be submitted as pull requests only
after the exact scope has been accepted as described in Section 1.

---

## 5. Reporting bugs

When you open a bug report, please include:

- The platform (iOS, Android, macOS, Windows, Linux, etc.) and OS version.
- The Layergram app version or commit hash.
- Exact steps to reproduce the issue.
- What you expected to happen.
- What actually happened, including logs or screenshots if helpful and safe to share.

Clear, reproducible reports make fixes much easier and faster.

Submitting a bug report does not guarantee a fix or a response time. Reports
are prioritized according to reproducibility, user impact, security relevance,
supported versions, and available maintenance capacity.

---

## 6. Proposing changes and new features

For new features or significant changes:

1. Open a change proposal issue.
2. Describe:
   - The problem you want to solve.
   - Why it belongs in the public Layergram repository.
   - Any protocol, storage, UX, or compatibility implications.
   - A rough idea of the solution, if you already have one.
3. Wait for explicit maintainer approval before implementing or opening a pull
   request.

This is especially important for changes that touch:

- Cryptography or key management.
- Message storage, indexing, or migration logic.
- Steganographic encoding and decoding behavior.
- Deep links, identity exchange, or protocol compatibility.
- Capability boundaries for future optional add-ons.

For these security-sensitive areas, a public change proposal may discuss goals
and non-sensitive design constraints, but it is not authorization to submit
code. The maintainer may require additional design work, independent review,
or a different implementation path before accepting any patch.

---

## 7. Pull request gate and guidelines

Do not open a pull request unless its exact scope has been explicitly approved
in a linked issue or the maintainer invited the contribution directly. Pull
requests without that approval may be closed without technical review.

When you open a PR:

- Link the issue and the maintainer comment that approved implementation.
- Keep the change focused and as small as reasonably possible.
- Ensure the code builds and tests pass locally.
- Follow the existing project structure, naming, and style.
- Add or update tests when you change behavior.
- Update documentation and specifications when public behavior changes.
- Disclose third-party or automated-tool-generated material and confirm that
  you have the right to contribute it under Apache-2.0.
- Do not include secrets, real identities, recovery phrases, plaintext,
  private URLs, internal project material, or unpublished add-on details.

In the PR description, please include:

- A short summary of the change.
- Which issue it closes or relates to, if any.
- Any migration, compatibility, or security notes.
- Exact validation commands and their results.
- Provenance and licensing notes for generated, copied, adapted, or vendored
  material.

The maintainer may ask for design clarification, more tests, independent
review, or follow-up changes before merging. Review may be paused or stopped if
the change exceeds the approved scope or the remaining maintenance cost is not
sustainable.

---

## 8. Code style and testing

Layergram aims to have readable, consistent code.
As a general rule:

- Prefer clear, explicit code over clever shortcuts.
- Keep security-critical logic well tested and easy to audit.
- Avoid introducing new dependencies unless there is a strong justification.
- Do not log secrets or accidentally persist sensitive data in unsafe places.

Before submitting a PR, run the relevant tooling used by the repository, including formatting, analysis, and tests.

For the public repository, the minimum security checks are:

```bash
flutter analyze --fatal-infos --fatal-warnings
flutter test test/security
tool/security/gitleaks.sh working-tree
```

Run `tool/security/install_git_hooks.sh` once after cloning to enable the
repository-managed pre-commit secret scan. The hook downloads the pinned
Gitleaks release on first use, verifies its SHA-256 checksum, and scans staged
content with redacted output before a commit is created.

Test vectors must use clearly synthetic, reproducible material. Never paste a
real recovery phrase, private key, credential, or diagnostic identity into a
fixture. When a cryptographic public vector triggers a false positive, add the
narrowest rule-specific allowlist with an explanatory comment; do not exclude
the complete test tree from secret scanning.

---

## 9. Security and cryptography

Layergram is a privacy-focused project.
Extra care is required for any change that touches:

- Encryption, key derivation, or random number generation.
- LMF payload structure, deep links, or identity exchange.
- Steganographic algorithms and platform robustness.
- Secure local storage or data migration behavior.

For these areas:

- Obtain explicit design and implementation approval before opening a patch.
- Document assumptions, trade-offs, and compatibility impacts.
- Avoid making silent protocol or persistence changes without tests.
- Expect a higher review threshold and the possibility that the maintainer
  cannot accept the contribution without independent specialist review.

If you believe you have found a **security vulnerability**, please do **not** open a public issue.
Do not open a public pull request containing the vulnerability or a proposed
fix. Use [GitHub private vulnerability reporting](https://github.com/layergram/layergram/security/advisories/new)
or contact the maintainer privately at **security@layergram.app**.

---

## 10. Licensing, trademarks, and contributor rights

By contributing to Layergram, you agree that:

- Your contributions are licensed under the same license as the project (see `LICENSE`).
- You have the right to contribute the code or content.
- Contributing code does **not** grant rights to use the Layergram name, logo, or branding for your own releases. The Layergram name and related brand assets are owned by **Simone Riccetti**. See https://layergram.app/legal for additional legal and trademark information.

Forks and derivative works are welcome under the project license, but they must not present themselves as official Layergram releases unless explicitly authorized by **Simone Riccetti**. See https://layergram.app/legal for additional legal and trademark guidance.

The project may adopt a Contributor License Agreement (CLA) or similar mechanism in the future if it becomes necessary to support long-term stewardship.

---

## 11. Forward Secrecy implementation invariant

Any contribution to the Forward Secrecy subsystem must respect the following non-negotiable design constraint:

**Layergram has no direct app-to-app channel, no server, and no background synchronization.**

All FS negotiation, session repair, retry, confirmation, and capability discovery must occur only through ordinary Layergram messages that users copy, paste, share, import, or receive through external apps.

Implementation must never assume:

- direct socket communication between Layergram clients;
- background sync or push-based Layergram delivery;
- server-side device registry or remote prekey fetch;
- transport-level acknowledgement;
- ordered delivery or guaranteed receipt;
- remote device availability or online status.

UX wording must not imply any of the above. Avoid phrases like "Connecting to contact…", "Waiting for remote device…", or "Fetching secure session…". Use phrases like "Waiting for a compatible reply." or "Security upgrade will continue when this contact sends the next Layergram message."

This invariant is essential for Layergram's transport-agnostic design and for the plausible-deniability properties of passphrase-derived identities.

---

## 12. Code of Conduct

We want a welcoming and respectful community.

- Be kind and constructive in issues, discussions, and reviews.
- Assume good faith, especially in asynchronous communication.
- Technical disagreement is normal; harassment, abuse, or discriminatory behavior is not.

The terms in `CODE_OF_CONDUCT.md` apply to all project spaces.

---

## 13. Questions and support

If you are unsure about scope, design choices, or contribution fit:

- Read the issue forms and open a focused change proposal.
- Wait for a maintainer decision before preparing a pull request.
- Use the official project information at https://layergram.app for general
  product information.

The repository does not currently operate a guaranteed support, proposal, or
pull-request response service. The separate best-effort target in
[`SECURITY.md`](SECURITY.md) applies only to privately submitted vulnerability
reports.

Thank you for helping build a public, auditable, privacy-focused communication tool.
