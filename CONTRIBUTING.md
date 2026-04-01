# Contributing to Layergram

Thanks for your interest in contributing to Layergram.
This document explains how to propose changes, what belongs in this public repository, and how we work together.

---

## 1. Scope of this repository

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

Maintainers may decline contributions that are out of scope for this repository, even if they are technically sound.

---

## 2. Public repository boundary and future add-ons

Layergram is open source and freely compilable from this repository.
Layergram may also distribute official free binaries under the Layergram name through the Apple App Store, Google Play, and Microsoft Store.

Future optional paid add-ons may be developed separately outside this repository.
To keep the public repository clear and sustainable:

- Contributions must stand on their own inside the public codebase.
- Pull requests that depend on private services, hidden packages, or unreleased premium infrastructure are out of scope.
- Work that belongs better in a separate add-on, service, or fork may be declined or asked to be reshaped.

This does **not** prevent independent experimentation.
It simply means that not every feature is guaranteed to be merged into the official public Layergram repository.

If you are unsure whether an idea fits, please open an issue before investing significant time in implementation.

---

## 3. Ways to contribute

You can contribute in many ways, not only with code:

- Bug reports with clear reproduction steps.
- Bug fixes and edge-case hardening.
- Documentation and specification improvements.
- Tests and tooling that improve confidence and maintainability.
- UX and accessibility improvements that stay within the public repository scope.

Before starting a larger change, please open an issue or discussion so we can align early.

---

## 4. Reporting bugs

When you open a bug report, please include:

- The platform (iOS, Android, macOS, Windows, Linux, etc.) and OS version.
- The Layergram app version or commit hash.
- Exact steps to reproduce the issue.
- What you expected to happen.
- What actually happened, including logs or screenshots if helpful and safe to share.

Clear, reproducible reports make fixes much easier and faster.

---

## 5. Proposing new features

For new features or significant changes:

1. Open a feature request issue or discussion.
2. Describe:
   - The problem you want to solve.
   - Why it belongs in the public Layergram repository.
   - Any protocol, storage, UX, or compatibility implications.
   - A rough idea of the solution, if you already have one.
3. Wait for maintainer feedback before implementing large or security-sensitive work.

This is especially important for changes that touch:

- Cryptography or key management.
- Message storage, indexing, or migration logic.
- Steganographic encoding and decoding behavior.
- Deep links, identity exchange, or protocol compatibility.
- Capability boundaries for future optional add-ons.

---

## 6. Pull Request guidelines

When you open a PR:

- Keep the change focused and as small as reasonably possible.
- Ensure the code builds and tests pass locally.
- Follow the existing project structure, naming, and style.
- Add or update tests when you change behavior.
- Update documentation and specifications when public behavior changes.

In the PR description, please include:

- A short summary of the change.
- Which issue it closes or relates to, if any.
- Any migration, compatibility, or security notes.

Maintainers may ask for design clarification, more tests, or follow-up changes before merging.

---

## 7. Code style and testing

Layergram aims to have readable, consistent code.
As a general rule:

- Prefer clear, explicit code over clever shortcuts.
- Keep security-critical logic well tested and easy to audit.
- Avoid introducing new dependencies unless there is a strong justification.
- Do not log secrets or accidentally persist sensitive data in unsafe places.

Before submitting a PR, run the relevant tooling used by the repository, including formatting, analysis, and tests.

---

## 8. Security and cryptography

Layergram is a privacy-focused project.
Extra care is required for any change that touches:

- Encryption, key derivation, or random number generation.
- LMF payload structure, deep links, or identity exchange.
- Steganographic algorithms and platform robustness.
- Secure local storage or data migration behavior.

For these areas:

- Prefer discussing the design before shipping a large patch.
- Document assumptions, trade-offs, and compatibility impacts.
- Avoid making silent protocol or persistence changes without tests.

If you believe you have found a **security vulnerability**, please do **not** open a public issue.
Instead, contact the maintainers privately at **security@layergram.app**.

---

## 9. Licensing, trademarks, and contributor rights

By contributing to Layergram, you agree that:

- Your contributions are licensed under the same license as the project (see `LICENSE`).
- You have the right to contribute the code or content.
- Contributing code does **not** grant rights to use the Layergram name, logo, or branding for your own releases. The Layergram name and related brand assets are owned by **Simone Riccetti**. See https://layergram.app/legal for additional legal and trademark information.

Forks and derivative works are welcome under the project license, but they must not present themselves as official Layergram releases unless explicitly authorized by **Simone Riccetti**. See https://layergram.app/legal for additional legal and trademark guidance.

The project may adopt a Contributor License Agreement (CLA) or similar mechanism in the future if it becomes necessary to support long-term stewardship.

---

## 10. Code of Conduct

We want a welcoming and respectful community.

- Be kind and constructive in issues, discussions, and reviews.
- Assume good faith, especially in asynchronous communication.
- Technical disagreement is normal; harassment, abuse, or discriminatory behavior is not.

The terms in `CODE_OF_CONDUCT.md` apply to all project spaces.

---

## 11. Questions and support

If you are unsure about scope, design choices, or contribution fit, please:

- Open a discussion or question issue in the repository, or
- Use the official project information published at https://layergram.app.

Thank you for helping build a public, auditable, privacy-focused communication tool.
