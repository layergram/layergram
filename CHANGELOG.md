# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.1.0+1] - 2026-04-01

### Added
- First public open-source release of the official Layergram Flutter application.
- Public repository documentation covering project scope, contributing, code of conduct, and the Layergram Message Format (LMF).
- Cryptography export compliance notes for store and compliance review workflows.
- Real test coverage for core encryption and app lock services in place of placeholder tests.
- Public capability scaffold for a future optional secure in-app keyboard add-on on touch devices, including locale discovery, session configuration, and optional scramble support.
- Opt-in session decryption cache setting that preloads a bounded set of recent chat decryption keys in RAM only while the app is open and unlocked.

### Changed
- Public release messaging aligned with the official Layergram website, GitHub organization, trademark policy, and URI scheme policy.
- README and specifications updated to reflect the official open-source release model and current implementation details.
- README premium capability documentation updated to mention the future secure keyboard add-on and its security boundaries.
- Session decryption key retention is now explicitly bounded in memory and cleared when the app is backgrounded or locked, or when the active identity/passphrase changes.

### Security
- End-to-end local encryption using X25519, HKDF-SHA256, and AES-GCM.
- Secure local storage and app lock flows with biometric support and PIN fallback.
- Steganographic encoding and decoding for transport-agnostic hidden message exchange.

### Notes
- This initial public release does not include a distributed web target.
- Future optional paid add-ons are intentionally outside this repository.
- Version 1.1.0+1 marks the first public open-source release; previous versions (1.0.x) were used for internal testing and limited store releases.
