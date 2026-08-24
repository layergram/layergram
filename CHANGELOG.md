# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog and reflects the public GitHub Releases published for this repository.

## [Unreleased]

## [2.0.0+27] - 2026-08-24

### Added
- Activated Layergram protocol v3 with hybrid
  X25519 + ML-KEM-768 identity and handshake, LMF v3 framing, and combined EC +
  sparse post-quantum ratcheting.
- Added durable, retryable v3 message processing for an unreliable external
  transport where parts may be lost, delayed, duplicated, or reordered.
- Added v3 carriage through direct text, deep links, and zero-width
  steganography, plus complete public-identity exchange through text, deep link,
  and one static QR code.
- Added public specifications, vectors, platform checks, native dependency
  notices, audit-package tooling, and a user migration guide.

### Changed
- Introduced an explicit v2-to-v3 migration using the existing 24-word recovery
  phrase (and optional passphrase) to derive new v3 cryptographic keys.
- Activated Normal multi-device and Maximum single-device security modes for the
  v3 runtime without adding a Layergram server or account system.

### Migration
- V3 intentionally has a different public identity, fingerprint, contact
  binding, and session state from v2. Users must share their complete v3 public
  identity and verify contacts again; old v2 messaging is not silently accepted
  as v3.

### Security
- Protocol v3 is active in Layergram 2.0.0. Identity sharing, messaging, and
  production approval use one fail-closed all-or-nothing selector. Official
  packages require the exact allowlisted native backend on every shipped ABI.

## [1.4.0+20] - 2026-06-29

### Added
- Integrated Forward Secrecy support with Advanced opportunistic FS and Maximum device-bound FS.
- Added LMF v2.1 Forward Secrecy envelope fields, control extensions, and multi-envelope support.
- Added text-only payload output mode alongside cover text and deep-link output modes.

### Changed
- Active Forward Secrecy messages are ratchet-only and no longer include legacy identity-key content fallback.
- Updated Forward Secrecy documentation and localized security copy for the integrated no-fallback behavior.
- Improved onboarding flow guidance for create and restore paths.
- Improved message composer ergonomics, default output behavior, and clear-button handling.
- Hardened mnemonic input fields against autocorrect, suggestions, smart quotes, and automatic capitalization.

### Fixed
- Hardened Maximum Forward Secrecy negotiation, startup restore, disable confirmation, and setup messaging.
- Improved Forward Secrecy startup and multi-device edge-case handling.

## [1.3.0+19] - 2026-04-23

### Added
- Introduced Layergram Message Format (LMF) v2.
- Added full steganography compatibility with Telegram.
- Added search and contact-related improvements.

### Changed
- Updated the public message format specification to document LMF v2.

### Fixed
- Fixed cryptographic and identity restoration issues.
- Reintroduced the previously removed Share button for messages on Android, with corrected WhatsApp share intent handling.

## [1.2.2+18] - 2026-04-17

### Changed
- Dismiss the keyboard before parsing identity input in the Add Identity view.
- Added a dismissible close button to the unverified contact banner in the chat view.

### Fixed
- Fixed iOS native asset platform detection to prevent false matches.

## [1.2.1+17] - 2026-04-17

### Changed
- Improved the onboarding flow for new users.

## [1.2.0+15] - 2026-04-16

### Added
- Added onboarding mode.
- Added SAS ceremony support documentation and introduced `THREAT_MODEL.md`.

### Changed
- Introduced versioned identity passphrase derivation.

### Fixed
- Fixed the missing macOS camera privacy description.
- Hardened app lock PIN handling.

## [1.1.1+14] - 2026-04-07

### Removed
- Removed the Share button for messages on Android, since messages cannot be large enough there for a Layergram cover + secret message workflow.

## [1.1.1+13] - 2026-04-06

### Changed
- Version bump release only.

## [1.1.0+12] - 2026-04-03

### Changed
- Display both version and build number as `v1.1.0 (12)` instead of only `1.1.0`.
- Updated the main About view and `LicensePage` for consistency.
- Improved build visibility so users can distinguish between different builds such as `+10`, `+11`, and `+12`.

### Fixed
- Fixed macOS publishing parameters.

## [1.1.0+11] - 2026-04-03

### Changed
- Public release version bump to `1.1.0+11`.

## [1.1.0+10] - 2026-04-02

### Changed
- Bumped Android `versionCode` for Play Store compatibility.

### Notes
- No functional changes.

## [1.1.0+1] - 2026-04-01

### Added
- First official public open-source release of the Layergram Flutter application.
- Privacy-first local encryption with no required backend.
- Steganographic message exchange over ordinary Unicode text.
- Official public documentation.
- Contribution guidelines.
- Code of conduct.
- Security policy.
- Support for 42 included languages.

### Changed
- Published the official public Layergram app repository and public specifications.

### Notes
- This public OSS release shipped without premium functionality enabled.
- The repository does not include premium add-ons, billing logic, private hosted services, or a distributed web release target.
- Official store builds were to be published after approval by the respective app stores.
