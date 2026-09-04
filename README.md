# Layergram

**Privacy-first encrypted messaging — transport agnostic, fully local, with no Layergram message relay.**

Layergram is the official open-source Layergram app built with Flutter.
It lets users encrypt sensitive content locally and share it through **any** existing text-based communication channel — WhatsApp, Telegram, Signal, iMessage, email, social networks, or any other platform that preserves Unicode text.

Layergram can carry encrypted payloads inside ordinary-looking cover text using
zero-width Unicode steganography. This can make the protected payload less
obvious to a casual reader, but it is not intended to defeat technical
detection, normalization, or filtering by the transport platform. The
cryptographic workflow remains local to the device.

For transport channels that do not support invisible Unicode characters (or when steganography fails), Layergram also supports sending messages as **direct text payloads** (`<payload>`) or **direct deep links** (`layergram://m/<payload>`). Direct text payloads are not clickable, but they avoid exposing the Layergram URI scheme. Deep links are useful where custom URI schemes are interpreted, but make the presence of a Layergram message visibly obvious to anyone seeing the link.

## Official Project Links

- **Website:** https://layergram.app
- **Latest release:** https://github.com/layergram/layergram/releases/latest
- **Verified Android APKs:** https://layergram.app/apk/
- **GitHub organization:** https://github.com/layergram

## Protocol v3 Post-Quantum Protection

Layergram 2.0 activates the intentionally incompatible protocol v3 with hybrid
post-quantum protection. It combines X25519 with ML-KEM-768, keeps Layergram
serverless and transport-agnostic, and carries messages through the same three
user-facing forms: direct text, deep link, and zero-width steganography.

**Protocol v3 is active in Layergram 2.0 and later.** Its security design,
implementation, test evidence, migration contract, and release tooling remain
public so researchers can inspect and audit the complete protocol boundary.
The custom composition has not yet received an independent cryptographic
audit; the published tests and release evidence are not a substitute for one.

The migration is deliberately explicit:

- users keep their existing 24-word recovery phrase and optional passphrase;
- those secrets deterministically derive new v3 X25519 and ML-KEM-768 key
  material, so the v3 public identity, ID, fingerprint, contacts, and sessions
  are different from v2;
- every user must share their complete new public identity by text, deep link,
  or one branded static QR code and verify contacts again;
- v2 identities and sessions are not silently treated as v3, and v2 message
  sending will be blocked after a contact migrates.

Read the [Protocol v3 migration guide](specs/PROTOCOL_V3_MIGRATION.md) for the
user and compatibility consequences. Keeping the same recovery phrase does
not mean reusing the old cryptographic keys, and the recovery phrase must never
be shared with a contact.

## Release and Distribution Model

- This repository contains the public source code for the official Layergram app.
- Anyone may inspect, compile, modify, and run the app under the terms of the [Apache License 2.0](LICENSE).
- Official Layergram builds may also be distributed free of charge by Layergram through the Apple App Store, Google Play, and Microsoft Store.
- This repository does **not** ship a web distribution target.
- This public release ships without premium functionality enabled.
- Future optional paid add-ons may be developed separately and are **not** part of this repository.

## Supported Platforms

| Platform | Status |
|----------|--------|
| Android  | Ready |
| iOS      | Ready |
| macOS    | Ready |
| Windows  | Ready |
| Linux    | Compilable from source |
| Web      | Not distributed in this release |

## Key Features

### Security
- **Hybrid post-quantum end-to-end encryption (active protocol v3)** — mandatory X25519 + ML-KEM-768 authenticated handshake, EC Double Ratchet, and sparse post-quantum ratcheting, with no classical-only v3 fallback
- **Forward Secrecy** — Normal multi-device and Maximum device-bound session policies, without a Layergram server
- **Passphrase identities and plausible deniability** — an optional passphrase derives a separate identity and encrypted keyspace that remain unavailable while the passphrase is inactive, providing practical but limited plausible deniability (not a guarantee against coercion, forensic correlation, or a compromised device)
- **Steganographic encoding** — encrypted payloads hidden inside zero-width Unicode characters, with direct text and deep-link fallbacks for transports that don't support invisible characters
- **App lock** — biometric unlock with PIN fallback support
- **Secure local storage** — sensitive state protected at rest
- **Screen protection** — optional privacy shielding where supported

### Core Functionality
- **Compose and share** encrypted messages over any text-based channel
- **Decode** received messages by pasting them into the app
- **Identity management** — create, export, and import complete public identities via a single branded static QR code, deep link, or text block; the enlarged QR temporarily improves display brightness and restores the previous setting when closed
- **Local chat history** — encrypted archive of sent and received messages
- **Pin / search / delete** conversations
- **Self-destructing messages** — optional expiration and delete-after-read
- **Backup exclusion contract** — per-contact setting marks new messages so official Layergram clients exclude them from official backups and exports
- **42 languages** included

### Architecture
- **Capability interfaces** — clean extension points for future optional add-ons
- **Riverpod** state management
- **Hive + secure storage** for local persistence
- **Clear separation of concerns** between crypto, storage, UI, and capability boundaries

## What This Repository Includes

- The public Layergram Flutter application
- The open **Layergram Message Format (LMF)** specification
- The Forward Secrecy specification and implementation notes
- Local identity, encryption, steganography, and secure storage logic
- No-op capability implementations for features that are intentionally outside the public repository scope

## What This Repository Does Not Include

- A proprietary messaging network, relay, or backend
- Hosted user accounts or cloud message storage
- Closed-source premium implementations or billing logic

## Project Structure

```text
lib/
├── core/
│   ├── capabilities/     # Capability interfaces + no-op stubs
│   ├── crypto/           # Encryption, key management, message format
│   ├── domain/           # Domain types (IdentityId, etc.)
│   ├── security/         # App lock, biometrics, screen protection
│   └── storage/          # Hive repositories, secure storage
├── features/
│   ├── home/             # Chat list, message composer/viewer
│   ├── settings/         # Settings & about screens
│   └── premium/          # Optional entry points kept inactive in the public OSS release
├── app.dart              # App entry point
└── main.dart             # Bootstrap
```

## Capability Interfaces

Layergram uses capability interfaces to keep the public repository clean while preserving extension points for future official add-ons.

| Capability | Description |
|------------|-------------|
| `IdentityCapability` | Multi-identity management |
| `BackupCapability` | Encrypted backup and restore |
| `CoverGeneratorCapability` | AI-assisted cover message generation |
| `ChatFoldersCapability` | Custom chat folder organization |
| `MediaLightCapability` | Lightweight media attachments |
| `SecureKeyboardCapability` | In-app touch keyboard with multilingual layouts and optional key scrambling |

In this public repository, these optional capabilities default to **safe no-op implementations**. Any future official paid add-ons will live outside this repository and are intentionally excluded from the public codebase.

A future optional add-on may provide an in-app secure keyboard for touch devices so sensitive input can avoid the system IME and optionally use scrambled key layouts per supported locale. This is intended as defense in depth only: it can reduce exposure to third-party keyboard telemetry and learned suggestions, but it does not protect against a compromised OS, screen recording, abusive accessibility tooling, or direct visual observation.

## Getting Started

### Prerequisites
- Flutter SDK >= 3.4
- Dart SDK >= 3.4
- Rust 1.87.0 and Cargo for protocol-v3 native builds
- Platform-specific tooling (Xcode for iOS/macOS, Android SDK, Visual Studio for Windows, Linux toolchain as needed)

### Fetch Dependencies and Run Checks

```bash
flutter pub get
flutter analyze
flutter test
```

### Build a Functional Android App

Protocol v3 uses a native Rust SCKA backend. The default native ABI is
deliberately fail-closed, so a plain `flutter run` is not a functional
protocol-v3 build. To compile the active backend from this repository and
package it into an Android build:

```bash
cargo fetch --locked --manifest-path native/layergram_scka/Cargo.toml
tool/pq/prepare_scka_packaged_android.sh
ORG_GRADLE_PROJECT_layergramSckaCandidatePackage=true \
  flutter run -d <android-device>
```

The first command populates the Cargo cache from the exact lockfile; the
packaging step then runs offline. This path also requires Android NDK tooling
and the Android Rust targets checked by the preparation script. Generated
native libraries stay under the ignored `.dart_tool/` directory. The complete
release-container and cross-platform verification commands are documented in
[the post-quantum packaging guide](tool/pq/README.md).

### Generate API Docs

```bash
dart doc
```

## Specifications

- [Layergram Message Format (LMF)](specs/LAYERGRAM_MESSAGE_FORMAT.md)
- [Forward Secrecy](specs/FORWARD_SECRECY.md)
- [Protocol v3 migration guide](specs/PROTOCOL_V3_MIGRATION.md)
- [Protocol v3 security goals](specs/PROTOCOL_V3_SECURITY_GOALS.md)
- [Protocol v3 identity and protocol specification](specs/PROTOCOL_V3_DRAFT.md)
- [LMF v3 canonical framing specification](specs/LMF_V3_DRAFT.md)
- [Protocol v3 handshake](specs/PROTOCOL_V3_HANDSHAKE.md)
- [Protocol v3 key schedule and ratchet](specs/PROTOCOL_V3_KEY_SCHEDULE.md)
- [Protocol v3 application messages](specs/APPLICATION_MESSAGE_V3.md)
- [Protocol v3 audit package](specs/PROTOCOL_V3_AUDIT_PACKAGE.md)
- [Cryptography Export Compliance Notes](specs/CRYPTOGRAPHY_EXPORT_COMPLIANCE.md)

### Forward Secrecy Status

Forward Secrecy is an integrated Layergram feature. New contacts default to Advanced FS, which
upgrades compatible conversations opportunistically as messages are exchanged. Maximum FS provides
stricter device-bound sending for contacts that explicitly request it.

The implementation preserves Layergram's core model: no Layergram server, no accounts, no key
directory, and no contact public-key redistribution. FS control messages are carried inside
ordinary encrypted Layergram messages, and older clients can ignore them while continuing to use
the base identity-key encryption model. Advanced FS is therefore an automatic compatibility upgrade,
not a guarantee that an active transport attacker cannot suppress whole negotiation messages before
the first FS session is confirmed. Maximum FS does not make those control messages deliverable, but
it makes the pending/not-active state explicit: while Maximum FS is pending or being repaired,
Layergram can exchange setup/control messages but does not send the user's plaintext. This prevents
silent legacy fallback for Maximum contacts; the remaining transport limitation is documented in
the threat model.

## Contributing

Layergram is a maintainer-led open-source project. Reproducible bug reports and
focused change proposals are welcome, but pull requests require explicit scope
approval in a linked issue before they are opened. Unsolicited or
unapproved pull requests may be closed without a complete review, and there is
no guaranteed review or merge timeline.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing work, especially for
cryptography, storage, protocol behavior, or the boundary between the public
app and future optional add-ons. Independent experimentation remains welcome
in personal forks under the project license.

## Security

If you believe you have found a security vulnerability, **please do not open a public issue**.
Report it privately to **security@layergram.app** and see [SECURITY.md](SECURITY.md) for the reporting policy.

For general project information, see https://layergram.app.

## License

### Apache License 2.0

Layergram is released under the [Apache License, Version 2.0](LICENSE).
You may use, modify, and redistribute this code — including in commercial and closed-source products — as long as you comply with the license conditions.

### Trademark Notice

The name **Layergram**, the Layergram logo, the official Layergram store listings, and related brand assets remain the property of **Simone Riccetti**.
Additional legal and trademark information is available at https://layergram.app/legal.
This repository's open-source license does **not** grant permission to ship your own fork under the Layergram name or branding.

### Forks and Derivative Works

If you create a fork or derivative application based on this repository, you must:

- Use your own product name, logo, and branding.
- Clearly disclose that your project is derived from Layergram and is **not** an official Layergram release.
- Use your own URI scheme and application identifiers unless you have explicit written permission from **Simone Riccetti**. See https://layergram.app/legal for additional legal and trademark guidance.

### URI Scheme

The custom URI scheme `layergram://` is reserved for official Layergram applications and explicitly authorized interoperable clients.
Forks and derivative projects must use their own URI schemes (for example `yourapp://`) unless they have obtained prior written permission from **Simone Riccetti**. See https://layergram.app/legal for additional legal and trademark guidance.
