# Dependency updates

Dependabot groups routine updates by ecosystem. Rust and Android toolchain
groups include only patch releases: a Rust crate below 1.0 can introduce API
changes in a minor release, and Gradle/Kotlin updates need a compatible Android
toolchain. Other ecosystems group minor and patch updates. Major updates remain
visible individually. Grouping does not approve an update or suppress security
updates.

Review each proposal against current `main`, using the SDK versions documented
in the README. A historical green check does not validate a new base revision.
Keep dependency lockfiles reproducible; the Dart analysis workflow uses
`flutter pub get --enforce-lockfile`. Android updates must preserve dependency
locking and artifact verification, with new artifacts checked against their
publisher before verification metadata is updated.

Native cryptography changes also run the Rust 1.87 unit and hostile-input tests
on pull requests. The dependency-feature check follows the actual AES instance
used by AES-GCM-SIV and requires its `zeroize` feature. Enabling `zeroize` on a
different version of AES does not satisfy this check. Scheduled fuzzing remains
a separate check.

When an update needs an SDK, plugin API or cryptographic dependency migration,
track the coordinated work in an issue and link it from the superseded PR.
Keep the observed failure and the acceptance criteria in that issue. Changes
to cryptography, biometrics or platform sharing also need the affected cases
in [the native validation protocol](QA_V3_SIMULATOR_PROTOCOL.md); passing
source checks alone does not certify those behaviors.
