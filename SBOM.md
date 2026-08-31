# Software Bill of Materials

Layergram publishes machine-readable Software Package Data Exchange (SPDX)
inventories so reviewers can inspect the dependencies associated with a source
revision or release.

## Current Source Inventory

The default branch inventory can be exported from GitHub's dependency graph:

- [Download the current SPDX SBOM](https://github.com/layergram/layergram/dependency-graph/sbom)

This is a source-dependency inventory inferred from manifests and dependency
submissions that GitHub supports. It is not a binary-level attestation and must
not be interpreted as proof that every package was included in a particular
store or release build.

## Release Inventories

Release-specific SBOMs are attached to the corresponding GitHub release and
named `layergram-<version>.spdx.json`. They are generated from the exact release
tag in a clean source tree and reviewed before publication.

The current public release inventory was generated with Syft 1.51.1 from tag
`v2.0.3+30` (`71035e163c4afdb7aab454c906634088020b683d`):

- [SPDX 2.3 SBOM for v2.0.3+30](https://github.com/layergram/layergram/releases/download/v2.0.3%2B30/layergram-v2.0.3%2B30.spdx.json)
- [SHA-256 checksum](https://github.com/layergram/layergram/releases/download/v2.0.3%2B30/layergram-v2.0.3%2B30.spdx.json.sha256)

That inventory contains 727 package records discovered from the release source,
including Pub, Cargo, Maven/Gradle, CocoaPods, GitHub Actions, and Python package
metadata. Duplicate package names can be intentional when different platforms,
versions, or lockfiles resolve the same dependency independently.

The SPDX inventory does not change Layergram's Apache-2.0 license or the licenses
of third-party packages. License fields describe discovered package metadata;
they do not relicense any component.

## Coverage Boundaries

The repository tracks dependency evidence for several ecosystems, including the
root Pub lockfile, two Rust Cargo lockfiles, Android Gradle locking and
verification metadata, and the iOS and macOS CocoaPods lockfiles. GitHub's live
export and individual generators may not support every ecosystem equally.

In particular, an inventory must not be described as complete merely because it
was generated successfully. Reviewers should compare its package coverage with
the tracked lockfiles and treat unsupported ecosystems, build-tool downloads,
platform SDKs, and store-side processing as explicit scope boundaries.

Dependency vulnerability monitoring is complementary to the SBOM. The scheduled
OSV scan covers recognized lockfiles, while [`SECURITY.md`](SECURITY.md) explains
how to report gaps or vulnerable components privately.
