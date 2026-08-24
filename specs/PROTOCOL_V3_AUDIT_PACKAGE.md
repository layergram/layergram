# Layergram protocol v3 — independent review package

Status: **audit input for active protocol v3**. The package binds every review
to one exact open-source commit and exposes the complete production protocol
boundary without including downstream non-OSS source.

## 1. Purpose and scope

`tool/pq/create_v3_audit_bundle.sh` creates one immutable snapshot of the whole
tracked Apache-2.0 Layergram open-source repository. The complete repository is
included deliberately: the review boundary covers not only primitives, but
also identity derivation and import, handshake/session ownership, persistence,
text/link/steganographic carriers, the static identity QR, Normal/Maximum
policy, passphrase scope isolation, application presentation, platform
packaging, and every associated test and specification.

Non-OSS downstream extension source is not a review input and is never read or
copied by the bundle tool. Any downstream distribution must consume the exact
reviewed OSS commit and run compatibility tests without replacing protocol
code or adding an incompatible dependency.

## 2. Reproducible creation

Run from a clean checkout of the exact commit to be reviewed:

```sh
tool/pq/create_v3_audit_bundle.sh
```

The tool refuses a dirty tree, exports tracked bytes directly from `git`, and
writes generated output only below ignored `.dart_tool/layergram_pq/audit/`
unless `LAYERGRAM_V3_AUDIT_OUTPUT_DIR` selects another directory. The archive
contains:

- `AUDIT_SNAPSHOT.txt` with the exact commit and tree object;
- `SOURCE_SHA256SUMS.txt` covering every bundled file;
- all source, test, specification, workflow, packaging, lock, notice, and
  license files tracked by that OSS commit.

The sibling `.sha256` file authenticates the resulting compressed archive. The
compressed byte stream is not claimed to be reproducible across different tar
implementations; the Git tree, per-file manifest, and source bytes are the
canonical review identity.

## 3. Mandatory review questions

The independent reviewer must evaluate at least:

1. the hybrid identity and HP3 transcript bindings, downgrade resistance, role
   separation, device binding, and ML-KEM/X25519 combination;
2. the complete authenticated SCKA/Braid revision-1 state machine, incremental
   ML-KEM continuation, erasure coding, state sealing, nonce construction,
   panic containment, allocation limits, and secret lifetime;
3. Triple Ratchet key separation, skipped-key behavior, epoch transitions,
   forward secrecy and post-compromise recovery claims;
4. atomic receive/send/checkpoint/outbox/ACK/retirement crash boundaries,
   rollback/replay protection, exact-byte retry, and concurrent ownership;
5. hostile identity, QR, deep-link, text, steganographic and message parsing,
   including size/resource limits before allocation;
6. Normal multi-device and Maximum device-pinned policy under delayed,
   duplicated, reordered, omitted, and replayed carrier messages;
7. mnemonic restore, multiple identities, passphrase and plausible-deniability
   scope isolation, plus public/downstream capability boundaries;
8. platform FFI ABI, release hardening, package contents, dependency provenance
   and commercial-license compatibility.

Layergram-authored tests, vectors, receipts, policy assertions, and security
scans are evidence for an independent reviewer, not assumptions the reviewer
must accept. Findings must identify the exact commit, affected surface,
severity, proof or counterevidence, and remediation status. Any validated
critical or high-severity finding must be resolved before a further release.

## 4. Evidence expected alongside the package

The release candidate should attach results for:

- full Flutter analysis and tests on macOS, Linux and Windows;
- packaged integration traversal on iOS and Android, plus current physical
  devices for every shipped architecture;
- locked Rust tests, independent cross-implementation vectors, sanitizers,
  hostile/stateful campaigns, and monitored coverage-guided fuzz runs;
- signed/notarized or store-shaped package inspection without publishing;
- real text, link, steganography and static-QR exchange on supported carrier
  applications and representative printed/scanned QR samples;
- a dependency/license inventory and the exact `SOURCE_SHA256SUMS.txt`.

Any unavailable evidence remains an explicit release-candidate failure. It
must not be converted into a positive claim based only on compilation or
simulator results.

## 5. Active-release boundary

The bundle tool verifies that all three Dart activation booleans are true, the
allowlisted SCKA path is production-registered, the receipt records protocol v3
as active, and continuous release requirements remain explicit. It never
changes those values. Official artifacts must still be built and inspected
through the documented signed/store packaging paths; an ordinary source build
that leaves the defensive default ABI at `NOT_READY` is not an official
Layergram 2.0 package.
