# Third-party notices for `layergram-scka-fuzz`

This separate Cargo package is an engineering-only fuzzing tool. It is not a
workspace member of the production SCKA crate, is never linked into Layergram,
and is excluded from every application package. Its independent `Cargo.lock`
exists only to make the bounded fuzzing checkpoint reproducible.

Layergram selects the Apache License 2.0 alternative for packages that offer
it. The repository root `LICENSE` contains that license text.

The fuzz-only dependency delta relative to `native/layergram_scka/Cargo.lock`
is:

| Package | Version | Licensing |
|---|---:|---|
| `arbitrary` | 1.4.2 | MIT OR Apache-2.0 |
| `jobserver` | 0.1.35 | MIT OR Apache-2.0 |
| `libfuzzer-sys` | 0.4.13 | (MIT OR Apache-2.0) AND NCSA |

`libfuzzer-sys` wraps the LLVM libFuzzer runtime. Its crate metadata requires
the permissive NCSA terms in addition to the selected Apache-2.0 path, while
the vendored LLVM sources in version 0.4.13 identify themselves as
Apache-2.0 WITH LLVM-exception. These test-tool licenses do not impose a
copyleft requirement on Layergram or its paid Premium distribution.

The fuzz manifest and lockfile must not be copied into application packaging.
Regenerate this inventory and repeat the commercial-compatibility review for
every fuzz dependency, feature, version, or toolchain change.
