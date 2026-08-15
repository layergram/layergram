# Third-party notices for `layergram-scka`

The SCKA crate is currently an inactive research/build target and is not linked
into Layergram applications. This file records the exact dependencies that
would contribute to the crate's normal/build output at the frozen checkpoint.

Layergram selects the Apache License 2.0 alternative for every package that is
dual licensed. The complete Apache License 2.0 text is the repository root
`LICENSE` file.

| Package | Version | Selected licensing path |
|---|---:|---|
| `libcrux-ml-kem` | 0.0.10 | Apache-2.0 |
| `hax-lib` | 0.3.7 | Apache-2.0 |
| `hax-lib-macros` | 0.3.7 | Apache-2.0 |
| `libcrux-intrinsics` | 0.0.8 | Apache-2.0 |
| `libcrux-platform` | 0.0.3 | Apache-2.0 |
| `libcrux-secrets` | 0.0.6 | Apache-2.0 |
| `libcrux-sha3` | 0.0.10 | Apache-2.0 |
| `libcrux-traits` | 0.0.8 | Apache-2.0 |
| `proc-macro2` | 1.0.107 | Apache-2.0 alternative |
| `quote` | 1.0.47 | Apache-2.0 alternative |
| `syn` | 2.0.119 | Apache-2.0 alternative |
| `unicode-ident` | 1.0.24 | Apache-2.0 alternative **and** Unicode-3.0 |
| `libc` | 0.2.189 | Apache-2.0 alternative |
| `rand` | 0.10.2 | Apache-2.0 alternative |
| `rand_core` | 0.10.1 | Apache-2.0 alternative |
| `zeroize` | 1.8.1 | Apache-2.0 alternative |

The test-only `sha2` 0.10.9 graph (`block-buffer`, `cfg-if`, `cpufeatures`,
`crypto-common`, `digest`, `generic-array`, `typenum`, and `version_check`) is
not linked into release artifacts. All packages provide an Apache-2.0 licensing
alternative except `generic-array` 0.14.7, which is MIT licensed. Its exact MIT
license is retained at `licenses/MIT-generic-array.txt`.

The Unicode-3.0 notice required by `unicode-ident` is retained at
`licenses/UNICODE-3.0.txt`. Exact package checksums are pinned in `Cargo.lock`;
locked/offline builds are required after the dependency cache is populated.

This inventory must be regenerated and reviewed for every dependency, feature,
target, or toolchain change and before the crate is packaged into any public or
paid Premium binary.
