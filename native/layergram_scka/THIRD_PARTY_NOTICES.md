# Third-party notices for `layergram-scka`

The SCKA crate is currently an inactive research/build target and is not linked
into Layergram applications. This file records the exact dependencies that
would contribute to the crate's normal/build output at the frozen checkpoint.

Layergram selects the Apache License 2.0 alternative for every package that is
dual licensed. The complete Apache License 2.0 text is the repository root
`LICENSE` file.

| Package | Version | Selected licensing path |
|---|---:|---|
| `aes-gcm-siv` | 0.11.1 | Apache-2.0 alternative |
| `aead` | 0.5.2 | Apache-2.0 alternative |
| `aes` | 0.8.4 | Apache-2.0 alternative |
| `block-buffer` | 0.10.4 | Apache-2.0 alternative |
| `cfg-if` | 1.0.4 | Apache-2.0 alternative |
| `cipher` | 0.4.4 | Apache-2.0 alternative |
| `cpufeatures` | 0.2.17 | Apache-2.0 alternative |
| `crypto-common` | 0.1.7 | Apache-2.0 alternative |
| `ctr` | 0.9.2 | Apache-2.0 alternative |
| `digest` | 0.10.7 | Apache-2.0 alternative |
| `generic-array` | 0.14.7 | MIT |
| `getrandom` | 0.4.3 | Apache-2.0 alternative |
| `hkdf` | 0.12.4 | Apache-2.0 alternative |
| `hmac` | 0.12.1 | Apache-2.0 alternative |
| `inout` | 0.1.4 | Apache-2.0 alternative |
| `opaque-debug` | 0.3.1 | Apache-2.0 alternative |
| `polyval` | 0.6.2 | Apache-2.0 alternative |
| `subtle` | 2.6.1 | BSD-3-Clause |
| `typenum` | 1.20.1 | Apache-2.0 alternative |
| `universal-hash` | 0.5.1 | Apache-2.0 alternative |
| `version_check` | 0.9.5 | Apache-2.0 alternative |
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
| `r-efi` | 6.0.0 | Apache-2.0 alternative |
| `sha2` | 0.10.9 | Apache-2.0 alternative |
| `zeroize` | 1.8.1 | Apache-2.0 alternative |

The LS3 state envelope uses `aes-gcm-siv` 0.11.1 under its Apache-2.0
alternative. This RFC 8452 construction replaces the earlier AES-GCM
candidate so a divergent same-revision recomputation cannot cause AES-GCM's
catastrophic nonce-reuse failure. Its applicable graph is the permissive
`aead`, `aes`, `cipher`, `ctr`, `polyval`, `subtle`, and `zeroize` graph listed
above. The crate also pins `aes` 0.8.4 directly with its `zeroize` feature so
Cargo feature unification enables best-effort erasure of expanded AES round
keys when the envelope cipher is dropped.

The normal/build ratcheted-authenticator graph adds `hkdf` 0.12.4 and `hmac`
0.12.1 and promotes the already locked `sha2` 0.10.9, `block-buffer` 0.10.4,
and `digest` 0.10.7 packages from test-only use. Each provides an Apache-2.0
licensing alternative. `cfg-if`, `cpufeatures`, `crypto-common`,
`generic-array`, `typenum`, `version_check`, and `subtle` are shared with other
normal/build paths and are listed once above.
`generic-array` 0.14.7 is MIT licensed; its exact license is retained at
`licenses/MIT-generic-array.txt`.

The first private transition slice promotes `getrandom` 0.4.3 to a direct
normal dependency for operating-system entropy. Layergram selects its
Apache-2.0 alternative and the Apache-2.0 alternatives offered by its
applicable `cfg-if`, `libc`, `rand_core`, and target-specific `r-efi` graph.

The Unicode-3.0 notice required by `unicode-ident` is retained at
`licenses/UNICODE-3.0.txt`. Exact package checksums are pinned in `Cargo.lock`;
locked/offline builds are required after the dependency cache is populated.

The BSD-3-Clause license required by `subtle` is retained at
`licenses/BSD-3-Clause-subtle.txt` and must accompany source and binary
redistribution as described by that license.

This inventory must be regenerated and reviewed for every dependency, feature,
target, or toolchain change and before the crate is packaged into any public or
paid Premium binary.
