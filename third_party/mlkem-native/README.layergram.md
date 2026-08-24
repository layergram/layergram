# Vendored mlkem-native source

Layergram vendors the `mlkem/` library directory from `mlkem-native` v2.0.0,
commit `d1b2fe782888bdb761a50336012923180be7f502`.

- Upstream: <https://github.com/pq-code-package/mlkem-native>
- Parameter set used by Layergram: ML-KEM-768 only
- Selected license for the library sources: Apache-2.0
- Vendored Markdown documentation: CC-BY-4.0, as declared upstream
- Local changes inside `mlkem/`: none
- `test/expected_test_vectors.h`: unmodified upstream deterministic KAT fixture
- Upstream randomized API: disabled; Layergram's narrow ABI accepts explicit
  FIPS 203 `d || z` for deterministic identity restoration, while production
  encapsulation randomness is obtained inside the wrapper from the OS CSPRNG
- Explicit encapsulation randomness is available only in test builds for KATs

`LICENSE` is an unmodified copy of the upstream license inventory. The
Layergram wrapper is separate under `native/layergram_mlkem/`.

An update must pin a new commit, compare the vendored tree byte-for-byte,
repeat upstream validation, run Layergram ABI known-answer/negative/lifecycle
tests, and receive a fresh security review before activation.
