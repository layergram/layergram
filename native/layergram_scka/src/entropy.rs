// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Approved operating-system entropy boundary for inactive SCKA transitions.
//!
//! Production transition entry points use [`OsEntropy`] directly. The trait is
//! private to this crate so deterministic providers can exercise exact vectors
//! without creating a caller-supplied-randomness seam in the future C ABI.

// Layergram supports only getrandom's automatically selected operating-system
// backend. In particular, never allow a build flag to silently replace it with
// a custom provider, a CPU-instruction-only source, a legacy provider, or the
// always-failing unsupported backend. This deliberately turns entropy-source
// configuration drift into a compile-time failure.
#[cfg(any(
    getrandom_backend = "custom",
    getrandom_backend = "efi_rng",
    getrandom_backend = "rdrand",
    getrandom_backend = "rndr",
    getrandom_backend = "linux_getrandom",
    getrandom_backend = "linux_raw",
    getrandom_backend = "windows_legacy",
    getrandom_backend = "unsupported",
    getrandom_backend = "extern_impl",
))]
compile_error!(
    "Layergram requires getrandom's default operating-system backend; opt-in backends are forbidden"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntropyError {
    Unavailable,
}

pub(crate) trait EntropySource {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError>;
}

pub(crate) struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(output).map_err(|_| EntropyError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operating_system_entropy_fills_the_requested_buffer() {
        let mut output = [0_u8; 64];
        OsEntropy.fill(&mut output).unwrap();
        assert_eq!(output.len(), 64);
    }
}
