// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Inactive, Layergram-owned boundary around incremental ML-KEM-768.
//!
//! This module deliberately exposes no C ABI. Its key-generation entry point is
//! used only by the private transition-1 slice; encapsulation, decapsulation,
//! and every exported operation remain disconnected while the complete backend
//! stays `NOT_READY`.

use libcrux_ml_kem::mlkem768::incremental::{
    decapsulate_compressed_key, encapsulate1, encapsulate2, validate_pk_bytes, Ciphertext1,
    Ciphertext2, KeyPairCompressedBytes,
};
use libcrux_ml_kem::mlkem768::{portable::validate_private_key_only, MlKem768PrivateKey};
use zeroize::Zeroize;

pub(crate) const KEY_GENERATION_SEED_BYTES: usize = 64;
pub(crate) const ENCAPSULATION_SEED_BYTES: usize = 32;
pub(crate) const PUBLIC_KEY_HEADER_BYTES: usize = 64;
pub(crate) const PUBLIC_KEY_VECTOR_BYTES: usize = 1_152;
pub(crate) const PRIVATE_KEY_BYTES: usize = 2_400;
pub(crate) const ENCAPSULATION_STATE_BYTES: usize = 2_080;
pub(crate) const CIPHERTEXT_PART_ONE_BYTES: usize = 960;
pub(crate) const CIPHERTEXT_PART_TWO_BYTES: usize = 128;
pub(crate) const SHARED_SECRET_BYTES: usize = 32;

const PUBLIC_KEY_VECTOR_OFFSET: usize = 1_152;
const PUBLIC_KEY_HEADER_OFFSET: usize = 2_304;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IncrementalMlKemError {
    InvalidLength,
    InvalidPublicKey,
    PrimitiveFailure,
}

pub(crate) struct IncrementalKeyPair {
    private_key: [u8; PRIVATE_KEY_BYTES],
}

impl IncrementalKeyPair {
    pub(crate) fn public_key_header(&self) -> &[u8; PUBLIC_KEY_HEADER_BYTES] {
        self.private_key
            [PUBLIC_KEY_HEADER_OFFSET..PUBLIC_KEY_HEADER_OFFSET + PUBLIC_KEY_HEADER_BYTES]
            .try_into()
            .expect("frozen ML-KEM-768 private-key layout")
    }

    pub(crate) fn public_key_vector(&self) -> &[u8; PUBLIC_KEY_VECTOR_BYTES] {
        self.private_key
            [PUBLIC_KEY_VECTOR_OFFSET..PUBLIC_KEY_VECTOR_OFFSET + PUBLIC_KEY_VECTOR_BYTES]
            .try_into()
            .expect("frozen ML-KEM-768 private-key layout")
    }

    pub(crate) fn private_key(&self) -> &[u8; PRIVATE_KEY_BYTES] {
        &self.private_key
    }
}

impl Drop for IncrementalKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

pub(crate) struct IncrementalSharedSecret {
    bytes: [u8; SHARED_SECRET_BYTES],
}

impl IncrementalSharedSecret {
    pub(crate) fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.bytes
    }
}

impl Drop for IncrementalSharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub(crate) struct EncapsulationPartOne {
    public_key_header: [u8; PUBLIC_KEY_HEADER_BYTES],
    state: [u8; ENCAPSULATION_STATE_BYTES],
    ciphertext: [u8; CIPHERTEXT_PART_ONE_BYTES],
}

impl EncapsulationPartOne {
    pub(crate) fn public_key_header(&self) -> &[u8; PUBLIC_KEY_HEADER_BYTES] {
        &self.public_key_header
    }

    pub(crate) fn state(&self) -> &[u8; ENCAPSULATION_STATE_BYTES] {
        &self.state
    }

    pub(crate) fn ciphertext(&self) -> &[u8; CIPHERTEXT_PART_ONE_BYTES] {
        &self.ciphertext
    }
}

impl Drop for EncapsulationPartOne {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

/// One-shot result of the ML-KEM Braid `Encaps1` transition.
///
/// Revision 1 emits the epoch secret as soon as ciphertext part one is sampled.
/// The caller may borrow that secret only while it owns this transient result,
/// then must consume the result into the key-bound pending completion state.
/// The shared secret is dropped and zeroized during that conversion; it is not
/// retained in the serializable continuation state.
pub(crate) struct EncapsulationStarted {
    pending: EncapsulationPartOne,
    shared_secret: IncrementalSharedSecret,
}

impl EncapsulationStarted {
    pub(crate) fn ciphertext(&self) -> &[u8; CIPHERTEXT_PART_ONE_BYTES] {
        self.pending.ciphertext()
    }

    pub(crate) fn shared_secret(&self) -> &[u8; SHARED_SECRET_BYTES] {
        self.shared_secret.as_bytes()
    }

    pub(crate) fn into_pending(self) -> EncapsulationPartOne {
        self.pending
    }
}

pub(crate) struct EncapsulationPartTwo {
    ciphertext: [u8; CIPHERTEXT_PART_TWO_BYTES],
}

impl EncapsulationPartTwo {
    pub(crate) fn ciphertext(&self) -> &[u8; CIPHERTEXT_PART_TWO_BYTES] {
        &self.ciphertext
    }
}

pub(crate) fn key_pair_from_seed(seed: &[u8]) -> Result<IncrementalKeyPair, IncrementalMlKemError> {
    let mut checked_seed = exact_array::<KEY_GENERATION_SEED_BYTES>(seed)?;
    let key_pair = KeyPairCompressedBytes::from_seed(checked_seed);
    checked_seed.zeroize();

    let private_key = key_pair.to_bytes();
    Ok(IncrementalKeyPair { private_key })
}

pub(crate) fn key_pair_from_private_key(
    private_key: &[u8],
) -> Result<IncrementalKeyPair, IncrementalMlKemError> {
    let checked = exact_array::<PRIVATE_KEY_BYTES>(private_key)?;
    let typed = MlKem768PrivateKey::from(checked);
    if !validate_private_key_only(&typed) {
        let mut rejected: [u8; PRIVATE_KEY_BYTES] = typed.into();
        rejected.zeroize();
        return Err(IncrementalMlKemError::InvalidPublicKey);
    }
    let mut checked: [u8; PRIVATE_KEY_BYTES] = typed.into();
    if validate_public_key(
        &checked[PUBLIC_KEY_HEADER_OFFSET..PUBLIC_KEY_HEADER_OFFSET + PUBLIC_KEY_HEADER_BYTES],
        &checked[PUBLIC_KEY_VECTOR_OFFSET..PUBLIC_KEY_VECTOR_OFFSET + PUBLIC_KEY_VECTOR_BYTES],
    )
    .is_err()
    {
        checked.zeroize();
        return Err(IncrementalMlKemError::InvalidPublicKey);
    }
    Ok(IncrementalKeyPair {
        private_key: checked,
    })
}

pub(crate) fn validate_public_key(
    public_key_header: &[u8],
    public_key_vector: &[u8],
) -> Result<(), IncrementalMlKemError> {
    require_exact_length(public_key_header, PUBLIC_KEY_HEADER_BYTES)?;
    require_exact_length(public_key_vector, PUBLIC_KEY_VECTOR_BYTES)?;
    validate_pk_bytes(public_key_header, public_key_vector)
        .map_err(|_| IncrementalMlKemError::InvalidPublicKey)
}

pub(crate) fn encapsulate_part_one_from_seed(
    public_key_header: &[u8],
    seed: &[u8],
) -> Result<EncapsulationStarted, IncrementalMlKemError> {
    let checked_public_key_header = exact_array::<PUBLIC_KEY_HEADER_BYTES>(public_key_header)?;
    let mut checked_seed = exact_array::<ENCAPSULATION_SEED_BYTES>(seed)?;
    let mut state = [0u8; ENCAPSULATION_STATE_BYTES];
    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];
    let result = encapsulate1(
        public_key_header,
        checked_seed,
        &mut state,
        &mut shared_secret,
    );
    checked_seed.zeroize();

    match result {
        Ok(ciphertext) => Ok(EncapsulationStarted {
            pending: EncapsulationPartOne {
                public_key_header: checked_public_key_header,
                state,
                ciphertext: ciphertext.value,
            },
            shared_secret: IncrementalSharedSecret {
                bytes: shared_secret,
            },
        }),
        Err(_) => {
            state.zeroize();
            shared_secret.zeroize();
            Err(IncrementalMlKemError::PrimitiveFailure)
        }
    }
}

pub(crate) fn encapsulate_part_two(
    part_one: EncapsulationPartOne,
    public_key_vector: &[u8],
) -> Result<EncapsulationPartTwo, IncrementalMlKemError> {
    validate_public_key(&part_one.public_key_header, public_key_vector)?;
    let checked_vector = exact_array_ref::<PUBLIC_KEY_VECTOR_BYTES>(public_key_vector)?;
    let ciphertext = encapsulate2(&part_one.state, checked_vector).value;
    Ok(EncapsulationPartTwo { ciphertext })
}

pub(crate) fn restore_encapsulation_part_one(
    public_key_header: &[u8],
    state: &[u8],
    ciphertext: &[u8],
) -> Result<EncapsulationPartOne, IncrementalMlKemError> {
    Ok(EncapsulationPartOne {
        public_key_header: exact_array::<PUBLIC_KEY_HEADER_BYTES>(public_key_header)?,
        state: exact_array::<ENCAPSULATION_STATE_BYTES>(state)?,
        ciphertext: exact_array::<CIPHERTEXT_PART_ONE_BYTES>(ciphertext)?,
    })
}

pub(crate) fn decapsulate(
    key_pair: &IncrementalKeyPair,
    ciphertext_part_one: &[u8],
    ciphertext_part_two: &[u8],
) -> Result<IncrementalSharedSecret, IncrementalMlKemError> {
    let part_one = exact_array::<CIPHERTEXT_PART_ONE_BYTES>(ciphertext_part_one)?;
    let part_two = exact_array::<CIPHERTEXT_PART_TWO_BYTES>(ciphertext_part_two)?;
    Ok(IncrementalSharedSecret {
        bytes: decapsulate_compressed_key(
            key_pair.private_key(),
            &Ciphertext1 { value: part_one },
            &Ciphertext2 { value: part_two },
        ),
    })
}

fn require_exact_length(bytes: &[u8], expected: usize) -> Result<(), IncrementalMlKemError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(IncrementalMlKemError::InvalidLength)
    }
}

fn exact_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], IncrementalMlKemError> {
    bytes
        .try_into()
        .map_err(|_| IncrementalMlKemError::InvalidLength)
}

fn exact_array_ref<const N: usize>(bytes: &[u8]) -> Result<&[u8; N], IncrementalMlKemError> {
    bytes
        .try_into()
        .map_err(|_| IncrementalMlKemError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_kem::mlkem768::incremental::{
        encaps_state_len, key_pair_compressed_len, pk1_len, pk2_len, shared_secret_size,
    };
    use sha2::{Digest, Sha256};

    const D: [u8; 32] = hex32("934d60b35624d740b30a7f227af2ae7c678e4e04e13c5f509eade2b79aea77e2");
    const Z: [u8; 32] = hex32("3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0");
    const EXPECTED_SHARED_SECRET: [u8; 32] =
        hex32("0b1b32be26247cbcbe0916f8b0b729699c32a96d51efa4a4cd5b289239c8207e");

    #[test]
    fn primitive_sizes_are_frozen() {
        assert_eq!(pk1_len(), PUBLIC_KEY_HEADER_BYTES);
        assert_eq!(pk2_len(), PUBLIC_KEY_VECTOR_BYTES);
        assert_eq!(key_pair_compressed_len(), PRIVATE_KEY_BYTES);
        assert_eq!(encaps_state_len(), ENCAPSULATION_STATE_BYTES);
        assert_eq!(shared_secret_size(), SHARED_SECRET_BYTES);
        assert_eq!(Ciphertext1::len(), CIPHERTEXT_PART_ONE_BYTES);
        assert_eq!(Ciphertext2::len(), CIPHERTEXT_PART_TWO_BYTES);
    }

    #[test]
    fn incremental_flow_matches_independent_mlkem_native_vector() {
        let mut key_seed = [0u8; KEY_GENERATION_SEED_BYTES];
        key_seed[..32].copy_from_slice(&D);
        key_seed[32..].copy_from_slice(&Z);
        let key_pair = key_pair_from_seed(&key_seed).unwrap();
        key_seed.zeroize();

        validate_public_key(key_pair.public_key_header(), key_pair.public_key_vector()).unwrap();

        let mut standard_public_key = [0u8; PUBLIC_KEY_VECTOR_BYTES + 32];
        standard_public_key[..PUBLIC_KEY_VECTOR_BYTES]
            .copy_from_slice(key_pair.public_key_vector());
        standard_public_key[PUBLIC_KEY_VECTOR_BYTES..]
            .copy_from_slice(&key_pair.public_key_header()[..32]);
        assert_eq!(
            hex(&Sha256::digest(standard_public_key)),
            "c45a699a9efcb1a799578ce95f24b063b0b9ddc0879afdb3967fd9e1e3e8c247"
        );

        let started = encapsulate_part_one_from_seed(key_pair.public_key_header(), &D).unwrap();
        let first_ciphertext = *started.ciphertext();
        assert_eq!(started.shared_secret(), &EXPECTED_SHARED_SECRET);
        let first = started.into_pending();
        let second = encapsulate_part_two(first, key_pair.public_key_vector()).unwrap();
        let mut standard_ciphertext = [0u8; CIPHERTEXT_PART_ONE_BYTES + CIPHERTEXT_PART_TWO_BYTES];
        standard_ciphertext[..CIPHERTEXT_PART_ONE_BYTES].copy_from_slice(&first_ciphertext);
        standard_ciphertext[CIPHERTEXT_PART_ONE_BYTES..].copy_from_slice(second.ciphertext());
        assert_eq!(
            hex(&Sha256::digest(standard_ciphertext)),
            "0b99b2af81971943e4ef6e6f17f42be4f3caa9fea18da0f63df1d43639a74743"
        );
        let decapsulated = decapsulate(&key_pair, &first_ciphertext, second.ciphertext()).unwrap();
        assert_eq!(decapsulated.as_bytes(), &EXPECTED_SHARED_SECRET);
    }

    #[test]
    fn full_public_key_validation_precedes_part_two() {
        let key_pair = key_pair_from_seed(&[0x13; KEY_GENERATION_SEED_BYTES]).unwrap();
        let first = encapsulate_part_one_from_seed(
            key_pair.public_key_header(),
            &[0xaf; ENCAPSULATION_SEED_BYTES],
        )
        .unwrap()
        .into_pending();
        let mut conflicting_vector = *key_pair.public_key_vector();
        conflicting_vector[0] ^= 1;

        assert_eq!(
            validate_public_key(key_pair.public_key_header(), &conflicting_vector),
            Err(IncrementalMlKemError::InvalidPublicKey)
        );
        assert!(matches!(
            encapsulate_part_two(first, &conflicting_vector),
            Err(IncrementalMlKemError::InvalidPublicKey)
        ));
    }

    #[test]
    fn part_two_rejects_a_vector_from_another_public_key() {
        let key_pair_a = key_pair_from_seed(&[0x41; KEY_GENERATION_SEED_BYTES]).unwrap();
        let key_pair_b = key_pair_from_seed(&[0x42; KEY_GENERATION_SEED_BYTES]).unwrap();
        let first_a = encapsulate_part_one_from_seed(
            key_pair_a.public_key_header(),
            &[0x24; ENCAPSULATION_SEED_BYTES],
        )
        .unwrap()
        .into_pending();

        assert!(matches!(
            encapsulate_part_two(first_a, key_pair_b.public_key_vector()),
            Err(IncrementalMlKemError::InvalidPublicKey)
        ));
    }

    #[test]
    fn every_boundary_requires_exact_lengths() {
        assert!(matches!(
            key_pair_from_seed(&[0u8; KEY_GENERATION_SEED_BYTES - 1]),
            Err(IncrementalMlKemError::InvalidLength)
        ));
        assert!(matches!(
            key_pair_from_seed(&[0u8; KEY_GENERATION_SEED_BYTES + 1]),
            Err(IncrementalMlKemError::InvalidLength)
        ));
        assert!(matches!(
            encapsulate_part_one_from_seed(
                &[0u8; PUBLIC_KEY_HEADER_BYTES + 1],
                &[0u8; ENCAPSULATION_SEED_BYTES],
            ),
            Err(IncrementalMlKemError::InvalidLength)
        ));
        assert_eq!(
            validate_public_key(
                &[0u8; PUBLIC_KEY_HEADER_BYTES],
                &[0u8; PUBLIC_KEY_VECTOR_BYTES - 1],
            ),
            Err(IncrementalMlKemError::InvalidLength)
        );

        let key_pair = key_pair_from_seed(&[0x42; KEY_GENERATION_SEED_BYTES]).unwrap();
        let first = encapsulate_part_one_from_seed(
            key_pair.public_key_header(),
            &[0x24; ENCAPSULATION_SEED_BYTES],
        )
        .unwrap()
        .into_pending();
        assert!(matches!(
            encapsulate_part_two(
                first,
                &key_pair.public_key_vector()[..PUBLIC_KEY_VECTOR_BYTES - 1],
            ),
            Err(IncrementalMlKemError::InvalidLength)
        ));
        let first = encapsulate_part_one_from_seed(
            key_pair.public_key_header(),
            &[0x24; ENCAPSULATION_SEED_BYTES],
        )
        .unwrap()
        .into_pending();
        assert!(matches!(
            decapsulate(
                &key_pair,
                &first.ciphertext()[..CIPHERTEXT_PART_ONE_BYTES - 1],
                &[0u8; CIPHERTEXT_PART_TWO_BYTES],
            ),
            Err(IncrementalMlKemError::InvalidLength)
        ));
        assert!(matches!(
            decapsulate(
                &key_pair,
                first.ciphertext(),
                &[0u8; CIPHERTEXT_PART_TWO_BYTES + 1],
            ),
            Err(IncrementalMlKemError::InvalidLength)
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(DIGITS[(byte >> 4) as usize] as char);
            output.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        output
    }

    const fn hex32(value: &str) -> [u8; 32] {
        let bytes = value.as_bytes();
        let mut output = [0u8; 32];
        let mut index = 0;
        while index < 32 {
            output[index] = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
            index += 1;
        }
        output
    }

    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test vector"),
        }
    }
}
