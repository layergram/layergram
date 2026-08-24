// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Layergram-owned systematic Reed-Solomon erasure coding for ML-KEM Braid.
//!
//! This module freezes only the public-message erasure-code representation. It
//! is deliberately reached only through the authenticated SCKA state
//! machine. Public messages are authenticated by ML-KEM Braid above this layer;
//! this code detects malformed shapes and conflicting duplicates, but it is not
//! an authenticity primitive.

use core::fmt;

pub(crate) const SYMBOL_BYTES: usize = 32;
pub(crate) const ENCODED_CHUNK_BYTES: usize = 34;
pub(crate) const MAX_SOURCE_CHUNKS: usize = 36;
pub(crate) const MAX_RECEIVED_CHUNKS: usize = MAX_SOURCE_CHUNKS * 2;
pub(crate) const MAX_ENCODING_INDEX: u16 = u16::MAX - 1;

const FIELD_REDUCTION: u16 = 0x100b;
const FIELD_ORDER_MINUS_ONE: u32 = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ErasureMessageKind {
    HeaderAndMac,
    MlKem768PublicKeyVector,
    MlKem768Ciphertext1,
    MlKem768Ciphertext2AndMac,
}

impl ErasureMessageKind {
    pub(crate) const fn message_bytes(self) -> usize {
        match self {
            Self::HeaderAndMac => 96,
            Self::MlKem768PublicKeyVector => 1_152,
            Self::MlKem768Ciphertext1 => 960,
            Self::MlKem768Ciphertext2AndMac => 160,
        }
    }

    pub(crate) const fn source_chunks(self) -> usize {
        self.message_bytes() / SYMBOL_BYTES
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct EncodedChunk {
    index: u16,
    symbol: [u8; SYMBOL_BYTES],
}

impl fmt::Debug for EncodedChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedChunk")
            .field("index", &self.index)
            .field("symbol_len", &self.symbol.len())
            .finish()
    }
}

impl EncodedChunk {
    pub(crate) fn index(&self) -> u16 {
        self.index
    }

    pub(crate) fn symbol(&self) -> &[u8; SYMBOL_BYTES] {
        &self.symbol
    }

    pub(crate) fn encode(&self) -> [u8; ENCODED_CHUNK_BYTES] {
        let mut encoded = [0_u8; ENCODED_CHUNK_BYTES];
        encoded[..2].copy_from_slice(&self.index.to_be_bytes());
        encoded[2..].copy_from_slice(&self.symbol);
        encoded
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ErasureError> {
        if encoded.len() != ENCODED_CHUNK_BYTES {
            return Err(ErasureError::InvalidEncodedChunkLength);
        }
        let index = u16::from_be_bytes([encoded[0], encoded[1]]);
        if index > MAX_ENCODING_INDEX {
            return Err(ErasureError::InvalidEncodingIndex);
        }
        let mut symbol = [0_u8; SYMBOL_BYTES];
        symbol.copy_from_slice(&encoded[2..]);
        Ok(Self { index, symbol })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ErasureError {
    InvalidMessageLength,
    InvalidEncodedChunkLength,
    InvalidEncodingIndex,
    TooManyChunks,
    InsufficientUniqueChunks,
    ConflictingDuplicate,
    SingularMatrix,
}

pub(crate) fn encode_chunks(
    kind: ErasureMessageKind,
    message: &[u8],
    indexes: &[u16],
) -> Result<Vec<EncodedChunk>, ErasureError> {
    if message.len() != kind.message_bytes() {
        return Err(ErasureError::InvalidMessageLength);
    }
    if indexes.len() > MAX_RECEIVED_CHUNKS {
        return Err(ErasureError::TooManyChunks);
    }
    if indexes.iter().any(|index| *index > MAX_ENCODING_INDEX) {
        return Err(ErasureError::InvalidEncodingIndex);
    }

    let source = bytes_to_symbols(message);
    let source_chunks = kind.source_chunks();
    debug_assert_eq!(source.len(), source_chunks);
    let systematic_inverse = invert_matrix(vandermonde(source_chunks))?;
    let mut encoded = Vec::with_capacity(indexes.len());

    for index in indexes {
        let coefficients =
            generator_coefficients(source_chunks, *index as usize, &systematic_inverse);
        let mut field_symbol = [0_u16; SYMBOL_BYTES / 2];
        for (source_index, coefficient) in coefficients.iter().enumerate() {
            for (word_index, output) in field_symbol.iter_mut().enumerate() {
                *output ^= gf_mul(*coefficient, source[source_index][word_index]);
            }
        }
        encoded.push(EncodedChunk {
            index: *index,
            symbol: field_symbol_to_bytes(field_symbol),
        });
    }
    Ok(encoded)
}

pub(crate) fn decode_message(
    kind: ErasureMessageKind,
    chunks: &[EncodedChunk],
) -> Result<Vec<u8>, ErasureError> {
    if chunks.len() > MAX_RECEIVED_CHUNKS {
        return Err(ErasureError::TooManyChunks);
    }
    let source_chunks = kind.source_chunks();
    let mut unique = Vec::<&EncodedChunk>::with_capacity(chunks.len());
    for chunk in chunks {
        if chunk.index > MAX_ENCODING_INDEX {
            return Err(ErasureError::InvalidEncodingIndex);
        }
        if let Some(existing) = unique.iter().find(|existing| existing.index == chunk.index) {
            if existing.symbol != chunk.symbol {
                return Err(ErasureError::ConflictingDuplicate);
            }
            continue;
        }
        unique.push(chunk);
    }
    if unique.len() < source_chunks {
        return Err(ErasureError::InsufficientUniqueChunks);
    }

    unique.sort_unstable_by_key(|chunk| chunk.index);
    unique.truncate(source_chunks);

    let systematic_inverse = invert_matrix(vandermonde(source_chunks))?;
    let mut received_matrix = Vec::with_capacity(source_chunks);
    let mut received_symbols = Vec::with_capacity(source_chunks);
    for chunk in unique {
        received_matrix.push(generator_coefficients(
            source_chunks,
            chunk.index as usize,
            &systematic_inverse,
        ));
        received_symbols.push(bytes_to_field_symbol(&chunk.symbol));
    }
    let decoding_matrix = invert_matrix(received_matrix)?;

    let mut source = vec![[0_u16; SYMBOL_BYTES / 2]; source_chunks];
    for source_index in 0..source_chunks {
        for (received_index, coefficient) in decoding_matrix[source_index].iter().enumerate() {
            for word_index in 0..SYMBOL_BYTES / 2 {
                source[source_index][word_index] ^=
                    gf_mul(*coefficient, received_symbols[received_index][word_index]);
            }
        }
    }

    let mut message = Vec::with_capacity(kind.message_bytes());
    for symbol in source {
        message.extend_from_slice(&field_symbol_to_bytes(symbol));
    }
    debug_assert_eq!(message.len(), kind.message_bytes());
    Ok(message)
}

fn bytes_to_symbols(message: &[u8]) -> Vec<[u16; SYMBOL_BYTES / 2]> {
    message
        .chunks_exact(SYMBOL_BYTES)
        .map(bytes_to_field_symbol)
        .collect()
}

fn bytes_to_field_symbol(bytes: &[u8]) -> [u16; SYMBOL_BYTES / 2] {
    debug_assert_eq!(bytes.len(), SYMBOL_BYTES);
    let mut symbol = [0_u16; SYMBOL_BYTES / 2];
    for (output, pair) in symbol.iter_mut().zip(bytes.chunks_exact(2)) {
        *output = u16::from_be_bytes([pair[0], pair[1]]);
    }
    symbol
}

fn field_symbol_to_bytes(symbol: [u16; SYMBOL_BYTES / 2]) -> [u8; SYMBOL_BYTES] {
    let mut bytes = [0_u8; SYMBOL_BYTES];
    for (word, output) in symbol.iter().zip(bytes.chunks_exact_mut(2)) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

fn vandermonde(size: usize) -> Vec<Vec<u16>> {
    let mut matrix = vec![vec![0_u16; size]; size];
    for (row, values) in matrix.iter_mut().enumerate() {
        for (column, value) in values.iter_mut().enumerate() {
            *value = gf_alpha_pow((row * column) as u32);
        }
    }
    matrix
}

fn generator_coefficients(
    source_chunks: usize,
    index: usize,
    systematic_inverse: &[Vec<u16>],
) -> Vec<u16> {
    if index < source_chunks {
        let mut identity = vec![0_u16; source_chunks];
        identity[index] = 1;
        return identity;
    }

    let mut vandermonde_column = vec![0_u16; source_chunks];
    for (row, value) in vandermonde_column.iter_mut().enumerate() {
        *value = gf_alpha_pow(((row as u32) * (index as u32)) % FIELD_ORDER_MINUS_ONE);
    }
    multiply_matrix_vector(systematic_inverse, &vandermonde_column)
}

fn multiply_matrix_vector(matrix: &[Vec<u16>], vector: &[u16]) -> Vec<u16> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(vector)
                .fold(0_u16, |sum, (left, right)| sum ^ gf_mul(*left, *right))
        })
        .collect()
}

fn invert_matrix(matrix: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, ErasureError> {
    let size = matrix.len();
    if size == 0 || matrix.iter().any(|row| row.len() != size) {
        return Err(ErasureError::SingularMatrix);
    }
    let mut augmented = vec![vec![0_u16; size * 2]; size];
    for row in 0..size {
        augmented[row][..size].copy_from_slice(&matrix[row]);
        augmented[row][size + row] = 1;
    }

    for column in 0..size {
        let pivot = (column..size)
            .find(|row| augmented[*row][column] != 0)
            .ok_or(ErasureError::SingularMatrix)?;
        augmented.swap(column, pivot);
        let inverse = gf_inverse(augmented[column][column]).ok_or(ErasureError::SingularMatrix)?;
        for value in &mut augmented[column] {
            *value = gf_mul(*value, inverse);
        }

        let pivot_row = augmented[column].clone();
        for (row_index, row) in augmented.iter_mut().enumerate() {
            if row_index == column {
                continue;
            }
            let factor = row[column];
            if factor == 0 {
                continue;
            }
            for (value, pivot_value) in row.iter_mut().zip(&pivot_row) {
                *value ^= gf_mul(factor, *pivot_value);
            }
        }
    }

    Ok(augmented
        .into_iter()
        .map(|row| row[size..].to_vec())
        .collect())
}

fn gf_alpha_pow(exponent: u32) -> u16 {
    gf_pow(2, exponent % FIELD_ORDER_MINUS_ONE)
}

fn gf_inverse(value: u16) -> Option<u16> {
    if value == 0 {
        None
    } else {
        Some(gf_pow(value, FIELD_ORDER_MINUS_ONE - 1))
    }
}

fn gf_pow(mut base: u16, mut exponent: u32) -> u16 {
    let mut result = 1_u16;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn gf_mul(mut left: u16, mut right: u16) -> u16 {
    let mut product = 0_u16;
    for _ in 0..16 {
        if right & 1 != 0 {
            product ^= left;
        }
        let carry = left & 0x8000 != 0;
        left <<= 1;
        if carry {
            left ^= FIELD_REDUCTION;
        }
        right >>= 1;
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: ErasureMessageKind) -> Vec<u8> {
        (0..kind.message_bytes())
            .map(|index| ((index * 197 + 91) & 0xff) as u8)
            .collect()
    }

    fn round_trip(kind: ErasureMessageKind, indexes: Vec<u16>) {
        let original = message(kind);
        let chunks = encode_chunks(kind, &original, &indexes).unwrap();
        assert_eq!(decode_message(kind, &chunks).unwrap(), original);
    }

    #[test]
    fn signal_revision_one_sizes_are_frozen() {
        assert_eq!(ErasureMessageKind::HeaderAndMac.message_bytes(), 96);
        assert_eq!(ErasureMessageKind::HeaderAndMac.source_chunks(), 3);
        assert_eq!(
            ErasureMessageKind::MlKem768PublicKeyVector.message_bytes(),
            1_152
        );
        assert_eq!(
            ErasureMessageKind::MlKem768PublicKeyVector.source_chunks(),
            36
        );
        assert_eq!(ErasureMessageKind::MlKem768Ciphertext1.message_bytes(), 960);
        assert_eq!(ErasureMessageKind::MlKem768Ciphertext1.source_chunks(), 30);
        assert_eq!(
            ErasureMessageKind::MlKem768Ciphertext2AndMac.message_bytes(),
            160
        );
        assert_eq!(
            ErasureMessageKind::MlKem768Ciphertext2AndMac.source_chunks(),
            5
        );
    }

    #[test]
    fn rfc5510_field_polynomial_and_inverses_are_stable() {
        assert_eq!(gf_mul(0x8000, 2), FIELD_REDUCTION);
        assert_eq!(gf_mul(0x1234, 0xabcd), 0x4792);
        for value in 1..=u16::MAX {
            assert_eq!(gf_mul(value, gf_inverse(value).unwrap()), 1);
        }
    }

    #[test]
    fn wire_encoding_is_big_endian_and_rejects_reserved_index() {
        let chunk = EncodedChunk {
            index: 0x1234,
            symbol: [0xa5; SYMBOL_BYTES],
        };
        let encoded = chunk.encode();
        assert_eq!(&encoded[..2], &[0x12, 0x34]);
        assert_eq!(EncodedChunk::decode(&encoded).unwrap(), chunk);
        assert_eq!(chunk.index(), 0x1234);
        assert_eq!(chunk.symbol(), &[0xa5; SYMBOL_BYTES]);
        assert_eq!(
            EncodedChunk::decode(&encoded[..ENCODED_CHUNK_BYTES - 1]),
            Err(ErasureError::InvalidEncodedChunkLength)
        );
        let mut reserved = encoded;
        reserved[..2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            EncodedChunk::decode(&reserved),
            Err(ErasureError::InvalidEncodingIndex)
        );
    }

    #[test]
    fn systematic_chunks_are_exact_source_bytes() {
        let kind = ErasureMessageKind::HeaderAndMac;
        let original = message(kind);
        let chunks = encode_chunks(kind, &original, &[0, 1, 2]).unwrap();
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.index as usize, index);
            assert_eq!(
                chunk.symbol.as_slice(),
                &original[index * SYMBOL_BYTES..(index + 1) * SYMBOL_BYTES]
            );
        }
    }

    #[test]
    fn rfc5510_systematic_vandermonde_parity_vector_is_frozen() {
        let kind = ErasureMessageKind::HeaderAndMac;
        let original = message(kind);
        let chunk = encode_chunks(kind, &original, &[3]).unwrap().remove(0);
        assert_eq!(
            chunk.symbol,
            [
                0x9f, 0x8c, 0xe1, 0x2a, 0x6b, 0xb4, 0xfd, 0x3e, 0xf7, 0xf9, 0x79, 0x63, 0xe3, 0xed,
                0xe1, 0xca, 0x6b, 0x5c, 0xf5, 0xd6, 0x78, 0xa8, 0x8e, 0x22, 0x14, 0xb4, 0x99, 0x8e,
                0xe3, 0x2c, 0x75, 0xb6,
            ]
        );
    }

    #[test]
    fn every_revision_one_payload_recovers_from_systematic_parity_and_mixed_sets() {
        for kind in [
            ErasureMessageKind::HeaderAndMac,
            ErasureMessageKind::MlKem768PublicKeyVector,
            ErasureMessageKind::MlKem768Ciphertext1,
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
        ] {
            let count = kind.source_chunks();
            round_trip(kind, (0..count as u16).collect());
            round_trip(kind, (count as u16..(count * 2) as u16).collect());
            let mixed = (0..count)
                .map(|offset| {
                    if offset % 2 == 0 {
                        offset as u16
                    } else {
                        (count + offset * 7) as u16
                    }
                })
                .rev()
                .collect();
            round_trip(kind, mixed);
        }
    }

    #[test]
    fn deterministic_loss_and_reordering_samples_are_mds() {
        let kind = ErasureMessageKind::MlKem768PublicKeyVector;
        let count = kind.source_chunks();
        let original = message(kind);
        let mut state = 0x6d5a_56e9_u32;
        for _ in 0..32 {
            let mut indexes = Vec::with_capacity(count);
            while indexes.len() < count {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let candidate = (state % (MAX_ENCODING_INDEX as u32 + 1)) as u16;
                if !indexes.contains(&candidate) {
                    indexes.push(candidate);
                }
            }
            let chunks = encode_chunks(kind, &original, &indexes).unwrap();
            assert_eq!(decode_message(kind, &chunks).unwrap(), original);
        }
    }

    #[test]
    fn exact_duplicates_are_idempotent_and_conflicts_fail_closed() {
        let kind = ErasureMessageKind::HeaderAndMac;
        let original = message(kind);
        let mut chunks = encode_chunks(kind, &original, &[7, 9, 11]).unwrap();
        chunks.push(chunks[1].clone());
        chunks.reverse();
        assert_eq!(decode_message(kind, &chunks).unwrap(), original);

        let mut conflicting = chunks[0].clone();
        conflicting.symbol[0] ^= 1;
        chunks.push(conflicting);
        assert_eq!(
            decode_message(kind, &chunks),
            Err(ErasureError::ConflictingDuplicate)
        );
    }

    #[test]
    fn malformed_and_resource_exhaustion_inputs_fail_before_recovery() {
        let kind = ErasureMessageKind::HeaderAndMac;
        assert_eq!(
            encode_chunks(kind, &[0_u8; 95], &[0]),
            Err(ErasureError::InvalidMessageLength)
        );
        assert_eq!(
            encode_chunks(kind, &[0_u8; 96], &[u16::MAX]),
            Err(ErasureError::InvalidEncodingIndex)
        );
        assert_eq!(
            encode_chunks(kind, &[0_u8; 96], &[0_u16; MAX_RECEIVED_CHUNKS + 1],),
            Err(ErasureError::TooManyChunks)
        );

        let chunks = encode_chunks(kind, &[0_u8; 96], &[0, 1]).unwrap();
        assert_eq!(
            decode_message(kind, &chunks),
            Err(ErasureError::InsufficientUniqueChunks)
        );
        let too_many = vec![chunks[0].clone(); MAX_RECEIVED_CHUNKS + 1];
        assert_eq!(
            decode_message(kind, &too_many),
            Err(ErasureError::TooManyChunks)
        );
    }

    #[test]
    fn highest_allowed_encoding_index_round_trips() {
        let kind = ErasureMessageKind::HeaderAndMac;
        round_trip(kind, vec![MAX_ENCODING_INDEX, 17, 31]);
    }
}
