// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Canonical public-message codec for inactive ML-KEM Braid revision 1.
//!
//! This Layergram-owned `BM3` representation carries the exact logical
//! `epoch`, `type`, and optional erasure chunk from the public-domain
//! specification. It is private to the native crate and remains disconnected
//! from the state machine and C ABI.

use crate::erasure::{EncodedChunk, ErasureMessageKind, ENCODED_CHUNK_BYTES};
use crate::{MAX_COUNTER, MAX_MESSAGE_BYTES};

pub(crate) const HEADER_BYTES: usize = 24;
pub(crate) const NO_DATA_MESSAGE_BYTES: usize = HEADER_BYTES;
pub(crate) const DATA_MESSAGE_BYTES: usize = HEADER_BYTES + ENCODED_CHUNK_BYTES;

const MAGIC: &[u8; 3] = b"BM3";
const FORMAT_VERSION: u8 = 1;
const SUITE: u8 = 1;
const PROTOCOL_REVISION: u16 = 1;
const FLAGS_OFFSET: usize = 6;
const HEADER_LENGTH_OFFSET: usize = 7;
const TOTAL_LENGTH_OFFSET: usize = 8;
const PROTOCOL_REVISION_OFFSET: usize = 10;
const EPOCH_OFFSET: usize = 12;
const RESERVED_OFFSET: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum BraidMessageType {
    None = 0,
    Header = 1,
    EncapsulationKey = 2,
    EncapsulationKeyAndCiphertext1Ack = 3,
    Ciphertext1Ack = 4,
    Ciphertext1 = 5,
    Ciphertext2 = 6,
}

impl BraidMessageType {
    fn decode(value: u8) -> Result<Self, BraidMessageError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Header),
            2 => Ok(Self::EncapsulationKey),
            3 => Ok(Self::EncapsulationKeyAndCiphertext1Ack),
            4 => Ok(Self::Ciphertext1Ack),
            5 => Ok(Self::Ciphertext1),
            6 => Ok(Self::Ciphertext2),
            _ => Err(BraidMessageError::Type),
        }
    }

    pub(crate) const fn erasure_kind(self) -> Option<ErasureMessageKind> {
        match self {
            Self::None | Self::Ciphertext1Ack => None,
            Self::Header => Some(ErasureMessageKind::HeaderAndMac),
            Self::EncapsulationKey | Self::EncapsulationKeyAndCiphertext1Ack => {
                Some(ErasureMessageKind::MlKem768PublicKeyVector)
            }
            Self::Ciphertext1 => Some(ErasureMessageKind::MlKem768Ciphertext1),
            Self::Ciphertext2 => Some(ErasureMessageKind::MlKem768Ciphertext2AndMac),
        }
    }

    const fn requires_chunk(self) -> bool {
        self.erasure_kind().is_some()
    }

    const fn encoded_length(self) -> usize {
        if self.requires_chunk() {
            DATA_MESSAGE_BYTES
        } else {
            NO_DATA_MESSAGE_BYTES
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BraidPublicMessage {
    epoch: u64,
    message_type: BraidMessageType,
    chunk: Option<EncodedChunk>,
}

impl BraidPublicMessage {
    pub(crate) fn without_data(
        epoch: u64,
        message_type: BraidMessageType,
    ) -> Result<Self, BraidMessageError> {
        Self::from_parts(epoch, message_type, None)
    }

    pub(crate) fn with_chunk(
        epoch: u64,
        message_type: BraidMessageType,
        chunk: EncodedChunk,
    ) -> Result<Self, BraidMessageError> {
        Self::from_parts(epoch, message_type, Some(chunk))
    }

    fn from_parts(
        epoch: u64,
        message_type: BraidMessageType,
        chunk: Option<EncodedChunk>,
    ) -> Result<Self, BraidMessageError> {
        validate_epoch(epoch)?;
        if message_type.requires_chunk() != chunk.is_some() {
            return Err(BraidMessageError::Shape);
        }
        Ok(Self {
            epoch,
            message_type,
            chunk,
        })
    }

    pub(crate) const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) const fn message_type(&self) -> BraidMessageType {
        self.message_type
    }

    pub(crate) fn chunk(&self) -> Option<&EncodedChunk> {
        self.chunk.as_ref()
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let total_length = self.message_type.encoded_length();
        debug_assert!(total_length <= MAX_MESSAGE_BYTES as usize);
        let mut encoded = vec![0_u8; total_length];
        encoded[..MAGIC.len()].copy_from_slice(MAGIC);
        encoded[3] = FORMAT_VERSION;
        encoded[4] = SUITE;
        encoded[5] = self.message_type as u8;
        encoded[FLAGS_OFFSET] = 0;
        encoded[HEADER_LENGTH_OFFSET] = HEADER_BYTES as u8;
        encoded[TOTAL_LENGTH_OFFSET..PROTOCOL_REVISION_OFFSET]
            .copy_from_slice(&(total_length as u16).to_be_bytes());
        encoded[PROTOCOL_REVISION_OFFSET..EPOCH_OFFSET]
            .copy_from_slice(&PROTOCOL_REVISION.to_be_bytes());
        encoded[EPOCH_OFFSET..RESERVED_OFFSET].copy_from_slice(&self.epoch.to_be_bytes());
        if let Some(chunk) = &self.chunk {
            encoded[HEADER_BYTES..].copy_from_slice(&chunk.encode());
        }
        encoded
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, BraidMessageError> {
        if encoded.len() != NO_DATA_MESSAGE_BYTES && encoded.len() != DATA_MESSAGE_BYTES {
            return Err(BraidMessageError::Length);
        }
        if &encoded[..MAGIC.len()] != MAGIC {
            return Err(BraidMessageError::Magic);
        }
        if encoded[3] != FORMAT_VERSION
            || encoded[4] != SUITE
            || encoded[FLAGS_OFFSET] != 0
            || encoded[HEADER_LENGTH_OFFSET] != HEADER_BYTES as u8
            || u16::from_be_bytes([
                encoded[TOTAL_LENGTH_OFFSET],
                encoded[TOTAL_LENGTH_OFFSET + 1],
            ]) as usize
                != encoded.len()
            || u16::from_be_bytes([
                encoded[PROTOCOL_REVISION_OFFSET],
                encoded[PROTOCOL_REVISION_OFFSET + 1],
            ]) != PROTOCOL_REVISION
            || encoded[RESERVED_OFFSET..HEADER_BYTES]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(BraidMessageError::Format);
        }

        let message_type = BraidMessageType::decode(encoded[5])?;
        if encoded.len() != message_type.encoded_length() {
            return Err(BraidMessageError::Shape);
        }
        let epoch = u64::from_be_bytes(
            encoded[EPOCH_OFFSET..RESERVED_OFFSET]
                .try_into()
                .map_err(|_| BraidMessageError::Length)?,
        );
        validate_epoch(epoch)?;
        let chunk = if message_type.requires_chunk() {
            Some(
                EncodedChunk::decode(&encoded[HEADER_BYTES..])
                    .map_err(|_| BraidMessageError::Chunk)?,
            )
        } else {
            None
        };
        let decoded = Self::from_parts(epoch, message_type, chunk)?;
        if decoded.encode().as_slice() != encoded {
            return Err(BraidMessageError::Format);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BraidMessageError {
    Length,
    Magic,
    Format,
    Epoch,
    Type,
    Shape,
    Chunk,
}

fn validate_epoch(epoch: u64) -> Result<(), BraidMessageError> {
    if epoch == 0 || epoch > MAX_COUNTER {
        Err(BraidMessageError::Epoch)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erasure::{decode_message, encode_chunks, MAX_ENCODING_INDEX};

    #[test]
    fn independent_binary_goldens_are_frozen() {
        let none = BraidPublicMessage::without_data(1, BraidMessageType::None).unwrap();
        assert_eq!(
            hex(&none.encode()),
            "424d33010100001800180001000000000000000100000000"
        );

        let mut chunk_bytes = [0_u8; ENCODED_CHUNK_BYTES];
        chunk_bytes[..2].copy_from_slice(&0x1234_u16.to_be_bytes());
        for (index, value) in chunk_bytes[2..].iter_mut().enumerate() {
            *value = index as u8;
        }
        let header = BraidPublicMessage::with_chunk(
            0x0102_0304_0506_0708,
            BraidMessageType::Header,
            EncodedChunk::decode(&chunk_bytes).unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex(&header.encode()),
            "424d330101010018003a00010102030405060708000000001234000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );

        let ack = BraidPublicMessage::without_data(MAX_COUNTER, BraidMessageType::Ciphertext1Ack)
            .unwrap();
        assert_eq!(
            hex(&ack.encode()),
            "424d330101040018001800017fffffffffffffff00000000"
        );
    }

    #[test]
    fn all_seven_message_types_round_trip_canonically() {
        for message_type in [
            BraidMessageType::None,
            BraidMessageType::Header,
            BraidMessageType::EncapsulationKey,
            BraidMessageType::EncapsulationKeyAndCiphertext1Ack,
            BraidMessageType::Ciphertext1Ack,
            BraidMessageType::Ciphertext1,
            BraidMessageType::Ciphertext2,
        ] {
            let message = if message_type.requires_chunk() {
                BraidPublicMessage::with_chunk(
                    7,
                    message_type,
                    EncodedChunk::decode(&[0x5a; ENCODED_CHUNK_BYTES]).unwrap(),
                )
                .unwrap()
            } else {
                BraidPublicMessage::without_data(7, message_type).unwrap()
            };
            let encoded = message.encode();
            assert_eq!(BraidPublicMessage::decode(&encoded).unwrap(), message);
            assert_eq!(message.epoch(), 7);
            assert_eq!(message.message_type(), message_type);
            assert_eq!(message.chunk().is_some(), message_type.requires_chunk());
        }
    }

    #[test]
    fn message_type_selects_exact_erasure_payload_class() {
        for (message_type, erasure_kind) in [
            (BraidMessageType::Header, ErasureMessageKind::HeaderAndMac),
            (
                BraidMessageType::EncapsulationKey,
                ErasureMessageKind::MlKem768PublicKeyVector,
            ),
            (
                BraidMessageType::EncapsulationKeyAndCiphertext1Ack,
                ErasureMessageKind::MlKem768PublicKeyVector,
            ),
            (
                BraidMessageType::Ciphertext1,
                ErasureMessageKind::MlKem768Ciphertext1,
            ),
            (
                BraidMessageType::Ciphertext2,
                ErasureMessageKind::MlKem768Ciphertext2AndMac,
            ),
        ] {
            assert_eq!(message_type.erasure_kind(), Some(erasure_kind));
            let payload: Vec<u8> = (0..erasure_kind.message_bytes())
                .map(|index| ((index * 73 + 19) & 0xff) as u8)
                .collect();
            let indexes: Vec<u16> = (0..erasure_kind.source_chunks() as u16).collect();
            let chunks = encode_chunks(erasure_kind, &payload, &indexes).unwrap();
            let decoded_chunks: Vec<EncodedChunk> = chunks
                .into_iter()
                .map(|chunk| {
                    let message = BraidPublicMessage::with_chunk(3, message_type, chunk).unwrap();
                    BraidPublicMessage::decode(&message.encode())
                        .unwrap()
                        .chunk()
                        .unwrap()
                        .clone()
                })
                .collect();
            assert_eq!(
                decode_message(erasure_kind, &decoded_chunks).unwrap(),
                payload
            );
        }
        assert_eq!(BraidMessageType::None.erasure_kind(), None);
        assert_eq!(BraidMessageType::Ciphertext1Ack.erasure_kind(), None);
    }

    #[test]
    fn constructors_reject_type_payload_mismatches_and_invalid_epochs() {
        let chunk = EncodedChunk::decode(&[0x11; ENCODED_CHUNK_BYTES]).unwrap();
        assert_eq!(
            BraidPublicMessage::without_data(1, BraidMessageType::Header),
            Err(BraidMessageError::Shape)
        );
        assert_eq!(
            BraidPublicMessage::with_chunk(1, BraidMessageType::None, chunk),
            Err(BraidMessageError::Shape)
        );
        assert_eq!(
            BraidPublicMessage::without_data(0, BraidMessageType::None),
            Err(BraidMessageError::Epoch)
        );
        assert_eq!(
            BraidPublicMessage::without_data(MAX_COUNTER + 1, BraidMessageType::None),
            Err(BraidMessageError::Epoch)
        );
    }

    #[test]
    fn malformed_headers_types_shapes_and_chunks_fail_closed() {
        let valid = BraidPublicMessage::without_data(1, BraidMessageType::None).unwrap();
        let encoded = valid.encode();
        assert_eq!(
            BraidPublicMessage::decode(&[]),
            Err(BraidMessageError::Length)
        );
        assert_eq!(
            BraidPublicMessage::decode(&encoded[..encoded.len() - 1]),
            Err(BraidMessageError::Length)
        );

        for (offset, value, error) in [
            (0, 0, BraidMessageError::Magic),
            (3, 2, BraidMessageError::Format),
            (4, 2, BraidMessageError::Format),
            (5, 7, BraidMessageError::Type),
            (FLAGS_OFFSET, 1, BraidMessageError::Format),
            (HEADER_LENGTH_OFFSET, 23, BraidMessageError::Format),
            (PROTOCOL_REVISION_OFFSET + 1, 2, BraidMessageError::Format),
            (RESERVED_OFFSET, 1, BraidMessageError::Format),
        ] {
            let mut malformed = encoded.clone();
            malformed[offset] = value;
            assert_eq!(BraidPublicMessage::decode(&malformed), Err(error));
        }

        let mut wrong_total = encoded.clone();
        wrong_total[TOTAL_LENGTH_OFFSET..PROTOCOL_REVISION_OFFSET]
            .copy_from_slice(&(DATA_MESSAGE_BYTES as u16).to_be_bytes());
        assert_eq!(
            BraidPublicMessage::decode(&wrong_total),
            Err(BraidMessageError::Format)
        );

        let mut missing_chunk = encoded.clone();
        missing_chunk[5] = BraidMessageType::Header as u8;
        assert_eq!(
            BraidPublicMessage::decode(&missing_chunk),
            Err(BraidMessageError::Shape)
        );

        let mut extra_chunk = vec![0_u8; DATA_MESSAGE_BYTES];
        extra_chunk[..encoded.len()].copy_from_slice(&encoded);
        extra_chunk[TOTAL_LENGTH_OFFSET..PROTOCOL_REVISION_OFFSET]
            .copy_from_slice(&(DATA_MESSAGE_BYTES as u16).to_be_bytes());
        assert_eq!(
            BraidPublicMessage::decode(&extra_chunk),
            Err(BraidMessageError::Shape)
        );

        let header = BraidPublicMessage::with_chunk(
            1,
            BraidMessageType::Header,
            EncodedChunk::decode(&[0x22; ENCODED_CHUNK_BYTES]).unwrap(),
        )
        .unwrap();
        let mut reserved_index = header.encode();
        reserved_index[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            BraidPublicMessage::decode(&reserved_index),
            Err(BraidMessageError::Chunk)
        );
    }

    #[test]
    fn epoch_boundaries_and_wire_size_are_exact() {
        let minimum = BraidPublicMessage::without_data(1, BraidMessageType::None).unwrap();
        assert_eq!(minimum.encode().len(), NO_DATA_MESSAGE_BYTES);
        let maximum = BraidPublicMessage::with_chunk(
            MAX_COUNTER,
            BraidMessageType::Ciphertext2,
            EncodedChunk::decode(&[
                (MAX_ENCODING_INDEX >> 8) as u8,
                MAX_ENCODING_INDEX as u8,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
                0x33,
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(maximum.encode().len(), DATA_MESSAGE_BYTES);
        assert!(DATA_MESSAGE_BYTES <= MAX_MESSAGE_BYTES as usize);

        let mut zero_epoch = minimum.encode();
        zero_epoch[EPOCH_OFFSET..RESERVED_OFFSET].fill(0);
        assert_eq!(
            BraidPublicMessage::decode(&zero_epoch),
            Err(BraidMessageError::Epoch)
        );
        let mut high_bit_epoch = minimum.encode();
        high_bit_epoch[EPOCH_OFFSET..RESERVED_OFFSET]
            .copy_from_slice(&0x8000_0000_0000_0000_u64.to_be_bytes());
        assert_eq!(
            BraidPublicMessage::decode(&high_bit_epoch),
            Err(BraidMessageError::Epoch)
        );
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
}
