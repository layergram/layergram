// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Inactive ML-KEM Braid revision-1 ratcheted authenticator.
//!
//! This module freezes Layergram's implementation-defined protocol domain and
//! the exact `KDF_AUTH`, `KDF_OK`, header-MAC, and ciphertext-MAC operations
//! from the public-domain ML-KEM Braid specification. It is private to the
//! native crate and remains disconnected from the state machine and C ABI.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::incremental_mlkem::{
    CIPHERTEXT_PART_ONE_BYTES, CIPHERTEXT_PART_TWO_BYTES, PUBLIC_KEY_HEADER_BYTES,
    SHARED_SECRET_BYTES,
};
use crate::MAX_COUNTER;

pub(crate) const AUTH_KEY_BYTES: usize = 32;
pub(crate) const MAC_BYTES: usize = 32;
pub(crate) const PROTOCOL_INFO: &[u8] = b"LayergramV3_MLKEM768_HMAC-SHA256";

const AUTHENTICATOR_UPDATE_LABEL: &[u8] = b":Authenticator Update";
const SCKA_KEY_LABEL: &[u8] = b":SCKA Key";
const HEADER_MAC_LABEL: &[u8] = b":ekheader";
const CIPHERTEXT_MAC_LABEL: &[u8] = b":ciphertext";
const AUTH_MATERIAL_BYTES: usize = AUTH_KEY_BYTES * 2;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BraidAuthenticatorError {
    InvalidLength,
    InvalidEpoch,
    Authentication,
    PrimitiveFailure,
}

/// Immutable ratcheted-authenticator state candidate.
///
/// It intentionally implements neither `Clone` nor `Debug`. Calling
/// [`BraidAuthenticator::ratchet`] derives a detached successor while retaining
/// this prior state for an external atomic-commit decision.
pub(crate) struct BraidAuthenticator {
    root_key: [u8; AUTH_KEY_BYTES],
    mac_key: [u8; AUTH_KEY_BYTES],
}

impl BraidAuthenticator {
    /// Implements `Authenticator.Init(epoch, key)` from revision 1.
    pub(crate) fn initialize(
        epoch: u64,
        initial_key: &[u8],
    ) -> Result<Self, BraidAuthenticatorError> {
        validate_epoch(epoch)?;
        require_exact_length(initial_key, AUTH_KEY_BYTES)?;
        derive_authenticator(&[0_u8; AUTH_KEY_BYTES], initial_key, epoch)
    }

    /// Restores already-authenticated state from the canonical `LB3` payload.
    pub(crate) fn restore(
        root_key: &[u8],
        mac_key: &[u8],
    ) -> Result<Self, BraidAuthenticatorError> {
        require_exact_length(root_key, AUTH_KEY_BYTES)?;
        require_exact_length(mac_key, AUTH_KEY_BYTES)?;
        let mut owned_root = [0_u8; AUTH_KEY_BYTES];
        let mut owned_mac = [0_u8; AUTH_KEY_BYTES];
        owned_root.copy_from_slice(root_key);
        owned_mac.copy_from_slice(mac_key);
        Ok(Self {
            root_key: owned_root,
            mac_key: owned_mac,
        })
    }

    pub(crate) fn root_key(&self) -> &[u8; AUTH_KEY_BYTES] {
        &self.root_key
    }

    pub(crate) fn mac_key(&self) -> &[u8; AUTH_KEY_BYTES] {
        &self.mac_key
    }

    /// Implements `Authenticator.Update(epoch, key)` without mutating the
    /// durable prior state.
    pub(crate) fn ratchet(
        &self,
        epoch: u64,
        output_key: &BraidOutputKey,
    ) -> Result<Self, BraidAuthenticatorError> {
        validate_epoch(epoch)?;
        derive_authenticator(&self.root_key, output_key.as_bytes(), epoch)
    }

    pub(crate) fn mac_header(
        &self,
        epoch: u64,
        header: &[u8],
    ) -> Result<[u8; MAC_BYTES], BraidAuthenticatorError> {
        validate_epoch(epoch)?;
        require_exact_length(header, PUBLIC_KEY_HEADER_BYTES)?;
        compute_mac(&self.mac_key, HEADER_MAC_LABEL, epoch, &[header])
    }

    pub(crate) fn verify_header(
        &self,
        epoch: u64,
        header: &[u8],
        expected_mac: &[u8],
    ) -> Result<(), BraidAuthenticatorError> {
        validate_epoch(epoch)?;
        require_exact_length(header, PUBLIC_KEY_HEADER_BYTES)?;
        require_exact_length(expected_mac, MAC_BYTES)?;
        verify_mac(
            &self.mac_key,
            HEADER_MAC_LABEL,
            epoch,
            &[header],
            expected_mac,
        )
    }

    pub(crate) fn mac_ciphertext(
        &self,
        epoch: u64,
        ciphertext_part_one: &[u8],
        ciphertext_part_two: &[u8],
    ) -> Result<[u8; MAC_BYTES], BraidAuthenticatorError> {
        validate_epoch(epoch)?;
        require_exact_length(ciphertext_part_one, CIPHERTEXT_PART_ONE_BYTES)?;
        require_exact_length(ciphertext_part_two, CIPHERTEXT_PART_TWO_BYTES)?;
        compute_mac(
            &self.mac_key,
            CIPHERTEXT_MAC_LABEL,
            epoch,
            &[ciphertext_part_one, ciphertext_part_two],
        )
    }

    pub(crate) fn verify_ciphertext(
        &self,
        epoch: u64,
        ciphertext_part_one: &[u8],
        ciphertext_part_two: &[u8],
        expected_mac: &[u8],
    ) -> Result<(), BraidAuthenticatorError> {
        validate_epoch(epoch)?;
        require_exact_length(ciphertext_part_one, CIPHERTEXT_PART_ONE_BYTES)?;
        require_exact_length(ciphertext_part_two, CIPHERTEXT_PART_TWO_BYTES)?;
        require_exact_length(expected_mac, MAC_BYTES)?;
        verify_mac(
            &self.mac_key,
            CIPHERTEXT_MAC_LABEL,
            epoch,
            &[ciphertext_part_one, ciphertext_part_two],
            expected_mac,
        )
    }

    fn wipe(&mut self) {
        self.root_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl Drop for BraidAuthenticator {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Implements the revision-1 `KDF_OK(shared_secret, epoch)` operation.
pub(crate) fn derive_output_key(
    shared_secret: &[u8],
    epoch: u64,
) -> Result<BraidOutputKey, BraidAuthenticatorError> {
    validate_epoch(epoch)?;
    require_exact_length(shared_secret, SHARED_SECRET_BYTES)?;

    let epoch_bytes = epoch.to_be_bytes();
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut output = [0_u8; SHARED_SECRET_BYTES];
    let result =
        hkdf.expand_multi_info(&[PROTOCOL_INFO, SCKA_KEY_LABEL, &epoch_bytes], &mut output);
    if result.is_err() {
        output.zeroize();
        return Err(BraidAuthenticatorError::PrimitiveFailure);
    }
    Ok(BraidOutputKey { bytes: output })
}

/// Zeroizing owner for the epoch key emitted by `KDF_OK`.
pub(crate) struct BraidOutputKey {
    bytes: [u8; SHARED_SECRET_BYTES],
}

impl BraidOutputKey {
    pub(crate) fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.bytes
    }

    fn wipe(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for BraidOutputKey {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn derive_authenticator(
    root_key: &[u8; AUTH_KEY_BYTES],
    update_key: &[u8],
    epoch: u64,
) -> Result<BraidAuthenticator, BraidAuthenticatorError> {
    let epoch_bytes = epoch.to_be_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), update_key);
    let mut material = [0_u8; AUTH_MATERIAL_BYTES];
    let result = hkdf.expand_multi_info(
        &[PROTOCOL_INFO, AUTHENTICATOR_UPDATE_LABEL, &epoch_bytes],
        &mut material,
    );
    if result.is_err() {
        material.zeroize();
        return Err(BraidAuthenticatorError::PrimitiveFailure);
    }

    let mut next_root = [0_u8; AUTH_KEY_BYTES];
    let mut next_mac = [0_u8; AUTH_KEY_BYTES];
    next_root.copy_from_slice(&material[..AUTH_KEY_BYTES]);
    next_mac.copy_from_slice(&material[AUTH_KEY_BYTES..]);
    material.zeroize();
    Ok(BraidAuthenticator {
        root_key: next_root,
        mac_key: next_mac,
    })
}

fn compute_mac(
    mac_key: &[u8; AUTH_KEY_BYTES],
    label: &[u8],
    epoch: u64,
    values: &[&[u8]],
) -> Result<[u8; MAC_BYTES], BraidAuthenticatorError> {
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|_| BraidAuthenticatorError::PrimitiveFailure)?;
    update_mac(&mut mac, label, epoch, values);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_mac(
    mac_key: &[u8; AUTH_KEY_BYTES],
    label: &[u8],
    epoch: u64,
    values: &[&[u8]],
    expected_mac: &[u8],
) -> Result<(), BraidAuthenticatorError> {
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|_| BraidAuthenticatorError::PrimitiveFailure)?;
    update_mac(&mut mac, label, epoch, values);
    mac.verify_slice(expected_mac)
        .map_err(|_| BraidAuthenticatorError::Authentication)
}

fn update_mac(mac: &mut HmacSha256, label: &[u8], epoch: u64, values: &[&[u8]]) {
    mac.update(PROTOCOL_INFO);
    mac.update(label);
    mac.update(&epoch.to_be_bytes());
    for value in values {
        mac.update(value);
    }
}

fn validate_epoch(epoch: u64) -> Result<(), BraidAuthenticatorError> {
    if epoch == 0 || epoch > MAX_COUNTER {
        Err(BraidAuthenticatorError::InvalidEpoch)
    } else {
        Ok(())
    }
}

fn require_exact_length(bytes: &[u8], expected: usize) -> Result<(), BraidAuthenticatorError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(BraidAuthenticatorError::InvalidLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_domain_is_frozen() {
        assert_eq!(PROTOCOL_INFO, b"LayergramV3_MLKEM768_HMAC-SHA256");
    }

    #[test]
    fn independent_golden_vectors_freeze_every_revision_one_primitive() {
        // Expected bytes were produced independently with Python 3's standard
        // `hashlib`/`hmac` implementation of RFC 5869 and HMAC-SHA-256.
        let auth = BraidAuthenticator::initialize(1, &[0x11; AUTH_KEY_BYTES]).unwrap();
        assert_eq!(
            hex(auth.root_key()),
            "13df9e7f5632599df46117f0e287de72bb4a974f68256161dfb8400359251d00"
        );
        assert_eq!(
            hex(auth.mac_key()),
            "4ec6a0d51543fcb45838bd4b13f16eb7e75b1eb533d9362b44fb89ab546c4449"
        );

        let mut header = [0_u8; PUBLIC_KEY_HEADER_BYTES];
        for (index, byte) in header.iter_mut().enumerate() {
            *byte = index as u8;
        }
        assert_eq!(
            hex(&auth.mac_header(1, &header).unwrap()),
            "1a618178126d0fe6f6422e4970734e6aad038c4473c705672c3296b161ebd97f"
        );

        let ciphertext: Vec<u8> = (0..CIPHERTEXT_PART_ONE_BYTES + CIPHERTEXT_PART_TWO_BYTES)
            .map(|index| (index % 251) as u8)
            .collect();
        let (ciphertext_part_one, ciphertext_part_two) =
            ciphertext.split_at(CIPHERTEXT_PART_ONE_BYTES);
        assert_eq!(
            hex(&auth
                .mac_ciphertext(1, ciphertext_part_one, ciphertext_part_two)
                .unwrap()),
            "bee5414a01b3e1df7d447b1e37526c92e18f9bc12ce81461384c98e6b3dae0c6"
        );

        let output = derive_output_key(&[0x22; SHARED_SECRET_BYTES], 7).unwrap();
        assert_eq!(
            hex(output.as_bytes()),
            "62f99bbddf1c0cf2a78273da7c482a603f45b4db70e26f534c4156a0a3383cd1"
        );
        let next = auth.ratchet(7, &output).unwrap();
        assert_eq!(
            hex(next.root_key()),
            "22dec5bd7fb7c619af2f1704691e22aaa24ef6942648b777263dc7c4111fe93d"
        );
        assert_eq!(
            hex(next.mac_key()),
            "464c7b7482a569bca8d9b7748b1814dccba494ef5424236264d3253a08f6cfc6"
        );
    }

    #[test]
    fn verification_is_exact_and_fail_closed() {
        let auth = BraidAuthenticator::initialize(1, &[0x33; AUTH_KEY_BYTES]).unwrap();
        let header = [0x44; PUBLIC_KEY_HEADER_BYTES];
        let tag = auth.mac_header(1, &header).unwrap();
        assert_eq!(auth.verify_header(1, &header, &tag), Ok(()));

        let mut wrong_tag = tag;
        wrong_tag[0] ^= 1;
        assert_eq!(
            auth.verify_header(1, &header, &wrong_tag),
            Err(BraidAuthenticatorError::Authentication)
        );
        let mut wrong_header = header;
        wrong_header[0] ^= 1;
        assert_eq!(
            auth.verify_header(1, &wrong_header, &tag),
            Err(BraidAuthenticatorError::Authentication)
        );
        assert_eq!(
            auth.verify_header(2, &header, &tag),
            Err(BraidAuthenticatorError::Authentication)
        );
    }

    #[test]
    fn header_and_ciphertext_domains_cannot_be_reinterpreted() {
        let auth = BraidAuthenticator::initialize(1, &[0x55; AUTH_KEY_BYTES]).unwrap();
        let header = [0x66; PUBLIC_KEY_HEADER_BYTES];
        let header_tag = auth.mac_header(1, &header).unwrap();
        let ciphertext_part_one = [0x66; CIPHERTEXT_PART_ONE_BYTES];
        let ciphertext_part_two = [0x66; CIPHERTEXT_PART_TWO_BYTES];
        let ciphertext_tag = auth
            .mac_ciphertext(1, &ciphertext_part_one, &ciphertext_part_two)
            .unwrap();
        assert_ne!(header_tag, ciphertext_tag);
        assert_eq!(
            auth.verify_ciphertext(1, &ciphertext_part_one, &ciphertext_part_two, &header_tag,),
            Err(BraidAuthenticatorError::Authentication)
        );
    }

    #[test]
    fn every_boundary_requires_exact_lengths_and_signed_63_epochs() {
        assert!(matches!(
            BraidAuthenticator::initialize(1, &[0_u8; AUTH_KEY_BYTES - 1]),
            Err(BraidAuthenticatorError::InvalidLength)
        ));
        assert!(matches!(
            derive_output_key(&[0_u8; SHARED_SECRET_BYTES + 1], 1),
            Err(BraidAuthenticatorError::InvalidLength)
        ));
        assert!(matches!(
            BraidAuthenticator::initialize(0, &[0_u8; AUTH_KEY_BYTES]),
            Err(BraidAuthenticatorError::InvalidEpoch)
        ));
        assert!(matches!(
            BraidAuthenticator::initialize(MAX_COUNTER + 1, &[0_u8; AUTH_KEY_BYTES]),
            Err(BraidAuthenticatorError::InvalidEpoch)
        ));

        let auth = BraidAuthenticator::initialize(MAX_COUNTER, &[0x71; AUTH_KEY_BYTES]).unwrap();
        assert!(auth
            .mac_header(MAX_COUNTER, &[0_u8; PUBLIC_KEY_HEADER_BYTES])
            .is_ok());
        assert_eq!(
            auth.mac_header(1, &[0_u8; PUBLIC_KEY_HEADER_BYTES - 1]),
            Err(BraidAuthenticatorError::InvalidLength)
        );
        assert_eq!(
            auth.mac_ciphertext(
                1,
                &[0_u8; CIPHERTEXT_PART_ONE_BYTES + 1],
                &[0_u8; CIPHERTEXT_PART_TWO_BYTES],
            ),
            Err(BraidAuthenticatorError::InvalidLength)
        );
        assert_eq!(
            auth.mac_ciphertext(
                1,
                &[0_u8; CIPHERTEXT_PART_ONE_BYTES],
                &[0_u8; CIPHERTEXT_PART_TWO_BYTES - 1],
            ),
            Err(BraidAuthenticatorError::InvalidLength)
        );
        assert_eq!(
            auth.verify_header(1, &[0_u8; PUBLIC_KEY_HEADER_BYTES], &[0_u8; MAC_BYTES - 1],),
            Err(BraidAuthenticatorError::InvalidLength)
        );
    }

    #[test]
    fn restore_is_exact_and_detached_ratchets_do_not_mutate_the_prior() {
        let auth = BraidAuthenticator::initialize(1, &[0x81; AUTH_KEY_BYTES]).unwrap();
        let root_before = *auth.root_key();
        let mac_before = *auth.mac_key();
        let restored = BraidAuthenticator::restore(&root_before, &mac_before).unwrap();
        assert_eq!(restored.root_key(), &root_before);
        assert_eq!(restored.mac_key(), &mac_before);

        let output = derive_output_key(&[0x91; SHARED_SECRET_BYTES], 2).unwrap();
        let next = auth.ratchet(2, &output).unwrap();
        assert_eq!(auth.root_key(), &root_before);
        assert_eq!(auth.mac_key(), &mac_before);
        assert_ne!(next.root_key(), auth.root_key());
        assert!(matches!(
            BraidAuthenticator::restore(&root_before[..AUTH_KEY_BYTES - 1], &mac_before),
            Err(BraidAuthenticatorError::InvalidLength)
        ));
    }

    #[test]
    fn owned_secrets_are_zeroized_by_explicit_drop_paths() {
        let mut auth = BraidAuthenticator::initialize(1, &[0xa1; AUTH_KEY_BYTES]).unwrap();
        auth.wipe();
        assert!(auth.root_key.iter().all(|byte| *byte == 0));
        assert!(auth.mac_key.iter().all(|byte| *byte == 0));

        let mut output = derive_output_key(&[0xb2; SHARED_SECRET_BYTES], 1).unwrap();
        output.wipe();
        assert!(output.bytes.iter().all(|byte| *byte == 0));
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
