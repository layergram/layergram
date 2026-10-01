import CryptoKit
import Foundation

/// AES-GCM key schedule for one mailbox session.
///
/// The session secret is the 32-byte symmetric key produced by
/// `XWingMLKEM768X25519` (hybrid ML-KEM-768 + X25519). It exists only inside this
/// derivation: the owner generates one hybrid private key when it opens the
/// window, the client encapsulates against the owner public key exactly once at
/// attach, and the resulting secret is never written anywhere.
///
/// Request and response keys are derived from distinct HKDF info strings and are
/// salted with the session id, the client encapsulation and the owner public key,
/// so keys are bound to exactly one session, one encapsulation and one peer pair.
struct MailboxKeySet {
    let requestKey: SymmetricKey
    let responseKey: SymmetricKey

    static func derive(
        sharedSecret: SymmetricKey,
        sessionId: Data,
        clientEncapsulation: Data,
        ownerPublicKey: Data
    ) -> MailboxKeySet {
        var salt = Data()
        salt.append(sessionId)
        salt.append(clientEncapsulation)
        salt.append(ownerPublicKey)
        let version = MailboxConstants.protocolVersion
        let requestKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: salt,
            info: Data("layergram.system-keyboard.mailbox/v\(version)/request".utf8),
            outputByteCount: MailboxConstants.symmetricKeyBytes
        )
        let responseKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: salt,
            info: Data("layergram.system-keyboard.mailbox/v\(version)/response".utf8),
            outputByteCount: MailboxConstants.symmetricKeyBytes
        )
        return MailboxKeySet(requestKey: requestKey, responseKey: responseKey)
    }

    private func key(for kind: MailboxEnvelopeKind) -> SymmetricKey {
        switch kind {
        case .request: return requestKey
        case .response: return responseKey
        }
    }

    /// AES-GCM with a fresh random nonce per message. Returns the raw nonce and
    /// the ciphertext-with-tag separately so the wire format can carry both as
    /// strict base64 fields.
    func seal(_ plaintext: Data, kind: MailboxEnvelopeKind, aad: Data) throws -> (nonce: Data, ciphertext: Data) {
        do {
            let box = try AES.GCM.seal(plaintext, using: key(for: kind), authenticating: aad)
            guard let combined = box.combined, combined.count >= MailboxConstants.nonceBytes + MailboxConstants.authenticationTagBytes else {
                throw MailboxError.malformed(.cryptoFailure)
            }
            let nonce = combined.prefix(MailboxConstants.nonceBytes)
            let ciphertext = combined.suffix(from: MailboxConstants.nonceBytes)
            return (Data(nonce), Data(ciphertext))
        } catch let error as MailboxError {
            throw error
        } catch {
            throw MailboxError.malformed(.cryptoFailure)
        }
    }

    func open(nonce: Data, ciphertext: Data, kind: MailboxEnvelopeKind, aad: Data) throws -> Data {
        guard nonce.count == MailboxConstants.nonceBytes,
              ciphertext.count >= MailboxConstants.authenticationTagBytes else {
            throw MailboxError.malformed(.badLength)
        }
        do {
            let nonceValue = try AES.GCM.Nonce(data: nonce)
            let tagStart = ciphertext.count - MailboxConstants.authenticationTagBytes
            let tag = ciphertext.suffix(MailboxConstants.authenticationTagBytes)
            let body = ciphertext.prefix(tagStart)
            let box = try AES.GCM.SealedBox(nonce: nonceValue, ciphertext: body, tag: tag)
            let plaintext = try AES.GCM.open(box, using: key(for: kind), authenticating: aad)
            guard plaintext.count <= MailboxConstants.maxPlaintextBytes else {
                throw MailboxError.malformed(.tooLarge)
            }
            return plaintext
        } catch let error as MailboxError {
            throw error
        } catch {
            throw MailboxError.malformed(.cryptoFailure)
        }
    }
}

/// Owner hybrid private key, type-erased so the public owner/service API needs no
/// availability annotation while the package still deploys to iOS 15 / macOS 11.
///
/// The real `XWingMLKEM768X25519.PrivateKey` is captured by the decapsulation
/// closure, which is created only inside an `#available(iOS 26, macOS 26, *)`
/// branch. Only `publicKeyBytes` (public, 1216 bytes) is ever exposed; the closure
/// is internal. `revoke()` on the cores drops the reference. No zeroization of the
/// captured key material is promised.
struct MailboxOwnerPrivateKey {
    let publicKeyBytes: Data
    let decapsulate: (Data) throws -> SymmetricKey

    func decapsulating(_ encapsulated: Data) throws -> SymmetricKey {
        guard encapsulated.count == MailboxConstants.clientEncapsulationBytes else {
            throw MailboxError.malformed(.badLength)
        }
        do {
            let secret = try decapsulate(encapsulated)
            guard secret.bitCount == MailboxConstants.kemSharedSecretBytes * 8 else {
                throw MailboxError.malformed(.cryptoFailure)
            }
            return secret
        } catch let error as MailboxError {
            throw error
        } catch {
            throw MailboxError.malformed(.cryptoFailure)
        }
    }
}

/// The client-side half of one hybrid encapsulation.
struct MailboxClientSecret {
    let encapsulated: Data
    let sharedSecret: SymmetricKey
}

/// Hybrid post-quantum key agreement.
///
/// There is no classical helper and no fallback: on an OS without
/// `XWingMLKEM768X25519` every factory throws `unavailable` and the mailbox stays
/// closed. Session secrets remain in process memory and are never serialized.
enum MailboxKEMAgreement {
    static func generateOwnerKey() throws -> MailboxOwnerPrivateKey {
        guard MailboxCryptoAvailability.isSupported else {
            throw MailboxError.unavailable(.cryptoUnavailable)
        }
        #if compiler(>=6.2)
        guard #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) else {
            throw MailboxError.unavailable(.cryptoUnavailable)
        }
        do {
            let key = try XWingMLKEM768X25519.PrivateKey.generate()
            let publicKeyBytes = key.publicKey.rawRepresentation
            guard publicKeyBytes.count == MailboxConstants.ownerPublicKeyBytes else {
                throw MailboxError.malformed(.badLength)
            }
            return MailboxOwnerPrivateKey(publicKeyBytes: publicKeyBytes) { encapsulated in
                try key.decapsulate(encapsulated)
            }
        } catch let error as MailboxError {
            throw error
        } catch {
            throw MailboxError.unavailable(.cryptoUnavailable)
        }
        #else
        throw MailboxError.unavailable(.cryptoUnavailable)
        #endif
    }

    static func encapsulate(ownerPublicKey: Data) throws -> MailboxClientSecret {
        guard MailboxCryptoAvailability.isSupported else {
            throw MailboxError.unavailable(.cryptoUnavailable)
        }
        guard ownerPublicKey.count == MailboxConstants.ownerPublicKeyBytes else {
            throw MailboxError.malformed(.badLength)
        }
        #if compiler(>=6.2)
        guard #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) else {
            throw MailboxError.unavailable(.cryptoUnavailable)
        }
        do {
            let peer = try XWingMLKEM768X25519.PublicKey(rawRepresentation: ownerPublicKey)
            let result = try peer.encapsulate()
            guard result.encapsulated.count == MailboxConstants.clientEncapsulationBytes else {
                throw MailboxError.malformed(.badLength)
            }
            guard result.sharedSecret.bitCount == MailboxConstants.kemSharedSecretBytes * 8 else {
                throw MailboxError.malformed(.cryptoFailure)
            }
            return MailboxClientSecret(encapsulated: result.encapsulated, sharedSecret: result.sharedSecret)
        } catch let error as MailboxError {
            throw error
        } catch {
            throw MailboxError.malformed(.cryptoFailure)
        }
        #else
        throw MailboxError.unavailable(.cryptoUnavailable)
        #endif
    }
}
