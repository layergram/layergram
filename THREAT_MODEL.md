# Layergram Threat Model

This document describes, in plain language, what Layergram is designed to protect against and — just as importantly — what it does **not** protect against. It is written for users, integrators and security researchers evaluating whether Layergram fits their threat model.

Layergram is an end-to-end encrypted messaging tool that is transport-agnostic: encrypted payloads travel as opaque text (steganographic cover messages or direct deep links) over an untrusted transport of the user's choice (WhatsApp, Telegram, email, handwritten notes, etc.). This framing drives every decision below.

**Note on transport compatibility:** Steganographic embedding uses invisible Unicode characters and requires a transport that preserves them. For transports that strip or normalize zero-width characters, Layergram supports an alternative **direct message link** format (`layergram://m/<payload>`). Unlike steganography, deep links make the presence of encrypted communication visually obvious to anyone who sees the link.

## Design goals

- **Content confidentiality over untrusted transports.** Message content must not be readable by the transport operator, by anyone observing transport traffic, or by any intermediary between sender and recipient.
- **Pairwise authenticity.** If Alice imports what she believes to be Bob's public key and verifies it out-of-band, only Bob can produce messages that decrypt successfully with that key.
- **Deniable wire format.** An encrypted payload in isolation carries no sender or recipient identifiers, so no party in the transport chain can attribute it on a per-message basis.
- **Minimal infrastructure.** Layergram does not operate a server. There is no account, no key directory, no backend under Layergram's control. The absence of a server is itself part of the threat model — Layergram cannot be compelled to hand over data it never has.
- **Readable, auditable source.** All client code is public. The cryptographic choices are deliberately plain (X25519 + AES-GCM-256 + HKDF-SHA256) rather than exotic, so third parties can verify the implementation.

## What Layergram protects against

- **Transport operators reading message content.** Message bodies are encrypted end-to-end with an AEAD (AES-256-GCM) using a key derived via HKDF-SHA256 from an X25519 shared secret. The transport only sees ciphertext (or a cover message that looks innocuous).
- **Passive network observers reading message content.** Same as above: ciphertext is indistinguishable from random bytes.
- **Integrity tampering of message content.** AES-GCM's 16-byte authentication tag is verified on decryption. Any modified byte causes decryption to fail cleanly; it does not produce a silently corrupted plaintext.
- **Per-message attribution in the wire format.** The serialized encrypted payload contains no sender or recipient identifier, no version byte, and no protocol marker. Attribution is only possible by someone who already holds one of the private keys involved.
- **Casual impersonation of a known contact.** When a contact has been verified via the in-app SAS (Short Authentication String) ceremony, any mismatch between the locally-stored public key and the key an attacker tries to substitute will cause the decrypt path to fail and the SAS code to change visibly.
- **At-rest disclosure from a locked device.** Identity material, contacts and messages are held in the OS secure storage (Keychain / Keystore) and in an app-lock-gated local database. The app lock uses a KDF-derived PIN hash (not plaintext), with a constant-time comparison, random per-install salt, rate limiting, and exponential backoff on failed attempts.
- **Silent identity-format drift.** Identity derivation is explicitly versioned (`v1` legacy sha256, `v2` HKDF-SHA256 with domain separation). Legacy identities are never silently upgraded, and a one-time localized notice informs users with `v1` identities that they should migrate.
- **Recovery-phrase-only compromise.** Knowledge of the mnemonic alone is enough to recreate identity keys by design — Layergram inherits the BIP39 semantics — but identity-scoped data in the encrypted vault and in session caches is never exposed until the device is unlocked.
- **Limited deniability for passphrase-protected data.** When the optional passphrase feature is used, Layergram derives a separate identity/keyspace from the mnemonic+passphrase and keeps the passphrase-derived keys in memory only while active. If the user unlocks the app without activating the passphrase, the base vault remains visible while passphrase-scoped messages stay absent. This can provide a practical, limited form of plausible deniability against casual inspection.

## What Layergram does *not* protect against

Layergram is honest about its limits. The following concerns are explicitly out of scope or only partially mitigated, and users who require these protections should combine Layergram with additional tools or choose a different solution.

- **Transport metadata.** WhatsApp, Telegram, email and similar channels always see *who* is communicating with *whom*, *when*, *how often*, and *how much*. Layergram encrypts content but does not conceal the social graph or the timing pattern of messages over the chosen transport. This is intrinsic to delegating delivery to a third party.
- **Active traffic analysis.** Message timing, message size after encoding, and typing patterns on the transport may allow correlation attacks. Layergram does not pad messages to a fixed size or randomize their timing.
- **Detection of a hidden message.** The zero-width steganography used to embed ciphertext into cover text is designed to resist casual observation and rendering issues. It is not designed to resist an adversary who explicitly looks for hidden codepoints. If your threat model requires hiding the *existence* of encrypted communication from a motivated adversary, zero-width stego alone is not sufficient. (Note: direct message links do not provide any hiding of the message's existence.)
- **Cover-message content inspection.** Layergram does not generate cover messages for you in the open-source build. The authenticity and innocence of the cover text are the user's responsibility.
- **Man-in-the-middle during the *initial* key exchange.** When Alice and Bob exchange identity links over a non-trusted transport (WhatsApp, Telegram, email), an attacker on that channel can substitute a key. Layergram mitigates this with an explicit, localized **SAS verification ceremony** that must be performed out-of-band (voice call, in person, or another channel believed to be MITM-free). Until that ceremony is completed, the contact is clearly marked "not verified" in the contact list and a persistent banner is shown in the chat view warning the user of this state.
- **Rubber-hose / coercion.** Layergram does not provide a formal duress PIN, panic mode, or a cryptographically separate decoy vault with strong anti-forensic guarantees. The optional passphrase can create a limited deniability layer because passphrase-derived keys are not present unless the user activates them, but this should not be treated as a strong guarantee against coercion, repeated questioning, device seizure, side-channel observation, or forensic correlation.
- **Compromised or rooted device.** Layergram relies on the platform to enforce process isolation and on the OS keystore for hardware-backed key material. A device that is rooted, jailbroken, or compromised by malware running with screen-recording, input-injection or memory-dumping privileges can read or influence anything Layergram does while it is unlocked.
- **Compromised recipient.** If the recipient's device is compromised, or if they share their recovery phrase, the content you sent them can be recovered. End-to-end encryption protects the transport, not the endpoint.
- **Future compromise of long-term keys (no forward secrecy).** The current message encryption uses static–static X25519 between identity keys. If a long-term identity key is compromised in the future, all past messages encrypted for that key with the corresponding peer can be decrypted. This is a known, documented limitation and is planned to be addressed by a forward-secret ratchet while preserving the manual key-exchange model. Until then, Layergram should not be used in threat models that require protection of past messages after a future device seizure.
- **Recovery of messages without device state.** Messages are stored locally and are not automatically backed up anywhere. Loss or wipe of the device (without a user-managed backup) means loss of access to previously received messages, even if the recovery phrase is known.
- **Anonymity of the user on the underlying transport.** If the transport requires a phone number or account, that identity is visible to the transport operator. Layergram does not anonymize the user at the transport layer.
- **Legal or regulatory compulsion against the user or the transport.** Layergram cannot protect against an adversary who can compel the user (or the transport operator) to reveal information they hold. Layergram's contribution is to minimize the information actually held by the transport (content is encrypted; attribution is not present in the wire format).

## Assumptions the model relies on

- The device's operating system enforces process isolation and protects the OS-level secure storage against other apps.
- The recipient is running a genuine build of Layergram or an interoperable implementation that honors the same cryptographic protocol.
- The user verifies new contacts via the SAS ceremony before relying on the "verified" badge.
- The user keeps their recovery phrase and PIN confidential.
- If the user relies on passphrase-based deniability, the passphrase has not been entered under observation and no external evidence independently proves its use.
- The platform-provided sources of randomness (`cryptography` package APIs, OS CSPRNG) behave correctly.

## Roles considered

- **Transport operator** (e.g. the messaging app used to ship cover text): untrusted for content, assumed honest-but-curious for delivery.
- **Network observer**: untrusted for both content and routing.
- **Endpoint user**: trusted for their own device. Compromised endpoints are out of scope.
- **Attacker at initial contact exchange**: modeled; the SAS ceremony is the mitigation.
- **Device-level local attacker with physical access and time**: partially mitigated by OS secure storage, PIN hashing, and lockout; not fully mitigated.
- **Adversary running a cover-text classifier / detector**: not mitigated by the stego layer alone.

## Cryptographic specifics

- **Identity keys (v2):** Ed25519/X25519-equivalent 32-byte keypairs derived from a BIP39 mnemonic via HKDF-SHA256 with domain-separated labels (`layergram-id-v2` / `layergram-passphrase-id-v2`). Version metadata is persisted so derivation remains stable across app upgrades.
- **Identity keys (v1, legacy):** SHA-256 of the BIP39 seed. Preserved for users onboarded in early versions; never silently upgraded.
- **Per-peer shared secret:** X25519(local_private, peer_public), expanded via HKDF-SHA256 with `info = "msg-encryption"` and a fixed salt.
- **Message AEAD:** AES-256-GCM with a 12-byte random nonce and a 16-byte authentication tag.
- **Wire format:** `nonce (12 bytes) || ciphertext+tag (N bytes)`. No version byte, no sender or recipient identifier.
- **SAS ceremony:** HKDF-SHA256 over the canonically-ordered pair of peer public keys, `info = "layergram-sas-v1"`, truncated to 6 decimal digits plus 4 emoji drawn from a fixed 64-emoji palette. Any key substitution changes the output with overwhelming probability.
- **App-lock PIN:** stored as a KDF-hashed value with a versioned KDF descriptor, random per-install salt, constant-time comparison, rate-limited validation, and exponential backoff on consecutive failed attempts.

## Reporting security issues

Please follow the instructions in `SECURITY.md`. Reports that intersect the items in **"What Layergram does not protect against"** above are welcome as feedback but are expected to be out-of-scope as vulnerabilities unless they represent a regression from the documented protections.
