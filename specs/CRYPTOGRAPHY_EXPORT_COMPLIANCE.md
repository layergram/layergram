# Layergram – Cryptography Export Compliance Statement

**App Name:** Layergram  
**Bundle ID:** app.layergram.app  
**Developer:** Simone Riccetti (individual Apple Developer Program)  
**Contact Email:** dev@layergram.app

## 1. Overview
Layergram is a secure messaging application that embeds encrypted payloads inside natural-language cover text. The app implements only well-known, publicly documented cryptographic algorithms to provide confidentiality and authenticity between users. No proprietary or unpublished cryptography is used.

## 2. Cryptographic Functions
| Purpose | Algorithm | Key Size / Parameters | Standard Reference |
| --- | --- | --- | --- |
| Asymmetric key agreement | **X25519** (Elliptic-curve Diffie–Hellman over Curve25519) | 256-bit private/public keys | RFC 7748 (IETF)
| Symmetric encryption & authentication | **AES-GCM** | 256-bit key, 96-bit nonce, 128-bit authentication tag | FIPS 197, NIST SP 800-38D
| Key derivation | **HKDF** (HMAC-SHA-256) | 256-bit output keying material | RFC 5869 (IETF)
| Hashing / fingerprinting | **SHA-256** | 256-bit digest | FIPS 180-4

All algorithms are implemented via the open-source `package:cryptography` Dart library, which relies on Apple’s CommonCrypto on iOS/macOS and platform-native backends on other targets.

## 3. Key Management & Usage
1. Each user generates a 256-bit seed locally; from this we deterministically derive:
   - An X25519 key pair for long-term identity.
   - Session keys obtained via X25519 ECDH, HKDF expansion, and AES-GCM encryption.
2. Keys never leave the device unencrypted. Private keys are stored in the user’s secure enclave / keychain (via `flutter_secure_storage`).
3. Messages are encrypted end-to-end between sender and recipient. The app does not expose cryptographic functionality to third parties other than the described messaging flow.
4. There is no functionality to hide or mask cryptography; the app does not provide generic VPN, proxy, or voice/data encryption outside of its messaging use case.

## 4. Compliance Notes
- The app exclusively uses **standard, publicly available** algorithms approved by international standard bodies (IETF, NIST).  
- No proprietary cryptography, no custom cipher suites, and no functionality for mass-market telecommunications interception are included.  
- Source code for the cryptographic components is available within the app bundle and relies on open-source libraries.
- The app does not ship to embargoed territories beyond Apple’s standard distribution restrictions.

## 5. Export Classification (informational)
Based on the implemented algorithms, Layergram falls under U.S. EAR category **5D002.c.1** (mass-market encryption software). Apple’s standard export review process and key request for the `ITSAppUsesNonExemptEncryption` entry in `Info.plist` will be followed.

## 6. Contact
For any compliance questions, please contact the developer at **dev@layergram.app**.
