// Diagnostic tests using the real public keys from Alex and Sofia's identity
// links to reproduce and pinpoint the decryption failure.
//
// Alex link:  layergram://i/eyJ2IjoxLCJpZCI6IlNKNDU2NkJUM09aVFVSUlRaN0lNNVFaS0JSTjRKWUdLWUVBMkhaSU5WUDdEWEFOVElKT0EiLCJwayI6IllhSTZzT2l0c0dpNWxFSHhpTGxLdUJ0UVNFU2RLZ2hjMTlNbWltVFo2Z1k9IiwiZnAiOiI5Mi03OS1ERi03OC0zMy1EQi1CMy0zQSIsIm4iOiJBbGV4In0.z3O9g58_
// Sofia link: layergram://i/eyJ2IjoxLCJpZCI6IlhFVTQyTFFXTzNDWEkyTVRJNFRMSFdZS0RMUTJERjNPVFpUN1ZEUlRLRUk2MkNGSklZS0EiLCJwayI6IjFsb2gxYnhPQllxUXVqaGUwMkM0Q1ZzWmNFK005KzZsa0pRY3Zmc1ZTRTg9IiwiZnAiOiJCOS0yOS1DRC0yRS0xNi03Ni1DNS03NCIsIm4iOiJTb2ZpYSJ9.AYtqi696

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/identity_link_codec.dart';
import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/stego_decoder.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/contact_verification/contact_sas_service.dart';

// ── Real identity data decoded from the provided links ──────────────────────

// Alex:  id=SJ4566BT3OZTURRTZ7IM5QZKBRN4JYGKYEA2HZINVP7DXANTIJOA  pk=YaI6sOitsGi5lEHxiLlKuBtQSESdKghc19MmimTZ6gY=
// Sofia: id=XEU42LQWO3CXI2MTI4TLHWYKDLQ2DF3OTZT7VDRTKEI62CFJIYKA   pk=1loh1bxOBYqQujhe02C4CVsZcE+M9+6lkJQcvfsVSE8=

const _alexLink =
    'layergram://i/eyJ2IjoxLCJpZCI6IlNKNDU2NkJUM09aVFVSUlRaN0lNNVFaS0JSTjRKWUdLWUVBMkhaSU5WUDdEWEFOVElKT0EiLCJwayI6IllhSTZzT2l0c0dpNWxFSHhpTGxLdUJ0UVNFU2RLZ2hjMTlNbWltVFo2Z1k9IiwiZnAiOiI5Mi03OS1ERi03OC0zMy1EQi1CMy0zQSIsIm4iOiJBbGV4In0.z3O9g58_';
const _sofiaLink =
    'layergram://i/eyJ2IjoxLCJpZCI6IlhFVTQyTFFXTzNDWEkyTVRJNFRMSFdZS0RMUTJERjNPVFpUN1ZEUlRLRUk2MkNGSklZS0EiLCJwayI6IjFsb2gxYnhPQllxUXVqaGUwMkM0Q1ZzWmNFK005KzZsa0pRY3Zmc1ZTRTg9IiwiZnAiOiJCOS0yOS1DRC0yRS0xNi03Ni1DNS03NCIsIm4iOiJTb2ZpYSJ9.AYtqi696';

// The cover + secret message provided by the user
const _cover =
    'Hi Alex, I\'m sending you the login credentials to access the backend panel. '
    'Please keep them secure and remember to log out at the end of each work session '
    'or whenever you leave your desk unattended.';
const _secret = 'user: admin\npassword: jusg-Yets!gJdh@GTfJ';

class _MemStorage extends SecureStorageService {
  final _s = <String, String>{};
  @override
  Future<void> write(String k, String v) async => _s[k] = v;
  @override
  Future<String?> read(String k) async => _s[k];
  @override
  Future<void> delete(String k) async => _s.remove(k);
  @override
  Future<void> deleteAll() async => _s.clear();
}

IdentityManager _mgr() => IdentityManager(
      seedService: SeedService(),
      localIdentityVault: LocalIdentityVault(secureStorage: _MemStorage()),
    );

void main() {
  // ── 1. Parse the identity links ──────────────────────────────────────────

  group('Identity link parsing', () {
    test('Alex link parses to the expected public key and fingerprint', () {
      final alex = IdentityLinkCodec.decode(_alexLink);
      expect(alex.publicKeyBase64,
          equals('YaI6sOitsGi5lEHxiLlKuBtQSESdKghc19MmimTZ6gY='));
      expect(alex.fingerprint, equals('92-79-DF-78-33-DB-B3-3A'));
      expect(alex.displayName, equals('Alex'));
      expect(alex.publicKeyBase64.length, greaterThan(30));
    });

    test('Sofia link parses to the expected public key and fingerprint', () {
      final sofia = IdentityLinkCodec.decode(_sofiaLink);
      expect(sofia.publicKeyBase64,
          equals('1loh1bxOBYqQujhe02C4CVsZcE+M9+6lkJQcvfsVSE8='));
      expect(sofia.fingerprint, equals('B9-29-CD-2E-16-76-C5-74'));
      expect(sofia.displayName, equals('Sofia'));
    });

    test('Alex and Sofia have different public keys', () {
      final alex = IdentityLinkCodec.decode(_alexLink);
      final sofia = IdentityLinkCodec.decode(_sofiaLink);
      expect(alex.publicKeyBase64, isNot(equals(sofia.publicKeyBase64)));
    });

    test('Both public keys are valid 32-byte X25519 points', () {
      final alex = IdentityLinkCodec.decode(_alexLink);
      final sofia = IdentityLinkCodec.decode(_sofiaLink);
      expect(base64Decode(alex.publicKeyBase64).length, equals(32));
      expect(base64Decode(sofia.publicKeyBase64).length, equals(32));
    });
  });

  // ── 2. SAS: verify it is NOT time-dependent ──────────────────────────────

  group('SAS ceremony – time independence', () {
    const sas = ContactSasService();
    final alex = IdentityLinkCodec.decode(_alexLink);
    final sofia = IdentityLinkCodec.decode(_sofiaLink);

    test(
        'SAS digits derived from real keys are the same on every call (not time-based)',
        () async {
      final r1 = await sas.derive(
          localPublicKeyBase64: alex.publicKeyBase64,
          peerPublicKeyBase64: sofia.publicKeyBase64);
      final r2 = await sas.derive(
          localPublicKeyBase64: alex.publicKeyBase64,
          peerPublicKeyBase64: sofia.publicKeyBase64);
      final r3 = await sas.derive(
          localPublicKeyBase64: alex.publicKeyBase64,
          peerPublicKeyBase64: sofia.publicKeyBase64);
      expect(r1.digits, equals(r2.digits));
      expect(r2.digits, equals(r3.digits));
    });

    test('SAS is symmetric: Alex viewing Sofia == Sofia viewing Alex',
        () async {
      final alexView = await sas.derive(
          localPublicKeyBase64: alex.publicKeyBase64,
          peerPublicKeyBase64: sofia.publicKeyBase64);
      final sofiaView = await sas.derive(
          localPublicKeyBase64: sofia.publicKeyBase64,
          peerPublicKeyBase64: alex.publicKeyBase64);
      expect(alexView.digits, equals(sofiaView.digits),
          reason: 'Both must see identical SAS digits');
      expect(alexView.emojiIndices, equals(sofiaView.emojiIndices),
          reason: 'Both must see identical emoji');
    });

    test('Print the expected SAS so user can compare with device', () async {
      final code = await sas.derive(
        localPublicKeyBase64: alex.publicKeyBase64,
        peerPublicKeyBase64: sofia.publicKeyBase64,
      );
      // This test always passes — it just prints the ground-truth SAS.
      // ignore: avoid_print
      print('\n>>> Expected SAS (Alex ↔ Sofia)');
      // ignore: avoid_print
      print('    digits: ${code.digits}');
      // ignore: avoid_print
      print('    emoji indices: ${code.emojiIndices}');
      // ignore: avoid_print
      print('    emoji: ${code.emojiGlyphs.join(' ')}');
      expect(code.digits, hasLength(6));
    });
  });

  // ── 3. Diagnose why one identity's public key in the contact list might
  //      differ from the one in the link (v1 vs v2 derivation mismatch) ──────

  group(
      'v1 vs v2 derivation: does the identity link embed the right public key?',
      () {
    // We don't have the private keys, but we CAN verify that:
    // if an identity is RE-DERIVED from the same mnemonic with v1 vs v2,
    // the resulting public key differs — and ONLY ONE of these will match
    // the public key in the shared link.
    //
    // This is the most likely root cause: Sofia's app stores a v2 identity
    // but Alex imported a link generated from a v1 key (or vice versa),
    // so the ECDH shared secret differs and decryption fails.

    const mnemonic24 =
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon art';

    test(
        'v1 and v2 restoration produce different public keys from the same mnemonic',
        () async {
      final mgrV1 = _mgr();
      final mgrV2 = _mgr();

      final v1 = await mgrV1.restoreIdentityFromMnemonic(mnemonic24,
          derivationVersion: IdentityDerivationVersion.v1);
      final v2 = await mgrV2.restoreIdentityFromMnemonic(mnemonic24,
          derivationVersion: IdentityDerivationVersion.v2);

      expect(v1.publicKeyBase64, isNot(equals(v2.publicKeyBase64)),
          reason: 'v1 and v2 MUST produce different key pairs – '
              'if app stores v2 but link was shared from v1, ECDH secret will differ');

      // ignore: avoid_print
      print('\n>>> v1 pk: ${v1.publicKeyBase64}');
      // ignore: avoid_print
      print('>>> v2 pk: ${v2.publicKeyBase64}');
    });

    test(
        'If Sofia uses v2 key in app but shares v1 link, Alex encrypts to WRONG key',
        () async {
      // Simulate: Sofia has v2 identity on device, but accidentally shared a v1 link.
      final sofiaMgrV1 = _mgr();
      final sofiaMgrV2 = _mgr();
      const mn =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

      final sofiaV1 = await sofiaMgrV1.restoreIdentityFromMnemonic(mn,
          derivationVersion: IdentityDerivationVersion.v1);
      final sofiaV2 = await sofiaMgrV2.restoreIdentityFromMnemonic(mn,
          derivationVersion: IdentityDerivationVersion.v2);

      final privSofiaV2 = (await sofiaMgrV2.getLocalPrivateKeyBase64())!;

      // Alex uses a random key pair.
      final alexPair = await X25519().newKeyPair();
      final alexPriv = base64Encode(await alexPair.extractPrivateKeyBytes());
      final alexPub = base64Encode((await alexPair.extractPublicKey()).bytes);

      final enc = EncryptionService();

      // Sofia (v2) encrypts TO Alex using Alex's correct public key.
      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: privSofiaV2,
        recipientPublicKeyBase64: alexPub,
        payload: PlaintextPayload(
          senderId: sofiaV2.identityId,
          recipientId: 'alex',
          text: _secret,
          timestamp: 1700000000,
          senderDisplayName: 'Sofia',
        ),
      );
      final encrypted = encResult.message;

      // Alex decrypts with Sofia's V2 public key → SUCCESS (correct key).
      final correctDecrypt = await enc.tryDecryptWithKey(
        message: encrypted,
        key: await enc.deriveSymmetricKey(
          localPrivateKeyBase64: alexPriv,
          remotePublicKeyBase64: sofiaV2.publicKeyBase64,
        ),
      );
      expect(correctDecrypt, isNotNull,
          reason:
              'Alex must decrypt when using Sofia\'s correct v2 public key');
      expect(correctDecrypt!.text, equals(_secret));

      // Alex decrypts with Sofia's V1 public key → FAIL (wrong key, different ECDH).
      final wrongDecrypt = await enc.tryDecryptWithKey(
        message: encrypted,
        key: await enc.deriveSymmetricKey(
          localPrivateKeyBase64: alexPriv,
          remotePublicKeyBase64: sofiaV1.publicKeyBase64,
        ),
      );
      expect(wrongDecrypt, isNull,
          reason: 'If Alex has the v1 public key but Sofia used v2, '
              'decryption MUST fail — this reproduces the reported bug');
    });
  });

  // ── 4. Full stego roundtrip with Sofia→Alex cover message ────────────────

  group('Stego roundtrip: Sofia cover message to Alex', () {
    test('cover text is long enough to embed a typical secret payload', () {
      final estimatedBytes =
          StegoEncoder.estimatedEncryptedPayloadBytes(_secret);
      final minCover = StegoEncoder.minCoverLengthForBytes(estimatedBytes);
      final coverLen = StegoEncoder.visibleCharacterCount(_cover);

      // ignore: avoid_print
      print('\n>>> Secret payload estimate: $estimatedBytes bytes');
      // ignore: avoid_print
      print('>>> Min cover chars needed:  $minCover');
      // ignore: avoid_print
      print('>>> Actual cover chars:      $coverLen');
      // ignore: avoid_print
      print('>>> Cover is sufficient:     ${coverLen >= minCover}');

      expect(coverLen, greaterThanOrEqualTo(minCover),
          reason: 'Cover text must be long enough to embed the secret');
    });

    test('full stego+encryption roundtrip with the provided cover and secret',
        () async {
      // We don't have Sofia's private key, so we use a fresh key pair whose
      // PUBLIC key we will tell "Alex" to expect (simulating the protocol).
      final sofiaSimPair = await X25519().newKeyPair();
      final sofiaSimPriv =
          base64Encode(await sofiaSimPair.extractPrivateKeyBytes());
      final sofiaSimPub =
          base64Encode((await sofiaSimPair.extractPublicKey()).bytes);

      final alexSimPair = await X25519().newKeyPair();
      final alexSimPriv =
          base64Encode(await alexSimPair.extractPrivateKeyBytes());
      final alexSimPub =
          base64Encode((await alexSimPair.extractPublicKey()).bytes);

      final enc = EncryptionService();
      final encoder = StegoEncoder();
      final decoder = StegoDecoder();

      // Sofia encrypts to Alex.
      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: sofiaSimPriv,
        recipientPublicKeyBase64: alexSimPub,
        payload: PlaintextPayload(
          senderId: 'sofia',
          recipientId: 'alex',
          text: _secret,
          timestamp: 1700000000,
          senderDisplayName: 'Sofia',
        ),
      );
      final encrypted = encResult.message;

      // Sofia embeds in cover text.
      final hiddenMsg = encoder.encodeBytes(_cover, encrypted.toRawBytes());

      // Alex decodes and decrypts.
      final candidates = decoder.decodeByteCandidates(hiddenMsg);
      expect(candidates, isNotEmpty,
          reason: 'Stego decode must find candidates');

      PlaintextPayload? decrypted;
      for (final raw in candidates) {
        EncryptedMessage msg;
        try {
          msg = EncryptedMessage.fromRawBytes(raw);
        } catch (_) {
          continue;
        }
        final key = await enc.deriveSymmetricKey(
          localPrivateKeyBase64: alexSimPriv,
          remotePublicKeyBase64: sofiaSimPub,
        );
        decrypted = await enc.tryDecryptWithKey(message: msg, key: key);
        if (decrypted != null) break;
      }

      expect(decrypted, isNotNull,
          reason: 'Alex must be able to decrypt Sofia\'s message');
      expect(decrypted!.text, equals(_secret));
    });

    test('wrong key (v1 public key mismatch) cannot decrypt stego message',
        () async {
      // This reproduces the exact reported failure:
      // Sofia uses v2, Alex imported a v1 link → decryption fails silently.
      final sofiaV2Pair = await X25519().newKeyPair();
      final sofiaV2Priv =
          base64Encode(await sofiaV2Pair.extractPrivateKeyBytes());

      // Simulate: Alex has a DIFFERENT public key for Sofia (e.g. v1 mismatch).
      final sofiaFakeV1Pair = await X25519().newKeyPair();
      final sofiaFakeV1Pub =
          base64Encode((await sofiaFakeV1Pair.extractPublicKey()).bytes);

      final alexPair = await X25519().newKeyPair();
      final alexPriv = base64Encode(await alexPair.extractPrivateKeyBytes());
      final alexPub = base64Encode((await alexPair.extractPublicKey()).bytes);

      final enc = EncryptionService();
      final encoder = StegoEncoder();
      final decoder = StegoDecoder();

      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: sofiaV2Priv,
        recipientPublicKeyBase64: alexPub,
        payload: PlaintextPayload(
          senderId: 'sofia',
          recipientId: 'alex',
          text: _secret,
          timestamp: 1700000000,
        ),
      );

      final hiddenMsg =
          encoder.encodeBytes(_cover, encResult.message.toRawBytes());
      final candidates = decoder.decodeByteCandidates(hiddenMsg);
      expect(candidates, isNotEmpty);

      // Alex tries to decrypt with the WRONG (fake v1) public key for Sofia.
      PlaintextPayload? wrongDecrypt;
      for (final raw in candidates) {
        EncryptedMessage msg;
        try {
          msg = EncryptedMessage.fromRawBytes(raw);
        } catch (_) {
          continue;
        }
        final wrongKey = await enc.deriveSymmetricKey(
          localPrivateKeyBase64: alexPriv,
          remotePublicKeyBase64: sofiaFakeV1Pub, // ← WRONG key
        );
        wrongDecrypt = await enc.tryDecryptWithKey(message: msg, key: wrongKey);
        if (wrongDecrypt != null) break;
      }

      expect(wrongDecrypt, isNull,
          reason:
              'With wrong public key for Sofia, decryption must silently fail — '
              'this is exactly what the user experiences');
    });
  });

  // ── 5. Verify the identity link encode→decode roundtrip is lossless ───────

  group('Identity link codec roundtrip', () {
    test('encode then decode preserves all fields including public key',
        () async {
      final mgr = _mgr();
      final identity = await mgr.createNewIdentity(displayName: 'Test');
      final link = IdentityLinkCodec.encode(identity);
      final decoded = IdentityLinkCodec.decode(link);

      expect(decoded.publicKeyBase64, equals(identity.publicKeyBase64),
          reason:
              'Public key in link must exactly match the identity\'s public key');
      expect(decoded.identityId, equals(identity.identityId));
      expect(decoded.fingerprint, equals(identity.fingerprint));
    });

    test('link generated by v2 identity contains v2 public key, not v1',
        () async {
      const mn =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

      final mgrV1 = _mgr();
      final mgrV2 = _mgr();

      final v1 = await mgrV1.restoreIdentityFromMnemonic(mn,
          derivationVersion: IdentityDerivationVersion.v1);
      final v2 = await mgrV2.restoreIdentityFromMnemonic(mn,
          derivationVersion: IdentityDerivationVersion.v2);

      final linkV1 = IdentityLinkCodec.encode(v1);
      final linkV2 = IdentityLinkCodec.encode(v2);

      expect(linkV1, isNot(equals(linkV2)),
          reason:
              'v1 and v2 identities from same mnemonic must produce DIFFERENT links');

      final decodedV1 = IdentityLinkCodec.decode(linkV1);
      final decodedV2 = IdentityLinkCodec.decode(linkV2);

      expect(decodedV1.publicKeyBase64, equals(v1.publicKeyBase64));
      expect(decodedV2.publicKeyBase64, equals(v2.publicKeyBase64));
      expect(
          decodedV1.publicKeyBase64, isNot(equals(decodedV2.publicKeyBase64)),
          reason: 'If Alex imports link v1 but Sofia\'s device uses v2, '
              'ECDH shared secret differs → encryption/decryption fails');
    });
  });
}
