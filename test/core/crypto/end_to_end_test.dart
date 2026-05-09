// End-to-end tests covering the three scenarios reported by the user:
//
//   1. Mnemonic restore (24 words) - determinism, identity derivation, cross-
//      version restore, and case-insensitive input.
//   2. Contact SAS verification ceremony - symmetry between two identities
//      on the same device, determinism, and sensitivity to key changes (MITM).
//   3. Stego + encryption roundtrip - full pipeline from secret text → hidden
//      cover message → stego decode → decrypt → original text.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/stego_decoder.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
import 'package:layergram/features/contact_verification/contact_sas_service.dart';

// ── Helpers ──────────────────────────────────────────────────────────────────

/// A minimal in-memory stub that satisfies [LocalIdentityVault]'s interface
/// without touching the file system or platform channels.
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/secure_storage.dart';

class _MemSecureStorage extends SecureStorageService {
  final _store = <String, String>{};
  @override Future<void> write(String key, String value) async => _store[key] = value;
  @override Future<String?> read(String key) async => _store[key];
  @override Future<void> delete(String key) async => _store.remove(key);
  @override Future<void> deleteAll() async => _store.clear();
}

IdentityManager _makeManager({_MemSecureStorage? storage}) {
  final s = storage ?? _MemSecureStorage();
  return IdentityManager(
    seedService: SeedService(),
    localIdentityVault: LocalIdentityVault(secureStorage: s),
  );
}

// ── 1. Mnemonic restore ───────────────────────────────────────────────────────

void main() {
  group('Scenario 1 – Mnemonic restore (24 words)', () {
    // A well-known 24-word BIP39 mnemonic whose derivation outputs are pinned.
    const mnemonic24 =
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon art';

    test('24-word mnemonic is valid', () {
      expect(SeedService().validateMnemonic(mnemonic24), isTrue);
    });

    test('restoring a 24-word mnemonic twice yields the same identityId and fingerprint', () async {
      final mgr = _makeManager();
      final a = await mgr.restoreIdentityFromMnemonic(mnemonic24, displayName: 'A');
      final b = await mgr.restoreIdentityFromMnemonic(mnemonic24, displayName: 'B');

      expect(a.identityId, equals(b.identityId),
          reason: 'identityId must be deterministic from mnemonic');
      expect(a.fingerprint, equals(b.fingerprint),
          reason: 'fingerprint must be deterministic from mnemonic');
      expect(a.publicKeyBase64, equals(b.publicKeyBase64));
      expect(a.mnemonic, equals(mnemonic24));
    });

    test('UI-normalised (toLowerCase) mnemonic yields the same identity as the original lowercase', () async {
      // The UI layer (create_or_restore_view.dart) calls .toLowerCase() before
      // passing the input to restoreIdentityFromMnemonic. This test verifies
      // that the lowercase-normalised version of a mixed-case input produces
      // the same identity as the canonical lowercase mnemonic.
      final mgrA = _makeManager();
      final mgrB = _makeManager();

      // Simulate what the UI does: normalise with toLowerCase before restore.
      final mixedCase = mnemonic24
          .split(' ')
          .map((w) => w[0].toUpperCase() + w.substring(1))
          .join(' ');

      final fromLower = await mgrA.restoreIdentityFromMnemonic(
        mnemonic24.toLowerCase(),
        displayName: 'Lower',
      );
      final fromNormalised = await mgrB.restoreIdentityFromMnemonic(
        mixedCase.toLowerCase(), // UI normalisation step
        displayName: 'Normalised',
      );

      expect(fromNormalised.identityId, equals(fromLower.identityId),
          reason: 'toLowerCase normalisation must produce the same identity');
      expect(fromNormalised.publicKeyBase64, equals(fromLower.publicKeyBase64));
    });

    test('restored identity private key matches re-derived private key from mnemonic', () async {
      final seed = SeedService().mnemonicToSeed(mnemonic24);
      final seedService = SeedService();
      final mgr = _makeManager();
      final restored = await mgr.restoreIdentityFromMnemonic(mnemonic24, displayName: 'R');

      final expectedPrivKey = await seedService.deriveIdentityPrivateKey(
        seed,
        version: restored.derivationVersion,
      );
      final actualPrivKey = await mgr.getLocalPrivateKeyBase64();

      expect(actualPrivKey, equals(base64Encode(expectedPrivKey)),
          reason: 'Stored private key must equal the deterministically re-derived one');
    });

    test('restored identity v1 and v2 derivations produce different public keys', () async {
      final mgrV1 = _makeManager();
      final mgrV2 = _makeManager();

      final v1 = await mgrV1.restoreIdentityFromMnemonic(
        mnemonic24,
        derivationVersion: IdentityDerivationVersion.v1,
      );
      final v2 = await mgrV2.restoreIdentityFromMnemonic(
        mnemonic24,
        derivationVersion: IdentityDerivationVersion.v2,
      );

      expect(v1.publicKeyBase64, isNot(equals(v2.publicKeyBase64)),
          reason: 'v1 and v2 must yield different key pairs');
      expect(v1.identityId, isNot(equals(v2.identityId)));
    });

    test('invalid mnemonic throws ArgumentError', () {
      final mgr = _makeManager();
      expect(
        () => mgr.restoreIdentityFromMnemonic('not a valid mnemonic phrase at all'),
        throwsArgumentError,
      );
    });

    test('12-word mnemonic restore is deterministic', () async {
      const mnemonic12 =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final mgrA = _makeManager();
      final mgrB = _makeManager();

      final a = await mgrA.restoreIdentityFromMnemonic(mnemonic12);
      final b = await mgrB.restoreIdentityFromMnemonic(mnemonic12);

      expect(a.identityId, equals(b.identityId));
      expect(a.publicKeyBase64, equals(b.publicKeyBase64));
    });
  });

  // ── 2. SAS verification ceremony ─────────────────────────────────────────

  group('Scenario 2 – SAS ceremony with two identities on the same device', () {
    const sas = ContactSasService();

    test('Alice sees Bob and Bob sees Alice: SAS digits match', () async {
      final x25519 = X25519();
      final alicePair = await x25519.newKeyPair();
      final bobPair = await x25519.newKeyPair();
      final alicePub = base64Encode((await alicePair.extractPublicKey()).bytes);
      final bobPub = base64Encode((await bobPair.extractPublicKey()).bytes);

      final aliceView = await sas.derive(
        localPublicKeyBase64: alicePub,
        peerPublicKeyBase64: bobPub,
      );
      final bobView = await sas.derive(
        localPublicKeyBase64: bobPub,
        peerPublicKeyBase64: alicePub,
      );

      expect(aliceView.digits, equals(bobView.digits),
          reason: 'Both users must see the same SAS digits');
      expect(aliceView.emojiIndices, equals(bobView.emojiIndices),
          reason: 'Both users must see the same emoji');
    });

    test('SAS for real identity key pairs derived from mnemonics matches both ways', () async {
      final seedSvc = SeedService();

      const mnemonicAlice =
          'abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon abandon abandon art';
      const mnemonicBob =
          'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

      final aliceSeed = seedSvc.mnemonicToSeed(mnemonicAlice);
      final bobSeed = seedSvc.mnemonicToSeed(mnemonicBob);

      final alicePriv = await seedSvc.deriveIdentityPrivateKey(aliceSeed);
      final bobPriv = await seedSvc.deriveIdentityPrivateKey(bobSeed);

      final x25519 = X25519();
      final alicePub = base64Encode(
          (await (await x25519.newKeyPairFromSeed(alicePriv)).extractPublicKey()).bytes);
      final bobPub = base64Encode(
          (await (await x25519.newKeyPairFromSeed(bobPriv)).extractPublicKey()).bytes);

      final aliceView = await sas.derive(
        localPublicKeyBase64: alicePub,
        peerPublicKeyBase64: bobPub,
      );
      final bobView = await sas.derive(
        localPublicKeyBase64: bobPub,
        peerPublicKeyBase64: alicePub,
      );

      expect(aliceView.digits, equals(bobView.digits));
      expect(aliceView.emojiIndices, equals(bobView.emojiIndices));
    });

    test('SAS is stable across multiple derivation calls (deterministic)', () async {
      final x25519 = X25519();
      final a = base64Encode((await (await x25519.newKeyPair()).extractPublicKey()).bytes);
      final b = base64Encode((await (await x25519.newKeyPair()).extractPublicKey()).bytes);

      final first = await sas.derive(localPublicKeyBase64: a, peerPublicKeyBase64: b);
      final second = await sas.derive(localPublicKeyBase64: a, peerPublicKeyBase64: b);
      final third = await sas.derive(localPublicKeyBase64: a, peerPublicKeyBase64: b);

      expect(first.digits, equals(second.digits));
      expect(second.digits, equals(third.digits));
      expect(first.emojiIndices, equals(second.emojiIndices));
    });

    test('Swapping Alice key (MITM simulation) changes the SAS', () async {
      final x25519 = X25519();
      final alice = base64Encode((await (await x25519.newKeyPair()).extractPublicKey()).bytes);
      final bob = base64Encode((await (await x25519.newKeyPair()).extractPublicKey()).bytes);
      final mitm = base64Encode((await (await x25519.newKeyPair()).extractPublicKey()).bytes);

      final genuine = await sas.derive(localPublicKeyBase64: alice, peerPublicKeyBase64: bob);
      final attacked = await sas.derive(localPublicKeyBase64: mitm, peerPublicKeyBase64: bob);

      // It is astronomically unlikely both digits AND emoji match by chance.
      final sameDigits = genuine.digits == attacked.digits;
      final sameEmoji = const _ListEq<int>().equals(genuine.emojiIndices, attacked.emojiIndices);
      expect(sameDigits && sameEmoji, isFalse,
          reason: 'MITM must change SAS');
    });

    test('Emoji palette has exactly 64 unique entries', () {
      expect(ContactSasService.emojiPalette.length, equals(64));
      expect(ContactSasService.emojiPalette.toSet().length, equals(64),
          reason: 'All emoji must be unique');
    });

    test('SAS digits are always 6 decimal characters', () async {
      final x25519 = X25519();
      for (var i = 0; i < 8; i++) {
        final a = base64Encode((await (await x25519.newKeyPair()).extractPublicKey()).bytes);
        final b = base64Encode((await (await x25519.newKeyPair()).extractPublicKey()).bytes);
        final code = await sas.derive(localPublicKeyBase64: a, peerPublicKeyBase64: b);
        expect(code.digits.length, equals(6));
        expect(RegExp(r'^\d{6}$').hasMatch(code.digits), isTrue);
      }
    });
  });

  // ── 3. Full stego + encryption roundtrip ─────────────────────────────────

  group('Scenario 3 – Stego + encryption end-to-end roundtrip', () {
    final enc = EncryptionService();
    final encoder = StegoEncoder();
    final decoder = StegoDecoder();

    Future<({String priv, String pub})> _makeKeyPair() async {
      final pair = await X25519().newKeyPair();
      final priv = base64Encode(await pair.extractPrivateKeyBytes());
      final pub = base64Encode((await pair.extractPublicKey()).bytes);
      return (priv: priv, pub: pub);
    }

    test('encrypt → encodeBytes → decodeByteCandidates → decrypt yields original text', () async {
      final alice = await _makeKeyPair();
      final bob = await _makeKeyPair();
      const secretText = 'Messaggio segreto di test 🔐';
      const cover = 'Questo è un lungo messaggio di copertura con abbastanza testo visibile per permettere il corretto embedding del payload cifrato nel suffisso del messaggio.';

      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: alice.priv,
        recipientPublicKeyBase64: bob.pub,
        payload: PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: secretText,
          timestamp: DateTime.now().millisecondsSinceEpoch,
          senderDisplayName: 'Alice Test',
        ),
      );
      final encrypted = encResult.message;

      final rawBytes = encrypted.toRawBytes();
      expect(rawBytes.length, greaterThanOrEqualTo(28),
          reason: 'Encrypted payload must be at least 28 bytes');

      final hiddenMessage = encoder.encodeBytes(cover, rawBytes);

      // The cover text must be visually unchanged (strip hidden runes).
      final visibleOnly = hiddenMessage.runes
          .where((r) => r >= 0x20 && r <= 0x7E || r > 0x7E && !_isZeroWidth(r))
          .map(String.fromCharCode)
          .join();
      expect(visibleOnly.trimRight(), equals(StegoEncoder.normalizeCoverText(cover)));

      // Decode step.
      final candidates = decoder.decodeByteCandidates(hiddenMessage);
      expect(candidates, isNotEmpty, reason: 'Must find at least one candidate');

      // Try each candidate (alignment 0 should be correct).
      PlaintextPayload? decrypted;
      for (final raw in candidates) {
        EncryptedMessage msg;
        try {
          msg = EncryptedMessage.fromRawBytes(raw);
        } catch (_) {
          continue;
        }
        final key = await enc.deriveSymmetricKey(
          localPrivateKeyBase64: bob.priv,
          remotePublicKeyBase64: alice.pub,
        );
        decrypted = await enc.tryDecryptWithKey(message: msg, key: key);
        if (decrypted != null) break;
      }

      expect(decrypted, isNotNull, reason: 'Must successfully decrypt with Bob\'s key');
      expect(decrypted!.text, equals(secretText));
      expect(decrypted.senderDisplayName, equals('Alice Test'));
    });

    test('wrong key cannot decrypt the hidden payload', () async {
      final alice = await _makeKeyPair();
      final bob = await _makeKeyPair();
      final eve = await _makeKeyPair(); // attacker

      const cover = 'Lungo messaggio di copertura sufficientemente ampio per il test di sicurezza con chiave errata nel payload cifrato nascosto.';
      const secretText = 'Il segreto di Alice per Bob';

      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: alice.priv,
        recipientPublicKeyBase64: bob.pub,
        payload: PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: secretText,
          timestamp: DateTime.now().millisecondsSinceEpoch,
        ),
      );
      final encrypted = encResult.message;

      final hidden = encoder.encodeBytes(cover, encrypted.toRawBytes());
      final candidates = decoder.decodeByteCandidates(hidden);
      expect(candidates, isNotEmpty);

      final eveKey = await enc.deriveSymmetricKey(
        localPrivateKeyBase64: eve.priv,
        remotePublicKeyBase64: alice.pub,
      );

      PlaintextPayload? eveDecrypted;
      for (final raw in candidates) {
        EncryptedMessage msg;
        try {
          msg = EncryptedMessage.fromRawBytes(raw);
        } catch (_) {
          continue;
        }
        eveDecrypted = await enc.tryDecryptWithKey(message: msg, key: eveKey);
        if (eveDecrypted != null) break;
      }
      expect(eveDecrypted, isNull, reason: 'Eve must not decrypt a message for Bob');
    });

    test('roundtrip works with long secret text (emoji + accents)', () async {
      final alice = await _makeKeyPair();
      final bob = await _makeKeyPair();
      const secretText = 'Caffè, mañana, déjà vu, résumé, 😄🔐🚀🌍 — un messaggio lungo con caratteri speciali!';
      const cover = 'Caro amico, ti scrivo questa lunga lettera di copertura che non contiene alcun significato nascosto ma è abbastanza lunga da tenere pulita la parte iniziale del preview per il destinatario.';

      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: alice.priv,
        recipientPublicKeyBase64: bob.pub,
        payload: PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: secretText,
          timestamp: DateTime.now().millisecondsSinceEpoch,
          senderDisplayName: 'Àlice 😄',
        ),
      );
      final encrypted = encResult.message;

      final hidden = encoder.encodeBytes(cover, encrypted.toRawBytes());
      final candidates = decoder.decodeByteCandidates(hidden);

      PlaintextPayload? decrypted;
      for (final raw in candidates) {
        EncryptedMessage msg;
        try {
          msg = EncryptedMessage.fromRawBytes(raw);
        } catch (_) {
          continue;
        }
        final key = await enc.deriveSymmetricKey(
          localPrivateKeyBase64: bob.priv,
          remotePublicKeyBase64: alice.pub,
        );
        decrypted = await enc.tryDecryptWithKey(message: msg, key: key);
        if (decrypted != null) break;
      }

      expect(decrypted, isNotNull);
      expect(decrypted!.text, equals(secretText));
      expect(decrypted.senderDisplayName, equals('Àlice 😄'));
    });

    test('symmetric key derivation: same key for sender and recipient', () async {
      final alice = await _makeKeyPair();
      final bob = await _makeKeyPair();

      final senderKey = await enc.deriveSymmetricKey(
        localPrivateKeyBase64: alice.priv,
        remotePublicKeyBase64: bob.pub,
      );
      final recipientKey = await enc.deriveSymmetricKey(
        localPrivateKeyBase64: bob.priv,
        remotePublicKeyBase64: alice.pub,
      );

      expect(
        await senderKey.extractBytes(),
        equals(await recipientKey.extractBytes()),
        reason: 'X25519 ECDH must produce the same shared secret for both parties',
      );
    });

    test('encodeBytes → decodeByteCandidates[0] == original bytes (binary stability)', () async {
      final payload = Uint8List.fromList(List.generate(44, (i) => (i * 7 + 13) & 0xFF));
      const cover = 'Cover text long enough to safely embed the payload in the hidden suffix while keeping the visible preview clean and readable for any observer.';

      final encoded = encoder.encodeBytes(cover, payload);
      final candidates = decoder.decodeByteCandidates(encoded);

      expect(candidates, isNotEmpty);
      expect(candidates[0].sublist(0, payload.length), equals(payload),
          reason: 'Alignment-0 candidate must begin with the original payload bytes');
    });

    test('plain text (no hidden runes) returns empty candidates', () {
      final candidates = decoder.decodeByteCandidates(
        'Questo è un normalissimo messaggio senza nulla di nascosto.',
      );
      expect(candidates, isEmpty);
    });

    test('roundtrip via link format (layergram://m/...) preserves bytes', () async {
      final alice = await _makeKeyPair();
      final bob = await _makeKeyPair();

      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: alice.priv,
        recipientPublicKeyBase64: bob.pub,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: 'Messaggio da cifrare',
          timestamp: 1234567890,
        ),
      );
      final encrypted = encResult.message;

      final raw = encrypted.toRawBytes();
      final link = 'layergram://m/${base64Url.encode(raw).replaceAll('=', '')}';

      // Simulate decoding from link (as done in home_controller).
      final encoded = link.substring('layergram://m/'.length);
      final padded = encoded.padRight(encoded.length + (4 - encoded.length % 4) % 4, '=');
      final decoded = Uint8List.fromList(base64Url.decode(padded));
      final msg = EncryptedMessage.fromRawBytes(decoded);

      final key = await enc.deriveSymmetricKey(
        localPrivateKeyBase64: bob.priv,
        remotePublicKeyBase64: alice.pub,
      );
      final decryptedPayload = await enc.tryDecryptWithKey(message: msg, key: key);

      expect(decryptedPayload, isNotNull);
      expect(decryptedPayload!.text, equals('Messaggio da cifrare'));
    });
  });

  // ── 4. Cross-scenario: full identity lifecycle ────────────────────────────

  group('Scenario 4 – Full identity lifecycle (create → export as contact → encrypt → decrypt)', () {
    test('identity created on device A can receive a message from device B', () async {
      // Simulate two separate identity managers (two "devices").
      final mgrA = _makeManager();
      final mgrB = _makeManager();

      final identityA = await mgrA.createNewIdentity(displayName: 'Alice');
      final identityB = await mgrB.createNewIdentity(displayName: 'Bob');

      final privA = (await mgrA.getLocalPrivateKeyBase64())!;
      final privB = (await mgrB.getLocalPrivateKeyBase64())!;

      // Bob encrypts to Alice.
      final enc = EncryptionService();
      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: privB,
        recipientPublicKeyBase64: identityA.publicKeyBase64,
        payload: PlaintextPayload(
          senderId: identityB.identityId,
          recipientId: identityA.identityId,
          text: 'Secret for Alice',
          timestamp: 1234567890,
        ),
      );

      // Alice decrypts.
      final decResult = await enc.decrypt(
        recipientPrivateKeyBase64: privA,
        senderPublicKeyBase64: identityB.publicKeyBase64,
        message: encResult.message,
      );

      expect(decResult.payload.text, equals('Secret for Alice'));
      expect(decResult.payload.senderId, equals(identityB.identityId));
      expect(decResult.payload.recipientId, equals(identityA.identityId));
    });

    test('restored identity can decrypt messages that were encrypted to it before restore', () async {
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon abandon abandon art';

      // First time: "install" the identity.
      final mgrFirst = _makeManager();
      final original = await mgrFirst.restoreIdentityFromMnemonic(mnemonic, displayName: 'Alice');
      final privFirst = (await mgrFirst.getLocalPrivateKeyBase64())!;

      // Bob encrypts a message to Alice.
      final bobPair = await X25519().newKeyPair();
      final bobPriv = base64Encode(await bobPair.extractPrivateKeyBytes());
      final bobPub = base64Encode((await bobPair.extractPublicKey()).bytes);

      final enc = EncryptionService();
      final encResult = await enc.encrypt(
        senderPrivateKeyBase64: bobPriv,
        recipientPublicKeyBase64: original.publicKeyBase64,
        payload: PlaintextPayload(
          senderId: 'bob',
          recipientId: original.identityId,
          text: 'Messaggio precedente al restore',
          timestamp: 1234567890,
        ),
      );
      final encrypted = encResult.message;

      // Now Alice restores her identity from mnemonic on a new device.
      final mgrRestored = _makeManager();
      final restored = await mgrRestored.restoreIdentityFromMnemonic(mnemonic, displayName: 'Alice restored');
      final privRestored = (await mgrRestored.getLocalPrivateKeyBase64())!;

      // Public keys must be identical.
      expect(restored.publicKeyBase64, equals(original.publicKeyBase64),
          reason: 'Restored public key must equal original');
      expect(privRestored, equals(privFirst),
          reason: 'Restored private key must equal original');

      // Decryption must succeed using the restored private key.
      final decResult = await enc.decrypt(
        recipientPrivateKeyBase64: privRestored,
        senderPublicKeyBase64: bobPub,
        message: encrypted,
      );

      expect(decResult.payload.text, equals('Messaggio precedente al restore'));
    });
  });
}

// ── Utilities ─────────────────────────────────────────────────────────────────

bool _isZeroWidth(int rune) {
  const zwChars = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0xFEFF,
  };
  return zwChars.contains(rune);
}

class _ListEq<T> {
  const _ListEq();
  bool equals(List<T>? a, List<T>? b) {
    if (identical(a, b)) return true;
    if (a == null || b == null || a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
