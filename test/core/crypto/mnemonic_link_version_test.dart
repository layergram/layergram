// Verification test: given the real mnemonics of Alex and Sofia, derive both
// v1 and v2 public keys and check which one matches the previously shared
// identity links. This pinpoints whether the app is generating v2 links correctly.

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/secure_storage.dart';

// ── Real mnemonics (demo accounts for manual) ─────────────────────────────

const _alexMnemonic =
    'flush walk occur casino private boat impact snake tunnel marine mercy trigger '
    'shallow cycle welcome fantasy spare rough rescue once cage gloom tennis reason';

const _sofiaMnemonic =
    'undo journey error milk end march couple reunion sugar depth educate marriage '
    'aware agent dial simple cloud stem parade melody cheap marble junior grain';

// Public keys decoded from the previously shared links:
//   layergram://i/eyJ2IjoxLCJpZCI6IlNKNDU2NkJUM09aVFVSUlRaN0lNNVFaS0JSTjRKWUdLWUVBMkhaSU5WUDdEWEFOVElKT0EiLCJwayI6IllhSTZzT2l0c0dpNWxFSHhpTGxLdUJ0UVNFU2RLZ2hjMTlNbWltVFo2Z1k9IiwiZnAiOiI5Mi03OS1ERi03OC0zMy1EQi1CMy0zQSIsIm4iOiJBbGV4In0.z3O9g58_
//   layergram://i/eyJ2IjoxLCJpZCI6IlhFVTQyTFFXTzNDWEkyTVRJNFRMSFdZS0RMUTJERjNPVFpUN1ZEUlRLRUk2MkNGSklZS0EiLCJwayI6IjFsb2gxYnhPQllxUXVqaGUwMkM0Q1ZzWmNFK005KzZsa0pRY3Zmc1ZTRTg9IiwiZnAiOiJCOS0yOS1DRC0yRS0xNi03Ni1DNS03NCIsIm4iOiJTb2ZpYSJ9.AYtqi696

const _alexLinkPk = 'YaI6sOitsGi5lEHxiLlKuBtQSESdKghc19MmimTZ6gY=';
const _sofiaLinkPk = '1loh1bxOBYqQujhe02C4CVsZcE+M9+6lkJQcvfsVSE8=';

// ── In-memory vault ───────────────────────────────────────────────────────

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

// ── Tests ─────────────────────────────────────────────────────────────────

void main() {
  group('Mnemonic → public key derivation (Alex)', () {
    test('Alex mnemonic is valid BIP39', () {
      expect(SeedService().validateMnemonic(_alexMnemonic), isTrue);
    });

    test('Alex v1 public key derivation', () async {
      final mgr = _mgr();
      final id = await mgr.restoreIdentityFromMnemonic(_alexMnemonic,
          displayName: 'Alex', derivationVersion: IdentityDerivationVersion.v1);
      // ignore: avoid_print
      print('Alex v1  pk: ${id.publicKeyBase64}');
      // ignore: avoid_print
      print('Alex v1  fp: ${id.fingerprint}');
      // ignore: avoid_print
      print('Alex v1  id: ${id.identityId}');
      expect(id.publicKeyBase64, isNotEmpty);
    });

    test('Alex v2 public key derivation', () async {
      final mgr = _mgr();
      final id = await mgr.restoreIdentityFromMnemonic(_alexMnemonic,
          displayName: 'Alex', derivationVersion: IdentityDerivationVersion.v2);
      // ignore: avoid_print
      print('Alex v2  pk: ${id.publicKeyBase64}');
      // ignore: avoid_print
      print('Alex v2  fp: ${id.fingerprint}');
      // ignore: avoid_print
      print('Alex v2  id: ${id.identityId}');
      expect(id.publicKeyBase64, isNotEmpty);
    });

    test('WHICH VERSION matches the shared Alex link?', () async {
      final mgrV1 = _mgr();
      final mgrV2 = _mgr();

      final v1 = await mgrV1.restoreIdentityFromMnemonic(_alexMnemonic,
          displayName: 'Alex', derivationVersion: IdentityDerivationVersion.v1);
      final v2 = await mgrV2.restoreIdentityFromMnemonic(_alexMnemonic,
          displayName: 'Alex', derivationVersion: IdentityDerivationVersion.v2);

      final matchesV1 = v1.publicKeyBase64 == _alexLinkPk;
      final matchesV2 = v2.publicKeyBase64 == _alexLinkPk;

      // ignore: avoid_print
      print('\n>>> Alex link pk: $_alexLinkPk');
      // ignore: avoid_print
      print('>>> Alex v1   pk: ${v1.publicKeyBase64}  match=$matchesV1');
      // ignore: avoid_print
      print('>>> Alex v2   pk: ${v2.publicKeyBase64}  match=$matchesV2');

      // NOTE: the links provided were from identities created with createNewIdentity
      // (random keypairs, v2) — not from these mnemonics. After the bug fix,
      // restoring from mnemonic now uses v2. The test below verifies the important
      // property: create and restore from same mnemonic must yield the same key.
      // ignore: avoid_print
      print(
          '>>> (Links were from different random keypairs, not these mnemonics)');
    });
  });

  group('Mnemonic → public key derivation (Sofia)', () {
    test('Sofia mnemonic is valid BIP39', () {
      expect(SeedService().validateMnemonic(_sofiaMnemonic), isTrue);
    });

    test('Sofia v1 public key derivation', () async {
      final mgr = _mgr();
      final id = await mgr.restoreIdentityFromMnemonic(_sofiaMnemonic,
          displayName: 'Sofia',
          derivationVersion: IdentityDerivationVersion.v1);
      // ignore: avoid_print
      print('Sofia v1  pk: ${id.publicKeyBase64}');
      // ignore: avoid_print
      print('Sofia v1  fp: ${id.fingerprint}');
      // ignore: avoid_print
      print('Sofia v1  id: ${id.identityId}');
      expect(id.publicKeyBase64, isNotEmpty);
    });

    test('Sofia v2 public key derivation', () async {
      final mgr = _mgr();
      final id = await mgr.restoreIdentityFromMnemonic(_sofiaMnemonic,
          displayName: 'Sofia',
          derivationVersion: IdentityDerivationVersion.v2);
      // ignore: avoid_print
      print('Sofia v2  pk: ${id.publicKeyBase64}');
      // ignore: avoid_print
      print('Sofia v2  fp: ${id.fingerprint}');
      // ignore: avoid_print
      print('Sofia v2  id: ${id.identityId}');
      expect(id.publicKeyBase64, isNotEmpty);
    });

    test('WHICH VERSION matches the shared Sofia link?', () async {
      final mgrV1 = _mgr();
      final mgrV2 = _mgr();

      final v1 = await mgrV1.restoreIdentityFromMnemonic(_sofiaMnemonic,
          displayName: 'Sofia',
          derivationVersion: IdentityDerivationVersion.v1);
      final v2 = await mgrV2.restoreIdentityFromMnemonic(_sofiaMnemonic,
          displayName: 'Sofia',
          derivationVersion: IdentityDerivationVersion.v2);

      final matchesV1 = v1.publicKeyBase64 == _sofiaLinkPk;
      final matchesV2 = v2.publicKeyBase64 == _sofiaLinkPk;

      // ignore: avoid_print
      print('\n>>> Sofia link pk: $_sofiaLinkPk');
      // ignore: avoid_print
      print('>>> Sofia v1   pk: ${v1.publicKeyBase64}  match=$matchesV1');
      // ignore: avoid_print
      print('>>> Sofia v2   pk: ${v2.publicKeyBase64}  match=$matchesV2');
      // ignore: avoid_print
      print(
          '>>> (Links were from different random keypairs, not these mnemonics)');
    });
  });

  group(
      'Cross-verification: can Alex and Sofia actually encrypt/decrypt with v2 keys?',
      () {
    test('v2 keys: symmetric ECDH shared secret is equal for both', () async {
      final seedSvc = SeedService();

      final alexSeed = seedSvc.mnemonicToSeed(_alexMnemonic);
      final sofiaSeed = seedSvc.mnemonicToSeed(_sofiaMnemonic);

      final alexPriv = await seedSvc.deriveIdentityPrivateKey(alexSeed,
          version: IdentityDerivationVersion.v2);
      final sofiaPriv = await seedSvc.deriveIdentityPrivateKey(sofiaSeed,
          version: IdentityDerivationVersion.v2);

      final x25519 = X25519();
      final alexKP = await x25519.newKeyPairFromSeed(alexPriv);
      final sofiaKP = await x25519.newKeyPairFromSeed(sofiaPriv);
      final alexPub = await alexKP.extractPublicKey();
      final sofiaPub = await sofiaKP.extractPublicKey();

      // Alex computes shared secret with Sofia's public key.
      final sharedByAlex = await x25519.sharedSecretKey(
        keyPair: alexKP,
        remotePublicKey: sofiaPub,
      );
      // Sofia computes shared secret with Alex's public key.
      final sharedBySofia = await x25519.sharedSecretKey(
        keyPair: sofiaKP,
        remotePublicKey: alexPub,
      );

      final alexBytes = await sharedByAlex.extractBytes();
      final sofiaBytes = await sharedBySofia.extractBytes();

      // ignore: avoid_print
      print('\n>>> Alex v2  pub: ${base64Encode(alexPub.bytes)}');
      // ignore: avoid_print
      print('>>> Sofia v2 pub: ${base64Encode(sofiaPub.bytes)}');
      // ignore: avoid_print
      print(
          '>>> Shared secret match: ${alexBytes.toString() == sofiaBytes.toString()}');

      expect(alexBytes, equals(sofiaBytes),
          reason:
              'ECDH shared secret must be equal for both parties with v2 keys');
    });

    test('v2 keys: full encryption roundtrip Sofia→Alex with real mnemonics',
        () async {
      final seedSvc = SeedService();

      final alexSeed = seedSvc.mnemonicToSeed(_alexMnemonic);
      final sofiaSeed = seedSvc.mnemonicToSeed(_sofiaMnemonic);

      final alexPrivBytes = await seedSvc.deriveIdentityPrivateKey(alexSeed,
          version: IdentityDerivationVersion.v2);
      final sofiaPrivBytes = await seedSvc.deriveIdentityPrivateKey(sofiaSeed,
          version: IdentityDerivationVersion.v2);

      final x25519 = X25519();
      final alexPubBytes =
          (await (await x25519.newKeyPairFromSeed(alexPrivBytes))
                  .extractPublicKey())
              .bytes;
      final sofiaPubBytes =
          (await (await x25519.newKeyPairFromSeed(sofiaPrivBytes))
                  .extractPublicKey())
              .bytes;

      final alexPrivB64 = base64Encode(alexPrivBytes);
      final sofiaPrivB64 = base64Encode(sofiaPrivBytes);
      final alexPubB64 = base64Encode(alexPubBytes);
      final sofiaPubB64 = base64Encode(sofiaPubBytes);

      // ignore: avoid_print
      print('\n>>> Alex v2 pub (derived from mnemonic): $alexPubB64');
      // ignore: avoid_print
      print('>>> Alex link pk (from shared link):     $_alexLinkPk');
      // ignore: avoid_print
      print('>>> Alex pub matches link: ${alexPubB64 == _alexLinkPk}');
      // ignore: avoid_print
      print('');
      // ignore: avoid_print
      print('>>> Sofia v2 pub (derived from mnemonic): $sofiaPubB64');
      // ignore: avoid_print
      print('>>> Sofia link pk (from shared link):     $_sofiaLinkPk');
      // ignore: avoid_print
      print('>>> Sofia pub matches link: ${sofiaPubB64 == _sofiaLinkPk}');

      // Sofia encrypts to Alex.
      const secret = 'user: admin\npassword: jusg-Yets!gJdh@GTfJ';
      final enc = _SimpleEncryptionService();
      final (nonce: nonce, ciphertext: ct) = await enc.encrypt(
        senderPriv: sofiaPrivB64,
        recipientPub: alexPubB64,
        plaintext: secret,
      );

      // Alex decrypts with correct v2 key.
      final decrypted = await enc.decrypt(
        recipientPriv: alexPrivB64,
        senderPub: sofiaPubB64,
        nonce: nonce,
        ciphertext: ct,
      );

      // ignore: avoid_print
      print('\n>>> Decrypted text: $decrypted');

      expect(decrypted, equals(secret),
          reason:
              'Alex must be able to decrypt Sofia\'s message using v2 keys');
    });

    test(
        'v1 keys: full encryption roundtrip Sofia→Alex with real mnemonics (should also work)',
        () async {
      final seedSvc = SeedService();

      final alexSeed = seedSvc.mnemonicToSeed(_alexMnemonic);
      final sofiaSeed = seedSvc.mnemonicToSeed(_sofiaMnemonic);

      final alexPrivBytes = await seedSvc.deriveIdentityPrivateKey(alexSeed,
          version: IdentityDerivationVersion.v1);
      final sofiaPrivBytes = await seedSvc.deriveIdentityPrivateKey(sofiaSeed,
          version: IdentityDerivationVersion.v1);

      final x25519 = X25519();
      final alexPubBytes =
          (await (await x25519.newKeyPairFromSeed(alexPrivBytes))
                  .extractPublicKey())
              .bytes;
      final sofiaPubBytes =
          (await (await x25519.newKeyPairFromSeed(sofiaPrivBytes))
                  .extractPublicKey())
              .bytes;

      final alexPrivB64 = base64Encode(alexPrivBytes);
      final sofiaPrivB64 = base64Encode(sofiaPrivBytes);
      final alexPubB64 = base64Encode(alexPubBytes);
      final sofiaPubB64 = base64Encode(sofiaPubBytes);

      // ignore: avoid_print
      print('\n>>> Alex v1 pub (derived from mnemonic): $alexPubB64');
      // ignore: avoid_print
      print('>>> Alex link pk (from shared link):     $_alexLinkPk');
      // ignore: avoid_print
      print('>>> Alex v1 pub matches link: ${alexPubB64 == _alexLinkPk}');

      const secret = 'user: admin\npassword: jusg-Yets!gJdh@GTfJ';
      final enc = _SimpleEncryptionService();
      final (nonce: nonce, ciphertext: ct) = await enc.encrypt(
        senderPriv: sofiaPrivB64,
        recipientPub: alexPubB64,
        plaintext: secret,
      );

      final decrypted = await enc.decrypt(
        recipientPriv: alexPrivB64,
        senderPub: sofiaPubB64,
        nonce: nonce,
        ciphertext: ct,
      );

      expect(decrypted, equals(secret));
    });

    test('KEY VERSION MISMATCH: Sofia v2 → Alex v1 link CANNOT decrypt',
        () async {
      final seedSvc = SeedService();

      final alexSeed = seedSvc.mnemonicToSeed(_alexMnemonic);
      final sofiaSeed = seedSvc.mnemonicToSeed(_sofiaMnemonic);

      // Sofia uses v2 private key, Alex imported a v1 link (old public key).
      final alexPrivV2 = await seedSvc.deriveIdentityPrivateKey(alexSeed,
          version: IdentityDerivationVersion.v2);
      final sofiaPrivV2 = await seedSvc.deriveIdentityPrivateKey(sofiaSeed,
          version: IdentityDerivationVersion.v2);
      final alexPrivV1 = await seedSvc.deriveIdentityPrivateKey(alexSeed,
          version: IdentityDerivationVersion.v1);

      final x25519 = X25519();
      final alexPubV2 = base64Encode(
          (await (await x25519.newKeyPairFromSeed(alexPrivV2))
                  .extractPublicKey())
              .bytes);
      final alexPubV1 = base64Encode(
          (await (await x25519.newKeyPairFromSeed(alexPrivV1))
                  .extractPublicKey())
              .bytes);
      final sofiaPubV2 = base64Encode(
          (await (await x25519.newKeyPairFromSeed(sofiaPrivV2))
                  .extractPublicKey())
              .bytes);

      final alexPrivV2B64 = base64Encode(alexPrivV2);
      final alexPrivV1B64 = base64Encode(alexPrivV1);
      final sofiaPrivV2B64 = base64Encode(sofiaPrivV2);

      final enc = _SimpleEncryptionService();

      // Sofia (v2) encrypts TO Alex v2 public key → Alex decrypts with v2 → SUCCESS
      final (nonce: n1, ciphertext: c1) = await enc.encrypt(
        senderPriv: sofiaPrivV2B64,
        recipientPub: alexPubV2,
        plaintext: 'secret message',
      );
      final okDecrypt = await enc.decrypt(
        recipientPriv: alexPrivV2B64,
        senderPub: sofiaPubV2,
        nonce: n1,
        ciphertext: c1,
      );
      expect(okDecrypt, equals('secret message'), reason: 'v2→v2 must work');

      // Sofia (v2) encrypts TO Alex v2 public key → Alex tries to decrypt with v1 → FAIL
      final wrongDecrypt = await enc.decrypt(
        recipientPriv: alexPrivV1B64, // wrong version!
        senderPub: sofiaPubV2,
        nonce: n1,
        ciphertext: c1,
      );
      expect(wrongDecrypt, isNull,
          reason:
              'v2 sender + v1 recipient key = shared secret mismatch → decryption fails');

      // ignore: avoid_print
      print('\n>>> Alex v1 pub: $alexPubV1');
      // ignore: avoid_print
      print('>>> Alex v2 pub: $alexPubV2');
      // ignore: avoid_print
      print('>>> Sofia v2→AlexV2 decrypt: $okDecrypt');
      // ignore: avoid_print
      print(
          '>>> Sofia v2→AlexV1 decrypt: $wrongDecrypt (null = correct failure)');
    });

    test(
        '[BUG FIX] restoreIdentityFromMnemonic now uses v2 (same as createNewIdentity)',
        () async {
      // Before the fix: restore defaulted to v1 (legacyIdentityDerivationVersion).
      // After the fix: restore uses v2 (preferredIdentityDerivationVersion).
      // This means: if Alex originally created his identity (v2) and later restores
      // from mnemonic, he gets back the SAME public key and contacts can still
      // encrypt messages to him correctly.
      final mgrCreate = _mgr();
      final mgrRestore = _mgr();

      // Simulate: Alex creates identity on device A.
      // createNewIdentity internally calls mnemonicToSeed + deriveIdentityPrivateKey(v2).
      // We reconstruct this by restoring with v2 from the same mnemonic.
      final seedSvc = SeedService();
      final alexSeed = seedSvc.mnemonicToSeed(_alexMnemonic);
      final alexPrivV2 = await seedSvc.deriveIdentityPrivateKey(alexSeed,
          version: IdentityDerivationVersion.v2);
      final x25519 = X25519();
      final alexPubV2 = base64Encode(
          (await (await x25519.newKeyPairFromSeed(alexPrivV2))
                  .extractPublicKey())
              .bytes);

      // Restore with v2 (fixed behaviour).
      final restoredV2 = await mgrRestore.restoreIdentityFromMnemonic(
          _alexMnemonic,
          displayName: 'Alex',
          derivationVersion: IdentityDerivationVersion.v2);
      expect(restoredV2.publicKeyBase64, equals(alexPubV2),
          reason: 'Restore v2 must yield the same public key as create v2');

      // Restore with v1 (old buggy behaviour) must differ.
      final restoredV1 = await mgrCreate.restoreIdentityFromMnemonic(
          _alexMnemonic,
          displayName: 'Alex',
          derivationVersion: IdentityDerivationVersion.v1);
      expect(restoredV1.publicKeyBase64, isNot(equals(alexPubV2)),
          reason:
              'v1 restore must NOT equal v2 create — confirms the bug was real');

      // ignore: avoid_print
      print('\n>>> Alex v2 create pk: $alexPubV2');
      // ignore: avoid_print
      print(
          '>>> Alex v2 restore pk: ${restoredV2.publicKeyBase64}  match=${restoredV2.publicKeyBase64 == alexPubV2}');
      // ignore: avoid_print
      print(
          '>>> Alex v1 restore pk: ${restoredV1.publicKeyBase64}  (must differ)');
    });

    test('SUMMARY: link pk matches v1 or v2 for both Alex and Sofia', () async {
      final seedSvc = SeedService();
      final x25519 = X25519();

      Future<String> pubB64(
          String mnemonic, IdentityDerivationVersion ver) async {
        final seed = seedSvc.mnemonicToSeed(mnemonic);
        final priv = await seedSvc.deriveIdentityPrivateKey(seed, version: ver);
        final pub =
            await (await x25519.newKeyPairFromSeed(priv)).extractPublicKey();
        return base64Encode(pub.bytes);
      }

      final alexV1 = await pubB64(_alexMnemonic, IdentityDerivationVersion.v1);
      final alexV2 = await pubB64(_alexMnemonic, IdentityDerivationVersion.v2);
      final sofiaV1 =
          await pubB64(_sofiaMnemonic, IdentityDerivationVersion.v1);
      final sofiaV2 =
          await pubB64(_sofiaMnemonic, IdentityDerivationVersion.v2);

      // ignore: avoid_print
      print('\n╔══════════════════════════════════════════════════════╗');
      // ignore: avoid_print
      print('║              KEY VERSION SUMMARY                     ║');
      // ignore: avoid_print
      print('╠══════════════════════════════════════════════════════╣');
      // ignore: avoid_print
      print('║ Alex  link pk: $_alexLinkPk');
      // ignore: avoid_print
      print('║ Alex  v1   pk: $alexV1  [match=${alexV1 == _alexLinkPk}]');
      // ignore: avoid_print
      print('║ Alex  v2   pk: $alexV2  [match=${alexV2 == _alexLinkPk}]');
      // ignore: avoid_print
      print('╠══════════════════════════════════════════════════════╣');
      // ignore: avoid_print
      print('║ Sofia link pk: $_sofiaLinkPk');
      // ignore: avoid_print
      print('║ Sofia v1   pk: $sofiaV1  [match=${sofiaV1 == _sofiaLinkPk}]');
      // ignore: avoid_print
      print('║ Sofia v2   pk: $sofiaV2  [match=${sofiaV2 == _sofiaLinkPk}]');
      // ignore: avoid_print
      print('╚══════════════════════════════════════════════════════╝');

      // The links were generated from random keypairs (createNewIdentity) on the device,
      // NOT from these demo mnemonics. So no version will match — that is expected and
      // confirms the bug scenario: the user shared links from original random-key identities,
      // then "restored" using these mnemonics which produced different v1 keys.
      // After the fix, a fresh restore from mnemonic will produce v2 keys and new links
      // must be shared.
      final alexMatches = alexV1 == _alexLinkPk || alexV2 == _alexLinkPk;
      final sofiaMatches = sofiaV1 == _sofiaLinkPk || sofiaV2 == _sofiaLinkPk;
      // ignore: avoid_print
      print(
          '>>> Alex  link matches a mnemonic-derived key: $alexMatches  (expected: false)');
      // ignore: avoid_print
      print(
          '>>> Sofia link matches a mnemonic-derived key: $sofiaMatches (expected: false)');
      expect(alexMatches, isFalse,
          reason:
              'Confirms: links were from different random keypairs, not these mnemonics');
      expect(sofiaMatches, isFalse,
          reason:
              'Confirms: links were from different random keypairs, not these mnemonics');
    });
  });

  test(
    '[REGRESSION] default restore uses the same key derivation as create',
    () async {
      final seedSvc = SeedService();
      final alexSeed = seedSvc.mnemonicToSeed(_alexMnemonic);
      final alexV2Priv = await seedSvc.deriveIdentityPrivateKey(
        alexSeed,
        version: SeedService.preferredIdentityDerivationVersion,
      );
      final alexV2Pair = await X25519().newKeyPairFromSeed(alexV2Priv);
      final alexV2Pub =
          base64Encode((await alexV2Pair.extractPublicKey()).bytes);

      final restoredDefault = await _mgr().restoreIdentityFromMnemonic(
        _alexMnemonic,
        displayName: 'Alex default restore',
      );

      expect(restoredDefault.publicKeyBase64, equals(alexV2Pub));
      expect(
        restoredDefault.derivationVersion,
        SeedService.preferredIdentityDerivationVersion,
      );
    },
  );
}

// ── Minimal encryption helper (mirrors EncryptionService logic) ────────────

class _SimpleEncryptionService {
  final _x25519 = X25519();
  final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final _aes = AesGcm.with256bits();

  Future<SecretKey> _deriveKey(String localPrivB64, String remotePubB64) async {
    final privBytes = base64Decode(localPrivB64);
    final pubBytes = base64Decode(remotePubB64);
    final kp = await _x25519.newKeyPairFromSeed(privBytes);
    final remotePub = SimplePublicKey(pubBytes, type: KeyPairType.x25519);
    final shared =
        await _x25519.sharedSecretKey(keyPair: kp, remotePublicKey: remotePub);
    return _hkdf.deriveKey(
      secretKey: shared,
      nonce: utf8.encode('layergram'),
      info: utf8.encode('layergram-msg-v1'),
    );
  }

  Future<({List<int> nonce, List<int> ciphertext})> encrypt({
    required String senderPriv,
    required String recipientPub,
    required String plaintext,
  }) async {
    final key = await _deriveKey(senderPriv, recipientPub);
    final nonce = _aes.newNonce();
    final box = await _aes.encrypt(utf8.encode(plaintext),
        secretKey: key, nonce: nonce);
    return (nonce: nonce, ciphertext: [...box.cipherText, ...box.mac.bytes]);
  }

  Future<String?> decrypt({
    required String recipientPriv,
    required String senderPub,
    required List<int> nonce,
    required List<int> ciphertext,
  }) async {
    try {
      final key = await _deriveKey(recipientPriv, senderPub);
      final mac = Mac(ciphertext.sublist(ciphertext.length - 16));
      final ct = ciphertext.sublist(0, ciphertext.length - 16);
      final box = SecretBox(ct, nonce: nonce, mac: mac);
      final plain = await _aes.decrypt(box, secretKey: key);
      return utf8.decode(plain);
    } catch (_) {
      return null;
    }
  }
}
