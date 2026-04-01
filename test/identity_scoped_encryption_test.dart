import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/models.dart';

void main() {
  test('encryption uses different keys between identities', () async {
    // Deterministic seeds so the test is stable.
    final seedA = List<int>.generate(32, (i) => i);
    final seedB = List<int>.generate(32, (i) => 255 - i);
    final seedRecipient = List<int>.generate(32, (i) => (i * 7) % 256);

    final x25519 = X25519();
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

    Future<({String privB64, String pubB64})> keyPairFromSeed(
        List<int> seed) async {
      final pair = await x25519.newKeyPairFromSeed(seed);
      final publicKey = await pair.extractPublicKey();
      return (
        privB64: base64Encode(Uint8List.fromList(seed)),
        pubB64: base64Encode(Uint8List.fromList(publicKey.bytes)),
      );
    }

    Future<List<int>> deriveKeyBytes({
      required String localPrivateKeyBase64,
      required String remotePublicKeyBase64,
    }) async {
      final localPrivateBytes = base64Decode(localPrivateKeyBase64);
      final remotePublicBytes = base64Decode(remotePublicKeyBase64);

      final localPublic = await x25519
          .newKeyPairFromSeed(localPrivateBytes)
          .then((pair) => pair.extractPublicKey());

      final localKeyPair = SimpleKeyPairData(
        Uint8List.fromList(localPrivateBytes),
        type: KeyPairType.x25519,
        publicKey: localPublic,
      );
      final remotePublic = SimplePublicKey(
        Uint8List.fromList(remotePublicBytes),
        type: KeyPairType.x25519,
      );

      final shared = await x25519.sharedSecretKey(
        keyPair: localKeyPair,
        remotePublicKey: remotePublic,
      );

      final key = await hkdf.deriveKey(
        secretKey: shared,
        nonce: utf8.encode('layergram-v1'),
        info: utf8.encode('msg-encryption'),
      );
      return await key.extractBytes();
    }

    final a = await keyPairFromSeed(seedA);
    final b = await keyPairFromSeed(seedB);
    final recipient = await keyPairFromSeed(seedRecipient);

    final keyABytes = await deriveKeyBytes(
      localPrivateKeyBase64: a.privB64,
      remotePublicKeyBase64: recipient.pubB64,
    );
    final keyBBytes = await deriveKeyBytes(
      localPrivateKeyBase64: b.privB64,
      remotePublicKeyBase64: recipient.pubB64,
    );

    expect(keyABytes, isNot(equals(keyBBytes)));

    final algo = AesGcm.with256bits();
    final fixedNonce = Uint8List.fromList(List<int>.generate(12, (i) => i + 1));
    const clearText = 'hello-layergram';

    final boxA = await algo.encrypt(
      utf8.encode(clearText),
      secretKey: SecretKey(keyABytes),
      nonce: fixedNonce,
    );
    final boxB = await algo.encrypt(
      utf8.encode(clearText),
      secretKey: SecretKey(keyBBytes),
      nonce: fixedNonce,
    );

    final aCipher = <int>[...boxA.cipherText, ...boxA.mac.bytes];
    final bCipher = <int>[...boxB.cipherText, ...boxB.mac.bytes];
    expect(aCipher, isNot(equals(bCipher)));

    // End-to-end: a message encrypted by identity A must fail to decrypt if we
    // use identity B's public key as the sender.
    final service = EncryptionService();

    final encryptedA = await service.encrypt(
      senderPrivateKeyBase64: a.privB64,
      recipientPublicKeyBase64: recipient.pubB64,
      payload: const PlaintextPayload(
        senderId: 'A',
        recipientId: 'R',
        text: 'test',
        timestamp: 123,
      ),
    );

    final decrypted = await service.decrypt(
      recipientPrivateKeyBase64: recipient.privB64,
      senderPublicKeyBase64: a.pubB64,
      message: encryptedA,
    );
    expect(decrypted.text, 'test');

    expect(
      () => service.decrypt(
        recipientPrivateKeyBase64: recipient.privB64,
        senderPublicKeyBase64: b.pubB64,
        message: encryptedA,
      ),
      throwsA(isA<SecretBoxAuthenticationError>()),
    );
  });
}
