import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/models.dart';

Future<({String privateKeyBase64, String publicKeyBase64})> _keyMaterial(
  SimpleKeyPair keyPair,
) async {
  final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
  final publicKeyBytes = (await keyPair.extractPublicKey()).bytes;
  return (
    privateKeyBase64: base64Encode(privateKeyBytes),
    publicKeyBase64: base64Encode(publicKeyBytes),
  );
}

void main() {
  group('EncryptionService', () {
    test('deriveSymmetricKey is symmetric between sender and recipient', () async {
      final service = EncryptionService();
      final x25519 = X25519();
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());

      final senderSideKey = await service.deriveSymmetricKey(
        localPrivateKeyBase64: alice.privateKeyBase64,
        remotePublicKeyBase64: bob.publicKeyBase64,
      );
      final recipientSideKey = await service.deriveSymmetricKey(
        localPrivateKeyBase64: bob.privateKeyBase64,
        remotePublicKeyBase64: alice.publicKeyBase64,
      );

      expect(
        await senderSideKey.extractBytes(),
        await recipientSideKey.extractBytes(),
      );
    });

    test('tryDecryptWithKey returns payload for the correct key and null otherwise', () async {
      final service = EncryptionService();
      final x25519 = X25519();
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());
      final charlie = await _keyMaterial(await x25519.newKeyPair());
      const payload = PlaintextPayload(
        senderId: 'alice',
        recipientId: 'bob',
        text: 'hidden text',
        timestamp: 1700000000,
        senderDisplayName: 'Alice',
        expireAfter: 60,
        deleteAfterRead: true,
      );

      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: payload,
      );

      final correctKey = await service.deriveSymmetricKey(
        localPrivateKeyBase64: bob.privateKeyBase64,
        remotePublicKeyBase64: alice.publicKeyBase64,
      );
      final wrongKey = await service.deriveSymmetricKey(
        localPrivateKeyBase64: charlie.privateKeyBase64,
        remotePublicKeyBase64: alice.publicKeyBase64,
      );

      final decrypted = await service.tryDecryptWithKey(
        message: encResult.message,
        key: correctKey,
      );
      final failed = await service.tryDecryptWithKey(
        message: encResult.message,
        key: wrongKey,
      );

      expect(decrypted, isNotNull);
      expect(decrypted?.text, payload.text);
      expect(decrypted?.senderId, payload.senderId);
      expect(decrypted?.recipientId, payload.recipientId);
      expect(decrypted?.deleteAfterRead, isTrue);
      expect(failed, isNull);
    });

    test('encrypt and decrypt preserve accented and emoji secret text', () async {
      final service = EncryptionService();
      final x25519 = X25519();
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());
      const payload = PlaintextPayload(
        senderId: 'alice',
        recipientId: 'bob',
        text: 'Caffè, mañana, déjà vu, 😄🔐🚀',
        timestamp: 1700000001,
        senderDisplayName: 'Àlice 😄',
      );

      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: payload,
      );

      final decResult = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: encResult.message,
      );

      expect(decResult.payload.text, payload.text);
      expect(decResult.payload.senderDisplayName, payload.senderDisplayName);
    });

    test('encrypted message raw bytes roundtrip preserves nonce and ciphertext', () async {
      final service = EncryptionService();
      final x25519 = X25519();
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());
      const payload = PlaintextPayload(
        senderId: 'alice',
        recipientId: 'bob',
        text: 'raw payload test',
        timestamp: 42,
      );

      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: payload,
      );
      final encrypted = encResult.message;

      final raw = encrypted.toRawBytes();
      final reconstructed = EncryptedMessage.fromRawBytes(raw);

      expect(reconstructed.nonceBase64, encrypted.nonceBase64);
      expect(reconstructed.ciphertextBase64, encrypted.ciphertextBase64);
      expect(reconstructed.version, 2);
      expect(reconstructed.senderId, isEmpty);
      expect(reconstructed.recipientId, isEmpty);
    });
  });
}
