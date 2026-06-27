import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart';
import 'dart:convert';

import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/models.dart';

void main() {
  test('encrypt/decrypt roundtrip returns original payload fields', () async {
    final service = EncryptionService();
    final x25519 = X25519();
    final alice = await x25519.newKeyPair();
    final bob = await x25519.newKeyPair();
    final alicePrivate = await alice.extractPrivateKeyBytes();
    final alicePublic = (await alice.extractPublicKey()).bytes;
    final bobPrivate = await bob.extractPrivateKeyBytes();
    final bobPublic = (await bob.extractPublicKey()).bytes;
    const payload = PlaintextPayload(
      senderId: 'alice',
      recipientId: 'bob',
      text: 'secret',
      timestamp: 1234567890,
      senderDisplayName: 'Alice',
      expireAfter: 1234569999,
      deleteAfterRead: true,
    );

    final encResult = await service.encrypt(
      senderPrivateKeyBase64: base64Encode(alicePrivate),
      recipientPublicKeyBase64: base64Encode(bobPublic),
      payload: payload,
    );

    final decResult = await service.decrypt(
      recipientPrivateKeyBase64: base64Encode(bobPrivate),
      senderPublicKeyBase64: base64Encode(alicePublic),
      message: encResult.message,
    );

    expect(decResult.payload.senderId, payload.senderId);
    expect(decResult.payload.recipientId, payload.recipientId);
    expect(decResult.payload.text, payload.text);
    expect(decResult.payload.timestamp, payload.timestamp);
    expect(decResult.payload.senderDisplayName, payload.senderDisplayName);
    expect(decResult.payload.expireAfter, payload.expireAfter);
    expect(decResult.payload.deleteAfterRead, payload.deleteAfterRead);
  });

  test('decrypt accepts base64url (no padding) nonce/ciphertext', () async {
    final service = EncryptionService();
    final x25519 = X25519();
    final alice = await x25519.newKeyPair();
    final bob = await x25519.newKeyPair();
    final alicePrivate = await alice.extractPrivateKeyBytes();
    final alicePublic = (await alice.extractPublicKey()).bytes;
    final bobPrivate = await bob.extractPrivateKeyBytes();
    final bobPublic = (await bob.extractPublicKey()).bytes;
    const payload = PlaintextPayload(
      senderId: 'alice',
      recipientId: 'bob',
      text: 'secret',
      timestamp: 1234567890,
      senderDisplayName: 'Alice',
      expireAfter: 1234569999,
      deleteAfterRead: true,
    );

    final encResult = await service.encrypt(
      senderPrivateKeyBase64: base64Encode(alicePrivate),
      recipientPublicKeyBase64: base64Encode(bobPublic),
      payload: payload,
    );
    final encrypted = encResult.message;

    String toBase64UrlNoPad(String input) {
      return input.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    }

    final urlMessage = EncryptedMessage(
      version: encrypted.version,
      senderId: encrypted.senderId,
      recipientId: encrypted.recipientId,
      nonceBase64: toBase64UrlNoPad(encrypted.nonceBase64),
      ciphertextBase64: toBase64UrlNoPad(encrypted.ciphertextBase64),
    );

    final decResult = await service.decrypt(
      recipientPrivateKeyBase64: base64Encode(bobPrivate),
      senderPublicKeyBase64: base64Encode(alicePublic),
      message: urlMessage,
    );

    expect(decResult.payload.senderId, payload.senderId);
    expect(decResult.payload.recipientId, payload.recipientId);
    expect(decResult.payload.text, payload.text);
    expect(decResult.payload.timestamp, payload.timestamp);
    expect(decResult.payload.senderDisplayName, payload.senderDisplayName);
    expect(decResult.payload.expireAfter, payload.expireAfter);
    expect(decResult.payload.deleteAfterRead, payload.deleteAfterRead);
  });
}
