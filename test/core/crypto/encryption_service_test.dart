import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_key_codec.dart';
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
    test('deriveSymmetricKey is symmetric between sender and recipient',
        () async {
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

    test(
        'tryDecryptWithKey returns payload for the correct key and null otherwise',
        () async {
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

    test('encrypt and decrypt preserve accented and emoji secret text',
        () async {
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

    test('encrypted message raw bytes roundtrip preserves nonce and ciphertext',
        () async {
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

  group('EncryptionService – FS encrypt/decrypt', () {
    final x255190 = X25519();

    Future<(Uint8List, Uint8List)> genDhPair() async {
      final pair = await x255190.newKeyPair();
      final priv = Uint8List.fromList(await pair.extractPrivateKeyBytes());
      final pub = Uint8List.fromList((await pair.extractPublicKey()).bytes);
      return (priv, pub);
    }

    Future<(RatchetState, RatchetState)> buildRatchets() async {
      final (ikAPriv, ikAPub) = await genDhPair();
      final (dkAPriv, _) = await genDhPair();
      final (ikBPriv, ikBPub) = await genDhPair();
      final (dkBPriv, _) = await genDhPair();

      final initPayload = await FsHandshake.generateFsInit(
        ikAPriv: ikAPriv,
        dkAPriv: dkAPriv,
      );
      final fsInit = initPayload.toMessage();

      final replyPayload = await FsHandshake.processFsInitAsResponder(
        ikBPriv: ikBPriv,
        dkBPriv: dkBPriv,
        ikAPub: ikAPub,
        init: fsInit,
      );
      final fsReply = replyPayload.toMessage();

      final confirmPayload = await FsHandshake.processFsReplyAsInitiator(
        ikAPriv: ikAPriv,
        dkAPriv: dkAPriv,
        ekAPrivBytes: initPayload.ekAPrivBytes,
        ikBPub: ikBPub,
        sentInit: fsInit,
        reply: fsReply,
      );
      final fsConfirm = confirmPayload.toMessage();

      final ok = await FsHandshake.verifyFsConfirmAsResponder(
        confirm: fsConfirm,
        bState: replyPayload.partialState,
        ikAPub: ikAPub,
      );
      expect(ok, isTrue);
      replyPayload.partialState.wipeRawRootSecret();

      final aState = confirmPayload.partialState;
      final bState = replyPayload.partialState;

      final ratchetAPriv = confirmPayload.initiatorInitialRatchetPriv;
      final ratchetAPub =
          FsKeyCodec.decodeKey(confirmPayload.initiatorInitialRatchetPub);
      final ratchetBPriv = replyPayload.responderInitialRatchetPriv;
      final ratchetBPub =
          FsKeyCodec.decodeKey(replyPayload.responderInitialRatchetPub);

      final aRatchet = await FsDoubleRatchet.initRatchet(
        rootKey0: aState.rootKey0,
        sendingChainKey0: aState.sendingChainKey0,
        receivingChainKey0: aState.receivingChainKey0,
        localRatchetPriv: ratchetAPriv,
        localRatchetPub: ratchetAPub,
        lastRemoteRatchetPub: ratchetBPub,
        sessionId: 'test-session',
      );

      final bRatchet = await FsDoubleRatchet.initRatchet(
        rootKey0: bState.rootKey0,
        sendingChainKey0: bState.sendingChainKey0,
        receivingChainKey0: bState.receivingChainKey0,
        localRatchetPriv: ratchetBPriv,
        localRatchetPub: ratchetBPub,
        lastRemoteRatchetPub: ratchetAPub,
        sessionId: 'test-session',
      );

      return (aRatchet, bRatchet);
    }

    Future<EncryptedMessage> encryptEnvelopeWithKey({
      required Map<String, dynamic> envelope,
      required SecretKey key,
      required String senderId,
      required String recipientId,
    }) async {
      final algo = AesGcm.with256bits();
      final nonce = algo.newNonce();
      final box = await algo.encrypt(
        utf8.encode(jsonEncode(envelope)),
        secretKey: key,
        nonce: nonce,
      );
      return EncryptedMessage(
        version: 2,
        senderId: senderId,
        recipientId: recipientId,
        nonceBase64: base64Encode(nonce),
        ciphertextBase64: base64Encode([...box.cipherText, ...box.mac.bytes]),
      );
    }

    test('FS-encrypted message can be decrypted by recipient', () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x255190.newKeyPair());
      final bob = await _keyMaterial(await x255190.newKeyPair());
      var (aRatchet, bRatchet) = await buildRatchets();

      const secretText = 'Messaggio con Forward Secrecy';
      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: secretText,
          timestamp: 1700000000,
          backupExcluded: true,
        ),
        ratchetState: aRatchet,
      );

      expect(encResult.newRatchetState, isNotNull);
      aRatchet = encResult.newRatchetState!;

      final decResult = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: encResult.message,
        ratchetState: bRatchet,
      );

      expect(decResult.payload.text, equals(secretText));
      expect(decResult.payload.backupExcluded, isTrue);
      expect(decResult.newRatchetState, isNotNull);
    });

    test('FS message cannot be re-decrypted after ratchet advances', () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x255190.newKeyPair());
      final bob = await _keyMaterial(await x255190.newKeyPair());
      var (aRatchet, bRatchet) = await buildRatchets();

      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: 'FS message',
          timestamp: 1700000000,
        ),
        ratchetState: aRatchet,
      );

      // First decrypt succeeds and advances the ratchet.
      final decResult = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: encResult.message,
        ratchetState: bRatchet,
      );
      expect(decResult.payload.text, equals('FS message'));
      final advancedRatchet = decResult.newRatchetState!;

      // Re-decrypt with advanced ratchet must throw (one-time decrypt).
      expect(
        () => service.decrypt(
          recipientPrivateKeyBase64: bob.privateKeyBase64,
          senderPublicKeyBase64: alice.publicKeyBase64,
          message: encResult.message,
          ratchetState: advancedRatchet,
        ),
        throwsA(anything),
      );
    });

    test('FS encryption rejects legacy fallback generation', () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x255190.newKeyPair());
      final bob = await _keyMaterial(await x255190.newKeyPair());
      final (aRatchet, _) = await buildRatchets();

      expect(
        () => service.encrypt(
          senderPrivateKeyBase64: alice.privateKeyBase64,
          recipientPublicKeyBase64: bob.publicKeyBase64,
          payload: const PlaintextPayload(
            senderId: 'alice',
            recipientId: 'bob',
            text: 'fallback must not be generated',
            timestamp: 1700000000,
          ),
          ratchetState: aRatchet,
          includeLegacyFallback: true,
        ),
        throwsArgumentError,
      );
    });

    test('historic single-envelope fallback is not used without ratchet',
        () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x255190.newKeyPair());
      final bob = await _keyMaterial(await x255190.newKeyPair());
      final (aRatchet, _) = await buildRatchets();
      const secretText = 'fallback text must be ignored';

      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: secretText,
          timestamp: 1700000000,
        ),
        ratchetState: aRatchet,
      );

      final key = await service.deriveSymmetricKey(
        localPrivateKeyBase64: bob.privateKeyBase64,
        remotePublicKeyBase64: alice.publicKeyBase64,
      );
      final envelope = await service.tryDecryptEnvelopeWithKey(
        message: encResult.message,
        key: key,
      );
      expect(envelope, isNotNull);
      final historicEnvelope = <String, dynamic>{
        ...envelope!,
        'text': secretText,
      };
      final historicMessage = await encryptEnvelopeWithKey(
        envelope: historicEnvelope,
        key: key,
        senderId: 'alice',
        recipientId: 'bob',
      );

      final decoded = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: historicMessage,
      );

      expect(decoded.fsDecryptFailed, isTrue);
      expect(decoded.isFsEnvelope, isTrue);
      expect(decoded.hasLegacyFallback, isTrue);
      expect(decoded.payload.text, isEmpty);
    });

    test('sender cannot re-decrypt own FS-encrypted message', () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x255190.newKeyPair());
      final bob = await _keyMaterial(await x255190.newKeyPair());
      var (aRatchet, bRatchet) = await buildRatchets();

      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: 'FS sent message',
          timestamp: 1700000000,
        ),
        ratchetState: aRatchet,
      );

      // Sender tries to decrypt own message with their ratchet — must fail
      // because send and receive chains use different keys.
      expect(
        () => service.decrypt(
          recipientPrivateKeyBase64: alice.privateKeyBase64,
          senderPublicKeyBase64: bob.publicKeyBase64,
          message: encResult.message,
          ratchetState: encResult.newRatchetState!,
        ),
        throwsA(anything),
      );
    });

    test('MessageRecord.text enables display without re-decryption', () {
      const text = 'Stored plaintext';
      final record = MessageRecord(
        id: '1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 1700000000,
        text: text,
        ciphertextBase64: 'encrypted_data',
        nonceBase64: 'nonce_data',
      );

      // Verify text is stored and retrievable.
      expect(record.text, equals(text));

      // Verify text survives serialization round-trip.
      final map = record.toMap();
      final restored = MessageRecord.fromMap(map);
      expect(restored.text, equals(text));
    });
  });
}
