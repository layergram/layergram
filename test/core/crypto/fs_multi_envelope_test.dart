// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// §9.6 — Multi-envelope messages.
//
// A single payload is encrypted once with a per-message content key; that
// content key is wrapped for every active device session of the contact. This
// lets one sent message be read in FS by all devices that already have a
// matching ratchet, without a legacy plaintext/content-key fallback.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_key_codec.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';

final _x25519 = X25519();

Future<({String privateKeyBase64, String publicKeyBase64})> _identity() async {
  final pair = await _x25519.newKeyPair();
  return (
    privateKeyBase64: base64Encode(await pair.extractPrivateKeyBytes()),
    publicKeyBase64: base64Encode((await pair.extractPublicKey()).bytes),
  );
}

Future<(Uint8List, Uint8List)> _genDhPair() async {
  final pair = await _x25519.newKeyPair();
  final priv = Uint8List.fromList(await pair.extractPrivateKeyBytes());
  final pub = Uint8List.fromList((await pair.extractPublicKey()).bytes);
  return (priv, pub);
}

/// Establishes an independent FS session with [sessionId] and returns the
/// sender ratchet (A) and the recipient device ratchet (B).
Future<(RatchetState sender, RatchetState device)> _buildSession(
  String sessionId,
) async {
  final (ikAPriv, ikAPub) = await _genDhPair();
  final (dkAPriv, _) = await _genDhPair();
  final (ikBPriv, ikBPub) = await _genDhPair();
  final (dkBPriv, _) = await _genDhPair();

  final initPayload =
      await FsHandshake.generateFsInit(ikAPriv: ikAPriv, dkAPriv: dkAPriv);
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
  final ok = await FsHandshake.verifyFsConfirmAsResponder(
    confirm: confirmPayload.toMessage(),
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
    sessionId: sessionId,
  );
  final bRatchet = await FsDoubleRatchet.initRatchet(
    rootKey0: bState.rootKey0,
    sendingChainKey0: bState.sendingChainKey0,
    receivingChainKey0: bState.receivingChainKey0,
    localRatchetPriv: ratchetBPriv,
    localRatchetPub: ratchetBPub,
    lastRemoteRatchetPub: ratchetAPub,
    sessionId: sessionId,
  );
  return (aRatchet, bRatchet);
}

Future<EncryptedMessage> _encryptEnvelopeWithKey({
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

void main() {
  group('§9.6 multi-envelope', () {
    const text = 'segreto multi-dispositivo';

    test('single message is readable in FS by both device sessions', () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity(); // same identity on both devices

      final (aRatchetA, bRatchetA) = await _buildSession('session-A');
      final (aRatchetB, bRatchetB) = await _buildSession('session-B');

      final result = await service.encryptMultiEnvelope(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: text,
          timestamp: 1700000000,
        ),
        sessionRatchets: {'session-A': aRatchetA, 'session-B': aRatchetB},
      );

      // One advanced ratchet returned per session.
      expect(result.newRatchetStates.keys.toSet(),
          equals({'session-A', 'session-B'}));

      // Device A reads it via session A's ratchet only.
      final decA = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: result.message,
        allRatchetStates: {'session-A': bRatchetA},
      );
      expect(decA.payload.text, equals(text));
      expect(decA.fsDecryptFailed, isFalse);
      expect(decA.newRatchetState, isNotNull);

      // Device B reads the same payload via session B's ratchet only.
      final decB = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: result.message,
        allRatchetStates: {'session-B': bRatchetB},
      );
      expect(decB.payload.text, equals(text));
      expect(decB.fsDecryptFailed, isFalse);
      expect(decB.newRatchetState, isNotNull);
    });

    test('payload encrypted once; one wrap per session, single ciphertext',
        () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity();
      final (aRatchetA, _) = await _buildSession('session-A');
      final (aRatchetB, _) = await _buildSession('session-B');

      final result = await service.encryptMultiEnvelope(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: text,
          timestamp: 1700000000,
        ),
        sessionRatchets: {'session-A': aRatchetA, 'session-B': aRatchetB},
      );

      // Inspect the inner envelope via the identity (outer) key.
      final outerKey = await service.deriveSymmetricKey(
        localPrivateKeyBase64: bob.privateKeyBase64,
        remotePublicKeyBase64: alice.publicKeyBase64,
      );
      final env = await service.tryDecryptEnvelopeWithKey(
        message: result.message,
        key: outerKey,
      );
      expect(env, isNotNull);
      expect(env!['fs_multi'], equals(1));
      expect((env['fs_wraps'] as List).length, equals(2));
      expect(env['mc_cipher'], isA<String>());
      // No legacy fallback by default → stays full FS.
      expect(env.containsKey('mc_fallback_key'), isFalse);
    });

    test('cover estimate scales with active multi-session wraps', () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity();
      final (aRatchetA, _) = await _buildSession('session-A');
      final (aRatchetB, _) = await _buildSession('session-B');

      const secret = 'x';
      final result = await service.encryptMultiEnvelope(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'ZDUAW7VUD2REOOXCEM42V2YLLWWEWXAHMANIQN6SSR2OUMZAA3SQ',
          recipientId: 'TUJLJ5VUTD7S5B3S2CMVLOHNPDNBVPWJVPDFUENAI4NRYDZIIQVA',
          text: secret,
          timestamp: 1700000000,
          senderDisplayName: 'Layergram sender with realistic display name',
        ),
        sessionRatchets: {'session-A': aRatchetA, 'session-B': aRatchetB},
      );

      final singleWrapEstimate = StegoEncoder.estimatedCoverMessagePayloadBytes(
        secret,
        fsActive: true,
      );
      final multiWrapEstimate = StegoEncoder.estimatedCoverMessagePayloadBytes(
        secret,
        fsActive: true,
        fsWrapCount: 2,
      );
      final actualBytes = result.message.toRawBytes().length;

      expect(singleWrapEstimate, lessThan(multiWrapEstimate));
      expect(multiWrapEstimate, greaterThanOrEqualTo(actualBytes));
    });

    test('decrypting wrap advances only that device session ratchet', () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity();
      final (aRatchetA, bRatchetA) = await _buildSession('session-A');
      final (aRatchetB, _) = await _buildSession('session-B');

      final result = await service.encryptMultiEnvelope(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: text,
          timestamp: 1700000000,
        ),
        sessionRatchets: {'session-A': aRatchetA, 'session-B': aRatchetB},
      );

      final decA = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: result.message,
        allRatchetStates: {'session-A': bRatchetA},
      );
      final advanced = decA.newRatchetState!;

      // Re-decrypting the same message with the advanced ratchet must fail
      // (one-time decrypt — forward secrecy holds per device).
      expect(
        () => service.decrypt(
          recipientPrivateKeyBase64: bob.privateKeyBase64,
          senderPublicKeyBase64: alice.publicKeyBase64,
          message: result.message,
          allRatchetStates: {'session-A': advanced},
        ),
        throwsA(anything),
      );
    });

    test('device with no matching session and no fallback cannot read',
        () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity();
      final (aRatchetA, _) = await _buildSession('session-A');
      final (aRatchetB, _) = await _buildSession('session-B');

      final result = await service.encryptMultiEnvelope(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: text,
          timestamp: 1700000000,
        ),
        sessionRatchets: {'session-A': aRatchetA, 'session-B': aRatchetB},
      );

      // A third device with no FS session for this message.
      final dec = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: result.message,
        allRatchetStates: const {},
      );
      expect(dec.fsDecryptFailed, isTrue);
      expect(dec.payload.text, isEmpty);
    });

    test('legacy fallback generation is rejected', () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity();
      final (aRatchetA, _) = await _buildSession('session-A');
      final (aRatchetB, _) = await _buildSession('session-B');

      expect(
        () => service.encryptMultiEnvelope(
          senderPrivateKeyBase64: alice.privateKeyBase64,
          recipientPublicKeyBase64: bob.publicKeyBase64,
          payload: const PlaintextPayload(
            senderId: 'alice',
            recipientId: 'bob',
            text: text,
            timestamp: 1700000000,
          ),
          sessionRatchets: {'session-A': aRatchetA, 'session-B': aRatchetB},
          includeLegacyFallback: true,
        ),
        throwsArgumentError,
      );
    });

    test('historic mc_fallback_key is ignored without matching ratchet',
        () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity();
      final (aRatchetA, _) = await _buildSession('session-A');
      final (aRatchetB, _) = await _buildSession('session-B');

      final result = await service.encryptMultiEnvelope(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: text,
          timestamp: 1700000000,
        ),
        sessionRatchets: {'session-A': aRatchetA, 'session-B': aRatchetB},
      );
      final outerKey = await service.deriveSymmetricKey(
        localPrivateKeyBase64: bob.privateKeyBase64,
        remotePublicKeyBase64: alice.publicKeyBase64,
      );
      final env = await service.tryDecryptEnvelopeWithKey(
        message: result.message,
        key: outerKey,
      );
      expect(env, isNotNull);
      final historicEnvelope = <String, dynamic>{
        ...env!,
        'mc_fallback_key': base64Encode(Uint8List(32)),
      };
      final historicMessage = await _encryptEnvelopeWithKey(
        envelope: historicEnvelope,
        key: outerKey,
        senderId: 'alice',
        recipientId: 'bob',
      );

      final dec = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: historicMessage,
        allRatchetStates: const {},
      );
      expect(dec.payload.text, isEmpty);
      expect(dec.fsDecryptFailed, isTrue);
      expect(dec.hasLegacyFallback, isTrue);
      expect(dec.newRatchetState, isNull);
    });

    test('plaintext never appears in the outer envelope (no fallback)',
        () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity();
      final (aRatchetA, _) = await _buildSession('session-A');
      final (aRatchetB, _) = await _buildSession('session-B');

      final result = await service.encryptMultiEnvelope(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: text,
          timestamp: 1700000000,
        ),
        sessionRatchets: {'session-A': aRatchetA, 'session-B': aRatchetB},
      );

      final outerKey = await service.deriveSymmetricKey(
        localPrivateKeyBase64: bob.privateKeyBase64,
        remotePublicKeyBase64: alice.publicKeyBase64,
      );
      final env = await service.tryDecryptEnvelopeWithKey(
        message: result.message,
        key: outerKey,
      );
      // Identity-key holder sees structure but not the content: no plaintext,
      // no content key — content is recoverable only via an FS ratchet.
      expect(env!.containsKey('text'), isFalse);
      expect(env.containsKey('mc_fallback_key'), isFalse);
      // The content ciphertext bytes do not contain the plaintext.
      final mcBytes = base64Decode(env['mc_cipher'] as String);
      expect(mcBytes, isNot(containsAllInOrder(utf8.encode(text))));
      expect(jsonEncode(env), isNot(contains(text)));
    });

    test('empty sessionRatchets is rejected', () async {
      final service = EncryptionService();
      final alice = await _identity();
      final bob = await _identity();
      expect(
        () => service.encryptMultiEnvelope(
          senderPrivateKeyBase64: alice.privateKeyBase64,
          recipientPublicKeyBase64: bob.publicKeyBase64,
          payload: const PlaintextPayload(
            senderId: 'alice',
            recipientId: 'bob',
            text: text,
            timestamp: 1700000000,
          ),
          sessionRatchets: const {},
        ),
        throwsArgumentError,
      );
    });
  });
}
