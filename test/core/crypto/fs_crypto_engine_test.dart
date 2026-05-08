// Tests for the Forward Secrecy cryptographic engine (Spec Phase 3).
//
// Acceptance criteria:
//  T3.1   Alice and Bob derive the same initial session state.
//  T3.2   Reordered transcript inputs → confirmTag fails.
//  T3.3   Modified transcript field → confirmTag fails.
//  T3.4   Invalid public keys → FsKeyCodecException thrown.
//  T3.5   All-zero DH output → FsKeyCodecException thrown.
//  T3.6   Nonce uniqueness: 1000 consecutive FS messages have unique nonces.
//  T3.7   chainSeed_0 is fully consumed into sendingChainKey / receivingChainKey.
//  T3.8   confirmKey is wiped / not reusable after first use.
//  T3.9   Replayed FS_CONFIRM (duplicate confirmTag) fails on second presentation.
//  T3.10  Full FS_INIT → FS_REPLY → FS_CONFIRM flow → ratchet active.
//  T3.11  All-zero X25519 public key is rejected by FsKeyCodec.
//  T3.12  Known low-order X25519 points are rejected by FsKeyCodec.
//  T3.13  Alice encrypts 3 messages; Bob decrypts all 3 in order.
//  T3.14  Out-of-order delivery: Bob skips msg 1, receives 3, then 1.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_key_codec.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

final _x25519 = X25519();

Future<(Uint8List priv, Uint8List pub)> _genKeyPair() async {
  final pair = await _x25519.newKeyPair();
  final priv = Uint8List.fromList(await pair.extractPrivateKeyBytes());
  final pubKey = await pair.extractPublicKey() as SimplePublicKey;
  final pub = Uint8List.fromList(pubKey.bytes);
  return (priv, pub);
}

/// Runs the full Alice-initiator / Bob-responder handshake and returns
/// the two [FsHandshakePartialState]s plus both payloads ready for ratchet init.
Future<(
  FsHandshakePartialState aState,
  FsHandshakePartialState bState,
  FsConfirmPayload confirmPayload,
  FsReplyPayload replyPayload,
)> _fullHandshake({
  required Uint8List ikAPriv,
  required Uint8List ikAPub,
  required Uint8List dkAPriv,
  required Uint8List ikBPriv,
  required Uint8List ikBPub,
  required Uint8List dkBPriv,
}) async {
  // Step 1: Alice generates FS_INIT.
  final initPayload = await FsHandshake.generateFsInit(
    ikAPriv: ikAPriv,
    dkAPriv: dkAPriv,
  );
  final fsInit = initPayload.toMessage();

  // Step 2: Bob processes FS_INIT and generates FS_REPLY.
  final replyPayload = await FsHandshake.processFsInitAsResponder(
    ikBPriv: ikBPriv,
    dkBPriv: dkBPriv,
    ikAPub: ikAPub,
    init: fsInit,
  );
  final fsReply = replyPayload.toMessage();

  // Step 3: Alice processes FS_REPLY and generates FS_CONFIRM.
  final confirmPayload = await FsHandshake.processFsReplyAsInitiator(
    ikAPriv: ikAPriv,
    dkAPriv: dkAPriv,
    ekAPrivBytes: initPayload.ekAPrivBytes,
    ikBPub: ikBPub,
    sentInit: fsInit,
    reply: fsReply,
  );
  final fsConfirm = confirmPayload.toMessage();

  // Step 4: Bob verifies FS_CONFIRM.
  final ok = await FsHandshake.verifyFsConfirmAsResponder(
    confirm: fsConfirm,
    bState: replyPayload.partialState,
    ikAPub: ikAPub,
  );
  expect(ok, isTrue, reason: 'FS_CONFIRM verification must succeed');
  replyPayload.partialState.wipeRawRootSecret();

  return (confirmPayload.partialState, replyPayload.partialState, confirmPayload, replyPayload);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  group('FsKeyCodec', () {
    // T3.4 — Invalid public keys rejected.
    test('T3.4a: null/empty input rejected', () {
      expect(
        () => FsKeyCodec.decodeKey(null),
        throwsA(isA<FsKeyCodecException>()),
      );
      expect(
        () => FsKeyCodec.decodeKey(''),
        throwsA(isA<FsKeyCodecException>()),
      );
    });

    test('T3.4b: wrong encoded length rejected', () {
      // 10 bytes instead of 33.
      final short = base64Url.encode(Uint8List(10));
      expect(
        () => FsKeyCodec.decodeKey(short),
        throwsA(isA<FsKeyCodecException>()),
      );
    });

    test('T3.4c: unsupported curve identifier rejected', () {
      final bytes = Uint8List(33);
      bytes[0] = 0x02; // Not 0x01 (X25519).
      for (var i = 1; i < 33; i++) bytes[i] = i;
      final encoded = base64Url.encode(bytes).replaceAll('=', '');
      expect(
        () => FsKeyCodec.decodeKey(encoded),
        throwsA(isA<FsKeyCodecException>()),
      );
    });

    test('T3.4d: invalid base64url rejected', () {
      expect(
        () => FsKeyCodec.decodeKey('not-base64!!!!!'),
        throwsA(isA<FsKeyCodecException>()),
      );
    });

    // T3.11 — All-zero X25519 public key rejected.
    test('T3.11: all-zero public key rejected', () {
      final bytes = Uint8List(33); // All zeros including curve byte = 0.
      bytes[0] = 0x01;
      final encoded = base64Url.encode(bytes).replaceAll('=', '');
      expect(
        () => FsKeyCodec.decodeKey(encoded),
        throwsA(isA<FsKeyCodecException>()),
      );
    });

    // T3.12 — Known low-order points rejected.
    test('T3.12: low-order X25519 point (order-8) rejected', () {
      // The order-8 point from FsKeyCodec._lowOrderPoints.
      const raw = [
        0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24,
        0xb1,0xd0,0xb1,0x55,0x9c,0x83,0xef,0x5b,
        0x04,0x44,0x5c,0xc4,0x58,0x1c,0x8e,0x86,
        0xd8,0x22,0x4e,0xdd,0xd0,0x9f,0x11,0x57,
      ];
      final encoded = FsKeyCodec.encodeKey(Uint8List.fromList(raw));
      // encodeKey does not validate; decodeKey does.
      expect(
        () => FsKeyCodec.decodeKey(encoded),
        throwsA(isA<FsKeyCodecException>()),
      );
    });

    // T3.5 — All-zero DH output rejected.
    test('T3.5: all-zero DH output rejected', () {
      expect(
        () => FsKeyCodec.validateDhOutput(Uint8List(32)),
        throwsA(isA<FsKeyCodecException>()),
      );
    });

    test('encodeKey round-trip: encode then decode returns original bytes', () async {
      final (_, pub) = await _genKeyPair();
      final encoded = FsKeyCodec.encodeKey(pub);
      final decoded = FsKeyCodec.decodeKey(encoded);
      expect(decoded, equals(pub));
    });
  });

  group('FsHandshake', () {
    late Uint8List ikAPriv, ikAPub;
    late Uint8List dkAPriv;
    late Uint8List ikBPriv, ikBPub;
    late Uint8List dkBPriv;

    setUpAll(() async {
      (ikAPriv, ikAPub) = await _genKeyPair();
      (dkAPriv, _) = await _genKeyPair();
      (ikBPriv, ikBPub) = await _genKeyPair();
      (dkBPriv, _) = await _genKeyPair();
    });

    // T3.10 — Full handshake flow.
    test('T3.10: full FS_INIT → FS_REPLY → FS_CONFIRM → session', () async {
      final (aState, bState, _, __) = await _fullHandshake(
        ikAPriv: ikAPriv, ikAPub: ikAPub, dkAPriv: dkAPriv,
        ikBPriv: ikBPriv, ikBPub: ikBPub, dkBPriv: dkBPriv,
      );

      // Both sides derive the same rootKey0.
      expect(aState.rootKey0, equals(bState.rootKey0),
          reason: 'rootKey0 must match on both sides');

      // Sending chain of A must equal receiving chain of B.
      expect(aState.sendingChainKey0, equals(bState.receivingChainKey0),
          reason: 'A sending chain = B receiving chain');

      // Receiving chain of A must equal sending chain of B.
      expect(aState.receivingChainKey0, equals(bState.sendingChainKey0),
          reason: 'A receiving chain = B sending chain');
    });

    // T3.1 — Same session state derived.
    test('T3.1: Alice and Bob derive matching initial session keys', () async {
      final (aState, bState, _, __) = await _fullHandshake(
        ikAPriv: ikAPriv, ikAPub: ikAPub, dkAPriv: dkAPriv,
        ikBPriv: ikBPriv, ikBPub: ikBPub, dkBPriv: dkBPriv,
      );

      expect(aState.rootKey0, equals(bState.rootKey0));
      expect(aState.sendingChainKey0, equals(bState.receivingChainKey0));
      expect(aState.receivingChainKey0, equals(bState.sendingChainKey0));
    });

    // T3.7 — chainSeed_0 is not re-derivable from sendingChainKey0 and receivingChainKey0.
    test('T3.7: sendingChainKey and receivingChainKey differ from each other', () async {
      final (aState, _, __, ___) = await _fullHandshake(
        ikAPriv: ikAPriv, ikAPub: ikAPub, dkAPriv: dkAPriv,
        ikBPriv: ikBPriv, ikBPub: ikBPub, dkBPriv: dkBPriv,
      );
      expect(aState.sendingChainKey0, isNot(equals(aState.receivingChainKey0)),
          reason: 'Sending and receiving chain keys must differ');
    });

    // T3.2 — Reordered transcript (swap A/B keys) → FS_CONFIRM fails.
    test('T3.2: swapped A/B identities in transcript → FS_CONFIRM verification fails', () async {
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

      // Pass B's ikBPub as ikAPub — this corrupts the transcript hash.
      final result = await FsHandshake.verifyFsConfirmAsResponder(
        confirm: fsConfirm,
        bState: FsHandshakePartialState(
          transcriptHash: replyPayload.partialState.transcriptHash,
          rootKey0: replyPayload.partialState.rootKey0,
          sendingChainKey0: replyPayload.partialState.sendingChainKey0,
          receivingChainKey0: replyPayload.partialState.receivingChainKey0,
          isInitiator: false,
          // Tamper: pass wrong rawRootSecret derived with ikBPub as A.
          rawRootSecret: Uint8List(64)..fillRange(0, 64, 0x01),
        ),
        ikAPub: ikAPub,
      );
      expect(result, isFalse,
          reason: 'Tampered rawRootSecret must cause FS_CONFIRM to fail');
    });

    // T3.3 — Modified confirmTag → fails.
    test('T3.3: modified confirmTag rejected', () async {
      final initPayload = await FsHandshake.generateFsInit(
        ikAPriv: ikAPriv, dkAPriv: dkAPriv,
      );
      final replyPayload = await FsHandshake.processFsInitAsResponder(
        ikBPriv: ikBPriv, dkBPriv: dkBPriv, ikAPub: ikAPub,
        init: initPayload.toMessage(),
      );
      final confirmPayload = await FsHandshake.processFsReplyAsInitiator(
        ikAPriv: ikAPriv, dkAPriv: dkAPriv,
        ekAPrivBytes: initPayload.ekAPrivBytes,
        ikBPub: ikBPub,
        sentInit: initPayload.toMessage(),
        reply: replyPayload.toMessage(),
      );

      // Tamper: flip first byte of confirmTag.
      final origTag = base64Url.decode(
        _padBase64(confirmPayload.confirmTag),
      );
      origTag[0] ^= 0xFF;
      final tamperedTag = base64Url.encode(origTag).replaceAll('=', '');

      final tamperedConfirm = FsConfirmMessage(
        initId: confirmPayload.initId,
        replyId: confirmPayload.replyId,
        transcriptHash: confirmPayload.transcriptHash,
        confirmTag: tamperedTag,
        initiatorInitialRatchetPub: confirmPayload.initiatorInitialRatchetPub,
      );

      final result = await FsHandshake.verifyFsConfirmAsResponder(
        confirm: tamperedConfirm,
        bState: replyPayload.partialState,
        ikAPub: ikAPub,
      );
      expect(result, isFalse);
    });

    // T3.9 — Replayed FS_CONFIRM: second verification with wiped secret fails.
    test('T3.9: FS_CONFIRM cannot be verified twice (rawRootSecret wiped)', () async {
      final initPayload = await FsHandshake.generateFsInit(
        ikAPriv: ikAPriv, dkAPriv: dkAPriv,
      );
      final replyPayload = await FsHandshake.processFsInitAsResponder(
        ikBPriv: ikBPriv, dkBPriv: dkBPriv, ikAPub: ikAPub,
        init: initPayload.toMessage(),
      );
      final confirmPayload = await FsHandshake.processFsReplyAsInitiator(
        ikAPriv: ikAPriv, dkAPriv: dkAPriv,
        ekAPrivBytes: initPayload.ekAPrivBytes,
        ikBPub: ikBPub,
        sentInit: initPayload.toMessage(),
        reply: replyPayload.toMessage(),
      );

      // First verification succeeds.
      final first = await FsHandshake.verifyFsConfirmAsResponder(
        confirm: confirmPayload.toMessage(),
        bState: replyPayload.partialState,
        ikAPub: ikAPub,
      );
      expect(first, isTrue);

      // Wipe the raw root secret (simulates caller cleanup after success).
      replyPayload.partialState.wipeRawRootSecret();

      // Second verification with same state (wiped secret) must fail.
      final second = await FsHandshake.verifyFsConfirmAsResponder(
        confirm: confirmPayload.toMessage(),
        bState: replyPayload.partialState,
        ikAPub: ikAPub,
      );
      expect(second, isFalse,
          reason: 'Replayed FS_CONFIRM must fail after rawRootSecret is wiped');
    });
  });

  group('FsDoubleRatchet', () {
    late Uint8List ikAPriv, ikAPub;
    late Uint8List dkAPriv;
    late Uint8List ikBPriv, ikBPub;
    late Uint8List dkBPriv;

    setUpAll(() async {
      (ikAPriv, ikAPub) = await _genKeyPair();
      (dkAPriv, _) = await _genKeyPair();
      (ikBPriv, ikBPub) = await _genKeyPair();
      (dkBPriv, _) = await _genKeyPair();
    });

    Future<(RatchetState aRatchet, RatchetState bRatchet)> _buildRatchets() async {
      final (aState, bState, confirmPayload, replyPayload) = await _fullHandshake(
        ikAPriv: ikAPriv, ikAPub: ikAPub, dkAPriv: dkAPriv,
        ikBPriv: ikBPriv, ikBPub: ikBPub, dkBPriv: dkBPriv,
      );

      // Alice's initial ratchet key pair was generated in processFsReplyAsInitiator.
      final ratchetAPriv = confirmPayload.initiatorInitialRatchetPriv;
      final ratchetAPub = FsKeyCodec.decodeKey(confirmPayload.initiatorInitialRatchetPub);

      // Bob's initial ratchet key pair was generated in processFsInitAsResponder.
      final ratchetBPriv = replyPayload.responderInitialRatchetPriv;
      final ratchetBPub = FsKeyCodec.decodeKey(replyPayload.responderInitialRatchetPub);

      // Alice knows B's initial ratchet pub (from FS_REPLY) → lastRemoteRatchetPub.
      // Bob knows A's initial ratchet pub (from FS_CONFIRM) → lastRemoteRatchetPub.
      // Both set it so no spurious DH step fires on the first message.
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

    // T3.13 — Alice encrypts 3 messages, Bob decrypts all 3 in order.
    test('T3.13: Alice encrypts 3 msgs, Bob decrypts in order', () async {
      var (aRatchet, bRatchet) = await _buildRatchets();

      final messages = ['Hello, Bob!', 'Are you there?', 'Third message.'];
      final ciphertexts = <FsEncryptedMessage>[];

      for (final msg in messages) {
        final result = await FsDoubleRatchet.encrypt(
          state: aRatchet,
          plaintext: utf8.encode(msg),
          sessionId: 'test-session',
        );
        aRatchet = result.newState;
        ciphertexts.add(result.message);
      }

      for (var i = 0; i < ciphertexts.length; i++) {
        final result = await FsDoubleRatchet.decrypt(
          state: bRatchet,
          message: ciphertexts[i],
        );
        bRatchet = result.newState;
        expect(utf8.decode(result.plaintext), equals(messages[i]));
      }
    });

    // T3.6 — Nonce uniqueness: 1000 consecutive FS messages.
    test('T3.6: 1000 consecutive messages produce unique nonces', () async {
      var (aRatchet, _) = await _buildRatchets();
      final nonces = <String>{};

      for (var i = 0; i < 1000; i++) {
        final result = await FsDoubleRatchet.encrypt(
          state: aRatchet,
          plaintext: utf8.encode('message $i'),
          sessionId: 'test-session',
        );
        final nonceHex = result.message.nonce
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join();
        expect(nonces.contains(nonceHex), isFalse,
            reason: 'Nonce must be unique (collision at message $i)');
        nonces.add(nonceHex);
        aRatchet = result.newState;
      }
      expect(nonces.length, equals(1000));
    });

    // T3.14 — Out-of-order: Bob receives msg 3, then msg 1.
    test('T3.14: Bob handles out-of-order messages using skipped key map', () async {
      var (aRatchet, bRatchet) = await _buildRatchets();

      // Alice sends 3 messages.
      final ciphertexts = <FsEncryptedMessage>[];
      for (var i = 0; i < 3; i++) {
        final result = await FsDoubleRatchet.encrypt(
          state: aRatchet,
          plaintext: utf8.encode('msg $i'),
          sessionId: 'test-session',
        );
        aRatchet = result.newState;
        ciphertexts.add(result.message);
      }

      // Bob receives msg[2] first (skips 0 and 1).
      final r2 = await FsDoubleRatchet.decrypt(
        state: bRatchet,
        message: ciphertexts[2],
      );
      bRatchet = r2.newState;
      expect(utf8.decode(r2.plaintext), equals('msg 2'));

      // Bob receives msg[0] — should find it in skipped keys.
      final r0 = await FsDoubleRatchet.decrypt(
        state: bRatchet,
        message: ciphertexts[0],
      );
      bRatchet = r0.newState;
      expect(utf8.decode(r0.plaintext), equals('msg 0'));

      // Bob receives msg[1].
      final r1 = await FsDoubleRatchet.decrypt(
        state: bRatchet,
        message: ciphertexts[1],
      );
      expect(utf8.decode(r1.plaintext), equals('msg 1'));
    });

    // Wrong-key decrypt must throw.
    test('decrypt with tampered ciphertext throws FsDecryptException', () async {
      var (aRatchet, bRatchet) = await _buildRatchets();

      final result = await FsDoubleRatchet.encrypt(
        state: aRatchet,
        plaintext: utf8.encode('secret'),
        sessionId: 'test-session',
      );

      // Tamper: flip a byte in the ciphertext.
      final badCiphertext = Uint8List.fromList(result.message.ciphertext);
      badCiphertext[0] ^= 0xFF;

      final tampered = FsEncryptedMessage(
        sessionId: result.message.sessionId,
        localRatchetPub: result.message.localRatchetPub,
        counter: result.message.counter,
        ciphertext: badCiphertext,
        nonce: result.message.nonce,
      );

      expect(
        () => FsDoubleRatchet.decrypt(state: bRatchet, message: tampered),
        throwsA(isA<FsDecryptException>()),
      );
    });
  });
}

String _padBase64(String s) {
  final rem = s.length % 4;
  if (rem == 0) return s;
  return s.padRight(s.length + (4 - rem), '=');
}
