/// Tests for multi-device / identity cloning scenario.
///
/// Scenario: disp1 and disp2 communicate with FS green.  A third device
/// disp1b restores the SAME identity (same seed phrase) and starts
/// communicating with disp2.  This simulates:
/// - device cloning
/// - identity restored on a second device without wiping the first
///
/// Expected behavior:
/// 1. disp1b has same legacy keys but NO ratchet state
/// 2. disp1b's messages to disp2 are legacy-encrypted (no FS)
/// 3. disp1b sends fs_init → disp2 detects partner reset → accepts new handshake
/// 4. disp2's FS-encrypted messages (with old ratchet) can't be decrypted by disp1b
/// 5. After disp1b↔disp2 complete new handshake → new FS session works
/// 6. disp1 tries to resume with old ratchet → disp2 has reset → old FS fails

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_key_codec.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
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

class _TestClock implements FsClock {
  int _now = 1700000000;

  @override
  int nowSeconds() => _now;

  void advance(int seconds) => _now += seconds;
}

void main() {
  final x25519 = X25519();

  Future<(Uint8List, Uint8List)> genDhPair() async {
    final pair = await x25519.newKeyPair();
    final priv = Uint8List.fromList(await pair.extractPrivateKeyBytes());
    final pub = Uint8List.fromList((await pair.extractPublicKey()).bytes);
    return (priv, pub);
  }

  /// Performs a full FS handshake and returns ratchet states for both parties.
  Future<({
    RatchetState initiatorRatchet,
    RatchetState responderRatchet,
    String sessionId,
  })> performHandshake({
    required Uint8List ikAPriv,
    required Uint8List ikAPub,
    required Uint8List ikBPriv,
    required Uint8List ikBPub,
  }) async {
    final (dkAPriv, _) = await genDhPair();
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

    final sessionId = 'session-${DateTime.now().microsecondsSinceEpoch}';

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

    return (
      initiatorRatchet: aRatchet,
      responderRatchet: bRatchet,
      sessionId: sessionId,
    );
  }

  group('Multi-device clone scenario', () {
    test('disp1b (same identity, no ratchet) sends legacy message that disp2 can decrypt', () async {
      // Setup: disp1 and disp2 have FS green
      final service = EncryptionService();
      final disp1Keys = await _keyMaterial(await x25519.newKeyPair());
      final disp2Keys = await _keyMaterial(await x25519.newKeyPair());

      // disp1b has the SAME identity keys as disp1 (restored from seed)
      // This means same privateKeyBase64 and publicKeyBase64
      final disp1bKeys = disp1Keys; // same identity

      // disp1b sends a message to disp2 WITHOUT FS (no ratchet state)
      final encResult = await service.encrypt(
        senderPrivateKeyBase64: disp1bKeys.privateKeyBase64,
        recipientPublicKeyBase64: disp2Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp1',
          recipientId: 'disp2',
          text: 'Ciao da disp1b!',
          timestamp: 1700000100,
        ),
        // ratchetState: null → legacy encryption
      );

      // Verify: no FS was used
      expect(encResult.newRatchetState, isNull);

      // disp2 can decrypt with legacy keys (same shared secret)
      final decResult = await service.decrypt(
        recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
        senderPublicKeyBase64: disp1bKeys.publicKeyBase64,
        message: encResult.message,
        // Even if disp2 has a ratchet, legacy messages don't have fs_v/fs_cipher
        // so the decrypt path returns the legacy plaintext directly
      );

      expect(decResult.fsDecryptFailed, isFalse);
      expect(decResult.payload.text, 'Ciao da disp1b!');
    });

    test('disp2 FS-encrypted messages cannot be decrypted by disp1b (no ratchet)', () async {
      final service = EncryptionService();
      final disp1Pair = await x25519.newKeyPair();
      final disp1Keys = await _keyMaterial(disp1Pair);
      final disp2Pair = await x25519.newKeyPair();
      final disp2Keys = await _keyMaterial(disp2Pair);

      // Build FS session between disp1 and disp2
      final disp1Priv = Uint8List.fromList(await disp1Pair.extractPrivateKeyBytes());
      final disp1Pub = Uint8List.fromList((await disp1Pair.extractPublicKey()).bytes);
      final disp2Priv = Uint8List.fromList(await disp2Pair.extractPrivateKeyBytes());
      final disp2Pub = Uint8List.fromList((await disp2Pair.extractPublicKey()).bytes);

      final handshake = await performHandshake(
        ikAPriv: disp1Priv,
        ikAPub: disp1Pub,
        ikBPriv: disp2Priv,
        ikBPub: disp2Pub,
      );

      // disp2 sends FS-encrypted message using its ratchet
      final encResult = await service.encrypt(
        senderPrivateKeyBase64: disp2Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp1Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp2',
          recipientId: 'disp1',
          text: 'Messaggio FS da disp2',
          timestamp: 1700000200,
        ),
        ratchetState: handshake.responderRatchet,
      );
      expect(encResult.newRatchetState, isNotNull);

      // disp1b has same identity keys but NO ratchet state
      // Trying to decrypt returns fsDecryptFailed (outer layer decrypts,
      // inner FS layer cannot be decrypted without ratchet)
      final decResult = await service.decrypt(
        recipientPrivateKeyBase64: disp1Keys.privateKeyBase64,
        senderPublicKeyBase64: disp2Keys.publicKeyBase64,
        message: encResult.message,
        ratchetState: null, // disp1b has no ratchet
      );

      expect(decResult.fsDecryptFailed, isTrue);
    });

    test('disp2 session manager accepts new fs_init from disp1b (partner reset detection)', () {
      final clock = _TestClock();
      final disp2SessionManager = FsSessionManager(clock: clock);

      // disp2 is in fsActive (green FS with disp1)
      disp2SessionManager.setStateForTesting(FsSessionState.fsActive,
          sessionId: 'old-session');

      // disp1b sends fs_init (it has no FS session, starts fresh handshake)
      final result = disp2SessionManager.processFsInitReceived(
        message: FsInitMessage(
          initId: 'new-init-from-disp1b',
          ikAPub: 'disp1-pub-key',
          ekAPub: 'ephemeral-pub-key',
          dkAPub: 'deniable-pub-key',
          createdAt: clock.nowSeconds(),
        ),
        localInitId: '',
      );

      // disp2 should accept (partner reset detected)
      expect(result.accepted, isTrue);
      expect(disp2SessionManager.state, FsSessionState.fsInitSeen);
      expect(disp2SessionManager.activeSessionId, isNull); // old session cleared
    });

    test('after disp1b↔disp2 complete new handshake, messages work', () async {
      final service = EncryptionService();
      final disp1Pair = await x25519.newKeyPair();
      final disp1Keys = await _keyMaterial(disp1Pair);
      final disp2Pair = await x25519.newKeyPair();
      final disp2Keys = await _keyMaterial(disp2Pair);

      final disp1Priv = Uint8List.fromList(await disp1Pair.extractPrivateKeyBytes());
      final disp1Pub = Uint8List.fromList((await disp1Pair.extractPublicKey()).bytes);
      final disp2Priv = Uint8List.fromList(await disp2Pair.extractPrivateKeyBytes());
      final disp2Pub = Uint8List.fromList((await disp2Pair.extractPublicKey()).bytes);

      // 1) Original FS session between disp1 and disp2
      final originalHandshake = await performHandshake(
        ikAPriv: disp1Priv,
        ikAPub: disp1Pub,
        ikBPriv: disp2Priv,
        ikBPub: disp2Pub,
      );

      // Exchange a message to confirm original session works
      final origEnc = await service.encrypt(
        senderPrivateKeyBase64: disp1Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp2Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp1',
          recipientId: 'disp2',
          text: 'Original FS message',
          timestamp: 1700000000,
        ),
        ratchetState: originalHandshake.initiatorRatchet,
      );
      final origDec = await service.decrypt(
        recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
        senderPublicKeyBase64: disp1Keys.publicKeyBase64,
        message: origEnc.message,
        ratchetState: originalHandshake.responderRatchet,
      );
      expect(origDec.payload.text, 'Original FS message');

      // 2) disp1b starts new handshake with disp2 (same identity keys!)
      // This creates a completely new FS session
      final newHandshake = await performHandshake(
        ikAPriv: disp1Priv, // same keys as disp1
        ikAPub: disp1Pub,
        ikBPriv: disp2Priv,
        ikBPub: disp2Pub,
      );

      // 3) disp1b sends FS message with new ratchet → disp2 decrypts with new ratchet
      final newEnc = await service.encrypt(
        senderPrivateKeyBase64: disp1Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp2Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp1',
          recipientId: 'disp2',
          text: 'New FS from disp1b!',
          timestamp: 1700000300,
        ),
        ratchetState: newHandshake.initiatorRatchet,
      );
      final newDec = await service.decrypt(
        recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
        senderPublicKeyBase64: disp1Keys.publicKeyBase64,
        message: newEnc.message,
        ratchetState: newHandshake.responderRatchet,
      );
      expect(newDec.fsDecryptFailed, isFalse);
      expect(newDec.payload.text, 'New FS from disp1b!');
    });

    test('disp1 resumes with old ratchet after disp2 reset → decrypt fails', () async {
      final service = EncryptionService();
      final disp1Pair = await x25519.newKeyPair();
      final disp1Keys = await _keyMaterial(disp1Pair);
      final disp2Pair = await x25519.newKeyPair();
      final disp2Keys = await _keyMaterial(disp2Pair);

      final disp1Priv = Uint8List.fromList(await disp1Pair.extractPrivateKeyBytes());
      final disp1Pub = Uint8List.fromList((await disp1Pair.extractPublicKey()).bytes);
      final disp2Priv = Uint8List.fromList(await disp2Pair.extractPrivateKeyBytes());
      final disp2Pub = Uint8List.fromList((await disp2Pair.extractPublicKey()).bytes);

      // 1) Original FS session between disp1 and disp2
      final originalHandshake = await performHandshake(
        ikAPriv: disp1Priv,
        ikAPub: disp1Pub,
        ikBPriv: disp2Priv,
        ikBPub: disp2Pub,
      );

      // 2) disp1b creates new FS session with disp2 (disp2 resets old session)
      final newHandshake = await performHandshake(
        ikAPriv: disp1Priv,
        ikAPub: disp1Pub,
        ikBPriv: disp2Priv,
        ikBPub: disp2Pub,
      );

      // 3) disp1 tries to send with OLD ratchet
      final oldEnc = await service.encrypt(
        senderPrivateKeyBase64: disp1Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp2Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp1',
          recipientId: 'disp2',
          text: 'Old ratchet message from disp1',
          timestamp: 1700000400,
        ),
        ratchetState: originalHandshake.initiatorRatchet,
      );

      // 4) disp2 tries to decrypt with NEW ratchet → must fail
      //    The session IDs and chain keys are different
      expect(
        () => service.decrypt(
          recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
          senderPublicKeyBase64: disp1Keys.publicKeyBase64,
          message: oldEnc.message,
          ratchetState: newHandshake.responderRatchet,
        ),
        throwsA(anything),
      );

      // 5) disp2 without any ratchet → fsDecryptFailed (graceful degradation)
      final decNoRatchet = await service.decrypt(
        recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
        senderPublicKeyBase64: disp1Keys.publicKeyBase64,
        message: oldEnc.message,
        ratchetState: null,
      );
      expect(decNoRatchet.fsDecryptFailed, isTrue);
    });

    test('full multi-device scenario: disp1 → disp1b → disp1 resume', () async {
      final service = EncryptionService();
      final clock = _TestClock();
      final disp1Pair = await x25519.newKeyPair();
      final disp1Keys = await _keyMaterial(disp1Pair);
      final disp2Pair = await x25519.newKeyPair();
      final disp2Keys = await _keyMaterial(disp2Pair);

      final disp1Priv = Uint8List.fromList(await disp1Pair.extractPrivateKeyBytes());
      final disp1Pub = Uint8List.fromList((await disp1Pair.extractPublicKey()).bytes);
      final disp2Priv = Uint8List.fromList(await disp2Pair.extractPrivateKeyBytes());
      final disp2Pub = Uint8List.fromList((await disp2Pair.extractPublicKey()).bytes);

      // ── Phase 1: disp1 ↔ disp2 communicate with FS green ──

      final originalHandshake = await performHandshake(
        ikAPriv: disp1Priv,
        ikAPub: disp1Pub,
        ikBPriv: disp2Priv,
        ikBPub: disp2Pub,
      );

      var disp1Ratchet = originalHandshake.initiatorRatchet;
      var disp2Ratchet = originalHandshake.responderRatchet;

      // disp1 → disp2: FS message
      final msg1Enc = await service.encrypt(
        senderPrivateKeyBase64: disp1Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp2Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp1',
          recipientId: 'disp2',
          text: 'Msg1 from disp1',
          timestamp: 1700000001,
        ),
        ratchetState: disp1Ratchet,
      );
      disp1Ratchet = msg1Enc.newRatchetState!;
      final msg1Dec = await service.decrypt(
        recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
        senderPublicKeyBase64: disp1Keys.publicKeyBase64,
        message: msg1Enc.message,
        ratchetState: disp2Ratchet,
      );
      disp2Ratchet = msg1Dec.newRatchetState!;
      expect(msg1Dec.payload.text, 'Msg1 from disp1');

      // disp2 → disp1: FS message
      final msg2Enc = await service.encrypt(
        senderPrivateKeyBase64: disp2Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp1Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp2',
          recipientId: 'disp1',
          text: 'Msg2 from disp2',
          timestamp: 1700000002,
        ),
        ratchetState: disp2Ratchet,
      );
      disp2Ratchet = msg2Enc.newRatchetState!;
      final msg2Dec = await service.decrypt(
        recipientPrivateKeyBase64: disp1Keys.privateKeyBase64,
        senderPublicKeyBase64: disp2Keys.publicKeyBase64,
        message: msg2Enc.message,
        ratchetState: disp1Ratchet,
      );
      disp1Ratchet = msg2Dec.newRatchetState!;
      expect(msg2Dec.payload.text, 'Msg2 from disp2');

      // Both in FS green ✓

      // ── Phase 2: disp1b joins with same identity (no ratchet) ──

      // disp2's session manager detects partner reset when receiving fs_init
      final disp2SessionMgr = FsSessionManager(clock: clock);
      disp2SessionMgr.setStateForTesting(FsSessionState.fsActive,
          sessionId: originalHandshake.sessionId);

      final resetResult = disp2SessionMgr.processFsInitReceived(
        message: FsInitMessage(
          initId: 'disp1b-init',
          ikAPub: base64Encode(disp1Pub),
          ekAPub: 'ek-disp1b',
          dkAPub: 'dk-disp1b',
          createdAt: clock.nowSeconds(),
        ),
        localInitId: '',
      );
      expect(resetResult.accepted, isTrue,
          reason: 'disp2 should accept fs_init from disp1b (partner reset)');
      expect(disp2SessionMgr.state, FsSessionState.fsInitSeen);
      expect(disp2SessionMgr.activeSessionId, isNull,
          reason: 'Old session ID should be cleared');

      // ── Phase 3: disp1b and disp2 complete new handshake ──

      final newHandshake = await performHandshake(
        ikAPriv: disp1Priv, // same identity!
        ikAPub: disp1Pub,
        ikBPriv: disp2Priv,
        ikBPub: disp2Pub,
      );

      var disp1bRatchet = newHandshake.initiatorRatchet;
      var disp2NewRatchet = newHandshake.responderRatchet;

      // disp1b → disp2: new FS message works
      final msg3Enc = await service.encrypt(
        senderPrivateKeyBase64: disp1Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp2Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp1',
          recipientId: 'disp2',
          text: 'Msg3 from disp1b',
          timestamp: 1700000003,
        ),
        ratchetState: disp1bRatchet,
      );
      disp1bRatchet = msg3Enc.newRatchetState!;
      final msg3Dec = await service.decrypt(
        recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
        senderPublicKeyBase64: disp1Keys.publicKeyBase64,
        message: msg3Enc.message,
        ratchetState: disp2NewRatchet,
      );
      disp2NewRatchet = msg3Dec.newRatchetState!;
      expect(msg3Dec.payload.text, 'Msg3 from disp1b');
      expect(msg3Dec.fsDecryptFailed, isFalse);

      // ── Phase 4: disp1 resumes with OLD ratchet ──

      // disp1 sends FS message with OLD ratchet
      final msg4Enc = await service.encrypt(
        senderPrivateKeyBase64: disp1Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp2Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp1',
          recipientId: 'disp2',
          text: 'Msg4 from disp1 (old ratchet)',
          timestamp: 1700000004,
        ),
        ratchetState: disp1Ratchet,
      );

      // disp2 with NEW ratchet cannot decrypt old session's message
      expect(
        () => service.decrypt(
          recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
          senderPublicKeyBase64: disp1Keys.publicKeyBase64,
          message: msg4Enc.message,
          ratchetState: disp2NewRatchet,
        ),
        throwsA(anything),
        reason: 'Old ratchet message should fail with new ratchet',
      );

      // If disp2 has no ratchet at all → fsDecryptFailed (graceful)
      final msg4DecNoRatchet = await service.decrypt(
        recipientPrivateKeyBase64: disp2Keys.privateKeyBase64,
        senderPublicKeyBase64: disp1Keys.publicKeyBase64,
        message: msg4Enc.message,
        ratchetState: null,
      );
      expect(msg4DecNoRatchet.fsDecryptFailed, isTrue,
          reason: 'FS message without ratchet should fail gracefully');

      // ── Phase 5: disp2 continues with disp1b normally ──

      final msg5Enc = await service.encrypt(
        senderPrivateKeyBase64: disp2Keys.privateKeyBase64,
        recipientPublicKeyBase64: disp1Keys.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'disp2',
          recipientId: 'disp1',
          text: 'Msg5 from disp2 to disp1b',
          timestamp: 1700000005,
        ),
        ratchetState: disp2NewRatchet,
      );
      disp2NewRatchet = msg5Enc.newRatchetState!;
      final msg5Dec = await service.decrypt(
        recipientPrivateKeyBase64: disp1Keys.privateKeyBase64,
        senderPublicKeyBase64: disp2Keys.publicKeyBase64,
        message: msg5Enc.message,
        ratchetState: disp1bRatchet,
      );
      disp1bRatchet = msg5Dec.newRatchetState!;
      expect(msg5Dec.payload.text, 'Msg5 from disp2 to disp1b');
      expect(msg5Dec.fsDecryptFailed, isFalse);
    });
  });
}
