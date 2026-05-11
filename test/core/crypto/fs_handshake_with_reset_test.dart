import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_opportunistic_controller.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

/// T_HANDSHAKE_RESET_1: Complete handshake after FS reset
///
/// This test simulates the exact sequence reported by the user:
/// 1. FS reset (simulating app restart or identity reset)
/// 2. Device A (initiator) sends message → generates FS_INIT
/// 3. Device B (responder) receives → generates FS_REPLY
/// 4. Device A receives FS_REPLY → sends FS_CONFIRM and activates
/// 5. Device B receives FS_CONFIRM → activates
/// 6. Device A sends message (should use FS) - CRITICAL CHECK
/// 7. Device B responds using FS
/// 8. Device A must decrypt successfully
///
/// The bug: After step 5, Device A shows fsActive but sessionId is null
/// causing FS encryption to fail at step 6.
void main() {
  group('FS Handshake After Reset Tests', () {
    test('T_HANDSHAKE_RESET_1: Full handshake flow with reset', () async {
      final algo = X25519();

      // Device A (initiator) keys
      final ikA = await algo.newKeyPair();
      final ikAPriv = Uint8List.fromList(await ikA.extractPrivateKeyBytes());
      final ikAPub = (await ikA.extractPublicKey()) as SimplePublicKey;
      final dkA = await algo.newKeyPair();
      final dkAPriv = Uint8List.fromList(await dkA.extractPrivateKeyBytes());

      // Device B (responder) keys
      final ikB = await algo.newKeyPair();
      final ikBPriv = Uint8List.fromList(await ikB.extractPrivateKeyBytes());
      final ikBPub = (await ikB.extractPublicKey()) as SimplePublicKey;
      final dkB = await algo.newKeyPair();
      final dkBPriv = Uint8List.fromList(await dkB.extractPrivateKeyBytes());

      // Create session managers (simulating reset - fresh instances)
      var sessionManagerA = FsSessionManager();
      var sessionManagerB = FsSessionManager();

      // Create registries
      var registryA = FsContactSecurityRegistry();
      var registryB = FsContactSecurityRegistry();

      // Track ratchet states
      RatchetState? ratchetStateA;
      RatchetState? ratchetStateB;

      // Create controllers
      var controllerA = FsOpportunisticController(
        localContactId: 'device_b',
        identityContext: 'test',
        sessionManager: sessionManagerA,
        registry: registryA,
        onRatchetInitialized: (state) => ratchetStateA = state,
      );

      var controllerB = FsOpportunisticController(
        localContactId: 'device_a',
        identityContext: 'test',
        sessionManager: sessionManagerB,
        registry: registryB,
        onRatchetInitialized: (state) => ratchetStateB = state,
      );

      // Step 1: Device A generates FS_INIT
      final initResult = await FsHandshake.generateFsInit(
        ikAPriv: ikAPriv,
        dkAPriv: dkAPriv,
      );

      expect(initResult, isNotNull);

      // Build outgoing extension — this internally calls recordFsInitSent
      final initExt = await controllerA.buildOutgoingExtension(pendingInit: initResult);
      expect(initExt?.json, isNotNull);
      expect(sessionManagerA.state, FsSessionState.fsInitSent);

      // Step 2: Device B receives FS_INIT, sends FS_REPLY
      final initMessage = initResult.toMessage();

      sessionManagerB.processFsInitReceived(
        message: initMessage,
        localInitId: '',
      );
      expect(sessionManagerB.state, FsSessionState.fsInitSeen);

      final replyPayload = await FsHandshake.processFsInitAsResponder(
        ikBPriv: ikBPriv,
        dkBPriv: dkBPriv,
        ikAPub: Uint8List.fromList(ikAPub.bytes),
        init: initMessage,
      );

      // Build outgoing extension — this internally calls recordFsReplySent
      final replyExt = await controllerB.buildOutgoingExtension(pendingReply: replyPayload);
      expect(replyExt?.json, isNotNull);
      expect(sessionManagerB.state, FsSessionState.fsReplySent);

      // Step 3: Device A receives FS_REPLY, sends FS_CONFIRM
      final replyMessage = replyPayload.toMessage();
      sessionManagerA.processFsReplyReceived(replyMessage);
      expect(sessionManagerA.state, FsSessionState.fsReplySeen);

      final confirmPayload = await FsHandshake.processFsReplyAsInitiator(
        ikAPriv: ikAPriv,
        dkAPriv: dkAPriv,
        ekAPrivBytes: initResult.ekAPrivBytes,
        ikBPub: Uint8List.fromList(ikBPub.bytes),
        sentInit: initMessage,
        reply: replyMessage,
      );

      final confirmExt = await controllerA.buildOutgoingExtension(pendingConfirm: confirmPayload);
      expect(confirmExt?.json, isNotNull);

      // CRITICAL CHECK: Device A should have activeSessionId set
      expect(sessionManagerA.activeSessionId, isNotNull,
          reason: 'CRITICAL: After sending CONFIRM, Device A should have activeSessionId set');
      expect(sessionManagerA.state, FsSessionState.fsActive,
          reason: 'Device A should be fsActive');
      expect(ratchetStateA, isNotNull,
          reason: 'Device A should have ratchet initialized');

      // Step 4: Device B receives FS_CONFIRM
      final confirmMessage = confirmPayload.toMessage();

      final confirmEnvelope = {
        'v': 2,
        'senderId': 'device_a',
        'x': {'fs': confirmMessage.toJson()},
      };
      await controllerB.processIncomingEnvelope(
        confirmEnvelope,
        remoteContactId: 'device_a',
      );

      expect(sessionManagerB.activeSessionId, isNotNull,
          reason: 'CRITICAL: After receiving CONFIRM, Device B should have activeSessionId set');
      expect(sessionManagerB.state, FsSessionState.fsActive,
          reason: 'Device B should be fsActive');

      // Step 5: Verify ratchet encryption works
      if (ratchetStateA != null && ratchetStateB != null) {
        final testMessage = 'Hello from Device A';
        final encrypted = await FsDoubleRatchet.encrypt(
          state: ratchetStateA!,
          plaintext: Uint8List.fromList(utf8.encode(testMessage)),
          sessionId: ratchetStateA!.sessionId,
        );

        final decrypted = await FsDoubleRatchet.decrypt(
          state: ratchetStateB!,
          message: encrypted.message,
        );

        expect(utf8.decode(decrypted.plaintext), equals(testMessage));
      }

      // Step 6: Simulate Device A sending with FS
      // CRITICAL: Check that Device A has all required state for FS
      final canUseFs = sessionManagerA.state == FsSessionState.fsActive &&
          sessionManagerA.activeSessionId != null &&
          ratchetStateA != null;

      expect(canUseFs, isTrue,
          reason: 'Device A should be able to use FS for sending. '
              'state=${sessionManagerA.state}, '
              'activeSessionId=${sessionManagerA.activeSessionId}, '
              'ratchetStateA=${ratchetStateA != null}');
    });
  });
}
