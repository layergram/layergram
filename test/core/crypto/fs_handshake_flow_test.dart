import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_opportunistic_controller.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

/// T_HANDSHAKE_FLOW_1: Complete handshake flow from legacy to active
///
/// This test verifies the complete FS handshake flow:
/// 1. Device A (initiator) sends FS_INIT -> state: fsInitSent
/// 2. Device B (responder) receives FS_INIT, sends FS_REPLY -> state: fsReplySent
/// 3. Device A receives FS_REPLY, sends FS_CONFIRM and activates -> state: fsActive
/// 4. Device B receives FS_CONFIRM and activates -> state: fsActive
///
/// Expected: Both devices end up with fsActive state, NOT fsBroken
void main() {
  group('FS Handshake Flow Tests', () {
    test('T_HANDSHAKE_FLOW_1: Complete handshake initiator->responder flow', () async {
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

      // Create session managers
      final sessionManagerA = FsSessionManager();
      final sessionManagerB = FsSessionManager();

      // Create registries
      final registryA = FsContactSecurityRegistry();
      final registryB = FsContactSecurityRegistry();

      // Track ratchet states
      RatchetState? ratchetStateA;
      RatchetState? ratchetStateB;

      // Create controllers
      final controllerA = FsOpportunisticController(
        localContactId: 'device_b',
        identityContext: 'test',
        sessionManager: sessionManagerA,
        registry: registryA,
        onRatchetInitialized: (state) => ratchetStateA = state,
      );

      final controllerB = FsOpportunisticController(
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

      // Record init in session manager
      final initRecordResult = sessionManagerA.recordFsInitSent(initResult);
      expect(initRecordResult.accepted, isTrue);
      expect(sessionManagerA.state, FsSessionState.fsInitSent);

      // Build outgoing extension
      final initExt = await controllerA.buildOutgoingExtension(pendingInit: initResult);
      expect(initExt, isNotNull);

      // Step 2: Device B receives FS_INIT, generates FS_REPLY
      final initMessage = initResult.toMessage();

      // Process the init
      final processInitResult = sessionManagerB.processFsInitReceived(
        message: initMessage,
        localInitId: '',
      );
      expect(processInitResult.accepted, isTrue);
      expect(sessionManagerB.state, FsSessionState.fsInitSeen);

      // Generate reply
      final replyPayload = await FsHandshake.processFsInitAsResponder(
        ikBPriv: ikBPriv,
        dkBPriv: dkBPriv,
        ikAPub: Uint8List.fromList(ikAPub.bytes),
        init: initMessage,
      );
      expect(replyPayload, isNotNull);

      // Record reply sent
      final replyRecordResult = sessionManagerB.recordFsReplySent(replyPayload);
      expect(replyRecordResult.accepted, isTrue);
      expect(sessionManagerB.state, FsSessionState.fsReplySent);

      // Build outgoing extension with reply
      final replyExt = await controllerB.buildOutgoingExtension(pendingReply: replyPayload);
      expect(replyExt, isNotNull);

      // Step 3: Device A receives FS_REPLY, sends FS_CONFIRM
      final replyMessage = replyPayload.toMessage();

      // Process reply
      final processReplyResult = sessionManagerA.processFsReplyReceived(replyMessage);
      expect(processReplyResult.accepted, isTrue);
      expect(sessionManagerA.state, FsSessionState.fsReplySeen);

      // Generate confirm
      final confirmPayload = await FsHandshake.processFsReplyAsInitiator(
        ikAPriv: ikAPriv,
        dkAPriv: dkAPriv,
        ekAPrivBytes: initResult.ekAPrivBytes,
        ikBPub: Uint8List.fromList(ikBPub.bytes),
        sentInit: initMessage,
        reply: replyMessage,
      );
      expect(confirmPayload, isNotNull);

      // Build outgoing extension with confirm
      final confirmExt = await controllerA.buildOutgoingExtension(pendingConfirm: confirmPayload);
      expect(confirmExt, isNotNull);

      // CRITICAL: Session should be ACTIVE, not BROKEN
      expect(sessionManagerA.state, FsSessionState.fsActive,
          reason: 'Initiator should have fsActive state after successful handshake, not fsBroken');
      expect(ratchetStateA, isNotNull,
          reason: 'Initiator should have ratchet state initialized');

      // Step 4: Device B receives FS_CONFIRM
      final confirmMessage = confirmPayload.toMessage();

      // Verify the confirm
      final verifyResult = await FsHandshake.verifyFsConfirmAsResponder(
        confirm: confirmMessage,
        bState: replyPayload.partialState,
        ikAPub: Uint8List.fromList(ikAPub.bytes),
      );
      expect(verifyResult, isTrue);

      // Process confirm through controller
      final confirmEnvelope = {
        'v': 2,
        'senderId': 'device_a',
        'x': {'fs': confirmMessage.toJson()},
      };
      await controllerB.processIncomingEnvelope(
        confirmEnvelope,
        remoteContactId: 'device_a',
      );

      expect(sessionManagerB.state, FsSessionState.fsActive,
          reason: 'Responder should have fsActive state after successful handshake');

      // Step 5: Verify both ratchets can encrypt/decrypt
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
    });
  });
}
