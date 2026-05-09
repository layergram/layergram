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
      final ikAPriv = await ikA.extractPrivateKeyBytes();
      final ikAPub = await ikA.extractPublicKey();
      
      // Device B (responder) keys  
      final ikB = await algo.newKeyPair();
      final ikBPriv = await ikB.extractPrivateKeyBytes();
      final ikBPub = await ikB.extractPublicKey();

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
        contactId: 'device_b',
        identityContext: 'test',
        sessionManager: sessionManagerA,
        registry: registryA,
        onRatchetInitialized: (state) => ratchetStateA = state,
        localCaps: FsCapability.values,
      ); 

      var controllerB = FsOpportunisticController(
        contactId: 'device_a',
        identityContext: 'test',
        sessionManager: sessionManagerB,
        registry: registryB,
        onRatchetInitialized: (state) => ratchetStateB = state,
        localCaps: FsCapability.values,
      );

      print('[TEST] === Step 1: Device A generates FS_INIT ===');
      final initResult = await FsHandshake.generateFsInit(
        ikPriv: ikAPriv,
        ikPub: ikAPub,
        dkPriv: ikAPriv,
      );
      
      expect(initResult, isNotNull);
      sessionManagerA.recordFsInitSent(initResult);
      expect(sessionManagerA.state, FsSessionState.fsInitSent);
      
      // Build outgoing extension
      final initExt = await controllerA.buildOutgoingExtension(pendingInit: initResult);
      expect(initExt.json, isNotNull);
      print('[TEST] Device A sent FS_INIT, state: ${sessionManagerA.state}');

      print('[TEST] === Step 2: Device B receives FS_INIT, sends FS_REPLY ===');
      final initMessage = FsInitMessage(
        initId: initResult.initId,
        initiatorDevicePub: initResult.initiatorDevicePub,
        initiatorEphemeralPub: initResult.initiatorEphemeralPub,
        caps: initResult.caps,
        createdAt: initResult.createdAt,
      );
      
      sessionManagerB.processFsInitReceived(initMessage);
      expect(sessionManagerB.state, FsSessionState.fsInitSeen);
      
      final replyResult = await FsHandshake.generateFsReply(
        ikPriv: ikBPriv,
        ikPub: ikBPub,
        dkPriv: ikBPriv,
        receivedInit: initMessage,
      );
      
      final replyMessage = FsReplyMessage(
        initId: replyResult.initId,
        replyId: replyResult.replyId,
        responderDevicePub: replyResult.responderDevicePub,
        responderEphemeralPub: replyResult.responderEphemeralPub,
        responderInitialRatchetPub: replyResult.responderInitialRatchetPub,
        caps: replyResult.caps,
        createdAt: replyResult.createdAt,
      );
      
      sessionManagerB.recordFsReplySent(replyMessage);
      expect(sessionManagerB.state, FsSessionState.fsReplySent);
      
      final replyExt = await controllerB.buildOutgoingExtension(pendingReply: replyResult);
      expect(replyExt.json, isNotNull);
      print('[TEST] Device B sent FS_REPLY, state: ${sessionManagerB.state}');

      print('[TEST] === Step 3: Device A receives FS_REPLY, sends FS_CONFIRM ===');
      sessionManagerA.processFsReplyReceived(replyMessage);
      expect(sessionManagerA.state, FsSessionState.fsReplySeen);
      
      final confirmResult = await FsHandshake.processFsReplyAsInitiator(
        ikAPriv: ikAPriv,
        dkAPriv: ikAPriv,
        ekAPrivBytes: initResult.ekAPrivBytes,
        ikBPub: Uint8List.fromList(ikBPub.bytes),
        sentInit: initMessage,
        reply: replyMessage,
      );
      
      final confirmExt = await controllerA.buildOutgoingExtension(pendingConfirm: confirmResult);
      expect(confirmExt.json, isNotNull);
      
      print('[TEST] Device A sent FS_CONFIRM:');
      print('[TEST]   - state: ${sessionManagerA.state}');
      print('[TEST]   - activeSessionId: ${sessionManagerA.activeSessionId}');
      print('[TEST]   - ratchetStateA: ${ratchetStateA != null}');
      
      // CRITICAL CHECK: Device A should have activeSessionId set
      expect(sessionManagerA.activeSessionId, isNotNull,
        reason: 'CRITICAL: After sending CONFIRM, Device A should have activeSessionId set');
      expect(sessionManagerA.state, FsSessionState.fsActive,
        reason: 'Device A should be fsActive');
      expect(ratchetStateA, isNotNull,
        reason: 'Device A should have ratchet initialized');

      print('[TEST] === Step 4: Device B receives FS_CONFIRM ===');
      final confirmMessage = FsConfirmMessage(
        initId: confirmResult.initId,
        replyId: confirmResult.replyId,
        initiatorDevicePub: confirmResult.initiatorDevicePub,
        initiatorEphemeralPub: confirmResult.initiatorEphemeralPub,
        initiatorInitialRatchetPub: confirmResult.initiatorInitialRatchetPub,
        caps: confirmResult.caps,
        createdAt: confirmResult.createdAt,
        signature: confirmResult.signature,
      );
      
      await controllerB.processIncomingEnvelope(
        jsonEncode({'fs': confirmMessage.toJson()}),
        remoteId: 'device_a',
        identityContext: 'test',
        ikPriv: ikBPriv,
        ikPub: ikBPub,
        verifyConfirm: () async => true,
      );
      
      print('[TEST] Device B received FS_CONFIRM:');
      print('[TEST]   - state: ${sessionManagerB.state}');
      print('[TEST]   - activeSessionId: ${sessionManagerB.activeSessionId}');
      print('[TEST]   - ratchetStateB: ${ratchetStateB != null}');
      
      expect(sessionManagerB.activeSessionId, isNotNull,
        reason: 'CRITICAL: After receiving CONFIRM, Device B should have activeSessionId set');
      expect(sessionManagerB.state, FsSessionState.fsActive,
        reason: 'Device B should be fsActive');
      expect(ratchetStateB, isNotNull,
        reason: 'Device B should have ratchet initialized');

      print('[TEST] === Step 5: Verify ratchet encryption works ===');
      final testMessage = 'Hello from Device A';
      final encrypted = await FsDoubleRatchet.encrypt(
        ratchetState: ratchetStateA!,
        plaintext: utf8.encode(testMessage),
      );
      
      final decrypted = await FsDoubleRatchet.decrypt(
        state: ratchetStateB!,
        ciphertext: encrypted.ciphertext,
      );
      
      expect(utf8.decode(decrypted.plaintext), equals(testMessage));
      print('[TEST] Ratchet encryption/decryption works!');

      print('[TEST] === Step 6: Simulate Device A sending with FS ===');
      // CRITICAL: Check that Device A has all required state for FS
      print('[TEST] Device A before sending:');
      print('[TEST]   - state: ${sessionManagerA.state}');
      print('[TEST]   - activeSessionId: ${sessionManagerA.activeSessionId}');
      print('[TEST]   - ratchetInCache: ${ratchetStateA != null}');
      
      // This is what home_controller checks
      final canUseFs = sessionManagerA.state == FsSessionState.fsActive &&
                       sessionManagerA.activeSessionId != null &&
                       ratchetStateA != null;
      
      expect(canUseFs, isTrue,
        reason: 'Device A should be able to use FS for sending. '
                'state=${sessionManagerA.state}, '
                'activeSessionId=${sessionManagerA.activeSessionId}, '
                'ratchetStateA=${ratchetStateA != null}');

      print('[TEST] === SUCCESS: All checks passed ===');
    });
  });
}
