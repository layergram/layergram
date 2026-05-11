import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_opportunistic_controller.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/models.dart';

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
    late SimpleSecureStorage mockStorage;

    setUp(() {
      mockStorage = SimpleSecureStorage();
    });

    test('T_HANDSHAKE_FLOW_1: Complete handshake initiator->responder flow', () async {
      // Setup keys for both devices
      final algo = X25519();
      
      // Device A (initiator) keys
      final ikA = await algo.newKeyPair();
      final ikAPriv = await ikA.extractPrivateKeyBytes();
      final ikAPub = await ikA.extractPublicKey();
      final dkA = await algo.newKeyPair();
      
      // Device B (responder) keys  
      final ikB = await algo.newKeyPair();
      final ikBPriv = await ikB.extractPrivateKeyBytes();
      final ikBPub = await ikB.extractPublicKey();
      final dkB = await algo.newKeyPair();

      // Create session managers
      final sessionManagerA = FsSessionManager();
      final sessionManagerB = FsSessionManager();

      // Create registries
      final registryA = FsContactSecurityRegistry();
      final registryB = FsContactSecurityRegistry();

      // Track ratchet states
      RatchetState? ratchetStateA;
      RatchetState? ratchetStateB;

      // Create controllers with callbacks
      final controllerA = FsOpportunisticController(
        contactId: 'device_b',
        identityContext: 'test',
        sessionManager: sessionManagerA,
        registry: registryA,
        onRatchetInitialized: (state) => ratchetStateA = state,
        localCaps: FsCapability.values,
      ); 

      final controllerB = FsOpportunisticController(
        contactId: 'device_a',
        identityContext: 'test',
        sessionManager: sessionManagerB,
        registry: registryB,
        onRatchetInitialized: (state) => ratchetStateB = state,
        localCaps: FsCapability.values,
      );

      // Step 1: Device A generates FS_INIT
      print('[TEST] Step 1: Device A generates FS_INIT');
      final initResult = await FsHandshake.generateFsInit(
        ikPriv: ikAPriv,
        ikPub: ikAPub,
        dkPriv: ikAPriv, // Using same key for simplicity
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
      print('[TEST] Step 2: Device B receives FS_INIT, generates FS_REPLY');
      
      // Create FsInitMessage from the payload
      final initMessage = FsInitMessage(
        initId: initResult.initId,
        initiatorDevicePub: initResult.initiatorDevicePub,
        initiatorEphemeralPub: initResult.initiatorEphemeralPub,
        caps: initResult.caps,
        createdAt: initResult.createdAt,
      );
      
      // Process the init
      final processInitResult = sessionManagerB.processFsInitReceived(
        message: initMessage,
        localInitId: '',
      );
      expect(processInitResult.accepted, isTrue);
      expect(sessionManagerB.state, FsSessionState.fsInitSeen);
      
      // Generate reply
      final replyResult = await FsHandshake.generateFsReply(
        ikPriv: ikBPriv,
        ikPub: ikBPub,
        dkPriv: ikBPriv,
        receivedInit: initMessage,
      );
      expect(replyResult, isNotNull);
      
      // Record reply sent
      final replyMessage = FsReplyMessage(
        initId: replyResult.initId,
        replyId: replyResult.replyId,
        responderDevicePub: replyResult.responderDevicePub,
        responderEphemeralPub: replyResult.responderEphemeralPub,
        responderInitialRatchetPub: replyResult.responderInitialRatchetPub,
        caps: replyResult.caps,
        createdAt: replyResult.createdAt,
      );
      
      final replyRecordResult = sessionManagerB.recordFsReplySent(replyMessage);
      expect(replyRecordResult.accepted, isTrue);
      expect(sessionManagerB.state, FsSessionState.fsReplySent);
      
      // Build outgoing extension with reply
      final replyExt = await controllerB.buildOutgoingExtension(pendingReply: replyResult);
      expect(replyExt, isNotNull);

      // Step 3: Device A receives FS_REPLY, sends FS_CONFIRM
      print('[TEST] Step 3: Device A receives FS_REPLY, sends FS_CONFIRM');
      
      // Process reply
      final processReplyResult = sessionManagerA.processFsReplyReceived(replyMessage);
      expect(processReplyResult.accepted, isTrue);
      expect(sessionManagerA.state, FsSessionState.fsReplySeen);
      
      // Generate confirm using original init and received reply
      final confirmResult = await FsHandshake.processFsReplyAsInitiator(
        ikAPriv: ikAPriv,
        dkAPriv: ikAPriv,
        ekAPrivBytes: initResult.ekAPrivBytes,
        ikBPub: Uint8List.fromList(ikBPub.bytes),
        sentInit: FsInitMessage(
          initId: initResult.initId,
          initiatorDevicePub: initResult.initiatorDevicePub,
          initiatorEphemeralPub: initResult.initiatorEphemeralPub,
          caps: initResult.caps,
          createdAt: initResult.createdAt,
        ),
        reply: replyMessage,
      );
      expect(confirmResult, isNotNull);
      
      // Build outgoing extension with confirm
      // This is where the bug was: ratchet should initialize properly
      final confirmExt = await controllerA.buildOutgoingExtension(pendingConfirm: confirmResult);
      expect(confirmExt, isNotNull);
      
      // CRITICAL: Session should be ACTIVE, not BROKEN
      print('[TEST] Device A state after sending CONFIRM: ${sessionManagerA.state}');
      expect(sessionManagerA.state, FsSessionState.fsActive, 
        reason: 'Initiator should have fsActive state after successful handshake, not fsBroken');
      expect(ratchetStateA, isNotNull, 
        reason: 'Initiator should have ratchet state initialized');

      // Step 4: Device B receives FS_CONFIRM
      print('[TEST] Step 4: Device B receives FS_CONFIRM');
      
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
      
      // Process confirm - this should initialize ratchet and activate session
      final verifyResult = await FsHandshake.verifyFsConfirmAsResponder(
        ikBPriv: ikBPriv,
        dkBPriv: ikBPriv,
        ekBPriv: replyResult.ekBPrivBytes,
        ikAPub: ikAPub.bytes,
        sentReply: FsReplyPayload(
          initId: replyResult.initId,
          replyId: replyResult.replyId,
          responderDevicePub: replyResult.responderDevicePub,
          responderEphemeralPub: replyResult.responderEphemeralPub,
          responderInitialRatchetPub: replyResult.responderInitialRatchetPub,
          caps: replyResult.caps,
          createdAt: replyResult.createdAt,
        ),
        confirm: confirmMessage,
      );
      expect(verifyResult, isTrue);
      
      // Process in controller
      await controllerB.processIncomingEnvelope(
        jsonEncode({'fs': confirmMessage.toJson()}),
        remoteId: 'device_a',
        identityContext: 'test',
        ikPriv: ikBPriv,
        ikPub: ikBPub,
        verifyConfirm: () async => true,
      );
      
      print('[TEST] Device B state after receiving CONFIRM: ${sessionManagerB.state}');
      expect(sessionManagerB.state, FsSessionState.fsActive,
        reason: 'Responder should have fsActive state after successful handshake');
      expect(ratchetStateB, isNotNull,
        reason: 'Responder should have ratchet state initialized');

      // Step 5: Verify both ratchets can encrypt/decrypt
      print('[TEST] Step 5: Verify ratchet encryption/decryption');
      
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
      
      print('[TEST] Handshake flow completed successfully!');
    });
  });
}

/// Simple mock storage for testing
class SimpleSecureStorage {
  final Map<String, String> _storage = {};
  
  Future<void> write({required String key, required String? value}) async {
    if (value == null) {
      _storage.remove(key);
    } else {
      _storage[key] = value;
    }
  }
  
  Future<String?> read({required String key}) async {
    return _storage[key];
  }
  
  Future<void> delete({required String key}) async {
    _storage.remove(key);
  }
}
