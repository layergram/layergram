// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.
//
// End-to-end integration of the keyboard custody path over the REAL V3 stack.
//
// Unlike the unit tests around it, this file never stubs the protocol: it runs
// one real Maximum-mode handshake, produces canonical session records and a
// prior application message, then feeds those records through the actual
// [SystemKeyboardWorkingSet] selector, [SystemKeyboardRecordSnapshot] codec,
// [SystemKeyboardRecordStore] and `V3ApplicationSessionRuntime
// .openEstablishedSessions` restricted factory, and drives a real
// [SystemKeyboardV3Backend] against the peer runtime. Only ML-KEM and SCKA are
// deterministic fakes (crypto boundary), exactly as in
// test/core/crypto/v3/established_session_runtime_v3_test.dart, whose bounded
// harness this file copies rather than edits.
//
// The restricted path has no identity or device key. The delegated path below
// exercises a one-grant key capability and an exclusive device-key record.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/application_chat_bridge_v3.dart';
import 'package:layergram/core/crypto/v3/application_session_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/handshake_frame_inbox_v3.dart';
import 'package:layergram/core/crypto/v3/handshake_transport_v3.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/crypto/v3/session_persistence_scope_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_controller.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_custody.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_history.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_record_store.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_runtime_config.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_v3_backend.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_working_set.dart';

const _aliceMnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const _bobMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
const _aliceScope = 'alice-v3-scope01';
const _bobScope = 'bob-v3-scope0000';
const _aliceKeyboardScope = 'alice-kb-scope01';
const _aliceReloadScope = 'alice-kb-reload1';
const _bobKeyboardScope = 'bob-kb-scope0001';
const _importScope = 'kbd-import-scope';
const _pendingBaseline = 'v3_handshake_pending_v1';
const _handoffBaseline = 'v3_handshake_handoff_v1';

final SecretKey _auxKey = SecretKey(List<int>.filled(32, 71));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'real Maximum records select into a restricted keyboard runtime without loss',
    () async {
      final harness = await _PeerHarness.establish();
      try {
        // One canonical prior application message, fully acknowledged.
        final prior =
            await harness.aliceRuntime.sendApplicationMessageToIdentity(
          remoteIdentity: harness.bobPublic,
          expectedMode: V3HandshakeMode.maximum,
          text: 'prior canonical message',
          maximumRemoteDeviceId: _armor(harness.bobDeviceId),
        );
        expect(prior.frames, isNotEmpty);
        final priorInbound = await harness.bobRuntime.receiveApplicationFrame(
          frame: prior.frames.first,
          expectedMode: V3HandshakeMode.maximum,
          maximumRemoteDeviceId: _armor(harness.aliceDeviceId),
        );
        expect(priorInbound.status, V3ApplicationInboundStatus.delivered);
        expect(priorInbound.payload?.text, 'prior canonical message');
        await harness.aliceRuntime.applySendAcknowledgement(
          acknowledgementFrame: priorInbound.acknowledgementFrame!,
        );
        expect(await harness.aliceRuntime.pendingMessageExports(), isEmpty);

        // The app runtime drains (as delegation requires) before custody.
        await harness.aliceRuntime.close();
        await harness.bobRuntime.close();

        // Records a real private identity store also holds beside session state.
        final presentationId = harness.aliceStore.seed(
          'v3_application_presentation_v1',
          'v3:assembly-presentation',
          {'preview': 'private chat presentation'},
        );
        final deviceKeyId = harness.aliceStore.seed(
          'v3_device_key_v1',
          null,
          {'deviceId': 'transferred-under-exclusive-custody'},
        );
        final historyId = harness.aliceStore.seed(
          'v3_application_record_v1',
          'v3:assembly-history',
          {'body': 'private unreferenced history body'},
        );

        final all = await harness.aliceStore.readAll();
        final kinds = <String>{
          for (final record in all)
            (record.payload['kind'] as Object? ?? '?').toString(),
        };
        expect(kinds, contains('v3_session_checkpoint_v1'), reason: '$kinds');
        expect(kinds, contains('v3_handshake_completion_v1'), reason: '$kinds');
        expect(kinds, contains('v3_application_record_v1'), reason: '$kinds');
        expect(
          kinds.intersection({_pendingBaseline, _handoffBaseline}),
          isEmpty,
          reason: 'completed handshake left baseline state: $kinds',
        );

        // The actual selector keeps protocol state and hides private archives.
        final selected = SystemKeyboardWorkingSet.select(all);
        final selectedIds = selected.map((r) => r.storageId).toSet();
        expect(selectedIds, isNot(contains(presentationId)));
        expect(selectedIds, contains(deviceKeyId));
        expect(selectedIds, isNot(contains(historyId)));
        final droppedIds =
            all.map((r) => r.storageId).toSet().difference(selectedIds);
        final selectedKinds = selected.map((r) => r.payload['kind']).toSet();
        expect(
          selectedKinds,
          containsAll(<String>[
            'v3_session_checkpoint_v1',
            'v3_handshake_completion_v1',
            'v3_application_record_v1',
            'v3_send_effect_v1',
          ]),
          reason: 'canonical records missing from custody: $selectedKinds',
        );
        expect(
          droppedIds,
          <String>{presentationId, historyId},
          reason: 'unexpected protocol records were dropped from custody',
        );

        // Canonical byte codec used by native custody is lossless for them.
        final bytes = SystemKeyboardRecordSnapshot.encode(selected);
        final decoded = SystemKeyboardRecordSnapshot.decode(bytes);
        expect(
          decoded.map((r) => r.storageId).toSet(),
          selectedIds,
        );
        for (final record in selected) {
          final restored =
              decoded.singleWhere((r) => r.storageId == record.storageId);
          expect(restored.payload, record.payload, reason: record.storageId);
        }

        // Restore the restricted runtime from the selected snapshot only.
        final cas = _SnapshotCas(initial: bytes);
        final store = SystemKeyboardRecordStore(
          snapshot: bytes,
          revision: cas.revision,
          commit: cas.commit,
        );
        final runtime = await _openKeyboardRuntime(harness, store);
        try {
          expect(runtime.isEstablishedSessionOnly, isTrue);
          expect(() => runtime.localIdentity, throwsStateError);
          expect(
            runtime.localPublicIdentity.identityId,
            harness.alicePublic.identityId,
          );
          expect(runtime.localDeviceId, orderedEquals(harness.aliceDeviceId));
          final sessions =
              await runtime.sessionsForRemoteIdentity(harness.bobPublic);
          expect(sessions, hasLength(1));
          expect(sessions.single.mode, V3HandshakeMode.maximum);
          expect(
            sessions.single.remoteDeviceId,
            _armor(harness.bobDeviceId),
          );
          expect(
            runtime
                .protocolV3EligibilityForIdentity(harness.bobPublic)
                ?.revision,
            7,
          );

          // The prior application state reached the restored store.
          final restoredRecords = await store.readAll();
          final restoredKinds =
              restoredRecords.map((r) => r.payload['kind']).toSet();
          expect(restoredKinds, contains('v3_session_checkpoint_v1'));
          expect(restoredKinds, contains('v3_handshake_completion_v1'));
          expect(
            restoredRecords.map((r) => r.storageId).toSet(),
            selectedIds,
            reason: 'restore changed the selected protocol record set',
          );
          final priorRecord = selected.singleWhere(
              (r) => r.payload['kind'] == 'v3_application_record_v1');
          expect(
            restoredRecords
                .singleWhere((r) => r.storageId == priorRecord.storageId)
                .payload,
            priorRecord.payload,
            reason: 'the prior canonical message record must survive custody',
          );
        } finally {
          await runtime.close();
        }
      } finally {
        await harness.dispose();
      }
    },
  );

  for (final restartMode in ['live', 'snapshot', 'custody', 'reset']) {
    test(
        'autonomous Normal keyboard delivers text from the first message while FS advances'
        '${restartMode == 'live' ? '' : ' across $restartMode reopen'}',
        () async {
      final factory = V3LocalIdentityFactory(
        seedService: SeedService(),
        mlKem768Backend: _FakeMlKemBackend(),
      );
      final aliceOwner = await factory.restorePrimary(mnemonic: _aliceMnemonic);
      final bobOwner = await factory.restorePrimary(mnemonic: _bobMnemonic);
      final alicePublic = aliceOwner.publicIdentity;
      final bobPublic = bobOwner.publicIdentity;
      final aliceKeyMaterial = aliceOwner.exportKeyboardKeyMaterial();
      final bobKeyMaterial = bobOwner.exportKeyboardKeyMaterial();
      final aliceDeviceSeed = Uint8List.fromList(List.filled(32, 41));
      final bobDeviceSeed = Uint8List.fromList(List.filled(32, 42));
      var aliceDevice = await V3LocalDeviceHandle.fromSeed(aliceDeviceSeed);
      var bobDevice = await V3LocalDeviceHandle.fromSeed(bobDeviceSeed);
      SystemKeyboardRuntimeConfig configFor({
        required V3PublicIdentity own,
        required V3PublicIdentity peer,
        required Uint8List keyMaterial,
        required Uint8List deviceId,
        required String scopeToken,
        Set<String> excludedHandshakeIds = const {},
      }) =>
          SystemKeyboardRuntimeConfig.parse({
            'v': 2,
            'publicIdentity': V3PublicIdentityCodec.encodeBinary(own),
            'identityKeyMaterial': keyMaterial,
            'scopeToken': scopeToken,
            'localDeviceId': deviceId,
            'epoch': Uint8List.fromList(List.filled(16, 1)),
            'editorNonce': 'test-editor',
            'idleMillis': 60000,
            'scramble': false,
            'contacts': [
              {
                'identity': V3PublicIdentityCodec.encodeBinary(peer),
                'displayName': 'Peer',
                'mode': 'normal',
                'revision': 0,
                'excludedHandshakeIds': excludedHandshakeIds.toList(),
                'maximumRemoteDeviceId': null,
              }
            ],
          });
      var aliceConfig = configFor(
          own: alicePublic,
          peer: bobPublic,
          keyMaterial: aliceKeyMaterial,
          deviceId: aliceDevice.deviceId,
          scopeToken: _aliceKeyboardScope);
      var bobConfig = configFor(
          own: bobPublic,
          peer: alicePublic,
          keyMaterial: bobKeyMaterial,
          deviceId: bobDevice.deviceId,
          scopeToken: _bobKeyboardScope);
      final alice = await factory.restoreKeyboardSession(
        keyMaterial: aliceKeyMaterial,
        expectedPublicIdentity: alicePublic,
      );
      final bob = await factory.restoreKeyboardSession(
        keyMaterial: bobKeyMaterial,
        expectedPublicIdentity: bobPublic,
      );
      final aliceStore = _KeyboardStore();
      final bobStore = _KeyboardStore();
      V3LmfRecordStore currentAliceStore = aliceStore;
      V3LmfRecordStore currentBobStore = bobStore;
      final aliceNative = _FakeNativeCustody();
      final bobNative = _FakeNativeCustody();
      final aliceCustody =
          SystemKeyboardCustody(privateStore: aliceStore, native: aliceNative);
      final bobCustody =
          SystemKeyboardCustody(privateStore: bobStore, native: bobNative);
      V3ApplicationSessionRuntime? aliceRuntime;
      V3ApplicationSessionRuntime? bobRuntime;
      try {
        aliceRuntime =
            await V3ApplicationSessionRuntime.openDelegatedKeyboardSessions(
          localIdentity: alice,
          localDevice: aliceDevice,
          scopeToken: aliceConfig.scopeToken,
          store: currentAliceStore,
          sckaBackend: _FakeSckaBackend(),
          approvedContactPolicies: aliceConfig.policies,
        );
        bobRuntime =
            await V3ApplicationSessionRuntime.openDelegatedKeyboardSessions(
          localIdentity: bob,
          localDevice: bobDevice,
          scopeToken: bobConfig.scopeToken,
          store: currentBobStore,
          sckaBackend: _FakeSckaBackend(),
          approvedContactPolicies: bobConfig.policies,
        );
        var diagnosticEvents = 0;
        void diagnostic(V3ChatHandshakeDiagnostic category) {
          diagnosticEvents++;
          throw StateError(
              'Observer failure must not affect authenticated text');
        }

        var aliceBackend = SystemKeyboardV3Backend(
          runtime: aliceRuntime,
          contacts: [V3IdentityAdapter.toRemoteIdentity(bobPublic)],
          recordStore: currentAliceStore,
          handshakeDiagnostic: diagnostic,
          isAuthorized: () => true,
        );
        var bobBackend = SystemKeyboardV3Backend(
          runtime: bobRuntime,
          contacts: [V3IdentityAdapter.toRemoteIdentity(alicePublic)],
          recordStore: currentBobStore,
          handshakeDiagnostic: diagnostic,
          isAuthorized: () => true,
        );
        Future<void> reopenCustody() async {
          if (restartMode == 'live') return;
          aliceBackend.close();
          bobBackend.close();
          await aliceRuntime!.close();
          await bobRuntime!.close();
          // The containing app selects and serializes the working set before
          // delegating again. Incomplete handshake fragments must survive it.
          if (restartMode == 'custody') {
            if (await aliceNative.hasPending()) await aliceCustody.recover();
            if (await bobNative.hasPending()) await bobCustody.recover();
            final leftGrant = await aliceCustody.delegate();
            final rightGrant = await bobCustody.delegate();
            leftGrant.close();
            rightGrant.close();
            currentAliceStore = SystemKeyboardRecordStore(
                snapshot: aliceNative.snapshotBytes!,
                revision: aliceNative.revision,
                commit: aliceNative.commit);
            currentBobStore = SystemKeyboardRecordStore(
                snapshot: bobNative.snapshotBytes!,
                revision: bobNative.revision,
                commit: bobNative.commit);
          } else {
            for (final store in [aliceStore, bobStore]) {
              final bytes = SystemKeyboardRecordSnapshot.encode(
                  SystemKeyboardWorkingSet.select(await store.readAll()));
              final restored = SystemKeyboardRecordSnapshot.decode(bytes);
              store.rows
                ..clear()
                ..addEntries(restored.map(
                    (record) => MapEntry(record.storageId, record.payload)));
              bytes.fillRange(0, bytes.length, 0);
            }
          }
          aliceDevice = await V3LocalDeviceHandle.fromSeed(aliceDeviceSeed);
          bobDevice = await V3LocalDeviceHandle.fromSeed(bobDeviceSeed);
          aliceRuntime =
              await V3ApplicationSessionRuntime.openDelegatedKeyboardSessions(
                  localIdentity: alice,
                  localDevice: aliceDevice,
                  scopeToken: aliceConfig.scopeToken,
                  store: currentAliceStore,
                  sckaBackend: _FakeSckaBackend(),
                  approvedContactPolicies: aliceConfig.policies);
          bobRuntime =
              await V3ApplicationSessionRuntime.openDelegatedKeyboardSessions(
                  localIdentity: bob,
                  localDevice: bobDevice,
                  scopeToken: bobConfig.scopeToken,
                  store: currentBobStore,
                  sckaBackend: _FakeSckaBackend(),
                  approvedContactPolicies: bobConfig.policies);
          aliceBackend = SystemKeyboardV3Backend(
              runtime: aliceRuntime!,
              contacts: [V3IdentityAdapter.toRemoteIdentity(bobPublic)],
              recordStore: currentAliceStore,
              handshakeDiagnostic: diagnostic,
              isAuthorized: () => true);
          bobBackend = SystemKeyboardV3Backend(
              runtime: bobRuntime!,
              contacts: [V3IdentityAdapter.toRemoteIdentity(alicePublic)],
              recordStore: currentBobStore,
              handshakeDiagnostic: diagnostic,
              isAuthorized: () => true);
        }

        final resetHandshakeIds = <String>{};
        try {
          expect(
            await aliceBackend.securityPhaseForContact(
                bobPublic.identityId, bobPublic.fingerprint),
            'setupRequired',
            reason: 'the first readable keyboard message still has orange FS',
          );
          Future<void> send({
            required SystemKeyboardV3Backend sender,
            required SystemKeyboardV3Backend recipient,
            required V3PublicIdentity recipientIdentity,
            required String text,
            required int index,
          }) async {
            final export = await sender.prepareTextOutbound(
              SystemKeyboardOutboundRequest(
                requestId: 'normal-$index',
                contactId: recipientIdentity.identityId,
                contactFingerprint: recipientIdentity.fingerprint,
                text: text,
                editorNonce: 'test-editor',
                inputSessionEpoch: 1,
              ),
            );
            expect(export, isNotNull, reason: 'message $index was blocked');
            expect(export!.carriers, hasLength(1));
            expect(export.carriers.single.length, lessThanOrEqualTo(4000),
                reason: 'message $index exceeded the keyboard carrier limit');
            for (final part in export.carriers.single.split('\n')) {
              if (!part.startsWith(V3LmfFrameCodec.tokenPrefix)) continue;
              final frame = V3LmfFrameCodec.decodeToken(part);
              if (frame.metadata.kind == V3LmfFrameKind.handshake) {
                expect(resetHandshakeIds,
                    isNot(contains(_armor(frame.metadata.sessionId))),
                    reason:
                        'A reset handshake must not return from the keyboard control outbox');
              }
            }
            await sender.markExported(export.exportHandle);
            final received =
                await recipient.decodeCarrier(export.carriers.single);
            expect(received?.text, text,
                reason: 'message $index was not readable on arrival');
          }

          if (restartMode == 'reset') {
            // Generate a real reply outbox, then change only the contact policy.
            // Preserve identity/device keys, history and all protocol records.
            await send(
                sender: aliceBackend,
                recipient: bobBackend,
                recipientIdentity: bobPublic,
                text: 'before contact reset',
                index: 100);
            final oldControls = (await currentBobStore.readAll())
                .where((record) =>
                    record.payload['kind'] == 'v3_keyboard_control_outbox_v1')
                .toList();
            expect(oldControls, isNotEmpty);
            for (final record in oldControls) {
              final frame =
                  V3LmfFrameCodec.decodeToken(record.payload['part'] as String);
              resetHandshakeIds.add(_armor(frame.metadata.sessionId));
            }
            aliceConfig = configFor(
                own: alicePublic,
                peer: bobPublic,
                keyMaterial: aliceConfig.identityKeyMaterial,
                deviceId: aliceDevice.deviceId,
                scopeToken: _aliceKeyboardScope,
                excludedHandshakeIds: resetHandshakeIds);
            bobConfig = configFor(
                own: bobPublic,
                peer: alicePublic,
                keyMaterial: bobConfig.identityKeyMaterial,
                deviceId: bobDevice.deviceId,
                scopeToken: _bobKeyboardScope,
                excludedHandshakeIds: resetHandshakeIds);
            await reopenCustody();
            expect(
                await bobBackend.securityPhaseForContact(
                    alicePublic.identityId, alicePublic.fingerprint),
                'setupRequired');
          }

          for (var index = 0; index < 8; index++) {
            await send(
              sender: aliceBackend,
              recipient: bobBackend,
              recipientIdentity: bobPublic,
              text: 'Alice $index',
              index: index * 2,
            );
            await reopenCustody();
            await send(
              sender: bobBackend,
              recipient: aliceBackend,
              recipientIdentity: alicePublic,
              text: 'Bob $index',
              index: index * 2 + 1,
            );
            await reopenCustody();
          }
          expect(await aliceRuntime!.sessionsForRemoteIdentity(bobPublic),
              isNotEmpty);
          expect(await bobRuntime!.sessionsForRemoteIdentity(alicePublic),
              isNotEmpty);
          final aliceStatus =
              await V3ApplicationChatBridge.forDelegatedKeyboard(
            runtime: aliceRuntime!,
          ).securityStatus(
            contact: V3IdentityAdapter.toRemoteIdentity(bobPublic),
            selectedMode: V3HandshakeMode.normal,
            eligibilityPolicy: aliceConfig.policies[bobPublic.identityId]!
                .toEligibilityPolicy(),
            requireEligibilityPolicy: true,
          );
          final bobStatus = await V3ApplicationChatBridge.forDelegatedKeyboard(
            runtime: bobRuntime!,
          ).securityStatus(
            contact: V3IdentityAdapter.toRemoteIdentity(alicePublic),
            selectedMode: V3HandshakeMode.normal,
            eligibilityPolicy: bobConfig.policies[alicePublic.identityId]!
                .toEligibilityPolicy(),
            requireEligibilityPolicy: true,
          );
          expect(aliceStatus.phase, V3ChatContactSecurityPhase.normalActive);
          expect(bobStatus.phase, V3ChatContactSecurityPhase.normalActive);
          expect(
            await aliceBackend.securityPhaseForContact(
                bobPublic.identityId, bobPublic.fingerprint),
            'normalActive',
          );
          expect(diagnosticEvents, greaterThan(0));
          final preFsHistory = (await currentAliceStore.readAll())
              .where((record) =>
                  record.payload['kind'] == SystemKeyboardHistory.kind)
              .toList();
          expect(preFsHistory, isNotEmpty,
              reason: 'identity-only keyboard text needs an app-chat handoff');
          expect(
              preFsHistory.any((record) =>
                  record.payload['contactId'] == bobPublic.identityId &&
                  record.payload['localIdentityId'] == alicePublic.identityId &&
                  record.payload['text'] == 'Alice 0'),
              isTrue);

          final hiddenBefore = (await currentAliceStore.readAll())
              .where((record) =>
                  record.payload['kind'] == 'v3_application_presentation_v1')
              .length;
          final privateBackend = SystemKeyboardV3Backend(
            runtime: aliceRuntime!,
            contacts: [V3IdentityAdapter.toRemoteIdentity(bobPublic)],
            recordStore: currentAliceStore,
            handshakeDiagnostic: diagnostic,
            saveHistory: false,
            isAuthorized: () => true,
          );
          try {
            final privateExport = await privateBackend.prepareTextOutbound(
              SystemKeyboardOutboundRequest(
                requestId: 'normal-private',
                contactId: bobPublic.identityId,
                contactFingerprint: bobPublic.fingerprint,
                text: 'not in Layergram history',
                editorNonce: 'test-editor',
                inputSessionEpoch: 1,
              ),
            );
            expect(privateExport, isNotNull);
            await privateBackend.markExported(privateExport!.exportHandle);
            expect(
                (await bobBackend.decodeCarrier(privateExport.carriers.single))
                    ?.text,
                'not in Layergram history');
            final after = await currentAliceStore.readAll();
            expect(
                after
                    .where((record) =>
                        record.payload['kind'] ==
                        'v3_application_presentation_v1')
                    .length,
                greaterThan(hiddenBefore),
                reason:
                    'unsaved FS messages must not reappear on reconciliation');
            expect(
                after.where((record) =>
                    record.payload['kind'] == SystemKeyboardHistory.kind &&
                    record.payload['text'] == 'not in Layergram history'),
                isEmpty);
          } finally {
            privateBackend.close();
          }
        } finally {
          aliceBackend.close();
          bobBackend.close();
        }
      } finally {
        await aliceRuntime?.close();
        await bobRuntime?.close();
        await alice.close();
        await bob.close();
        await aliceOwner.close();
        await bobOwner.close();
      }
    });
  }

  test(
    'keyboard backend delivers a prepared outbound, authenticates the peer reply and durably rejects replay',
    () async {
      final harness = await _PeerHarness.establish();
      try {
        final prior =
            await harness.aliceRuntime.sendApplicationMessageToIdentity(
          remoteIdentity: harness.bobPublic,
          expectedMode: V3HandshakeMode.maximum,
          text: 'prior canonical message',
          maximumRemoteDeviceId: _armor(harness.bobDeviceId),
        );
        final priorInbound = await harness.bobRuntime.receiveApplicationFrame(
          frame: prior.frames.first,
          expectedMode: V3HandshakeMode.maximum,
          maximumRemoteDeviceId: _armor(harness.aliceDeviceId),
        );
        await harness.aliceRuntime.applySendAcknowledgement(
          acknowledgementFrame: priorInbound.acknowledgementFrame!,
        );
        await harness.aliceRuntime.close();
        await harness.bobRuntime.close();

        final selected = SystemKeyboardWorkingSet.select(
          await harness.aliceStore.readAll(),
        );
        final bytes = SystemKeyboardRecordSnapshot.encode(selected);
        final cas = _SnapshotCas(initial: bytes);

        // Alice is the keyboard: only a restricted runtime over selected bytes.
        final aliceStore = SystemKeyboardRecordStore(
          snapshot: bytes,
          revision: cas.revision,
          commit: cas.commit,
        );
        final aliceRuntime = await _openKeyboardRuntime(harness, aliceStore);
        // Bob is the peer installation, also restricted over his own records.
        final bobRuntime =
            await V3ApplicationSessionRuntime.openEstablishedSessions(
          publicIdentity: harness.bobPublic,
          localDeviceId: harness.bobDeviceId,
          scopeToken: _bobKeyboardScope,
          store: harness.bobStore,
          sckaBackend: _FakeSckaBackend(),
          approvedContactPolicies: <String, V3EstablishedSessionPolicy>{
            harness.alicePublic.identityId:
                _maximumPolicy(_armor(harness.aliceDeviceId)),
          },
        );
        var aliceAuthorized = true;
        final aliceBackend = SystemKeyboardV3Backend(
          runtime: aliceRuntime,
          contacts: <RemoteIdentity>[
            V3IdentityAdapter.toRemoteIdentity(harness.bobPublic,
                verified: true),
          ],
          isAuthorized: () => aliceAuthorized,
        );
        final bobBackend = SystemKeyboardV3Backend(
          runtime: bobRuntime,
          contacts: <RemoteIdentity>[
            V3IdentityAdapter.toRemoteIdentity(harness.alicePublic,
                verified: true),
          ],
          isAuthorized: () => true,
        );
        try {
          final contacts = await aliceBackend.listApprovedContacts();
          expect(contacts, hasLength(1));
          expect(contacts.single.id, harness.bobPublic.identityId);
          expect(contacts.single.fingerprint, harness.bobPublic.fingerprint);

          final beforeOversize =
              SystemKeyboardRecordSnapshot.encode(await aliceStore.readAll());
          await expectLater(
            aliceBackend.prepareTextOutbound(SystemKeyboardOutboundRequest(
              requestId: 'oversize-keyboard-request',
              contactId: harness.bobPublic.identityId,
              contactFingerprint: harness.bobPublic.fingerprint,
              text: "${List.filled(3998, '€').join()}😀",
              editorNonce: 'editor-nonce-1',
              inputSessionEpoch: 1,
            )),
            throwsA(isA<V3ChatPreFsCapacityException>()),
          );
          expect(
            SystemKeyboardRecordSnapshot.encode(await aliceStore.readAll()),
            beforeOversize,
            reason: 'oversized carrier must not advance the ratchet',
          );

          final outboundText = "${List.filled(40, '€').join()}😀";
          expect(outboundText.length, 42);
          final outbound = await aliceBackend.prepareTextOutbound(
            SystemKeyboardOutboundRequest(
              requestId: 'keyboard-request-1',
              contactId: harness.bobPublic.identityId,
              contactFingerprint: harness.bobPublic.fingerprint,
              text: outboundText,
              editorNonce: 'editor-nonce-1',
              inputSessionEpoch: 1,
            ),
          );
          expect(outbound, isNotNull);
          final carrier = outbound!.carriers.single;
          expect(carrier.split('\n').length, greaterThan(1));
          expect(carrier.length, lessThanOrEqualTo(4000));
          await aliceBackend.markExported(outbound.exportHandle);
          await expectLater(
            aliceBackend.markExported(outbound.exportHandle),
            throwsStateError,
            reason: 'an acknowledgement handle is single use',
          );

          // The real peer runtime receives and authenticates the sender.
          final delivered = await bobBackend.decodeCarrier(carrier);
          expect(delivered, isNotNull);
          expect(delivered!.contact.id, harness.alicePublic.identityId);
          expect(
            delivered.contact.fingerprint,
            harness.alicePublic.fingerprint,
            reason: 'inbound sender authentication',
          );
          expect(delivered.text, outboundText);

          // Authenticated peer reply, produced by the peer's own backend.
          final reply = await bobBackend.prepareTextOutbound(
            SystemKeyboardOutboundRequest(
              requestId: 'keyboard-request-2',
              contactId: harness.alicePublic.identityId,
              contactFingerprint: harness.alicePublic.fingerprint,
              text: 'authenticated peer reply',
              editorNonce: 'editor-nonce-2',
              inputSessionEpoch: 1,
            ),
          );
          expect(reply, isNotNull);
          await bobBackend.markExported(reply!.exportHandle);
          final replyCarrier = reply.carriers.single;

          final decoded = await aliceBackend.decodeCarrier(replyCarrier);
          expect(decoded, isNotNull);
          expect(decoded!.contact.id, harness.bobPublic.identityId);
          expect(
            decoded.contact.fingerprint,
            harness.bobPublic.fingerprint,
            reason: 'peer reply sender authentication',
          );
          expect(decoded.text, 'authenticated peer reply');
          expect(await aliceRuntime.pendingMessageExports(), isEmpty,
              reason:
                  'reply must return the selected contact protocol acknowledgement');
          expect(await aliceBackend.decodeCarrier(replyCarrier), isNull,
              reason: 'committed replay must not decode twice');
          expect(await bobBackend.decodeCarrier(carrier), isNull,
              reason: 'the peer must not re-deliver the same message');

          // A revoked keyboard grant closes the backend before any decode.
          aliceAuthorized = false;
          await expectLater(
            aliceBackend.decodeCarrier(replyCarrier),
            throwsStateError,
            reason: 'a revoked keyboard grant must fail closed',
          );

          // Replay rejection is durable: reload the keyboard runtime from the
          // persisted snapshot and replay the same peer carrier again.
          expect(cas.commits, greaterThan(0));
          expect(cas.bytes, isNot(equals(bytes)),
              reason: 'the keyboard must persist its own protocol progress');
          final persistedBytes = Uint8List.fromList(cas.bytes!);
          final persistedRevision = cas.revision;
          await aliceRuntime.close();

          final reloadStore = SystemKeyboardRecordStore(
            snapshot: persistedBytes,
            revision: persistedRevision,
            commit: cas.commit,
          );
          final reloadedRuntime =
              await V3ApplicationSessionRuntime.openEstablishedSessions(
            publicIdentity: harness.alicePublic,
            localDeviceId: harness.aliceDeviceId,
            scopeToken: _aliceReloadScope,
            store: reloadStore,
            sckaBackend: _FakeSckaBackend(),
            approvedContactPolicies: <String, V3EstablishedSessionPolicy>{
              harness.bobPublic.identityId:
                  _maximumPolicy(_armor(harness.bobDeviceId)),
            },
          );
          final reloadedBackend = SystemKeyboardV3Backend(
            runtime: reloadedRuntime,
            contacts: <RemoteIdentity>[
              V3IdentityAdapter.toRemoteIdentity(harness.bobPublic,
                  verified: true),
            ],
            isAuthorized: () => true,
          );
          try {
            expect(await reloadedBackend.decodeCarrier(replyCarrier), isNull,
                reason: 'replay state must survive a serialized reload');
            // A new outbound still works after the reload.
            final next = await reloadedBackend.prepareTextOutbound(
              SystemKeyboardOutboundRequest(
                requestId: 'keyboard-request-3',
                contactId: harness.bobPublic.identityId,
                contactFingerprint: harness.bobPublic.fingerprint,
                text: 'after reload',
                editorNonce: 'editor-nonce-3',
                inputSessionEpoch: 1,
              ),
            );
            expect(next, isNotNull);
            await reloadedBackend.markExported(next!.exportHandle);
            final afterReload = await bobBackend.decodeCarrier(
              next.carriers.single,
            );
            expect(afterReload?.text, 'after reload');
          } finally {
            reloadedBackend.close();
            await reloadedRuntime.close();
          }
        } finally {
          aliceBackend.close();
          bobBackend.close();
          await aliceRuntime.close();
          await bobRuntime.close();
        }
      } finally {
        await harness.dispose();
      }
    },
  );

  test(
    'keyboard-returned record state merges with the retained private archive without loss',
    () async {
      final harness = await _PeerHarness.establish();
      try {
        final prior =
            await harness.aliceRuntime.sendApplicationMessageToIdentity(
          remoteIdentity: harness.bobPublic,
          expectedMode: V3HandshakeMode.maximum,
          text: 'prior canonical message',
          maximumRemoteDeviceId: _armor(harness.bobDeviceId),
        );
        final priorInbound = await harness.bobRuntime.receiveApplicationFrame(
          frame: prior.frames.first,
          expectedMode: V3HandshakeMode.maximum,
          maximumRemoteDeviceId: _armor(harness.aliceDeviceId),
        );
        await harness.aliceRuntime.applySendAcknowledgement(
          acknowledgementFrame: priorInbound.acknowledgementFrame!,
        );
        await harness.aliceRuntime.close();
        await harness.bobRuntime.close();

        // Private archive records that keyboard custody must never destroy.
        final presentationId = harness.aliceStore.seed(
          'v3_application_presentation_v1',
          'v3:assembly-presentation',
          {'preview': 'private chat presentation'},
        );
        final deviceKeyId = harness.aliceStore.seed(
          'v3_device_key_v1',
          null,
          {'deviceId': 'transferred-under-exclusive-custody'},
        );
        final historyId = harness.aliceStore.seed(
          'v3_application_record_v1',
          'v3:assembly-history',
          {'body': 'private unreferenced history body'},
        );

        final native = _FakeNativeCustody();
        final custody = SystemKeyboardCustody(
          privateStore: harness.aliceStore,
          native: native,
        );
        final all = await harness.aliceStore.readAll();
        final selectedIds = SystemKeyboardWorkingSet.select(all)
            .map((r) => r.storageId)
            .toSet();
        final retainedBefore = <String, Map<String, dynamic>>{
          for (final record in all)
            if (!selectedIds.contains(record.storageId))
              record.storageId: record.payload,
        };
        expect(retainedBefore.keys,
            containsAll(<String>[presentationId, historyId]));
        expect(selectedIds, contains(deviceKeyId));

        final grant = await custody.delegate();
        grant.close();
        expect(native.snapshotBytes, isNotNull);
        // Session state moved to native custody; the private archive stayed.
        for (final id in selectedIds) {
          expect(harness.aliceStore.rows.containsKey(id), isFalse);
        }
        for (final entry in retainedBefore.entries) {
          expect(harness.aliceStore.rows[entry.key], entry.value);
        }

        // The keyboard runtime writes real protocol state through the CAS store.
        final store = SystemKeyboardRecordStore(
          snapshot: native.snapshotBytes!,
          revision: native.revision,
          commit: native.commit,
        );
        final runtime = await _openKeyboardRuntime(harness, store,
            scopeToken: _aliceKeyboardScope);
        final backend = SystemKeyboardV3Backend(
          runtime: runtime,
          contacts: <RemoteIdentity>[
            V3IdentityAdapter.toRemoteIdentity(harness.bobPublic,
                verified: true),
          ],
          isAuthorized: () => true,
        );
        final outbound = await backend.prepareTextOutbound(
          SystemKeyboardOutboundRequest(
            requestId: 'keyboard-request-merge',
            contactId: harness.bobPublic.identityId,
            contactFingerprint: harness.bobPublic.fingerprint,
            text: 'keyboard merge message',
            editorNonce: 'editor-nonce-merge',
            inputSessionEpoch: 1,
          ),
        );
        expect(outbound, isNotNull);
        await backend.markExported(outbound!.exportHandle);
        backend.close();
        await runtime.close();
        expect(native.revision, greaterThan(0));
        final returnedBytes = Uint8List.fromList(native.snapshotBytes!);
        final returned = SystemKeyboardRecordSnapshot.decode(returnedBytes);
        expect(returned, isNotEmpty);
        // The keyboard really advanced the session, not a byte-identical echo.
        final baselineById = <String, Map<String, dynamic>>{
          for (final record in all) record.storageId: record.payload,
        };
        expect(
          returned.where((record) {
            final previous = baselineById[record.storageId];
            return previous == null ||
                jsonEncode(previous) != jsonEncode(record.payload);
          }),
          isNotEmpty,
          reason: 'keyboard returned only the delegated baseline state',
        );

        // Native returns custody: the returned records merge into the archive.
        await custody.recover();
        expect(native.snapshotBytes, isNull);
        for (final record in returned) {
          expect(harness.aliceStore.rows[record.storageId], record.payload,
              reason: 'returned ${record.storageId} lost in merge');
        }
        for (final entry in retainedBefore.entries) {
          expect(harness.aliceStore.rows[entry.key], entry.value,
              reason: 'retained ${entry.key} lost in merge');
        }
        expect(
          harness.aliceStore.rows.keys.toSet(),
          <String>{
            ...retainedBefore.keys,
            ...returned.map((r) => r.storageId),
          },
          reason: 'merge created or lost private records',
        );
        expect(
          harness.aliceStore.rows.values.where((payload) =>
              payload['kind'] == SystemKeyboardCustody.markerKind ||
              payload['kind'] == SystemKeyboardCustody.importKind),
          isEmpty,
        );
        final mergedKinds =
            harness.aliceStore.rows.values.map((p) => p['kind']).toSet();
        expect(mergedKinds, contains('v3_session_checkpoint_v1'));
        expect(mergedKinds, contains('v3_application_record_v1'));
      } finally {
        await harness.dispose();
      }
    },
  );
}

Future<V3ApplicationSessionRuntime> _openKeyboardRuntime(
  _PeerHarness harness,
  SystemKeyboardRecordStore store, {
  String scopeToken = _aliceKeyboardScope,
}) =>
    V3ApplicationSessionRuntime.openEstablishedSessions(
      publicIdentity: harness.alicePublic,
      localDeviceId: harness.aliceDeviceId,
      scopeToken: scopeToken,
      store: store,
      sckaBackend: _FakeSckaBackend(),
      approvedContactPolicies: <String, V3EstablishedSessionPolicy>{
        harness.bobPublic.identityId:
            _maximumPolicy(_armor(harness.bobDeviceId)),
      },
    );

V3EstablishedSessionPolicy _maximumPolicy(String remoteDeviceId) =>
    V3EstablishedSessionPolicy(
      mode: FsSecurityMode.strict,
      revision: 7,
      maximumRemoteDeviceId: remoteDeviceId,
    );

/// In-memory keyboard working set store: valid opaque custody IDs, JSON-copied
/// payloads, and the custody private-store surface used by delegation.
final class _KeyboardStore
    implements V3LmfRecordStore, SystemKeyboardCustodyPrivateStore {
  final Map<String, Map<String, dynamic>> rows =
      <String, Map<String, dynamic>>{};
  int _ids = 0;

  int get recordCount => rows.length;

  static Map<String, dynamic> _copy(Map<String, dynamic> value) =>
      jsonDecode(jsonEncode(value)) as Map<String, dynamic>;

  static String _newId(int counter) {
    final bytes = Uint8List(16);
    ByteData.sublistView(bytes).setUint32(0, counter, Endian.big);
    return 'r${base64Url.encode(bytes).replaceAll('=', '')}';
  }

  /// Plants one record the real identity store would hold beside session state.
  String seed(
    String kind,
    String? stableRecordId,
    Map<String, dynamic> extra,
  ) {
    final id = _newId(++_ids);
    rows[id] = _copy(<String, dynamic>{
      'kind': kind,
      if (stableRecordId != null) ...<String, dynamic>{
        'stableRecordId': stableRecordId,
        'assemblyId': stableRecordId.substring(3),
      },
      ...extra,
    });
    return id;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => <V3LmfStoredRecord>[
        for (final entry in rows.entries)
          V3LmfStoredRecord(
            storageId: entry.key,
            payload: _copy(entry.value),
          ),
      ];

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = _newId(++_ids);
    rows[id] = _copy(payload);
    return id;
  }

  @override
  Future<void> delete(String storageId) async {
    rows.remove(storageId);
  }

  @override
  Future<void> flush() async {}

  @override
  Future<PreparedAuxRecord> prepare(
      String storageId, Map<String, dynamic> payload) async {
    final encrypted =
        await AuxRecordCipher.encrypt(payload: payload, auxStorageKey: _auxKey);
    return PreparedAuxRecord.fromJson(<String, dynamic>{
      'scope': _importScope,
      'id': storageId,
      'sealed': encrypted.encryptedRecord,
    });
  }

  @override
  Future<void> apply(PreparedAuxRecord record) async {
    final clear = await AuxRecordCipher.decrypt(
        encryptedRecord: record.encryptedRecord, auxStorageKey: _auxKey);
    if (clear == null) {
      throw StateError('keyboard import record could not be opened');
    }
    rows[record.storageId] = _copy(clear);
  }
}

/// In-memory native custody commit: revision-checked compare-and-swap.
final class _SnapshotCas {
  _SnapshotCas({Uint8List? initial})
      : bytes = initial == null ? null : Uint8List.fromList(initial);

  int revision = 0;
  Uint8List? bytes;
  int commits = 0;

  Future<int> commit(Uint8List snapshot, int expectedRevision) async {
    if (expectedRevision != revision) {
      throw StateError('unexpected keyboard custody revision');
    }
    commits++;
    bytes = Uint8List.fromList(snapshot);
    revision++;
    return revision;
  }
}

/// Native custody adapter fake: stores the exact snapshot bytes it was given.
final class _FakeNativeCustody implements SystemKeyboardCustodyNative {
  Uint8List? snapshotBytes;
  Uint8List? epoch;
  Uint8List? key;
  int revision = 0;
  bool active = false;

  @override
  Future<bool> hasPending() async => snapshotBytes != null;

  @override
  Future<void> prepare(Uint8List epoch, Uint8List key, Uint8List bytes) async {
    this.epoch = Uint8List.fromList(epoch);
    this.key = Uint8List.fromList(key);
    snapshotBytes = Uint8List.fromList(bytes);
  }

  @override
  Future<void> activate(Uint8List epoch, Uint8List key) async {
    active = true;
  }

  @override
  Future<SystemKeyboardCustodySnapshot> reclaim(
      Uint8List epoch, Uint8List key) async {
    final snapshot = snapshotBytes;
    if (snapshot == null) throw const SystemKeyboardCustodyMissing();
    active = false;
    return SystemKeyboardCustodySnapshot(
        revision, Uint8List.fromList(snapshot));
  }

  @override
  Future<void> removeAfterImport(
      Uint8List epoch, Uint8List key, int revision) async {
    if (snapshotBytes != null && revision != this.revision) {
      throw StateError('unexpected returned keyboard custody revision');
    }
    snapshotBytes = null;
  }

  Future<int> commit(Uint8List snapshot, int expectedRevision) async {
    if (expectedRevision != revision) {
      throw StateError('unexpected keyboard custody revision');
    }
    snapshotBytes = Uint8List.fromList(snapshot);
    revision++;
    return revision;
  }
}

/// One Hive-free pair of peers with a completed Maximum-mode session.
final class _PeerHarness {
  _PeerHarness._({
    required this.alice,
    required this.bob,
    required this.aliceDeviceId,
    required this.bobDeviceId,
    required this.aliceStore,
    required this.bobStore,
    required this.aliceRuntime,
    required this.bobRuntime,
  });

  final V3LocalIdentityHandle alice;
  final V3LocalIdentityHandle bob;
  final Uint8List aliceDeviceId;
  final Uint8List bobDeviceId;
  final _KeyboardStore aliceStore;
  final _KeyboardStore bobStore;
  final V3ApplicationSessionRuntime aliceRuntime;
  final V3ApplicationSessionRuntime bobRuntime;

  V3PublicIdentity get alicePublic => alice.publicIdentity;
  V3PublicIdentity get bobPublic => bob.publicIdentity;

  static Future<_PeerHarness> establish() async {
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: _FakeMlKemBackend(),
    );
    final alice = await factory.restorePrimary(mnemonic: _aliceMnemonic);
    final bob = await factory.restorePrimary(mnemonic: _bobMnemonic);
    final aliceDevice = await V3LocalDeviceHandle.generate();
    final bobDevice = await V3LocalDeviceHandle.generate();
    final aliceStore = _KeyboardStore();
    final bobStore = _KeyboardStore();
    V3ApplicationSessionRuntime? aliceRuntime;
    V3ApplicationSessionRuntime? bobRuntime;
    V3SessionPersistenceScope? aliceScope;
    V3SessionPersistenceScope? bobScope;
    try {
      aliceScope = await V3SessionPersistenceScope.openWithStore(
        scopeToken: _aliceScope,
        store: aliceStore,
        sckaBackend: _FakeSckaBackend(),
      );
      bobScope = await V3SessionPersistenceScope.openWithStore(
        scopeToken: _bobScope,
        store: bobStore,
        sckaBackend: _FakeSckaBackend(),
      );
      await aliceScope.restore(checkpoints: const <V3TripleRatchetState>[]);
      await bobScope.restore(checkpoints: const <V3TripleRatchetState>[]);
      await _runMaximumHandshake(
        initiatorScope: aliceScope,
        responderScope: bobScope,
        initiator: alice,
        initiatorDevice: aliceDevice,
        responder: bob,
        responderDevice: bobDevice,
      );
      await aliceScope.close();
      aliceScope = null;
      await bobScope.close();
      bobScope = null;

      aliceRuntime = await V3ApplicationSessionRuntime.openEstablishedSessions(
        publicIdentity: alice.publicIdentity,
        localDeviceId: aliceDevice.deviceId,
        scopeToken: _aliceScope,
        store: aliceStore,
        sckaBackend: _FakeSckaBackend(),
        approvedContactPolicies: <String, V3EstablishedSessionPolicy>{
          bob.publicIdentity.identityId:
              _maximumPolicy(_armor(bobDevice.deviceId)),
        },
      );
      bobRuntime = await V3ApplicationSessionRuntime.openEstablishedSessions(
        publicIdentity: bob.publicIdentity,
        localDeviceId: bobDevice.deviceId,
        scopeToken: _bobScope,
        store: bobStore,
        sckaBackend: _FakeSckaBackend(),
        approvedContactPolicies: <String, V3EstablishedSessionPolicy>{
          alice.publicIdentity.identityId:
              _maximumPolicy(_armor(aliceDevice.deviceId)),
        },
      );
      final harness = _PeerHarness._(
        alice: alice,
        bob: bob,
        aliceDeviceId: aliceDevice.deviceId,
        bobDeviceId: bobDevice.deviceId,
        aliceStore: aliceStore,
        bobStore: bobStore,
        aliceRuntime: aliceRuntime,
        bobRuntime: bobRuntime,
      );
      aliceRuntime = null;
      bobRuntime = null;
      return harness;
    } finally {
      await aliceScope?.close();
      await bobScope?.close();
      await aliceRuntime?.close();
      await bobRuntime?.close();
    }
  }

  Future<void> dispose() async {
    await aliceRuntime.close();
    await bobRuntime.close();
    await alice.close();
    await bob.close();
  }
}

Future<void> _runMaximumHandshake({
  required V3SessionPersistenceScope initiatorScope,
  required V3SessionPersistenceScope responderScope,
  required V3LocalIdentityHandle initiator,
  required V3LocalDeviceHandle initiatorDevice,
  required V3LocalIdentityHandle responder,
  required V3LocalDeviceHandle responderDevice,
}) async {
  final initiatorPublic = initiator.publicIdentity;
  final responderPublic = responder.publicIdentity;

  final offer = await initiatorScope.handshakes.createOffer(
    localIdentity: initiator,
    localDevice: initiatorDevice,
    remoteIdentity: responderPublic,
    mode: V3HandshakeMode.maximum,
  );
  final offerFrames = await V3HandshakeTransport.seal(
    record: offer.outboundRecord,
    initiatorIdentity: initiatorPublic,
    responderIdentity: responderPublic,
  );
  final offerAssembly =
      await _receiveAssembly(responderScope.handshakeInbox, offerFrames);
  final openedOffer = await V3HandshakeTransport.open(
    frames: offerAssembly.frames,
    initiatorIdentity: initiatorPublic,
    responderIdentity: responderPublic,
  );
  late final V3HandshakeOffer decodedOffer;
  try {
    decodedOffer = openedOffer.decodeOffer();
  } finally {
    openedOffer.close();
  }
  final reply = await responderScope.handshakes.createReply(
    localIdentity: responder,
    localDevice: responderDevice,
    initiatorIdentity: initiatorPublic,
    offer: decodedOffer,
    expectedMode: V3HandshakeMode.maximum,
  );
  await responderScope.handshakeInbox.commit(offerAssembly.assemblyId);
  final replyFrames = await V3HandshakeTransport.seal(
    record: reply.outboundRecord,
    initiatorIdentity: initiatorPublic,
    responderIdentity: responderPublic,
  );

  final replyAssembly =
      await _receiveAssembly(initiatorScope.handshakeInbox, replyFrames);
  final openedReply = await V3HandshakeTransport.open(
    frames: replyAssembly.frames,
    initiatorIdentity: initiatorPublic,
    responderIdentity: responderPublic,
  );
  late final V3HandshakeReply decodedReply;
  try {
    decodedReply = openedReply.decodeReply();
  } finally {
    openedReply.close();
  }
  final handshakeId = _armor(decodedReply.handshakeId);
  final initiatorStateDigest =
      await initiatorScope.handshakes.stateDigestForId(handshakeId);
  if (initiatorStateDigest == null) {
    throw StateError('missing initiator handshake state');
  }
  final handoff = await initiatorScope.handoffs.completeInitiator(
    handshakeId: handshakeId,
    expectedStateDigest: initiatorStateDigest,
    localIdentity: initiator,
    localDevice: initiatorDevice,
    responderIdentity: responderPublic,
    reply: decodedReply,
  );
  final confirmationRecord = Uint8List.fromList(handoff.confirmationRecord);
  late final List<V3LmfFrame> confirmationFrames;
  try {
    confirmationFrames = await V3HandshakeTransport.seal(
      record: confirmationRecord,
      initiatorIdentity: initiatorPublic,
      responderIdentity: responderPublic,
    );
  } finally {
    confirmationRecord.fillRange(0, confirmationRecord.length, 0);
  }
  await initiatorScope.handshakeInbox.commit(replyAssembly.assemblyId);

  final confirmationAssembly =
      await _receiveAssembly(responderScope.handshakeInbox, confirmationFrames);
  final openedConfirmation = await V3HandshakeTransport.open(
    frames: confirmationAssembly.frames,
    initiatorIdentity: initiatorPublic,
    responderIdentity: responderPublic,
  );
  late final V3HandshakeConfirmation decodedConfirmation;
  try {
    decodedConfirmation = openedConfirmation.decodeConfirmation();
  } finally {
    openedConfirmation.close();
  }
  final confirmationId = _armor(decodedConfirmation.handshakeId);
  final responderStateDigest =
      await responderScope.handshakes.stateDigestForId(confirmationId);
  if (responderStateDigest == null) {
    throw StateError('missing responder handshake state');
  }
  await responderScope.handoffs.completeResponder(
    handshakeId: confirmationId,
    expectedStateDigest: responderStateDigest,
    initiatorIdentity: initiatorPublic,
    responderIdentity: responderPublic,
    confirmation: decodedConfirmation,
  );
  await responderScope.handshakeInbox.commit(confirmationAssembly.assemblyId);
}

Future<V3HandshakeFrameAssembly> _receiveAssembly(
  V3HandshakeFrameInbox inbox,
  List<V3LmfFrame> frames,
) async {
  V3HandshakeFrameAssembly? assembly;
  for (final frame in frames) {
    final outcome = await inbox.receive(frame: frame);
    assembly ??= outcome.assembly;
  }
  final resolved = assembly;
  if (resolved == null) {
    throw StateError('handshake assembly was incomplete');
  }
  return resolved;
}

String _armor(Uint8List value) => base64UrlEncode(value).replaceAll('=', '');

final class _MlKemPrivateKeyHandle implements MlKem768PrivateKeyHandle {
  _MlKemPrivateKeyHandle(this.publicKey);

  final Uint8List publicKey;

  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    if (isClosed) return;
    publicKey.fillRange(0, publicKey.length, 0);
    isClosed = true;
  }
}

final class _FakeMlKemBackend implements MlKem768Backend {
  int _encapsulationCounter = 0;

  @override
  String get implementationId => 'keyboard-integration-test-ml-kem';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    final digest = sha512.convert(seed).bytes;
    final publicKey = Uint8List.fromList(
      List<int>.generate(
        MlKem768.publicKeyBytes,
        (index) => digest[index % digest.length],
      ),
    );
    return MlKem768KeyPair(
      publicKey: publicKey,
      privateKeyHandle: _MlKemPrivateKeyHandle(Uint8List.fromList(publicKey)),
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async =>
      publicKey.length == MlKem768.publicKeyBytes &&
      publicKey.any((byte) => byte != 0);

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) async {
    _encapsulationCounter++;
    final counter = Uint8List(4);
    ByteData.sublistView(counter).setUint32(0, _encapsulationCounter);
    final block = sha512.convert(<int>[...publicKey, ...counter]).bytes;
    final ciphertext = Uint8List.fromList(
      List<int>.generate(
        MlKem768.ciphertextBytes,
        (index) => block[index % block.length] ^ (index & 0xff),
      ),
    );
    return MlKem768Encapsulation(
      ciphertext: ciphertext,
      sharedSecret: _sharedSecret(publicKey, ciphertext),
    );
  }

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) async {
    if (privateKeyHandle is! _MlKemPrivateKeyHandle ||
        privateKeyHandle.isClosed ||
        ciphertext.length != MlKem768.ciphertextBytes) {
      throw StateError('invalid test ML-KEM input');
    }
    return _sharedSecret(privateKeyHandle.publicKey, ciphertext);
  }

  Uint8List _sharedSecret(Uint8List publicKey, Uint8List ciphertext) =>
      Uint8List.fromList(
        sha256.convert(<int>[
          ...'keyboard-integration-test-shared\x00'.codeUnits,
          ...publicKey,
          ...ciphertext,
        ]).bytes,
      );
}

final class _FakeSckaBackend implements V3SckaBackend {
  @override
  String get implementationId => 'layergram-keyboard-integration-test-scka/1';

  @override
  int get protocolRevision => V3SparsePqRatchet.requiredBackendProtocolRevision;

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
    required Uint8List stateSealKey,
  }) async =>
      _state(role, sessionId, 0, 0);

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    if (authenticatedState.length != 26 ||
        authenticatedState[0] != role.wireId ||
        !_constantTimeBytesEqual(
          Uint8List.sublistView(authenticatedState, 1, 17),
          sessionId,
        ) ||
        ByteData.sublistView(authenticatedState).getUint64(18, Endian.big) !=
            expectedStateRevision) {
      throw StateError('invalid test SCKA state');
    }
  }

  @override
  Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
    required V3SckaMessage message,
  }) async {
    final currentEpoch = authenticatedState[17];
    final payload = message.nativePayload;
    if (payload.length != 1 || payload.single < currentEpoch) {
      throw const FormatException('invalid test SCKA message');
    }
    final outputEpoch = payload.single;
    return V3SckaReceiveCandidate(
      nextAuthenticatedState:
          _state(role, sessionId, outputEpoch, expectedStateRevision + 1),
      stateRevision: expectedStateRevision + 1,
      receivingEpoch: message.sendingEpoch,
      epochSecret: outputEpoch == currentEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _epochSecret(sessionId, outputEpoch),
            ),
    );
  }

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    final currentEpoch = authenticatedState[17];
    final outputEpoch = currentEpoch == 0 ? 1 : currentEpoch;
    return V3SckaSendCandidate(
      nextAuthenticatedState:
          _state(role, sessionId, outputEpoch, expectedStateRevision + 1),
      stateRevision: expectedStateRevision + 1,
      sendingEpoch: currentEpoch,
      nativePayload: Uint8List.fromList(<int>[outputEpoch]),
      epochSecret: currentEpoch == outputEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _epochSecret(sessionId, outputEpoch),
            ),
    );
  }

  static Uint8List _state(
    V3SessionRole role,
    Uint8List sessionId,
    int epoch,
    int revision,
  ) {
    final result = Uint8List.fromList(<int>[
      role.wireId,
      ...sessionId,
      epoch,
      ...List<int>.filled(8, 0),
    ]);
    ByteData.sublistView(result).setUint64(18, revision, Endian.big);
    return result;
  }

  static Uint8List _epochSecret(Uint8List sessionId, int epoch) =>
      Uint8List.fromList(
        sha256.convert(<int>[0x53, ...sessionId, epoch]).bytes,
      );
}

bool _constantTimeBytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
