import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/fs_message_classification.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/application_chat_bridge_v3.dart';
import 'package:layergram/core/crypto/v3/application_session_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768_ffi.dart';
import 'package:layergram/core/crypto/v3/prefs_envelope_v3.dart';
import 'package:layergram/core/crypto/v3/prefs_bootstrap_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';
import 'package:layergram/features/home/v3_pending_response_queue.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  for (final mode in V3ChatCarrierMode.values) {
    for (final simultaneous in [false, true]) {
      for (final adverse in [false, true]) {
        test(
            'independent acceptance: first data and organic FS in ${mode.name}, adverse=$adverse, simultaneous=$simultaneous',
            () async {
          final temp = await Directory.systemTemp
              .createTemp('lg_identity_first_independent_');
          Hive.init(temp.path);
          await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
          final factory = V3LocalIdentityFactory(
              seedService: SeedService(),
              mlKem768Backend: Platform
                          .environment['LAYERGRAM_MLKEM_PRODUCTION_LIBRARY'] ==
                      null
                  ? _HandshakeMlKemBackend()
                  : MlKem768FfiBackend.open(
                      libraryPath: Platform
                          .environment['LAYERGRAM_MLKEM_PRODUCTION_LIBRARY']!));
          final a = await factory.restorePrimary(
              mnemonic:
                  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
          final b = await factory.restorePrimary(
              mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');
          var ar = await V3ApplicationSessionRuntime.open(
              localIdentity: a,
              scopeToken: 'independent-a-01',
              sckaBackend: _InitialSckaBackend());
          var br = await V3ApplicationSessionRuntime.open(
              localIdentity: b,
              scopeToken: 'independent-b-01',
              sckaBackend: _InitialSckaBackend());
          final am = MessagesRepository();
          final bm = _FaultInjectingMessagesRepository();
          await am.setActiveContext(
              scopeToken: 'independent-a-01',
              storageKey: SecretKey(_testBytes(32, 41)));
          await bm.setActiveContext(
              scopeToken: 'independent-b-01',
              storageKey: SecretKey(_testBytes(32, 91)));
          var ab = V3ApplicationChatBridge(
              runtime: ar, messagesRepository: am, keyTag: 'a');
          var bb = V3ApplicationChatBridge(
              runtime: br, messagesRepository: bm, keyTag: 'b');
          final ac = V3IdentityAdapter.toRemoteIdentity(a.publicIdentity,
              verified: true);
          final bc = V3IdentityAdapter.toRemoteIdentity(b.publicIdentity,
              verified: true);
          await ab.ensureContactPolicy(bc, V3HandshakeMode.normal);
          await bb.ensureContactPolicy(ac, V3HandshakeMode.normal);
          var bothActive = false;
          var applicationSendCount = 0;
          String? initialRecordId;
          String? initialCarrier;
          int? firstActiveTurn;
          V3ChatOutboundExport? delayed;
          try {
            V3ChatOutboundExport? firstA;
            V3ChatOutboundExport? firstB;
            if (simultaneous) {
              firstA = await ab.prepareOutbound(
                  contact: bc,
                  mode: V3HandshakeMode.normal,
                  carrierMode: mode,
                  text: 'Messaggio reale 0',
                  deleteAfterRead: true,
                  coverText: 'Ci vediamo domani per parlare con calma. '
                      .padRight(360, 'a'),
                  eligibilityPolicy: ab.eligibilityForContact(bc),
                  eligibilityForContact: ab.eligibilityForContact);
              firstB = await bb.prepareOutbound(
                  contact: ac,
                  mode: V3HandshakeMode.normal,
                  carrierMode: mode,
                  text: 'Messaggio reale 1',
                  coverText: 'Ci vediamo domani per parlare con calma. '
                      .padRight(360, 'a'),
                  eligibilityPolicy: bb.eligibilityForContact(ac),
                  eligibilityForContact: bb.eligibilityForContact);
            }
            for (var turn = 0; turn < 64; turn++) {
              final sender = turn.isEven ? ab : bb;
              final receiver = turn.isEven ? bb : ab;
              final target = turn.isEven ? bc : ac;
              final source = turn.isEven ? ac : bc;
              final text = 'Messaggio reale $turn';
              final out = simultaneous && turn == 0
                  ? firstA!
                  : simultaneous && turn == 1
                      ? firstB!
                      : await sender.prepareOutbound(
                          contact: target,
                          mode: V3HandshakeMode.normal,
                          carrierMode:
                              mode == V3ChatCarrierMode.steganography &&
                                      turn == 2
                                  ? V3ChatCarrierMode.text
                                  : mode,
                          text: text,
                          deleteAfterRead: turn == 0,
                          coverText: 'Ci vediamo domani per parlare con calma. '
                              .padRight(360, 'a'),
                          eligibilityPolicy:
                              sender.eligibilityForContact(target),
                          eligibilityForContact: sender.eligibilityForContact);
              if (out.purpose == V3ChatOutboundPurpose.application) {
                applicationSendCount++;
              }
              expect(out.purpose.name, anyOf('application', 'preFs'),
                  reason: 'turn=$turn must carry user data');
              expect(out.parts.length, 1,
                  reason:
                      'short ordinary data must not need technical-only sends');
              expect(out.parts.single.length, lessThanOrEqualTo(4000),
                  reason: 'turn=$turn must remain portable as one copy');
              if (out.purpose.name == 'preFs' && turn > 1) {
                final sendingStatus = await sender.securityStatus(
                    contact: target,
                    selectedMode: V3HandshakeMode.normal,
                    eligibilityPolicy: sender.eligibilityForContact(target));
                expect(sendingStatus.isActive, isFalse,
                    reason:
                        'conversation cannot show green while sending new classical bootstrap data');
              }
              await sender.markExported(out);
              if (turn == 0 && mode != V3ChatCarrierMode.steganography) {
                final restored = await sender.pendingExportsForContact(
                  contact: target,
                  carrierMode: mode,
                  coverText: 'Ci vediamo domani per parlare con calma. '
                      .padRight(360, 'a'),
                );
                expect(
                    restored
                        .singleWhere((candidate) =>
                            candidate.preFsMetadata?.messageId ==
                            out.preFsMetadata?.messageId)
                        .parts
                        .single,
                    out.parts.single,
                    reason: 'bundled control must retransmit byte for byte');
              }
              if (adverse && turn == 2) {
                delayed = out;
                continue;
              }
              if (adverse && turn == 3) {
                continue;
              }
              if (turn == 0 && mode == V3ChatCarrierMode.text) {
                final token = out.parts.single;
                final envelopeToken = token.split('\n').first;
                final separator = envelopeToken.indexOf('.');
                final damagedBytes = base64Url.decode(base64Url
                    .normalize(envelopeToken.substring(separator + 1)));
                damagedBytes[damagedBytes.length - 1] ^= 1;
                final damaged = envelopeToken.substring(0, separator + 1) +
                    base64UrlEncode(damagedBytes).replaceAll('=', '');
                final rejected = await bb.receiveCarrier(
                    carrier: damaged,
                    contacts: [ac],
                    modeForContact: bb.modeForContact,
                    eligibilityForContact: bb.eligibilityForContact,
                    ensureEligibilityForContact: bb.ensureContactPolicy);
                expect(rejected.status, V3ChatInboundStatus.invalid,
                    reason:
                        'tampered authenticated envelope must not mutate data/control state');
                expect(
                    (await bm.getAllMessages())
                        .where((record) => record.direction == 'incoming'),
                    isEmpty);
                final wrongRecipient = await ab.receiveCarrier(
                    carrier: token,
                    contacts: [bc],
                    modeForContact: ab.modeForContact,
                    eligibilityForContact: ab.eligibilityForContact,
                    ensureEligibilityForContact: ab.ensureContactPolicy);
                expect(wrongRecipient.status,
                    isNot(V3ChatInboundStatus.delivered));
              }
              var deliveredCarrier = out.parts.single;
              if (adverse && turn == 0 && mode == V3ChatCarrierMode.text) {
                final lines = deliveredCarrier.split('\n');
                expect(lines.length, greaterThan(1));
                lines[lines.length - 1] = '${lines.last}!';
                deliveredCarrier = lines.join('\n');
              }
              final incoming = await receiver.receiveCarrier(
                  carrier: deliveredCarrier,
                  contacts: [source],
                  modeForContact: receiver.modeForContact,
                  eligibilityForContact: receiver.eligibilityForContact,
                  ensureEligibilityForContact: receiver.ensureContactPolicy);
              expect(incoming.status, V3ChatInboundStatus.delivered,
                  reason: 'turn=$turn immediate delivery');
              expect(incoming.payload?.text, text,
                  reason: 'turn=$turn exact user data');
              if (turn == 0) {
                initialRecordId = 'v3m:${incoming.payload!.stableMessageId}';
                initialCarrier = deliveredCarrier;
              }
              if (adverse && turn % 5 == 0) {
                final replay = await receiver.receiveCarrier(
                    carrier: deliveredCarrier,
                    contacts: [source],
                    modeForContact: receiver.modeForContact,
                    eligibilityForContact: receiver.eligibilityForContact,
                    ensureEligibilityForContact: receiver.ensureContactPolicy);
                expect(replay.status, V3ChatInboundStatus.committedReplay);
              }
              if (adverse && turn == 8) {
                final late = await bb.receiveCarrier(
                    carrier: delayed!.parts.single,
                    contacts: [ac],
                    modeForContact: bb.modeForContact,
                    eligibilityForContact: bb.eligibilityForContact,
                    ensureEligibilityForContact: bb.ensureContactPolicy);
                expect(late.status, V3ChatInboundStatus.delivered,
                    reason: 'late original preFS data remains readable');
                expect(late.payload?.text, 'Messaggio reale 2');
              }
              if (adverse && turn == 7) {
                await ar.close();
                await br.close();
                ar = await V3ApplicationSessionRuntime.open(
                    localIdentity: a,
                    scopeToken: 'independent-a-01',
                    sckaBackend: _InitialSckaBackend());
                br = await V3ApplicationSessionRuntime.open(
                    localIdentity: b,
                    scopeToken: 'independent-b-01',
                    sckaBackend: _InitialSckaBackend());
                ab = V3ApplicationChatBridge(
                    runtime: ar, messagesRepository: am, keyTag: 'a');
                bb = V3ApplicationChatBridge(
                    runtime: br, messagesRepository: bm, keyTag: 'b');
              }
              // Deliberately do NOT export an automatic technical response: only ordinary sends progress FS.
              final ast = await ab.securityStatus(
                  contact: bc,
                  selectedMode: V3HandshakeMode.normal,
                  eligibilityPolicy: ab.eligibilityForContact(bc));
              final bst = await bb.securityStatus(
                  contact: ac,
                  selectedMode: V3HandshakeMode.normal,
                  eligibilityPolicy: bb.eligibilityForContact(ac));
              if (ast.isActive && bst.isActive) {
                firstActiveTurn ??= turn;
                if (turn >= firstActiveTurn + 6 && (!adverse || turn >= 8)) {
                  bothActive = true;
                  break;
                }
              }
            }
            expect(bothActive, isTrue,
                reason:
                    'ordinary data must eventually establish real sessions on both sides');
            if (!adverse && mode != V3ChatCarrierMode.steganography) {
              expect(firstActiveTurn, lessThanOrEqualTo(7),
                  reason:
                      'both sides must reach FS within eight ordinary text/link messages');
            }
            final pendingApplications =
                (await ar.pendingMessageExports()).length +
                    (await br.pendingMessageExports()).length;
            expect(applicationSendCount, greaterThan(1));
            expect(pendingApplications, lessThan(applicationSendCount),
                reason:
                    'ordinary carriers must apply authenticated ACKs without technical-only exports');
            for (final (bridge, contact) in [(ab, bc), (bb, ac)]) {
              final restored = await bridge.pendingExportsForContact(
                  contact: contact,
                  carrierMode: mode,
                  coverText: 'Ci vediamo domani per parlare con calma. '
                      .padRight(360, 'a'));
              expect(
                  restored.map((export) => export.purpose),
                  everyElement(anyOf(V3ChatOutboundPurpose.application,
                      V3ChatOutboundPurpose.preFs)),
                  reason:
                      'bootstrap restore must not expose technical-only exports');
            }
            expect(
                await bb.loadPlaintext(initialRecordId!), 'Messaggio reale 0',
                reason: 'initial history remains readable after FS/restart');
            expect(await ab.loadPlaintext(initialRecordId), 'Messaggio reale 0',
                reason: 'sender history remains readable');
            for (final repository in [am, bm]) {
              final record = (await repository.getAllMessages())
                  .singleWhere((m) => m.id == initialRecordId);
              expect(record.isFsEncrypted, isFalse);
              expect(record.fsClassification, FsMessageClassification.preFs,
                  reason:
                      'initial message must remain gray after FS activation');
            }
            if (adverse) {
              bm.failNextDelete = true;
              await expectLater(
                br.markProjectedMessageRead(
                    messagesRepository: bm,
                    messageRecordId: initialRecordId,
                    keyTag: 'b'),
                throwsA(isA<StateError>()),
              );
              await br.close();
              br = await V3ApplicationSessionRuntime.open(
                  localIdentity: b,
                  scopeToken: 'independent-b-01',
                  sckaBackend: _InitialSckaBackend());
              bb = V3ApplicationChatBridge(
                  runtime: br, messagesRepository: bm, keyTag: 'b');
            } else {
              await br.markProjectedMessageRead(
                  messagesRepository: bm,
                  messageRecordId: initialRecordId,
                  keyTag: 'b');
            }
            expect(await bb.loadPlaintext(initialRecordId), isNull,
                reason:
                    'preFS read-once must honor the same durable presentation policy');
            await br.reconcileMessageRepository(
                messagesRepository: bm, keyTag: 'b');
            expect(await bb.loadPlaintext(initialRecordId), isNull,
                reason:
                    'reconciliation must not resurrect read-once preFS plaintext');
            final afterReadReplay = await bb.receiveCarrier(
                carrier: initialCarrier!,
                contacts: [ac],
                modeForContact: bb.modeForContact,
                eligibilityForContact: bb.eligibilityForContact,
                ensureEligibilityForContact: bb.ensureContactPolicy);
            expect(
                afterReadReplay.status, isNot(V3ChatInboundStatus.delivered));
            expect(await bb.loadPlaintext(initialRecordId), isNull,
                reason:
                    'reimport must not resurrect read-once preFS plaintext');
          } finally {
            am.dispose();
            bm.dispose();
            await ar.close();
            await br.close();
            await a.close();
            await b.close();
            await Hive.close();
            await temp.delete(recursive: true);
          }
        }, timeout: const Timeout(Duration(minutes: 3)));
      }
    }
  }

  for (final mixedCarrierMode in V3ChatCarrierMode.values) {
    test(
        'two same-identity devices negotiate while both shields are orange in ${mixedCarrierMode.name}',
        () async {
      final temp =
          await Directory.systemTemp.createTemp('lg_parallel_devices_');
      Hive.init(temp.path);
      await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
      final factory = V3LocalIdentityFactory(
        seedService: SeedService(),
        mlKem768Backend: _HandshakeMlKemBackend(),
      );
      final alice = await factory.restorePrimary(
          mnemonic:
              'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
      final bob = await factory.restorePrimary(
          mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');
      final scopes = [
        base64UrlEncode(_testBytes(12, 111)).replaceAll('=', ''),
        base64UrlEncode(_testBytes(12, 131)).replaceAll('=', ''),
        base64UrlEncode(_testBytes(12, 151)).replaceAll('=', ''),
      ];
      final runtimes = <V3ApplicationSessionRuntime>[
        await V3ApplicationSessionRuntime.open(
            localIdentity: alice,
            scopeToken: scopes[0],
            sckaBackend: _InitialSckaBackend()),
        await V3ApplicationSessionRuntime.open(
            localIdentity: alice,
            scopeToken: scopes[1],
            sckaBackend: _InitialSckaBackend()),
        await V3ApplicationSessionRuntime.open(
            localIdentity: bob,
            scopeToken: scopes[2],
            sckaBackend: _InitialSckaBackend()),
      ];
      final repositories = <MessagesRepository>[
        MessagesRepository(),
        MessagesRepository(),
        MessagesRepository(),
      ];
      for (var i = 0; i < repositories.length; i++) {
        await repositories[i].setActiveContext(
            scopeToken: scopes[i],
            storageKey: SecretKey(_testBytes(32, 40 + i)));
      }
      final bridges = <V3ApplicationChatBridge>[
        for (var i = 0; i < runtimes.length; i++)
          V3ApplicationChatBridge(
              runtime: runtimes[i],
              messagesRepository: repositories[i],
              keyTag: 'parallel-$i'),
      ];
      final aliceContact = V3IdentityAdapter.toRemoteIdentity(
          alice.publicIdentity,
          verified: true);
      final bobContact = V3IdentityAdapter.toRemoteIdentity(bob.publicIdentity,
          verified: true);
      final responseQueue = V3PendingResponseQueue();
      try {
        expect(runtimes[0].localDeviceId, isNot(runtimes[1].localDeviceId));
        for (final bridge in bridges.take(2)) {
          await bridge.ensureContactPolicy(bobContact, V3HandshakeMode.normal);
        }
        await bridges[2]
            .ensureContactPolicy(aliceContact, V3HandshakeMode.normal);

        for (var i = 0; i < 2; i++) {
          final outbound = await bridges[i].prepareOutbound(
              contact: bobContact,
              mode: V3HandshakeMode.normal,
              carrierMode: V3ChatCarrierMode.text,
              text: 'first message from device $i',
              timestampUnixSeconds: 100 + i,
              eligibilityPolicy: bridges[i].eligibilityForContact(bobContact),
              eligibilityForContact: bridges[i].eligibilityForContact);
          final inbound = await bridges[2].receiveCarrier(
              carrier: outbound.bundledText,
              contacts: [aliceContact],
              modeForContact: bridges[2].modeForContact,
              eligibilityForContact: bridges[2].eligibilityForContact,
              ensureEligibilityForContact: bridges[2].ensureContactPolicy);
          expect(inbound.status, V3ChatInboundStatus.delivered);
          expect(inbound.payload?.text, 'first message from device $i');
          responseQueue.addAll(aliceContact.identityId, inbound.responses);
        }
        expect(
            await runtimes[2].sessionsForRemoteIdentity(alice.publicIdentity),
            isEmpty);
        final parallel = await runtimes[2].pendingHandshakesForRemoteIdentity(
            remoteIdentity: alice.publicIdentity, mode: V3HandshakeMode.normal);
        expect(parallel.map((item) => item.handshakeId).toSet(), hasLength(2));
        expect({
          responseQueue.take(aliceContact.identityId)?.handshakeId,
          responseQueue.take(aliceContact.identityId)?.handshakeId,
        }, parallel.map((item) => item.handshakeId).toSet(),
            reason: 'both device replies must survive in the UI queue');
        expect(responseQueue.take(aliceContact.identityId), isNull);
        expect(
            (await bridges[2].securityStatus(
                    contact: aliceContact,
                    selectedMode: V3HandshakeMode.normal,
                    eligibilityPolicy:
                        bridges[2].eligibilityForContact(aliceContact)))
                .isActive,
            isFalse);

        final confirmedIds = <String>{};
        var mixedSends = 0;
        for (var turn = 0; turn < 64 && confirmedIds.length < 2; turn++) {
          final activeBefore =
              await runtimes[2].sessionsForRemoteIdentity(alice.publicIdentity);
          final carrierMode =
              activeBefore.isEmpty ? V3ChatCarrierMode.text : mixedCarrierMode;
          final coverText = carrierMode == V3ChatCarrierMode.steganography
              ? 'Ci vediamo domani e ne parliamo con calma. '
                  .padRight(900 + (turn.isOdd ? 120 : 0), 'a')
              : '';
          final outbound = await bridges[2].prepareOutbound(
              contact: aliceContact,
              mode: V3HandshakeMode.normal,
              carrierMode: carrierMode,
              text: 'reply while both are orange $turn',
              coverText: coverText,
              timestampUnixSeconds: 200 + turn,
              eligibilityPolicy: bridges[2].eligibilityForContact(aliceContact),
              eligibilityForContact: bridges[2].eligibilityForContact);
          expect(outbound.carriesPreFs, isTrue);
          expect(outbound.parts, hasLength(1),
              reason: 'one ordinary message must require exactly one copy');
          if (activeBefore.isEmpty) {
            expect(outbound.purpose, V3ChatOutboundPurpose.preFs);
          } else {
            final mixedStatus = await bridges[2].securityStatus(
                contact: aliceContact,
                selectedMode: V3HandshakeMode.normal,
                eligibilityPolicy:
                    bridges[2].eligibilityForContact(aliceContact));
            expect(mixedStatus.phase, V3ChatContactSecurityPhase.setupPending);
            expect(mixedStatus.activeSessionCount, greaterThan(0));
            expect(outbound.purpose, V3ChatOutboundPurpose.preFs);
            mixedSends++;
            if (mixedSends == 1) {
              final restored = await bridges[2].pendingExportsForContact(
                  contact: aliceContact,
                  carrierMode: carrierMode,
                  coverText: coverText);
              final mixedRetry = restored.singleWhere((candidate) =>
                  candidate.purpose == V3ChatOutboundPurpose.preFs &&
                  candidate.preFsMetadata?.messageId ==
                      outbound.preFsMetadata?.messageId);
              expect(mixedRetry.carriesPreFs, isTrue);
              if (carrierMode == V3ChatCarrierMode.steganography) {
                expect(V3PreFsTransport.decodeStego(mixedRetry.parts.first),
                    V3PreFsTransport.decodeStego(outbound.parts.first),
                    reason: 'restart retry keeps the sealed preFs envelope');
              } else {
                expect(mixedRetry.parts.first, outbound.parts.first,
                    reason:
                        'restart retry keeps the sealed identity-wide bytes');
              }
              expect(mixedRetry.parts, hasLength(1),
                  reason: 'restart must not restore a second copy step');
              if (carrierMode == V3ChatCarrierMode.text) {
                final token = outbound.parts.first.split('\n').first;
                final tampered =
                    base64Url.decode(base64Url.normalize(token.substring(3)));
                tampered[6] ^=
                    V3PreFsEnvelopeCodec.identityWideNormalFallbackFlag;
                final rejected = await bridges[1].receiveCarrier(
                    carrier: V3PreFsTransport.encodeText(tampered),
                    contacts: [bobContact],
                    modeForContact: bridges[1].modeForContact,
                    eligibilityForContact: bridges[1].eligibilityForContact,
                    ensureEligibilityForContact:
                        bridges[1].ensureContactPolicy);
                expect(rejected.status, V3ChatInboundStatus.invalid,
                    reason: 'a modified identity-wide flag must fail AEAD');
              }
            }
          }
          final confirmations = <V3ChatOutboundExport>[];
          for (var deviceIndex = 0; deviceIndex < 2; deviceIndex++) {
            final bridge = bridges[deviceIndex];
            final delivered = <String>[];
            for (final part in outbound.parts) {
              final inbound = await bridge.receiveCarrier(
                  carrier: part,
                  contacts: [bobContact],
                  modeForContact: bridge.modeForContact,
                  eligibilityForContact: bridge.eligibilityForContact,
                  ensureEligibilityForContact: bridge.ensureContactPolicy);
              if (inbound.status == V3ChatInboundStatus.delivered) {
                delivered.add(inbound.payload!.text);
              }
              confirmations.addAll(inbound.responses.where((response) =>
                  response.purpose == V3ChatOutboundPurpose.handshake));
            }
            expect(delivered, ['reply while both are orange $turn']);
          }
          if (activeBefore.isNotEmpty) {
            final messageId = 'v3m:${outbound.preFsMetadata!.messageId}';
            for (final repository in repositories) {
              final matching = (await repository.getAllMessages())
                  .where((record) => record.id == messageId)
                  .toList(growable: false);
              expect(matching, hasLength(1));
              expect(matching.single.fsClassification,
                  FsMessageClassification.preFs,
                  reason: 'a mixed delivery must carry the weakest shield');
            }
          }
          for (final confirmation in confirmations) {
            if (!confirmedIds.add(confirmation.handshakeId!)) continue;
            for (final part in confirmation.parts) {
              await bridges[2].receiveCarrier(
                  carrier: part,
                  contacts: [aliceContact],
                  modeForContact: bridges[2].modeForContact,
                  eligibilityForContact: bridges[2].eligibilityForContact,
                  ensureEligibilityForContact: bridges[2].ensureContactPolicy);
            }
          }
        }
        expect(confirmedIds, parallel.map((item) => item.handshakeId).toSet());
        expect(mixedSends, greaterThan(0),
            reason: 'one device must remain readable after it turns green');
        final established =
            await runtimes[2].sessionsForRemoteIdentity(alice.publicIdentity);
        expect(established.map((item) => item.remoteDeviceId).toSet(),
            hasLength(2));
        expect(
            (await bridges[2].securityStatus(
                    contact: aliceContact,
                    selectedMode: V3HandshakeMode.normal,
                    eligibilityPolicy:
                        bridges[2].eligibilityForContact(aliceContact)))
                .isActive,
            isTrue);
        final reply = await bridges[2].prepareOutbound(
            contact: aliceContact,
            mode: V3HandshakeMode.normal,
            carrierMode: mixedCarrierMode,
            coverText: mixedCarrierMode == V3ChatCarrierMode.steganography
                ? 'Un messaggio unico per entrambi i dispositivi. '
                    .padRight(1250, 'a')
                : '',
            text: 'both installations after green',
            eligibilityPolicy: bridges[2].eligibilityForContact(aliceContact),
            eligibilityForContact: bridges[2].eligibilityForContact);
        expect(
            reply.purpose,
            mixedCarrierMode == V3ChatCarrierMode.steganography
                ? V3ChatOutboundPurpose.preFs
                : V3ChatOutboundPurpose.application);
        expect(reply.parts, hasLength(1),
            reason: 'even after both sessions turn green there is one copy');
        expect(reply.carriesPreFs,
            mixedCarrierMode == V3ChatCarrierMode.steganography,
            reason: 'the message security class is independent of chat green');
        for (final bridge in bridges.take(2)) {
          final delivered = <String>[];
          for (final part in reply.parts) {
            final inbound = await bridge.receiveCarrier(
                carrier: part,
                contacts: [bobContact],
                modeForContact: bridge.modeForContact,
                eligibilityForContact: bridge.eligibilityForContact,
                ensureEligibilityForContact: bridge.ensureContactPolicy);
            if (inbound.status == V3ChatInboundStatus.delivered) {
              expect(inbound.preFs == null,
                  mixedCarrierMode != V3ChatCarrierMode.steganography,
                  reason: 'FS messages and gray identity-only fallback differ');
              delivered.add(inbound.payload!.text);
            }
          }
          expect(delivered, ['both installations after green']);
        }
        if (mixedCarrierMode != V3ChatCarrierMode.steganography) {
          final longText =
              'Messaggio leggibile su entrambi. '.padRight(700, 'x');
          final longReply = await bridges[2].prepareOutbound(
              contact: aliceContact,
              mode: V3HandshakeMode.normal,
              carrierMode: mixedCarrierMode,
              text: longText,
              eligibilityPolicy: bridges[2].eligibilityForContact(aliceContact),
              eligibilityForContact: bridges[2].eligibilityForContact);
          expect(longReply.parts, hasLength(1),
              reason: 'a larger ordinary message cannot become any fraction');
          expect(longReply.purpose, V3ChatOutboundPurpose.preFs,
              reason: 'capacity fallback happens before a ratchet send');
          expect(longReply.carriesPreFs, isTrue,
              reason: 'the larger single carrier must remain labeled gray');
          for (final bridge in bridges.take(2)) {
            final inbound = await bridge.receiveCarrier(
                carrier: longReply.parts.single,
                contacts: [bobContact],
                modeForContact: bridge.modeForContact,
                eligibilityForContact: bridge.eligibilityForContact,
                ensureEligibilityForContact: bridge.ensureContactPolicy);
            expect(inbound.status, V3ChatInboundStatus.delivered);
            expect(inbound.preFs, isNotNull,
                reason: 'recipient must retain the non-PQ classification');
            expect(inbound.payload?.text, longText);
          }
          expect(
              (await bridges[2].securityStatus(
                      contact: aliceContact,
                      selectedMode: V3HandshakeMode.normal,
                      eligibilityPolicy:
                          bridges[2].eligibilityForContact(aliceContact)))
                  .activeSessionCount,
              2,
              reason: 'the gray fallback must retain both PQ FS sessions');
        }
      } finally {
        for (final repository in repositories) {
          repository.dispose();
        }
        for (final runtime in runtimes) {
          await runtime.close();
        }
        await alice.close();
        await bob.close();
        await Hive.close();
        await temp.delete(recursive: true);
      }
    }, timeout: const Timeout(Duration(minutes: 3)));
  }

  test('a second device starts readable Normal FS without replacing the first',
      () async {
    final temp = await Directory.systemTemp.createTemp('lg_multi_device_');
    final firstScope = base64UrlEncode(_testBytes(12, 11)).replaceAll('=', '');
    final secondScope = base64UrlEncode(_testBytes(12, 31)).replaceAll('=', '');
    final receiverScope =
        base64UrlEncode(_testBytes(12, 51)).replaceAll('=', '');
    Hive.init(temp.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: _HandshakeMlKemBackend(),
    );
    final alice = await factory.restorePrimary(
        mnemonic:
            'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
    final bob = await factory.restorePrimary(
        mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');
    final first = await V3ApplicationSessionRuntime.open(
        localIdentity: alice,
        scopeToken: firstScope,
        sckaBackend: _InitialSckaBackend());
    final second = await V3ApplicationSessionRuntime.open(
        localIdentity: alice,
        scopeToken: secondScope,
        sckaBackend: _InitialSckaBackend());
    final receiver = await V3ApplicationSessionRuntime.open(
        localIdentity: bob,
        scopeToken: receiverScope,
        sckaBackend: _InitialSckaBackend());
    final firstMessages = MessagesRepository();
    final secondMessages = MessagesRepository();
    final receiverMessages = MessagesRepository();
    await firstMessages.setActiveContext(
        scopeToken: firstScope, storageKey: SecretKey(_testBytes(32, 21)));
    await secondMessages.setActiveContext(
        scopeToken: secondScope, storageKey: SecretKey(_testBytes(32, 31)));
    await receiverMessages.setActiveContext(
        scopeToken: receiverScope, storageKey: SecretKey(_testBytes(32, 41)));
    final firstBridge = V3ApplicationChatBridge(
        runtime: first, messagesRepository: firstMessages, keyTag: 'first');
    final secondBridge = V3ApplicationChatBridge(
        runtime: second, messagesRepository: secondMessages, keyTag: 'second');
    final receiverBridge = V3ApplicationChatBridge(
        runtime: receiver,
        messagesRepository: receiverMessages,
        keyTag: 'receiver');
    final aliceContact = V3IdentityAdapter.toRemoteIdentity(
        alice.publicIdentity,
        verified: true);
    final bobContact =
        V3IdentityAdapter.toRemoteIdentity(bob.publicIdentity, verified: true);
    try {
      expect(first.localDeviceId, isNot(second.localDeviceId));
      await firstBridge.ensureContactPolicy(bobContact, V3HandshakeMode.normal);
      await secondBridge.ensureContactPolicy(
          bobContact, V3HandshakeMode.normal);
      await receiverBridge.ensureContactPolicy(
          aliceContact, V3HandshakeMode.normal);
      for (var turn = 0; turn < 12; turn++) {
        final fromFirst = turn.isEven;
        final sender = fromFirst ? firstBridge : receiverBridge;
        final target = fromFirst ? bobContact : aliceContact;
        final recipient = fromFirst ? receiverBridge : firstBridge;
        final source = fromFirst ? aliceContact : bobContact;
        final outbound = await sender.prepareOutbound(
            contact: target,
            mode: V3HandshakeMode.normal,
            carrierMode: V3ChatCarrierMode.text,
            text: 'first-device-$turn',
            timestampUnixSeconds: 100 + turn,
            eligibilityPolicy: sender.eligibilityForContact(target),
            eligibilityForContact: sender.eligibilityForContact);
        final inbound = await recipient.receiveCarrier(
            carrier: outbound.bundledText,
            contacts: [source],
            modeForContact: recipient.modeForContact,
            eligibilityForContact: recipient.eligibilityForContact,
            ensureEligibilityForContact: recipient.ensureContactPolicy);
        expect(inbound.status, V3ChatInboundStatus.delivered);
        final firstStatus = await firstBridge.securityStatus(
            contact: bobContact,
            selectedMode: V3HandshakeMode.normal,
            eligibilityPolicy: firstBridge.eligibilityForContact(bobContact));
        final receiverStatus = await receiverBridge.securityStatus(
            contact: aliceContact,
            selectedMode: V3HandshakeMode.normal,
            eligibilityPolicy:
                receiverBridge.eligibilityForContact(aliceContact));
        if (firstStatus.isActive && receiverStatus.isActive) break;
      }
      final firstSessions =
          await receiver.sessionsForRemoteIdentity(alice.publicIdentity);
      expect(firstSessions, hasLength(1));
      expect(
          (await receiverBridge.securityStatus(
                  contact: aliceContact,
                  selectedMode: V3HandshakeMode.normal,
                  eligibilityPolicy:
                      receiverBridge.eligibilityForContact(aliceContact)))
              .isActive,
          isTrue);

      final contactDigest = base64UrlEncode(
              V3PreFsEnvelopeCodec.identityDigest(alice.publicIdentity))
          .replaceAll('=', '');
      await receiver.preFsPendingStore.markPeerFsReady(
          contactDigest: contactDigest,
          handshakeId: firstSessions.single.handshakeId,
          preFsFenceUnixSeconds: 200);
      final contextId = V3PreFsEnvelopeCodec.deriveContextId(
          localIdentity: alice.publicIdentity,
          remoteIdentity: bob.publicIdentity);
      for (final (deviceId, label) in [
        (first.localDeviceId, 'same device'),
        (null, 'legacy ambiguous device'),
      ]) {
        final sealed = await V3PreFsEnvelopeCodec.seal(
            localIdentity: alice,
            remoteIdentity: bob.publicIdentity,
            senderDeviceId: deviceId,
            kind: V3PreFsEnvelopeKind.data,
            messageId: _testBytes(16, label.length),
            contextId: contextId,
            fragmentIndex: 0,
            fragmentCount: 1,
            plaintext: Uint8List.fromList([1]),
            timestampUnixSeconds: 1000);
        final rejected = await receiverBridge.receiveCarrier(
            carrier: V3PreFsTransport.encodeText(sealed),
            contacts: [aliceContact],
            modeForContact: receiverBridge.modeForContact,
            eligibilityForContact: receiverBridge.eligibilityForContact,
            ensureEligibilityForContact: receiverBridge.ensureContactPolicy);
        expect(rejected.status, V3ChatInboundStatus.invalid,
            reason: '$label must not bypass the established-device fence');
      }

      final fromSecond = await secondBridge.prepareOutbound(
          contact: bobContact,
          mode: V3HandshakeMode.normal,
          carrierMode: V3ChatCarrierMode.text,
          text: 'hello from the other device',
          timestampUnixSeconds: 1000,
          eligibilityPolicy: secondBridge.eligibilityForContact(bobContact),
          eligibilityForContact: secondBridge.eligibilityForContact);
      expect(fromSecond.purpose, V3ChatOutboundPurpose.preFs);
      final token = fromSecond.parts.single.split('\n').first;
      final envelope = await V3PreFsEnvelopeCodec.open(
          localIdentity: bob,
          remoteIdentity: alice.publicIdentity,
          encoded: base64Url.decode(base64Url.normalize(token.substring(3))));
      expect(envelope.formatVersion, V3PreFsEnvelopeCodec.formatVersion);
      expect(envelope.senderDeviceId, second.localDeviceId);
      final originalLines = fromSecond.parts.single.split('\n');
      expect(originalLines.length, greaterThan(1));
      final legacyEnvelope = await V3PreFsEnvelopeCodec.seal(
          localIdentity: alice,
          remoteIdentity: bob.publicIdentity,
          kind: V3PreFsEnvelopeKind.data,
          messageId: envelope.messageId,
          contextId: envelope.contextId,
          fragmentIndex: 0,
          fragmentCount: 1,
          plaintext: envelope.plaintext,
          timestampUnixSeconds: envelope.timestampUnixSeconds);
      final legacyCarrier = <String>[
        V3PreFsTransport.encodeText(legacyEnvelope),
        ...originalLines.skip(1),
      ].join('\n');
      final received = await receiverBridge.receiveCarrier(
          carrier: legacyCarrier,
          contacts: [aliceContact],
          modeForContact: receiverBridge.modeForContact,
          eligibilityForContact: receiverBridge.eligibilityForContact,
          ensureEligibilityForContact: receiverBridge.ensureContactPolicy);
      expect(received.status, V3ChatInboundStatus.delivered);
      expect(received.payload?.text, 'hello from the other device');
      expect(received.responses, isNotEmpty,
          reason: 'the new device must receive its own FS negotiation');
      final migratedReplay = await receiverBridge.receiveCarrier(
          carrier: token,
          contacts: [aliceContact],
          modeForContact: receiverBridge.modeForContact,
          eligibilityForContact: receiverBridge.eligibilityForContact,
          ensureEligibilityForContact: receiverBridge.ensureContactPolicy);
      expect(migratedReplay.status, V3ChatInboundStatus.committedReplay,
          reason: 'the original and migrated carrier are one logical message');
      final freshV2 = await secondBridge.prepareOutbound(
          contact: bobContact,
          mode: V3HandshakeMode.normal,
          carrierMode: V3ChatCarrierMode.text,
          text: 'new envelope from the second device',
          timestampUnixSeconds: 1001,
          eligibilityPolicy: secondBridge.eligibilityForContact(bobContact),
          eligibilityForContact: secondBridge.eligibilityForContact);
      final freshReceived = await receiverBridge.receiveCarrier(
          carrier: freshV2.bundledText,
          contacts: [aliceContact],
          modeForContact: receiverBridge.modeForContact,
          eligibilityForContact: receiverBridge.eligibilityForContact,
          ensureEligibilityForContact: receiverBridge.ensureContactPolicy);
      expect(freshReceived.status, V3ChatInboundStatus.delivered);
      expect(
          freshReceived.payload?.text, 'new envelope from the second device');
      expect(await receiver.sessionsForRemoteIdentity(alice.publicIdentity),
          hasLength(1),
          reason: 'the first device session must remain live during setup');
      final mixedStatus = await receiverBridge.securityStatus(
          contact: aliceContact,
          selectedMode: V3HandshakeMode.normal,
          eligibilityPolicy:
              receiverBridge.eligibilityForContact(aliceContact));
      expect(mixedStatus.phase, V3ChatContactSecurityPhase.setupPending);
      expect(mixedStatus.activeSessionCount, 1,
          reason: 'the original FS session remains active during setup');

      final secondHandshakeResponse = await secondBridge.receiveCarrier(
          carrier: received.responses.first.bundledText,
          contacts: [bobContact],
          modeForContact: secondBridge.modeForContact,
          eligibilityForContact: secondBridge.eligibilityForContact,
          ensureEligibilityForContact: secondBridge.ensureContactPolicy);
      expect(secondHandshakeResponse.responses, isNotEmpty);
      await receiverBridge.receiveCarrier(
          carrier: secondHandshakeResponse.responses.first.bundledText,
          contacts: [aliceContact],
          modeForContact: receiverBridge.modeForContact,
          eligibilityForContact: receiverBridge.eligibilityForContact,
          ensureEligibilityForContact: receiverBridge.ensureContactPolicy);
      final bothSessions =
          await receiver.sessionsForRemoteIdentity(alice.publicIdentity);
      expect(bothSessions, hasLength(2));
      expect(bothSessions.map((session) => session.remoteDeviceId).toSet(),
          hasLength(2));
      expect(bothSessions.map((session) => session.sessionId),
          contains(firstSessions.single.sessionId));

      final replyToBoth = await receiverBridge.prepareOutbound(
          contact: aliceContact,
          mode: V3HandshakeMode.normal,
          carrierMode: V3ChatCarrierMode.text,
          text: 'both installations receive this',
          eligibilityPolicy: receiverBridge.eligibilityForContact(aliceContact),
          eligibilityForContact: receiverBridge.eligibilityForContact);
      expect(replyToBoth.purpose, V3ChatOutboundPurpose.application);
      for (final (bridge, label) in [
        (firstBridge, 'first'),
        (secondBridge, 'second'),
      ]) {
        final delivered = <String>[];
        for (final part in replyToBoth.parts) {
          final inbound = await bridge.receiveCarrier(
              carrier: part,
              contacts: [bobContact],
              modeForContact: bridge.modeForContact,
              eligibilityForContact: bridge.eligibilityForContact,
              ensureEligibilityForContact: bridge.ensureContactPolicy);
          if (inbound.status == V3ChatInboundStatus.delivered) {
            delivered.add(inbound.payload!.text);
          }
        }
        expect(delivered, ['both installations receive this'],
            reason: '$label device gets one copy');
      }
      await receiverBridge.setContactSecurityMode(
          aliceContact, FsSecurityMode.strict);
      final strictRejected = await receiverBridge.receiveCarrier(
          carrier: freshV2.parts.single.split('\n').first,
          contacts: [aliceContact],
          modeForContact: receiverBridge.modeForContact,
          eligibilityForContact: receiverBridge.eligibilityForContact,
          ensureEligibilityForContact: receiverBridge.ensureContactPolicy);
      expect(strictRejected.status, V3ChatInboundStatus.invalid,
          reason: 'Maximum must never accept identity-only pre-session text');
    } finally {
      firstMessages.dispose();
      secondMessages.dispose();
      receiverMessages.dispose();
      await first.close();
      await second.close();
      await receiver.close();
      await alice.close();
      await bob.close();
      await Hive.close();
      await temp.delete(recursive: true);
    }
  }, timeout: const Timeout(Duration(minutes: 3)));
}

class _FaultInjectingMessagesRepository extends MessagesRepository {
  bool failNextDelete = false;

  @override
  Future<void> delete(String id) async {
    if (failNextDelete) {
      failNextDelete = false;
      throw StateError('injected interruption before metadata deletion');
    }
    await super.delete(id);
  }
}

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

final class _HandshakeMlKemBackend implements MlKem768Backend {
  int _encapsulationCounter = 0;

  @override
  String get implementationId => 'application-runtime-test-ml-kem';

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
      privateKeyHandle: _MlKemPrivateKeyHandle(
        Uint8List.fromList(publicKey),
      ),
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
          ...'application-runtime-test-shared\x00'.codeUnits,
          ...publicKey,
          ...ciphertext,
        ]).bytes,
      );
}

final class _InitialSckaBackend implements V3SckaBackend {
  @override
  String get implementationId => 'layergram-application-runtime-test-scka/1';

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

Uint8List _testBytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
