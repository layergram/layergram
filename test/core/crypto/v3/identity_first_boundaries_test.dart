import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
import 'package:layergram/core/crypto/v3/application_chat_bridge_v3.dart';
import 'package:layergram/core/crypto/v3/application_session_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/prefs_bootstrap_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/chat_meta_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';
import 'package:layergram/core/utils/clipboard_service.dart';
import 'package:layergram/features/home/chat_view.dart';
import 'package:layergram/features/home/home_controller.dart';
import 'package:layergram/features/home/message_output_mode.dart';
import 'package:layergram/utils/sharing.dart';
import 'package:share_plus/share_plus.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final size in <Size>[const Size(390, 844), const Size(1200, 800)]) {
    for (final mode in <MessageOutputMode>[
      MessageOutputMode.text,
      MessageOutputMode.cover,
    ]) {
      for (final established in <bool>[false, true]) {
        testWidgets(
          'Normal ${mode.name} ${size.width.toInt()} ${established ? "FS" : "first"} copy then share reuses message',
          (tester) async {
            const firstText = 'First user message';
            const nextText = 'Next user message';
            final cover = 'A' *
                (4000 -
                    StegoEncoder.minimumHiddenLengthForBytes(
                      V3LmfFrameCodec.maxPortableStegoFrameBytes,
                    ));
            final prepared = await tester.runAsync(
              () => _withFixture((fixture) async {
                if (established) await _establishBoundaryFs(fixture);
                final exports = <V3ChatOutboundExport>[];
                for (final text in <String>[firstText, nextText]) {
                  final export = await fixture.aliceBridge.prepareOutbound(
                    contact: fixture.bobContact,
                    mode: V3HandshakeMode.normal,
                    carrierMode: mode == MessageOutputMode.cover
                        ? V3ChatCarrierMode.steganography
                        : V3ChatCarrierMode.text,
                    text: text,
                    coverText: cover,
                    eligibilityPolicy:
                        fixture.aliceBridge.eligibilityForContact(
                      fixture.bobContact,
                    ),
                    maxCarrierCharacters: 4000,
                  );
                  expect(
                      export.purpose,
                      established
                          ? V3ChatOutboundPurpose.application
                          : V3ChatOutboundPurpose.preFs);
                  expect(export.parts, hasLength(1));
                  final received = await fixture.bobBridge.receiveCarrier(
                    carrier: export.parts.single,
                    contacts: [fixture.aliceContact],
                    modeForContact: fixture.bobBridge.modeForContact,
                    eligibilityForContact:
                        fixture.bobBridge.eligibilityForContact,
                    ensureEligibilityForContact:
                        fixture.bobBridge.ensureContactPolicy,
                  );
                  expect(received.status, V3ChatInboundStatus.delivered);
                  expect(received.payload?.text, text);
                  exports.add(export);
                }
                return (contact: fixture.bobContact, exports: exports);
              }),
            );
            final uiDirectory = await tester.runAsync(() async {
              final directory =
                  await Directory.systemTemp.createTemp('lg_export_ui_');
              Hive.init(directory.path);
              await Hive.openBox<Map>(LocalDatabase.chatMetaBoxName);
              await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
              return directory;
            });
            addTearDown(() async {
              await Hive.close();
              await uiDirectory!.delete(recursive: true);
            });
            final clipboard = _BoundaryClipboard();
            final shared = <String>[];
            late _BoundaryExportController controller;
            tester.view.devicePixelRatio = 1;
            tester.view.physicalSize = size;
            addTearDown(() {
              tester.view.resetDevicePixelRatio();
              tester.view.resetPhysicalSize();
            });
            await tester.pumpWidget(
              ProviderScope(
                overrides: [
                  protocolV3MessagingEnabledProvider.overrideWithValue(true),
                  chatMetaRepositoryProvider.overrideWithValue(
                    _BoundaryChatMeta(),
                  ),
                  messagesRepositoryProvider.overrideWithValue(
                    _BoundaryEmptyMessages(),
                  ),
                  homeControllerProvider.overrideWith(
                    (ref) => controller = _BoundaryExportController(
                      ref,
                      prepared!.exports,
                    ),
                  ),
                  clipboardServiceProvider.overrideWithValue(clipboard),
                  externalTextShareProvider.overrideWithValue((
                    context,
                    text, {
                    required bool forceStegoCover,
                  }) async {
                    expect(forceStegoCover, mode == MessageOutputMode.cover);
                    shared.add(text);
                    return const ShareResult('', ShareResultStatus.success);
                  }),
                ],
                child: MaterialApp(
                  home: ChatView(
                    contact: prepared!.contact,
                    embedded: true,
                    initialOutputMode: mode,
                    initialCover:
                        mode == MessageOutputMode.cover ? cover : null,
                    initialSecret: firstText,
                  ),
                ),
              ),
            );
            await tester.pumpAndSettle();
            final secret = find.byType(TextField).last;
            await tester.tap(find.byIcon(Icons.copy_outlined).last);
            await tester.pumpAndSettle();
            expect(clipboard.value, prepared.exports.first.parts.single);
            expect(tester.widget<TextField>(secret).controller!.text, isEmpty);
            await tester.tap(find.byIcon(Icons.ios_share_outlined).last);
            await tester.pumpAndSettle();
            expect(shared, <String>[clipboard.value!]);
            expect(controller.preparations, 1);

            // A new draft must invalidate the old output rather than resend it.
            await tester.enterText(secret, nextText);
            await tester.pumpAndSettle();
            await tester.tap(find.byIcon(Icons.copy_outlined).last);
            await tester.pumpAndSettle();
            expect(clipboard.value, prepared.exports.last.parts.single);
            expect(clipboard.value, isNot(shared.single));
            expect(controller.preparations, 2);
            await tester.tap(find.byIcon(Icons.ios_share_outlined).last);
            await tester.pumpAndSettle();
            expect(
                shared, prepared.exports.map((e) => e.parts.single).toList());
            expect(controller.preparations, 2);
            await tester.pumpWidget(const SizedBox.shrink());
          },
        );
      }
    }
  }

  test('first Normal stego message fits the AI cover budget and is visible',
      () async {
    await _withFixture((fixture) async {
      final hidden = StegoEncoder.minimumHiddenLengthForBytes(
        V3LmfFrameCodec.maxPortableStegoFrameBytes,
      );
      final cover = 'A' * (4000 - hidden);
      final export = await fixture.aliceBridge.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.normal,
        carrierMode: V3ChatCarrierMode.steganography,
        text: 'Ciao dal primo messaggio',
        coverText: cover,
        eligibilityPolicy:
            fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
        maxCarrierCharacters: 4000,
      );

      expect(export.purpose, V3ChatOutboundPurpose.preFs);
      expect(export.parts, hasLength(1));
      expect(export.parts.single.length, lessThanOrEqualTo(4000));
      final received = await fixture.bobBridge.receiveCarrier(
        carrier: export.parts.single,
        contacts: [fixture.aliceContact],
        modeForContact: fixture.bobBridge.modeForContact,
        eligibilityForContact: fixture.bobBridge.eligibilityForContact,
        ensureEligibilityForContact: fixture.bobBridge.ensureContactPolicy,
      );
      expect(received.status, V3ChatInboundStatus.delivered);
      expect(received.payload?.text, 'Ciao dal primo messaggio');
      expect(
        (await fixture.bobMessages.getAllMessages())
            .where((record) => record.direction == 'incoming'),
        hasLength(1),
      );
    });
  });

  test('an already-imported setup-only carrier does not block new first text',
      () async {
    await _withFixture((fixture) async {
      final cover = 'A' *
          (4000 -
              StegoEncoder.minimumHiddenLengthForBytes(
                V3LmfFrameCodec.maxPortableStegoFrameBytes,
              ));
      final oldBridge = V3ApplicationChatBridge(
        runtime: fixture.aliceRuntime,
        messagesRepository: fixture.aliceMessages,
        keyTag: 'alice',
        preFsBootstrapEnabled: false,
      );
      final oldExport = await oldBridge.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.normal,
        carrierMode: V3ChatCarrierMode.steganography,
        text: 'testo che la vecchia versione non trasportava',
        coverText: cover,
        eligibilityPolicy: oldBridge.eligibilityForContact(fixture.bobContact),
      );
      expect(oldExport.purpose, V3ChatOutboundPurpose.handshake);
      final oldInbound = await fixture.bobBridge.receiveCarrier(
        carrier: oldExport.parts.first,
        contacts: [fixture.aliceContact],
        modeForContact: fixture.bobBridge.modeForContact,
        eligibilityForContact: fixture.bobBridge.eligibilityForContact,
        ensureEligibilityForContact: fixture.bobBridge.ensureContactPolicy,
      );
      expect(oldInbound.status, isNot(V3ChatInboundStatus.delivered));
      expect(await fixture.bobMessages.getAllMessages(), isEmpty);

      final newExport = await fixture.aliceBridge.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.normal,
        carrierMode: V3ChatCarrierMode.steganography,
        text: 'Ciao, ora si legge',
        coverText: cover,
        eligibilityPolicy:
            fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
      );
      expect(newExport.purpose, V3ChatOutboundPurpose.preFs);
      final newInbound = await fixture.bobBridge.receiveCarrier(
        carrier: newExport.parts.single,
        contacts: [fixture.aliceContact],
        modeForContact: fixture.bobBridge.modeForContact,
        eligibilityForContact: fixture.bobBridge.eligibilityForContact,
        ensureEligibilityForContact: fixture.bobBridge.ensureContactPolicy,
      );
      expect(newInbound.status, V3ChatInboundStatus.delivered);
      expect(newInbound.payload?.text, 'Ciao, ora si legge');
      expect(
        (await fixture.bobMessages.getAllMessages())
            .where((record) => record.direction == 'incoming'),
        hasLength(1),
      );
    });
  });

  test('fresh Normal enforces configured text limit before mutation', () async {
    await _withFixture((fixture) async {
      final longText = List<String>.filled(3000, 'x').join();
      final beforePending = await fixture.aliceBridge.pendingExportsForContact(
        contact: fixture.bobContact,
        carrierMode: V3ChatCarrierMode.text,
        maxCarrierCharacters: 4000,
      );

      await expectLater(
        fixture.aliceBridge.prepareOutbound(
          contact: fixture.bobContact,
          mode: V3HandshakeMode.normal,
          carrierMode: V3ChatCarrierMode.text,
          text: longText,
          eligibilityPolicy:
              fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
          maxCarrierCharacters: 4000,
        ),
        throwsA(isA<V3ChatPreFsCapacityException>()),
      );
      expect(await fixture.aliceMessages.getAllMessages(), isEmpty);
      expect(
        await fixture.aliceBridge.pendingExportsForContact(
          contact: fixture.bobContact,
          carrierMode: V3ChatCarrierMode.text,
          maxCarrierCharacters: 4000,
        ),
        hasLength(beforePending.length),
      );

      final export = await fixture.aliceBridge.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.normal,
        carrierMode: V3ChatCarrierMode.text,
        text: longText,
        eligibilityPolicy:
            fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
        maxCarrierCharacters: null,
      );
      expect(export.purpose, V3ChatOutboundPurpose.preFs);
      expect(export.parts, hasLength(1));
      expect(export.parts.single, startsWith('p1.'));
      expect(export.parts.single.length, greaterThan(4000));

      final received = await fixture.bobBridge.receiveCarrier(
        carrier: export.parts.single,
        contacts: [fixture.aliceContact],
        modeForContact: fixture.bobBridge.modeForContact,
        eligibilityForContact: fixture.bobBridge.eligibilityForContact,
        ensureEligibilityForContact: fixture.bobBridge.ensureContactPolicy,
      );
      expect(received.status, V3ChatInboundStatus.delivered);
      expect(received.payload?.text, longText);
    });
  });

  test('fresh Normal stego honors configured and absolute limits', () async {
    await _withFixture((fixture) async {
      final cover = 'Visible cover '.padRight(6200, 'z');
      const text = 'authenticated identity-only stego payload';

      await expectLater(
        fixture.aliceBridge.prepareOutbound(
          contact: fixture.bobContact,
          mode: V3HandshakeMode.normal,
          carrierMode: V3ChatCarrierMode.steganography,
          text: text,
          coverText: cover,
          eligibilityPolicy:
              fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
          maxCarrierCharacters: 4000,
        ),
        throwsA(anyOf(
          isA<V3ChatPreFsCapacityException>(),
          isA<V3ChatCoverCapacityException>(),
        )),
      );
      expect(await fixture.aliceMessages.getAllMessages(), isEmpty);

      final export = await fixture.aliceBridge.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.normal,
        carrierMode: V3ChatCarrierMode.steganography,
        text: text,
        coverText: cover,
        eligibilityPolicy:
            fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
        maxCarrierCharacters: null,
      );
      expect(export.purpose, V3ChatOutboundPurpose.preFs);
      expect(export.parts, hasLength(1));
      expect(export.parts.single.length, greaterThan(4000));
      expect(export.parts.single.length, lessThanOrEqualTo(131072));

      final received = await fixture.bobBridge.receiveCarrier(
        carrier: export.parts.single,
        contacts: [fixture.aliceContact],
        modeForContact: fixture.bobBridge.modeForContact,
        eligibilityForContact: fixture.bobBridge.eligibilityForContact,
        ensureEligibilityForContact: fixture.bobBridge.ensureContactPolicy,
      );
      expect(received.status, V3ChatInboundStatus.delivered);
      expect(received.payload?.text, text);
    });
  });

  test('Maximum first send remains handshake-only with no user projection',
      () async {
    await _withFixture((fixture) async {
      await fixture.aliceBridge.setContactSecurityMode(
        fixture.bobContact,
        FsSecurityMode.strict,
      );
      final export = await fixture.aliceBridge.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.maximum,
        carrierMode: V3ChatCarrierMode.text,
        text: 'must not be carried before Maximum is active',
        eligibilityPolicy:
            fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
        maxCarrierCharacters: 4000,
      );
      expect(export.purpose, V3ChatOutboundPurpose.handshake);
      expect(await fixture.aliceMessages.getAllMessages(), isEmpty);
      expect(export.messageExport, isNull);
      expect(export.preFsMetadata, isNull);
    });
  });

  test('an established Normal session never falls back to pre-session data',
      () async {
    await _withFixture((fixture) async {
      var active = false;
      for (var turn = 0; turn < 64; turn++) {
        final aliceSends = turn.isEven;
        final sender = aliceSends ? fixture.aliceBridge : fixture.bobBridge;
        final receiver = aliceSends ? fixture.bobBridge : fixture.aliceBridge;
        final target = aliceSends ? fixture.bobContact : fixture.aliceContact;
        final source = aliceSends ? fixture.aliceContact : fixture.bobContact;
        final export = await sender.prepareOutbound(
          contact: target,
          mode: V3HandshakeMode.normal,
          carrierMode: V3ChatCarrierMode.text,
          text: 'ordinary setup message $turn',
          eligibilityPolicy: sender.eligibilityForContact(target),
        );
        expect(
          export.purpose,
          anyOf(
            V3ChatOutboundPurpose.preFs,
            V3ChatOutboundPurpose.application,
          ),
        );
        final received = await receiver.receiveCarrier(
          carrier: export.parts.single,
          contacts: [source],
          modeForContact: receiver.modeForContact,
          eligibilityForContact: receiver.eligibilityForContact,
          ensureEligibilityForContact: receiver.ensureContactPolicy,
        );
        expect(received.status, V3ChatInboundStatus.delivered);
        final aliceStatus = await fixture.aliceBridge.securityStatus(
          contact: fixture.bobContact,
          selectedMode: V3HandshakeMode.normal,
          eligibilityPolicy:
              fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
        );
        final bobStatus = await fixture.bobBridge.securityStatus(
          contact: fixture.aliceContact,
          selectedMode: V3HandshakeMode.normal,
          eligibilityPolicy:
              fixture.bobBridge.eligibilityForContact(fixture.aliceContact),
        );
        if (aliceStatus.isActive && bobStatus.isActive) {
          active = true;
          break;
        }
      }
      expect(active, isTrue);

      final afterActivation = await fixture.aliceBridge.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.normal,
        carrierMode: V3ChatCarrierMode.text,
        text: 'must stay on the established session',
        eligibilityPolicy:
            fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
      );
      expect(afterActivation.purpose, V3ChatOutboundPurpose.application);
    });
  });

  test('peer FS readiness and its first fence survive replay eviction',
      () async {
    const contactDigest = 'peer-contact-digest';
    const handshakeId = 'peer-handshake-id';
    final backingStore = _MemoryLmfRecordStore();
    var pending = V3PreFsPendingStore(
      store: backingStore,
      maxReplayEntries: 2,
    );
    await pending.restore();
    await pending.markPeerFsReady(
      contactDigest: contactDigest,
      handshakeId: handshakeId,
      preFsFenceUnixSeconds: 10,
    );

    for (var index = 0; index < 8; index++) {
      expect(
        await pending.noteInboundData(contactDigest, 'message-$index'),
        isTrue,
      );
    }
    expect(await pending.isPeerFsReady(contactDigest, handshakeId), isTrue);
    expect(await pending.preFsFenceFor(contactDigest, handshakeId), 10);

    await pending.markPeerFsReady(
      contactDigest: contactDigest,
      handshakeId: handshakeId,
      preFsFenceUnixSeconds: 99,
    );
    expect(await pending.preFsFenceFor(contactDigest, handshakeId), 10);

    await pending.close();
    pending = V3PreFsPendingStore(
      store: backingStore,
      maxReplayEntries: 2,
    );
    await pending.restore();
    expect(await pending.isPeerFsReady(contactDigest, handshakeId), isTrue);
    expect(await pending.preFsFenceFor(contactDigest, handshakeId), 10);
    await pending.close();

    final failingStore = _MemoryLmfRecordStore()..failNextWrite = true;
    final poisoned = V3PreFsPendingStore(store: failingStore);
    await poisoned.restore();
    await expectLater(
      poisoned.markPeerFsReady(
        contactDigest: contactDigest,
        handshakeId: handshakeId,
        preFsFenceUnixSeconds: 10,
      ),
      throwsStateError,
    );
    await expectLater(
      poisoned.isPeerFsReady(contactDigest, handshakeId),
      throwsStateError,
    );
    await poisoned.close();
  });

  test('a pre-upgrade established session stays FS on a default bridge',
      () async {
    await _withFixture((fixture) async {
      final legacyAlice = V3ApplicationChatBridge(
        runtime: fixture.aliceRuntime,
        messagesRepository: fixture.aliceMessages,
        keyTag: 'alice-legacy',
        preFsBootstrapEnabled: false,
      );
      final legacyBob = V3ApplicationChatBridge(
        runtime: fixture.bobRuntime,
        messagesRepository: fixture.bobMessages,
        keyTag: 'bob-legacy',
        preFsBootstrapEnabled: false,
      );
      final offer = await legacyAlice.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.normal,
        carrierMode: V3ChatCarrierMode.text,
        text: 'queued legacy application message',
        eligibilityPolicy: legacyAlice.eligibilityForContact(
          fixture.bobContact,
        ),
      );
      expect(offer.purpose, V3ChatOutboundPurpose.handshake);

      V3ChatInboundResult? receivedOffer;
      for (final part in offer.parts) {
        receivedOffer = await legacyBob.receiveCarrier(
          carrier: part,
          contacts: [fixture.aliceContact],
          modeForContact: legacyBob.modeForContact,
          eligibilityForContact: legacyBob.eligibilityForContact,
          ensureEligibilityForContact: legacyBob.ensureContactPolicy,
        );
      }
      expect(receivedOffer?.status, V3ChatInboundStatus.handshakeResponse);

      final receivedReply = await legacyAlice.receiveCarrier(
        carrier: receivedOffer!.response!.bundledText,
        contacts: [fixture.bobContact],
        modeForContact: legacyAlice.modeForContact,
        eligibilityForContact: legacyAlice.eligibilityForContact,
        ensureEligibilityForContact: legacyAlice.ensureContactPolicy,
      );
      expect(receivedReply.status, V3ChatInboundStatus.handshakeResponse);

      final receivedConfirmation = await legacyBob.receiveCarrier(
        carrier: receivedReply.response!.bundledText,
        contacts: [fixture.aliceContact],
        modeForContact: legacyBob.modeForContact,
        eligibilityForContact: legacyBob.eligibilityForContact,
        ensureEligibilityForContact: legacyBob.ensureContactPolicy,
      );
      expect(
        receivedConfirmation.status,
        V3ChatInboundStatus.sessionEstablished,
      );

      final upgradedAlice = V3ApplicationChatBridge(
        runtime: fixture.aliceRuntime,
        messagesRepository: fixture.aliceMessages,
        keyTag: 'alice-upgraded-default',
      );
      final status = await upgradedAlice.securityStatus(
        contact: fixture.bobContact,
        selectedMode: V3HandshakeMode.normal,
        eligibilityPolicy: upgradedAlice.eligibilityForContact(
          fixture.bobContact,
        ),
      );
      expect(status.isActive, isTrue);

      final application = await upgradedAlice.prepareOutbound(
        contact: fixture.bobContact,
        mode: V3HandshakeMode.normal,
        carrierMode: V3ChatCarrierMode.text,
        text: 'must use the established forward-secure session',
        eligibilityPolicy: upgradedAlice.eligibilityForContact(
          fixture.bobContact,
        ),
      );
      expect(application.purpose, V3ChatOutboundPurpose.application);
      expect(application.preFsMetadata, isNull);
    });
  });
}

Future<void> _establishBoundaryFs(_BoundaryFixture fixture) async {
  for (var turn = 0; turn < 32; turn++) {
    final aliceSends = turn.isEven;
    final sender = aliceSends ? fixture.aliceBridge : fixture.bobBridge;
    final receiver = aliceSends ? fixture.bobBridge : fixture.aliceBridge;
    final recipient = aliceSends ? fixture.bobContact : fixture.aliceContact;
    final senderContact =
        aliceSends ? fixture.aliceContact : fixture.bobContact;
    final export = await sender.prepareOutbound(
      contact: recipient,
      mode: V3HandshakeMode.normal,
      carrierMode: V3ChatCarrierMode.text,
      text: 'Session fixture $turn',
      eligibilityPolicy: sender.eligibilityForContact(recipient),
    );
    expect(export.parts, hasLength(1));
    final received = await receiver.receiveCarrier(
      carrier: export.parts.single,
      contacts: [senderContact],
      modeForContact: receiver.modeForContact,
      eligibilityForContact: receiver.eligibilityForContact,
      ensureEligibilityForContact: receiver.ensureContactPolicy,
    );
    expect(received.status, V3ChatInboundStatus.delivered);
    final aliceStatus = await fixture.aliceBridge.securityStatus(
      contact: fixture.bobContact,
      selectedMode: V3HandshakeMode.normal,
      eligibilityPolicy:
          fixture.aliceBridge.eligibilityForContact(fixture.bobContact),
    );
    final bobStatus = await fixture.bobBridge.securityStatus(
      contact: fixture.aliceContact,
      selectedMode: V3HandshakeMode.normal,
      eligibilityPolicy:
          fixture.bobBridge.eligibilityForContact(fixture.aliceContact),
    );
    if (aliceStatus.isActive && bobStatus.isActive) return;
  }
  fail('Normal session fixture did not establish FS');
}

Future<T> _withFixture<T>(
  Future<T> Function(_BoundaryFixture fixture) body,
) async {
  final temp = await Directory.systemTemp.createTemp('lg_identity_boundaries_');
  Hive.init(temp.path);
  await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  final factory = V3LocalIdentityFactory(
    seedService: SeedService(),
    mlKem768Backend: _HandshakeMlKemBackend(),
  );
  final alice = await factory.restorePrimary(
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
  final bob = await factory.restorePrimary(
    mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  );
  final aliceRuntime = await V3ApplicationSessionRuntime.open(
    localIdentity: alice,
    scopeToken: 'bndAliceScope001',
    sckaBackend: _InitialSckaBackend(),
  );
  final bobRuntime = await V3ApplicationSessionRuntime.open(
    localIdentity: bob,
    scopeToken: 'bndBobScope00001',
    sckaBackend: _InitialSckaBackend(),
  );
  final aliceMessages = MessagesRepository();
  final bobMessages = MessagesRepository();
  await aliceMessages.setActiveContext(
    scopeToken: 'bndAliceScope001',
    storageKey: SecretKey(_testBytes(32, 21)),
  );
  await bobMessages.setActiveContext(
    scopeToken: 'bndBobScope00001',
    storageKey: SecretKey(_testBytes(32, 71)),
  );
  final aliceBridge = V3ApplicationChatBridge(
    runtime: aliceRuntime,
    messagesRepository: aliceMessages,
    keyTag: 'alice',
  );
  final bobBridge = V3ApplicationChatBridge(
    runtime: bobRuntime,
    messagesRepository: bobMessages,
    keyTag: 'bob',
  );
  final aliceContact =
      V3IdentityAdapter.toRemoteIdentity(alice.publicIdentity, verified: true);
  final bobContact =
      V3IdentityAdapter.toRemoteIdentity(bob.publicIdentity, verified: true);
  await aliceBridge.ensureContactPolicy(bobContact, V3HandshakeMode.normal);
  await bobBridge.ensureContactPolicy(aliceContact, V3HandshakeMode.normal);
  try {
    return await body(_BoundaryFixture(
      aliceBridge: aliceBridge,
      bobBridge: bobBridge,
      aliceRuntime: aliceRuntime,
      bobRuntime: bobRuntime,
      aliceMessages: aliceMessages,
      bobMessages: bobMessages,
      aliceContact: aliceContact,
      bobContact: bobContact,
    ));
  } finally {
    aliceMessages.dispose();
    bobMessages.dispose();
    await aliceRuntime.close();
    await bobRuntime.close();
    await alice.close();
    await bob.close();
    await Hive.close();
    await temp.delete(recursive: true);
  }
}

final class _BoundaryClipboard extends ClipboardService {
  String? value;

  @override
  Future<void> writeText(String text) async => value = text;
}

final class _BoundaryChatMeta extends ChatMetaRepository {
  _BoundaryChatMeta() : super(identityId: 'boundary-ui');

  @override
  Future<Map<String, dynamic>?> getChatSettings({required String chatId}) async =>
      null;

  @override
  Future<void> saveChatSettings({
    required String chatId,
    required String outputMode,
    required int? expiryMinutes,
    required bool deleteAfterRead,
    required bool excludeFromBackups,
  }) async {}
}

final class _BoundaryEmptyMessages extends MessagesRepository {
  @override
  Stream<List<MessageRecord>> watchThread(String contactId, {int limit = 50}) =>
      Stream.value(const <MessageRecord>[]);

  @override
  void dispose() {}
}

final class _BoundaryExportController extends HomeController {
  _BoundaryExportController(super.ref, this.exports);
  final List<V3ChatOutboundExport> exports;
  int preparations = 0;
  @override
  bool isProtocolV3Contact(RemoteIdentity contact) => true;
  @override
  Future<V3ChatOutboundExport> prepareProtocolV3Outbound({
    required RemoteIdentity recipient,
    required V3ChatCarrierMode carrierMode,
    required String text,
    String coverText = '',
    int? expireAfter,
    bool deleteAfterRead = false,
    bool backupExcluded = false,
  }) async =>
      exports[preparations++];
  @override
  Future<void> markProtocolV3Exported(
    V3ChatOutboundExport export, {
    int? partIndex,
  }) async {}
  @override
  Future<List<V3ChatOutboundExport>> restorePendingProtocolV3Exports({
    required RemoteIdentity contact,
    required V3ChatCarrierMode carrierMode,
    String coverText = '',
  }) async =>
      const [];
  @override
  Future<V3ChatContactSecurityStatus?> protocolV3SecurityStatus(
    RemoteIdentity contact,
  ) async =>
      null;
  @override
  Future<void> primeDisplayKey({required RemoteIdentity contact}) async {}
  @override
  Future<void> purgeReadDeleteAfterReadFor(String contactId) async {}
}

final class _BoundaryFixture {
  const _BoundaryFixture({
    required this.aliceBridge,
    required this.bobBridge,
    required this.aliceRuntime,
    required this.bobRuntime,
    required this.aliceMessages,
    required this.bobMessages,
    required this.aliceContact,
    required this.bobContact,
  });

  final V3ApplicationChatBridge aliceBridge;
  final V3ApplicationChatBridge bobBridge;
  final V3ApplicationSessionRuntime aliceRuntime;
  final V3ApplicationSessionRuntime bobRuntime;
  final MessagesRepository aliceMessages;
  final MessagesRepository bobMessages;
  final RemoteIdentity aliceContact;
  final RemoteIdentity bobContact;
}

final class _MemoryLmfRecordStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;
  bool failNextWrite = false;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    if (failNextWrite) {
      failNextWrite = false;
      throw StateError('injected write failure');
    }
    final id = 'record-${_nextId++}';
    records[id] = Map<String, dynamic>.from(payload);
    return id;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => records.entries
      .map(
        (entry) => V3LmfStoredRecord(
          storageId: entry.key,
          payload: Map<String, dynamic>.from(entry.value),
        ),
      )
      .toList(growable: false);

  @override
  Future<void> delete(String storageId) async {
    records.remove(storageId);
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
