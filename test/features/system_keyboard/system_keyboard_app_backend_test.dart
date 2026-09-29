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

/// Bounded integration coverage for the *real* [SystemKeyboardAppBackend]
/// against the real V3 application session runtime, the real V3 chat bridge,
/// the real projection/persistence and the real message state machine.
///
/// Only the identity/crypto *backend adapters* below are synthetic: the test
/// ML-KEM-768 and SCKA adapters replace native libraries so the full flow can
/// run in a unit-test process. They prove flow wiring and fail-closed gates,
/// never the cryptographic algorithms themselves.
///
/// The suite never loosens a production gate to make a fixture pass: missing
/// policy, unestablished session, changed fingerprint and a revoked owner
/// context must all be refused by the production code under test.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/fs_message_classification.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/application_chat_bridge_v3.dart';
import 'package:layergram/core/crypto/v3/application_session_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/identities_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_app_backend.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_controller.dart';

/// A real [SystemKeyboardAppBackend] bound to the active container and the
/// guard supplied through [_testGuardProvider].
final Provider<SystemKeyboardAppBackend> _testKeyboardBackendProvider =
    Provider<SystemKeyboardAppBackend>(
  (ref) => SystemKeyboardAppBackend(
    ref: ref,
    guard: ref.read(_testGuardProvider),
  ),
);

final Provider<SystemKeyboardIntegrationGuard> _testGuardProvider =
    Provider<SystemKeyboardIntegrationGuard>(
  (ref) => throw StateError('The system keyboard test guard was not provided'),
);

void main() {
  const String aliceMnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const String bobMnemonic =
      'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
  const String aliceScope = 'alice-v3-scope01';
  const String bobScope = 'bob-v3-scope0000';

  late Directory temporaryDirectory;
  late Box<Map> messagesBox;
  late Box<Map> identitiesBox;
  late V3LocalIdentityHandle alice;
  late V3LocalIdentityHandle bob;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    temporaryDirectory =
        await Directory.systemTemp.createTemp('layergram_sk_backend_');
    Hive.init(temporaryDirectory.path);
    messagesBox = await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    identitiesBox = await Hive.openBox<Map>(LocalDatabase.identitiesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await temporaryDirectory.delete(recursive: true);
  });

  setUp(() async {
    await messagesBox.clear();
    await identitiesBox.clear();
    final V3LocalIdentityFactory factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: _TestMlKemBackend(),
    );
    alice = await factory.restorePrimary(
      mnemonic: aliceMnemonic,
      displayName: 'Alice',
    );
    bob = await factory.restorePrimary(
      mnemonic: bobMnemonic,
      displayName: 'Bob',
    );
  });

  tearDown(() async {
    await alice.close();
    await bob.close();
  });

  test(
    'real backend accepts the ordinary X25519 owner ID and exchanges a V3 message',
    () async {
      final _SessionFixture fixture = await _openSessionFixture(
        alice: alice,
        bob: bob,
        aliceScope: aliceScope,
        bobScope: bobScope,
        aliceStorageKeyStart: 0xa1,
        bobStorageKeyStart: 0xc1,
      );
      final IdentitiesRepository identities = await _openAliceIdentities(
        alice: alice,
        bobContact: fixture.bobContact,
        scopeToken: aliceScope,
      );
      // The app's ordinary identity ID is SHA-256(X25519 public key); the V3
      // wire identity ID hashes the entire hybrid public bundle with SHA-384.
      // This mismatch is real and must not block the app-owned V3 runtime.
      final ordinaryIdentityId = base32
          .encode(Uint8List.fromList(
              sha256.convert(alice.publicIdentity.x25519PublicKey).bytes))
          .replaceAll('=', '');
      expect(ordinaryIdentityId, isNot(alice.publicIdentity.identityId));
      final _KeyboardHarness harness = _openKeyboardHarness(
        fixture: fixture,
        identities: identities,
        ordinaryIdentityId: ordinaryIdentityId,
      );
      await harness.container.read(originalKeyTagProvider.future);
      try {
        final String bobId = fixture.bobContact.identityId;
        final String bobFingerprint = fixture.bobContact.fingerprint;
        const String plaintext = 'testo in chiaro per la tastiera di sistema';
        const String replyText = 'risposta autenticata del destinatario';

        // ── Contact surface only exposes the saved V3 contact ──────────────
        final List<SystemKeyboardContact> contacts =
            await harness.backend.listApprovedContacts();
        expect(contacts, hasLength(1));
        expect(contacts.single.id, bobId);
        expect(contacts.single.name, 'Bob');
        expect(contacts.single.fingerprint, bobFingerprint);

        await _establishNormalSession(fixture);
        final int aliceBaseline =
            (await fixture.aliceMessages.getAllMessages()).length;
        final int bobBaseline =
            (await fixture.bobMessages.getAllMessages()).length;

        final V3ApplicationHandshakeExport? handshakeBefore =
            await fixture.aliceRuntime.pendingHandshakeForRemoteIdentity(
          remoteIdentity: bob.publicIdentity,
          mode: V3HandshakeMode.normal,
        );
        // ── Changed fingerprint is refused even with an active session ─────
        expect(
          await harness.backend.prepareTextOutbound(
            _outboundRequest(
              contactId: bobId,
              contactFingerprint: 'not-the-saved-fingerprint',
              text: plaintext,
            ),
          ),
          isNull,
        );
        expect(
          await fixture.aliceMessages.getAllMessages(),
          hasLength(aliceBaseline),
        );
        final V3ApplicationHandshakeExport? handshakeAfter =
            await fixture.aliceRuntime.pendingHandshakeForRemoteIdentity(
          remoteIdentity: bob.publicIdentity,
          mode: V3HandshakeMode.normal,
        );
        // The established session may retain its recoverable handshake export;
        // a rejected recipient must not replace or mutate that durable packet.
        expect(handshakeAfter?.text, handshakeBefore?.text);
        expect(handshakeAfter?.handshakeId, handshakeBefore?.handshakeId);

        // ── One bounded text ciphertext, distinct from the plaintext ───────
        final SystemKeyboardBackendExport? prepared =
            await harness.backend.prepareTextOutbound(
          _outboundRequest(
            contactId: bobId,
            contactFingerprint: bobFingerprint,
            text: plaintext,
          ),
        );
        expect(prepared, isNotNull);
        final SystemKeyboardBackendExport export = prepared!;
        expect(export.carriers, hasLength(1));
        final String carrier = export.carriers.single;
        expect(carrier, isNotEmpty);
        expect(carrier, isNot(plaintext));
        expect(carrier.contains(plaintext), isFalse);
        expect(
          carrier.length,
          lessThanOrEqualTo(systemKeyboardSurfaceOutboundCarrierMaxLength),
        );
        expect(export.ciphertextCodeUnits, carrier.length);

        // ── Projection into Alice history happens exactly once ─────────────
        final List<MessageRecord> outgoingHistory =
            await fixture.aliceMessages.getAllMessages();
        expect(outgoingHistory, hasLength(aliceBaseline + 1));
        MessageRecord? projectedOutgoing;
        for (final record in outgoingHistory) {
          if (record.direction == 'outgoing' &&
              await fixture.aliceBridge.loadPlaintext(record.id) == plaintext) {
            projectedOutgoing = record;
            break;
          }
        }
        expect(projectedOutgoing, isNotNull);
        final outgoing = projectedOutgoing!;
        expect(outgoing.direction, 'outgoing');
        expect(outgoing.senderId, alice.publicIdentity.identityId);
        expect(outgoing.recipientId, bobId);
        expect(outgoing.text, isNull);
        expect(outgoing.isFsEncrypted, isTrue);
        expect(outgoing.keyTag, 'alice-original-keytag');
        expect(await fixture.aliceBridge.loadPlaintext(outgoing.id), plaintext);

        await harness.backend.markExported(export.exportHandle);
        expect(
          await fixture.aliceMessages.getAllMessages(),
          hasLength(aliceBaseline + 1),
        );

        // ── Bob receives the exported carrier and reads the original text ──
        V3ChatInboundResult? delivered;
        for (final String part in export.carriers) {
          delivered = await fixture.bobBridge.receiveCarrier(
            carrier: part,
            contacts: <RemoteIdentity>[fixture.aliceContact],
            modeForContact: fixture.bobBridge.modeForContact,
            eligibilityForContact: fixture.bobBridge.eligibilityForContact,
          );
        }
        expect(delivered?.status, V3ChatInboundStatus.delivered);
        expect(delivered?.payload?.text, plaintext);
        final List<MessageRecord> bobHistory =
            await fixture.bobMessages.getAllMessages();
        expect(bobHistory, hasLength(bobBaseline + 1));
        MessageRecord? deliveredRecord;
        for (final record in bobHistory) {
          if (record.direction == 'incoming' &&
              await fixture.bobBridge.loadPlaintext(record.id) == plaintext) {
            deliveredRecord = record;
            break;
          }
        }
        expect(deliveredRecord, isNotNull);
        final bobIncoming = deliveredRecord!;
        expect(bobIncoming.text, isNull);
        expect(
          await fixture.bobBridge.loadPlaintext(bobIncoming.id),
          plaintext,
        );

        // ── Bob replies; the backend authenticates it and projects once ────
        final V3ChatOutboundExport reply =
            await fixture.bobBridge.prepareOutbound(
          contact: fixture.aliceContact,
          mode: V3HandshakeMode.normal,
          carrierMode: V3ChatCarrierMode.text,
          text: replyText,
          eligibilityPolicy:
              fixture.bobBridge.eligibilityForContact(fixture.aliceContact),
        );
        expect(reply.purpose, V3ChatOutboundPurpose.application);
        expect(reply.parts, hasLength(1));

        final SystemKeyboardBackendDecoded? decoded =
            await harness.backend.decodeCarrier(reply.parts.single);
        expect(decoded, isNotNull);
        final SystemKeyboardBackendDecoded preview = decoded!;
        expect(preview.contact.id, bobId);
        expect(preview.contact.fingerprint, bobFingerprint);
        expect(preview.text, replyText);
        expect(preview.readOnce, isFalse);
        expect(preview.expired, isFalse);
        expect(preview.hasExpiry, isFalse);

        final List<MessageRecord> afterReply =
            await fixture.aliceMessages.getAllMessages();
        expect(afterReply, hasLength(aliceBaseline + 2));
        MessageRecord? incoming;
        for (final record in afterReply) {
          if (record.direction == 'incoming' &&
              await fixture.aliceBridge.loadPlaintext(record.id) == replyText) {
            incoming = record;
            break;
          }
        }
        expect(incoming, isNotNull);
        final replyRecord = incoming!;
        expect(replyRecord.senderId, bobId);
        expect(replyRecord.recipientId, alice.publicIdentity.identityId);
        expect(replyRecord.text, isNull);
        expect(
          await fixture.aliceBridge.loadPlaintext(replyRecord.id),
          replyText,
        );

        // ── Replay produces no duplicate preview and no duplicate history ──
        expect(await harness.backend.decodeCarrier(reply.parts.single), isNull);
        expect(
          await fixture.aliceMessages.getAllMessages(),
          hasLength(aliceBaseline + 2),
        );

        // ── Guard denial happens before any provider access ────────────────
        await _expectGuardDenialReadsNoProvider(
          alice: alice,
          request: _outboundRequest(
            contactId: bobId,
            contactFingerprint: bobFingerprint,
            text: plaintext,
          ),
          carrier: reply.parts.single,
          initialIdentityId: null,
        );
      } finally {
        harness.container.dispose();
        identities.dispose();
        fixture.aliceMessages.dispose();
        fixture.bobMessages.dispose();
        await fixture.aliceRuntime.close();
        await fixture.bobRuntime.close();
      }
    },
  );

  test(
    'fresh eligible Normal contact sends one readable pre-session carrier',
    () async {
      final _SessionFixture fixture = await _openSessionFixture(
        alice: alice,
        bob: bob,
        aliceScope: aliceScope,
        bobScope: bobScope,
        aliceStorageKeyStart: 0xb1,
        bobStorageKeyStart: 0xd1,
      );
      final IdentitiesRepository identities = await _openAliceIdentities(
        alice: alice,
        bobContact: fixture.bobContact,
        scopeToken: aliceScope,
      );
      final _KeyboardHarness harness = _openKeyboardHarness(
        fixture: fixture,
        identities: identities,
        ordinaryIdentityId: alice.publicIdentity.identityId,
      );
      await harness.container.read(originalKeyTagProvider.future);
      try {
        const String plaintext = 'primo messaggio Normal autenticato';
        final SystemKeyboardBackendExport? prepared =
            await harness.backend.prepareTextOutbound(
          _outboundRequest(
            contactId: fixture.bobContact.identityId,
            contactFingerprint: fixture.bobContact.fingerprint,
            text: plaintext,
          ),
        );

        expect(prepared, isNotNull);
        expect(prepared!.carriers, hasLength(1));
        expect(prepared.carriers.single.length,
            lessThanOrEqualTo(systemKeyboardSurfaceOutboundCarrierMaxLength));
        final List<MessageRecord> aliceHistory =
            await fixture.aliceMessages.getAllMessages();
        expect(aliceHistory, hasLength(1));
        expect(aliceHistory.single.text, plaintext);
        expect(
          aliceHistory.single.effectiveClassification,
          FsMessageClassification.preFs,
        );

        final V3ChatInboundResult delivered =
            await fixture.bobBridge.receiveCarrier(
          carrier: prepared.carriers.single,
          contacts: <RemoteIdentity>[fixture.aliceContact],
          modeForContact: fixture.bobBridge.modeForContact,
          eligibilityForContact: fixture.bobBridge.eligibilityForContact,
          ensureEligibilityForContact: fixture.bobBridge.ensureContactPolicy,
          responseCarrierMode: V3ChatCarrierMode.text,
        );
        expect(delivered.hasUserMessage, isTrue);
        expect(delivered.payload?.text, plaintext);
        final List<MessageRecord> bobHistory =
            await fixture.bobMessages.getAllMessages();
        expect(bobHistory, hasLength(1));
        expect(
          bobHistory.single.effectiveClassification,
          FsMessageClassification.preFs,
        );
        await harness.backend.markExported(prepared.exportHandle);
      } finally {
        harness.container.dispose();
        identities.dispose();
        fixture.aliceMessages.dispose();
        fixture.bobMessages.dispose();
        await fixture.aliceRuntime.close();
        await fixture.bobRuntime.close();
      }
    },
  );

  test('Maximum setup remains blocked in the system keyboard', () async {
    final _SessionFixture fixture = await _openSessionFixture(
      alice: alice,
      bob: bob,
      aliceScope: aliceScope,
      bobScope: bobScope,
      aliceStorageKeyStart: 0xb2,
      bobStorageKeyStart: 0xd2,
    );
    final IdentitiesRepository identities = await _openAliceIdentities(
      alice: alice,
      bobContact: fixture.bobContact,
      scopeToken: aliceScope,
    );
    final _KeyboardHarness harness = _openKeyboardHarness(
      fixture: fixture,
      identities: identities,
      ordinaryIdentityId: alice.publicIdentity.identityId,
    );
    await harness.container.read(originalKeyTagProvider.future);
    try {
      await fixture.aliceBridge.ensureContactPolicy(
        fixture.bobContact,
        V3HandshakeMode.maximum,
      );
      expect(
        await harness.backend.securityPhaseForContact(
            fixture.bobContact.identityId, fixture.bobContact.fingerprint),
        'maximumSetupRequired',
      );
      expect(
        await harness.backend.prepareTextOutbound(
          _outboundRequest(
            contactId: fixture.bobContact.identityId,
            contactFingerprint: fixture.bobContact.fingerprint,
            text: 'non deve uscire dalla tastiera',
          ),
        ),
        isNull,
      );
      expect(await fixture.aliceMessages.getAllMessages(), isEmpty);
    } finally {
      harness.container.dispose();
      identities.dispose();
      fixture.aliceMessages.dispose();
      fixture.bobMessages.dispose();
      await fixture.aliceRuntime.close();
      await fixture.bobRuntime.close();
    }
  });

  test(
    'a revoked owner context cannot mark a pinned export into another scope',
    () async {
      final _SessionFixture fixture = await _openSessionFixture(
        alice: alice,
        bob: bob,
        aliceScope: aliceScope,
        bobScope: bobScope,
        aliceStorageKeyStart: 0xb1,
        bobStorageKeyStart: 0xd1,
      );
      final IdentitiesRepository identities = await _openAliceIdentities(
        alice: alice,
        bobContact: fixture.bobContact,
        scopeToken: aliceScope,
      );
      final _KeyboardHarness harness = _openKeyboardHarness(
        fixture: fixture,
        identities: identities,
        ordinaryIdentityId: alice.publicIdentity.identityId,
      );
      await harness.container.read(originalKeyTagProvider.future);
      MessagesRepository? otherScope;
      try {
        await _establishNormalSession(fixture);
        final int baseline =
            (await fixture.aliceMessages.getAllMessages()).length;
        final SystemKeyboardBackendExport? export =
            await harness.backend.prepareTextOutbound(
          _outboundRequest(
            contactId: fixture.bobContact.identityId,
            contactFingerprint: fixture.bobContact.fingerprint,
            text: 'messaggio in attesa di conferma export',
          ),
        );
        expect(export, isNotNull);
        expect(
          await fixture.aliceMessages.getAllMessages(),
          hasLength(baseline + 1),
        );

        // The owner context is revoked before the acknowledgement: the pinned
        // handle must fail closed instead of exporting into whatever scope is
        // current at ack time. The durable projection stays exactly once.
        harness.guard.revoke();
        await expectLater(
          harness.backend.markExported(export!.exportHandle),
          throwsStateError,
        );
        expect(
          await fixture.aliceMessages.getAllMessages(),
          hasLength(baseline + 1),
        );

        // A different scope keeps its own empty history: nothing leaked.
        otherScope = MessagesRepository();
        await otherScope.setActiveContext(
          scopeToken: 'alice-other-0001',
          storageKey: SecretKey(_testBytes(32, 0xe1)),
        );
        expect(await otherScope.getAllMessages(), isEmpty);
      } finally {
        otherScope?.dispose();
        harness.container.dispose();
        identities.dispose();
        fixture.aliceMessages.dispose();
        fixture.bobMessages.dispose();
        await fixture.aliceRuntime.close();
        await fixture.bobRuntime.close();
      }
    },
  );
}

/// Proves a denied guard refuses every backend operation before the identity,
/// message or runtime providers are ever initialized.
Future<void> _expectGuardDenialReadsNoProvider({
  required V3LocalIdentityHandle alice,
  required SystemKeyboardOutboundRequest request,
  required String carrier,
  required String? initialIdentityId,
}) async {
  int providerReads = 0;
  final _TestIntegrationGuard guard =
      _TestIntegrationGuard(ordinaryIdentityId: initialIdentityId);
  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      _testGuardProvider.overrideWithValue(guard),
      identitiesRepositoryProvider.overrideWith((ref) {
        providerReads++;
        throw StateError('Identities repository must not be read');
      }),
      messagesRepositoryProvider.overrideWith((ref) {
        providerReads++;
        throw StateError('Messages repository must not be read');
      }),
      v3ApplicationSessionRuntimeProvider.overrideWith((ref) async {
        providerReads++;
        throw StateError('Session runtime must not be read');
      }),
    ],
  );
  addTearDown(container.dispose);
  final SystemKeyboardAppBackend backend =
      container.read(_testKeyboardBackendProvider);

  // No bound ordinary identity: everything is refused up front.
  expect(await backend.listApprovedContacts(), isEmpty);
  expect(await backend.prepareTextOutbound(request), isNull);
  expect(await backend.decodeCarrier(carrier), isNull);
  expect(providerReads, 0);

  // Bound identity but revoked generation/context: still refused up front.
  guard.ordinaryIdentityId = alice.publicIdentity.identityId;
  guard.revoke();
  expect(await backend.listApprovedContacts(), isEmpty);
  expect(await backend.prepareTextOutbound(request), isNull);
  expect(await backend.decodeCarrier(carrier), isNull);
  expect(providerReads, 0);
  expect(guard.admitsCalls, greaterThan(0));
}

Future<_SessionFixture> _openSessionFixture({
  required V3LocalIdentityHandle alice,
  required V3LocalIdentityHandle bob,
  required String aliceScope,
  required String bobScope,
  required int aliceStorageKeyStart,
  required int bobStorageKeyStart,
}) async {
  final V3ApplicationSessionRuntime aliceRuntime =
      await V3ApplicationSessionRuntime.open(
    localIdentity: alice,
    scopeToken: aliceScope,
    sckaBackend: _TestSckaBackend(),
  );
  final V3ApplicationSessionRuntime bobRuntime =
      await V3ApplicationSessionRuntime.open(
    localIdentity: bob,
    scopeToken: bobScope,
    sckaBackend: _TestSckaBackend(),
  );
  final MessagesRepository aliceMessages = MessagesRepository();
  final MessagesRepository bobMessages = MessagesRepository();
  await aliceMessages.setActiveContext(
    scopeToken: aliceScope,
    storageKey: SecretKey(_testBytes(32, aliceStorageKeyStart)),
  );
  await bobMessages.setActiveContext(
    scopeToken: bobScope,
    storageKey: SecretKey(_testBytes(32, bobStorageKeyStart)),
  );
  return _SessionFixture(
    aliceRuntime: aliceRuntime,
    bobRuntime: bobRuntime,
    aliceMessages: aliceMessages,
    bobMessages: bobMessages,
    aliceBridge: V3ApplicationChatBridge(
      runtime: aliceRuntime,
      messagesRepository: aliceMessages,
      keyTag: 'alice-original-keytag',
    ),
    bobBridge: V3ApplicationChatBridge(
      runtime: bobRuntime,
      messagesRepository: bobMessages,
      keyTag: 'bob-primary',
    ),
    aliceContact: V3IdentityAdapter.toRemoteIdentity(
      alice.publicIdentity,
      verified: true,
    ),
    bobContact: V3IdentityAdapter.toRemoteIdentity(
      bob.publicIdentity,
      verified: true,
    ),
  );
}

Future<IdentitiesRepository> _openAliceIdentities({
  required V3LocalIdentityHandle alice,
  required RemoteIdentity bobContact,
  required String scopeToken,
}) async {
  final IdentitiesRepository repository = IdentitiesRepository(
    ownerIdentityId: alice.publicIdentity.identityId,
  );
  await repository.setActiveContext(
    scopeToken: scopeToken,
    encryptionKey: SecretKey(_testBytes(32, 0x71)),
    selfIdentity: V3IdentityAdapter.toRemoteIdentity(
      alice.publicIdentity,
      verified: true,
    ),
  );
  await repository.upsertRemoteIdentity(bobContact);
  return repository;
}

_KeyboardHarness _openKeyboardHarness({
  required _SessionFixture fixture,
  required IdentitiesRepository identities,
  required String ordinaryIdentityId,
}) {
  final _TestIntegrationGuard guard =
      _TestIntegrationGuard(ordinaryIdentityId: ordinaryIdentityId);
  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      _testGuardProvider.overrideWithValue(guard),
      identitiesRepositoryProvider.overrideWithValue(identities),
      messagesRepositoryProvider.overrideWithValue(fixture.aliceMessages),
      v3ApplicationSessionRuntimeProvider
          .overrideWith((ref) async => fixture.aliceRuntime),
      protocolV3IdentityEnabledProvider.overrideWithValue(false),
      originalKeyTagProvider
          .overrideWith((ref) async => 'alice-original-keytag'),
    ],
  );
  return _KeyboardHarness(
    container: container,
    guard: guard,
    backend: container.read(_testKeyboardBackendProvider),
  );
}

/// Establishes a real Normal-mode V3 session over the actual chat bridges.
Future<void> _establishNormalSession(_SessionFixture fixture) async {
  final V3SessionEligibilityPolicy alicePolicy =
      await fixture.aliceBridge.ensureContactPolicy(
    fixture.bobContact,
    V3HandshakeMode.normal,
  );
  await fixture.bobBridge.ensureContactPolicy(
    fixture.aliceContact,
    V3HandshakeMode.normal,
  );

  V3ChatOutboundExport outbound = await fixture.aliceBridge.prepareOutbound(
    contact: fixture.bobContact,
    mode: V3HandshakeMode.normal,
    carrierMode: V3ChatCarrierMode.text,
    text: '',
    eligibilityPolicy: alicePolicy,
  );
  var aliceIsSender = true;
  for (var step = 0; step < 16; step++) {
    final receiver = aliceIsSender ? fixture.bobBridge : fixture.aliceBridge;
    final senderContact =
        aliceIsSender ? fixture.aliceContact : fixture.bobContact;
    final received = await receiver.receiveCarrier(
      carrier: outbound.bundledText,
      contacts: <RemoteIdentity>[senderContact],
      modeForContact: receiver.modeForContact,
      eligibilityForContact: receiver.eligibilityForContact,
      ensureEligibilityForContact: receiver.ensureContactPolicy,
      responseCarrierMode: V3ChatCarrierMode.text,
    );

    final aliceStatus = await fixture.aliceBridge.securityStatus(
      contact: fixture.bobContact,
      selectedMode: V3HandshakeMode.normal,
    );
    final bobStatus = await fixture.bobBridge.securityStatus(
      contact: fixture.aliceContact,
      selectedMode: V3HandshakeMode.normal,
    );
    if (aliceStatus.isActive && bobStatus.isActive) {
      expect(aliceStatus.activeSessionCount, 1);
      expect(bobStatus.activeSessionCount, 1);
      return;
    }

    aliceIsSender = !aliceIsSender;
    final response = received.response;
    if (response != null) {
      outbound = response;
      continue;
    }
    final sender = aliceIsSender ? fixture.aliceBridge : fixture.bobBridge;
    final recipient = aliceIsSender ? fixture.bobContact : fixture.aliceContact;
    outbound = await sender.prepareOutbound(
      contact: recipient,
      mode: V3HandshakeMode.normal,
      carrierMode: V3ChatCarrierMode.text,
      text: 'normal setup step $step',
      eligibilityPolicy: sender.eligibilityForContact(recipient),
    );
  }
  fail('Normal V3 session did not become active within the bounded exchange');
}

SystemKeyboardOutboundRequest _outboundRequest({
  required String contactId,
  required String contactFingerprint,
  required String text,
}) =>
    SystemKeyboardOutboundRequest(
      requestId: 'request-1',
      contactId: contactId,
      contactFingerprint: contactFingerprint,
      text: text,
      editorNonce: 'editor-1',
      inputSessionEpoch: 1,
    );

final class _SessionFixture {
  _SessionFixture({
    required this.aliceRuntime,
    required this.bobRuntime,
    required this.aliceMessages,
    required this.bobMessages,
    required this.aliceBridge,
    required this.bobBridge,
    required this.aliceContact,
    required this.bobContact,
  });

  final V3ApplicationSessionRuntime aliceRuntime;
  final V3ApplicationSessionRuntime bobRuntime;
  final MessagesRepository aliceMessages;
  final MessagesRepository bobMessages;
  final V3ApplicationChatBridge aliceBridge;
  final V3ApplicationChatBridge bobBridge;
  final RemoteIdentity aliceContact;
  final RemoteIdentity bobContact;
}

final class _KeyboardHarness {
  _KeyboardHarness({
    required this.container,
    required this.guard,
    required this.backend,
  });

  final ProviderContainer container;
  final _TestIntegrationGuard guard;
  final SystemKeyboardAppBackend backend;
}

/// Test guard that binds one exact ordinary identity id plus generation and
/// denies as soon as the owner generation is revoked.
final class _TestIntegrationGuard implements SystemKeyboardIntegrationGuard {
  _TestIntegrationGuard({required this.ordinaryIdentityId});

  @override
  String? ordinaryIdentityId;

  int _generation = 0;
  bool _revoked = false;

  /// Number of admission checks, used to prove the guard was consulted.
  int admitsCalls = 0;

  @override
  int get generation => _generation;

  void revoke() {
    _revoked = true;
    _generation++;
  }

  @override
  bool admits(int generation, String? identityId) {
    admitsCalls++;
    if (_revoked) return false;
    return generation == _generation &&
        identityId != null &&
        identityId.isNotEmpty &&
        identityId == ordinaryIdentityId;
  }
}

// ── Synthetic crypto adapters (flow only, never crypto proof) ──────────────

final class _TestMlKemPrivateKeyHandle implements MlKem768PrivateKeyHandle {
  _TestMlKemPrivateKeyHandle(this.publicKey);

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

final class _TestMlKemBackend implements MlKem768Backend {
  int _encapsulationCounter = 0;

  @override
  String get implementationId => 'system-keyboard-test-ml-kem';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    final List<int> digest = sha512.convert(seed).bytes;
    final Uint8List publicKey = Uint8List.fromList(
      List<int>.generate(
        MlKem768.publicKeyBytes,
        (int index) => digest[index % digest.length],
      ),
    );
    return MlKem768KeyPair(
      publicKey: publicKey,
      privateKeyHandle: _TestMlKemPrivateKeyHandle(
        Uint8List.fromList(publicKey),
      ),
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async =>
      publicKey.length == MlKem768.publicKeyBytes &&
      publicKey.any((int byte) => byte != 0);

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) async {
    _encapsulationCounter++;
    final Uint8List counter = Uint8List(4);
    ByteData.sublistView(counter).setUint32(0, _encapsulationCounter);
    final List<int> block =
        sha512.convert(<int>[...publicKey, ...counter]).bytes;
    final Uint8List ciphertext = Uint8List.fromList(
      List<int>.generate(
        MlKem768.ciphertextBytes,
        (int index) => block[index % block.length] ^ (index & 0xff),
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
    if (privateKeyHandle is! _TestMlKemPrivateKeyHandle ||
        privateKeyHandle.isClosed ||
        ciphertext.length != MlKem768.ciphertextBytes) {
      throw StateError('invalid test ML-KEM input');
    }
    return _sharedSecret(privateKeyHandle.publicKey, ciphertext);
  }

  Uint8List _sharedSecret(Uint8List publicKey, Uint8List ciphertext) =>
      Uint8List.fromList(
        sha256.convert(<int>[
          ...'system-keyboard-test-shared\x00'.codeUnits,
          ...publicKey,
          ...ciphertext,
        ]).bytes,
      );
}

final class _TestSckaBackend implements V3SckaBackend {
  @override
  String get implementationId => 'layergram-system-keyboard-test-scka/1';

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
    final int currentEpoch = authenticatedState[17];
    final Uint8List payload = message.nativePayload;
    if (payload.length != 1 || payload.single < currentEpoch) {
      throw const FormatException('invalid test SCKA message');
    }
    final int outputEpoch = payload.single;
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
    final int currentEpoch = authenticatedState[17];
    final int outputEpoch = currentEpoch == 0 ? 1 : currentEpoch;
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
    final Uint8List result = Uint8List.fromList(<int>[
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
  int difference = 0;
  for (int index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

Uint8List _testBytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (int index) => (start + index) & 0xff),
    );
