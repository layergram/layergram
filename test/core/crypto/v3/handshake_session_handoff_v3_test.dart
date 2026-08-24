import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/committed_record_materializer_v3.dart';
import 'package:layergram/core/crypto/v3/handshake_persistence_v3.dart';
import 'package:layergram/core/crypto/v3/handshake_session_handoff_v3.dart';
import 'package:layergram/core/crypto/v3/initial_session_handoff_authority_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_atomic_commit.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/session_checkpoint_v3.dart';
import 'package:layergram/core/crypto/v3/session_commit_controller_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';

void main() {
  const aliceMnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const bobMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

  late _HandshakeMlKemBackend mlKem;
  late _InitialSckaBackend scka;
  late V3LocalIdentityHandle alice;
  late V3LocalIdentityHandle bob;
  late V3LocalDeviceHandle aliceDevice;
  late V3LocalDeviceHandle bobDevice;

  setUp(() async {
    mlKem = _HandshakeMlKemBackend();
    scka = _InitialSckaBackend();
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: mlKem,
    );
    alice = await factory.restorePrimary(mnemonic: aliceMnemonic);
    bob = await factory.restorePrimary(mnemonic: bobMnemonic);
    aliceDevice = await V3LocalDeviceHandle.fromSeed(_bytes(32, 0x11));
    bobDevice = await V3LocalDeviceHandle.fromSeed(_bytes(32, 0x51));
  });

  tearDown(() async {
    aliceDevice.close();
    bobDevice.close();
    await alice.close();
    await bob.close();
  });

  group('inactive v3 atomic handshake session handoff', () {
    test('initial factory derives matching directional PQ epoch for both roles',
        () async {
      final offer = await V3HybridHandshake.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      final responder = await V3HybridHandshake.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: offer.offer,
        expectedMode: V3HandshakeMode.normal,
      );
      final initiator = await V3HybridHandshake.acceptReply(
        pending: offer,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: responder.reply,
      );
      final responderEstablished = await V3HybridHandshake.acceptConfirmation(
        pending: responder,
        initiatorIdentity: alice.publicIdentity,
        responderIdentity: bob.publicIdentity,
        confirmation: initiator.confirmation,
      );
      final initiatorSnapshot = await V3InitialSessionFactory.initialize(
        established: initiator.established,
        backend: scka,
      );
      final responderSnapshot = await V3InitialSessionFactory.initialize(
        established: responderEstablished,
        backend: scka,
      );
      final initiatorEpoch = initiatorSnapshot.pqEpochStates.single;
      final responderEpoch = responderSnapshot.pqEpochStates.single;
      final initiatorSending = initiatorEpoch.sendingChainKey!;
      final initiatorReceiving = initiatorEpoch.receivingChainKey!;
      final responderSending = responderEpoch.sendingChainKey!;
      final responderReceiving = responderEpoch.receivingChainKey!;
      final initiatorSession = initiatorSnapshot.sessionId;
      final responderSession = responderSnapshot.sessionId;
      final initiatorSealKey = initiatorSnapshot.sckaStateSealKey;
      final responderSealKey = responderSnapshot.sckaStateSealKey;
      try {
        expect(initiatorSession, orderedEquals(responderSession));
        expect(initiatorSending, orderedEquals(responderReceiving));
        expect(initiatorReceiving, orderedEquals(responderSending));
        expect(initiatorSnapshot.revision, 0);
        expect(responderSnapshot.revision, 0);
        expect(initiatorSealKey, orderedEquals(responderSealKey));
        await V3SparsePqRatchet.validateSnapshot(
          backend: scka,
          snapshot: initiatorSnapshot,
        );
        await V3SparsePqRatchet.validateSnapshot(
          backend: scka,
          snapshot: responderSnapshot,
        );
      } finally {
        initiatorSending.fillRange(0, initiatorSending.length, 0);
        initiatorReceiving.fillRange(0, initiatorReceiving.length, 0);
        responderSending.fillRange(0, responderSending.length, 0);
        responderReceiving.fillRange(0, responderReceiving.length, 0);
        initiatorSession.fillRange(0, initiatorSession.length, 0);
        responderSession.fillRange(0, responderSession.length, 0);
        initiatorSealKey.fillRange(0, initiatorSealKey.length, 0);
        responderSealKey.fillRange(0, responderSealKey.length, 0);
        initiatorEpoch.wipeSecrets();
        responderEpoch.wipeSecrets();
        initiatorSnapshot.wipeSecrets();
        responderSnapshot.wipeSecrets();
        initiator.established.close();
        responderEstablished.close();
      }
    });

    test('forged capability loses the claim race and cannot register TR3',
        () async {
      final store = _FaultStore();
      final harness = _Harness(store, sckaBackend: scka);
      await harness.restoreDependencies();
      final forged = V3InitialSessionHandoffAuthority();
      final forgedHandshakeClaim =
          harness.handshakes.claimInitialHandoffAuthority(forged);
      final forgedSessionClaim =
          harness.sessions.claimInitialHandoffAuthority(forged);
      final properRestore = harness.handoffs.restore();
      await expectLater(forgedHandshakeClaim, throwsStateError);
      await expectLater(forgedSessionClaim, throwsStateError);
      await properRestore;
      await expectLater(
        harness.handshakes.claimInitialHandoffAuthority(
          harness.initialHandoffAuthority,
        ),
        throwsStateError,
      );
      await expectLater(
        harness.sessions.claimInitialHandoffAuthority(
          harness.initialHandoffAuthority,
        ),
        throwsStateError,
      );

      final offer = await V3HybridHandshake.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      final responder = await V3HybridHandshake.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: offer.offer,
        expectedMode: V3HandshakeMode.normal,
      );
      final accepted = await V3HybridHandshake.acceptReply(
        pending: offer,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: responder.reply,
      );
      final snapshot = await V3InitialSessionFactory.initialize(
        established: accepted.established,
        backend: scka,
      );
      try {
        await expectLater(
          harness.sessions.registerInitialSession(
            snapshot: snapshot,
            authority: forged,
          ),
          throwsStateError,
        );
        expect(harness.sessions.sessionCount, 0);
        expect(
          store.records.values.where(
            (value) =>
                value['kind'] == V3SessionCheckpointRepository.recordKind,
          ),
          isEmpty,
        );
      } finally {
        snapshot.wipeSecrets();
        accepted.established.close();
        responder.close();
        await harness.close();
      }
    });

    test('commits initiator TR3 before retiring HP3 or returning confirmation',
        () async {
      final store = _FaultStore();
      final harness = _Harness(store, sckaBackend: scka);
      await harness.restore();
      final exchange = await _initiatorExchange(
        harness: harness,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );

      final result = await harness.handoffs.completeInitiator(
        handshakeId: exchange.outbound.handshakeId,
        expectedStateDigest: exchange.outbound.stateDigest,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: exchange.responder.reply,
        preparedAt: DateTime.utc(2026, 8, 15, 1),
        completedAt: DateTime.utc(2026, 8, 15, 1, 1),
      );

      expect(result.role, V3SessionRole.initiator);
      expect(result.recovered, isFalse);
      expect(harness.sessions.sessionCount, 1);
      expect(await harness.handshakes.pendingOutbound(), isEmpty);
      expect(
        (await harness.handshakes.completedConfirmationForId(
          result.handshakeId,
        ))!
            .outboundRecord,
        orderedEquals(result.confirmationRecord),
      );
      expect(
        store.records.values.where((value) =>
            value['kind'] == V3HandshakeHandoffRepository.recordKind),
        isEmpty,
      );
      final session = await harness.sessions.snapshotForSession(
        _decodeId(result.sessionId),
      );
      expect(session.revision, 0);
      expect(session.role, V3SessionRole.initiator);
      session.wipeSecrets();

      exchange.responder.close();
      await harness.close();
    });

    test('pinned handoff backend rejects a divergent backend before crypto',
        () async {
      final store = _FaultStore();
      final pinned = _InitialSckaBackend();
      final divergent = _InitialSckaBackend();
      final harness = _Harness(store, sckaBackend: pinned);
      await harness.restore();
      final exchange = await _initiatorExchange(
        harness: harness,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );

      await expectLater(
        harness.handoffs.completeInitiator(
          handshakeId: exchange.outbound.handshakeId,
          expectedStateDigest: exchange.outbound.stateDigest,
          localIdentity: alice,
          localDevice: aliceDevice,
          responderIdentity: bob.publicIdentity,
          reply: exchange.responder.reply,
          backend: divergent,
        ),
        throwsStateError,
      );

      expect(pinned.initializeCount, 0);
      expect(divergent.initializeCount, 0);
      expect(harness.sessions.sessionCount, 0);
      expect(
        store.records.values.where(
          (value) => value['kind'] == V3HandshakeHandoffRepository.recordKind,
        ),
        isEmpty,
      );
      exchange.responder.close();
      await harness.close();
    });

    test('commits responder TR3 from the exact authenticated confirmation',
        () async {
      final store = _FaultStore();
      final harness = _Harness(store);
      await harness.restore();
      final offer = await V3HybridHandshake.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.maximum,
      );
      final replyOutbound = await harness.handshakes.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: offer.offer,
        expectedMode: V3HandshakeMode.maximum,
      );
      final reply = V3HandshakeCodec.decodeReply(replyOutbound.outboundRecord);
      final initiator = await V3HybridHandshake.acceptReply(
        pending: offer,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: reply,
      );

      final result = await harness.handoffs.completeResponder(
        handshakeId: replyOutbound.handshakeId,
        expectedStateDigest: replyOutbound.stateDigest,
        initiatorIdentity: alice.publicIdentity,
        responderIdentity: bob.publicIdentity,
        confirmation: initiator.confirmation,
        backend: scka,
      );

      expect(result.role, V3SessionRole.responder);
      final session = await harness.sessions.snapshotForSession(
        _decodeId(result.sessionId),
      );
      expect(session.role, V3SessionRole.responder);
      expect(session.revision, 0);
      session.wipeSecrets();
      initiator.established.close();
      await harness.close();
    });

    test('durable-then-throw preparation recovers without rerunning crypto',
        () async {
      final store = _FaultStore()
        ..persistAndThrowKindOnce = V3HandshakeHandoffRepository.recordKind;
      final first = _Harness(store);
      await first.restore();
      final exchange = await _initiatorExchange(
        harness: first,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );

      await expectLater(
        first.handoffs.completeInitiator(
          handshakeId: exchange.outbound.handshakeId,
          expectedStateDigest: exchange.outbound.stateDigest,
          localIdentity: alice,
          localDevice: aliceDevice,
          responderIdentity: bob.publicIdentity,
          reply: exchange.responder.reply,
          backend: scka,
        ),
        throwsStateError,
      );
      expect(first.handoffs.requiresRecovery, isTrue);
      final initialized = scka.initializeCount;
      await first.close();

      final recovered = _Harness(store);
      final restored = await recovered.restore();
      expect(restored.recoveredHandoffs, hasLength(1));
      expect(restored.recoveredHandoffs.single.recovered, isTrue);
      expect(scka.initializeCount, initialized);
      expect(recovered.sessions.sessionCount, 1);
      expect(await recovered.handshakes.pendingOutbound(), isEmpty);
      expect(
        store.records.values.where((value) =>
            value['kind'] == V3HandshakeHandoffRepository.recordKind),
        isEmpty,
      );

      exchange.responder.close();
      await recovered.close();
    });

    test('ambiguous checkpoint write resumes exact prepared TR3', () async {
      final store = _FaultStore()
        ..persistAndThrowKindOnce = V3SessionCheckpointRepository.recordKind;
      final first = _Harness(store);
      await first.restore();
      final exchange = await _initiatorExchange(
        harness: first,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );

      await expectLater(
        first.handoffs.completeInitiator(
          handshakeId: exchange.outbound.handshakeId,
          expectedStateDigest: exchange.outbound.stateDigest,
          localIdentity: alice,
          localDevice: aliceDevice,
          responderIdentity: bob.publicIdentity,
          reply: exchange.responder.reply,
          backend: scka,
        ),
        throwsStateError,
      );
      final initialized = scka.initializeCount;
      await first.close();

      final recovered = _Harness(store);
      final restored = await recovered.restore();
      expect(restored.recoveredHandoffs, hasLength(1));
      expect(scka.initializeCount, initialized);
      expect(
        store.records.values.where((value) =>
            value['kind'] == V3SessionCheckpointRepository.recordKind),
        hasLength(1),
      );
      expect(await recovered.handshakes.pendingOutbound(), isEmpty);

      exchange.responder.close();
      await recovered.close();
    });

    test('ambiguous completion write restores tombstone then collects prepare',
        () async {
      final store = _FaultStore()
        ..persistAndThrowKindOnce =
            V3HandshakePendingRepository.completionRecordKind;
      final first = _Harness(store);
      await first.restore();
      final exchange = await _initiatorExchange(
        harness: first,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );

      await expectLater(
        first.handoffs.completeInitiator(
          handshakeId: exchange.outbound.handshakeId,
          expectedStateDigest: exchange.outbound.stateDigest,
          localIdentity: alice,
          localDevice: aliceDevice,
          responderIdentity: bob.publicIdentity,
          reply: exchange.responder.reply,
          backend: scka,
        ),
        throwsStateError,
      );
      expect(first.sessions.isRestored, isFalse);
      expect(first.handshakes.isRestored, isFalse);
      await first.close();

      final recovered = _Harness(store);
      final restored = await recovered.restore();
      expect(restored.recoveredHandoffs, hasLength(1));
      expect(await recovered.handshakes.pendingOutbound(), isEmpty);
      expect(
        await recovered.handshakes.completedConfirmationForId(
          exchange.outbound.handshakeId,
        ),
        isNotNull,
      );
      expect(
        store.records.values.where((value) =>
            value['kind'] == V3HandshakeHandoffRepository.recordKind),
        isEmpty,
      );

      exchange.responder.close();
      await recovered.close();
    });

    test('ambiguous prepare deletion is idempotently collected on restart',
        () async {
      final store = _FaultStore()
        ..deleteAndThrowKindOnce = V3HandshakeHandoffRepository.recordKind;
      final first = _Harness(store);
      await first.restore();
      final exchange = await _initiatorExchange(
        harness: first,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );

      await expectLater(
        first.handoffs.completeInitiator(
          handshakeId: exchange.outbound.handshakeId,
          expectedStateDigest: exchange.outbound.stateDigest,
          localIdentity: alice,
          localDevice: aliceDevice,
          responderIdentity: bob.publicIdentity,
          reply: exchange.responder.reply,
          backend: scka,
        ),
        throwsStateError,
      );
      await first.close();

      final recovered = _Harness(store);
      final restored = await recovered.restore();
      // The delete itself was durable before its injected error, so no prepare
      // remains to replay; checkpoint and completion still restore atomically.
      expect(restored.recoveredHandoffs, isEmpty);
      expect(recovered.sessions.sessionCount, 1);
      expect(
        await recovered.handshakes.completedConfirmationForId(
          exchange.outbound.handshakeId,
        ),
        isNotNull,
      );

      exchange.responder.close();
      await recovered.close();
    });

    test('completed initiator retry returns exact confirmation without SCKA',
        () async {
      final store = _FaultStore();
      final harness = _Harness(store);
      await harness.restore();
      final exchange = await _initiatorExchange(
        harness: harness,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      final first = await harness.handoffs.completeInitiator(
        handshakeId: exchange.outbound.handshakeId,
        expectedStateDigest: exchange.outbound.stateDigest,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: exchange.responder.reply,
        backend: scka,
      );
      final initialized = scka.initializeCount;

      final retry = await harness.handoffs.completeInitiator(
        handshakeId: exchange.outbound.handshakeId,
        expectedStateDigest: exchange.outbound.stateDigest,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: exchange.responder.reply,
        backend: scka,
      );

      expect(retry.recovered, isTrue);
      expect(retry.confirmationRecord, orderedEquals(first.confirmationRecord));
      expect(retry.checkpointDigest, first.checkpointDigest);
      expect(scka.initializeCount, initialized);

      exchange.responder.close();
      await harness.close();
    });

    test('completion without any durable session checkpoint fails closed',
        () async {
      final store = _FaultStore();
      final first = _Harness(store);
      await first.restore();
      final exchange = await _initiatorExchange(
        harness: first,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      await first.handoffs.completeInitiator(
        handshakeId: exchange.outbound.handshakeId,
        expectedStateDigest: exchange.outbound.stateDigest,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: exchange.responder.reply,
        backend: scka,
      );
      await first.close();
      store.records.removeWhere(
        (_, value) => value['kind'] == V3SessionCheckpointRepository.recordKind,
      );

      final recovered = _Harness(store);
      await expectLater(
        recovered.restore(),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(
        store.records.values.where(
          (value) =>
              value['kind'] ==
              V3HandshakePendingRepository.completionRecordKind,
        ),
        hasLength(1),
      );
      await recovered.close();

      exchange.responder.close();
    });

    test('capacity rejects before handshake acceptance and SCKA initialization',
        () async {
      final store = _FaultStore();
      final harness = _Harness(
        store,
        handoffRepository: V3HandshakeHandoffRepository(
          store: store,
          maxTotalRetainedBytes: 1,
        ),
      );
      await harness.restore();
      final exchange = await _initiatorExchange(
        harness: harness,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );

      await expectLater(
        harness.handoffs.completeInitiator(
          handshakeId: exchange.outbound.handshakeId,
          expectedStateDigest: exchange.outbound.stateDigest,
          localIdentity: alice,
          localDevice: aliceDevice,
          responderIdentity: bob.publicIdentity,
          reply: exchange.responder.reply,
          backend: scka,
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(scka.initializeCount, 0);
      expect(harness.handoffs.requiresRecovery, isFalse);
      expect(await harness.handshakes.pendingOutbound(), hasLength(1));

      exchange.responder.close();
      await harness.close();
    });

    test('corrupt prepared snapshot fails closed and remains stored', () async {
      final store = _FaultStore()
        ..persistAndThrowKindOnce = V3HandshakeHandoffRepository.recordKind;
      final first = _Harness(store);
      await first.restore();
      final exchange = await _initiatorExchange(
        harness: first,
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      await expectLater(
        first.handoffs.completeInitiator(
          handshakeId: exchange.outbound.handshakeId,
          expectedStateDigest: exchange.outbound.stateDigest,
          localIdentity: alice,
          localDevice: aliceDevice,
          responderIdentity: bob.publicIdentity,
          reply: exchange.responder.reply,
          backend: scka,
        ),
        throwsStateError,
      );
      await first.close();
      final handoffEntry = store.records.entries.singleWhere(
        (entry) =>
            entry.value['kind'] == V3HandshakeHandoffRepository.recordKind,
      );
      final snapshot = handoffEntry.value['snapshot'] as String;
      handoffEntry.value['snapshot'] =
          '${snapshot.substring(0, snapshot.length - 1)}${snapshot.endsWith('A') ? 'B' : 'A'}';

      final recovered = _Harness(store);
      await expectLater(recovered.restore(), throwsFormatException);
      expect(store.records.containsKey(handoffEntry.key), isTrue);
      await recovered.close();
      exchange.responder.close();
    });
  });
}

final class _Harness {
  _Harness(
    this.store, {
    V3HandshakeHandoffRepository? handoffRepository,
    V3SckaBackend? sckaBackend,
  }) {
    initialHandoffAuthority = V3InitialSessionHandoffAuthority();
    inbox = V3LmfDurableInbox(store: store);
    handshakes = V3HandshakePersistenceController(
      repository: V3HandshakePendingRepository(store: store),
      initialHandoffAuthority: initialHandoffAuthority,
    );
    sessions = V3SessionCommitController(
      journal: V3LmfAtomicCommitJournal(store: store, inbox: inbox),
      sckaBackend: sckaBackend,
      committedRecordMaterializer: V3CommittedRecordMaterializer(store: store),
      checkpointRepository: V3SessionCheckpointRepository(store: store),
      initialHandoffAuthority: initialHandoffAuthority,
    );
    handoffs = V3HandshakeSessionHandoffController(
      repository:
          handoffRepository ?? V3HandshakeHandoffRepository(store: store),
      handshakes: handshakes,
      sessions: sessions,
      initialHandoffAuthority: initialHandoffAuthority,
      sckaBackend: sckaBackend,
    );
  }

  final _FaultStore store;
  late final V3InitialSessionHandoffAuthority initialHandoffAuthority;
  late final V3LmfDurableInbox inbox;
  late final V3HandshakePersistenceController handshakes;
  late final V3SessionCommitController sessions;
  late final V3HandshakeSessionHandoffController handoffs;

  Future<V3HandshakeSessionHandoffRestoreResult> restore() async {
    await restoreDependencies();
    return handoffs.restore();
  }

  Future<void> restoreDependencies() async {
    await inbox.restore(keyResolver: (_) => null);
    await handshakes.restore();
    await sessions.restore(checkpoints: const []);
  }

  Future<void> close() async {
    await handoffs.close();
    await handshakes.close();
    await sessions.close();
    await inbox.close();
  }
}

final class _InitiatorExchange {
  const _InitiatorExchange({
    required this.outbound,
    required this.responder,
  });

  final V3DurableHandshakeOutbound outbound;
  final V3ResponderPendingHandshake responder;
}

Future<_InitiatorExchange> _initiatorExchange({
  required _Harness harness,
  required V3LocalIdentityHandle alice,
  required V3LocalDeviceHandle aliceDevice,
  required V3LocalIdentityHandle bob,
  required V3LocalDeviceHandle bobDevice,
}) async {
  final outbound = await harness.handshakes.createOffer(
    localIdentity: alice,
    localDevice: aliceDevice,
    remoteIdentity: bob.publicIdentity,
    mode: V3HandshakeMode.normal,
  );
  final offer = V3HandshakeCodec.decodeOffer(outbound.outboundRecord);
  final responder = await V3HybridHandshake.createReply(
    localIdentity: bob,
    localDevice: bobDevice,
    initiatorIdentity: alice.publicIdentity,
    offer: offer,
    expectedMode: V3HandshakeMode.normal,
  );
  return _InitiatorExchange(outbound: outbound, responder: responder);
}

final class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  int _nextId = 0;
  String? persistAndThrowKindOnce;
  String? deleteAndThrowKindOnce;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final storageId = 'record-${_nextId++}';
    records[storageId] = _copy(payload);
    if (persistAndThrowKindOnce == payload['kind']) {
      persistAndThrowKindOnce = null;
      throw StateError('persisted then failed');
    }
    return storageId;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => records.entries
      .map(
        (entry) => V3LmfStoredRecord(
          storageId: entry.key,
          payload: _copy(entry.value),
        ),
      )
      .toList(growable: false);

  @override
  Future<void> delete(String storageId) async {
    final kind = records[storageId]?['kind'];
    records.remove(storageId);
    if (deleteAndThrowKindOnce == kind) {
      deleteAndThrowKindOnce = null;
      throw StateError('deleted then failed');
    }
  }
}

final class _InitialSckaBackend implements V3SckaBackend {
  int initializeCount = 0;

  @override
  String get implementationId => 'layergram-test-initial-scka/1';

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
  }) async {
    initializeCount++;
    return Uint8List.fromList(
      sha256.convert(<int>[
        ...'test-only-initial-scka\x00'.codeUnits,
        role.wireId,
        ...sessionId,
        ...sharedSecret,
        ...stateSealKey,
      ]).bytes,
    );
  }

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    if (sessionId.length != 16 ||
        authenticatedState.length != 32 ||
        authenticatedState.every((byte) => byte == 0) ||
        expectedStateRevision != 0) {
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
  }) =>
      throw UnimplementedError();

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) =>
      throw UnimplementedError();
}

final class _HandshakeMlKemPrivateKeyHandle
    implements MlKem768PrivateKeyHandle {
  _HandshakeMlKemPrivateKeyHandle(this.publicKey);

  final Uint8List publicKey;

  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    isClosed = true;
  }
}

final class _HandshakeMlKemBackend implements MlKem768Backend {
  int _encapsulationCounter = 0;

  @override
  String get implementationId => 'test-only-handoff-ml-kem';

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
      privateKeyHandle: _HandshakeMlKemPrivateKeyHandle(publicKey),
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
    final handle = privateKeyHandle as _HandshakeMlKemPrivateKeyHandle;
    if (handle.isClosed || ciphertext.length != MlKem768.ciphertextBytes) {
      throw StateError('invalid test ML-KEM handle or ciphertext');
    }
    return _sharedSecret(handle.publicKey, ciphertext);
  }

  Uint8List _sharedSecret(Uint8List publicKey, Uint8List ciphertext) =>
      Uint8List.fromList(
        sha256.convert(<int>[
          ...'test-only-handshake-shared\x00'.codeUnits,
          ...publicKey,
          ...ciphertext,
        ]).bytes,
      );
}

Map<String, dynamic> _copy(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

Uint8List _decodeId(String value) =>
    Uint8List.fromList(base64Url.decode(base64Url.normalize(value)));

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
