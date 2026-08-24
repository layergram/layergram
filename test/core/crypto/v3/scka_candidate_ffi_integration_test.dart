import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/pq_message_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/scka_candidate_ffi.dart';
import 'package:layergram/core/crypto/v3/session_persistence_scope_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  final candidatePath =
      Platform.environment['LAYERGRAM_SCKA_CANDIDATE_LIBRARY'];
  final scaffoldPath = Platform.environment['LAYERGRAM_SCKA_SCAFFOLD_LIBRARY'];

  test(
    'default scaffold cannot satisfy the candidate build allowlist',
    () {
      expect(
        () => V3SckaCandidateFfiBackend.open(libraryPath: scaffoldPath!),
        throwsStateError,
      );
    },
    skip: scaffoldPath == null,
  );

  test(
    'real LS3 candidate commits exact TR3 and frames across send receive restarts',
    () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      final temporaryDirectory =
          await Directory.systemTemp.createTemp('layergram_scka_candidate_');
      Hive.init(temporaryDirectory.path);
      await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
      final box = Hive.box<Map>(LocalDatabase.messagesBoxName);
      final auxiliaryKey =
          await AuxRecordCipher.deriveAuxStorageKey(_bytes(32, 0x77));
      final backend = V3SckaCandidateFfiBackend.open(
        libraryPath: candidatePath!,
      );
      final pair = await _nativePair(backend);
      final plaintext = _bytes(700, 0x45);
      final encodedFrames = <Uint8List>[];
      V3SessionPersistenceScope? aliceScope;
      V3SessionPersistenceScope? bobScope;
      V3SessionPersistenceScope? restoredAlice;
      V3SessionPersistenceScope? resumedBob;
      V3SessionPersistenceScope? restoredBob;
      Uint8List? deliveredPlaintext;
      try {
        expect(backend.implementationId,
            V3SckaCandidateFfiBackend.approvedImplementationId);
        expect(await backend.selfTest(), isTrue);

        aliceScope = await V3SessionPersistenceScope.open(
          scopeToken: 'native-send-0001',
          auxStorageKey: auxiliaryKey,
          sckaBackend: backend,
        );
        await aliceScope.restore(
          checkpoints: <V3TripleRatchetState>[pair.alice],
        );
        final sent = await aliceScope.sendMessage(
          sessionId: pair.alice.sessionId,
          expectedRevision: 0,
          plaintext: plaintext,
        );
        expect(sent.ratchetRevision, 1);
        expect(sent.frames.length, greaterThan(1));
        encodedFrames.addAll(
          sent.frames.map(V3LmfFrameCodec.encodeBinary),
        );
        final sentSnapshot =
            await aliceScope.snapshotForSession(pair.alice.sessionId);
        try {
          expect(sentSnapshot.revision, 1);
          await V3SparsePqRatchet.validateSnapshot(
            backend: backend,
            snapshot: sentSnapshot,
          );
        } finally {
          sentSnapshot.wipeSecrets();
        }
        await aliceScope.close();
        aliceScope = null;

        restoredAlice = await V3SessionPersistenceScope.open(
          scopeToken: 'native-send-0001',
          auxStorageKey: auxiliaryKey,
          sckaBackend: backend,
        );
        final aliceRestore = await restoredAlice.restore(
          checkpoints: const <V3TripleRatchetState>[],
        );
        expect(aliceRestore.sessions.sessionRevisions.values, <int>[1]);
        final retryFrames = await restoredAlice.pendingSendFrames(
          sent.assemblyId,
        );
        expect(retryFrames, hasLength(encodedFrames.length));
        for (var index = 0; index < retryFrames.length; index++) {
          expect(
            V3LmfFrameCodec.encodeBinary(retryFrames[index]),
            orderedEquals(encodedFrames[index]),
          );
        }

        bobScope = await V3SessionPersistenceScope.open(
          scopeToken: 'native-recv-0001',
          auxStorageKey: auxiliaryKey,
          sckaBackend: backend,
        );
        await bobScope.restore(
          checkpoints: <V3TripleRatchetState>[pair.bob],
        );
        final delayed = await bobScope.receiveFrame(
          frame: V3LmfFrameCodec.decodeBinary(encodedFrames.last),
          nowUnixSeconds: 7000,
        );
        expect(delayed.status, V3LmfInboxStatus.deferred);
        final duplicate = await bobScope.receiveFrame(
          frame: V3LmfFrameCodec.decodeBinary(encodedFrames.last),
          nowUnixSeconds: 7000,
        );
        expect(duplicate.status, V3LmfInboxStatus.duplicate);
        await bobScope.close();
        bobScope = null;

        resumedBob = await V3SessionPersistenceScope.open(
          scopeToken: 'native-recv-0001',
          auxStorageKey: auxiliaryKey,
          sckaBackend: backend,
        );
        final resumedState = await resumedBob.restore(
          checkpoints: const <V3TripleRatchetState>[],
        );
        expect(resumedState.inbox.deferredFrames, 1);
        expect(resumedState.sessions.sessionRevisions.values, <int>[0]);
        V3SessionInboundFrameResult? completed;
        for (final encoded in encodedFrames.reversed.skip(1)) {
          final received = await resumedBob.receiveFrame(
            frame: V3LmfFrameCodec.decodeBinary(encoded),
            nowUnixSeconds: 7000,
          );
          if (received.delivery != null) completed = received;
        }
        expect(completed, isNotNull);
        expect(completed!.status, V3LmfInboxStatus.complete);
        deliveredPlaintext = completed.delivery!.plaintext;
        expect(deliveredPlaintext, orderedEquals(plaintext));
        final committed = await resumedBob.commitDelivery(
          delivery: completed.delivery!,
        );
        expect(committed.ratchetRevision, 1);
        final receivedSnapshot =
            await resumedBob.snapshotForSession(pair.bob.sessionId);
        try {
          expect(receivedSnapshot.revision, 1);
          await V3SparsePqRatchet.validateSnapshot(
            backend: backend,
            snapshot: receivedSnapshot,
          );
        } finally {
          receivedSnapshot.wipeSecrets();
        }
        await resumedBob.close();
        resumedBob = null;

        restoredBob = await V3SessionPersistenceScope.open(
          scopeToken: 'native-recv-0001',
          auxStorageKey: auxiliaryKey,
          sckaBackend: backend,
        );
        final bobRestore = await restoredBob.restore(
          checkpoints: const <V3TripleRatchetState>[],
        );
        expect(bobRestore.inbox.deferredFrames, 0);
        expect(bobRestore.sessions.sessionRevisions.values, <int>[1]);
        final replay = await restoredBob.receiveFrame(
          frame: V3LmfFrameCodec.decodeBinary(encodedFrames.first),
          nowUnixSeconds: 7000,
        );
        expect(replay.status, V3LmfInboxStatus.committedReplay);
        expect(replay.delivery, isNull);

        expect(box.values, isNotEmpty);
        for (final record in box.values) {
          expect(record.keys, {'encryptedRecord'});
          expect(record['encryptedRecord'], isA<String>());
        }
      } finally {
        await aliceScope?.close();
        await bobScope?.close();
        await restoredAlice?.close();
        await resumedBob?.close();
        await restoredBob?.close();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
        _wipe(plaintext);
        if (deliveredPlaintext != null) _wipe(deliveredPlaintext);
        for (final frame in encodedFrames) {
          _wipe(frame);
        }
        await Hive.close();
        await temporaryDirectory.delete(recursive: true);
      }
    },
    skip: candidatePath == null,
  );
}

Future<({V3TripleRatchetState alice, V3TripleRatchetState bob})> _nativePair(
  V3SckaBackend backend,
) async {
  final sessionId = _bytes(16, 0x11);
  final sharedSecret = _bytes(32, 0x41);
  final stateSealKey = _bytes(32, 0xf1);
  final pqSeed = _bytes(32, 0x31);
  final aliceNative = await V3SparsePqRatchet.initialize(
    backend: backend,
    role: V3SessionRole.initiator,
    sessionId: sessionId,
    sharedSecret: sharedSecret,
    stateSealKey: stateSealKey,
  );
  final bobNative = await V3SparsePqRatchet.initialize(
    backend: backend,
    role: V3SessionRole.responder,
    sessionId: sessionId,
    sharedSecret: sharedSecret,
    stateSealKey: stateSealKey,
  );
  final alicePq = await V3PqMessageRatchet.deriveInitialEpoch(
    role: V3SessionRole.initiator,
    sessionId: sessionId,
    pqRootSeed: pqSeed,
  );
  final bobPq = await V3PqMessageRatchet.deriveInitialEpoch(
    role: V3SessionRole.responder,
    sessionId: sessionId,
    pqRootSeed: pqSeed,
  );
  final x25519 = X25519();
  final alicePrivate = _bytes(32, 0x51);
  final bobPrivate = _bytes(32, 0x91);
  final alicePublic = Uint8List.fromList(
    (await (await x25519.newKeyPairFromSeed(alicePrivate)).extractPublicKey())
        .bytes,
  );
  final bobPublic = Uint8List.fromList(
    (await (await x25519.newKeyPairFromSeed(bobPrivate)).extractPublicKey())
        .bytes,
  );
  final aliceToBobEc = _bytes(32, 0xb1);
  final bobToAliceEc = _bytes(32, 0xd1);
  V3TripleRatchetState? alice;
  V3TripleRatchetState? bob;
  try {
    alice = _snapshot(
      role: V3SessionRole.initiator,
      sessionId: sessionId,
      ecPrivate: alicePrivate,
      ecPublic: alicePublic,
      ecRemote: bobPublic,
      ecSending: aliceToBobEc,
      ecReceiving: null,
      pqRoot: alicePq.rootKey,
      pqEpoch: alicePq.epoch,
      stateSealKey: stateSealKey,
      nativeState: aliceNative,
    );
    bob = _snapshot(
      role: V3SessionRole.responder,
      sessionId: sessionId,
      ecPrivate: bobPrivate,
      ecPublic: bobPublic,
      ecRemote: alicePublic,
      ecSending: bobToAliceEc,
      ecReceiving: aliceToBobEc,
      pqRoot: bobPq.rootKey,
      pqEpoch: bobPq.epoch,
      stateSealKey: stateSealKey,
      nativeState: bobNative,
    );
    final result = (alice: alice, bob: bob);
    alice = null;
    bob = null;
    return result;
  } finally {
    alice?.wipeSecrets();
    bob?.wipeSecrets();
    alicePq.epoch.wipeSecrets();
    bobPq.epoch.wipeSecrets();
    _wipe(alicePq.rootKey);
    _wipe(bobPq.rootKey);
    _wipe(aliceNative);
    _wipe(bobNative);
    _wipe(sessionId);
    _wipe(sharedSecret);
    _wipe(stateSealKey);
    _wipe(pqSeed);
    _wipe(alicePrivate);
    _wipe(bobPrivate);
    _wipe(alicePublic);
    _wipe(bobPublic);
    _wipe(aliceToBobEc);
    _wipe(bobToAliceEc);
  }
}

V3TripleRatchetState _snapshot({
  required V3SessionRole role,
  required Uint8List sessionId,
  required Uint8List ecPrivate,
  required Uint8List ecPublic,
  required Uint8List ecRemote,
  required Uint8List ecSending,
  required Uint8List? ecReceiving,
  required Uint8List pqRoot,
  required V3PqEpochState pqEpoch,
  required Uint8List stateSealKey,
  required Uint8List nativeState,
}) =>
    V3TripleRatchetState(
      role: role,
      lifecycle: V3RatchetLifecycle.active,
      revision: 0,
      sessionId: sessionId,
      transcriptDigest: _bytes(48, 0x21),
      initiatorRoutingBinding: _bytes(32, 0x31),
      responderRoutingBinding: _bytes(32, 0x71),
      initiatorToResponderAckRootKey: _bytes(32, 0xa1),
      responderToInitiatorAckRootKey: _bytes(32, 0xc1),
      ecRootKey: _bytes(32, 0xe1),
      ecSendingChainKey: ecSending,
      ecReceivingChainKey: ecReceiving,
      ecLocalDhPrivateKey: ecPrivate,
      ecLocalDhPublicKey: ecPublic,
      ecRemoteDhPublicKey: ecRemote,
      ecSendCounter: 0,
      ecReceiveCounter: 0,
      ecPreviousSendingChainLength: 0,
      pqRootKey: pqRoot,
      sckaStateSealKey: stateSealKey,
      pqCurrentEpoch: 0,
      pqSendingEpoch: 0,
      pqReceivingEpoch: 0,
      pqEpochStates: <V3PqEpochState>[pqEpoch],
      nativeSckaState: nativeState,
    );

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
