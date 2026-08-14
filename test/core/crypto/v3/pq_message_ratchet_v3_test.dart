import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_atomic_commit.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/pq_message_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/session_ratchet_key_resolver_v3.dart';
import 'package:layergram/core/crypto/v3/session_commit_controller_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_engine_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  group('protocol v3 Sparse-PQ message ratchet', () {
    test('initial epoch derives matching directional chains', () async {
      final sessionId = _bytes(16, 0x11);
      final seed = _bytes(32, 0x31);
      final initiator = await V3PqMessageRatchet.deriveInitialEpoch(
        role: V3SessionRole.initiator,
        sessionId: sessionId,
        pqRootSeed: seed,
      );
      final responder = await V3PqMessageRatchet.deriveInitialEpoch(
        role: V3SessionRole.responder,
        sessionId: sessionId,
        pqRootSeed: seed,
      );
      final initiatorSending = initiator.epoch.sendingChainKey!;
      final initiatorReceiving = initiator.epoch.receivingChainKey!;
      final responderSending = responder.epoch.sendingChainKey!;
      final responderReceiving = responder.epoch.receivingChainKey!;
      try {
        expect(initiator.rootKey, orderedEquals(responder.rootKey));
        expect(
          _hex(initiator.rootKey),
          '10b41e054ec17f83eae13159a803b5f701da201b4ddec3f64a6061cd8b5c2f21',
        );
        expect(
          _hex(initiatorSending),
          'dbda34bc9dc4e2c1d267fbe402eb2874ae611b68d6e258af16428b1bb217500c',
        );
        expect(
          _hex(initiatorReceiving),
          '29d77d7b0bb350e7514fb9108cff9bb9e3be604dff1fc5ee5d21a33ea5685073',
        );
        expect(initiatorSending, orderedEquals(responderReceiving));
        expect(initiatorReceiving, orderedEquals(responderSending));
        expect(initiatorSending, isNot(orderedEquals(initiatorReceiving)));
      } finally {
        _wipe(initiator.rootKey);
        _wipe(responder.rootKey);
        _wipe(initiatorSending);
        _wipe(initiatorReceiving);
        _wipe(responderSending);
        _wipe(responderReceiving);
        initiator.epoch.wipeSecrets();
        responder.epoch.wipeSecrets();
      }
    });

    test('new output epoch is independent from the current message epoch',
        () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final originalAlice = V3TripleRatchetStateCodec.encode(pair.alice);
      final originalBob = V3TripleRatchetStateCodec.encode(pair.bob);
      final sent = await _send(pair.alice, backend);
      final received = await _receive(
        pair.bob,
        backend,
        sent,
        nowUnixSeconds: 1000,
      );
      try {
        expect(sent.message.sendingEpoch, 0);
        expect(sent.message.messageCounter, 0);
        expect(sent.snapshot.pqCurrentEpoch, 1);
        expect(sent.snapshot.pqSendingEpoch, 0);
        expect(received.snapshot.pqCurrentEpoch, 1);
        expect(received.snapshot.pqReceivingEpoch, 0);
        expect(received.pqMessageKey, orderedEquals(sent.pqMessageKey));
        expect(
          V3TripleRatchetStateCodec.encode(pair.alice),
          orderedEquals(originalAlice),
        );
        expect(
          V3TripleRatchetStateCodec.encode(pair.bob),
          orderedEquals(originalBob),
        );
      } finally {
        sent.close();
        received.close();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
        _wipe(originalAlice);
        _wipe(originalBob);
      }
    });

    test('recovers bounded out-of-order keys without advancing old state',
        () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final message0 = await _send(pair.alice, backend);
      final receive0 = await _receive(
        pair.bob,
        backend,
        message0,
        nowUnixSeconds: 2000,
      );
      final message1 = await _send(message0.snapshot, backend);
      final message2 = await _send(message1.snapshot, backend);
      final receive2 = await _receive(
        receive0.snapshot,
        backend,
        message2,
        nowUnixSeconds: 2001,
      );
      final receive1 = await _receive(
        receive2.snapshot,
        backend,
        message1,
        nowUnixSeconds: 2002,
      );
      try {
        expect(message1.message.sendingEpoch, 1);
        expect(message1.message.messageCounter, 0);
        expect(message2.message.sendingEpoch, 1);
        expect(message2.message.messageCounter, 1);
        expect(receive2.pqMessageKey, orderedEquals(message2.pqMessageKey));
        expect(receive1.pqMessageKey, orderedEquals(message1.pqMessageKey));
        expect(receive2.snapshot.pqSkippedMessageKeys, hasLength(1));
        expect(receive1.snapshot.pqSkippedMessageKeys, isEmpty);
        expect(receive1.snapshot.pqReceivingEpoch, 1);
      } finally {
        message0.close();
        receive0.close();
        message1.close();
        message2.close();
        receive2.close();
        receive1.close();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
      }
    });

    test(
        'receives a delayed retained epoch without lowering its high-water mark',
        () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final delayedEpoch0 = await _send(pair.alice, backend);
      final epoch1 = await _send(delayedEpoch0.snapshot, backend);
      final receiveEpoch1 = await _receive(
        pair.bob,
        backend,
        epoch1,
        nowUnixSeconds: 2100,
      );
      final receiveEpoch0 = await _receive(
        receiveEpoch1.snapshot,
        backend,
        delayedEpoch0,
        nowUnixSeconds: 2101,
      );
      try {
        expect(epoch1.message.sendingEpoch, 1);
        expect(delayedEpoch0.message.sendingEpoch, 0);
        expect(receiveEpoch1.snapshot.pqReceivingEpoch, 1);
        expect(receiveEpoch0.snapshot.pqReceivingEpoch, 1);
        expect(
          receiveEpoch0.pqMessageKey,
          orderedEquals(delayedEpoch0.pqMessageKey),
        );
      } finally {
        delayedEpoch0.close();
        epoch1.close();
        receiveEpoch1.close();
        receiveEpoch0.close();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
      }
    });

    test('rejects a gap larger than the retained-key bound', () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final message = V3SckaMessage(
        sendingEpoch: 0,
        messageCounter: V3PqMessageRatchet.maxSkippedMessageKeys + 1,
        nativePayload: Uint8List.fromList(<int>[1]),
      );
      await expectLater(
        V3PqMessageRatchet.receive(
          snapshot: pair.bob,
          backend: backend,
          message: message,
          nowUnixSeconds: 3000,
          skippedKeyLifetimeSeconds: 100,
        ),
        throwsFormatException,
      );
      pair.alice.wipeSecrets();
      pair.bob.wipeSecrets();
    });

    test('rejects EC and PQ candidates derived from same-revision forks',
        () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final encodedFork = V3TripleRatchetStateCodec.encode(pair.alice)
        ..[430] ^= 1;
      final fork = V3TripleRatchetStateCodec.decode(encodedFork);
      final ecState = await V3EcDoubleRatchet.restore(pair.alice);
      final ec = await V3EcDoubleRatchet.send(ecState);
      final pq = await V3PqMessageRatchet.send(
        snapshot: fork,
        backend: backend,
      );
      try {
        expect(pair.alice.sessionId, orderedEquals(fork.sessionId));
        expect(pair.alice.revision, fork.revision);
        expect(
          () => pq.toTripleRatchetSnapshot(
            previous: fork,
            ecCandidate: ec.nextState,
          ),
          throwsStateError,
        );
      } finally {
        pq.close();
        ec.close();
        ecState.close();
        fork.wipeSecrets();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
        _wipe(encodedFork);
      }
    });
  });

  group('protocol v3 Triple Ratchet engine', () {
    test('seals and opens one frame with one exact hybrid candidate', () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final plaintext = _bytes(20, 0x41);
      V3TripleRatchetTransition? sent;
      V3TripleRatchetTransition? received;
      Uint8List? nonce;
      Uint8List? opened;
      try {
        sent = await V3TripleRatchetEngine.send(
          snapshot: pair.alice,
          backend: backend,
          kind: V3LmfFrameKind.application,
        );
        nonce = await sent.nonceForFragment(
          fragmentIndex: 0,
          fragmentCount: 1,
          assembledPlaintextLength: plaintext.length,
        );
        final frame = await V3LmfAead.sealSingle(
          metadata: sent.metadata,
          plaintext: plaintext,
          secretKey: sent.secretKey,
          nonce: nonce,
          hybridRatchetHeader: sent.header,
        );
        received = await V3TripleRatchetEngine.receiveFirstFragment(
          snapshot: pair.bob,
          backend: backend,
          metadata: frame.metadata,
          header: frame.hybridRatchetHeader!,
          nonce: frame.nonce,
          fragmentCount: frame.fragmentCount,
          assembledPlaintextLength: frame.assembledPlaintextLength,
          nowUnixSeconds: 4000,
          skippedKeyLifetimeSeconds: 100,
        );
        opened = await V3LmfAead.openSingle(
          frame: frame,
          secretKey: received.secretKey,
        );
        expect(opened, orderedEquals(plaintext));
        expect(received.messageId, orderedEquals(sent.messageId));
        expect(sent.nextSnapshot.revision, 1);
        expect(received.nextSnapshot.revision, 1);
      } finally {
        if (opened != null) _wipe(opened);
        if (nonce != null) _wipe(nonce);
        sent?.close();
        received?.close();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
        _wipe(plaintext);
      }
    });

    test('rejects visible coordinate or nonce drift without state advance',
        () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final originalBob = V3TripleRatchetStateCodec.encode(pair.bob);
      final sent = await V3TripleRatchetEngine.send(
        snapshot: pair.alice,
        backend: backend,
        kind: V3LmfFrameKind.application,
      );
      final nonce = await sent.nonceForFragment(
        fragmentIndex: 0,
        fragmentCount: 1,
        assembledPlaintextLength: 20,
      );
      final wrongCoordinates = V3LmfMessageMetadata(
        kind: sent.metadata.kind,
        senderBinding: sent.metadata.senderBinding,
        recipientBinding: sent.metadata.recipientBinding,
        messageId: sent.metadata.messageId,
        sessionId: sent.metadata.sessionId,
        epoch: sent.metadata.epoch,
        messageCounter: sent.metadata.messageCounter + 1,
      );
      await expectLater(
        V3TripleRatchetEngine.receiveFirstFragment(
          snapshot: pair.bob,
          backend: backend,
          metadata: wrongCoordinates,
          header: sent.header,
          nonce: nonce,
          fragmentCount: 1,
          assembledPlaintextLength: 20,
          nowUnixSeconds: 5000,
          skippedKeyLifetimeSeconds: 100,
        ),
        throwsFormatException,
      );
      final wrongNonce = Uint8List.fromList(nonce)..[0] ^= 1;
      await expectLater(
        V3TripleRatchetEngine.receiveFirstFragment(
          snapshot: pair.bob,
          backend: backend,
          metadata: sent.metadata,
          header: sent.header,
          nonce: wrongNonce,
          fragmentCount: 1,
          assembledPlaintextLength: 20,
          nowUnixSeconds: 5000,
          skippedKeyLifetimeSeconds: 100,
        ),
        throwsFormatException,
      );
      expect(
        V3TripleRatchetStateCodec.encode(pair.bob),
        orderedEquals(originalBob),
      );
      sent.close();
      expect(() => sent.secretKey, throwsStateError);
      _wipe(nonce);
      _wipe(wrongNonce);
      _wipe(originalBob);
      pair.alice.wipeSecrets();
      pair.bob.wipeSecrets();
    });
  });

  group('protocol v3 session key resolver', () {
    test('persists continuations before fragment zero and resumes exactly',
        () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final plaintext = _bytes(900, 0x41);
      final sent = await V3TripleRatchetEngine.send(
        snapshot: pair.alice,
        backend: backend,
        kind: V3LmfFrameKind.application,
      );
      final headerLength =
          V3HybridRatchetHeaderCodec.encode(sent.header).length;
      final fragmentCount = V3LmfFrameCodec.canonicalFragmentCount(
        assembledPlaintextLength: plaintext.length,
        hybridRatchetHeaderLength: headerLength,
      );
      final nonces = <Uint8List>[];
      for (var index = 0; index < fragmentCount; index++) {
        nonces.add(
          await sent.nonceForFragment(
            fragmentIndex: index,
            fragmentCount: fragmentCount,
            assembledPlaintextLength: plaintext.length,
          ),
        );
      }
      final frames = await V3LmfAead.sealFragmented(
        metadata: sent.metadata,
        plaintext: plaintext,
        secretKey: sent.secretKey,
        nonceForFragment: (index) => nonces[index],
        hybridRatchetHeader: sent.header,
      );
      final store = _MemoryRecordStore();
      final initialInbox = V3LmfDurableInbox(store: store);
      await initialInbox.restore(keyResolver: (_) => null);
      for (final frame in frames.skip(1).toList().reversed) {
        final outcome = await initialInbox.persistDeferred(frame: frame);
        expect(outcome.status, V3LmfInboxStatus.deferred);
      }
      await initialInbox.close();

      final inbox = V3LmfDurableInbox(store: store);
      final restoredInbox = await inbox.restore(keyResolver: (_) => null);
      expect(restoredInbox.deferredFrames, fragmentCount - 1);
      final journal = V3LmfAtomicCommitJournal(store: store, inbox: inbox);
      final controller = V3SessionCommitController(journal: journal);
      await controller.restore(checkpoints: <V3TripleRatchetState>[pair.bob]);
      final resolver = V3SessionRatchetKeyResolver(
        backend: backend,
        snapshotProvider: controller.snapshotForSession,
        skippedKeyLifetimeSeconds: 100,
      );
      Uint8List? deliveredPlaintext;
      try {
        final firstKey = await resolver.resolve(
          frames.first,
          nowUnixSeconds: 6000,
        );
        expect(firstKey, isNotNull);
        final first = await inbox.receive(
          frame: frames.first,
          secretKey: firstKey!,
        );
        expect(first.status, V3LmfInboxStatus.accepted);

        final resumed = await inbox.resumeDeferred(
          keyResolver: (frame) => resolver.resolve(frame, nowUnixSeconds: 6000),
          onAuthenticationFailure: resolver.discardUnauthenticatedFirstFragment,
        );
        expect(resumed.deferredFrames, 0);
        expect(resumed.deliveries, hasLength(1));
        final delivery = resumed.deliveries.single;
        deliveredPlaintext = delivery.plaintext;
        expect(deliveredPlaintext, orderedEquals(plaintext));
        final committed = await resolver.commitDelivery(
          delivery: delivery,
          controller: controller,
        );
        expect(committed.ratchetRevision, 1);
        final committedSnapshot =
            await controller.snapshotForSession(pair.bob.sessionId);
        expect(committedSnapshot.revision, 1);
        committedSnapshot.wipeSecrets();
        expect(resolver.pendingCandidateCount, 0);
      } finally {
        if (deliveredPlaintext != null) _wipe(deliveredPlaintext);
        await resolver.close();
        await controller.close();
        await inbox.close();
        sent.close();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
        for (final nonce in nonces) {
          _wipe(nonce);
        }
        _wipe(plaintext);
      }
    });

    test(
        'restart discards a forged first-fragment candidate after AEAD failure',
        () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final plaintext = _bytes(20, 0x51);
      final sent = await V3TripleRatchetEngine.send(
        snapshot: pair.alice,
        backend: backend,
        kind: V3LmfFrameKind.application,
      );
      final nonce = await sent.nonceForFragment(
        fragmentIndex: 0,
        fragmentCount: 1,
        assembledPlaintextLength: plaintext.length,
      );
      final frame = await V3LmfAead.sealSingle(
        metadata: sent.metadata,
        plaintext: plaintext,
        secretKey: sent.secretKey,
        nonce: nonce,
        hybridRatchetHeader: sent.header,
      );
      final encoded = V3LmfFrameCodec.encodeBinary(frame);
      final forgedBytes = Uint8List.fromList(encoded)..last ^= 1;
      final forged = V3LmfFrameCodec.decodeBinary(forgedBytes);
      final duplicateForgedBytes = Uint8List.fromList(encoded)..last ^= 2;
      final duplicateForged =
          V3LmfFrameCodec.decodeBinary(duplicateForgedBytes);
      final store = _MemoryRecordStore();
      final initialInbox = V3LmfDurableInbox(store: store);
      await initialInbox.restore(keyResolver: (_) => null);
      await initialInbox.persistDeferred(frame: forged);
      await initialInbox.close();

      final inbox = V3LmfDurableInbox(store: store);
      final restored = await inbox.restore(keyResolver: (_) => null);
      expect(restored.deferredFrames, 1);
      final journal = V3LmfAtomicCommitJournal(store: store, inbox: inbox);
      final controller = V3SessionCommitController(journal: journal);
      await controller.restore(checkpoints: <V3TripleRatchetState>[pair.bob]);
      final resolver = V3SessionRatchetKeyResolver(
        backend: backend,
        snapshotProvider: controller.snapshotForSession,
        skippedKeyLifetimeSeconds: 100,
      );
      try {
        final rejected = await inbox.resumeDeferred(
          keyResolver: (candidate) =>
              resolver.resolve(candidate, nowUnixSeconds: 6100),
          onAuthenticationFailure: resolver.discardUnauthenticatedFirstFragment,
        );
        expect(rejected.deliveries, isEmpty);
        expect(rejected.deferredFrames, 0);
        expect(resolver.pendingCandidateCount, 0);

        final duplicateKey = await resolver.resolve(
          duplicateForged,
          nowUnixSeconds: 6100,
        );
        expect(duplicateKey, isNotNull);
        await inbox.persistDeferred(frame: duplicateForged);
        await expectLater(
          inbox.receive(
            frame: duplicateForged,
            secretKey: duplicateKey!,
            onAuthenticationFailure:
                resolver.discardUnauthenticatedFirstFragment,
          ),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
        expect(resolver.pendingCandidateCount, 0);
        final afterDuplicateFailure = await inbox.resumeDeferred(
          keyResolver: (_) => null,
        );
        expect(afterDuplicateFailure.deferredFrames, 0);

        final validKey = await resolver.resolve(frame, nowUnixSeconds: 6100);
        expect(validKey, isNotNull);
        final accepted = await inbox.receive(
          frame: frame,
          secretKey: validKey!,
          onAuthenticationFailure: resolver.discardUnauthenticatedFirstFragment,
        );
        expect(accepted.status, V3LmfInboxStatus.complete);
        expect(accepted.delivery, isNotNull);
        await resolver.discardDelivery(accepted.delivery!);
        expect(resolver.pendingCandidateCount, 0);
      } finally {
        await resolver.close();
        await controller.close();
        await inbox.close();
        sent.close();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
        _wipe(nonce);
        _wipe(encoded);
        _wipe(forgedBytes);
        _wipe(duplicateForgedBytes);
        _wipe(plaintext);
      }
    });

    test('drops a pending candidate superseded by a concurrent commit',
        () async {
      final backend = _DeterministicEpochBackend();
      final pair = await _pairedSnapshots();
      final plaintext = _bytes(20, 0x61);
      final sent = await V3TripleRatchetEngine.send(
        snapshot: pair.alice,
        backend: backend,
        kind: V3LmfFrameKind.application,
      );
      final nonce = await sent.nonceForFragment(
        fragmentIndex: 0,
        fragmentCount: 1,
        assembledPlaintextLength: plaintext.length,
      );
      final frame = await V3LmfAead.sealSingle(
        metadata: sent.metadata,
        plaintext: plaintext,
        secretKey: sent.secretKey,
        nonce: nonce,
        hybridRatchetHeader: sent.header,
      );
      final store = _MemoryRecordStore();
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => null);
      final journal = V3LmfAtomicCommitJournal(store: store, inbox: inbox);
      final controller = V3SessionCommitController(journal: journal);
      await controller.restore(checkpoints: <V3TripleRatchetState>[pair.bob]);
      final firstResolver = V3SessionRatchetKeyResolver(
        backend: backend,
        snapshotProvider: controller.snapshotForSession,
        skippedKeyLifetimeSeconds: 100,
      );
      final staleResolver = V3SessionRatchetKeyResolver(
        backend: backend,
        snapshotProvider: controller.snapshotForSession,
        skippedKeyLifetimeSeconds: 100,
      );
      try {
        final firstKey = await firstResolver.resolve(
          frame,
          nowUnixSeconds: 6200,
        );
        final staleKey = await staleResolver.resolve(
          frame,
          nowUnixSeconds: 6200,
        );
        expect(firstKey, isNotNull);
        expect(staleKey, isNotNull);
        final received = await inbox.receive(
          frame: frame,
          secretKey: firstKey!,
          onAuthenticationFailure:
              firstResolver.discardUnauthenticatedFirstFragment,
        );
        final delivery = received.delivery!;
        final committed = await firstResolver.commitDelivery(
          delivery: delivery,
          controller: controller,
        );
        expect(committed.ratchetRevision, 1);

        await expectLater(
          staleResolver.commitDelivery(
            delivery: delivery,
            controller: controller,
          ),
          throwsStateError,
        );
        expect(staleResolver.pendingCandidateCount, 0);
      } finally {
        await firstResolver.close();
        await staleResolver.close();
        await controller.close();
        await inbox.close();
        sent.close();
        pair.alice.wipeSecrets();
        pair.bob.wipeSecrets();
        _wipe(nonce);
        _wipe(plaintext);
      }
    });
  });
}

final class _SentCandidate {
  _SentCandidate({
    required this.snapshot,
    required this.ecHeader,
    required this.message,
    required this.pqMessageKey,
  });

  final V3TripleRatchetState snapshot;
  final V3EcRatchetHeader ecHeader;
  final V3SckaMessage message;
  final Uint8List pqMessageKey;

  void close() {
    snapshot.wipeSecrets();
    _wipe(pqMessageKey);
  }
}

final class _ReceivedCandidate {
  _ReceivedCandidate({required this.snapshot, required this.pqMessageKey});

  final V3TripleRatchetState snapshot;
  final Uint8List pqMessageKey;

  void close() {
    snapshot.wipeSecrets();
    _wipe(pqMessageKey);
  }
}

Future<_SentCandidate> _send(
  V3TripleRatchetState snapshot,
  V3SckaBackend backend,
) async {
  final ecState = await V3EcDoubleRatchet.restore(snapshot);
  V3EcRatchetTransition? ec;
  V3PqMessageRatchetTransition? pq;
  try {
    ec = await V3EcDoubleRatchet.send(ecState);
    pq = await V3PqMessageRatchet.send(snapshot: snapshot, backend: backend);
    final next = pq.toTripleRatchetSnapshot(
      previous: snapshot,
      ecCandidate: ec.nextState,
    );
    return _SentCandidate(
      snapshot: next,
      ecHeader: ec.header,
      message: pq.message,
      pqMessageKey: pq.messageKey,
    );
  } finally {
    pq?.close();
    ec?.close();
    ecState.close();
  }
}

Future<_ReceivedCandidate> _receive(
  V3TripleRatchetState snapshot,
  V3SckaBackend backend,
  _SentCandidate sent, {
  required int nowUnixSeconds,
}) async {
  final ecState = await V3EcDoubleRatchet.restore(snapshot);
  V3EcRatchetTransition? ec;
  V3PqMessageRatchetTransition? pq;
  try {
    ec = await V3EcDoubleRatchet.receive(
      state: ecState,
      header: sent.ecHeader,
      nowUnixSeconds: nowUnixSeconds,
      skippedKeyLifetimeSeconds: 100,
    );
    pq = await V3PqMessageRatchet.receive(
      snapshot: snapshot,
      backend: backend,
      message: sent.message,
      nowUnixSeconds: nowUnixSeconds,
      skippedKeyLifetimeSeconds: 100,
    );
    final next = pq.toTripleRatchetSnapshot(
      previous: snapshot,
      ecCandidate: ec.nextState,
    );
    return _ReceivedCandidate(snapshot: next, pqMessageKey: pq.messageKey);
  } finally {
    pq?.close();
    ec?.close();
    ecState.close();
  }
}

Future<({V3TripleRatchetState alice, V3TripleRatchetState bob})>
    _pairedSnapshots() async {
  final sessionId = _bytes(16, 0x11);
  final pqSeed = _bytes(32, 0x31);
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
    _wipe(pqSeed);
    _wipe(alicePrivate);
    _wipe(bobPrivate);
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
}) {
  return V3TripleRatchetState(
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
    pqCurrentEpoch: 0,
    pqSendingEpoch: 0,
    pqReceivingEpoch: 0,
    pqEpochStates: <V3PqEpochState>[pqEpoch],
    nativeSckaState: _DeterministicEpochBackend.state(role, sessionId, 0),
  );
}

final class _DeterministicEpochBackend implements V3SckaBackend {
  static Uint8List state(V3SessionRole role, Uint8List sessionId, int epoch) {
    return Uint8List.fromList(<int>[role.wireId, ...sessionId, epoch]);
  }

  @override
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
  }) async {
    return state(role, sessionId, 0);
  }

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
  }) async {
    if (authenticatedState.length != 18 ||
        authenticatedState[0] != role.wireId ||
        !_bytesEqual(
          Uint8List.sublistView(authenticatedState, 1, 17),
          sessionId,
        )) {
      throw const FormatException('Test SCKA state binding mismatch');
    }
  }

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
  }) async {
    final currentEpoch = authenticatedState[17];
    final outputEpoch = currentEpoch == 0 ? 1 : currentEpoch;
    return V3SckaSendCandidate(
      nextAuthenticatedState: state(role, sessionId, outputEpoch),
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

  @override
  Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required V3SckaMessage message,
  }) async {
    final currentEpoch = authenticatedState[17];
    final payload = message.nativePayload;
    if (payload.length != 1 || payload.single < currentEpoch) {
      throw const FormatException('Test SCKA message is invalid');
    }
    final outputEpoch = payload.single;
    return V3SckaReceiveCandidate(
      nextAuthenticatedState: state(role, sessionId, outputEpoch),
      receivingEpoch: message.sendingEpoch,
      epochSecret: outputEpoch == currentEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _epochSecret(sessionId, outputEpoch),
            ),
    );
  }
}

Uint8List _epochSecret(Uint8List sessionId, int epoch) => Uint8List.fromList(
      crypto.sha256.convert(<int>[0x53, ...sessionId, epoch]).bytes,
    );

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

String _hex(List<int> value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);

final class _MemoryRecordStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> _records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    _records[id] = Map<String, dynamic>.from(payload);
    return id;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => _records.entries
      .map(
        (entry) => V3LmfStoredRecord(
          storageId: entry.key,
          payload: Map<String, dynamic>.from(entry.value),
        ),
      )
      .toList(growable: false);

  @override
  Future<void> delete(String storageId) async {
    _records.remove(storageId);
  }
}
