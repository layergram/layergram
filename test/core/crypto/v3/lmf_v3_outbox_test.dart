import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_acknowledgement.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_outbox.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';

void main() {
  final key = SecretKeyData(_bytes(32, 0x11));
  final wrongKey = SecretKeyData(_bytes(32, 0x91));

  group('LMF v3 durable outbox', () {
    test('persists exact sealed bytes and restores highest durable revision',
        () async {
      final store = _FaultStore();
      final frames = await _frames(key);
      final originalBinary = frames
          .map(V3LmfFrameCodec.encodeBinary)
          .map(Uint8List.fromList)
          .toList(growable: false);
      final outbox = V3LmfDurableOutbox(store: store);
      await outbox.restore();

      final entry = await outbox.enqueue(frames.reversed.toList());
      expect(entry.frames.map((frame) => frame.fragmentIndex), [0, 1, 2]);
      expect(store.records, hasLength(1));
      _expectExactFrames(entry.frames, originalBinary);

      store.deleteFailuresRemaining = 1;
      final updated = await outbox.markExported(
        assemblyId: entry.assemblyId,
        fragmentIndexes: {0, 2},
        exportedAt: DateTime.utc(2026, 8, 13),
      );
      expect(updated.revision, 1);
      expect(updated.exportAttempts, [1, 0, 1]);
      expect(store.records, hasLength(2));
      _expectExactFrames(updated.frames, originalBinary);
      await outbox.close();

      final restored = V3LmfDurableOutbox(store: store);
      final result = await restored.restore();
      expect(result.entries, hasLength(1));
      expect(result.removedSupersededRecords, 1);
      expect(result.entries.single.revision, 1);
      expect(result.entries.single.exportAttempts, [1, 0, 1]);
      expect(store.records, hasLength(1));
      _expectExactFrames(result.entries.single.frames, originalBinary);
    });

    test('authenticated cumulative ACK advances, deduplicates, and completes',
        () async {
      final store = _FaultStore();
      final frames = await _frames(key);
      final outbox = V3LmfDurableOutbox(store: store);
      await outbox.restore();
      final entry = await outbox.enqueue(frames);

      final partial = await _ackFrame(
        targetFrames: frames,
        indexes: {0, 2},
        key: key,
      );
      expect(
        await outbox.applyAcknowledgement(
          acknowledgementFrame: partial,
          secretKey: key,
        ),
        V3LmfOutboxAckStatus.advanced,
      );
      expect(
        outbox
            .pendingFrames(entry.assemblyId)
            .map((frame) => frame.fragmentIndex),
        [1],
      );
      final revisionAfterPartial = outbox.entry(entry.assemblyId)!.revision;

      expect(
        await outbox.applyAcknowledgement(
          acknowledgementFrame: partial,
          secretKey: key,
        ),
        V3LmfOutboxAckStatus.duplicate,
      );
      expect(outbox.entry(entry.assemblyId)!.revision, revisionAfterPartial);

      final complete = await _ackFrame(
        targetFrames: frames,
        indexes: {0, 1, 2},
        key: key,
        messageIdStart: 0xd0,
        nonceStart: 0xe0,
      );
      expect(
        await outbox.applyAcknowledgement(
          acknowledgementFrame: complete,
          secretKey: key,
        ),
        V3LmfOutboxAckStatus.complete,
      );
      expect(outbox.pendingFrames(entry.assemblyId), isEmpty);
      final completedRevision = outbox.entry(entry.assemblyId)!.revision;
      expect(
        (await outbox.markExported(
          assemblyId: entry.assemblyId,
          fragmentIndexes: {0},
        ))
            .revision,
        completedRevision,
      );
      await outbox.removeFullyAcknowledged(entry.assemblyId);
      expect(outbox.entryCount, 0);
      expect(store.records, isEmpty);
    });

    test('rejects unauthenticated or context-mismatched ACKs', () async {
      final store = _FaultStore();
      final frames = await _frames(key);
      final outbox = V3LmfDurableOutbox(store: store);
      await outbox.restore();
      final entry = await outbox.enqueue(frames);
      final ack = await _ackFrame(
        targetFrames: frames,
        indexes: {0},
        key: key,
      );

      await expectLater(
        outbox.applyAcknowledgement(
          acknowledgementFrame: ack,
          secretKey: wrongKey,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );

      final wrongRoute = await _ackFrame(
        targetFrames: frames,
        indexes: {0},
        key: key,
        reverseRoute: false,
        messageIdStart: 0xd1,
        nonceStart: 0xe1,
      );
      await expectLater(
        outbox.applyAcknowledgement(
          acknowledgementFrame: wrongRoute,
          secretKey: key,
        ),
        throwsFormatException,
      );
      expect(
          outbox.entry(entry.assemblyId)!.acknowledgedFragmentIndexes, isEmpty);
    });

    test('replacement write failure keeps the prior revision authoritative',
        () async {
      final store = _FaultStore();
      final outbox = V3LmfDurableOutbox(store: store);
      await outbox.restore();
      final entry = await outbox.enqueue(await _frames(key));
      store.failNextWrite = true;

      await expectLater(
        outbox.markExported(
          assemblyId: entry.assemblyId,
          fragmentIndexes: {1},
        ),
        throwsStateError,
      );
      expect(outbox.entry(entry.assemblyId)!.revision, 0);
      expect(outbox.entry(entry.assemblyId)!.exportAttempts, [0, 0, 0]);
      expect(store.records, hasLength(1));
    });

    test('same revision with conflicting state is rejected on restore',
        () async {
      final store = _FaultStore();
      final outbox = V3LmfDurableOutbox(store: store);
      await outbox.restore();
      await outbox.enqueue(await _frames(key));
      final conflicting = _deepCopy(store.records.values.single);
      (conflicting['attempts'] as List<dynamic>)[0] = 1;
      await store.write(conflicting);
      await outbox.close();

      final restored = V3LmfDurableOutbox(store: store);
      await expectLater(
        restored.restore(),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
    });

    test('corrupt outbox records are removed without touching unrelated state',
        () async {
      final store = _FaultStore();
      final writer = V3LmfDurableOutbox(store: store);
      await writer.restore();
      await writer.enqueue(await _frames(key));
      await writer.close();
      store.records.values.single['updatedAt'] = 8640000000000001;
      await store.write(<String, dynamic>{'kind': 'fs_state_v1', 'v': 1});

      final outbox = V3LmfDurableOutbox(store: store);
      final result = await outbox.restore();
      expect(result.discardedCorruptRecords, 1);
      expect(store.records.values.single['kind'], 'fs_state_v1');
    });

    test('requires a complete coherent non-ACK frame set', () async {
      final store = _FaultStore();
      final frames = await _frames(key);
      final outbox = V3LmfDurableOutbox(store: store);
      await outbox.restore();

      await expectLater(
          outbox.enqueue(frames.sublist(0, 2)), throwsArgumentError);
      await expectLater(outbox.enqueue([frames[0], frames[0], frames[2]]),
          throwsArgumentError);

      final ack = await _ackFrame(
        targetFrames: frames,
        indexes: {0},
        key: key,
      );
      await expectLater(outbox.enqueue([ack]), throwsArgumentError);
      expect(store.records, isEmpty);
    });

    test('entry, byte, and physical-record caps fail closed', () async {
      final store = _FaultStore();
      final frames = await _frames(key);
      final byteLimited = V3LmfDurableOutbox(
        store: store,
        maxSealedFrameBytes: 1,
      );
      await byteLimited.restore();
      await expectLater(
        byteLimited.enqueue(frames),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      await byteLimited.close();

      final writer = V3LmfDurableOutbox(store: store, maxEntries: 1);
      await writer.restore();
      await writer.enqueue(frames);
      await expectLater(
        writer.enqueue(await _frames(key, messageIdStart: 0x91)),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      await store.write(_deepCopy(store.records.values.single));
      await writer.close();

      final physicalLimited = V3LmfDurableOutbox(
        store: store,
        maxStoredRecords: 1,
      );
      await expectLater(
        physicalLimited.restore(),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
    });

    test('queued export completes before close and cannot repopulate afterward',
        () async {
      final store = _FaultStore();
      final outbox = V3LmfDurableOutbox(store: store);
      await outbox.restore();
      store.pauseNextWrite();
      final enqueue = outbox.enqueue(await _frames(key));
      await store.writeStarted.future;
      final closing = outbox.close();
      store.resumeWrite();

      final entry = await enqueue;
      expect(entry.revision, 0);
      await closing;
      expect(outbox.entryCount, 0);
      expect(() => outbox.pendingFrames(entry.assemblyId), throwsStateError);
    });

    test('no implicit clock policy modifies pending exact bytes', () async {
      final store = _FaultStore();
      final frames = await _frames(key);
      final outbox = V3LmfDurableOutbox(store: store);
      await outbox.restore();
      final entry = await outbox.enqueue(
        frames,
        queuedAt: DateTime.utc(2000),
      );

      expect(outbox.pendingFrames(entry.assemblyId), hasLength(3));
      expect(outbox.entry(entry.assemblyId)!.exportAttempts, [0, 0, 0]);
      _expectExactFrames(
        outbox.pendingFrames(entry.assemblyId),
        frames.map(V3LmfFrameCodec.encodeBinary).toList(growable: false),
      );
    });
  });
}

Future<List<V3LmfFrame>> _frames(
  SecretKey key, {
  int messageIdStart = 0x81,
}) =>
    V3LmfAead.sealFragmented(
      metadata: _metadata(messageIdStart: messageIdStart),
      plaintext: _bytes(600, 0x30),
      secretKey: key,
      nonceForFragment: (index) =>
          _bytes(V3LmfFrameCodec.nonceBytes, 0x50 + index),
    );

Future<V3LmfFrame> _ackFrame({
  required List<V3LmfFrame> targetFrames,
  required Set<int> indexes,
  required SecretKey key,
  bool reverseRoute = true,
  int messageIdStart = 0xc0,
  int nonceStart = 0xd0,
}) async {
  final selected = targetFrames
      .where((frame) => indexes.contains(frame.fragmentIndex))
      .toList(growable: false);
  final acknowledgement = V3LmfAcknowledgementCodec.forReceivedFrames(selected);
  final target = targetFrames.first.metadata;
  final metadata = V3LmfMessageMetadata(
    kind: V3LmfFrameKind.acknowledgement,
    suite: target.suite,
    senderBinding:
        reverseRoute ? target.recipientBinding : target.senderBinding,
    recipientBinding:
        reverseRoute ? target.senderBinding : target.recipientBinding,
    messageId: _bytes(V3LmfFrameCodec.messageIdBytes, messageIdStart),
    sessionId: target.sessionId,
    epoch: target.epoch,
    messageCounter: target.messageCounter + 1,
  );
  return V3LmfAead.sealSingle(
    metadata: metadata,
    plaintext: V3LmfAcknowledgementCodec.encode(acknowledgement),
    secretKey: key,
    nonce: _bytes(V3LmfFrameCodec.nonceBytes, nonceStart),
  );
}

V3LmfMessageMetadata _metadata({int messageIdStart = 0x81}) =>
    V3LmfMessageMetadata(
      kind: V3LmfFrameKind.application,
      senderBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x01),
      recipientBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x41),
      messageId: _bytes(V3LmfFrameCodec.messageIdBytes, messageIdStart),
      sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
      epoch: 7,
      messageCounter: 9,
    );

void _expectExactFrames(
  List<V3LmfFrame> actual,
  List<Uint8List> expectedBinary,
) {
  expect(actual, hasLength(expectedBinary.length));
  for (var index = 0; index < actual.length; index++) {
    expect(
      V3LmfFrameCodec.encodeBinary(actual[index]),
      orderedEquals(expectedBinary[index]),
    );
  }
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Map<String, dynamic> _deepCopy(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;
  bool failNextWrite = false;
  int deleteFailuresRemaining = 0;
  Completer<void>? _writeGate;
  Completer<void> writeStarted = Completer<void>();

  void pauseNextWrite() {
    _writeGate = Completer<void>();
    writeStarted = Completer<void>();
  }

  void resumeWrite() => _writeGate?.complete();

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    if (!writeStarted.isCompleted) writeStarted.complete();
    final gate = _writeGate;
    if (gate != null) {
      await gate.future;
      _writeGate = null;
    }
    if (failNextWrite) {
      failNextWrite = false;
      throw StateError('injected write failure');
    }
    final storageId = 'record-${_nextId++}';
    records[storageId] = _deepCopy(payload);
    return storageId;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => records.entries
      .map(
        (entry) => V3LmfStoredRecord(
          storageId: entry.key,
          payload: _deepCopy(entry.value),
        ),
      )
      .toList(growable: false);

  @override
  Future<void> delete(String storageId) async {
    if (deleteFailuresRemaining > 0) {
      deleteFailuresRemaining--;
      throw StateError('injected delete failure');
    }
    records.remove(storageId);
  }
}
