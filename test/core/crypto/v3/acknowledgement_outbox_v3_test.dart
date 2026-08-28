import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/acknowledgement_outbox_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_acknowledgement.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';

void main() {
  test('persists exact ACK bytes and returns them after restart', () async {
    final store = _FaultStore();
    final first = V3AcknowledgementOutbox(
      store: store,
      secureRandom: Random(7),
    );
    await first.restore();
    final entry = await first.getOrCreate(
      targetAssemblyId: _id(32, 0x21),
      partitionKey: _sessionPartition(),
      builder: _ackFrame,
      createdAt: DateTime.utc(2026, 8, 19),
    );
    final duplicate = await first.getOrCreate(
      targetAssemblyId: entry.targetAssemblyId,
      partitionKey: _sessionPartition(),
      builder: (_) => throw StateError('must not reseal'),
    );
    _expectExactFrame(entry.frame, duplicate.frame);
    await first.close();

    final restored = V3AcknowledgementOutbox(store: store);
    final result = await restored.restore();
    expect(result.entries, hasLength(1));
    _expectExactFrame(entry.frame, result.entries.single.frame);
    await restored.close();
  });

  test('durable-then-throw ACK write requires restart and recovers exact frame',
      () async {
    final store = _FaultStore()..persistAndThrowOnce = true;
    final first = V3AcknowledgementOutbox(
      store: store,
      secureRandom: Random(9),
    );
    await first.restore();
    await expectLater(
      first.getOrCreate(
        targetAssemblyId: _id(32, 0x41),
        partitionKey: _sessionPartition(),
        builder: _ackFrame,
      ),
      throwsStateError,
    );
    expect(first.requiresRecovery, isTrue);
    await expectLater(first.entries(), throwsStateError);
    await first.close();

    final restored = V3AcknowledgementOutbox(store: store);
    final result = await restored.restore();
    expect(result.entries, hasLength(1));
    expect(
      result.entries.single.frame.metadata.kind,
      V3LmfFrameKind.acknowledgement,
    );
    await restored.close();
  });

  test('preflight uses the exact ACK footprint before state may advance',
      () async {
    final store = _FaultStore();
    final outbox = V3AcknowledgementOutbox(
      store: store,
      maxEntries: 1,
      maxTotalBytes: V3AcknowledgementOutbox.acknowledgementFrameBytes,
    );
    await outbox.restore();
    final firstTarget = _id(32, 0x21);
    await outbox.preflightGetOrCreate(
      firstTarget,
      partitionKey: _sessionPartition(),
    );
    await outbox.getOrCreate(
      targetAssemblyId: firstTarget,
      partitionKey: _sessionPartition(),
      builder: _ackFrame,
    );
    await outbox.preflightGetOrCreate(
      firstTarget,
      partitionKey: _sessionPartition(),
    );
    await expectLater(
      outbox.preflightGetOrCreate(
        _id(32, 0x41),
        partitionKey: _sessionPartition(),
      ),
      throwsA(isA<V3LmfPersistenceLimitException>()),
    );
    await outbox.close();

    final byteLimited = V3AcknowledgementOutbox(
      store: _FaultStore(),
      maxTotalBytes: V3AcknowledgementOutbox.acknowledgementFrameBytes - 1,
    );
    await byteLimited.restore();
    await expectLater(
      byteLimited.preflightGetOrCreate(
        firstTarget,
        partitionKey: _sessionPartition(),
      ),
      throwsA(isA<V3LmfPersistenceLimitException>()),
    );
    await byteLimited.close();
  });

  test('one contact partition cannot consume another contact headroom',
      () async {
    final outbox = V3AcknowledgementOutbox(
      store: _FaultStore(),
      maxEntries: 2,
      maxEntriesPerPartition: 1,
      maxTotalBytes: V3AcknowledgementOutbox.acknowledgementFrameBytes * 2,
      maxTotalBytesPerPartition:
          V3AcknowledgementOutbox.acknowledgementFrameBytes,
    );
    await outbox.restore();
    final firstPartition = _id(48, 0x11);
    final secondPartition = _id(48, 0x61);
    await outbox.getOrCreate(
      targetAssemblyId: _id(32, 0x21),
      partitionKey: firstPartition,
      builder: _ackFrame,
    );
    await expectLater(
      outbox.preflightGetOrCreate(
        _id(32, 0x41),
        partitionKey: firstPartition,
      ),
      throwsA(isA<V3LmfPersistenceLimitException>()),
    );
    await outbox.preflightGetOrCreate(
      _id(32, 0x71),
      partitionKey: secondPartition,
    );
    await outbox.close();
  });

  for (final durableDelete in <bool>[false, true]) {
    test(
        'ambiguous ACK delete requires restore '
        '(${durableDelete ? 'durable delete' : 'failed delete'})', () async {
      final store = _FaultStore();
      final outbox = V3AcknowledgementOutbox(store: store);
      await outbox.restore();
      await outbox.getOrCreate(
        targetAssemblyId: _id(32, 0x21),
        partitionKey: _sessionPartition(),
        builder: _ackFrame,
        createdAt: DateTime.utc(2026, 1, 1),
      );
      store
        ..deleteAndThrowOnce = true
        ..removeBeforeDeleteThrow = durableDelete;

      await expectLater(
        outbox.deleteOlderThan(DateTime.utc(2026, 2, 1)),
        throwsStateError,
      );
      expect(outbox.requiresRecovery, isTrue);
      await expectLater(outbox.entries(), throwsStateError);
      await outbox.close();
    });
  }
}

Future<V3LmfFrame> _ackFrame(Uint8List messageId) async {
  final acknowledgement = V3LmfAcknowledgement(
    targetSuite: V3LmfSuite.hybridX25519MlKem768Aes256Gcm,
    targetKind: V3LmfFrameKind.application,
    targetMessageId: _bytes(16, 0x51),
    targetEpoch: 2,
    targetMessageCounter: 3,
    targetAssembledPlaintextLength: 1,
    targetFragmentCount: 1,
    receivedFragmentIndexes: const <int>{0},
  );
  final plaintext = V3LmfAcknowledgementCodec.encode(acknowledgement);
  final key = SecretKeyData(_bytes(32, 0x71));
  try {
    return await V3LmfAead.sealSingle(
      metadata: V3LmfMessageMetadata(
        kind: V3LmfFrameKind.acknowledgement,
        senderBinding: _bytes(32, 0x91),
        recipientBinding: _bytes(32, 0xb1),
        messageId: messageId,
        sessionId: _bytes(16, 0xd1),
        epoch: 2,
        messageCounter: 3,
      ),
      plaintext: plaintext,
      secretKey: key,
      nonce: _bytes(12, 0xf1),
    );
  } finally {
    plaintext.fillRange(0, plaintext.length, 0);
    key.destroy();
  }
}

void _expectExactFrame(V3LmfFrame left, V3LmfFrame right) {
  expect(
    V3LmfFrameCodec.encodeBinary(right),
    orderedEquals(V3LmfFrameCodec.encodeBinary(left)),
  );
}

String _id(int length, int start) =>
    base64UrlEncode(_bytes(length, start)).replaceAll('=', '');

String _sessionPartition() {
  final sessionId = _bytes(16, 0xd1);
  final expanded = Uint8List(48);
  for (var index = 0; index < expanded.length; index++) {
    expanded[index] = sessionId[index % sessionId.length];
  }
  return base64UrlEncode(expanded).replaceAll('=', '');
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

final class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records = {};
  int _nextId = 0;
  bool persistAndThrowOnce = false;
  bool deleteAndThrowOnce = false;
  bool removeBeforeDeleteThrow = false;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    records[id] = Map<String, dynamic>.from(payload);
    if (persistAndThrowOnce) {
      persistAndThrowOnce = false;
      throw StateError('persisted then failed');
    }
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
    if (deleteAndThrowOnce) {
      deleteAndThrowOnce = false;
      if (removeBeforeDeleteThrow) records.remove(storageId);
      throw StateError('ambiguous delete');
    }
    records.remove(storageId);
  }
}
