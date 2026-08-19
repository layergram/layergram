import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/application_presentation_state_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';

void main() {
  test('read and delete state survive restart monotonically', () async {
    final store = _MemoryStore();
    var journal = V3ApplicationPresentationJournal(store: store);
    await journal.restore();
    final messageId = _messageId(0x11);
    final read = await journal.markRead(
      messageRecordId: messageId,
      readAt: DateTime.fromMillisecondsSinceEpoch(1000, isUtc: true),
    );
    expect(read.revision, 0);
    expect(read.readAtUnixSeconds, 1);
    await expectLater(
      journal.markDeleted(
        messageRecordId: messageId,
        deletedAt: DateTime.fromMillisecondsSinceEpoch(500, isUtc: true),
      ),
      throwsArgumentError,
    );
    expect(journal.requiresRecovery, isFalse);
    final deleted = await journal.markDeleted(
      messageRecordId: messageId,
      deletedAt: DateTime.fromMillisecondsSinceEpoch(2000, isUtc: true),
    );
    expect(deleted.revision, 1);
    expect(deleted.readAtUnixSeconds, 1);
    expect(deleted.deletedAtUnixSeconds, 2);
    await journal.close();

    journal = V3ApplicationPresentationJournal(store: store);
    final restored = await journal.restore();
    expect(restored.states, hasLength(1));
    expect(restored.states[messageId]?.revision, 1);
    expect(restored.states[messageId]?.readAtUnixSeconds, 1);
    expect(restored.states[messageId]?.deletedAtUnixSeconds, 2);
    expect(
      (await journal.markRead(messageRecordId: messageId)).revision,
      1,
    );
    await journal.close();
  });

  test('durable-then-throw requires fresh restore and preserves state',
      () async {
    final store = _MemoryStore();
    var journal = V3ApplicationPresentationJournal(store: store);
    await journal.restore();
    store.throwAfterNextWrite = true;
    await expectLater(
      journal.markDeleted(
        messageRecordId: _messageId(0x41),
        deletedAt: DateTime.fromMillisecondsSinceEpoch(3000, isUtc: true),
      ),
      throwsStateError,
    );
    expect(journal.requiresRecovery, isTrue);
    await journal.close();

    journal = V3ApplicationPresentationJournal(store: store);
    final restored = await journal.restore();
    expect(restored.states.values.single.deletedAtUnixSeconds, 3);
    await journal.close();
  });
}

String _messageId(int seed) {
  final bytes = List<int>.generate(16, (index) => (seed + index) & 0xff);
  return 'v3m:${base64UrlEncode(bytes).replaceAll('=', '')}';
}

final class _MemoryStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> _records = {};
  int _nextId = 0;
  bool throwAfterNextWrite = false;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    _records[id] = Map<String, dynamic>.from(payload);
    if (throwAfterNextWrite) {
      throwAfterNextWrite = false;
      throw StateError('durable write reported failure');
    }
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
