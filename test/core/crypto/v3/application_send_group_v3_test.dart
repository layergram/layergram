import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/application_send_group_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';

void main() {
  late _FaultStore store;
  late Map<String, int> targets;

  setUp(() {
    store = _FaultStore();
    targets = <String, int>{
      _id(16, 0x11): 3,
      _id(16, 0x31): 7,
    };
  });

  test('restores partially committed multi-device group and deletes when ready',
      () async {
    final first = V3ApplicationSendGroupJournal(
      store: store,
      secureRandom: Random(7),
    );
    await first.restore();
    final created = await first.create(
      plaintext: Uint8List.fromList('one logical message'.codeUnits),
      kind: V3LmfFrameKind.application,
      expiresAtUnixSeconds: 0,
      targetExpectedRevisions: targets,
    );
    final firstTarget = created.targets.first;
    final partial = await first.markCommitted(
      groupId: created.groupId,
      sessionId: firstTarget.sessionId,
      assemblyId: _id(32, 0x51),
      ratchetRevision: firstTarget.expectedRevision + 1,
    );
    expect(partial.isReady, isFalse);
    await first.close();

    final restored = V3ApplicationSendGroupJournal(store: store);
    final state = await restored.restore();
    expect(state.groups, hasLength(1));
    expect(state.groups.single.targets.where((target) => target.isCommitted),
        hasLength(1));
    final secondTarget = state.groups.single.targets
        .singleWhere((target) => !target.isCommitted);
    final complete = await restored.markCommitted(
      groupId: state.groups.single.groupId,
      sessionId: secondTarget.sessionId,
      assemblyId: _id(32, 0x91),
      ratchetRevision: secondTarget.expectedRevision + 1,
    );
    expect(complete.isReady, isTrue);
    await restored.deleteReady(complete.groupId);
    await restored.close();

    final empty = V3ApplicationSendGroupJournal(store: store);
    expect((await empty.restore()).groups, isEmpty);
    await empty.close();
  });

  test('durable-then-throw target update recovers without another send',
      () async {
    final first = V3ApplicationSendGroupJournal(
      store: store,
      secureRandom: Random(9),
    );
    await first.restore();
    final created = await first.create(
      plaintext: Uint8List.fromList('retry exactly'.codeUnits),
      kind: V3LmfFrameKind.application,
      expiresAtUnixSeconds: 0,
      targetExpectedRevisions: <String, int>{targets.keys.first: 0},
    );
    store.persistAndThrowKindOnce = V3ApplicationSendGroupJournal.recordKind;
    await expectLater(
      first.markCommitted(
        groupId: created.groupId,
        sessionId: created.targets.single.sessionId,
        assemblyId: _id(32, 0xb1),
        ratchetRevision: 1,
      ),
      throwsStateError,
    );
    expect(first.requiresRecovery, isTrue);
    await first.close();

    final restored = V3ApplicationSendGroupJournal(store: store);
    final state = await restored.restore();
    expect(state.groups.single.isReady, isTrue);
    expect(
      state.groups.single.targets.single.assemblyId,
      _id(32, 0xb1),
    );
    await restored.close();
  });
}

String _id(int length, int start) => base64UrlEncode(
      Uint8List.fromList(
        List<int>.generate(length, (index) => (start + index) & 0xff),
      ),
    ).replaceAll('=', '');

final class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records = {};
  int _nextId = 0;
  String? persistAndThrowKindOnce;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    records[id] = _copy(payload);
    if (persistAndThrowKindOnce == payload['kind']) {
      persistAndThrowKindOnce = null;
      throw StateError('persisted then failed');
    }
    return id;
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
    records.remove(storageId);
  }
}

Map<String, dynamic> _copy(Map<String, dynamic> value) =>
    Map<String, dynamic>.fromEntries(
      value.entries.map(
        (entry) => MapEntry(
          entry.key,
          entry.value is List
              ? (entry.value as List)
                  .map(
                    (item) =>
                        item is Map ? Map<String, dynamic>.from(item) : item,
                  )
                  .toList(growable: false)
              : entry.value,
        ),
      ),
    );
