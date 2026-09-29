import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_record_store.dart';

const id = 'rAAAAAAAAAAAAAAAAAAAAAA';
Map<String, dynamic> payload([int revision = 0]) => {
      'kind': 'v3_session_checkpoint_v1',
      'revision': revision,
      'nested': {
        'proof': [1, 2, 3]
      },
    };
Uint8List initial() => SystemKeyboardRecordSnapshot.encode([
      V3LmfStoredRecord(storageId: id, payload: payload()),
    ]);

void main() {
  test('writes become visible only after durable CAS, with detached payloads',
      () async {
    final entered = Completer<void>();
    final committed = Completer<int>();
    Uint8List? retained;
    final store = SystemKeyboardRecordStore(
        snapshot: initial(),
        revision: 7,
        commit: (bytes, revision) {
          expect(revision, 7);
          retained = bytes;
          entered.complete();
          return committed.future;
        });
    final candidate = payload(1);
    final pending = store.write(candidate);
    await entered.future;
    candidate['revision'] = 999;
    var readCompleted = false;
    final read = store.readAll().then((value) {
      readCompleted = true;
      return value;
    });
    await Future<void>.delayed(Duration.zero);
    expect(readCompleted, false);
    committed.complete(8);
    final nextId = await pending;
    final records = await read;
    expect(
        records.singleWhere((r) => r.storageId == nextId).payload['revision'],
        1);
    expect(() => records.first.payload['revision'] = 123,
        throwsUnsupportedError);
    expect(() => ((records.first.payload['nested'] as Map)['proof'] as List)[0] = 99,
        throwsUnsupportedError);
    expect((await store.readAll()).first.payload['revision'], 0);
    expect(
        (((await store.readAll()).first.payload['nested'] as Map)['proof']
            as List)[0],
        1);
    final repeated = await store.readAll();
    expect(identical(records.first.payload, repeated.first.payload), isTrue,
        reason: 'repeated V3 lookups must not clone the entire working set');
    expect(retained, everyElement(0));
    store.close();
  });

  test(
      'a durable write with lost reply is terminal; queued operations cannot retry',
      () async {
    var commits = 0;
    Uint8List? disk;
    final store = SystemKeyboardRecordStore(
        snapshot: initial(),
        revision: 0,
        commit: (bytes, revision) async {
          commits++;
          disk = Uint8List.fromList(bytes);
          throw StateError('reply lost after fsync');
        });
    final first = expectLater(store.write(payload(1)), throwsStateError);
    final second = expectLater(store.write(payload(2)), throwsStateError);
    await Future.wait([first, second]);
    expect(commits, 1);
    expect(store.isClosed, true);
    expect(SystemKeyboardRecordSnapshot.decode(disk!), hasLength(2));
    await expectLater(store.readAll(), throwsStateError);
  });

  test('revocation while native commit is pending suppresses success',
      () async {
    final gate = Completer<int>();
    final entered = Completer<void>();
    final store = SystemKeyboardRecordStore(
        snapshot: initial(),
        revision: 0,
        commit: (_, __) {
          entered.complete();
          return gate.future;
        });
    final outcome = expectLater(store.write(payload(1)), throwsStateError);
    await entered.future;
    store.close();
    gate.complete(1);
    await outcome;
    await expectLater(store.readAll(), throwsStateError);
  });

  test('native revision mismatch and revision exhaustion stop the store',
      () async {
    for (final revision in [0, SystemKeyboardRecordSnapshot.maxRevision]) {
      var calls = 0;
      final store = SystemKeyboardRecordStore(
          snapshot: initial(),
          revision: revision,
          commit: (_, __) async {
            calls++;
            return 9;
          });
      await expectLater(store.write(payload(1)), throwsStateError);
      expect(store.isClosed, true);
      expect(calls, revision == 0 ? 1 : 0);
    }
  });

  test('deletes persist and missing deletes are idempotent', () async {
    Uint8List? disk;
    var calls = 0;
    final store = SystemKeyboardRecordStore(
        snapshot: initial(),
        revision: 3,
        commit: (bytes, revision) async {
          calls++;
          disk = Uint8List.fromList(bytes);
          return revision + 1;
        });
    await store.delete(id);
    await store.delete(id);
    expect(calls, 1);
    expect(SystemKeyboardRecordSnapshot.decode(disk!), isEmpty);
    expect(await store.readAll(), isEmpty);
  });

  test('unknown protocol records and duplicate IDs deny', () {
    for (final kind in ['v3_unknown_v2', 'passphrase_settings']) {
      expect(
          () => SystemKeyboardRecordSnapshot.encode([
                V3LmfStoredRecord(storageId: id, payload: {'kind': kind}),
              ]),
          throwsFormatException);
    }
    expect(
        () => SystemKeyboardRecordSnapshot.encode([
              V3LmfStoredRecord(storageId: id, payload: payload()),
              V3LmfStoredRecord(storageId: id, payload: payload()),
            ]),
        throwsFormatException);
  });

  test('pending V3 handshake survives the keyboard snapshot codec', () {
    final pending = V3LmfStoredRecord(storageId: id, payload: {
      'kind': 'v3_handshake_pending_v1',
      'pendingState': 'sealed-private-state',
    });
    final encoded = SystemKeyboardRecordSnapshot.encode([pending]);
    expect(SystemKeyboardRecordSnapshot.decode(encoded).single.payload,
        pending.payload);
  });

  test('metadata-only kind check neither exposes records nor works after close',
      () {
    final store = SystemKeyboardRecordStore(
        snapshot: initial(), revision: 0, commit: (_, __) async => 1);
    expect(store.containsKind('v3_session_checkpoint_v1'), isTrue);
    expect(store.containsKind('v3_device_key_v1'), isFalse);
    store.close();
    expect(
        () => store.containsKind('v3_session_checkpoint_v1'), throwsStateError);
  });

  test('round-trips device and incomplete negotiation records', () {
    final records = [
      V3LmfStoredRecord(storageId: id, payload: {'kind': 'v3_device_key_v1'}),
      V3LmfStoredRecord(
          storageId: 'rBBBBBBBBBBBBBBBBBBBBBB',
          payload: {'kind': 'v3_handshake_handoff_v1'}),
      V3LmfStoredRecord(
          storageId: 'rCCCCCCCCCCCCCCCCCCCCCC',
          payload: {'kind': 'v3.prefs.pending.manifest'}),
    ];
    final bytes = SystemKeyboardRecordSnapshot.encode(records);
    expect(
        SystemKeyboardRecordSnapshot.decode(bytes)
            .map((record) => record.payload['kind']),
        records.map((record) => record.payload['kind']));
    bytes.fillRange(0, bytes.length, 0);
  });

  test('fused snapshot encoder preserves the exact V3 JSON bytes', () {
    final record = V3LmfStoredRecord(storageId: id, payload: {
      'kind': 'v3_session_checkpoint_v1',
      'text': 'ñ € 😄',
      'nested': [true, null, 42]
    });
    final expected = utf8.encode(jsonEncode({
      'v': 1,
      'records': [
        {'id': id, 'payload': record.payload}
      ]
    }));
    final actual = SystemKeyboardRecordSnapshot.encode([record]);
    expect(actual, expected);
    actual.fillRange(0, actual.length, 0);
  });

  test(
      'unsupported envelope, malformed IDs and oversize state deny without truncation',
      () {
    for (final value in [
      {'v': 2, 'records': []},
      {'v': 1, 'records': [], 'extra': true},
      {
        'v': 1,
        'records': [
          {'id': '../bad', 'payload': payload()}
        ]
      },
    ]) {
      expect(
          () => SystemKeyboardRecordSnapshot.decode(
              Uint8List.fromList(utf8.encode(jsonEncode(value)))),
          throwsFormatException);
    }
    expect(
        () => SystemKeyboardRecordSnapshot.encode([
              V3LmfStoredRecord(storageId: id, payload: {
                ...payload(),
                'large': 'x' * SystemKeyboardRecordSnapshot.maxBytes
              }),
            ]),
        throwsFormatException);
  });
}
