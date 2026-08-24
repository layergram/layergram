import 'dart:convert';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/device_key_repository_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';

void main() {
  test('same encrypted scope restores one installation device identity',
      () async {
    final store = _MemoryStore();
    final first = await V3DeviceKeyRepository(
      store: store,
      secureRandom: Random(11),
    ).loadOrCreate();
    final firstId = first.deviceId;
    final firstPublic = first.publicKey;
    first.close();

    final restored = await V3DeviceKeyRepository(
      store: store,
      secureRandom: Random(99),
    ).loadOrCreate();
    expect(restored.deviceId, orderedEquals(firstId));
    expect(restored.publicKey, orderedEquals(firstPublic));
    expect(store.records, hasLength(1));
    restored.close();
  });

  test('independent installation receives a different device identity',
      () async {
    final first = await V3DeviceKeyRepository(
      store: _MemoryStore(),
      secureRandom: Random(11),
    ).loadOrCreate();
    final second = await V3DeviceKeyRepository(
      store: _MemoryStore(),
      secureRandom: Random(12),
    ).loadOrCreate();
    expect(second.deviceId, isNot(orderedEquals(first.deviceId)));
    first.close();
    second.close();
  });

  test('exact duplicates are collected but divergent seeds fail closed',
      () async {
    final store = _MemoryStore();
    final original = await V3DeviceKeyRepository(
      store: store,
      secureRandom: Random(21),
    ).loadOrCreate();
    original.close();
    final payload = Map<String, dynamic>.from(store.records.values.single);
    await store.write(Map<String, dynamic>.from(payload));

    final restored = await V3DeviceKeyRepository(store: store).loadOrCreate();
    expect(store.records, hasLength(1));
    restored.close();

    final divergent = Map<String, dynamic>.from(payload);
    final seed = base64Url.decode(
      base64Url.normalize(divergent['seed'] as String),
    )..first ^= 1;
    divergent['seed'] = base64UrlEncode(seed).replaceAll('=', '');
    await store.write(divergent);
    await expectLater(
      V3DeviceKeyRepository(store: store).loadOrCreate(),
      throwsA(isA<V3LmfPersistenceConflictException>()),
    );
  });

  test('malformed records and physical record floods fail closed', () async {
    final malformed = _MemoryStore();
    await malformed.write(<String, dynamic>{
      'kind': V3DeviceKeyRepository.recordKind,
      'version': 1,
      'seed': 'not-a-seed',
    });
    await expectLater(
      V3DeviceKeyRepository(store: malformed).loadOrCreate(),
      throwsFormatException,
    );

    final flooded = _MemoryStore();
    for (var index = 0; index < 3; index++) {
      await flooded.write(<String, dynamic>{
        'kind': V3DeviceKeyRepository.recordKind,
        'version': 1,
        'seed': 'A' * 43,
      });
    }
    await expectLater(
      V3DeviceKeyRepository(
        store: flooded,
        maxPhysicalRecords: 2,
      ).loadOrCreate(),
      throwsA(isA<V3LmfPersistenceLimitException>()),
    );
  });
}

final class _MemoryStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records = {};
  int _nextId = 0;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    records[id] = Map<String, dynamic>.from(payload);
    return id;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async {
    return records.entries
        .map(
          (entry) => V3LmfStoredRecord(
            storageId: entry.key,
            payload: Map<String, dynamic>.from(entry.value),
          ),
        )
        .toList(growable: false);
  }

  @override
  Future<void> delete(String storageId) async {
    records.remove(storageId);
  }
}
