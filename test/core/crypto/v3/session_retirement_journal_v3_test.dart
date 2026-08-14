import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/session_checkpoint_v3.dart';
import 'package:layergram/core/crypto/v3/session_retirement_journal_v3.dart';

void main() {
  group('inactive v3 session retirement journal', () {
    test('persists prepared and checkpoint-replaced stages across restart',
        () async {
      final store = _Store()..failDeletes = true;
      final journal = V3SessionRetirementJournal(store: store);
      await journal.restore();

      final prepared = await _prepare(journal);
      expect(prepared.stage, V3SessionRetirementStage.prepared);
      expect(prepared.checkpointWasReplaced, isFalse);
      expect(journal.planCount, 1);
      expect(store.records, hasLength(1));

      final replacement = _digest(0x71);
      final advanced = await journal.markCheckpointReplaced(
        planId: prepared.planId,
        expectedSourceCheckpointDigest: prepared.sourceCheckpointDigest,
        replacementCheckpointDigest: replacement,
      );
      expect(advanced.stage, V3SessionRetirementStage.checkpointReplaced);
      expect(advanced.replacementCheckpointDigest, replacement);
      expect(store.records, hasLength(2));
      await journal.close();

      store.failDeletes = false;
      final restoredJournal = V3SessionRetirementJournal(store: store);
      final restored = await restoredJournal.restore();
      expect(restored.plans, hasLength(1));
      expect(restored.plans.single.checkpointWasReplaced, isTrue);
      expect(restored.plans.single.replacementCheckpointDigest, replacement);
      expect(restored.removedSupersededRecords, 1);
      expect(store.records, hasLength(1));
      await restoredJournal.close();
    });

    test('enforces local proof age before the first durable write', () async {
      final store = _Store();
      final journal = V3SessionRetirementJournal(store: store);
      await journal.restore();

      await expectLater(
        _prepare(
          journal,
          proofRecordedAt: DateTime.utc(2026, 1, 1),
          preparedAt: DateTime.utc(2026, 1, 2),
          minimumProofLifetimeSeconds: 2 * 24 * 60 * 60,
        ),
        throwsFormatException,
      );
      expect(store.records, isEmpty);
      expect(journal.requiresRecovery, isFalse);

      await expectLater(
        _prepare(
          journal,
          proofRecordedAt: DateTime.utc(2026, 1, 2),
          preparedAt: DateTime.utc(2026, 1, 1),
          minimumProofLifetimeSeconds: 1,
        ),
        throwsFormatException,
      );
      expect(store.records, isEmpty);
      await journal.close();
    });

    test('fails stopped after a durable-then-throw ambiguous write', () async {
      final store = _Store()..throwAfterNextWrite = true;
      final journal = V3SessionRetirementJournal(store: store);
      await journal.restore();

      await expectLater(_prepare(journal), throwsStateError);
      expect(journal.requiresRecovery, isTrue);
      expect(store.records, hasLength(1));
      await expectLater(_prepare(journal), throwsStateError);
      await journal.close();

      final restoredJournal = V3SessionRetirementJournal(store: store);
      final restored = await restoredJournal.restore();
      expect(restored.plans, hasLength(1));
      final recovered = restored.plans.single;
      expect(recovered.stage, V3SessionRetirementStage.prepared);
      final idempotent = await _prepare(restoredJournal);
      expect(idempotent.planId, recovered.planId);
      expect(store.records, hasLength(1));
      await restoredJournal.close();
    });

    test('rejects corrupt bindings and divergent replacement checkpoints',
        () async {
      final store = _Store();
      final journal = V3SessionRetirementJournal(store: store);
      await journal.restore();
      final prepared = await _prepare(journal);
      await journal.close();

      store.records.values.single['recordDigest'] =
          '${store.records.values.single['recordDigest']}=';
      await expectLater(
        V3SessionRetirementJournal(store: store).restore(),
        throwsFormatException,
      );

      final validStore = _Store();
      final validJournal = V3SessionRetirementJournal(store: validStore);
      await validJournal.restore();
      final validPrepared = await _prepare(validJournal);
      await validJournal.markCheckpointReplaced(
        planId: validPrepared.planId,
        expectedSourceCheckpointDigest: validPrepared.sourceCheckpointDigest,
        replacementCheckpointDigest: _digest(0x81),
      );
      await expectLater(
        validJournal.markCheckpointReplaced(
          planId: validPrepared.planId,
          expectedSourceCheckpointDigest: validPrepared.sourceCheckpointDigest,
          replacementCheckpointDigest: _digest(0x82),
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(validJournal.requiresRecovery, isFalse);
      await validJournal.close();
      expect(prepared.planId, validPrepared.planId);

      final divergentStore = _Store();
      final divergentJournal = V3SessionRetirementJournal(
        store: divergentStore,
      );
      await divergentJournal.restore();
      final divergent = await _prepare(
        divergentJournal,
        proofDigest: _digest(0x39),
      );
      await divergentJournal.close();
      expect(divergent.planId, validPrepared.planId);
      validStore.records['divergent-valid-stage'] = Map<String, dynamic>.from(
        divergentStore.records.values.single,
      );
      await expectLater(
        V3SessionRetirementJournal(store: validStore).restore(),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
    });

    test('enforces authority and logical, byte, and physical limits', () async {
      final authorityStore = _Store();
      final authorityJournal = V3SessionRetirementJournal(
        store: authorityStore,
      );
      final authority =
          await authorityJournal.claimSessionCoordinatorAuthority();
      await expectLater(authorityJournal.restore(), throwsStateError);
      await authorityJournal.restore(authority: authority);
      await expectLater(_prepare(authorityJournal), throwsStateError);
      await _prepare(authorityJournal, authority: authority);
      expect(
        () => authorityJournal.plans(),
        throwsStateError,
      );
      expect(authorityJournal.plans(authority: authority), hasLength(1));
      await expectLater(authorityJournal.close(), throwsStateError);
      await authorityJournal.close(authority: authority);

      final countJournal = V3SessionRetirementJournal(
        store: _Store(),
        maxPlans: 1,
      );
      await countJournal.restore();
      await _prepare(countJournal);
      await expectLater(
        _prepare(
          countJournal,
          direction: V3CheckpointEffectDirection.outgoing,
          assemblyId: _digest(0x92),
          stableRecordId: 'v3:${_digest(0x92)}',
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      await countJournal.close();

      final byteJournal = V3SessionRetirementJournal(
        store: _Store(),
        maxTotalRetainedBytes: 1023,
      );
      await byteJournal.restore();
      await expectLater(
        _prepare(byteJournal),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      await byteJournal.close();

      final physicalStore = _Store();
      final physicalJournal = V3SessionRetirementJournal(store: physicalStore);
      await physicalJournal.restore();
      await _prepare(physicalJournal);
      await physicalJournal.close();
      final duplicate = Map<String, dynamic>.from(
        physicalStore.records.values.single,
      );
      physicalStore.records['duplicate'] = duplicate;
      await expectLater(
        V3SessionRetirementJournal(
          store: physicalStore,
          maxStoredRecords: 1,
        ).restore(),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
    });
  });
}

Future<V3SessionRetirementPlan> _prepare(
  V3SessionRetirementJournal journal, {
  V3CheckpointEffectDirection direction = V3CheckpointEffectDirection.incoming,
  String? assemblyId,
  String? proofDigest,
  String? stableRecordId,
  DateTime? proofRecordedAt,
  DateTime? preparedAt,
  int minimumProofLifetimeSeconds = 365 * 24 * 60 * 60,
  V3SessionRetirementAuthority? authority,
}) {
  final assembly = assemblyId ?? _digest(0x21);
  return journal.prepare(
    direction: direction,
    assemblyId: assembly,
    proofDigest: proofDigest ?? _digest(0x31),
    stableRecordId: stableRecordId ?? 'v3:$assembly',
    sessionKey: _id(16, 0x41),
    ratchetRevision: 7,
    stateDigest: _digest(0x51),
    sourceCheckpointDigest: _digest(0x61),
    proofRecordedAt: proofRecordedAt ?? DateTime.utc(2025, 1, 1),
    preparedAt: preparedAt ?? DateTime.utc(2026, 1, 2),
    minimumProofLifetimeSeconds: minimumProofLifetimeSeconds,
    authority: authority,
  );
}

String _digest(int start) => _id(32, start);

String _id(int length, int start) => base64Url
    .encode(Uint8List.fromList(List<int>.generate(
      length,
      (index) => (start + index) & 0xff,
    )))
    .replaceAll('=', '');

final class _Store implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  int _nextId = 0;
  bool failDeletes = false;
  bool throwAfterNextWrite = false;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    records[id] = _deepCopy(payload);
    if (throwAfterNextWrite) {
      throwAfterNextWrite = false;
      throw StateError('durable write completed before transport error');
    }
    return id;
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
    if (failDeletes) throw StateError('injected delete failure');
    records.remove(storageId);
  }
}

Map<String, dynamic> _deepCopy(Map<String, dynamic> value) =>
    jsonDecode(jsonEncode(value)) as Map<String, dynamic>;
