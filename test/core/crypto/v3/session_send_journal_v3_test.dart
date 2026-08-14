import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/session_send_journal_v3.dart';

void main() {
  group('inactive v3 session send journal', () {
    test('restores highest revision and wipes superseded owned secrets',
        () async {
      final store = _Store()..failDeletes = true;
      final journal = V3SessionSendJournal(store: store);
      await journal.restore();
      final frames = await _frames(messageStart: 0x21);
      final application = _bytes(96, 0x41);
      final ratchet = _bytes(128, 0x61);
      final originalApplication = Uint8List.fromList(application);
      final originalRatchet = Uint8List.fromList(ratchet);
      final pending = await journal.persist(
        previousRatchetRevision: 0,
        frames: frames,
        applicationState: application,
        ratchetState: ratchet,
        persistedAt: DateTime.utc(2026, 8, 14),
      );
      _wipe(application);
      _wipe(ratchet);
      expect(pending.applicationState, originalApplication);
      expect(pending.ratchetState, originalRatchet);

      final completed = await journal.markFullyAcknowledged(
        assemblyId: pending.assemblyId,
        acknowledgedAt: DateTime.utc(2026, 8, 14, 1),
      );
      expect(completed.revision, 1);
      expect(completed.isFullyAcknowledged, isTrue);
      expect(pending.applicationState, everyElement(0));
      expect(pending.ratchetState, everyElement(0));
      await journal.close();
      expect(completed.applicationState, everyElement(0));
      expect(completed.ratchetState, everyElement(0));

      store.failDeletes = false;
      final restoredJournal = V3SessionSendJournal(store: store);
      final restored = await restoredJournal.restore();
      expect(restored.effects, hasLength(1));
      expect(restored.effects.single.revision, 1);
      expect(restored.effects.single.isFullyAcknowledged, isTrue);
      expect(restored.effects.single.applicationState, originalApplication);
      expect(restored.effects.single.ratchetState, originalRatchet);
      expect(restored.removedSupersededRecords, 1);

      _wipe(originalApplication);
      _wipe(originalRatchet);
      await restoredJournal.close();
    });

    test('rejects corrupt canonical records and divergent valid revisions',
        () async {
      final corruptStore = _Store();
      final corruptJournal = V3SessionSendJournal(store: corruptStore);
      await corruptJournal.restore();
      await corruptJournal.persist(
        previousRatchetRevision: 0,
        frames: await _frames(messageStart: 0x31),
        applicationState: _bytes(64, 0x51),
        ratchetState: _bytes(64, 0x71),
      );
      await corruptJournal.close();
      corruptStore.records.values.single['application'] =
          '${corruptStore.records.values.single['application']}=';
      await expectLater(
        V3SessionSendJournal(store: corruptStore).restore(),
        throwsFormatException,
      );

      final frames = await _frames(messageStart: 0x41);
      final firstStore = _Store();
      final firstJournal = V3SessionSendJournal(store: firstStore);
      await firstJournal.restore();
      await firstJournal.persist(
        previousRatchetRevision: 0,
        frames: frames,
        applicationState: _bytes(64, 0x81),
        ratchetState: _bytes(64, 0x91),
      );
      await firstJournal.close();

      final secondStore = _Store();
      final secondJournal = V3SessionSendJournal(store: secondStore);
      await secondJournal.restore();
      final second = await secondJournal.persist(
        previousRatchetRevision: 0,
        frames: frames,
        applicationState: _bytes(64, 0xa1),
        ratchetState: _bytes(64, 0xb1),
      );
      await secondJournal.markFullyAcknowledged(
        assemblyId: second.assemblyId,
      );
      await secondJournal.close();
      firstStore.records['divergent-valid-revision'] =
          _deepCopy(secondStore.records.values.single);
      await expectLater(
        V3SessionSendJournal(store: firstStore).restore(),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
    });

    test('enforces logical, retained-byte, and physical record limits',
        () async {
      final store = _Store();
      final journal = V3SessionSendJournal(store: store, maxEffects: 1);
      await journal.restore();
      await journal.persist(
        previousRatchetRevision: 0,
        frames: await _frames(messageStart: 0x51),
        applicationState: _bytes(32, 0x11),
        ratchetState: _bytes(32, 0x21),
      );
      await expectLater(
        journal.persist(
          previousRatchetRevision: 1,
          frames: await _frames(messageStart: 0x61),
          applicationState: _bytes(32, 0x31),
          ratchetState: _bytes(32, 0x41),
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(journal.requiresRecovery, isFalse);
      await journal.close();

      final byteLimited = V3SessionSendJournal(
        store: _Store(),
        maxTotalRetainedBytes: 1,
      );
      await byteLimited.restore();
      await expectLater(
        byteLimited.persist(
          previousRatchetRevision: 0,
          frames: await _frames(messageStart: 0x71),
          applicationState: _bytes(1, 1),
          ratchetState: _bytes(1, 2),
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(byteLimited.effectCount, 0);
      await byteLimited.close();

      final physicalStore = _Store();
      physicalStore.records['one'] = _deepCopy(store.records.values.single);
      physicalStore.records['two'] = _deepCopy(store.records.values.single);
      await expectLater(
        V3SessionSendJournal(
          store: physicalStore,
          maxStoredRecords: 1,
        ).restore(),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
    });

    test('authority blocks direct reads and lifecycle calls after claim',
        () async {
      final journal = V3SessionSendJournal(store: _Store());
      final authority = await journal.claimSessionCoordinatorAuthority();
      await expectLater(journal.restore(), throwsStateError);
      final restored = await journal.restore(authority: authority);
      expect(restored.effects, isEmpty);
      expect(() => journal.effects(), throwsStateError);
      expect(
        () => journal.effectForAssembly('not-an-assembly'),
        throwsStateError,
      );
      await expectLater(journal.close(), throwsStateError);
      await journal.close(authority: authority);
      await expectLater(
        journal.persist(
          previousRatchetRevision: 0,
          frames: await _frames(messageStart: 0x81),
          applicationState: _bytes(1, 1),
          ratchetState: _bytes(1, 2),
          authority: authority,
        ),
        throwsStateError,
      );
    });
  });
}

Future<List<V3LmfFrame>> _frames({required int messageStart}) async {
  final metadata = V3LmfMessageMetadata(
    kind: V3LmfFrameKind.handshake,
    senderBinding: _bytes(32, 0x11),
    recipientBinding: _bytes(32, 0x31),
    messageId: _bytes(16, messageStart),
    sessionId: _bytes(16, 0x51),
    epoch: 0,
    messageCounter: messageStart,
  );
  final frame = await V3LmfAead.sealSingle(
    metadata: metadata,
    plaintext: _bytes(48, 0x71),
    secretKey: SecretKeyData(_bytes(32, 0x91)),
    nonce: _bytes(V3LmfFrameCodec.nonceBytes, messageStart),
  );
  return <V3LmfFrame>[frame];
}

final class _Store implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;
  bool failDeletes = false;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    records[id] = _deepCopy(payload);
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
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
