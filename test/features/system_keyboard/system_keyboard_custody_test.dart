import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_custody.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_record_store.dart';

String id(int n) =>
    'r${base64Url.encode(List<int>.filled(16, n)).replaceAll('=', '')}';
Map<String, dynamic> copy(Map<String, dynamic> value) =>
    jsonDecode(jsonEncode(value)) as Map<String, dynamic>;
const scope = 'AAAAAAAAAAAAAAAA';
final auxKey = SecretKey(List<int>.filled(32, 71));
final baseline = <String, Map<String, dynamic>>{
  id(1): {'kind': 'v3_session_checkpoint_v1', 'revision': 1},
  id(2): {'kind': 'v3_handshake_completion_v1', 'binding': 'fixed'},
  id(3): {'kind': 'v3_device_key_v1', 'private': 'never-export'},
  id(4): {'kind': 'contact_policy_v1', 'mode': 'maximum'},
};

class _Crash implements Exception {}

void _legacyV2Marker(_Private private) {
  final marker = private.rows.values.singleWhere(
    (row) => row['kind'] == SystemKeyboardCustody.markerKind,
  );
  marker['v'] = 2;
  private.persist();
}

class _Faults {
  int count = 0;
  int? stopAfter;
  void step() {
    if (++count == stopAfter) {
      throw _Crash();
    }
  }
}

class _Private
    implements
        SystemKeyboardCustodyPrivateStore,
        SystemKeyboardCustodyHistoricalStore {
  // Existing fault fixtures exercise the deployed v3 journal. New tests opt
  // into the v4 transaction; production always writes v4.
  _Private(this.faults, this.writeThrough, {this.transactional = false}) {
    rows.addAll(baseline.map((key, value) => MapEntry(key, copy(value))));
    durable.addAll(rows.map((key, value) => MapEntry(key, copy(value))));
  }
  final _Faults faults;
  final bool writeThrough;
  final bool transactional;
  final rows = <String, Map<String, dynamic>>{};
  final durable = <String, Map<String, dynamic>>{};
  final applied = <String, String>{};
  final historical = <String, Map<String, dynamic>>{};
  int next = 90;
  bool reverseReads = false;
  void persist() {
    durable
      ..clear()
      ..addAll(rows.map((key, value) => MapEntry(key, copy(value))));
  }

  void crash() {
    rows
      ..clear()
      ..addAll(durable.map((key, value) => MapEntry(key, copy(value))));
  }

  void mutation() {
    if (writeThrough) {
      persist();
    }
    faults.step();
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async =>
      (reverseReads ? rows.entries.toList().reversed : rows.entries)
          .map(
            (e) => V3LmfStoredRecord(storageId: e.key, payload: copy(e.value)),
          )
          .toList();
  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final storageId = id(next++);
    if (!transactional &&
        (payload['kind'] == SystemKeyboardCustody.activationKind ||
            payload['kind'] == SystemKeyboardCustody.backupKind)) {
      return storageId;
    }
    final row = copy(payload);
    if (!transactional &&
        row['kind'] == SystemKeyboardCustody.markerKind) {
      row['v'] = 3;
    }
    rows[storageId] = row;
    mutation();
    return storageId;
  }

  @override
  Future<void> delete(String storageId) async {
    final removed = rows.remove(storageId);
    if (removed != null) historical[storageId] = copy(removed);
    mutation();
  }

  @override
  Future<V3LmfStoredRecord?> readDeleted(String storageId) async {
    final payload = historical[storageId];
    return payload == null
        ? null
        : V3LmfStoredRecord(storageId: storageId, payload: copy(payload));
  }

  @override
  Future<void> flush() async {
    persist();
    faults.step();
  }

  @override
  Future<PreparedAuxRecord> prepare(
    String storageId,
    Map<String, dynamic> payload,
  ) async {
    final encrypted = await AuxRecordCipher.encrypt(
      payload: payload,
      auxStorageKey: auxKey,
    );
    faults.step();
    return PreparedAuxRecord.fromJson({
      'scope': scope,
      'id': storageId,
      'sealed': encrypted.encryptedRecord,
    });
  }

  @override
  Future<void> apply(PreparedAuxRecord record) async {
    expect(record.scopeToken, scope);
    final clear = await AuxRecordCipher.decrypt(
      encryptedRecord: record.encryptedRecord,
      auxStorageKey: auxKey,
    );
    expect(clear, isNotNull);
    if (rows.containsKey(record.storageId)) {
      expect(
        applied[record.storageId],
        record.encryptedRecord,
        reason: 'A restart must replay exact bytes, not reseal an existing ID',
      );
    }
    applied[record.storageId] = record.encryptedRecord;
    rows[record.storageId] = copy(clear!);
    mutation();
  }
}

class _Native implements SystemKeyboardCustodyNative {
  _Native(this.faults, this.private);
  final _Faults faults;
  final _Private private;
  Uint8List? bytes;
  Uint8List? epoch;
  Uint8List? key;
  int revision = 0;
  bool active = false;
  @override
  Future<bool> hasPending() async => bytes != null;
  @override
  Future<void> prepare(Uint8List epoch, Uint8List key, Uint8List bytes) async {
    expect(this.bytes, isNull);
    expect(
      private.durable.values.any(
        (r) => r['kind'] == SystemKeyboardCustody.markerKind,
      ),
      true,
    );
    this.epoch = Uint8List.fromList(epoch);
    this.key = Uint8List.fromList(key);
    this.bytes = Uint8List.fromList(bytes);
    faults.step();
  }

  @override
  Future<void> activate(Uint8List epoch, Uint8List key) async {
    expect(epoch, this.epoch);
    expect(key, this.key);
    expect(private.durable.containsKey(id(1)), false);
    expect(private.durable.containsKey(id(2)), false);
    active = true;
    faults.step();
  }

  @override
  Future<SystemKeyboardCustodySnapshot> reclaim(
    Uint8List epoch,
    Uint8List key,
  ) async {
    if (bytes == null) {
      throw const SystemKeyboardCustodyMissing();
    }
    expect(epoch, this.epoch);
    expect(key, this.key);
    active = false;
    faults.step();
    return SystemKeyboardCustodySnapshot(revision, Uint8List.fromList(bytes!));
  }

  @override
  Future<void> removeAfterImport(
    Uint8List epoch,
    Uint8List key,
    int revision,
  ) async {
    expect(active, false);
    if (bytes != null) {
      expect(epoch, this.epoch);
      expect(key, this.key);
      expect(revision, this.revision);
    }
    bytes = null;
    faults.step();
  }

  void receiveNewState() {
    revision = 4;
    bytes = SystemKeyboardRecordSnapshot.encode([
      V3LmfStoredRecord(
        storageId: id(5),
        payload: {'kind': 'v3_session_checkpoint_v1', 'revision': 2},
      ),
      V3LmfStoredRecord(storageId: id(2), payload: baseline[id(2)]!),
      V3LmfStoredRecord(storageId: id(3), payload: baseline[id(3)]!),
      V3LmfStoredRecord(
        storageId: id(6),
        payload: {'kind': 'v3_application_record_v1', 'message': 'new'},
      ),
    ]);
  }
}

void main() {
  test('v4 restores a deleted source if native prepare disappears before activation',
      () async {
    final faults = _Faults()..stopAfter = 7;
    final private = _Private(faults, true, transactional: true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(privateStore: private, native: native);
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    native.bytes = null;
    private.historical.clear();
    expect(private.rows[id(1)], isNull);
    expect(await custody.hasLostAuthoritativeState(), isFalse);
    await custody.recover();
    expect(private.rows, baseline);
    expect(native.active, isFalse);
  });

  test('v4 interrupted private repair replays its durable exact ciphertext',
      () async {
    final faults = _Faults()..stopAfter = 7;
    final private = _Private(faults, true, transactional: true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(privateStore: private, native: native);
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    native.bytes = null;
    private.historical.clear();
    faults.stopAfter = faults.count + 4;
    await expectLater(custody.recover(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    private.crash();
    await custody.recover();
    expect(private.rows, baseline);
    expect(private.applied[id(1)], isNotNull);
  });

  test('v4 never restores pre-activation state after keyboard activation',
      () async {
    final faults = _Faults();
    final private = _Private(faults, true, transactional: true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(privateStore: private, native: native);
    (await custody.delegate()).close();
    expect(private.rows.values.any((row) =>
        row['kind'] == SystemKeyboardCustody.backupKind), isFalse);
    native.bytes = null;
    private.historical.clear();
    expect(await custody.hasLostAuthoritativeState(), isTrue);
    await expectLater(custody.recover(), throwsStateError);
    expect(private.rows[id(1)], isNull);
    expect(private.rows.values.any((row) =>
        row['kind'] == SystemKeyboardCustody.activationKind), isTrue);
  });

  test('v4 refuses an ambiguous concurrent checkpoint during private abort',
      () async {
    final faults = _Faults()..stopAfter = 7;
    final private = _Private(faults, true, transactional: true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(privateStore: private, native: native);
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    native.bytes = null;
    private.historical.clear();
    final newer = await private.write({
      'kind': 'v3_session_checkpoint_v1',
      'revision': 2,
    });
    await expectLater(custody.recover(), throwsStateError);
    expect(private.rows[newer]?['revision'], 2);
    expect(private.rows[id(1)], isNull);
  });

  test('v4 return preserves the keyboard ratchet and clears activation intent',
      () async {
    final faults = _Faults();
    final private = _Private(faults, true, transactional: true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(privateStore: private, native: native);
    (await custody.delegate()).close();
    native.receiveNewState();
    await custody.recover();
    expect(private.rows[id(1)], isNull);
    expect(private.rows[id(5)]?['revision'], 2);
    expect(private.rows.values.any((row) =>
        row['kind'] == SystemKeyboardCustody.activationKind), isFalse);
    (await custody.delegate()).close();
    await custody.recover();
    expect(private.rows[id(5)]?['revision'], 2);
  });

  test('v4 abort survives every deletion crash if native state disappears',
      () async {
    // 7-9 are source deletes; 10 is the durable source-deletion flush.
    // Activation intent is written only after those boundaries.
    for (final cut in [7, 8, 9, 10]) {
      final faults = _Faults()..stopAfter = cut;
      final private = _Private(faults, true, transactional: true);
      final native = _Native(faults, private);
      final custody =
          SystemKeyboardCustody(privateStore: private, native: native);
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      faults.stopAfter = null;
      native.bytes = null;
      private.historical.clear();
      await custody.recover();
      expect(private.rows, baseline, reason: 'deletion boundary $cut');
    }
  });

  for (final writeThrough in [false, true]) {
    test('v4 survives every delegation boundary with native custody; '
        'writeThrough=$writeThrough', () async {
      int? total;
      for (var cut = 0; total == null || cut <= total; cut++) {
        final faults = _Faults()..stopAfter = cut == 0 ? null : cut;
        final private =
            _Private(faults, writeThrough, transactional: true);
        final native = _Native(faults, private);
        final custody =
            SystemKeyboardCustody(privateStore: private, native: native);
        try {
          (await custody.delegate()).close();
        } on _Crash {
          // Simulated process death at this durable boundary.
        }
        total ??= faults.count;
        faults.stopAfter = null;
        private.crash();
        await custody.recover();
        expect(private.rows, baseline, reason: 'boundary $cut');
        expect(native.bytes, isNull);
      }
    });

    test('v4 never rolls back if every native copy vanishes; '
        'writeThrough=$writeThrough', () async {
      int? total;
      for (var cut = 0; total == null || cut <= total; cut++) {
        final faults = _Faults()..stopAfter = cut == 0 ? null : cut;
        final private =
            _Private(faults, writeThrough, transactional: true);
        final native = _Native(faults, private);
        final custody =
            SystemKeyboardCustody(privateStore: private, native: native);
        try {
          (await custody.delegate()).close();
        } on _Crash {
          // Simulate a device update also removing App Group and mirror state.
        }
        total ??= faults.count;
        faults.stopAfter = null;
        private.crash();
        native.bytes = null;
        private.historical.clear();
        final activated = private.rows.values.any((row) =>
            row['kind'] == SystemKeyboardCustody.activationKind);
        if (activated) {
          await expectLater(custody.recover(), throwsStateError);
          expect(private.rows.values.any((row) =>
              row['kind'] == SystemKeyboardCustody.markerKind), isTrue,
              reason: 'boundary $cut');
        } else {
          await custody.recover();
          expect(private.rows, baseline, reason: 'boundary $cut');
        }
      }
    });
  }

  test('v4 rejects a damaged encrypted abort snapshot without changing FS',
      () async {
    final faults = _Faults()..stopAfter = 7;
    final private = _Private(faults, true, transactional: true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(privateStore: private, native: native);
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    native.bytes = null;
    final backup = private.rows.values.singleWhere((row) =>
        row['kind'] == SystemKeyboardCustody.backupKind);
    backup['snapshot'] = base64Url.encode(utf8.encode('tampered'));
    private.persist();
    await expectLater(custody.recover(), throwsFormatException);
    expect(private.rows[id(1)], isNull);
    expect(private.rows.values.any((row) =>
        row['kind'] == SystemKeyboardCustody.markerKind), isTrue);
  });

  test('v4 preserves a newer pre-FS manifest and active checkpoint', () async {
    final faults = _Faults()..stopAfter = 4;
    final private = _Private(faults, true, transactional: true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 1,
    };
    private.persist();
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(privateStore: private, native: native);
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    native.bytes = null;
    await private.delete(id(7));
    private.historical.clear();
    final successor = await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 2,
    });
    await custody.recover();
    expect(private.rows[id(1)], baseline[id(1)]);
    expect(private.rows[id(7)], isNull);
    expect(private.rows[successor]?['revision'], 2);
    expect(private.rows.values.any((row) =>
        row['kind'] == SystemKeyboardCustody.backupKind), isFalse);
  });

  test('v4 explicit reset is crash-idempotent after proven native loss',
      () async {
    int? total;
    for (var cut = 0; total == null || cut <= total; cut++) {
      final faults = _Faults();
      final private = _Private(faults, true, transactional: true);
      final native = _Native(faults, private);
      final custody =
          SystemKeyboardCustody(privateStore: private, native: native);
      (await custody.delegate()).close();
      native.bytes = null;
      faults.count = 0;
      faults.stopAfter = cut == 0 ? null : cut;
      try {
        await custody.abandonLostAuthoritativeState();
      } on _Crash {
        // A user-authorized simulated reset was interrupted.
      }
      total ??= faults.count;
      faults.stopAfter = null;
      private.crash();
      if (private.rows.values.any((row) =>
          row['kind'] == SystemKeyboardCustody.markerKind ||
          row['kind'] == SystemKeyboardCustody.resetKind)) {
        await custody.abandonLostAuthoritativeState();
      }
      expect(private.rows, {id(4): baseline[id(4)]}, reason: 'reset $cut');
    }
  });

  test(
      'legacy partial handoff restores exact handshake frames without FS reset',
      () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    };
    for (var index = 8; index < 13; index++) {
      private.rows[id(index)] = {
        'kind': 'v3_handshake_frame_v1',
        'fragment': index,
      };
    }
    private.persist();
    final native = _Native(faults, private);
    final custody =
        SystemKeyboardCustody(privateStore: private, native: native);
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    _legacyV2Marker(private);
    native.bytes = null;
    for (var index = 7; index < 13; index++) {
      await private.delete(id(index));
    }
    final successor = await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });

    await custody.recover();
    expect(private.rows[id(7)], isNull);
    for (var index = 8; index < 13; index++) {
      expect(private.rows[id(index)]?['fragment'], index);
    }
    expect(private.rows[successor]?['revision'], 5);
    expect(private.rows[id(3)], baseline[id(3)]);
    expect(
        private.rows.values.any((row) =>
            row['kind'] == SystemKeyboardCustody.markerKind ||
            row['kind'] == SystemKeyboardCustody.repairKind),
        isFalse);
  });

  test('interrupted frame repair replays its exact durable receipt', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    };
    for (var index = 8; index < 10; index++) {
      private.rows[id(index)] = {
        'kind': 'v3_handshake_frame_v1',
        'fragment': index,
      };
    }
    private.persist();
    final native = _Native(faults, private);
    final custody =
        SystemKeyboardCustody(privateStore: private, native: native);
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    _legacyV2Marker(private);
    native.bytes = null;
    for (var index = 7; index < 10; index++) {
      await private.delete(id(index));
    }
    await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });
    faults.stopAfter = faults.count + 4;
    await expectLater(custody.recover(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    private.crash();
    expect(
        private.rows.values
            .any((row) => row['kind'] == SystemKeyboardCustody.repairKind),
        isTrue);

    await SystemKeyboardCustody(privateStore: private, native: native)
        .recover();
    expect(private.rows[id(8)]?['fragment'], 8);
    expect(private.rows[id(9)]?['fragment'], 9);
    expect(
        private.rows.values.any((row) =>
            row['kind'] == SystemKeyboardCustody.markerKind ||
            row['kind'] == SystemKeyboardCustody.repairKind),
        isFalse);
  });

  test('legacy frame repair rejects a changed retained ratchet checkpoint',
      () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    };
    private.rows[id(8)] = {'kind': 'v3_handshake_frame_v1', 'fragment': 0};
    private.persist();
    final native = _Native(faults, private);
    final custody =
        SystemKeyboardCustody(privateStore: private, native: native);
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    _legacyV2Marker(private);
    native.bytes = null;
    await private.delete(id(7));
    await private.delete(id(8));
    await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });
    private.rows[id(1)]!['revision'] = 99;
    private.persist();

    await expectLater(
        custody.recover(), throwsA(isA<SystemKeyboardCustodyMissing>()));
    expect(
        private.rows.values
            .any((row) => row['kind'] == SystemKeyboardCustody.markerKind),
        isTrue);
    expect(
        private.rows.values
            .any((row) => row['kind'] == SystemKeyboardCustody.repairKind),
        isFalse);
  });

  test('v3 unprepared marker recovers changed private V3 state without reset',
      () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    final custody =
        SystemKeyboardCustody(privateStore: private, native: native);
    faults.stopAfter = 3; // native prepare did not complete
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    native.bytes = null;
    await private.delete(id(1));
    await private.delete(id(2));
    final checkpoint = await private.write({
      'kind': 'v3_session_checkpoint_v1',
      'revision': 2,
    });
    final handshake = await private.write({
      'kind': 'v3_handshake_completion_v1',
      'binding': 'new',
    });
    expect(await custody.hasLostAuthoritativeState(), isFalse);
    await custody.recover();
    expect(private.rows[checkpoint]?['revision'], 2);
    expect(private.rows[handshake]?['binding'], 'new');
    expect(
        private.rows.values
            .any((row) => row['kind'] == SystemKeyboardCustody.markerKind),
        isFalse);
  });

  test('v3 prepared receipt blocks unsafe recovery when native state is lost',
      () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    final custody =
        SystemKeyboardCustody(privateStore: private, native: native);
    faults.stopAfter = 4; // receipt written after native prepare
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    native.bytes = null;
    await private.delete(id(1));
    await expectLater(
        custody.recover(), throwsA(isA<SystemKeyboardCustodyMissing>()));
    expect(
        private.rows.values
            .any((row) => row['kind'] == SystemKeyboardCustody.markerKind),
        isTrue);
  });

  test('a completed keyboard export can return and delegate again', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );

    (await custody.delegate()).close();
    native.receiveNewState();
    await custody.recover();
    expect(private.rows[id(5)]?['revision'], 2);
    expect(private.rows[id(6)]?['message'], 'new');

    (await custody.delegate()).close();
    final secondWorkingSet = SystemKeyboardRecordSnapshot.decode(native.bytes!);
    expect(
      secondWorkingSet.any(
        (record) =>
            record.storageId == id(5) && record.payload['revision'] == 2,
      ),
      isTrue,
    );
    expect(
      secondWorkingSet.any(
        (record) =>
            record.storageId == id(6) && record.payload['message'] == 'new',
      ),
      isTrue,
    );
    await custody.recover();
    expect(native.bytes, isNull);
    expect(
      private.rows.values.any(
        (row) =>
            row['kind'] == SystemKeyboardCustody.markerKind ||
            row['kind'] == SystemKeyboardCustody.importKind,
      ),
      isFalse,
    );
  });

  test(
    'first-message negotiation can delegate before any FS checkpoint',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      private.rows.remove(id(1));
      private.rows.remove(id(2));
      private.rows[id(5)] = {'kind': 'v3_handshake_handoff_v1'};
      private.rows[id(6)] = {'kind': 'v3.prefs.pending.manifest'};
      private.rows[id(7)] = {'kind': 'v3_handshake_pending_v1'};
      private.persist();
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      (await custody.delegate()).close();
      final moved = SystemKeyboardRecordSnapshot.decode(native.bytes!);
      expect(
        moved.map((record) => record.payload['kind']),
        containsAll([
          'v3_device_key_v1',
          'v3_handshake_handoff_v1',
          'v3_handshake_pending_v1',
          'v3.prefs.pending.manifest',
        ]),
      );
      expect(
        moved.any(
          (record) => record.payload['kind'] == 'v3_session_checkpoint_v1',
        ),
        isFalse,
      );
      await custody.recover();
      expect(private.rows[id(3)], baseline[id(3)]);
      expect(private.rows[id(5)]!['kind'], 'v3_handshake_handoff_v1');
      expect(private.rows[id(6)]!['kind'], 'v3.prefs.pending.manifest');
      expect(private.rows[id(7)]!['kind'], 'v3_handshake_pending_v1');
    },
  );

  test(
    'two custody objects cannot concurrently mutate the private journal',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      final native = _Native(faults, private);
      final one = SystemKeyboardCustody(privateStore: private, native: native);
      final two = SystemKeyboardCustody(privateStore: private, native: native);
      final first = one.delegate();
      await expectLater(two.delegate(), throwsStateError);
      (await first).close();
      await one.recover();
      expect(
        private.rows.values.where(
          (r) => r['kind'] == SystemKeyboardCustody.markerKind,
        ),
        isEmpty,
      );
    },
  );

  test(
    'abort recovery uses marker ID order when private iteration changes',
    () async {
      final faults = _Faults()
        ..stopAfter = 2; // Marker flushed; native prepare never ran.
      final private = _Private(faults, false);
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      private.crash();
      faults.stopAfter = null;
      private.reverseReads = true;
      await custody.recover();
      expect(private.rows, baseline);
    },
  );

  for (final writeThrough in [false, true]) {
    test(
      'delegation survives every durable boundary; writeThrough=$writeThrough',
      () async {
        int? total;
        for (var cut = 0; total == null || cut <= total; cut++) {
          final faults = _Faults();
          final private = _Private(faults, writeThrough);
          final native = _Native(faults, private);
          faults.stopAfter = cut == 0 ? null : cut;
          final custody = SystemKeyboardCustody(
            privateStore: private,
            native: native,
          );
          try {
            (await custody.delegate()).close();
          } on _Crash {
            /* simulated process death */
          }
          total ??= faults.count;
          faults.stopAfter = null;
          private.crash();
          await SystemKeyboardCustody(
            privateStore: private,
            native: native,
          ).recover();
          expect(private.rows, baseline, reason: 'boundary $cut');
          expect(native.active, false);
          expect(native.bytes, isNull);
        }
      },
    );

    test(
      'return import survives every boundary without stale state; writeThrough=$writeThrough',
      () async {
        int? total;
        for (var cut = 0; total == null || cut <= total; cut++) {
          final faults = _Faults();
          final private = _Private(faults, writeThrough);
          final native = _Native(faults, private);
          final custody = SystemKeyboardCustody(
            privateStore: private,
            native: native,
          );
          (await custody.delegate()).close();
          native.receiveNewState();
          faults.count = 0;
          faults.stopAfter = cut == 0 ? null : cut;
          try {
            await custody.recover();
          } on _Crash {
            /* simulated process death */
          }
          total ??= faults.count;
          faults.stopAfter = null;
          private.crash();
          await SystemKeyboardCustody(
            privateStore: private,
            native: native,
          ).recover();
          expect(
            private.rows[id(1)],
            isNull,
            reason: 'old ratchet never restored at $cut',
          );
          expect(private.rows[id(5)]!['revision'], 2);
          expect(private.rows[id(6)]!['message'], 'new');
          expect(private.rows[id(3)], baseline[id(3)]);
          expect(private.rows[id(4)], baseline[id(4)]);
          expect(private.rows.length, 5);
          expect(native.active, false);
          expect(native.bytes, isNull);
        }
      },
    );
  }

  test(
    'lost authoritative state cannot fall back after authorization',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      (await custody.delegate()).close();
      native.bytes = null;
      private.rows[id(8)] = {'kind': 'v3_session_checkpoint_v1', 'revision': 2};
      private.persist();
      await expectLater(
        custody.recover(),
        throwsA(isA<SystemKeyboardCustodyMissing>()),
      );
      expect(private.rows.containsKey(id(1)), false);
      expect(
        private.rows.values.any(
          (r) => r['kind'] == SystemKeyboardCustody.markerKind,
        ),
        true,
      );
    },
  );

  test(
    'confirmed loss abandons only delegated V3 state and preserves policy',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      private.rows[id(8)] = {
        'kind': 'v3_application_presentation_v1',
        'body': 'private history',
      };
      private.persist();
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      (await custody.delegate()).close();
      native.bytes = null;

      expect(await custody.hasLostAuthoritativeState(), isTrue);
      await custody.abandonLostAuthoritativeState();
      await custody.recover();
      expect(private.rows[id(1)], isNull);
      expect(private.rows[id(2)], isNull);
      expect(private.rows[id(3)], isNull);
      expect(private.rows[id(4)], baseline[id(4)]);
      expect(private.rows[id(8)]?['body'], 'private history');
      expect(
        private.rows.values.any(
          (row) =>
              row['kind'] == SystemKeyboardCustody.markerKind ||
              row['kind'] == SystemKeyboardCustody.resetKind,
        ),
        isFalse,
      );
    },
  );

  test('confirmed loss also removes one successor pre-FS manifest', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    };
    private.rows[id(8)] = {
      'kind': 'v3_application_presentation_v1',
      'body': 'retained chat',
    };
    private.persist();
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    native.bytes = null;
    final marker = private.rows.entries.singleWhere(
      (entry) => entry.value['kind'] == SystemKeyboardCustody.markerKind,
    );
    marker.value.remove('preFsAbort');
    marker.value['v'] = 1; // Existing physical fixture has a legacy marker.
    private.persist();
    await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });
    await private.delete(id(7));
    private.historical.clear();

    expect(await custody.hasLostAuthoritativeState(), isTrue);
    await custody.abandonLostAuthoritativeState();
    await custody.recover();
    expect(private.rows[id(3)], isNull);
    expect(private.rows[id(4)], baseline[id(4)]);
    expect(private.rows[id(8)]?['body'], 'retained chat');
    expect(
      private.rows.values.any(
        (row) => row['kind'] == 'v3.prefs.pending.manifest',
      ),
      isFalse,
    );
    expect(
      private.rows.values.any(
        (row) =>
            row['kind'] == SystemKeyboardCustody.markerKind ||
            row['kind'] == SystemKeyboardCustody.resetKind,
      ),
      isFalse,
    );
  });

  test('lost custody never silently discards a newer FS checkpoint', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    final custody =
        SystemKeyboardCustody(privateStore: private, native: native);
    (await custody.delegate()).close();
    native.bytes = null;
    await private.write({
      'kind': 'v3_session_checkpoint_v1',
      'revision': 2,
    });
    final before = private.rows.map((id, row) => MapEntry(id, copy(row)));

    expect(await custody.hasLostAuthoritativeState(), isTrue);
    await expectLater(
        custody.abandonLostAuthoritativeState(), throwsA(isA<StateError>()));
    expect(private.rows, before);
    expect(private.rows[id(4)], baseline[id(4)]);
  });

  test('successor pre-FS reset resumes after an interrupted delete', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    };
    private.persist();
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    _legacyV2Marker(private);
    native.bytes = null;
    await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });
    await private.delete(id(7));
    private.historical.clear();
    faults.stopAfter = faults.count + 3;
    await expectLater(
      custody.abandonLostAuthoritativeState(),
      throwsA(isA<_Crash>()),
    );
    faults.stopAfter = null;
    private.crash();

    await SystemKeyboardCustody(
      privateStore: private,
      native: native,
    ).recover();
    expect(private.rows[id(4)], baseline[id(4)]);
    expect(
      private.rows.values.any(
        (row) =>
            row['kind'] == 'v3.prefs.pending.manifest' ||
            row['kind'] == SystemKeyboardCustody.markerKind ||
            row['kind'] == SystemKeyboardCustody.resetKind,
      ),
      isFalse,
    );
  });

  test('legacy reset receipt remains replayable', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );
    (await custody.delegate()).close();
    native.bytes = null;
    final marker = private.rows.entries.singleWhere(
      (entry) => entry.value['kind'] == SystemKeyboardCustody.markerKind,
    );
    await private.write({
      'kind': SystemKeyboardCustody.resetKind,
      'v': 1,
      'markerId': marker.key,
      'epoch': marker.value['epoch'],
    });

    await custody.recover();
    expect(private.rows[id(4)], baseline[id(4)]);
    expect(
      private.rows.values.any(
        (row) =>
            row['kind'] == SystemKeyboardCustody.markerKind ||
            row['kind'] == SystemKeyboardCustody.resetKind,
      ),
      isFalse,
    );
  });

  test('lost-state reset resumes after an interrupted delete', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );
    (await custody.delegate()).close();
    native.bytes = null;
    faults.stopAfter = faults.count + 3;
    await expectLater(
      custody.abandonLostAuthoritativeState(),
      throwsA(isA<_Crash>()),
    );
    faults.stopAfter = null;
    private.crash();
    await SystemKeyboardCustody(
      privateStore: private,
      native: native,
    ).recover();
    expect(private.rows.keys, contains(id(4)));
    expect(private.rows.keys, isNot(contains(id(3))));
    expect(
      private.rows.values.any(
        (row) =>
            row['kind'] == SystemKeyboardCustody.markerKind ||
            row['kind'] == SystemKeyboardCustody.resetKind,
      ),
      isFalse,
    );
  });

  test('lost-state reset refuses an intact native snapshot', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );
    (await custody.delegate()).close();
    expect(await custody.hasLostAuthoritativeState(), isFalse);
    await expectLater(
      custody.abandonLostAuthoritativeState(),
      throwsStateError,
    );
    await custody.recover();
    expect(private.rows[id(3)], baseline[id(3)]);
  });

  test(
    'missing native prepare with an intact baseline is not a reset case',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      faults.stopAfter = 3; // marker write, flush, then native prepare
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      faults.stopAfter = null;
      native.bytes = null; // native prepare did not durably take effect
      private.crash();
      expect(await custody.hasLostAuthoritativeState(), isFalse);
      await custody.recover();
      expect(private.rows[id(3)], baseline[id(3)]);
      expect(
        private.rows.values.any(
          (row) => row['kind'] == SystemKeyboardCustody.markerKind,
        ),
        isFalse,
      );
    },
  );

  test(
    'intact baseline plus one new pre-FS manifest recovers without reset',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      faults.stopAfter = 3; // marker durable; native prepare interrupted
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      faults.stopAfter = null;
      native.bytes = null;
      private.rows[id(8)] = {
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 2,
      };
      private.persist();

      expect(await custody.hasLostAuthoritativeState(), isFalse);
      await custody.recover();
      expect(private.rows[id(1)], baseline[id(1)]);
      expect(private.rows[id(8)]?['revision'], 2);
      expect(
        private.rows.values.any(
          (row) => row['kind'] == SystemKeyboardCustody.markerKind,
        ),
        isFalse,
      );
    },
  );

  test(
    'pre-activation manifest replacement restores custody without FS reset',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      private.rows.remove(id(1));
      private.rows.remove(id(2));
      private.rows[id(5)] = {'kind': 'v3_handshake_pending_v1'};
      private.rows[id(6)] = {'kind': 'v3_handshake_pending_v1'};
      private.rows[id(7)] = {
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 4,
      };
      private.persist();
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      faults.stopAfter = 3; // marker durable, native prepare interrupted
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      faults.stopAfter = null;
      native.bytes = null;
      await private.write({
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 7,
      });
      await private.delete(id(7));
      // Hive may compact away a deleted frame; the v2 journal carries the
      // narrow proof needed to recognize this pre-activation replacement.
      private.historical.clear();

      await custody.recover();
      expect(private.rows[id(3)], baseline[id(3)]);
      expect(private.rows[id(5)]?['kind'], 'v3_handshake_pending_v1');
      expect(private.rows[id(6)]?['kind'], 'v3_handshake_pending_v1');
      expect(private.rows[id(7)], isNull);
      expect(
        private.rows.values
            .where((row) => row['kind'] == 'v3.prefs.pending.manifest')
            .single['revision'],
        7,
      );
      expect(
        private.rows.values.any(
          (row) => row['kind'] == SystemKeyboardCustody.markerKind,
        ),
        isFalse,
      );
    },
  );

  test(
    'legacy marker without deleted frame never guesses missing record kind',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      private.rows[id(7)] = {
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 4,
      };
      private.persist();
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      faults.stopAfter = 3;
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      faults.stopAfter = null;
      native.bytes = null;
      final marker = private.rows.entries.singleWhere(
        (entry) => entry.value['kind'] == SystemKeyboardCustody.markerKind,
      );
      marker.value.remove('preFsAbort');
      marker.value['v'] = 1;
      private.persist();
      await private.write({
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 5,
      });
      await private.delete(id(7));
      private.historical.clear();

      await expectLater(
        custody.recover(),
        throwsA(isA<SystemKeyboardCustodyMissing>()),
      );
      expect(private.rows[marker.key], isNotNull);
    },
  );

  test(
    'legacy marker still accepts an authenticated deleted pre-FS frame',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      private.rows[id(7)] = {
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 4,
      };
      private.persist();
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      faults.stopAfter = 3;
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      faults.stopAfter = null;
      native.bytes = null;
      final marker = private.rows.entries.singleWhere(
        (entry) => entry.value['kind'] == SystemKeyboardCustody.markerKind,
      );
      marker.value.remove('preFsAbort');
      marker.value['v'] = 1;
      private.persist();
      await private.write({
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 5,
      });
      await private.delete(id(7));

      await custody.recover();
      expect(private.rows[marker.key], isNull);
      expect(private.rows[id(3)], baseline[id(3)]);
    },
  );

  test('legacy abort preserves concurrent protocol records without FS reset',
      () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    };
    private.persist();
    final native = _Native(faults, private);
    final custody =
        SystemKeyboardCustody(privateStore: private, native: native);
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    native.bytes = null;
    final marker = private.rows.entries.singleWhere(
      (entry) => entry.value['kind'] == SystemKeyboardCustody.markerKind,
    );
    marker.value.remove('preFsAbort');
    marker.value['v'] = 1;
    private.persist();
    final successor = await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });
    final extraCheckpoint = await private.write({
      'kind': 'v3_session_checkpoint_v1',
      'revision': 2,
    });
    final extraHandshake = await private.write({
      'kind': 'v3_handshake_pending_v1',
    });
    await private.delete(id(7));

    await custody.recover();
    expect(private.rows[marker.key], isNull);
    expect(private.rows[successor]?['revision'], 5);
    expect(private.rows[extraCheckpoint]?['revision'], 2);
    expect(private.rows[extraHandshake]?['kind'], 'v3_handshake_pending_v1');
    expect(private.rows[id(3)], baseline[id(3)]);
  });

  test('legacy abort rejects two competing successor manifests', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    };
    private.persist();
    final native = _Native(faults, private);
    final custody =
        SystemKeyboardCustody(privateStore: private, native: native);
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    _legacyV2Marker(private);
    native.bytes = null;
    await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });
    await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 6,
    });
    await private.delete(id(7));

    await expectLater(
        custody.recover(), throwsA(isA<SystemKeyboardCustodyMissing>()));
    expect(
        private.rows.values
            .any((row) => row['kind'] == SystemKeyboardCustody.markerKind),
        isTrue);
  });

  test(
    'v2 abort proof refuses mutation of any retained source record',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      private.rows[id(7)] = {
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 4,
      };
      private.persist();
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      faults.stopAfter = 3;
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      faults.stopAfter = null;
      _legacyV2Marker(private);
      native.bytes = null;
      await private.write({
        'kind': 'v3.prefs.pending.manifest',
        'version': 1,
        'revision': 5,
      });
      await private.delete(id(7));
      private.historical.clear();
      private.rows[id(1)]!['revision'] = 2;
      private.persist();

      await expectLater(
        custody.recover(),
        throwsA(isA<SystemKeyboardCustodyMissing>()),
      );
      expect(
        private.rows.values.any(
          (row) => row['kind'] == SystemKeyboardCustody.markerKind,
        ),
        isTrue,
      );
    },
  );

  test('v2 abort proof cannot excuse a missing ratchet checkpoint', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    private.rows[id(7)] = {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    };
    private.persist();
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    _legacyV2Marker(private);
    native.bytes = null;
    await private.delete(id(1));
    private.historical.clear();
    await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });

    await expectLater(
      custody.recover(),
      throwsA(isA<SystemKeyboardCustodyMissing>()),
    );
    expect(private.rows[id(7)], isNotNull);
    expect(
      private.rows.values.any(
        (row) => row['kind'] == SystemKeyboardCustody.markerKind,
      ),
      isTrue,
    );
  });

  test('historical manifest cannot mask a missing checkpoint', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );
    faults.stopAfter = 3;
    await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
    faults.stopAfter = null;
    _legacyV2Marker(private);
    native.bytes = null;
    await private.delete(id(1));
    await private.write({
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 5,
    });

    await expectLater(
      custody.recover(),
      throwsA(isA<SystemKeyboardCustodyMissing>()),
    );
    expect(
      private.rows.values.any(
        (row) => row['kind'] == SystemKeyboardCustody.markerKind,
      ),
      isTrue,
    );
  });

  for (final revision in [3, 4]) {
    test(
      'historical manifest refuses non-newer replacement $revision',
      () async {
        final faults = _Faults();
        final private = _Private(faults, true);
        private.rows.remove(id(1));
        private.rows.remove(id(2));
        private.rows[id(7)] = {
          'kind': 'v3.prefs.pending.manifest',
          'version': 1,
          'revision': 4,
        };
        private.persist();
        final native = _Native(faults, private);
        final custody = SystemKeyboardCustody(
          privateStore: private,
          native: native,
        );
        faults.stopAfter = 3;
        await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
        faults.stopAfter = null;
        _legacyV2Marker(private);
        native.bytes = null;
        await private.write({
          'kind': 'v3.prefs.pending.manifest',
          'version': 1,
          'revision': revision,
        });
        await private.delete(id(7));

        await expectLater(
          custody.recover(),
          throwsA(isA<SystemKeyboardCustodyMissing>()),
        );
        expect(
          private.rows.values.any(
            (row) => row['kind'] == SystemKeyboardCustody.markerKind,
          ),
          isTrue,
        );
      },
    );
  }

  test(
    'intact baseline abort keeps multiple concurrent private V3 records',
    () async {
      final faults = _Faults();
      final private = _Private(faults, true);
      final native = _Native(faults, private);
      final custody = SystemKeyboardCustody(
        privateStore: private,
        native: native,
      );
      faults.stopAfter = 3; // marker committed; native prepare interrupted
      await expectLater(custody.delegate(), throwsA(isA<_Crash>()));
      faults.stopAfter = null;
      native.bytes = null;
      private.rows[id(8)] = {'kind': 'v3_session_checkpoint_v1', 'revision': 2};
      private.rows[id(9)] = {'kind': 'v3_handshake_pending_v1', 'revision': 3};
      private.persist();

      await custody.recover();
      expect(private.rows[id(1)], baseline[id(1)]);
      expect(private.rows[id(8)]?['revision'], 2);
      expect(private.rows[id(9)]?['revision'], 3);
      expect(
        private.rows.values.any(
          (row) => row['kind'] == SystemKeyboardCustody.markerKind,
        ),
        isFalse,
      );
    },
  );

  test('missing private journal never opens an unowned native store', () async {
    final faults = _Faults();
    final private = _Private(faults, true);
    final native = _Native(faults, private);
    native.bytes = Uint8List(20);
    final custody = SystemKeyboardCustody(
      privateStore: private,
      native: native,
    );
    await expectLater(custody.recover(), throwsStateError);
    await expectLater(custody.delegate(), throwsStateError);
    expect(faults.count, 0);
  });

  test('unknown protocol state denies before custody mutation', () async {
    for (final kind in ['v3_unknown_v2', 'v3.future.pending']) {
      final faults = _Faults();
      final private = _Private(faults, true);
      private.rows[id(8)] = {'kind': kind};
      final native = _Native(faults, private);
      await expectLater(
        SystemKeyboardCustody(privateStore: private, native: native).delegate(),
        throwsStateError,
      );
      expect(faults.count, 0);
      expect(native.bytes, isNull);
    }
  });
}
