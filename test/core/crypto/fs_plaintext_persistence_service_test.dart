/// Tests for FsPlaintextPersistenceService (FS Spec §12.3).
///
/// Verifies:
///  1. savePlaintext + loadPlaintext round-trip via encrypted aux records.
///  2. loadPlaintext returns null for unknown messageId.
///  3. rebuildIndex restores the index after cold start.
///  4. removeAll wipes all FS plaintext aux records.
///  5. removePlaintext removes a single record.
///  6. Duplicate savePlaintext overwrites the record.
///  7. Records are opaque — kind is only visible after decryption.
///  8. Plausible deniability: FS plaintext records are indistinguishable from
///     other aux records in the Hive box.

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/fs_plaintext_persistence_service.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory tmpDir;
  late Box<Map> box;
  final masterBytes = Uint8List(32)..fillRange(0, 32, 0xAA);

  Future<SecretKey> buildAuxKey() =>
      AuxRecordCipher.deriveAuxStorageKey(masterBytes);

  Future<AuxRecordRepository> buildAuxRepo({
    String scope = 'test-scope',
  }) async {
    final key = await buildAuxKey();
    final repo = AuxRecordRepository();
    repo.setActiveContext(scopeToken: scope, auxStorageKey: key);
    return repo;
  }

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_fs_pt_persist_');
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    box = Hive.box<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await box.clear();
  });

  // ── Round-trip ──────────────────────────────────────────────────────────

  test('savePlaintext + loadPlaintext round-trips through aux records', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    await service.savePlaintext(
      messageId: 'msg-001',
      plaintext: 'Hello from FS!',
      contactId: 'alice',
    );

    final loaded = await service.loadPlaintext('msg-001');
    expect(loaded, equals('Hello from FS!'));
  });

  test('loadPlaintext returns null for unknown messageId', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    final loaded = await service.loadPlaintext('nonexistent');
    expect(loaded, isNull);
  });

  // ── Multiple messages ──────────────────────────────────────────────────

  test('multiple messages stored and retrieved independently', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    await service.savePlaintext(
      messageId: 'msg-1',
      plaintext: 'First message',
      contactId: 'alice',
    );
    await service.savePlaintext(
      messageId: 'msg-2',
      plaintext: 'Second message',
      contactId: 'bob',
    );
    await service.savePlaintext(
      messageId: 'msg-3',
      plaintext: 'Third message',
      contactId: 'alice',
    );

    expect(await service.loadPlaintext('msg-1'), 'First message');
    expect(await service.loadPlaintext('msg-2'), 'Second message');
    expect(await service.loadPlaintext('msg-3'), 'Third message');
  });

  // ── Cold-start index rebuild ───────────────────────────────────────────

  test('rebuildIndex restores lookups after fresh service instance', () async {
    final auxRepo = await buildAuxRepo();
    final service1 = FsPlaintextPersistenceService(auxRepository: auxRepo);

    await service1.savePlaintext(
      messageId: 'msg-A',
      plaintext: 'Segreto A',
      contactId: 'alice',
    );
    await service1.savePlaintext(
      messageId: 'msg-B',
      plaintext: 'Segreto B',
      contactId: 'bob',
    );

    // Create a fresh service (simulates app restart — no in-memory index)
    final service2 = FsPlaintextPersistenceService(auxRepository: auxRepo);
    await service2.rebuildIndex();

    expect(await service2.loadPlaintext('msg-A'), 'Segreto A');
    expect(await service2.loadPlaintext('msg-B'), 'Segreto B');
  });

  test('cold-start scan works even without explicit rebuildIndex', () async {
    final auxRepo = await buildAuxRepo();
    final service1 = FsPlaintextPersistenceService(auxRepository: auxRepo);

    await service1.savePlaintext(
      messageId: 'msg-scan',
      plaintext: 'Found by scan',
      contactId: 'alice',
    );

    // Fresh service without rebuildIndex — loadPlaintext falls back to scan
    final service2 = FsPlaintextPersistenceService(auxRepository: auxRepo);
    expect(await service2.loadPlaintext('msg-scan'), 'Found by scan');
  });

  // ── Overwrite ──────────────────────────────────────────────────────────

  test('savePlaintext overwrites previous value for same messageId', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    await service.savePlaintext(
      messageId: 'msg-overwrite',
      plaintext: 'original',
      contactId: 'alice',
    );
    expect(await service.loadPlaintext('msg-overwrite'), 'original');

    await service.savePlaintext(
      messageId: 'msg-overwrite',
      plaintext: 'updated',
      contactId: 'alice',
    );
    expect(await service.loadPlaintext('msg-overwrite'), 'updated');
  });

  // ── Remove single ──────────────────────────────────────────────────────

  test('removePlaintext removes a single record', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    await service.savePlaintext(
      messageId: 'msg-keep',
      plaintext: 'keep',
      contactId: 'alice',
    );
    await service.savePlaintext(
      messageId: 'msg-delete',
      plaintext: 'delete me',
      contactId: 'alice',
    );

    await service.removePlaintext('msg-delete');

    expect(await service.loadPlaintext('msg-keep'), 'keep');
    expect(await service.loadPlaintext('msg-delete'), isNull);
  });

  // ── Remove all ─────────────────────────────────────────────────────────

  test('removeAll wipes all FS plaintext records (identity reset)', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    await service.savePlaintext(
      messageId: 'msg-1',
      plaintext: 'one',
      contactId: 'alice',
    );
    await service.savePlaintext(
      messageId: 'msg-2',
      plaintext: 'two',
      contactId: 'bob',
    );

    await service.removeAll();

    expect(await service.loadPlaintext('msg-1'), isNull);
    expect(await service.loadPlaintext('msg-2'), isNull);
  });

  test('removeAll does not affect non-plaintext aux records', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    // Write a FS plaintext record
    await service.savePlaintext(
      messageId: 'msg-pt',
      plaintext: 'plaintext',
      contactId: 'alice',
    );

    // Write a different kind of aux record directly
    final otherRecord = await auxRepo.write(
      payload: {'kind': 'fs_state_v1', 'data': 'ratchet-state'},
    );

    await service.removeAll();

    // FS plaintext gone
    expect(await service.loadPlaintext('msg-pt'), isNull);

    // Other aux record still exists
    final otherPayload = await auxRepo.read(
      storageId: otherRecord.storageId,
      recordId: otherRecord.recordId,
    );
    expect(otherPayload, isNotNull);
    expect(otherPayload!['kind'], 'fs_state_v1');
  });

  // ── Plausible deniability ──────────────────────────────────────────────

  test('FS plaintext records are externally indistinguishable from other aux records', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    // Write FS plaintext record
    await service.savePlaintext(
      messageId: 'msg-pd',
      plaintext: 'secret message',
      contactId: 'alice',
    );

    // Write a regular aux record
    await auxRepo.write(
      payload: {'kind': 'fs_state_v1', 'data': 'some-state'},
    );

    // All aux records in the Hive box should look identical externally
    final allKeys = box.keys
        .where((k) => k.toString().startsWith('m|test-scope|'))
        .toList();
    expect(allKeys.length, greaterThanOrEqualTo(2));

    // Each record should have the same external structure
    for (final key in allKeys) {
      final raw = box.get(key)!;
      // All aux records have 'a' flag and encrypted payload
      expect(raw.containsKey('encryptedRecord'), isTrue);
      expect(raw.containsKey('a'), isTrue);
      expect(raw['a'], isTrue);
      // No 'kind', 'msgId', or 'pt' visible externally
      expect(raw.containsKey('kind'), isFalse);
      expect(raw.containsKey('msgId'), isFalse);
      expect(raw.containsKey('pt'), isFalse);
    }
  });

  // ── Unicode and empty text ─────────────────────────────────────────────

  test('handles unicode plaintext correctly', () async {
    final auxRepo = await buildAuxRepo();
    final service = FsPlaintextPersistenceService(auxRepository: auxRepo);

    const unicodeText = '🔒 Ciao, come stai? Ça va bien? 日本語テスト';
    await service.savePlaintext(
      messageId: 'msg-unicode',
      plaintext: unicodeText,
      contactId: 'alice',
    );

    expect(await service.loadPlaintext('msg-unicode'), unicodeText);
  });
}
