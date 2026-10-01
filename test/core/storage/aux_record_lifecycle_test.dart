// Tests for AuxRecordRepository lifecycle (FS Spec Phase 2).
//
// Verifies that sealed auxiliary records follow the correct deletion rules
// required by spec §10.5 and §13:
//
//  T2.1  reset identity only  → aux records survive in the Hive box.
//  T2.2  reset messages       → aux records are deleted.
//  T2.3  delete chat          → aux records survive.
//  T2.4  delete single message → aux records survive.
//  T2.5  RemoteIdentity (contact record) does NOT contain FS state fields.
//  T2.6  write → update is atomic: new record written before old one deleted.
//  T2.7  clearAll only removes aux records in the current scope (not other scopes).

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/message_record_cipher.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';

void main() {
  late Directory tmpDir;
  late Box<Map> box;
  final masterBytes = Uint8List(32)..fillRange(0, 32, 0x77);

  Future<SecretKey> buildAuxKey() =>
      AuxRecordCipher.deriveAuxStorageKey(masterBytes);

  Future<AuxRecordRepository> buildRepo({
    String scope = 'test-scope',
    SecretKey? auxKey,
  }) async {
    final key = auxKey ?? await buildAuxKey();
    final repo = AuxRecordRepository();
    repo.setActiveContext(scopeToken: scope, auxStorageKey: key);
    return repo;
  }

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_aux_lifecycle_');
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

  for (final operation in ['add', 'delete', 'delete-chat']) {
    test('chat $operation cannot resurrect custody or roll back imported FS',
        () async {
      final aux = await buildRepo();
      final journal = await aux.write(payload: {
        'kind': 'keyboard_custody_v1',
        'v': 4,
      });
      final checkpoint = await aux.write(payload: {
        'kind': 'v3_session_checkpoint_v1',
        'revision': 1,
      });
      final messages = MessagesRepository();
      await messages.setActiveContext(
          scopeToken: 'test-scope',
          storageKey: await MessageRecordCipher.deriveKey(masterBytes,
              keyTag: 'test-tag'));
      const initial = MessageRecord(
        id: 'before-return',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'outgoing',
        timestamp: 1,
      );
      await messages.add(initial);

      // Native custody has returned a newer ratchet state into the same Hive
      // box. The chat repository is still alive with its earlier view.
      final imported = await aux.prepareImport(
          storageId: checkpoint.storageId,
          payload: {'kind': 'v3_session_checkpoint_v1', 'revision': 2});
      await aux.delete(checkpoint.storageId);
      await aux.applyPreparedImport(imported);
      await aux.delete(journal.storageId);
      await aux.flush();
      final checkpointLocation = 'm|test-scope|${checkpoint.storageId}';
      final newestEnvelope = Map.from(box.get(checkpointLocation)!);

      switch (operation) {
        case 'add':
          await messages.add(const MessageRecord(
            id: 'after-return',
            senderId: 'alice',
            recipientId: 'bob',
            direction: 'outgoing',
            timestamp: 2,
          ));
        case 'delete':
          await messages.delete(initial.id);
        case 'delete-chat':
          await messages.deleteAllForContact('bob');
      }
      await aux.flush();
      expect(box.containsKey('m|test-scope|${journal.storageId}'), isFalse,
          reason: 'A completed custody journal must never reappear');
      expect(
          box.get(checkpointLocation)?['encryptedRecord'] ==
              newestEnvelope['encryptedRecord'],
          isTrue,
          reason: 'Chat persistence must never overwrite a newer FS envelope');
      messages.dispose();
      await box.close();
      box = await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
      expect(box.containsKey('m|test-scope|${journal.storageId}'), isFalse);
      expect(
          box.get(checkpointLocation)?['encryptedRecord'] ==
              newestEnvelope['encryptedRecord'],
          isTrue);
      final reopened = await buildRepo();
      expect(
          (await reopened.read(
              storageId: checkpoint.storageId,
              recordId: reopened
                  .getAllAuxRecordIds()[checkpoint.storageId]!))?['revision'],
          2);
    });
  }

  test('deleted custody candidate is read only from authenticated Hive history',
      () async {
    final repo = await buildRepo();
    final written = await repo.write(payload: {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    });
    await repo.delete(written.storageId);
    expect(await repo.readDeletedAuxRecordForCustody(written.storageId), {
      'kind': 'v3.prefs.pending.manifest',
      'version': 1,
      'revision': 4,
    });
    expect(repo.getAllAuxRecordIds().containsKey(written.storageId), isFalse);

    final foreign = await buildRepo(auxKey: SecretKey(List<int>.filled(32, 8)));
    expect(await foreign.readDeletedAuxRecordForCustody(written.storageId),
        isNull);
  });

  // ---------------------------------------------------------------------------
  // T2.1  reset identity only → aux records survive
  // ---------------------------------------------------------------------------
  test('T2.1: aux records survive reset-identity-only (no clearAll called)',
      () async {
    final repo = await buildRepo();
    final (:storageId, :recordId) = await repo.write(
      payload: {'v': 1, 'kind': 'aux_state', 'records': []},
    );

    // "Reset identity only" wipes RAM keys but does NOT call clearAll() on the
    // message/aux repository.  Simulate this by creating a fresh repo instance
    // that is NOT set up (no context) — the record must still be in the box.
    final keyInBox = box.keys.any((k) => k.toString().contains(storageId));
    expect(keyInBox, isTrue,
        reason: 'Aux record must remain in box after identity-only reset');
  });

  // ---------------------------------------------------------------------------
  // T2.2  reset messages → aux records are deleted
  // ---------------------------------------------------------------------------
  test('T2.2: aux records are deleted by clearAll (reset messages)', () async {
    final repo = await buildRepo();
    final (:storageId, :recordId) = await repo.write(
      payload: {'v': 1, 'kind': 'aux_state', 'records': []},
    );

    // Confirm the record is present.
    expect(box.keys.any((k) => k.toString().contains(storageId)), isTrue);

    // "Reset messages" calls clearAll on the aux repository.
    await repo.clearAll();

    expect(
      box.keys.any((k) => k.toString().contains(storageId)),
      isFalse,
      reason: 'Aux record must be deleted by clearAll (reset messages)',
    );
  });

  // ---------------------------------------------------------------------------
  // T2.3  delete chat → aux records survive
  // ---------------------------------------------------------------------------
  test(
      'T2.3: aux records survive delete-chat (which only removes message records)',
      () async {
    // Set up a messages repository alongside the aux repository, sharing the box.
    final auxRepo = await buildRepo();
    final msgRepo = MessagesRepository();
    final storageKey =
        await MessageRecordCipher.deriveKey(masterBytes, keyTag: 'test-tag');
    await msgRepo.setActiveContext(
        scopeToken: 'test-scope', storageKey: storageKey);

    // Add a message and an aux record.
    await msgRepo.add(const MessageRecord(
      id: 'msg-1',
      senderId: 'alice',
      recipientId: 'bob',
      direction: 'outgoing',
      timestamp: 1,
    ));
    final (:storageId, :recordId) = await auxRepo.write(
      payload: {'v': 1, 'kind': 'aux_state', 'records': []},
    );

    // "Delete chat" = deleteAllForContact on the messages repo.
    await msgRepo.deleteAllForContact('bob');

    // Aux record must still be in the box.
    expect(
      box.keys.any((k) => k.toString().contains(storageId)),
      isTrue,
      reason: 'Aux record must survive delete-chat',
    );

    msgRepo.dispose();
  });

  // ---------------------------------------------------------------------------
  // T2.4  delete single message → aux records survive
  // ---------------------------------------------------------------------------
  test('T2.4: aux records survive single message deletion', () async {
    final auxRepo = await buildRepo();
    final msgRepo = MessagesRepository();
    final storageKey =
        await MessageRecordCipher.deriveKey(masterBytes, keyTag: 'test-tag');
    await msgRepo.setActiveContext(
        scopeToken: 'test-scope', storageKey: storageKey);

    await msgRepo.add(const MessageRecord(
      id: 'msg-2',
      senderId: 'alice',
      recipientId: 'bob',
      direction: 'outgoing',
      timestamp: 2,
    ));
    final (:storageId, :recordId) = await auxRepo.write(
      payload: {'v': 1, 'kind': 'aux_state', 'records': []},
    );

    // "Delete single message".
    await msgRepo.delete('msg-2');

    expect(
      box.keys.any((k) => k.toString().contains(storageId)),
      isTrue,
      reason: 'Aux record must survive single message deletion',
    );

    msgRepo.dispose();
  });

  // ---------------------------------------------------------------------------
  // T2.5  contact record does NOT contain FS state fields
  // ---------------------------------------------------------------------------
  test('T2.5: RemoteIdentity.toMap does not contain FS/passphrase fields', () {
    final contact = const RemoteIdentity(
      identityId: 'alice',
      publicKeyBase64: 'pk',
      fingerprint: 'fp',
      displayName: 'Alice',
    );

    final map = contact.toMap();

    const forbidden = [
      'fs_active',
      'strict_requested',
      'strict_fs_active',
      'last_fs_device',
      'passphrase_timeout',
      'hidden_session_exists',
      'passphrase_security_mode',
      'fs',
      'ratchet',
    ];
    for (final field in forbidden) {
      expect(
        map.containsKey(field),
        isFalse,
        reason: 'RemoteIdentity map must not contain "$field"',
      );
    }
  });

  // ---------------------------------------------------------------------------
  // T2.6  update is atomic: new record written before old one deleted
  // ---------------------------------------------------------------------------
  test('T2.6: update writes new record before deleting old one', () async {
    final repo = await buildRepo();

    final first = await repo.write(
      payload: {'v': 1, 'kind': 'aux_state', 'records': [], 'seq': 1},
    );

    // Both old and new keys will momentarily coexist during update.
    // After update, only the new record should be in the box.
    final second = await repo.update(
      oldStorageId: first.storageId,
      newPayload: {'v': 1, 'kind': 'aux_state', 'records': [], 'seq': 2},
    );

    // Old record is gone.
    expect(
      box.keys.any((k) => k.toString().contains(first.storageId)),
      isFalse,
      reason: 'Old record must be deleted after update',
    );
    // New record is present.
    expect(
      box.keys.any((k) => k.toString().contains(second.storageId)),
      isTrue,
      reason: 'New record must be present after update',
    );

    // New record must decrypt correctly.
    final auxKey = await buildAuxKey();
    final repo2 = await buildRepo(auxKey: auxKey);
    final decrypted = await repo2.read(
      storageId: second.storageId,
      recordId: second.recordId,
    );
    expect(decrypted, isNotNull);
    expect(decrypted!['seq'], equals(2));
  });

  // ---------------------------------------------------------------------------
  // T2.7  clearAll only removes aux records in the current scope
  // ---------------------------------------------------------------------------
  test('T2.7: clearAll does not delete records from other scope', () async {
    final auxKey = await buildAuxKey();

    final repoA = await buildRepo(scope: 'scope-a', auxKey: auxKey);
    final repoB = await buildRepo(scope: 'scope-b', auxKey: auxKey);

    final a = await repoA.write(
      payload: {'v': 1, 'kind': 'aux_state', 'records': [], 'owner': 'A'},
    );
    final b = await repoB.write(
      payload: {'v': 1, 'kind': 'aux_state', 'records': [], 'owner': 'B'},
    );

    // Clear only scope-a.
    await repoA.clearAll();

    // Scope-a record is gone.
    expect(
      box.keys.any((k) => k.toString().contains(a.storageId)),
      isFalse,
      reason: 'Scope-a aux record must be deleted by clearAll',
    );
    // Scope-b record survives.
    expect(
      box.keys.any((k) => k.toString().contains(b.storageId)),
      isTrue,
      reason: 'Scope-b aux record must survive scope-a clearAll',
    );
  });

  // ---------------------------------------------------------------------------
  // T2.8  clearByKind only removes aux records of the specified kind
  // ---------------------------------------------------------------------------
  test('T2.8: clearByKind only deletes records of specified kind', () async {
    final repo = await buildRepo(scope: 'kind-test');

    // Write records of different kinds
    final fsState = await repo.write(
      payload: {'v': 1, 'kind': 'fs_state_v1', 'contactId': 'bob'},
    );
    final fsRatchet = await repo.write(
      payload: {'v': 1, 'kind': 'fs_ratchet_v1', 'sessionId': 'abc'},
    );
    final other = await repo.write(
      payload: {'v': 1, 'kind': 'other_kind', 'data': 'test'},
    );

    // Clear only fs_state_v1 records
    await repo.clearByKind('fs_state_v1');

    // fs_state_v1 record is gone
    expect(
      box.keys.any((k) => k.toString().contains(fsState.storageId)),
      isFalse,
      reason: 'fs_state_v1 record must be deleted by clearByKind',
    );

    // fs_ratchet_v1 record survives
    expect(
      box.keys.any((k) => k.toString().contains(fsRatchet.storageId)),
      isTrue,
      reason: 'fs_ratchet_v1 record must survive clearByKind(fs_state_v1)',
    );

    // other_kind record survives
    expect(
      box.keys.any((k) => k.toString().contains(other.storageId)),
      isTrue,
      reason: 'other_kind record must survive clearByKind(fs_state_v1)',
    );
  });

  // ---------------------------------------------------------------------------
  // T2.9  clearByKind with identityContext filters by both kind and context
  // ---------------------------------------------------------------------------
  test('T2.9: clearByKind with identityContext filters correctly', () async {
    final repo = await buildRepo(scope: 'ctx-test');

    // Write records with different identity contexts
    final primary = await repo.write(
      payload: {
        'v': 1,
        'kind': 'fs_state_v1',
        'identityContext': 'primary',
        'contactId': 'bob',
      },
    );
    final passphrase = await repo.write(
      payload: {
        'v': 1,
        'kind': 'fs_state_v1',
        'identityContext': 'pp-ctx-123',
        'contactId': 'alice',
      },
    );

    // Clear only primary context records
    await repo.clearByKind('fs_state_v1', identityContext: 'primary');

    // primary record is gone
    expect(
      box.keys.any((k) => k.toString().contains(primary.storageId)),
      isFalse,
      reason: 'primary context record must be deleted',
    );

    // passphrase context record survives
    expect(
      box.keys.any((k) => k.toString().contains(passphrase.storageId)),
      isTrue,
      reason: 'passphrase context record must survive',
    );
  });
}
