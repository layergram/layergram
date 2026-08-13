import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_outbox.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory temporaryDirectory;
  late Box<Map> box;
  late SecretKey auxiliaryKey;
  final messageKey = SecretKeyData(_bytes(32, 0x11));

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    temporaryDirectory =
        await Directory.systemTemp.createTemp('layergram_v3_lmf_aux_');
    Hive.init(temporaryDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    box = Hive.box<Map>(LocalDatabase.messagesBoxName);
    auxiliaryKey = await AuxRecordCipher.deriveAuxStorageKey(_bytes(32, 0x77));
  });

  tearDownAll(() async {
    await Hive.close();
    await temporaryDirectory.delete(recursive: true);
  });

  setUp(() => box.clear());

  test('inbox frames and commit tombstones stay externally opaque', () async {
    final frames = await _frames(messageKey);
    final firstRepository = _repository(auxiliaryKey, 'primary-scope');
    final first = V3LmfDurableInbox(
      store: V3LmfAuxRecordStore(firstRepository),
    );
    await first.restore(keyResolver: (_) => messageKey);
    await first.receive(frame: frames.first, secretKey: messageKey);

    _expectOnlyOpaqueRecords(box);
    expect(box.values.single.toString(), isNot(contains('v3_lmf_in_v1')));
    expect(box.values.single.toString(), isNot(contains('frame')));
    await first.close();

    final restored = V3LmfDurableInbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'primary-scope'),
      ),
    );
    final restoreResult =
        await restored.restore(keyResolver: (_) => messageKey);
    expect(restoreResult.deliveries, isEmpty);
    final complete = await restored.receive(
      frame: frames.last,
      secretKey: messageKey,
    );
    expect(complete.delivery!.plaintext, orderedEquals(_bytes(300, 0x31)));
    await restored.commit(complete.delivery!);

    _expectOnlyOpaqueRecords(box);
    expect(box.values.single.toString(), isNot(contains('v3_lmf_done_v1')));
    await restored.close();

    final afterCommit = V3LmfDurableInbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'primary-scope'),
      ),
    );
    final afterCommitResult =
        await afterCommit.restore(keyResolver: (_) => messageKey);
    expect(afterCommitResult.deliveries, isEmpty);
    expect(afterCommit.committedTombstoneCount, 1);
  });

  test('outbox exact bytes restore through encrypted aux records', () async {
    final frames = await _frames(messageKey);
    final original = frames.map(V3LmfFrameCodec.encodeBinary).toList();
    final first = V3LmfDurableOutbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'passphrase-scope'),
      ),
    );
    await first.restore();
    final entry = await first.enqueue(frames);
    await first.markExported(
      assemblyId: entry.assemblyId,
      fragmentIndexes: {0},
    );
    _expectOnlyOpaqueRecords(box);
    expect(box.values.single.toString(), isNot(contains('v3_lmf_out_v1')));
    await first.close();

    final restored = V3LmfDurableOutbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'passphrase-scope'),
      ),
    );
    final result = await restored.restore();
    expect(result.entries.single.exportAttempts, [1, 0]);
    for (var index = 0; index < original.length; index++) {
      expect(
        V3LmfFrameCodec.encodeBinary(result.entries.single.frames[index]),
        orderedEquals(original[index]),
      );
    }

    // A different identity/passphrase scope cannot enumerate these records.
    final isolated = V3LmfDurableOutbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'different-scope'),
      ),
    );
    expect((await isolated.restore()).entries, isEmpty);
  });
}

AuxRecordRepository _repository(SecretKey key, String scope) {
  final repository = AuxRecordRepository();
  repository.setActiveContext(scopeToken: scope, auxStorageKey: key);
  return repository;
}

void _expectOnlyOpaqueRecords(Box<Map> box) {
  expect(box.values, isNotEmpty);
  for (final raw in box.values) {
    expect(raw.keys, {'encryptedRecord'});
    final encrypted = raw['encryptedRecord'];
    expect(encrypted, isA<String>());
    expect((encrypted! as String).length, greaterThan(100));
  }
}

Future<List<V3LmfFrame>> _frames(SecretKey key) => V3LmfAead.sealFragmented(
      metadata: V3LmfMessageMetadata(
        kind: V3LmfFrameKind.application,
        senderBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x01),
        recipientBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x41),
        messageId: _bytes(V3LmfFrameCodec.messageIdBytes, 0x81),
        sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
        epoch: 7,
        messageCounter: 9,
      ),
      plaintext: _bytes(300, 0x31),
      secretKey: key,
      nonceForFragment: (index) =>
          _bytes(V3LmfFrameCodec.nonceBytes, 0x51 + index),
    );

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
