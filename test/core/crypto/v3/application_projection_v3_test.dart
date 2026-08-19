import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/v3/application_payload_v3.dart';
import 'package:layergram/core/crypto/v3/application_projection_v3.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/hybrid_ratchet_header_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';

void main() {
  late Directory temporaryDirectory;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    temporaryDirectory =
        await Directory.systemTemp.createTemp('layergram_v3_projection_');
    Hive.init(temporaryDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await temporaryDirectory.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
  });

  test('projects Normal-device duplicates once and reloads plaintext from AR3',
      () async {
    final alice = _identity(0x11, 'Alice');
    final bob = _identity(0x61, 'Bob');
    final payload = V3ApplicationPayloadCodec.encode(
      V3ApplicationPayload(
        messageId: _bytes(16, 0xa1),
        senderIdentityDigest: _identityDigest(alice),
        recipientIdentityDigest: _identityDigest(bob),
        text: 'ciao post-quantum',
        timestampUnixSeconds: 2000000000,
        senderDisplayName: 'Alice',
        expireAfterUnixSeconds: 2000003600,
        deleteAfterRead: true,
        backupExcluded: true,
      ),
    );
    final records = <Uint8List>[
      _committed(payload, 0x21),
      _committed(payload, 0x31),
    ];
    final repository = MessagesRepository();
    await repository.setActiveContext(
      scopeToken: 'projection-scope',
      storageKey: SecretKey(_bytes(32, 0x41)),
    );
    var projector = V3ApplicationMessageProjector(
      messagesRepository: repository,
      localIdentity: alice,
      recordLoader: () async =>
          records.map(Uint8List.fromList).toList(growable: false),
      keyTag: 'primary-tag',
    );

    final first = await projector.reconcile(nowUnixSeconds: 2000000001);
    expect(first.discoveredRecords, 2);
    expect(first.insertedMessages, 1);
    expect(first.exactDeviceDuplicates, 1);
    final message = (await repository.getAllMessages()).single;
    expect(
        message.id, startsWith(V3ApplicationMessageProjector.messageIdPrefix));
    expect(message.senderId, alice.identityId);
    expect(message.recipientId, bob.identityId);
    expect(message.direction, 'outgoing');
    expect(message.text, isNull);
    expect(message.isFsEncrypted, isTrue);
    expect(message.isV3Encrypted, isTrue);
    expect(message.protocolVersion, 3);
    expect(message.deleteAfterRead, isTrue);
    expect(message.backupExcluded, isTrue);
    expect(await projector.loadPlaintext(message.id), 'ciao post-quantum');
    projector.close();
    repository.dispose();

    final reopened = MessagesRepository();
    await reopened.setActiveContext(
      scopeToken: 'projection-scope',
      storageKey: SecretKey(_bytes(32, 0x41)),
    );
    projector = V3ApplicationMessageProjector(
      messagesRepository: reopened,
      localIdentity: alice,
      recordLoader: () async =>
          records.map(Uint8List.fromList).toList(growable: false),
      keyTag: 'primary-tag',
    );
    expect((await reopened.getAllMessages()).single.isV3Encrypted, isTrue);
    final restored = await projector.reconcile(nowUnixSeconds: 2000000001);
    expect(restored.insertedMessages, 0);
    expect(restored.alreadyProjectedMessages, 1);
    expect(await projector.loadPlaintext(message.id), 'ciao post-quantum');
    projector.close();
    reopened.dispose();

    payload.fillRange(0, payload.length, 0);
    for (final record in records) {
      record.fillRange(0, record.length, 0);
    }
  });

  test('does not overwrite a conflicting existing chat record', () async {
    final alice = _identity(0x11, 'Alice');
    final bob = _identity(0x61, 'Bob');
    final payload = V3ApplicationPayloadCodec.encode(
      V3ApplicationPayload(
        messageId: _bytes(16, 0xb1),
        senderIdentityDigest: _identityDigest(bob),
        recipientIdentityDigest: _identityDigest(alice),
        text: 'incoming',
        timestampUnixSeconds: 1770000000,
      ),
    );
    final record = _committed(payload, 0x51);
    final stableMessageId =
        V3ApplicationPayloadCodec.decode(payload).stableMessageId;
    final repository = MessagesRepository();
    await repository.setActiveContext(
      scopeToken: 'projection-scope',
      storageKey: SecretKey(_bytes(32, 0x41)),
    );
    await repository.add(
      MessageRecord(
        id: '${V3ApplicationMessageProjector.messageIdPrefix}$stableMessageId',
        senderId: 'different',
        recipientId: alice.identityId,
        direction: 'incoming',
        timestamp: 1770000000,
      ),
    );
    final projector = V3ApplicationMessageProjector(
      messagesRepository: repository,
      localIdentity: alice,
      recordLoader: () async => [Uint8List.fromList(record)],
      keyTag: 'primary-tag',
    );

    await expectLater(
      projector.reconcile(),
      throwsA(isA<V3LmfPersistenceConflictException>()),
    );
    expect((await repository.getAllMessages()).single.senderId, 'different');

    projector.close();
    repository.dispose();
    payload.fillRange(0, payload.length, 0);
    record.fillRange(0, record.length, 0);
  });
}

Uint8List _committed(Uint8List content, int seed) {
  final frame = V3LmfFrame(
    metadata: V3LmfMessageMetadata(
      kind: V3LmfFrameKind.application,
      senderBinding: _bytes(32, seed),
      recipientBinding: _bytes(32, seed + 1),
      messageId: _bytes(16, seed + 2),
      sessionId: _bytes(16, seed + 3),
      epoch: 0,
      messageCounter: 0,
    ),
    fragmentIndex: 0,
    fragmentCount: 1,
    assembledPlaintextLength: content.length,
    nonce: _bytes(12, seed + 4),
    ciphertext: _bytes(content.length, seed + 5),
    authenticationTag: _bytes(16, seed + 6),
    hybridRatchetHeader: V3HybridRatchetHeader(
      ecHeader: V3EcRatchetHeader(
        ratchetPublicKey: _bytes(32, seed + 7),
        previousSendingChainLength: 0,
        messageCounter: 0,
      ),
      sckaMessage: V3SckaMessage(
        sendingEpoch: 0,
        messageCounter: 0,
        nativePayload: Uint8List(0),
      ),
    ),
  );
  final committed = V3CommittedRecord.fromDelivery(
    targetFrame: frame,
    content: content,
  );
  try {
    return V3CommittedRecordCodec.encode(committed);
  } finally {
    committed.wipeContent();
  }
}

V3PublicIdentity _identity(int seed, String name) => V3PublicIdentity(
      x25519PublicKey: _bytes(32, seed),
      mlKem768PublicKey: _bytes(MlKem768.publicKeyBytes, seed + 1),
      displayName: name,
    );

Uint8List _identityDigest(V3PublicIdentity identity) {
  final binding = identity.identityBindingBytes;
  try {
    return Uint8List.fromList(crypto.sha384.convert(binding).bytes);
  } finally {
    binding.fillRange(0, binding.length, 0);
  }
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
