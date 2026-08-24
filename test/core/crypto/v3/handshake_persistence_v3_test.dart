import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/handshake_persistence_v3.dart';
import 'package:layergram/core/crypto/v3/initial_session_handoff_authority_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';

void main() {
  const aliceMnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const bobMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

  late _HandshakeMlKemBackend backend;
  late V3LocalIdentityHandle alice;
  late V3LocalIdentityHandle bob;
  late V3LocalDeviceHandle aliceDevice;
  late V3LocalDeviceHandle bobDevice;

  setUp(() async {
    backend = _HandshakeMlKemBackend();
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: backend,
    );
    alice = await factory.restorePrimary(mnemonic: aliceMnemonic);
    bob = await factory.restorePrimary(mnemonic: bobMnemonic);
    aliceDevice = await V3LocalDeviceHandle.fromSeed(_bytes(32, 0x11));
    bobDevice = await V3LocalDeviceHandle.fromSeed(_bytes(32, 0x51));
  });

  tearDown(() async {
    aliceDevice.close();
    bobDevice.close();
    await alice.close();
    await bob.close();
  });

  group('inactive v3 durable handshake persistence', () {
    test('persists an offer before returning exact export bytes', () async {
      final store = _FaultStore();
      final controller = _controller(store);
      final restored = await controller.restore();
      expect(restored.pendingOutbound, isEmpty);

      final outbound = await controller.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
        createdAt: DateTime.utc(2026, 8, 14, 20),
      );

      expect(outbound.restored, isFalse);
      expect(outbound.kind, V3HandshakeRecordKind.offer);
      expect(outbound.stateDigest, hasLength(43));
      expect(
        V3HandshakeCodec.decodeOffer(outbound.outboundRecord).messageId,
        orderedEquals(_decodeId(outbound.messageId)),
      );
      expect(
        store.records.values.single['kind'],
        V3HandshakePendingRepository.pendingRecordKind,
      );
      final retry = (await controller.pendingOutbound()).single;
      expect(retry.restored, isTrue);
      expect(retry.outboundRecord, orderedEquals(outbound.outboundRecord));
      await controller.close();
    });

    test('restart restores exact offer and secret HP3 without new crypto',
        () async {
      final store = _FaultStore();
      final first = _controller(store);
      await first.restore();
      final outbound = await first.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.maximum,
      );
      final encapsulations = backend.encapsulationCount;
      await first.close();

      final recovered = _controller(store);
      final restore = await recovered.restore();
      expect(restore.pendingOutbound, hasLength(1));
      expect(
        restore.pendingOutbound.single.outboundRecord,
        orderedEquals(outbound.outboundRecord),
      );
      expect(backend.encapsulationCount, encapsulations);

      final pending = await recovered.resumeInitiator(outbound.handshakeId);
      final responder = await V3HybridHandshake.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: pending.offer,
        expectedMode: V3HandshakeMode.maximum,
      );
      final result = await V3HybridHandshake.acceptReply(
        pending: pending,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: responder.reply,
      );
      expect(result.confirmation.mode, V3HandshakeMode.maximum);
      result.established.close();
      responder.close();
      await recovered.close();
    });

    test('duplicate offer returns the exact durable reply without ML-KEM rerun',
        () async {
      final offer = await V3HybridHandshake.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      final store = _FaultStore();
      final controller = _controller(store);
      await controller.restore();
      final first = await controller.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: offer.offer,
        expectedMode: V3HandshakeMode.normal,
      );
      final encapsulations = backend.encapsulationCount;

      final retry = await controller.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: offer.offer,
        expectedMode: V3HandshakeMode.normal,
      );

      expect(retry.restored, isTrue);
      expect(retry.outboundRecord, orderedEquals(first.outboundRecord));
      expect(backend.encapsulationCount, encapsulations);
      offer.close();
      await controller.close();
    });

    test('ambiguous pending write requires restore and never exports',
        () async {
      final store = _FaultStore()
        ..persistAndThrowKindOnce =
            V3HandshakePendingRepository.pendingRecordKind;
      final controller = _controller(store);
      await controller.restore();

      await expectLater(
        controller.createOffer(
          localIdentity: alice,
          localDevice: aliceDevice,
          remoteIdentity: bob.publicIdentity,
          mode: V3HandshakeMode.normal,
        ),
        throwsStateError,
      );
      expect(controller.requiresRecovery, isTrue);
      expect(backend.encapsulationCount, 1);
      await controller.close();

      final recovered = _controller(store);
      final restore = await recovered.restore();
      expect(restore.pendingOutbound, hasLength(1));
      expect(restore.pendingOutbound.single.restored, isTrue);
      expect(backend.encapsulationCount, 1);
      await recovered.close();
    });

    test('completion tombstone suppresses HP3 and retains exact confirmation',
        () async {
      final store = _FaultStore();
      final authority = V3InitialSessionHandoffAuthority();
      final controller = _controller(
        store,
        initialHandoffAuthority: authority,
      );
      await controller.restore();
      await controller.claimInitialHandoffAuthority(authority);
      final outbound = await controller.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      final pending = await controller.resumeInitiator(outbound.handshakeId);
      final responder = await V3HybridHandshake.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: pending.offer,
        expectedMode: V3HandshakeMode.normal,
      );
      final result = await V3HybridHandshake.acceptReply(
        pending: pending,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: responder.reply,
      );
      final confirmationBytes =
          V3HandshakeCodec.encodeConfirmation(result.confirmation);
      final sessionId = result.established.sessionKeys.sessionId;
      await expectLater(
        controller.markHandoffCommitted(
          handshakeId: outbound.handshakeId,
          expectedStateDigest: outbound.stateDigest,
          confirmation: result.confirmation,
          sessionId: sessionId,
          checkpointDigest: _id(_bytes(32, 0x91)),
          completedAt: DateTime.utc(2026, 8, 14, 21),
          authority: V3InitialSessionHandoffAuthority(),
        ),
        throwsStateError,
      );
      expect(await controller.pendingOutbound(), hasLength(1));
      await expectLater(
        controller.markHandoffCommitted(
          handshakeId: outbound.handshakeId,
          expectedStateDigest: outbound.stateDigest,
          confirmation: result.confirmation,
          sessionId: Uint8List(16),
          checkpointDigest: _id(_bytes(32, 0x91)),
          completedAt: DateTime.utc(2026, 8, 14, 21),
          authority: authority,
        ),
        throwsFormatException,
      );
      expect(controller.requiresRecovery, isFalse);
      expect(await controller.pendingOutbound(), hasLength(1));
      final completion = await controller.markHandoffCommitted(
        handshakeId: outbound.handshakeId,
        expectedStateDigest: outbound.stateDigest,
        confirmation: result.confirmation,
        sessionId: sessionId,
        checkpointDigest: _id(_bytes(32, 0x91)),
        completedAt: DateTime.utc(2026, 8, 14, 21),
        authority: authority,
      );

      expect(completion.terminalRecord, orderedEquals(confirmationBytes));
      expect(await controller.pendingOutbound(), isEmpty);
      expect(
        store.records.values.map((value) => value['kind']).toSet(),
        {V3HandshakePendingRepository.completionRecordKind},
      );
      await controller.close();

      final recovered = _controller(store);
      final restore = await recovered.restore();
      expect(restore.pendingOutbound, isEmpty);
      expect(restore.completionCount, 1);
      final resend = await recovered.completedConfirmationForId(
        outbound.handshakeId,
      );
      expect(resend, isNotNull);
      expect(resend!.outboundRecord, orderedEquals(confirmationBytes));
      expect(resend.messageId, _id(result.confirmation.messageId));

      _wipe(sessionId);
      _wipe(confirmationBytes);
      result.established.close();
      responder.close();
      await recovered.close();
    });

    test('ambiguous completion write restores the tombstone without HP3',
        () async {
      final store = _FaultStore();
      final authority = V3InitialSessionHandoffAuthority();
      final controller = _controller(
        store,
        initialHandoffAuthority: authority,
      );
      await controller.restore();
      await controller.claimInitialHandoffAuthority(authority);
      final outbound = await controller.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      final pending = await controller.resumeInitiator(outbound.handshakeId);
      final responder = await V3HybridHandshake.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: pending.offer,
        expectedMode: V3HandshakeMode.normal,
      );
      final result = await V3HybridHandshake.acceptReply(
        pending: pending,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: responder.reply,
      );
      final sessionId = result.established.sessionKeys.sessionId;
      store.persistAndThrowKindOnce =
          V3HandshakePendingRepository.completionRecordKind;

      await expectLater(
        controller.markHandoffCommitted(
          handshakeId: outbound.handshakeId,
          expectedStateDigest: outbound.stateDigest,
          confirmation: result.confirmation,
          sessionId: sessionId,
          checkpointDigest: _id(_bytes(32, 0xb1)),
          completedAt: DateTime.utc(2026, 8, 14, 23),
          authority: authority,
        ),
        throwsStateError,
      );
      expect(controller.requiresRecovery, isTrue);
      await controller.close();

      final recovered = _controller(store);
      final restore = await recovered.restore();
      expect(restore.pendingOutbound, isEmpty);
      expect(restore.completionCount, 1);
      expect(restore.suppressedCompletedPending, 1);
      expect(
        await recovered.completedConfirmationForId(outbound.handshakeId),
        isNotNull,
      );

      _wipe(sessionId);
      result.established.close();
      responder.close();
      await recovered.close();
    });

    test('ambiguous pending delete recovers from the durable tombstone',
        () async {
      final store = _FaultStore();
      final authority = V3InitialSessionHandoffAuthority();
      final controller = _controller(
        store,
        initialHandoffAuthority: authority,
      );
      await controller.restore();
      await controller.claimInitialHandoffAuthority(authority);
      final outbound = await controller.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      final pending = await controller.resumeInitiator(outbound.handshakeId);
      final responder = await V3HybridHandshake.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: pending.offer,
        expectedMode: V3HandshakeMode.normal,
      );
      final result = await V3HybridHandshake.acceptReply(
        pending: pending,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: responder.reply,
      );
      final sessionId = result.established.sessionKeys.sessionId;
      store.deleteAndThrowOnce = true;

      await expectLater(
        controller.markHandoffCommitted(
          handshakeId: outbound.handshakeId,
          expectedStateDigest: outbound.stateDigest,
          confirmation: result.confirmation,
          sessionId: sessionId,
          checkpointDigest: _id(_bytes(32, 0xa1)),
          completedAt: DateTime.utc(2026, 8, 14, 22),
          authority: authority,
        ),
        throwsStateError,
      );
      expect(controller.requiresRecovery, isTrue);
      await controller.close();

      final recovered = _controller(store);
      final restore = await recovered.restore();
      expect(restore.pendingOutbound, isEmpty);
      expect(restore.completionCount, 1);
      expect(
        await recovered.completedConfirmationForId(outbound.handshakeId),
        isNotNull,
      );

      _wipe(sessionId);
      result.established.close();
      responder.close();
      await recovered.close();
    });

    test('per-contact cap rejects before running expensive cryptography',
        () async {
      final store = _FaultStore();
      final repository = V3HandshakePendingRepository(
        store: store,
        maxPending: 2,
        maxPendingPerRemoteIdentity: 1,
      );
      final controller = V3HandshakePersistenceController(
        repository: repository,
      );
      await controller.restore();
      await controller.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      final encapsulations = backend.encapsulationCount;

      await expectLater(
        controller.createOffer(
          localIdentity: alice,
          localDevice: aliceDevice,
          remoteIdentity: bob.publicIdentity,
          mode: V3HandshakeMode.normal,
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(backend.encapsulationCount, encapsulations);
      expect(controller.requiresRecovery, isFalse);
      await controller.close();
    });

    test('corrupt pending state fails closed and remains stored', () async {
      final store = _FaultStore();
      final controller = _controller(store);
      await controller.restore();
      await controller.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      await controller.close();
      final storageId = store.records.keys.single;
      final payload = store.records[storageId]!;
      final encoded = payload['pendingState'] as String;
      payload['pendingState'] =
          '${encoded.substring(0, encoded.length - 1)}${encoded.endsWith('A') ? 'B' : 'A'}';

      final recovered = _controller(store);
      await expectLater(recovered.restore(), throwsFormatException);
      expect(store.records.containsKey(storageId), isTrue);
      await recovered.close();
    });

    test('claimed repository rejects direct reads and a second controller',
        () async {
      final store = _FaultStore();
      final repository = V3HandshakePendingRepository(store: store);
      final controller = V3HandshakePersistenceController(
        repository: repository,
      );
      await controller.restore();

      expect(repository.pending, throwsStateError);
      await expectLater(
        repository.claimControllerAuthority(),
        throwsStateError,
      );
      await controller.close();
    });

    test('same pending state is idempotent even with a later caller timestamp',
        () async {
      final store = _FaultStore();
      final repository = V3HandshakePendingRepository(store: store);
      await repository.restore();
      final state = await V3HybridHandshake.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      final first = await repository.persistInitiator(
        state: state,
        createdAt: DateTime.utc(2026, 8, 14, 20),
      );
      final repeated = await repository.persistInitiator(
        state: state,
        createdAt: DateTime.utc(2026, 8, 14, 21),
      );

      expect(repeated.storageId, first.storageId);
      expect(store.records, hasLength(1));
      state.close();
      await repository.close();
    });

    test('restore removes an exact duplicate and keeps one pending export',
        () async {
      final store = _FaultStore();
      final first = _controller(store);
      await first.restore();
      final outbound = await first.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      await first.close();
      store.records['record-duplicate'] = _copy(store.records.values.single);

      final restored = _controller(store);
      final result = await restored.restore();
      expect(result.pendingOutbound, hasLength(1));
      expect(result.pendingOutbound.single.outboundRecord,
          orderedEquals(outbound.outboundRecord));
      expect(result.removedObsoleteRecords, 1);
      expect(store.records, hasLength(1));
      await restored.close();
    });
  });
}

V3HandshakePersistenceController _controller(
  V3LmfRecordStore store, {
  V3InitialSessionHandoffAuthority? initialHandoffAuthority,
}) =>
    V3HandshakePersistenceController(
      repository: V3HandshakePendingRepository(store: store),
      initialHandoffAuthority: initialHandoffAuthority,
    );

final class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  int _nextId = 0;
  String? persistAndThrowKindOnce;
  bool deleteAndThrowOnce = false;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final storageId = 'record-${_nextId++}';
    records[storageId] = _copy(payload);
    if (persistAndThrowKindOnce == payload['kind']) {
      persistAndThrowKindOnce = null;
      throw StateError('persisted then failed');
    }
    return storageId;
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
    if (deleteAndThrowOnce) {
      deleteAndThrowOnce = false;
      throw StateError('deleted then failed');
    }
  }
}

Map<String, dynamic> _copy(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

String _id(Uint8List value) => base64Url.encode(value).replaceAll('=', '');

Uint8List _decodeId(String value) =>
    Uint8List.fromList(base64Url.decode(base64Url.normalize(value)));

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Uint8List _u32(int value) {
  final result = Uint8List(4);
  ByteData.sublistView(result).setUint32(0, value, Endian.big);
  return result;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);

final class _HandshakeMlKemPrivateKeyHandle
    implements MlKem768PrivateKeyHandle {
  _HandshakeMlKemPrivateKeyHandle(this.publicKey);

  final Uint8List publicKey;

  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    isClosed = true;
  }
}

final class _HandshakeMlKemBackend implements MlKem768Backend {
  int _encapsulationCounter = 0;

  int get encapsulationCount => _encapsulationCounter;

  @override
  String get implementationId => 'test-only-handshake-persistence-ml-kem';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    final digest = sha512.convert(seed).bytes;
    final publicKey = Uint8List.fromList(
      List<int>.generate(
        MlKem768.publicKeyBytes,
        (index) => digest[index % digest.length],
      ),
    );
    return MlKem768KeyPair(
      publicKey: publicKey,
      privateKeyHandle: _HandshakeMlKemPrivateKeyHandle(publicKey),
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async =>
      publicKey.length == MlKem768.publicKeyBytes &&
      publicKey.any((byte) => byte != 0);

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) async {
    _encapsulationCounter++;
    final counter = _u32(_encapsulationCounter);
    final block = sha512.convert(<int>[...publicKey, ...counter]).bytes;
    final ciphertext = Uint8List.fromList(
      List<int>.generate(
        MlKem768.ciphertextBytes,
        (index) => block[index % block.length] ^ (index & 0xff),
      ),
    );
    return MlKem768Encapsulation(
      ciphertext: ciphertext,
      sharedSecret: _sharedSecret(publicKey, ciphertext),
    );
  }

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) async {
    final handle = privateKeyHandle as _HandshakeMlKemPrivateKeyHandle;
    if (handle.isClosed || ciphertext.length != MlKem768.ciphertextBytes) {
      throw StateError('invalid test ML-KEM handle or ciphertext');
    }
    return _sharedSecret(handle.publicKey, ciphertext);
  }

  Uint8List _sharedSecret(Uint8List publicKey, Uint8List ciphertext) =>
      Uint8List.fromList(
        sha256.convert(<int>[
          ...'test-only-handshake-shared\x00'.codeUnits,
          ...publicKey,
          ...ciphertext,
        ]).bytes,
      );
}
