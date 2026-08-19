import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/application_session_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  const aliceMnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const bobMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
  const aliceScope = 'alice-v3-scope01';
  const bobScope = 'bob-v3-scope0000';

  late Directory temporaryDirectory;
  late Box<Map> box;
  late V3LocalIdentityHandle alice;
  late V3LocalIdentityHandle bob;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    temporaryDirectory =
        await Directory.systemTemp.createTemp('layergram_v3_app_runtime_');
    Hive.init(temporaryDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    box = Hive.box<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await temporaryDirectory.delete(recursive: true);
  });

  setUp(() async {
    await box.clear();
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: _HandshakeMlKemBackend(),
    );
    alice = await factory.restorePrimary(mnemonic: aliceMnemonic);
    bob = await factory.restorePrimary(mnemonic: bobMnemonic);
  });

  tearDown(() async {
    await alice.close();
    await bob.close();
  });

  test('durable handshake establishes and restores both application sessions',
      () async {
    final aliceBackend = _InitialSckaBackend();
    final bobBackend = _InitialSckaBackend();
    var aliceRuntime = await V3ApplicationSessionRuntime.open(
      localIdentity: alice,
      scopeToken: aliceScope,
      sckaBackend: aliceBackend,
    );
    var bobRuntime = await V3ApplicationSessionRuntime.open(
      localIdentity: bob,
      scopeToken: bobScope,
      sckaBackend: bobBackend,
    );

    final aliceDeviceId = aliceRuntime.localDeviceId;
    final bobDeviceId = bobRuntime.localDeviceId;
    final offer = await aliceRuntime.createOffer(
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    final offerRetry = await aliceRuntime.retryHandshake(
      handshakeId: offer.handshakeId,
      remoteIdentity: bob.publicIdentity,
    );
    expect(offerRetry, isNotNull);
    _expectExactFrames(offer.frames, offerRetry!.frames);

    // Receive half an offer, restart, then finish it out of order.
    for (final frame in offer.frames.skip(3)) {
      final partial = await bobRuntime.receiveHandshakeFrame(
        frame: frame,
        remoteIdentity: alice.publicIdentity,
        expectedMode: V3HandshakeMode.normal,
      );
      expect(partial.isComplete, isFalse);
    }
    await bobRuntime.close();
    bobRuntime = await V3ApplicationSessionRuntime.open(
      localIdentity: bob,
      scopeToken: bobScope,
      sckaBackend: bobBackend,
    );
    expect(bobRuntime.restoreResult.handshakeInbox.deferredFrames, 3);
    V3ApplicationHandshakeExport? reply;
    for (final frame in offer.frames.take(3).toList().reversed) {
      final accepted = await bobRuntime.receiveHandshakeFrame(
        frame: frame,
        remoteIdentity: alice.publicIdentity,
        expectedMode: V3HandshakeMode.normal,
      );
      reply ??= accepted.outbound;
    }
    expect(reply, isNotNull);

    V3ApplicationHandshakeExport? confirmation;
    for (final frame in reply!.frames.reversed) {
      final accepted = await aliceRuntime.receiveHandshakeFrame(
        frame: frame,
        remoteIdentity: bob.publicIdentity,
        expectedMode: V3HandshakeMode.normal,
      );
      confirmation ??= accepted.outbound;
    }
    expect(confirmation, isNotNull);
    final establishedConfirmation = confirmation!;
    expect(establishedConfirmation.session, isNotNull);
    expect(
      establishedConfirmation.session!.role,
      V3SessionRole.initiator,
    );

    V3ApplicationSessionBinding? responderSession;
    for (final frame in establishedConfirmation.frames.reversed) {
      final accepted = await bobRuntime.receiveHandshakeFrame(
        frame: frame,
        remoteIdentity: alice.publicIdentity,
        expectedMode: V3HandshakeMode.normal,
      );
      responderSession ??= accepted.session;
    }
    expect(responderSession, isNotNull);
    final establishedResponder = responderSession!;
    expect(establishedResponder.role, V3SessionRole.responder);
    expect(
      establishedResponder.sessionId,
      establishedConfirmation.session!.sessionId,
    );

    final aliceSessionId = establishedConfirmation.session!.sessionIdBytes;
    final bobSessionId = establishedResponder.sessionIdBytes;
    final aliceSnapshot = await aliceRuntime.snapshotForSession(aliceSessionId);
    final bobSnapshot = await bobRuntime.snapshotForSession(bobSessionId);
    try {
      expect(aliceSnapshot.revision, 0);
      expect(bobSnapshot.revision, 0);
      expect(aliceSnapshot.role, V3SessionRole.initiator);
      expect(bobSnapshot.role, V3SessionRole.responder);
    } finally {
      aliceSnapshot.wipeSecrets();
      bobSnapshot.wipeSecrets();
      aliceSessionId.fillRange(0, aliceSessionId.length, 0);
      bobSessionId.fillRange(0, bobSessionId.length, 0);
    }

    await aliceRuntime.close();
    await bobRuntime.close();

    aliceRuntime = await V3ApplicationSessionRuntime.open(
      localIdentity: alice,
      scopeToken: aliceScope,
      sckaBackend: aliceBackend,
    );
    bobRuntime = await V3ApplicationSessionRuntime.open(
      localIdentity: bob,
      scopeToken: bobScope,
      sckaBackend: bobBackend,
    );
    expect(aliceRuntime.localDeviceId, orderedEquals(aliceDeviceId));
    expect(bobRuntime.localDeviceId, orderedEquals(bobDeviceId));
    expect(
      aliceRuntime.restoreResult.sessions.sessionRevisions.values,
      <int>[0],
    );
    expect(
      bobRuntime.restoreResult.sessions.sessionRevisions.values,
      <int>[0],
    );

    final confirmationRetry = await aliceRuntime.retryHandshake(
      handshakeId: offer.handshakeId,
      remoteIdentity: bob.publicIdentity,
    );
    expect(confirmationRetry, isNotNull);
    expect(
      confirmationRetry!.kind,
      V3HandshakeRecordKind.confirmation,
    );
    _expectExactFrames(
      establishedConfirmation.frames,
      confirmationRetry.frames,
    );

    // A duplicate terminal carrier delivery is idempotent after restart.
    final duplicate = await bobRuntime.receiveConfirmation(
      frames: confirmationRetry.frames,
      initiatorIdentity: alice.publicIdentity,
    );
    expect(duplicate.sessionId, establishedResponder.sessionId);
    expect(duplicate.recovered, isTrue);

    aliceDeviceId.fillRange(0, aliceDeviceId.length, 0);
    bobDeviceId.fillRange(0, bobDeviceId.length, 0);
    await aliceRuntime.close();
    await bobRuntime.close();
  });

  test('maximum-mode mismatch fails before a reply becomes exportable',
      () async {
    final aliceRuntime = await V3ApplicationSessionRuntime.open(
      localIdentity: alice,
      scopeToken: aliceScope,
      sckaBackend: _InitialSckaBackend(),
    );
    final bobRuntime = await V3ApplicationSessionRuntime.open(
      localIdentity: bob,
      scopeToken: bobScope,
      sckaBackend: _InitialSckaBackend(),
    );
    try {
      final offer = await aliceRuntime.createOffer(
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.maximum,
      );
      await expectLater(
        bobRuntime.receiveOffer(
          frames: offer.frames,
          initiatorIdentity: alice.publicIdentity,
          expectedMode: V3HandshakeMode.normal,
        ),
        throwsA(anything),
      );
      expect(
        await bobRuntime.retryHandshake(
          handshakeId: offer.handshakeId,
          remoteIdentity: alice.publicIdentity,
        ),
        isNull,
      );
    } finally {
      await aliceRuntime.close();
      await bobRuntime.close();
    }
  });
}

void _expectExactFrames(List<V3LmfFrame> left, List<V3LmfFrame> right) {
  expect(right, hasLength(left.length));
  for (var index = 0; index < left.length; index++) {
    expect(
      V3LmfFrameCodec.encodeBinary(right[index]),
      orderedEquals(V3LmfFrameCodec.encodeBinary(left[index])),
    );
  }
}

final class _MlKemPrivateKeyHandle implements MlKem768PrivateKeyHandle {
  _MlKemPrivateKeyHandle(this.publicKey);

  final Uint8List publicKey;

  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    if (isClosed) return;
    publicKey.fillRange(0, publicKey.length, 0);
    isClosed = true;
  }
}

final class _HandshakeMlKemBackend implements MlKem768Backend {
  int _encapsulationCounter = 0;

  @override
  String get implementationId => 'application-runtime-test-ml-kem';

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
      privateKeyHandle: _MlKemPrivateKeyHandle(
        Uint8List.fromList(publicKey),
      ),
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async =>
      publicKey.length == MlKem768.publicKeyBytes &&
      publicKey.any((byte) => byte != 0);

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) async {
    _encapsulationCounter++;
    final counter = Uint8List(4);
    ByteData.sublistView(counter).setUint32(0, _encapsulationCounter);
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
    if (privateKeyHandle is! _MlKemPrivateKeyHandle ||
        privateKeyHandle.isClosed ||
        ciphertext.length != MlKem768.ciphertextBytes) {
      throw StateError('invalid test ML-KEM input');
    }
    return _sharedSecret(privateKeyHandle.publicKey, ciphertext);
  }

  Uint8List _sharedSecret(Uint8List publicKey, Uint8List ciphertext) =>
      Uint8List.fromList(
        sha256.convert(<int>[
          ...'application-runtime-test-shared\x00'.codeUnits,
          ...publicKey,
          ...ciphertext,
        ]).bytes,
      );
}

final class _InitialSckaBackend implements V3SckaBackend {
  @override
  String get implementationId => 'layergram-application-runtime-test-scka/1';

  @override
  int get protocolRevision => V3SparsePqRatchet.requiredBackendProtocolRevision;

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
    required Uint8List stateSealKey,
  }) async =>
      Uint8List.fromList(
        sha256.convert(<int>[
          ...'application-runtime-test-scka\x00'.codeUnits,
          role.wireId,
          ...sessionId,
          ...sharedSecret,
          ...stateSealKey,
        ]).bytes,
      );

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    if (sessionId.length != 16 ||
        authenticatedState.length != 32 ||
        authenticatedState.every((byte) => byte == 0) ||
        expectedStateRevision != 0) {
      throw StateError('invalid test SCKA state');
    }
  }

  @override
  Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
    required V3SckaMessage message,
  }) =>
      throw UnsupportedError('not needed by application runtime handshake');

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) =>
      throw UnsupportedError('not needed by application runtime handshake');
}
