import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/application_session_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/application_projection_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';

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
    final aliceSessions =
        await aliceRuntime.sessionsForRemoteIdentity(bob.publicIdentity);
    final bobSessions =
        await bobRuntime.sessionsForRemoteIdentity(alice.publicIdentity);
    expect(aliceSessions, hasLength(1));
    expect(bobSessions, hasLength(1));
    expect(aliceSessions.single.mode, V3HandshakeMode.normal);
    expect(
        aliceSessions.single.remoteDeviceId, bobSessions.single.localDeviceId);

    // Normal mode may start another independent device session. Moving an
    // existing contact to Maximum requires explicit session reset/rekey.
    final additionalDeviceOffer = await aliceRuntime.createOffer(
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    expect(additionalDeviceOffer.handshakeId, isNot(offer.handshakeId));
    final bobSecondBackend = _InitialSckaBackend();
    final bobSecondRuntime = await V3ApplicationSessionRuntime.open(
      localIdentity: bob,
      scopeToken: 'bob2-v3-scope000',
      sckaBackend: bobSecondBackend,
    );
    final secondReply = await bobSecondRuntime.receiveOffer(
      frames: additionalDeviceOffer.frames,
      initiatorIdentity: alice.publicIdentity,
      expectedMode: V3HandshakeMode.normal,
    );
    final secondConfirmation = await aliceRuntime.receiveReply(
      frames: secondReply.frames,
      responderIdentity: bob.publicIdentity,
    );
    await bobSecondRuntime.receiveConfirmation(
      frames: secondConfirmation.frames,
      initiatorIdentity: alice.publicIdentity,
    );
    final twoDeviceSessions =
        await aliceRuntime.sessionsForRemoteIdentity(bob.publicIdentity);
    expect(twoDeviceSessions, hasLength(2));
    expect(
      twoDeviceSessions.map((session) => session.remoteDeviceId).toSet(),
      hasLength(2),
    );
    await expectLater(
      aliceRuntime.createOffer(
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.maximum,
      ),
      throwsA(anything),
    );

    final messageExport = await aliceRuntime.sendApplicationMessageToIdentity(
      remoteIdentity: bob.publicIdentity,
      expectedMode: V3HandshakeMode.normal,
      text: 'hello two devices',
      timestampUnixSeconds: 2000000000,
      deleteAfterRead: true,
      backupExcluded: true,
    );
    expect(messageExport.targets, hasLength(2));
    expect(messageExport.frames, isNotEmpty);
    expect(
      messageExport.textParts,
      everyElement(
        hasLength(
          lessThanOrEqualTo(V3LmfFrameCodec.portableShareCharacterLimit),
        ),
      ),
    );
    await aliceRuntime.markMessageExported(messageExport);

    V3ApplicationMessageInboundResult? firstDeviceDelivery;
    V3ApplicationMessageInboundResult? secondDeviceDelivery;
    var firstDeviceIgnored = 0;
    var secondDeviceIgnored = 0;
    final firstStatuses = <V3ApplicationInboundStatus>[];
    final secondStatuses = <V3ApplicationInboundStatus>[];
    for (final frame in messageExport.frames.reversed) {
      final first = await bobRuntime.receiveApplicationFrame(
        frame: frame,
        nowUnixSeconds: 2000000001,
      );
      firstStatuses.add(first.status);
      if (first.status == V3ApplicationInboundStatus.notForThisInstallation) {
        firstDeviceIgnored++;
      } else if (first.status == V3ApplicationInboundStatus.delivered) {
        firstDeviceDelivery = first;
      }
      final second = await bobSecondRuntime.receiveApplicationFrame(
        frame: frame,
        nowUnixSeconds: 2000000001,
      );
      secondStatuses.add(second.status);
      if (second.status == V3ApplicationInboundStatus.notForThisInstallation) {
        secondDeviceIgnored++;
      } else if (second.status == V3ApplicationInboundStatus.delivered) {
        secondDeviceDelivery = second;
      }
    }
    expect(firstDeviceIgnored, greaterThan(0));
    expect(secondDeviceIgnored, greaterThan(0));
    expect(firstDeviceDelivery, isNotNull, reason: '$firstStatuses');
    expect(secondDeviceDelivery, isNotNull, reason: '$secondStatuses');
    expect(firstDeviceDelivery?.payload?.text, 'hello two devices');
    expect(secondDeviceDelivery?.payload?.text, 'hello two devices');
    expect(firstDeviceDelivery?.payload?.deleteAfterRead, isTrue);
    expect(firstDeviceDelivery?.payload?.backupExcluded, isTrue);
    expect(
      firstDeviceDelivery?.payload?.stableMessageId,
      secondDeviceDelivery?.payload?.stableMessageId,
    );
    expect(firstDeviceDelivery?.acknowledgementFrame, isNotNull);
    expect(secondDeviceDelivery?.acknowledgementFrame, isNotNull);

    expect(
      await aliceRuntime.receiveApplicationCarrier(
        carrier: firstDeviceDelivery!.acknowledgementText!,
      ),
      isA<V3ApplicationMessageInboundResult>().having(
        (result) => result.status,
        'status',
        V3ApplicationInboundStatus.acknowledgementApplied,
      ),
    );
    final afterFirstAck = await aliceRuntime.pendingMessageExports();
    expect(afterFirstAck, hasLength(1));
    expect(afterFirstAck.single.frames, isNotEmpty);
    expect(
      await aliceRuntime.receiveApplicationCarrier(
        carrier: secondDeviceDelivery!.acknowledgementLink!,
      ),
      isA<V3ApplicationMessageInboundResult>().having(
        (result) => result.status,
        'status',
        V3ApplicationInboundStatus.acknowledgementApplied,
      ),
    );
    expect(await aliceRuntime.pendingMessageExports(), isEmpty);
    final firstDeviceAck = firstDeviceDelivery.acknowledgementFrame!;
    await bobSecondRuntime.close();

    final aliceMessages = MessagesRepository();
    await aliceMessages.setActiveContext(
      scopeToken: aliceScope,
      storageKey: SecretKey(_testBytes(32, 0x91)),
    );
    final firstProjection = await aliceRuntime.reconcileMessageRepository(
      messagesRepository: aliceMessages,
      keyTag: 'primary-test',
      nowUnixSeconds: 2000000001,
    );
    expect(firstProjection.insertedMessages, 1);
    expect(firstProjection.exactDeviceDuplicates, 1);
    final projected = (await aliceMessages.getAllMessages()).single;
    expect(projected.isV3Encrypted, isTrue);
    expect(projected.text, isNull);
    expect(
      await aliceRuntime.loadProjectedPlaintext(
        messagesRepository: aliceMessages,
        messageRecordId: projected.id,
        keyTag: 'primary-test',
      ),
      'hello two devices',
    );
    final readProjection = await aliceRuntime.markProjectedMessageRead(
      messagesRepository: aliceMessages,
      messageRecordId: projected.id,
      keyTag: 'primary-test',
      readAt: DateTime.fromMillisecondsSinceEpoch(
        2000000100 * 1000,
        isUtc: true,
      ),
    );
    expect(readProjection.updatedMessages, 1);
    expect(
      (await aliceMessages.getAllMessages()).single.readAt,
      2000000100,
    );

    final aliceSessionId = establishedConfirmation.session!.sessionIdBytes;
    final bobSessionId = establishedResponder.sessionIdBytes;
    final aliceSnapshot = await aliceRuntime.snapshotForSession(aliceSessionId);
    final bobSnapshot = await bobRuntime.snapshotForSession(bobSessionId);
    try {
      expect(aliceSnapshot.revision, 1);
      expect(bobSnapshot.revision, 1);
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
      everyElement(1),
    );
    expect(aliceRuntime.restoreResult.sessions.sessionRevisions, hasLength(2));
    expect(
      bobRuntime.restoreResult.sessions.sessionRevisions.values,
      <int>[1],
    );
    final pendingMessageExports = await aliceRuntime.pendingMessageExports();
    expect(pendingMessageExports, isEmpty);
    final restoredProjection = await aliceRuntime.reconcileMessageRepository(
      messagesRepository: aliceMessages,
      keyTag: 'primary-test',
      nowUnixSeconds: 2000000002,
    );
    expect(restoredProjection.insertedMessages, 0);
    expect(restoredProjection.alreadyProjectedMessages, 1);
    expect(
      (await aliceMessages.getAllMessages()).single.readAt,
      2000000100,
    );
    final pendingAcks = await bobRuntime.pendingAcknowledgementFrames();
    expect(pendingAcks, hasLength(1));
    _expectExactFrames(
      <V3LmfFrame>[firstDeviceAck],
      pendingAcks,
    );

    final replay = await bobRuntime.receiveApplicationFrame(
      frame: messageExport.targets
          .singleWhere(
            (target) => target.sessionId == establishedResponder.sessionId,
          )
          .frames
          .first,
      nowUnixSeconds: 2000000002,
    );
    expect(replay.status, V3ApplicationInboundStatus.committedReplay);
    _expectExactFrames(
      <V3LmfFrame>[firstDeviceAck],
      <V3LmfFrame>[replay.acknowledgementFrame!],
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

    final deletedProjection = await aliceRuntime.deleteProjectedMessage(
      messagesRepository: aliceMessages,
      messageRecordId: projected.id,
      keyTag: 'primary-test',
      deletedAt: DateTime.fromMillisecondsSinceEpoch(
        2000000200 * 1000,
        isUtc: true,
      ),
    );
    expect(deletedProjection.removedMessages, 1);
    expect(await aliceMessages.getAllMessages(), isEmpty);
    expect(
      await aliceRuntime.reconcileMessageRepository(
        messagesRepository: aliceMessages,
        keyTag: 'primary-test',
        nowUnixSeconds: 2000000201,
      ),
      isA<V3ApplicationProjectionResult>().having(
        (result) => result.insertedMessages,
        'insertedMessages',
        0,
      ),
    );
    expect(
      await aliceRuntime.loadProjectedPlaintext(
        messagesRepository: aliceMessages,
        messageRecordId: projected.id,
        keyTag: 'primary-test',
      ),
      isNull,
    );

    aliceDeviceId.fillRange(0, aliceDeviceId.length, 0);
    bobDeviceId.fillRange(0, bobDeviceId.length, 0);
    aliceMessages.dispose();
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
      final retry = await aliceRuntime.createOffer(
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.maximum,
      );
      expect(retry.handshakeId, offer.handshakeId);
      _expectExactFrames(retry.frames, offer.frames);
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
      _state(role, sessionId, 0, 0);

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    if (authenticatedState.length != 26 ||
        authenticatedState[0] != role.wireId ||
        !_constantTimeBytesEqual(
          Uint8List.sublistView(authenticatedState, 1, 17),
          sessionId,
        ) ||
        ByteData.sublistView(authenticatedState).getUint64(18, Endian.big) !=
            expectedStateRevision) {
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
  }) async {
    final currentEpoch = authenticatedState[17];
    final payload = message.nativePayload;
    if (payload.length != 1 || payload.single < currentEpoch) {
      throw const FormatException('invalid test SCKA message');
    }
    final outputEpoch = payload.single;
    return V3SckaReceiveCandidate(
      nextAuthenticatedState:
          _state(role, sessionId, outputEpoch, expectedStateRevision + 1),
      stateRevision: expectedStateRevision + 1,
      receivingEpoch: message.sendingEpoch,
      epochSecret: outputEpoch == currentEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _epochSecret(sessionId, outputEpoch),
            ),
    );
  }

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    final currentEpoch = authenticatedState[17];
    final outputEpoch = currentEpoch == 0 ? 1 : currentEpoch;
    return V3SckaSendCandidate(
      nextAuthenticatedState:
          _state(role, sessionId, outputEpoch, expectedStateRevision + 1),
      stateRevision: expectedStateRevision + 1,
      sendingEpoch: currentEpoch,
      nativePayload: Uint8List.fromList(<int>[outputEpoch]),
      epochSecret: currentEpoch == outputEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _epochSecret(sessionId, outputEpoch),
            ),
    );
  }

  static Uint8List _state(
    V3SessionRole role,
    Uint8List sessionId,
    int epoch,
    int revision,
  ) {
    final result = Uint8List.fromList(<int>[
      role.wireId,
      ...sessionId,
      epoch,
      ...List<int>.filled(8, 0),
    ]);
    ByteData.sublistView(result).setUint64(18, revision, Endian.big);
    return result;
  }

  static Uint8List _epochSecret(Uint8List sessionId, int epoch) =>
      Uint8List.fromList(
        sha256.convert(<int>[0x53, ...sessionId, epoch]).bytes,
      );
}

bool _constantTimeBytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

Uint8List _testBytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
