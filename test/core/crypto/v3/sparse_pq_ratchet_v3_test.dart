import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';

void main() {
  group('protocol v3 SCKA public envelope', () {
    test('freezes a canonical 64-bit epoch and counter vector', () {
      final message = V3SckaMessage(
        sendingEpoch: 0x100000007,
        messageCounter: 0x200000009,
        nativePayload: _bytes(37, 0x41),
      );
      final encoded = V3SckaMessageCodec.encode(message);
      expect(encoded, hasLength(V3SckaMessageCodec.headerBytes + 37));
      expect(
        crypto.sha256.convert(encoded).toString(),
        '70bd8a395b0cbd2a401b01d63033fa1fd5fc8407e186d35849a65aab7663f996',
      );

      final decoded = V3SckaMessageCodec.decode(encoded);
      expect(decoded.sendingEpoch, 0x100000007);
      expect(decoded.messageCounter, 0x200000009);
      expect(decoded.nativePayload, message.nativePayload);
      expect(V3SckaMessageCodec.encode(decoded), encoded);

      final detached = decoded.nativePayload..[0] ^= 1;
      expect(detached, isNot(decoded.nativePayload));
    });

    test('rejects malformed and oversized public messages', () {
      final valid = V3SckaMessageCodec.encode(
        V3SckaMessage(
          sendingEpoch: 7,
          messageCounter: 9,
          nativePayload: _bytes(32, 0x41),
        ),
      );
      for (final changed in <Uint8List>[
        Uint8List.fromList(valid)..[0] ^= 1,
        Uint8List.fromList(valid)..[3] = 2,
        Uint8List.fromList(valid)..[4] = 0xff,
        Uint8List.fromList(valid)..[5] = 1,
        Uint8List.fromList(valid)..[7] -= 1,
        Uint8List.fromList(valid.sublist(0, valid.length - 1)),
        Uint8List.fromList(<int>[...valid, 0]),
      ]) {
        expect(() => V3SckaMessageCodec.decode(changed), throwsFormatException);
      }
      expect(
        () => V3SckaMessage(
          sendingEpoch: 1,
          messageCounter: 1,
          nativePayload:
              Uint8List(V3SckaMessageCodec.maxNativePayloadBytes + 1),
        ),
        throwsArgumentError,
      );
    });

    test('bounded hostile inputs never escape parser errors', () {
      final random = Random(0x534b33);
      for (var iteration = 0; iteration < 500; iteration++) {
        final length = random.nextInt(V3SckaMessageCodec.maxEncodedBytes + 32);
        final encoded = Uint8List.fromList(
          List<int>.generate(length, (_) => random.nextInt(256)),
        );
        try {
          V3SckaMessageCodec.decode(encoded);
        } on FormatException {
          continue;
        } catch (error) {
          fail('SCKA parser leaked ${error.runtimeType} at length $length');
        }
      }
    });
  });

  group('protocol v3 hybrid ratchet header', () {
    test('binds exact EC and SCKA encodings in one canonical vector', () {
      final header = _hybridHeader();
      final encoded = V3HybridRatchetHeaderCodec.encode(header);
      expect(
        crypto.sha256.convert(encoded).toString(),
        '54fc93aab31dced914eea2edae46834bdeb043f1e00df97c6aa6a09773ef2e82',
      );
      final decoded = V3HybridRatchetHeaderCodec.decode(encoded);
      expect(
          decoded.ecHeader.ratchetPublicKey, header.ecHeader.ratchetPublicKey);
      expect(decoded.ecHeader.previousSendingChainLength, 7);
      expect(decoded.ecHeader.messageCounter, 9);
      expect(decoded.sckaMessage.sendingEpoch, 11);
      expect(decoded.sckaMessage.messageCounter, 13);
      expect(decoded.sckaMessage.nativePayload, _bytes(32, 0x61));
      expect(V3HybridRatchetHeaderCodec.encode(decoded), encoded);
    });

    test('rejects outer and nested length or format changes', () {
      final valid = V3HybridRatchetHeaderCodec.encode(_hybridHeader());
      for (final changed in <Uint8List>[
        Uint8List.fromList(valid)..[0] ^= 1,
        Uint8List.fromList(valid)..[3] = 2,
        Uint8List.fromList(valid)..[4] = 0xff,
        Uint8List.fromList(valid)..[5] = 1,
        Uint8List.fromList(valid)..[7] -= 1,
        Uint8List.fromList(valid)..[9] -= 1,
        Uint8List.fromList(valid)..[11] -= 1,
        Uint8List.fromList(valid)..[13] -= 1,
        Uint8List.fromList(valid)..[15] = 1,
        Uint8List.fromList(valid)
          ..[V3HybridRatchetHeaderCodec.headerBytes] ^= 1,
        Uint8List.fromList(valid.sublist(0, valid.length - 1)),
        Uint8List.fromList(<int>[...valid, 0]),
      ]) {
        expect(
          () => V3HybridRatchetHeaderCodec.decode(changed),
          throwsFormatException,
        );
      }
    });
  });

  group('protocol v3 SCKA backend boundary', () {
    test('copies inputs and returns non-mutating validated candidates',
        () async {
      final backend = _DeterministicTestSckaBackend();
      final sessionId = _bytes(16, 0x11);
      final sharedSecret = _bytes(32, 0x31);
      final stateSealKey = _bytes(32, 0x71);
      final originalSession = Uint8List.fromList(sessionId);
      final originalSecret = Uint8List.fromList(sharedSecret);
      final originalStateSealKey = Uint8List.fromList(stateSealKey);

      final state = await V3SparsePqRatchet.initialize(
        backend: backend,
        role: V3SessionRole.initiator,
        sessionId: sessionId,
        sharedSecret: sharedSecret,
        stateSealKey: stateSealKey,
      );
      expect(sessionId, originalSession);
      expect(sharedSecret, originalSecret);
      expect(stateSealKey, originalStateSealKey);
      final originalState = Uint8List.fromList(state);

      await V3SparsePqRatchet.validateAuthenticatedState(
        backend: backend,
        role: V3SessionRole.initiator,
        sessionId: sessionId,
        authenticatedState: state,
        stateSealKey: stateSealKey,
        expectedStateRevision: 0,
      );

      final sent = await V3SparsePqRatchet.sendCandidate(
        backend: backend,
        role: V3SessionRole.initiator,
        sessionId: sessionId,
        authenticatedState: state,
        stateSealKey: stateSealKey,
        expectedStateRevision: 0,
      );
      expect(state, originalState);
      final sentMessage = sent.messageForCounter(0x100000009);
      expect(sentMessage.sendingEpoch, 7);
      expect(sentMessage.messageCounter, 0x100000009);
      expect(sent.epochSecret?.epoch, 7);
      expect(sent.nextAuthenticatedState, isNot(originalState));
      expect(sent.stateRevision, 1);

      final received = await V3SparsePqRatchet.receiveCandidate(
        backend: backend,
        role: V3SessionRole.initiator,
        sessionId: sessionId,
        authenticatedState: state,
        stateSealKey: stateSealKey,
        expectedStateRevision: 0,
        message: sentMessage,
      );
      expect(state, originalState);
      expect(received.receivingEpoch, 7);
      expect(received.stateRevision, 1);
      expect(received.epochSecret?.epoch, 7);

      final sentState = sent.nextAuthenticatedState..[18] ^= 1;
      expect(sentState, isNot(sent.nextAuthenticatedState));
      sent.close();
      received.close();
      expect(sent.isClosed, isTrue);
      expect(received.isClosed, isTrue);
      expect(() => sent.nextAuthenticatedState, throwsStateError);
      expect(() => received.nextAuthenticatedState, throwsStateError);
      expect(() => sent.epochSecret?.secret, throwsStateError);
      expect(() => received.epochSecret?.secret, throwsStateError);
      expect(backend.selfTestCalls, 4);
    });

    test('backend self-test failure stops before state initialization',
        () async {
      final backend = _DeterministicTestSckaBackend(selfTestResult: false);
      await expectLater(
        V3SparsePqRatchet.initialize(
          backend: backend,
          role: V3SessionRole.initiator,
          sessionId: _bytes(16, 0x11),
          sharedSecret: _bytes(32, 0x31),
          stateSealKey: _bytes(32, 0x71),
        ),
        throwsStateError,
      );
      expect(backend.selfTestCalls, 1);
      expect(backend.initializeCalls, 0);
    });

    test('unknown protocol revision stops before backend self-test', () async {
      final backend = _DeterministicTestSckaBackend(
        testProtocolRevision:
            V3SparsePqRatchet.requiredBackendProtocolRevision + 1,
      );
      await expectLater(
        V3SparsePqRatchet.initialize(
          backend: backend,
          role: V3SessionRole.initiator,
          sessionId: _bytes(16, 0x11),
          sharedSecret: _bytes(32, 0x31),
          stateSealKey: _bytes(32, 0x71),
        ),
        throwsStateError,
      );
      expect(backend.selfTestCalls, 0);
      expect(backend.initializeCalls, 0);
    });

    test('non-canonical implementation ID stops before backend self-test',
        () async {
      final backend = _DeterministicTestSckaBackend(
        testImplementationId: 'Signal SPQR/1.5.3',
      );
      await expectLater(
        V3SparsePqRatchet.initialize(
          backend: backend,
          role: V3SessionRole.initiator,
          sessionId: _bytes(16, 0x11),
          sharedSecret: _bytes(32, 0x31),
          stateSealKey: _bytes(32, 0x71),
        ),
        throwsStateError,
      );
      expect(backend.selfTestCalls, 0);
      expect(backend.initializeCalls, 0);
    });

    test('fails closed when backend returns an unbound candidate', () async {
      final backend = _DeterministicTestSckaBackend(corruptNextState: true);
      final sessionId = _bytes(16, 0x11);
      final state = await V3SparsePqRatchet.initialize(
        backend: backend,
        role: V3SessionRole.responder,
        sessionId: sessionId,
        sharedSecret: _bytes(32, 0x31),
        stateSealKey: _bytes(32, 0x71),
      );
      await expectLater(
        V3SparsePqRatchet.sendCandidate(
          backend: backend,
          role: V3SessionRole.responder,
          sessionId: sessionId,
          authenticatedState: state,
          stateSealKey: _bytes(32, 0x71),
          expectedStateRevision: 0,
        ),
        throwsFormatException,
      );
    });

    test('fails closed when backend changes the received epoch', () async {
      final backend = _DeterministicTestSckaBackend(
        changeReceivingEpoch: true,
      );
      final sessionId = _bytes(16, 0x11);
      final state = await V3SparsePqRatchet.initialize(
        backend: backend,
        role: V3SessionRole.responder,
        sessionId: sessionId,
        sharedSecret: _bytes(32, 0x31),
        stateSealKey: _bytes(32, 0x71),
      );
      await expectLater(
        V3SparsePqRatchet.receiveCandidate(
          backend: backend,
          role: V3SessionRole.responder,
          sessionId: sessionId,
          authenticatedState: state,
          stateSealKey: _bytes(32, 0x71),
          expectedStateRevision: 0,
          message: V3SckaMessage(
            sendingEpoch: 7,
            messageCounter: 9,
            nativePayload: _bytes(32, 0x61),
          ),
        ),
        throwsStateError,
      );
    });

    test('binds the state seal key and exact native revision', () async {
      final backend = _DeterministicTestSckaBackend();
      final sessionId = _bytes(16, 0x11);
      final stateSealKey = _bytes(32, 0x71);
      final state = await V3SparsePqRatchet.initialize(
        backend: backend,
        role: V3SessionRole.initiator,
        sessionId: sessionId,
        sharedSecret: _bytes(32, 0x31),
        stateSealKey: stateSealKey,
      );

      await expectLater(
        V3SparsePqRatchet.validateAuthenticatedState(
          backend: backend,
          role: V3SessionRole.initiator,
          sessionId: sessionId,
          authenticatedState: state,
          stateSealKey: Uint8List.fromList(stateSealKey)..[0] ^= 1,
          expectedStateRevision: 0,
        ),
        throwsFormatException,
      );
      await expectLater(
        V3SparsePqRatchet.validateAuthenticatedState(
          backend: backend,
          role: V3SessionRole.initiator,
          sessionId: sessionId,
          authenticatedState: state,
          stateSealKey: stateSealKey,
          expectedStateRevision: 1,
        ),
        throwsFormatException,
      );
      await expectLater(
        V3SparsePqRatchet.sendCandidate(
          backend: _DeterministicTestSckaBackend(
            changeCandidateRevision: true,
          ),
          role: V3SessionRole.initiator,
          sessionId: sessionId,
          authenticatedState: state,
          stateSealKey: stateSealKey,
          expectedStateRevision: 0,
        ),
        throwsStateError,
      );
    });
  });
}

V3HybridRatchetHeader _hybridHeader() => V3HybridRatchetHeader(
      ecHeader: V3EcRatchetHeader(
        ratchetPublicKey: _bytes(32, 0x21),
        previousSendingChainLength: 7,
        messageCounter: 9,
      ),
      sckaMessage: V3SckaMessage(
        sendingEpoch: 11,
        messageCounter: 13,
        nativePayload: _bytes(32, 0x61),
      ),
    );

final class _DeterministicTestSckaBackend implements V3SckaBackend {
  _DeterministicTestSckaBackend({
    this.corruptNextState = false,
    this.changeReceivingEpoch = false,
    this.changeCandidateRevision = false,
    this.selfTestResult = true,
    this.testImplementationId = 'layergram-test-scka/1',
    this.testProtocolRevision =
        V3SparsePqRatchet.requiredBackendProtocolRevision,
  });

  final bool corruptNextState;
  final bool changeReceivingEpoch;
  final bool changeCandidateRevision;
  final bool selfTestResult;
  final String testImplementationId;
  final int testProtocolRevision;
  int initializeCalls = 0;
  int selfTestCalls = 0;

  @override
  String get implementationId => testImplementationId;

  @override
  int get protocolRevision => testProtocolRevision;

  @override
  Future<bool> selfTest() async {
    selfTestCalls++;
    return selfTestResult;
  }

  @override
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
    required Uint8List stateSealKey,
  }) async {
    initializeCalls++;
    final digest = crypto.sha256.convert(<int>[
      role.wireId,
      ...sessionId,
      ...sharedSecret,
      ...stateSealKey,
    ]).bytes;
    final result = _state(
      role: role,
      sessionId: sessionId,
      stateSealKey: stateSealKey,
      revision: 0,
      payloadDigest: digest,
    );
    sharedSecret[0] ^= 1;
    stateSealKey[0] ^= 1;
    return result;
  }

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    final stateSealKeyDigest = _digest(stateSealKey);
    final data = ByteData.sublistView(authenticatedState);
    if (authenticatedState.length != 89 ||
        authenticatedState[0] != role.wireId ||
        !_bytesEqual(
          Uint8List.sublistView(authenticatedState, 1, 17),
          sessionId,
        ) ||
        data.getUint64(17, Endian.big) != expectedStateRevision ||
        !_bytesEqual(
          Uint8List.sublistView(authenticatedState, 25, 57),
          stateSealKeyDigest,
        )) {
      throw const FormatException('Test SCKA state binding mismatch');
    }
  }

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    authenticatedState[18] ^= 1;
    final next = _nextState(
      authenticatedState,
      stateSealKey,
      expectedStateRevision + 1,
      0x53,
    );
    if (corruptNextState) next[0] ^= 1;
    return V3SckaSendCandidate(
      nextAuthenticatedState: next,
      stateRevision: expectedStateRevision + (changeCandidateRevision ? 2 : 1),
      sendingEpoch: 7,
      nativePayload: _bytes(32, 0x61),
      epochSecret: V3SckaEpochSecret(
        epoch: 7,
        secret: _digest(<int>[...authenticatedState, 0x6b]),
      ),
    );
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
    authenticatedState[18] ^= 1;
    return V3SckaReceiveCandidate(
      nextAuthenticatedState: _nextState(
        authenticatedState,
        stateSealKey,
        expectedStateRevision + 1,
        0x52,
      ),
      stateRevision: expectedStateRevision + (changeCandidateRevision ? 2 : 1),
      receivingEpoch: changeReceivingEpoch
          ? message.sendingEpoch + 1
          : message.sendingEpoch,
      epochSecret: V3SckaEpochSecret(
        epoch: changeReceivingEpoch
            ? message.sendingEpoch + 1
            : message.sendingEpoch,
        secret: _digest(<int>[...authenticatedState, 0x72]),
      ),
    );
  }

  Uint8List _nextState(
    Uint8List state,
    Uint8List stateSealKey,
    int revision,
    int marker,
  ) =>
      _state(
        role: V3SessionRole.fromWireId(state[0]),
        sessionId: Uint8List.sublistView(state, 1, 17),
        stateSealKey: stateSealKey,
        revision: revision,
        payloadDigest: _digest(<int>[...state, marker]),
      );

  Uint8List _state({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List stateSealKey,
    required int revision,
    required List<int> payloadDigest,
  }) {
    final result = Uint8List(89);
    result[0] = role.wireId;
    result.setRange(1, 17, sessionId);
    ByteData.sublistView(result).setUint64(17, revision, Endian.big);
    result.setRange(25, 57, _digest(stateSealKey));
    result.setRange(57, 89, payloadDigest);
    return result;
  }
}

Uint8List _digest(List<int> value) =>
    Uint8List.fromList(crypto.sha256.convert(value).bytes);

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
