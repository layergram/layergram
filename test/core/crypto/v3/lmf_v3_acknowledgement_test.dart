import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_acknowledgement.dart';

void main() {
  test('canonical ACK golden vector round-trips cumulative fragment bitmap',
      () {
    final acknowledgement = V3LmfAcknowledgement(
      targetSuite: V3LmfSuite.hybridX25519MlKem768Aes256Gcm,
      targetKind: V3LmfFrameKind.handshake,
      targetMessageId: _bytes(V3LmfFrameCodec.messageIdBytes, 0x81),
      targetEpoch: 7,
      targetMessageCounter: 9,
      targetAssembledPlaintextLength: 1088,
      targetFragmentCount: 5,
      receivedFragmentIndexes: const <int>{0, 2, 4},
    );

    final encoded = V3LmfAcknowledgementCodec.encode(acknowledgement);
    expect(encoded, hasLength(48));
    expect(
      _hex(encoded),
      '414b3301010100058182838485868788898a8b8c8d8e8f90'
      '000000070000000000000009000004401500000000000000',
    );

    final decoded = V3LmfAcknowledgementCodec.decode(encoded);
    expect(decoded.targetMessageId,
        orderedEquals(acknowledgement.targetMessageId));
    expect(decoded.targetEpoch, 7);
    expect(decoded.targetMessageCounter, 9);
    expect(decoded.targetAssembledPlaintextLength, 1088);
    expect(decoded.targetFragmentCount, 5);
    expect(decoded.receivedFragmentIndexes, <int>{0, 2, 4});
    expect(decoded.isComplete, isFalse);
  });

  test('complete ACK covers every fragment and ACK loops are forbidden', () {
    final complete = V3LmfAcknowledgement(
      targetSuite: V3LmfSuite.hybridX25519MlKem768Aes256Gcm,
      targetKind: V3LmfFrameKind.application,
      targetMessageId: _bytes(V3LmfFrameCodec.messageIdBytes, 1),
      targetEpoch: 1,
      targetMessageCounter: 2,
      targetAssembledPlaintextLength: 512,
      targetFragmentCount: 2,
      receivedFragmentIndexes: const <int>{0, 1},
    );
    expect(complete.isComplete, isTrue);

    expect(
      () => V3LmfAcknowledgement(
        targetSuite: V3LmfSuite.hybridX25519MlKem768Aes256Gcm,
        targetKind: V3LmfFrameKind.application,
        targetMessageId: _bytes(V3LmfFrameCodec.messageIdBytes, 1),
        targetEpoch: 1,
        targetMessageCounter: 2,
        targetAssembledPlaintextLength: 512,
        targetFragmentCount: 3,
        receivedFragmentIndexes: const <int>{0},
      ),
      throwsArgumentError,
    );

    expect(
      () => V3LmfAcknowledgement(
        targetSuite: V3LmfSuite.hybridX25519MlKem768Aes256Gcm,
        targetKind: V3LmfFrameKind.acknowledgement,
        targetMessageId: _bytes(V3LmfFrameCodec.messageIdBytes, 1),
        targetEpoch: 1,
        targetMessageCounter: 2,
        targetAssembledPlaintextLength: 48,
        targetFragmentCount: 1,
        receivedFragmentIndexes: const <int>{0},
      ),
      throwsArgumentError,
    );
  });

  test('strict decoder rejects malformed ACKs and unused bitmap bits', () {
    final valid = V3LmfAcknowledgementCodec.encode(
      V3LmfAcknowledgement(
        targetSuite: V3LmfSuite.hybridX25519MlKem768Aes256Gcm,
        targetKind: V3LmfFrameKind.handshake,
        targetMessageId: _bytes(V3LmfFrameCodec.messageIdBytes, 1),
        targetEpoch: 1,
        targetMessageCounter: 2,
        targetAssembledPlaintextLength: 300,
        targetFragmentCount: 2,
        receivedFragmentIndexes: const <int>{0},
      ),
    );

    for (final changed in <Uint8List>[
      Uint8List.fromList(valid)..[0] = 0,
      Uint8List.fromList(valid)..[3] = 2,
      Uint8List.fromList(valid)..[4] = 0xff,
      Uint8List.fromList(valid)..[5] = V3LmfFrameKind.acknowledgement.wireId,
      Uint8List.fromList(valid)..[6] = 1,
      Uint8List.fromList(valid)..[7] = 0,
      Uint8List.fromList(valid)..fillRange(40, 48, 0),
      Uint8List.fromList(valid)..[40] |= 1 << 2,
      Uint8List.fromList(valid.sublist(0, 47)),
      Uint8List.fromList(<int>[...valid, 0]),
    ]) {
      expect(
        () => V3LmfAcknowledgementCodec.decode(changed),
        throwsFormatException,
      );
    }
  });

  test('forReceivedFrames rejects mixed messages and deduplicates indexes', () {
    final first = _frame(fragmentIndex: 0);
    final second = _frame(fragmentIndex: 1);
    final acknowledgement = V3LmfAcknowledgementCodec.forReceivedFrames(
      <V3LmfFrame>[second, first, first],
    );
    expect(acknowledgement.receivedFragmentIndexes, <int>{0, 1});
    expect(acknowledgement.isComplete, isTrue);

    expect(
      () => V3LmfAcknowledgementCodec.forReceivedFrames(<V3LmfFrame>[]),
      throwsArgumentError,
    );
    expect(
      () => V3LmfAcknowledgementCodec.forReceivedFrames(<V3LmfFrame>[
        first,
        _frame(fragmentIndex: 1, messageStart: 0x91),
      ]),
      throwsArgumentError,
    );
    expect(
      () => V3LmfAcknowledgementCodec.forReceivedFrames(<V3LmfFrame>[
        first,
        _frame(fragmentIndex: 1, expiresAtUnixSeconds: 2000000000),
      ]),
      throwsArgumentError,
    );
  });

  test('forReceivedFrames bounds the total iterable before deduplication', () {
    var generated = 0;
    final repeated = Iterable<V3LmfFrame>.generate(
      V3LmfFrameCodec.maxFragments + 100,
      (_) {
        generated++;
        return _frame(fragmentIndex: 0);
      },
    );

    expect(
      () => V3LmfAcknowledgementCodec.forReceivedFrames(repeated),
      throwsArgumentError,
    );
    expect(generated, V3LmfFrameCodec.maxFragments + 1);
  });
}

V3LmfFrame _frame({
  required int fragmentIndex,
  int messageStart = 0x81,
  int expiresAtUnixSeconds = 0,
}) {
  return V3LmfFrame(
    metadata: V3LmfMessageMetadata(
      kind: V3LmfFrameKind.handshake,
      senderBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 1),
      recipientBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x41),
      messageId: _bytes(V3LmfFrameCodec.messageIdBytes, messageStart),
      sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
      epoch: 7,
      messageCounter: 9,
      expiresAtUnixSeconds: expiresAtUnixSeconds,
    ),
    fragmentIndex: fragmentIndex,
    fragmentCount: 2,
    assembledPlaintextLength: 512,
    nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0xc0 + fragmentIndex),
    ciphertext: _bytes(V3LmfFrameCodec.fragmentPlaintextBytes, fragmentIndex),
    authenticationTag:
        _bytes(V3LmfFrameCodec.authenticationTagBytes, 0xe0 + fragmentIndex),
  );
}

Uint8List _bytes(int length, int start) {
  return Uint8List.fromList(
    List<int>.generate(length, (index) => (start + index) & 0xff),
  );
}

String _hex(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
