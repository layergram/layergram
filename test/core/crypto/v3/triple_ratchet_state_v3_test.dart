import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  group('protocol v3 Triple Ratchet state codec', () {
    test('publishes bounded canonical state limits', () {
      expect(V3TripleRatchetStateCodec.headerBytes, 496);
      expect(V3TripleRatchetStateCodec.pqEpochRecordBytes, 96);
      expect(V3TripleRatchetStateCodec.ecSkippedRecordBytes, 80);
      expect(V3TripleRatchetStateCodec.pqSkippedRecordBytes, 56);
      expect(V3TripleRatchetStateCodec.maxRetainedPqEpochs, 2);
      expect(V3TripleRatchetStateCodec.maxSkippedKeysPerRatchet, 50);
      expect(V3TripleRatchetStateCodec.maxEncodedBytes, 256 * 1024);
    });

    test('round-trips a complete snapshot with a frozen binary digest', () {
      final state = _state();
      final encoded = V3TripleRatchetStateCodec.encode(state);
      expect(encoded, hasLength(1032));
      expect(
        crypto.sha256.convert(encoded).toString(),
        '80e1674013878a56deaee2fce71e451f956dce2415a53e254f4652ae7954bf76',
      );

      final decoded = V3TripleRatchetStateCodec.decode(encoded);
      expect(decoded.role, V3SessionRole.initiator);
      expect(decoded.lifecycle, V3RatchetLifecycle.active);
      expect(decoded.revision, 3);
      expect(decoded.sessionId, _bytes(16, 1));
      expect(decoded.ecSendCounter, 5);
      expect(decoded.ecReceiveCounter, 6);
      expect(decoded.ecPreviousSendingChainLength, 4);
      expect(decoded.pqCurrentEpoch, 7);
      expect(decoded.pqSendingEpoch, 7);
      expect(decoded.pqReceivingEpoch, 6);
      expect(decoded.pqEpochStates.map((value) => value.epoch), <int>[6, 7]);
      expect(decoded.ecSkippedMessageKeys, hasLength(2));
      expect(decoded.pqSkippedMessageKeys, hasLength(1));
      expect(decoded.nativeSckaState, _bytes(128, 0x44));
      expect(V3TripleRatchetStateCodec.encode(decoded), encoded);

      decoded.wipeSecrets();
      state.wipeSecrets();
    });

    test('canonicalizes epoch and skipped-key ordering', () {
      final state = _state(reverseInputOrder: true);
      final decoded = V3TripleRatchetStateCodec.decode(
        V3TripleRatchetStateCodec.encode(state),
      );
      expect(decoded.pqEpochStates.map((value) => value.epoch), <int>[6, 7]);
      expect(
        decoded.ecSkippedMessageKeys
            .map((value) => value.ratchetPublicKey.first),
        <int>[0x11, 0x31],
      );
      expect(
        decoded.pqSkippedMessageKeys
            .map((value) => (value.epoch, value.messageCounter)),
        <(int, int)>[(6, 2)],
      );
      decoded.wipeSecrets();
      state.wipeSecrets();
    });

    test('encodes absent remote DH key canonically as zero bytes', () {
      final state = _state(remoteDhPublicKey: Uint8List(0));
      final encoded = V3TripleRatchetStateCodec.encode(state);
      expect(encoded[7], 2);
      expect(encoded.sublist(374, 406), everyElement(0));
      final decoded = V3TripleRatchetStateCodec.decode(encoded);
      expect(decoded.ecRemoteDhPublicKey, isNull);
      decoded.wipeSecrets();
      state.wipeSecrets();
    });

    test('encodes an absent initial EC receiving chain canonically', () {
      final state = _state(absentReceivingChain: true);
      final encoded = V3TripleRatchetStateCodec.encode(state);
      expect(encoded[7], 1);
      expect(encoded.sublist(278, 310), everyElement(0));
      final decoded = V3TripleRatchetStateCodec.decode(encoded);
      expect(decoded.ecReceivingChainKey, isNull);
      expect(decoded.ecReceiveCounter, 0);

      final nonCanonical = Uint8List.fromList(encoded)..[278] = 1;
      expect(
        () => V3TripleRatchetStateCodec.decode(nonCanonical),
        throwsFormatException,
      );
      decoded.wipeSecrets();
      state.wipeSecrets();
    });

    test('rejects malformed headers, lengths, flags, and reserved bytes', () {
      final state = _state();
      final encoded = V3TripleRatchetStateCodec.encode(state);
      for (final changed in <Uint8List>[
        Uint8List.fromList(encoded)..[0] = 0,
        Uint8List.fromList(encoded)..[3] = 2,
        Uint8List.fromList(encoded)..[4] = 0xff,
        Uint8List.fromList(encoded)..[5] = 0xff,
        Uint8List.fromList(encoded)..[6] = 0xff,
        Uint8List.fromList(encoded)..[7] |= 0x80,
        Uint8List.fromList(encoded)..[9] = 0,
        Uint8List.fromList(encoded)..[13] ^= 1,
        Uint8List.fromList(encoded)..[489] = 1,
        Uint8List.fromList(encoded.sublist(0, encoded.length - 1)),
        Uint8List.fromList(<int>[...encoded, 0]),
      ]) {
        expect(
          () => V3TripleRatchetStateCodec.decode(changed),
          throwsFormatException,
        );
      }
      state.wipeSecrets();
    });

    test('rejects non-canonical sealed chains and duplicate skipped keys', () {
      final state = _state();
      final encoded = V3TripleRatchetStateCodec.encode(state);
      final sealedSendKeyOffset = V3TripleRatchetStateCodec.headerBytes + 32;
      final changed = Uint8List.fromList(encoded)..[sealedSendKeyOffset] = 1;
      expect(
        () => V3TripleRatchetStateCodec.decode(changed),
        throwsFormatException,
      );

      final duplicate = V3EcSkippedMessageKey(
        ratchetPublicKey: _bytes(32, 0x11),
        messageCounter: 4,
        messageKey: _bytes(32, 0x71),
        expiresAtUnixSeconds: 2000000000,
      );
      expect(
        () => _state(extraEcSkipped: duplicate),
        throwsArgumentError,
      );
      state.wipeSecrets();
    });

    test('rejects non-canonical X25519 public-key encodings', () {
      final fieldPrime = _x25519FieldPrime();
      expect(
        () => _state(remoteDhPublicKey: fieldPrime),
        throwsArgumentError,
      );
      expect(
        () => V3EcSkippedMessageKey(
          ratchetPublicKey: fieldPrime,
          messageCounter: 0,
          messageKey: _bytes(32, 0x41),
          expiresAtUnixSeconds: 2000000000,
        ),
        throwsArgumentError,
      );
    });

    test('requires current consecutive PQ epochs and available directions', () {
      expect(
        () => _state(
          overrideEpochs: <V3PqEpochState>[
            V3PqEpochState(
              epoch: 5,
              receivingChainKey: _bytes(32, 0x51),
              receiveCounter: 1,
            ),
            V3PqEpochState(
              epoch: 7,
              sendingChainKey: _bytes(32, 0x61),
              sendCounter: 1,
              receivingChainKey: _bytes(32, 0x71),
              receiveCounter: 1,
            ),
          ],
        ),
        throwsArgumentError,
      );
      expect(
        () => _state(
          overrideEpochs: <V3PqEpochState>[
            V3PqEpochState(
              epoch: 6,
              sendingChainKey: _bytes(32, 0x41),
              sendCounter: 1,
            ),
            V3PqEpochState(
              epoch: 7,
              sendingChainKey: _bytes(32, 0x61),
              sendCounter: 1,
              receivingChainKey: _bytes(32, 0x71),
              receiveCounter: 1,
            ),
          ],
        ),
        throwsArgumentError,
      );
    });

    test('wiping invalidates all secret access and serialization', () {
      final state = _state();
      final publicSession = state.sessionId;
      state.wipeSecrets();
      expect(state.isWiped, isTrue);
      expect(state.sessionId, publicSession);
      expect(() => state.ecRootKey, throwsStateError);
      expect(() => state.nativeSckaState, throwsStateError);
      expect(
        () => V3TripleRatchetStateCodec.encode(state),
        throwsStateError,
      );
      state.wipeSecrets();
    });

    test('detached epoch and skipped-key copies can be wiped independently',
        () {
      final state = _state();
      final epoch = state.pqEpochStates.first;
      final ecSkipped = state.ecSkippedMessageKeys.first;
      final pqSkipped = state.pqSkippedMessageKeys.first;

      epoch.wipeSecrets();
      ecSkipped.wipeSecret();
      pqSkipped.wipeSecret();
      expect(epoch.isWiped, isTrue);
      expect(ecSkipped.isWiped, isTrue);
      expect(pqSkipped.isWiped, isTrue);
      expect(() => epoch.receivingChainKey, throwsStateError);
      expect(() => ecSkipped.messageKey, throwsStateError);
      expect(() => pqSkipped.messageKey, throwsStateError);

      expect(state.pqEpochStates.first.receivingChainKey, isNotNull);
      expect(state.ecSkippedMessageKeys.first.messageKey, hasLength(32));
      expect(state.pqSkippedMessageKeys.first.messageKey, hasLength(32));
      state.wipeSecrets();
    });

    test('rejects zero native state and equal directional ACK roots', () {
      expect(
        () => _state(nativeSckaState: Uint8List(128)),
        throwsArgumentError,
      );
      expect(
        () => _state(
          initiatorToResponderAckRootKey: _bytes(32, 0xb1),
          responderToInitiatorAckRootKey: _bytes(32, 0xb1),
        ),
        throwsArgumentError,
      );
    });
  });
}

V3TripleRatchetState _state({
  bool reverseInputOrder = false,
  Uint8List? remoteDhPublicKey,
  V3EcSkippedMessageKey? extraEcSkipped,
  List<V3PqEpochState>? overrideEpochs,
  Uint8List? initiatorToResponderAckRootKey,
  Uint8List? responderToInitiatorAckRootKey,
  Uint8List? nativeSckaState,
  bool absentReceivingChain = false,
}) {
  final epochs = overrideEpochs ??
      <V3PqEpochState>[
        V3PqEpochState(
          epoch: 6,
          receivingChainKey: _bytes(32, 0x51),
          receiveCounter: 3,
        ),
        V3PqEpochState(
          epoch: 7,
          sendingChainKey: _bytes(32, 0x61),
          sendCounter: 2,
          receivingChainKey: _bytes(32, 0x71),
          receiveCounter: 1,
        ),
      ];
  final ecSkipped = <V3EcSkippedMessageKey>[
    V3EcSkippedMessageKey(
      ratchetPublicKey: _bytes(32, 0x11),
      messageCounter: 4,
      messageKey: _bytes(32, 0x81),
      expiresAtUnixSeconds: 2000000000,
    ),
    V3EcSkippedMessageKey(
      ratchetPublicKey: _bytes(32, 0x31),
      messageCounter: 2,
      messageKey: _bytes(32, 0xa1),
      expiresAtUnixSeconds: 2000000100,
    ),
    if (extraEcSkipped != null) extraEcSkipped,
  ];
  final pqSkipped = <V3PqSkippedMessageKey>[
    V3PqSkippedMessageKey(
      epoch: 6,
      messageCounter: 2,
      messageKey: _bytes(32, 0xc1),
      expiresAtUnixSeconds: 2000000200,
    ),
  ];
  if (reverseInputOrder) {
    epochs.setAll(0, epochs.reversed.toList());
    ecSkipped.setAll(0, ecSkipped.reversed.toList());
    pqSkipped.setAll(0, pqSkipped.reversed.toList());
  }
  return V3TripleRatchetState(
    role: V3SessionRole.initiator,
    lifecycle: V3RatchetLifecycle.active,
    revision: 3,
    sessionId: _bytes(16, 1),
    transcriptDigest: _bytes(48, 0x21),
    initiatorRoutingBinding: _bytes(32, 0x61),
    responderRoutingBinding: _bytes(32, 0x91),
    initiatorToResponderAckRootKey:
        initiatorToResponderAckRootKey ?? _bytes(32, 0xb1),
    responderToInitiatorAckRootKey:
        responderToInitiatorAckRootKey ?? _bytes(32, 0xd1),
    ecRootKey: _bytes(32, 0x12),
    ecSendingChainKey: _bytes(32, 0x32),
    ecReceivingChainKey: absentReceivingChain ? null : _bytes(32, 0x52),
    ecLocalDhPrivateKey: _bytes(32, 0x72),
    ecLocalDhPublicKey: _bytes(32, 0x12),
    ecRemoteDhPublicKey: remoteDhPublicKey == null
        ? _bytes(32, 0x32)
        : remoteDhPublicKey.isEmpty
            ? null
            : remoteDhPublicKey,
    ecSendCounter: 5,
    ecReceiveCounter: absentReceivingChain ? 0 : 6,
    ecPreviousSendingChainLength: 4,
    pqRootKey: _bytes(32, 0xd2),
    pqCurrentEpoch: 7,
    pqSendingEpoch: 7,
    pqReceivingEpoch: 6,
    pqEpochStates: epochs,
    ecSkippedMessageKeys: ecSkipped,
    pqSkippedMessageKeys: pqSkipped,
    nativeSckaState: nativeSckaState ?? _bytes(128, 0x44),
  );
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Uint8List _x25519FieldPrime() => Uint8List.fromList(
      <int>[0xed, ...List<int>.filled(30, 0xff), 0x7f],
    );
