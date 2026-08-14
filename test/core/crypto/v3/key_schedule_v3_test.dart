import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/hybrid_ratchet_header_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_acknowledgement.dart';

void main() {
  group('protocol v3 session key schedule', () {
    test('matches independent HKDF-SHA-256 golden vectors', () async {
      final session = await _session();
      expect(_hex(session.sessionId), '061f5e09bff2fe666654633d01cfa24b');
      expect(
        _hex(session.initiatorRoutingBinding),
        'ceb7563a6e4165a2df30a980fa8e8ae93279a9a6c55149804a78de0f04daaf15',
      );
      expect(
        _hex(session.responderRoutingBinding),
        '53f66eed702998bd4a7ac896b40da8f05d3a095ac757a33378201f57c4731d4c',
      );
      expect(
        _hex(session.ecRatchetRootKey),
        '73c2636e4d89e9303f607cd78e67b7177f1b006285b787f3f3f9a005751e1d43',
      );
      expect(
        _hex(session.pqRatchetRootKey),
        '62be0328e19531a0631325eb567df83b0e761b485d757117dde3f1026d941468',
      );
      expect(
        _hex(session.initiatorToResponderAckRootKey),
        '108ea358215118864bafef48536bd78943ed3dd479cd021c73113d544c786e52',
      );
      expect(
        _hex(session.responderToInitiatorAckRootKey),
        '2b9d4fb5b0e80dce363b7dcf4719f77a9bd0c980669ff4fa2abafc2b153c3dca',
      );
      session.close();
    });

    test('requires both branches and binds every transcript byte', () async {
      final baseline = await _session();
      final changedClassical = await V3KeySchedule.deriveSession(
        classicalHandshakeSecret: _bytes(32, 1)..[31] ^= 1,
        postQuantumHandshakeSecret: _bytes(32, 0x20),
        transcriptDigest: _bytes(48, 0x40),
      );
      final changedPq = await V3KeySchedule.deriveSession(
        classicalHandshakeSecret: _bytes(32, 0),
        postQuantumHandshakeSecret: _bytes(32, 0x20)..[31] ^= 1,
        transcriptDigest: _bytes(48, 0x40),
      );
      final changedTranscript = await V3KeySchedule.deriveSession(
        classicalHandshakeSecret: _bytes(32, 0),
        postQuantumHandshakeSecret: _bytes(32, 0x20),
        transcriptDigest: _bytes(48, 0x40)..[47] ^= 1,
      );

      expect(changedClassical.sessionId, isNot(baseline.sessionId));
      expect(changedPq.sessionId, isNot(baseline.sessionId));
      expect(changedTranscript.sessionId, isNot(baseline.sessionId));
      expect(
        changedTranscript.initiatorRoutingBinding,
        isNot(baseline.initiatorRoutingBinding),
      );
      expect(
        changedTranscript.initiatorToResponderAckRootKey,
        isNot(baseline.initiatorToResponderAckRootKey),
      );

      expect(
        () => V3KeySchedule.deriveSession(
          classicalHandshakeSecret: Uint8List(32),
          postQuantumHandshakeSecret: _bytes(32, 0x20),
          transcriptDigest: _bytes(48, 0x40),
        ),
        throwsArgumentError,
      );
      expect(
        () => V3KeySchedule.deriveSession(
          classicalHandshakeSecret: _bytes(32, 0),
          postQuantumHandshakeSecret: Uint8List(32),
          transcriptDigest: _bytes(48, 0x40),
        ),
        throwsArgumentError,
      );

      baseline.close();
      changedClassical.close();
      changedPq.close();
      changedTranscript.close();
    });

    test('routing direction is canonical and reversed for replies', () async {
      final session = await _session();
      final forward = session.bindingsFor(
        V3TrafficDirection.initiatorToResponder,
      );
      final reverse = session.bindingsFor(
        V3TrafficDirection.responderToInitiator,
      );
      expect(forward.senderBinding, session.initiatorRoutingBinding);
      expect(forward.recipientBinding, session.responderRoutingBinding);
      expect(reverse.senderBinding, forward.recipientBinding);
      expect(reverse.recipientBinding, forward.senderBinding);
      expect(
        session.directionFor(
          senderBinding: forward.senderBinding,
          recipientBinding: forward.recipientBinding,
        ),
        V3TrafficDirection.initiatorToResponder,
      );
      expect(
        () => session.directionFor(
          senderBinding: forward.senderBinding,
          recipientBinding: forward.senderBinding,
        ),
        throwsFormatException,
      );
      session.close();
    });
  });

  group('protocol v3 hybrid message schedule', () {
    test('matches message, AEAD key, and fragment nonce vectors', () async {
      final session = await _session();
      final material = await _message(session);
      final header = _hybridHeader();
      final headerLength = V3HybridRatchetHeaderCodec.encode(header).length;
      final headerDigest = V3LmfFrameCodec.digestHybridRatchetHeader(header);
      expect(_hex(material.messageId), '044aaf313888fab0f9caa64f00a93eb5');
      expect(
        _hex(Uint8List.fromList(await material.secretKey.extractBytes())),
        '59ec62ab5d2940ec7c899703859858560e98ed720bd26045d323d7f7d3a1eb14',
      );
      expect(
        _hex(await material.nonceForFragment(
          fragmentIndex: 0,
          fragmentCount: 5,
          assembledPlaintextLength: 1088,
          hybridRatchetHeaderLength: headerLength,
          hybridRatchetHeaderDigest: headerDigest,
        )),
        '264ded9339d4d0cda864d1c8',
      );
      expect(
        _hex(await material.nonceForFragment(
          fragmentIndex: 4,
          fragmentCount: 5,
          assembledPlaintextLength: 1088,
          hybridRatchetHeaderLength: headerLength,
          hybridRatchetHeaderDigest: headerDigest,
        )),
        'bc0928a2fe7deb2ee71766cf',
      );
      material.close();
      session.close();
    });

    test('seals and reassembles canonical fragmented LMF with derived nonces',
        () async {
      final session = await _session();
      final material = await _message(session);
      final header = _hybridHeader();
      final headerLength = V3HybridRatchetHeaderCodec.encode(header).length;
      final headerDigest = V3LmfFrameCodec.digestHybridRatchetHeader(header);
      final bindings = session.bindingsFor(
        V3TrafficDirection.initiatorToResponder,
      );
      final metadata = V3LmfMessageMetadata(
        kind: V3LmfFrameKind.application,
        senderBinding: bindings.senderBinding,
        recipientBinding: bindings.recipientBinding,
        messageId: material.messageId,
        sessionId: session.sessionId,
        epoch: 7,
        messageCounter: 9,
      );
      final plaintext = Uint8List.fromList(
        List<int>.generate(1088, (index) => index & 0xff),
      );
      final nonces = <Uint8List>[];
      for (var index = 0; index < 5; index++) {
        nonces.add(
          await material.nonceForFragment(
            fragmentIndex: index,
            fragmentCount: 5,
            assembledPlaintextLength: plaintext.length,
            hybridRatchetHeaderLength: headerLength,
            hybridRatchetHeaderDigest: headerDigest,
          ),
        );
      }
      final frames = await V3LmfAead.sealFragmented(
        metadata: metadata,
        plaintext: plaintext,
        secretKey: material.secretKey,
        nonceForFragment: (index) => nonces[index],
        hybridRatchetHeader: header,
      );
      expect(frames, hasLength(5));
      for (var index = 0; index < frames.length; index++) {
        expect(frames[index].metadata.messageId, material.messageId);
        expect(frames[index].nonce, nonces[index]);
        expect(
          await material.matchesNonce(
            candidate: frames[index].nonce,
            fragmentIndex: index,
            fragmentCount: frames.length,
            assembledPlaintextLength: plaintext.length,
            hybridRatchetHeaderLength: headerLength,
            hybridRatchetHeaderDigest: headerDigest,
          ),
          isTrue,
        );
      }

      final reassembler = V3LmfReassembler();
      V3LmfReassemblyOutcome? complete;
      for (final index in <int>[3, 1, 4, 0, 2]) {
        final outcome = await reassembler.accept(
          frame: frames[index],
          secretKey: material.secretKey,
        );
        if (outcome.isComplete) complete = outcome;
      }
      expect(complete?.plaintext, plaintext);
      complete?.wipePlaintext();
      reassembler.close();
      material.close();
      session.close();
    });

    test('separates direction, kind, epoch, counter, and either ratchet key',
        () async {
      final session = await _session();
      final baseline = await _message(session);
      final variants = <V3MessageKeyMaterial>[
        await _message(
          session,
          direction: V3TrafficDirection.responderToInitiator,
        ),
        await _message(session, kind: V3LmfFrameKind.pqRatchet),
        await _message(session, epoch: 8),
        await _message(session, counter: 10),
        await _message(session, ecKey: _bytes(32, 0x81)),
        await _message(session, pqKey: _bytes(32, 0xa1)),
      ];
      for (final variant in variants) {
        expect(variant.messageId, isNot(baseline.messageId));
        expect(
          await variant.secretKey.extractBytes(),
          isNot(await baseline.secretKey.extractBytes()),
        );
        variant.close();
      }
      expect(
        () => V3KeySchedule.deriveMessage(
          ecMessageKey: _bytes(32, 0x80),
          pqMessageKey: Uint8List(32),
          sessionId: session.sessionId,
          direction: V3TrafficDirection.initiatorToResponder,
          kind: V3LmfFrameKind.application,
          epoch: 7,
          messageCounter: 9,
        ),
        throwsArgumentError,
      );
      baseline.close();
      expect(() => baseline.secretKey, throwsStateError);
      session.close();
    });

    test('preserves epoch bits above the legacy 32-bit range', () async {
      final session = await _session();
      final legacy = await _message(session, epoch: 7);
      final widened = await _message(session, epoch: 0x100000007);
      expect(widened.messageId, isNot(legacy.messageId));
      expect(
        await widened.secretKey.extractBytes(),
        isNot(await legacy.secretKey.extractBytes()),
      );
      widened.close();
      legacy.close();
      session.close();
    });
  });

  group('protocol v3 acknowledgement schedule', () {
    test('matches golden key and nonce and opens a canonical ACK', () async {
      final session = await _session();
      final bindings = session.bindingsFor(
        V3TrafficDirection.responderToInitiator,
      );
      final metadata = V3LmfMessageMetadata(
        kind: V3LmfFrameKind.acknowledgement,
        senderBinding: bindings.senderBinding,
        recipientBinding: bindings.recipientBinding,
        messageId: _bytes(16, 0xc0),
        sessionId: session.sessionId,
        epoch: 7,
        messageCounter: 9,
      );
      final material = await V3KeySchedule.deriveAcknowledgement(
        session: session,
        direction: V3TrafficDirection.responderToInitiator,
        metadata: metadata,
      );
      expect(
        _hex(Uint8List.fromList(await material.secretKey.extractBytes())),
        '739104c8a947f09b02cc24b896063786c23c6393950e89f1e2b43018585d63f3',
      );
      expect(_hex(material.nonce), 'c95dfd5806ba2937dbc551d9');

      final acknowledgement = V3LmfAcknowledgement(
        targetSuite: V3LmfSuite.hybridX25519MlKem768Aes256Gcm,
        targetKind: V3LmfFrameKind.application,
        targetMessageId: _bytes(16, 0x80),
        targetEpoch: 7,
        targetMessageCounter: 9,
        targetAssembledPlaintextLength: 1088,
        targetFragmentCount: 5,
        receivedFragmentIndexes: const <int>{0, 2, 4},
      );
      final frame = await V3LmfAead.sealSingle(
        metadata: metadata,
        plaintext: V3LmfAcknowledgementCodec.encode(acknowledgement),
        secretKey: material.secretKey,
        nonce: material.nonce,
      );
      final opened = await V3LmfAead.openSingle(
        frame: frame,
        secretKey: material.secretKey,
      );
      final decoded = V3LmfAcknowledgementCodec.decode(opened);
      expect(decoded.receivedFragmentIndexes, <int>{0, 2, 4});
      opened.fillRange(0, opened.length, 0);
      material.close();
      session.close();
    });

    test('requires exact direction and fresh ACK message identity', () async {
      final session = await _session();
      final bindings = session.bindingsFor(
        V3TrafficDirection.responderToInitiator,
      );
      V3LmfMessageMetadata metadata(int start) => V3LmfMessageMetadata(
            kind: V3LmfFrameKind.acknowledgement,
            senderBinding: bindings.senderBinding,
            recipientBinding: bindings.recipientBinding,
            messageId: _bytes(16, start),
            sessionId: session.sessionId,
            epoch: 7,
            messageCounter: 9,
          );
      final first = await V3KeySchedule.deriveAcknowledgement(
        session: session,
        direction: V3TrafficDirection.responderToInitiator,
        metadata: metadata(0xc0),
      );
      final second = await V3KeySchedule.deriveAcknowledgement(
        session: session,
        direction: V3TrafficDirection.responderToInitiator,
        metadata: metadata(0xd0),
      );
      expect(second.nonce, isNot(first.nonce));
      expect(
        await second.secretKey.extractBytes(),
        isNot(await first.secretKey.extractBytes()),
      );
      expect(
        () => V3KeySchedule.deriveAcknowledgement(
          session: session,
          direction: V3TrafficDirection.initiatorToResponder,
          metadata: metadata(0xe0),
        ),
        throwsFormatException,
      );
      first.close();
      second.close();
      session.close();
    });

    test('committed-state adapter matches the frozen session schedule',
        () async {
      final session = await _session();
      final sessionId = session.sessionId;
      final initiatorBinding = session.initiatorRoutingBinding;
      final responderBinding = session.responderRoutingBinding;
      final initiatorRoot = session.initiatorToResponderAckRootKey;
      final responderRoot = session.responderToInitiatorAckRootKey;
      try {
        for (final direction in V3TrafficDirection.values) {
          final bindings = session.bindingsFor(direction);
          final metadata = V3LmfMessageMetadata(
            kind: V3LmfFrameKind.acknowledgement,
            senderBinding: bindings.senderBinding,
            recipientBinding: bindings.recipientBinding,
            messageId: _bytes(
              16,
              direction == V3TrafficDirection.initiatorToResponder
                  ? 0xd1
                  : 0xe1,
            ),
            sessionId: sessionId,
            epoch: 0x100000007,
            messageCounter: 0x100000009,
          );
          final frozen = await V3KeySchedule.deriveAcknowledgement(
            session: session,
            direction: direction,
            metadata: metadata,
          );
          final committed =
              await V3KeySchedule.deriveAcknowledgementFromCommittedState(
            sessionId: sessionId,
            initiatorRoutingBinding: initiatorBinding,
            responderRoutingBinding: responderBinding,
            initiatorToResponderAckRootKey: initiatorRoot,
            responderToInitiatorAckRootKey: responderRoot,
            direction: direction,
            metadata: metadata,
          );
          try {
            expect(committed.nonce, frozen.nonce);
            expect(
              await committed.secretKey.extractBytes(),
              await frozen.secretKey.extractBytes(),
            );
          } finally {
            committed.close();
            frozen.close();
          }
        }

        final validBindings = session.bindingsFor(
          V3TrafficDirection.responderToInitiator,
        );
        final wrongSessionMetadata = V3LmfMessageMetadata(
          kind: V3LmfFrameKind.acknowledgement,
          senderBinding: validBindings.senderBinding,
          recipientBinding: validBindings.recipientBinding,
          messageId: _bytes(16, 0xf1),
          sessionId: _bytes(16, 0x01),
          epoch: 7,
          messageCounter: 9,
        );
        await expectLater(
          V3KeySchedule.deriveAcknowledgementFromCommittedState(
            sessionId: sessionId,
            initiatorRoutingBinding: initiatorBinding,
            responderRoutingBinding: responderBinding,
            initiatorToResponderAckRootKey: initiatorRoot,
            responderToInitiatorAckRootKey: responderRoot,
            direction: V3TrafficDirection.responderToInitiator,
            metadata: wrongSessionMetadata,
          ),
          throwsFormatException,
        );
      } finally {
        sessionId.fillRange(0, sessionId.length, 0);
        initiatorBinding.fillRange(0, initiatorBinding.length, 0);
        responderBinding.fillRange(0, responderBinding.length, 0);
        initiatorRoot.fillRange(0, initiatorRoot.length, 0);
        responderRoot.fillRange(0, responderRoot.length, 0);
        session.close();
      }
    });
  });
}

Future<V3SessionKeyMaterial> _session() => V3KeySchedule.deriveSession(
      classicalHandshakeSecret: _bytes(32, 0),
      postQuantumHandshakeSecret: _bytes(32, 0x20),
      transcriptDigest: _bytes(48, 0x40),
    );

Future<V3MessageKeyMaterial> _message(
  V3SessionKeyMaterial session, {
  V3TrafficDirection direction = V3TrafficDirection.initiatorToResponder,
  V3LmfFrameKind kind = V3LmfFrameKind.application,
  int epoch = 7,
  int counter = 9,
  Uint8List? ecKey,
  Uint8List? pqKey,
}) {
  return V3KeySchedule.deriveMessage(
    ecMessageKey: ecKey ?? _bytes(32, 0x80),
    pqMessageKey: pqKey ?? _bytes(32, 0xa0),
    sessionId: session.sessionId,
    direction: direction,
    kind: kind,
    epoch: epoch,
    messageCounter: counter,
  );
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

String _hex(Uint8List value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

V3HybridRatchetHeader _hybridHeader() => V3HybridRatchetHeader(
      ecHeader: V3EcRatchetHeader(
        ratchetPublicKey: _bytes(32, 0x21),
        previousSendingChainLength: 3,
        messageCounter: 5,
      ),
      sckaMessage: V3SckaMessage(
        sendingEpoch: 7,
        messageCounter: 9,
        nativePayload: Uint8List(0),
      ),
    );
