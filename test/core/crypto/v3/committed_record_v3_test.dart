import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';

void main() {
  group('protocol v3 committed application/control record', () {
    test('round-trips exact delivery content with a frozen binary digest',
        () async {
      final delivery = await _delivery();
      final content = _bytes(300, 0x31);
      final record = V3CommittedRecord.fromDelivery(
        targetFrame: delivery.first,
        content: content,
      );
      final encoded = V3CommittedRecordCodec.encode(record);
      expect(encoded, hasLength(492));
      expect(
        crypto.sha256.convert(encoded).toString(),
        'ad2ae14b5ee380ec9d62b406795230191e0c36c8f3e4eecacfaf71f828e652b3',
      );
      expect(record.assemblyId, V3LmfFrameCodec.assemblyId(delivery.first));
      expect(record.stableRecordId, 'v3:${record.assemblyId}');

      final decoded = V3CommittedRecordCodec.decode(encoded);
      expect(decoded.kind, V3CommittedRecordKind.application);
      expect(decoded.sessionId, delivery.first.metadata.sessionId);
      expect(decoded.messageId, delivery.first.metadata.messageId);
      expect(decoded.senderBinding, delivery.first.metadata.senderBinding);
      expect(
        decoded.recipientBinding,
        delivery.first.metadata.recipientBinding,
      );
      expect(decoded.epoch, 7);
      expect(decoded.messageCounter, 9);
      expect(decoded.content, content);
      expect(V3CommittedRecordCodec.encode(decoded), encoded);
      decoded.wipeContent();
      record.wipeContent();
    });

    test('maps every non-ACK frame kind to one semantic record kind', () async {
      for (final pair in <(V3LmfFrameKind, V3CommittedRecordKind)>[
        (V3LmfFrameKind.application, V3CommittedRecordKind.application),
        (V3LmfFrameKind.handshake, V3CommittedRecordKind.handshakeControl),
        (V3LmfFrameKind.pqRatchet, V3CommittedRecordKind.pqRatchetControl),
      ]) {
        final delivery = await _delivery(kind: pair.$1);
        final record = V3CommittedRecord.fromDelivery(
          targetFrame: delivery.first,
          content: _bytes(300, 0x31),
        );
        expect(record.kind, pair.$2);
        record.wipeContent();
      }
      final ackFrame = _frame(kind: V3LmfFrameKind.acknowledgement);
      expect(
        () => V3CommittedRecord.fromDelivery(
          targetFrame: ackFrame,
          content: _bytes(48, 1),
        ),
        throwsArgumentError,
      );
    });

    test('rejects content not matching authenticated assembled length',
        () async {
      final delivery = await _delivery();
      expect(
        () => V3CommittedRecord.fromDelivery(
          targetFrame: delivery.first,
          content: _bytes(299, 0x31),
        ),
        throwsArgumentError,
      );
    });

    test('detects header, routing, source, digest, content, and length changes',
        () async {
      final delivery = await _delivery();
      final record = V3CommittedRecord.fromDelivery(
        targetFrame: delivery.first,
        content: _bytes(300, 0x31),
      );
      final encoded = V3CommittedRecordCodec.encode(record);
      for (final changed in <Uint8List>[
        Uint8List.fromList(encoded)..[0] = 0,
        Uint8List.fromList(encoded)..[3] = 1,
        Uint8List.fromList(encoded)..[4] = 0xff,
        Uint8List.fromList(encoded)..[5] = 0xff,
        Uint8List.fromList(encoded)..[6] = 1,
        Uint8List.fromList(encoded)..[7] = 0,
        Uint8List.fromList(encoded)..[11] ^= 1,
        Uint8List.fromList(encoded)..[12] ^= 1,
        Uint8List.fromList(encoded)..[76] ^= 1,
        Uint8List.fromList(encoded)..[140] ^= 1,
        Uint8List.fromList(encoded)..[151] ^= 1,
        Uint8List.fromList(encoded)..[156] ^= 1,
        Uint8List.fromList(encoded)..[188] ^= 1,
        Uint8List.fromList(encoded)..[192] ^= 1,
        Uint8List.fromList(encoded.sublist(0, encoded.length - 1)),
        Uint8List.fromList(<int>[...encoded, 0]),
      ]) {
        expect(
          () => V3CommittedRecordCodec.decode(changed),
          throwsFormatException,
        );
      }
      record.wipeContent();
    });

    test('supports the full LMF plaintext bound within the journal limit', () {
      final frame = _frame(
        assembledLength: V3LmfFrameCodec.maxAssembledPlaintextBytes,
        fragmentCount: V3LmfFrameCodec.maxFragments,
      );
      final record = V3CommittedRecord.fromDelivery(
        targetFrame: frame,
        content: _bytes(V3LmfFrameCodec.maxAssembledPlaintextBytes, 1),
      );
      final encoded = V3CommittedRecordCodec.encode(record);
      expect(encoded, hasLength(V3CommittedRecordCodec.maxEncodedBytes));
      expect(encoded.length, lessThanOrEqualTo(17 * 1024));
      final decoded = V3CommittedRecordCodec.decode(encoded);
      expect(
        decoded.content,
        hasLength(V3LmfFrameCodec.maxAssembledPlaintextBytes),
      );
      decoded.wipeContent();
      record.wipeContent();
    });

    test('wiping makes plaintext inaccessible and prevents re-encoding',
        () async {
      final delivery = await _delivery();
      final record = V3CommittedRecord.fromDelivery(
        targetFrame: delivery.first,
        content: _bytes(300, 0x31),
      );
      final stableId = record.stableRecordId;
      record.wipeContent();
      expect(record.isWiped, isTrue);
      expect(record.stableRecordId, stableId);
      expect(() => record.content, throwsStateError);
      expect(() => V3CommittedRecordCodec.encode(record), throwsStateError);
    });

    test('round-trips widened epoch and counter boundaries', () async {
      final delivery = await _delivery(
        epoch: 0x7fffffffffffffff,
        messageCounter: 0x7fffffffffffffff,
      );
      final record = V3CommittedRecord.fromDelivery(
        targetFrame: delivery.first,
        content: _bytes(300, 0x31),
      );
      final decoded = V3CommittedRecordCodec.decode(
        V3CommittedRecordCodec.encode(record),
      );
      expect(decoded.epoch, 0x7fffffffffffffff);
      expect(decoded.messageCounter, 0x7fffffffffffffff);
      decoded.wipeContent();
      record.wipeContent();
    });

    test('rejects high-bit epoch and counter with matching content digest',
        () async {
      final delivery = await _delivery();
      final record = V3CommittedRecord.fromDelivery(
        targetFrame: delivery.first,
        content: _bytes(300, 0x31),
      );
      final encoded = V3CommittedRecordCodec.encode(record);
      for (final counterOffset in <int>[140, 148]) {
        final changed = Uint8List.fromList(encoded);
        ByteData.sublistView(changed).setUint64(
          counterOffset,
          0x8000000000000000,
          Endian.big,
        );
        final digest = crypto.sha256.convert(<int>[
          ...'layergram/v3/committed-record/content\u0000'.codeUnits,
          ...changed.sublist(12, 44),
          ...changed.sublist(140, 156),
          ...changed.sublist(V3CommittedRecordCodec.headerBytes),
        ]).bytes;
        changed.setRange(160, 192, digest);
        expect(
          () => V3CommittedRecordCodec.decode(changed),
          throwsFormatException,
        );
      }
      record.wipeContent();
    });
  });
}

Future<List<V3LmfFrame>> _delivery({
  V3LmfFrameKind kind = V3LmfFrameKind.application,
  int epoch = 7,
  int messageCounter = 9,
}) {
  return V3LmfAead.sealFragmented(
    metadata: _metadata(
      kind: kind,
      epoch: epoch,
      messageCounter: messageCounter,
    ),
    plaintext: _bytes(300, 0x31),
    secretKey: SecretKey(_bytes(32, 0x11)),
    nonceForFragment: (index) => _bytes(12, 0x51 + index),
  );
}

V3LmfFrame _frame({
  V3LmfFrameKind kind = V3LmfFrameKind.application,
  int assembledLength = 48,
  int fragmentCount = 1,
}) {
  final fragmentLength = fragmentCount == 1
      ? assembledLength
      : V3LmfFrameCodec.fragmentPlaintextBytes;
  return V3LmfFrame(
    metadata: _metadata(kind: kind),
    fragmentIndex: 0,
    fragmentCount: fragmentCount,
    assembledPlaintextLength: assembledLength,
    nonce: _bytes(12, 0x51),
    ciphertext: _bytes(fragmentLength, 0x61),
    authenticationTag: _bytes(16, 0x71),
  );
}

V3LmfMessageMetadata _metadata({
  required V3LmfFrameKind kind,
  int epoch = 7,
  int messageCounter = 9,
}) =>
    V3LmfMessageMetadata(
      kind: kind,
      senderBinding: _bytes(32, 1),
      recipientBinding: _bytes(32, 0x41),
      messageId: _bytes(16, 0x81),
      sessionId: _bytes(16, 0xa1),
      epoch: epoch,
      messageCounter: messageCounter,
    );

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
