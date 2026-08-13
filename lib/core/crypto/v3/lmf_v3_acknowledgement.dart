// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:typed_data';

import 'lmf_v3.dart';

/// Cumulative acknowledgement for authenticated fragments of one v3 message.
///
/// This is plaintext only inside an LMF frame whose kind is
/// [V3LmfFrameKind.acknowledgement]. The ACK frame must itself be protected by
/// the future session/ratchet key and is never acknowledged, preventing loops.
class V3LmfAcknowledgement {
  factory V3LmfAcknowledgement({
    required V3LmfSuite targetSuite,
    required V3LmfFrameKind targetKind,
    required Uint8List targetMessageId,
    required int targetEpoch,
    required int targetMessageCounter,
    required int targetAssembledPlaintextLength,
    required int targetFragmentCount,
    required Set<int> receivedFragmentIndexes,
  }) {
    if (targetKind == V3LmfFrameKind.acknowledgement) {
      throw ArgumentError.value(
        targetKind,
        'targetKind',
        'acknowledgements must not acknowledge acknowledgements',
      );
    }
    if (targetMessageId.length != V3LmfFrameCodec.messageIdBytes) {
      throw ArgumentError.value(
        targetMessageId.length,
        'targetMessageId.length',
        'must be exactly ${V3LmfFrameCodec.messageIdBytes} bytes',
      );
    }
    if (_isAllZero(targetMessageId)) {
      throw ArgumentError.value(
        targetMessageId,
        'targetMessageId',
        'must not be all zero',
      );
    }
    if (targetEpoch < 0 || targetEpoch > 0xffffffff) {
      throw ArgumentError.value(targetEpoch, 'targetEpoch');
    }
    if (targetMessageCounter < 0 || targetMessageCounter > 0x7fffffffffffffff) {
      throw ArgumentError.value(
        targetMessageCounter,
        'targetMessageCounter',
      );
    }
    if (targetAssembledPlaintextLength < 1 ||
        targetAssembledPlaintextLength >
            V3LmfFrameCodec.maxAssembledPlaintextBytes) {
      throw ArgumentError.value(
        targetAssembledPlaintextLength,
        'targetAssembledPlaintextLength',
      );
    }
    if (targetFragmentCount < 1 ||
        targetFragmentCount > V3LmfFrameCodec.maxFragments) {
      throw ArgumentError.value(
        targetFragmentCount,
        'targetFragmentCount',
      );
    }
    if (targetFragmentCount > 1) {
      final expectedFragmentCount = (targetAssembledPlaintextLength +
              V3LmfFrameCodec.fragmentPlaintextBytes -
              1) ~/
          V3LmfFrameCodec.fragmentPlaintextBytes;
      if (targetAssembledPlaintextLength <=
              V3LmfFrameCodec.fragmentPlaintextBytes ||
          targetFragmentCount != expectedFragmentCount) {
        throw ArgumentError(
          'target fragment count does not match canonical fragmentation',
        );
      }
    }
    if (receivedFragmentIndexes.isEmpty) {
      throw ArgumentError.value(
        receivedFragmentIndexes,
        'receivedFragmentIndexes',
        'must acknowledge at least one fragment',
      );
    }
    final sorted = receivedFragmentIndexes.toList()..sort();
    for (final index in sorted) {
      if (index < 0 || index >= targetFragmentCount) {
        throw ArgumentError.value(
          index,
          'receivedFragmentIndexes',
          'is outside the target fragment set',
        );
      }
    }
    return V3LmfAcknowledgement._(
      targetSuite: targetSuite,
      targetKind: targetKind,
      targetMessageId: Uint8List.fromList(targetMessageId),
      targetEpoch: targetEpoch,
      targetMessageCounter: targetMessageCounter,
      targetAssembledPlaintextLength: targetAssembledPlaintextLength,
      targetFragmentCount: targetFragmentCount,
      receivedFragmentIndexes: Set<int>.unmodifiable(sorted),
    );
  }

  const V3LmfAcknowledgement._({
    required this.targetSuite,
    required this.targetKind,
    required Uint8List targetMessageId,
    required this.targetEpoch,
    required this.targetMessageCounter,
    required this.targetAssembledPlaintextLength,
    required this.targetFragmentCount,
    required this.receivedFragmentIndexes,
  }) : _targetMessageId = targetMessageId;

  final V3LmfSuite targetSuite;
  final V3LmfFrameKind targetKind;
  final Uint8List _targetMessageId;
  final int targetEpoch;
  final int targetMessageCounter;
  final int targetAssembledPlaintextLength;
  final int targetFragmentCount;
  final Set<int> receivedFragmentIndexes;

  Uint8List get targetMessageId => Uint8List.fromList(_targetMessageId);

  bool get isComplete => receivedFragmentIndexes.length == targetFragmentCount;
}

/// Canonical 48-byte acknowledgement plaintext.
abstract final class V3LmfAcknowledgementCodec {
  static const List<int> magic = <int>[0x41, 0x4b, 0x33]; // "AK3"
  static const int formatVersion = 1;
  static const int encodedBytes = 48;
  static const int bitmapBytes = 8;

  static Uint8List encode(V3LmfAcknowledgement acknowledgement) {
    final result = Uint8List(encodedBytes);
    final data = ByteData.sublistView(result);
    var offset = 0;
    result.setRange(offset, offset + magic.length, magic);
    offset += magic.length;
    result[offset++] = formatVersion;
    result[offset++] = acknowledgement.targetSuite.wireId;
    result[offset++] = acknowledgement.targetKind.wireId;
    result[offset++] = 0; // Reserved flags.
    result[offset++] = acknowledgement.targetFragmentCount;
    result.setRange(
      offset,
      offset + V3LmfFrameCodec.messageIdBytes,
      acknowledgement._targetMessageId,
    );
    offset += V3LmfFrameCodec.messageIdBytes;
    data.setUint32(offset, acknowledgement.targetEpoch, Endian.big);
    offset += 4;
    data.setUint64(
      offset,
      acknowledgement.targetMessageCounter,
      Endian.big,
    );
    offset += 8;
    data.setUint32(
      offset,
      acknowledgement.targetAssembledPlaintextLength,
      Endian.big,
    );
    offset += 4;
    for (final index in acknowledgement.receivedFragmentIndexes) {
      final byteOffset = offset + (index ~/ 8);
      result[byteOffset] |= 1 << (index % 8);
    }
    offset += bitmapBytes;
    if (offset != encodedBytes) {
      throw StateError('Layergram v3 acknowledgement implementation drift');
    }
    return result;
  }

  static V3LmfAcknowledgement decode(Uint8List encoded) {
    if (encoded.length != encodedBytes) {
      throw const FormatException(
        'Invalid Layergram v3 acknowledgement length',
      );
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException(
          'Invalid Layergram v3 acknowledgement magic',
        );
      }
    }
    if (encoded[3] != formatVersion) {
      throw const FormatException(
        'Unsupported Layergram v3 acknowledgement version',
      );
    }
    final suite = V3LmfSuite.fromWireId(encoded[4]);
    final kind = V3LmfFrameKind.fromWireId(encoded[5]);
    if (kind == V3LmfFrameKind.acknowledgement || encoded[6] != 0) {
      throw const FormatException(
        'Invalid Layergram v3 acknowledgement target',
      );
    }
    final fragmentCount = encoded[7];
    if (fragmentCount < 1 || fragmentCount > V3LmfFrameCodec.maxFragments) {
      throw const FormatException(
        'Invalid Layergram v3 acknowledgement fragment count',
      );
    }
    final data = ByteData.sublistView(encoded);
    final messageId = Uint8List.fromList(encoded.sublist(8, 24));
    final epoch = data.getUint32(24, Endian.big);
    final messageCounter = data.getUint64(28, Endian.big);
    final assembledLength = data.getUint32(36, Endian.big);
    final indexes = <int>{};
    for (var index = 0; index < V3LmfFrameCodec.maxFragments; index++) {
      final bit = encoded[40 + (index ~/ 8)] & (1 << (index % 8));
      if (bit == 0) continue;
      if (index >= fragmentCount) {
        throw const FormatException(
          'Non-canonical Layergram v3 acknowledgement bitmap',
        );
      }
      indexes.add(index);
    }
    if (indexes.isEmpty) {
      throw const FormatException(
        'Empty Layergram v3 acknowledgement bitmap',
      );
    }
    try {
      final acknowledgement = V3LmfAcknowledgement(
        targetSuite: suite,
        targetKind: kind,
        targetMessageId: messageId,
        targetEpoch: epoch,
        targetMessageCounter: messageCounter,
        targetAssembledPlaintextLength: assembledLength,
        targetFragmentCount: fragmentCount,
        receivedFragmentIndexes: indexes,
      );
      if (!_bytesEqual(encode(acknowledgement), encoded)) {
        throw const FormatException(
          'Non-canonical Layergram v3 acknowledgement',
        );
      }
      return acknowledgement;
    } on ArgumentError {
      throw const FormatException(
        'Invalid Layergram v3 acknowledgement fields',
      );
    }
  }

  static V3LmfAcknowledgement forReceivedFrames(
    Iterable<V3LmfFrame> frames,
  ) {
    final iterator = frames.iterator;
    if (!iterator.moveNext()) {
      throw ArgumentError.value(frames, 'frames', 'must not be empty');
    }
    final first = iterator.current;
    if (first.metadata.kind == V3LmfFrameKind.acknowledgement) {
      throw ArgumentError('Acknowledgement frames must not be acknowledged');
    }
    final indexes = <int>{first.fragmentIndex};
    var receivedFrameCount = 1;
    while (iterator.moveNext()) {
      receivedFrameCount++;
      if (receivedFrameCount > V3LmfFrameCodec.maxFragments) {
        throw ArgumentError.value(
          receivedFrameCount,
          'frames.length',
          'must not exceed ${V3LmfFrameCodec.maxFragments}',
        );
      }
      final frame = iterator.current;
      if (!_sameTarget(first, frame)) {
        throw ArgumentError('Frames do not belong to one v3 message');
      }
      indexes.add(frame.fragmentIndex);
    }
    return V3LmfAcknowledgement(
      targetSuite: first.metadata.suite,
      targetKind: first.metadata.kind,
      targetMessageId: first.metadata.messageId,
      targetEpoch: first.metadata.epoch,
      targetMessageCounter: first.metadata.messageCounter,
      targetAssembledPlaintextLength: first.assembledPlaintextLength,
      targetFragmentCount: first.fragmentCount,
      receivedFragmentIndexes: indexes,
    );
  }
}

bool _sameTarget(V3LmfFrame left, V3LmfFrame right) {
  return left.metadata.suite == right.metadata.suite &&
      left.metadata.kind == right.metadata.kind &&
      left.metadata.epoch == right.metadata.epoch &&
      left.metadata.messageCounter == right.metadata.messageCounter &&
      left.metadata.expiresAtUnixSeconds ==
          right.metadata.expiresAtUnixSeconds &&
      left.fragmentCount == right.fragmentCount &&
      left.assembledPlaintextLength == right.assembledPlaintextLength &&
      _bytesEqual(left.metadata.senderBinding, right.metadata.senderBinding) &&
      _bytesEqual(
        left.metadata.recipientBinding,
        right.metadata.recipientBinding,
      ) &&
      _bytesEqual(left.metadata.messageId, right.metadata.messageId) &&
      _bytesEqual(left.metadata.sessionId, right.metadata.sessionId);
}

bool _isAllZero(Uint8List bytes) {
  var anyNonZero = false;
  for (final byte in bytes) {
    anyNonZero |= byte != 0;
  }
  return !anyNonZero;
}

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
