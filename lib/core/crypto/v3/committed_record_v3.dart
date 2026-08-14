// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'lmf_v3.dart';

/// Higher-level semantic class durably materialized from a complete delivery.
enum V3CommittedRecordKind {
  application(1, V3LmfFrameKind.application),
  handshakeControl(2, V3LmfFrameKind.handshake),
  pqRatchetControl(3, V3LmfFrameKind.pqRatchet);

  const V3CommittedRecordKind(this.wireId, this.frameKind);

  final int wireId;
  final V3LmfFrameKind frameKind;

  static V3CommittedRecordKind fromWireId(int wireId) {
    for (final value in values) {
      if (value.wireId == wireId) return value;
    }
    throw const FormatException(
      'Unsupported Layergram v3 committed record kind',
    );
  }

  static V3CommittedRecordKind fromFrameKind(V3LmfFrameKind frameKind) {
    for (final value in values) {
      if (value.frameKind == frameKind) return value;
    }
    throw ArgumentError.value(
      frameKind,
      'frameKind',
      'acknowledgements never create committed effects',
    );
  }
}

/// Canonical application/control effect stored by the v3 atomic journal.
///
/// The record independently binds the source assembly, complete routing
/// context, counters, and exact delivered content. It is still kept only in
/// Layergram's encrypted, identity-scoped auxiliary storage.
final class V3CommittedRecord {
  factory V3CommittedRecord.fromDelivery({
    required V3LmfFrame targetFrame,
    required Uint8List content,
  }) {
    if (targetFrame.metadata.kind == V3LmfFrameKind.acknowledgement) {
      throw ArgumentError(
        'Layergram v3 acknowledgements do not create committed records',
      );
    }
    if (content.length != targetFrame.assembledPlaintextLength) {
      throw ArgumentError.value(
        content.length,
        'content.length',
        'must match the authenticated assembled plaintext length',
      );
    }
    if (content.isEmpty ||
        content.length > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
      throw ArgumentError.value(content.length, 'content.length');
    }
    final metadata = targetFrame.metadata;
    final assemblyDigest = _deriveAssemblyDigest(
      suite: metadata.suite,
      frameKind: metadata.kind,
      senderBinding: metadata.senderBinding,
      recipientBinding: metadata.recipientBinding,
      messageId: metadata.messageId,
      sessionId: metadata.sessionId,
    );
    return V3CommittedRecord._(
      suite: metadata.suite,
      kind: V3CommittedRecordKind.fromFrameKind(metadata.kind),
      assemblyDigest: assemblyDigest,
      sessionId: metadata.sessionId,
      messageId: metadata.messageId,
      senderBinding: metadata.senderBinding,
      recipientBinding: metadata.recipientBinding,
      epoch: metadata.epoch,
      messageCounter: metadata.messageCounter,
      content: content,
      contentDigest: _deriveContentDigest(
        assemblyDigest,
        epoch: metadata.epoch,
        messageCounter: metadata.messageCounter,
        content: content,
      ),
    );
  }

  V3CommittedRecord._({
    required this.suite,
    required this.kind,
    required Uint8List assemblyDigest,
    required Uint8List sessionId,
    required Uint8List messageId,
    required Uint8List senderBinding,
    required Uint8List recipientBinding,
    required this.epoch,
    required this.messageCounter,
    required Uint8List content,
    required Uint8List contentDigest,
  })  : _assemblyDigest = Uint8List.fromList(assemblyDigest),
        _sessionId = Uint8List.fromList(sessionId),
        _messageId = Uint8List.fromList(messageId),
        _senderBinding = Uint8List.fromList(senderBinding),
        _recipientBinding = Uint8List.fromList(recipientBinding),
        _content = Uint8List.fromList(content),
        _contentDigest = Uint8List.fromList(contentDigest);

  final V3LmfSuite suite;
  final V3CommittedRecordKind kind;
  final Uint8List _assemblyDigest;
  final Uint8List _sessionId;
  final Uint8List _messageId;
  final Uint8List _senderBinding;
  final Uint8List _recipientBinding;
  final int epoch;
  final int messageCounter;
  final Uint8List _content;
  final Uint8List _contentDigest;

  bool _isWiped = false;

  bool get isWiped => _isWiped;

  String get assemblyId => base64UrlEncode(_assemblyDigest).replaceAll('=', '');

  String get stableRecordId => 'v3:$assemblyId';

  Uint8List get sessionId => Uint8List.fromList(_sessionId);
  Uint8List get messageId => Uint8List.fromList(_messageId);
  Uint8List get senderBinding => Uint8List.fromList(_senderBinding);
  Uint8List get recipientBinding => Uint8List.fromList(_recipientBinding);
  Uint8List get contentDigest => Uint8List.fromList(_contentDigest);

  Uint8List get content {
    _ensureNotWiped();
    return Uint8List.fromList(_content);
  }

  void wipeContent() {
    if (_isWiped) return;
    _content.fillRange(0, _content.length, 0);
    _isWiped = true;
  }

  void _ensureNotWiped() {
    if (_isWiped) {
      throw StateError('Layergram v3 committed record content is wiped');
    }
  }
}

/// Strict fixed-header encoding for [V3CommittedRecord].
abstract final class V3CommittedRecordCodec {
  static const List<int> magic = <int>[0x41, 0x52, 0x33]; // "AR3"
  static const int formatVersion = 2;
  static const int headerBytes = 192;
  static const int maxEncodedBytes =
      headerBytes + V3LmfFrameCodec.maxAssembledPlaintextBytes;

  static Uint8List encode(V3CommittedRecord record) {
    record._ensureNotWiped();
    final totalLength = headerBytes + record._content.length;
    if (totalLength > maxEncodedBytes) {
      throw StateError('Layergram v3 committed record exceeds limit');
    }
    final result = Uint8List(totalLength);
    final data = ByteData.sublistView(result);
    var offset = 0;
    result.setRange(offset, offset + magic.length, magic);
    offset += magic.length;
    result[offset++] = formatVersion;
    result[offset++] = record.suite.wireId;
    result[offset++] = record.kind.wireId;
    result[offset++] = 0; // Reserved flags.
    result[offset++] = headerBytes;
    data.setUint32(offset, totalLength, Endian.big);
    offset += 4;
    offset = _writeBytes(result, offset, record._assemblyDigest);
    offset = _writeBytes(result, offset, record._sessionId);
    offset = _writeBytes(result, offset, record._messageId);
    offset = _writeBytes(result, offset, record._senderBinding);
    offset = _writeBytes(result, offset, record._recipientBinding);
    data.setUint64(offset, record.epoch, Endian.big);
    offset += 8;
    data.setUint64(offset, record.messageCounter, Endian.big);
    offset += 8;
    data.setUint32(offset, record._content.length, Endian.big);
    offset += 4;
    offset = _writeBytes(result, offset, record._contentDigest);
    if (offset != headerBytes) {
      throw StateError('Layergram v3 committed record header drift');
    }
    offset = _writeBytes(result, offset, record._content);
    if (offset != result.length) {
      throw StateError('Layergram v3 committed record encoding drift');
    }
    return result;
  }

  static V3CommittedRecord decode(Uint8List encoded) {
    if (encoded.length <= headerBytes || encoded.length > maxEncodedBytes) {
      throw const FormatException(
        'Invalid Layergram v3 committed record length',
      );
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException(
          'Invalid Layergram v3 committed record magic',
        );
      }
    }
    if (encoded[3] != formatVersion ||
        encoded[4] != V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId ||
        encoded[6] != 0 ||
        encoded[7] != headerBytes) {
      throw const FormatException(
        'Unsupported Layergram v3 committed record format',
      );
    }
    final suite = V3LmfSuite.fromWireId(encoded[4]);
    final kind = V3CommittedRecordKind.fromWireId(encoded[5]);
    final data = ByteData.sublistView(encoded);
    if (data.getUint32(8, Endian.big) != encoded.length) {
      throw const FormatException(
        'Non-canonical Layergram v3 committed record total length',
      );
    }
    var offset = 12;
    final assemblyDigest = _copyRange(encoded, offset, 32);
    offset += 32;
    final sessionId = _copyRange(encoded, offset, 16);
    offset += 16;
    final messageId = _copyRange(encoded, offset, 16);
    offset += 16;
    final senderBinding = _copyRange(encoded, offset, 32);
    offset += 32;
    final recipientBinding = _copyRange(encoded, offset, 32);
    offset += 32;
    final epoch = data.getUint64(offset, Endian.big);
    offset += 8;
    final messageCounter = data.getUint64(offset, Endian.big);
    offset += 8;
    final contentLength = data.getUint32(offset, Endian.big);
    offset += 4;
    final contentDigest = _copyRange(encoded, offset, 32);
    offset += 32;
    if (offset != headerBytes ||
        epoch < 0 ||
        epoch > 0x7fffffffffffffff ||
        messageCounter < 0 ||
        messageCounter > 0x7fffffffffffffff ||
        contentLength < 1 ||
        contentLength > V3LmfFrameCodec.maxAssembledPlaintextBytes ||
        headerBytes + contentLength != encoded.length ||
        _isAllZero(assemblyDigest) ||
        _isAllZero(sessionId) ||
        _isAllZero(messageId) ||
        _isAllZero(senderBinding) ||
        _isAllZero(recipientBinding)) {
      throw const FormatException(
        'Invalid Layergram v3 committed record fields',
      );
    }
    final content = _copyRange(encoded, offset, contentLength);
    final expectedAssembly = _deriveAssemblyDigest(
      suite: suite,
      frameKind: kind.frameKind,
      senderBinding: senderBinding,
      recipientBinding: recipientBinding,
      messageId: messageId,
      sessionId: sessionId,
    );
    final expectedContentDigest = _deriveContentDigest(
      expectedAssembly,
      epoch: epoch,
      messageCounter: messageCounter,
      content: content,
    );
    if (!_bytesEqual(assemblyDigest, expectedAssembly) ||
        !_bytesEqual(contentDigest, expectedContentDigest)) {
      content.fillRange(0, content.length, 0);
      throw const FormatException(
        'Mismatched Layergram v3 committed record digest',
      );
    }
    final record = V3CommittedRecord._(
      suite: suite,
      kind: kind,
      assemblyDigest: assemblyDigest,
      sessionId: sessionId,
      messageId: messageId,
      senderBinding: senderBinding,
      recipientBinding: recipientBinding,
      epoch: epoch,
      messageCounter: messageCounter,
      content: content,
      contentDigest: contentDigest,
    );
    content.fillRange(0, content.length, 0);
    final canonical = encode(record);
    try {
      if (!_bytesEqual(canonical, encoded)) {
        record.wipeContent();
        throw const FormatException(
          'Non-canonical Layergram v3 committed record',
        );
      }
    } finally {
      canonical.fillRange(0, canonical.length, 0);
    }
    return record;
  }
}

Uint8List _deriveAssemblyDigest({
  required V3LmfSuite suite,
  required V3LmfFrameKind frameKind,
  required Uint8List senderBinding,
  required Uint8List recipientBinding,
  required Uint8List messageId,
  required Uint8List sessionId,
}) {
  return Uint8List.fromList(
    crypto.sha256.convert(<int>[
      ...utf8.encode('layergram/v3/lmf/assembly-id\u0000'),
      suite.wireId,
      frameKind.wireId,
      ...senderBinding,
      ...recipientBinding,
      ...messageId,
      ...sessionId,
    ]).bytes,
  );
}

Uint8List _deriveContentDigest(
  Uint8List assemblyDigest, {
  required int epoch,
  required int messageCounter,
  required Uint8List content,
}) {
  final counters = ByteData(16)
    ..setUint64(0, epoch, Endian.big)
    ..setUint64(8, messageCounter, Endian.big);
  return Uint8List.fromList(
    crypto.sha256.convert(<int>[
      ...utf8.encode('layergram/v3/committed-record/content\u0000'),
      ...assemblyDigest,
      ...counters.buffer.asUint8List(),
      ...content,
    ]).bytes,
  );
}

Uint8List _copyRange(Uint8List source, int offset, int length) =>
    Uint8List.fromList(source.sublist(offset, offset + length));

int _writeBytes(Uint8List target, int offset, List<int> value) {
  target.setRange(offset, offset + value.length, value);
  return offset + value.length;
}

bool _isAllZero(List<int> bytes) {
  var accumulator = 0;
  for (final byte in bytes) {
    accumulator |= byte;
  }
  return accumulator == 0;
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
