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

import 'lmf_v3.dart';

/// Canonical user-message plaintext carried inside an authenticated TR3 frame.
///
/// The same [messageId] and payload bytes are sealed independently for every
/// selected remote device. This gives the application one stable logical
/// message identity without sharing a message key or ratchet state across
/// devices.
final class V3ApplicationPayload {
  factory V3ApplicationPayload({
    required Uint8List messageId,
    required Uint8List senderIdentityDigest,
    required Uint8List recipientIdentityDigest,
    required String text,
    required int timestampUnixSeconds,
    String senderDisplayName = '',
    int? expireAfterUnixSeconds,
    bool deleteAfterRead = false,
    bool backupExcluded = false,
  }) {
    _validateCounter(timestampUnixSeconds, 'timestampUnixSeconds');
    final expiry = expireAfterUnixSeconds;
    if (expiry != null) {
      _validateCounter(expiry, 'expireAfterUnixSeconds');
      if (expiry <= timestampUnixSeconds) {
        throw ArgumentError.value(
          expiry,
          'expireAfterUnixSeconds',
          'must be later than the message timestamp',
        );
      }
    }
    final nameBytes = _validatedUtf8(
      senderDisplayName,
      V3ApplicationPayloadCodec.maxDisplayNameBytes,
      'senderDisplayName',
      allowEmpty: true,
    );
    final textBytes = _validatedUtf8(
      text,
      V3ApplicationPayloadCodec.maxTextBytes,
      'text',
      allowEmpty: false,
    );
    Uint8List? checkedMessageId;
    Uint8List? checkedSender;
    Uint8List? checkedRecipient;
    try {
      checkedMessageId = _validatedBytes(
        messageId,
        V3ApplicationPayloadCodec.messageIdBytes,
        'messageId',
      );
      checkedSender = _validatedBytes(
        senderIdentityDigest,
        V3ApplicationPayloadCodec.identityDigestBytes,
        'senderIdentityDigest',
      );
      checkedRecipient = _validatedBytes(
        recipientIdentityDigest,
        V3ApplicationPayloadCodec.identityDigestBytes,
        'recipientIdentityDigest',
      );
      final result = V3ApplicationPayload._(
        messageId: checkedMessageId,
        senderIdentityDigest: checkedSender,
        recipientIdentityDigest: checkedRecipient,
        text: text,
        timestampUnixSeconds: timestampUnixSeconds,
        senderDisplayName: senderDisplayName,
        expireAfterUnixSeconds: expireAfterUnixSeconds,
        deleteAfterRead: deleteAfterRead,
        backupExcluded: backupExcluded,
      );
      checkedMessageId = null;
      checkedSender = null;
      checkedRecipient = null;
      return result;
    } finally {
      _wipe(nameBytes);
      _wipe(textBytes);
      if (checkedMessageId != null) _wipe(checkedMessageId);
      if (checkedSender != null) _wipe(checkedSender);
      if (checkedRecipient != null) _wipe(checkedRecipient);
    }
  }

  const V3ApplicationPayload._({
    required Uint8List messageId,
    required Uint8List senderIdentityDigest,
    required Uint8List recipientIdentityDigest,
    required this.text,
    required this.timestampUnixSeconds,
    required this.senderDisplayName,
    required this.expireAfterUnixSeconds,
    required this.deleteAfterRead,
    required this.backupExcluded,
  })  : _messageId = messageId,
        _senderIdentityDigest = senderIdentityDigest,
        _recipientIdentityDigest = recipientIdentityDigest;

  final Uint8List _messageId;
  final Uint8List _senderIdentityDigest;
  final Uint8List _recipientIdentityDigest;
  final String text;
  final int timestampUnixSeconds;
  final String senderDisplayName;
  final int? expireAfterUnixSeconds;
  final bool deleteAfterRead;
  final bool backupExcluded;

  Uint8List get messageId => Uint8List.fromList(_messageId);
  Uint8List get senderIdentityDigest =>
      Uint8List.fromList(_senderIdentityDigest);
  Uint8List get recipientIdentityDigest =>
      Uint8List.fromList(_recipientIdentityDigest);

  String get stableMessageId => base64UrlEncode(_messageId).replaceAll('=', '');
}

/// Strict AP3 application-payload encoding.
abstract final class V3ApplicationPayloadCodec {
  static const List<int> magic = <int>[0x41, 0x50, 0x33]; // "AP3"
  static const int formatVersion = 1;
  static const int messageIdBytes = 16;
  static const int identityDigestBytes = 48;
  static const int headerBytes = 144;
  static const int maxDisplayNameBytes = 32;
  static const int maxEncodedBytes = V3LmfFrameCodec.maxAssembledPlaintextBytes;
  static const int maxTextBytes =
      maxEncodedBytes - headerBytes - maxDisplayNameBytes;

  static const int _deleteAfterReadFlag = 1 << 0;
  static const int _backupExcludedFlag = 1 << 1;
  static const int _knownFlags = _deleteAfterReadFlag | _backupExcludedFlag;

  static Uint8List encode(V3ApplicationPayload payload) {
    final name = _validatedUtf8(
      payload.senderDisplayName,
      maxDisplayNameBytes,
      'senderDisplayName',
      allowEmpty: true,
    );
    final text = _validatedUtf8(
      payload.text,
      maxTextBytes,
      'text',
      allowEmpty: false,
    );
    try {
      final totalLength = headerBytes + name.length + text.length;
      if (totalLength > maxEncodedBytes) {
        throw ArgumentError('Layergram v3 application payload is too large');
      }
      final encoded = Uint8List(totalLength);
      final data = ByteData.sublistView(encoded);
      var offset = 0;
      encoded.setRange(offset, offset + magic.length, magic);
      offset += magic.length;
      encoded[offset++] = formatVersion;
      var flags = 0;
      if (payload.deleteAfterRead) flags |= _deleteAfterReadFlag;
      if (payload.backupExcluded) flags |= _backupExcludedFlag;
      encoded[offset++] = flags;
      encoded[offset++] = name.length;
      data.setUint16(offset, 0, Endian.big);
      offset += 2;
      data.setUint32(offset, totalLength, Endian.big);
      offset += 4;
      encoded.setRange(offset, offset + messageIdBytes, payload._messageId);
      offset += messageIdBytes;
      encoded.setRange(
        offset,
        offset + identityDigestBytes,
        payload._senderIdentityDigest,
      );
      offset += identityDigestBytes;
      encoded.setRange(
        offset,
        offset + identityDigestBytes,
        payload._recipientIdentityDigest,
      );
      offset += identityDigestBytes;
      data.setUint64(offset, payload.timestampUnixSeconds, Endian.big);
      offset += 8;
      data.setUint64(offset, payload.expireAfterUnixSeconds ?? 0, Endian.big);
      offset += 8;
      data.setUint32(offset, text.length, Endian.big);
      offset += 4;
      if (offset != headerBytes) {
        throw StateError('Layergram v3 application payload header drift');
      }
      encoded.setRange(offset, offset + name.length, name);
      offset += name.length;
      encoded.setRange(offset, offset + text.length, text);
      return encoded;
    } finally {
      _wipe(name);
      _wipe(text);
    }
  }

  static V3ApplicationPayload decode(Uint8List encoded) {
    if (encoded.length <= headerBytes || encoded.length > maxEncodedBytes) {
      throw const FormatException(
        'Invalid Layergram v3 application payload length',
      );
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException(
          'Invalid Layergram v3 application payload magic',
        );
      }
    }
    final flags = encoded[4];
    final nameLength = encoded[5];
    final data = ByteData.sublistView(encoded);
    final totalLength = data.getUint32(8, Endian.big);
    if (encoded[3] != formatVersion ||
        flags & ~_knownFlags != 0 ||
        nameLength > maxDisplayNameBytes ||
        data.getUint16(6, Endian.big) != 0 ||
        totalLength != encoded.length) {
      throw const FormatException(
        'Invalid Layergram v3 application payload header',
      );
    }
    var offset = 12;
    final messageId = _copyRange(encoded, offset, messageIdBytes);
    offset += messageIdBytes;
    final sender = _copyRange(encoded, offset, identityDigestBytes);
    offset += identityDigestBytes;
    final recipient = _copyRange(encoded, offset, identityDigestBytes);
    offset += identityDigestBytes;
    try {
      final timestamp = data.getUint64(offset, Endian.big);
      offset += 8;
      final rawExpiry = data.getUint64(offset, Endian.big);
      offset += 8;
      final textLength = data.getUint32(offset, Endian.big);
      offset += 4;
      if (offset != headerBytes ||
          timestamp < 0 ||
          timestamp > _maxCounter ||
          rawExpiry < 0 ||
          rawExpiry > _maxCounter ||
          (rawExpiry != 0 && rawExpiry <= timestamp) ||
          textLength < 1 ||
          textLength > maxTextBytes ||
          headerBytes + nameLength + textLength != encoded.length ||
          _isAllZero(messageId) ||
          _isAllZero(sender) ||
          _isAllZero(recipient)) {
        throw const FormatException(
          'Invalid Layergram v3 application payload fields',
        );
      }
      late final String displayName;
      late final String text;
      try {
        displayName = utf8.decode(
          encoded.sublist(offset, offset + nameLength),
          allowMalformed: false,
        );
        offset += nameLength;
        text = utf8.decode(
          encoded.sublist(offset, offset + textLength),
          allowMalformed: false,
        );
      } on FormatException {
        throw const FormatException(
          'Invalid Layergram v3 application payload UTF-8',
        );
      }
      final payload = V3ApplicationPayload(
        messageId: messageId,
        senderIdentityDigest: sender,
        recipientIdentityDigest: recipient,
        text: text,
        timestampUnixSeconds: timestamp,
        senderDisplayName: displayName,
        expireAfterUnixSeconds: rawExpiry == 0 ? null : rawExpiry,
        deleteAfterRead: flags & _deleteAfterReadFlag != 0,
        backupExcluded: flags & _backupExcludedFlag != 0,
      );
      final canonical = encode(payload);
      try {
        if (!_bytesEqual(canonical, encoded)) {
          throw const FormatException(
            'Non-canonical Layergram v3 application payload',
          );
        }
      } finally {
        _wipe(canonical);
      }
      return payload;
    } finally {
      _wipe(messageId);
      _wipe(sender);
      _wipe(recipient);
    }
  }
}

const int _maxCounter = 0x7fffffffffffffff;

Uint8List _validatedBytes(
  Uint8List value,
  int expectedLength,
  String name,
) {
  if (value.length != expectedLength || _isAllZero(value)) {
    throw ArgumentError.value(value.length, name);
  }
  return Uint8List.fromList(value);
}

Uint8List _validatedUtf8(
  String value,
  int maximumBytes,
  String name, {
  required bool allowEmpty,
}) {
  final bytes = Uint8List.fromList(utf8.encode(value));
  if ((!allowEmpty && bytes.isEmpty) || bytes.length > maximumBytes) {
    throw ArgumentError.value(bytes.length, name);
  }
  return bytes;
}

void _validateCounter(int value, String name) {
  if (value < 0 || value > _maxCounter) {
    throw ArgumentError.value(value, name);
  }
}

Uint8List _copyRange(Uint8List value, int offset, int length) =>
    Uint8List.fromList(value.sublist(offset, offset + length));

bool _isAllZero(List<int> value) {
  var accumulator = 0;
  for (final byte in value) {
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

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
