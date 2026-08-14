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

import 'ec_double_ratchet_v3.dart';

/// Wire identifier shared by the inactive v3 hybrid codecs.
const int v3HybridSuiteWireId = 1;

/// Public SCKA message carried alongside one EC Double Ratchet header.
///
/// [nativePayload] is the canonical public message emitted by the future
/// reviewed ML-KEM Braid backend. It is not a serialized private state. The
/// visible epoch and PQ message counter let the receiver select the exact PQ
/// chain key before authenticating the enclosing LMF message.
final class V3SckaMessage {
  factory V3SckaMessage({
    required int sendingEpoch,
    required int messageCounter,
    required Uint8List nativePayload,
  }) {
    _validateCounter(sendingEpoch, 'sendingEpoch');
    _validateCounter(messageCounter, 'messageCounter');
    if (nativePayload.length > V3SckaMessageCodec.maxNativePayloadBytes) {
      throw ArgumentError.value(
        nativePayload.length,
        'nativePayload.length',
        'must not exceed ${V3SckaMessageCodec.maxNativePayloadBytes} bytes',
      );
    }
    return V3SckaMessage._(
      sendingEpoch: sendingEpoch,
      messageCounter: messageCounter,
      nativePayload: Uint8List.fromList(nativePayload),
    );
  }

  V3SckaMessage._({
    required this.sendingEpoch,
    required this.messageCounter,
    required Uint8List nativePayload,
  }) : _nativePayload = nativePayload;

  final int sendingEpoch;
  final int messageCounter;
  final Uint8List _nativePayload;

  Uint8List get nativePayload => Uint8List.fromList(_nativePayload);
}

/// Strict envelope around the backend-owned public SCKA message.
abstract final class V3SckaMessageCodec {
  static const List<int> magic = <int>[0x53, 0x4b, 0x33]; // "SK3"
  static const int formatVersion = 1;
  static const int headerBytes = 24;
  static const int maxNativePayloadBytes = 512;
  static const int maxEncodedBytes = headerBytes + maxNativePayloadBytes;

  static Uint8List encode(V3SckaMessage message) {
    final totalLength = headerBytes + message._nativePayload.length;
    final result = Uint8List(totalLength);
    final data = ByteData.sublistView(result);
    result.setRange(0, magic.length, magic);
    result[3] = formatVersion;
    result[4] = v3HybridSuiteWireId;
    result[5] = 0;
    data.setUint16(6, totalLength, Endian.big);
    data.setUint64(8, message.sendingEpoch, Endian.big);
    data.setUint64(16, message.messageCounter, Endian.big);
    result.setRange(headerBytes, totalLength, message._nativePayload);
    return result;
  }

  static V3SckaMessage decode(Uint8List encoded) {
    if (encoded.length < headerBytes || encoded.length > maxEncodedBytes) {
      throw const FormatException('Invalid Layergram v3 SCKA message length');
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException('Invalid Layergram v3 SCKA message magic');
      }
    }
    final data = ByteData.sublistView(encoded);
    if (encoded[3] != formatVersion ||
        encoded[4] != v3HybridSuiteWireId ||
        encoded[5] != 0 ||
        data.getUint16(6, Endian.big) != encoded.length) {
      throw const FormatException(
        'Unsupported Layergram v3 SCKA message format',
      );
    }
    try {
      return V3SckaMessage(
        sendingEpoch: data.getUint64(8, Endian.big),
        messageCounter: data.getUint64(16, Endian.big),
        nativePayload: Uint8List.fromList(encoded.sublist(headerBytes)),
      );
    } on ArgumentError catch (error) {
      throw FormatException('Invalid Layergram v3 SCKA message fields', error);
    }
  }
}

/// Canonical public Triple Ratchet header containing both mandatory branches.
///
/// The exact encoded bytes are carried by the first LMF fragment and bound by
/// every fragment's AEAD associated data. Encoding this object without that
/// authentication does not authorize a state transition.
final class V3HybridRatchetHeader {
  const V3HybridRatchetHeader({
    required this.ecHeader,
    required this.sckaMessage,
  });

  final V3EcRatchetHeader ecHeader;
  final V3SckaMessage sckaMessage;
}

/// Strict container for the EC and sparse-PQ public ratchet messages.
abstract final class V3HybridRatchetHeaderCodec {
  static const List<int> magic = <int>[0x48, 0x52, 0x33]; // "HR3"
  static const int formatVersion = 1;
  static const int headerBytes = 16;
  static const int minEncodedBytes = headerBytes +
      V3EcRatchetHeaderCodec.encodedBytes +
      V3SckaMessageCodec.headerBytes;
  static const int maxEncodedBytes = headerBytes +
      V3EcRatchetHeaderCodec.encodedBytes +
      V3SckaMessageCodec.maxEncodedBytes;

  static Uint8List encode(V3HybridRatchetHeader header) {
    final ec = V3EcRatchetHeaderCodec.encode(header.ecHeader);
    final scka = V3SckaMessageCodec.encode(header.sckaMessage);
    final totalLength = headerBytes + ec.length + scka.length;
    final result = Uint8List(totalLength);
    final data = ByteData.sublistView(result);
    result.setRange(0, magic.length, magic);
    result[3] = formatVersion;
    result[4] = v3HybridSuiteWireId;
    result[5] = 0;
    data.setUint16(6, headerBytes, Endian.big);
    data.setUint16(8, totalLength, Endian.big);
    data.setUint16(10, ec.length, Endian.big);
    data.setUint16(12, scka.length, Endian.big);
    data.setUint16(14, 0, Endian.big);
    result.setRange(headerBytes, headerBytes + ec.length, ec);
    result.setRange(headerBytes + ec.length, totalLength, scka);
    return result;
  }

  static V3HybridRatchetHeader decode(Uint8List encoded) {
    if (encoded.length < minEncodedBytes || encoded.length > maxEncodedBytes) {
      throw const FormatException(
        'Invalid Layergram v3 hybrid ratchet header length',
      );
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException(
          'Invalid Layergram v3 hybrid ratchet header magic',
        );
      }
    }
    final data = ByteData.sublistView(encoded);
    final ecLength = data.getUint16(10, Endian.big);
    final sckaLength = data.getUint16(12, Endian.big);
    if (encoded[3] != formatVersion ||
        encoded[4] != v3HybridSuiteWireId ||
        encoded[5] != 0 ||
        data.getUint16(6, Endian.big) != headerBytes ||
        data.getUint16(8, Endian.big) != encoded.length ||
        ecLength != V3EcRatchetHeaderCodec.encodedBytes ||
        sckaLength < V3SckaMessageCodec.headerBytes ||
        sckaLength > V3SckaMessageCodec.maxEncodedBytes ||
        data.getUint16(14, Endian.big) != 0 ||
        headerBytes + ecLength + sckaLength != encoded.length) {
      throw const FormatException(
        'Unsupported Layergram v3 hybrid ratchet header format',
      );
    }
    final ecEnd = headerBytes + ecLength;
    return V3HybridRatchetHeader(
      ecHeader: V3EcRatchetHeaderCodec.decode(
        Uint8List.fromList(encoded.sublist(headerBytes, ecEnd)),
      ),
      sckaMessage: V3SckaMessageCodec.decode(
        Uint8List.fromList(encoded.sublist(ecEnd)),
      ),
    );
  }
}

void _validateCounter(int value, String name) {
  if (value < 0 || value > 0x7fffffffffffffff) {
    throw ArgumentError.value(value, name);
  }
}
