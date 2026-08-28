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

part of 'local_identity_v3.dart';

/// Security mode committed by one protocol-v3 handshake.
enum V3HandshakeMode {
  normal(1),
  maximum(2);

  const V3HandshakeMode(this.wireId);

  final int wireId;

  static V3HandshakeMode fromWireId(int wireId) {
    for (final value in values) {
      if (value.wireId == wireId) return value;
    }
    throw const FormatException('Unsupported Layergram v3 handshake mode');
  }
}

enum V3HandshakeRecordKind {
  offer(1),
  reply(2),
  confirmation(3);

  const V3HandshakeRecordKind(this.wireId);

  final int wireId;

  static V3HandshakeRecordKind fromWireId(int wireId) {
    for (final value in values) {
      if (value.wireId == wireId) return value;
    }
    throw const FormatException('Unsupported Layergram v3 handshake record');
  }
}

/// One installation-scoped X25519 device key.
///
/// It is intentionally independent from the BIP39 identity. A reinstall or a
/// second device must create a different seed, public key, and derived device
/// identifier. The seed remains managed-memory material and is overwritten on
/// [close] as a best effort.
final class V3LocalDeviceHandle {
  V3LocalDeviceHandle._({
    required Uint8List privateSeed,
    required Uint8List publicKey,
  })  : _privateSeed = Uint8List.fromList(privateSeed),
        _publicKey = Uint8List.fromList(publicKey),
        _deviceId = _V3HandshakePrimitives.deviceId(publicKey);

  final Uint8List _privateSeed;
  final Uint8List _publicKey;
  final Uint8List _deviceId;
  bool _isClosed = false;

  bool get isClosed => _isClosed;

  Uint8List get publicKey => Uint8List.fromList(_publicKey);

  Uint8List get deviceId => Uint8List.fromList(_deviceId);

  static Future<V3LocalDeviceHandle> generate() async {
    final pair = await _V3HandshakePrimitives.x25519.newKeyPair();
    final privateSeed = Uint8List.fromList(
      await pair.extractPrivateKeyBytes(),
    );
    try {
      return fromSeed(privateSeed);
    } finally {
      _wipeV3HandshakeBytes(privateSeed);
    }
  }

  /// Restores an installation device key from encrypted local state.
  static Future<V3LocalDeviceHandle> fromSeed(Uint8List privateSeed) async {
    final checked = _copyV3HandshakeBytes(
      privateSeed,
      32,
      'privateSeed',
      rejectAllZero: true,
    );
    try {
      final publicKey = await _V3HandshakePrimitives.publicKey(checked);
      return V3LocalDeviceHandle._(
        privateSeed: checked,
        publicKey: publicKey,
      );
    } finally {
      _wipeV3HandshakeBytes(checked);
    }
  }

  void close() {
    if (_isClosed) return;
    _wipeV3HandshakeBytes(_privateSeed);
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 device handle is closed');
    }
  }
}

/// Canonical `offer` record. All byte-array accessors return copies.
final class V3HandshakeOffer {
  V3HandshakeOffer._({
    required this.mode,
    required this.capabilities,
    required Uint8List handshakeId,
    required Uint8List messageId,
    required Uint8List initiatorIdentityDigest,
    required Uint8List responderIdentityDigest,
    required Uint8List initiatorDeviceId,
    required Uint8List initiatorDevicePublicKey,
    required Uint8List initiatorEphemeralPublicKey,
    required Uint8List initiatorToResponderCiphertext,
  })  : _handshakeId = Uint8List.fromList(handshakeId),
        _messageId = Uint8List.fromList(messageId),
        _initiatorIdentityDigest = Uint8List.fromList(initiatorIdentityDigest),
        _responderIdentityDigest = Uint8List.fromList(responderIdentityDigest),
        _initiatorDeviceId = Uint8List.fromList(initiatorDeviceId),
        _initiatorDevicePublicKey =
            Uint8List.fromList(initiatorDevicePublicKey),
        _initiatorEphemeralPublicKey =
            Uint8List.fromList(initiatorEphemeralPublicKey),
        _initiatorToResponderCiphertext =
            Uint8List.fromList(initiatorToResponderCiphertext);

  final V3HandshakeMode mode;
  final int capabilities;
  final Uint8List _handshakeId;
  final Uint8List _messageId;
  final Uint8List _initiatorIdentityDigest;
  final Uint8List _responderIdentityDigest;
  final Uint8List _initiatorDeviceId;
  final Uint8List _initiatorDevicePublicKey;
  final Uint8List _initiatorEphemeralPublicKey;
  final Uint8List _initiatorToResponderCiphertext;

  Uint8List get handshakeId => Uint8List.fromList(_handshakeId);
  Uint8List get messageId => Uint8List.fromList(_messageId);
  Uint8List get initiatorIdentityDigest =>
      Uint8List.fromList(_initiatorIdentityDigest);
  Uint8List get responderIdentityDigest =>
      Uint8List.fromList(_responderIdentityDigest);
  Uint8List get initiatorDeviceId => Uint8List.fromList(_initiatorDeviceId);
  Uint8List get initiatorDevicePublicKey =>
      Uint8List.fromList(_initiatorDevicePublicKey);
  Uint8List get initiatorEphemeralPublicKey =>
      Uint8List.fromList(_initiatorEphemeralPublicKey);
  Uint8List get initiatorToResponderCiphertext =>
      Uint8List.fromList(_initiatorToResponderCiphertext);
}

/// Canonical `reply` record. [proof] is a symmetric hybrid key-confirmation
/// tag, not a publicly verifiable signature.
final class V3HandshakeReply {
  V3HandshakeReply._({
    required this.mode,
    required this.capabilities,
    required Uint8List handshakeId,
    required Uint8List messageId,
    required Uint8List offerMessageId,
    required Uint8List initiatorIdentityDigest,
    required Uint8List responderIdentityDigest,
    required Uint8List initiatorDeviceId,
    required Uint8List responderDeviceId,
    required Uint8List responderDevicePublicKey,
    required Uint8List responderEphemeralPublicKey,
    required Uint8List responderInitialRatchetPublicKey,
    required Uint8List responderToInitiatorCiphertext,
    required Uint8List proof,
  })  : _handshakeId = Uint8List.fromList(handshakeId),
        _messageId = Uint8List.fromList(messageId),
        _offerMessageId = Uint8List.fromList(offerMessageId),
        _initiatorIdentityDigest = Uint8List.fromList(initiatorIdentityDigest),
        _responderIdentityDigest = Uint8List.fromList(responderIdentityDigest),
        _initiatorDeviceId = Uint8List.fromList(initiatorDeviceId),
        _responderDeviceId = Uint8List.fromList(responderDeviceId),
        _responderDevicePublicKey =
            Uint8List.fromList(responderDevicePublicKey),
        _responderEphemeralPublicKey =
            Uint8List.fromList(responderEphemeralPublicKey),
        _responderInitialRatchetPublicKey =
            Uint8List.fromList(responderInitialRatchetPublicKey),
        _responderToInitiatorCiphertext =
            Uint8List.fromList(responderToInitiatorCiphertext),
        _proof = Uint8List.fromList(proof);

  final V3HandshakeMode mode;
  final int capabilities;
  final Uint8List _handshakeId;
  final Uint8List _messageId;
  final Uint8List _offerMessageId;
  final Uint8List _initiatorIdentityDigest;
  final Uint8List _responderIdentityDigest;
  final Uint8List _initiatorDeviceId;
  final Uint8List _responderDeviceId;
  final Uint8List _responderDevicePublicKey;
  final Uint8List _responderEphemeralPublicKey;
  final Uint8List _responderInitialRatchetPublicKey;
  final Uint8List _responderToInitiatorCiphertext;
  final Uint8List _proof;

  Uint8List get handshakeId => Uint8List.fromList(_handshakeId);
  Uint8List get messageId => Uint8List.fromList(_messageId);
  Uint8List get offerMessageId => Uint8List.fromList(_offerMessageId);
  Uint8List get initiatorIdentityDigest =>
      Uint8List.fromList(_initiatorIdentityDigest);
  Uint8List get responderIdentityDigest =>
      Uint8List.fromList(_responderIdentityDigest);
  Uint8List get initiatorDeviceId => Uint8List.fromList(_initiatorDeviceId);
  Uint8List get responderDeviceId => Uint8List.fromList(_responderDeviceId);
  Uint8List get responderDevicePublicKey =>
      Uint8List.fromList(_responderDevicePublicKey);
  Uint8List get responderEphemeralPublicKey =>
      Uint8List.fromList(_responderEphemeralPublicKey);
  Uint8List get responderInitialRatchetPublicKey =>
      Uint8List.fromList(_responderInitialRatchetPublicKey);
  Uint8List get responderToInitiatorCiphertext =>
      Uint8List.fromList(_responderToInitiatorCiphertext);
  Uint8List get proof => Uint8List.fromList(_proof);
}

/// Canonical `confirmation` record and initiator hybrid key confirmation.
final class V3HandshakeConfirmation {
  V3HandshakeConfirmation._({
    required this.mode,
    required this.capabilities,
    required Uint8List handshakeId,
    required Uint8List messageId,
    required Uint8List offerMessageId,
    required Uint8List replyMessageId,
    required Uint8List initiatorIdentityDigest,
    required Uint8List responderIdentityDigest,
    required Uint8List initiatorDeviceId,
    required Uint8List responderDeviceId,
    required Uint8List initiatorInitialRatchetPublicKey,
    required Uint8List replyTranscriptDigest,
    required Uint8List proof,
  })  : _handshakeId = Uint8List.fromList(handshakeId),
        _messageId = Uint8List.fromList(messageId),
        _offerMessageId = Uint8List.fromList(offerMessageId),
        _replyMessageId = Uint8List.fromList(replyMessageId),
        _initiatorIdentityDigest = Uint8List.fromList(initiatorIdentityDigest),
        _responderIdentityDigest = Uint8List.fromList(responderIdentityDigest),
        _initiatorDeviceId = Uint8List.fromList(initiatorDeviceId),
        _responderDeviceId = Uint8List.fromList(responderDeviceId),
        _initiatorInitialRatchetPublicKey =
            Uint8List.fromList(initiatorInitialRatchetPublicKey),
        _replyTranscriptDigest = Uint8List.fromList(replyTranscriptDigest),
        _proof = Uint8List.fromList(proof);

  final V3HandshakeMode mode;
  final int capabilities;
  final Uint8List _handshakeId;
  final Uint8List _messageId;
  final Uint8List _offerMessageId;
  final Uint8List _replyMessageId;
  final Uint8List _initiatorIdentityDigest;
  final Uint8List _responderIdentityDigest;
  final Uint8List _initiatorDeviceId;
  final Uint8List _responderDeviceId;
  final Uint8List _initiatorInitialRatchetPublicKey;
  final Uint8List _replyTranscriptDigest;
  final Uint8List _proof;

  Uint8List get handshakeId => Uint8List.fromList(_handshakeId);
  Uint8List get messageId => Uint8List.fromList(_messageId);
  Uint8List get offerMessageId => Uint8List.fromList(_offerMessageId);
  Uint8List get replyMessageId => Uint8List.fromList(_replyMessageId);
  Uint8List get initiatorIdentityDigest =>
      Uint8List.fromList(_initiatorIdentityDigest);
  Uint8List get responderIdentityDigest =>
      Uint8List.fromList(_responderIdentityDigest);
  Uint8List get initiatorDeviceId => Uint8List.fromList(_initiatorDeviceId);
  Uint8List get responderDeviceId => Uint8List.fromList(_responderDeviceId);
  Uint8List get initiatorInitialRatchetPublicKey =>
      Uint8List.fromList(_initiatorInitialRatchetPublicKey);
  Uint8List get replyTranscriptDigest =>
      Uint8List.fromList(_replyTranscriptDigest);
  Uint8List get proof => Uint8List.fromList(_proof);
}

/// Strict fixed-layout codec for all three handshake records.
abstract final class V3HandshakeCodec {
  static const int formatVersion = 1;
  static const int requiredCapabilities = 0x0000001f;
  static const int commonHeaderBytes = 20;
  static const int digestBytes = 48;
  static const int idBytes = 16;
  static const int x25519PublicKeyBytes = 32;
  static const int proofBytes = 32;
  static const int offerBytes = 1316;
  static const int replyBodyBytes = 1380;
  static const int replyBytes = 1412;
  static const int confirmationBodyBytes = 292;
  static const int confirmationBytes = 324;
  static const List<int> magic = <int>[0x48, 0x48, 0x33]; // HH3

  static Uint8List encodeOffer(V3HandshakeOffer value) {
    final output = Uint8List(offerBytes);
    _writeCommon(
      output,
      kind: V3HandshakeRecordKind.offer,
      mode: value.mode,
      totalLength: offerBytes,
      capabilities: value.capabilities,
    );
    var offset = 20;
    offset = _put(output, offset, value._handshakeId);
    offset = _put(output, offset, value._messageId);
    offset = _put(output, offset, value._initiatorIdentityDigest);
    offset = _put(output, offset, value._responderIdentityDigest);
    offset = _put(output, offset, value._initiatorDeviceId);
    offset = _put(output, offset, value._initiatorDevicePublicKey);
    offset = _put(output, offset, value._initiatorEphemeralPublicKey);
    offset = _put(output, offset, value._initiatorToResponderCiphertext);
    if (offset != offerBytes) {
      throw StateError('Layergram v3 offer layout drift');
    }
    return output;
  }

  static Uint8List encodeReply(V3HandshakeReply value) {
    final output = _encodeReplyBody(value);
    final full = Uint8List(replyBytes)..setRange(0, replyBodyBytes, output);
    full.setRange(replyBodyBytes, replyBytes, value._proof);
    return full;
  }

  static Uint8List encodeConfirmation(V3HandshakeConfirmation value) {
    final output = _encodeConfirmationBody(value);
    final full = Uint8List(confirmationBytes)
      ..setRange(0, confirmationBodyBytes, output)
      ..setRange(confirmationBodyBytes, confirmationBytes, value._proof);
    return full;
  }

  static V3HandshakeOffer decodeOffer(Uint8List encoded) {
    _readCommon(
      encoded,
      expectedKind: V3HandshakeRecordKind.offer,
      expectedLength: offerBytes,
    );
    final mode = V3HandshakeMode.fromWireId(encoded[7]);
    final capabilities = _capabilities(encoded);
    var offset = 20;
    final handshakeId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final messageId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final initiatorIdentityDigest = _take(encoded, offset, digestBytes);
    offset += digestBytes;
    final responderIdentityDigest = _take(encoded, offset, digestBytes);
    offset += digestBytes;
    final initiatorDeviceId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final initiatorDevicePublicKey =
        _take(encoded, offset, x25519PublicKeyBytes);
    offset += x25519PublicKeyBytes;
    final initiatorEphemeralPublicKey =
        _take(encoded, offset, x25519PublicKeyBytes);
    offset += x25519PublicKeyBytes;
    final ciphertext = _take(encoded, offset, MlKem768.ciphertextBytes);
    final value = V3HandshakeOffer._(
      mode: mode,
      capabilities: capabilities,
      handshakeId: handshakeId,
      messageId: messageId,
      initiatorIdentityDigest: initiatorIdentityDigest,
      responderIdentityDigest: responderIdentityDigest,
      initiatorDeviceId: initiatorDeviceId,
      initiatorDevicePublicKey: initiatorDevicePublicKey,
      initiatorEphemeralPublicKey: initiatorEphemeralPublicKey,
      initiatorToResponderCiphertext: ciphertext,
    );
    _validateOffer(value);
    _requireCanonical(encoded, encodeOffer(value));
    return value;
  }

  static V3HandshakeReply decodeReply(Uint8List encoded) {
    _readCommon(
      encoded,
      expectedKind: V3HandshakeRecordKind.reply,
      expectedLength: replyBytes,
    );
    final mode = V3HandshakeMode.fromWireId(encoded[7]);
    final capabilities = _capabilities(encoded);
    var offset = 20;
    final handshakeId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final messageId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final offerMessageId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final initiatorIdentityDigest = _take(encoded, offset, digestBytes);
    offset += digestBytes;
    final responderIdentityDigest = _take(encoded, offset, digestBytes);
    offset += digestBytes;
    final initiatorDeviceId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final responderDeviceId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final responderDevicePublicKey =
        _take(encoded, offset, x25519PublicKeyBytes);
    offset += x25519PublicKeyBytes;
    final responderEphemeralPublicKey =
        _take(encoded, offset, x25519PublicKeyBytes);
    offset += x25519PublicKeyBytes;
    final responderRatchetPublicKey =
        _take(encoded, offset, x25519PublicKeyBytes);
    offset += x25519PublicKeyBytes;
    final ciphertext = _take(encoded, offset, MlKem768.ciphertextBytes);
    offset += MlKem768.ciphertextBytes;
    final proof = _take(encoded, offset, proofBytes);
    final value = V3HandshakeReply._(
      mode: mode,
      capabilities: capabilities,
      handshakeId: handshakeId,
      messageId: messageId,
      offerMessageId: offerMessageId,
      initiatorIdentityDigest: initiatorIdentityDigest,
      responderIdentityDigest: responderIdentityDigest,
      initiatorDeviceId: initiatorDeviceId,
      responderDeviceId: responderDeviceId,
      responderDevicePublicKey: responderDevicePublicKey,
      responderEphemeralPublicKey: responderEphemeralPublicKey,
      responderInitialRatchetPublicKey: responderRatchetPublicKey,
      responderToInitiatorCiphertext: ciphertext,
      proof: proof,
    );
    _validateReply(value);
    _requireCanonical(encoded, encodeReply(value));
    return value;
  }

  static V3HandshakeConfirmation decodeConfirmation(Uint8List encoded) {
    _readCommon(
      encoded,
      expectedKind: V3HandshakeRecordKind.confirmation,
      expectedLength: confirmationBytes,
    );
    final mode = V3HandshakeMode.fromWireId(encoded[7]);
    final capabilities = _capabilities(encoded);
    var offset = 20;
    final handshakeId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final messageId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final offerMessageId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final replyMessageId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final initiatorIdentityDigest = _take(encoded, offset, digestBytes);
    offset += digestBytes;
    final responderIdentityDigest = _take(encoded, offset, digestBytes);
    offset += digestBytes;
    final initiatorDeviceId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final responderDeviceId = _take(encoded, offset, idBytes);
    offset += idBytes;
    final initiatorRatchetPublicKey =
        _take(encoded, offset, x25519PublicKeyBytes);
    offset += x25519PublicKeyBytes;
    final replyTranscriptDigest = _take(encoded, offset, digestBytes);
    offset += digestBytes;
    final proof = _take(encoded, offset, proofBytes);
    final value = V3HandshakeConfirmation._(
      mode: mode,
      capabilities: capabilities,
      handshakeId: handshakeId,
      messageId: messageId,
      offerMessageId: offerMessageId,
      replyMessageId: replyMessageId,
      initiatorIdentityDigest: initiatorIdentityDigest,
      responderIdentityDigest: responderIdentityDigest,
      initiatorDeviceId: initiatorDeviceId,
      responderDeviceId: responderDeviceId,
      initiatorInitialRatchetPublicKey: initiatorRatchetPublicKey,
      replyTranscriptDigest: replyTranscriptDigest,
      proof: proof,
    );
    _validateConfirmation(value);
    _requireCanonical(encoded, encodeConfirmation(value));
    return value;
  }

  static Uint8List _encodeReplyBody(V3HandshakeReply value) {
    final output = Uint8List(replyBodyBytes);
    _writeCommon(
      output,
      kind: V3HandshakeRecordKind.reply,
      mode: value.mode,
      totalLength: replyBytes,
      capabilities: value.capabilities,
    );
    var offset = 20;
    offset = _put(output, offset, value._handshakeId);
    offset = _put(output, offset, value._messageId);
    offset = _put(output, offset, value._offerMessageId);
    offset = _put(output, offset, value._initiatorIdentityDigest);
    offset = _put(output, offset, value._responderIdentityDigest);
    offset = _put(output, offset, value._initiatorDeviceId);
    offset = _put(output, offset, value._responderDeviceId);
    offset = _put(output, offset, value._responderDevicePublicKey);
    offset = _put(output, offset, value._responderEphemeralPublicKey);
    offset = _put(output, offset, value._responderInitialRatchetPublicKey);
    offset = _put(output, offset, value._responderToInitiatorCiphertext);
    if (offset != replyBodyBytes) {
      throw StateError('Layergram v3 reply layout drift');
    }
    return output;
  }

  static Uint8List _encodeConfirmationBody(V3HandshakeConfirmation value) {
    final output = Uint8List(confirmationBodyBytes);
    _writeCommon(
      output,
      kind: V3HandshakeRecordKind.confirmation,
      mode: value.mode,
      totalLength: confirmationBytes,
      capabilities: value.capabilities,
    );
    var offset = 20;
    offset = _put(output, offset, value._handshakeId);
    offset = _put(output, offset, value._messageId);
    offset = _put(output, offset, value._offerMessageId);
    offset = _put(output, offset, value._replyMessageId);
    offset = _put(output, offset, value._initiatorIdentityDigest);
    offset = _put(output, offset, value._responderIdentityDigest);
    offset = _put(output, offset, value._initiatorDeviceId);
    offset = _put(output, offset, value._responderDeviceId);
    offset = _put(output, offset, value._initiatorInitialRatchetPublicKey);
    offset = _put(output, offset, value._replyTranscriptDigest);
    if (offset != confirmationBodyBytes) {
      throw StateError('Layergram v3 confirmation layout drift');
    }
    return output;
  }

  static void _writeCommon(
    Uint8List output, {
    required V3HandshakeRecordKind kind,
    required V3HandshakeMode mode,
    required int totalLength,
    required int capabilities,
  }) {
    if (capabilities != requiredCapabilities) {
      throw ArgumentError.value(
        capabilities,
        'capabilities',
        'must equal the frozen v3 capability set',
      );
    }
    output.setRange(0, magic.length, magic);
    output[3] = formatVersion;
    output[4] = V3PublicIdentityCodec.protocolVersion;
    output[5] = V3IdentitySuite.hybridX25519MlKem768.wireId;
    output[6] = kind.wireId;
    output[7] = mode.wireId;
    output[8] = 0;
    output[9] = 0;
    final data = ByteData.sublistView(output)
      ..setUint16(10, commonHeaderBytes, Endian.big)
      ..setUint32(12, totalLength, Endian.big)
      ..setUint32(16, capabilities, Endian.big);
    if (data.lengthInBytes != output.length) {
      throw StateError('Layergram v3 handshake header drift');
    }
  }

  static void _readCommon(
    Uint8List encoded, {
    required V3HandshakeRecordKind expectedKind,
    required int expectedLength,
  }) {
    if (encoded.length != expectedLength) {
      throw const FormatException('Invalid Layergram v3 handshake length');
    }
    if (!_constantTimeV3HandshakeEquals(
      Uint8List.sublistView(encoded, 0, 3),
      Uint8List.fromList(magic),
    )) {
      throw const FormatException('Invalid Layergram v3 handshake magic');
    }
    final data = ByteData.sublistView(encoded);
    if (encoded[3] != formatVersion ||
        encoded[4] != V3PublicIdentityCodec.protocolVersion ||
        encoded[5] != V3IdentitySuite.hybridX25519MlKem768.wireId ||
        encoded[6] != expectedKind.wireId ||
        encoded[8] != 0 ||
        encoded[9] != 0 ||
        data.getUint16(10, Endian.big) != commonHeaderBytes ||
        data.getUint32(12, Endian.big) != expectedLength) {
      throw const FormatException('Invalid Layergram v3 handshake header');
    }
    V3HandshakeMode.fromWireId(encoded[7]);
    if (_capabilities(encoded) != requiredCapabilities) {
      throw const FormatException('Unsupported Layergram v3 capabilities');
    }
  }

  static int _capabilities(Uint8List encoded) =>
      ByteData.sublistView(encoded).getUint32(16, Endian.big);

  static void _validateOffer(V3HandshakeOffer value) {
    _requireV3HandshakeNonZero(value._handshakeId, 'handshake ID');
    _requireV3HandshakeNonZero(value._messageId, 'offer message ID');
    _requireV3HandshakeNonZero(
      value._initiatorIdentityDigest,
      'initiator identity digest',
    );
    _requireV3HandshakeNonZero(
      value._responderIdentityDigest,
      'responder identity digest',
    );
    if (_constantTimeV3HandshakeEquals(
      value._initiatorIdentityDigest,
      value._responderIdentityDigest,
    )) {
      throw const FormatException('Layergram v3 identities must be distinct');
    }
    _requireV3HandshakeNonZero(
      value._initiatorDevicePublicKey,
      'initiator device key',
    );
    _requireV3HandshakeNonZero(
      value._initiatorEphemeralPublicKey,
      'initiator ephemeral key',
    );
    _requireV3HandshakeNonZero(
      value._initiatorToResponderCiphertext,
      'initiator ML-KEM ciphertext',
    );
    final expectedDeviceId =
        _V3HandshakePrimitives.deviceId(value._initiatorDevicePublicKey);
    final expectedHandshakeId = _V3HandshakePrimitives.offerHandshakeId(
      mode: value.mode,
      capabilities: value.capabilities,
      initiatorIdentityDigest: value._initiatorIdentityDigest,
      responderIdentityDigest: value._responderIdentityDigest,
      initiatorDeviceId: value._initiatorDeviceId,
      initiatorDevicePublicKey: value._initiatorDevicePublicKey,
      initiatorEphemeralPublicKey: value._initiatorEphemeralPublicKey,
      ciphertext: value._initiatorToResponderCiphertext,
    );
    final expectedMessageId = _V3HandshakePrimitives.offerMessageId(
      handshakeId: value._handshakeId,
      initiatorEphemeralPublicKey: value._initiatorEphemeralPublicKey,
      ciphertext: value._initiatorToResponderCiphertext,
    );
    try {
      if (!_constantTimeV3HandshakeEquals(
            value._initiatorDeviceId,
            expectedDeviceId,
          ) ||
          !_constantTimeV3HandshakeEquals(
            value._handshakeId,
            expectedHandshakeId,
          ) ||
          !_constantTimeV3HandshakeEquals(
            value._messageId,
            expectedMessageId,
          )) {
        throw const FormatException(
          'Invalid Layergram v3 derived offer identifiers',
        );
      }
    } finally {
      _wipeV3HandshakeBytes(expectedDeviceId);
      _wipeV3HandshakeBytes(expectedHandshakeId);
      _wipeV3HandshakeBytes(expectedMessageId);
    }
  }

  static void _validateReply(V3HandshakeReply value) {
    for (final entry in <(Uint8List, String)>[
      (value._handshakeId, 'handshake ID'),
      (value._messageId, 'reply message ID'),
      (value._offerMessageId, 'offer message ID'),
      (value._initiatorIdentityDigest, 'initiator identity digest'),
      (value._responderIdentityDigest, 'responder identity digest'),
      (value._initiatorDeviceId, 'initiator device ID'),
      (value._responderDeviceId, 'responder device ID'),
      (value._responderDevicePublicKey, 'responder device key'),
      (value._responderEphemeralPublicKey, 'responder ephemeral key'),
      (value._responderInitialRatchetPublicKey, 'responder ratchet key'),
      (value._responderToInitiatorCiphertext, 'responder ML-KEM ciphertext'),
      (value._proof, 'reply proof'),
    ]) {
      _requireV3HandshakeNonZero(entry.$1, entry.$2);
    }
    final expectedDeviceId =
        _V3HandshakePrimitives.deviceId(value._responderDevicePublicKey);
    final expectedMessageId = _V3HandshakePrimitives.replyMessageId(
      mode: value.mode,
      capabilities: value.capabilities,
      handshakeId: value._handshakeId,
      offerMessageId: value._offerMessageId,
      initiatorIdentityDigest: value._initiatorIdentityDigest,
      responderIdentityDigest: value._responderIdentityDigest,
      initiatorDeviceId: value._initiatorDeviceId,
      responderDeviceId: value._responderDeviceId,
      responderDevicePublicKey: value._responderDevicePublicKey,
      responderEphemeralPublicKey: value._responderEphemeralPublicKey,
      responderRatchetPublicKey: value._responderInitialRatchetPublicKey,
      ciphertext: value._responderToInitiatorCiphertext,
    );
    try {
      if (!_constantTimeV3HandshakeEquals(
            value._responderDeviceId,
            expectedDeviceId,
          ) ||
          !_constantTimeV3HandshakeEquals(
            value._messageId,
            expectedMessageId,
          )) {
        throw const FormatException(
          'Invalid Layergram v3 derived reply identifiers',
        );
      }
    } finally {
      _wipeV3HandshakeBytes(expectedDeviceId);
      _wipeV3HandshakeBytes(expectedMessageId);
    }
  }

  static void _validateConfirmation(V3HandshakeConfirmation value) {
    for (final entry in <(Uint8List, String)>[
      (value._handshakeId, 'handshake ID'),
      (value._messageId, 'confirmation message ID'),
      (value._offerMessageId, 'offer message ID'),
      (value._replyMessageId, 'reply message ID'),
      (value._initiatorIdentityDigest, 'initiator identity digest'),
      (value._responderIdentityDigest, 'responder identity digest'),
      (value._initiatorDeviceId, 'initiator device ID'),
      (value._responderDeviceId, 'responder device ID'),
      (value._initiatorInitialRatchetPublicKey, 'initiator ratchet key'),
      (value._replyTranscriptDigest, 'reply transcript digest'),
      (value._proof, 'confirmation proof'),
    ]) {
      _requireV3HandshakeNonZero(entry.$1, entry.$2);
    }
    final expectedMessageId = _V3HandshakePrimitives.confirmationMessageId(
      mode: value.mode,
      capabilities: value.capabilities,
      handshakeId: value._handshakeId,
      offerMessageId: value._offerMessageId,
      replyMessageId: value._replyMessageId,
      initiatorIdentityDigest: value._initiatorIdentityDigest,
      responderIdentityDigest: value._responderIdentityDigest,
      initiatorDeviceId: value._initiatorDeviceId,
      responderDeviceId: value._responderDeviceId,
      initiatorRatchetPublicKey: value._initiatorInitialRatchetPublicKey,
      replyTranscriptDigest: value._replyTranscriptDigest,
    );
    try {
      if (!_constantTimeV3HandshakeEquals(
        value._messageId,
        expectedMessageId,
      )) {
        throw const FormatException(
          'Invalid Layergram v3 confirmation message identifier',
        );
      }
    } finally {
      _wipeV3HandshakeBytes(expectedMessageId);
    }
  }
}

/// Initiator state that must remain encrypted and durable until a reply is
/// accepted. It contains one X25519 ephemeral seed and one ML-KEM secret.
final class V3InitiatorPendingHandshake {
  V3InitiatorPendingHandshake._({
    required this.offer,
    required Uint8List ephemeralPrivateSeed,
    required Uint8List initiatorToResponderSecret,
  })  : _ephemeralPrivateSeed = Uint8List.fromList(ephemeralPrivateSeed),
        _initiatorToResponderSecret =
            Uint8List.fromList(initiatorToResponderSecret);

  final V3HandshakeOffer offer;
  final Uint8List _ephemeralPrivateSeed;
  final Uint8List _initiatorToResponderSecret;
  bool _isClosed = false;

  bool get isClosed => _isClosed;

  void close() {
    if (_isClosed) return;
    _wipeV3HandshakeBytes(_ephemeralPrivateSeed);
    _wipeV3HandshakeBytes(_initiatorToResponderSecret);
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 initiator handshake state is closed');
    }
  }
}

/// Responder state retained only until the confirmation is authenticated.
final class V3ResponderPendingHandshake {
  V3ResponderPendingHandshake._({
    required this.offer,
    required this.reply,
    required Uint8List classicalSecret,
    required Uint8List postQuantumSecret,
    required Uint8List localInitialRatchetPrivateSeed,
  })  : _classicalSecret = Uint8List.fromList(classicalSecret),
        _postQuantumSecret = Uint8List.fromList(postQuantumSecret),
        _localInitialRatchetPrivateSeed =
            Uint8List.fromList(localInitialRatchetPrivateSeed);

  final V3HandshakeOffer offer;
  final V3HandshakeReply reply;
  final Uint8List _classicalSecret;
  final Uint8List _postQuantumSecret;
  final Uint8List _localInitialRatchetPrivateSeed;
  bool _isClosed = false;

  bool get isClosed => _isClosed;

  void close() {
    if (_isClosed) return;
    _wipeV3HandshakeBytes(_classicalSecret);
    _wipeV3HandshakeBytes(_postQuantumSecret);
    _wipeV3HandshakeBytes(_localInitialRatchetPrivateSeed);
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 responder handshake state is closed');
    }
  }
}

/// Complete authenticated material ready for the still-future EC/PQ ratchet
/// initializers. It is not itself an active application session.
final class V3HandshakeEstablishedMaterial {
  V3HandshakeEstablishedMaterial._({
    required this.role,
    required this.mode,
    required this.capabilities,
    required this.sessionKeys,
    required Uint8List localDeviceId,
    required Uint8List remoteDeviceId,
    required Uint8List localInitialRatchetPrivateSeed,
    required Uint8List localInitialRatchetPublicKey,
    required Uint8List remoteInitialRatchetPublicKey,
  })  : _localDeviceId = Uint8List.fromList(localDeviceId),
        _remoteDeviceId = Uint8List.fromList(remoteDeviceId),
        _localInitialRatchetPrivateSeed =
            Uint8List.fromList(localInitialRatchetPrivateSeed),
        _localInitialRatchetPublicKey =
            Uint8List.fromList(localInitialRatchetPublicKey),
        _remoteInitialRatchetPublicKey =
            Uint8List.fromList(remoteInitialRatchetPublicKey);

  final V3SessionRole role;
  final V3HandshakeMode mode;
  final int capabilities;
  final V3SessionKeyMaterial sessionKeys;
  final Uint8List _localDeviceId;
  final Uint8List _remoteDeviceId;
  final Uint8List _localInitialRatchetPrivateSeed;
  final Uint8List _localInitialRatchetPublicKey;
  final Uint8List _remoteInitialRatchetPublicKey;
  bool _isClosed = false;

  bool get isClosed => _isClosed;
  Uint8List get localDeviceId => Uint8List.fromList(_localDeviceId);
  Uint8List get remoteDeviceId => Uint8List.fromList(_remoteDeviceId);

  Uint8List get localInitialRatchetPrivateSeed {
    _ensureOpen();
    return Uint8List.fromList(_localInitialRatchetPrivateSeed);
  }

  Uint8List get localInitialRatchetPublicKey =>
      Uint8List.fromList(_localInitialRatchetPublicKey);
  Uint8List get remoteInitialRatchetPublicKey =>
      Uint8List.fromList(_remoteInitialRatchetPublicKey);

  void close() {
    if (_isClosed) return;
    _wipeV3HandshakeBytes(_localInitialRatchetPrivateSeed);
    sessionKeys.close();
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 established handshake is closed');
    }
  }
}

final class V3InitiatorHandshakeResult {
  const V3InitiatorHandshakeResult({
    required this.confirmation,
    required this.established,
  });

  final V3HandshakeConfirmation confirmation;
  final V3HandshakeEstablishedMaterial established;
}

/// Three-message authenticated hybrid handshake for protocol v3.
///
/// The proof tags are HMACs derived from both the five ordered X25519 outputs
/// and both ordered ML-KEM shared secrets. Either participant knows the MAC
/// keys after a valid run, so the wire transcript is not a transferable
/// signature. The active application runtime reaches this class only through
/// the durable HP3 controller and the all-or-nothing v3 activation selector.
abstract final class V3HybridHandshake {
  /// Deterministically resolves two crossed offers for the same identity pair.
  ///
  /// The lexicographically smaller complete canonical offer remains live. Both
  /// peers reach the same decision without trusting arrival order or a clock.
  static V3HandshakeOffer resolveSimultaneousOffers(
    V3HandshakeOffer first,
    V3HandshakeOffer second,
  ) {
    V3HandshakeCodec._validateOffer(first);
    V3HandshakeCodec._validateOffer(second);
    if (first.mode != second.mode ||
        first.capabilities != second.capabilities ||
        !_constantTimeV3HandshakeEquals(
          first._initiatorIdentityDigest,
          second._responderIdentityDigest,
        ) ||
        !_constantTimeV3HandshakeEquals(
          first._responderIdentityDigest,
          second._initiatorIdentityDigest,
        )) {
      throw const FormatException(
        'Layergram v3 simultaneous offers do not describe the same pair',
      );
    }
    final firstBytes = V3HandshakeCodec.encodeOffer(first);
    final secondBytes = V3HandshakeCodec.encodeOffer(second);
    for (var index = 0; index < firstBytes.length; index++) {
      final comparison = firstBytes[index] - secondBytes[index];
      if (comparison < 0) return first;
      if (comparison > 0) return second;
    }
    throw const FormatException('Duplicate Layergram v3 simultaneous offer');
  }

  static Future<V3InitiatorPendingHandshake> createOffer({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode mode,
  }) async {
    await _V3HandshakePrimitives.validateLocalIdentity(localIdentity);
    localDevice._ensureOpen();
    await _V3HandshakePrimitives.validateRemoteIdentity(
      localIdentity,
      remoteIdentity,
    );
    final initiatorDigest =
        _V3HandshakePrimitives.identityDigest(localIdentity.publicIdentity);
    final responderDigest =
        _V3HandshakePrimitives.identityDigest(remoteIdentity);
    Uint8List? ephemeralPrivate;
    Uint8List? ephemeralPublic;
    MlKem768Encapsulation? encapsulation;
    try {
      final ephemeralPair = await _V3HandshakePrimitives.x25519.newKeyPair();
      ephemeralPrivate = Uint8List.fromList(
        await ephemeralPair.extractPrivateKeyBytes(),
      );
      ephemeralPublic = Uint8List.fromList(
        (await ephemeralPair.extractPublicKey()).bytes,
      );
      encapsulation = await localIdentity._mlKem768Backend.encapsulate(
        remoteIdentity.mlKem768PublicKey,
      );
      _V3HandshakePrimitives.validateMlKemSecret(
        encapsulation.sharedSecret,
      );
      final deviceId = localDevice.deviceId;
      final devicePublicKey = localDevice.publicKey;
      final handshakeId = _V3HandshakePrimitives.offerHandshakeId(
        mode: mode,
        capabilities: V3HandshakeCodec.requiredCapabilities,
        initiatorIdentityDigest: initiatorDigest,
        responderIdentityDigest: responderDigest,
        initiatorDeviceId: deviceId,
        initiatorDevicePublicKey: devicePublicKey,
        initiatorEphemeralPublicKey: ephemeralPublic,
        ciphertext: encapsulation.ciphertext,
      );
      final messageId = _V3HandshakePrimitives.offerMessageId(
        handshakeId: handshakeId,
        initiatorEphemeralPublicKey: ephemeralPublic,
        ciphertext: encapsulation.ciphertext,
      );
      final offer = V3HandshakeOffer._(
        mode: mode,
        capabilities: V3HandshakeCodec.requiredCapabilities,
        handshakeId: handshakeId,
        messageId: messageId,
        initiatorIdentityDigest: initiatorDigest,
        responderIdentityDigest: responderDigest,
        initiatorDeviceId: deviceId,
        initiatorDevicePublicKey: devicePublicKey,
        initiatorEphemeralPublicKey: ephemeralPublic,
        initiatorToResponderCiphertext: encapsulation.ciphertext,
      );
      V3HandshakeCodec._validateOffer(offer);
      return V3InitiatorPendingHandshake._(
        offer: offer,
        ephemeralPrivateSeed: ephemeralPrivate,
        initiatorToResponderSecret: encapsulation.sharedSecret,
      );
    } finally {
      _wipeV3HandshakeBytes(initiatorDigest);
      _wipeV3HandshakeBytes(responderDigest);
      if (ephemeralPrivate != null) _wipeV3HandshakeBytes(ephemeralPrivate);
      if (ephemeralPublic != null) _wipeV3HandshakeBytes(ephemeralPublic);
      encapsulation?.wipeSharedSecret();
    }
  }

  static Future<V3ResponderPendingHandshake> createReply({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity initiatorIdentity,
    required V3HandshakeOffer offer,
    required V3HandshakeMode expectedMode,
  }) async {
    await _V3HandshakePrimitives.validateLocalIdentity(localIdentity);
    localDevice._ensureOpen();
    await _V3HandshakePrimitives.validateRemoteIdentity(
      localIdentity,
      initiatorIdentity,
    );
    _V3HandshakePrimitives.validateOfferContext(
      offer: offer,
      initiatorIdentity: initiatorIdentity,
      responderIdentity: localIdentity.publicIdentity,
      expectedMode: expectedMode,
    );
    Uint8List? initiatorToResponderSecret;
    MlKem768Encapsulation? responderEncapsulation;
    Uint8List? ephemeralPrivate;
    Uint8List? ephemeralPublic;
    Uint8List? ratchetPrivate;
    Uint8List? ratchetPublic;
    Uint8List? classicalSecret;
    Uint8List? postQuantumSecret;
    Uint8List? stageOne;
    Uint8List? proof;
    try {
      initiatorToResponderSecret =
          await localIdentity._mlKem768Backend.decapsulate(
        localIdentity._mlKem768PrivateKeyHandle,
        offer._initiatorToResponderCiphertext,
      );
      _V3HandshakePrimitives.validateMlKemSecret(
        initiatorToResponderSecret,
      );
      responderEncapsulation = await localIdentity._mlKem768Backend.encapsulate(
        initiatorIdentity.mlKem768PublicKey,
      );
      _V3HandshakePrimitives.validateMlKemSecret(
        responderEncapsulation.sharedSecret,
      );

      final ephemeralPair = await _V3HandshakePrimitives.x25519.newKeyPair();
      ephemeralPrivate = Uint8List.fromList(
        await ephemeralPair.extractPrivateKeyBytes(),
      );
      ephemeralPublic = Uint8List.fromList(
        (await ephemeralPair.extractPublicKey()).bytes,
      );
      final ratchetPair = await _V3HandshakePrimitives.x25519.newKeyPair();
      ratchetPrivate = Uint8List.fromList(
        await ratchetPair.extractPrivateKeyBytes(),
      );
      ratchetPublic = Uint8List.fromList(
        (await ratchetPair.extractPublicKey()).bytes,
      );

      final responderDeviceId = localDevice.deviceId;
      final responderDevicePublicKey = localDevice.publicKey;
      final replyMessageId = _V3HandshakePrimitives.replyMessageId(
        mode: offer.mode,
        capabilities: offer.capabilities,
        handshakeId: offer._handshakeId,
        offerMessageId: offer._messageId,
        initiatorIdentityDigest: offer._initiatorIdentityDigest,
        responderIdentityDigest: offer._responderIdentityDigest,
        initiatorDeviceId: offer._initiatorDeviceId,
        responderDeviceId: responderDeviceId,
        responderDevicePublicKey: responderDevicePublicKey,
        responderEphemeralPublicKey: ephemeralPublic,
        responderRatchetPublicKey: ratchetPublic,
        ciphertext: responderEncapsulation.ciphertext,
      );
      var reply = V3HandshakeReply._(
        mode: offer.mode,
        capabilities: offer.capabilities,
        handshakeId: offer._handshakeId,
        messageId: replyMessageId,
        offerMessageId: offer._messageId,
        initiatorIdentityDigest: offer._initiatorIdentityDigest,
        responderIdentityDigest: offer._responderIdentityDigest,
        initiatorDeviceId: offer._initiatorDeviceId,
        responderDeviceId: responderDeviceId,
        responderDevicePublicKey: responderDevicePublicKey,
        responderEphemeralPublicKey: ephemeralPublic,
        responderInitialRatchetPublicKey: ratchetPublic,
        responderToInitiatorCiphertext: responderEncapsulation.ciphertext,
        proof: Uint8List(V3HandshakeCodec.proofBytes),
      );
      stageOne = _V3HandshakePrimitives.replyTranscriptDigest(
        initiatorIdentity: initiatorIdentity,
        responderIdentity: localIdentity.publicIdentity,
        offer: offer,
        reply: reply,
      );
      classicalSecret = await _V3HandshakePrimitives.classicalSecretResponder(
        localIdentity: localIdentity,
        localDevice: localDevice,
        initiatorIdentity: initiatorIdentity,
        offer: offer,
        responderEphemeralPrivateSeed: ephemeralPrivate,
        transcriptDigest: stageOne,
      );
      postQuantumSecret = await _V3HandshakePrimitives.postQuantumSecret(
        initiatorToResponderSecret: initiatorToResponderSecret,
        responderToInitiatorSecret: responderEncapsulation.sharedSecret,
        transcriptDigest: stageOne,
      );
      proof = await _V3HandshakePrimitives.proof(
        classicalSecret: classicalSecret,
        postQuantumSecret: postQuantumSecret,
        transcriptDigest: stageOne,
        keyLabel: _V3HandshakePrimitives.replyProofKeyLabel,
        dataLabel: _V3HandshakePrimitives.replyProofDataLabel,
      );
      reply = V3HandshakeReply._(
        mode: reply.mode,
        capabilities: reply.capabilities,
        handshakeId: reply._handshakeId,
        messageId: reply._messageId,
        offerMessageId: reply._offerMessageId,
        initiatorIdentityDigest: reply._initiatorIdentityDigest,
        responderIdentityDigest: reply._responderIdentityDigest,
        initiatorDeviceId: reply._initiatorDeviceId,
        responderDeviceId: reply._responderDeviceId,
        responderDevicePublicKey: reply._responderDevicePublicKey,
        responderEphemeralPublicKey: reply._responderEphemeralPublicKey,
        responderInitialRatchetPublicKey:
            reply._responderInitialRatchetPublicKey,
        responderToInitiatorCiphertext: reply._responderToInitiatorCiphertext,
        proof: proof,
      );
      V3HandshakeCodec._validateReply(reply);
      return V3ResponderPendingHandshake._(
        offer: offer,
        reply: reply,
        classicalSecret: classicalSecret,
        postQuantumSecret: postQuantumSecret,
        localInitialRatchetPrivateSeed: ratchetPrivate,
      );
    } finally {
      if (initiatorToResponderSecret != null) {
        _wipeV3HandshakeBytes(initiatorToResponderSecret);
      }
      responderEncapsulation?.wipeSharedSecret();
      if (ephemeralPrivate != null) _wipeV3HandshakeBytes(ephemeralPrivate);
      if (ephemeralPublic != null) _wipeV3HandshakeBytes(ephemeralPublic);
      if (ratchetPrivate != null) _wipeV3HandshakeBytes(ratchetPrivate);
      if (ratchetPublic != null) _wipeV3HandshakeBytes(ratchetPublic);
      if (classicalSecret != null) _wipeV3HandshakeBytes(classicalSecret);
      if (postQuantumSecret != null) _wipeV3HandshakeBytes(postQuantumSecret);
      if (stageOne != null) _wipeV3HandshakeBytes(stageOne);
      if (proof != null) _wipeV3HandshakeBytes(proof);
    }
  }

  static Future<V3InitiatorHandshakeResult> acceptReply({
    required V3InitiatorPendingHandshake pending,
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity responderIdentity,
    required V3HandshakeReply reply,
  }) async {
    pending._ensureOpen();
    await _V3HandshakePrimitives.validateLocalIdentity(localIdentity);
    localDevice._ensureOpen();
    await _V3HandshakePrimitives.validateRemoteIdentity(
      localIdentity,
      responderIdentity,
    );
    _V3HandshakePrimitives.validateReplyContext(
      offer: pending.offer,
      reply: reply,
      initiatorIdentity: localIdentity.publicIdentity,
      responderIdentity: responderIdentity,
      initiatorDevice: localDevice,
    );
    Uint8List? responderToInitiatorSecret;
    Uint8List? stageOne;
    Uint8List? classicalSecret;
    Uint8List? postQuantumSecret;
    Uint8List? expectedProof;
    Uint8List? ratchetPrivate;
    Uint8List? ratchetPublic;
    Uint8List? stageTwo;
    Uint8List? confirmationProof;
    Uint8List? finalTranscript;
    V3SessionKeyMaterial? sessionKeys;
    var transferredSession = false;
    try {
      stageOne = _V3HandshakePrimitives.replyTranscriptDigest(
        initiatorIdentity: localIdentity.publicIdentity,
        responderIdentity: responderIdentity,
        offer: pending.offer,
        reply: reply,
      );
      responderToInitiatorSecret =
          await localIdentity._mlKem768Backend.decapsulate(
        localIdentity._mlKem768PrivateKeyHandle,
        reply._responderToInitiatorCiphertext,
      );
      _V3HandshakePrimitives.validateMlKemSecret(
        responderToInitiatorSecret,
      );
      classicalSecret = await _V3HandshakePrimitives.classicalSecretInitiator(
        localIdentity: localIdentity,
        localDevice: localDevice,
        responderIdentity: responderIdentity,
        pending: pending,
        reply: reply,
        transcriptDigest: stageOne,
      );
      postQuantumSecret = await _V3HandshakePrimitives.postQuantumSecret(
        initiatorToResponderSecret: pending._initiatorToResponderSecret,
        responderToInitiatorSecret: responderToInitiatorSecret,
        transcriptDigest: stageOne,
      );
      expectedProof = await _V3HandshakePrimitives.proof(
        classicalSecret: classicalSecret,
        postQuantumSecret: postQuantumSecret,
        transcriptDigest: stageOne,
        keyLabel: _V3HandshakePrimitives.replyProofKeyLabel,
        dataLabel: _V3HandshakePrimitives.replyProofDataLabel,
      );
      if (!_constantTimeV3HandshakeEquals(expectedProof, reply._proof)) {
        throw const FormatException(
          'Layergram v3 responder proof verification failed',
        );
      }

      final ratchetPair = await _V3HandshakePrimitives.x25519.newKeyPair();
      ratchetPrivate = Uint8List.fromList(
        await ratchetPair.extractPrivateKeyBytes(),
      );
      ratchetPublic = Uint8List.fromList(
        (await ratchetPair.extractPublicKey()).bytes,
      );
      final confirmationMessageId =
          _V3HandshakePrimitives.confirmationMessageId(
        mode: reply.mode,
        capabilities: reply.capabilities,
        handshakeId: reply._handshakeId,
        offerMessageId: reply._offerMessageId,
        replyMessageId: reply._messageId,
        initiatorIdentityDigest: reply._initiatorIdentityDigest,
        responderIdentityDigest: reply._responderIdentityDigest,
        initiatorDeviceId: reply._initiatorDeviceId,
        responderDeviceId: reply._responderDeviceId,
        initiatorRatchetPublicKey: ratchetPublic,
        replyTranscriptDigest: stageOne,
      );
      var confirmation = V3HandshakeConfirmation._(
        mode: reply.mode,
        capabilities: reply.capabilities,
        handshakeId: reply._handshakeId,
        messageId: confirmationMessageId,
        offerMessageId: reply._offerMessageId,
        replyMessageId: reply._messageId,
        initiatorIdentityDigest: reply._initiatorIdentityDigest,
        responderIdentityDigest: reply._responderIdentityDigest,
        initiatorDeviceId: reply._initiatorDeviceId,
        responderDeviceId: reply._responderDeviceId,
        initiatorInitialRatchetPublicKey: ratchetPublic,
        replyTranscriptDigest: stageOne,
        proof: Uint8List(V3HandshakeCodec.proofBytes),
      );
      stageTwo = _V3HandshakePrimitives.confirmationTranscriptDigest(
        initiatorIdentity: localIdentity.publicIdentity,
        responderIdentity: responderIdentity,
        offer: pending.offer,
        reply: reply,
        confirmation: confirmation,
      );
      confirmationProof = await _V3HandshakePrimitives.proof(
        classicalSecret: classicalSecret,
        postQuantumSecret: postQuantumSecret,
        transcriptDigest: stageTwo,
        keyLabel: _V3HandshakePrimitives.confirmProofKeyLabel,
        dataLabel: _V3HandshakePrimitives.confirmProofDataLabel,
      );
      confirmation = V3HandshakeConfirmation._(
        mode: confirmation.mode,
        capabilities: confirmation.capabilities,
        handshakeId: confirmation._handshakeId,
        messageId: confirmation._messageId,
        offerMessageId: confirmation._offerMessageId,
        replyMessageId: confirmation._replyMessageId,
        initiatorIdentityDigest: confirmation._initiatorIdentityDigest,
        responderIdentityDigest: confirmation._responderIdentityDigest,
        initiatorDeviceId: confirmation._initiatorDeviceId,
        responderDeviceId: confirmation._responderDeviceId,
        initiatorInitialRatchetPublicKey:
            confirmation._initiatorInitialRatchetPublicKey,
        replyTranscriptDigest: confirmation._replyTranscriptDigest,
        proof: confirmationProof,
      );
      V3HandshakeCodec._validateConfirmation(confirmation);
      finalTranscript = _V3HandshakePrimitives.finalTranscriptDigest(
        initiatorIdentity: localIdentity.publicIdentity,
        responderIdentity: responderIdentity,
        offer: pending.offer,
        reply: reply,
        confirmation: confirmation,
      );
      sessionKeys = await V3KeySchedule.deriveSession(
        classicalHandshakeSecret: classicalSecret,
        postQuantumHandshakeSecret: postQuantumSecret,
        transcriptDigest: finalTranscript,
      );
      final established = V3HandshakeEstablishedMaterial._(
        role: V3SessionRole.initiator,
        mode: reply.mode,
        capabilities: reply.capabilities,
        sessionKeys: sessionKeys,
        localDeviceId: reply._initiatorDeviceId,
        remoteDeviceId: reply._responderDeviceId,
        localInitialRatchetPrivateSeed: ratchetPrivate,
        localInitialRatchetPublicKey: ratchetPublic,
        remoteInitialRatchetPublicKey: reply._responderInitialRatchetPublicKey,
      );
      transferredSession = true;
      pending.close();
      return V3InitiatorHandshakeResult(
        confirmation: confirmation,
        established: established,
      );
    } finally {
      if (responderToInitiatorSecret != null) {
        _wipeV3HandshakeBytes(responderToInitiatorSecret);
      }
      if (stageOne != null) _wipeV3HandshakeBytes(stageOne);
      if (classicalSecret != null) _wipeV3HandshakeBytes(classicalSecret);
      if (postQuantumSecret != null) _wipeV3HandshakeBytes(postQuantumSecret);
      if (expectedProof != null) _wipeV3HandshakeBytes(expectedProof);
      if (ratchetPrivate != null) _wipeV3HandshakeBytes(ratchetPrivate);
      if (ratchetPublic != null) _wipeV3HandshakeBytes(ratchetPublic);
      if (stageTwo != null) _wipeV3HandshakeBytes(stageTwo);
      if (confirmationProof != null) {
        _wipeV3HandshakeBytes(confirmationProof);
      }
      if (finalTranscript != null) _wipeV3HandshakeBytes(finalTranscript);
      if (!transferredSession) sessionKeys?.close();
    }
  }

  static Future<V3HandshakeEstablishedMaterial> acceptConfirmation({
    required V3ResponderPendingHandshake pending,
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    required V3HandshakeConfirmation confirmation,
  }) async {
    pending._ensureOpen();
    _V3HandshakePrimitives.validateConfirmationContext(
      offer: pending.offer,
      reply: pending.reply,
      confirmation: confirmation,
      initiatorIdentity: initiatorIdentity,
      responderIdentity: responderIdentity,
    );
    Uint8List? stageOne;
    Uint8List? stageTwo;
    Uint8List? expectedProof;
    Uint8List? finalTranscript;
    Uint8List? localRatchetPublic;
    V3SessionKeyMaterial? sessionKeys;
    var transferredSession = false;
    try {
      stageOne = _V3HandshakePrimitives.replyTranscriptDigest(
        initiatorIdentity: initiatorIdentity,
        responderIdentity: responderIdentity,
        offer: pending.offer,
        reply: pending.reply,
      );
      if (!_constantTimeV3HandshakeEquals(
        stageOne,
        confirmation._replyTranscriptDigest,
      )) {
        throw const FormatException(
          'Layergram v3 reply transcript binding mismatch',
        );
      }
      stageTwo = _V3HandshakePrimitives.confirmationTranscriptDigest(
        initiatorIdentity: initiatorIdentity,
        responderIdentity: responderIdentity,
        offer: pending.offer,
        reply: pending.reply,
        confirmation: confirmation,
      );
      expectedProof = await _V3HandshakePrimitives.proof(
        classicalSecret: pending._classicalSecret,
        postQuantumSecret: pending._postQuantumSecret,
        transcriptDigest: stageTwo,
        keyLabel: _V3HandshakePrimitives.confirmProofKeyLabel,
        dataLabel: _V3HandshakePrimitives.confirmProofDataLabel,
      );
      if (!_constantTimeV3HandshakeEquals(
        expectedProof,
        confirmation._proof,
      )) {
        throw const FormatException(
          'Layergram v3 initiator proof verification failed',
        );
      }
      finalTranscript = _V3HandshakePrimitives.finalTranscriptDigest(
        initiatorIdentity: initiatorIdentity,
        responderIdentity: responderIdentity,
        offer: pending.offer,
        reply: pending.reply,
        confirmation: confirmation,
      );
      sessionKeys = await V3KeySchedule.deriveSession(
        classicalHandshakeSecret: pending._classicalSecret,
        postQuantumHandshakeSecret: pending._postQuantumSecret,
        transcriptDigest: finalTranscript,
      );
      localRatchetPublic = await _V3HandshakePrimitives.publicKey(
        pending._localInitialRatchetPrivateSeed,
      );
      if (!_constantTimeV3HandshakeEquals(
        localRatchetPublic,
        pending.reply._responderInitialRatchetPublicKey,
      )) {
        throw const FormatException(
          'Layergram v3 responder ratchet key mismatch',
        );
      }
      final established = V3HandshakeEstablishedMaterial._(
        role: V3SessionRole.responder,
        mode: pending.reply.mode,
        capabilities: pending.reply.capabilities,
        sessionKeys: sessionKeys,
        localDeviceId: pending.reply._responderDeviceId,
        remoteDeviceId: pending.reply._initiatorDeviceId,
        localInitialRatchetPrivateSeed: pending._localInitialRatchetPrivateSeed,
        localInitialRatchetPublicKey: localRatchetPublic,
        remoteInitialRatchetPublicKey:
            confirmation._initiatorInitialRatchetPublicKey,
      );
      transferredSession = true;
      pending.close();
      return established;
    } finally {
      if (stageOne != null) _wipeV3HandshakeBytes(stageOne);
      if (stageTwo != null) _wipeV3HandshakeBytes(stageTwo);
      if (expectedProof != null) _wipeV3HandshakeBytes(expectedProof);
      if (finalTranscript != null) _wipeV3HandshakeBytes(finalTranscript);
      if (localRatchetPublic != null) {
        _wipeV3HandshakeBytes(localRatchetPublic);
      }
      if (!transferredSession) sessionKeys?.close();
    }
  }
}

/// Canonical encrypted-record plaintext used to survive process restarts.
///
/// The returned bytes contain secrets and MUST only be stored inside an
/// identity/passphrase-scoped encrypted, padded auxiliary record.
abstract final class V3HandshakePendingStateCodec {
  static const int _headerBytes = 60;
  static const int _formatVersion = 1;
  static const int initiatorEncodedBytes =
      _headerBytes + V3HandshakeCodec.offerBytes + 64;
  static const int responderEncodedBytes = _headerBytes +
      V3HandshakeCodec.offerBytes +
      V3HandshakeCodec.replyBytes +
      96;
  static const int maxEncodedBytes = 4096;
  static const List<int> _magic = <int>[0x48, 0x50, 0x33]; // HP3
  static final Uint8List _digestLabel = Uint8List.fromList(
    'layergram/v3/handshake/pending-state\x00'.codeUnits,
  );

  static Uint8List encodeInitiator(V3InitiatorPendingHandshake state) {
    state._ensureOpen();
    final offer = V3HandshakeCodec.encodeOffer(state.offer);
    final secrets = _concatV3Handshake(<List<int>>[
      state._ephemeralPrivateSeed,
      state._initiatorToResponderSecret,
    ]);
    try {
      return _encode(
        role: V3SessionRole.initiator,
        mode: state.offer.mode,
        capabilities: state.offer.capabilities,
        firstRecord: offer,
        secondRecord: Uint8List(0),
        secrets: secrets,
      );
    } finally {
      _wipeV3HandshakeBytes(secrets);
    }
  }

  static Uint8List encodeResponder(V3ResponderPendingHandshake state) {
    state._ensureOpen();
    final secrets = _concatV3Handshake(<List<int>>[
      state._classicalSecret,
      state._postQuantumSecret,
      state._localInitialRatchetPrivateSeed,
    ]);
    try {
      return _encode(
        role: V3SessionRole.responder,
        mode: state.reply.mode,
        capabilities: state.reply.capabilities,
        firstRecord: V3HandshakeCodec.encodeOffer(state.offer),
        secondRecord: V3HandshakeCodec.encodeReply(state.reply),
        secrets: secrets,
      );
    } finally {
      _wipeV3HandshakeBytes(secrets);
    }
  }

  static V3InitiatorPendingHandshake decodeInitiator(Uint8List encoded) {
    final decoded = _decode(encoded, V3SessionRole.initiator);
    try {
      final offer = V3HandshakeCodec.decodeOffer(decoded.firstRecord);
      if (decoded.secondRecord.isNotEmpty ||
          decoded.secrets.length != 64 ||
          offer.mode != decoded.mode ||
          offer.capabilities != decoded.capabilities) {
        throw const FormatException(
          'Invalid Layergram v3 initiator pending state',
        );
      }
      final ephemeral = _take(decoded.secrets, 0, 32);
      final pqSecret = _take(decoded.secrets, 32, 32);
      try {
        _requireV3HandshakeNonZero(ephemeral, 'pending ephemeral seed');
        _requireV3HandshakeNonZero(pqSecret, 'pending ML-KEM secret');
        return V3InitiatorPendingHandshake._(
          offer: offer,
          ephemeralPrivateSeed: ephemeral,
          initiatorToResponderSecret: pqSecret,
        );
      } finally {
        _wipeV3HandshakeBytes(ephemeral);
        _wipeV3HandshakeBytes(pqSecret);
      }
    } finally {
      _wipeV3HandshakeBytes(decoded.secrets);
    }
  }

  static V3ResponderPendingHandshake decodeResponder(Uint8List encoded) {
    final decoded = _decode(encoded, V3SessionRole.responder);
    try {
      final offer = V3HandshakeCodec.decodeOffer(decoded.firstRecord);
      final reply = V3HandshakeCodec.decodeReply(decoded.secondRecord);
      if (decoded.secrets.length != 96 ||
          offer.mode != decoded.mode ||
          reply.mode != decoded.mode ||
          offer.capabilities != decoded.capabilities ||
          reply.capabilities != decoded.capabilities) {
        throw const FormatException(
          'Invalid Layergram v3 responder pending state',
        );
      }
      _V3HandshakePrimitives.validateReplyLink(offer, reply);
      final classical = _take(decoded.secrets, 0, 32);
      final postQuantum = _take(decoded.secrets, 32, 32);
      final ratchetPrivate = _take(decoded.secrets, 64, 32);
      try {
        _requireV3HandshakeNonZero(classical, 'pending classical secret');
        _requireV3HandshakeNonZero(postQuantum, 'pending ML-KEM secret');
        _requireV3HandshakeNonZero(
          ratchetPrivate,
          'pending ratchet private seed',
        );
        return V3ResponderPendingHandshake._(
          offer: offer,
          reply: reply,
          classicalSecret: classical,
          postQuantumSecret: postQuantum,
          localInitialRatchetPrivateSeed: ratchetPrivate,
        );
      } finally {
        _wipeV3HandshakeBytes(classical);
        _wipeV3HandshakeBytes(postQuantum);
        _wipeV3HandshakeBytes(ratchetPrivate);
      }
    } finally {
      _wipeV3HandshakeBytes(decoded.secrets);
    }
  }

  static Uint8List _encode({
    required V3SessionRole role,
    required V3HandshakeMode mode,
    required int capabilities,
    required Uint8List firstRecord,
    required Uint8List secondRecord,
    required Uint8List secrets,
  }) {
    final total = _headerBytes +
        firstRecord.length +
        secondRecord.length +
        secrets.length;
    final output = Uint8List(total);
    output.setRange(0, 3, _magic);
    output[3] = _formatVersion;
    output[4] = V3IdentitySuite.hybridX25519MlKem768.wireId;
    output[5] = role.wireId;
    output[6] = mode.wireId;
    output[7] = 0;
    ByteData.sublistView(output)
      ..setUint32(8, total, Endian.big)
      ..setUint32(12, capabilities, Endian.big)
      ..setUint32(16, firstRecord.length, Endian.big)
      ..setUint32(20, secondRecord.length, Endian.big)
      ..setUint32(24, secrets.length, Endian.big);
    var offset = _headerBytes;
    offset = _put(output, offset, firstRecord);
    offset = _put(output, offset, secondRecord);
    _put(output, offset, secrets);
    final digest = _pendingStateDigest(output);
    output.setRange(28, 60, digest);
    _wipeV3HandshakeBytes(digest);
    return output;
  }

  static ({
    V3HandshakeMode mode,
    int capabilities,
    Uint8List firstRecord,
    Uint8List secondRecord,
    Uint8List secrets,
  }) _decode(Uint8List encoded, V3SessionRole expectedRole) {
    if (encoded.length < _headerBytes || encoded.length > maxEncodedBytes) {
      throw const FormatException('Invalid Layergram v3 pending state length');
    }
    final data = ByteData.sublistView(encoded);
    if (!_constantTimeV3HandshakeEquals(
          Uint8List.sublistView(encoded, 0, 3),
          Uint8List.fromList(_magic),
        ) ||
        encoded[3] != _formatVersion ||
        encoded[4] != V3IdentitySuite.hybridX25519MlKem768.wireId ||
        encoded[5] != expectedRole.wireId ||
        encoded[7] != 0 ||
        data.getUint32(8, Endian.big) != encoded.length) {
      throw const FormatException('Invalid Layergram v3 pending state header');
    }
    final mode = V3HandshakeMode.fromWireId(encoded[6]);
    final capabilities = data.getUint32(12, Endian.big);
    if (capabilities != V3HandshakeCodec.requiredCapabilities) {
      throw const FormatException('Unsupported pending-state capabilities');
    }
    final firstLength = data.getUint32(16, Endian.big);
    final secondLength = data.getUint32(20, Endian.big);
    final secretLength = data.getUint32(24, Endian.big);
    if (_headerBytes + firstLength + secondLength + secretLength !=
        encoded.length) {
      throw const FormatException('Non-canonical pending-state lengths');
    }
    final expectedDigest = _pendingStateDigest(encoded);
    try {
      if (!_constantTimeV3HandshakeEquals(
        Uint8List.sublistView(encoded, 28, 60),
        expectedDigest,
      )) {
        throw const FormatException('Invalid pending-state digest');
      }
    } finally {
      _wipeV3HandshakeBytes(expectedDigest);
    }
    var offset = _headerBytes;
    final first = _take(encoded, offset, firstLength);
    offset += firstLength;
    final second = _take(encoded, offset, secondLength);
    offset += secondLength;
    final secrets = _take(encoded, offset, secretLength);
    _requireV3HandshakeNonZero(secrets, 'pending-state secrets');
    return (
      mode: mode,
      capabilities: capabilities,
      firstRecord: first,
      secondRecord: second,
      secrets: secrets,
    );
  }

  static Uint8List _pendingStateDigest(Uint8List encoded) {
    final headerPrefix = Uint8List.sublistView(encoded, 0, 28);
    final payload = Uint8List.sublistView(encoded, _headerBytes);
    return Uint8List.fromList(
      crypto.sha256
          .convert(<int>[..._digestLabel, ...headerPrefix, ...payload]).bytes,
    );
  }
}

abstract final class _V3HandshakePrimitives {
  static final X25519 x25519 = X25519();
  static final Hmac _hmac = Hmac.sha256();
  static final Uint8List _transcriptLabel = Uint8List.fromList(
    'layergram/v3/handshake/transcript\x00'.codeUnits,
  );
  static final Uint8List _classicalSecretLabel = Uint8List.fromList(
    'layergram/v3/handshake/classical-secret\x00'.codeUnits,
  );
  static final Uint8List _postQuantumSecretLabel = Uint8List.fromList(
    'layergram/v3/handshake/post-quantum-secret\x00'.codeUnits,
  );
  static final Uint8List _proofClassicalExtractLabel = Uint8List.fromList(
    'layergram/v3/handshake/proof/classical-extract\x00'.codeUnits,
  );
  static final Uint8List _proofPostQuantumExtractLabel = Uint8List.fromList(
    'layergram/v3/handshake/proof/post-quantum-extract\x00'.codeUnits,
  );
  static final Uint8List replyProofKeyLabel = Uint8List.fromList(
    'layergram/v3/handshake/proof/responder-key\x00'.codeUnits,
  );
  static final Uint8List confirmProofKeyLabel = Uint8List.fromList(
    'layergram/v3/handshake/proof/initiator-key\x00'.codeUnits,
  );
  static final Uint8List replyProofDataLabel = Uint8List.fromList(
    'layergram/v3/handshake/proof/responder\x00'.codeUnits,
  );
  static final Uint8List confirmProofDataLabel = Uint8List.fromList(
    'layergram/v3/handshake/proof/initiator\x00'.codeUnits,
  );
  static final Uint8List _deviceIdLabel = Uint8List.fromList(
    'layergram/v3/device/id\x00'.codeUnits,
  );
  static final Uint8List _handshakeIdLabel = Uint8List.fromList(
    'layergram/v3/handshake/id\x00'.codeUnits,
  );
  static final Uint8List _offerMessageIdLabel = Uint8List.fromList(
    'layergram/v3/handshake/offer-message-id\x00'.codeUnits,
  );
  static final Uint8List _replyMessageIdLabel = Uint8List.fromList(
    'layergram/v3/handshake/reply-message-id\x00'.codeUnits,
  );
  static final Uint8List _confirmationMessageIdLabel = Uint8List.fromList(
    'layergram/v3/handshake/confirm-message-id\x00'.codeUnits,
  );

  static Uint8List identityDigest(V3PublicIdentity identity) =>
      Uint8List.fromList(
        crypto.sha384.convert(identity.identityBindingBytes).bytes,
      );

  static Uint8List deviceId(Uint8List publicKey) => _hashPrefix(
        <List<int>>[_deviceIdLabel, publicKey],
        V3HandshakeCodec.idBytes,
      );

  static Uint8List offerHandshakeId({
    required V3HandshakeMode mode,
    required int capabilities,
    required Uint8List initiatorIdentityDigest,
    required Uint8List responderIdentityDigest,
    required Uint8List initiatorDeviceId,
    required Uint8List initiatorDevicePublicKey,
    required Uint8List initiatorEphemeralPublicKey,
    required Uint8List ciphertext,
  }) =>
      _hashPrefix(
        <List<int>>[
          _handshakeIdLabel,
          <int>[mode.wireId],
          _u32(capabilities),
          initiatorIdentityDigest,
          responderIdentityDigest,
          initiatorDeviceId,
          initiatorDevicePublicKey,
          initiatorEphemeralPublicKey,
          ciphertext,
        ],
        V3HandshakeCodec.idBytes,
      );

  static Uint8List offerMessageId({
    required Uint8List handshakeId,
    required Uint8List initiatorEphemeralPublicKey,
    required Uint8List ciphertext,
  }) =>
      _hashPrefix(
        <List<int>>[
          _offerMessageIdLabel,
          handshakeId,
          initiatorEphemeralPublicKey,
          ciphertext,
        ],
        V3HandshakeCodec.idBytes,
      );

  static Uint8List replyMessageId({
    required V3HandshakeMode mode,
    required int capabilities,
    required Uint8List handshakeId,
    required Uint8List offerMessageId,
    required Uint8List initiatorIdentityDigest,
    required Uint8List responderIdentityDigest,
    required Uint8List initiatorDeviceId,
    required Uint8List responderDeviceId,
    required Uint8List responderDevicePublicKey,
    required Uint8List responderEphemeralPublicKey,
    required Uint8List responderRatchetPublicKey,
    required Uint8List ciphertext,
  }) =>
      _hashPrefix(
        <List<int>>[
          _replyMessageIdLabel,
          <int>[mode.wireId],
          _u32(capabilities),
          handshakeId,
          offerMessageId,
          initiatorIdentityDigest,
          responderIdentityDigest,
          initiatorDeviceId,
          responderDeviceId,
          responderDevicePublicKey,
          responderEphemeralPublicKey,
          responderRatchetPublicKey,
          ciphertext,
        ],
        V3HandshakeCodec.idBytes,
      );

  static Uint8List confirmationMessageId({
    required V3HandshakeMode mode,
    required int capabilities,
    required Uint8List handshakeId,
    required Uint8List offerMessageId,
    required Uint8List replyMessageId,
    required Uint8List initiatorIdentityDigest,
    required Uint8List responderIdentityDigest,
    required Uint8List initiatorDeviceId,
    required Uint8List responderDeviceId,
    required Uint8List initiatorRatchetPublicKey,
    required Uint8List replyTranscriptDigest,
  }) =>
      _hashPrefix(
        <List<int>>[
          _confirmationMessageIdLabel,
          <int>[mode.wireId],
          _u32(capabilities),
          handshakeId,
          offerMessageId,
          replyMessageId,
          initiatorIdentityDigest,
          responderIdentityDigest,
          initiatorDeviceId,
          responderDeviceId,
          initiatorRatchetPublicKey,
          replyTranscriptDigest,
        ],
        V3HandshakeCodec.idBytes,
      );

  static Future<void> validateLocalIdentity(
    V3LocalIdentityHandle identity,
  ) async {
    if (identity._isClosed) {
      throw StateError('Layergram v3 identity handle is closed');
    }
    if (!await identity._mlKem768Backend.selfTest()) {
      throw StateError('ML-KEM-768 backend self-test failed');
    }
    if (!await identity._mlKem768Backend.validatePublicKey(
      identity.publicIdentity.mlKem768PublicKey,
    )) {
      throw StateError('Local ML-KEM-768 public key is invalid');
    }
    final derived = await publicKey(identity._x25519PrivateSeed);
    try {
      if (!_constantTimeV3HandshakeEquals(
        derived,
        identity.publicIdentity.x25519PublicKey,
      )) {
        throw StateError(
          'Local X25519 private seed does not match the public identity',
        );
      }
    } finally {
      _wipeV3HandshakeBytes(derived);
    }
  }

  static Future<void> validateRemoteIdentity(
    V3LocalIdentityHandle localIdentity,
    V3PublicIdentity remoteIdentity,
  ) async {
    if (remoteIdentity.suite != V3IdentitySuite.hybridX25519MlKem768 ||
        !await localIdentity._mlKem768Backend.validatePublicKey(
          remoteIdentity.mlKem768PublicKey,
        )) {
      throw const FormatException('Invalid remote Layergram v3 identity');
    }
    final localDigest = identityDigest(localIdentity.publicIdentity);
    final remoteDigest = identityDigest(remoteIdentity);
    try {
      if (_constantTimeV3HandshakeEquals(localDigest, remoteDigest)) {
        throw const FormatException(
          'Layergram v3 handshake identities must be distinct',
        );
      }
    } finally {
      _wipeV3HandshakeBytes(localDigest);
      _wipeV3HandshakeBytes(remoteDigest);
    }
  }

  static void validateMlKemSecret(Uint8List value) {
    if (value.length != MlKem768.sharedSecretBytes || _allZero(value)) {
      throw const FormatException('Invalid ML-KEM-768 shared secret');
    }
  }

  static Future<Uint8List> publicKey(Uint8List privateSeed) async {
    final pair = await x25519.newKeyPairFromSeed(privateSeed);
    return Uint8List.fromList((await pair.extractPublicKey()).bytes);
  }

  static Future<Uint8List> _dh(
    Uint8List privateSeed,
    Uint8List remotePublicKey,
  ) async {
    if (privateSeed.length != 32 || remotePublicKey.length != 32) {
      throw const FormatException('Invalid X25519 handshake key length');
    }
    final localPublic = await publicKey(privateSeed);
    try {
      final pair = SimpleKeyPairData(
        Uint8List.fromList(privateSeed),
        type: KeyPairType.x25519,
        publicKey: SimplePublicKey(
          localPublic,
          type: KeyPairType.x25519,
        ),
      );
      final shared = await x25519.sharedSecretKey(
        keyPair: pair,
        remotePublicKey: SimplePublicKey(
          remotePublicKey,
          type: KeyPairType.x25519,
        ),
      );
      final bytes = Uint8List.fromList(await shared.extractBytes());
      if (bytes.length != 32 || _allZero(bytes)) {
        _wipeV3HandshakeBytes(bytes);
        throw const FormatException('Invalid all-zero X25519 output');
      }
      return bytes;
    } finally {
      _wipeV3HandshakeBytes(localPublic);
    }
  }

  static Future<Uint8List> classicalSecretResponder({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity initiatorIdentity,
    required V3HandshakeOffer offer,
    required Uint8List responderEphemeralPrivateSeed,
    required Uint8List transcriptDigest,
  }) async {
    final outputs = <Uint8List>[];
    try {
      outputs.add(await _dh(
        localDevice._privateSeed,
        initiatorIdentity.x25519PublicKey,
      ));
      outputs.add(await _dh(
        localIdentity._x25519PrivateSeed,
        offer._initiatorDevicePublicKey,
      ));
      outputs.add(await _dh(
        localDevice._privateSeed,
        offer._initiatorEphemeralPublicKey,
      ));
      outputs.add(await _dh(
        responderEphemeralPrivateSeed,
        offer._initiatorDevicePublicKey,
      ));
      outputs.add(await _dh(
        responderEphemeralPrivateSeed,
        offer._initiatorEphemeralPublicKey,
      ));
      final input = _concatV3Handshake(outputs);
      try {
        return await _hkdf(
          ikm: input,
          salt: transcriptDigest,
          info: _classicalSecretLabel,
          length: 32,
        );
      } finally {
        _wipeV3HandshakeBytes(input);
      }
    } finally {
      for (final output in outputs) {
        _wipeV3HandshakeBytes(output);
      }
    }
  }

  static Future<Uint8List> classicalSecretInitiator({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity responderIdentity,
    required V3InitiatorPendingHandshake pending,
    required V3HandshakeReply reply,
    required Uint8List transcriptDigest,
  }) async {
    final outputs = <Uint8List>[];
    try {
      outputs.add(await _dh(
        localIdentity._x25519PrivateSeed,
        reply._responderDevicePublicKey,
      ));
      outputs.add(await _dh(
        localDevice._privateSeed,
        responderIdentity.x25519PublicKey,
      ));
      outputs.add(await _dh(
        pending._ephemeralPrivateSeed,
        reply._responderDevicePublicKey,
      ));
      outputs.add(await _dh(
        localDevice._privateSeed,
        reply._responderEphemeralPublicKey,
      ));
      outputs.add(await _dh(
        pending._ephemeralPrivateSeed,
        reply._responderEphemeralPublicKey,
      ));
      final input = _concatV3Handshake(outputs);
      try {
        return await _hkdf(
          ikm: input,
          salt: transcriptDigest,
          info: _classicalSecretLabel,
          length: 32,
        );
      } finally {
        _wipeV3HandshakeBytes(input);
      }
    } finally {
      for (final output in outputs) {
        _wipeV3HandshakeBytes(output);
      }
    }
  }

  static Future<Uint8List> postQuantumSecret({
    required Uint8List initiatorToResponderSecret,
    required Uint8List responderToInitiatorSecret,
    required Uint8List transcriptDigest,
  }) async {
    validateMlKemSecret(initiatorToResponderSecret);
    validateMlKemSecret(responderToInitiatorSecret);
    final input = _concatV3Handshake(<List<int>>[
      initiatorToResponderSecret,
      responderToInitiatorSecret,
    ]);
    try {
      return await _hkdf(
        ikm: input,
        salt: transcriptDigest,
        info: _postQuantumSecretLabel,
        length: 32,
      );
    } finally {
      _wipeV3HandshakeBytes(input);
    }
  }

  static Future<Uint8List> proof({
    required Uint8List classicalSecret,
    required Uint8List postQuantumSecret,
    required Uint8List transcriptDigest,
    required Uint8List keyLabel,
    required Uint8List dataLabel,
  }) async {
    Uint8List? classicalSeed;
    Uint8List? postQuantumSeed;
    Uint8List? key;
    try {
      classicalSeed = await _hkdf(
        ikm: classicalSecret,
        salt: transcriptDigest,
        info: _proofClassicalExtractLabel,
        length: 32,
      );
      postQuantumSeed = await _hkdf(
        ikm: postQuantumSecret,
        salt: transcriptDigest,
        info: _proofPostQuantumExtractLabel,
        length: 32,
      );
      final info = _concatV3Handshake(<List<int>>[keyLabel, transcriptDigest]);
      final data = _concatV3Handshake(<List<int>>[dataLabel, transcriptDigest]);
      try {
        key = await _hkdf(
          ikm: classicalSeed,
          salt: postQuantumSeed,
          info: info,
          length: 32,
        );
        final mac = await _hmac.calculateMac(
          data,
          secretKey: SecretKey(key),
        );
        return Uint8List.fromList(mac.bytes);
      } finally {
        _wipeV3HandshakeBytes(info);
        _wipeV3HandshakeBytes(data);
      }
    } finally {
      if (classicalSeed != null) _wipeV3HandshakeBytes(classicalSeed);
      if (postQuantumSeed != null) _wipeV3HandshakeBytes(postQuantumSeed);
      if (key != null) _wipeV3HandshakeBytes(key);
    }
  }

  static Uint8List replyTranscriptDigest({
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    required V3HandshakeOffer offer,
    required V3HandshakeReply reply,
  }) =>
      _transcriptDigest(
        initiatorIdentity: initiatorIdentity,
        responderIdentity: responderIdentity,
        records: <Uint8List>[
          V3HandshakeCodec.encodeOffer(offer),
          V3HandshakeCodec._encodeReplyBody(reply),
        ],
      );

  static Uint8List confirmationTranscriptDigest({
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    required V3HandshakeOffer offer,
    required V3HandshakeReply reply,
    required V3HandshakeConfirmation confirmation,
  }) =>
      _transcriptDigest(
        initiatorIdentity: initiatorIdentity,
        responderIdentity: responderIdentity,
        records: <Uint8List>[
          V3HandshakeCodec.encodeOffer(offer),
          V3HandshakeCodec.encodeReply(reply),
          V3HandshakeCodec._encodeConfirmationBody(confirmation),
        ],
      );

  static Uint8List finalTranscriptDigest({
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    required V3HandshakeOffer offer,
    required V3HandshakeReply reply,
    required V3HandshakeConfirmation confirmation,
  }) =>
      _transcriptDigest(
        initiatorIdentity: initiatorIdentity,
        responderIdentity: responderIdentity,
        records: <Uint8List>[
          V3HandshakeCodec.encodeOffer(offer),
          V3HandshakeCodec.encodeReply(reply),
          V3HandshakeCodec.encodeConfirmation(confirmation),
        ],
      );

  static Uint8List _transcriptDigest({
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    required List<Uint8List> records,
  }) {
    final initiator = initiatorIdentity.identityBindingBytes;
    final responder = responderIdentity.identityBindingBytes;
    final builder = BytesBuilder(copy: false)
      ..add(_transcriptLabel)
      ..add(_u32(initiator.length))
      ..add(initiator)
      ..add(_u32(responder.length))
      ..add(responder);
    for (final record in records) {
      builder
        ..add(_u32(record.length))
        ..add(record);
    }
    return Uint8List.fromList(crypto.sha384.convert(builder.takeBytes()).bytes);
  }

  static void validateOfferContext({
    required V3HandshakeOffer offer,
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    required V3HandshakeMode expectedMode,
  }) {
    V3HandshakeCodec._validateOffer(offer);
    if (offer.mode != expectedMode ||
        offer.capabilities != V3HandshakeCodec.requiredCapabilities) {
      throw const FormatException('Layergram v3 handshake downgrade');
    }
    _validateIdentityDigests(
      initiatorIdentity,
      responderIdentity,
      offer._initiatorIdentityDigest,
      offer._responderIdentityDigest,
    );
  }

  static void validateReplyLink(
    V3HandshakeOffer offer,
    V3HandshakeReply reply,
  ) {
    if (offer.mode != reply.mode ||
        offer.capabilities != reply.capabilities ||
        !_constantTimeV3HandshakeEquals(
          offer._handshakeId,
          reply._handshakeId,
        ) ||
        !_constantTimeV3HandshakeEquals(
          offer._messageId,
          reply._offerMessageId,
        ) ||
        !_constantTimeV3HandshakeEquals(
          offer._initiatorIdentityDigest,
          reply._initiatorIdentityDigest,
        ) ||
        !_constantTimeV3HandshakeEquals(
          offer._responderIdentityDigest,
          reply._responderIdentityDigest,
        ) ||
        !_constantTimeV3HandshakeEquals(
          offer._initiatorDeviceId,
          reply._initiatorDeviceId,
        )) {
      throw const FormatException('Layergram v3 reply does not match offer');
    }
  }

  static void validateReplyContext({
    required V3HandshakeOffer offer,
    required V3HandshakeReply reply,
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    required V3LocalDeviceHandle initiatorDevice,
  }) {
    V3HandshakeCodec._validateReply(reply);
    validateReplyLink(offer, reply);
    _validateIdentityDigests(
      initiatorIdentity,
      responderIdentity,
      reply._initiatorIdentityDigest,
      reply._responderIdentityDigest,
    );
    if (!_constantTimeV3HandshakeEquals(
          initiatorDevice._deviceId,
          reply._initiatorDeviceId,
        ) ||
        !_constantTimeV3HandshakeEquals(
          initiatorDevice._publicKey,
          offer._initiatorDevicePublicKey,
        )) {
      throw const FormatException('Unexpected Layergram v3 initiator device');
    }
  }

  static void validateConfirmationContext({
    required V3HandshakeOffer offer,
    required V3HandshakeReply reply,
    required V3HandshakeConfirmation confirmation,
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
  }) {
    V3HandshakeCodec._validateConfirmation(confirmation);
    validateReplyLink(offer, reply);
    if (confirmation.mode != reply.mode ||
        confirmation.capabilities != reply.capabilities ||
        !_constantTimeV3HandshakeEquals(
          confirmation._handshakeId,
          reply._handshakeId,
        ) ||
        !_constantTimeV3HandshakeEquals(
          confirmation._offerMessageId,
          reply._offerMessageId,
        ) ||
        !_constantTimeV3HandshakeEquals(
          confirmation._replyMessageId,
          reply._messageId,
        ) ||
        !_constantTimeV3HandshakeEquals(
          confirmation._initiatorDeviceId,
          reply._initiatorDeviceId,
        ) ||
        !_constantTimeV3HandshakeEquals(
          confirmation._responderDeviceId,
          reply._responderDeviceId,
        )) {
      throw const FormatException(
        'Layergram v3 confirmation does not match reply',
      );
    }
    _validateIdentityDigests(
      initiatorIdentity,
      responderIdentity,
      confirmation._initiatorIdentityDigest,
      confirmation._responderIdentityDigest,
    );
  }

  static void _validateIdentityDigests(
    V3PublicIdentity initiatorIdentity,
    V3PublicIdentity responderIdentity,
    Uint8List initiatorDigest,
    Uint8List responderDigest,
  ) {
    final expectedInitiator = identityDigest(initiatorIdentity);
    final expectedResponder = identityDigest(responderIdentity);
    try {
      if (!_constantTimeV3HandshakeEquals(
            initiatorDigest,
            expectedInitiator,
          ) ||
          !_constantTimeV3HandshakeEquals(
            responderDigest,
            expectedResponder,
          )) {
        throw const FormatException('Layergram v3 identity binding mismatch');
      }
    } finally {
      _wipeV3HandshakeBytes(expectedInitiator);
      _wipeV3HandshakeBytes(expectedResponder);
    }
  }

  static Future<Uint8List> _hkdf({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    required int length,
  }) async {
    final result = await Hkdf(
      hmac: Hmac.sha256(),
      outputLength: length,
    ).deriveKey(
      secretKey: SecretKey(ikm),
      nonce: salt,
      info: info,
    );
    final bytes = Uint8List.fromList(await result.extractBytes());
    if (_allZero(bytes)) {
      _wipeV3HandshakeBytes(bytes);
      throw StateError('Layergram v3 handshake KDF returned all zero');
    }
    return bytes;
  }

  static bool _allZero(List<int> value) {
    var any = 0;
    for (final byte in value) {
      any |= byte;
    }
    return any == 0;
  }

  static Uint8List _hashPrefix(List<List<int>> chunks, int length) =>
      Uint8List.fromList(
        crypto.sha256
            .convert(chunks.expand((chunk) => chunk).toList(growable: false))
            .bytes
            .take(length)
            .toList(growable: false),
      );
}

Uint8List _copyV3HandshakeBytes(
  Uint8List value,
  int expectedLength,
  String name, {
  bool rejectAllZero = false,
}) {
  if (value.length != expectedLength ||
      (rejectAllZero && _V3HandshakePrimitives._allZero(value))) {
    throw ArgumentError.value(value.length, name, 'invalid byte string');
  }
  return Uint8List.fromList(value);
}

Uint8List _take(Uint8List source, int offset, int length) {
  if (offset < 0 || length < 0 || offset > source.length - length) {
    throw const FormatException('Layergram v3 handshake field overflow');
  }
  return Uint8List.fromList(source.sublist(offset, offset + length));
}

int _put(Uint8List target, int offset, List<int> value) {
  if (offset < 0 || offset > target.length - value.length) {
    throw StateError('Layergram v3 handshake field overflow');
  }
  target.setRange(offset, offset + value.length, value);
  return offset + value.length;
}

Uint8List _concatV3Handshake(List<List<int>> chunks) => Uint8List.fromList(
      chunks.expand((chunk) => chunk).toList(growable: false),
    );

Uint8List _u32(int value) {
  if (value < 0 || value > 0xffffffff) {
    throw RangeError.range(value, 0, 0xffffffff, 'value');
  }
  final result = Uint8List(4);
  ByteData.sublistView(result).setUint32(0, value, Endian.big);
  return result;
}

void _requireV3HandshakeNonZero(Uint8List value, String name) {
  if (_V3HandshakePrimitives._allZero(value)) {
    throw FormatException('Layergram v3 $name must not be all zero');
  }
}

void _requireCanonical(Uint8List input, Uint8List canonical) {
  if (!_constantTimeV3HandshakeEquals(input, canonical)) {
    throw const FormatException('Non-canonical Layergram v3 handshake');
  }
}

bool _constantTimeV3HandshakeEquals(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipeV3HandshakeBytes(Uint8List value) {
  value.fillRange(0, value.length, 0);
}
