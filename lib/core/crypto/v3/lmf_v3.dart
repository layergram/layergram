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

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import '../stego_alphabet_v2.dart';
import '../stego_encoder.dart';
import 'hybrid_ratchet_header_v3.dart';

/// Inactive protocol-v3 suite identifier used by the research wire format.
enum V3LmfSuite {
  hybridX25519MlKem768Aes256Gcm(1);

  const V3LmfSuite(this.wireId);

  final int wireId;

  static V3LmfSuite fromWireId(int wireId) {
    for (final suite in values) {
      if (suite.wireId == wireId) return suite;
    }
    throw const FormatException('Unsupported Layergram v3 message suite');
  }
}

/// Semantic class of an LMF v3 frame.
///
/// This registry reserves wire values only. It does not enable the future
/// handshake, application-message, PQ-ratchet, or acknowledgement flows.
enum V3LmfFrameKind {
  handshake(1),
  application(2),
  pqRatchet(3),
  acknowledgement(4);

  const V3LmfFrameKind(this.wireId);

  final int wireId;

  static V3LmfFrameKind fromWireId(int wireId) {
    for (final kind in values) {
      if (kind.wireId == wireId) return kind;
    }
    throw const FormatException('Unsupported Layergram v3 frame kind');
  }
}

/// Shared authenticated metadata for one logical v3 message.
///
/// [senderBinding] and [recipientBinding] are opaque, session-context routing
/// bindings. They are not public identity IDs and are not owner authentication.
/// Their derivation remains a handshake/ratchet specification gate.
class V3LmfMessageMetadata {
  factory V3LmfMessageMetadata({
    required V3LmfFrameKind kind,
    required Uint8List senderBinding,
    required Uint8List recipientBinding,
    required Uint8List messageId,
    required Uint8List sessionId,
    required int epoch,
    required int messageCounter,
    int expiresAtUnixSeconds = 0,
    V3LmfSuite suite = V3LmfSuite.hybridX25519MlKem768Aes256Gcm,
    int flags = 0,
  }) {
    if (flags != 0) {
      throw ArgumentError.value(flags, 'flags', 'no v3 flags are assigned yet');
    }
    _validateUnsigned(epoch, 0x7fffffffffffffff, 'epoch');
    _validateUnsigned(
      messageCounter,
      0x7fffffffffffffff,
      'messageCounter',
    );
    _validateUnsigned(
      expiresAtUnixSeconds,
      0xffffffff,
      'expiresAtUnixSeconds',
    );
    return V3LmfMessageMetadata._(
      kind: kind,
      senderBinding: _validatedOpaqueBytes(
        senderBinding,
        V3LmfFrameCodec.routingBindingBytes,
        'senderBinding',
      ),
      recipientBinding: _validatedOpaqueBytes(
        recipientBinding,
        V3LmfFrameCodec.routingBindingBytes,
        'recipientBinding',
      ),
      messageId: _validatedOpaqueBytes(
        messageId,
        V3LmfFrameCodec.messageIdBytes,
        'messageId',
      ),
      sessionId: _validatedOpaqueBytes(
        sessionId,
        V3LmfFrameCodec.sessionIdBytes,
        'sessionId',
      ),
      epoch: epoch,
      messageCounter: messageCounter,
      expiresAtUnixSeconds: expiresAtUnixSeconds,
      suite: suite,
      flags: flags,
    );
  }

  const V3LmfMessageMetadata._({
    required this.kind,
    required Uint8List senderBinding,
    required Uint8List recipientBinding,
    required Uint8List messageId,
    required Uint8List sessionId,
    required this.epoch,
    required this.messageCounter,
    required this.expiresAtUnixSeconds,
    required this.suite,
    required this.flags,
  })  : _senderBinding = senderBinding,
        _recipientBinding = recipientBinding,
        _messageId = messageId,
        _sessionId = sessionId;

  final V3LmfFrameKind kind;
  final V3LmfSuite suite;
  final int flags;
  final Uint8List _senderBinding;
  final Uint8List _recipientBinding;
  final Uint8List _messageId;
  final Uint8List _sessionId;
  final int epoch;
  final int messageCounter;

  /// Authenticated sender policy value. Zero means no sender-declared expiry.
  /// Clock interpretation is intentionally left to a higher-level policy.
  final int expiresAtUnixSeconds;

  Uint8List get senderBinding => Uint8List.fromList(_senderBinding);

  Uint8List get recipientBinding => Uint8List.fromList(_recipientBinding);

  Uint8List get messageId => Uint8List.fromList(_messageId);

  Uint8List get sessionId => Uint8List.fromList(_sessionId);
}

/// One canonical, independently authenticated LMF v3 frame.
///
/// The encrypted fragment remains opaque. For multi-frame messages, plaintext
/// is exposed only by [V3LmfReassembler] after every fragment authenticates.
class V3LmfFrame {
  factory V3LmfFrame({
    required V3LmfMessageMetadata metadata,
    required int fragmentIndex,
    required int fragmentCount,
    required int assembledPlaintextLength,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List authenticationTag,
    V3HybridRatchetHeader? hybridRatchetHeader,
    Uint8List? hybridRatchetHeaderDigest,
    int hybridRatchetHeaderLength = 0,
  }) {
    final copiedNonce = _validatedBytes(
      nonce,
      V3LmfFrameCodec.nonceBytes,
      'nonce',
    );
    final copiedCiphertext = _validatedCiphertext(ciphertext);
    final copiedTag = _validatedBytes(
      authenticationTag,
      V3LmfFrameCodec.authenticationTagBytes,
      'authenticationTag',
    );
    final hybridBinding = _validatedHybridRatchetBinding(
      metadata: metadata,
      fragmentIndex: fragmentIndex,
      hybridRatchetHeader: hybridRatchetHeader,
      hybridRatchetHeaderDigest: hybridRatchetHeaderDigest,
      hybridRatchetHeaderLength: hybridRatchetHeaderLength,
    );
    _validateFragmentShape(
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
      assembledPlaintextLength: assembledPlaintextLength,
      ciphertextLength: copiedCiphertext.length,
      hybridRatchetHeaderLength: hybridBinding.totalLength,
    );
    return V3LmfFrame._(
      metadata: metadata,
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
      assembledPlaintextLength: assembledPlaintextLength,
      nonce: copiedNonce,
      ciphertext: copiedCiphertext,
      authenticationTag: copiedTag,
      hybridRatchetHeaderBytes: hybridBinding.encodedHeader,
      hybridRatchetHeaderDigest: hybridBinding.digest,
      hybridRatchetHeaderLength: hybridBinding.totalLength,
    );
  }

  const V3LmfFrame._({
    required this.metadata,
    required this.fragmentIndex,
    required this.fragmentCount,
    required this.assembledPlaintextLength,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List authenticationTag,
    required Uint8List? hybridRatchetHeaderBytes,
    required Uint8List hybridRatchetHeaderDigest,
    required int hybridRatchetHeaderLength,
  })  : _nonce = nonce,
        _ciphertext = ciphertext,
        _authenticationTag = authenticationTag,
        _hybridRatchetHeaderBytes = hybridRatchetHeaderBytes,
        _hybridRatchetHeaderDigest = hybridRatchetHeaderDigest,
        _hybridRatchetHeaderLength = hybridRatchetHeaderLength;

  final V3LmfMessageMetadata metadata;
  final int fragmentIndex;
  final int fragmentCount;
  final int assembledPlaintextLength;
  final Uint8List _nonce;
  final Uint8List _ciphertext;
  final Uint8List _authenticationTag;
  final Uint8List? _hybridRatchetHeaderBytes;
  final Uint8List _hybridRatchetHeaderDigest;
  final int _hybridRatchetHeaderLength;

  Uint8List get nonce => Uint8List.fromList(_nonce);

  Uint8List get ciphertext => Uint8List.fromList(_ciphertext);

  Uint8List get authenticationTag => Uint8List.fromList(_authenticationTag);

  /// Exact canonical HR3 bytes, present only on fragment zero.
  Uint8List? get hybridRatchetHeaderBytes => _hybridRatchetHeaderBytes == null
      ? null
      : Uint8List.fromList(_hybridRatchetHeaderBytes);

  /// Domain-separated digest that binds every fragment to the same HR3.
  Uint8List get hybridRatchetHeaderDigest =>
      Uint8List.fromList(_hybridRatchetHeaderDigest);

  V3HybridRatchetHeader? get hybridRatchetHeader =>
      _hybridRatchetHeaderBytes == null
          ? null
          : V3HybridRatchetHeaderCodec.decode(
              Uint8List.fromList(_hybridRatchetHeaderBytes),
            );

  int get hybridRatchetHeaderLength => _hybridRatchetHeaderLength;

  bool get isFragmented => fragmentCount > 1;
}

/// Canonical binary, text, link, and steganographic codec for inactive LMF v3.
abstract final class V3LmfFrameCodec {
  static const int protocolVersion = 3;
  static const List<int> magic = <int>[0x4c, 0x4d, 0x33]; // "LM3"
  static const int routingBindingBytes = 32;
  static const int messageIdBytes = 16;
  static const int sessionIdBytes = 16;
  static const int nonceBytes = 12;
  static const int authenticationTagBytes = 16;
  static const int hybridRatchetHeaderDigestBytes = 32;

  /// Continuation fragments use this canonical payload size. A first fragment
  /// carrying HR3 may be smaller so every encoded transport remains portable.
  static const int fragmentPlaintextBytes = 256;
  static const int maxFragments = 64;
  static const int maxAssembledPlaintextBytes =
      fragmentPlaintextBytes * maxFragments;

  static const int headerBytes = 180;
  static const int maxPortableStegoFrameBytes = 828;
  static const int minBinaryFrameBytes =
      headerBytes + 1 + authenticationTagBytes;
  static const int maxBinaryFrameBytes =
      headerBytes + maxAssembledPlaintextBytes + authenticationTagBytes;

  static const String tokenPrefix = 'm3.';
  static const String scheme = 'layergram';
  static const String messageHost = 'm';
  static const int maxTokenCharacters =
      3 + ((maxBinaryFrameBytes * 4 + 2) ~/ 3);
  static const int maxLinkCharacters =
      14 + maxTokenCharacters; // "layergram://m/"

  /// Conservative common-app sharing target. Actual adapters may enforce a
  /// smaller channel-specific value or require fragmentation.
  static const int portableShareCharacterLimit = 4000;

  /// Hard input cap applied before a steganographic decoder collects runes.
  static const int maxStegoInputCodeUnits = 131072;

  static Uint8List encodeBinary(V3LmfFrame frame) {
    final header = authenticationData(frame);
    final result = Uint8List(
      header.length + frame._ciphertext.length + authenticationTagBytes,
    );
    result.setRange(0, header.length, header);
    var offset = header.length;
    result.setRange(
      offset,
      offset + frame._ciphertext.length,
      frame._ciphertext,
    );
    offset += frame._ciphertext.length;
    result.setRange(
      offset,
      offset + authenticationTagBytes,
      frame._authenticationTag,
    );
    return result;
  }

  /// Exact bytes passed as AES-GCM associated authenticated data.
  static Uint8List authenticationData(V3LmfFrame frame) {
    final base = _encodeHeader(
      metadata: frame.metadata,
      fragmentIndex: frame.fragmentIndex,
      fragmentCount: frame.fragmentCount,
      assembledPlaintextLength: frame.assembledPlaintextLength,
      nonce: frame._nonce,
      ciphertextLength: frame._ciphertext.length,
      hybridRatchetHeaderLength: frame._hybridRatchetHeaderLength,
      hybridRatchetHeaderDigest: frame._hybridRatchetHeaderDigest,
    );
    final embedded = frame._hybridRatchetHeaderBytes;
    if (embedded == null) return base;
    final result = Uint8List(base.length + embedded.length);
    result.setRange(0, base.length, base);
    result.setRange(base.length, result.length, embedded);
    return result;
  }

  /// Stable, non-secret identifier for one logical framed message.
  ///
  /// It is a domain-separated SHA-256 digest over the canonical context used
  /// by reassembly. It is suitable as an encrypted local persistence key, not
  /// as contact authentication or a public identity identifier.
  static String assemblyId(V3LmfFrame frame) {
    final metadata = frame.metadata;
    final binding = <int>[
      ...utf8.encode('layergram/v3/lmf/assembly-id\u0000'),
      metadata.suite.wireId,
      metadata.kind.wireId,
      ...metadata._senderBinding,
      ...metadata._recipientBinding,
      ...metadata._messageId,
      ...metadata._sessionId,
    ];
    return base64UrlEncode(crypto.sha256.convert(binding).bytes)
        .replaceAll('=', '');
  }

  static V3LmfFrame decodeBinary(Uint8List encoded) {
    if (encoded.length < minBinaryFrameBytes ||
        encoded.length > maxBinaryFrameBytes) {
      throw const FormatException('Invalid Layergram v3 frame length');
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException('Invalid Layergram v3 frame magic');
      }
    }
    if (encoded[3] != protocolVersion) {
      throw const FormatException('Unsupported Layergram v3 frame version');
    }

    final suite = V3LmfSuite.fromWireId(encoded[4]);
    final kind = V3LmfFrameKind.fromWireId(encoded[5]);
    final flags = encoded[6];
    if (flags != 0) {
      throw const FormatException('Unsupported Layergram v3 frame flags');
    }
    if (encoded[7] != headerBytes) {
      throw const FormatException('Non-canonical Layergram v3 header length');
    }

    final data = ByteData.sublistView(encoded);
    final ciphertextLength = data.getUint16(8, Endian.big);
    if (ciphertextLength == 0 ||
        ciphertextLength > maxAssembledPlaintextBytes) {
      throw const FormatException('Invalid Layergram v3 ciphertext length');
    }
    var offset = 10;
    final senderBinding = _copyRange(
      encoded,
      offset,
      routingBindingBytes,
    );
    offset += routingBindingBytes;
    final recipientBinding = _copyRange(
      encoded,
      offset,
      routingBindingBytes,
    );
    offset += routingBindingBytes;
    final messageId = _copyRange(encoded, offset, messageIdBytes);
    offset += messageIdBytes;
    final sessionId = _copyRange(encoded, offset, sessionIdBytes);
    offset += sessionIdBytes;
    final epoch = data.getUint64(offset, Endian.big);
    offset += 8;
    final messageCounter = data.getUint64(offset, Endian.big);
    offset += 8;
    final expiresAtUnixSeconds = data.getUint32(offset, Endian.big);
    offset += 4;
    final fragmentIndex = data.getUint16(offset, Endian.big);
    offset += 2;
    final fragmentCount = data.getUint16(offset, Endian.big);
    offset += 2;
    final assembledPlaintextLength = data.getUint32(offset, Endian.big);
    offset += 4;
    final nonce = _copyRange(encoded, offset, nonceBytes);
    offset += nonceBytes;
    final hybridRatchetHeaderLength = data.getUint16(offset, Endian.big);
    offset += 2;
    if (hybridRatchetHeaderLength != 0 &&
        (hybridRatchetHeaderLength <
                V3HybridRatchetHeaderCodec.minEncodedBytes ||
            hybridRatchetHeaderLength >
                V3HybridRatchetHeaderCodec.maxEncodedBytes)) {
      throw const FormatException(
        'Invalid Layergram v3 hybrid ratchet header length',
      );
    }
    final hybridRatchetHeaderDigest = _copyRange(
      encoded,
      offset,
      hybridRatchetHeaderDigestBytes,
    );
    offset += hybridRatchetHeaderDigestBytes;
    if (offset != headerBytes) {
      throw StateError('Layergram v3 header implementation drift');
    }

    final embeddedHybridHeaderLength =
        fragmentIndex == 0 ? hybridRatchetHeaderLength : 0;
    final expectedLength = headerBytes +
        embeddedHybridHeaderLength +
        ciphertextLength +
        authenticationTagBytes;
    if (encoded.length != expectedLength) {
      throw const FormatException('Non-canonical Layergram v3 frame length');
    }

    V3HybridRatchetHeader? hybridRatchetHeader;
    if (embeddedHybridHeaderLength != 0) {
      hybridRatchetHeader = V3HybridRatchetHeaderCodec.decode(
        _copyRange(encoded, offset, embeddedHybridHeaderLength),
      );
      offset += embeddedHybridHeaderLength;
    }
    final ciphertext = _copyRange(encoded, offset, ciphertextLength);
    offset += ciphertextLength;
    final tag = _copyRange(encoded, offset, authenticationTagBytes);

    try {
      final metadata = V3LmfMessageMetadata(
        kind: kind,
        senderBinding: senderBinding,
        recipientBinding: recipientBinding,
        messageId: messageId,
        sessionId: sessionId,
        epoch: epoch,
        messageCounter: messageCounter,
        expiresAtUnixSeconds: expiresAtUnixSeconds,
        suite: suite,
        flags: flags,
      );
      return V3LmfFrame(
        metadata: metadata,
        fragmentIndex: fragmentIndex,
        fragmentCount: fragmentCount,
        assembledPlaintextLength: assembledPlaintextLength,
        nonce: nonce,
        ciphertext: ciphertext,
        authenticationTag: tag,
        hybridRatchetHeader: hybridRatchetHeader,
        hybridRatchetHeaderDigest: hybridRatchetHeaderDigest,
        hybridRatchetHeaderLength: hybridRatchetHeaderLength,
      );
    } on ArgumentError {
      throw const FormatException('Invalid Layergram v3 frame fields');
    }
  }

  static String encodeToken(V3LmfFrame frame) {
    return '$tokenPrefix${base64UrlEncode(encodeBinary(frame)).replaceAll('=', '')}';
  }

  static V3LmfFrame decodeToken(String token) {
    if (token.length < tokenPrefix.length ||
        token.length > maxTokenCharacters ||
        !token.startsWith(tokenPrefix)) {
      throw const FormatException('Invalid Layergram v3 message token');
    }
    final armored = token.substring(tokenPrefix.length);
    if (armored.isEmpty || !_isCanonicalBase64Url(armored)) {
      throw const FormatException('Invalid Layergram v3 message token');
    }
    late final Uint8List bytes;
    try {
      bytes = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(armored)),
      );
    } on FormatException {
      throw const FormatException('Invalid Layergram v3 message armor');
    }
    final frame = decodeBinary(bytes);
    if (encodeToken(frame) != token) {
      throw const FormatException('Non-canonical Layergram v3 message token');
    }
    return frame;
  }

  static String encodeLink(V3LmfFrame frame) {
    return Uri(
      scheme: scheme,
      host: messageHost,
      pathSegments: <String>[encodeToken(frame)],
    ).toString();
  }

  static V3LmfFrame decodeLink(String link) {
    if (link.length > maxLinkCharacters) {
      throw const FormatException('Invalid Layergram v3 message link');
    }
    final uri = Uri.tryParse(link);
    if (uri == null ||
        uri.scheme != scheme ||
        uri.host != messageHost ||
        uri.pathSegments.length != 1 ||
        uri.userInfo.isNotEmpty ||
        uri.hasPort ||
        uri.hasQuery ||
        uri.hasFragment) {
      throw const FormatException('Invalid Layergram v3 message link');
    }
    final frame = decodeToken(uri.pathSegments.single);
    if (encodeLink(frame) != link) {
      throw const FormatException('Non-canonical Layergram v3 message link');
    }
    return frame;
  }

  static String encodeStego({
    required V3LmfFrame frame,
    required String coverText,
    int? maxTotalCharacters,
  }) {
    if (coverText.length > maxStegoInputCodeUnits) {
      throw ArgumentError.value(
        coverText.length,
        'coverText.length',
        'exceeds the Layergram v3 stego input limit',
      );
    }
    final encoded = StegoEncoder().encodeBytes(
      coverText,
      encodeBinary(frame),
      maxTotalCharacters: maxTotalCharacters,
    );
    if (encoded.length > maxStegoInputCodeUnits) {
      throw StateError('Layergram v3 stego output exceeds its decoder limit');
    }
    return encoded;
  }

  static V3LmfFrame decodeStego(String stegoText) {
    if (stegoText.length > maxStegoInputCodeUnits) {
      throw const FormatException('Layergram v3 stego input exceeds its limit');
    }
    final payloadRunes = <int>[];
    final maxPayloadRunes = maxBinaryFrameBytes * 4;
    for (final rune in stegoText.runes) {
      if (StegoAlphabetV2.isForbiddenRune(rune)) {
        throw const FormatException('Forbidden Layergram v3 stego rune');
      }
      if (StegoAlphabetV2.isPayloadRune(rune)) {
        if (payloadRunes.length >= maxPayloadRunes) {
          throw const FormatException(
            'Layergram v3 stego payload exceeds its limit',
          );
        }
        payloadRunes.add(rune);
      }
    }
    final bytes = StegoAlphabetV2.payloadRunesToBytes(payloadRunes);
    if (bytes == null || bytes.isEmpty) {
      throw const FormatException('Invalid Layergram v3 stego payload');
    }
    return decodeBinary(bytes);
  }

  static bool fitsPortableText(V3LmfFrame frame) {
    return encodeToken(frame).length <= portableShareCharacterLimit;
  }

  static bool fitsPortableLink(V3LmfFrame frame) {
    return encodeLink(frame).length <= portableShareCharacterLimit;
  }

  static bool fitsPortableStego({
    required V3LmfFrame frame,
    required String coverText,
  }) {
    return StegoEncoder.canEncodeBytesWithinCharacterLimit(
      coverText,
      encodeBinary(frame).length,
      portableShareCharacterLimit,
    );
  }

  static int canonicalFragmentCount({
    required int assembledPlaintextLength,
    int hybridRatchetHeaderLength = 0,
  }) {
    return _fragmentLayout(
      assembledPlaintextLength: assembledPlaintextLength,
      hybridRatchetHeaderLength: hybridRatchetHeaderLength,
    ).length;
  }

  static int firstFragmentPlaintextCapacity({
    int hybridRatchetHeaderLength = 0,
  }) {
    return _firstFragmentPlaintextCapacity(hybridRatchetHeaderLength);
  }

  static int maxAssembledPlaintextBytesForHybridHeader({
    int hybridRatchetHeaderLength = 0,
  }) {
    return _firstFragmentPlaintextCapacity(hybridRatchetHeaderLength) +
        (maxFragments - 1) * fragmentPlaintextBytes;
  }

  static Uint8List digestHybridRatchetHeader(
    V3HybridRatchetHeader hybridRatchetHeader,
  ) {
    return _hybridRatchetHeaderDigest(
      V3HybridRatchetHeaderCodec.encode(hybridRatchetHeader),
    );
  }

  static Uint8List _encodeHeader({
    required V3LmfMessageMetadata metadata,
    required int fragmentIndex,
    required int fragmentCount,
    required int assembledPlaintextLength,
    required Uint8List nonce,
    required int ciphertextLength,
    required int hybridRatchetHeaderLength,
    required Uint8List hybridRatchetHeaderDigest,
  }) {
    _validateFragmentShape(
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
      assembledPlaintextLength: assembledPlaintextLength,
      ciphertextLength: ciphertextLength,
      hybridRatchetHeaderLength: hybridRatchetHeaderLength,
    );
    final checkedNonce = _validatedBytes(nonce, nonceBytes, 'nonce');
    final checkedHybridDigest = _validatedBytes(
      hybridRatchetHeaderDigest,
      hybridRatchetHeaderDigestBytes,
      'hybridRatchetHeaderDigest',
    );
    final header = Uint8List(headerBytes);
    final data = ByteData.sublistView(header);
    var offset = 0;
    header.setRange(offset, offset + magic.length, magic);
    offset += magic.length;
    header[offset++] = protocolVersion;
    header[offset++] = metadata.suite.wireId;
    header[offset++] = metadata.kind.wireId;
    header[offset++] = metadata.flags;
    header[offset++] = headerBytes;
    data.setUint16(offset, ciphertextLength, Endian.big);
    offset += 2;
    header.setRange(
      offset,
      offset + routingBindingBytes,
      metadata._senderBinding,
    );
    offset += routingBindingBytes;
    header.setRange(
      offset,
      offset + routingBindingBytes,
      metadata._recipientBinding,
    );
    offset += routingBindingBytes;
    header.setRange(offset, offset + messageIdBytes, metadata._messageId);
    offset += messageIdBytes;
    header.setRange(offset, offset + sessionIdBytes, metadata._sessionId);
    offset += sessionIdBytes;
    data.setUint64(offset, metadata.epoch, Endian.big);
    offset += 8;
    data.setUint64(offset, metadata.messageCounter, Endian.big);
    offset += 8;
    data.setUint32(offset, metadata.expiresAtUnixSeconds, Endian.big);
    offset += 4;
    data.setUint16(offset, fragmentIndex, Endian.big);
    offset += 2;
    data.setUint16(offset, fragmentCount, Endian.big);
    offset += 2;
    data.setUint32(offset, assembledPlaintextLength, Endian.big);
    offset += 4;
    header.setRange(offset, offset + nonceBytes, checkedNonce);
    offset += nonceBytes;
    data.setUint16(offset, hybridRatchetHeaderLength, Endian.big);
    offset += 2;
    header.setRange(
      offset,
      offset + hybridRatchetHeaderDigestBytes,
      checkedHybridDigest,
    );
    offset += hybridRatchetHeaderDigestBytes;
    if (offset != headerBytes) {
      throw StateError('Layergram v3 header implementation drift');
    }
    return header;
  }
}

/// AES-256-GCM sealing boundary for LMF v3 frames.
///
/// This class deliberately does not derive keys or nonces. In protocol-v3
/// research flows, `V3KeySchedule` supplies the mandatory hybrid key and exact
/// deterministic fragment nonce. Direct callers receive no session-wide nonce
/// or ratchet-safety guarantee.
abstract final class V3LmfAead {
  static final _algorithm = AesGcm.with256bits();

  static Future<V3LmfFrame> sealSingle({
    required V3LmfMessageMetadata metadata,
    required Uint8List plaintext,
    required SecretKey secretKey,
    required Uint8List nonce,
    V3HybridRatchetHeader? hybridRatchetHeader,
  }) async {
    if (plaintext.isEmpty ||
        plaintext.length > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
      throw ArgumentError.value(
        plaintext.length,
        'plaintext.length',
        'must be between 1 and '
            '${V3LmfFrameCodec.maxAssembledPlaintextBytes} bytes',
      );
    }
    final localPlaintext = Uint8List.fromList(plaintext);
    try {
      return await _seal(
        metadata: metadata,
        plaintext: localPlaintext,
        fragmentIndex: 0,
        fragmentCount: 1,
        assembledPlaintextLength: localPlaintext.length,
        secretKey: secretKey,
        nonce: nonce,
        hybridRatchetHeader: hybridRatchetHeader,
        hybridRatchetHeaderDigest: null,
        hybridRatchetHeaderLength: 0,
      );
    } finally {
      localPlaintext.fillRange(0, localPlaintext.length, 0);
    }
  }

  static Future<List<V3LmfFrame>> sealFragmented({
    required V3LmfMessageMetadata metadata,
    required Uint8List plaintext,
    required SecretKey secretKey,
    required Uint8List Function(int fragmentIndex) nonceForFragment,
    V3HybridRatchetHeader? hybridRatchetHeader,
  }) async {
    if (plaintext.isEmpty ||
        plaintext.length > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
      throw ArgumentError.value(
        plaintext.length,
        'plaintext.length',
        'must be between 1 and '
            '${V3LmfFrameCodec.maxAssembledPlaintextBytes} bytes',
      );
    }
    final hybridBinding = _validatedHybridRatchetBinding(
      metadata: metadata,
      fragmentIndex: 0,
      hybridRatchetHeader: hybridRatchetHeader,
      hybridRatchetHeaderDigest: null,
      hybridRatchetHeaderLength: 0,
    );
    final layout = _fragmentLayout(
      assembledPlaintextLength: plaintext.length,
      hybridRatchetHeaderLength: hybridBinding.totalLength,
    );
    final fragmentCount = layout.length;
    final frames = <V3LmfFrame>[];
    final nonces = <String>{};
    for (var fragmentIndex = 0;
        fragmentIndex < fragmentCount;
        fragmentIndex++) {
      final shape = layout[fragmentIndex];
      final start = shape.offset;
      final end = start + shape.length;
      final fragment = Uint8List.fromList(plaintext.sublist(start, end));
      final nonce = _validatedBytes(
        nonceForFragment(fragmentIndex),
        V3LmfFrameCodec.nonceBytes,
        'nonceForFragment($fragmentIndex)',
      );
      final nonceKey = base64UrlEncode(nonce);
      if (!nonces.add(nonceKey)) {
        fragment.fillRange(0, fragment.length, 0);
        throw StateError('Duplicate nonce in one Layergram v3 message');
      }
      try {
        frames.add(
          await _seal(
            metadata: metadata,
            plaintext: fragment,
            fragmentIndex: fragmentIndex,
            fragmentCount: fragmentCount,
            assembledPlaintextLength: plaintext.length,
            secretKey: secretKey,
            nonce: nonce,
            hybridRatchetHeader:
                fragmentIndex == 0 ? hybridRatchetHeader : null,
            hybridRatchetHeaderDigest: hybridBinding.digest,
            hybridRatchetHeaderLength: hybridBinding.totalLength,
          ),
        );
      } finally {
        fragment.fillRange(0, fragment.length, 0);
      }
    }
    return List<V3LmfFrame>.unmodifiable(frames);
  }

  /// Opens only a canonical single-frame message. Fragment plaintext is never
  /// returned through this API; use [V3LmfReassembler] for multi-frame input.
  static Future<Uint8List> openSingle({
    required V3LmfFrame frame,
    required SecretKey secretKey,
  }) async {
    if (frame.isFragmented) {
      throw StateError('Fragmented Layergram v3 messages require reassembly');
    }
    return _open(frame: frame, secretKey: secretKey);
  }

  /// Authenticates any canonical frame and discards its fragment plaintext.
  ///
  /// Persistence uses this for conflicting candidates without creating a
  /// second reassembly path that could expose partial content.
  static Future<void> authenticate({
    required V3LmfFrame frame,
    required SecretKey secretKey,
  }) async {
    final plaintext = await _open(frame: frame, secretKey: secretKey);
    plaintext.fillRange(0, plaintext.length, 0);
  }

  static Future<V3LmfFrame> _seal({
    required V3LmfMessageMetadata metadata,
    required Uint8List plaintext,
    required int fragmentIndex,
    required int fragmentCount,
    required int assembledPlaintextLength,
    required SecretKey secretKey,
    required Uint8List nonce,
    required V3HybridRatchetHeader? hybridRatchetHeader,
    required Uint8List? hybridRatchetHeaderDigest,
    required int hybridRatchetHeaderLength,
  }) async {
    final checkedNonce = _validatedBytes(
      nonce,
      V3LmfFrameCodec.nonceBytes,
      'nonce',
    );
    final hybridBinding = _validatedHybridRatchetBinding(
      metadata: metadata,
      fragmentIndex: fragmentIndex,
      hybridRatchetHeader: hybridRatchetHeader,
      hybridRatchetHeaderDigest: hybridRatchetHeaderDigest,
      hybridRatchetHeaderLength: hybridRatchetHeaderLength,
    );
    final baseAad = V3LmfFrameCodec._encodeHeader(
      metadata: metadata,
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
      assembledPlaintextLength: assembledPlaintextLength,
      nonce: checkedNonce,
      ciphertextLength: plaintext.length,
      hybridRatchetHeaderLength: hybridBinding.totalLength,
      hybridRatchetHeaderDigest: hybridBinding.digest,
    );
    final embedded = hybridBinding.encodedHeader;
    final aad = embedded == null
        ? baseAad
        : (Uint8List(baseAad.length + embedded.length)
          ..setRange(0, baseAad.length, baseAad)
          ..setRange(
              baseAad.length, baseAad.length + embedded.length, embedded));
    final box = await _algorithm.encrypt(
      plaintext,
      secretKey: secretKey,
      nonce: checkedNonce,
      aad: aad,
    );
    return V3LmfFrame._(
      metadata: metadata,
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
      assembledPlaintextLength: assembledPlaintextLength,
      nonce: Uint8List.fromList(box.nonce),
      ciphertext: Uint8List.fromList(box.cipherText),
      authenticationTag: Uint8List.fromList(box.mac.bytes),
      hybridRatchetHeaderBytes: embedded,
      hybridRatchetHeaderDigest: hybridBinding.digest,
      hybridRatchetHeaderLength: hybridBinding.totalLength,
    );
  }

  static Future<Uint8List> _open({
    required V3LmfFrame frame,
    required SecretKey secretKey,
  }) async {
    final cleartext = await _algorithm.decrypt(
      SecretBox(
        frame._ciphertext,
        nonce: frame._nonce,
        mac: Mac(frame._authenticationTag),
      ),
      secretKey: secretKey,
      aad: V3LmfFrameCodec.authenticationData(frame),
    );
    final result = Uint8List.fromList(cleartext);
    cleartext.fillRange(0, cleartext.length, 0);
    return result;
  }
}

enum V3LmfReassemblyStatus { accepted, duplicate, complete }

/// Result that never exposes an incomplete authenticated fragment.
class V3LmfReassemblyOutcome {
  const V3LmfReassemblyOutcome._(this.status, this._plaintext);

  const V3LmfReassemblyOutcome.accepted()
      : this._(V3LmfReassemblyStatus.accepted, null);

  const V3LmfReassemblyOutcome.duplicate()
      : this._(V3LmfReassemblyStatus.duplicate, null);

  V3LmfReassemblyOutcome.complete(Uint8List plaintext)
      : this._(
          V3LmfReassemblyStatus.complete,
          Uint8List.fromList(plaintext),
        );

  final V3LmfReassemblyStatus status;
  final Uint8List? _plaintext;

  bool get isComplete => status == V3LmfReassemblyStatus.complete;

  Uint8List? get plaintext =>
      _plaintext == null ? null : Uint8List.fromList(_plaintext);

  /// Best-effort wipes complete plaintext retained by this managed result.
  void wipePlaintext() {
    _plaintext?.fillRange(0, _plaintext.length, 0);
  }
}

class V3LmfReassemblyLimitException implements Exception {
  const V3LmfReassemblyLimitException(this.message);

  final String message;

  @override
  String toString() => 'V3LmfReassemblyLimitException: $message';
}

class V3LmfReassemblyConflictException implements Exception {
  const V3LmfReassemblyConflictException(this.message);

  final String message;

  @override
  String toString() => 'V3LmfReassemblyConflictException: $message';
}

/// Bounded, duplicate-aware reassembler for authenticated LMF v3 fragments.
///
/// Persistence remains outside this cryptographic primitive. The inactive
/// durable inbox wraps it by storing each sealed frame before calling [accept];
/// callers that use this class directly receive no crash-recovery guarantee.
class V3LmfReassembler {
  V3LmfReassembler({
    this.maxPendingAssemblies = 8,
    this.maxBufferedPlaintextBytes = 64 * 1024,
  }) {
    if (maxPendingAssemblies <= 0) {
      throw ArgumentError.value(
        maxPendingAssemblies,
        'maxPendingAssemblies',
        'must be positive',
      );
    }
    if (maxBufferedPlaintextBytes <= 0) {
      throw ArgumentError.value(
        maxBufferedPlaintextBytes,
        'maxBufferedPlaintextBytes',
        'must be positive',
      );
    }
  }

  final int maxPendingAssemblies;
  final int maxBufferedPlaintextBytes;
  final Map<String, _PendingAssembly> _pending = <String, _PendingAssembly>{};
  int _bufferedPlaintextBytes = 0;
  bool _isClosed = false;

  int get pendingAssemblyCount => _pending.length;

  int get bufferedPlaintextBytes => _bufferedPlaintextBytes;

  Future<V3LmfReassemblyOutcome> accept({
    required V3LmfFrame frame,
    required SecretKey secretKey,
    DateTime? receivedAt,
  }) async {
    if (_isClosed) {
      throw StateError('Layergram v3 reassembler is closed');
    }

    final plaintext = await V3LmfAead._open(
      frame: frame,
      secretKey: secretKey,
    );
    if (_isClosed) {
      plaintext.fillRange(0, plaintext.length, 0);
      throw StateError('Layergram v3 reassembler is closed');
    }
    if (!frame.isFragmented) {
      final outcome = V3LmfReassemblyOutcome.complete(plaintext);
      plaintext.fillRange(0, plaintext.length, 0);
      return outcome;
    }

    final assemblyKey = V3LmfFrameCodec.assemblyId(frame);
    final now = (receivedAt ?? DateTime.now()).toUtc();
    var state = _pending[assemblyKey];
    if (state == null) {
      if (_pending.length >= maxPendingAssemblies) {
        plaintext.fillRange(0, plaintext.length, 0);
        throw const V3LmfReassemblyLimitException(
          'pending assembly limit reached',
        );
      }
      state = _PendingAssembly(frame: frame, lastUpdated: now);
      _pending[assemblyKey] = state;
    } else if (!state.matches(frame)) {
      plaintext.fillRange(0, plaintext.length, 0);
      _removeAndWipe(assemblyKey);
      throw const V3LmfReassemblyConflictException(
        'authenticated fragment metadata conflict',
      );
    }

    final frameDigest = Uint8List.fromList(
      crypto.sha256
          .convert(V3LmfFrameCodec.encodeBinary(frame))
          .bytes
          .toList(growable: false),
    );
    final previous = state.fragments[frame.fragmentIndex];
    if (previous != null) {
      final sameFrame = _constantTimeEquals(previous.frameDigest, frameDigest);
      final samePlaintext = _constantTimeEquals(previous.plaintext, plaintext);
      plaintext.fillRange(0, plaintext.length, 0);
      frameDigest.fillRange(0, frameDigest.length, 0);
      if (!sameFrame || !samePlaintext) {
        _removeAndWipe(assemblyKey);
        throw const V3LmfReassemblyConflictException(
          'authenticated duplicate fragment conflict',
        );
      }
      state.lastUpdated = now;
      return const V3LmfReassemblyOutcome.duplicate();
    }

    if (_bufferedPlaintextBytes + plaintext.length >
        maxBufferedPlaintextBytes) {
      plaintext.fillRange(0, plaintext.length, 0);
      frameDigest.fillRange(0, frameDigest.length, 0);
      if (state.fragments.isEmpty) {
        _pending.remove(assemblyKey);
      }
      throw const V3LmfReassemblyLimitException(
        'buffered plaintext limit reached',
      );
    }

    state.fragments[frame.fragmentIndex] = _BufferedFragment(
      plaintext: plaintext,
      frameDigest: frameDigest,
    );
    state.lastUpdated = now;
    _bufferedPlaintextBytes += plaintext.length;
    if (state.fragments.length != frame.fragmentCount) {
      return const V3LmfReassemblyOutcome.accepted();
    }

    final assembled = Uint8List(frame.assembledPlaintextLength);
    var offset = 0;
    for (var index = 0; index < frame.fragmentCount; index++) {
      final bufferedFragment = state.fragments[index];
      if (bufferedFragment == null) {
        _removeAndWipe(assemblyKey);
        throw const V3LmfReassemblyConflictException(
          'fragment set is incomplete',
        );
      }
      final fragment = bufferedFragment.plaintext;
      assembled.setRange(offset, offset + fragment.length, fragment);
      offset += fragment.length;
    }
    if (offset != frame.assembledPlaintextLength) {
      assembled.fillRange(0, assembled.length, 0);
      _removeAndWipe(assemblyKey);
      throw const V3LmfReassemblyConflictException(
        'assembled plaintext length mismatch',
      );
    }
    _removeAndWipe(assemblyKey);
    final outcome = V3LmfReassemblyOutcome.complete(assembled);
    assembled.fillRange(0, assembled.length, 0);
    return outcome;
  }

  /// Removes pending assemblies last touched at or before [cutoff]. Retention
  /// policy is explicit because Layergram has no trusted shared clock and
  /// legitimate manual exchanges may take a long time.
  int purgeOlderThan(DateTime cutoff) {
    if (_isClosed) return 0;
    final normalized = cutoff.toUtc();
    final keys = _pending.entries
        .where(
          (entry) =>
              entry.value.lastUpdated.isBefore(normalized) ||
              entry.value.lastUpdated.isAtSameMomentAs(normalized),
        )
        .map((entry) => entry.key)
        .toList(growable: false);
    for (final key in keys) {
      _removeAndWipe(key);
    }
    return keys.length;
  }

  /// Wipes one pending assembly after a durable-storage conflict or explicit
  /// cancellation. A completed or unknown assembly is a no-op.
  bool discardAssembly(V3LmfFrame frame) {
    if (_isClosed) return false;
    final key = V3LmfFrameCodec.assemblyId(frame);
    if (!_pending.containsKey(key)) return false;
    _removeAndWipe(key);
    return true;
  }

  void close() {
    if (_isClosed) return;
    for (final state in _pending.values) {
      state.wipe();
    }
    _pending.clear();
    _bufferedPlaintextBytes = 0;
    _isClosed = true;
  }

  void _removeAndWipe(String key) {
    final state = _pending.remove(key);
    if (state == null) return;
    _bufferedPlaintextBytes -= state.bufferedBytes;
    state.wipe();
  }
}

class _PendingAssembly {
  _PendingAssembly({required V3LmfFrame frame, required this.lastUpdated})
      : metadata = frame.metadata,
        fragmentCount = frame.fragmentCount,
        assembledPlaintextLength = frame.assembledPlaintextLength,
        hybridRatchetHeaderLength = frame._hybridRatchetHeaderLength,
        hybridRatchetHeaderDigest =
            Uint8List.fromList(frame._hybridRatchetHeaderDigest);

  final V3LmfMessageMetadata metadata;
  final int fragmentCount;
  final int assembledPlaintextLength;
  final int hybridRatchetHeaderLength;
  final Uint8List hybridRatchetHeaderDigest;
  final Map<int, _BufferedFragment> fragments = <int, _BufferedFragment>{};
  DateTime lastUpdated;

  int get bufferedBytes =>
      fragments.values.fold<int>(0, (sum, item) => sum + item.plaintext.length);

  bool matches(V3LmfFrame frame) {
    final other = frame.metadata;
    return metadata.suite == other.suite &&
        metadata.kind == other.kind &&
        metadata.flags == other.flags &&
        metadata.epoch == other.epoch &&
        metadata.messageCounter == other.messageCounter &&
        metadata.expiresAtUnixSeconds == other.expiresAtUnixSeconds &&
        fragmentCount == frame.fragmentCount &&
        assembledPlaintextLength == frame.assembledPlaintextLength &&
        hybridRatchetHeaderLength == frame._hybridRatchetHeaderLength &&
        _constantTimeEquals(
          hybridRatchetHeaderDigest,
          frame._hybridRatchetHeaderDigest,
        ) &&
        _constantTimeEquals(metadata._senderBinding, other._senderBinding) &&
        _constantTimeEquals(
          metadata._recipientBinding,
          other._recipientBinding,
        ) &&
        _constantTimeEquals(metadata._messageId, other._messageId) &&
        _constantTimeEquals(metadata._sessionId, other._sessionId);
  }

  void wipe() {
    for (final fragment in fragments.values) {
      fragment.wipe();
    }
    fragments.clear();
    hybridRatchetHeaderDigest.fillRange(
      0,
      hybridRatchetHeaderDigest.length,
      0,
    );
  }
}

class _BufferedFragment {
  _BufferedFragment({required this.plaintext, required this.frameDigest});

  final Uint8List plaintext;
  final Uint8List frameDigest;

  void wipe() {
    plaintext.fillRange(0, plaintext.length, 0);
    frameDigest.fillRange(0, frameDigest.length, 0);
  }
}

final class _HybridRatchetBinding {
  const _HybridRatchetBinding({
    required this.encodedHeader,
    required this.digest,
    required this.totalLength,
  });

  final Uint8List? encodedHeader;
  final Uint8List digest;
  final int totalLength;
}

_HybridRatchetBinding _validatedHybridRatchetBinding({
  required V3LmfMessageMetadata metadata,
  required int fragmentIndex,
  required V3HybridRatchetHeader? hybridRatchetHeader,
  required Uint8List? hybridRatchetHeaderDigest,
  required int hybridRatchetHeaderLength,
}) {
  final providedDigest = hybridRatchetHeaderDigest == null
      ? null
      : _validatedBytes(
          hybridRatchetHeaderDigest,
          V3LmfFrameCodec.hybridRatchetHeaderDigestBytes,
          'hybridRatchetHeaderDigest',
        );
  final encoded = hybridRatchetHeader == null
      ? null
      : V3HybridRatchetHeaderCodec.encode(hybridRatchetHeader);
  final totalLength = encoded == null
      ? hybridRatchetHeaderLength
      : (hybridRatchetHeaderLength == 0
          ? encoded.length
          : hybridRatchetHeaderLength);
  if (totalLength < 0 ||
      (totalLength != 0 &&
          (totalLength < V3HybridRatchetHeaderCodec.minEncodedBytes ||
              totalLength > V3HybridRatchetHeaderCodec.maxEncodedBytes)) ||
      (encoded != null && encoded.length != totalLength)) {
    throw ArgumentError.value(
      hybridRatchetHeaderLength,
      'hybridRatchetHeaderLength',
      'does not describe one canonical HR3 header',
    );
  }

  final requiresHybrid = metadata.kind == V3LmfFrameKind.application ||
      metadata.kind == V3LmfFrameKind.pqRatchet;
  if (!requiresHybrid) {
    if (encoded != null ||
        totalLength != 0 ||
        (providedDigest != null && !_isAllZero(providedDigest))) {
      throw ArgumentError(
        'Layergram v3 handshake and acknowledgement frames cannot carry HR3',
      );
    }
    return _HybridRatchetBinding(
      encodedHeader: null,
      digest: Uint8List(V3LmfFrameCodec.hybridRatchetHeaderDigestBytes),
      totalLength: 0,
    );
  }

  if (totalLength == 0) {
    throw ArgumentError('Layergram v3 application/control frame requires HR3');
  }
  if (fragmentIndex == 0 && encoded == null) {
    throw ArgumentError('Layergram v3 first fragment must carry complete HR3');
  }
  if (fragmentIndex != 0 && encoded != null) {
    throw ArgumentError(
      'Layergram v3 continuation fragments reference HR3 by digest only',
    );
  }

  Uint8List digest;
  if (providedDigest == null) {
    if (encoded == null) {
      throw ArgumentError(
        'Layergram v3 continuation fragment requires the HR3 digest',
      );
    }
    digest = _hybridRatchetHeaderDigest(encoded);
  } else {
    digest = providedDigest;
    if (_isAllZero(digest)) {
      throw ArgumentError(
        'Layergram v3 hybrid ratchet header digest must not be zero',
      );
    }
    if (encoded != null) {
      final expected = _hybridRatchetHeaderDigest(encoded);
      final matches = _constantTimeEquals(digest, expected);
      expected.fillRange(0, expected.length, 0);
      if (!matches) {
        throw ArgumentError(
          'Layergram v3 hybrid ratchet header digest mismatch',
        );
      }
    }
  }

  if (hybridRatchetHeader != null &&
      (hybridRatchetHeader.sckaMessage.sendingEpoch != metadata.epoch ||
          hybridRatchetHeader.sckaMessage.messageCounter !=
              metadata.messageCounter)) {
    digest.fillRange(0, digest.length, 0);
    throw ArgumentError(
      'Layergram v3 HR3 PQ coordinates do not match LMF metadata',
    );
  }
  return _HybridRatchetBinding(
    encodedHeader: encoded,
    digest: digest,
    totalLength: totalLength,
  );
}

Uint8List _hybridRatchetHeaderDigest(Uint8List encoded) => Uint8List.fromList(
      crypto.sha256.convert(<int>[
        ...utf8.encode('layergram/v3/lmf/hybrid-ratchet-header\u0000'),
        ...encoded,
      ]).bytes,
    );

final class _FragmentShape {
  const _FragmentShape({required this.offset, required this.length});

  final int offset;
  final int length;
}

List<_FragmentShape> _fragmentLayout({
  required int assembledPlaintextLength,
  required int hybridRatchetHeaderLength,
}) {
  if (assembledPlaintextLength < 1 ||
      assembledPlaintextLength > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
    throw ArgumentError.value(
      assembledPlaintextLength,
      'assembledPlaintextLength',
      'is outside the Layergram v3 limit',
    );
  }
  final boundedFirstCapacity =
      _firstFragmentPlaintextCapacity(hybridRatchetHeaderLength);
  final shapes = <_FragmentShape>[];
  final firstLength = assembledPlaintextLength < boundedFirstCapacity
      ? assembledPlaintextLength
      : boundedFirstCapacity;
  shapes.add(_FragmentShape(offset: 0, length: firstLength));
  var offset = firstLength;
  while (offset < assembledPlaintextLength) {
    if (shapes.length >= V3LmfFrameCodec.maxFragments) {
      throw ArgumentError(
        'Layergram v3 fragmented message exceeds its fragment limit',
      );
    }
    final remaining = assembledPlaintextLength - offset;
    final length = remaining < V3LmfFrameCodec.fragmentPlaintextBytes
        ? remaining
        : V3LmfFrameCodec.fragmentPlaintextBytes;
    shapes.add(_FragmentShape(offset: offset, length: length));
    offset += length;
  }
  return List<_FragmentShape>.unmodifiable(shapes);
}

int _firstFragmentPlaintextCapacity(int hybridRatchetHeaderLength) {
  if (hybridRatchetHeaderLength < 0 ||
      (hybridRatchetHeaderLength != 0 &&
          (hybridRatchetHeaderLength <
                  V3HybridRatchetHeaderCodec.minEncodedBytes ||
              hybridRatchetHeaderLength >
                  V3HybridRatchetHeaderCodec.maxEncodedBytes))) {
    throw ArgumentError.value(
      hybridRatchetHeaderLength,
      'hybridRatchetHeaderLength',
    );
  }
  final capacity = hybridRatchetHeaderLength == 0
      ? V3LmfFrameCodec.fragmentPlaintextBytes
      : V3LmfFrameCodec.maxPortableStegoFrameBytes -
          V3LmfFrameCodec.headerBytes -
          hybridRatchetHeaderLength -
          V3LmfFrameCodec.authenticationTagBytes;
  if (capacity < 1) {
    throw ArgumentError(
      'Layergram v3 HR3 leaves no portable first-fragment capacity',
    );
  }
  return capacity < V3LmfFrameCodec.fragmentPlaintextBytes
      ? capacity
      : V3LmfFrameCodec.fragmentPlaintextBytes;
}

void _validateFragmentShape({
  required int fragmentIndex,
  required int fragmentCount,
  required int assembledPlaintextLength,
  required int ciphertextLength,
  required int hybridRatchetHeaderLength,
}) {
  if (fragmentCount < 1 || fragmentCount > V3LmfFrameCodec.maxFragments) {
    throw ArgumentError.value(
      fragmentCount,
      'fragmentCount',
      'must be between 1 and ${V3LmfFrameCodec.maxFragments}',
    );
  }
  if (fragmentIndex < 0 || fragmentIndex >= fragmentCount) {
    throw ArgumentError.value(
      fragmentIndex,
      'fragmentIndex',
      'must identify one fragment in the declared set',
    );
  }
  if (ciphertextLength < 1 ||
      ciphertextLength > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
    throw ArgumentError.value(
      ciphertextLength,
      'ciphertextLength',
      'is outside the Layergram v3 limit',
    );
  }

  if (fragmentCount == 1 && hybridRatchetHeaderLength == 0) {
    if (fragmentIndex != 0 || ciphertextLength != assembledPlaintextLength) {
      throw ArgumentError('Non-canonical single-frame Layergram v3 message');
    }
    return;
  }

  final layout = _fragmentLayout(
    assembledPlaintextLength: assembledPlaintextLength,
    hybridRatchetHeaderLength: hybridRatchetHeaderLength,
  );
  if (fragmentCount != layout.length) {
    throw ArgumentError('Non-canonical Layergram v3 fragment count');
  }
  if (ciphertextLength != layout[fragmentIndex].length) {
    throw ArgumentError('Non-canonical Layergram v3 fragment length');
  }
}

Uint8List _validatedOpaqueBytes(
  Uint8List value,
  int expectedLength,
  String name,
) {
  final copy = _validatedBytes(value, expectedLength, name);
  var anyNonZero = false;
  for (final byte in copy) {
    anyNonZero |= byte != 0;
  }
  if (!anyNonZero) {
    throw ArgumentError.value(value, name, 'must not be all zero');
  }
  return copy;
}

Uint8List _validatedBytes(
  Uint8List value,
  int expectedLength,
  String name,
) {
  if (value.length != expectedLength) {
    throw ArgumentError.value(
      value.length,
      '$name.length',
      'must be exactly $expectedLength bytes',
    );
  }
  return Uint8List.fromList(value);
}

Uint8List _validatedCiphertext(Uint8List value) {
  if (value.isEmpty ||
      value.length > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
    throw ArgumentError.value(
      value.length,
      'ciphertext.length',
      'is outside the Layergram v3 limit',
    );
  }
  return Uint8List.fromList(value);
}

void _validateUnsigned(int value, int maximum, String name) {
  if (value < 0 || value > maximum) {
    throw ArgumentError.value(value, name, 'is outside its unsigned range');
  }
}

Uint8List _copyRange(Uint8List source, int offset, int length) {
  return Uint8List.fromList(source.sublist(offset, offset + length));
}

bool _isCanonicalBase64Url(String value) {
  for (final codeUnit in value.codeUnits) {
    final isUppercase = codeUnit >= 0x41 && codeUnit <= 0x5a;
    final isLowercase = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final isDigit = codeUnit >= 0x30 && codeUnit <= 0x39;
    if (!isUppercase &&
        !isLowercase &&
        !isDigit &&
        codeUnit != 0x2d &&
        codeUnit != 0x5f) {
      return false;
    }
  }
  return true;
}

bool _constantTimeEquals(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool _isAllZero(Uint8List value) {
  var accumulator = 0;
  for (final byte in value) {
    accumulator |= byte;
  }
  return accumulator == 0;
}
