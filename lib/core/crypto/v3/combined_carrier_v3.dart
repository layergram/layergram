// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

import 'dart:convert';
import 'dart:typed_data';

import '../stego_alphabet_v2.dart';
import '../stego_decoder.dart';
import '../stego_encoder.dart';
import 'lmf_v3.dart';

/// A bounded transport wrapper for one application LMF frame and its ACKs.
///
/// Inner frames remain byte-for-byte canonical LMFv3 frames. This codec adds
/// no authentication: callers must pass decoded frames through the ordinary
/// authenticated LMF receive path.
abstract final class V3CombinedCarrierCodec {
  static const List<int> magic = <int>[0x4c, 0x33, 0x42]; // "L3B"
  static const int version = 1;
  static const int minFrames = 2;
  static const int maxFrames = 16;
  static const int headerBytes = 5;
  static const int lengthPrefixBytes = 4;

  static const String tokenPrefix = 'b3.';
  static const String scheme = 'layergram';
  static const String messageHost = 'm';
  static const int portableShareCharacterLimit = 4000;

  /// Matches the existing stego decoder's absolute decoded-payload ceiling.
  static const int maxBinaryCarrierBytes = StegoDecoder.maxDecodedBytes;
  static const int maxTokenCharacters =
      3 + ((maxBinaryCarrierBytes * 4 + 2) ~/ 3);
  static const int maxLinkCharacters = 14 + maxTokenCharacters;
  static const int maxStegoInputCodeUnits =
      V3LmfFrameCodec.maxStegoInputCodeUnits;

  static Uint8List encodeBinary(List<V3LmfFrame> frames) {
    _validateFrameShape(frames, encode: true);
    final encodedFrames =
        frames.map(V3LmfFrameCodec.encodeBinary).toList(growable: false);
    var total = headerBytes + encodedFrames.length * lengthPrefixBytes;
    for (final encoded in encodedFrames) {
      total += encoded.length;
      if (total > maxBinaryCarrierBytes) {
        throw ArgumentError.value(
          frames,
          'frames',
          'combined Layergram v3 carrier exceeds its byte limit',
        );
      }
    }

    final result = Uint8List(total);
    result.setRange(0, magic.length, magic);
    result[3] = version;
    result[4] = encodedFrames.length;
    final data = ByteData.sublistView(result);
    var offset = headerBytes;
    for (final encoded in encodedFrames) {
      data.setUint32(offset, encoded.length, Endian.big);
      offset += lengthPrefixBytes;
      result.setRange(offset, offset + encoded.length, encoded);
      offset += encoded.length;
    }
    return result;
  }

  static List<V3LmfFrame> decodeBinary(Uint8List encoded) {
    if (encoded.length < headerBytes + minFrames * lengthPrefixBytes ||
        encoded.length > maxBinaryCarrierBytes ||
        !hasMagic(encoded)) {
      throw const FormatException('Invalid combined Layergram v3 carrier');
    }
    if (encoded[3] != version) {
      throw const FormatException(
        'Unsupported combined Layergram v3 carrier version',
      );
    }
    final count = encoded[4];
    if (count < minFrames || count > maxFrames) {
      throw const FormatException('Invalid combined Layergram v3 frame count');
    }

    final data = ByteData.sublistView(encoded);
    final frames = <V3LmfFrame>[];
    var offset = headerBytes;
    for (var index = 0; index < count; index++) {
      if (offset + lengthPrefixBytes > encoded.length) {
        throw const FormatException(
          'Truncated combined Layergram v3 frame length',
        );
      }
      final length = data.getUint32(offset, Endian.big);
      offset += lengthPrefixBytes;
      if (length < V3LmfFrameCodec.minBinaryFrameBytes ||
          length > V3LmfFrameCodec.maxBinaryFrameBytes ||
          length > encoded.length - offset) {
        throw const FormatException(
            'Invalid combined Layergram v3 frame length');
      }
      final inner = Uint8List.sublistView(encoded, offset, offset + length);
      final frame = V3LmfFrameCodec.decodeBinary(inner);
      if (!_bytesEqual(V3LmfFrameCodec.encodeBinary(frame), inner)) {
        throw const FormatException(
            'Non-canonical combined Layergram v3 frame');
      }
      frames.add(frame);
      offset += length;
    }
    if (offset != encoded.length) {
      throw const FormatException(
          'Trailing combined Layergram v3 carrier bytes');
    }
    _validateFrameShape(frames, encode: false);
    return List<V3LmfFrame>.unmodifiable(frames);
  }

  static String encodeText(
    List<V3LmfFrame> frames, {
    int? maxTotalCharacters = portableShareCharacterLimit,
  }) {
    final token =
        '$tokenPrefix${base64UrlEncode(encodeBinary(frames)).replaceAll('=', '')}';
    _enforceCharacterLimit(token, maxTotalCharacters, 'combined message token');
    return token;
  }

  static List<V3LmfFrame> decodeText(String token) {
    if (token.length > maxTokenCharacters || !isTextPart(token)) {
      throw const FormatException(
          'Invalid combined Layergram v3 message token');
    }
    final armored = token.substring(tokenPrefix.length);
    if (armored.isEmpty || !_isCanonicalBase64Url(armored)) {
      throw const FormatException(
          'Invalid combined Layergram v3 message token');
    }
    late final Uint8List bytes;
    try {
      bytes =
          Uint8List.fromList(base64Url.decode(base64Url.normalize(armored)));
    } on FormatException {
      throw const FormatException(
          'Invalid combined Layergram v3 message armor');
    }
    final frames = decodeBinary(bytes);
    if (encodeText(frames, maxTotalCharacters: null) != token) {
      throw const FormatException(
        'Non-canonical combined Layergram v3 message token',
      );
    }
    return frames;
  }

  static String encodeLink(
    List<V3LmfFrame> frames, {
    int? maxTotalCharacters = portableShareCharacterLimit,
  }) {
    final token = encodeText(frames, maxTotalCharacters: null);
    final link = '$scheme://$messageHost/$token';
    _enforceCharacterLimit(link, maxTotalCharacters, 'combined message link');
    return link;
  }

  static List<V3LmfFrame> decodeLink(String link) {
    if (link.length > maxLinkCharacters || !isLinkPart(link)) {
      throw const FormatException('Invalid combined Layergram v3 message link');
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
      throw const FormatException('Invalid combined Layergram v3 message link');
    }
    final frames = decodeText(uri.pathSegments.single);
    if (encodeLink(frames, maxTotalCharacters: null) != link) {
      throw const FormatException(
          'Non-canonical combined Layergram v3 message link');
    }
    return frames;
  }

  static String encodeStego({
    required List<V3LmfFrame> frames,
    required String coverText,
    int? maxTotalCharacters = portableShareCharacterLimit,
  }) {
    if (coverText.length > maxStegoInputCodeUnits) {
      throw ArgumentError.value(
        coverText.length,
        'coverText.length',
        'exceeds the combined Layergram v3 stego input limit',
      );
    }
    final encoded = StegoEncoder().encodeBytes(
      coverText,
      encodeBinary(frames),
      maxTotalCharacters: maxTotalCharacters,
    );
    if (encoded.length > maxStegoInputCodeUnits) {
      throw StateError(
        'Combined Layergram v3 stego output exceeds its decoder limit',
      );
    }
    return encoded;
  }

  static List<V3LmfFrame> decodeStego(String stegoText) {
    if (stegoText.length > maxStegoInputCodeUnits) {
      throw const FormatException(
        'Combined Layergram v3 stego input exceeds its limit',
      );
    }
    for (final rune in stegoText.runes) {
      if (StegoAlphabetV2.isForbiddenRune(rune)) {
        throw const FormatException('Forbidden Layergram v3 stego rune');
      }
    }
    final candidates = StegoDecoder().decodeByteCandidates(
      stegoText,
      minBytes: headerBytes + minFrames * lengthPrefixBytes,
    );
    for (final candidate in candidates) {
      if (!hasMagic(candidate)) continue;
      try {
        return decodeBinary(candidate);
      } on FormatException {
        // Other byte alignments are permitted candidates, but only a complete,
        // canonical wrapper is accepted.
      }
    }
    throw const FormatException('Invalid combined Layergram v3 stego payload');
  }

  static bool hasMagic(Uint8List bytes) {
    if (bytes.length < magic.length) return false;
    for (var index = 0; index < magic.length; index++) {
      if (bytes[index] != magic[index]) return false;
    }
    return true;
  }

  static bool isTextPart(String value) => value.startsWith(tokenPrefix);

  static bool isLinkPart(String value) =>
      value.startsWith('$scheme://$messageHost/$tokenPrefix');

  static bool looksLikeStegoPart(String value) {
    if (value.length > maxStegoInputCodeUnits) return false;
    try {
      for (final candidate in StegoDecoder().decodeByteCandidates(
        value,
        minBytes: magic.length,
      )) {
        if (hasMagic(candidate)) return true;
      }
    } on FormatException {
      return false;
    }
    return false;
  }

  static void _validateFrameShape(
    List<V3LmfFrame> frames, {
    required bool encode,
  }) {
    void fail(String message) {
      if (encode) throw ArgumentError.value(frames, 'frames', message);
      throw FormatException(message);
    }

    if (frames.length < minFrames || frames.length > maxFrames) {
      fail('Invalid combined Layergram v3 frame count');
    }
    if (frames.first.metadata.kind != V3LmfFrameKind.application) {
      fail(
          'Combined Layergram v3 carrier must start with an application frame');
    }
    for (var index = 1; index < frames.length; index++) {
      if (frames[index].metadata.kind != V3LmfFrameKind.acknowledgement) {
        fail('Combined Layergram v3 carrier may append only ACK frames');
      }
    }
  }

  static void _enforceCharacterLimit(
    String value,
    int? maxTotalCharacters,
    String description,
  ) {
    if (maxTotalCharacters != null && maxTotalCharacters < 0) {
      throw ArgumentError.value(
        maxTotalCharacters,
        'maxTotalCharacters',
        'must be zero or greater',
      );
    }
    if (maxTotalCharacters != null && value.length > maxTotalCharacters) {
      throw ArgumentError('$description exceeds maxTotalCharacters');
    }
  }

  static bool _isCanonicalBase64Url(String value) {
    for (final codeUnit in value.codeUnits) {
      final isUpper = codeUnit >= 0x41 && codeUnit <= 0x5a;
      final isLower = codeUnit >= 0x61 && codeUnit <= 0x7a;
      final isDigit = codeUnit >= 0x30 && codeUnit <= 0x39;
      if (!isUpper &&
          !isLower &&
          !isDigit &&
          codeUnit != 0x2d &&
          codeUnit != 0x5f) {
        return false;
      }
    }
    return value.length % 4 != 1;
  }

  static bool _bytesEqual(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}
