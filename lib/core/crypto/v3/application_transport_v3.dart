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

import 'lmf_v3.dart';

enum V3ApplicationCarrierKind { text, link, steganography }

/// One independently shareable message/ACK part for an unreliable carrier.
///
/// Layergram does not infer delivery from generation or export. Every part is
/// a complete canonical LMF frame and can be imported in any order, repeated,
/// delayed, or never delivered.
abstract final class V3ApplicationTransport {
  static String encodeText(V3LmfFrame frame) {
    final encoded = V3LmfFrameCodec.encodeToken(frame);
    _requirePortable(encoded);
    return encoded;
  }

  static String encodeLink(V3LmfFrame frame) {
    final encoded = V3LmfFrameCodec.encodeLink(frame);
    _requirePortable(encoded);
    return encoded;
  }

  static String encodeStego({
    required V3LmfFrame frame,
    required String coverText,
  }) {
    return V3LmfFrameCodec.encodeStego(
      frame: frame,
      coverText: coverText,
      maxTotalCharacters: V3LmfFrameCodec.portableShareCharacterLimit,
    );
  }

  static V3LmfFrame decodeText(String value) {
    final normalized = value.trim();
    if (normalized.length > V3LmfFrameCodec.portableShareCharacterLimit) {
      throw const FormatException('Layergram v3 text part is too large');
    }
    return V3LmfFrameCodec.decodeToken(normalized);
  }

  static V3LmfFrame decodeLink(String value) {
    final normalized = value.trim();
    if (normalized.length > V3LmfFrameCodec.portableShareCharacterLimit) {
      throw const FormatException('Layergram v3 link part is too large');
    }
    return V3LmfFrameCodec.decodeLink(normalized);
  }

  static V3LmfFrame decodeStego(String value) =>
      V3LmfFrameCodec.decodeStego(value);

  static ({V3ApplicationCarrierKind kind, V3LmfFrame frame}) decode(
    String value,
  ) {
    final normalized = value.trim();
    if (normalized.startsWith('${V3LmfFrameCodec.scheme}://')) {
      return (
        kind: V3ApplicationCarrierKind.link,
        frame: decodeLink(normalized),
      );
    }
    if (normalized.startsWith(V3LmfFrameCodec.tokenPrefix)) {
      return (
        kind: V3ApplicationCarrierKind.text,
        frame: decodeText(normalized),
      );
    }
    return (
      kind: V3ApplicationCarrierKind.steganography,
      frame: decodeStego(value),
    );
  }

  static void _requirePortable(String value) {
    if (value.length > V3LmfFrameCodec.portableShareCharacterLimit) {
      throw StateError('Layergram v3 carrier part exceeds portable limit');
    }
  }
}
