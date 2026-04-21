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

import 'package:zstd/zstd.dart';

/// LMF v2 compression using Zstandard (zstd).
///
/// Compression policy:
/// - Level: 3 (default)
/// - Skip if plaintext < 96 bytes
/// - Only use compressed if it saves at least 4 bytes
class CompressionZstd {
  /// Minimum plaintext size to attempt compression.
  static const int compressionThresholdBytes = 96;

  /// Minimum byte savings required to use compressed form.
  static const int minSavingsBytes = 4;

  /// Zstd compression level (1-22, where 3 is the default).
  static const int compressionLevel = 3;

  /// Compress [plaintext] according to LMF v2 policy.
  ///
  /// Returns a tuple: (bytes, wasCompressed)
  /// - If plaintext < 96 bytes: returns (original, false)
  /// - Otherwise tries zstd compression
  /// - Uses compressed only if it saves at least 4 bytes
  static (Uint8List bytes, bool wasCompressed) compress(Uint8List plaintext) {
    // Policy: don't compress if below threshold
    if (plaintext.length < compressionThresholdBytes) {
      return (plaintext, false);
    }

    try {
      final compressed = ZstdCodec(level: compressionLevel).encode(plaintext);

      // Policy: only use compressed if it saves at least 4 bytes
      if (compressed.length + minSavingsBytes < plaintext.length) {
        return (Uint8List.fromList(compressed), true);
      } else {
        return (plaintext, false);
      }
    } catch (_) {
      // If compression fails, fall back to uncompressed
      return (plaintext, false);
    }
  }

  /// Decompress zstd-compressed bytes.
  ///
  /// Returns the decompressed bytes, or null if decompression fails.
  static Uint8List? decompress(Uint8List compressed) {
    try {
      final decompressed = ZstdCodec().decode(compressed);
      return Uint8List.fromList(decompressed);
    } catch (_) {
      return null;
    }
  }

  /// Compress without applying policy (always compress if possible).
  /// Used for testing or when policy is applied externally.
  static Uint8List? compressRaw(Uint8List plaintext, {int level = compressionLevel}) {
    try {
      final compressed = ZstdCodec(level: level).encode(plaintext);
      return Uint8List.fromList(compressed);
    } catch (_) {
      return null;
    }
  }
}
