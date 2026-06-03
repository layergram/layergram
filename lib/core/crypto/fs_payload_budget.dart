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
import 'stego_encoder.dart';

/// Payload budget analysis for FS control messages carried inside LMF v2.
///
/// Each FS control message (fs_init, fs_reply, fs_confirm) is embedded
/// inside the encrypted `x.fs` field of an LMF v2 JSON envelope.
/// This module calculates the total encoded byte cost and derives
/// conservative limits that fit within Layergram's steganographic transport.
///
/// Spec reference: §6 (payload budget), §5.3 (x.fs extension).
class FsPayloadBudget {
  FsPayloadBudget._();

  // ---------------------------------------------------------------------------
  // LMF v2 wire overhead
  // ---------------------------------------------------------------------------

  /// Fixed overhead added by LMF v2 encrypt+wrap per message:
  ///   12 bytes  AES-GCM nonce
  ///    4 bytes  LMFv2Inner header (formatVersion, flags, 2 reserved)
  ///   16 bytes  AES-GCM authentication tag
  static const int lmfV2WireOverheadBytes = 12 + 4 + 16;

  /// Conservative baseline JSON envelope size (without `x.fs` extension):
  ///   v, senderId, recipientId, timestamp, text, deleteAfterRead, …
  static const int baseJsonEnvelopeBytes = 256;

  // ---------------------------------------------------------------------------
  // Steganographic transport limits
  // ---------------------------------------------------------------------------

  /// Maximum FS extension payload bytes we allow before falling back
  /// to legacy mode in Opportunistic FS.
  ///
  /// Derived from: a typical cover text of ~600 visible ASCII characters can
  /// carry ≈1 700 bytes of payload (6 bytes/visible-char, 4 runes/byte).
  /// We reserve half of that budget for the visible text JSON envelope,
  /// leaving ≈850 bytes for the `x.fs` extension.  We use 800 as the
  /// conservative ceiling to leave headroom for future extension fields.
  static const int kMaxFsControlPayloadBytes = 800;

  /// Hard limit for Strict / Maximum FS: if the control payload exceeds
  /// this we MUST NOT silently downgrade.  Instead we must surface an error
  /// or offer Link Mode.
  static const int kStrictMaxFsControlPayloadBytes = kMaxFsControlPayloadBytes;

  // ---------------------------------------------------------------------------
  // Measurement helpers
  // ---------------------------------------------------------------------------

  /// Returns the raw byte length of [fsExtensionJson] as serialised into
  /// the `x.fs` field of the LMF v2 envelope (UTF-8, uncompressed).
  ///
  /// This is the primary cost metric used by [fitsInOpportunisticBudget] and
  /// [fitsInStrictBudget].
  static int fsExtensionBytes(Map<String, dynamic> fsExtensionJson) {
    return utf8.encode(jsonEncode(fsExtensionJson)).length;
  }

  /// Total LMF v2 encrypted payload bytes when a message carries [fsExtensionJson].
  ///
  /// Formula:
  ///   lmfV2WireOverheadBytes
  ///   + baseJsonEnvelopeBytes          (conservative envelope without x.fs)
  ///   + fsExtensionBytes(fsExtensionJson)   (x.fs serialised size)
  static int totalEncryptedBytesWithFs(Map<String, dynamic> fsExtensionJson) {
    return lmfV2WireOverheadBytes +
        baseJsonEnvelopeBytes +
        fsExtensionBytes(fsExtensionJson);
  }

  /// Number of zero-width stego runes required to carry [rawBytes] bytes.
  ///
  /// At 2 bits per rune (base-4 alphabet), 1 byte requires 4 runes.
  static int stegoRuneCount(int rawBytes) =>
      StegoEncoder.hiddenRuneCount(rawBytes);

  /// Minimum number of carrier-safe visible ASCII characters in the cover text
  /// needed to embed [rawBytes] bytes.
  static int minimumCoverCharsForBytes(int rawBytes) =>
      StegoEncoder.minCoverLengthForBytes(rawBytes);

  // ---------------------------------------------------------------------------
  // Policy checks
  // ---------------------------------------------------------------------------

  /// Returns true if [fsExtensionJson] fits within the Opportunistic FS budget.
  ///
  /// In Opportunistic mode the caller MAY skip the `x.fs` extension and retry
  /// on the next message if this returns false.
  static bool fitsInOpportunisticBudget(Map<String, dynamic> fsExtensionJson) {
    return fsExtensionBytes(fsExtensionJson) <= kMaxFsControlPayloadBytes;
  }

  /// Returns true if [fsExtensionJson] fits within the Strict / Maximum FS budget.
  ///
  /// In Strict mode the caller MUST NOT silently drop the extension if this
  /// returns false — it must surface an error or offer an alternative path.
  static bool fitsInStrictBudget(Map<String, dynamic> fsExtensionJson) {
    return fsExtensionBytes(fsExtensionJson) <= kStrictMaxFsControlPayloadBytes;
  }

  /// Returns a [FsPayloadBudgetResult] with all metrics for [fsExtensionJson].
  static FsPayloadBudgetResult measure(Map<String, dynamic> fsExtensionJson) {
    final ext = fsExtensionBytes(fsExtensionJson);
    final total = lmfV2WireOverheadBytes + baseJsonEnvelopeBytes + ext;
    final runes = stegoRuneCount(total);
    final minChars = minimumCoverCharsForBytes(total);
    return FsPayloadBudgetResult(
      fsExtensionBytes: ext,
      totalEncryptedBytes: total,
      stegoRuneCount: runes,
      minimumCoverChars: minChars,
      fitsOpportunistic: ext <= kMaxFsControlPayloadBytes,
      fitsStrict: ext <= kStrictMaxFsControlPayloadBytes,
    );
  }
}

/// Measurement result returned by [FsPayloadBudget.measure].
class FsPayloadBudgetResult {
  const FsPayloadBudgetResult({
    required this.fsExtensionBytes,
    required this.totalEncryptedBytes,
    required this.stegoRuneCount,
    required this.minimumCoverChars,
    required this.fitsOpportunistic,
    required this.fitsStrict,
  });

  /// Serialised byte length of the `x.fs` JSON object alone.
  final int fsExtensionBytes;

  /// Total LMF v2 encrypted payload bytes (overhead + envelope + x.fs).
  final int totalEncryptedBytes;

  /// Number of zero-width stego runes needed to transport the full payload.
  final int stegoRuneCount;

  /// Minimum visible cover-text characters needed to embed the full payload.
  final int minimumCoverChars;

  /// Whether the payload fits within the Opportunistic FS ceiling.
  final bool fitsOpportunistic;

  /// Whether the payload fits within the Strict / Maximum FS ceiling.
  final bool fitsStrict;

  @override
  String toString() => 'FsPayloadBudgetResult('
      'fsExt=$fsExtensionBytes B, '
      'total=$totalEncryptedBytes B, '
      'runes=$stegoRuneCount, '
      'minCover=$minimumCoverChars chars, '
      'oppo=$fitsOpportunistic, '
      'strict=$fitsStrict)';
}
