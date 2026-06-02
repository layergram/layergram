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

/// Internal per-message security classification (spec §14.4).
///
/// Every sent/received message must have exactly one of these classifications.
/// The chat UI may show only an icon; the message details panel must explain
/// the classification.
///
/// The enum order intentionally groups values by security level so that
/// [downgradeLevel] can map each classification to the 3-level hierarchy
/// used by [FsDowngradeDetector].
enum FsMessageClassification {
  /// Standard identity encryption. No FS negotiation has occurred.
  legacy,

  /// Message sent/received before FS was established for this contact.
  /// Same encryption as [legacy], but provides context that FS was not
  /// yet available at the time.
  preFs,

  /// Control message during FS handshake (fs_init, fs_reply, fs_confirm,
  /// fs_ack, etc.). The message may carry user content alongside the
  /// negotiation payload.
  fsNegotiation,

  /// FS encrypted *and also* legacy identity-key encrypted (same content
  /// wrapped both ways), so the message is decryptable via either the FS
  /// ratchet or the long-term identity key.
  ///
  /// Per §9.5 this is the only case that must NOT be treated as full FS.
  /// It corresponds to a multi-envelope message (§9.6) that includes the
  /// optional legacy fallback (`mc_fallback_key`). The live classifier does
  /// not emit it because Layergram sends multi-envelope messages without a
  /// legacy fallback by default (they stay `fsOnly`/`strictFs`).
  fsWithFallback,

  /// FS encrypted only; not decryptable by the legacy identity key.
  fsOnly,

  /// FS encrypted under strict/maximum mode — legacy fallback is
  /// disabled by policy for this contact.
  strictFs,

  /// FS decryption failed. The message was FS-encrypted but the
  /// ratchet state was unavailable or invalid (session reset, device
  /// change, key loss).
  fsFailed,

  /// Classification could not be determined.
  unknown,
}

/// Extension on [FsMessageClassification] for downgrade-level mapping
/// and serialization helpers.
extension FsMessageClassificationExt on FsMessageClassification {
  /// Maps this per-message classification to the 3-level security
  /// hierarchy used by [FsDowngradeDetector].
  ///
  /// Returns `null` for classifications that are not meaningful for
  /// downgrade tracking ([fsFailed], [unknown], [fsNegotiation]).
  FsMessageSecurity? get downgradeLevel {
    switch (this) {
      case FsMessageClassification.legacy:
      case FsMessageClassification.preFs:
        return FsMessageSecurity.legacy;
      case FsMessageClassification.fsWithFallback:
        return FsMessageSecurity.fsWithFallback;
      case FsMessageClassification.fsOnly:
      case FsMessageClassification.strictFs:
        return FsMessageSecurity.fsOnly;
      case FsMessageClassification.fsNegotiation:
      case FsMessageClassification.fsFailed:
      case FsMessageClassification.unknown:
        return null;
    }
  }

  /// Whether this classification represents a message whose plaintext
  /// was protected by Forward Secrecy.
  bool get isFsProtected {
    switch (this) {
      case FsMessageClassification.fsWithFallback:
      case FsMessageClassification.fsOnly:
      case FsMessageClassification.strictFs:
        return true;
      case FsMessageClassification.legacy:
      case FsMessageClassification.preFs:
      case FsMessageClassification.fsNegotiation:
      case FsMessageClassification.fsFailed:
      case FsMessageClassification.unknown:
        return false;
    }
  }

  /// Serialization index for opaque storage. Uses [index] directly —
  /// the integer is as opaque as the existing [isFsEncrypted] boolean.
  int get storageIndex => index;

  /// Deserialize from storage index. Returns [unknown] for out-of-range
  /// values (forward compatibility).
  static FsMessageClassification fromStorageIndex(int idx) {
    if (idx >= 0 && idx < FsMessageClassification.values.length) {
      return FsMessageClassification.values[idx];
    }
    return FsMessageClassification.unknown;
  }

  /// Infers a classification from the legacy [isFsEncrypted] boolean
  /// for backward compatibility with records that don't have an
  /// explicit classification.
  ///
  /// §9.5: an FS-encrypted record is FS-only on the wire (Layergram never
  /// dual-encrypts a message with the legacy key), so it maps to [fsOnly].
  static FsMessageClassification fromLegacyFlag(bool isFsEncrypted) {
    return isFsEncrypted
        ? FsMessageClassification.fsOnly
        : FsMessageClassification.legacy;
  }
}

/// 3-level security hierarchy for downgrade detection (§7.6).
///
/// Kept separate from [FsMessageClassification] because downgrade
/// tracking cares about security strength, not message context.
enum FsMessageSecurity {
  /// Message encrypted with long-term identity key only.
  legacy,

  /// Message encrypted with FS and also with legacy key.
  fsWithFallback,

  /// Message encrypted with FS only; not legacy-decryptable.
  fsOnly,
}
