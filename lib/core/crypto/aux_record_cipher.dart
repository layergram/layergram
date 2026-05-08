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
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Handles encryption/decryption of sealed auxiliary records used to store
/// Forward Secrecy state, passphrase settings, and other internal protocol
/// state in a form externally indistinguishable from message archive records.
///
/// The auxiliary storage key is derived separately from the message storage key
/// using a different HKDF info string, so old clients that attempt to decrypt
/// these records using the message key will fail and preserve them as unknown
/// encrypted residual records — which is exactly the desired plausible-deniability
/// behaviour.
///
/// Nonce derivation: per-record nonce is deterministically derived from the
/// recordId (128-bit random) using HKDF, so no record is ever written with a
/// reused nonce. Records are never updated in-place; on update, a new record
/// with a new recordId is written and the old one deleted after commit.
class AuxRecordCipher {
  static final _algo = AesGcm.with256bits();
  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final _hkdf12 = Hkdf(hmac: Hmac.sha256(), outputLength: 12);
  static final Random _rng = Random.secure();

  /// HKDF info string used to derive the auxiliary storage key.
  /// Distinct from "layergram-message-records-v1" used for ordinary messages.
  static const String _auxKeyInfo = 'layergram-message-shaped-aux-v1';

  /// Derives the auxiliary storage key from the effective secret key material.
  ///
  /// [effectiveSecret] is the raw bytes of the master secret for the current
  /// effective identity context (primary or passphrase-derived).
  static Future<SecretKey> deriveAuxStorageKey(Uint8List effectiveSecret) async {
    return _hkdf.deriveKey(
      secretKey: SecretKey(effectiveSecret),
      nonce: utf8.encode('aux-key'),
      info: utf8.encode(_auxKeyInfo),
    );
  }

  /// Encrypts [payload] into an opaque base64url-encoded string.
  ///
  /// A fresh 128-bit [recordId] is generated and returned alongside the
  /// encrypted blob. The nonce is derived from [recordId] + [auxStorageKey]
  /// so no random nonce is ever reused.
  ///
  /// The plaintext is padded to a random size in one of four buckets before
  /// encryption, making individual auxiliary records indistinguishable by size.
  static Future<({String recordId, String encryptedRecord})> encrypt({
    required Map<String, dynamic> payload,
    required SecretKey auxStorageKey,
  }) async {
    final recordId = _generateRecordId();
    final recordIdBytes = base64Url.decode(_padBase64Url(recordId));

    final encKey = await _deriveRecordKey(auxStorageKey, recordIdBytes);
    final nonce = await _deriveRecordNonce(auxStorageKey, recordIdBytes);

    final paddedJson = _padPayload(jsonEncode(payload));

    final box = await _algo.encrypt(
      paddedJson,
      secretKey: encKey,
      nonce: nonce,
    );

    final blob = Uint8List.fromList([
      ...nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);

    return (
      recordId: recordId,
      encryptedRecord: base64Url.encode(blob).replaceAll('=', ''),
    );
  }

  /// Decrypts an encrypted auxiliary record previously produced by [encrypt].
  ///
  /// Returns the decrypted payload map, or null if decryption fails
  /// (wrong key, corrupted data, or a record belonging to a different context).
  static Future<Map<String, dynamic>?> decrypt({
    required String encryptedRecord,
    required String recordId,
    required SecretKey auxStorageKey,
  }) async {
    try {
      final recordIdBytes = base64Url.decode(_padBase64Url(recordId));
      final encKey = await _deriveRecordKey(auxStorageKey, recordIdBytes);
      final nonce = await _deriveRecordNonce(auxStorageKey, recordIdBytes);

      final blob = Uint8List.fromList(
        base64Url.decode(_padBase64Url(encryptedRecord)),
      );
      if (blob.length < 28) return null;

      final storedNonce = blob.sublist(0, 12);
      final mac = Mac(blob.sublist(blob.length - 16));
      final cipher = blob.sublist(12, blob.length - 16);

      // The nonce in the blob is redundant (it's derived from recordId) but
      // we include it for forward compatibility and verify it matches.
      if (!_listEquals(storedNonce, nonce)) return null;

      final box = SecretBox(cipher, nonce: storedNonce, mac: mac);
      final clear = await _algo.decrypt(box, secretKey: encKey);

      final unpaddedJson = _stripPadding(clear);
      final decoded = jsonDecode(utf8.decode(unpaddedJson));
      if (decoded is! Map) return null;
      return decoded.cast<String, dynamic>();
    } catch (_) {
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  static Future<SecretKey> _deriveRecordKey(
    SecretKey auxStorageKey,
    Uint8List recordIdBytes,
  ) {
    return _hkdf.deriveKey(
      secretKey: auxStorageKey,
      nonce: recordIdBytes,
      info: utf8.encode('Layergram aux record key v1'),
    );
  }

  static Future<List<int>> _deriveRecordNonce(
    SecretKey auxStorageKey,
    Uint8List recordIdBytes,
  ) async {
    final k = await _hkdf12.deriveKey(
      secretKey: auxStorageKey,
      nonce: recordIdBytes,
      info: utf8.encode('Layergram aux record nonce v1'),
    );
    return k.extractBytes();
  }

  /// Pads [plaintext] to a random size within one of four buckets so that
  /// auxiliary records are indistinguishable by length.
  ///
  /// Padding format: raw JSON bytes + 0x00 delimiter + random padding bytes.
  /// The delimiter allows [_stripPadding] to locate the end of the actual JSON.
  static Uint8List _padPayload(String json) {
    final jsonBytes = utf8.encode(json);
    final targetSize = _pickPaddingTarget(jsonBytes.length);
    final paddingSize = targetSize - jsonBytes.length - 1; // 1 byte for delimiter
    final padding = Uint8List(paddingSize > 0 ? paddingSize : 0);
    for (var i = 0; i < padding.length; i++) {
      padding[i] = _rng.nextInt(256);
    }
    return Uint8List.fromList([...jsonBytes, 0x00, ...padding]);
  }

  /// Strips padding added by [_padPayload], returning the original JSON bytes.
  static Uint8List _stripPadding(List<int> padded) {
    final delimIndex = padded.indexOf(0x00);
    if (delimIndex < 0) return Uint8List.fromList(padded);
    return Uint8List.fromList(padded.sublist(0, delimIndex));
  }

  /// Picks a random padded target size in bytes from four size buckets.
  ///
  /// Buckets (spec §10.7):
  ///   1 →  8–16 KB
  ///   2 → 16–32 KB
  ///   3 → 32–64 KB
  ///   4 → 64–96 KB
  ///
  /// If the payload already exceeds 96 KB, we use the next power-of-two
  /// bucket above it to avoid truncation (should never happen in practice).
  static int _pickPaddingTarget(int payloadSize) {
    const buckets = [
      (8 * 1024, 16 * 1024),
      (16 * 1024, 32 * 1024),
      (32 * 1024, 64 * 1024),
      (64 * 1024, 96 * 1024),
    ];

    // Pick a random bucket that is large enough for the payload.
    final eligible = buckets
        .where((b) => b.$2 > payloadSize)
        .toList();

    if (eligible.isEmpty) {
      // Payload is > 96 KB — pad to next 32 KB boundary above it.
      const step = 32 * 1024;
      final next = ((payloadSize ~/ step) + 1) * step;
      return next + _rng.nextInt(step);
    }

    final bucket = eligible[_rng.nextInt(eligible.length)];
    final low = bucket.$1 > payloadSize ? bucket.$1 : payloadSize + 1;
    return low + _rng.nextInt(bucket.$2 - low);
  }

  /// Generates a new 128-bit random record ID encoded as unpadded base64url.
  static String _generateRecordId() {
    final bytes = Uint8List(16);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = _rng.nextInt(256);
    }
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  static String _padBase64Url(String s) {
    final rem = s.length % 4;
    if (rem == 0) return s;
    return s.padRight(s.length + (4 - rem), '=');
  }

  static bool _listEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
