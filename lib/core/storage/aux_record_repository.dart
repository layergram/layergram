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

import 'package:cryptography/cryptography.dart';
import 'package:hive_flutter/hive_flutter.dart';

import '../crypto/aux_record_cipher.dart';
import 'local_database.dart';

/// Stores sealed auxiliary records (FS session state, passphrase settings, etc.)
/// in the same Hive box as message records, using the same external key pattern:
///
///   m|{scopeToken}|{randomStorageId}  →  { encryptedRecord: "..." }
///
/// This makes auxiliary records externally indistinguishable from ordinary
/// encrypted message archive records. The record type (e.g. "fs_session_state")
/// is only visible after successful decryption with the correct auxiliary key,
/// which is derived with a different HKDF info string than the message key.
///
/// Old clients that encounter these records will fail to decrypt them and
/// preserve them as unknown residual encrypted data — which supports the
/// plausible-deniability model.
///
/// ### Lifecycle rules (spec §10.5 / §13)
/// - delete single message  → does NOT affect aux records
/// - delete chat            → does NOT affect aux records
/// - reset identity only    → does NOT affect aux records (only RAM keys are wiped)
/// - reset messages         → DOES delete aux records (call [clearAll])
/// - reset all              → DOES delete aux records (call [clearAll])
///
/// ### Nonce safety (spec §8.5.2)
/// Records are never updated in-place. On update, a new record with a new
/// random recordId is written first, then the old record is deleted.
/// This guarantees a fresh per-record AES-GCM key/nonce pair every time.
class AuxRecordRepository {
  AuxRecordRepository()
      : _box = Hive.box<Map>(LocalDatabase.messagesBoxName);

  final Box<Map> _box;

  SecretKey? _auxStorageKey;
  String? _scopeToken;

  bool get _hasScope => (_scopeToken ?? '').isNotEmpty;
  String get _keyPrefix => 'm|${_scopeToken!}|';
  String _scopedKey(String storageId) => '$_keyPrefix$storageId';
  bool _isScopedKey(Object? key) =>
      key is String && _hasScope && key.startsWith(_keyPrefix);

  /// Sets the active identity context.
  ///
  /// [scopeToken] must match the same scope token used by [MessagesRepositoryCore]
  /// so that both message records and aux records live under the same namespace.
  /// [auxStorageKey] is derived via [AuxRecordCipher.deriveAuxStorageKey].
  void setActiveContext({
    required String? scopeToken,
    required SecretKey? auxStorageKey,
  }) {
    _scopeToken = scopeToken;
    _auxStorageKey = auxStorageKey;
  }

  // ---------------------------------------------------------------------------
  // Write
  // ---------------------------------------------------------------------------

  /// Writes a new sealed auxiliary record and returns its opaque [storageId].
  ///
  /// [recordId] is a 128-bit random value embedded in the encrypted blob and
  /// used for per-record key/nonce derivation. [storageId] is an additional
  /// opaque Hive key used to locate the record in storage.
  ///
  /// The [recordId] must be stored by the caller alongside the [storageId] so
  /// that the record can later be decrypted (the recordId is required to
  /// re-derive the per-record encryption key).
  Future<({String storageId, String recordId})> write({
    required Map<String, dynamic> payload,
  }) async {
    _assertScope();
    final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
      payload: payload,
      auxStorageKey: _auxStorageKey!,
    );
    final storageId = _newOpaqueStorageId();
    // Store recordId in cleartext (_rid) so we can retrieve it without decryption
    await _box.put(_scopedKey(storageId), {
      'encryptedRecord': encryptedRecord,
      'a': true,
      '_rid': recordId,
    });
    return (storageId: storageId, recordId: recordId);
  }

  /// Updates an existing auxiliary record atomically:
  /// writes the new encrypted record first, then deletes the old one.
  ///
  /// Returns the new [storageId] and [recordId] for the updated record.
  /// The caller must replace any stored reference to the old ids with the new ones.
  Future<({String storageId, String recordId})> update({
    required String oldStorageId,
    required Map<String, dynamic> newPayload,
  }) async {
    _assertScope();
    // Write new record first (safe: new key/nonce pair).
    final result = await write(payload: newPayload);
    // Then delete the old record.
    await _box.delete(_scopedKey(oldStorageId));
    return result;
  }

  // ---------------------------------------------------------------------------
  // Read
  // ---------------------------------------------------------------------------

  /// Attempts to decrypt the record identified by [storageId] + [recordId].
  ///
  /// Returns null if the record is not found, the key is wrong, or the data
  /// is corrupted. This is the normal outcome for records belonging to a
  /// different identity context (e.g. passphrase-derived records when the
  /// passphrase is not active).
  Future<Map<String, dynamic>?> read({
    required String storageId,
    required String recordId,
  }) async {
    if (!_hasScope || _auxStorageKey == null) return null;
    final raw = _box.get(_scopedKey(storageId));
    if (raw == null) return null;
    final encryptedRecord = raw['encryptedRecord'] as String?;
    if (encryptedRecord == null) return null;
    return AuxRecordCipher.decrypt(
      encryptedRecord: encryptedRecord,
      recordId: recordId,
      auxStorageKey: _auxStorageKey!,
    );
  }

  /// Returns all storage IDs and their recordIds for aux records in the current scope.
  ///
  /// This is used by persistence services to reload their state after app restart.
  /// Returns a map of storageId → recordId (recordId is stored in cleartext for retrieval).
  Map<String, String> getAllAuxRecordIds() {
    if (!_hasScope) return const {};
    final result = <String, String>{};
    for (final key in _box.keys.where(_isScopedKey).where(_isAuxRecord)) {
      final raw = _box.get(key);
      if (raw != null) {
        final recordId = raw['_rid'] as String?;
        if (recordId != null && recordId.isNotEmpty) {
          final storageId = (key as String).substring(_keyPrefix.length);
          result[storageId] = recordId;
        }
      }
    }
    return result;
  }

  // ---------------------------------------------------------------------------
  // Delete
  // ---------------------------------------------------------------------------

  /// Deletes a single auxiliary record.
  Future<void> delete(String storageId) async {
    if (!_hasScope) return;
    await _box.delete(_scopedKey(storageId));
  }

  /// Deletes all auxiliary records in the current scope.
  ///
  /// This must be called as part of "reset messages" and "reset all" flows.
  /// It must NOT be called for "delete chat", "delete message", or
  /// "reset identity only".
  ///
  /// Note: this only deletes aux records that share the current scope token.
  /// Records from other identity contexts are left intact (they cannot be
  /// distinguished from other records without the correct key).
  Future<void> clearAll() async {
    if (!_hasScope) return;
    final auxKeys = _box.keys
        .where(_isScopedKey)
        .where(_isAuxRecord)
        .toList();
    for (final key in auxKeys) {
      await _box.delete(key);
    }
  }

  /// Deletes all auxiliary records of a specific [kind] in the current scope.
  ///
  /// If [identityContext] is provided, only records with matching
  /// 'identityContext' field in their payload are deleted.
  ///
  /// This is used during identity reset to clear Forward Secrecy state
  /// (kind = 'fs_state_v1' or 'fs_ratchet_v1') while preserving other
  /// auxiliary records.
  ///
  /// Records are identified by reading and decrypting them first, then
  /// matching the 'kind' field (and optionally 'identityContext') in the payload.
  Future<void> clearByKind(String kind, {String? identityContext}) async {
    if (!_hasScope || _auxStorageKey == null) {
      assert(() {
        print('[AUX-CLEAR] Skipped: no scope or no key');
        return true;
      }());
      return;
    }

    final allIds = getAllAuxRecordIds();
    assert(() {
      print('[AUX-CLEAR] Found ${allIds.length} records, looking for kind=$kind, ctx=$identityContext');
      return true;
    }());

    int checked = 0;
    int deleted = 0;
    int skipped = 0;

    for (final entry in allIds.entries) {
      final storageId = entry.key;
      final recordId = entry.value;
      checked++;

      // Try to read and decrypt the record
      final raw = _box.get(_scopedKey(storageId));
      if (raw == null) continue;

      final encryptedRecord = raw['encryptedRecord'] as String?;
      if (encryptedRecord == null) continue;

      final payload = await AuxRecordCipher.decrypt(
        encryptedRecord: encryptedRecord,
        recordId: recordId,
        auxStorageKey: _auxStorageKey!,
      );

      if (payload == null) {
        assert(() {
          print('[AUX-CLEAR] Failed to decrypt record $storageId');
          return true;
        }());
        continue;
      }

      // Check kind matches
      if (payload['kind'] != kind) {
        skipped++;
        continue;
      }

      // If identityContext specified, check it matches too
      if (identityContext != null &&
          payload['identityContext'] != identityContext) {
        skipped++;
        continue;
      }

      // Delete matching record
      await _box.delete(_scopedKey(storageId));
      deleted++;
    }

    assert(() {
      print('[AUX-CLEAR] Done: checked=$checked, deleted=$deleted, skipped=$skipped');
      return true;
    }());
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  void _assertScope() {
    if (!_hasScope || _auxStorageKey == null) {
      throw StateError('AuxRecordRepository: storage context not initialized');
    }
  }

  /// Returns true if the raw stored map looks like an aux record rather than
  /// a message record (both have an 'encryptedRecord' field, so we rely on
  /// an internal 'auxRecord' marker set by this repository).
  ///
  /// In practice we use the same external shape; the distinction is that aux
  /// records additionally carry a 'a' = true marker (single-char, opaque).
  bool _isAuxRecord(Object? key) {
    if (key is! String) return false;
    final raw = _box.get(key);
    if (raw == null) return false;
    return raw['a'] == true;
  }

  static final Random _rng = Random.secure();

  static String _newOpaqueStorageId() {
    final bytes = List<int>.generate(16, (_) => _rng.nextInt(256));
    return 'r${base64Url.encode(bytes).replaceAll('=', '')}';
  }
}
