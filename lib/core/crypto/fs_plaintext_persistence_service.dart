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

import '../storage/aux_record_repository.dart';

/// Persists FS-decrypted plaintext as opaque encrypted auxiliary records.
///
/// **Design rationale (§12.3 compliance):**
///
/// The Double Ratchet is one-time-decrypt: once a message key is consumed,
/// it cannot be re-derived.  To allow FS messages to be re-displayed after
/// app restart, the decrypted plaintext must be persisted somewhere.
///
/// Storing plaintext in [MessageRecord.text] violates §12.3 ("never store
/// plaintext messages in the local database") and breaks plausible
/// deniability because it makes FS messages externally indistinguishable
/// from legacy messages in the message table.
///
/// Instead, this service stores each FS-decrypted plaintext as a sealed
/// auxiliary record (same opaque format as FS state and ratchet records).
/// The plaintext is encrypted with the auxiliary storage key and is
/// externally indistinguishable from any other auxiliary record.
///
/// **Lifecycle:**
/// - Written immediately after successful FS decryption.
/// - Read on-demand when the in-memory [FsPlaintextCache] has no entry
///   (e.g. after app restart).
/// - Deleted on identity reset via [removeAll] (called by
///   [stripEncryptedPlaintext]).
/// - For passphrase contexts: only decryptable while the passphrase-derived
///   aux key is active — after expulsion, the records become opaque.
///
/// **Plausible deniability:**
/// - Records use kind `fs_pt_v1`, visible only after decryption with the
///   correct aux key.
/// - External shape: `m|scopeToken|randomId` — identical to message records.
/// - Padding: 8–96 KB random buckets (inherited from [AuxRecordCipher]).
/// - No message ID, contact ID, or device label is visible externally.
///
/// Spec reference: §12.3, §10, §5.3.
class FsPlaintextPersistenceService {
  FsPlaintextPersistenceService({
    required AuxRecordRepository auxRepository,
  }) : _auxRepository = auxRepository;

  final AuxRecordRepository _auxRepository;

  /// In-memory index: messageId → (storageId, recordId).
  final Map<String, ({String storageId, String recordId})> _index = {};

  static const String _kRecordKind = 'fs_pt_v1';

  // ---------------------------------------------------------------------------
  // Write
  // ---------------------------------------------------------------------------

  /// Persists FS-decrypted plaintext for the given message.
  ///
  /// [messageId] is the unique identifier of the [MessageRecord].
  /// [plaintext] is the decrypted text content.
  /// [contactId] is stored inside the encrypted payload for cleanup purposes.
  Future<void> savePlaintext({
    required String messageId,
    required String plaintext,
    required String contactId,
  }) async {
    final payload = <String, dynamic>{
      'kind': _kRecordKind,
      'v': 1,
      'msgId': messageId,
      'cid': contactId,
      'pt': plaintext,
    };

    final existing = _index[messageId];
    if (existing != null) {
      final result = await _auxRepository.update(
        oldStorageId: existing.storageId,
        newPayload: payload,
      );
      _index[messageId] = result;
    } else {
      final result = await _auxRepository.write(payload: payload);
      _index[messageId] = result;
    }
  }

  // ---------------------------------------------------------------------------
  // Read
  // ---------------------------------------------------------------------------

  /// Retrieves the persisted FS plaintext for [messageId].
  ///
  /// Returns null if no record exists or decryption fails.
  Future<String?> loadPlaintext(String messageId) async {
    // Check index first
    final info = _index[messageId];
    if (info != null) {
      final payload = await _auxRepository.read(
        storageId: info.storageId,
        recordId: info.recordId,
      );
      if (payload != null && payload['kind'] == _kRecordKind) {
        return payload['pt'] as String?;
      }
    }

    // Index miss — scan all aux records (cold start)
    return _scanForMessage(messageId);
  }

  /// Rebuilds the in-memory index by scanning all aux records.
  ///
  /// Call this once after app startup / identity context initialization
  /// to populate the index for fast lookups.
  Future<void> rebuildIndex() async {
    _index.clear();
    final allIds = _auxRepository.getAllAuxRecordIds();

    for (final entry in allIds.entries) {
      try {
        final payload = await _auxRepository.read(
          storageId: entry.key,
          recordId: entry.value,
        );
        if (payload == null) continue;
        if (payload['kind'] != _kRecordKind) continue;

        final msgId = payload['msgId'] as String?;
        if (msgId == null) continue;

        _index[msgId] = (storageId: entry.key, recordId: entry.value);
      } catch (_) {
        continue;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Delete
  // ---------------------------------------------------------------------------

  /// Removes the persisted plaintext for a single message.
  Future<void> removePlaintext(String messageId) async {
    final info = _index[messageId];
    if (info != null) {
      await _auxRepository.delete(info.storageId);
      _index.remove(messageId);
    }
  }

  /// Removes all persisted FS plaintext records.
  ///
  /// Called on identity reset to ensure FS message content is irrecoverable
  /// after the ratchet keys are destroyed.
  Future<void> removeAll() async {
    await _auxRepository.clearByKind(_kRecordKind);
    _index.clear();
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  Future<String?> _scanForMessage(String messageId) async {
    final allIds = _auxRepository.getAllAuxRecordIds();

    for (final entry in allIds.entries) {
      try {
        final payload = await _auxRepository.read(
          storageId: entry.key,
          recordId: entry.value,
        );
        if (payload == null) continue;
        if (payload['kind'] != _kRecordKind) continue;

        final msgId = payload['msgId'] as String?;
        if (msgId == null) continue;

        // Cache in index for future lookups
        _index[msgId] = (storageId: entry.key, recordId: entry.value);

        if (msgId == messageId) {
          return payload['pt'] as String?;
        }
      } catch (_) {
        continue;
      }
    }

    return null;
  }
}
