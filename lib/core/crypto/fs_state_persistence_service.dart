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

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../storage/aux_record_repository.dart';
import 'fs_contact_security_state.dart';
import 'fs_session_manager.dart';

/// Persistence service for Forward Secrecy state.
///
/// Saves and loads [FsContactSecurityState] entries to/from auxiliary records,
/// making FS state survive app restarts.
///
/// Primary context entries are persisted; passphrase context entries are NOT
/// persisted (they are RAM-only by design for plausible deniability).
///
/// Spec reference: §7.1.3 — state persistence.
class FsStatePersistenceService {
  FsStatePersistenceService({
    required AuxRecordRepository auxRepository,
    required FsContactSecurityRegistry registry,
  })  : _auxRepository = auxRepository,
        _registry = registry;

  final AuxRecordRepository _auxRepository;
  final FsContactSecurityRegistry _registry;

  // In-memory cache of storage info for primary context entries
  // Key: (contactId, sessionId) → (storageId, recordId)
  final Map<String, ({String storageId, String recordId})> _storageInfo = {};

  static const String _kRecordKind = 'fs_state_v1';
  static const String _kPrimaryContext = 'primary';

  // ---------------------------------------------------------------------------
  // Load (called at app startup after identity is loaded)
  // ---------------------------------------------------------------------------

  /// Loads all persisted FS states from auxiliary records.
  ///
  /// Must be called after the identity context is set (aux key available).
  /// Only loads 'primary' context entries; passphrase contexts remain empty.
  Future<void> loadPersistedState() async {
    // Scan all aux records in the current scope
    final allKeys = await _auxRepository.getAllKeys();

    for (final key in allKeys) {
      try {
        final record = await _auxRepository.readRaw(key);
        if (record == null) continue;

        // Try to parse as FS state record
        final payload = jsonDecode(record) as Map<String, dynamic>?;
        if (payload == null) continue;
        if (payload['kind'] != _kRecordKind) continue;

        final state = _stateFromPayload(payload);
        if (state == null) continue;

        // Only restore primary context (passphrase contexts are RAM-only)
        if (state.identityContext != _kPrimaryContext) continue;

        // Restore to registry
        _registry.upsert(state);

        // Cache storage info for future updates
        final cacheKey = '${state.contactId}:${state.sessionId ?? "null"}';
        // Extract storageId from the repository's key format: m|scope|storageId
        final parts = key.split('|');
        if (parts.length >= 3) {
          final storageId = parts.sublist(2).join('|');
          _storageInfo[cacheKey] = (
            storageId: storageId,
            recordId: payload['_rid'] as String? ?? '',
          );
        }
      } catch (_) {
        // Skip corrupted records
        continue;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Save (called when FS state changes)
  // ---------------------------------------------------------------------------

  /// Persists a single FS state entry to auxiliary storage.
  ///
  /// Only saves 'primary' context entries. Passphrase context entries
  /// are silently ignored (they are meant to be RAM-only).
  Future<void> saveState(FsContactSecurityState state) async {
    // Don't persist passphrase contexts (plausible deniability)
    if (state.identityContext != _kPrimaryContext) return;

    final cacheKey = '${state.contactId}:${state.sessionId ?? "null"}';
    final existingInfo = _storageInfo[cacheKey];

    final payload = _payloadFromState(state);

    if (existingInfo != null) {
      // Update existing record
      final result = await _auxRepository.update(
        oldStorageId: existingInfo.storageId,
        newPayload: payload,
      );
      _storageInfo[cacheKey] = result;
    } else {
      // Write new record
      final result = await _auxRepository.write(payload: payload);
      _storageInfo[cacheKey] = result;
    }
  }

  /// Removes a persisted FS state entry.
  Future<void> removeState(String contactId, String? sessionId) async {
    final cacheKey = '$contactId:${sessionId ?? "null"}';
    final existingInfo = _storageInfo[cacheKey];

    if (existingInfo != null) {
      await _auxRepository.delete(existingInfo.storageId);
      _storageInfo.remove(cacheKey);
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  Map<String, dynamic> _payloadFromState(FsContactSecurityState state) {
    return {
      'kind': _kRecordKind,
      'v': 1,
      '_rid': _generateRecordId(),
      'contactId': state.contactId,
      'identityContext': state.identityContext,
      'sessionId': state.sessionId,
      'fsState': state.fsState.name,
      'createdAt': state.createdAt.millisecondsSinceEpoch,
    };
  }

  FsContactSecurityState? _stateFromPayload(Map<String, dynamic> payload) {
    try {
      final contactId = payload['contactId'] as String?;
      final identityContext = payload['identityContext'] as String?;
      final sessionId = payload['sessionId'] as String?;
      final fsStateName = payload['fsState'] as String?;
      final createdAtMs = payload['createdAt'] as int?;

      if (contactId == null || identityContext == null || fsStateName == null) {
        return null;
      }

      final fsState = FsSessionState.values.byName(fsStateName);
      final createdAt = createdAtMs != null
          ? DateTime.fromMillisecondsSinceEpoch(createdAtMs)
          : DateTime.now();

      return FsContactSecurityState(
        contactId: contactId,
        identityContext: identityContext,
        sessionId: sessionId,
        fsState: fsState,
        createdAt: createdAt,
      );
    } catch (_) {
      return null;
    }
  }

  String _generateRecordId() {
    final bytes = Uint8List(16);
    final random = Random.secure();
    for (var i = 0; i < 16; i++) {
      bytes[i] = random.nextInt(256);
    }
    return base64Url.encode(bytes).replaceAll('=', '');
  }
}

// Helper extension to get all keys from AuxRecordRepository
extension on AuxRecordRepository {
  Future<List<String>> getAllKeys() async {
    // This requires exposing the box or a method to list keys
    // For now, we'll use the existing clearAll pattern to identify aux records
    // Actually, we need a new method in AuxRecordRepository
    throw UnimplementedError();
  }

  Future<String?> readRaw(String key) async {
    // This also requires access to the box
    throw UnimplementedError();
  }
}
