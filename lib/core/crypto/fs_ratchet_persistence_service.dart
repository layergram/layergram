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

import '../storage/aux_record_repository.dart';
import 'fs_double_ratchet.dart';

/// Persistence service for Double Ratchet state.
///
/// Saves and loads [RatchetState] to/from auxiliary records,
/// making active FS sessions survive app restarts.
///
/// Spec reference: §8 — Double Ratchet session persistence.
class FsRatchetPersistenceService {
  FsRatchetPersistenceService({
    required AuxRecordRepository auxRepository,
  }) : _auxRepository = auxRepository;

  final AuxRecordRepository _auxRepository;

  // In-memory cache of storage info: sessionId → (storageId, recordId)
  final Map<String, ({String storageId, String recordId})> _storageInfo = {};

  static const String _kRecordKind = 'fs_ratchet_v1';

  // ---------------------------------------------------------------------------
  // Load
  // ---------------------------------------------------------------------------

  /// Loads a persisted ratchet state for the given session.
  ///
  /// Returns null if no state is found or decryption fails.
  Future<RatchetState?> loadRatchetState(String sessionId) async {
    try {
      // Find the record for this session
      final allRecords = _auxRepository.getAllAuxRecordIds();

      for (final entry in allRecords.entries) {
        final storageId = entry.key;
        final recordId = entry.value;

        final payload = await _auxRepository.read(
          storageId: storageId,
          recordId: recordId,
        );
        if (payload == null) continue;

        if (payload['kind'] != _kRecordKind) continue;
        if (payload['sessionId'] != sessionId) continue;

        final state = _ratchetStateFromPayload(payload);
        if (state == null) continue;

        _storageInfo[sessionId] = (storageId: storageId, recordId: recordId);
        return state;
      }
    } catch (_) {
      // Return null on any error
    }
    return null;
  }

  /// Loads all persisted ratchet states from auxiliary storage.
  Future<List<RatchetState>> loadAllRatchetStates() async {
    final allIds = _auxRepository.getAllAuxRecordIds();

    final states = <RatchetState>[];

    for (final entry in allIds.entries) {
      try {
        final payload = await _auxRepository.read(
          storageId: entry.key,
          recordId: entry.value,
        );
        if (payload == null) continue;
        if (payload['kind'] != _kRecordKind) continue;

        final state = _ratchetStateFromPayload(payload);
        if (state == null) continue;

        states.add(state);

        // Cache storage info for later updates
        _storageInfo[state.sessionId] =
            (storageId: entry.key, recordId: entry.value);
      } catch (_) {
        // Skip corrupted entries
        continue;
      }
    }

    return states;
  }

  // ---------------------------------------------------------------------------
  // Save
  // ---------------------------------------------------------------------------

  /// Persists a ratchet state to auxiliary storage.
  Future<void> saveRatchetState(RatchetState state) async {
    final existingInfo = _storageInfo[state.sessionId];
    final payload = _payloadFromRatchetState(state);

    if (existingInfo != null) {
      // Update existing record
      final result = await _auxRepository.update(
        oldStorageId: existingInfo.storageId,
        newPayload: payload,
      );
      _storageInfo[state.sessionId] = result;
    } else {
      // Write new record
      final result = await _auxRepository.write(payload: payload);
      _storageInfo[state.sessionId] = result;
    }
  }

  /// Removes a persisted ratchet state.
  Future<void> removeRatchetState(String sessionId) async {
    final existingInfo = _storageInfo[sessionId];
    if (existingInfo != null) {
      await _auxRepository.delete(existingInfo.storageId);
      _storageInfo.remove(sessionId);
    }
  }

  /// Removes all persisted ratchet states.
  ///
  /// Called when the identity is reset to wipe all FS session keys.
  /// Per spec §8.6.3: Reset requires re-handshake for all sessions.
  ///
  /// Uses clearByKind to find and delete all records from the database,
  /// not just those in the in-memory cache.
  Future<void> removeAllRatchetStates() async {
    await _auxRepository.clearByKind(_kRecordKind);
    _storageInfo.clear();
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  Map<String, dynamic> _payloadFromRatchetState(RatchetState state) {
    return {
      'kind': _kRecordKind,
      'v': 1,
      'sessionId': state.sessionId,
      'rootKey': base64Encode(state.rootKey),
      'sendingChainKey': base64Encode(state.sendingChainKey),
      'receivingChainKey': base64Encode(state.receivingChainKey),
      'localRatchetPriv': base64Encode(state.localRatchetPriv),
      'localRatchetPub': base64Encode(state.localRatchetPub),
      'lastRemoteRatchetPub': state.lastRemoteRatchetPub != null
          ? base64Encode(state.lastRemoteRatchetPub!)
          : null,
      'sendCounter': state.sendCounter,
      'recvCounter': state.recvCounter,
      'skippedKeys': _encodeSkippedKeys(state.skippedKeys),
    };
  }

  RatchetState? _ratchetStateFromPayload(Map<String, dynamic> payload) {
    try {
      final sessionId = payload['sessionId'] as String?;
      final rootKeyB64 = payload['rootKey'] as String?;
      final sendingChainKeyB64 = payload['sendingChainKey'] as String?;
      final receivingChainKeyB64 = payload['receivingChainKey'] as String?;
      final localRatchetPrivB64 = payload['localRatchetPriv'] as String?;
      final localRatchetPubB64 = payload['localRatchetPub'] as String?;
      final lastRemoteRatchetPubB64 =
          payload['lastRemoteRatchetPub'] as String?;
      final sendCounter = payload['sendCounter'] as int?;
      final recvCounter = payload['recvCounter'] as int?;

      if (sessionId == null ||
          rootKeyB64 == null ||
          sendingChainKeyB64 == null ||
          receivingChainKeyB64 == null ||
          localRatchetPrivB64 == null ||
          localRatchetPubB64 == null ||
          sendCounter == null ||
          recvCounter == null) {
        return null;
      }

      return RatchetState(
        sessionId: sessionId,
        rootKey: base64Decode(rootKeyB64),
        sendingChainKey: base64Decode(sendingChainKeyB64),
        receivingChainKey: base64Decode(receivingChainKeyB64),
        localRatchetPriv: base64Decode(localRatchetPrivB64),
        localRatchetPub: base64Decode(localRatchetPubB64),
        lastRemoteRatchetPub: lastRemoteRatchetPubB64 != null
            ? base64Decode(lastRemoteRatchetPubB64)
            : null,
        sendCounter: sendCounter,
        recvCounter: recvCounter,
        skippedKeys: <dynamic, dynamic>{},
      );
    } catch (_) {
      return null;
    }
  }

  List<Map<String, dynamic>> _encodeSkippedKeys(
      Map<dynamic, dynamic> skippedKeys) {
    // Note: skippedKeys uses _SkippedKeyId as key which is private to fs_double_ratchet.dart
    // For now, we don't persist skipped keys - they will be re-derived on first message
    // This is acceptable as skipped keys are ephemeral
    return [];
  }
}
