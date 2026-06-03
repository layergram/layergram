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

/// Per-contact Forward Secrecy security mode (spec §6.1–§6.3, §14.3).
///
/// Each contact (per identity context) has an independently selectable mode:
///
/// - [base]: Legacy encryption only. FS negotiation is suppressed.
/// - [advanced]: Opportunistic FS (default). FS upgrades automatically when
///   both sides support it; legacy fallback is allowed.
/// - [strict]: Maximum FS. After a verified session, legacy fallback is
///   blocked. Requires explicit user consent (§14.6.2).
///
/// The mode is persisted as an opaque encrypted auxiliary record
/// (`kind: fs_mode_v1`) so it survives app restarts and maintains
/// plausible deniability for passphrase-derived contexts.
///
/// Spec reference: §6.1–§6.3, §6.8, §14.3.
enum FsSecurityMode {
  /// §6.1 — Standard Layergram encryption, no Forward Secrecy.
  base,

  /// §6.2 — Opportunistic FS (default). FS when available, legacy otherwise.
  advanced,

  /// §6.3 — Strict FS. FS-only after verified session; no legacy fallback.
  strict,
}

/// Persists the per-contact security mode as encrypted auxiliary records.
///
/// **Design:**
/// - One aux record per `(contactId, identityContext)` pair.
/// - Kind: `fs_mode_v1` — opaque after encryption, indistinguishable from
///   other aux records.
/// - Default mode is [FsSecurityMode.advanced] when no record exists.
/// - Passphrase-context modes are only accessible while the passphrase-derived
///   aux key is active; after expulsion they become opaque.
///
/// Spec reference: §14.3, §14.6.5.
class FsSecurityModeService {
  FsSecurityModeService({
    required AuxRecordRepository auxRepository,
  }) : _auxRepository = auxRepository;

  final AuxRecordRepository _auxRepository;

  static const String _kRecordKind = 'fs_mode_v1';

  /// In-memory index: `contactId:identityContext` → mode + storage info.
  final Map<String, _ModeEntry> _index = {};

  // ---------------------------------------------------------------------------
  // Read
  // ---------------------------------------------------------------------------

  /// Returns the security mode for [contactId] in [identityContext].
  ///
  /// Returns [FsSecurityMode.advanced] if no mode has been explicitly set
  /// (the default upgrade path per §6.2).
  Future<FsSecurityMode> getMode({
    required String contactId,
    required String identityContext,
  }) async {
    final key = _indexKey(contactId, identityContext);
    final cached = _index[key];
    if (cached != null) return cached.mode;

    // Scan aux records for this contact's mode
    final scanned = await _scanForMode(contactId, identityContext);
    return scanned ?? FsSecurityMode.advanced;
  }

  /// Synchronous check — returns cached mode or default.
  /// Use after [rebuildIndex] for hot-path reads.
  FsSecurityMode getModeSync({
    required String contactId,
    required String identityContext,
  }) {
    final key = _indexKey(contactId, identityContext);
    return _index[key]?.mode ?? FsSecurityMode.advanced;
  }

  // ---------------------------------------------------------------------------
  // Write
  // ---------------------------------------------------------------------------

  /// Sets the security mode for [contactId] in [identityContext].
  ///
  /// Persists as an encrypted aux record. If a previous mode record exists,
  /// it is atomically replaced (write-then-delete).
  Future<void> setMode({
    required String contactId,
    required String identityContext,
    required FsSecurityMode mode,
  }) async {
    final key = _indexKey(contactId, identityContext);
    final payload = <String, dynamic>{
      'kind': _kRecordKind,
      'v': 1,
      'cid': contactId,
      'ctx': identityContext,
      'mode': mode.name,
    };

    final existing = _index[key];
    if (existing != null) {
      final result = await _auxRepository.update(
        oldStorageId: existing.storageId,
        newPayload: payload,
      );
      _index[key] = _ModeEntry(
        mode: mode,
        storageId: result.storageId,
        recordId: result.recordId,
      );
    } else {
      final result = await _auxRepository.write(payload: payload);
      _index[key] = _ModeEntry(
        mode: mode,
        storageId: result.storageId,
        recordId: result.recordId,
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Index management
  // ---------------------------------------------------------------------------

  /// Rebuilds the in-memory index by scanning all aux records.
  ///
  /// Call once after app startup / identity context initialization.
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

        final cid = payload['cid'] as String?;
        final ctx = payload['ctx'] as String?;
        final modeStr = payload['mode'] as String?;
        if (cid == null || ctx == null || modeStr == null) continue;

        final mode = _parseMode(modeStr);
        if (mode == null) continue;

        final key = _indexKey(cid, ctx);
        _index[key] = _ModeEntry(
          mode: mode,
          storageId: entry.key,
          recordId: entry.value,
        );
      } catch (_) {
        continue;
      }
    }
  }

  /// Removes the mode record for a specific contact+context.
  Future<void> removeMode({
    required String contactId,
    required String identityContext,
  }) async {
    final key = _indexKey(contactId, identityContext);
    final entry = _index[key];
    if (entry != null) {
      await _auxRepository.delete(entry.storageId);
      _index.remove(key);
    }
  }

  /// Removes all mode records (e.g., on full data reset).
  Future<void> removeAll() async {
    await _auxRepository.clearByKind(_kRecordKind);
    _index.clear();
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  static String _indexKey(String contactId, String identityContext) =>
      '$contactId:$identityContext';

  static FsSecurityMode? _parseMode(String name) {
    for (final mode in FsSecurityMode.values) {
      if (mode.name == name) return mode;
    }
    return null;
  }

  Future<FsSecurityMode?> _scanForMode(
    String contactId,
    String identityContext,
  ) async {
    final allIds = _auxRepository.getAllAuxRecordIds();
    final targetKey = _indexKey(contactId, identityContext);

    for (final entry in allIds.entries) {
      try {
        final payload = await _auxRepository.read(
          storageId: entry.key,
          recordId: entry.value,
        );
        if (payload == null) continue;
        if (payload['kind'] != _kRecordKind) continue;

        final cid = payload['cid'] as String?;
        final ctx = payload['ctx'] as String?;
        final modeStr = payload['mode'] as String?;
        if (cid == null || ctx == null || modeStr == null) continue;

        final key = _indexKey(cid, ctx);
        final mode = _parseMode(modeStr);
        if (mode == null) continue;

        _index[key] = _ModeEntry(
          mode: mode,
          storageId: entry.key,
          recordId: entry.value,
        );

        if (key == targetKey) return mode;
      } catch (_) {
        continue;
      }
    }

    return null;
  }
}

class _ModeEntry {
  const _ModeEntry({
    required this.mode,
    required this.storageId,
    required this.recordId,
  });

  final FsSecurityMode mode;
  final String storageId;
  final String recordId;
}
