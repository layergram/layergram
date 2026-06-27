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

/// Passphrase timeout options (spec §11.3).
///
/// The timeout governs how long a passphrase-derived context stays active
/// after the last user interaction. On expiry, [FsPassphraseContextService]
/// wipes all in-memory state.
enum PassphraseTimeout {
  seconds30(Duration(seconds: 30), '30s'),
  minutes1(Duration(minutes: 1), '1m'),
  minutes2(Duration(minutes: 2), '2m'),
  minutes5(Duration(minutes: 5), '5m'),
  minutes10(Duration(minutes: 10), '10m'),
  manual(Duration.zero, 'manual');

  const PassphraseTimeout(this.duration, this.serialKey);

  final Duration duration;
  final String serialKey;

  bool get isManual => this == manual;

  static PassphraseTimeout fromSerialKey(String key) {
    for (final v in values) {
      if (v.serialKey == key) return v;
    }
    return defaultTimeout;
  }

  static const PassphraseTimeout defaultTimeout = minutes2;
}

/// Passphrase history mode (spec §12.2).
///
/// Controls how chat history is retained for a passphrase-derived context.
enum PassphraseHistoryMode {
  /// Messages remain available when the identity is unlocked again.
  keepEncrypted('keep'),

  /// Messages may be shown only during active session or limited time.
  volatile_('volatile'),

  /// FS state and history are RAM-only. FS restarts after expulsion.
  ephemeral('ephemeral');

  const PassphraseHistoryMode(this.serialKey);

  final String serialKey;

  static PassphraseHistoryMode fromSerialKey(String key) {
    for (final v in values) {
      if (v.serialKey == key) return v;
    }
    return defaultMode;
  }

  static const PassphraseHistoryMode defaultMode = keepEncrypted;
}

/// Passphrase FS persistence mode (spec §11.5, §6.4–§6.7).
///
/// Controls whether FS session state survives passphrase expulsion.
enum PassphraseFsPersistence {
  /// FS state persisted as encrypted aux records. Recommended (§6.5).
  persistent('persistent'),

  /// FS state is RAM-only. Lost on expulsion (§6.7).
  ephemeral('ephemeral');

  const PassphraseFsPersistence(this.serialKey);

  final String serialKey;

  static PassphraseFsPersistence fromSerialKey(String key) {
    for (final v in values) {
      if (v.serialKey == key) return v;
    }
    return defaultMode;
  }

  static const PassphraseFsPersistence defaultMode = persistent;
}

/// In-memory snapshot of preferences for one passphrase-derived context.
class PassphrasePreferences {
  const PassphrasePreferences({
    this.timeout = PassphraseTimeout.minutes2,
    this.expelOnScreenLock = false,
    this.historyMode = PassphraseHistoryMode.keepEncrypted,
    this.fsPersistence = PassphraseFsPersistence.persistent,
  });

  final PassphraseTimeout timeout;
  final bool expelOnScreenLock;
  final PassphraseHistoryMode historyMode;
  final PassphraseFsPersistence fsPersistence;

  PassphrasePreferences copyWith({
    PassphraseTimeout? timeout,
    bool? expelOnScreenLock,
    PassphraseHistoryMode? historyMode,
    PassphraseFsPersistence? fsPersistence,
  }) {
    return PassphrasePreferences(
      timeout: timeout ?? this.timeout,
      expelOnScreenLock: expelOnScreenLock ?? this.expelOnScreenLock,
      historyMode: historyMode ?? this.historyMode,
      fsPersistence: fsPersistence ?? this.fsPersistence,
    );
  }
}

/// Persists per-passphrase-context preferences as encrypted aux records.
///
/// **Design (spec §11.2, §11.3.1):**
/// - Preferences are stored inside opaque auxiliary records (`kind: fs_pp_v1`),
///   indistinguishable from other aux records.
/// - When no passphrase is active, no preferences are visible or loadable.
/// - When no stored preference exists, hardcoded defaults are used (§11.3.1).
/// - No global `passphrase_settings` key is created.
///
/// **First-activation behavior (§11.3.1):**
/// - The hardcoded default timeout is used until the user changes it.
/// - A preference record is only created when the user explicitly changes
///   a setting while the passphrase context is active.
class FsPassphrasePreferencesService {
  FsPassphrasePreferencesService({
    required AuxRecordRepository auxRepository,
  }) : _auxRepository = auxRepository;

  final AuxRecordRepository _auxRepository;

  static const String _kRecordKind = 'fs_pp_v1';

  /// In-memory index: contextTag → prefs + storage info.
  final Map<String, _PrefsEntry> _index = {};

  // ---------------------------------------------------------------------------
  // Read
  // ---------------------------------------------------------------------------

  /// Returns preferences for [contextTag], or defaults if none stored.
  PassphrasePreferences getPreferences(String contextTag) {
    return _index[contextTag]?.prefs ?? const PassphrasePreferences();
  }

  // ---------------------------------------------------------------------------
  // Write
  // ---------------------------------------------------------------------------

  /// Saves preferences for [contextTag].
  ///
  /// Creates a new aux record if none exists, or updates the existing one.
  Future<void> savePreferences({
    required String contextTag,
    required PassphrasePreferences prefs,
  }) async {
    final payload = _payloadFromPrefs(contextTag, prefs);
    final existing = _index[contextTag];

    if (existing != null) {
      final result = await _auxRepository.update(
        oldStorageId: existing.storageId,
        newPayload: payload,
      );
      _index[contextTag] = _PrefsEntry(
        prefs: prefs,
        storageId: result.storageId,
        recordId: result.recordId,
      );
    } else {
      final result = await _auxRepository.write(payload: payload);
      _index[contextTag] = _PrefsEntry(
        prefs: prefs,
        storageId: result.storageId,
        recordId: result.recordId,
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Remove
  // ---------------------------------------------------------------------------

  /// Removes stored preferences for [contextTag].
  Future<void> removePreferences(String contextTag) async {
    final existing = _index[contextTag];
    if (existing != null) {
      await _auxRepository.delete(existing.storageId);
      _index.remove(contextTag);
    }
  }

  /// Removes all passphrase preference records (e.g. on full data reset).
  Future<void> removeAll() async {
    await _auxRepository.clearByKind(_kRecordKind);
    _index.clear();
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

        final ctx = payload['ctx'] as String?;
        if (ctx == null) continue;

        final prefs = _prefsFromPayload(payload);
        _index[ctx] = _PrefsEntry(
          prefs: prefs,
          storageId: entry.key,
          recordId: entry.value,
        );
      } catch (_) {
        continue;
      }
    }
  }

  /// Clears the in-memory index without touching storage.
  void clearMemoryIndex() {
    _index.clear();
  }

  /// Returns all context tags that have stored preferences.
  Set<String> get storedContextTags => Set.unmodifiable(_index.keys);

  // ---------------------------------------------------------------------------
  // Serialization
  // ---------------------------------------------------------------------------

  Map<String, dynamic> _payloadFromPrefs(
    String contextTag,
    PassphrasePreferences prefs,
  ) {
    return {
      'kind': _kRecordKind,
      'v': 1,
      'ctx': contextTag,
      'to': prefs.timeout.serialKey,
      'sl': prefs.expelOnScreenLock ? 1 : 0,
      'hm': prefs.historyMode.serialKey,
      'fp': prefs.fsPersistence.serialKey,
    };
  }

  PassphrasePreferences _prefsFromPayload(Map<String, dynamic> payload) {
    return PassphrasePreferences(
      timeout: PassphraseTimeout.fromSerialKey(
        payload['to'] as String? ?? '',
      ),
      expelOnScreenLock: (payload['sl'] as int? ?? 0) == 1,
      historyMode: PassphraseHistoryMode.fromSerialKey(
        payload['hm'] as String? ?? '',
      ),
      fsPersistence: PassphraseFsPersistence.fromSerialKey(
        payload['fp'] as String? ?? '',
      ),
    );
  }
}

class _PrefsEntry {
  const _PrefsEntry({
    required this.prefs,
    required this.storageId,
    required this.recordId,
  });

  final PassphrasePreferences prefs;
  final String storageId;
  final String recordId;
}
