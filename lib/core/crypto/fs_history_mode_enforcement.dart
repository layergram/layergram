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

import 'fs_passphrase_preferences.dart';
import 'fs_plaintext_cache.dart';
import 'fs_plaintext_persistence_service.dart';
import 'fs_state_persistence_service.dart';
import 'fs_ratchet_persistence_service.dart';
import 'fs_contact_security_state.dart';

/// Enforces passphrase history mode behavior on expulsion (§12.2).
///
/// Called when a passphrase-derived context is deactivated (timeout,
/// manual expulsion, screen lock). The actions depend on the history
/// mode configured for that context:
///
/// - **keepEncrypted**: no additional cleanup — plaintext aux records
///   remain and can be re-read when the passphrase is re-entered.
/// - **volatile**: wipe FS plaintext aux records and in-memory cache.
///   The FS session state is preserved so the handshake is not repeated.
/// - **ephemeral**: wipe FS plaintext, FS session state, and ratchet
///   state. FS starts fresh after next passphrase activation.
///
/// Spec references: §12.2, §6.4–§6.7, §11.5.
class FsHistoryModeEnforcement {
  FsHistoryModeEnforcement({
    required FsPlaintextCache plaintextCache,
    required FsPlaintextPersistenceService plaintextPersistence,
    required FsStatePersistenceService statePersistence,
    required FsRatchetPersistenceService ratchetPersistence,
    required FsContactSecurityRegistry securityRegistry,
  })  : _plaintextCache = plaintextCache,
        _plaintextPersistence = plaintextPersistence,
        _statePersistence = statePersistence,
        _ratchetPersistence = ratchetPersistence,
        _securityRegistry = securityRegistry;

  final FsPlaintextCache _plaintextCache;
  final FsPlaintextPersistenceService _plaintextPersistence;
  final FsStatePersistenceService _statePersistence;
  final FsRatchetPersistenceService _ratchetPersistence;
  final FsContactSecurityRegistry _securityRegistry;

  /// Execute cleanup actions for the given [historyMode] and
  /// [fsPersistence] on passphrase expulsion.
  ///
  /// [identityContext] identifies the passphrase context being expelled
  /// (typically the keyTag of the passphrase-derived identity).
  Future<void> onPassphraseExpelled({
    required PassphraseHistoryMode historyMode,
    required PassphraseFsPersistence fsPersistence,
    required String identityContext,
  }) async {
    switch (historyMode) {
      case PassphraseHistoryMode.keepEncrypted:
        _plaintextCache.wipe();
        break;

      case PassphraseHistoryMode.volatile_:
        _plaintextCache.wipe();
        await _plaintextPersistence.removeAll();
        break;

      case PassphraseHistoryMode.ephemeral:
        _plaintextCache.wipe();
        await _plaintextPersistence.removeAll();
        await _wipeEphemeralFsState(identityContext);
        break;
    }

    // Also enforce FS persistence mode (§11.5)
    if (fsPersistence == PassphraseFsPersistence.ephemeral &&
        historyMode != PassphraseHistoryMode.ephemeral) {
      await _wipeEphemeralFsState(identityContext);
    }
  }

  /// Wipes all FS session and ratchet state for the given context.
  Future<void> _wipeEphemeralFsState(String identityContext) async {
    _securityRegistry.markAllBroken(identityContext);
    await _statePersistence.removeAllStates(identityContext);
    await _ratchetPersistence.removeAllRatchetStates();

    assert(() {
      print('[FS-HISTORY] Wiped ephemeral FS state for context=$identityContext');
      return true;
    }());
  }

  /// Whether messages should be persisted for the given history mode.
  ///
  /// Returns `false` for ephemeral mode — callers should skip writing
  /// plaintext aux records when sending/receiving in this mode.
  static bool shouldPersistPlaintext(PassphraseHistoryMode mode) {
    return mode != PassphraseHistoryMode.ephemeral;
  }

  /// Whether FS state should be persisted for the given combination.
  ///
  /// Returns `false` for ephemeral FS persistence or ephemeral history mode.
  static bool shouldPersistFsState({
    required PassphraseHistoryMode historyMode,
    required PassphraseFsPersistence fsPersistence,
  }) {
    if (historyMode == PassphraseHistoryMode.ephemeral) return false;
    if (fsPersistence == PassphraseFsPersistence.ephemeral) return false;
    return true;
  }
}
