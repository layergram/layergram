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

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter/material.dart';

import 'capabilities/chat_folders_capability.dart';
import 'capabilities/layergram_capabilities.dart';
import 'domain/identity_id.dart';
import 'crypto/encryption_service.dart';
import 'crypto/identity_manager.dart';
import 'crypto/models.dart';
import 'crypto/passphrase_service.dart';
import 'crypto/seed_service.dart';
import 'crypto/v3/application_runtime_owner_v3.dart';
import 'crypto/v3/application_session_runtime_v3.dart';
import 'crypto/v3/identity_runtime_v3.dart';
import 'crypto/v3/protocol_v3_activation.dart';
import 'security/app_lock_service.dart';
import 'security/cover_message_length_limit_service.dart';
import 'security/screen_protection_service.dart';
import 'security/tooltip_service.dart';
import 'security/preview_service.dart';
import 'security/session_decryption_cache_service.dart';
import 'crypto/stego_decoder.dart';
import 'crypto/stego_encoder.dart';
import 'crypto/fs_state_persistence_service.dart';
import 'crypto/fs_ratchet_persistence_service.dart';
import 'crypto/fs_double_ratchet.dart' show RatchetState;
import 'storage/aux_record_repository.dart';
import 'storage/identities_repository.dart';
import 'storage/chat_meta_repository.dart';
import 'storage/local_identity_vault.dart';
import 'storage/local_storage_security_service.dart';
import 'storage/messages_repository.dart';
import 'storage/secure_storage.dart';
import 'utils/clipboard_service.dart';
import 'crypto/message_record_cipher.dart';
import '../features/contact_verification/contact_sas_service.dart';
import 'crypto/fs_contact_security_state.dart';
import 'crypto/fs_dos_resistance.dart';
import 'crypto/fs_downgrade_detector.dart';
import 'crypto/fs_opportunistic_controller.dart';
import 'crypto/fs_plaintext_cache.dart';
import 'crypto/fs_plaintext_persistence_service.dart';
import 'crypto/fs_history_mode_enforcement.dart';
import 'crypto/fs_passphrase_preferences.dart';
import 'crypto/fs_passphrase_timeout_controller.dart';
import 'crypto/fs_security_mode.dart';
import 'crypto/fs_replay_cache.dart';
import 'crypto/fs_session_manager.dart';
import 'crypto/fs_state_mutex.dart';
import 'crypto/fs_strict_mode_controller.dart';

final seedServiceProvider = Provider((_) => SeedService());
final stegoEncoderProvider = Provider((_) => StegoEncoder());
final stegoDecoderProvider = Provider((_) => StegoDecoder());
final encryptionServiceProvider = Provider((_) => EncryptionService());
final contactSasServiceProvider = Provider((_) => const ContactSasService());
final secureStorageProvider = Provider((_) => SecureStorageService());
final localIdentityVaultProvider = Provider((ref) {
  return LocalIdentityVault(secureStorage: ref.watch(secureStorageProvider));
});
final localStorageSecurityProvider = Provider((ref) {
  return LocalStorageSecurityService(
    secureStorage: ref.watch(secureStorageProvider),
    localIdentityVault: ref.watch(localIdentityVaultProvider),
  );
});

/// Identity currently active in the UI.
///
/// OSS sets this to the single local identity id. Premium can override/switch.
final activeIdentityIdProvider = StateProvider<IdentityId?>((_) => null);

final identitiesRepositoryProvider = Provider<IdentitiesRepository>((ref) {
  final ownerId = ref.watch(activeIdentityIdProvider) ?? '';
  final repo = IdentitiesRepository(ownerIdentityId: ownerId);
  ref.onDispose(repo.dispose);

  Future<void> updateStorageContext() async {
    final identityId = ref.read(activeIdentityIdProvider) ?? '';
    if (identityId.isEmpty) {
      await repo.setActiveContext(
        scopeToken: null,
        encryptionKey: null,
        selfIdentity: null,
      );
      return;
    }

    final context = await ref
        .read(localStorageSecurityProvider)
        .contextForIdentity(identityId);
    final local = await ref.read(identityManagerProvider).getLocalIdentity();
    final selfIdentity = local != null && local.identityId == identityId
        ? RemoteIdentity(
            identityId: local.identityId,
            publicKeyBase64: local.publicKeyBase64,
            fingerprint: local.fingerprint,
            displayName: local.displayName,
            verified: true,
          )
        : null;

    await repo.setActiveContext(
      scopeToken: context?.scopeToken,
      encryptionKey: context?.contactsKey,
      selfIdentity: selfIdentity,
    );
  }

  updateStorageContext();
  ref.listen<int>(identityReloadTokenProvider, (_, __) {
    updateStorageContext();
  });
  return repo;
});

final messagesRepositoryProvider = Provider<MessagesRepository>((ref) {
  ref.watch(activeIdentityIdProvider);
  final repo = MessagesRepository();
  ref.onDispose(repo.dispose);

  Future<void> updateStorageContext() async {
    final identityId = ref.read(activeIdentityIdProvider) ?? '';
    final keyTag = ref.read(effectiveKeyTagProvider);
    if (identityId.isEmpty) {
      await repo.setActiveContext(scopeToken: null, storageKey: null);
      return;
    }

    final context = await ref
        .read(localStorageSecurityProvider)
        .contextForIdentity(identityId);
    final pp = ref.read(passphraseProvider);
    if (keyTag == null) {
      await repo.setActiveContext(
        scopeToken: context?.scopeToken,
        storageKey: null,
      );
      return;
    }

    final String? privateKeyB64;
    if (pp.isActive && pp.privateKeyBase64 != null) {
      privateKeyB64 = pp.privateKeyBase64;
    } else {
      privateKeyB64 =
          await ref.read(identityManagerProvider).getLocalPrivateKeyBase64();
    }
    if (privateKeyB64 == null) {
      await repo.setActiveContext(
        scopeToken: context?.scopeToken,
        storageKey: null,
      );
      return;
    }
    final keyBytes = Uint8List.fromList(base64Decode(privateKeyB64));
    final storageKey =
        await MessageRecordCipher.deriveKey(keyBytes, keyTag: keyTag);
    await repo.setActiveContext(
      scopeToken: context?.scopeToken,
      storageKey: storageKey,
    );
  }

  updateStorageContext();

  ref.listen<String?>(effectiveKeyTagProvider, (_, next) {
    updateStorageContext();
  });
  ref.listen<int>(identityReloadTokenProvider, (_, __) {
    updateStorageContext();
  });

  return repo;
});

final chatMetaRepositoryProvider = Provider<ChatMetaRepository>((ref) {
  final identityId = ref.watch(activeIdentityIdProvider) ?? '';
  final repo = ChatMetaRepository(identityId: identityId);
  ref.onDispose(repo.dispose);

  Future<void> updateStorageContext() async {
    final activeId = ref.read(activeIdentityIdProvider) ?? '';
    if (activeId.isEmpty) {
      await repo.setActiveContext(scopeToken: null, encryptionKey: null);
      return;
    }
    final context = await ref
        .read(localStorageSecurityProvider)
        .contextForIdentity(activeId);
    await repo.setActiveContext(
      scopeToken: context?.scopeToken,
      encryptionKey: context?.chatMetaKey,
    );
  }

  updateStorageContext();
  ref.listen<int>(identityReloadTokenProvider, (_, __) {
    updateStorageContext();
  });
  return repo;
});
final clipboardServiceProvider = Provider((_) => ClipboardService());
final layergramCapabilitiesProvider =
    Provider<LayergramCapabilities>((_) => const LayergramCapabilities());

/// Selected chat folder in the UI.
///
/// Core uses only [kAllChatsFolderId]. Premium can provide additional folders.
final selectedChatFolderIdProvider =
    StateProvider<String>((_) => kAllChatsFolderId);

/// User-defined folders (excluding the implicit [kAllChatsFolderId]).
final chatFoldersProvider = StreamProvider<List<ChatFolder>>((ref) {
  final caps = ref.watch(layergramCapabilitiesProvider);
  return caps.chatFolders.watchFolders();
});

/// Membership for a specific folder.
final chatIdsInFolderProvider =
    StreamProvider.family<Set<String>, String>((ref, folderId) {
  final caps = ref.watch(layergramCapabilitiesProvider);
  return caps.chatFolders.watchChatIdsInFolder(folderId);
});

/// Pinned chats for the currently selected folder.
///
/// OSS core supports pinning inside the implicit [kAllChatsFolderId]. Premium
/// can support pinning per folder, per identity.
final pinnedChatsProvider = StreamProvider<Map<String, int>>((ref) {
  final folderId = ref.watch(selectedChatFolderIdProvider);
  final repo = ref.watch(chatMetaRepositoryProvider);
  return repo.watchPinnedChats(folderId: folderId);
});

final reducedEffectsProvider = StateProvider<bool>((_) => false);
final backgroundAnimationHoldCountProvider = StateProvider<int>((_) => 0);
final backgroundAnimationPausedProvider = Provider<bool>((ref) {
  return ref.watch(backgroundAnimationHoldCountProvider) > 0;
});

final themeModeProvider = StateProvider<ThemeMode>((_) => ThemeMode.system);
final pendingDeepLinkProvider = StateProvider<String?>((_) => null);
final pendingSharedTextProvider = StateProvider<String?>((_) => null);
final tooltipsEnabledProvider = StateProvider<bool>((_) => false);
final screenProtectionEnabledProvider = StateProvider<bool>((_) => true);
final privacyShieldVisibleProvider = StateProvider<bool>((_) => false);
final isSharingProvider = StateProvider<bool>((_) => false);
final appLockServiceProvider = Provider((ref) {
  return AppLockService(ref.watch(secureStorageProvider));
});
final screenProtectionServiceProvider = Provider((ref) {
  return ScreenProtectionService(ref.watch(secureStorageProvider));
});
final tooltipServiceProvider = Provider((ref) {
  return TooltipService(ref.watch(secureStorageProvider));
});
final coverMessageLengthLimitServiceProvider = Provider((ref) {
  return CoverMessageLengthLimitService(ref.watch(secureStorageProvider));
});
final previewServiceProvider = Provider((ref) {
  return PreviewService(ref.watch(secureStorageProvider));
});
final sessionDecryptionCacheServiceProvider = Provider((ref) {
  return SessionDecryptionCacheService(ref.watch(secureStorageProvider));
});
final coverMessageLengthLimitProvider =
    StateProvider<int?>((_) => CoverMessageLengthLimitService.defaultLimit);
final hideChatPreviewProvider = StateProvider<bool>((_) => false);
final sessionDecryptionCacheEnabledProvider = StateProvider<bool>((_) => false);
final appLockEnabledProvider = StateProvider<bool>((_) => false);
final appNeedsUnlockProvider = StateProvider<bool>((_) => false);
final appLockTimeoutProvider = StateProvider<int>((_) => 60);
final appLockForcePinProvider = StateProvider<bool>((_) => false);
final identityReloadTokenProvider = StateProvider<int>((_) => 0);

/// Initial index for AppShell navigation after onboarding.
/// null means use default (0 for messages).
/// Set to navigate to specific page after identity creation/restore.
final appShellInitialIndexProvider = StateProvider<int?>((_) => null);

final identityManagerProvider = Provider((ref) {
  return IdentityManager(
    seedService: ref.watch(seedServiceProvider),
    localIdentityVault: ref.watch(localIdentityVaultProvider),
  );
});

/// Fail-closed application selector for protocol-v3 identity presentation.
///
/// Tests may override this while the production value remains tied to the
/// reviewed activation policy. Identity sharing is never enabled on its own.
final protocolV3IdentityEnabledProvider = Provider<bool>((_) {
  return ProtocolV3Activation.isActive;
});

/// Fail-closed selector for the complete v3 session/message runtime.
///
/// Identity sharing and messaging deliberately use the same all-or-nothing
/// production decision. Tests may override this seam without changing the
/// compiled production policy.
final protocolV3MessagingEnabledProvider = Provider<bool>((_) {
  return ProtocolV3Activation.isActive;
});

/// Process owner for deterministic v3 identity handles.
///
/// The backend is loaded lazily on first use, so merely constructing the app
/// cannot activate or probe the native protocol path.
final v3IdentityRuntimeProvider = Provider<V3IdentityRuntime>((ref) {
  final runtime = V3IdentityRuntime(
    seedService: ref.watch(seedServiceProvider),
  );
  ref.onDispose(() => unawaited(runtime.close()));
  return runtime;
});

final v3ApplicationRuntimeFactoryProvider =
    Provider<V3ApplicationRuntimeFactory<V3ApplicationSessionRuntime>>((_) {
  return ({required localIdentity, required scopeToken}) =>
      V3ApplicationSessionRuntime.openPackagedScka(
        localIdentity: localIdentity,
        scopeToken: scopeToken,
      );
});

/// Sole owner of an open v3 identity/passphrase persistence scope.
///
/// The owner is kept separate from the async selector so rapid Riverpod
/// rebuilds cannot overlap two durable runtimes or destroy an identity handle
/// before its journals have drained.
final v3ApplicationRuntimeOwnerProvider =
    Provider<V3ApplicationRuntimeOwner<V3ApplicationSessionRuntime>>((ref) {
  final owner = V3ApplicationRuntimeOwner<V3ApplicationSessionRuntime>(
    identityRuntime: ref.watch(v3IdentityRuntimeProvider),
    runtimeFactory: ref.watch(v3ApplicationRuntimeFactoryProvider),
  );
  ref.onDispose(() => unawaited(owner.close()));
  return owner;
});

/// Restored v3 application runtime for the currently effective identity.
///
/// With the production activation constants still false this provider returns
/// without constructing the identity owner or loading any native library.
final v3ApplicationSessionRuntimeProvider =
    FutureProvider<V3ApplicationSessionRuntime?>((ref) async {
  if (!ref.watch(protocolV3MessagingEnabledProvider)) return null;

  final activeIdentityId = ref.watch(activeIdentityIdProvider);
  ref.watch(identityReloadTokenProvider);
  final passphrase = ref.watch(passphraseProvider);
  final owner = ref.watch(v3ApplicationRuntimeOwnerProvider);
  if (activeIdentityId == null || activeIdentityId.isEmpty) {
    await owner.closeCurrent();
    return null;
  }

  final local = await ref.read(identityManagerProvider).getLocalIdentity();
  if (local == null || local.identityId != activeIdentityId) {
    await owner.closeCurrent();
    return null;
  }
  final context = await ref
      .read(localStorageSecurityProvider)
      .contextForIdentity(activeIdentityId);
  if (context == null) {
    await owner.closeCurrent();
    return null;
  }

  final usePassphrase = passphrase.isActive;
  final effectiveIdentityId =
      usePassphrase ? passphrase.v3IdentityId : local.identityId;
  if (effectiveIdentityId == null || effectiveIdentityId.isEmpty) {
    await owner.closeCurrent();
    return null;
  }
  final runtime = await owner.open(
    recoveryIdentity: local,
    scopeToken: context.scopeToken,
    contextId:
        '${usePassphrase ? 'passphrase' : 'primary'}|$effectiveIdentityId|${context.scopeToken}',
    usePassphraseIdentity: usePassphrase,
  );
  await runtime.maintainRetainedState(now: DateTime.now().toUtc());
  return runtime;
});

final passphraseProvider =
    StateNotifierProvider<PassphraseNotifier, PassphraseState>((ref) {
  final enableProtocolV3 = ref.watch(protocolV3IdentityEnabledProvider);
  return PassphraseNotifier(
    seedService: ref.watch(seedServiceProvider),
    v3IdentityRuntime:
        enableProtocolV3 ? ref.watch(v3IdentityRuntimeProvider) : null,
    beforeV3ContextChange: enableProtocolV3
        ? ref.watch(v3ApplicationRuntimeOwnerProvider).closeCurrent
        : null,
    enableProtocolV3: enableProtocolV3,
  );
});

/// The keyTag for the original (non-passphrase) identity.
/// Recomputed when the identity changes.
final originalKeyTagProvider = FutureProvider<String?>((ref) async {
  ref.watch(activeIdentityIdProvider);
  ref.watch(identityReloadTokenProvider);
  final mgr = ref.read(identityManagerProvider);
  final local = await mgr.getLocalIdentity();
  if (local == null) return null;
  return PassphraseNotifier.computeKeyTagFromBase64(local.publicKeyBase64);
});

/// The effective keyTag for the currently active key.
/// When passphrase is active, returns the passphrase keyTag;
/// otherwise returns the original identity keyTag.
/// Widgets can `ref.watch` this to filter messages synchronously.
final effectiveKeyTagProvider = Provider<String?>((ref) {
  final pp = ref.watch(passphraseProvider);
  if (pp.isActive && pp.keyTag != null) return pp.keyTag;
  return ref.watch(originalKeyTagProvider).valueOrNull;
});

/// Whether a passphrase is currently active.
final isPassphraseActiveProvider = Provider<bool>((ref) {
  return ref.watch(passphraseProvider).isActive;
});

// ---------------------------------------------------------------------------
// Forward Secrecy runtime singletons (§7.7, §7.6, §12.3, §20.1, §20.3)
// ---------------------------------------------------------------------------

/// Shared replay cache for FS handshake IDs and message counters (§8.7).
final fsReplayCacheProvider = Provider<FsReplayCache>((_) => FsReplayCache());

/// Shared DoS guard for handshake rate limiting (§20.3).
final fsDoSGuardProvider = Provider<FsDoSGuard>((_) => FsDoSGuard());

/// Shared mutex for serializing per-contact FS state transitions (§20.1).
final fsStateMutexProvider = Provider<FsStateMutex>((_) => FsStateMutex());

/// Shared downgrade detector for tracking highest security levels (§7.6).
final fsDowngradeDetectorProvider =
    Provider<FsDowngradeDetector>((_) => FsDowngradeDetector());

/// In-memory plaintext cache for FS-decrypted messages (§12.3).
final fsPlaintextCacheProvider =
    Provider<FsPlaintextCache>((_) => FsPlaintextCache());

/// Per-contact [FsSessionManager] instances, keyed by contactId.
///
/// Each contact gets its own state machine. These are RAM-only; the caller
/// is responsible for persisting state to aux records.
final fsSessionManagerProvider =
    Provider.family<FsSessionManager, String>((ref, contactId) {
  return FsSessionManager();
});

/// Per-contact [FsStrictModeController], keyed by contactId.
///
/// Uses the primary identity context (`'primary'`) for non-passphrase use.
final fsStrictModeControllerProvider =
    Provider.family<FsStrictModeController, String>((ref, contactId) {
  return FsStrictModeController(
    contactId: contactId,
    identityContext: 'primary',
    sessionManager: ref.watch(fsSessionManagerProvider(contactId)),
    registry: ref.watch(fsContactSecurityRegistryProvider),
    persistenceService: ref.watch(fsStatePersistenceServiceProvider),
  );
});

/// Per-contact [FsOpportunisticController], keyed by contactId.
///
/// Orchestrates the opportunistic FS handshake (FS_INIT → FS_REPLY → FS_CONFIRM).
final fsOpportunisticControllerProvider =
    Provider.family<FsOpportunisticController, String>((ref, contactId) {
  return FsOpportunisticController(
    localContactId: contactId,
    identityContext: 'primary',
    sessionManager: ref.watch(fsSessionManagerProvider(contactId)),
    registry: ref.watch(fsContactSecurityRegistryProvider),
    persistenceService: ref.watch(fsStatePersistenceServiceProvider),
    ratchetPersistenceService: ref.watch(fsRatchetPersistenceServiceProvider),
    replayCache: ref.watch(fsReplayCacheProvider),
    dosGuard: ref.watch(fsDoSGuardProvider),
    stateMutex: ref.watch(fsStateMutexProvider),
    downgradeDetector: ref.watch(fsDowngradeDetectorProvider),
    plaintextCache: ref.watch(fsPlaintextCacheProvider),
    onRatchetInitialized: (ratchetState) {
      // Update the cache when ratchet is initialized after handshake
      ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
            ...cache,
            ratchetState.sessionId: ratchetState,
          });
    },
  );
});

/// Single in-memory registry of FS contact security states.
///
/// Scoped to the app lifetime. Controllers call [FsContactSecurityRegistry.upsert]
/// to update state; widgets watch [fsStateForContactProvider] to read it.
final fsContactSecurityRegistryProvider =
    Provider<FsContactSecurityRegistry>((_) => FsContactSecurityRegistry());

/// Notifier that widgets use to trigger a UI refresh after an FS state change.
///
/// Increment this whenever [FsContactSecurityRegistry.upsert] is called so that
/// [fsStateForContactProvider] family providers re-evaluate.
final fsRegistryVersionProvider = StateProvider<int>((_) => 0);

/// Returns the most-prominent [FsSessionState] for [contactId] in the primary
/// identity context.
///
/// Priority order (highest wins):
///   strictFsActive > fsActive > strictRequested > handshake-in-progress > legacyOnly
///
/// Returns [FsSessionState.legacyOnly] when no entry exists.
final fsStateForContactProvider =
    Provider.family<FsSessionState, String>((ref, contactId) {
  ref.watch(fsRegistryVersionProvider); // rebuild when registry changes
  final registry = ref.watch(fsContactSecurityRegistryProvider);
  final entries = registry.forContactAllContexts(contactId);
  if (entries.isEmpty) return FsSessionState.legacyOnly;

  const priority = [
    FsSessionState.fsBroken,
    FsSessionState.strictFsActive,
    FsSessionState.fsActive,
    FsSessionState.strictRequested,
    FsSessionState.fsConfirmed,
    FsSessionState.fsConfirmSent,
    FsSessionState.fsReplySeen,
    FsSessionState.fsReplySent,
    FsSessionState.fsInitSeen,
    FsSessionState.fsInitSent,
    FsSessionState.fsSuspended,
    FsSessionState.legacyOnly,
  ];

  FsSessionState best = FsSessionState.legacyOnly;
  for (final e in entries) {
    final pi = priority.indexOf(e.fsState);
    final bi = priority.indexOf(best);
    if (pi < bi) best = e.fsState;
  }
  return best;
});

/// [AuxRecordRepository] singleton for persisting sealed auxiliary records.
///
/// Used by FS state persistence and other auxiliary data storage.
final auxRecordRepositoryProvider =
    Provider<AuxRecordRepository>((_) => AuxRecordRepository());

/// [FsStatePersistenceService] singleton for persisting FS contact security state.
///
/// Saves and loads [FsContactSecurityState] entries to/from auxiliary records,
/// making FS state survive app restarts.
///
/// Call [loadPersistedState] after identity context is initialized.
final fsStatePersistenceServiceProvider =
    Provider<FsStatePersistenceService>((ref) {
  return FsStatePersistenceService(
    auxRepository: ref.watch(auxRecordRepositoryProvider),
    registry: ref.watch(fsContactSecurityRegistryProvider),
  );
});

/// [FsRatchetPersistenceService] singleton for persisting Double Ratchet state.
///
/// Saves and loads [RatchetState] to/from auxiliary records,
/// making active FS encryption sessions survive app restarts.
///
/// Call [loadAllRatchetStates] after identity context is initialized.
final fsRatchetPersistenceServiceProvider =
    Provider<FsRatchetPersistenceService>((ref) {
  return FsRatchetPersistenceService(
    auxRepository: ref.watch(auxRecordRepositoryProvider),
  );
});

/// In-memory cache of loaded ratchet states.
///
/// Key: sessionId → RatchetState
/// This is populated at app startup and updated when sessions are created.
final fsRatchetStateCacheProvider =
    StateProvider<Map<String, RatchetState>>((_) => {});

/// [FsPlaintextPersistenceService] singleton for persisting FS-decrypted
/// plaintext as encrypted auxiliary records (§12.3).
///
/// FS messages have `text: null` in [MessageRecord]. The decrypted plaintext
/// is stored in an opaque aux record, indistinguishable from FS state records.
/// On identity reset, [removeAll] deletes all persisted FS plaintext.
final fsPlaintextPersistenceServiceProvider =
    Provider<FsPlaintextPersistenceService>((ref) {
  return FsPlaintextPersistenceService(
    auxRepository: ref.watch(auxRecordRepositoryProvider),
  );
});

/// Per-contact security mode service (§14.3).
///
/// Persists the user's choice of Base/Advanced/Strict per contact as
/// encrypted aux records (`kind: fs_mode_v1`).
final fsSecurityModeServiceProvider = Provider<FsSecurityModeService>((ref) {
  return FsSecurityModeService(
    auxRepository: ref.watch(auxRecordRepositoryProvider),
  );
});

// ---------------------------------------------------------------------------
// Passphrase preferences & timeout (§11.2–§11.5, §14.2)
// ---------------------------------------------------------------------------

/// [FsPassphrasePreferencesService] singleton for persisting per-passphrase-
/// context preferences (timeout, screen lock, history mode, FS persistence).
final fsPassphrasePreferencesServiceProvider =
    Provider<FsPassphrasePreferencesService>((ref) {
  return FsPassphrasePreferencesService(
    auxRepository: ref.watch(auxRecordRepositoryProvider),
  );
});

/// Reactive passphrase preferences notifier.
///
/// Widgets watch this for the current passphrase-context preferences.
/// Returns hardcoded defaults when no passphrase is active (§11.3.1).
final passphrasePreferencesProvider =
    StateNotifierProvider<PassphrasePreferencesNotifier, PassphrasePreferences>(
        (ref) {
  return PassphrasePreferencesNotifier(
    preferencesService: ref.watch(fsPassphrasePreferencesServiceProvider),
    passphraseState: ref.watch(passphraseProvider),
  );
});

/// Passphrase timeout controller (§11.3, §11.4).
///
/// Manages the automatic expulsion timer. Call [start] when passphrase
/// activates, [stop] on deactivation.
final fsPassphraseTimeoutControllerProvider =
    Provider<FsPassphraseTimeoutController>((ref) {
  return FsPassphraseTimeoutController(
    onExpel: () {
      final pp = ref.read(passphraseProvider);
      final prefs = ref.read(passphrasePreferencesProvider);
      final keyTag = pp.keyTag;
      if (keyTag != null) {
        ref.read(fsHistoryModeEnforcementProvider).onPassphraseExpelled(
              historyMode: prefs.historyMode,
              fsPersistence: prefs.fsPersistence,
              identityContext: keyTag,
            );
      }
      unawaited(ref.read(passphraseProvider.notifier).deactivate());
    },
  );
});

/// [FsHistoryModeEnforcement] singleton for enforcing history mode
/// cleanup on passphrase expulsion (§12.2, §6.4–§6.7, §11.5).
final fsHistoryModeEnforcementProvider =
    Provider<FsHistoryModeEnforcement>((ref) {
  return FsHistoryModeEnforcement(
    plaintextCache: ref.watch(fsPlaintextCacheProvider),
    plaintextPersistence: ref.watch(fsPlaintextPersistenceServiceProvider),
    statePersistence: ref.watch(fsStatePersistenceServiceProvider),
    ratchetPersistence: ref.watch(fsRatchetPersistenceServiceProvider),
    securityRegistry: ref.watch(fsContactSecurityRegistryProvider),
  );
});

/// Reactive notifier for passphrase preferences.
///
/// Loads preferences from [FsPassphrasePreferencesService] when a passphrase
/// becomes active, and syncs changes back to storage.
class PassphrasePreferencesNotifier
    extends StateNotifier<PassphrasePreferences> {
  PassphrasePreferencesNotifier({
    required FsPassphrasePreferencesService preferencesService,
    required PassphraseState passphraseState,
  })  : _preferencesService = preferencesService,
        _passphraseState = passphraseState,
        super(const PassphrasePreferences()) {
    _loadIfActive();
  }

  final FsPassphrasePreferencesService _preferencesService;
  final PassphraseState _passphraseState;

  void _loadIfActive() {
    final tag = _passphraseState.keyTag;
    if (tag == null || !_passphraseState.isActive) {
      state = const PassphrasePreferences();
      return;
    }
    state = _preferencesService.getPreferences(tag);
  }

  Future<void> updateTimeout(PassphraseTimeout timeout) async {
    state = state.copyWith(timeout: timeout);
    await _persist();
  }

  Future<void> updateExpelOnScreenLock(bool value) async {
    state = state.copyWith(expelOnScreenLock: value);
    await _persist();
  }

  Future<void> updateHistoryMode(PassphraseHistoryMode mode) async {
    state = state.copyWith(historyMode: mode);
    await _persist();
  }

  Future<void> updateFsPersistence(PassphraseFsPersistence mode) async {
    state = state.copyWith(fsPersistence: mode);
    await _persist();
  }

  Future<void> _persist() async {
    final tag = _passphraseState.keyTag;
    if (tag == null || !_passphraseState.isActive) return;
    await _preferencesService.savePreferences(
      contextTag: tag,
      prefs: state,
    );
  }
}
