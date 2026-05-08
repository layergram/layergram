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
import 'security/app_lock_service.dart';
import 'security/cover_message_length_limit_service.dart';
import 'security/screen_protection_service.dart';
import 'security/tooltip_service.dart';
import 'security/preview_service.dart';
import 'security/session_decryption_cache_service.dart';
import 'crypto/stego_decoder.dart';
import 'crypto/stego_encoder.dart';
import 'storage/identities_repository.dart';
import 'storage/chat_meta_repository.dart';
import 'storage/local_identity_vault.dart';
import 'storage/local_storage_security_service.dart';
import 'storage/messages_repository.dart';
import 'storage/secure_storage.dart';
import 'utils/clipboard_service.dart';
import 'crypto/message_record_cipher.dart';
import '../features/contact_verification/contact_sas_service.dart';
import '../features/identity_migration_notice/identity_migration_notice_controller.dart';
import '../features/identity_migration_notice/identity_migration_notice_service.dart';
import 'crypto/fs_contact_security_state.dart';
import 'crypto/fs_session_manager.dart';
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

    final context =
        await ref.read(localStorageSecurityProvider).contextForIdentity(identityId);
    final local = await ref.read(identityManagerProvider).getLocalIdentity();
    final selfIdentity =
        local != null && local.identityId == identityId
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

    final context =
        await ref.read(localStorageSecurityProvider).contextForIdentity(identityId);
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
      privateKeyB64 = await ref.read(identityManagerProvider).getLocalPrivateKeyBase64();
    }
    if (privateKeyB64 == null) {
      await repo.setActiveContext(
        scopeToken: context?.scopeToken,
        storageKey: null,
      );
      return;
    }
    final keyBytes = Uint8List.fromList(base64Decode(privateKeyB64));
    final storageKey = await MessageRecordCipher.deriveKey(keyBytes, keyTag: keyTag);
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
    final context =
        await ref.read(localStorageSecurityProvider).contextForIdentity(activeId);
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
final identityMigrationNoticeServiceProvider = Provider((ref) {
  return IdentityMigrationNoticeService(ref.watch(secureStorageProvider));
});
final identityMigrationNoticeControllerProvider = Provider((ref) {
  return IdentityMigrationNoticeController(
    service: ref.watch(identityMigrationNoticeServiceProvider),
    loadIdentity: () => ref.read(identityManagerProvider).getLocalIdentity(),
  );
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

final passphraseProvider =
    StateNotifierProvider<PassphraseNotifier, PassphraseState>((ref) {
  return PassphraseNotifier(seedService: ref.watch(seedServiceProvider));
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
