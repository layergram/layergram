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
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/crypto/fs_double_ratchet.dart';
import '../../core/crypto/fs_handshake.dart';
import '../../core/crypto/encryption_service.dart';
import '../../core/crypto/fs_message_classification.dart';
import '../../core/crypto/fs_opportunistic_controller.dart';
import '../../core/crypto/fs_security_mode.dart';
import '../../core/crypto/lmf_v2_decoder.dart';
import '../../core/crypto/fs_session_manager.dart';
import '../../core/crypto/message_record_cipher.dart';
import '../../core/crypto/models.dart';
import '../../core/crypto/passphrase_service.dart';
import '../../core/providers.dart';

class DecryptedMessagePreview {
  const DecryptedMessagePreview({
    required this.text,
    required this.timestamp,
  });

  final String text;
  final int timestamp;
}

class HomeController {
  HomeController(this.ref);

  final Ref ref;
  final LinkedHashMap<String, Future<SecretKey?>> _displayKeys =
      LinkedHashMap<String, Future<SecretKey?>>();

  static const int _maxRetainedDisplayKeys = 12;
  static const int _sessionWarmContactLimit = 6;

  // ── Passphrase helpers ──────────────────────────────────────────────────

  /// Returns the private key to use for encryption/decryption.
  /// If a passphrase is active, returns the passphrase-derived key;
  /// otherwise returns the identity manager's stored key.
  Future<String?> _activePrivateKey() async {
    final pp = ref.read(passphraseProvider);
    if (pp.isActive && pp.privateKeyBase64 != null) {
      return pp.privateKeyBase64;
    }
    return ref.read(identityManagerProvider).getLocalPrivateKeyBase64();
  }

  Future<SecretKey?> currentStorageKey() async {
    final privateKeyB64 = await _activePrivateKey();
    if (privateKeyB64 == null) return null;
    final keyTag = await currentKeyTag();
    if (keyTag == null) return null;
    final keyBytes = Uint8List.fromList(base64Decode(privateKeyB64));
    return MessageRecordCipher.deriveKey(keyBytes, keyTag: keyTag);
  }

  /// The keyTag for the currently active key (passphrase or original).
  /// Returns `null` only if the identity is not yet initialized.
  Future<String?> currentKeyTag() async {
    // Fast path: provider already resolved.
    final cached = ref.read(effectiveKeyTagProvider);
    if (cached != null) return cached;
    // Slow path: compute from identity manager.
    final pp = ref.read(passphraseProvider);
    if (pp.isActive && pp.keyTag != null) return pp.keyTag;
    final local = await ref.read(identityManagerProvider).getLocalIdentity();
    if (local == null) return null;
    return PassphraseNotifier.computeKeyTagFromBase64(local.publicKeyBase64);
  }

  /// V2: link payload is base64url of raw bytes (nonce + ciphertext).
  String buildLinkPayload(EncryptedMessage encrypted) {
    final raw = encrypted.toRawBytes();
    return 'layergram://m/${base64Url.encode(raw).replaceAll('=', '')}';
  }

  Future<String> generateHiddenMessage({
    required String coverText,
    required String secretText,
    required RemoteIdentity recipient,
    int? expireAfter,
    bool deleteAfterRead = false,
  }) async {
    final result = await encryptForRecipient(
      secretText: secretText,
      recipient: recipient,
      expireAfter: expireAfter,
      deleteAfterRead: deleteAfterRead,
    );

    return ref
        .read(stegoEncoderProvider)
        .encodeBytes(coverText, result.message.toRawBytes());
  }

  Future<
      ({
        EncryptedMessage message,
        bool isFsEncrypted,
        FsMessageClassification classification
      })> encryptForRecipient({
    required String secretText,
    required RemoteIdentity recipient,
    int? expireAfter,
    bool deleteAfterRead = false,
    bool selfCopy = false,
  }) async {
    final identityManager = ref.read(identityManagerProvider);
    final local = await identityManager.getLocalIdentity();
    final privateKey = await _activePrivateKey();
    if (local == null || privateKey == null) {
      throw StateError('Identity not initialized');
    }

    // Check Maximum/Strict FS policy before sending
    if (!selfCopy) {
      final strictController = ref.read(
        fsStrictModeControllerProvider(recipient.identityId),
      );
      // TODO: Track device changes for strict mode - currently assumes known device
      if (!strictController.canSendMessage(deviceChanged: false)) {
        final reason = strictController.sendBlockReason(deviceChanged: false) ??
            'Maximum Forward Secrecy prevents sending in current state';
        throw StateError(reason);
      }
    }

    final payload = PlaintextPayload(
      senderId: local.identityId,
      recipientId: selfCopy ? local.identityId : recipient.identityId,
      text: secretText,
      timestamp: DateTime.now().millisecondsSinceEpoch ~/ 1000,
      senderDisplayName: local.displayName,
      expireAfter: expireAfter,
      deleteAfterRead: deleteAfterRead,
    );

    // Use passphrase-derived public key for self-copy when passphrase is active.
    final pp = ref.read(passphraseProvider);
    final selfPublic = (pp.isActive && pp.publicKeyBase64 != null)
        ? pp.publicKeyBase64!
        : local.publicKeyBase64;

    // Get FS extension for opportunistic Forward Secrecy handshake
    Map<String, dynamic>? fsExtension;
    RatchetState? ratchetState;
    String? sessionId;
    // §9.6: when the contact has multiple active device sessions, the content
    // key is wrapped for all of them in a single multi-envelope message.
    Map<String, RatchetState>? multiSessionRatchets;
    bool includeLegacyFallback = false;

    if (!selfCopy) {
      final fsController = ref.read(
        fsOpportunisticControllerProvider(recipient.identityId),
      );
      // CRITICAL: Use the controller's session manager to ensure we're using
      // the same instance that the controller uses for state transitions.
      // Using a separate provider could result in different instances.
      final sessionManager = fsController.sessionManager;

      // Prepare handshake payload based on current state
      final state = sessionManager.state;
      final securityMode = ref.read(fsSecurityModeServiceProvider).getModeSync(
            contactId: recipient.identityId,
            identityContext: fsController.identityContext,
          );
      fsController.securityMode = securityMode;
      final outgoingExt = await _buildFsOutgoingExtension(
        fsController: fsController,
        sessionManager: sessionManager,
        state: state,
        recipient: recipient,
        privateKey: privateKey,
      );
      if (outgoingExt?.json != null) {
        fsExtension = outgoingExt!.json;
      }

      // If FS is active, get the ratchet state for encryption
      if (securityMode != FsSecurityMode.base &&
          (state == FsSessionState.fsActive ||
              state == FsSessionState.strictFsActive)) {
        sessionId = sessionManager.activeSessionId;
        if (sessionId != null) {
          ratchetState = ref.read(fsRatchetStateCacheProvider)[sessionId];
          // If not in cache but session is active, try to load from persistence
          if (ratchetState == null) {
            ratchetState = await ref
                .read(fsRatchetPersistenceServiceProvider)
                .loadRatchetState(sessionId);
            if (ratchetState != null) {
              // Put it back in cache for future use
              ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
                    ...cache,
                    sessionId!: ratchetState!,
                  });
            } else {
              // CRITICAL: Ratchet state is missing from both cache and persistence.
              // This should never happen in normal operation - the session is inconsistent.
              // Mark session as broken and fall back to legacy encryption (safe default).
              sessionManager.markBroken();
            }
          }
        } else {
          // CRITICAL: State is fsActive but activeSessionId is null.
          // This is an inconsistent state - the session activation failed or was lost.
          // Mark session as broken to recover gracefully.
          sessionManager.markBroken();
        }
      }

      // §9.6: collect active device sessions so one payload can be read by
      // every known device. Single-session Advanced uses the smaller FS
      // envelope plus legacy fallback instead of forcing fs_multi.
      includeLegacyFallback = securityMode == FsSecurityMode.advanced &&
          state == FsSessionState.fsActive;
      if (ratchetState != null) {
        final activeIds = fsController.allActiveSessionIds;
        if (activeIds.length >= 2) {
          final cache = ref.read(fsRatchetStateCacheProvider);
          final persistence = ref.read(fsRatchetPersistenceServiceProvider);
          final collected = <String, RatchetState>{};
          for (final id in activeIds) {
            final r = cache[id] ?? await persistence.loadRatchetState(id);
            if (r != null) collected[id] = r;
          }
          if (collected.length >= 2) {
            multiSessionRatchets = collected;
          }
        }
      }

      // Trigger UI refresh if FS state changed
      ref.read(fsRegistryVersionProvider.notifier).state++;
    }

    final EncryptedMessage outMessage;
    final bool isFsEncrypted;
    if (multiSessionRatchets != null) {
      // §9.6 multi-envelope path.
      final multi =
          await ref.read(encryptionServiceProvider).encryptMultiEnvelope(
                senderPrivateKeyBase64: privateKey,
                recipientPublicKeyBase64: recipient.publicKeyBase64,
                payload: payload,
                sessionRatchets: multiSessionRatchets,
                fsExtension: fsExtension,
                includeLegacyFallback: includeLegacyFallback,
              );
      final cacheNotifier = ref.read(fsRatchetStateCacheProvider.notifier);
      final persistence = ref.read(fsRatchetPersistenceServiceProvider);
      for (final entry in multi.newRatchetStates.entries) {
        cacheNotifier.update((cache) => {...cache, entry.key: entry.value});
        await persistence.saveRatchetState(entry.value);
      }
      outMessage = multi.message;
      isFsEncrypted = true;
    } else {
      final result = await ref.read(encryptionServiceProvider).encrypt(
            senderPrivateKeyBase64: privateKey,
            recipientPublicKeyBase64:
                selfCopy ? selfPublic : recipient.publicKeyBase64,
            payload: payload,
            fsExtension: fsExtension,
            ratchetState: ratchetState,
            includeLegacyFallback: includeLegacyFallback,
          );

      // Save updated ratchet state if FS was used
      if (result.newRatchetState != null && sessionId != null) {
        final newState = result.newRatchetState!;
        final sid = sessionId; // Promote to non-nullable
        ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
              ...cache,
              sid: newState,
            });

        // Persist to storage
        await ref
            .read(fsRatchetPersistenceServiceProvider)
            .saveRatchetState(newState);
      }

      outMessage = result.message;
      isFsEncrypted = result.newRatchetState != null;
    }

    // §14.4: Classify the outgoing message.
    final FsMessageClassification classification;
    if (selfCopy) {
      classification = isFsEncrypted
          ? FsMessageClassification.fsOnly
          : FsMessageClassification.legacy;
    } else {
      final fsController = ref.read(
        fsOpportunisticControllerProvider(recipient.identityId),
      );
      classification = _classifyOutgoing(
        isFsEncrypted: isFsEncrypted,
        hasLegacyFallback: includeLegacyFallback,
        hasFsExtension: fsExtension != null,
        sessionState: fsController.sessionManager.state,
        securityMode: fsController.securityMode,
      );
    }

    return (
      message: outMessage,
      isFsEncrypted: isFsEncrypted,
      classification: classification,
    );
  }

  void clearSessionDecryptionCache() {
    _displayKeys.clear();
  }

  void _trimDisplayKeys() {
    while (_displayKeys.length > _maxRetainedDisplayKeys) {
      _displayKeys.remove(_displayKeys.keys.first);
    }
  }

  Future<SecretKey?> _deriveDisplayKey(RemoteIdentity contact) async {
    final privateKey = await _activePrivateKey();
    if (privateKey == null) return null;
    return ref.read(encryptionServiceProvider).deriveSymmetricKey(
          localPrivateKeyBase64: privateKey,
          remotePublicKeyBase64: contact.publicKeyBase64,
        );
  }

  Future<SecretKey?> _displayKeyForContact(RemoteIdentity contact) async {
    final currentTag = ref.read(effectiveKeyTagProvider);
    final keyTag = currentTag ?? await currentKeyTag();
    if (keyTag == null) return null;

    final cacheKey = '$keyTag|${contact.publicKeyBase64}';
    final cached = _displayKeys.remove(cacheKey);
    if (cached != null) {
      _displayKeys[cacheKey] = cached;
      return cached;
    }

    final future = _deriveDisplayKey(contact);
    _displayKeys[cacheKey] = future;
    _trimDisplayKeys();

    try {
      return await future;
    } catch (_) {
      _displayKeys.remove(cacheKey);
      rethrow;
    }
  }

  Future<void> primeDisplayKey({
    required RemoteIdentity contact,
  }) async {
    await _displayKeyForContact(contact);
  }

  Future<void> warmSessionDisplayKeys({
    String? hintContactId,
  }) async {
    if (!ref.read(sessionDecryptionCacheEnabledProvider) ||
        ref.read(appNeedsUnlockProvider)) {
      return;
    }

    final contacts = await _contactsByPriority(hintContactId);
    for (final contact in contacts.take(_sessionWarmContactLimit)) {
      await _displayKeyForContact(contact);
    }
  }

  Future<String?> decryptForDisplay({
    required MessageRecord message,
    required RemoteIdentity contact,
  }) async {
    if (message.text != null) return message.text;
    if (message.ciphertextBase64 == null || message.nonceBase64 == null) {
      return null;
    }

    // §12.3: Check in-memory cache first, then aux record persistence.
    final fsController =
        ref.read(fsOpportunisticControllerProvider(contact.identityId));
    fsController.securityMode =
        ref.read(fsSecurityModeServiceProvider).getModeSync(
              contactId: contact.identityId,
              identityContext: fsController.identityContext,
            );
    final cacheKey = '${contact.identityId}|${message.id}';
    final cached = fsController.getCachedPlaintext(cacheKey);
    if (cached != null) return cached;

    // FS messages have text=null in DB; plaintext lives in encrypted aux records.
    if (message.isFsEncrypted) {
      final ptService = ref.read(fsPlaintextPersistenceServiceProvider);
      final persisted = await ptService.loadPlaintext(message.id);
      if (persisted != null) {
        // Warm the in-memory cache for subsequent reads
        fsController.cachePlaintext(cacheKey, persisted);
        return persisted;
      }
      // Aux record missing (identity reset wiped it) → unrecoverable
      return null;
    }

    final privateKey = await _activePrivateKey();
    if (privateKey == null) return null;

    // §7.3: Get ratchet state for decryption — supports per-device sessions.
    // Pass all known ratchets so the decrypt method can match by fs_session.
    final allRatchets = ref.read(fsRatchetStateCacheProvider);
    RatchetState? ratchetState;
    final sessionManager = fsController.sessionManager;
    final activeSessionId = sessionManager.activeSessionId;
    if (activeSessionId != null) {
      ratchetState = allRatchets[activeSessionId];
    }

    final encMessage = EncryptedMessage(
      version: 1,
      senderId: message.senderId,
      recipientId: message.recipientId,
      nonceBase64: message.nonceBase64 ?? '',
      ciphertextBase64: message.ciphertextBase64 ?? '',
    );

    final result = await ref.read(encryptionServiceProvider).decrypt(
          recipientPrivateKeyBase64: privateKey,
          senderPublicKeyBase64: contact.publicKeyBase64,
          message: encMessage,
          ratchetState: ratchetState,
          allRatchetStates: allRatchets,
          isFsReplay: fsController.isMessageReplay,
        );

    if (result.fsReplayDetected) return null;

    // FS-encrypted but ratchet state is missing (identity reset / broken session)
    if (result.fsDecryptFailed) {
      return null;
    }

    final isFs = result.isFsEnvelope;

    // Update ratchet state if it changed (e.g., received new message advanced counter)
    if (result.newRatchetState != null) {
      final newState = result.newRatchetState!;
      ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
            ...cache,
            newState.sessionId: newState,
          });
      // Persist updated state
      await ref
          .read(fsRatchetPersistenceServiceProvider)
          .saveRatchetState(newState);

      // Cache FS-decrypted plaintext (§12.3) — ratchet has already advanced
      fsController.cachePlaintext(cacheKey, result.payload.text);

      // Persist to encrypted aux record for restart survival
      await ref.read(fsPlaintextPersistenceServiceProvider).savePlaintext(
            messageId: message.id,
            plaintext: result.payload.text,
            contactId: contact.identityId,
          );

      // Record message counter in replay cache (§8.7)
      fsController.recordMessageProcessed(
        sessionId: newState.sessionId,
        counter: newState.recvCounter - 1,
      );
    }

    // Downgrade detection: record the security level (§7.6)
    final chatDecryptLevel =
        (isFs ? FsMessageClassification.fsOnly : FsMessageClassification.legacy)
            .downgradeLevel;
    if (chatDecryptLevel != null) {
      fsController.recordSecurityLevel(
        contactId: contact.identityId,
        level: chatDecryptLevel,
      );
    }

    return result.payload.text;
  }

  Future<DecryptedMessagePreview?> getLastDecryptableMessagePreview({
    required List<MessageRecord> messages,
    required RemoteIdentity contact,
  }) async {
    final privateKey = await _activePrivateKey();
    if (privateKey == null) return null;

    // §7.3: Get ratchet state for decryption — supports per-device sessions.
    final allRatchets = ref.read(fsRatchetStateCacheProvider);
    final fsController =
        ref.read(fsOpportunisticControllerProvider(contact.identityId));
    final sessionManager = fsController.sessionManager;
    final activeSessionId = sessionManager.activeSessionId;
    RatchetState? ratchetState;
    if (activeSessionId != null) {
      ratchetState = allRatchets[activeSessionId];
    }

    // Sort messages descending by timestamp to find the latest
    final sortedMessages = List<MessageRecord>.from(messages)
      ..sort((a, b) {
        final byTs = b.timestamp.compareTo(a.timestamp);
        if (byTs != 0) return byTs;
        return b.id.compareTo(a.id);
      });

    for (final message in sortedMessages) {
      if (message.text != null) {
        return DecryptedMessagePreview(
          text: message.text!,
          timestamp: message.timestamp,
        );
      }

      // FS message: try aux record cache
      if (message.isFsEncrypted) {
        final ptService = ref.read(fsPlaintextPersistenceServiceProvider);
        final persisted = await ptService.loadPlaintext(message.id);
        if (persisted != null) {
          return DecryptedMessagePreview(
            text: persisted,
            timestamp: message.timestamp,
          );
        }
        continue;
      }

      if (message.ciphertextBase64 == null || message.nonceBase64 == null) {
        continue;
      }

      try {
        final result = await ref.read(encryptionServiceProvider).decrypt(
              recipientPrivateKeyBase64: privateKey,
              senderPublicKeyBase64: contact.publicKeyBase64,
              message: EncryptedMessage(
                version: 1,
                senderId: message.senderId,
                recipientId: message.recipientId,
                nonceBase64: message.nonceBase64 ?? '',
                ciphertextBase64: message.ciphertextBase64 ?? '',
              ),
              ratchetState: ratchetState,
              allRatchetStates: allRatchets,
              isFsReplay: fsController.isMessageReplay,
            );

        if (result.fsReplayDetected) continue;

        // FS message whose ratchet is gone — skip to next message
        if (result.fsDecryptFailed) continue;

        // Update ratchet state if it changed
        if (result.newRatchetState != null) {
          final newState = result.newRatchetState!;
          ratchetState = newState; // Update local var for next iteration
          ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
                ...cache,
                newState.sessionId: newState,
              });
          // Persist updated state (don't await in loop)
          unawaited(ref
              .read(fsRatchetPersistenceServiceProvider)
              .saveRatchetState(newState));
        }

        return DecryptedMessagePreview(
          text: result.payload.text,
          timestamp: message.timestamp,
        );
      } catch (_) {
        continue;
      }
    }

    return null;
  }

  /// Decode a hidden message from [source].
  ///
  /// If [hintContactId] is provided (e.g. the currently open chat), that
  /// contact's key is tried first for maximum speed.
  Future<DecodeOutcome> decodeHiddenMessage(
    String source, {
    String? hintContactId,
  }) async {
    final normalizedSource = source.trim();
    final identityManager = ref.read(identityManagerProvider);
    final local = await identityManager.getLocalIdentity();
    final privateKey = await _activePrivateKey();
    if (local == null || privateKey == null) {
      return const DecodeOutcome.error('Identity not initialized');
    }

    // ── 1. Try v2 binary format (fully encrypted, no LAYERGRAM| prefix) ────
    final v2 = await _tryDecodeV2(
      normalizedSource,
      local: local,
      privateKey: privateKey,
      hintContactId: hintContactId,
    );
    return v2 ?? const DecodeOutcome.noData();
  }

  // ── V2 binary decode ────────────────────────────────────────────────────

  Future<DecodeOutcome?> _tryDecodeV2(
    String source, {
    required LocalIdentity local,
    required String privateKey,
    String? hintContactId,
  }) async {
    // Extract raw byte candidates from stego or link.
    List<Uint8List> candidates;

    final linkCandidates = _decodeLinkRawCandidates(source);
    if (linkCandidates.isNotEmpty) {
      candidates = linkCandidates;
    } else if (source.toLowerCase().contains('layergram://m/')) {
      return null;
    } else {
      candidates = ref.read(stegoDecoderProvider).decodeByteCandidates(source);
      if (candidates.isEmpty) return null;
    }

    final encService = ref.read(encryptionServiceProvider);
    final orderedContacts = await _contactsByPriority(hintContactId);

    // Also try "self" key (message encrypted to self).
    final selfRemote = RemoteIdentity(
      identityId: local.identityId,
      publicKeyBase64: local.publicKeyBase64,
      fingerprint: '',
      displayName: local.displayName,
    );

    for (final rawBytes in candidates) {
      EncryptedMessage msg;
      try {
        msg = EncryptedMessage.fromRawBytes(rawBytes);
      } catch (_) {
        continue;
      }

      // Try each contact key.
      for (final contact in [selfRemote, ...orderedContacts]) {
        // §7.3: Get ratchet state for decryption — supports per-device sessions.
        final allRatchets = ref.read(fsRatchetStateCacheProvider);
        RatchetState? ratchetState;
        final fsController =
            ref.read(fsOpportunisticControllerProvider(contact.identityId));
        fsController.securityMode =
            ref.read(fsSecurityModeServiceProvider).getModeSync(
                  contactId: contact.identityId,
                  identityContext: fsController.identityContext,
                );
        final sessionManager = fsController.sessionManager;
        final activeSessionId = sessionManager.activeSessionId;
        if (activeSessionId != null) {
          ratchetState = allRatchets[activeSessionId];
        }

        // Try full decrypt (handles both legacy and FS-encrypted messages)
        DecryptionResult? result;
        try {
          result = await encService.decrypt(
            recipientPrivateKeyBase64: privateKey,
            senderPublicKeyBase64: contact.publicKeyBase64,
            message: msg,
            ratchetState: ratchetState,
            allRatchetStates: allRatchets,
            isFsReplay: fsController.isMessageReplay,
          );
        } catch (_) {
          // Wrong key - try next contact
          continue;
        }

        if (result.fsReplayDetected) {
          continue;
        }

        if (result.payload.recipientId != local.identityId ||
            result.payload.senderId != contact.identityId) {
          continue;
        }

        // Update ratchet state if it changed (e.g., received new message advanced counter)
        final fsCtrl = ref.read(
          fsOpportunisticControllerProvider(contact.identityId),
        );
        fsCtrl.securityMode =
            ref.read(fsSecurityModeServiceProvider).getModeSync(
                  contactId: contact.identityId,
                  identityContext: fsCtrl.identityContext,
                );
        final isFs = result.isFsEnvelope;
        if (result.newRatchetState != null) {
          final newState = result.newRatchetState!;
          ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
                ...cache,
                newState.sessionId: newState,
              });
          // Persist updated state
          unawaited(ref
              .read(fsRatchetPersistenceServiceProvider)
              .saveRatchetState(newState));

          // Record message counter in replay cache (§8.7)
          fsCtrl.recordMessageProcessed(
            sessionId: newState.sessionId,
            counter: newState.recvCounter - 1,
          );
        }

        // Downgrade detection: record the incoming message security level (§7.6)
        final incomingDowngradeLevel = (isFs
                ? FsMessageClassification.fsOnly
                : FsMessageClassification.legacy)
            .downgradeLevel;
        if (incomingDowngradeLevel != null) {
          fsCtrl.recordSecurityLevel(
            contactId: contact.identityId,
            level: incomingDowngradeLevel,
          );
        }

        // Process FS extension for opportunistic Forward Secrecy handshake
        // We need to decrypt envelope separately to access FS extension
        final key = await encService.deriveSymmetricKey(
          localPrivateKeyBase64: privateKey,
          remotePublicKeyBase64: contact.publicKeyBase64,
        );
        final envelope = await encService.tryDecryptEnvelopeWithKey(
          message: msg,
          key: key,
        );
        if (envelope != null) {
          final fsResult = await fsCtrl.processIncomingEnvelope(
            envelope,
            remoteContactId: contact.identityId,
            remoteIdentityPublicKey: contact.publicKeyBase64,
          );
          // Trigger UI refresh if FS state changed
          if (fsResult.type != FsIncomingType.noExtension) {
            ref.read(fsRegistryVersionProvider.notifier).state++;
          }
        }

        // FS-encrypted but ratchet state is missing (identity reset)
        if (result.fsDecryptFailed) {
          return const DecodeOutcome.fsLost();
        }

        // §14.4: Classify the incoming message.
        final hasFsExt = envelope != null &&
            LmfV2Decoder.extractFsExtension(envelope) != null;
        final incomingClassification = _classifyIncoming(
          isFsEncrypted: isFs,
          fsDecryptFailed: false,
          hasLegacyFallback: result.hasLegacyFallback,
          hasFsExtension: hasFsExt,
          sessionState: fsCtrl.sessionManager.state,
          securityMode: fsCtrl.securityMode,
        );

        // Decryption succeeded!
        return _persistAndReturn(
          payload: result.payload,
          encryptedMessage: msg,
          rawSource: source,
          senderContact: contact,
          isFsEncrypted: isFs,
          classification: incomingClassification,
        );
      }
    }

    return const DecodeOutcome
        .notForMe(); // candidates existed, but none decrypted
  }

  // ── Persist decoded message and return success ──────────────────────────

  Future<DecodeOutcome> _persistAndReturn({
    required PlaintextPayload payload,
    required EncryptedMessage encryptedMessage,
    required String rawSource,
    required RemoteIdentity senderContact,
    bool isFsEncrypted = false,
    FsMessageClassification? classification,
  }) async {
    final nowTs = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    if (payload.expireAfter != null && payload.expireAfter! < nowTs) {
      return const DecodeOutcome.expired();
    }

    final recordTs = payload.timestamp > nowTs ? payload.timestamp : nowTs;
    final recordId = DateTime.now().microsecondsSinceEpoch.toString();
    final keyTag = await currentKeyTag();
    final storageKey = await currentStorageKey();

    // §12.3: FS plaintext must NOT be stored in MessageRecord.text.
    // Instead, persist it as an opaque encrypted auxiliary record.
    if (isFsEncrypted && payload.text.isNotEmpty) {
      final ptService = ref.read(fsPlaintextPersistenceServiceProvider);
      await ptService.savePlaintext(
        messageId: recordId,
        plaintext: payload.text,
        contactId: senderContact.identityId,
      );
      // Also cache in memory for immediate display
      final fsController = ref.read(
        fsOpportunisticControllerProvider(senderContact.identityId),
      );
      fsController.cachePlaintext(
        '${senderContact.identityId}|$recordId',
        payload.text,
      );
    }

    await ref.read(messagesRepositoryProvider).add(
          MessageRecord(
            id: recordId,
            senderId: payload.senderId,
            recipientId: payload.recipientId,
            direction: 'incoming',
            timestamp: recordTs,
            text: isFsEncrypted ? null : payload.text,
            ciphertextBase64: encryptedMessage.ciphertextBase64,
            nonceBase64: encryptedMessage.nonceBase64,
            rawSource: rawSource,
            expireAfter: payload.expireAfter,
            deleteAfterRead: payload.deleteAfterRead,
            keyTag: keyTag,
            isFsEncrypted: isFsEncrypted,
            fsClassification: classification,
          ),
          storageKey: storageKey,
        );

    if (payload.deleteAfterRead) {
      await ref.read(messagesRepositoryProvider).markRead(recordId);
    }

    return DecodeOutcome.success(payload);
  }

  // ── Message classification (§14.4) ─────────────────────────────────────────

  static FsMessageClassification _classifyOutgoing({
    required bool isFsEncrypted,
    required bool hasLegacyFallback,
    required bool hasFsExtension,
    required FsSessionState sessionState,
    required FsSecurityMode securityMode,
  }) {
    if (isFsEncrypted) {
      if (hasLegacyFallback) {
        return FsMessageClassification.fsWithFallback;
      }

      if (securityMode == FsSecurityMode.strict &&
          sessionState == FsSessionState.strictFsActive) {
        return FsMessageClassification.strictFs;
      }
      // §9.5: an FS-encrypted message is only ever encrypted with the ratchet
      // (never dual-encrypted with the legacy identity key), so it is true
      // FS-only. fs_with_fallback is reserved for the multi-envelope case (§9.6)
      // which Layergram does not implement.
      return FsMessageClassification.fsOnly;
    }
    if (hasFsExtension) {
      return FsMessageClassification.fsNegotiation;
    }
    if (sessionState == FsSessionState.legacyOnly) {
      return FsMessageClassification.preFs;
    }
    return FsMessageClassification.legacy;
  }

  static FsMessageClassification _classifyIncoming({
    required bool isFsEncrypted,
    required bool fsDecryptFailed,
    required bool hasLegacyFallback,
    required bool hasFsExtension,
    required FsSessionState sessionState,
    required FsSecurityMode securityMode,
  }) {
    if (fsDecryptFailed) {
      return FsMessageClassification.fsFailed;
    }
    if (isFsEncrypted) {
      if (hasLegacyFallback) {
        return FsMessageClassification.fsWithFallback;
      }

      if (securityMode == FsSecurityMode.strict &&
          sessionState == FsSessionState.strictFsActive) {
        return FsMessageClassification.strictFs;
      }
      // §9.5: FS-encrypted messages are FS-only on the wire (not dual-encrypted
      // with the legacy key). See _classifyOutgoing.
      return FsMessageClassification.fsOnly;
    }
    if (hasFsExtension) {
      return FsMessageClassification.fsNegotiation;
    }
    if (sessionState == FsSessionState.legacyOnly) {
      return FsMessageClassification.preFs;
    }
    return FsMessageClassification.legacy;
  }

  // ── Contact priority ordering ───────────────────────────────────────────────

  /// Returns contacts sorted by priority for trial decryption:
  /// 1. [hintContactId] contact (if provided)
  /// 2. Contacts with the most messages in the DB (descending)
  /// 3. All remaining contacts
  Future<List<RemoteIdentity>> _contactsByPriority(
      String? hintContactId) async {
    final allContacts =
        await ref.read(identitiesRepositoryProvider).watchRemote().first;
    if (allContacts.isEmpty) return const [];

    // Count messages per contact for priority sorting.
    final allMessages =
        await ref.read(messagesRepositoryProvider).getAllMessages();
    final countByContactId = <String, int>{};
    for (final m in allMessages) {
      countByContactId[m.senderId] = (countByContactId[m.senderId] ?? 0) + 1;
      countByContactId[m.recipientId] =
          (countByContactId[m.recipientId] ?? 0) + 1;
    }

    final sorted = List<RemoteIdentity>.from(allContacts)
      ..sort((a, b) {
        final ca = countByContactId[a.identityId] ?? 0;
        final cb = countByContactId[b.identityId] ?? 0;
        return cb.compareTo(ca); // most messages first
      });

    // Promote hint contact to front.
    if (hintContactId != null) {
      final idx = sorted.indexWhere((c) => c.identityId == hintContactId);
      if (idx > 0) {
        final hint = sorted.removeAt(idx);
        sorted.insert(0, hint);
      }
    }

    return sorted;
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  String _padBase64(String input) {
    final rem = input.length % 4;
    if (rem == 0) return input;
    return input.padRight(input.length + (4 - rem), '=');
  }

  List<Uint8List> _decodeLinkRawCandidates(String source) {
    final prefix = RegExp('layergram://m/', caseSensitive: false);
    final match = prefix.firstMatch(source);
    if (match == null) return const [];

    final tail = source.substring(match.end);
    final tokenMatches = RegExp(r'[A-Za-z0-9_-]+={0,2}').allMatches(tail);
    final candidates = <Uint8List>[];
    final seen = <String>{};
    final buffer = StringBuffer();
    var expectedStart = 0;

    for (final token in tokenMatches) {
      final separator = tail.substring(expectedStart, token.start);
      if (separator.isNotEmpty && !RegExp(r'^\s+$').hasMatch(separator)) {
        break;
      }

      buffer.write(token.group(0)!);
      expectedStart = token.end;
      final encoded = buffer.toString();
      if (!seen.add(encoded)) continue;

      try {
        final raw = Uint8List.fromList(base64Url.decode(_padBase64(encoded)));
        if (raw.length >= 28) {
          candidates.add(raw);
        }
      } catch (_) {
        // Keep collecting; a wrapped link may only decode after later tokens.
      }
    }

    return candidates;
  }

  RemoteIdentity parseIdentityBlock(String text) {
    final scoped = _withinIdentityBlock(text);
    final name = _extract(scoped, 'Name:') ?? 'Unknown';
    final identityId = _extract(scoped, 'Identity ID:') ?? '';
    final fp = _extract(scoped, 'Fingerprint:') ?? '';
    final key = _extractAfter(scoped, 'Public Key (Base64):') ?? '';
    return RemoteIdentity(
      identityId: identityId,
      publicKeyBase64: key.trim(),
      fingerprint: fp,
      displayName: name,
    );
  }

  String _withinIdentityBlock(String text) {
    const start = '[Layergram Identity]';
    const end = '[/Layergram Identity]';
    final s = text.indexOf(start);
    final e = text.indexOf(end);
    if (s < 0 || e < 0 || e <= s) return text;
    return text.substring(s + start.length, e).trim();
  }

  String? _extract(String text, String prefix) {
    final lines = const LineSplitter().convert(text);
    for (final line in lines) {
      if (line.trimLeft().startsWith(prefix)) {
        return line.split(':').skip(1).join(':').trim();
      }
    }
    return null;
  }

  String? _extractAfter(String text, String marker) {
    final idx = text.indexOf(marker);
    if (idx < 0) return null;
    final remaining = text.substring(idx + marker.length).trim();
    final lines = const LineSplitter().convert(remaining);
    if (lines.isEmpty) return null;
    return lines
        .firstWhere((line) => line.trim().isNotEmpty, orElse: () => '')
        .trim();
  }

  // ── Forward Secrecy handshake payload preparation ───────────────────────

  /// Prepares the appropriate handshake payload for the current FS state.
  ///
  /// This generates FS_INIT, FS_REPLY, or FS_CONFIRM payloads based on the
  /// session state. Only FS_INIT generation is fully implemented here;
  /// FS_REPLY and FS_CONFIRM require state from previous handshake messages
  /// that should be stored in the session manager.
  Future<FsOutgoingExtension?> _buildFsOutgoingExtension({
    required FsOpportunisticController fsController,
    required FsSessionManager sessionManager,
    required FsSessionState state,
    required RemoteIdentity recipient,
    required String privateKey,
  }) async {
    switch (state) {
      case FsSessionState.legacyOnly:
        // Generate FS_INIT payload to start handshake
        final identityManager = ref.read(identityManagerProvider);
        final local = await identityManager.getLocalIdentity();
        if (local == null) return null;

        // Derive device key from identity key (simplified: use identity key as device key)
        final ikPrivBytes = base64Decode(privateKey);
        final dkPrivBytes =
            ikPrivBytes; // In production, derive separate device key

        final initPayload = await FsHandshake.generateFsInit(
          ikAPriv: ikPrivBytes,
          dkAPriv: dkPrivBytes,
        );

        // Store the ephemeral key for later use in FS_CONFIRM
        sessionManager.setPendingInitEphemeralPriv(initPayload.ekAPrivBytes);

        return await fsController.buildOutgoingExtension(
            pendingInit: initPayload);

      case FsSessionState.fsInitSeen:
        // Generate FS_REPLY in response to received FS_INIT
        final initMessage = sessionManager.storedInitMessage;
        if (initMessage == null) {
          return await fsController.buildOutgoingExtension();
        }

        // Decode remote identity public key
        final remoteIkPub = base64Decode(recipient.publicKeyBase64);

        // Use local identity keys (simplified: derive device key from identity key)
        final ikPrivBytes = base64Decode(privateKey);
        final dkPrivBytes =
            ikPrivBytes; // In production, derive separate device key

        try {
          final replyPayload = await FsHandshake.processFsInitAsResponder(
            ikBPriv: ikPrivBytes,
            dkBPriv: dkPrivBytes,
            ikAPub: remoteIkPub,
            init: initMessage,
          );

          // Store the ratchet private key and raw root secret for later use
          sessionManager.setPendingReplyEphemeralPriv(
            replyPayload.responderInitialRatchetPriv,
          );
          // Store raw root secret and transcript hash for FS_CONFIRM verification
          if (replyPayload.partialState.rawRootSecret != null) {
            sessionManager.setPendingRawRootSecret(
              replyPayload.partialState.rawRootSecret!,
            );
          }
          sessionManager.setPendingTranscriptHash(
            replyPayload.partialState.transcriptHash,
          );

          return await fsController.buildOutgoingExtension(
              pendingReply: replyPayload);
        } catch (e) {
          // Failed to generate reply, skip FS extension this message
          return await fsController.buildOutgoingExtension();
        }

      case FsSessionState.fsReplySeen:
        // Generate FS_CONFIRM in response to received FS_REPLY
        final replyMessage = sessionManager.storedReplyMessage;
        final ekAPriv = sessionManager.pendingInitEphemeralPriv;
        if (replyMessage == null || ekAPriv == null) {
          return await fsController.buildOutgoingExtension();
        }

        // Decode remote identity public key
        final remoteIkPub = base64Decode(recipient.publicKeyBase64);

        // Use local identity and device keys
        final ikPrivBytes = base64Decode(privateKey);
        final dkPrivBytes =
            ikPrivBytes; // In production, derive separate device key

        // Retrieve the init message we originally sent
        final sentInit = sessionManager.storedSentInitMessage;
        if (sentInit == null) {
          return await fsController.buildOutgoingExtension();
        }

        try {
          // Generate FS_CONFIRM using stored ephemeral key and received reply
          final confirmPayload = await FsHandshake.processFsReplyAsInitiator(
            ikAPriv: ikPrivBytes,
            dkAPriv: dkPrivBytes,
            ekAPrivBytes: ekAPriv,
            ikBPub: remoteIkPub,
            sentInit: sentInit,
            reply: replyMessage,
          );

          return await fsController.buildOutgoingExtension(
              pendingConfirm: confirmPayload);
        } catch (e) {
          // Failed to generate confirm, skip FS extension this message
          return await fsController.buildOutgoingExtension();
        }

      case FsSessionState.fsActive:
      case FsSessionState.strictFsActive:
      case FsSessionState.strictRequested:
      case FsSessionState.fsInitSent:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
      case FsSessionState.fsSuspended:
      case FsSessionState.fsBroken:
        // No handshake message needed in these states
        return await fsController.buildOutgoingExtension();
    }
  }
}

class DecodeOutcome {
  const DecodeOutcome._(
      {this.payload, this.kind = DecodeKind.error, this.errorCode});

  const DecodeOutcome.success(PlaintextPayload payload)
      : this._(payload: payload, kind: DecodeKind.success);

  const DecodeOutcome.noData() : this._(kind: DecodeKind.noData);
  const DecodeOutcome.notForMe() : this._(kind: DecodeKind.notForMe);
  const DecodeOutcome.unknownSender() : this._(kind: DecodeKind.unknownSender);
  const DecodeOutcome.expired() : this._(kind: DecodeKind.expired);
  const DecodeOutcome.fsLost() : this._(kind: DecodeKind.fsLost);
  const DecodeOutcome.error(String code)
      : this._(kind: DecodeKind.error, errorCode: code);

  final PlaintextPayload? payload;
  final DecodeKind kind;
  final String? errorCode;
}

enum DecodeKind {
  success,
  noData,
  notForMe,
  unknownSender,
  expired,
  fsLost,
  error
}

final homeControllerProvider = Provider<HomeController>((ref) {
  final controller = HomeController(ref);
  ref.onDispose(controller.clearSessionDecryptionCache);
  ref.listen<String?>(effectiveKeyTagProvider, (_, __) {
    controller.clearSessionDecryptionCache();
  });
  ref.listen<String?>(activeIdentityIdProvider, (_, __) {
    controller.clearSessionDecryptionCache();
  });
  ref.listen<int>(identityReloadTokenProvider, (_, __) {
    controller.clearSessionDecryptionCache();
  });
  ref.listen<bool>(appNeedsUnlockProvider, (_, next) {
    if (next) {
      controller.clearSessionDecryptionCache();
    }
  });
  ref.listen<bool>(sessionDecryptionCacheEnabledProvider, (_, next) {
    if (!next) {
      controller.clearSessionDecryptionCache();
    }
  });
  return controller;
});
final encodeRecipientProvider = StateProvider<RemoteIdentity?>((_) => null);

/// Stores composer handoff state during narrow↔wide layout transitions.
/// Survives HomeView State disposal/recreation.
final pendingComposerStateProvider =
    StateProvider<Map<String, dynamic>?>((_) => null);
