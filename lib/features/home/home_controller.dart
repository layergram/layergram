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
import '../../core/crypto/fs_opportunistic_controller.dart';
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
    final encrypted = await encryptForRecipient(
      secretText: secretText,
      recipient: recipient,
      expireAfter: expireAfter,
      deleteAfterRead: deleteAfterRead,
    );

    return ref
        .read(stegoEncoderProvider)
        .encodeBytes(coverText, encrypted.toRawBytes());
  }

  Future<EncryptedMessage> encryptForRecipient({
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
        final reason = strictController.sendBlockReason(deviceChanged: false)
            ?? 'Maximum Forward Secrecy prevents sending in current state';
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

    if (!selfCopy) {
      final fsController = ref.read(
        fsOpportunisticControllerProvider(recipient.identityId),
      );
      final sessionManager = ref.read(
        fsSessionManagerProvider(recipient.identityId),
      );

      // Prepare handshake payload based on current state
      final state = sessionManager.state;
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
      if (state == FsSessionState.fsActive ||
          state == FsSessionState.strictFsActive) {
        sessionId = sessionManager.activeSessionId;
        if (sessionId != null) {
          ratchetState = ref.read(fsRatchetStateCacheProvider)[sessionId];
        }
      }

      // Trigger UI refresh if FS state changed
      ref.read(fsRegistryVersionProvider.notifier).state++;
    }

    final result = await ref.read(encryptionServiceProvider).encrypt(
      senderPrivateKeyBase64: privateKey,
      recipientPublicKeyBase64:
          selfCopy ? selfPublic : recipient.publicKeyBase64,
      payload: payload,
      fsExtension: fsExtension,
      ratchetState: ratchetState,
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
      await ref.read(fsRatchetPersistenceServiceProvider).saveRatchetState(newState);
    }

    return result.message;
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
    if (message.ciphertextBase64 == null || message.nonceBase64 == null) {
      return null;
    }

    final privateKey = await _activePrivateKey();
    if (privateKey == null) return null;

    // Get ratchet state if FS session is active for this contact
    RatchetState? ratchetState;
    final sessionManager = ref.read(fsSessionManagerProvider(contact.identityId));
    final activeSessionId = sessionManager.activeSessionId;
    if (activeSessionId != null) {
      ratchetState = ref.read(fsRatchetStateCacheProvider)[activeSessionId];
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
    );

    // Update ratchet state if it changed (e.g., received new message advanced counter)
    if (result.newRatchetState != null && activeSessionId != null) {
      final newState = result.newRatchetState!;
      ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
            ...cache,
            activeSessionId: newState,
          });
      // Persist updated state
      await ref.read(fsRatchetPersistenceServiceProvider).saveRatchetState(newState);
    }

    return result.payload.text;
  }

  Future<DecryptedMessagePreview?> getLastDecryptableMessagePreview({
    required List<MessageRecord> messages,
    required RemoteIdentity contact,
  }) async {
    final privateKey = await _activePrivateKey();
    if (privateKey == null) return null;

    // Get ratchet state if FS session is active for this contact
    final sessionManager = ref.read(fsSessionManagerProvider(contact.identityId));
    final activeSessionId = sessionManager.activeSessionId;
    RatchetState? ratchetState;
    if (activeSessionId != null) {
      ratchetState = ref.read(fsRatchetStateCacheProvider)[activeSessionId];
    }

    // Sort messages descending by timestamp to find the latest
    final sortedMessages = List<MessageRecord>.from(messages)
      ..sort((a, b) => b.timestamp.compareTo(a.timestamp));

    for (final message in sortedMessages) {
      if (message.ciphertextBase64 == null || message.nonceBase64 == null) {
        continue;
      }

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
      );

      // Update ratchet state if it changed
      if (result.newRatchetState != null && activeSessionId != null) {
        final newState = result.newRatchetState!;
        ratchetState = newState; // Update local var for next iteration
        ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
              ...cache,
              activeSessionId: newState,
            });
        // Persist updated state (don't await in loop)
        unawaited(ref.read(fsRatchetPersistenceServiceProvider).saveRatchetState(newState));
      }

      return DecryptedMessagePreview(
        text: result.payload.text,
        timestamp: message.timestamp,
      );
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

    if (source.startsWith('layergram://m/')) {
      final encoded = source.substring('layergram://m/'.length);
      final cleaned = encoded.replaceAll(RegExp(r'\s+'), '');
      try {
        final raw = Uint8List.fromList(base64Url.decode(_padBase64(cleaned)));
        if (raw.length >= 28) {
          candidates = [raw];
        } else {
          return null;
        }
      } catch (_) {
        return null;
      }
    } else {
      candidates = ref
          .read(stegoDecoderProvider)
          .decodeByteCandidates(source);
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
        // Get ratchet state if FS session is active for this contact
        RatchetState? ratchetState;
        final sessionManager = ref.read(fsSessionManagerProvider(contact.identityId));
        final activeSessionId = sessionManager.activeSessionId;
        if (activeSessionId != null) {
          ratchetState = ref.read(fsRatchetStateCacheProvider)[activeSessionId];
        }

        // Try full decrypt (handles both legacy and FS-encrypted messages)
        DecryptionResult? result;
        try {
          result = await encService.decrypt(
            recipientPrivateKeyBase64: privateKey,
            senderPublicKeyBase64: contact.publicKeyBase64,
            message: msg,
            ratchetState: ratchetState,
          );
        } catch (_) {
          // Wrong key - try next contact
          continue;
        }

        // Update ratchet state if it changed (e.g., received new message advanced counter)
        if (result.newRatchetState != null && activeSessionId != null) {
          final newState = result.newRatchetState!;
          ref.read(fsRatchetStateCacheProvider.notifier).update((cache) => {
                ...cache,
                activeSessionId: newState,
              });
          // Persist updated state
          unawaited(ref.read(fsRatchetPersistenceServiceProvider).saveRatchetState(newState));
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
          final fsController = ref.read(
            fsOpportunisticControllerProvider(contact.identityId),
          );
          final fsResult = await fsController.processIncomingEnvelope(
            envelope,
            remoteContactId: contact.identityId,
          );
          // Trigger UI refresh if FS state changed
          if (fsResult.type != FsIncomingType.noExtension) {
            ref.read(fsRegistryVersionProvider.notifier).state++;
          }
        }

        // Decryption succeeded!
        return _persistAndReturn(
          payload: result.payload,
          encryptedMessage: msg,
          rawSource: source,
          senderContact: contact,
        );
      }
    }

    return null; // no candidate decrypted successfully
  }

  // ── Persist decoded message and return success ──────────────────────────

  Future<DecodeOutcome> _persistAndReturn({
    required PlaintextPayload payload,
    required EncryptedMessage encryptedMessage,
    required String rawSource,
    required RemoteIdentity senderContact,
  }) async {
    final nowTs = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    if (payload.expireAfter != null && payload.expireAfter! < nowTs) {
      return const DecodeOutcome.expired();
    }

    final recordTs = payload.timestamp > nowTs ? payload.timestamp : nowTs;
    final recordId = DateTime.now().microsecondsSinceEpoch.toString();
    final keyTag = await currentKeyTag();
    final storageKey = await currentStorageKey();
    await ref.read(messagesRepositoryProvider).add(
          MessageRecord(
            id: recordId,
            senderId: payload.senderId,
            recipientId: payload.recipientId,
            direction: 'incoming',
            timestamp: recordTs,
            ciphertextBase64: encryptedMessage.ciphertextBase64,
            nonceBase64: encryptedMessage.nonceBase64,
            rawSource: rawSource,
            expireAfter: payload.expireAfter,
            deleteAfterRead: payload.deleteAfterRead,
            keyTag: keyTag,
          ),
          storageKey: storageKey,
        );

    if (payload.deleteAfterRead) {
      await ref.read(messagesRepositoryProvider).markRead(recordId);
    }

    return DecodeOutcome.success(payload);
  }

  // ── Contact priority ordering ───────────────────────────────────────────

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
        final dkPrivBytes = ikPrivBytes; // In production, derive separate device key

        final initPayload = await FsHandshake.generateFsInit(
          ikAPriv: ikPrivBytes,
          dkAPriv: dkPrivBytes,
        );

        // Store the ephemeral key for later use in FS_CONFIRM
        sessionManager.setPendingInitEphemeralPriv(initPayload.ekAPrivBytes);

        return fsController.buildOutgoingExtension(pendingInit: initPayload);

      case FsSessionState.fsInitSeen:
        // Generate FS_REPLY in response to received FS_INIT
        final initMessage = sessionManager.storedInitMessage;
        if (initMessage == null) {
          return fsController.buildOutgoingExtension();
        }

        // Decode remote identity public key
        final remoteIkPub = base64Decode(recipient.publicKeyBase64);

        // Use local identity keys (simplified: derive device key from identity key)
        final ikPrivBytes = base64Decode(privateKey);
        final dkPrivBytes = ikPrivBytes; // In production, derive separate device key

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

          return fsController.buildOutgoingExtension(pendingReply: replyPayload);
        } catch (e) {
          // Failed to generate reply, skip FS extension this message
          return fsController.buildOutgoingExtension();
        }

      case FsSessionState.fsReplySeen:
        // Generate FS_CONFIRM in response to received FS_REPLY
        final replyMessage = sessionManager.storedReplyMessage;
        final ekAPriv = sessionManager.pendingInitEphemeralPriv;
        if (replyMessage == null || ekAPriv == null) {
          return fsController.buildOutgoingExtension();
        }

        // Decode remote identity public key
        final remoteIkPub = base64Decode(recipient.publicKeyBase64);

        // Use local identity and device keys
        final ikPrivBytes = base64Decode(privateKey);
        final dkPrivBytes = ikPrivBytes; // In production, derive separate device key

        // Retrieve the init message we originally sent
        final sentInit = sessionManager.storedSentInitMessage;
        if (sentInit == null) {
          return fsController.buildOutgoingExtension();
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

          return fsController.buildOutgoingExtension(pendingConfirm: confirmPayload);
        } catch (e) {
          // Failed to generate confirm, skip FS extension this message
          return fsController.buildOutgoingExtension();
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
        return fsController.buildOutgoingExtension();
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
  const DecodeOutcome.error(String code)
      : this._(kind: DecodeKind.error, errorCode: code);

  final PlaintextPayload? payload;
  final DecodeKind kind;
  final String? errorCode;
}

enum DecodeKind { success, noData, notForMe, unknownSender, expired, error }

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
final pendingComposerStateProvider = StateProvider<Map<String, dynamic>?>((_) => null);
