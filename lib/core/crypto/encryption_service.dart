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

import 'package:cryptography/cryptography.dart';

import 'fs_double_ratchet.dart';
import 'models.dart';

/// Result of an encryption operation with optional FS double ratchet.
class EncryptionResult {
  const EncryptionResult({
    required this.message,
    this.newRatchetState,
  });

  final EncryptedMessage message;
  final RatchetState? newRatchetState;
}

/// Result of a §9.6 multi-envelope encryption operation.
///
/// The payload is encrypted once with a per-message content key; that key is
/// wrapped for each active device session. [newRatchetStates] maps each
/// wrapped session id to its advanced ratchet state — callers must persist
/// all of them.
class MultiEnvelopeEncryptionResult {
  const MultiEnvelopeEncryptionResult({
    required this.message,
    required this.newRatchetStates,
  });

  final EncryptedMessage message;
  final Map<String, RatchetState> newRatchetStates;
}

/// Result of a decryption operation with optional FS double ratchet.
class DecryptionResult {
  const DecryptionResult({
    required this.payload,
    this.newRatchetState,
    this.fsDecryptFailed = false,
  });

  final PlaintextPayload payload;
  final RatchetState? newRatchetState;

  /// `true` when the message was FS-encrypted but the ratchet state is
  /// missing (identity reset, broken session).  The outer legacy layer
  /// was decrypted but the inner FS content is unrecoverable.
  /// [payload.text] will be empty in this case.
  final bool fsDecryptFailed;
}

class EncryptionService {
  final _algo = AesGcm.with256bits();
  final _keyAgreement = X25519();
  final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  /// Encrypts a message using legacy encryption or FS double ratchet.
  ///
  /// If [ratchetState] is provided, uses the double ratchet for encryption
  /// and returns the updated state in [EncryptionResult.newRatchetState].
  /// Otherwise, falls back to legacy X25519+HKDF encryption.
  Future<EncryptionResult> encrypt({
    required String senderPrivateKeyBase64,
    required String recipientPublicKeyBase64,
    required PlaintextPayload payload,
    Map<String, dynamic>? fsExtension,
    RatchetState? ratchetState,
  }) async {
    // If we have an active ratchet state, use double ratchet encryption
    if (ratchetState != null) {
      final (:message, :newState) = await FsDoubleRatchet.encrypt(
        state: ratchetState,
        plaintext: utf8.encode(payload.text),
        sessionId: ratchetState.sessionId,
      );

      // Build v2 envelope with FS-encrypted payload
      final envelope = <String, dynamic>{
        'v': 2,
        'senderId': payload.senderId,
        'recipientId': payload.recipientId,
        'timestamp': payload.timestamp,
        'fs_v': 1, // FS protocol version
        'fs_session': message.sessionId,
        'fs_ratchet_pub': message.localRatchetPub,
        'fs_counter': message.counter,
        'fs_cipher': base64Encode(message.ciphertext),
        'fs_nonce': base64Encode(message.nonce),
        if (payload.senderDisplayName != null)
          'senderDisplayName': payload.senderDisplayName,
        if (payload.expireAfter != null) 'expireAfter': payload.expireAfter,
        'deleteAfterRead': payload.deleteAfterRead,
        if (fsExtension != null) 'x': <String, dynamic>{'fs': fsExtension},
      };
      final plainJson = jsonEncode(envelope);

      // Use legacy encryption for outer layer (backward compatibility)
      // The inner payload is FS-encrypted, outer is legacy-encrypted
      final key = await _deriveSymmetricKey(
        localPrivateKeyBase64: senderPrivateKeyBase64,
        remotePublicKeyBase64: recipientPublicKeyBase64,
      );
      final nonce = _algo.newNonce();

      final box = await _algo.encrypt(
        utf8.encode(plainJson),
        secretKey: key,
        nonce: nonce,
      );

      return EncryptionResult(
        message: EncryptedMessage(
          version: 2,
          senderId: payload.senderId,
          recipientId: payload.recipientId,
          nonceBase64: base64Encode(nonce),
          ciphertextBase64: base64Encode([...box.cipherText, ...box.mac.bytes]),
        ),
        newRatchetState: newState,
      );
    }

    // Legacy encryption (non-FS)
    final key = await _deriveSymmetricKey(
      localPrivateKeyBase64: senderPrivateKeyBase64,
      remotePublicKeyBase64: recipientPublicKeyBase64,
    );
    final nonce = _algo.newNonce();

    // Build v2 envelope with optional FS extension
    final envelope = <String, dynamic>{
      'v': 2,
      'senderId': payload.senderId,
      'recipientId': payload.recipientId,
      'timestamp': payload.timestamp,
      'text': payload.text,
      if (payload.senderDisplayName != null)
        'senderDisplayName': payload.senderDisplayName,
      if (payload.expireAfter != null) 'expireAfter': payload.expireAfter,
      'deleteAfterRead': payload.deleteAfterRead,
      if (fsExtension != null) 'x': <String, dynamic>{'fs': fsExtension},
    };
    final plainJson = jsonEncode(envelope);

    final box = await _algo.encrypt(
      utf8.encode(plainJson),
      secretKey: key,
      nonce: nonce,
    );

    return EncryptionResult(
      message: EncryptedMessage(
        version: 2,
        senderId: payload.senderId,
        recipientId: payload.recipientId,
        nonceBase64: base64Encode(nonce),
        ciphertextBase64: base64Encode([...box.cipherText, ...box.mac.bytes]),
      ),
    );
  }

  /// §9.6 — Encrypts [payload] once and wraps the content key for every active
  /// device session in [sessionRatchets].
  ///
  /// A fresh random content key encrypts the payload text a single time
  /// (`mc_cipher`). That content key is then wrapped (ratchet-encrypted) once
  /// per session, so each of the contact's devices can recover it with its own
  /// ratchet. When [includeLegacyFallback] is true, the content key is also
  /// included in the identity-encrypted outer envelope (`mc_fallback_key`) so a
  /// device without an FS session can still read it — this makes the message
  /// `fs_with_fallback`, never full FS. Strict callers must pass `false`.
  Future<MultiEnvelopeEncryptionResult> encryptMultiEnvelope({
    required String senderPrivateKeyBase64,
    required String recipientPublicKeyBase64,
    required PlaintextPayload payload,
    required Map<String, RatchetState> sessionRatchets,
    Map<String, dynamic>? fsExtension,
    bool includeLegacyFallback = false,
  }) async {
    if (sessionRatchets.isEmpty) {
      throw ArgumentError('sessionRatchets must not be empty');
    }

    // Per-message content key: encrypt the payload text exactly once.
    final contentKey = await _algo.newSecretKey();
    final contentKeyBytes =
        Uint8List.fromList(await contentKey.extractBytes());
    final mcNonce = _algo.newNonce();
    final mcBox = await _algo.encrypt(
      utf8.encode(payload.text),
      secretKey: contentKey,
      nonce: mcNonce,
    );

    // Wrap the content key for each device session via its ratchet.
    final wraps = <Map<String, dynamic>>[];
    final newStates = <String, RatchetState>{};
    for (final entry in sessionRatchets.entries) {
      final (:message, :newState) = await FsDoubleRatchet.encrypt(
        state: entry.value,
        plaintext: contentKeyBytes,
        sessionId: entry.value.sessionId,
      );
      newStates[entry.key] = newState;
      wraps.add(<String, dynamic>{
        'fs_session': message.sessionId,
        'fs_ratchet_pub': message.localRatchetPub,
        'fs_counter': message.counter,
        'fs_cipher': base64Encode(message.ciphertext),
        'fs_nonce': base64Encode(message.nonce),
      });
    }

    final envelope = <String, dynamic>{
      'v': 2,
      'senderId': payload.senderId,
      'recipientId': payload.recipientId,
      'timestamp': payload.timestamp,
      'fs_v': 1,
      'fs_multi': 1,
      'mc_cipher':
          base64Encode([...mcBox.cipherText, ...mcBox.mac.bytes]),
      'mc_nonce': base64Encode(mcNonce),
      'fs_wraps': wraps,
      if (includeLegacyFallback)
        'mc_fallback_key': base64Encode(contentKeyBytes),
      if (payload.senderDisplayName != null)
        'senderDisplayName': payload.senderDisplayName,
      if (payload.expireAfter != null) 'expireAfter': payload.expireAfter,
      'deleteAfterRead': payload.deleteAfterRead,
      if (fsExtension != null) 'x': <String, dynamic>{'fs': fsExtension},
    };
    final plainJson = jsonEncode(envelope);

    // Identity-key outer layer (transport wrapper), as for all envelopes.
    final key = await _deriveSymmetricKey(
      localPrivateKeyBase64: senderPrivateKeyBase64,
      remotePublicKeyBase64: recipientPublicKeyBase64,
    );
    final nonce = _algo.newNonce();
    final box = await _algo.encrypt(
      utf8.encode(plainJson),
      secretKey: key,
      nonce: nonce,
    );

    return MultiEnvelopeEncryptionResult(
      message: EncryptedMessage(
        version: 2,
        senderId: payload.senderId,
        recipientId: payload.recipientId,
        nonceBase64: base64Encode(nonce),
        ciphertextBase64: base64Encode([...box.cipherText, ...box.mac.bytes]),
      ),
      newRatchetStates: newStates,
    );
  }

  /// Decrypts a message using legacy decryption or FS double ratchet.
  ///
  /// Decrypts a message. For multi-device support (§7.3), pass
  /// [allRatchetStates] with all known ratchets for this contact — the
  /// method selects the correct one based on the `fs_session` field in the
  /// envelope. Falls back to [ratchetState] when no match is found.
  Future<DecryptionResult> decrypt({
    required String recipientPrivateKeyBase64,
    required String senderPublicKeyBase64,
    required EncryptedMessage message,
    RatchetState? ratchetState,
    Map<String, RatchetState>? allRatchetStates,
  }) async {
    // Decrypt outer layer once to get the full envelope map.
    final key = await _deriveSymmetricKey(
      localPrivateKeyBase64: recipientPrivateKeyBase64,
      remotePublicKeyBase64: senderPublicKeyBase64,
    );
    final allBytes = base64Decode(_fixBase64(_sanitizeBase64(message.ciphertextBase64)));
    final nonce = base64Decode(_fixBase64(_sanitizeBase64(message.nonceBase64)));
    final mac = Mac(allBytes.sublist(allBytes.length - 16));
    final cipherText = allBytes.sublist(0, allBytes.length - 16);
    final box = SecretBox(cipherText, nonce: nonce, mac: mac);
    final clear = await _algo.decrypt(box, secretKey: key);
    final map = jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;

    // §9.6 multi-envelope: content key wrapped for one or more device sessions.
    if (map['fs_multi'] == 1) {
      return _decryptMultiEnvelope(
        map: map,
        ratchetState: ratchetState,
        allRatchetStates: allRatchetStates,
      );
    }

    final bool isFsEncrypted = map['fs_v'] != null && map['fs_cipher'] != null;

    assert(() {
      print('[ENC-DECRYPT] isFsEncrypted=$isFsEncrypted, hasRatchetState=${ratchetState != null}, fs_session=${map['fs_session']}, fs_counter=${map['fs_counter']}');
      return true;
    }());

    if (isFsEncrypted) {
      // §7.3: Per-device ratchet selection — match by fs_session from envelope
      final envelopeFsSession = map['fs_session'] as String?;
      RatchetState? effectiveRatchet = ratchetState;
      if (envelopeFsSession != null && allRatchetStates != null) {
        effectiveRatchet = allRatchetStates[envelopeFsSession] ?? ratchetState;
      }

      print('[FS-DECRYPT-PROD] FS msg detected - session=$envelopeFsSession, counter=${map['fs_counter']}, hasRatchet=${effectiveRatchet != null}');

      if (effectiveRatchet == null) {
        print('[FS-DECRYPT-PROD] WARN: FS msg but ratchetState is NULL — '
            'session was reset, inner FS content unrecoverable');
        // The outer legacy layer was decrypted successfully, but the FS
        // inner payload requires the ratchet state which is gone (identity
        // reset, app reinstall, etc.).  Return metadata-only result so the
        // UI can show a placeholder instead of silently dropping the message.
        return DecryptionResult(
          payload: PlaintextPayload(
            senderId: map['senderId'] as String,
            recipientId: map['recipientId'] as String,
            text: '',
            timestamp: map['timestamp'] as int,
            senderDisplayName: map['senderDisplayName'] as String?,
            expireAfter: map['expireAfter'] as int?,
            deleteAfterRead: (map['deleteAfterRead'] as bool?) ?? false,
          ),
          fsDecryptFailed: true,
        );
      }

      print('[FS-DECRYPT-PROD] Attempting FS decrypt with ratchet session=${effectiveRatchet.sessionId}');
      final fsCipher = base64Decode(map['fs_cipher'] as String);
      final fsNonce = base64Decode(map['fs_nonce'] as String);
      final fsSessionId = map['fs_session'] as String? ?? effectiveRatchet.sessionId;
      final fsRatchetPub = map['fs_ratchet_pub'] as String;
      final fsCounter = map['fs_counter'] as int;

      final fsMessage = FsEncryptedMessage(
        sessionId: fsSessionId,
        localRatchetPub: fsRatchetPub,
        counter: fsCounter,
        ciphertext: fsCipher,
        nonce: fsNonce,
      );

      final (:plaintext, :newState) = await FsDoubleRatchet.decrypt(
        state: effectiveRatchet,
        message: fsMessage,
      );

      print('[FS-DECRYPT-PROD] FS decrypt SUCCESS - session=${newState.sessionId}, newCounter=${newState.recvCounter}');
      return DecryptionResult(
        payload: PlaintextPayload(
          senderId: map['senderId'] as String,
          recipientId: map['recipientId'] as String,
          text: utf8.decode(plaintext),
          timestamp: map['timestamp'] as int,
          senderDisplayName: map['senderDisplayName'] as String?,
          expireAfter: map['expireAfter'] as int?,
          deleteAfterRead: (map['deleteAfterRead'] as bool?) ?? false,
        ),
        newRatchetState: newState,
      );
    }

    // Legacy message — text is in the envelope directly.
    return DecryptionResult(
      payload: PlaintextPayload(
        senderId: map['senderId'] as String,
        recipientId: map['recipientId'] as String,
        text: map['text'] as String,
        timestamp: map['timestamp'] as int,
        senderDisplayName: map['senderDisplayName'] as String?,
        expireAfter: map['expireAfter'] as int?,
        deleteAfterRead: (map['deleteAfterRead'] as bool?) ?? false,
      ),
    );
  }

  /// §9.6 — Decrypts a multi-envelope message whose outer layer is already
  /// decoded into [map].
  ///
  /// Picks the wrap matching one of the recipient's sessions, unwraps the
  /// content key (advancing that session's ratchet), then decrypts the single
  /// payload ciphertext. Falls back to `mc_fallback_key` when present and no
  /// session matches; otherwise reports [DecryptionResult.fsDecryptFailed].
  Future<DecryptionResult> _decryptMultiEnvelope({
    required Map<String, dynamic> map,
    RatchetState? ratchetState,
    Map<String, RatchetState>? allRatchetStates,
  }) async {
    PlaintextPayload buildPayload(String text) => PlaintextPayload(
          senderId: map['senderId'] as String,
          recipientId: map['recipientId'] as String,
          text: text,
          timestamp: map['timestamp'] as int,
          senderDisplayName: map['senderDisplayName'] as String?,
          expireAfter: map['expireAfter'] as int?,
          deleteAfterRead: (map['deleteAfterRead'] as bool?) ?? false,
        );

    final wraps = (map['fs_wraps'] as List?) ?? const [];

    // Find a wrap addressed to one of our sessions.
    Map<String, dynamic>? matchedWrap;
    RatchetState? effectiveRatchet;
    for (final w in wraps) {
      final wrap = w as Map<String, dynamic>;
      final sid = wrap['fs_session'] as String?;
      if (sid == null) continue;
      final candidate = allRatchetStates?[sid] ??
          (ratchetState?.sessionId == sid ? ratchetState : null);
      if (candidate != null) {
        matchedWrap = wrap;
        effectiveRatchet = candidate;
        break;
      }
    }

    Uint8List? contentKeyBytes;
    RatchetState? newState;
    if (matchedWrap != null && effectiveRatchet != null) {
      final fsMessage = FsEncryptedMessage(
        sessionId: matchedWrap['fs_session'] as String,
        localRatchetPub: matchedWrap['fs_ratchet_pub'] as String,
        counter: matchedWrap['fs_counter'] as int,
        ciphertext: base64Decode(matchedWrap['fs_cipher'] as String),
        nonce: base64Decode(matchedWrap['fs_nonce'] as String),
      );
      final (:plaintext, newState: ns) = await FsDoubleRatchet.decrypt(
        state: effectiveRatchet,
        message: fsMessage,
      );
      contentKeyBytes = Uint8List.fromList(plaintext);
      newState = ns;
    } else if (map['mc_fallback_key'] != null) {
      // Legacy fallback: content key is readable via the identity-key outer
      // layer (already decrypted to reach `map`).
      contentKeyBytes = base64Decode(map['mc_fallback_key'] as String);
    }

    if (contentKeyBytes == null) {
      // No matching session and no fallback — inner content unrecoverable.
      return DecryptionResult(
        payload: buildPayload(''),
        fsDecryptFailed: true,
      );
    }

    final mcAll = base64Decode(map['mc_cipher'] as String);
    final mcNonce = base64Decode(map['mc_nonce'] as String);
    final mcMac = Mac(mcAll.sublist(mcAll.length - 16));
    final mcCipher = mcAll.sublist(0, mcAll.length - 16);
    final clear = await _algo.decrypt(
      SecretBox(mcCipher, nonce: mcNonce, mac: mcMac),
      secretKey: SecretKey(contentKeyBytes),
    );

    return DecryptionResult(
      payload: buildPayload(utf8.decode(clear)),
      newRatchetState: newState,
    );
  }

  /// Try to decrypt [message] with a pre-derived [key].
  /// Returns the decrypted payload on success, or null if MAC verification
  /// fails (wrong key).
  Future<PlaintextPayload?> tryDecryptWithKey({
    required EncryptedMessage message,
    required SecretKey key,
  }) async {
    try {
      final allBytes = base64Decode(_fixBase64(_sanitizeBase64(message.ciphertextBase64)));
      final nonce = base64Decode(_fixBase64(_sanitizeBase64(message.nonceBase64)));
      if (allBytes.length < 16) return null;

      final mac = Mac(allBytes.sublist(allBytes.length - 16));
      final cipherText = allBytes.sublist(0, allBytes.length - 16);
      final box = SecretBox(cipherText, nonce: nonce, mac: mac);
      final clear = await _algo.decrypt(box, secretKey: key);
      final map = jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;

      return PlaintextPayload(
        senderId: map['senderId'] as String,
        recipientId: map['recipientId'] as String,
        text: map['text'] as String,
        timestamp: map['timestamp'] as int,
        senderDisplayName: map['senderDisplayName'] as String?,
        expireAfter: map['expireAfter'] as int?,
        deleteAfterRead: (map['deleteAfterRead'] as bool?) ?? false,
      );
    } catch (_) {
      return null;
    }
  }

  /// Try to decrypt [message] with a pre-derived [key].
  /// Returns the full JSON envelope on success (including 'x.fs' extension),
  /// or null if MAC verification fails (wrong key).
  Future<Map<String, dynamic>?> tryDecryptEnvelopeWithKey({
    required EncryptedMessage message,
    required SecretKey key,
  }) async {
    try {
      final allBytes = base64Decode(_fixBase64(_sanitizeBase64(message.ciphertextBase64)));
      final nonce = base64Decode(_fixBase64(_sanitizeBase64(message.nonceBase64)));
      if (allBytes.length < 16) return null;

      final mac = Mac(allBytes.sublist(allBytes.length - 16));
      final cipherText = allBytes.sublist(0, allBytes.length - 16);
      final box = SecretBox(cipherText, nonce: nonce, mac: mac);
      final clear = await _algo.decrypt(box, secretKey: key);
      return jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;
    } catch (_) {
      return null;
    }
  }

  /// Derive the shared symmetric key for a local/remote key pair.
  /// Exposed so callers can pre-derive keys for multi-key trial decryption.
  Future<SecretKey> deriveSymmetricKey({
    required String localPrivateKeyBase64,
    required String remotePublicKeyBase64,
  }) async {
    return _deriveSymmetricKey(
      localPrivateKeyBase64: localPrivateKeyBase64,
      remotePublicKeyBase64: remotePublicKeyBase64,
    );
  }

  Future<SecretKey> _deriveSymmetricKey({
    required String localPrivateKeyBase64,
    required String remotePublicKeyBase64,
  }) async {
    final localPrivateBytes = base64Decode(localPrivateKeyBase64);
    final remotePublicBytes = base64Decode(remotePublicKeyBase64);
    final localPublic = await _keyAgreement
        .newKeyPairFromSeed(localPrivateBytes)
        .then((pair) => pair.extractPublicKey());

    final localKeyPair = SimpleKeyPairData(
      Uint8List.fromList(localPrivateBytes),
      type: KeyPairType.x25519,
      publicKey: localPublic,
    );
    final remotePublic = SimplePublicKey(
      Uint8List.fromList(remotePublicBytes),
      type: KeyPairType.x25519,
    );

    final shared = await _keyAgreement.sharedSecretKey(
      keyPair: localKeyPair,
      remotePublicKey: remotePublic,
    );

    return _hkdf.deriveKey(
      secretKey: shared,
      nonce: utf8.encode('layergram-v1'),
      info: utf8.encode('msg-encryption'),
    );
  }

  // WhatsApp può rimuovere padding '=' dal base64; ripristiniamo al multiplo di 4.
  String _fixBase64(String input) {
    final mod = input.length % 4;
    if (mod == 0) return input;
    return input.padRight(input.length + (4 - mod), '=');
  }

  String _sanitizeBase64(String input) {
    // Rimuove whitespace e caratteri fuori dall'alfabeto base64.
    // Nota: i payload compatti usano base64url ("-" e "_") senza padding.
    // Normalizziamo a base64 standard prima della sanitizzazione.
    final normalized = input.replaceAll('-', '+').replaceAll('_', '/');
    final cleaned = normalized.replaceAll(RegExp(r'[^A-Za-z0-9+/=]'), '');
    return cleaned;
  }
}
