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

/// Result of a decryption operation with optional FS double ratchet.
class DecryptionResult {
  const DecryptionResult({
    required this.payload,
    this.newRatchetState,
  });

  final PlaintextPayload payload;
  final RatchetState? newRatchetState;
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

  /// Decrypts a message using legacy decryption or FS double ratchet.
  ///
  /// First decrypts the outer layer with legacy X25519+HKDF.
  /// If the envelope contains FS-encrypted payload and [ratchetState] is provided,
  /// decrypts the inner layer with the double ratchet.
  Future<DecryptionResult> decrypt({
    required String recipientPrivateKeyBase64,
    required String senderPublicKeyBase64,
    required EncryptedMessage message,
    RatchetState? ratchetState,
  }) async {
    // Step 1: Decrypt outer layer with legacy encryption
    final outerResult = await _legacyDecrypt(
      recipientPrivateKeyBase64: recipientPrivateKeyBase64,
      senderPublicKeyBase64: senderPublicKeyBase64,
      message: message,
    );

    // Check if this is an FS-encrypted message (has fs_v and fs_cipher)
    // Note: We need access to the raw envelope to check for FS fields
    // Re-decrypt to get the envelope
    final key = await _deriveSymmetricKey(
      localPrivateKeyBase64: recipientPrivateKeyBase64,
      remotePublicKeyBase64: senderPublicKeyBase64,
    );
    final allBytes = base64Decode(_fixBase64(_sanitizeBase64(message.ciphertextBase64)));
    final nonce = base64Decode(_fixBase64(_sanitizeBase64(message.nonceBase64)));
    final mac = Mac(allBytes.sublist(allBytes.length - 16));
    final cipherText = allBytes.sublist(0, allBytes.length - 16);
    final box = SecretBox(cipherText, nonce: nonce, mac: mac);

    try {
      final clear = await _algo.decrypt(box, secretKey: key);
      final map = jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;

      // Check if this is an FS-encrypted message
      final bool isFsEncrypted = map['fs_v'] != null && map['fs_cipher'] != null;

      assert(() {
        print('[ENC-DECRYPT] isFsEncrypted=$isFsEncrypted, hasRatchetState=${ratchetState != null}, fs_session=${map['fs_session']}, fs_counter=${map['fs_counter']}');
        return true;
      }());

      if (isFsEncrypted) {
        // FS-encrypted message requires ratchet state
        if (ratchetState == null) {
          throw Exception(
            'FS-encrypted message received but no ratchet state available. '
            'Session may have been reset or broken.',
          );
        }

        // Decrypt the inner FS payload
        final fsCipher = base64Decode(map['fs_cipher'] as String);
        final fsNonce = base64Decode(map['fs_nonce'] as String);
        final fsSessionId = map['fs_session'] as String? ?? ratchetState.sessionId;
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
          state: ratchetState,
          message: fsMessage,
        );

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

      // Not an FS message, return legacy result
      return outerResult;
    } on Exception catch (e) {
      // Re-throw FS-related errors (missing ratchet state, broken session)
      // These should not be silently caught as they indicate session issues
      final message = e.toString();
      if (message.contains('FS-encrypted message') ||
          message.contains('ratchet state') ||
          message.contains('Session may have been reset')) {
        rethrow;
      }
      // For other errors, return the legacy result
      return outerResult;
    }
  }

  Future<DecryptionResult> _legacyDecrypt({
    required String recipientPrivateKeyBase64,
    required String senderPublicKeyBase64,
    required EncryptedMessage message,
  }) async {
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
