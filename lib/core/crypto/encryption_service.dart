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

import 'models.dart';

class EncryptionService {
  final _algo = AesGcm.with256bits();
  final _keyAgreement = X25519();
  final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  Future<EncryptedMessage> encrypt({
    required String senderPrivateKeyBase64,
    required String recipientPublicKeyBase64,
    required PlaintextPayload payload,
    Map<String, dynamic>? fsExtension,
  }) async {
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

    return EncryptedMessage(
      version: 2,
      senderId: payload.senderId,
      recipientId: payload.recipientId,
      nonceBase64: base64Encode(nonce),
      ciphertextBase64: base64Encode([...box.cipherText, ...box.mac.bytes]),
    );
  }

  Future<PlaintextPayload> decrypt({
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

    return PlaintextPayload(
      senderId: map['senderId'] as String,
      recipientId: map['recipientId'] as String,
      text: map['text'] as String,
      timestamp: map['timestamp'] as int,
      senderDisplayName: map['senderDisplayName'] as String?,
      expireAfter: map['expireAfter'] as int?,
      deleteAfterRead: (map['deleteAfterRead'] as bool?) ?? false,
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
