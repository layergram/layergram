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

import '../domain/identity_id.dart';
import 'fs_message_classification.dart';
import 'seed_service.dart';

class IdentityBase {
  const IdentityBase({
    required this.identityId,
    required this.publicKeyBase64,
    required this.fingerprint,
    required this.displayName,
  });

  final IdentityId identityId;
  final String publicKeyBase64;
  final String fingerprint;
  final String displayName;
}

class LocalIdentity extends IdentityBase {
  const LocalIdentity({
    required super.identityId,
    required super.publicKeyBase64,
    required super.fingerprint,
    required super.displayName,
    required this.mnemonic,
    this.derivationVersion = IdentityDerivationVersion.v1,
    this.derivationAlgorithm = 'sha256-seed',
  });

  final String mnemonic;
  final IdentityDerivationVersion derivationVersion;
  final String derivationAlgorithm;

  Map<String, dynamic> toMap() {
    return {
      'identityId': identityId,
      'publicKeyBase64': publicKeyBase64,
      'fingerprint': fingerprint,
      'displayName': displayName,
      'mnemonic': mnemonic,
      'derivationVersion': derivationVersion.storageValue,
      'derivationAlgorithm': derivationAlgorithm,
    };
  }

  factory LocalIdentity.fromMap(Map<dynamic, dynamic> map) {
    final derivationVersion = IdentityDerivationVersion.fromStorageValue(
      map['derivationVersion'] as String?,
    );
    return LocalIdentity(
      identityId: map['identityId'] as String,
      publicKeyBase64: map['publicKeyBase64'] as String,
      fingerprint: map['fingerprint'] as String,
      displayName: map['displayName'] as String,
      mnemonic: map['mnemonic'] as String,
      derivationVersion: derivationVersion,
      derivationAlgorithm:
          (map['derivationAlgorithm'] as String?) ?? derivationVersion.algorithm,
    );
  }
}

class RemoteIdentity extends IdentityBase {
  const RemoteIdentity({
    required super.identityId,
    required super.publicKeyBase64,
    required super.fingerprint,
    required super.displayName,
    this.verified = false,
  });

  final bool verified;

  RemoteIdentity copyWith({bool? verified, String? displayName}) {
    return RemoteIdentity(
      identityId: identityId,
      publicKeyBase64: publicKeyBase64,
      fingerprint: fingerprint,
      displayName: displayName ?? this.displayName,
      verified: verified ?? this.verified,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'identityId': identityId,
      'publicKeyBase64': publicKeyBase64,
      'fingerprint': fingerprint,
      'displayName': displayName,
      'verified': verified,
    };
  }

  factory RemoteIdentity.fromMap(Map<dynamic, dynamic> map) {
    return RemoteIdentity(
      identityId: map['identityId'] as String,
      publicKeyBase64: map['publicKeyBase64'] as String,
      fingerprint: map['fingerprint'] as String,
      displayName: map['displayName'] as String,
      verified: (map['verified'] as bool?) ?? false,
    );
  }
}

class PlaintextPayload {
  const PlaintextPayload({
    required this.senderId,
    required this.recipientId,
    required this.text,
    required this.timestamp,
    this.senderDisplayName,
    this.expireAfter,
    this.deleteAfterRead = false,
  });

  final IdentityId senderId;
  final IdentityId recipientId;
  final String text;
  final int timestamp;
  final String? senderDisplayName;
  final int? expireAfter;
  final bool deleteAfterRead;
}

class EncryptedMessage {
  const EncryptedMessage({
    required this.version,
    required this.senderId,
    required this.recipientId,
    required this.nonceBase64,
    required this.ciphertextBase64,
  });

  final int version;
  final IdentityId senderId;
  final IdentityId recipientId;
  final String nonceBase64;
  final String ciphertextBase64;

  /// Serialize to raw bytes: nonce (12) + ciphertext+MAC (N).
  /// No version byte, no sender/recipient IDs — maximum deniability.
  Uint8List toRawBytes() {
    final nonce = base64Decode(_fixBase64(nonceBase64));
    final cipher = base64Decode(_fixBase64(ciphertextBase64));
    return Uint8List.fromList([...nonce, ...cipher]);
  }

  /// Reconstruct from raw bytes: nonce (first 12) + ciphertext+MAC (rest).
  /// senderId/recipientId are unknown until decryption succeeds.
  factory EncryptedMessage.fromRawBytes(Uint8List bytes) {
    if (bytes.length < 28) {
      throw ArgumentError('Raw bytes too short: need >= 28, got ${bytes.length}');
    }
    final nonce = bytes.sublist(0, 12);
    final cipher = bytes.sublist(12);
    return EncryptedMessage(
      version: 2,
      senderId: '',
      recipientId: '',
      nonceBase64: base64Encode(nonce),
      ciphertextBase64: base64Encode(cipher),
    );
  }

  static String _fixBase64(String input) {
    final normalized = input.replaceAll('-', '+').replaceAll('_', '/');
    final mod = normalized.length % 4;
    if (mod == 0) return normalized;
    return normalized.padRight(normalized.length + (4 - mod), '=');
  }
}

class MessageRecord {
  const MessageRecord({
    required this.id,
    required this.senderId,
    required this.recipientId,
    required this.direction,
    required this.timestamp,
    this.text,
    this.ciphertextBase64,
    this.nonceBase64,
    this.rawSource,
    this.expireAfter,
    this.deleteAfterRead = false,
    this.readAt,
    this.deletedAt,
    this.keyTag,
    this.isFsEncrypted = false,
    this.fsClassification,
  });

  final String id;
  final IdentityId senderId;
  final IdentityId recipientId;
  final String direction;
  final int timestamp;
  final String? text;
  final String? ciphertextBase64;
  final String? nonceBase64;
  final String? rawSource;
  final int? expireAfter;
  final bool deleteAfterRead;
  final int? readAt;
  final int? deletedAt;
  final String? keyTag;
  final bool isFsEncrypted;

  /// Per-message security classification (§14.4).
  ///
  /// Nullable for backward compatibility: old records that predate this
  /// field are classified via [effectiveClassification].
  final FsMessageClassification? fsClassification;

  /// Returns [fsClassification] if set, otherwise infers from [isFsEncrypted].
  FsMessageClassification get effectiveClassification =>
      fsClassification ??
      FsMessageClassificationExt.fromLegacyFlag(isFsEncrypted);

  bool get isDeleted => deletedAt != null;

  MessageRecord copyWith({
    String? id,
    String? senderId,
    String? recipientId,
    String? direction,
    int? timestamp,
    String? text,
    bool clearText = false,
    String? ciphertextBase64,
    String? nonceBase64,
    String? rawSource,
    int? expireAfter,
    bool? deleteAfterRead,
    int? readAt,
    int? deletedAt,
    String? keyTag,
    bool? isFsEncrypted,
    FsMessageClassification? fsClassification,
  }) {
    return MessageRecord(
      id: id ?? this.id,
      senderId: senderId ?? this.senderId,
      recipientId: recipientId ?? this.recipientId,
      direction: direction ?? this.direction,
      timestamp: timestamp ?? this.timestamp,
      text: clearText ? null : (text ?? this.text),
      ciphertextBase64: ciphertextBase64 ?? this.ciphertextBase64,
      nonceBase64: nonceBase64 ?? this.nonceBase64,
      rawSource: rawSource ?? this.rawSource,
      expireAfter: expireAfter ?? this.expireAfter,
      deleteAfterRead: deleteAfterRead ?? this.deleteAfterRead,
      readAt: readAt ?? this.readAt,
      deletedAt: deletedAt ?? this.deletedAt,
      keyTag: keyTag ?? this.keyTag,
      isFsEncrypted: isFsEncrypted ?? this.isFsEncrypted,
      fsClassification: fsClassification ?? this.fsClassification,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'id': id,
      'senderId': senderId,
      'recipientId': recipientId,
      'direction': direction,
      'timestamp': timestamp,
      'text': text,
      'ciphertextBase64': ciphertextBase64,
      'nonceBase64': nonceBase64,
      'rawSource': rawSource,
      'expireAfter': expireAfter,
      'deleteAfterRead': deleteAfterRead,
      'readAt': readAt,
      'deletedAt': deletedAt,
      'keyTag': keyTag,
      if (isFsEncrypted) 'isFsEncrypted': true,
      if (fsClassification != null) 'fsCls': fsClassification!.storageIndex,
    };
  }

  factory MessageRecord.fromMap(Map<dynamic, dynamic> map) {
    return MessageRecord(
      id: map['id'] as String,
      senderId: map['senderId'] as String,
      recipientId: map['recipientId'] as String,
      direction: map['direction'] as String,
      timestamp: map['timestamp'] as int,
      text: map['text'] as String?,
      ciphertextBase64: map['ciphertextBase64'] as String?,
      nonceBase64: map['nonceBase64'] as String?,
      rawSource: map['rawSource'] as String?,
      expireAfter: map['expireAfter'] as int?,
      deleteAfterRead: (map['deleteAfterRead'] as bool?) ?? false,
      readAt: map['readAt'] as int?,
      deletedAt: map['deletedAt'] as int?,
      keyTag: map['keyTag'] as String?,
      isFsEncrypted: (map['isFsEncrypted'] as bool?) ?? false,
      fsClassification: map['fsCls'] != null
          ? FsMessageClassificationExt.fromStorageIndex(map['fsCls'] as int)
          : null,
    );
  }
}
