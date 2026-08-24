// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:crypto/crypto.dart' as crypto;

import '../../storage/messages_repository_core.dart';
import '../fs_message_classification.dart';
import '../models.dart';
import 'application_payload_v3.dart';
import 'application_presentation_state_v3.dart';
import 'committed_record_v3.dart';
import 'lmf_v3_persistence.dart';
import 'public_identity_v3.dart';

typedef V3ApplicationRecordLoader = Future<List<Uint8List>> Function();

final class V3ApplicationProjectionResult {
  const V3ApplicationProjectionResult({
    required this.discoveredRecords,
    required this.insertedMessages,
    required this.alreadyProjectedMessages,
    required this.updatedMessages,
    required this.removedMessages,
    required this.exactDeviceDuplicates,
    required this.skippedInvalidPayloads,
    required this.skippedUnrelatedPayloads,
    required this.conflictingLogicalMessages,
  });

  final int discoveredRecords;
  final int insertedMessages;
  final int alreadyProjectedMessages;
  final int updatedMessages;
  final int removedMessages;
  final int exactDeviceDuplicates;
  final int skippedInvalidPayloads;
  final int skippedUnrelatedPayloads;
  final int conflictingLogicalMessages;
}

/// Idempotently projects encrypted AR3/AP3 source records into chat metadata.
///
/// [MessageRecord.text] remains null. The canonical AR3 materializer remains
/// the sole persisted plaintext source; [loadPlaintext] reads it on demand.
/// This makes a crash after metadata insertion safe: the next reconciliation
/// sees the same deterministic `v3m:<logical-id>` and performs no replacement
/// ratchet or transport operation.
final class V3ApplicationMessageProjector {
  V3ApplicationMessageProjector({
    required MessagesRepositoryCore messagesRepository,
    required V3PublicIdentity localIdentity,
    required V3ApplicationRecordLoader recordLoader,
    required String? keyTag,
    Map<String, V3ApplicationPresentationState> presentationStates = const {},
    Map<String, FsMessageClassification> classificationsBySessionId = const {},
  })  : _messagesRepository = messagesRepository,
        _recordLoader = recordLoader,
        _keyTag = keyTag,
        _presentationStates = Map.unmodifiable(presentationStates),
        _classificationsBySessionId =
            Map.unmodifiable(classificationsBySessionId),
        _localIdentityId = localIdentity.identityId,
        _localIdentityDigest = _identityDigest(localIdentity);

  static const String messageIdPrefix =
      V3ApplicationPayloadCodec.messageRecordIdPrefix;

  final MessagesRepositoryCore _messagesRepository;
  final V3ApplicationRecordLoader _recordLoader;
  final String? _keyTag;
  final Map<String, V3ApplicationPresentationState> _presentationStates;
  final Map<String, FsMessageClassification> _classificationsBySessionId;
  final String _localIdentityId;
  final Uint8List _localIdentityDigest;
  bool _closed = false;

  Future<V3ApplicationProjectionResult> reconcile({
    int? nowUnixSeconds,
  }) async {
    _ensureOpen();
    final encodedRecords = await _recordLoader();
    final candidates = <String, _ProjectionCandidate>{};
    final conflictingIds = <String>{};
    var invalid = 0;
    var unrelated = 0;
    var duplicates = 0;
    try {
      for (final encodedRecord in encodedRecords) {
        final committed = V3CommittedRecordCodec.decode(encodedRecord);
        Uint8List? content;
        try {
          if (committed.kind != V3CommittedRecordKind.application) continue;
          content = committed.content;
          V3ApplicationPayload payload;
          try {
            payload = V3ApplicationPayloadCodec.decode(content);
          } on FormatException {
            invalid++;
            continue;
          } on ArgumentError {
            invalid++;
            continue;
          }

          final senderDigest = payload.senderIdentityDigest;
          final recipientDigest = payload.recipientIdentityDigest;
          late final bool senderIsLocal;
          late final bool recipientIsLocal;
          try {
            senderIsLocal = _bytesEqual(senderDigest, _localIdentityDigest);
            recipientIsLocal =
                _bytesEqual(recipientDigest, _localIdentityDigest);
          } finally {
            _wipe(senderDigest);
            _wipe(recipientDigest);
          }
          if (senderIsLocal == recipientIsLocal) {
            unrelated++;
            continue;
          }

          final recordId = '$messageIdPrefix${payload.stableMessageId}';
          final presentation = _presentationStates[recordId];
          if (presentation?.isDeleted == true) continue;
          if (conflictingIds.contains(recordId)) continue;
          final candidate = _ProjectionCandidate(
            canonicalPayload: content,
            message: MessageRecord(
              id: recordId,
              senderId: senderIsLocal
                  ? _localIdentityId
                  : _identityId(payload.senderIdentityDigest),
              recipientId: recipientIsLocal
                  ? _localIdentityId
                  : _identityId(payload.recipientIdentityDigest),
              direction: senderIsLocal ? 'outgoing' : 'incoming',
              timestamp: payload.timestampUnixSeconds,
              expireAfter: payload.expireAfterUnixSeconds,
              deleteAfterRead: payload.deleteAfterRead,
              readAt: presentation?.readAtUnixSeconds,
              keyTag: _keyTag,
              isFsEncrypted: true,
              protocolVersion: V3PublicIdentityCodec.protocolVersion,
              fsClassification: _classificationFor(committed),
              backupExcluded: payload.backupExcluded,
            ),
          );
          content = null;

          final existing = candidates[recordId];
          if (existing == null) {
            candidates[recordId] = candidate;
          } else if (_bytesEqual(
            existing.canonicalPayload,
            candidate.canonicalPayload,
          )) {
            duplicates++;
            candidate.close();
          } else {
            existing.close();
            candidate.close();
            candidates.remove(recordId);
            conflictingIds.add(recordId);
          }
        } finally {
          if (content != null) _wipe(content);
          committed.wipeContent();
        }
      }

      final now = nowUnixSeconds ??
          DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
      candidates.removeWhere((_, candidate) {
        final expiry = candidate.message.expireAfter;
        if (expiry == null || expiry >= now) return false;
        candidate.close();
        return true;
      });

      final existingMessages = <String, MessageRecord>{
        for (final message in await _messagesRepository.getAllMessages())
          message.id: message,
      };
      var removed = 0;
      for (final presentation in _presentationStates.values) {
        if (!presentation.isDeleted) continue;
        final existing = existingMessages[presentation.messageRecordId];
        if (existing == null) continue;
        if (!existing.isV3Encrypted) {
          throw const V3LmfPersistenceConflictException(
            'v3 deletion state conflicts with non-v3 message metadata',
          );
        }
        await _messagesRepository.delete(existing.id);
        existingMessages.remove(existing.id);
        removed++;
      }
      var inserted = 0;
      var alreadyProjected = 0;
      var updated = 0;
      for (final entry in candidates.entries) {
        final existing = existingMessages[entry.key];
        if (existing != null) {
          if (_sameProjectedMetadata(existing, entry.value.message)) {
            alreadyProjected++;
            continue;
          }
          if (_sameProjectedBaseMetadata(existing, entry.value.message) &&
              existing.readAt == null &&
              entry.value.message.readAt != null) {
            await _messagesRepository.add(entry.value.message);
            updated++;
            continue;
          } else {
            throw const V3LmfPersistenceConflictException(
              'v3 chat projection conflicts with existing message metadata',
            );
          }
        }
        await _messagesRepository.add(entry.value.message);
        inserted++;
      }
      return V3ApplicationProjectionResult(
        discoveredRecords: encodedRecords.length,
        insertedMessages: inserted,
        alreadyProjectedMessages: alreadyProjected,
        updatedMessages: updated,
        removedMessages: removed,
        exactDeviceDuplicates: duplicates,
        skippedInvalidPayloads: invalid,
        skippedUnrelatedPayloads: unrelated,
        conflictingLogicalMessages: conflictingIds.length,
      );
    } finally {
      for (final candidate in candidates.values) {
        candidate.close();
      }
      for (final encodedRecord in encodedRecords) {
        _wipe(encodedRecord);
      }
    }
  }

  /// Resolves one visible v3 message from the encrypted AR3 source of truth.
  ///
  /// Metadata must still exist in the active repository. A user-deleted or
  /// expired projection therefore cannot be resurrected by a plaintext lookup.
  Future<String?> loadPlaintext(String messageRecordId) async {
    _ensureOpen();
    if (!messageRecordId.startsWith(messageIdPrefix)) return null;
    if (_presentationStates[messageRecordId]?.isDeleted == true) return null;
    MessageRecord? metadata;
    for (final message in await _messagesRepository.getAllMessages()) {
      if (message.id == messageRecordId) {
        metadata = message;
        break;
      }
    }
    if (metadata == null || !metadata.isV3Encrypted) return null;

    final encodedRecords = await _recordLoader();
    String? result;
    Uint8List? canonicalPayload;
    try {
      for (final encodedRecord in encodedRecords) {
        final committed = V3CommittedRecordCodec.decode(encodedRecord);
        Uint8List? content;
        try {
          if (committed.kind != V3CommittedRecordKind.application) continue;
          content = committed.content;
          V3ApplicationPayload payload;
          try {
            payload = V3ApplicationPayloadCodec.decode(content);
          } on FormatException {
            continue;
          } on ArgumentError {
            continue;
          }
          if ('$messageIdPrefix${payload.stableMessageId}' != messageRecordId) {
            continue;
          }
          final sender = payload.senderIdentityDigest;
          final recipient = payload.recipientIdentityDigest;
          late final bool senderIsLocal;
          late final bool recipientIsLocal;
          try {
            senderIsLocal = _bytesEqual(sender, _localIdentityDigest);
            recipientIsLocal = _bytesEqual(recipient, _localIdentityDigest);
          } finally {
            _wipe(sender);
            _wipe(recipient);
          }
          if (senderIsLocal == recipientIsLocal) continue;
          final expectedMetadata = MessageRecord(
            id: messageRecordId,
            senderId: _identityId(payload.senderIdentityDigest),
            recipientId: _identityId(payload.recipientIdentityDigest),
            direction: senderIsLocal ? 'outgoing' : 'incoming',
            timestamp: payload.timestampUnixSeconds,
            expireAfter: payload.expireAfterUnixSeconds,
            deleteAfterRead: payload.deleteAfterRead,
            readAt: _presentationStates[messageRecordId]?.readAtUnixSeconds,
            keyTag: _keyTag,
            isFsEncrypted: true,
            protocolVersion: V3PublicIdentityCodec.protocolVersion,
            fsClassification: _classificationFor(committed),
            backupExcluded: payload.backupExcluded,
          );
          if (!_sameProjectedMetadata(metadata, expectedMetadata)) {
            throw const V3LmfPersistenceConflictException(
              'v3 plaintext lookup conflicts with chat metadata',
            );
          }
          if (canonicalPayload != null &&
              !_bytesEqual(canonicalPayload, content)) {
            throw const V3LmfPersistenceConflictException(
              'v3 logical message has divergent durable payloads',
            );
          }
          canonicalPayload ??= Uint8List.fromList(content);
          result = payload.text;
        } finally {
          if (content != null) _wipe(content);
          committed.wipeContent();
        }
      }
      return result;
    } finally {
      if (canonicalPayload != null) _wipe(canonicalPayload);
      for (final encodedRecord in encodedRecords) {
        _wipe(encodedRecord);
      }
    }
  }

  void close() {
    if (_closed) return;
    _closed = true;
    _wipe(_localIdentityDigest);
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('Layergram v3 application projector is closed');
    }
  }

  FsMessageClassification _classificationFor(V3CommittedRecord committed) {
    final sessionId = committed.sessionId;
    try {
      final encoded = base64UrlEncode(sessionId).replaceAll('=', '');
      return _classificationsBySessionId[encoded] ??
          FsMessageClassification.fsOnly;
    } finally {
      _wipe(sessionId);
    }
  }
}

final class _ProjectionCandidate {
  _ProjectionCandidate({
    required this.canonicalPayload,
    required this.message,
  });

  final Uint8List canonicalPayload;
  final MessageRecord message;

  void close() => _wipe(canonicalPayload);
}

Uint8List _identityDigest(V3PublicIdentity identity) {
  final binding = identity.identityBindingBytes;
  try {
    return Uint8List.fromList(crypto.sha384.convert(binding).bytes);
  } finally {
    _wipe(binding);
  }
}

String _identityId(Uint8List digest) {
  try {
    return base32.encode(digest).replaceAll('=', '');
  } finally {
    _wipe(digest);
  }
}

bool _sameProjectedMetadata(MessageRecord left, MessageRecord right) {
  return left.id == right.id &&
      left.senderId == right.senderId &&
      left.recipientId == right.recipientId &&
      left.direction == right.direction &&
      left.timestamp == right.timestamp &&
      left.text == null &&
      right.text == null &&
      left.ciphertextBase64 == null &&
      right.ciphertextBase64 == null &&
      left.nonceBase64 == null &&
      right.nonceBase64 == null &&
      left.rawSource == null &&
      right.rawSource == null &&
      left.expireAfter == right.expireAfter &&
      left.deleteAfterRead == right.deleteAfterRead &&
      left.readAt == right.readAt &&
      left.deletedAt == right.deletedAt &&
      left.keyTag == right.keyTag &&
      left.isFsEncrypted &&
      right.isFsEncrypted &&
      left.protocolVersion == right.protocolVersion &&
      left.protocolVersion == V3PublicIdentityCodec.protocolVersion &&
      left.fsClassification == right.fsClassification &&
      left.backupExcluded == right.backupExcluded;
}

bool _sameProjectedBaseMetadata(MessageRecord left, MessageRecord right) {
  return _sameProjectedMetadata(
    left.copyWith(readAt: right.readAt, deletedAt: right.deletedAt),
    right,
  );
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
