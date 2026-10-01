// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import '../../core/crypto/fs_message_classification.dart';
import '../../core/crypto/models.dart';
import '../../core/crypto/v3/application_payload_v3.dart';
import '../../core/crypto/v3/lmf_v3_persistence.dart';
import '../../core/storage/messages_repository_core.dart';

/// Only identity-encrypted pre-FS text needs a keyboard history handoff. FS
/// messages already have canonical encrypted AR3 records and are projected by
/// the application runtime. These entries travel in the encrypted custody
/// snapshot and then the private auxiliary store, never in a host-app log.
abstract final class SystemKeyboardHistory {
  static const kind = 'v3_keyboard_history_v1';

  static Future<void> recordPreFs({
    required V3LmfRecordStore store,
    required String stableMessageId,
    required String localIdentityId,
    required String contactId,
    required String direction,
    required String text,
    required int timestampUnixSeconds,
    int? expireAfterUnixSeconds,
    bool backupExcluded = false,
  }) async {
    final messageId =
        '${V3ApplicationPayloadCodec.messageRecordIdPrefix}$stableMessageId';
    _validate(messageId, localIdentityId, contactId, direction, text,
        timestampUnixSeconds, expireAfterUnixSeconds);
    await store.write({
      'kind': kind,
      'v': 1,
      'messageId': messageId,
      'localIdentityId': localIdentityId,
      'contactId': contactId,
      'direction': direction,
      'text': text,
      'timestamp': timestampUnixSeconds,
      'expireAfter': expireAfterUnixSeconds,
      'backupExcluded': backupExcluded,
    });
  }

  /// Called only after keyboard custody is reclaimed for this unlocked
  /// identity. A crash after the chat write is harmless: the stable message ID
  /// makes replay idempotent, and the outbox is deleted only after persistence.
  static Future<int> restore({
    required V3LmfRecordStore store,
    required Future<bool> Function(String messageId) isDeleted,
    required MessagesRepositoryCore messages,
    required MessagesRepositoryContextLease lease,
    required String localIdentityId,
    required String? keyTag,
  }) async {
    var restored = 0;
    for (final entry in await store.readAll()) {
      final row = entry.payload;
      if (row['kind'] != kind) continue;
      final id = row['messageId'];
      final owner = row['localIdentityId'];
      final contact = row['contactId'];
      final direction = row['direction'];
      final body = row['text'];
      final timestamp = row['timestamp'];
      final expiry = row['expireAfter'];
      if (row.length != 10 ||
          row['v'] != 1 ||
          id is! String ||
          owner is! String ||
          contact is! String ||
          direction is! String ||
          body is! String ||
          timestamp is! int ||
          (expiry != null && expiry is! int) ||
          row['backupExcluded'] is! bool ||
          owner != localIdentityId) {
        throw const FormatException('Invalid keyboard history handoff');
      }
      final int? expireAfter = expiry as int?;
      _validate(id, owner, contact, direction, body, timestamp, expireAfter);
      if (!await isDeleted(id) &&
          (expireAfter == null ||
              expireAfter >=
                  DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000)) {
        await messages.addInContext(
          lease,
          MessageRecord(
            id: id,
            senderId: direction == 'outgoing' ? owner : contact,
            recipientId: direction == 'outgoing' ? contact : owner,
            direction: direction,
            timestamp: timestamp,
            text: body,
            expireAfter: expireAfter,
            keyTag: keyTag,
            isFsEncrypted: false,
            protocolVersion: 3,
            fsClassification: FsMessageClassification.preFs,
            backupExcluded: row['backupExcluded'] as bool,
          ),
        );
        restored++;
      }
      await store.delete(entry.storageId);
    }
    return restored;
  }

  static void _validate(String messageId, String owner, String contact,
      String direction, String text, int timestamp, int? expiry) {
    if (!RegExp(r'^v3m:[A-Za-z0-9_-]{22}$').hasMatch(messageId) ||
        owner.isEmpty ||
        owner.length > 128 ||
        contact.isEmpty ||
        contact.length > 128 ||
        contact == owner ||
        (direction != 'incoming' && direction != 'outgoing') ||
        text.isEmpty ||
        text.length > 4000 ||
        timestamp < 0 ||
        (expiry != null && expiry < 0)) {
      throw const FormatException('Invalid keyboard history message');
    }
  }
}
