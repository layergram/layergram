import 'dart:collection';

import '../../core/crypto/v3/application_chat_bridge_v3.dart';

/// Keeps replies for independent installations of one contact identity in
/// arrival order until each can be shown in the composer.
final class V3PendingResponseQueue {
  final Map<String, ListQueue<V3ChatOutboundExport>> _byContact = {};

  void addAll(String contactId, Iterable<V3ChatOutboundExport> responses) {
    for (final response in responses) {
      final pending = _byContact.putIfAbsent(
        contactId,
        ListQueue<V3ChatOutboundExport>.new,
      );
      if (pending.any((queued) =>
          queued.handshakeId == response.handshakeId &&
          queued.purpose == response.purpose &&
          queued.bundledText == response.bundledText)) {
        continue;
      }
      pending.addLast(response);
    }
  }

  V3ChatOutboundExport? take(String contactId) {
    final pending = _byContact[contactId];
    if (pending == null || pending.isEmpty) return null;
    final response = pending.removeFirst();
    if (pending.isEmpty) _byContact.remove(contactId);
    return response;
  }
}
