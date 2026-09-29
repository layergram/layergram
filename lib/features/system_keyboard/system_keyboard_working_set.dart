// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import '../../core/crypto/v3/lmf_v3_persistence.dart';
import 'system_keyboard_record_store.dart';

/// Conservative selection after the app's sole runtime has restored and drained.
/// It never rewrites protocol records, truncates a journal or removes receipts.
/// Chat presentation stays private. The installation device-key record and
/// incomplete handshake state move with the exclusive protocol owner.
/// An immutable AR3 archive body stays private
/// only when no transferred protocol record references its stable/assembly ID.
/// Required commit/replay evidence can contain a previous message body; it must
/// remain protected as session working state, not exposed as a history browser.
abstract final class SystemKeyboardWorkingSet {
  static List<V3LmfStoredRecord> select(List<V3LmfStoredRecord> all) {
    final protocol = <V3LmfStoredRecord>[];
    for (final record in all) {
      final kind = record.payload['kind'];
      if (kind == 'v3_application_presentation_v1') continue;
      if (SystemKeyboardRecordSnapshot.allowedKinds.contains(kind)) {
        protocol.add(record);
      } else if (kind is String &&
          (kind.startsWith('v3_') || kind.startsWith('v3.'))) {
        // Unknown protocol versions cannot safely be split across owners.
        throw StateError('Protocol state is not eligible for keyboard custody');
      }
    }
    final references = <String>{};
    void collect(Object? value) {
      if (value is String) {
        references.add(value);
      } else if (value is Map) {
        value.values.forEach(collect);
      } else if (value is List) {
        value.forEach(collect);
      }
    }

    for (final record in protocol) {
      if (record.payload['kind'] != 'v3_application_record_v1') {
        collect(record.payload);
      }
    }
    return protocol.where((record) {
      final p = record.payload;
      if (p['kind'] != 'v3_application_record_v1') return true;
      final stable = p['stableRecordId'];
      final assembly = p['assemblyId'];
      // A malformed record is never silently hidden from restore validation.
      if (stable is! String ||
          assembly is! String ||
          stable != 'v3:$assembly') {
        return true;
      }
      return references.contains(stable) || references.contains(assembly);
    }).toList(growable: false);
  }
}
