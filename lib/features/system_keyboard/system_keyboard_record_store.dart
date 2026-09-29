// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../../core/crypto/v3/lmf_v3_persistence.dart';

/// Native custody commits are durable compare-and-swap operations. An error may
/// have occurred after persistence: the caller must close the runtime, never
/// retry a ratchet computation against its previous snapshot.
typedef SystemKeyboardSnapshotCommit = Future<int> Function(
  Uint8List snapshot,
  int expectedRevision,
);

/// Bounded serialization of a delegated protocol working set. This is not an
/// authorization grant and contains secrets: only the encrypted native custody
/// store or an authenticated live channel may receive its bytes.
abstract final class SystemKeyboardRecordSnapshot {
  static const int maxBytes = 2 * 1024 * 1024;
  static const int maxRecords = 8192;
  static const int maxRevision = 9007199254740991;

  /// These exact V3 records are required to resume a protocol session from
  /// its first message through FS negotiation. Unknown versions fail closed.
  static const Set<String> allowedKinds = {
    'v3.prefs.pending.manifest',
    'v3_acknowledgement_outbox_v1',
    'v3_application_send_group_v1',
    'v3_application_presentation_v1',
    'v3_application_record_v1',
    'v3_application_record_deleted_v1',
    'v3_device_key_v1',
    'v3_handshake_completion_v1',
    'v3_handshake_frame_v1',
    'v3_handshake_frame_done_v1',
    'v3_handshake_handoff_v1',
    'v3_handshake_pending_v1',
    'v3_keyboard_control_outbox_v1',
    'v3_keyboard_history_v1',
    'v3_lmf_effect_v1',
    'v3_lmf_out_v1',
    'v3_lmf_in_v1',
    'v3_lmf_done_v1',
    'v3_lmf_replay_v1',
    'v3_session_checkpoint_v1',
    'v3_send_effect_v1',
    'v3_send_completion_v1',
    'v3_session_retirement_v1',
  };

  static Uint8List encode(Iterable<V3LmfStoredRecord> records) {
    final ids = <String>{};
    final encoded = <Map<String, dynamic>>[];
    for (final record in records) {
      _validate(record);
      if (!ids.add(record.storageId) || encoded.length >= maxRecords) {
        throw const FormatException('Invalid keyboard working set');
      }
      encoded.add({'id': record.storageId, 'payload': record.payload});
    }
    final encodedBytes = JsonUtf8Encoder().convert({
      'v': 1,
      'records': encoded,
    });
    final Uint8List bytes;
    if (encodedBytes is Uint8List) {
      bytes = encodedBytes;
    } else {
      bytes = Uint8List.fromList(encodedBytes);
      encodedBytes.fillRange(0, encodedBytes.length, 0);
    }
    if (bytes.length > maxBytes) {
      bytes.fillRange(0, bytes.length, 0);
      throw const FormatException('Keyboard working set exceeds capacity');
    }
    return bytes;
  }

  static List<V3LmfStoredRecord> decode(Uint8List bytes) {
    if (bytes.length > maxBytes) {
      throw const FormatException('Keyboard working set exceeds capacity');
    }
    final value = jsonDecode(utf8.decode(bytes));
    if (value is! Map<String, dynamic> ||
        value.length != 2 ||
        value['v'] != 1 ||
        value['records'] is! List) {
      throw const FormatException('Invalid keyboard working set');
    }
    final entries = value['records'] as List;
    if (entries.length > maxRecords) {
      throw const FormatException('Keyboard working set exceeds capacity');
    }
    final records = <V3LmfStoredRecord>[];
    final ids = <String>{};
    for (final entry in entries) {
      if (entry is! Map<String, dynamic> ||
          entry.length != 2 ||
          entry['id'] is! String ||
          entry['payload'] is! Map<String, dynamic>) {
        throw const FormatException('Invalid keyboard working record');
      }
      final record = V3LmfStoredRecord(
        storageId: entry['id'] as String,
        payload: entry['payload'] as Map<String, dynamic>,
      );
      _validate(record);
      if (!ids.add(record.storageId)) {
        throw const FormatException('Duplicate keyboard working record');
      }
      records.add(record);
    }
    return records;
  }

  static void _validate(V3LmfStoredRecord record) {
    if (!RegExp(r'^r[A-Za-z0-9_-]{22}$').hasMatch(record.storageId) ||
        !allowedKinds.contains(record.payload['kind'])) {
      throw const FormatException(
          'Record is not eligible for keyboard custody');
    }
  }
}

/// A single-use in-memory view backed by the encrypted native custody store.
/// Every write/delete persists before it becomes visible. No native error,
/// revocation, revision mismatch or close can resurrect this instance.
final class SystemKeyboardRecordStore implements V3LmfRecordStore {
  SystemKeyboardRecordStore({
    required Uint8List snapshot,
    required int revision,
    required SystemKeyboardSnapshotCommit commit,
  })  : _commit = commit,
        _revision = revision {
    if (revision < 0 || revision > SystemKeyboardRecordSnapshot.maxRevision) {
      throw ArgumentError.value(revision, 'revision');
    }
    for (final record in SystemKeyboardRecordSnapshot.decode(snapshot)) {
      _records[record.storageId] = _freezePayload(record.payload);
    }
  }

  final SystemKeyboardSnapshotCommit _commit;
  final Map<String, Map<String, dynamic>> _records = {};
  final Random _random = Random.secure();
  Future<void> _tail = Future<void>.value();
  int _revision;
  bool _closed = false;

  bool get isClosed => _closed;

  /// A metadata-only startup gate avoids cloning the full protocol snapshot
  /// just to check that the delegated installation key was transferred.
  bool containsKind(String kind) {
    _ensureOpen();
    return _records.values.any((payload) => payload['kind'] == kind);
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() => _serialized(() async {
        _ensureOpen();
        // Every stored payload and nested collection is immutable. Readers can
        // share them without copying the whole protocol state on each V3
        // lookup, and cannot change it without a durable CAS write.
        return _records.entries
            .map((entry) => V3LmfStoredRecord(
                storageId: entry.key, payload: entry.value))
            .toList(growable: false);
      });

  @override
  Future<String> write(Map<String, dynamic> payload) => _serialized(() async {
        _ensureOpen();
        String id;
        do {
          id =
              'r${base64Url.encode(List<int>.generate(16, (_) => _random.nextInt(256))).replaceAll('=', '')}';
        } while (_records.containsKey(id));
        await _persist({..._records, id: _freezePayload(_detachPayload(payload))});
        return id;
      });

  @override
  Future<void> delete(String storageId) => _serialized(() async {
        _ensureOpen();
        if (!_records.containsKey(storageId)) return;
        await _persist({..._records}..remove(storageId));
      });

  /// Immediate terminal invalidation, including while a commit is in flight.
  void close() {
    _closed = true;
    _records.clear();
  }

  Future<void> _persist(Map<String, Map<String, dynamic>> candidate) async {
    Uint8List? bytes;
    try {
      if (_revision >= SystemKeyboardRecordSnapshot.maxRevision) {
        throw StateError('Keyboard custody revision exhausted');
      }
      bytes = _encode(candidate);
      final next = await _commit(bytes, _revision);
      _ensureOpen();
      if (next != _revision + 1) {
        throw StateError('Keyboard custody revision conflict');
      }
      _revision = next;
      _records
        ..clear()
        ..addAll(candidate);
    } catch (_) {
      close();
      rethrow;
    } finally {
      bytes?.fillRange(0, bytes.length, 0);
    }
  }

  Uint8List _encode(Map<String, Map<String, dynamic>> records) =>
      SystemKeyboardRecordSnapshot.encode(records.entries.map((entry) =>
          V3LmfStoredRecord(storageId: entry.key, payload: entry.value)));

  // Payloads are JSON by the snapshot contract. Per-record detachment avoids
  // a second whole-snapshot byte/string/object graph at the write peak.
  Map<String, dynamic> _detachPayload(Map<String, dynamic> payload) =>
      jsonDecode(jsonEncode(payload)) as Map<String, dynamic>;

  Map<String, dynamic> _freezePayload(Map<String, dynamic> payload) =>
      _freezeJson(payload) as Map<String, dynamic>;

  Object? _freezeJson(Object? value) {
    if (value is Map<String, dynamic>) {
      return Map<String, dynamic>.unmodifiable(
        value.map((key, nested) => MapEntry(key, _freezeJson(nested))),
      );
    }
    if (value is List) {
      return List<dynamic>.unmodifiable(value.map(_freezeJson));
    }
    if (value == null || value is String || value is num || value is bool) {
      return value;
    }
    throw const FormatException('Invalid keyboard working record');
  }

  void _ensureOpen() {
    if (_closed) throw StateError('Keyboard working store is closed');
  }

  Future<T> _serialized<T>(Future<T> Function() operation) {
    final result = _tail.then((_) => operation());
    _tail = result.then<void>((_) {}, onError: (Object _, StackTrace __) {});
    return result;
  }
}
