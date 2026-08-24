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

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'lmf_v3.dart';
import 'lmf_v3_persistence.dart';

final class V3ApplicationSendTarget {
  const V3ApplicationSendTarget({
    required this.sessionId,
    required this.expectedRevision,
    required this.assemblyId,
    required this.committedRevision,
  });

  final String sessionId;
  final int expectedRevision;
  final String? assemblyId;
  final int? committedRevision;

  bool get isCommitted => assemblyId != null;
}

/// Durable all-or-none export group for one logical application message.
///
/// The plaintext is retained only inside the encrypted Aux boundary. A caller
/// may commit per-device ratchet transitions one by one, but no carrier export
/// is returned until every target has an exact durable assembly ID.
final class V3ApplicationSendGroup {
  V3ApplicationSendGroup._({
    required this.storageId,
    required this.groupId,
    required this.revision,
    required this.kind,
    required this.expiresAtUnixSeconds,
    required Uint8List plaintext,
    required this.targets,
    required this.createdAt,
    required this.updatedAt,
  }) : _plaintext = Uint8List.fromList(plaintext);

  final String storageId;
  final String groupId;
  final int revision;
  final V3LmfFrameKind kind;
  final int expiresAtUnixSeconds;
  final Uint8List _plaintext;
  final List<V3ApplicationSendTarget> targets;
  final DateTime createdAt;
  final DateTime updatedAt;

  Uint8List get plaintext => Uint8List.fromList(_plaintext);
  bool get isReady => targets.every((target) => target.isCommitted);
  int get retainedBytes => _plaintext.length + targets.length * 96;

  void _close() => _plaintext.fillRange(0, _plaintext.length, 0);
}

final class V3ApplicationSendGroupRestoreResult {
  const V3ApplicationSendGroupRestoreResult({
    required this.groups,
    required this.removedSupersededRecords,
  });

  final List<V3ApplicationSendGroup> groups;
  final int removedSupersededRecords;
}

/// Crash-consistent journal above the per-session send journals.
final class V3ApplicationSendGroupJournal {
  V3ApplicationSendGroupJournal({
    required V3LmfRecordStore store,
    Random? secureRandom,
    this.maxGroups = 512,
    this.maxTargetsPerGroup = 16,
    this.maxStoredRecords = 1024,
    this.maxTotalRetainedBytes = 16 * 1024 * 1024,
  })  : _store = store,
        _secureRandom = secureRandom ?? Random.secure() {
    if (maxGroups <= 0 ||
        maxTargetsPerGroup <= 0 ||
        maxStoredRecords <= 0 ||
        maxTotalRetainedBytes <= 0) {
      throw ArgumentError('Layergram v3 send-group limits are invalid');
    }
  }

  static const String recordKind = 'v3_application_send_group_v1';
  static const int _formatVersion = 1;
  static const int _maxTimestampMillis = 253402300799999;
  static const int _maxCounter = 0x7fffffffffffffff;

  final V3LmfRecordStore _store;
  final Random _secureRandom;
  final int maxGroups;
  final int maxTargetsPerGroup;
  final int maxStoredRecords;
  final int maxTotalRetainedBytes;

  final Map<String, V3ApplicationSendGroup> _groups = {};
  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;
  int _totalRetainedBytes = 0;

  bool get requiresRecovery => _writeRecoveryRequired;

  Future<V3ApplicationSendGroupRestoreResult> restore() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 send-group journal was restored');
      }
      final records = (await _store.readAll())
          .where((record) => record.payload['kind'] == recordKind)
          .toList(growable: false);
      if (records.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 send-group record limit exceeded',
        );
      }
      final decoded = <V3ApplicationSendGroup>[];
      try {
        for (final record in records) {
          decoded.add(_decode(record));
        }
        final grouped = <String, List<V3ApplicationSendGroup>>{};
        for (final group in decoded) {
          grouped.putIfAbsent(group.groupId, () => []).add(group);
        }
        if (grouped.length > maxGroups) {
          throw const V3LmfPersistenceLimitException(
            'v3 send-group count limit exceeded',
          );
        }
        final selectedGroups = <String, V3ApplicationSendGroup>{};
        final obsoleteGroups = <V3ApplicationSendGroup>[];
        var total = 0;
        for (final history in grouped.values) {
          history.sort((left, right) {
            final revision = left.revision.compareTo(right.revision);
            if (revision != 0) return revision;
            return left.storageId.compareTo(right.storageId);
          });
          V3ApplicationSendGroup selected = history.first;
          for (final candidate in history.skip(1)) {
            if (candidate.revision == selected.revision) {
              if (!_sameGroup(candidate, selected)) {
                throw const V3LmfPersistenceConflictException(
                  'divergent v3 send group at the same revision',
                );
              }
            } else if (!_extendsGroup(selected, candidate)) {
              throw const V3LmfPersistenceConflictException(
                'v3 send-group history is not monotonic',
              );
            }
            selected = candidate;
          }
          total += selected.retainedBytes;
          if (total > maxTotalRetainedBytes) {
            throw const V3LmfPersistenceLimitException(
              'v3 send-group retained-byte limit exceeded',
            );
          }
          selectedGroups[selected.groupId] = selected;
          obsoleteGroups.addAll(
            history.where((group) => !identical(group, selected)),
          );
        }
        for (final obsolete in obsoleteGroups) {
          await _store.delete(obsolete.storageId);
        }
        _groups.addAll(selectedGroups);
        _totalRetainedBytes = total;
        _restored = true;
        for (final obsolete in obsoleteGroups) {
          obsolete._close();
        }
        return V3ApplicationSendGroupRestoreResult(
          groups: List.unmodifiable(_groups.values),
          removedSupersededRecords: obsoleteGroups.length,
        );
      } catch (_) {
        for (final group in decoded) {
          group._close();
        }
        rethrow;
      }
    });
  }

  Future<List<V3ApplicationSendGroup>> groups() {
    return _serialized(() async {
      _ensureReady();
      return List.unmodifiable(_groups.values);
    });
  }

  Future<V3ApplicationSendGroup> create({
    required Uint8List plaintext,
    required V3LmfFrameKind kind,
    required int expiresAtUnixSeconds,
    required Map<String, int> targetExpectedRevisions,
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      if (plaintext.isEmpty ||
          plaintext.length > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
        throw ArgumentError.value(plaintext.length, 'plaintext.length');
      }
      if (kind != V3LmfFrameKind.application &&
          kind != V3LmfFrameKind.pqRatchet) {
        throw ArgumentError.value(kind, 'kind');
      }
      if (expiresAtUnixSeconds < 0 || expiresAtUnixSeconds > _maxCounter) {
        throw ArgumentError.value(
          expiresAtUnixSeconds,
          'expiresAtUnixSeconds',
        );
      }
      if (targetExpectedRevisions.isEmpty ||
          targetExpectedRevisions.length > maxTargetsPerGroup) {
        throw ArgumentError.value(
          targetExpectedRevisions.length,
          'targetExpectedRevisions.length',
        );
      }
      if (_groups.length >= maxGroups) {
        throw const V3LmfPersistenceLimitException(
          'v3 send-group capacity exceeded',
        );
      }
      final targets = targetExpectedRevisions.entries.map((entry) {
        _validateArmoredId(entry.key, 16, 'sessionId');
        _validateCounter(entry.value, 'expectedRevision');
        return V3ApplicationSendTarget(
          sessionId: entry.key,
          expectedRevision: entry.value,
          assemblyId: null,
          committedRevision: null,
        );
      }).toList(growable: false)
        ..sort((left, right) => left.sessionId.compareTo(right.sessionId));
      final timestamp = _validatedTimestamp(createdAt ?? DateTime.now());
      final candidate = V3ApplicationSendGroup._(
        storageId: '',
        groupId: _newId(),
        revision: 0,
        kind: kind,
        expiresAtUnixSeconds: expiresAtUnixSeconds,
        plaintext: plaintext,
        targets: List.unmodifiable(targets),
        createdAt: timestamp,
        updatedAt: timestamp,
      );
      if (_totalRetainedBytes + candidate.retainedBytes >
          maxTotalRetainedBytes) {
        candidate._close();
        throw const V3LmfPersistenceLimitException(
          'v3 send-group retained-byte capacity exceeded',
        );
      }
      try {
        final storageId = await _store.write(_encode(candidate));
        final committed = _copyWithStorage(candidate, storageId);
        _groups[committed.groupId] = committed;
        _totalRetainedBytes += committed.retainedBytes;
        return committed;
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      } finally {
        candidate._close();
      }
    });
  }

  Future<V3ApplicationSendGroup> markCommitted({
    required String groupId,
    required String sessionId,
    required String assemblyId,
    required int ratchetRevision,
    DateTime? updatedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final existing = _groups[groupId];
      if (existing == null) {
        throw StateError('Layergram v3 send group was not found');
      }
      _validateArmoredId(sessionId, 16, 'sessionId');
      _validateArmoredId(assemblyId, 32, 'assemblyId');
      _validateCounter(ratchetRevision, 'ratchetRevision');
      final index = existing.targets.indexWhere(
        (target) => target.sessionId == sessionId,
      );
      if (index < 0) {
        throw const V3LmfPersistenceConflictException(
          'v3 send group does not contain the session',
        );
      }
      final target = existing.targets[index];
      if (target.isCommitted) {
        if (target.assemblyId != assemblyId ||
            target.committedRevision != ratchetRevision) {
          throw const V3LmfPersistenceConflictException(
            'v3 send-group target commit diverged',
          );
        }
        return existing;
      }
      if (ratchetRevision != target.expectedRevision + 1) {
        throw const V3LmfPersistenceConflictException(
          'v3 send-group target revision is not consecutive',
        );
      }
      final timestamp = _validatedTimestamp(updatedAt ?? DateTime.now());
      if (timestamp.isBefore(existing.updatedAt)) {
        throw const V3LmfPersistenceConflictException(
          'v3 send-group timestamp moved backward',
        );
      }
      final plaintext = existing.plaintext;
      try {
        final targets = List<V3ApplicationSendTarget>.from(existing.targets);
        targets[index] = V3ApplicationSendTarget(
          sessionId: sessionId,
          expectedRevision: target.expectedRevision,
          assemblyId: assemblyId,
          committedRevision: ratchetRevision,
        );
        final candidate = V3ApplicationSendGroup._(
          storageId: '',
          groupId: existing.groupId,
          revision: existing.revision + 1,
          kind: existing.kind,
          expiresAtUnixSeconds: existing.expiresAtUnixSeconds,
          plaintext: plaintext,
          targets: List.unmodifiable(targets),
          createdAt: existing.createdAt,
          updatedAt: timestamp,
        );
        try {
          final storageId = await _store.write(_encode(candidate));
          final committed = _copyWithStorage(candidate, storageId);
          _groups[groupId] = committed;
          _totalRetainedBytes +=
              committed.retainedBytes - existing.retainedBytes;
          existing._close();
          await _store.delete(existing.storageId);
          return committed;
        } catch (_) {
          _writeRecoveryRequired = true;
          rethrow;
        } finally {
          candidate._close();
        }
      } finally {
        plaintext.fillRange(0, plaintext.length, 0);
      }
    });
  }

  Future<void> deleteReady(String groupId) {
    return _serialized(() async {
      _ensureReady();
      final existing = _groups[groupId];
      if (existing == null) return;
      if (!existing.isReady) {
        throw StateError('Layergram v3 send group is not fully committed');
      }
      await _store.delete(existing.storageId);
      _groups.remove(groupId);
      _totalRetainedBytes -= existing.retainedBytes;
      existing._close();
    });
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      for (final group in _groups.values) {
        group._close();
      }
      _groups.clear();
      _totalRetainedBytes = 0;
    }, allowClosed: true);
  }

  Map<String, dynamic> _encode(V3ApplicationSendGroup group) {
    return <String, dynamic>{
      'kind': recordKind,
      'version': _formatVersion,
      'groupId': group.groupId,
      'revision': group.revision,
      'frameKind': group.kind.wireId,
      'expiresAt': group.expiresAtUnixSeconds,
      'plaintext': base64UrlEncode(group._plaintext).replaceAll('=', ''),
      'targets': group.targets
          .map(
            (target) => <String, dynamic>{
              'sessionId': target.sessionId,
              'expectedRevision': target.expectedRevision,
              'assemblyId': target.assemblyId,
              'committedRevision': target.committedRevision,
            },
          )
          .toList(growable: false),
      'createdAt': group.createdAt.millisecondsSinceEpoch,
      'updatedAt': group.updatedAt.millisecondsSinceEpoch,
    };
  }

  V3ApplicationSendGroup _decode(V3LmfStoredRecord stored) {
    final value = stored.payload;
    if (value.length != 10 ||
        value['kind'] != recordKind ||
        value['version'] != _formatVersion ||
        value['groupId'] is! String ||
        value['revision'] is! int ||
        value['frameKind'] is! int ||
        value['expiresAt'] is! int ||
        value['plaintext'] is! String ||
        value['targets'] is! List ||
        value['createdAt'] is! int ||
        value['updatedAt'] is! int) {
      throw const FormatException('Invalid Layergram v3 send-group record');
    }
    final groupId = value['groupId'] as String;
    _validateArmoredId(groupId, 16, 'groupId');
    final revision = value['revision'] as int;
    final expiresAt = value['expiresAt'] as int;
    _validateCounter(revision, 'revision');
    _validateCounter(expiresAt, 'expiresAt');
    final kind = V3LmfFrameKind.fromWireId(value['frameKind'] as int);
    if (kind != V3LmfFrameKind.application &&
        kind != V3LmfFrameKind.pqRatchet) {
      throw const FormatException('Invalid Layergram v3 send-group kind');
    }
    final plaintext = _decodeCanonicalBase64Url(
      value['plaintext'] as String,
      maximumBytes: V3LmfFrameCodec.maxAssembledPlaintextBytes,
    );
    try {
      if (plaintext.isEmpty) {
        throw const FormatException(
          'Invalid Layergram v3 send-group plaintext',
        );
      }
      final rawTargets = value['targets'] as List;
      if (rawTargets.isEmpty || rawTargets.length > maxTargetsPerGroup) {
        throw const FormatException('Invalid Layergram v3 send-group targets');
      }
      final targets = <V3ApplicationSendTarget>[];
      String? previousSession;
      for (final raw in rawTargets) {
        if (raw is! Map || raw.length != 4) {
          throw const FormatException(
            'Invalid Layergram v3 send-group target',
          );
        }
        final map = Map<String, dynamic>.from(raw);
        if (map['sessionId'] is! String ||
            map['expectedRevision'] is! int ||
            (map['assemblyId'] != null && map['assemblyId'] is! String) ||
            (map['committedRevision'] != null &&
                map['committedRevision'] is! int)) {
          throw const FormatException(
            'Invalid Layergram v3 send-group target',
          );
        }
        final sessionId = map['sessionId'] as String;
        final expected = map['expectedRevision'] as int;
        final assemblyId = map['assemblyId'] as String?;
        final committedRevision = map['committedRevision'] as int?;
        _validateArmoredId(sessionId, 16, 'sessionId');
        _validateCounter(expected, 'expectedRevision');
        if ((assemblyId == null) != (committedRevision == null)) {
          throw const FormatException(
            'Invalid Layergram v3 send-group target completion',
          );
        }
        if (assemblyId != null) {
          _validateArmoredId(assemblyId, 32, 'assemblyId');
          _validateCounter(committedRevision!, 'committedRevision');
          if (committedRevision != expected + 1) {
            throw const FormatException(
              'Invalid Layergram v3 send-group target revision',
            );
          }
        }
        if (previousSession != null &&
            previousSession.compareTo(sessionId) >= 0) {
          throw const FormatException(
            'Non-canonical Layergram v3 send-group target order',
          );
        }
        previousSession = sessionId;
        targets.add(
          V3ApplicationSendTarget(
            sessionId: sessionId,
            expectedRevision: expected,
            assemblyId: assemblyId,
            committedRevision: committedRevision,
          ),
        );
      }
      final createdAt = _validatedTimestampMillis(value['createdAt'] as int);
      final updatedAt = _validatedTimestampMillis(value['updatedAt'] as int);
      if (updatedAt.isBefore(createdAt)) {
        throw const FormatException(
          'Invalid Layergram v3 send-group timestamp',
        );
      }
      return V3ApplicationSendGroup._(
        storageId: stored.storageId,
        groupId: groupId,
        revision: revision,
        kind: kind,
        expiresAtUnixSeconds: expiresAt,
        plaintext: plaintext,
        targets: List.unmodifiable(targets),
        createdAt: createdAt,
        updatedAt: updatedAt,
      );
    } finally {
      plaintext.fillRange(0, plaintext.length, 0);
    }
  }

  static V3ApplicationSendGroup _copyWithStorage(
    V3ApplicationSendGroup value,
    String storageId,
  ) {
    return V3ApplicationSendGroup._(
      storageId: storageId,
      groupId: value.groupId,
      revision: value.revision,
      kind: value.kind,
      expiresAtUnixSeconds: value.expiresAtUnixSeconds,
      plaintext: value._plaintext,
      targets: value.targets,
      createdAt: value.createdAt,
      updatedAt: value.updatedAt,
    );
  }

  static bool _sameGroup(
    V3ApplicationSendGroup left,
    V3ApplicationSendGroup right,
  ) {
    return left.groupId == right.groupId &&
        left.revision == right.revision &&
        left.kind == right.kind &&
        left.expiresAtUnixSeconds == right.expiresAtUnixSeconds &&
        left.createdAt == right.createdAt &&
        left.updatedAt == right.updatedAt &&
        _bytesEqual(left._plaintext, right._plaintext) &&
        _sameTargets(left.targets, right.targets);
  }

  static bool _extendsGroup(
    V3ApplicationSendGroup previous,
    V3ApplicationSendGroup next,
  ) {
    if (next.revision <= previous.revision ||
        next.groupId != previous.groupId ||
        next.kind != previous.kind ||
        next.expiresAtUnixSeconds != previous.expiresAtUnixSeconds ||
        next.createdAt != previous.createdAt ||
        next.updatedAt.isBefore(previous.updatedAt) ||
        !_bytesEqual(next._plaintext, previous._plaintext) ||
        next.targets.length != previous.targets.length) {
      return false;
    }
    var newlyCommitted = 0;
    for (var index = 0; index < previous.targets.length; index++) {
      final oldTarget = previous.targets[index];
      final newTarget = next.targets[index];
      if (oldTarget.sessionId != newTarget.sessionId ||
          oldTarget.expectedRevision != newTarget.expectedRevision) {
        return false;
      }
      if (oldTarget.isCommitted) {
        if (!_sameTarget(oldTarget, newTarget)) return false;
      } else if (newTarget.isCommitted) {
        newlyCommitted++;
      }
    }
    return next.revision == previous.revision + 1 && newlyCommitted == 1;
  }

  static bool _sameTargets(
    List<V3ApplicationSendTarget> left,
    List<V3ApplicationSendTarget> right,
  ) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (!_sameTarget(left[index], right[index])) return false;
    }
    return true;
  }

  static bool _sameTarget(
    V3ApplicationSendTarget left,
    V3ApplicationSendTarget right,
  ) =>
      left.sessionId == right.sessionId &&
      left.expectedRevision == right.expectedRevision &&
      left.assemblyId == right.assemblyId &&
      left.committedRevision == right.committedRevision;

  String _newId() {
    for (var attempt = 0; attempt < 16; attempt++) {
      final bytes = Uint8List.fromList(
        List<int>.generate(16, (_) => _secureRandom.nextInt(256)),
      );
      try {
        if (bytes.every((byte) => byte == 0)) continue;
        final id = base64UrlEncode(bytes).replaceAll('=', '');
        if (!_groups.containsKey(id)) return id;
      } finally {
        bytes.fillRange(0, bytes.length, 0);
      }
    }
    throw StateError('Unable to allocate a Layergram v3 send-group ID');
  }

  static Uint8List _decodeCanonicalBase64Url(
    String value, {
    required int maximumBytes,
  }) {
    if (value.isEmpty || value.length > ((maximumBytes + 2) ~/ 3) * 4) {
      throw const FormatException('Invalid Layergram v3 base64url value');
    }
    for (final codeUnit in value.codeUnits) {
      final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
      final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
      final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
      if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
        throw const FormatException('Invalid Layergram v3 base64url value');
      }
    }
    late final Uint8List decoded;
    try {
      decoded = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(value)),
      );
    } on FormatException {
      throw const FormatException('Invalid Layergram v3 base64url value');
    }
    if (decoded.length > maximumBytes ||
        base64UrlEncode(decoded).replaceAll('=', '') != value) {
      throw const FormatException('Invalid Layergram v3 base64url value');
    }
    return decoded;
  }

  static void _validateArmoredId(
    String value,
    int expectedBytes,
    String name,
  ) {
    final decoded = _decodeCanonicalBase64Url(
      value,
      maximumBytes: expectedBytes,
    );
    try {
      if (decoded.length != expectedBytes ||
          decoded.every((byte) => byte == 0)) {
        throw FormatException('Invalid Layergram v3 $name');
      }
    } finally {
      decoded.fillRange(0, decoded.length, 0);
    }
  }

  static void _validateCounter(int value, String name) {
    if (value < 0 || value > _maxCounter) {
      throw FormatException('Invalid Layergram v3 $name');
    }
  }

  static DateTime _validatedTimestamp(DateTime value) =>
      _validatedTimestampMillis(value.toUtc().millisecondsSinceEpoch);

  static DateTime _validatedTimestampMillis(int value) {
    if (value < 0 || value > _maxTimestampMillis) {
      throw const FormatException('Invalid Layergram v3 timestamp');
    }
    return DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
  }

  static bool _bytesEqual(Uint8List left, Uint8List right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
  }

  Future<T> _serialized<T>(
    Future<T> Function() operation, {
    bool allowClosed = false,
  }) {
    final completer = Completer<T>();
    final previous = _operationTail;
    _operationTail = previous.catchError((_) {}).then((_) async {
      try {
        if (_closed && !allowClosed) {
          throw StateError('Layergram v3 send-group journal is closed');
        }
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('Layergram v3 send-group journal is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || requiresRecovery) {
      throw StateError('Layergram v3 send-group journal requires restore');
    }
  }
}
