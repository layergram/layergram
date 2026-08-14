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

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'committed_record_v3.dart';
import 'lmf_v3.dart';
import 'lmf_v3_acknowledgement.dart';
import 'lmf_v3_persistence.dart';
import 'triple_ratchet_state_v3.dart';

/// One outgoing application/ratchet/frame-set commit.
///
/// The exact sealed frames are the durable resend source. Application and
/// ratchet bytes are copied on construction and access, and wiped when their
/// owning journal closes.
final class V3SessionSendEffect {
  V3SessionSendEffect._({
    required this.storageId,
    required this.assemblyId,
    required this.previousRatchetRevision,
    required this.revision,
    required this.frames,
    required Uint8List applicationState,
    required Uint8List ratchetState,
    required this.isFullyAcknowledged,
    required this.persistedAt,
    required this.updatedAt,
    required this.effectDigest,
  })  : _applicationState = Uint8List.fromList(applicationState),
        _ratchetState = Uint8List.fromList(ratchetState);

  final String storageId;
  final String assemblyId;
  final int previousRatchetRevision;
  final int revision;
  final List<V3LmfFrame> frames;
  final Uint8List _applicationState;
  final Uint8List _ratchetState;
  final bool isFullyAcknowledged;
  final DateTime persistedAt;
  final DateTime updatedAt;
  final String effectDigest;

  String get messageRecordId => 'v3:$assemblyId';
  Uint8List get applicationState => Uint8List.fromList(_applicationState);
  Uint8List get ratchetState => Uint8List.fromList(_ratchetState);

  int get retainedBytes =>
      _applicationState.length +
      _ratchetState.length +
      frames.fold<int>(
        0,
        (sum, frame) => sum + V3LmfFrameCodec.encodeBinary(frame).length,
      );

  void _wipe() {
    _wipeBytes(_applicationState);
    _wipeBytes(_ratchetState);
  }
}

final class V3SessionSendJournalRestoreResult {
  const V3SessionSendJournalRestoreResult({
    required this.effects,
    required this.removedSupersededRecords,
  });

  final List<V3SessionSendEffect> effects;
  final int removedSupersededRecords;
}

/// Unforgeable ownership token for the unified v3 session coordinator.
final class V3SessionSendJournalAuthority {
  const V3SessionSendJournalAuthority._();
}

/// Durable commit point for one outgoing Triple-Ratchet transition.
///
/// A revision-zero record binds the canonical AR3 plaintext record, complete
/// post-send TR3 snapshot, and exact complete LMF sealed frame set. It is
/// written before those frames are materialized in the outbox. A revision-one
/// record records that a complete authenticated ACK was observed; it is
/// written before the outbox copy can be removed. Any ambiguous write makes the
/// current instance fail stopped until a fresh restore.
final class V3SessionSendJournal {
  V3SessionSendJournal({
    required V3LmfRecordStore store,
    this.maxEffects = 4096,
    this.maxApplicationStateBytes = V3CommittedRecordCodec.maxEncodedBytes,
    this.maxRatchetStateBytes = V3TripleRatchetStateCodec.maxEncodedBytes,
    this.maxFrameBytesPerEffect = 512 * 1024,
    this.maxTotalRetainedBytes = 32 * 1024 * 1024,
    this.maxStoredRecords = 8192,
  }) : _store = store {
    if (maxEffects <= 0 ||
        maxApplicationStateBytes <= 0 ||
        maxRatchetStateBytes <= 0 ||
        maxFrameBytesPerEffect <= 0 ||
        maxTotalRetainedBytes <= 0 ||
        maxStoredRecords <= 0) {
      throw ArgumentError('Layergram v3 send journal limits are invalid');
    }
  }

  static const String recordKind = 'v3_send_effect_v1';

  final V3LmfRecordStore _store;
  final int maxEffects;
  final int maxApplicationStateBytes;
  final int maxRatchetStateBytes;
  final int maxFrameBytesPerEffect;
  final int maxTotalRetainedBytes;
  final int maxStoredRecords;

  final Map<String, V3SessionSendEffect> _effects =
      <String, V3SessionSendEffect>{};
  Future<void> _operationTail = Future<void>.value();
  V3SessionSendJournalAuthority? _authority;
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;
  int _totalRetainedBytes = 0;

  int get effectCount => _effects.length;
  int get totalRetainedBytes => _totalRetainedBytes;
  bool get requiresRecovery => _writeRecoveryRequired;
  List<V3SessionSendEffect> effects({
    V3SessionSendJournalAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return List<V3SessionSendEffect>.unmodifiable(_effects.values);
  }

  V3SessionSendEffect? effectForAssembly(
    String assemblyId, {
    V3SessionSendJournalAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return _effects[assemblyId];
  }

  Future<V3SessionSendJournalAuthority> claimSessionCoordinatorAuthority() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError(
          'Layergram v3 send journal authority must be claimed before restore',
        );
      }
      if (_authority != null) {
        throw StateError(
          'Layergram v3 send journal already has a session coordinator',
        );
      }
      final authority = V3SessionSendJournalAuthority._();
      _authority = authority;
      return authority;
    });
  }

  Future<V3SessionSendJournalRestoreResult> restore({
    V3SessionSendJournalAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 send journal was already restored');
      }
      final storedRecords = await _store.readAll();
      final relevant = storedRecords
          .where((record) => record.payload['kind'] == recordKind)
          .toList(growable: false);
      if (relevant.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 send-journal record limit exceeded',
        );
      }

      final grouped = <String, List<V3SessionSendEffect>>{};
      final decoded = <V3SessionSendEffect>[];
      try {
        for (final stored in relevant) {
          final effect = _decode(stored);
          decoded.add(effect);
          grouped
              .putIfAbsent(effect.assemblyId, () => <V3SessionSendEffect>[])
              .add(effect);
        }
        if (grouped.length > maxEffects) {
          throw const V3LmfPersistenceLimitException(
            'v3 send-journal effect limit exceeded',
          );
        }

        var superseded = 0;
        for (final candidates in grouped.values) {
          candidates.sort((left, right) => right.revision.compareTo(
                left.revision,
              ));
          final selected = candidates.first;
          for (final candidate in candidates.skip(1)) {
            if (!_sameBaseEffect(candidate, selected) ||
                (candidate.revision == selected.revision &&
                    !_sameEffect(candidate, selected))) {
              throw const V3LmfPersistenceConflictException(
                'conflicting v3 send-journal records',
              );
            }
          }
          final retainedBytes = selected.retainedBytes;
          if (_totalRetainedBytes + retainedBytes > maxTotalRetainedBytes) {
            throw const V3LmfPersistenceLimitException(
              'v3 send-journal retained-byte limit exceeded',
            );
          }
          _effects[selected.assemblyId] = selected;
          _totalRetainedBytes += retainedBytes;
          decoded.remove(selected);
          for (final candidate in candidates.skip(1)) {
            superseded++;
            await _deleteIgnoringFailure(candidate.storageId);
          }
        }
        _restored = true;
        return V3SessionSendJournalRestoreResult(
          effects: effects(authority: authority),
          removedSupersededRecords: superseded,
        );
      } finally {
        for (final effect in decoded) {
          effect._wipe();
        }
      }
    });
  }

  Future<V3SessionSendEffect> persist({
    required int previousRatchetRevision,
    required List<V3LmfFrame> frames,
    required Uint8List applicationState,
    required Uint8List ratchetState,
    DateTime? persistedAt,
    V3SessionSendJournalAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      if (previousRatchetRevision < 0 ||
          previousRatchetRevision >= 0x7fffffffffffffff) {
        throw ArgumentError.value(
          previousRatchetRevision,
          'previousRatchetRevision',
        );
      }
      final canonicalFrames = _validateCompleteFrameSet(frames);
      _validateStateSizes(applicationState, ratchetState, canonicalFrames);
      final assemblyId = V3LmfFrameCodec.assemblyId(canonicalFrames.first);
      final existing = _effects[assemblyId];
      final timestamp = (persistedAt ?? DateTime.now()).toUtc();
      if (!_validTimestamp(timestamp.millisecondsSinceEpoch)) {
        throw ArgumentError.value(
          persistedAt,
          'persistedAt',
          'must not precede Unix epoch',
        );
      }
      final candidate = _createEffect(
        storageId: '',
        assemblyId: assemblyId,
        previousRatchetRevision: previousRatchetRevision,
        revision: 0,
        frames: canonicalFrames,
        applicationState: applicationState,
        ratchetState: ratchetState,
        isFullyAcknowledged: false,
        persistedAt: timestamp,
        updatedAt: timestamp,
      );
      if (existing != null) {
        try {
          if (_sameBaseEffect(existing, candidate)) return existing;
          throw const V3LmfPersistenceConflictException(
            'v3 send assembly already has a different durable effect',
          );
        } finally {
          candidate._wipe();
        }
      }
      if (_effects.length >= maxEffects ||
          _totalRetainedBytes + candidate.retainedBytes >
              maxTotalRetainedBytes) {
        candidate._wipe();
        throw const V3LmfPersistenceLimitException(
          'v3 send-journal capacity exceeded',
        );
      }

      try {
        final storageId = await _store.write(_encode(candidate));
        _ensureOpen();
        final durable = _copyWith(candidate, storageId: storageId);
        _effects[assemblyId] = durable;
        _totalRetainedBytes += durable.retainedBytes;
        return durable;
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      } finally {
        candidate._wipe();
      }
    });
  }

  Future<V3SessionSendEffect> markFullyAcknowledged({
    required String assemblyId,
    DateTime? acknowledgedAt,
    V3SessionSendJournalAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final current = _effects[assemblyId];
      if (current == null) {
        throw StateError('Unknown Layergram v3 send-journal assembly');
      }
      if (current.isFullyAcknowledged) return current;
      final requestedUpdatedAt = (acknowledgedAt ?? DateTime.now()).toUtc();
      final canonicalUpdatedAt = requestedUpdatedAt.isBefore(
        current.persistedAt,
      )
          ? current.persistedAt
          : requestedUpdatedAt;
      final updated = _copyWith(
        current,
        storageId: '',
        revision: 1,
        isFullyAcknowledged: true,
        updatedAt: canonicalUpdatedAt,
      );
      try {
        final storageId = await _store.write(_encode(updated));
        _ensureOpen();
        final durable = _copyWith(updated, storageId: storageId);
        _effects[assemblyId] = durable;
        current._wipe();
        await _deleteIgnoringFailure(current.storageId);
        return durable;
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      } finally {
        updated._wipe();
      }
    });
  }

  Future<void> close({V3SessionSendJournalAuthority? authority}) {
    return _serialized(() async {
      _ensureAuthority(authority);
      if (_closed) return;
      _closed = true;
      for (final effect in _effects.values) {
        effect._wipe();
      }
      _effects.clear();
      _totalRetainedBytes = 0;
    });
  }

  V3SessionSendEffect _decode(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    if (payload.length != 13 ||
        payload['kind'] != recordKind ||
        payload['v'] != 1 ||
        payload['reserved'] != 0) {
      throw const FormatException('Invalid Layergram v3 send-journal record');
    }
    final assemblyId = payload['assemblyId'];
    final previousRevision = payload['previousRatchetRevision'];
    final revision = payload['revision'];
    final frameValues = payload['frames'];
    final applicationValue = payload['application'];
    final ratchetValue = payload['ratchet'];
    final acknowledged = payload['acknowledged'];
    final persistedAt = payload['persistedAt'];
    final updatedAt = payload['updatedAt'];
    final digest = payload['effectDigest'];
    if (assemblyId is! String ||
        assemblyId.length != 43 ||
        previousRevision is! int ||
        previousRevision < 0 ||
        previousRevision >= 0x7fffffffffffffff ||
        revision is! int ||
        (revision != 0 && revision != 1) ||
        frameValues is! List ||
        frameValues.isEmpty ||
        frameValues.length > V3LmfFrameCodec.maxFragments ||
        applicationValue is! String ||
        ratchetValue is! String ||
        acknowledged is! bool ||
        acknowledged != (revision == 1) ||
        !_validTimestamp(persistedAt) ||
        !_validTimestamp(updatedAt) ||
        (updatedAt as int) < (persistedAt as int) ||
        digest is! String ||
        digest.length != 43) {
      throw const FormatException('Invalid Layergram v3 send-journal fields');
    }
    final frames = <V3LmfFrame>[];
    for (final value in frameValues) {
      if (value is! String) {
        throw const FormatException('Invalid v3 send-journal frame');
      }
      final binary = _decodeBinary(
        value,
        V3LmfFrameCodec.maxBinaryFrameBytes,
      );
      final frame = V3LmfFrameCodec.decodeBinary(binary);
      final canonical = V3LmfFrameCodec.encodeBinary(frame);
      try {
        if (!_bytesEqual(binary, canonical)) {
          throw const FormatException('Non-canonical v3 send-journal frame');
        }
      } finally {
        _wipeBytes(binary);
        _wipeBytes(canonical);
      }
      frames.add(frame);
    }
    late final List<V3LmfFrame> canonicalFrames;
    try {
      canonicalFrames = _validateCompleteFrameSet(frames);
    } on ArgumentError {
      throw const FormatException('Invalid v3 send-journal frame set');
    }
    if (V3LmfFrameCodec.assemblyId(canonicalFrames.first) != assemblyId) {
      throw const FormatException('Mismatched v3 send-journal assembly');
    }
    final application = _decodeBinary(
      applicationValue,
      maxApplicationStateBytes,
    );
    final ratchet = _decodeBinary(ratchetValue, maxRatchetStateBytes);
    try {
      _validateStateSizes(application, ratchet, canonicalFrames);
      final effect = _createEffect(
        storageId: stored.storageId,
        assemblyId: assemblyId,
        previousRatchetRevision: previousRevision,
        revision: revision,
        frames: canonicalFrames,
        applicationState: application,
        ratchetState: ratchet,
        isFullyAcknowledged: acknowledged,
        persistedAt: DateTime.fromMillisecondsSinceEpoch(
          persistedAt,
          isUtc: true,
        ),
        updatedAt: DateTime.fromMillisecondsSinceEpoch(
          updatedAt,
          isUtc: true,
        ),
      );
      if (effect.effectDigest != digest ||
          !_mapEquals(_encode(effect), payload)) {
        effect._wipe();
        throw const FormatException(
          'Non-canonical Layergram v3 send-journal record',
        );
      }
      return effect;
    } finally {
      _wipeBytes(application);
      _wipeBytes(ratchet);
    }
  }

  V3SessionSendEffect _createEffect({
    required String storageId,
    required String assemblyId,
    required int previousRatchetRevision,
    required int revision,
    required List<V3LmfFrame> frames,
    required Uint8List applicationState,
    required Uint8List ratchetState,
    required bool isFullyAcknowledged,
    required DateTime persistedAt,
    required DateTime updatedAt,
  }) {
    final digest = _effectDigest(
      assemblyId: assemblyId,
      previousRatchetRevision: previousRatchetRevision,
      revision: revision,
      frames: frames,
      applicationState: applicationState,
      ratchetState: ratchetState,
      isFullyAcknowledged: isFullyAcknowledged,
      persistedAt: persistedAt,
      updatedAt: updatedAt,
    );
    return V3SessionSendEffect._(
      storageId: storageId,
      assemblyId: assemblyId,
      previousRatchetRevision: previousRatchetRevision,
      revision: revision,
      frames: List<V3LmfFrame>.unmodifiable(frames),
      applicationState: applicationState,
      ratchetState: ratchetState,
      isFullyAcknowledged: isFullyAcknowledged,
      persistedAt: persistedAt,
      updatedAt: updatedAt,
      effectDigest: digest,
    );
  }

  V3SessionSendEffect _copyWith(
    V3SessionSendEffect source, {
    String? storageId,
    int? revision,
    bool? isFullyAcknowledged,
    DateTime? updatedAt,
  }) {
    final application = source.applicationState;
    final ratchet = source.ratchetState;
    try {
      return _createEffect(
        storageId: storageId ?? source.storageId,
        assemblyId: source.assemblyId,
        previousRatchetRevision: source.previousRatchetRevision,
        revision: revision ?? source.revision,
        frames: source.frames,
        applicationState: application,
        ratchetState: ratchet,
        isFullyAcknowledged: isFullyAcknowledged ?? source.isFullyAcknowledged,
        persistedAt: source.persistedAt,
        updatedAt: updatedAt ?? source.updatedAt,
      );
    } finally {
      _wipeBytes(application);
      _wipeBytes(ratchet);
    }
  }

  Map<String, dynamic> _encode(V3SessionSendEffect effect) {
    final application = effect.applicationState;
    final ratchet = effect.ratchetState;
    try {
      return <String, dynamic>{
        'kind': recordKind,
        'v': 1,
        'assemblyId': effect.assemblyId,
        'previousRatchetRevision': effect.previousRatchetRevision,
        'revision': effect.revision,
        'frames': effect.frames
            .map((frame) => _encodeBinary(V3LmfFrameCodec.encodeBinary(frame)))
            .toList(growable: false),
        'application': _encodeBinary(application),
        'ratchet': _encodeBinary(ratchet),
        'acknowledged': effect.isFullyAcknowledged,
        'persistedAt': effect.persistedAt.millisecondsSinceEpoch,
        'updatedAt': effect.updatedAt.millisecondsSinceEpoch,
        'effectDigest': effect.effectDigest,
        'reserved': 0,
      };
    } finally {
      _wipeBytes(application);
      _wipeBytes(ratchet);
    }
  }

  void _validateStateSizes(
    Uint8List applicationState,
    Uint8List ratchetState,
    List<V3LmfFrame> frames,
  ) {
    final frameBytes = frames.fold<int>(
      0,
      (sum, frame) => sum + V3LmfFrameCodec.encodeBinary(frame).length,
    );
    if (applicationState.isEmpty ||
        applicationState.length > maxApplicationStateBytes ||
        ratchetState.isEmpty ||
        ratchetState.length > maxRatchetStateBytes ||
        frameBytes > maxFrameBytesPerEffect) {
      throw const V3LmfPersistenceLimitException(
        'v3 send-journal record bounds exceeded',
      );
    }
  }

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // A validated superseded encrypted record is harmless on restore.
    }
  }

  Future<T> _serialized<T>(Future<T> Function() operation) {
    final completer = Completer<T>();
    final previous = _operationTail;
    final next = previous.catchError((_) {}).then((_) async {
      try {
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    _operationTail = next;
    return completer.future;
  }

  void _ensureOpen() {
    if (_closed) throw StateError('Layergram v3 send journal is closed');
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored) {
      throw StateError('Layergram v3 send journal must be restored');
    }
    if (_writeRecoveryRequired) {
      throw StateError(
        'Layergram v3 send journal must be reconstructed and restored',
      );
    }
  }

  void _ensureAuthority(V3SessionSendJournalAuthority? authority) {
    final claimed = _authority;
    if (claimed != null && !identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 send journal is owned by a session coordinator',
      );
    }
  }
}

List<V3LmfFrame> _validateCompleteFrameSet(List<V3LmfFrame> frames) {
  if (frames.isEmpty || frames.length > V3LmfFrameCodec.maxFragments) {
    throw ArgumentError.value(frames.length, 'frames.length');
  }
  final sorted = frames.toList()
    ..sort((left, right) => left.fragmentIndex.compareTo(right.fragmentIndex));
  final acknowledgement = V3LmfAcknowledgementCodec.forReceivedFrames(sorted);
  if (!acknowledgement.isComplete ||
      sorted.length != sorted.first.fragmentCount) {
    throw ArgumentError('Send journal requires a complete frame set');
  }
  for (var index = 0; index < sorted.length; index++) {
    if (sorted[index].fragmentIndex != index ||
        sorted[index].metadata.kind == V3LmfFrameKind.acknowledgement) {
      throw ArgumentError('Invalid v3 send-journal frame set');
    }
  }
  return List<V3LmfFrame>.unmodifiable(sorted);
}

String _effectDigest({
  required String assemblyId,
  required int previousRatchetRevision,
  required int revision,
  required List<V3LmfFrame> frames,
  required Uint8List applicationState,
  required Uint8List ratchetState,
  required bool isFullyAcknowledged,
  required DateTime persistedAt,
  required DateTime updatedAt,
}) {
  final header = ByteData(45)
    ..setUint64(0, previousRatchetRevision, Endian.big)
    ..setUint32(8, revision, Endian.big)
    ..setUint32(12, frames.length, Endian.big)
    ..setUint32(16, applicationState.length, Endian.big)
    ..setUint32(20, ratchetState.length, Endian.big)
    ..setUint8(24, isFullyAcknowledged ? 1 : 0)
    ..setUint64(25, persistedAt.millisecondsSinceEpoch, Endian.big)
    ..setUint64(33, updatedAt.millisecondsSinceEpoch, Endian.big)
    ..setUint32(
      41,
      frames.fold<int>(
        0,
        (sum, frame) => sum + V3LmfFrameCodec.encodeBinary(frame).length,
      ),
      Endian.big,
    );
  final label = utf8.encode('layergram/v3/send-effect\u0000');
  final assembly = utf8.encode(assemblyId);
  final frameBytes = frames
      .map(V3LmfFrameCodec.encodeBinary)
      .toList(growable: false);
  final totalLength = label.length +
      assembly.length +
      header.lengthInBytes +
      frameBytes.fold<int>(0, (sum, value) => sum + value.length) +
      applicationState.length +
      ratchetState.length;
  final bytes = Uint8List(totalLength);
  var offset = 0;
  void append(List<int> value) {
    bytes.setRange(offset, offset + value.length, value);
    offset += value.length;
  }

  append(label);
  append(assembly);
  append(header.buffer.asUint8List());
  for (final value in frameBytes) {
    append(value);
  }
  append(applicationState);
  append(ratchetState);
  if (offset != bytes.length) {
    _wipeBytes(bytes);
    throw StateError('Layergram v3 send-effect digest length drift');
  }
  try {
    final digest = Uint8List.fromList(crypto.sha256.convert(bytes).bytes);
    try {
      return _encodeBinary(digest);
    } finally {
      _wipeBytes(digest);
    }
  } finally {
    _wipeBytes(bytes);
    for (final value in frameBytes) {
      _wipeBytes(value);
    }
  }
}

bool _sameBaseEffect(
  V3SessionSendEffect left,
  V3SessionSendEffect right,
) {
  if (left.assemblyId != right.assemblyId ||
      left.previousRatchetRevision != right.previousRatchetRevision ||
      !_sameFrameSet(left.frames, right.frames)) {
    return false;
  }
  final leftApplication = left.applicationState;
  final rightApplication = right.applicationState;
  final leftRatchet = left.ratchetState;
  final rightRatchet = right.ratchetState;
  try {
    return _bytesEqual(leftApplication, rightApplication) &&
        _bytesEqual(leftRatchet, rightRatchet);
  } finally {
    _wipeBytes(leftApplication);
    _wipeBytes(rightApplication);
    _wipeBytes(leftRatchet);
    _wipeBytes(rightRatchet);
  }
}

bool _sameEffect(V3SessionSendEffect left, V3SessionSendEffect right) =>
    _sameBaseEffect(left, right) &&
    left.revision == right.revision &&
    left.isFullyAcknowledged == right.isFullyAcknowledged &&
    left.persistedAt == right.persistedAt &&
    left.updatedAt == right.updatedAt &&
    left.effectDigest == right.effectDigest;

bool _sameFrameSet(List<V3LmfFrame> left, List<V3LmfFrame> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (!_bytesEqual(
      V3LmfFrameCodec.encodeBinary(left[index]),
      V3LmfFrameCodec.encodeBinary(right[index]),
    )) {
      return false;
    }
  }
  return true;
}

String _encodeBinary(Uint8List bytes) =>
    base64UrlEncode(bytes).replaceAll('=', '');

Uint8List _decodeBinary(String armored, int maxBytes) {
  if (armored.isEmpty || armored.length > ((maxBytes * 4 + 2) ~/ 3)) {
    throw const FormatException('Invalid v3 send-journal binary length');
  }
  for (final codeUnit in armored.codeUnits) {
    final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
    final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
    if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
      throw const FormatException('Invalid v3 send-journal binary armor');
    }
  }
  late final Uint8List bytes;
  try {
    bytes = Uint8List.fromList(base64Url.decode(base64Url.normalize(armored)));
  } on FormatException {
    throw const FormatException('Invalid v3 send-journal binary armor');
  }
  if (bytes.length > maxBytes || _encodeBinary(bytes) != armored) {
    _wipeBytes(bytes);
    throw const FormatException('Non-canonical v3 send-journal binary armor');
  }
  return bytes;
}

bool _mapEquals(Map<String, dynamic> left, Map<String, dynamic> right) {
  if (left.length != right.length) return false;
  for (final entry in left.entries) {
    if (!right.containsKey(entry.key)) return false;
    final other = right[entry.key];
    if (entry.value is List && other is List) {
      if (jsonEncode(entry.value) != jsonEncode(other)) return false;
    } else if (entry.value != other) {
      return false;
    }
  }
  return true;
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool _validTimestamp(Object? value) =>
    value is int && value >= 0 && value <= 8640000000000000;

void _wipeBytes(Uint8List value) => value.fillRange(0, value.length, 0);
