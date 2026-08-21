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

import '../storage/aux_record_repository.dart';

final class V3SessionEligibilityPolicy {
  V3SessionEligibilityPolicy({
    required this.isValid,
    required this.revision,
    required Iterable<String> excludedHandshakeIds,
    this.maximumRemoteDeviceId,
  }) : excludedHandshakeIds = Set<String>.unmodifiable(excludedHandshakeIds);

  final bool isValid;
  final int revision;
  final Set<String> excludedHandshakeIds;
  final String? maximumRemoteDeviceId;
}

/// Per-contact Forward Secrecy security mode (spec §6.1–§6.3, §14.3).
///
/// Each contact (per identity context) has an independently selectable mode:
///
/// - [base]: Legacy encryption only. FS negotiation is suppressed.
/// - [advanced]: Opportunistic FS (default). FS upgrades automatically when
///   both sides support it; active FS messages are ratchet-only.
/// - [strict]: Maximum FS. After a verified session, sending is device-bound
///   and silent downgrade is blocked. Requires explicit user consent (§14.6.2).
///
/// The mode is persisted as an opaque encrypted auxiliary record
/// (`kind: fs_mode_v1`) so it survives app restarts and maintains
/// plausible deniability for passphrase-derived contexts.
///
/// Spec reference: §6.1–§6.3, §6.8, §14.3.
enum FsSecurityMode {
  /// §6.1 — Standard Layergram encryption, no Forward Secrecy.
  base,

  /// §6.2 — Opportunistic FS (default). FS when available, legacy otherwise.
  /// Active FS messages are not sent with a legacy plaintext/content fallback.
  advanced,

  /// §6.3 — Strict FS. FS-only after verified session; no legacy fallback.
  strict,
}

/// Persists the per-contact security mode as encrypted auxiliary records.
///
/// **Design:**
/// - One aux record per `(contactId, identityContext)` pair.
/// - Kind: `fs_mode_v1` — opaque after encryption, indistinguishable from
///   other aux records.
/// - Default mode is [FsSecurityMode.advanced] when no record exists.
/// - Passphrase-context modes are only accessible while the passphrase-derived
///   aux key is active; after expulsion they become opaque.
///
/// Spec reference: §14.3, §14.6.5.
class FsSecurityModeService {
  FsSecurityModeService({
    required AuxRecordRepository auxRepository,
    DateTime Function()? now,
  })  : _auxRepository = auxRepository,
        _now = now ?? DateTime.now;

  final AuxRecordRepository _auxRepository;
  final DateTime Function() _now;

  static const String _kRecordKind = 'fs_mode_v1';
  static const int _recordVersion = 2;
  static const int _maxV3ExcludedHandshakes = 4096;
  static const int _maxRevision = 0x7fffffffffffffff;

  /// In-memory index: `contactId:identityContext` → mode + storage info.
  final Map<String, _ModeEntry> _index = {};
  final Set<String> _recoveryRequiredKeys = <String>{};
  Future<void> _operationTail = Future<void>.value();

  // ---------------------------------------------------------------------------
  // Read
  // ---------------------------------------------------------------------------

  /// Returns the security mode for [contactId] in [identityContext].
  ///
  /// Returns [FsSecurityMode.advanced] if no mode has been explicitly set
  /// (the default upgrade path per §6.2).
  Future<FsSecurityMode> getMode({
    required String contactId,
    required String identityContext,
  }) =>
      _serialized(() async {
        final key = _indexKey(contactId, identityContext);
        final cached = _index[key];
        if (cached != null) return cached.mode;

        final scanned = await _scanForMode(contactId, identityContext);
        return scanned ?? FsSecurityMode.advanced;
      });

  /// Synchronous check — returns cached mode or default.
  /// Use after [rebuildIndex] for hot-path reads.
  FsSecurityMode getModeSync({
    required String contactId,
    required String identityContext,
  }) {
    final key = _indexKey(contactId, identityContext);
    return _index[key]?.mode ?? FsSecurityMode.advanced;
  }

  /// Local policy boundary for protocols that require a fresh session after
  /// an explicit mode change. Legacy records return null and retain their
  /// historical behavior.
  DateTime? getModeChangedAtSync({
    required String contactId,
    required String identityContext,
  }) =>
      _index[_indexKey(contactId, identityContext)]?.changedAt;

  V3SessionEligibilityPolicy? getV3SessionEligibilitySync({
    required String contactId,
    required String identityContext,
  }) {
    final key = _indexKey(contactId, identityContext);
    if (_recoveryRequiredKeys.contains(key)) {
      final existing = _index[key]?.v3Eligibility;
      return V3SessionEligibilityPolicy(
        isValid: false,
        revision: existing?.revision ?? 0,
        excludedHandshakeIds:
            existing?.excludedHandshakeIds ?? const <String>{},
        maximumRemoteDeviceId: existing?.maximumRemoteDeviceId,
      );
    }
    return _index[key]?.v3Eligibility;
  }

  // ---------------------------------------------------------------------------
  // Write
  // ---------------------------------------------------------------------------

  /// Sets the security mode for [contactId] in [identityContext].
  ///
  /// Persists as an encrypted aux record. If a previous mode record exists,
  /// it is atomically replaced (write-then-delete).
  Future<void> setMode({
    required String contactId,
    required String identityContext,
    required FsSecurityMode mode,
  }) =>
      _serialized(
        () => _setModeUnlocked(
          contactId: contactId,
          identityContext: identityContext,
          mode: mode,
          v3ExcludedHandshakeIds: null,
          maximumRemoteDeviceId: null,
        ),
      );

  /// Changes the v3 contact policy and excludes every session that existed at
  /// the decision boundary. Newly completed sessions have new random IDs and
  /// become eligible without relying on the wall clock.
  Future<void> setProtocolV3Mode({
    required String contactId,
    required String identityContext,
    required FsSecurityMode mode,
    required Iterable<String> existingHandshakeIds,
  }) {
    if (mode == FsSecurityMode.base) {
      throw ArgumentError('Layergram v3 supports only Normal or Maximum mode');
    }
    final excluded = existingHandshakeIds.toSet();
    if (excluded.length > _maxV3ExcludedHandshakes ||
        excluded.any((value) => !_isCanonicalV3Id(value))) {
      throw ArgumentError('Invalid Layergram v3 session policy boundary');
    }
    return _serialized(
      () => _setModeUnlocked(
        contactId: contactId,
        identityContext: identityContext,
        mode: mode,
        v3ExcludedHandshakeIds: excluded,
        maximumRemoteDeviceId: null,
      ),
    );
  }

  /// Creates the initial v3 policy before the first setup message is accepted
  /// or generated. Existing policy is never weakened or silently replaced.
  Future<V3SessionEligibilityPolicy> ensureProtocolV3Policy({
    required String contactId,
    required String identityContext,
    required FsSecurityMode mode,
  }) {
    if (mode == FsSecurityMode.base) {
      throw ArgumentError('Layergram v3 supports only Normal or Maximum mode');
    }
    return _serialized(() async {
      final key = _indexKey(contactId, identityContext);
      _ensureWritable(key);
      final existing = _index[key];
      final policy = existing?.v3Eligibility;
      if (policy != null) {
        if (!policy.isValid) {
          throw StateError('Layergram v3 contact policy requires recovery');
        }
        return policy;
      }
      await _setModeUnlocked(
        contactId: contactId,
        identityContext: identityContext,
        mode: mode,
        v3ExcludedHandshakeIds: const <String>{},
        maximumRemoteDeviceId: null,
      );
      return _index[key]!.v3Eligibility!;
    });
  }

  /// Pins the first Maximum-mode peer device. A different device cannot
  /// replace it without a new explicit policy boundary.
  Future<V3SessionEligibilityPolicy> pinProtocolV3MaximumDevice({
    required String contactId,
    required String identityContext,
    required String remoteDeviceId,
  }) {
    if (!_isCanonicalV3Id(remoteDeviceId)) {
      throw ArgumentError('Invalid Layergram v3 remote device ID');
    }
    return _serialized(() async {
      final key = _indexKey(contactId, identityContext);
      _ensureWritable(key);
      final existing = _index[key];
      final policy = existing?.v3Eligibility;
      if (existing == null ||
          existing.mode != FsSecurityMode.strict ||
          policy == null ||
          !policy.isValid) {
        throw StateError('Maximum-mode Layergram v3 policy is unavailable');
      }
      final pinned = policy.maximumRemoteDeviceId;
      if (pinned != null) {
        if (pinned != remoteDeviceId) {
          throw StateError(
              'Maximum-mode Layergram v3 device is already pinned');
        }
        return policy;
      }
      await _setModeUnlocked(
        contactId: contactId,
        identityContext: identityContext,
        mode: existing.mode,
        v3ExcludedHandshakeIds: policy.excludedHandshakeIds,
        maximumRemoteDeviceId: remoteDeviceId,
      );
      return _index[key]!.v3Eligibility!;
    });
  }

  Future<void> _setModeUnlocked({
    required String contactId,
    required String identityContext,
    required FsSecurityMode mode,
    required Set<String>? v3ExcludedHandshakeIds,
    required String? maximumRemoteDeviceId,
  }) async {
    final key = _indexKey(contactId, identityContext);
    _ensureWritable(key);
    final existing = _index[key];
    final revision = (existing?.revision ?? -1) + 1;
    if (revision > _maxRevision) {
      _recoveryRequiredKeys.add(key);
      throw StateError('Layergram security policy revision is exhausted');
    }
    final now = _now().toUtc();
    final previousChangedAt = existing?.changedAt;
    final changedAt =
        previousChangedAt != null && !now.isAfter(previousChangedAt)
            ? previousChangedAt.add(const Duration(milliseconds: 1))
            : now;
    final payload = <String, dynamic>{
      'kind': _kRecordKind,
      'v': _recordVersion,
      'revision': revision,
      'cid': contactId,
      'ctx': identityContext,
      'mode': mode.name,
      'changedAt': changedAt.millisecondsSinceEpoch,
      if (v3ExcludedHandshakeIds != null)
        'v3ExcludedHandshakeIds': v3ExcludedHandshakeIds.toList(growable: false)
          ..sort(),
      if (maximumRemoteDeviceId != null)
        'v3MaximumRemoteDeviceId': maximumRemoteDeviceId,
    };
    try {
      final result = existing == null
          ? await _auxRepository.write(payload: payload)
          : await _auxRepository.update(
              oldStorageId: existing.storageId,
              newPayload: payload,
            );
      _index[key] = _ModeEntry(
        mode: mode,
        storageId: result.storageId,
        recordId: result.recordId,
        changedAt: changedAt,
        revision: revision,
        v3Eligibility: v3ExcludedHandshakeIds == null
            ? null
            : V3SessionEligibilityPolicy(
                isValid: true,
                revision: revision,
                excludedHandshakeIds: v3ExcludedHandshakeIds,
                maximumRemoteDeviceId: maximumRemoteDeviceId,
              ),
      );
    } catch (_) {
      _recoveryRequiredKeys.add(key);
      rethrow;
    }
  }

  // ---------------------------------------------------------------------------
  // Index management
  // ---------------------------------------------------------------------------

  /// Rebuilds the in-memory index by scanning all aux records.
  ///
  /// Call once after app startup / identity context initialization.
  Future<void> rebuildIndex() => _serialized(_rebuildIndexUnlocked);

  Future<void> _rebuildIndexUnlocked() async {
    _index.clear();
    _recoveryRequiredKeys.clear();
    final allIds = _auxRepository.getAllAuxRecordIds();
    final obsolete = <String>[];

    for (final entry in allIds.entries) {
      Map<String, dynamic>? payload;
      try {
        payload = await _auxRepository.read(
          storageId: entry.key,
          recordId: entry.value,
        );
        if (payload == null) continue;
        if (payload['kind'] != _kRecordKind) continue;
        final decoded = _decodeModeEntry(
          payload,
          storageId: entry.key,
          recordId: entry.value,
        );
        final key = _indexKey(decoded.contactId, decoded.identityContext);
        final existing = _index[key];
        if (existing == null || decoded.entry.revision > existing.revision) {
          if (existing != null) obsolete.add(existing.storageId);
          _index[key] = decoded.entry;
          continue;
        }
        if (decoded.entry.revision < existing.revision) {
          obsolete.add(decoded.entry.storageId);
          continue;
        }
        if (_sameModeEntry(existing, decoded.entry)) {
          final keepExisting =
              existing.storageId.compareTo(decoded.entry.storageId) <= 0;
          obsolete.add(
            keepExisting ? decoded.entry.storageId : existing.storageId,
          );
          if (!keepExisting) _index[key] = decoded.entry;
          continue;
        }
        _index[key] = existing.invalidV3();
        _recoveryRequiredKeys.add(key);
      } catch (_) {
        final cid = payload?['cid'];
        final ctx = payload?['ctx'];
        if (cid is String && ctx is String) {
          _recoveryRequiredKeys.add(_indexKey(cid, ctx));
        }
        continue;
      }
    }
    for (final storageId in obsolete) {
      try {
        await _auxRepository.delete(storageId);
      } catch (_) {
        // The highest revision is already authoritative; cleanup retries on
        // the next restore without changing the selected policy.
      }
    }
  }

  /// Removes the mode record for a specific contact+context.
  Future<void> removeMode({
    required String contactId,
    required String identityContext,
  }) =>
      _serialized(() async {
        final key = _indexKey(contactId, identityContext);
        _ensureWritable(key);
        final entry = _index[key];
        if (entry == null) return;
        try {
          await _auxRepository.delete(entry.storageId);
          _index.remove(key);
        } catch (_) {
          _recoveryRequiredKeys.add(key);
          rethrow;
        }
      });

  /// Removes all mode records (e.g., on full data reset).
  Future<void> removeAll() => _serialized(() async {
        await _auxRepository.clearByKind(_kRecordKind);
        _index.clear();
        _recoveryRequiredKeys.clear();
      });

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  static String _indexKey(String contactId, String identityContext) =>
      '${contactId.length}:$contactId$identityContext';

  static FsSecurityMode? _parseMode(String name) {
    for (final mode in FsSecurityMode.values) {
      if (mode.name == name) return mode;
    }
    return null;
  }

  Future<FsSecurityMode?> _scanForMode(
    String contactId,
    String identityContext,
  ) async {
    await _rebuildIndexUnlocked();
    return _index[_indexKey(contactId, identityContext)]?.mode;
  }

  static DateTime? _decodeChangedAt(Object? value) {
    if (value == null) return null;
    if (value is! int || value < 0) return null;
    try {
      return DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
    } on ArgumentError {
      return null;
    }
  }

  static V3SessionEligibilityPolicy? _decodeV3Eligibility(
    Map<String, dynamic> payload,
    int revision,
  ) {
    if (payload.containsKey('v3ExcludedSessionIds')) {
      return V3SessionEligibilityPolicy(
        isValid: false,
        revision: revision,
        excludedHandshakeIds: const <String>[],
      );
    }
    if (!payload.containsKey('v3ExcludedHandshakeIds')) return null;
    final encoded = payload['v3ExcludedHandshakeIds'];
    final maximumRemoteDeviceId = payload['v3MaximumRemoteDeviceId'];
    if (encoded is! List ||
        encoded.length > _maxV3ExcludedHandshakes ||
        (maximumRemoteDeviceId != null &&
            (maximumRemoteDeviceId is! String ||
                !_isCanonicalV3Id(maximumRemoteDeviceId)))) {
      return V3SessionEligibilityPolicy(
        isValid: false,
        revision: revision,
        excludedHandshakeIds: const <String>[],
      );
    }
    final values = <String>{};
    for (final value in encoded) {
      if (value is! String || !_isCanonicalV3Id(value) || !values.add(value)) {
        return V3SessionEligibilityPolicy(
          isValid: false,
          revision: revision,
          excludedHandshakeIds: const <String>[],
        );
      }
    }
    return V3SessionEligibilityPolicy(
      isValid: true,
      revision: revision,
      excludedHandshakeIds: values,
      maximumRemoteDeviceId: maximumRemoteDeviceId as String?,
    );
  }

  static bool _isCanonicalV3Id(String value) {
    if (value.length != 22 || !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value)) {
      return false;
    }
    try {
      final decoded = base64Url.decode(base64Url.normalize(value));
      return decoded.length == 16 &&
          decoded.any((byte) => byte != 0) &&
          base64UrlEncode(decoded).replaceAll('=', '') == value;
    } on FormatException {
      return false;
    }
  }

  static _DecodedModeEntry _decodeModeEntry(
    Map<String, dynamic> payload, {
    required String storageId,
    required String recordId,
  }) {
    final version = payload['v'];
    final contactId = payload['cid'];
    final identityContext = payload['ctx'];
    final modeName = payload['mode'];
    final revision = version == 1 ? 0 : payload['revision'];
    final changedAt = _decodeChangedAt(payload['changedAt']);
    if ((version != 1 && version != _recordVersion) ||
        contactId is! String ||
        contactId.isEmpty ||
        identityContext is! String ||
        identityContext.isEmpty ||
        modeName is! String ||
        revision is! int ||
        revision < 0 ||
        revision > _maxRevision ||
        (version == _recordVersion && changedAt == null)) {
      throw const FormatException('Invalid Layergram security mode record');
    }
    final mode = _parseMode(modeName);
    if (mode == null) {
      throw const FormatException('Invalid Layergram security mode value');
    }
    final eligibility = _decodeV3Eligibility(payload, revision);
    if (eligibility != null &&
        (mode == FsSecurityMode.base ||
            (mode != FsSecurityMode.strict &&
                eligibility.maximumRemoteDeviceId != null))) {
      throw const FormatException('Invalid Layergram v3 policy mode binding');
    }
    return _DecodedModeEntry(
      contactId: contactId,
      identityContext: identityContext,
      entry: _ModeEntry(
        mode: mode,
        storageId: storageId,
        recordId: recordId,
        changedAt: changedAt,
        revision: revision,
        v3Eligibility: eligibility,
      ),
    );
  }

  static bool _sameModeEntry(_ModeEntry left, _ModeEntry right) {
    final leftPolicy = left.v3Eligibility;
    final rightPolicy = right.v3Eligibility;
    return left.mode == right.mode &&
        left.changedAt == right.changedAt &&
        (leftPolicy == null) == (rightPolicy == null) &&
        leftPolicy?.isValid == rightPolicy?.isValid &&
        leftPolicy?.maximumRemoteDeviceId ==
            rightPolicy?.maximumRemoteDeviceId &&
        _sameStrings(
          leftPolicy?.excludedHandshakeIds ?? const <String>{},
          rightPolicy?.excludedHandshakeIds ?? const <String>{},
        );
  }

  static bool _sameStrings(Set<String> left, Set<String> right) =>
      left.length == right.length && left.containsAll(right);

  void _ensureWritable(String key) {
    if (_recoveryRequiredKeys.contains(key)) {
      throw StateError('Layergram security policy requires recovery');
    }
  }

  Future<T> _serialized<T>(Future<T> Function() operation) {
    final completer = Completer<T>();
    final previous = _operationTail;
    _operationTail = previous.catchError((_) {}).then((_) async {
      try {
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }
}

class _ModeEntry {
  const _ModeEntry({
    required this.mode,
    required this.storageId,
    required this.recordId,
    required this.changedAt,
    required this.revision,
    required this.v3Eligibility,
  });

  final FsSecurityMode mode;
  final String storageId;
  final String recordId;
  final DateTime? changedAt;
  final int revision;
  final V3SessionEligibilityPolicy? v3Eligibility;

  _ModeEntry invalidV3() => _ModeEntry(
        mode: mode,
        storageId: storageId,
        recordId: recordId,
        changedAt: changedAt,
        revision: revision,
        v3Eligibility: V3SessionEligibilityPolicy(
          isValid: false,
          revision: revision,
          excludedHandshakeIds:
              v3Eligibility?.excludedHandshakeIds ?? const <String>{},
          maximumRemoteDeviceId: v3Eligibility?.maximumRemoteDeviceId,
        ),
      );
}

final class _DecodedModeEntry {
  const _DecodedModeEntry({
    required this.contactId,
    required this.identityContext,
    required this.entry,
  });

  final String contactId;
  final String identityContext;
  final _ModeEntry entry;
}
