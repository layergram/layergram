// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../../core/crypto/v3/lmf_v3_persistence.dart';
import '../../core/storage/aux_record_repository.dart';
import 'system_keyboard_record_store.dart';
import 'system_keyboard_working_set.dart';

final class SystemKeyboardCustodySnapshot {
  const SystemKeyboardCustodySnapshot(this.revision, this.bytes);
  final int revision;
  final Uint8List bytes;
}

/// Only the native adapter may report this, and only when BOTH durable custody
/// files are absent. Corruption, protection/permission errors and partial state
/// must throw a different error; they can never authorize baseline fallback.
final class SystemKeyboardCustodyMissing implements Exception {
  const SystemKeyboardCustodyMissing();
}

abstract interface class SystemKeyboardCustodyNative {
  Future<bool> hasPending();
  Future<void> prepare(Uint8List epoch, Uint8List key, Uint8List bytes);
  Future<void> activate(Uint8List epoch, Uint8List key);
  Future<SystemKeyboardCustodySnapshot> reclaim(Uint8List epoch, Uint8List key);
  Future<void> removeAfterImport(Uint8List epoch, Uint8List key, int revision);
}

/// App-private storage; callers must pin one ordinary identity's auxiliary key
/// for its entire lifetime. The keyboard never receives this interface/key.
abstract interface class SystemKeyboardCustodyPrivateStore {
  Future<List<V3LmfStoredRecord>> readAll();
  Future<String> write(Map<String, dynamic> payload);
  Future<void> delete(String storageId);
  Future<void> flush();
  Future<PreparedAuxRecord> prepare(
    String storageId,
    Map<String, dynamic> payload,
  );
  Future<void> apply(PreparedAuxRecord record);
}

/// Optional read-only access to an authenticated deleted record in an
/// append-only private store. A caller may use it only to verify a complete
/// pre-activation snapshot; it never authorizes ratchet rollback.
abstract interface class SystemKeyboardCustodyHistoricalStore {
  Future<V3LmfStoredRecord?> readDeleted(String storageId);
}

final class SystemKeyboardCustodyAuxStore
    implements
        SystemKeyboardCustodyPrivateStore,
        SystemKeyboardCustodyHistoricalStore {
  SystemKeyboardCustodyAuxStore(this._repository, {this.diagnosticStage});
  final AuxRecordRepository _repository;
  final void Function(String stage)? diagnosticStage;
  @override
  Future<List<V3LmfStoredRecord>> readAll() =>
      V3LmfAuxRecordStore(_repository).readAll();
  @override
  Future<String> write(Map<String, dynamic> payload) async =>
      (await _repository.write(payload: payload)).storageId;
  @override
  Future<void> delete(String storageId) => _repository.delete(storageId);
  @override
  Future<void> flush() => _repository.flush();
  @override
  Future<PreparedAuxRecord> prepare(
    String storageId,
    Map<String, dynamic> payload,
  ) =>
      _repository.prepareImport(storageId: storageId, payload: payload);
  @override
  Future<void> apply(PreparedAuxRecord record) =>
      _repository.applyPreparedImport(record);

  @override
  Future<V3LmfStoredRecord?> readDeleted(String storageId) async {
    final payload = await _repository.readDeletedAuxRecordForCustody(
      storageId,
      diagnosticStage: diagnosticStage,
    );
    return payload == null
        ? null
        : V3LmfStoredRecord(storageId: storageId, payload: payload);
  }
}

/// Key material for ONE authenticated live grant. Transport it only inside the
/// existing encrypted mailbox. Destroy after acknowledgement or any failure.
final class SystemKeyboardCustodyGrant {
  SystemKeyboardCustodyGrant._(this.epoch, this.key);
  final Uint8List epoch;
  final Uint8List key;
  void close() {
    epoch.fillRange(0, epoch.length, 0);
    key.fillRange(0, key.length, 0);
  }
}

/// Crash recovery for a drained, exclusive ordinary-identity V3 scope.
///
/// The caller must close ALL app runtime owners before delegate/recover and
/// gate every later app runtime open, backup, reset and scope change on recover.
/// Native app activation must revoke keyboard custody before calling recover.
/// This object grants no identity admission and must never be used for a
/// passphrase scope. A missing/corrupt authoritative working set fails closed.
final class SystemKeyboardCustody {
  SystemKeyboardCustody({
    required this.privateStore,
    required this.native,
    void Function(String stage)? diagnosticStage,
  }) : _diagnosticStage = diagnosticStage;
  final SystemKeyboardCustodyPrivateStore privateStore;
  final SystemKeyboardCustodyNative native;
  final void Function(String stage)? _diagnosticStage;
  static const markerKind = 'keyboard_custody_v1';
  static const backupKind = 'keyboard_custody_abort_snapshot_v1';
  static const preparedKind = 'keyboard_custody_prepared_v1';
  static const activationKind = 'keyboard_custody_activation_v1';
  static const repairKind = 'keyboard_custody_repair_v1';
  static const importKind = 'keyboard_custody_import_v1';
  static const resetKind = 'keyboard_custody_reset_v1';
  // The app-private Hive store has one process/isolate owner. Reject overlapping
  // custody objects too, not only re-entry into the same instance. Native CAS
  // remains the cross-process boundary with the extension.
  static bool _busy = false;

  Future<SystemKeyboardCustodyGrant> delegate() => _exclusive(() async {
        _diagnosticStage?.call('custodyDelegateEntered');
        if (await native.hasPending()) {
          _diagnosticStage?.call('custodyDelegateNativePending');
          throw StateError('Native keyboard custody requires recovery');
        }
        final all = await privateStore.readAll();
        if (all.any(
          (r) =>
              r.payload['kind'] == markerKind ||
              r.payload['kind'] == backupKind ||
              r.payload['kind'] == preparedKind ||
              r.payload['kind'] == activationKind ||
              r.payload['kind'] == repairKind ||
              r.payload['kind'] == importKind ||
              r.payload['kind'] == resetKind,
        )) {
          _diagnosticStage?.call('custodyDelegateJournalPresent');
          throw StateError('Keyboard custody requires recovery');
        }
        final records = SystemKeyboardWorkingSet.select(all);
        if (records.isEmpty) {
          _diagnosticStage?.call('custodyDelegateWorkingSetEmpty');
          throw StateError('Keyboard requires a V3 protocol working set');
        }
        final bytes = SystemKeyboardRecordSnapshot.encode(records);
        final epoch = _randomBytes(16);
        final key = _randomBytes(32);
        try {
          final preFsAbort = _PreFsAbortProof.forWorkingSet(records);
          final markerId = await privateStore.write({
            'kind': markerKind,
            'v': 4,
            'epoch': base64Url.encode(epoch),
            'key': base64Url.encode(key),
            'ids': records.map((r) => r.storageId).toList(),
            'initialDigest': crypto.sha256.convert(bytes).toString(),
            'preFsAbort': preFsAbort?.toJson(),
          });
          // The exact source snapshot is a separate encrypted private journal
          // so it can be erased before keyboard activation and ratchet use.
          final backupId = await privateStore.write({
            'kind': backupKind,
            'v': 1,
            'markerId': markerId,
            'epoch': base64Url.encode(epoch),
            'digest': crypto.sha256.convert(bytes).toString(),
            'snapshot': base64Url.encode(bytes),
          });
          await privateStore.flush();
          _diagnosticStage?.call('custodyDelegateMarkerReady');
          _diagnosticStage?.call('custodyDelegateNativePrepareStart');
          await native.prepare(epoch, key, bytes);
          _diagnosticStage?.call('custodyDelegateNativePrepareReady');
          // This receipt must be durable BEFORE deleting any private source. If
          // native preparation fails (or its files disappear before this write), a
          // v3 marker without the receipt proves activation was never attempted.
          await privateStore.write({
            'kind': preparedKind,
            'v': 1,
            'epoch': base64Url.encode(epoch),
          });
          await privateStore.flush();
          _diagnosticStage?.call('custodyDelegateReceiptReady');
          // No previous ratchet baseline remains usable when the grant is enabled.
          for (final record in records) {
            await privateStore.delete(record.storageId);
          }
          await privateStore.flush();
          _diagnosticStage?.call('custodyDelegateSourcesRemoved');
          // A durable intent separates a provably unactivated deletion from a
          // potentially active keyboard. Once present, the private snapshot
          // may never be used as a fallback if native custody disappears.
          await privateStore.write({
            'kind': activationKind,
            'v': 1,
            'epoch': base64Url.encode(epoch),
          });
          await privateStore.flush();
          _diagnosticStage?.call('custodyDelegateActivationIntentReady');
          await privateStore.delete(backupId);
          await privateStore.flush();
          _diagnosticStage?.call('custodyDelegateAbortSnapshotRemoved');
          _diagnosticStage?.call('custodyDelegateActivateStart');
          await native.activate(epoch, key);
          _diagnosticStage?.call('custodyDelegateActivateReady');
          return SystemKeyboardCustodyGrant._(
            Uint8List.fromList(epoch),
            Uint8List.fromList(key),
          );
        } finally {
          bytes.fillRange(0, bytes.length, 0);
          epoch.fillRange(0, epoch.length, 0);
          key.fillRange(0, key.length, 0);
        }
      });

  /// Returns only after the app-private state is authoritative. Throws rather
  /// than opening stale state on any uncertain recovery outcome.
  Future<void> recover() => _exclusive(() async {
        _diagnosticStage?.call('custodyReadStart');
        final all = await privateStore.readAll();
        _diagnosticStage?.call('custodyReadReady');
        final markers =
            all.where((r) => r.payload['kind'] == markerKind).toList();
        final backups =
            all.where((r) => r.payload['kind'] == backupKind).toList();
        final imports =
            all.where((r) => r.payload['kind'] == importKind).toList();
        final resets =
            all.where((r) => r.payload['kind'] == resetKind).toList();
        final prepared =
            all.where((r) => r.payload['kind'] == preparedKind).toList();
        final activations =
            all.where((r) => r.payload['kind'] == activationKind).toList();
        final repairs =
            all.where((r) => r.payload['kind'] == repairKind).toList();
        if (resets.isNotEmpty) {
          _diagnosticStage?.call('custodyResetReceipt');
          await _finishConfirmedReset(
            all: all,
            markers: markers,
            imports: imports,
            resets: resets,
          );
          return;
        }
        if (markers.isEmpty && imports.isEmpty) {
          if (repairs.length == 1 && prepared.isEmpty) {
            if (await native.hasPending()) {
              throw StateError('Native keyboard state appeared after repair');
            }
            _validateRepair(repairs.single.payload);
            await privateStore.delete(repairs.single.storageId);
            await privateStore.flush();
            return;
          }
          _diagnosticStage?.call('custodyNoJournal');
          if (backups.isNotEmpty ||
              prepared.isNotEmpty ||
              activations.isNotEmpty ||
              repairs.isNotEmpty) {
            throw StateError('Orphaned keyboard preparation receipt');
          }
          if (await native.hasPending()) {
            throw StateError('Keyboard custody journal is unavailable');
          }
          return;
        }
        if (markers.isEmpty && imports.length == 1) {
          _diagnosticStage?.call('custodyImportReceipt');
          if (await native.hasPending()) {
            throw StateError('Keyboard custody cleanup receipt conflicts');
          }
          // Marker deletion is the final commit receipt: private writes were
          // flushed and native cleanup finished before it could be removed.
          // Reapply exact bytes to verify scope/authentication, then clear the
          // remaining import journal. Never restore authorization.
          await _applyManifest(imports.single.payload);
          if (backups.isNotEmpty ||
              activations.isNotEmpty ||
              prepared.length > 1 ||
              prepared.any((receipt) =>
                  receipt.payload.length != 3 ||
                  receipt.payload['kind'] != preparedKind ||
                  receipt.payload['v'] != 1 ||
                  receipt.payload['epoch'] !=
                      imports.single.payload['epoch'])) {
            throw const FormatException('Invalid orphaned preparation receipt');
          }
          for (final receipt in prepared) {
            await privateStore.delete(receipt.storageId);
          }
          await privateStore.flush();
          await privateStore.delete(imports.single.storageId);
          await privateStore.flush();
          return;
        }
        if (markers.length != 1 ||
            imports.length > 1 ||
            repairs.length > 1 ||
            (repairs.isNotEmpty && imports.isNotEmpty)) {
          _diagnosticStage?.call('custodyAmbiguousJournal');
          throw StateError('Ambiguous keyboard custody journal');
        }
        _diagnosticStage?.call('custodyMarkerPresent');
        final marker = markers.single;
        final parsed = _Marker.parse(marker.payload);
        _diagnosticStage?.call('custodyMarkerParsed');
        try {
          if (!_validPreparedReceipt(prepared, parsed)) {
            throw const FormatException('Invalid keyboard preparation receipt');
          }
          if (!_validActivationReceipt(activations, parsed)) {
            throw const FormatException('Invalid keyboard activation receipt');
          }
          if (!_validAbortSnapshot(backups, marker, parsed)) {
            throw const FormatException('Invalid keyboard abort snapshot');
          }
          if (repairs.isNotEmpty) {
            if (activations.isNotEmpty) {
              throw StateError('Activated custody cannot use private repair');
            }
            final repair = repairs.single;
            final body = repair.payload;
            _validateRepair(body);
            if (body['markerId'] != marker.storageId ||
                body['epoch'] != base64Url.encode(parsed.epoch) ||
                await native.hasPending()) {
              throw StateError('Keyboard repair receipt conflicts');
            }
            await _applyRepair(body);
            for (final backup in backups) {
              await privateStore.delete(backup.storageId);
            }
            for (final receipt in prepared) {
              await privateStore.delete(receipt.storageId);
            }
            await privateStore.flush();
            await privateStore.delete(marker.storageId);
            await privateStore.flush();
            await privateStore.delete(repair.storageId);
            await privateStore.flush();
            _diagnosticStage?.call('custodyLegacyFramesRecovered');
            return;
          }
          V3LmfStoredRecord manifest;
          if (imports.isEmpty) {
            SystemKeyboardCustodySnapshot snapshot;
            try {
              _diagnosticStage?.call('custodyNativeReclaimStart');
              snapshot = await native.reclaim(parsed.epoch, parsed.key);
              _diagnosticStage?.call('custodyNativeReclaimReady');
            } on SystemKeyboardCustodyMissing {
              _diagnosticStage?.call('custodyNativeMissing');
              if (parsed.version == 4) {
                if (activations.isNotEmpty) {
                  // The keyboard might have ratcheted after activation.
                  // A pre-activation copy is no longer authoritative.
                  throw StateError('Activated keyboard custody is missing');
                }
                if (parsed.preFsAbort != null &&
                    await _recoverReplacedPreFsManifest(
                        all: all, marker: marker, parsed: parsed)) {
                  _diagnosticStage?.call('custodyReplacedManifestRecovered');
                  return;
                }
                if (backups.isEmpty) {
                  if (!_originalBaselineIsIntact(all, parsed)) {
                    throw StateError('Pre-activation snapshot is missing');
                  }
                  await _finishIntactPrivateAbort(all: all, marker: marker);
                } else {
                  await _recoverPreActivationSnapshot(
                      all: all,
                      marker: marker,
                      parsed: parsed,
                      backup: backups.single);
                }
                _diagnosticStage?.call('custodyPreActivationRecovered');
                return;
              }
              if (parsed.version == 3 && prepared.isEmpty) {
                await _finishUnpreparedPrivateAbort(all: all, marker: marker);
                _diagnosticStage?.call('custodyUnpreparedRecovered');
                return;
              }
              if (await _recoverLegacyFramesAndManifest(
                  all: all, marker: marker, parsed: parsed)) {
                _diagnosticStage?.call('custodyLegacyFramesRecovered');
                return;
              }
              // An intact original baseline is a safe abort. A single replaced
              // pre-FS manifest has a separate exact-digest proof below.
              final byId = {for (final r in all) r.storageId: r};
              if (parsed.ids.any((id) => !byId.containsKey(id))) {
                if (await _recoverReplacedPreFsManifest(
                  all: all,
                  marker: marker,
                  parsed: parsed,
                )) {
                  _diagnosticStage?.call('custodyReplacedManifestRecovered');
                  return;
                }
                _diagnosticStage?.call('custodyReplacedManifestUnproven');
                _traceResetCandidate(all, parsed);
                rethrow;
              }
              final baseline = SystemKeyboardRecordSnapshot.encode(
                parsed.ids.map((id) => byId[id]!),
              );
              try {
                if (crypto.sha256.convert(baseline).toString() !=
                    parsed.initialDigest) {
                  rethrow;
                }
              } finally {
                baseline.fillRange(0, baseline.length, 0);
              }
              // Native activation happens only AFTER every original ID has
              // been deleted and flushed. If all exact originals remain, this
              // delegation never became keyboard-authoritative. Additional
              // authenticated app-private records may have been committed by
              // an in-flight app write; preserve them rather than rolling
              // back to the snapshot. A completed keyboard import would have
              // a durable import receipt until the marker is removed.
              await _finishIntactPrivateAbort(all: all, marker: marker);
              _diagnosticStage?.call('custodyBaselineRecovered');
              return;
            }
            try {
              if (snapshot.revision < 0 ||
                  snapshot.revision >
                      SystemKeyboardRecordSnapshot.maxRevision) {
                throw const FormatException('Invalid custody revision');
              }
              final records =
                  SystemKeyboardRecordSnapshot.decode(snapshot.bytes);
              // Also handles interruption halfway through deleting the baseline.
              // No import has started until its complete manifest is durable.
              for (final id in parsed.ids) {
                await privateStore.delete(id);
              }
              await privateStore.flush();
              final prepared = <Map<String, dynamic>>[];
              for (final record in records) {
                prepared.add(
                  (await privateStore.prepare(
                    record.storageId,
                    record.payload,
                  ))
                      .toJson(),
                );
              }
              final payload = <String, dynamic>{
                'kind': importKind,
                'v': 1,
                'epoch': base64Url.encode(parsed.epoch),
                'revision': snapshot.revision,
                'records': prepared,
              };
              final id = await privateStore.write(payload);
              await privateStore.flush();
              manifest = V3LmfStoredRecord(storageId: id, payload: payload);
            } finally {
              snapshot.bytes.fillRange(0, snapshot.bytes.length, 0);
            }
          } else {
            manifest = imports.single;
          }
          final body = manifest.payload;
          _diagnosticStage?.call('custodyManifestReady');
          if (body['epoch'] != base64Url.encode(parsed.epoch)) {
            throw const FormatException('Keyboard import epoch mismatch');
          }
          await _applyManifest(body);
          _diagnosticStage?.call('custodyManifestApplied');
          // Cleanup is idempotent and epoch bound. Keep both private journals until
          // shared cleanup finishes, so a crash cannot leave unowned shared state.
          _diagnosticStage?.call('custodyNativeCleanupStart');
          await native.removeAfterImport(
            parsed.epoch,
            parsed.key,
            body['revision'] as int,
          );
          _diagnosticStage?.call('custodyNativeCleanupReady');
          for (final receipt in prepared) {
            await privateStore.delete(receipt.storageId);
          }
          for (final receipt in activations) {
            await privateStore.delete(receipt.storageId);
          }
          for (final backup in backups) {
            await privateStore.delete(backup.storageId);
          }
          _diagnosticStage?.call('custodyReceiptsDeleted');
          await privateStore.flush();
          _diagnosticStage?.call('custodyReceiptsFlushed');
          await privateStore.delete(marker.storageId);
          _diagnosticStage?.call('custodyMarkerDeleted');
          await privateStore.flush();
          _diagnosticStage?.call('custodyMarkerFlushed');
          await privateStore.delete(manifest.storageId);
          _diagnosticStage?.call('custodyManifestDeleted');
          await privateStore.flush();
          _diagnosticStage?.call('custodyCleanupReady');
        } finally {
          parsed.close();
        }
      });

  /// Recover one legacy interrupted delegation with several retired handshake
  /// frames. At least one unchanged source ID proves the deletion loop did not
  /// finish and native activation was impossible. Every absent source is read
  /// from the authenticated Hive history and the entire original snapshot is
  /// bound to the marker digest before any write. A newer pending manifest
  /// supersedes the old one; exact frames are restored for the frame inbox to
  /// reconcile against its durable completion tombstones.
  Future<bool> _recoverLegacyFramesAndManifest({
    required List<V3LmfStoredRecord> all,
    required V3LmfStoredRecord marker,
    required _Marker parsed,
  }) async {
    final byId = {for (final record in all) record.storageId: record};
    final absent = parsed.ids.where((id) => !byId.containsKey(id)).toList();
    if (absent.length < 2 || absent.length >= parsed.ids.length) return false;
    final history = privateStore is SystemKeyboardCustodyHistoricalStore
        ? privateStore as SystemKeyboardCustodyHistoricalStore
        : null;
    if (history == null) return false;
    final recovered = <String, V3LmfStoredRecord>{};
    for (final id in absent) {
      final record = await history.readDeleted(id);
      if (record == null || record.storageId != id) return false;
      recovered[id] = record;
    }
    final missingRecords = [for (final id in absent) recovered[id]!];
    final oldManifests = missingRecords.where(
        (record) => record.payload['kind'] == 'v3.prefs.pending.manifest');
    if (oldManifests.length != 1 ||
        missingRecords.any((record) =>
            record.payload['kind'] != 'v3.prefs.pending.manifest' &&
            record.payload['kind'] != 'v3_handshake_frame_v1')) {
      return false;
    }
    final oldManifest = oldManifests.single;
    final oldRevision = oldManifest.payload['revision'];
    if (oldManifest.payload['version'] != 1 ||
        oldRevision is! int ||
        oldRevision < 0) {
      return false;
    }
    final original = [
      for (final id in parsed.ids) byId[id] ?? recovered[id]!,
    ];
    final bytes = SystemKeyboardRecordSnapshot.encode(original);
    try {
      if (crypto.sha256.convert(bytes).toString() != parsed.initialDigest) {
        return false;
      }
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
    // A retained original device key also excludes a silent device-identity
    // replacement during the interrupted handoff.
    if (!original.any((record) =>
        record.payload['kind'] == 'v3_device_key_v1' &&
        byId.containsKey(record.storageId))) {
      return false;
    }
    final selected = SystemKeyboardWorkingSet.select(all);
    final originalIds = parsed.ids.toSet();
    final successors = selected
        .where((record) =>
            !originalIds.contains(record.storageId) &&
            record.payload['kind'] == 'v3.prefs.pending.manifest')
        .toList();
    if (successors.length != 1 ||
        successors.single.payload['version'] != 1 ||
        successors.single.payload['revision'] is! int ||
        (successors.single.payload['revision'] as int) <= oldRevision) {
      return false;
    }
    final latest = await privateStore.readAll();
    final latestById = {for (final record in latest) record.storageId: record};
    if (latest.length != all.length ||
        latest.any((record) =>
            byId[record.storageId] == null ||
            jsonEncode(byId[record.storageId]!.payload) !=
                jsonEncode(record.payload)) ||
        latestById[marker.storageId] == null ||
        await native.hasPending()) {
      return false;
    }
    final prepared = <Map<String, dynamic>>[];
    for (final record in missingRecords) {
      if (record.storageId == oldManifest.storageId) {
        continue;
      }
      prepared.add(
          (await privateStore.prepare(record.storageId, record.payload))
              .toJson());
    }
    final receipt = <String, dynamic>{
      'kind': repairKind,
      'v': 1,
      'markerId': marker.storageId,
      'epoch': base64Url.encode(parsed.epoch),
      'records': prepared,
    };
    final receiptId = await privateStore.write(receipt);
    await privateStore.flush();
    await _applyRepair(receipt);
    await privateStore.delete(marker.storageId);
    await privateStore.flush();
    await privateStore.delete(receiptId);
    await privateStore.flush();
    return true;
  }

  void _validateRepair(Map<String, dynamic> body) {
    if (body.length != 5 ||
        body['kind'] != repairKind ||
        body['v'] != 1 ||
        body['markerId'] is! String ||
        !RegExp(r'^r[A-Za-z0-9_-]{22}$').hasMatch(body['markerId'] as String) ||
        body['epoch'] is! String ||
        base64Url.decode(body['epoch'] as String).length != 16 ||
        body['records'] is! List) {
      throw const FormatException('Invalid keyboard repair receipt');
    }
  }

  Future<void> _applyRepair(Map<String, dynamic> body) async {
    _validateRepair(body);
    await _applyManifest({
      'kind': importKind,
      'v': 1,
      'epoch': body['epoch'],
      'revision': 0,
      'records': body['records'],
    });
  }

  /// The sole safe partial-abort recovery supported for legacy journals. A
  /// remaining source ID proves delegate() did not reach activate(): it deletes
  /// every source ID and flushes before the native activation call. The one
  /// missing record must be the old pre-FS manifest, authenticated either by
  /// the new marker's exact source metadata or by a legacy Hive deleted frame.
  /// Exactly one successor must be a newer authenticated pre-FS manifest.
  /// Additional authenticated app-side protocol writes are preserved: the
  /// unchanged retained source records prove native activation was not reached.
  /// No ratchet checkpoint is rolled back and no deleted record is reinserted.
  Future<bool> _recoverReplacedPreFsManifest({
    required List<V3LmfStoredRecord> all,
    required V3LmfStoredRecord marker,
    required _Marker parsed,
  }) async {
    final byId = {for (final record in all) record.storageId: record};
    final absent = parsed.ids.where((id) => !byId.containsKey(id)).toList();
    if (absent.length != 1 || parsed.ids.length < 2) {
      final retained = parsed.ids.length - absent.length;
      _diagnosticStage?.call(retained == 0
          ? 'custodyRetainedNone'
          : retained == 1
              ? 'custodyRetainedOne'
              : 'custodyRetainedMultiple');
      final history = privateStore is SystemKeyboardCustodyHistoricalStore
          ? privateStore as SystemKeyboardCustodyHistoricalStore
          : null;
      if (history != null) {
        for (final id in absent) {
          final record = await history.readDeleted(id);
          _diagnosticStage?.call(switch (record?.payload['kind']) {
            'v3_device_key_v1' => 'custodyAbsentDeviceKey',
            'v3_session_checkpoint_v1' => 'custodyAbsentCheckpoint',
            'v3.prefs.pending.manifest' => 'custodyAbsentManifest',
            'v3_handshake_pending_v1' => 'custodyAbsentHandshake',
            'v3_handshake_completion_v1' => 'custodyAbsentCompletion',
            'v3_handshake_frame_v1' => 'custodyAbsentFrame',
            'v3_handshake_frame_done_v1' => 'custodyAbsentFrameDone',
            'v3_handshake_handoff_v1' => 'custodyAbsentHandoff',
            'v3_lmf_effect_v1' => 'custodyAbsentLmfEffect',
            'v3_lmf_out_v1' => 'custodyAbsentLmfOut',
            'v3_lmf_in_v1' => 'custodyAbsentLmfIn',
            'v3_lmf_done_v1' => 'custodyAbsentLmfDone',
            'v3_lmf_replay_v1' => 'custodyAbsentLmfReplay',
            'v3_application_send_group_v1' => 'custodyAbsentSendGroup',
            'v3_application_record_v1' => 'custodyAbsentApplicationRecord',
            'v3_acknowledgement_outbox_v1' => 'custodyAbsentAckOutbox',
            'v3_send_effect_v1' => 'custodyAbsentSendEffect',
            'v3_send_completion_v1' => 'custodyAbsentSendCompletion',
            'v3_keyboard_history_v1' => 'custodyAbsentKeyboardHistory',
            'v3_keyboard_control_outbox_v1' => 'custodyAbsentControlOutbox',
            null => 'custodyAbsentHistoryMissing',
            _ => 'custodyAbsentOther',
          });
        }
      }
      _diagnosticStage?.call('custodyAbsentShapeMismatch');
      return false;
    }
    _diagnosticStage?.call('custodyOneAbsentRecord');
    final abortProof = parsed.preFsAbort;
    if (abortProof != null) {
      if (absent.single != abortProof.id) return false;
      final retained = <V3LmfStoredRecord>[
        for (final id in parsed.ids)
          if (id != abortProof.id) byId[id]!,
      ];
      final bytes = SystemKeyboardRecordSnapshot.encode(retained);
      try {
        if (crypto.sha256.convert(bytes).toString() != abortProof.otherDigest) {
          return false;
        }
      } finally {
        bytes.fillRange(0, bytes.length, 0);
      }
      return _finishReplacedPreFsManifest(
        all: all,
        marker: marker,
        parsed: parsed,
        oldRevision: abortProof.revision,
      );
    }
    final history = privateStore is SystemKeyboardCustodyHistoricalStore
        ? privateStore as SystemKeyboardCustodyHistoricalStore
        : null;
    if (history == null) {
      _diagnosticStage?.call('custodyHistoryUnavailable');
      return false;
    }
    final missing = await history.readDeleted(absent.single);
    _diagnosticStage?.call(switch (missing?.payload['kind']) {
      'v3.prefs.pending.manifest' => 'custodyAbsentManifest',
      'v3_device_key_v1' => 'custodyAbsentDeviceKey',
      'v3_session_checkpoint_v1' => 'custodyAbsentCheckpoint',
      'v3_handshake_pending_v1' => 'custodyAbsentHandshake',
      'v3_handshake_completion_v1' => 'custodyAbsentCompletion',
      'v3_handshake_frame_v1' => 'custodyAbsentFrame',
      'v3_handshake_frame_done_v1' => 'custodyAbsentFrameDone',
      'v3_lmf_effect_v1' => 'custodyAbsentLmfEffect',
      'v3_lmf_out_v1' => 'custodyAbsentLmfOut',
      'v3_lmf_in_v1' => 'custodyAbsentLmfIn',
      'v3_lmf_done_v1' => 'custodyAbsentLmfDone',
      'v3_lmf_replay_v1' => 'custodyAbsentLmfReplay',
      'v3_application_send_group_v1' => 'custodyAbsentSendGroup',
      'v3_application_record_v1' => 'custodyAbsentApplicationRecord',
      'v3_keyboard_history_v1' => 'custodyAbsentKeyboardHistory',
      'v3_keyboard_control_outbox_v1' => 'custodyAbsentControlOutbox',
      null => 'custodyAbsentHistoryMissing',
      _ => 'custodyAbsentOther',
    });
    if (missing?.payload['kind'] != 'v3.prefs.pending.manifest' ||
        missing!.payload['version'] != 1) {
      _diagnosticStage?.call('custodyDeletedManifestUnavailable');
      return false;
    }
    _diagnosticStage?.call('custodyDeletedManifestReady');
    final oldRevision = missing.payload['revision'];
    if (oldRevision is! int || oldRevision < 0) {
      _diagnosticStage?.call('custodyOldRevisionInvalid');
      return false;
    }

    final original = <V3LmfStoredRecord>[
      for (final id in parsed.ids) byId[id] ?? missing,
    ];
    final bytes = SystemKeyboardRecordSnapshot.encode(original);
    try {
      if (crypto.sha256.convert(bytes).toString() != parsed.initialDigest) {
        _diagnosticStage?.call('custodyOriginalDigestMismatch');
        return false;
      }
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }

    return _finishReplacedPreFsManifest(
      all: all,
      marker: marker,
      parsed: parsed,
      oldRevision: oldRevision,
    );
  }

  Future<void> _finishIntactPrivateAbort({
    required List<V3LmfStoredRecord> all,
    required V3LmfStoredRecord marker,
  }) async {
    final selected = SystemKeyboardWorkingSet.select(all);
    final bytes = SystemKeyboardRecordSnapshot.encode(selected);
    bytes.fillRange(0, bytes.length, 0);
    final latest = await privateStore.readAll();
    final byId = {for (final record in all) record.storageId: record};
    if (latest.length != all.length ||
        latest.any(
          (record) =>
              byId[record.storageId] == null ||
              jsonEncode(byId[record.storageId]!.payload) !=
                  jsonEncode(record.payload),
        ) ||
        await native.hasPending()) {
      throw StateError('Private keyboard abort changed before commit');
    }
    for (final receipt in all.where((r) => r.payload['kind'] == preparedKind)) {
      await privateStore.delete(receipt.storageId);
    }
    for (final backup in all.where((r) => r.payload['kind'] == backupKind)) {
      await privateStore.delete(backup.storageId);
    }
    await privateStore.flush();
    await privateStore.delete(marker.storageId);
    await privateStore.flush();
  }

  /// A v3 marker without a prepared receipt proves this delegation never
  /// deleted private sources or activated the keyboard. Authenticated V3
  /// records may have changed while the attempted native prepare failed.
  Future<void> _finishUnpreparedPrivateAbort({
    required List<V3LmfStoredRecord> all,
    required V3LmfStoredRecord marker,
  }) async {
    final selected = SystemKeyboardWorkingSet.select(all);
    if (selected.isEmpty) {
      throw StateError('Keyboard private working set is unavailable');
    }
    final bytes = SystemKeyboardRecordSnapshot.encode(selected);
    bytes.fillRange(0, bytes.length, 0);
    final latest = await privateStore.readAll();
    final byId = {for (final record in all) record.storageId: record};
    if (latest.length != all.length ||
        latest.any((record) =>
            byId[record.storageId] == null ||
            jsonEncode(byId[record.storageId]!.payload) !=
                jsonEncode(record.payload)) ||
        await native.hasPending()) {
      throw StateError('Private keyboard state changed before abort');
    }
    await privateStore.delete(marker.storageId);
    await privateStore.flush();
  }

  // Read-only, coarse fixture diagnostics. They never authorize a reset and
  // never include record IDs, key material or payload contents in a trace.
  void _traceResetCandidate(List<V3LmfStoredRecord> all, _Marker marker) {
    if (_diagnosticStage == null) return;
    try {
      final originals = marker.ids.toSet();
      final extra = SystemKeyboardWorkingSet.select(all)
          .where((record) => !originals.contains(record.storageId))
          .toList();
      if (extra.isEmpty) {
        _diagnosticStage.call('resetCandidateNoExtra');
      } else if (extra.length > 1) {
        _diagnosticStage.call('resetCandidateMultipleExtras');
        final kinds = extra.map((record) => record.payload['kind']).toSet();
        if (kinds.contains('v3_session_checkpoint_v1')) {
          _diagnosticStage.call('resetCandidateHasCheckpoint');
        } else if (kinds.every((kind) =>
            kind == 'v3.prefs.pending.manifest' ||
            kind == 'v3_handshake_pending_v1' ||
            kind == 'v3_device_key_v1')) {
          _diagnosticStage.call('resetCandidateOnlyPending');
        } else {
          _diagnosticStage.call('resetCandidateHasOtherWorkingState');
        }
      } else if (extra.single.payload['kind'] == 'v3.prefs.pending.manifest') {
        _diagnosticStage.call('resetCandidateOneManifest');
      } else {
        _diagnosticStage.call('resetCandidateOtherExtra');
        if (extra.single.payload['kind'] == 'v3_session_checkpoint_v1') {
          _diagnosticStage.call('resetCandidateHasCheckpoint');
        }
      }
    } catch (_) {
      _diagnosticStage.call('resetCandidateUnknown');
    }
  }

  bool _validPreparedReceipt(List<V3LmfStoredRecord> receipts, _Marker marker) {
    if (marker.version < 3) return receipts.isEmpty;
    if (receipts.isEmpty) return true;
    if (receipts.length != 1) return false;
    final body = receipts.single.payload;
    return body.length == 3 &&
        body['kind'] == preparedKind &&
        body['v'] == 1 &&
        body['epoch'] == base64Url.encode(marker.epoch);
  }

  bool _validActivationReceipt(
      List<V3LmfStoredRecord> receipts, _Marker marker) {
    if (marker.version < 4) return receipts.isEmpty;
    if (receipts.isEmpty) return true;
    if (receipts.length != 1) return false;
    final body = receipts.single.payload;
    return body.length == 3 &&
        body['kind'] == activationKind &&
        body['v'] == 1 &&
        body['epoch'] == base64Url.encode(marker.epoch);
  }

  bool _validAbortSnapshot(List<V3LmfStoredRecord> backups,
      V3LmfStoredRecord marker, _Marker parsed) {
    if (parsed.version < 4) return backups.isEmpty;
    if (backups.isEmpty) return true;
    if (backups.length != 1) return false;
    final body = backups.single.payload;
    return body.length == 6 &&
        body['kind'] == backupKind &&
        body['v'] == 1 &&
        body['markerId'] == marker.storageId &&
        body['epoch'] == base64Url.encode(parsed.epoch) &&
        body['digest'] == parsed.initialDigest &&
        body['snapshot'] is String &&
        (body['snapshot'] as String).isNotEmpty &&
        (body['snapshot'] as String).length <=
            (SystemKeyboardRecordSnapshot.maxBytes * 4 ~/ 3) + 8;
  }

  /// A v4 marker contains the exact authenticated source snapshot. When the
  /// activation-intent receipt is absent, activate() was never called. Restore
  /// only unchanged source records, and only if no other protocol write has
  /// appeared. The receipt makes restoration crash-idempotent.
  Future<void> _recoverPreActivationSnapshot({
    required List<V3LmfStoredRecord> all,
    required V3LmfStoredRecord marker,
    required _Marker parsed,
    required V3LmfStoredRecord backup,
  }) async {
    final encoded = backup.payload['snapshot'] as String;
    final bytes = base64Url.decode(encoded);
    late final List<V3LmfStoredRecord> original;
    try {
      if (crypto.sha256.convert(bytes).toString() != parsed.initialDigest) {
        throw const FormatException('Pre-activation snapshot digest mismatch');
      }
      original = SystemKeyboardRecordSnapshot.decode(bytes);
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
    if (original.length != parsed.ids.length ||
        [for (final record in original) record.storageId].join('|') !=
            parsed.ids.join('|')) {
      throw const FormatException('Pre-activation source IDs mismatch');
    }
    final current = {for (final record in all) record.storageId: record};
    for (final record in original) {
      final retained = current[record.storageId];
      if (retained != null &&
          jsonEncode(retained.payload) != jsonEncode(record.payload)) {
        throw StateError('Pre-activation source changed');
      }
    }
    final originalIds = parsed.ids.toSet();
    if (SystemKeyboardWorkingSet.select(all)
        .any((record) => !originalIds.contains(record.storageId))) {
      throw StateError('Concurrent protocol writes block custody abort');
    }
    final latest = await privateStore.readAll();
    if (latest.length != all.length ||
        latest.any((record) =>
            current[record.storageId] == null ||
            jsonEncode(current[record.storageId]!.payload) !=
                jsonEncode(record.payload)) ||
        await native.hasPending()) {
      throw StateError('Pre-activation state changed before repair');
    }
    final missing = original
        .where((record) => !current.containsKey(record.storageId))
        .toList();
    final prepared = <Map<String, dynamic>>[];
    for (final record in missing) {
      prepared.add(
          (await privateStore.prepare(record.storageId, record.payload))
              .toJson());
    }
    final receipt = <String, dynamic>{
      'kind': repairKind,
      'v': 1,
      'markerId': marker.storageId,
      'epoch': base64Url.encode(parsed.epoch),
      'records': prepared,
    };
    final receiptId = await privateStore.write(receipt);
    await privateStore.flush();
    await _applyRepair(receipt);
    await privateStore.delete(backup.storageId);
    for (final row
        in all.where((record) => record.payload['kind'] == preparedKind)) {
      await privateStore.delete(row.storageId);
    }
    await privateStore.flush();
    await privateStore.delete(marker.storageId);
    await privateStore.flush();
    await privateStore.delete(receiptId);
    await privateStore.flush();
  }

  Future<bool> _finishReplacedPreFsManifest({
    required List<V3LmfStoredRecord> all,
    required V3LmfStoredRecord marker,
    required _Marker parsed,
    required int oldRevision,
  }) async {
    final byId = {for (final record in all) record.storageId: record};
    final originalIds = parsed.ids.toSet();
    final selected = SystemKeyboardWorkingSet.select(all);
    final extra = selected
        .where((record) => !originalIds.contains(record.storageId))
        .toList();
    final successors = extra
        .where(
            (record) => record.payload['kind'] == 'v3.prefs.pending.manifest')
        .toList();
    if (successors.length != 1 || successors.single.payload['version'] != 1) {
      if (successors.isEmpty && extra.isEmpty) {
        _diagnosticStage?.call('custodyExtraNone');
      } else if (successors.length > 1) {
        _diagnosticStage?.call('custodyExtraMultiple');
      } else {
        final kind = successors.isNotEmpty
            ? successors.single.payload['kind']
            : extra.first.payload['kind'];
        _diagnosticStage?.call(switch (kind) {
          'v3_session_checkpoint_v1' => 'custodyExtraCheckpoint',
          'v3_handshake_pending_v1' => 'custodyExtraHandshake',
          'v3_keyboard_history_v1' => 'custodyExtraHistory',
          'v3.prefs.pending.manifest' => 'custodyExtraManifestInvalid',
          _ => 'custodyExtraOther',
        });
      }
      _diagnosticStage?.call('custodyNewManifestShapeMismatch');
      return false;
    }
    if (successors.single.payload['revision'] is! int ||
        (successors.single.payload['revision'] as int) <= oldRevision) {
      _diagnosticStage?.call('custodyNewRevisionInvalid');
      return false;
    }

    // No concurrent app-side protocol mutation may cross the final receipt.
    // Aux records are immutable per storage ID; compare full authenticated
    // payloads as well as IDs before deleting the marker.
    final latest = await privateStore.readAll();
    final latestById = {for (final record in latest) record.storageId: record};
    if (latestById[marker.storageId] == null ||
        jsonEncode(latestById[marker.storageId]!.payload) !=
            jsonEncode(marker.payload) ||
        latest.length != all.length ||
        latest.any(
          (record) =>
              byId[record.storageId] == null ||
              jsonEncode(byId[record.storageId]!.payload) !=
                  jsonEncode(record.payload),
        ) ||
        await native.hasPending()) {
      _diagnosticStage?.call('custodyFinalReceiptChanged');
      return false;
    }
    for (final receipt in all.where((r) => r.payload['kind'] == preparedKind)) {
      await privateStore.delete(receipt.storageId);
    }
    for (final backup in all.where((r) => r.payload['kind'] == backupKind)) {
      await privateStore.delete(backup.storageId);
    }
    await privateStore.flush();
    await privateStore.delete(marker.storageId);
    await privateStore.flush();
    return true;
  }

  /// Reports only the precise, unrecoverable case. A transient I/O failure,
  /// corrupt native state or an interrupted but intact delegation is not a
  /// reason to abandon FS. No storage is changed by this probe.
  Future<bool> hasLostAuthoritativeState() => _exclusive(() async {
        _diagnosticStage?.call('resetProbeReadStart');
        final all = await privateStore.readAll();
        final markers =
            all.where((r) => r.payload['kind'] == markerKind).toList();
        if (markers.length != 1 ||
            all.any(
              (r) =>
                  r.payload['kind'] == importKind ||
                  r.payload['kind'] == resetKind ||
                  r.payload['kind'] == repairKind,
            )) {
          _diagnosticStage?.call('resetProbeJournalNotEligible');
          return false;
        }
        final parsed = _Marker.parse(markers.single.payload);
        try {
          final prepared =
              all.where((r) => r.payload['kind'] == preparedKind).toList();
          final activations =
              all.where((r) => r.payload['kind'] == activationKind).toList();
          if (!_validPreparedReceipt(prepared, parsed)) return false;
          if (!_validActivationReceipt(activations, parsed)) return false;
          if (parsed.version == 3 && prepared.isEmpty) return false;
          if (parsed.version == 4 && activations.isEmpty) return false;
          if (await native.hasPending()) return false;
          final lost = !_originalBaselineIsIntact(all, parsed);
          _diagnosticStage?.call(
              lost ? 'resetProbeBaselineLost' : 'resetProbeBaselineIntact');
          return lost;
        } finally {
          parsed.close();
        }
      });

  /// Explicit, user-confirmed recovery when the delegated native snapshot is
  /// gone. A durable reset receipt makes interruption safe. Only the exact
  /// records named by the old delegation and, if present, its sole newer
  /// pre-FS pending manifest are discarded. Identity, contacts, contact policy
  /// and presentation/history records stay private and intact.
  /// A fresh V3 device key is generated on the next runtime open.
  Future<void> abandonLostAuthoritativeState() => _exclusive(() async {
        _diagnosticStage?.call('resetCommitReadStart');
        final all = await privateStore.readAll();
        final markers =
            all.where((r) => r.payload['kind'] == markerKind).toList();
        final imports =
            all.where((r) => r.payload['kind'] == importKind).toList();
        final resets =
            all.where((r) => r.payload['kind'] == resetKind).toList();
        if (all.any((r) => r.payload['kind'] == repairKind)) {
          _diagnosticStage?.call('resetCommitRepairBlocked');
          throw StateError('Keyboard repair must finish before reset');
        }
        if (resets.isNotEmpty) {
          _diagnosticStage?.call('resetCommitResumeReceipt');
          await _finishConfirmedReset(
            all: all,
            markers: markers,
            imports: imports,
            resets: resets,
          );
          return;
        }
        if (markers.length != 1 || imports.isNotEmpty) {
          _diagnosticStage?.call('resetCommitJournalBlocked');
          throw StateError('No lost keyboard custody to reset');
        }
        final marker = markers.single;
        final parsed = _Marker.parse(marker.payload);
        try {
          final prepared =
              all.where((r) => r.payload['kind'] == preparedKind).toList();
          final activations =
              all.where((r) => r.payload['kind'] == activationKind).toList();
          if (!_validPreparedReceipt(prepared, parsed) ||
              !_validActivationReceipt(activations, parsed) ||
              (parsed.version == 3 && prepared.isEmpty) ||
              (parsed.version == 4 && activations.isEmpty)) {
            _diagnosticStage?.call('resetCommitPreparedBlocked');
            throw StateError(
                'Keyboard preparation is recoverable or ambiguous');
          }
          // A single native reclaim is the authoritative check. It must report
          // both custody leaves missing, rather than an I/O or auth error.
          try {
            _diagnosticStage?.call('resetCommitNativeCheck');
            final snapshot = await native.reclaim(parsed.epoch, parsed.key);
            snapshot.bytes.fillRange(0, snapshot.bytes.length, 0);
            _diagnosticStage?.call('resetCommitNativeRecoverable');
            throw StateError('Keyboard custody remains recoverable');
          } on SystemKeyboardCustodyMissing {
            // Expected only when BOTH native leaves are absent.
          }
          if (_originalBaselineIsIntact(all, parsed)) {
            _diagnosticStage?.call('resetCommitBaselineRecoverable');
            throw StateError('Keyboard baseline remains recoverable');
          }
          final selected = SystemKeyboardWorkingSet.select(all);
          final originalIds = parsed.ids.toSet();
          final extra = selected
              .where((record) => !originalIds.contains(record.storageId))
              .toList();
          if (extra.length > 1 ||
              extra.any(
                (record) =>
                    record.payload['kind'] != 'v3.prefs.pending.manifest' ||
                    record.payload['version'] != 1 ||
                    record.payload['revision'] is! int ||
                    (record.payload['revision'] as int) < 0,
              )) {
            _diagnosticStage?.call('resetCommitOtherProtocolBlocked');
            throw StateError('Unrelated V3 protocol state blocks reset');
          }
          _diagnosticStage?.call('resetCommitReceiptStart');
          await privateStore.write({
            'kind': resetKind,
            'v': 2,
            'markerId': marker.storageId,
            'epoch': base64Url.encode(parsed.epoch),
            'extraIds': extra.map((record) => record.storageId).toList(),
          });
          await privateStore.flush();
          _diagnosticStage?.call('resetCommitReceiptReady');
          final current = await privateStore.readAll();
          await _finishConfirmedReset(
            all: current,
            markers: [marker],
            imports: const [],
            resets:
                current.where((r) => r.payload['kind'] == resetKind).toList(),
          );
          _diagnosticStage?.call('resetCommitFinished');
        } finally {
          parsed.close();
        }
      });

  bool _originalBaselineIsIntact(List<V3LmfStoredRecord> all, _Marker marker) {
    final byId = {for (final record in all) record.storageId: record};
    if (marker.ids.any((id) => !byId.containsKey(id))) return false;
    final bytes = SystemKeyboardRecordSnapshot.encode(
      marker.ids.map((id) => byId[id]!),
    );
    try {
      return crypto.sha256.convert(bytes).toString() == marker.initialDigest;
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  Future<void> _finishConfirmedReset({
    required List<V3LmfStoredRecord> all,
    required List<V3LmfStoredRecord> markers,
    required List<V3LmfStoredRecord> imports,
    required List<V3LmfStoredRecord> resets,
  }) async {
    if (resets.length != 1 || imports.isNotEmpty || markers.length > 1) {
      throw StateError('Ambiguous keyboard reset journal');
    }
    final reset = resets.single;
    final body = reset.payload;
    final version = body['v'];
    if ((version != 1 && version != 2) ||
        body.length != (version == 1 ? 4 : 5) ||
        body['kind'] != resetKind ||
        body['markerId'] is! String ||
        !RegExp(r'^r[A-Za-z0-9_-]{22}$').hasMatch(body['markerId'] as String) ||
        body['epoch'] is! String ||
        base64Url.decode(body['epoch'] as String).length != 16 ||
        (version == 2 && body['extraIds'] is! List)) {
      throw const FormatException('Invalid keyboard reset journal');
    }
    final extraIds = <String>[];
    if (version == 2) {
      final raw = body['extraIds'] as List;
      if (raw.length > 1 ||
          raw.any(
            (id) =>
                id is! String || !RegExp(r'^r[A-Za-z0-9_-]{22}$').hasMatch(id),
          )) {
        throw const FormatException('Invalid keyboard reset extras');
      }
      extraIds.addAll(raw.cast<String>());
    }
    if (await native.hasPending()) {
      throw StateError('Native keyboard state appeared during reset');
    }
    if (markers.isNotEmpty) {
      final marker = markers.single;
      if (body['markerId'] != marker.storageId) {
        throw StateError('Keyboard reset marker mismatch');
      }
      final parsed = _Marker.parse(marker.payload);
      try {
        if (body['epoch'] != base64Url.encode(parsed.epoch)) {
          throw StateError('Keyboard reset epoch mismatch');
        }
        if (extraIds.any(parsed.ids.contains)) {
          throw StateError('Keyboard reset source overlaps an extra');
        }
        final allowedIds = {...parsed.ids, ...extraIds};
        final remaining = SystemKeyboardWorkingSet.select(
          all,
        ).map((record) => record.storageId).toSet();
        if (!allowedIds.containsAll(remaining)) {
          throw StateError('Unrelated V3 protocol state blocks reset');
        }
        for (final id in allowedIds) {
          await privateStore.delete(id);
        }
        await privateStore.flush();
        for (final receipt
            in all.where((r) => r.payload['kind'] == preparedKind)) {
          await privateStore.delete(receipt.storageId);
        }
        for (final receipt
            in all.where((r) => r.payload['kind'] == activationKind)) {
          await privateStore.delete(receipt.storageId);
        }
        for (final backup
            in all.where((r) => r.payload['kind'] == backupKind)) {
          await privateStore.delete(backup.storageId);
        }
        await privateStore.flush();
        await privateStore.delete(marker.storageId);
        await privateStore.flush();
      } finally {
        parsed.close();
      }
    } else if (body['markerId'] is! String) {
      throw StateError('Keyboard reset marker missing');
    }
    await privateStore.delete(reset.storageId);
    await privateStore.flush();
  }

  Future<void> _applyManifest(Map<String, dynamic> body) async {
    if (body.length != 5 ||
        body['kind'] != importKind ||
        body['v'] != 1 ||
        body['epoch'] is! String ||
        base64Url.decode(body['epoch'] as String).length != 16 ||
        body['revision'] is! int ||
        (body['revision'] as int) < 0 ||
        (body['revision'] as int) > SystemKeyboardRecordSnapshot.maxRevision ||
        body['records'] is! List) {
      throw const FormatException('Invalid keyboard import journal');
    }
    final rows = body['records'] as List;
    if (rows.length > SystemKeyboardRecordSnapshot.maxRecords) {
      throw const FormatException('Oversized keyboard import journal');
    }
    final ids = <String>{};
    final prepared = <PreparedAuxRecord>[];
    for (final row in rows) {
      if (row is! Map<String, dynamic>) {
        throw const FormatException('Invalid keyboard import row');
      }
      final record = PreparedAuxRecord.fromJson(row);
      if (!ids.add(record.storageId)) {
        throw const FormatException('Duplicate keyboard import row');
      }
      prepared.add(record);
    }
    for (final record in prepared) {
      await privateStore.apply(record);
    }
    await privateStore.flush();
  }

  Future<T> _exclusive<T>(Future<T> Function() operation) async {
    if (_busy) {
      throw StateError('Keyboard custody operation already in progress');
    }
    _busy = true;
    try {
      return await operation();
    } finally {
      _busy = false;
    }
  }

  static Uint8List _randomBytes(int count) {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(count, (_) => random.nextInt(256)),
    );
  }
}

/// The marker records only the identity and revision of the one replaceable
/// pre-FS manifest. A digest of every *other* source record proves that a
/// missing native snapshot cannot make an old ratchet checkpoint authoritative.
final class _PreFsAbortProof {
  const _PreFsAbortProof(this.id, this.revision, this.otherDigest);

  final String id;
  final int revision;
  final String otherDigest;

  static _PreFsAbortProof? forWorkingSet(List<V3LmfStoredRecord> records) {
    final pending = records
        .where(
          (record) => record.payload['kind'] == 'v3.prefs.pending.manifest',
        )
        .toList();
    if (pending.length != 1 || records.length < 2) return null;
    final source = pending.single;
    final revision = source.payload['revision'];
    if (source.payload['version'] != 1 || revision is! int || revision < 0) {
      return null;
    }
    final others = records
        .where((record) => record.storageId != source.storageId)
        .toList();
    final bytes = SystemKeyboardRecordSnapshot.encode(others);
    try {
      return _PreFsAbortProof(
        source.storageId,
        revision,
        crypto.sha256.convert(bytes).toString(),
      );
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  Map<String, Object> toJson() => {
        'id': id,
        'revision': revision,
        'otherDigest': otherDigest,
      };

  static _PreFsAbortProof? parse(Object? value, List<String> ids) {
    if (value == null) return null;
    if (value is! Map<String, dynamic> ||
        value.length != 3 ||
        value['id'] is! String ||
        !ids.contains(value['id']) ||
        value['revision'] is! int ||
        (value['revision'] as int) < 0 ||
        value['otherDigest'] is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(value['otherDigest'] as String)) {
      throw const FormatException('Invalid keyboard pre-FS abort proof');
    }
    return _PreFsAbortProof(
      value['id'] as String,
      value['revision'] as int,
      value['otherDigest'] as String,
    );
  }
}

final class _Marker {
  _Marker(this.version, this.epoch, this.key, this.ids, this.initialDigest,
      this.preFsAbort);
  final int version;
  final Uint8List epoch;
  final Uint8List key;
  final List<String> ids;
  final String initialDigest;
  final _PreFsAbortProof? preFsAbort;
  static _Marker parse(Map<String, dynamic> value) {
    final version = value['v'];
    if ((version != 1 && version != 2 && version != 3 && version != 4) ||
        value.length != (version == 1 ? 6 : 7) ||
        (version != 1 && !value.containsKey('preFsAbort')) ||
        value['epoch'] is! String ||
        value['key'] is! String ||
        value['ids'] is! List ||
        value['initialDigest'] is! String) {
      throw const FormatException('Invalid keyboard custody journal');
    }
    final epoch = base64Url.decode(value['epoch'] as String);
    final key = base64Url.decode(value['key'] as String);
    final rawIds = value['ids'] as List;
    final ids = <String>[];
    if (epoch.length != 16 ||
        key.length != 32 ||
        rawIds.isEmpty ||
        rawIds.length > SystemKeyboardRecordSnapshot.maxRecords ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(value['initialDigest'] as String)) {
      epoch.fillRange(0, epoch.length, 0);
      key.fillRange(0, key.length, 0);
      throw const FormatException('Invalid keyboard custody binding');
    }
    for (final id in rawIds) {
      if (id is! String ||
          !RegExp(r'^r[A-Za-z0-9_-]{22}$').hasMatch(id) ||
          ids.contains(id)) {
        epoch.fillRange(0, epoch.length, 0);
        key.fillRange(0, key.length, 0);
        throw const FormatException('Invalid keyboard custody source ID');
      }
      ids.add(id);
    }
    try {
      final proof = version != 1
          ? _PreFsAbortProof.parse(value['preFsAbort'], ids)
          : null;
      return _Marker(version as int, epoch, key, ids,
          value['initialDigest'] as String, proof);
    } catch (_) {
      epoch.fillRange(0, epoch.length, 0);
      key.fillRange(0, key.length, 0);
      rethrow;
    }
  }

  void close() {
    epoch.fillRange(0, epoch.length, 0);
    key.fillRange(0, key.length, 0);
  }
}
