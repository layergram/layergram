// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:convert';
import 'dart:typed_data';

import '../../core/crypto/v3/application_session_runtime_v3.dart';
import '../../core/crypto/v3/local_identity_v3.dart';
import '../../core/storage/aux_record_repository.dart';
import 'system_keyboard_custody.dart';

/// Process admission around the durable custody journal. Native revocation is
/// performed independently at the containing app's earliest lifecycle callback.
/// No live grant is reconstructed from the private recovery marker.
final class SystemKeyboardCustodyCoordinator {
  SystemKeyboardCustodyCoordinator({
    required this.native,
    void Function(String stage)? diagnosticStage,
  }) : _diagnosticStage = diagnosticStage;
  final SystemKeyboardCustodyNative native;
  final void Function(String stage)? _diagnosticStage;
  Future<void>? _preparing;
  bool _delegating = false;
  bool _unrecoveredAttempt = false;
  bool get hasUnrecoveredAttempt => _unrecoveredAttempt;
  int _generation = 0;
  SystemKeyboardCustodyGrant? _grant;
  Map<String, Object?>? _configuration;
  Uint8List? _identityKeyMaterial;

  bool get isDelegating => _delegating;
  bool get isPreparing => _preparing != null;

  /// Mandatory factory gate, including ordinary builds after an experimental
  /// installation. A private marker can never be ignored because a flag is off.
  Future<void> beforeRuntimeOpen(
      {required V3LocalIdentityHandle identity,
      required String scopeToken}) async {
    _diagnosticStage?.call('custodyGateEntered');
    if (_delegating) throw StateError('Keyboard owns the protocol scope');
    final pending = _preparing;
    if (pending != null) {
      try {
        await pending;
      } catch (_) {/* Recover the durable outcome below. */}
    }
    if (_delegating) throw StateError('Keyboard owns the protocol scope');
    _diagnosticStage?.call('custodyKeyStart');
    final derived = await identity.deriveAuxStorageKey();
    final key = await derived.extract();
    _diagnosticStage?.call('custodyKeyReady');
    final repository = AuxRecordRepository();
    repository.setActiveContext(scopeToken: scopeToken, auxStorageKey: key);
    try {
      _diagnosticStage?.call('custodyRecoverStart');
      await SystemKeyboardCustody(
              privateStore: SystemKeyboardCustodyAuxStore(repository,
                  diagnosticStage: _diagnosticStage),
              native: native,
              diagnosticStage: _diagnosticStage)
          .recover();
      _diagnosticStage?.call('custodyRecoverReady');
      _unrecoveredAttempt = false;
    } on SystemKeyboardCustodyMissing {
      _diagnosticStage?.call('custodyMissingFailure');
      rethrow;
    } on FormatException {
      _diagnosticStage?.call('custodyFormatFailure');
      rethrow;
    } on StateError {
      _diagnosticStage?.call('custodyStateFailure');
      rethrow;
    } catch (_) {
      _diagnosticStage?.call('custodyOtherFailure');
      rethrow;
    } finally {
      repository.setActiveContext(scopeToken: null, auxStorageKey: null);
      key.destroy();
      derived.destroy();
    }
  }

  /// Metadata is captured by the already-authorized caller before this call.
  /// Once invoked, no parent runtime may reopen until cancellation/recovery.
  Future<void> prepare(
      {required V3ApplicationSessionRuntime runtime,
      required String scopeToken,
      required Map<String, Object?> configuration,
      required Future<void> Function() closeRuntime,
      required bool Function() stillAdmitted}) {
    if (_delegating ||
        _preparing != null ||
        !stillAdmitted() ||
        runtime.isEstablishedSessionOnly) {
      throw StateError('Keyboard delegation is unavailable');
    }
    _delegating = true;
    _unrecoveredAttempt = true;
    final generation = ++_generation;
    final operation = _prepare(
        runtime: runtime,
        scopeToken: scopeToken,
        configuration: configuration,
        closeRuntime: closeRuntime,
        stillAdmitted: () =>
            generation == _generation && _delegating && stillAdmitted());
    _preparing = operation;
    return operation.whenComplete(() {
      if (identical(_preparing, operation)) _preparing = null;
    });
  }

  Future<void> _prepare(
      {required V3ApplicationSessionRuntime runtime,
      required String scopeToken,
      required Map<String, Object?> configuration,
      required Future<void> Function() closeRuntime,
      required bool Function() stillAdmitted}) async {
    _diagnosticStage?.call('custodyDelegateKeyStart');
    final derived = await runtime.localIdentity.deriveAuxStorageKey();
    final key = await derived.extract();
    _diagnosticStage?.call('custodyDelegateKeyReady');
    final repository = AuxRecordRepository();
    repository.setActiveContext(scopeToken: scopeToken, auxStorageKey: key);
    Uint8List? exportedIdentity;
    try {
      if (!stillAdmitted()) throw StateError('Keyboard delegation was revoked');
      exportedIdentity = runtime.localIdentity.exportKeyboardKeyMaterial();
      _diagnosticStage?.call('custodyDelegateIdentityReady');
      await closeRuntime();
      _diagnosticStage?.call('custodyDelegateRuntimeClosed');
      if (!stillAdmitted()) throw StateError('Keyboard delegation was revoked');
      final grant = await SystemKeyboardCustody(
              privateStore: SystemKeyboardCustodyAuxStore(repository),
              native: native,
              diagnosticStage: _diagnosticStage)
          .delegate();
      if (!stillAdmitted()) {
        grant.close();
        throw StateError('Keyboard delegation was revoked');
      }
      _grant = grant;
      _configuration = Map<String, Object?>.unmodifiable(configuration);
      _identityKeyMaterial = exportedIdentity;
      exportedIdentity = null;
    } finally {
      exportedIdentity?.fillRange(0, exportedIdentity.length, 0);
      repository.setActiveContext(scopeToken: null, auxStorageKey: null);
      key.destroy();
      derived.destroy();
    }
  }

  /// Consume the fresh grant exactly once. The native iOS host can redeliver
  /// this same reply only to its pinned client/editor through a fresh lease
  /// inside the original bootstrap window, until ACK or revocation. It never
  /// calls this method again or performs a second custody activation.
  Map<String, Object?>? takeGrant(String editorNonce) {
    final grant = _grant;
    final configuration = _configuration;
    final identityKeyMaterial = _identityKeyMaterial;
    if (!_delegating ||
        grant == null ||
        configuration == null ||
        identityKeyMaterial == null ||
        editorNonce.isEmpty ||
        editorNonce.length > 128) {
      return null;
    }
    _grant = null;
    _configuration = null;
    _identityKeyMaterial = null;
    try {
      return {
        'status': 'ok',
        'mode': 'autonomous-v1',
        'key': base64Encode(grant.key),
        'configuration': {
          ...configuration,
          'epoch': base64Encode(grant.epoch),
          'editorNonce': editorNonce,
          'identityKeyMaterial': base64Encode(identityKeyMaterial),
        }
      };
    } finally {
      identityKeyMaterial.fillRange(0, identityKeyMaterial.length, 0);
      grant.close();
    }
  }

  /// Called synchronously for app resume, lock, identity/passphrase/opt-in
  /// changes. It drops unsent authorization; recovery is the next factory gate.
  void cancel() {
    _generation++;
    _delegating = false;
    _grant?.close();
    _grant = null;
    _configuration = null;
    _identityKeyMaterial?.fillRange(0, _identityKeyMaterial!.length, 0);
    _identityKeyMaterial = null;
  }
}
