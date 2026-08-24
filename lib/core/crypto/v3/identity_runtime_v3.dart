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

import '../models.dart';
import '../seed_service.dart';
import 'local_identity_v3.dart';
import 'ml_kem_768.dart';
import 'ml_kem_768_ffi.dart';
import 'public_identity_v3.dart';
import 'public_identity_v3_validator.dart';

typedef V3MlKemBackendLoader = MlKem768Backend Function();
typedef V3IdentityHandleEvictionHandler = Future<void> Function(
  V3LocalIdentityHandle handle,
);

/// Owns protocol-v3 identity private material for one application process.
///
/// The recovery phrase remains the only persisted recovery root. ML-KEM
/// private bytes never enter the Dart model or secure storage: they are
/// regenerated into the native opaque handle and destroyed by [close].
final class V3IdentityRuntime {
  V3IdentityRuntime({
    required SeedService seedService,
    V3MlKemBackendLoader? backendLoader,
  })  : _seedService = seedService,
        _backendLoader = backendLoader ?? MlKem768FfiBackend.openPackaged;

  final SeedService _seedService;
  final V3MlKemBackendLoader _backendLoader;

  MlKem768Backend? _backend;
  V3LocalIdentityHandle? _primary;
  String? _primaryLegacyIdentityId;
  V3LocalIdentityHandle? _passphrase;
  Future<void> _operationTail = Future<void>.value();
  Object? _evictionOwner;
  V3IdentityHandleEvictionHandler? _evictionHandler;
  bool _isClosed = false;

  /// Registers the sole application-session owner that must drain before an
  /// identity handle is replaced or destroyed.
  Object registerHandleEvictionHandler(
    V3IdentityHandleEvictionHandler handler,
  ) {
    _ensureOpen();
    if (_evictionHandler != null) {
      throw StateError(
        'Layergram v3 identity runtime already has a session owner',
      );
    }
    final owner = Object();
    _evictionOwner = owner;
    _evictionHandler = handler;
    return owner;
  }

  void unregisterHandleEvictionHandler(Object owner) {
    if (!identical(_evictionOwner, owner)) return;
    _evictionOwner = null;
    _evictionHandler = null;
  }

  /// Returns the complete deterministic v3 public identity for [local].
  ///
  /// The native private handle remains owned by this runtime so the same
  /// instance can later authenticate handshakes without re-exporting secrets.
  Future<V3PublicIdentity> primaryPublicIdentity(LocalIdentity local) =>
      _serialized(() => _primaryPublicIdentity(local));

  Future<V3PublicIdentity> _primaryPublicIdentity(LocalIdentity local) async {
    _ensureOpen();
    var handle = _primary;
    if (handle == null ||
        handle.isClosed ||
        _primaryLegacyIdentityId != local.identityId) {
      await _closeHandle(handle);
      final backend = _backend ??= _backendLoader();
      handle = await V3LocalIdentityFactory(
        seedService: _seedService,
        mlKem768Backend: backend,
      ).restorePrimary(
        mnemonic: local.mnemonic,
        displayName: local.displayName,
      );
      _primary = handle;
      _primaryLegacyIdentityId = local.identityId;
    }

    final identity = handle.publicIdentity;
    if (identity.displayName == local.displayName) return identity;
    return V3PublicIdentity(
      x25519PublicKey: identity.x25519PublicKey,
      mlKem768PublicKey: identity.mlKem768PublicKey,
      displayName: local.displayName,
      suite: identity.suite,
      flags: identity.flags,
    );
  }

  /// Returns the runtime-owned handle for session/handshake integration.
  /// Callers must not close it; [V3IdentityRuntime] remains the sole owner.
  Future<V3LocalIdentityHandle> primaryHandle(LocalIdentity local) =>
      _serialized(() async {
        await _primaryPublicIdentity(local);
        return _primary!;
      });

  /// Validates imported public material with the same pinned ML-KEM backend
  /// used by local identities before any contact record is persisted.
  Future<V3StructurallyValidatedPublicIdentity> validateRemotePublicIdentity(
    V3PublicIdentity identity,
  ) =>
      _serialized(() async {
        _ensureOpen();
        final backend = _backend ??= _backendLoader();
        return V3PublicIdentityValidator(
          mlKem768Backend: backend,
        ).validate(identity);
      });

  /// Replaces the current ephemeral passphrase identity.
  ///
  /// No passphrase-derived private material is persisted. Calling this method
  /// again destroys the previous native handle before installing the new one.
  Future<V3PublicIdentity> activatePassphrase({
    required String mnemonic,
    required String passphrase,
    required String displayName,
  }) =>
      _serialized(() async {
        _ensureOpen();
        await _deactivatePassphrase();
        final backend = _backend ??= _backendLoader();
        final handle = await V3LocalIdentityFactory(
          seedService: _seedService,
          mlKem768Backend: backend,
        ).restorePassphrase(
          mnemonic: mnemonic,
          passphrase: passphrase,
          displayName: displayName,
        );
        _passphrase = handle;
        return handle.publicIdentity;
      });

  V3LocalIdentityHandle get activePassphraseHandle {
    _ensureOpen();
    final handle = _passphrase;
    if (handle == null || handle.isClosed) {
      throw StateError('Layergram v3 passphrase identity is not active');
    }
    return handle;
  }

  Future<V3LocalIdentityHandle> activePassphraseHandleAsync() =>
      _serialized(() async => activePassphraseHandle);

  Future<void> deactivatePassphrase() => _serialized(_deactivatePassphrase);

  Future<void> _deactivatePassphrase() async {
    final handle = _passphrase;
    _passphrase = null;
    await _closeHandle(handle);
  }

  Future<void> close() => _serialized(() async {
        if (_isClosed) return;
        _isClosed = true;
        final primary = _primary;
        final passphrase = _passphrase;
        _primary = null;
        _passphrase = null;
        _primaryLegacyIdentityId = null;
        try {
          await _closeHandle(primary);
        } finally {
          try {
            await _closeHandle(passphrase);
          } finally {
            _evictionOwner = null;
            _evictionHandler = null;
          }
        }
      }, allowClosed: true);

  Future<void> _closeHandle(V3LocalIdentityHandle? handle) async {
    if (handle == null || handle.isClosed) return;
    final handler = _evictionHandler;
    if (handler != null) {
      await handler(handle);
    }
    await handle.close();
  }

  Future<T> _serialized<T>(
    Future<T> Function() operation, {
    bool allowClosed = false,
  }) {
    final completer = Completer<T>();
    final previous = _operationTail;
    _operationTail = previous.catchError((_) {}).then((_) async {
      try {
        if (_isClosed && !allowClosed) {
          throw StateError('Layergram v3 identity runtime is closed');
        }
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 identity runtime is closed');
    }
  }
}
