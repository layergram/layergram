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

import '../models.dart';
import 'identity_runtime_v3.dart';
import 'local_identity_v3.dart';

/// Minimal lifecycle boundary implemented by the full application runtime.
abstract interface class V3ApplicationRuntimeSession {
  Future<void> close();
}

typedef V3ApplicationRuntimeFactory<T extends V3ApplicationRuntimeSession>
    = Future<T> Function({
  required V3LocalIdentityHandle localIdentity,
  required String scopeToken,
});

/// Serializes one protocol-v3 application runtime across identity contexts.
///
/// The owner closes the old primary/passphrase scope before opening the next
/// one. It also registers with [V3IdentityRuntime], so an identity handle can
/// never be replaced or destroyed while a session runtime still references it.
final class V3ApplicationRuntimeOwner<T extends V3ApplicationRuntimeSession> {
  V3ApplicationRuntimeOwner({
    required V3IdentityRuntime identityRuntime,
    required V3ApplicationRuntimeFactory<T> runtimeFactory,
  })  : _identityRuntime = identityRuntime,
        _runtimeFactory = runtimeFactory {
    _evictionRegistration = _identityRuntime.registerHandleEvictionHandler(
      _evictIdentityHandle,
    );
  }

  final V3IdentityRuntime _identityRuntime;
  final V3ApplicationRuntimeFactory<T> _runtimeFactory;
  late final Object _evictionRegistration;

  Future<void> _operationTail = Future<void>.value();
  T? _current;
  V3LocalIdentityHandle? _currentIdentity;
  String? _currentContextId;
  bool _closed = false;

  T? get current => _current;

  /// Opens or reuses the runtime for one exact primary/passphrase context.
  Future<T> open({
    required LocalIdentity recoveryIdentity,
    required String scopeToken,
    required String contextId,
    required bool usePassphraseIdentity,
  }) {
    return _serialized(() async {
      _ensureOpen();
      final current = _current;
      if (current != null && _currentContextId == contextId) {
        return current;
      }

      await _closeCurrent();
      final identity = usePassphraseIdentity
          ? await _identityRuntime.activePassphraseHandleAsync()
          : await _identityRuntime.primaryHandle(recoveryIdentity);
      _currentIdentity = identity;
      _currentContextId = contextId;
      try {
        final opened = await _runtimeFactory(
          localIdentity: identity,
          scopeToken: scopeToken,
        );
        _current = opened;
        return opened;
      } catch (_) {
        _currentIdentity = null;
        _currentContextId = null;
        rethrow;
      }
    });
  }

  /// Drains the current scope without destroying the identity runtime.
  Future<void> closeCurrent() => _serialized(_closeCurrent);

  Future<void> close() => _serialized(() async {
        if (_closed) return;
        try {
          await _closeCurrent();
        } finally {
          _identityRuntime.unregisterHandleEvictionHandler(
            _evictionRegistration,
          );
          _closed = true;
        }
      }, allowClosed: true);

  Future<void> _evictIdentityHandle(V3LocalIdentityHandle identity) {
    if (!identical(_currentIdentity, identity)) {
      return Future<void>.value();
    }
    return _serialized(() async {
      if (identical(_currentIdentity, identity)) {
        await _closeCurrent();
      }
    }, allowClosed: true);
  }

  Future<void> _closeCurrent() async {
    final current = _current;
    _current = null;
    _currentIdentity = null;
    _currentContextId = null;
    await current?.close();
  }

  Future<R> _serialized<R>(
    Future<R> Function() operation, {
    bool allowClosed = false,
  }) {
    final completer = Completer<R>();
    final previous = _operationTail;
    _operationTail = previous.catchError((_) {}).then((_) async {
      try {
        if (_closed && !allowClosed) {
          throw StateError('Layergram v3 application runtime owner is closed');
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
      throw StateError('Layergram v3 application runtime owner is closed');
    }
  }
}
