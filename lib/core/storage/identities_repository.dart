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
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:hive_flutter/hive_flutter.dart';

import '../crypto/sealed_map_cipher.dart';
import '../crypto/models.dart';
import 'local_database.dart';

class IdentitiesRepository {
  IdentitiesRepository({required this.ownerIdentityId})
      : _box = Hive.box<Map>(LocalDatabase.identitiesBoxName) {
    _loadFuture = _reloadFromBox();
    _operationTail = _loadFuture;
  }

  /// Local identity id used for scoping *remote* identities.
  ///
  /// In OSS this is set to the single local identity id. Premium can switch
  /// this value (via provider recreation) to support
  /// multi-identity.
  final String ownerIdentityId;

  final Box<Map> _box;
  final Map<String, RemoteIdentity> _remote = {};
  final _controller = StreamController<List<RemoteIdentity>>.broadcast();
  SecretKey? _encryptionKey;
  String? _scopeToken;
  RemoteIdentity? _selfIdentity;
  Future<void> _loadFuture = Future.value();
  Future<void> _operationTail = Future.value();
  bool _disposeRequested = false;

  bool get _hasScope => (_scopeToken ?? '').isNotEmpty;

  String get _storageKey => 'r|${_scopeToken!}';

  Future<void> setActiveContext({
    required String? scopeToken,
    required SecretKey? encryptionKey,
    required RemoteIdentity? selfIdentity,
  }) =>
      _serialized(() async {
        final detachedKey = await _detachEncryptionKey(encryptionKey);
        final previousKey = _encryptionKey;
        _scopeToken = scopeToken;
        _encryptionKey = detachedKey;
        _selfIdentity = selfIdentity;
        _destroyEncryptionKey(previousKey);
        _loadFuture = _reloadFromBox();
        await _loadFuture;
        _controller.add(_visibleRemote());
      });

  Future<void> _ensureLoaded() async {
    await _loadFuture;
  }

  Future<void> _reloadFromBox() async {
    _remote.clear();
    if (!_hasScope) return;
    final raw = _box.get(_storageKey);
    if (raw == null) return;
    final persisted = Map<dynamic, dynamic>.from(raw);
    final encryptedRecord = persisted['encryptedRecord'] as String?;
    final key = _encryptionKey;
    if (encryptedRecord == null || key == null) return;

    final decoded = await SealedMapCipher.decrypt(
      encryptedRecord: encryptedRecord,
      key: key,
    );
    if (decoded == null) return;

    final items = decoded['items'];
    if (items is! List) return;
    for (final item in items) {
      if (item is! Map) continue;
      try {
        final identity = RemoteIdentity.fromMap(item);
        _remote[identity.identityId] = identity;
      } catch (_) {}
    }
  }

  List<RemoteIdentity> _visibleRemote() {
    return _remote.values.toList(growable: false);
  }

  Future<void> _persist() async {
    await _ensureLoaded();
    if (!_hasScope) return;
    if (_remote.isEmpty) {
      await _box.delete(_storageKey);
      return;
    }
    final key = _encryptionKey;
    if (key == null) {
      throw StateError('Contacts storage key not initialized');
    }
    final encryptedRecord = await SealedMapCipher.encrypt(
      record: {
        'items': _remote.values.map((it) => it.toMap()).toList(growable: false),
      },
      key: key,
    );
    await _box.put(_storageKey, {
      'encryptedRecord': encryptedRecord,
    });
  }

  Future<void> upsertRemoteIdentity(RemoteIdentity identity) =>
      _serialized(() async {
        await _ensureLoaded();
        _ensureWritable();
        if (_selfIdentity?.identityId == identity.identityId) {
          throw StateError('Local identity cannot be stored as a contact');
        }
        final existing = _remote[identity.identityId];
        if (existing != null &&
            !_hasSameCryptographicIdentity(existing, identity)) {
          throw StateError(
              'Identity key change requires explicit verification');
        }
        _remote[identity.identityId] = identity.copyWith(
          verified: existing?.verified ?? false,
        );
        await _persist();
        _controller.add(_visibleRemote());
      });

  Future<void> setRemoteVerification({
    required RemoteIdentity expectedIdentity,
    required bool verified,
  }) =>
      _serialized(() async {
        await _ensureLoaded();
        _ensureWritable();
        final current = _remote[expectedIdentity.identityId];
        if (current == null ||
            !_hasSameCryptographicIdentity(current, expectedIdentity)) {
          throw StateError('Contact identity changed during verification');
        }
        _remote[current.identityId] = current.copyWith(verified: verified);
        await _persist();
        _controller.add(_visibleRemote());
      });

  Future<void> setRemoteDisplayName({
    required RemoteIdentity expectedIdentity,
    required String displayName,
  }) =>
      _serialized(() async {
        await _ensureLoaded();
        _ensureWritable();
        final current = _remote[expectedIdentity.identityId];
        if (current == null ||
            !_hasSameCryptographicIdentity(current, expectedIdentity)) {
          throw StateError('Contact identity changed during update');
        }
        _remote[current.identityId] =
            current.copyWith(displayName: displayName);
        await _persist();
        _controller.add(_visibleRemote());
      });

  Future<void> deleteRemoteIdentity(String identityId) => _serialized(() async {
        await _ensureLoaded();
        _remote.remove(identityId);
        await _persist();
        _controller.add(_visibleRemote());
      });

  Future<void> clearAll({bool deleteLocalIdentity = true}) =>
      _serialized(() async {
        await _ensureLoaded();
        _remote.clear();
        if (_hasScope) {
          await _box.delete(_storageKey);
        }
        _controller.add(_visibleRemote());
      });

  Future<RemoteIdentity?> getRemoteById(String identityId) =>
      _serialized(() async {
        await _ensureLoaded();
        final self = _selfIdentity;
        if (self != null && self.identityId == identityId) {
          return self;
        }
        return _remote[identityId];
      });

  Stream<List<RemoteIdentity>> watchRemote() async* {
    final initial = await _serialized(() async {
      await _ensureLoaded();
      return _visibleRemote();
    });
    yield initial;
    yield* _controller.stream;
  }

  /// Clean up resources and close stream controller.
  ///
  /// This method should be called when the repository is no longer needed
  /// to prevent memory leaks from the stream controller.
  void dispose() {
    if (_disposeRequested) return;
    _disposeRequested = true;
    final pending = _operationTail;
    unawaited(
      pending.catchError((_) {}).whenComplete(() async {
        final encryptionKey = _encryptionKey;
        _encryptionKey = null;
        _destroyEncryptionKey(encryptionKey);
        if (!_controller.isClosed) await _controller.close();
      }),
    );
  }

  void _ensureWritable() {
    if (!_hasScope || _encryptionKey == null) {
      throw StateError('Contacts storage not initialized');
    }
  }

  bool _hasSameCryptographicIdentity(
    RemoteIdentity first,
    RemoteIdentity second,
  ) {
    return first.identityId == second.identityId &&
        first.publicKeyBase64 == second.publicKeyBase64 &&
        first.fingerprint == second.fingerprint &&
        first.protocolVersion == second.protocolVersion &&
        first.publicIdentityBase64 == second.publicIdentityBase64;
  }

  Future<SecretKeyData?> _detachEncryptionKey(SecretKey? key) async {
    if (key == null) return null;
    final extracted = Uint8List.fromList(await key.extractBytes());
    final owned = Uint8List.fromList(extracted);
    extracted.fillRange(0, extracted.length, 0);
    return SecretKeyData(owned, overwriteWhenDestroyed: true);
  }

  void _destroyEncryptionKey(SecretKey? key) {
    key?.destroy();
  }

  Future<T> _serialized<T>(Future<T> Function() operation) {
    if (_disposeRequested) {
      return Future<T>.error(StateError('IdentitiesRepository is disposed'));
    }
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
}
