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

import 'package:cryptography/cryptography.dart';
import 'package:hive_flutter/hive_flutter.dart';

import '../crypto/sealed_map_cipher.dart';
import '../crypto/models.dart';
import 'local_database.dart';

class IdentitiesRepository {
  IdentitiesRepository({required this.ownerIdentityId})
      : _box = Hive.box<Map>(LocalDatabase.identitiesBoxName) {
    _loadFuture = _reloadFromBox();
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

  bool get _hasScope => (_scopeToken ?? '').isNotEmpty;

  String get _storageKey => 'r|${_scopeToken!}';

  Future<void> setActiveContext({
    required String? scopeToken,
    required SecretKey? encryptionKey,
    required RemoteIdentity? selfIdentity,
  }) async {
    _scopeToken = scopeToken;
    _encryptionKey = encryptionKey;
    _selfIdentity = selfIdentity;
    _loadFuture = _reloadFromBox();
    await _loadFuture;
    _controller.add(_visibleRemote());
  }

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

  Future<void> upsertRemoteIdentity(RemoteIdentity identity) async {
    await _ensureLoaded();
    if (!_hasScope || _encryptionKey == null) {
      throw StateError('Contacts storage not initialized');
    }
    _remote[identity.identityId] = identity;
    await _persist();
    _controller.add(_visibleRemote());
  }

  Future<void> deleteRemoteIdentity(String identityId) async {
    await _ensureLoaded();
    _remote.remove(identityId);
    await _persist();
    _controller.add(_visibleRemote());
  }

  Future<void> clearAll({bool deleteLocalIdentity = true}) async {
    await _ensureLoaded();
    _remote.clear();
    if (_hasScope) {
      await _box.delete(_storageKey);
    }
    _controller.add(_visibleRemote());
  }

  Future<RemoteIdentity?> getRemoteById(String identityId) async {
    await _ensureLoaded();
    final self = _selfIdentity;
    if (self != null && self.identityId == identityId) {
      return self;
    }
    return _remote[identityId];
  }

  Stream<List<RemoteIdentity>> watchRemote() async* {
    await _ensureLoaded();
    yield _visibleRemote();
    yield* _controller.stream;
  }

  /// Clean up resources and close stream controller.
  /// 
  /// This method should be called when the repository is no longer needed
  /// to prevent memory leaks from the stream controller.
  void dispose() {
    _controller.close();
  }
}
