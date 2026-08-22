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
import 'local_database.dart';

/// Lightweight per-chat metadata persisted locally.
///
/// In the OSS core this is used for features like pinned chats.
/// Premium can extend this repository (or replace it) to add more metadata,
/// potentially scoped per-identity and per-folder.
class ChatMetaRepository {
  ChatMetaRepository({required this.identityId})
      : _box = Hive.box<Map>(LocalDatabase.chatMetaBoxName) {
    _loadFuture = _reloadFromBox();
    _operationTail = _loadFuture;
  }

  /// Local identity id this repository instance is scoped to.
  ///
  /// If empty, the repository behaves as empty and won't touch persisted data.
  final String identityId;

  final Box<Map> _box;
  final _controller =
      StreamController<Map<String, Map<String, int>>>.broadcast();
  SecretKey? _encryptionKey;
  String? _scopeToken;
  Future<void> _loadFuture = Future.value();
  Future<void> _operationTail = Future.value();
  bool _disposeRequested = false;

  /// folderId -> (chatId -> pinnedAtSeconds)
  final Map<String, Map<String, int>> _pinnedByFolder = {};
  final Map<String, Map<String, dynamic>> _settingsByChatId = {};

  bool get _hasIdentityScope => (_scopeToken ?? '').isNotEmpty;

  String get _storageKey => 't|${_scopeToken!}';

  Future<void> setActiveContext({
    required String? scopeToken,
    required SecretKey? encryptionKey,
  }) =>
      _serialized(() async {
        final detachedKey = await _detachEncryptionKey(encryptionKey);
        final previousKey = _encryptionKey;
        _scopeToken = scopeToken;
        _encryptionKey = detachedKey;
        _destroyEncryptionKey(previousKey);
        _loadFuture = _reloadFromBox();
        await _loadFuture;
        _emitPinnedSnapshot();
      });

  Future<void> _ensureLoaded() async {
    await _loadFuture;
  }

  Future<void> _reloadFromBox() async {
    _pinnedByFolder.clear();
    _settingsByChatId.clear();
    if (!_hasIdentityScope) return;

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

    final pins = decoded['pins'];
    if (pins is Map) {
      for (final folderEntry in pins.entries) {
        final folderId = folderEntry.key?.toString();
        final rawChats = folderEntry.value;
        if (folderId == null || rawChats is! Map) continue;
        final pinned = <String, int>{};
        for (final chatEntry in rawChats.entries) {
          final chatId = chatEntry.key?.toString();
          final pinnedAt = chatEntry.value;
          if (chatId == null || pinnedAt is! int) continue;
          pinned[chatId] = pinnedAt;
        }
        if (pinned.isNotEmpty) {
          _pinnedByFolder[folderId] = pinned;
        }
      }
    }

    final settings = decoded['settings'];
    if (settings is Map) {
      for (final entry in settings.entries) {
        final chatId = entry.key?.toString();
        final value = entry.value;
        if (chatId == null || value is! Map) continue;
        _settingsByChatId[chatId] = value.cast<String, dynamic>();
      }
    }
  }

  Future<void> _persist() async {
    await _ensureLoaded();
    if (!_hasIdentityScope) return;

    final key = _encryptionKey;
    if (key == null) {
      throw StateError('Chat meta storage key not initialized');
    }

    final hasPins = _pinnedByFolder.values.any((m) => m.isNotEmpty);
    final hasSettings = _settingsByChatId.isNotEmpty;
    if (!hasPins && !hasSettings) {
      await _box.delete(_storageKey);
      return;
    }

    final encryptedRecord = await SealedMapCipher.encrypt(
      record: {
        'pins': _pinnedByFolder,
        'settings': _settingsByChatId,
      },
      key: key,
    );
    await _box.put(_storageKey, {
      'encryptedRecord': encryptedRecord,
    });
  }

  bool isPinned({required String folderId, required String chatId}) {
    return (_pinnedByFolder[folderId] ?? const <String, int>{})
        .containsKey(chatId);
  }

  Future<void> setPinned({
    required String folderId,
    required String chatId,
    required bool pinned,
  }) =>
      _serialized(() async {
        await _ensureLoaded();
        await _setPinned(
          folderId: folderId,
          chatId: chatId,
          pinned: pinned,
        );
      });

  Future<void> togglePinned(
          {required String folderId, required String chatId}) =>
      _serialized(() async {
        await _ensureLoaded();
        final pinned = isPinned(folderId: folderId, chatId: chatId);
        await _setPinned(
          folderId: folderId,
          chatId: chatId,
          pinned: !pinned,
        );
      });

  Stream<Map<String, int>> watchPinnedChats({required String folderId}) async* {
    final initial = await _serialized(() async {
      await _ensureLoaded();
      return _pinnedSnapshotFor(folderId);
    });
    yield initial;
    yield* _controller.stream.map(
      (snapshot) => Map<String, int>.unmodifiable(
        snapshot[folderId] ?? const <String, int>{},
      ),
    );
  }

  Future<void> clearAll() => _serialized(() async {
        await _ensureLoaded();
        _pinnedByFolder.clear();
        _settingsByChatId.clear();
        if (_hasIdentityScope) {
          await _box.delete(_storageKey);
        }
        _emitPinnedSnapshot();
      });

  Future<Map<String, dynamic>?> getChatSettings({required String chatId}) =>
      _serialized(() async {
        await _ensureLoaded();
        if (!_hasIdentityScope) return null;
        final settings = _settingsByChatId[chatId];
        if (settings == null) return null;
        return Map<String, dynamic>.from(settings);
      });

  Future<void> saveChatSettings({
    required String chatId,
    required String outputMode,
    required int? expiryMinutes,
    required bool deleteAfterRead,
    required bool excludeFromBackups,
  }) =>
      _serialized(() async {
        await _ensureLoaded();
        if (!_hasIdentityScope) return;
        _settingsByChatId[chatId] = {
          'outputMode': outputMode,
          'expiryMinutes': expiryMinutes,
          'deleteAfterRead': deleteAfterRead,
          'excludeFromBackups': excludeFromBackups,
        };
        await _persist();
      });

  Future<void> setExcludeFromBackups({
    required String chatId,
    required bool excludeFromBackups,
  }) =>
      _serialized(() async {
        await _ensureLoaded();
        if (!_hasIdentityScope) return;
        final current = _settingsByChatId[chatId] ?? const <String, dynamic>{};
        _settingsByChatId[chatId] = {
          'outputMode': (current['outputMode'] as String?) ?? 'text',
          'expiryMinutes': current['expiryMinutes'] as int?,
          'deleteAfterRead': (current['deleteAfterRead'] as bool?) ?? false,
          'excludeFromBackups': excludeFromBackups,
        };
        await _persist();
      });

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

  Future<void> _setPinned({
    required String folderId,
    required String chatId,
    required bool pinned,
  }) async {
    if (!_hasIdentityScope) return;
    if (pinned) {
      final pinnedAt = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      (_pinnedByFolder[folderId] ??= <String, int>{})[chatId] = pinnedAt;
    } else {
      _pinnedByFolder[folderId]?.remove(chatId);
      if ((_pinnedByFolder[folderId] ?? const <String, int>{}).isEmpty) {
        _pinnedByFolder.remove(folderId);
      }
    }
    await _persist();
    _emitPinnedSnapshot();
  }

  Map<String, int> _pinnedSnapshotFor(String folderId) {
    if (!_hasIdentityScope) return const <String, int>{};
    return Map<String, int>.unmodifiable(
      _pinnedByFolder[folderId] ?? const <String, int>{},
    );
  }

  void _emitPinnedSnapshot() {
    final snapshot = <String, Map<String, int>>{};
    for (final entry in _pinnedByFolder.entries) {
      snapshot[entry.key] = Map<String, int>.unmodifiable(entry.value);
    }
    _controller.add(Map<String, Map<String, int>>.unmodifiable(snapshot));
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
      return Future<T>.error(StateError('ChatMetaRepository is disposed'));
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
