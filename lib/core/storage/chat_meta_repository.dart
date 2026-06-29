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
  }

  /// Local identity id this repository instance is scoped to.
  ///
  /// If empty, the repository behaves as empty and won't touch persisted data.
  final String identityId;

  final Box<Map> _box;
  final _controller = StreamController<void>.broadcast();
  SecretKey? _encryptionKey;
  String? _scopeToken;
  Future<void> _loadFuture = Future.value();

  /// folderId -> (chatId -> pinnedAtSeconds)
  final Map<String, Map<String, int>> _pinnedByFolder = {};
  final Map<String, Map<String, dynamic>> _settingsByChatId = {};

  bool get _hasIdentityScope => (_scopeToken ?? '').isNotEmpty;

  String get _storageKey => 't|${_scopeToken!}';

  Future<void> setActiveContext({
    required String? scopeToken,
    required SecretKey? encryptionKey,
  }) async {
    _scopeToken = scopeToken;
    _encryptionKey = encryptionKey;
    _loadFuture = _reloadFromBox();
    await _loadFuture;
    _controller.add(null);
  }

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
  }) async {
    await _ensureLoaded();
    if (!_hasIdentityScope) return;

    if (pinned) {
      final pinnedAt = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      (_pinnedByFolder[folderId] ??= <String, int>{})[chatId] = pinnedAt;
      await _persist();
      _controller.add(null);
      return;
    }

    _pinnedByFolder[folderId]?.remove(chatId);
    if ((_pinnedByFolder[folderId] ?? const <String, int>{}).isEmpty) {
      _pinnedByFolder.remove(folderId);
    }
    await _persist();
    _controller.add(null);
  }

  Future<void> togglePinned(
      {required String folderId, required String chatId}) {
    final pinned = isPinned(folderId: folderId, chatId: chatId);
    return setPinned(folderId: folderId, chatId: chatId, pinned: !pinned);
  }

  Stream<Map<String, int>> watchPinnedChats({required String folderId}) async* {
    await _ensureLoaded();
    if (!_hasIdentityScope) {
      yield const <String, int>{};
      yield* _controller.stream.map((_) => const <String, int>{});
      return;
    }

    yield Map.unmodifiable(_pinnedByFolder[folderId] ?? const <String, int>{});
    yield* _controller.stream.map(
      (_) =>
          Map.unmodifiable(_pinnedByFolder[folderId] ?? const <String, int>{}),
    );
  }

  Future<void> clearAll() async {
    await _ensureLoaded();
    _pinnedByFolder.clear();
    _settingsByChatId.clear();
    if (!_hasIdentityScope) {
      _controller.add(null);
      return;
    }
    await _box.delete(_storageKey);
    _controller.add(null);
  }

  Future<Map<String, dynamic>?> getChatSettings(
      {required String chatId}) async {
    await _ensureLoaded();
    if (!_hasIdentityScope) return null;
    final settings = _settingsByChatId[chatId];
    if (settings == null) return null;
    return Map<String, dynamic>.from(settings);
  }

  Future<void> saveChatSettings({
    required String chatId,
    required String outputMode,
    required int? expiryMinutes,
    required bool deleteAfterRead,
  }) async {
    await _ensureLoaded();
    if (!_hasIdentityScope) return;
    _settingsByChatId[chatId] = {
      'outputMode': outputMode,
      'expiryMinutes': expiryMinutes,
      'deleteAfterRead': deleteAfterRead,
    };
    await _persist();
  }

  /// Clean up resources and close stream controller.
  ///
  /// This method should be called when the repository is no longer needed
  /// to prevent memory leaks from the stream controller.
  void dispose() {
    _controller.close();
  }
}
