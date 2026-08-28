import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:hive_flutter/hive_flutter.dart';

import '../crypto/models.dart';
import '../crypto/sealed_map_cipher.dart';
import 'local_database.dart';

class MessagesRepositoryCore {
  MessagesRepositoryCore()
      : _box = Hive.box<Map>(LocalDatabase.messagesBoxName) {
    _loadFuture = _reloadFromBox();
    _operationTail = _loadFuture;
  }

  final Box<Map> _box;
  final List<MessageRecord> _messages = [];
  final _controller = StreamController<List<MessageRecord>>.broadcast();

  SecretKey? _storageKey;
  String? _scopeToken;
  Future<void> _loadFuture = Future.value();
  Future<void> _operationTail = Future.value();
  bool _disposeRequested = false;
  int _reloadGeneration = 0;
  String? _visibleRecordKey;

  final Map<String, Map<dynamic, dynamic>> _hiddenPersistedRecords = {};

  static final Random _random = Random.secure();

  Future<void> setActiveContext({
    required String? scopeToken,
    required SecretKey? storageKey,
  }) =>
      _serialized(() async {
        final detachedKey = await _detachStorageKey(storageKey);
        final previousKey = _storageKey;
        _scopeToken = scopeToken;
        _storageKey = detachedKey;
        _destroyStorageKey(previousKey);
        _loadFuture = _reloadFromBox();
        final generation = _reloadGeneration;
        await _loadFuture;
        if (generation != _reloadGeneration) return;
        _controller.add(List.unmodifiable(_messages));
      });

  bool get _hasScope => (_scopeToken ?? '').isNotEmpty;

  String get _keyPrefix => 'm|${_scopeToken!}|';

  String _scopedKey(String storageId) => '$_keyPrefix$storageId';

  bool _isScopedKey(Object? key) =>
      key is String && _hasScope && key.startsWith(_keyPrefix);

  Future<void> _ensureLoaded() async {
    await _loadFuture;
  }

  Future<void> _reloadFromBox() async {
    final generation = ++_reloadGeneration;
    final storageKey = _storageKey;
    final visibleMessages = <MessageRecord>[];
    final hidden = <String, Map<dynamic, dynamic>>{};
    String? visibleRecordKey;

    if (_hasScope) {
      for (final key in _box.keys) {
        if (!_isScopedKey(key)) continue;
        final raw = _box.get(key);
        if (raw == null) continue;
        final persisted = Map<dynamic, dynamic>.from(raw);
        final scopedKey = key as String;

        if (!_isSealedPersistedRecord(persisted)) {
          hidden[scopedKey] = persisted;
          continue;
        }

        final decrypted = await _decryptPersistedRecord(
          persisted,
          storageKey: storageKey,
        );
        if (decrypted == null) {
          hidden[scopedKey] = persisted;
          continue;
        }

        visibleMessages.addAll(_messagesFromState(decrypted));
        visibleRecordKey ??= scopedKey;
      }
    }

    if (generation != _reloadGeneration) return;

    _messages
      ..clear()
      ..addAll(visibleMessages);
    _hiddenPersistedRecords
      ..clear()
      ..addAll(hidden);
    _visibleRecordKey = visibleRecordKey;
    _sortAndPrune();
  }

  bool _isSealedPersistedRecord(Map<dynamic, dynamic> persisted) {
    return persisted['encryptedRecord'] is String;
  }

  Future<Map<String, dynamic>?> _decryptPersistedRecord(
    Map<dynamic, dynamic> persisted, {
    required SecretKey? storageKey,
  }) async {
    final encryptedRecord = persisted['encryptedRecord'] as String?;
    if (encryptedRecord == null || storageKey == null) return null;
    return SealedMapCipher.decrypt(
      encryptedRecord: encryptedRecord,
      key: storageKey,
    );
  }

  List<MessageRecord> _messagesFromState(Map<String, dynamic> state) {
    final rawMessages = state['messages'];
    if (rawMessages is! List) return const [];
    final messages = <MessageRecord>[];
    for (final item in rawMessages) {
      if (item is! Map) continue;
      try {
        messages.add(MessageRecord.fromMap(item));
      } catch (_) {}
    }
    return messages;
  }

  Map<String, dynamic> _stateToPayload() {
    return {
      'messages': _messages.map((m) => m.toMap()).toList(growable: false),
    };
  }

  int get _now => DateTime.now().millisecondsSinceEpoch ~/ 1000;

  void _sortAndPrune() {
    _messages.removeWhere((m) => m.deletedAt != null);
    _messages
        .removeWhere((m) => m.expireAfter != null && m.expireAfter! < _now);
    _messages.sort(_compareNewestFirst);
  }

  int _compareNewestFirst(MessageRecord a, MessageRecord b) {
    final byTimestamp = b.timestamp.compareTo(a.timestamp);
    if (byTimestamp != 0) return byTimestamp;
    return b.id.compareTo(a.id);
  }

  bool _hasPrunableMessages() {
    return _messages.any(
      (m) =>
          m.deletedAt != null ||
          (m.expireAfter != null && m.expireAfter! < _now),
    );
  }

  bool _isDuplicateIncomingMessage(
      MessageRecord existing, MessageRecord candidate) {
    if (existing.direction != 'incoming' || candidate.direction != 'incoming') {
      return false;
    }
    if (existing.senderId != candidate.senderId ||
        existing.recipientId != candidate.recipientId ||
        existing.keyTag != candidate.keyTag) {
      return false;
    }

    final existingRaw = existing.rawSource?.trim();
    final candidateRaw = candidate.rawSource?.trim();
    if (existingRaw != null &&
        existingRaw.isNotEmpty &&
        candidateRaw != null &&
        candidateRaw.isNotEmpty) {
      return existingRaw == candidateRaw;
    }

    final existingNonce = existing.nonceBase64;
    final candidateNonce = candidate.nonceBase64;
    final existingCiphertext = existing.ciphertextBase64;
    final candidateCiphertext = candidate.ciphertextBase64;
    return existingNonce != null &&
        existingCiphertext != null &&
        existingNonce == candidateNonce &&
        existingCiphertext == candidateCiphertext;
  }

  Future<void> _persistAll() async {
    await _ensureLoaded();
    if (!_hasScope) return;

    // Rewrite only the visible message aggregate. Opaque encrypted residual
    // records in the same scope may be aux records or future archive formats;
    // normal message operations must preserve them.
    if (_visibleRecordKey != null) {
      await _box.delete(_visibleRecordKey);
    }
    for (final entry in _hiddenPersistedRecords.entries) {
      await _box.put(entry.key, entry.value);
    }

    final storageKey = _storageKey;
    if (_messages.isEmpty || storageKey == null) {
      _visibleRecordKey = null;
      return;
    }

    final encryptedRecord = await SealedMapCipher.encrypt(
      record: _stateToPayload(),
      key: storageKey,
    );
    final recordKey = _visibleRecordKey ?? _scopedKey(_newOpaqueStorageId());
    await _box.put(recordKey, {
      'encryptedRecord': encryptedRecord,
    });
    _visibleRecordKey = recordKey;
  }

  String _newOpaqueStorageId() {
    final bytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return 'r${base64Url.encode(bytes).replaceAll('=', '')}';
  }

  Future<void> add(MessageRecord message, {SecretKey? storageKey}) =>
      _serialized(() async {
        await _ensureLoaded();
        if (storageKey != null) {
          if (!_hasScope || !await _matchesStorageKey(storageKey)) {
            throw StateError(
              'Message storage key does not match the active scope',
            );
          }
        }
        if (_hasScope && _storageKey == null) {
          throw StateError('Storage context not initialized');
        }
        if (_messages.any((m) => _isDuplicateIncomingMessage(m, message))) {
          return;
        }
        _messages.removeWhere((m) => m.id == message.id);
        _messages.add(message);
        _sortAndPrune();
        await _persistAll();
        _controller.add(List.unmodifiable(_messages));
      });

  Future<void> clearAll() => _serialized(() async {
        _messages.clear();
        _hiddenPersistedRecords.clear();
        _visibleRecordKey = null;
        if (!_hasScope) {
          _controller.add(const []);
          return;
        }

        final keysToDelete = _box.keys.where(_isScopedKey).toList();
        for (final key in keysToDelete) {
          await _box.delete(key);
        }
        _controller.add(const []);
      });

  Future<void> markRead(String id) => _serialized(() async {
        await _ensureLoaded();
        final idx = _messages.indexWhere((m) => m.id == id);
        if (idx < 0) return;

        final current = _messages[idx];
        final updated = current.copyWith(readAt: _now);
        _messages[idx] = updated;
        await _persistAll();
        _controller.add(List.unmodifiable(_messages));
      });

  Future<void> delete(String id) => _serialized(() async {
        await _ensureLoaded();
        _messages.removeWhere((m) => m.id == id);
        _sortAndPrune();
        await _persistAll();
        _controller.add(List.unmodifiable(_messages));
      });

  Future<void> deleteAllForContact(String contactId) => _serialized(() async {
        await _ensureLoaded();
        _messages.removeWhere(
            (m) => m.senderId == contactId || m.recipientId == contactId);
        _sortAndPrune();
        await _persistAll();
        _controller.add(List.unmodifiable(_messages));
      });

  Future<void> deleteForContactByKeyFilter(
    String contactId, {
    required String? effectiveTag,
  }) =>
      _serialized(() async {
        await _ensureLoaded();
        _messages.removeWhere((m) {
          if (m.senderId != contactId && m.recipientId != contactId) {
            return false;
          }
          return _matchesKeyFilter(m, effectiveTag);
        });
        _sortAndPrune();
        await _persistAll();
        _controller.add(List.unmodifiable(_messages));
      });

  Future<void> deleteByKeyFilter({
    required String? effectiveTag,
  }) =>
      _serialized(() async {
        await _ensureLoaded();
        _messages.removeWhere(
          (m) => _matchesKeyFilter(m, effectiveTag),
        );
        _sortAndPrune();
        await _persistAll();
        _controller.add(List.unmodifiable(_messages));
      });

  static bool _matchesKeyFilter(MessageRecord m, String? effectiveTag) {
    if (effectiveTag == null) return true;
    return m.keyTag == effectiveTag;
  }

  Future<void> purgeReadDeleteAfterReadFor(String peerId) =>
      _serialized(() async {
        await _ensureLoaded();
        final hasMatches = _messages.any((m) =>
            m.deleteAfterRead &&
            m.readAt != null &&
            (m.senderId == peerId || m.recipientId == peerId));
        if (!hasMatches) return;
        _messages.removeWhere((m) =>
            m.deleteAfterRead &&
            m.readAt != null &&
            (m.senderId == peerId || m.recipientId == peerId));
        _sortAndPrune();
        await _persistAll();
        _controller.add(List.unmodifiable(_messages));
      });

  Stream<List<MessageRecord>> watchAll() async* {
    final initial = await _serialized(() async {
      await _ensureLoaded();
      final hadPrunableMessages = _hasPrunableMessages();
      _sortAndPrune();
      if (hadPrunableMessages) {
        await _persistAll();
      }
      return List<MessageRecord>.unmodifiable(_messages);
    });
    yield initial;
    yield* _controller.stream;
  }

  Future<List<MessageRecord>> getThread(String contactId) =>
      _serialized(() async {
        await _ensureLoaded();
        _sortAndPrune();
        final thread = _messages
            .where((m) => m.senderId == contactId || m.recipientId == contactId)
            .toList();
        thread.sort(_compareNewestFirst);
        return thread;
      });

  Future<List<MessageRecord>> getAllMessages() => _serialized(() async {
        await _ensureLoaded();
        _sortAndPrune();
        return List<MessageRecord>.unmodifiable(_messages);
      });

  Stream<List<MessageRecord>> watchThread(String contactId,
      {int limit = 50}) async* {
    List<MessageRecord> getFiltered(List<MessageRecord> messages) {
      final thread = messages
          .where((m) => m.senderId == contactId || m.recipientId == contactId)
          .toList()
        ..sort(_compareNewestFirst);
      if (thread.length > limit) {
        return thread.sublist(0, limit);
      }
      return thread;
    }

    final initial = await _serialized(() async {
      await _ensureLoaded();
      final hadPrunableMessages = _hasPrunableMessages();
      _sortAndPrune();
      if (hadPrunableMessages) {
        await _persistAll();
      }
      return List<MessageRecord>.unmodifiable(_messages);
    });
    yield List<MessageRecord>.unmodifiable(getFiltered(initial));

    await for (final messages in _controller.stream) {
      yield List<MessageRecord>.unmodifiable(getFiltered(messages));
    }
  }

  /// Strips persisted plaintext from all encrypted messages (§12.3).
  ///
  /// Called on identity reset to ensure FS messages cannot be read after
  /// the ratchet keys have been destroyed.  We strip ALL encrypted messages
  /// (not just those flagged `isFsEncrypted`) because messages exchanged
  /// before the flag was introduced lack the marker.  After identity restore,
  /// legacy messages will be re-decrypted on demand (same keys), while FS
  /// messages will fail inner-layer decryption (ratchet gone) and show a
  /// placeholder.
  Future<void> stripEncryptedPlaintext() => _serialized(() async {
        await _ensureLoaded();
        if (!_hasScope || _storageKey == null) {
          throw StateError(
            'Cannot strip message plaintext without an active storage scope',
          );
        }
        var changed = false;
        for (var i = 0; i < _messages.length; i++) {
          final m = _messages[i];
          if (m.text != null && m.ciphertextBase64 != null) {
            _messages[i] = m.copyWith(clearText: true);
            changed = true;
          }
        }
        if (changed) {
          await _persistAll();
          _controller.add(List.unmodifiable(_messages));
        }
      });

  /// Strips plaintext from every aggregate decryptable with a known key.
  ///
  /// Opaque aggregates are preserved verbatim: deleting them would reveal
  /// which ciphertext belongs to the identity being reset and would break the
  /// plausible-deniability contract. Callers may supply the primary key while
  /// a passphrase context is active so both currently knowable contexts are
  /// sanitized before identity destruction.
  Future<void> stripEncryptedPlaintextAcrossKnownContexts({
    String? scopeToken,
    Iterable<SecretKey> additionalStorageKeys = const <SecretKey>[],
  }) =>
      _serialized(() async {
        await _ensureLoaded();
        final effectiveScopeToken = scopeToken ?? _scopeToken;
        final activeKey = _storageKey;
        final candidateKeys = <SecretKey>[
          if (activeKey != null && _scopeToken == effectiveScopeToken)
            activeKey,
          ...additionalStorageKeys,
        ];
        if ((effectiveScopeToken ?? '').isEmpty || candidateKeys.isEmpty) {
          throw StateError(
            'Cannot strip message plaintext without a known scope and key',
          );
        }

        final keyPrefix = 'm|$effectiveScopeToken|';
        final scopedKeys = _box.keys
            .where((key) => key is String && key.startsWith(keyPrefix))
            .toList(growable: false);
        for (final boxKey in scopedKeys) {
          final raw = _box.get(boxKey);
          if (raw == null) continue;
          final persisted = Map<dynamic, dynamic>.from(raw);
          if (!_isSealedPersistedRecord(persisted)) continue;

          Map<String, dynamic>? decrypted;
          SecretKey? matchingKey;
          for (final candidateKey in candidateKeys) {
            try {
              decrypted = await _decryptPersistedRecord(
                persisted,
                storageKey: candidateKey,
              );
            } catch (_) {
              decrypted = null;
            }
            if (decrypted != null) {
              matchingKey = candidateKey;
              break;
            }
          }
          final rawMessages = decrypted?['messages'];
          if (decrypted == null ||
              matchingKey == null ||
              rawMessages is! List) {
            continue;
          }

          final sanitizedMessages = <Map<String, dynamic>>[];
          var valid = true;
          var changed = false;
          for (final rawMessage in rawMessages) {
            if (rawMessage is! Map) {
              valid = false;
              break;
            }
            try {
              final message = MessageRecord.fromMap(rawMessage);
              final sanitized =
                  message.text != null && message.ciphertextBase64 != null
                      ? message.copyWith(clearText: true)
                      : message;
              changed = changed || sanitized.text != message.text;
              sanitizedMessages.add(sanitized.toMap());
            } catch (_) {
              valid = false;
              break;
            }
          }
          if (!valid || !changed) continue;

          final sanitizedState = Map<String, dynamic>.from(decrypted)
            ..['messages'] = sanitizedMessages;
          final encryptedRecord = await SealedMapCipher.encrypt(
            record: sanitizedState,
            key: matchingKey,
          );
          await _box.put(boxKey, {'encryptedRecord': encryptedRecord});
        }

        if (_scopeToken == effectiveScopeToken) {
          _loadFuture = _reloadFromBox();
          await _loadFuture;
          _controller.add(List.unmodifiable(_messages));
        }
      });

  void dispose() {
    if (_disposeRequested) return;
    _disposeRequested = true;
    final pending = _operationTail;
    unawaited(
      pending.catchError((_) {}).whenComplete(() async {
        final storageKey = _storageKey;
        _storageKey = null;
        _destroyStorageKey(storageKey);
        if (!_controller.isClosed) await _controller.close();
      }),
    );
  }

  Future<SecretKeyData?> _detachStorageKey(SecretKey? storageKey) async {
    if (storageKey == null) return null;
    final extracted = Uint8List.fromList(await storageKey.extractBytes());
    final owned = Uint8List.fromList(extracted);
    extracted.fillRange(0, extracted.length, 0);
    return SecretKeyData(owned, overwriteWhenDestroyed: true);
  }

  Future<bool> _matchesStorageKey(SecretKey candidate) async {
    final current = _storageKey;
    if (current == null) return false;
    final currentBytes = Uint8List.fromList(await current.extractBytes());
    final candidateBytes = Uint8List.fromList(await candidate.extractBytes());
    try {
      if (currentBytes.length != candidateBytes.length) return false;
      var difference = 0;
      for (var index = 0; index < currentBytes.length; index++) {
        difference |= currentBytes[index] ^ candidateBytes[index];
      }
      return difference == 0;
    } finally {
      currentBytes.fillRange(0, currentBytes.length, 0);
      candidateBytes.fillRange(0, candidateBytes.length, 0);
    }
  }

  void _destroyStorageKey(SecretKey? storageKey) {
    storageKey?.destroy();
  }

  Future<T> _serialized<T>(Future<T> Function() operation) {
    if (_disposeRequested) {
      return Future<T>.error(
        StateError('MessagesRepository is disposed'),
      );
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
