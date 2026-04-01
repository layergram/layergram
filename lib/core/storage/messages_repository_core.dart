import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:hive_flutter/hive_flutter.dart';

import '../crypto/models.dart';
import '../crypto/sealed_map_cipher.dart';
import 'local_database.dart';

class MessagesRepositoryCore {
  MessagesRepositoryCore() : _box = Hive.box<Map>(LocalDatabase.messagesBoxName) {
    _loadFuture = _reloadFromBox();
  }

  final Box<Map> _box;
  final List<MessageRecord> _messages = [];
  final _controller = StreamController<List<MessageRecord>>.broadcast();

  SecretKey? _storageKey;
  String? _scopeToken;
  Future<void> _loadFuture = Future.value();
  int _reloadGeneration = 0;
  String? _visibleRecordKey;

  final Map<String, Map<dynamic, dynamic>> _hiddenPersistedRecords = {};

  static final Random _random = Random.secure();

  Future<void> setActiveContext({
    required String? scopeToken,
    required SecretKey? storageKey,
  }) async {
    _scopeToken = scopeToken;
    _storageKey = storageKey;
    _loadFuture = _reloadFromBox();
    await _loadFuture;
    _controller.add(List.unmodifiable(_messages));
  }

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
    Map<dynamic, dynamic> persisted,
    {
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
    _messages.removeWhere((m) => m.expireAfter != null && m.expireAfter! < _now);
    _messages.sort(_compareNewestFirst);
  }

  int _compareNewestFirst(MessageRecord a, MessageRecord b) {
    final byTimestamp = b.timestamp.compareTo(a.timestamp);
    if (byTimestamp != 0) return byTimestamp;
    return b.id.compareTo(a.id);
  }

  bool _hasPrunableMessages() {
    return _messages.any(
      (m) => m.deletedAt != null || (m.expireAfter != null && m.expireAfter! < _now),
    );
  }

  bool _isDuplicateIncomingMessage(MessageRecord existing, MessageRecord candidate) {
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

    final keysToDelete = _box.keys.where(_isScopedKey).toList();
    for (final key in keysToDelete) {
      await _box.delete(key);
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

  Future<void> add(MessageRecord message, {SecretKey? storageKey}) async {
    await _ensureLoaded();
    final effectiveStorageKey = storageKey ?? _storageKey;
    if (_hasScope && effectiveStorageKey == null) {
      throw StateError('Storage context not initialized');
    }
    if (effectiveStorageKey != null) {
      _storageKey = effectiveStorageKey;
    }
    if (_messages.any((m) => _isDuplicateIncomingMessage(m, message))) {
      return;
    }
    _messages.removeWhere((m) => m.id == message.id);
    _messages.add(message);
    _sortAndPrune();
    await _persistAll();
    _controller.add(List.unmodifiable(_messages));
  }

  Future<void> clearAll() async {
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
  }

  Future<void> markRead(String id) async {
    await _ensureLoaded();
    final idx = _messages.indexWhere((m) => m.id == id);
    if (idx < 0) return;

    final current = _messages[idx];
    final updated = current.copyWith(readAt: _now);
    _messages[idx] = updated;
    await _persistAll();
    _controller.add(List.unmodifiable(_messages));
  }

  Future<void> delete(String id) async {
    await _ensureLoaded();
    _messages.removeWhere((m) => m.id == id);
    _sortAndPrune();
    await _persistAll();
    _controller.add(List.unmodifiable(_messages));
  }

  Future<void> deleteAllForContact(String contactId) async {
    await _ensureLoaded();
    _messages.removeWhere((m) =>
        m.senderId == contactId || m.recipientId == contactId);
    _sortAndPrune();
    await _persistAll();
    _controller.add(List.unmodifiable(_messages));
  }

  Future<void> deleteForContactByKeyFilter(
    String contactId, {
    required String? effectiveTag,
  }) async {
    await _ensureLoaded();
    _messages.removeWhere((m) {
      if (m.senderId != contactId && m.recipientId != contactId) return false;
      return _matchesKeyFilter(m, effectiveTag);
    });
    _sortAndPrune();
    await _persistAll();
    _controller.add(List.unmodifiable(_messages));
  }

  Future<void> deleteByKeyFilter({
    required String? effectiveTag,
  }) async {
    await _ensureLoaded();
    _messages.removeWhere(
      (m) => _matchesKeyFilter(m, effectiveTag),
    );
    _sortAndPrune();
    await _persistAll();
    _controller.add(List.unmodifiable(_messages));
  }

  static bool _matchesKeyFilter(MessageRecord m, String? effectiveTag) {
    if (effectiveTag == null) return true;
    return m.keyTag == effectiveTag;
  }

  Future<void> purgeReadDeleteAfterReadFor(String peerId) async {
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
  }

  Stream<List<MessageRecord>> watchAll() async* {
    await _ensureLoaded();
    final hadPrunableMessages = _hasPrunableMessages();
    _sortAndPrune();
    if (hadPrunableMessages) {
      await _persistAll();
    }
    yield List.unmodifiable(_messages);
    yield* _controller.stream;
  }

  Future<List<MessageRecord>> getThread(String contactId) async {
    await _ensureLoaded();
    _sortAndPrune();
    final thread = _messages
        .where((m) => m.senderId == contactId || m.recipientId == contactId)
        .toList();
    thread.sort(_compareNewestFirst);
    return thread;
  }

  Future<List<MessageRecord>> getAllMessages() async {
    await _ensureLoaded();
    _sortAndPrune();
    return List.unmodifiable(_messages);
  }

  Stream<List<MessageRecord>> watchThread(String contactId, {int limit = 50}) async* {
    await _ensureLoaded();
    final hadPrunableMessages = _hasPrunableMessages();
    _sortAndPrune();
    if (hadPrunableMessages) {
      await _persistAll();
    }

    List<MessageRecord> getFiltered() {
      final thread = _messages
          .where((m) => m.senderId == contactId || m.recipientId == contactId)
          .toList()
        ..sort(_compareNewestFirst);
      if (thread.length > limit) {
        return thread.sublist(0, limit);
      }
      return thread;
    }

    yield List.unmodifiable(getFiltered());

    await for (final _ in _controller.stream) {
      yield List.unmodifiable(getFiltered());
    }
  }

  void dispose() {
    _controller.close();
  }
}
