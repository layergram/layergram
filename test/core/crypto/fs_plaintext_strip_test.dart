/// Tests for §12.3 compliance: FS-encrypted message plaintext must not survive
/// identity reset.
///
/// Verifies:
/// 1. `stripEncryptedPlaintext()` removes text from ALL encrypted messages
/// 2. Legacy messages can be re-decrypted on demand after stripping
/// 3. FS messages cannot be re-decrypted after stripping (ratchet gone)
/// 4. Old FS messages without `isFsEncrypted` flag are also stripped
/// 5. `isFsEncrypted` flag round-trips through serialization
/// 6. `clearText` in copyWith explicitly nulls text
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_key_codec.dart';
import 'package:layergram/core/crypto/message_record_cipher.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';

Future<({String privateKeyBase64, String publicKeyBase64})> _keyMaterial(
  SimpleKeyPair keyPair,
) async {
  final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
  final publicKeyBytes = (await keyPair.extractPublicKey()).bytes;
  return (
    privateKeyBase64: base64Encode(privateKeyBytes),
    publicKeyBase64: base64Encode(publicKeyBytes),
  );
}

void main() {
  late Directory tmpDir;
  final keyMaterial = Uint8List.fromList(List<int>.generate(32, (i) => i));
  final x25519 = X25519();

  Future<SecretKey> deriveStorageKey(String keyTag) async {
    return MessageRecordCipher.deriveKey(keyMaterial, keyTag: keyTag);
  }

  Future<MessagesRepository> openRepo(SecretKey storageKey) async {
    final repo = MessagesRepository();
    await repo.setActiveContext(
      scopeToken: 'test-scope',
      storageKey: storageKey,
    );
    return repo;
  }

  Future<(RatchetState, RatchetState)> buildRatchets() async {
    Future<(Uint8List, Uint8List)> genDhPair() async {
      final pair = await x25519.newKeyPair();
      final priv = Uint8List.fromList(await pair.extractPrivateKeyBytes());
      final pub = Uint8List.fromList((await pair.extractPublicKey()).bytes);
      return (priv, pub);
    }

    final (ikAPriv, ikAPub) = await genDhPair();
    final (dkAPriv, _) = await genDhPair();
    final (ikBPriv, ikBPub) = await genDhPair();
    final (dkBPriv, _) = await genDhPair();

    final initPayload = await FsHandshake.generateFsInit(
      ikAPriv: ikAPriv,
      dkAPriv: dkAPriv,
    );
    final fsInit = initPayload.toMessage();

    final replyPayload = await FsHandshake.processFsInitAsResponder(
      ikBPriv: ikBPriv,
      dkBPriv: dkBPriv,
      ikAPub: ikAPub,
      init: fsInit,
    );
    final fsReply = replyPayload.toMessage();

    final confirmPayload = await FsHandshake.processFsReplyAsInitiator(
      ikAPriv: ikAPriv,
      dkAPriv: dkAPriv,
      ekAPrivBytes: initPayload.ekAPrivBytes,
      ikBPub: ikBPub,
      sentInit: fsInit,
      reply: fsReply,
    );
    final fsConfirm = confirmPayload.toMessage();

    final ok = await FsHandshake.verifyFsConfirmAsResponder(
      confirm: fsConfirm,
      bState: replyPayload.partialState,
      ikAPub: ikAPub,
    );
    expect(ok, isTrue);
    replyPayload.partialState.wipeRawRootSecret();

    final aState = confirmPayload.partialState;
    final bState = replyPayload.partialState;

    final ratchetAPriv = confirmPayload.initiatorInitialRatchetPriv;
    final ratchetAPub =
        FsKeyCodec.decodeKey(confirmPayload.initiatorInitialRatchetPub);
    final ratchetBPriv = replyPayload.responderInitialRatchetPriv;
    final ratchetBPub =
        FsKeyCodec.decodeKey(replyPayload.responderInitialRatchetPub);

    final aRatchet = await FsDoubleRatchet.initRatchet(
      rootKey0: aState.rootKey0,
      sendingChainKey0: aState.sendingChainKey0,
      receivingChainKey0: aState.receivingChainKey0,
      localRatchetPriv: ratchetAPriv,
      localRatchetPub: ratchetAPub,
      lastRemoteRatchetPub: ratchetBPub,
      sessionId: 'test-session',
    );

    final bRatchet = await FsDoubleRatchet.initRatchet(
      rootKey0: bState.rootKey0,
      sendingChainKey0: bState.sendingChainKey0,
      receivingChainKey0: bState.receivingChainKey0,
      localRatchetPriv: ratchetBPriv,
      localRatchetPub: ratchetBPub,
      lastRemoteRatchetPub: ratchetAPub,
      sessionId: 'test-session',
    );

    return (aRatchet, bRatchet);
  }

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_strip_test_');
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
  });

  // ── Unit tests on MessageRecord ──────────────────────────────────────────

  group('MessageRecord.isFsEncrypted', () {
    test('defaults to false', () {
      const record = MessageRecord(
        id: '1',
        senderId: 'a',
        recipientId: 'b',
        direction: 'outgoing',
        timestamp: 1,
      );
      expect(record.isFsEncrypted, isFalse);
    });

    test('round-trips through toMap/fromMap when true', () {
      const record = MessageRecord(
        id: '1',
        senderId: 'a',
        recipientId: 'b',
        direction: 'outgoing',
        timestamp: 1,
        isFsEncrypted: true,
      );
      final map = record.toMap();
      expect(map['isFsEncrypted'], isTrue);

      final restored = MessageRecord.fromMap(map);
      expect(restored.isFsEncrypted, isTrue);
    });

    test('fromMap defaults to false when key is absent', () {
      final map = {
        'id': '1',
        'senderId': 'a',
        'recipientId': 'b',
        'direction': 'outgoing',
        'timestamp': 1,
      };
      final record = MessageRecord.fromMap(map);
      expect(record.isFsEncrypted, isFalse);
    });

    test('toMap omits isFsEncrypted when false', () {
      const record = MessageRecord(
        id: '1',
        senderId: 'a',
        recipientId: 'b',
        direction: 'outgoing',
        timestamp: 1,
        isFsEncrypted: false,
      );
      expect(record.toMap().containsKey('isFsEncrypted'), isFalse);
    });
  });

  group('MessageRecord.copyWith clearText', () {
    test('clearText: true sets text to null even when text was non-null', () {
      const record = MessageRecord(
        id: '1',
        senderId: 'a',
        recipientId: 'b',
        direction: 'outgoing',
        timestamp: 1,
        text: 'secret plaintext',
      );
      final stripped = record.copyWith(clearText: true);
      expect(stripped.text, isNull);
      expect(stripped.id, '1'); // other fields preserved
    });

    test('clearText: false preserves existing text', () {
      const record = MessageRecord(
        id: '1',
        senderId: 'a',
        recipientId: 'b',
        direction: 'outgoing',
        timestamp: 1,
        text: 'keep me',
      );
      final same = record.copyWith(clearText: false);
      expect(same.text, 'keep me');
    });
  });

  // ── Repository stripEncryptedPlaintext ──────────────────────────────────

  group('stripEncryptedPlaintext', () {
    test('fails closed without an active storage scope', () async {
      final repo = MessagesRepository();
      await expectLater(
        repo.stripEncryptedPlaintext(),
        throwsA(isA<StateError>()),
      );
      repo.dispose();
    });

    test('strips text from all messages with ciphertextBase64', () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = await openRepo(storageKey);

      // Legacy encrypted message (has ciphertext + text)
      await repo.add(const MessageRecord(
        id: 'legacy-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 100,
        text: 'legacy plaintext',
        ciphertextBase64: 'cipher-legacy',
        nonceBase64: 'nonce-legacy',
        keyTag: 'orig',
      ));

      // FS encrypted message WITH flag (new-style)
      await repo.add(const MessageRecord(
        id: 'fs-new-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 200,
        text: 'fs plaintext new',
        ciphertextBase64: 'cipher-fs',
        nonceBase64: 'nonce-fs',
        isFsEncrypted: true,
        keyTag: 'orig',
      ));

      // FS encrypted message WITHOUT flag (old-style, pre-PR#40)
      await repo.add(const MessageRecord(
        id: 'fs-old-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 300,
        text: 'fs plaintext old',
        ciphertextBase64: 'cipher-fs-old',
        nonceBase64: 'nonce-fs-old',
        isFsEncrypted: false, // ← no flag, but was actually FS
        keyTag: 'orig',
      ));

      // Unencrypted message (no ciphertext — should NOT be stripped)
      await repo.add(const MessageRecord(
        id: 'plain-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 400,
        text: 'plain message (no encryption)',
        keyTag: 'orig',
      ));

      // Before strip: all have text
      var messages = await repo.getAllMessages();
      expect(messages.length, 4);
      expect(messages.every((m) => m.text != null), isTrue);

      // Strip
      await repo.stripEncryptedPlaintext();

      // After strip
      messages = await repo.getAllMessages();
      final byId = {for (final m in messages) m.id: m};

      // Encrypted messages: text stripped
      expect(byId['legacy-1']!.text, isNull);
      expect(byId['fs-new-1']!.text, isNull);
      expect(byId['fs-old-1']!.text, isNull);

      // Unencrypted message: text preserved
      expect(byId['plain-1']!.text, 'plain message (no encryption)');

      repo.dispose();
    });

    test('persists stripped state across repo reopen', () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = await openRepo(storageKey);

      await repo.add(const MessageRecord(
        id: 'msg-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 100,
        text: 'secret',
        ciphertextBase64: 'cipher',
        nonceBase64: 'nonce',
        keyTag: 'orig',
      ));

      await repo.stripEncryptedPlaintext();
      repo.dispose();

      // Reopen with same key — text should still be null
      final reopened = await openRepo(storageKey);
      final messages = await reopened.getAllMessages();
      expect(messages.single.text, isNull);
      expect(messages.single.ciphertextBase64, 'cipher');
      reopened.dispose();
    });

    test('is idempotent — second call is a no-op', () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = await openRepo(storageKey);

      await repo.add(const MessageRecord(
        id: 'msg-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 100,
        text: 'secret',
        ciphertextBase64: 'cipher',
        nonceBase64: 'nonce',
        keyTag: 'orig',
      ));

      await repo.stripEncryptedPlaintext();
      await repo.stripEncryptedPlaintext(); // should not throw

      final messages = await repo.getAllMessages();
      expect(messages.single.text, isNull);
      repo.dispose();
    });
  });

  group('identity-reset multi-context sanitization', () {
    test('strips known contexts and preserves opaque ciphertext aggregates',
        () async {
      final primaryKey = await deriveStorageKey('primary');
      final activePassphraseKey = await deriveStorageKey('active-passphrase');
      final unknownContextKey = await deriveStorageKey('unknown-context');
      final repo = await openRepo(primaryKey);

      Future<void> addForCurrentContext(String id, String text) {
        return repo.add(MessageRecord(
          id: id,
          senderId: 'alice',
          recipientId: 'bob',
          direction: 'incoming',
          timestamp: 100,
          text: text,
          ciphertextBase64: 'cipher-$id',
          nonceBase64: 'nonce-$id',
          keyTag: id,
        ));
      }

      await addForCurrentContext('primary', 'primary plaintext');
      await repo.setActiveContext(
        scopeToken: 'test-scope',
        storageKey: activePassphraseKey,
      );
      await addForCurrentContext('active-passphrase', 'passphrase plaintext');
      await repo.setActiveContext(
        scopeToken: 'test-scope',
        storageKey: unknownContextKey,
      );
      await addForCurrentContext('unknown-context', 'opaque plaintext');

      await repo.setActiveContext(
        scopeToken: null,
        storageKey: null,
      );
      await repo.stripEncryptedPlaintextAcrossKnownContexts(
        scopeToken: 'test-scope',
        additionalStorageKeys: [primaryKey, activePassphraseKey],
      );

      await repo.setActiveContext(
        scopeToken: 'test-scope',
        storageKey: primaryKey,
      );
      expect((await repo.getAllMessages()).single.text, isNull);

      await repo.setActiveContext(
        scopeToken: 'test-scope',
        storageKey: activePassphraseKey,
      );
      expect((await repo.getAllMessages()).single.text, isNull);

      await repo.setActiveContext(
        scopeToken: 'test-scope',
        storageKey: unknownContextKey,
      );
      expect(
        (await repo.getAllMessages()).single.text,
        'opaque plaintext',
        reason: 'unknown ciphertext contexts preserve plausible deniability',
      );
      repo.dispose();
    });
  });

  // ── End-to-end: encrypt → strip → re-decrypt ────────────────────────────

  group('§12.3 end-to-end: identity reset strips plaintext', () {
    test('legacy message can be re-decrypted after plaintext is stripped',
        () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());

      // Alice encrypts a legacy (non-FS) message
      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: 'Ciao, come stai?',
          timestamp: 1700000000,
        ),
      );

      // No FS was used
      expect(encResult.newRatchetState, isNull);

      // Simulate: message was stored with plaintext, then stripped on reset
      final record = MessageRecord(
        id: 'msg-legacy',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 1700000000,
        text: null, // ← STRIPPED (was 'Ciao, come stai?' before reset)
        ciphertextBase64: encResult.message.ciphertextBase64,
        nonceBase64: encResult.message.nonceBase64,
        isFsEncrypted: false,
      );
      expect(record.text, isNull);

      // After identity restore: same keys → legacy decryption succeeds
      final decResult = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: EncryptedMessage(
          version: 1,
          senderId: record.senderId,
          recipientId: record.recipientId,
          nonceBase64: record.nonceBase64!,
          ciphertextBase64: record.ciphertextBase64!,
        ),
      );

      expect(decResult.payload.text, 'Ciao, come stai?');
      expect(decResult.fsDecryptFailed, isFalse);
    });

    test('FS message cannot be re-decrypted after strip — ratchet gone',
        () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());
      final (aRatchet, _) = await buildRatchets();

      // Alice encrypts an FS message
      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: 'FS segreto',
          timestamp: 1700000000,
        ),
        ratchetState: aRatchet,
      );
      expect(encResult.newRatchetState, isNotNull);

      // After identity reset: ratchet state is destroyed.
      // Attempting to decrypt WITHOUT ratchet state should return
      // fsDecryptFailed: true (outer legacy layer decrypts, inner FS fails).
      final decResult = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: encResult.message,
        ratchetState: null, // ← ratchet gone after reset
      );

      expect(decResult.fsDecryptFailed, isTrue);
      // The payload text should be empty (placeholder from failed FS decrypt)
      expect(decResult.payload.text, isEmpty);
    });

    test(
        'old FS message without isFsEncrypted flag: outer decrypts but inner fails',
        () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());
      final (aRatchet, _) = await buildRatchets();

      // Alice encrypts an FS message (pre-PR#40: no isFsEncrypted flag)
      final encResult = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: 'Old FS message',
          timestamp: 1700000000,
        ),
        ratchetState: aRatchet,
      );

      // Simulate old record: isFsEncrypted=false (field didn't exist)
      final record = MessageRecord(
        id: 'msg-old-fs',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 1700000000,
        text: null, // ← stripped by stripEncryptedPlaintext
        ciphertextBase64: encResult.message.ciphertextBase64,
        nonceBase64: encResult.message.nonceBase64,
        isFsEncrypted: false, // ← old record, no flag
      );

      // After reset: try decrypt without ratchet
      final decResult = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: EncryptedMessage(
          version: 1,
          senderId: record.senderId,
          recipientId: record.recipientId,
          nonceBase64: record.nonceBase64!,
          ciphertextBase64: record.ciphertextBase64!,
        ),
        ratchetState: null,
      );

      // FS inner layer fails — outer legacy layer succeeded but that's not enough
      expect(decResult.fsDecryptFailed, isTrue);
    });
  });

  // ── Full flow simulation ────────────────────────────────────────────────

  group('§12.3 full flow: encrypt → persist → reset → restore → verify', () {
    test(
        'after identity reset, FS messages show placeholder, legacy re-decrypt',
        () async {
      final service = EncryptionService();
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());
      final (aRatchet, _) = await buildRatchets();

      // 1) Alice sends a LEGACY message to Bob
      final legacyEnc = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: 'Legacy hello',
          timestamp: 1700000000,
        ),
      );
      expect(legacyEnc.newRatchetState, isNull);

      // 2) Alice sends an FS message to Bob
      final fsEnc = await service.encrypt(
        senderPrivateKeyBase64: alice.privateKeyBase64,
        recipientPublicKeyBase64: bob.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'alice',
          recipientId: 'bob',
          text: 'FS segreto!',
          timestamp: 1700000001,
        ),
        ratchetState: aRatchet,
      );
      expect(fsEnc.newRatchetState, isNotNull);

      // 3) Both messages are stored in the repository with plaintext
      final storageKey = await deriveStorageKey('orig');
      final repo = await openRepo(storageKey);

      await repo.add(MessageRecord(
        id: 'msg-legacy',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 1700000000,
        text: 'Legacy hello',
        ciphertextBase64: legacyEnc.message.ciphertextBase64,
        nonceBase64: legacyEnc.message.nonceBase64,
        isFsEncrypted: false,
        keyTag: 'orig',
      ));

      await repo.add(MessageRecord(
        id: 'msg-fs',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 1700000001,
        text: 'FS segreto!',
        ciphertextBase64: fsEnc.message.ciphertextBase64,
        nonceBase64: fsEnc.message.nonceBase64,
        isFsEncrypted: false, // ← old-style, no flag
        keyTag: 'orig',
      ));

      // Verify both readable before reset
      var messages = await repo.getAllMessages();
      expect(messages.length, 2);
      expect(messages.every((m) => m.text != null), isTrue);

      // 4) IDENTITY RESET: strip all encrypted plaintext
      await repo.stripEncryptedPlaintext();

      // Verify both stripped
      messages = await repo.getAllMessages();
      expect(messages.every((m) => m.text == null), isTrue);
      expect(messages.every((m) => m.ciphertextBase64 != null), isTrue);

      // 5) IDENTITY RESTORE: same keys from seed phrase

      // 5a) Re-decrypt legacy message → should succeed
      final legacyMsg = messages.firstWhere((m) => m.id == 'msg-legacy');
      final legacyDec = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: EncryptedMessage(
          version: 1,
          senderId: legacyMsg.senderId,
          recipientId: legacyMsg.recipientId,
          nonceBase64: legacyMsg.nonceBase64!,
          ciphertextBase64: legacyMsg.ciphertextBase64!,
        ),
      );
      expect(legacyDec.fsDecryptFailed, isFalse);
      expect(legacyDec.payload.text, 'Legacy hello');

      // 5b) Re-decrypt FS message without ratchet → should fail
      final fsMsg = messages.firstWhere((m) => m.id == 'msg-fs');
      final fsDec = await service.decrypt(
        recipientPrivateKeyBase64: bob.privateKeyBase64,
        senderPublicKeyBase64: alice.publicKeyBase64,
        message: EncryptedMessage(
          version: 1,
          senderId: fsMsg.senderId,
          recipientId: fsMsg.recipientId,
          nonceBase64: fsMsg.nonceBase64!,
          ciphertextBase64: fsMsg.ciphertextBase64!,
        ),
        ratchetState: null, // ← ratchet destroyed on reset
      );
      expect(fsDec.fsDecryptFailed, isTrue);

      repo.dispose();
    });
  });
}
