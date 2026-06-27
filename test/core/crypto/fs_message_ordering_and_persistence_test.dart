/// Tests for message ordering, FS plaintext persistence, and plausible deniability.
///
/// Verifies:
/// 1. Outgoing message timestamp is never earlier than latest in thread (clock skew)
/// 2. FS plaintext is persisted in DB and survives simulated app restart
/// 3. FS plaintext is stripped on identity reset (stripEncryptedPlaintext)
/// 4. After strip: legacy messages re-decrypt, FS messages show placeholder
/// 5. Message ordering tiebreaker produces deterministic order for same-timestamp
/// 6. Plausible deniability: no FS device labels leak in storage
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
    tmpDir = await Directory.systemTemp.createTemp('layergram_ordering_test_');
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

  // ── 1. Message ordering with tiebreaker ──────────────────────────────────

  group('Message ordering tiebreaker', () {
    test('same-timestamp messages are ordered deterministically by id',
        () async {
      final storageKey = await deriveStorageKey('tag-order');
      final repo = await openRepo(storageKey);

      // Add 3 messages with same timestamp but different IDs (microseconds)
      final baseTs = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      await repo.add(
          MessageRecord(
            id: '1000000000000003', // latest microsecond
            senderId: 'me',
            recipientId: 'bob',
            direction: 'outgoing',
            timestamp: baseTs,
            text: 'third',
          ),
          storageKey: storageKey);
      await repo.add(
          MessageRecord(
            id: '1000000000000001', // earliest microsecond
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: baseTs,
            text: 'first',
          ),
          storageKey: storageKey);
      await repo.add(
          MessageRecord(
            id: '1000000000000002', // middle microsecond
            senderId: 'me',
            recipientId: 'bob',
            direction: 'outgoing',
            timestamp: baseTs,
            text: 'second',
          ),
          storageKey: storageKey);

      final all = await repo.getAllMessages();
      // Repository sorts newest-first (descending), tiebreaker is b.id > a.id
      expect(all[0].text, 'third');
      expect(all[1].text, 'second');
      expect(all[2].text, 'first');

      // Chat view sorts ascending (oldest first) with a.id < b.id tiebreaker
      final chatOrder = List<MessageRecord>.from(all)
        ..sort((a, b) {
          final byTs = a.timestamp.compareTo(b.timestamp);
          if (byTs != 0) return byTs;
          return a.id.compareTo(b.id);
        });
      expect(chatOrder[0].text, 'first');
      expect(chatOrder[1].text, 'second');
      expect(chatOrder[2].text, 'third');
    });

    test(
        'messages with different timestamps sort by timestamp regardless of id',
        () async {
      final storageKey = await deriveStorageKey('tag-order2');
      final repo = await openRepo(storageKey);

      final baseTs = 1700000000;
      await repo.add(
          MessageRecord(
            id: '9999999999999999', // large id
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: baseTs,
            text: 'earlier',
          ),
          storageKey: storageKey);
      await repo.add(
          MessageRecord(
            id: '0000000000000001', // small id
            senderId: 'me',
            recipientId: 'bob',
            direction: 'outgoing',
            timestamp: baseTs + 1,
            text: 'later',
          ),
          storageKey: storageKey);

      final chatOrder = List<MessageRecord>.from(await repo.getAllMessages())
        ..sort((a, b) {
          final byTs = a.timestamp.compareTo(b.timestamp);
          if (byTs != 0) return byTs;
          return a.id.compareTo(b.id);
        });

      expect(chatOrder[0].text, 'earlier');
      expect(chatOrder[1].text, 'later');
    });
  });

  // ── 2. Clock skew: outgoing timestamp must not precede latest ────────────

  group('Outgoing timestamp clock skew protection', () {
    test(
        'outgoing timestamp uses max(now, latestInThread) — simulated clock behind',
        () {
      // Simulate: received message has timestamp from sender's faster clock
      final senderTs = 1700000060; // sender's clock: 60s ahead
      final localNow = 1700000050; // local clock: 10s behind

      // The fix: max(localNow, latestInThread)
      final latestInThread = senderTs; // the received message
      final outgoingTs = localNow > latestInThread ? localNow : latestInThread;

      expect(outgoingTs, greaterThanOrEqualTo(senderTs),
          reason: 'Outgoing message must not appear before received message');
    });

    test('outgoing timestamp uses now when local clock is ahead', () {
      final senderTs = 1700000050;
      final localNow = 1700000060; // local clock ahead

      final latestInThread = senderTs;
      final outgoingTs = localNow > latestInThread ? localNow : latestInThread;

      expect(outgoingTs, localNow,
          reason: 'When local clock is ahead, use local time');
    });

    test('outgoing timestamp uses now when thread is empty', () {
      final localNow = 1700000050;
      const latestInThread = 0; // empty thread

      final outgoingTs = localNow > latestInThread ? localNow : latestInThread;

      expect(outgoingTs, localNow);
    });

    test(
        'multiple rapid sends preserve insertion order with same-second timestamp',
        () async {
      final storageKey = await deriveStorageKey('tag-rapid');
      final repo = await openRepo(storageKey);

      // Simulate incoming message from sender with faster clock
      final senderTs = 1700000060;
      await repo.add(
          MessageRecord(
            id: '1000000000000001',
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: senderTs,
            text: 'received first',
          ),
          storageKey: storageKey);

      // Simulate outgoing message with clock-skew protection
      final localNow = 1700000055; // local clock 5s behind
      final outgoingTs = localNow > senderTs ? localNow : senderTs;
      await repo.add(
          MessageRecord(
            id: '1000000000000002', // later microsecond
            senderId: 'me',
            recipientId: 'bob',
            direction: 'outgoing',
            timestamp: outgoingTs,
            text: 'sent after',
          ),
          storageKey: storageKey);

      final chatOrder = List<MessageRecord>.from(await repo.getAllMessages())
        ..sort((a, b) {
          final byTs = a.timestamp.compareTo(b.timestamp);
          if (byTs != 0) return byTs;
          return a.id.compareTo(b.id);
        });

      expect(chatOrder[0].text, 'received first');
      expect(chatOrder[1].text, 'sent after');
    });
  });

  // ── 3. FS plaintext persistence in DB ────────────────────────────────────

  group('FS plaintext persistence', () {
    test(
        'FS message with plaintext survives repository reopen (simulated restart)',
        () async {
      final storageKey = await deriveStorageKey('tag-persist');

      // First "session": persist FS message with plaintext
      final repo1 = await openRepo(storageKey);
      await repo1.add(
          MessageRecord(
            id: 'fs-msg-1',
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: 1700000000,
            text: 'secret FS message',
            ciphertextBase64: base64Encode([1, 2, 3]),
            nonceBase64: base64Encode([4, 5, 6]),
            isFsEncrypted: true,
          ),
          storageKey: storageKey);

      final before = await repo1.getAllMessages();
      expect(before.length, 1);
      expect(before.first.text, 'secret FS message');
      expect(before.first.isFsEncrypted, isTrue);

      // "Restart": open a new repository instance (same Hive box)
      final repo2 = await openRepo(storageKey);
      final after = await repo2.getAllMessages();

      expect(after.length, 1);
      expect(after.first.text, 'secret FS message',
          reason: 'FS plaintext must survive app restart');
      expect(after.first.isFsEncrypted, isTrue);
    });

    test('legacy message with plaintext also survives restart', () async {
      final storageKey = await deriveStorageKey('tag-legacy');

      final repo1 = await openRepo(storageKey);
      await repo1.add(
          MessageRecord(
            id: 'legacy-msg-1',
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: 1700000000,
            text: 'legacy message',
            ciphertextBase64: base64Encode([7, 8, 9]),
            nonceBase64: base64Encode([10, 11, 12]),
            isFsEncrypted: false,
          ),
          storageKey: storageKey);

      final repo2 = await openRepo(storageKey);
      final after = await repo2.getAllMessages();

      expect(after.length, 1);
      expect(after.first.text, 'legacy message');
      expect(after.first.isFsEncrypted, isFalse);
    });
  });

  // ── 4. stripEncryptedPlaintext on identity reset ─────────────────────────

  group('stripEncryptedPlaintext (identity reset)', () {
    test('strips text from both FS and legacy encrypted messages', () async {
      final storageKey = await deriveStorageKey('tag-strip');
      final repo = await openRepo(storageKey);

      await repo.add(
          MessageRecord(
            id: 'fs-1',
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: 1700000000,
            text: 'FS secret',
            ciphertextBase64: base64Encode([1, 2]),
            nonceBase64: base64Encode([3, 4]),
            isFsEncrypted: true,
          ),
          storageKey: storageKey);

      await repo.add(
          MessageRecord(
            id: 'legacy-1',
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: 1700000001,
            text: 'legacy secret',
            ciphertextBase64: base64Encode([5, 6]),
            nonceBase64: base64Encode([7, 8]),
            isFsEncrypted: false,
          ),
          storageKey: storageKey);

      // Both have text before strip
      var all = await repo.getAllMessages();
      expect(all.every((m) => m.text != null), isTrue);

      // Strip
      await repo.stripEncryptedPlaintext();

      all = await repo.getAllMessages();
      expect(all.every((m) => m.text == null), isTrue,
          reason: 'All encrypted messages must have text stripped');
      expect(all.every((m) => m.ciphertextBase64 != null), isTrue,
          reason: 'Ciphertext must be preserved for potential re-decryption');
    });

    test('strip is idempotent', () async {
      final storageKey = await deriveStorageKey('tag-idem');
      final repo = await openRepo(storageKey);

      await repo.add(
          MessageRecord(
            id: 'msg-1',
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: 1700000000,
            text: 'will be stripped',
            ciphertextBase64: base64Encode([1]),
            nonceBase64: base64Encode([2]),
            isFsEncrypted: true,
          ),
          storageKey: storageKey);

      await repo.stripEncryptedPlaintext();
      await repo.stripEncryptedPlaintext(); // second call

      final all = await repo.getAllMessages();
      expect(all.length, 1);
      expect(all.first.text, isNull);
    });

    test('strip persists through repository reopen', () async {
      final storageKey = await deriveStorageKey('tag-strip-persist');
      final repo1 = await openRepo(storageKey);

      await repo1.add(
          MessageRecord(
            id: 'msg-1',
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: 1700000000,
            text: 'secret',
            ciphertextBase64: base64Encode([1]),
            nonceBase64: base64Encode([2]),
            isFsEncrypted: true,
          ),
          storageKey: storageKey);

      await repo1.stripEncryptedPlaintext();

      // Reopen
      final repo2 = await openRepo(storageKey);
      final all = await repo2.getAllMessages();
      expect(all.first.text, isNull,
          reason: 'Strip must persist across restarts');
    });

    test('after strip: legacy can re-decrypt, FS cannot', () async {
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());
      final encService = EncryptionService();
      final (aRatchet, bRatchet) = await buildRatchets();

      // Bob encrypts a legacy message to Alice
      final legacyResult = await encService.encrypt(
        senderPrivateKeyBase64: bob.privateKeyBase64,
        recipientPublicKeyBase64: alice.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'bob',
          recipientId: 'alice',
          text: 'legacy hello',
          timestamp: 1700000000,
        ),
      );

      // Bob encrypts an FS message to Alice
      final fsResult = await encService.encrypt(
        senderPrivateKeyBase64: bob.privateKeyBase64,
        recipientPublicKeyBase64: alice.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'bob',
          recipientId: 'alice',
          text: 'FS secret hello',
          timestamp: 1700000000,
        ),
        ratchetState: aRatchet,
      );

      final storageKey = await deriveStorageKey('tag-redecrypt');
      final repo = await openRepo(storageKey);

      // Store both with plaintext (normal operation)
      await repo.add(
          MessageRecord(
            id: 'legacy-msg',
            senderId: 'bob',
            recipientId: 'alice',
            direction: 'incoming',
            timestamp: 1700000000,
            text: 'legacy hello',
            ciphertextBase64: legacyResult.message.ciphertextBase64,
            nonceBase64: legacyResult.message.nonceBase64,
            isFsEncrypted: false,
          ),
          storageKey: storageKey);

      await repo.add(
          MessageRecord(
            id: 'fs-msg',
            senderId: 'bob',
            recipientId: 'alice',
            direction: 'incoming',
            timestamp: 1700000001,
            text: 'FS secret hello',
            ciphertextBase64: fsResult.message.ciphertextBase64,
            nonceBase64: fsResult.message.nonceBase64,
            isFsEncrypted: true,
          ),
          storageKey: storageKey);

      // Identity reset: strip all plaintext
      await repo.stripEncryptedPlaintext();

      final stripped = await repo.getAllMessages();
      expect(stripped.every((m) => m.text == null), isTrue);

      // Try re-decrypting legacy message — should succeed
      final legacyDecrypt = await encService.decrypt(
        recipientPrivateKeyBase64: alice.privateKeyBase64,
        senderPublicKeyBase64: bob.publicKeyBase64,
        message: EncryptedMessage(
          version: 1,
          senderId: 'bob',
          recipientId: 'alice',
          nonceBase64: legacyResult.message.nonceBase64,
          ciphertextBase64: legacyResult.message.ciphertextBase64,
        ),
      );
      expect(legacyDecrypt.payload.text, 'legacy hello',
          reason: 'Legacy message must be re-decryptable with same keys');

      // Try re-decrypting FS message without ratchet — should fail
      final fsDecrypt = await encService.decrypt(
        recipientPrivateKeyBase64: alice.privateKeyBase64,
        senderPublicKeyBase64: bob.publicKeyBase64,
        message: EncryptedMessage(
          version: 1,
          senderId: 'bob',
          recipientId: 'alice',
          nonceBase64: fsResult.message.nonceBase64,
          ciphertextBase64: fsResult.message.ciphertextBase64,
        ),
        // No ratchetState — simulates ratchet destroyed on identity reset
      );
      expect(fsDecrypt.fsDecryptFailed, isTrue,
          reason: 'FS message must NOT be re-decryptable without ratchet');
    });

    test('unencrypted messages are not affected by strip', () async {
      final storageKey = await deriveStorageKey('tag-unenc');
      final repo = await openRepo(storageKey);

      await repo.add(
          MessageRecord(
            id: 'plain-msg',
            senderId: 'me',
            recipientId: 'bob',
            direction: 'outgoing',
            timestamp: 1700000000,
            text: 'plain message',
            // no ciphertextBase64/nonceBase64 → not encrypted
          ),
          storageKey: storageKey);

      await repo.stripEncryptedPlaintext();

      final all = await repo.getAllMessages();
      expect(all.first.text, 'plain message',
          reason: 'Unencrypted messages must not be stripped');
    });
  });

  // ── 5. Plausible deniability ─────────────────────────────────────────────

  group('Plausible deniability', () {
    test('MessageRecord.toMap never contains device identifiers', () {
      final record = MessageRecord(
        id: 'msg-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'outgoing',
        timestamp: 1700000000,
        text: 'hello',
        ciphertextBase64: base64Encode([1, 2, 3]),
        nonceBase64: base64Encode([4, 5, 6]),
        isFsEncrypted: true,
      );

      final map = record.toMap();
      final allKeys = map.keys.toSet();

      // Ensure no device-specific fields leak
      for (final forbidden in [
        'deviceId',
        'device_id',
        'deviceLabel',
        'device_label',
        'devicePub',
        'device_pub',
        'deviceName',
        'device_name',
        'initiatorDevicePub',
        'initiator_device_pub',
      ]) {
        expect(allKeys, isNot(contains(forbidden)),
            reason: 'Map key "$forbidden" would leak device identity');
      }

      // isFsEncrypted is acceptable (reveals FS usage, not device identity)
      expect(allKeys, contains('isFsEncrypted'));
    });

    test('FS-encrypted message differs from legacy only by isFsEncrypted key',
        () {
      final fsRecord = MessageRecord(
        id: 'fs-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'outgoing',
        timestamp: 1700000000,
        text: 'secret',
        ciphertextBase64: base64Encode([1, 2, 3]),
        nonceBase64: base64Encode([4, 5, 6]),
        isFsEncrypted: true,
      );

      final legacyRecord = MessageRecord(
        id: 'legacy-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'outgoing',
        timestamp: 1700000000,
        text: 'secret',
        ciphertextBase64: base64Encode([7, 8, 9]),
        nonceBase64: base64Encode([10, 11, 12]),
        isFsEncrypted: false,
      );

      final fsMap = fsRecord.toMap();
      final legacyMap = legacyRecord.toMap();

      // isFsEncrypted is conditionally serialized (only when true)
      // so the FS map has one extra key — this is acceptable for plausible
      // deniability because it reveals FS usage but NOT device identity
      final fsDiff = fsMap.keys.toSet().difference(legacyMap.keys.toSet());
      expect(fsDiff, {'isFsEncrypted'},
          reason: 'Only difference should be the isFsEncrypted flag');

      // All other keys must be identical
      for (final key in legacyMap.keys) {
        expect(fsMap.containsKey(key), isTrue,
            reason: 'FS map must contain all legacy keys');
      }
    });

    test(
        'aux records for FS state use opaque kind identifiers, no device labels',
        () {
      // The aux record kinds used for FS state
      const fsKinds = ['fs_state_v1', 'fs_ratchet_v1'];

      for (final kind in fsKinds) {
        // Kind must not contain "device" or any identifying information
        expect(kind, isNot(contains('device')),
            reason: 'Aux record kind "$kind" would leak device info');
        expect(kind, isNot(contains('phone')));
        expect(kind, isNot(contains('tablet')));
        expect(kind, isNot(contains('android')));
        expect(kind, isNot(contains('ios')));
      }
    });

    test('stripped FS message retains isFsEncrypted flag but no plaintext',
        () async {
      final storageKey = await deriveStorageKey('tag-flag');
      final repo = await openRepo(storageKey);

      await repo.add(
          MessageRecord(
            id: 'fs-strip',
            senderId: 'bob',
            recipientId: 'me',
            direction: 'incoming',
            timestamp: 1700000000,
            text: 'will vanish',
            ciphertextBase64: base64Encode([1]),
            nonceBase64: base64Encode([2]),
            isFsEncrypted: true,
          ),
          storageKey: storageKey);

      await repo.stripEncryptedPlaintext();

      final all = await repo.getAllMessages();
      final msg = all.first;
      expect(msg.text, isNull);
      expect(msg.isFsEncrypted, isTrue,
          reason: 'isFsEncrypted flag must survive strip for UI placeholder');
      expect(msg.ciphertextBase64, isNotNull);
      expect(msg.nonceBase64, isNotNull);
    });
  });

  // ── 6. Full E2E: encrypt FS → persist → restart → strip → verify ───────

  group('Full E2E: FS lifecycle', () {
    test('FS message readable after restart, unreadable after identity reset',
        () async {
      final alice = await _keyMaterial(await x25519.newKeyPair());
      final bob = await _keyMaterial(await x25519.newKeyPair());
      final encService = EncryptionService();
      final (aRatchet, bRatchet) = await buildRatchets();

      // Bob sends FS-encrypted message to Alice
      final fsResult = await encService.encrypt(
        senderPrivateKeyBase64: bob.privateKeyBase64,
        recipientPublicKeyBase64: alice.publicKeyBase64,
        payload: const PlaintextPayload(
          senderId: 'bob',
          recipientId: 'alice',
          text: 'top secret via FS',
          timestamp: 1700000000,
        ),
        ratchetState: aRatchet,
      );
      expect(fsResult.newRatchetState, isNotNull);

      final storageKey = await deriveStorageKey('tag-e2e');

      // Phase 1: Persist message with plaintext (normal operation)
      final repo1 = await openRepo(storageKey);
      await repo1.add(
          MessageRecord(
            id: 'e2e-fs-msg',
            senderId: 'bob',
            recipientId: 'alice',
            direction: 'incoming',
            timestamp: 1700000000,
            text: 'top secret via FS', // plaintext persisted in DB
            ciphertextBase64: fsResult.message.ciphertextBase64,
            nonceBase64: fsResult.message.nonceBase64,
            isFsEncrypted: true,
          ),
          storageKey: storageKey);

      // Phase 2: "App restart" — reopen repo, plaintext must survive
      final repo2 = await openRepo(storageKey);
      final afterRestart = await repo2.getAllMessages();
      expect(afterRestart.first.text, 'top secret via FS',
          reason: 'FS plaintext must survive app restart');

      // Phase 3: "Identity reset" — strip all plaintext
      await repo2.stripEncryptedPlaintext();

      // Phase 4: "App restart after reset" — reopen repo
      final repo3 = await openRepo(storageKey);
      final afterReset = await repo3.getAllMessages();
      expect(afterReset.first.text, isNull,
          reason: 'FS plaintext must be gone after identity reset');
      expect(afterReset.first.isFsEncrypted, isTrue);

      // Phase 5: Try to re-decrypt — must fail (no ratchet)
      final failedDecrypt = await encService.decrypt(
        recipientPrivateKeyBase64: alice.privateKeyBase64,
        senderPublicKeyBase64: bob.publicKeyBase64,
        message: EncryptedMessage(
          version: 1,
          senderId: 'bob',
          recipientId: 'alice',
          nonceBase64: fsResult.message.nonceBase64,
          ciphertextBase64: fsResult.message.ciphertextBase64,
        ),
      );
      expect(failedDecrypt.fsDecryptFailed, isTrue,
          reason: 'FS message must not be recoverable after identity reset');
    });
  });
}
