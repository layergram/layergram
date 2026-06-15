import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_message_classification.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/identities_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/messages_repository.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/home/home_controller.dart';

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

Uint8List _bytes(int seed) => Uint8List.fromList(
      List<int>.generate(32, (i) => (seed + i) % 256),
    );

RatchetState _testRatchet(String sessionId) => RatchetState(
      sessionId: sessionId,
      rootKey: _bytes(1),
      sendingChainKey: _bytes(33),
      receivingChainKey: _bytes(65),
      localRatchetPriv: _bytes(97),
      localRatchetPub: _bytes(129),
      lastRemoteRatchetPub: _bytes(161),
      sendCounter: 0,
      recvCounter: 0,
      skippedKeys: const {},
    );

class _InMemorySecureStorageService extends SecureStorageService {
  final Map<String, String> _values = <String, String>{};

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<String?> read(String key) async {
    return _values[key];
  }

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }

  @override
  Future<void> deleteAll() async {
    _values.clear();
  }
}

class _FakeIdentityManager extends IdentityManager {
  _FakeIdentityManager({
    required LocalIdentity localIdentity,
    required String privateKeyBase64,
  })  : _localIdentity = localIdentity,
        _privateKeyBase64 = privateKeyBase64,
        super(
          seedService: SeedService(),
          localIdentityVault: LocalIdentityVault(
            secureStorage: _InMemorySecureStorageService(),
          ),
        );

  final LocalIdentity _localIdentity;
  final String _privateKeyBase64;

  @override
  Future<LocalIdentity?> getLocalIdentity() async {
    return _localIdentity;
  }

  @override
  Future<String?> getLocalPrivateKeyBase64() async {
    return _privateKeyBase64;
  }
}

class _FakeIdentitiesRepository extends IdentitiesRepository {
  _FakeIdentitiesRepository(this.contacts) : super(ownerIdentityId: 'owner');

  final List<RemoteIdentity> contacts;

  @override
  Stream<List<RemoteIdentity>> watchRemote() async* {
    yield List<RemoteIdentity>.unmodifiable(contacts);
  }

  @override
  Future<RemoteIdentity?> getRemoteById(String identityId) async {
    for (final contact in contacts) {
      if (contact.identityId == identityId) {
        return contact;
      }
    }
    return null;
  }
}

class _FakeMessagesRepository extends MessagesRepository {
  _FakeMessagesRepository(this.messages);

  final List<MessageRecord> messages;

  @override
  Future<List<MessageRecord>> getAllMessages() async {
    return List<MessageRecord>.unmodifiable(messages);
  }
}

class _CountingEncryptionService extends EncryptionService {
  int deriveCalls = 0;

  @override
  Future<SecretKey> deriveSymmetricKey({
    required String localPrivateKeyBase64,
    required String remotePublicKeyBase64,
  }) async {
    deriveCalls += 1;
    return super.deriveSymmetricKey(
      localPrivateKeyBase64: localPrivateKeyBase64,
      remotePublicKeyBase64: remotePublicKeyBase64,
    );
  }
}

class _Fixture {
  _Fixture({
    required this.container,
    required this.encryptionService,
    required this.contacts,
    required this.localKeys,
    required this.contactKeysById,
    required this.identitiesRepository,
    required this.messagesRepository,
  });

  final ProviderContainer container;
  final _CountingEncryptionService encryptionService;
  final List<RemoteIdentity> contacts;
  final ({String privateKeyBase64, String publicKeyBase64}) localKeys;
  final Map<String, ({String privateKeyBase64, String publicKeyBase64})>
      contactKeysById;
  final _FakeIdentitiesRepository identitiesRepository;
  final _FakeMessagesRepository messagesRepository;
}

Future<_Fixture> _createFixture() async {
  final x25519 = X25519();
  final localKeys = await _keyMaterial(await x25519.newKeyPair());
  final contactAKeys = await _keyMaterial(await x25519.newKeyPair());
  final contactBKeys = await _keyMaterial(await x25519.newKeyPair());

  final localIdentity = LocalIdentity(
    identityId: 'me',
    publicKeyBase64: localKeys.publicKeyBase64,
    fingerprint: 'fp-me',
    displayName: 'Me',
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
  final contacts = <RemoteIdentity>[
    RemoteIdentity(
      identityId: 'contact-a',
      publicKeyBase64: contactAKeys.publicKeyBase64,
      fingerprint: 'fp-a',
      displayName: 'Alice',
    ),
    RemoteIdentity(
      identityId: 'contact-b',
      publicKeyBase64: contactBKeys.publicKeyBase64,
      fingerprint: 'fp-b',
      displayName: 'Bob',
    ),
  ];
  final messagesRepository = _FakeMessagesRepository([
    const MessageRecord(
      id: '1',
      senderId: 'contact-a',
      recipientId: 'me',
      direction: 'incoming',
      timestamp: 1,
    ),
    const MessageRecord(
      id: '2',
      senderId: 'contact-a',
      recipientId: 'me',
      direction: 'incoming',
      timestamp: 2,
    ),
    const MessageRecord(
      id: '3',
      senderId: 'contact-b',
      recipientId: 'me',
      direction: 'incoming',
      timestamp: 3,
    ),
  ]);
  final identitiesRepository = _FakeIdentitiesRepository(contacts);
  final encryptionService = _CountingEncryptionService();
  final container = ProviderContainer(
    overrides: [
      identityManagerProvider.overrideWithValue(
        _FakeIdentityManager(
          localIdentity: localIdentity,
          privateKeyBase64: localKeys.privateKeyBase64,
        ),
      ),
      encryptionServiceProvider.overrideWithValue(encryptionService),
      identitiesRepositoryProvider.overrideWithValue(identitiesRepository),
      messagesRepositoryProvider.overrideWithValue(messagesRepository),
    ],
  );
  final auxStorageKey = await AuxRecordCipher.deriveAuxStorageKey(
    base64Decode(localKeys.privateKeyBase64),
  );
  container.read(auxRecordRepositoryProvider).setActiveContext(
        scopeToken: 'home-controller-cache-test',
        auxStorageKey: auxStorageKey,
      );

  return _Fixture(
    container: container,
    encryptionService: encryptionService,
    contacts: contacts,
    localKeys: localKeys,
    contactKeysById: {
      'contact-a': contactAKeys,
      'contact-b': contactBKeys,
    },
    identitiesRepository: identitiesRepository,
    messagesRepository: messagesRepository,
  );
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory tmpDir;

  setUpAll(() async {
    tmpDir = await Directory.systemTemp.createTemp(
      'layergram_home_controller_cache_',
    );
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.identitiesBoxName);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.identitiesBoxName).clear();
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
  });

  group('HomeController session decryption cache', () {
    test('warmSessionDisplayKeys is opt-in and reuses derived keys once warmed',
        () async {
      final fixture = await _createFixture();
      addTearDown(() {
        fixture.identitiesRepository.dispose();
        fixture.messagesRepository.dispose();
        fixture.container.dispose();
      });

      final controller = fixture.container.read(homeControllerProvider);

      await controller.warmSessionDisplayKeys();
      expect(fixture.encryptionService.deriveCalls, 0);

      fixture.container
          .read(sessionDecryptionCacheEnabledProvider.notifier)
          .state = true;
      await controller.warmSessionDisplayKeys();
      expect(fixture.encryptionService.deriveCalls, fixture.contacts.length);

      await controller.primeDisplayKey(contact: fixture.contacts.first);
      expect(fixture.encryptionService.deriveCalls, fixture.contacts.length);
    });

    test('clears cached keys when the app becomes locked', () async {
      final fixture = await _createFixture();
      addTearDown(() {
        fixture.identitiesRepository.dispose();
        fixture.messagesRepository.dispose();
        fixture.container.dispose();
      });

      fixture.container
          .read(sessionDecryptionCacheEnabledProvider.notifier)
          .state = true;
      final controller = fixture.container.read(homeControllerProvider);

      await controller.primeDisplayKey(contact: fixture.contacts.first);
      expect(fixture.encryptionService.deriveCalls, 1);

      fixture.container.read(appNeedsUnlockProvider.notifier).state = true;
      fixture.container.read(appNeedsUnlockProvider.notifier).state = false;

      await controller.primeDisplayKey(contact: fixture.contacts.first);
      expect(fixture.encryptionService.deriveCalls, 2);
    });

    test('clears cached keys when the identity context changes', () async {
      final fixture = await _createFixture();
      addTearDown(() {
        fixture.identitiesRepository.dispose();
        fixture.messagesRepository.dispose();
        fixture.container.dispose();
      });

      fixture.container
          .read(sessionDecryptionCacheEnabledProvider.notifier)
          .state = true;
      final controller = fixture.container.read(homeControllerProvider);

      await controller.primeDisplayKey(contact: fixture.contacts.first);
      expect(fixture.encryptionService.deriveCalls, 1);

      fixture.container.read(identityReloadTokenProvider.notifier).state += 1;

      await controller.primeDisplayKey(contact: fixture.contacts.first);
      expect(fixture.encryptionService.deriveCalls, 2);
    });

    test(
      'Advanced FS includes fallback readable by same identity without ratchet',
      () async {
        final fixture = await _createFixture();
        addTearDown(() {
          fixture.identitiesRepository.dispose();
          fixture.messagesRepository.dispose();
          fixture.container.dispose();
        });

        final contact = fixture.contacts.first;
        const sessionId = 'session-advanced';
        final sessionManager = fixture.container
            .read(fsSessionManagerProvider(contact.identityId));
        sessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: sessionId,
        );
        fixture.container.read(fsRatchetStateCacheProvider.notifier).state = {
          sessionId: _testRatchet(sessionId),
        };

        final controller = fixture.container.read(homeControllerProvider);
        const secret = 'Advanced FS stays readable from a restored device';
        final result = await controller.encryptForRecipient(
          secretText: secret,
          recipient: contact,
        );

        expect(result.isFsEncrypted, isTrue);
        expect(result.classification, FsMessageClassification.fsWithFallback);

        final contactKeys = fixture.contactKeysById[contact.identityId]!;
        final decoded = await fixture.encryptionService.decrypt(
          recipientPrivateKeyBase64: contactKeys.privateKeyBase64,
          senderPublicKeyBase64: fixture.localKeys.publicKeyBase64,
          message: result.message,
          allRatchetStates: const {},
        );

        expect(decoded.fsDecryptFailed, isFalse);
        expect(decoded.isFsEnvelope, isTrue);
        expect(decoded.hasLegacyFallback, isTrue);
        expect(decoded.payload.text, secret);
        expect(decoded.newRatchetState, isNull);
      },
    );

    test(
      'Strict FS omits fallback for same identity without ratchet',
      () async {
        final fixture = await _createFixture();
        addTearDown(() {
          fixture.identitiesRepository.dispose();
          fixture.messagesRepository.dispose();
          fixture.container.dispose();
        });

        final contact = fixture.contacts.first;
        const sessionId = 'session-strict';
        final sessionManager = fixture.container
            .read(fsSessionManagerProvider(contact.identityId));
        sessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: sessionId,
        );
        fixture.container.read(fsRatchetStateCacheProvider.notifier).state = {
          sessionId: _testRatchet(sessionId),
        };

        final modeService =
            fixture.container.read(fsSecurityModeServiceProvider);
        final fsController = fixture.container.read(
          fsOpportunisticControllerProvider(contact.identityId),
        );
        await modeService.setMode(
          contactId: contact.identityId,
          identityContext: fsController.identityContext,
          mode: FsSecurityMode.strict,
        );
        final strictController = fixture.container.read(
          fsStrictModeControllerProvider(contact.identityId),
        );
        expect(strictController.requestMaximum(sessionId).success, isTrue);
        expect(strictController.activateStrict(sessionId).success, isTrue);

        final controller = fixture.container.read(homeControllerProvider);
        final result = await controller.encryptForRecipient(
          secretText: 'Strict FS should not expose fallback',
          recipient: contact,
        );

        expect(result.isFsEncrypted, isTrue);
        expect(result.classification, FsMessageClassification.strictFs);

        final contactKeys = fixture.contactKeysById[contact.identityId]!;
        final decoded = await fixture.encryptionService.decrypt(
          recipientPrivateKeyBase64: contactKeys.privateKeyBase64,
          senderPublicKeyBase64: fixture.localKeys.publicKeyBase64,
          message: result.message,
          allRatchetStates: const {},
        );

        expect(decoded.fsDecryptFailed, isTrue);
        expect(decoded.isFsEnvelope, isTrue);
        expect(decoded.hasLegacyFallback, isFalse);
        expect(decoded.payload.text, isEmpty);
      },
    );
  });
}
