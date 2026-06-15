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

Future<
    ({
      LocalIdentity identity,
      ({String privateKeyBase64, String publicKeyBase64}) keys,
    })> _restoreIdentityFromMnemonicForTest(
  String mnemonic, {
  required String displayName,
  IdentityDerivationVersion? derivationVersion,
}) async {
  final manager = IdentityManager(
    seedService: SeedService(),
    localIdentityVault: LocalIdentityVault(
      secureStorage: _InMemorySecureStorageService(),
    ),
  );
  final identity = derivationVersion == null
      ? await manager.restoreIdentityFromMnemonic(
          mnemonic,
          displayName: displayName,
        )
      : await manager.restoreIdentityFromMnemonic(
          mnemonic,
          displayName: displayName,
          derivationVersion: derivationVersion,
        );
  final privateKeyBase64 = await manager.getLocalPrivateKeyBase64();
  return (
    identity: identity,
    keys: (
      privateKeyBase64: privateKeyBase64!,
      publicKeyBase64: identity.publicKeyBase64,
    ),
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

Future<_Fixture> _createFixtureFor({
  required String localIdentityId,
  required String localDisplayName,
  required ({String privateKeyBase64, String publicKeyBase64}) localKeys,
  required Map<String, ({String privateKeyBase64, String publicKeyBase64})>
      contactKeysById,
}) async {
  final localIdentity = LocalIdentity(
    identityId: localIdentityId,
    publicKeyBase64: localKeys.publicKeyBase64,
    fingerprint: 'fp-$localIdentityId',
    displayName: localDisplayName,
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
  final contacts = contactKeysById.entries
      .map(
        (entry) => RemoteIdentity(
          identityId: entry.key,
          publicKeyBase64: entry.value.publicKeyBase64,
          fingerprint: 'fp-${entry.key}',
          displayName: entry.key,
        ),
      )
      .toList();
  final messagesRepository = _FakeMessagesRepository(const []);
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
        scopeToken: 'home-controller-cache-test-$localIdentityId',
        auxStorageKey: auxStorageKey,
      );

  return _Fixture(
    container: container,
    encryptionService: encryptionService,
    contacts: contacts,
    localKeys: localKeys,
    contactKeysById: contactKeysById,
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
      'Advanced hidden message decodes on same identity device without ratchet',
      () async {
        final senderFixture = await _createFixture();
        final recipient = senderFixture.contacts.first;
        final recipientKeys =
            senderFixture.contactKeysById[recipient.identityId]!;
        final receiverFixture = await _createFixtureFor(
          localIdentityId: recipient.identityId,
          localDisplayName: recipient.displayName,
          localKeys: recipientKeys,
          contactKeysById: {'me': senderFixture.localKeys},
        );
        addTearDown(() {
          senderFixture.identitiesRepository.dispose();
          senderFixture.messagesRepository.dispose();
          senderFixture.container.dispose();
          receiverFixture.identitiesRepository.dispose();
          receiverFixture.messagesRepository.dispose();
          receiverFixture.container.dispose();
        });

        const sessionId = 'session-hidden-advanced';
        final sessionManager = senderFixture.container
            .read(fsSessionManagerProvider(recipient.identityId));
        sessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: sessionId,
        );
        senderFixture.container
            .read(fsRatchetStateCacheProvider.notifier)
            .state = {sessionId: _testRatchet(sessionId)};

        final senderController =
            senderFixture.container.read(homeControllerProvider);
        const secret = 'Advanced FS hidden message from another device';
        final hidden = await senderController.generateHiddenMessage(
          coverText: List.filled(
            30,
            'This is a normal looking carrier message.',
          ).join(' '),
          secretText: secret,
          recipient: recipient,
        );

        final receiverController =
            receiverFixture.container.read(homeControllerProvider);
        final outcome = await receiverController.decodeHiddenMessage(
          hidden,
          hintContactId: 'me',
        );

        expect(outcome.kind, DecodeKind.success);
        expect(outcome.payload?.senderId, 'me');
        expect(outcome.payload?.text, secret);
      },
    );

    test(
      'First message from same identity device decodes on FS-active receiver',
      () async {
        final disp2Fixture = await _createFixture();
        final disp1Contact = disp2Fixture.contacts.first;
        final disp1Keys =
            disp2Fixture.contactKeysById[disp1Contact.identityId]!;
        final disp3Fixture = await _createFixtureFor(
          localIdentityId: disp1Contact.identityId,
          localDisplayName: disp1Contact.displayName,
          localKeys: disp1Keys,
          contactKeysById: {'me': disp2Fixture.localKeys},
        );
        addTearDown(() {
          disp2Fixture.identitiesRepository.dispose();
          disp2Fixture.messagesRepository.dispose();
          disp2Fixture.container.dispose();
          disp3Fixture.identitiesRepository.dispose();
          disp3Fixture.messagesRepository.dispose();
          disp3Fixture.container.dispose();
        });

        const existingSessionId = 'disp1-disp2-green-session';
        final receiverSessionManager = disp2Fixture.container.read(
          fsSessionManagerProvider(disp1Contact.identityId),
        );
        receiverSessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: existingSessionId,
        );
        disp2Fixture.container
            .read(fsRatchetStateCacheProvider.notifier)
            .state = {existingSessionId: _testRatchet(existingSessionId)};

        final disp3Controller =
            disp3Fixture.container.read(homeControllerProvider);
        const secret = 'First hello from disp3 using disp1 identity';
        final hidden = await disp3Controller.generateHiddenMessage(
          coverText: List.filled(
            30,
            'This is a normal looking carrier message.',
          ).join(' '),
          secretText: secret,
          recipient: disp3Fixture.contacts.single,
        );

        final disp2Controller =
            disp2Fixture.container.read(homeControllerProvider);
        final outcome = await disp2Controller.decodeHiddenMessage(
          hidden,
          hintContactId: disp1Contact.identityId,
        );

        expect(outcome.kind, DecodeKind.success);
        expect(outcome.payload?.senderId, disp1Contact.identityId);
        expect(outcome.payload?.recipientId, 'me');
        expect(outcome.payload?.text, secret);
      },
    );

    test(
      'First link from same identity device decodes on FS-active receiver',
      () async {
        final disp2Fixture = await _createFixture();
        final disp1Contact = disp2Fixture.contacts.first;
        final disp1Keys =
            disp2Fixture.contactKeysById[disp1Contact.identityId]!;
        final disp3Fixture = await _createFixtureFor(
          localIdentityId: disp1Contact.identityId,
          localDisplayName: disp1Contact.displayName,
          localKeys: disp1Keys,
          contactKeysById: {'me': disp2Fixture.localKeys},
        );
        addTearDown(() {
          disp2Fixture.identitiesRepository.dispose();
          disp2Fixture.messagesRepository.dispose();
          disp2Fixture.container.dispose();
          disp3Fixture.identitiesRepository.dispose();
          disp3Fixture.messagesRepository.dispose();
          disp3Fixture.container.dispose();
        });

        const existingSessionId = 'disp1-disp2-green-session';
        final receiverSessionManager = disp2Fixture.container.read(
          fsSessionManagerProvider(disp1Contact.identityId),
        );
        receiverSessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: existingSessionId,
        );
        disp2Fixture.container
            .read(fsRatchetStateCacheProvider.notifier)
            .state = {existingSessionId: _testRatchet(existingSessionId)};

        final disp3Controller =
            disp3Fixture.container.read(homeControllerProvider);
        const secret = 'First link hello from disp3 using disp1 identity';
        final encrypted = await disp3Controller.encryptForRecipient(
          secretText: secret,
          recipient: disp3Fixture.contacts.single,
        );
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider('me')).state,
          FsSessionState.fsInitSent,
        );
        final link = disp3Controller.buildLinkPayload(encrypted.message);
        expect(link, startsWith('layergram://m/'));

        final disp2Controller =
            disp2Fixture.container.read(homeControllerProvider);
        final outcome = await disp2Controller.decodeHiddenMessage(
          link,
          hintContactId: disp1Contact.identityId,
        );

        expect(outcome.kind, DecodeKind.success);
        expect(outcome.payload?.senderId, disp1Contact.identityId);
        expect(outcome.payload?.recipientId, 'me');
        expect(outcome.payload?.text, secret);
      },
    );

    test(
      'First link from mnemonic-restored device decodes beside existing green FS',
      () async {
        const mnemonic =
            'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        final originalDisp1 = await _restoreIdentityFromMnemonicForTest(
          mnemonic,
          displayName: 'Disp1 original',
          derivationVersion: SeedService.preferredIdentityDerivationVersion,
        );
        final restoredDisp3 = await _restoreIdentityFromMnemonicForTest(
          mnemonic,
          displayName: 'Disp1 restored on disp3',
        );
        expect(
          restoredDisp3.identity.identityId,
          originalDisp1.identity.identityId,
        );
        expect(
          restoredDisp3.keys.publicKeyBase64,
          originalDisp1.keys.publicKeyBase64,
        );

        final disp2Keys = await _keyMaterial(await X25519().newKeyPair());
        final disp2Fixture = await _createFixtureFor(
          localIdentityId: 'me',
          localDisplayName: 'Disp2',
          localKeys: disp2Keys,
          contactKeysById: {
            originalDisp1.identity.identityId: originalDisp1.keys,
          },
        );
        final disp1Contact = disp2Fixture.contacts.single;
        final disp3Fixture = await _createFixtureFor(
          localIdentityId: restoredDisp3.identity.identityId,
          localDisplayName: restoredDisp3.identity.displayName,
          localKeys: restoredDisp3.keys,
          contactKeysById: {'me': disp2Keys},
        );
        addTearDown(() {
          disp2Fixture.identitiesRepository.dispose();
          disp2Fixture.messagesRepository.dispose();
          disp2Fixture.container.dispose();
          disp3Fixture.identitiesRepository.dispose();
          disp3Fixture.messagesRepository.dispose();
          disp3Fixture.container.dispose();
        });

        const existingSessionId = 'disp1-disp2-green-session';
        final receiverSessionManager = disp2Fixture.container.read(
          fsSessionManagerProvider(disp1Contact.identityId),
        );
        receiverSessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: existingSessionId,
        );
        disp2Fixture.container
            .read(fsRatchetStateCacheProvider.notifier)
            .state = {existingSessionId: _testRatchet(existingSessionId)};

        final disp3Controller =
            disp3Fixture.container.read(homeControllerProvider);
        const secret = 'Hello from disp3 restored from disp1 phrase';
        final encrypted = await disp3Controller.encryptForRecipient(
          secretText: secret,
          recipient: disp3Fixture.contacts.single,
        );
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider('me')).state,
          FsSessionState.fsInitSent,
        );
        final link = disp3Controller.buildLinkPayload(encrypted.message);

        final outcome = await disp2Fixture.container
            .read(homeControllerProvider)
            .decodeHiddenMessage(link, hintContactId: disp1Contact.identityId);

        expect(outcome.kind, DecodeKind.success);
        expect(outcome.payload?.senderId, disp1Contact.identityId);
        expect(outcome.payload?.recipientId, 'me');
        expect(outcome.payload?.text, secret);
      },
    );

    test('Layergram link decodes when pasted with surrounding text', () async {
      final senderFixture = await _createFixture();
      final recipient = senderFixture.contacts.first;
      final recipientKeys =
          senderFixture.contactKeysById[recipient.identityId]!;
      final receiverFixture = await _createFixtureFor(
        localIdentityId: recipient.identityId,
        localDisplayName: recipient.displayName,
        localKeys: recipientKeys,
        contactKeysById: {'me': senderFixture.localKeys},
      );
      addTearDown(() {
        senderFixture.identitiesRepository.dispose();
        senderFixture.messagesRepository.dispose();
        senderFixture.container.dispose();
        receiverFixture.identitiesRepository.dispose();
        receiverFixture.messagesRepository.dispose();
        receiverFixture.container.dispose();
      });

      final senderController =
          senderFixture.container.read(homeControllerProvider);
      const secret = 'Link pasted with context still decodes';
      final encrypted = await senderController.encryptForRecipient(
        secretText: secret,
        recipient: recipient,
      );
      final link = senderController.buildLinkPayload(encrypted.message);

      final receiverController =
          receiverFixture.container.read(homeControllerProvider);
      final outcome = await receiverController.decodeHiddenMessage(
        'Forwarded message: $link Thanks',
        hintContactId: 'me',
      );

      expect(outcome.kind, DecodeKind.success);
      expect(outcome.payload?.text, secret);
    });

    test('Layergram link decodes when payload is line wrapped', () async {
      final senderFixture = await _createFixture();
      final recipient = senderFixture.contacts.first;
      final recipientKeys =
          senderFixture.contactKeysById[recipient.identityId]!;
      final receiverFixture = await _createFixtureFor(
        localIdentityId: recipient.identityId,
        localDisplayName: recipient.displayName,
        localKeys: recipientKeys,
        contactKeysById: {'me': senderFixture.localKeys},
      );
      addTearDown(() {
        senderFixture.identitiesRepository.dispose();
        senderFixture.messagesRepository.dispose();
        senderFixture.container.dispose();
        receiverFixture.identitiesRepository.dispose();
        receiverFixture.messagesRepository.dispose();
        receiverFixture.container.dispose();
      });

      final senderController =
          senderFixture.container.read(homeControllerProvider);
      const secret = 'Wrapped link still decodes';
      final encrypted = await senderController.encryptForRecipient(
        secretText: secret,
        recipient: recipient,
      );
      final link = senderController.buildLinkPayload(encrypted.message);
      final prefix = 'layergram://m/';
      final encoded = link.substring(prefix.length);
      final wrappedLink =
          '$prefix${encoded.substring(0, 24)}\n${encoded.substring(24, 61)} '
          '${encoded.substring(61)}';

      final receiverController =
          receiverFixture.container.read(homeControllerProvider);
      final outcome = await receiverController.decodeHiddenMessage(
        'Forwarded:\n$wrappedLink\nThanks',
        hintContactId: 'me',
      );

      expect(outcome.kind, DecodeKind.success);
      expect(outcome.payload?.text, secret);
    });

    test(
      'Fresh reinstall with new identity returns notForMe for the old contact',
      () async {
        final disp2Fixture = await _createFixture();
        final oldDisp1Contact = disp2Fixture.contacts.first;
        addTearDown(() {
          disp2Fixture.identitiesRepository.dispose();
          disp2Fixture.messagesRepository.dispose();
          disp2Fixture.container.dispose();
        });

        const existingSessionId = 'old-disp1-disp2-green-session';
        final receiverSessionManager = disp2Fixture.container.read(
          fsSessionManagerProvider(oldDisp1Contact.identityId),
        );
        receiverSessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: existingSessionId,
        );
        disp2Fixture.container
            .read(fsRatchetStateCacheProvider.notifier)
            .state = {existingSessionId: _testRatchet(existingSessionId)};

        final freshDisp1Fixture = await _createFixtureFor(
          localIdentityId: 'disp1-reinstalled-new-key',
          localDisplayName: 'Disp1 Reinstalled',
          localKeys: await _keyMaterial(await X25519().newKeyPair()),
          contactKeysById: {'me': disp2Fixture.localKeys},
        );
        addTearDown(() {
          freshDisp1Fixture.identitiesRepository.dispose();
          freshDisp1Fixture.messagesRepository.dispose();
          freshDisp1Fixture.container.dispose();
        });

        final hidden = await freshDisp1Fixture.container
            .read(homeControllerProvider)
            .generateHiddenMessage(
              coverText: List.filled(
                30,
                'This is a normal looking carrier message.',
              ).join(' '),
              secretText: 'Hello after reinstall with a new identity',
              recipient: freshDisp1Fixture.contacts.single,
            );

        final outcome = await disp2Fixture.container
            .read(homeControllerProvider)
            .decodeHiddenMessage(
              hidden,
              hintContactId: oldDisp1Contact.identityId,
            );

        expect(outcome.kind, DecodeKind.notForMe);
      },
    );

    test(
      'Fresh reinstall with new imported identity decodes beside old FS session',
      () async {
        final oldDisp1Keys = await _keyMaterial(await X25519().newKeyPair());
        final freshDisp1Keys = await _keyMaterial(await X25519().newKeyPair());
        final disp2Keys = await _keyMaterial(await X25519().newKeyPair());
        final disp2Fixture = await _createFixtureFor(
          localIdentityId: 'me',
          localDisplayName: 'Disp2',
          localKeys: disp2Keys,
          contactKeysById: {
            'disp1-old': oldDisp1Keys,
            'disp1-reinstalled-new-key': freshDisp1Keys,
          },
        );
        addTearDown(() {
          disp2Fixture.identitiesRepository.dispose();
          disp2Fixture.messagesRepository.dispose();
          disp2Fixture.container.dispose();
        });

        const existingSessionId = 'old-disp1-disp2-green-session';
        final receiverSessionManager = disp2Fixture.container.read(
          fsSessionManagerProvider('disp1-old'),
        );
        receiverSessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: existingSessionId,
        );
        disp2Fixture.container
            .read(fsRatchetStateCacheProvider.notifier)
            .state = {existingSessionId: _testRatchet(existingSessionId)};

        final freshDisp1Fixture = await _createFixtureFor(
          localIdentityId: 'disp1-reinstalled-new-key',
          localDisplayName: 'Disp1 Reinstalled',
          localKeys: freshDisp1Keys,
          contactKeysById: {'me': disp2Keys},
        );
        addTearDown(() {
          freshDisp1Fixture.identitiesRepository.dispose();
          freshDisp1Fixture.messagesRepository.dispose();
          freshDisp1Fixture.container.dispose();
        });

        const secret = 'Hello after reinstall with imported identity';
        final hidden = await freshDisp1Fixture.container
            .read(homeControllerProvider)
            .generateHiddenMessage(
              coverText: List.filled(
                30,
                'This is a normal looking carrier message.',
              ).join(' '),
              secretText: secret,
              recipient: freshDisp1Fixture.contacts.single,
            );

        final outcome = await disp2Fixture.container
            .read(homeControllerProvider)
            .decodeHiddenMessage(hidden, hintContactId: 'disp1-old');

        expect(outcome.kind, DecodeKind.success);
        expect(outcome.payload?.senderId, 'disp1-reinstalled-new-key');
        expect(outcome.payload?.recipientId, 'me');
        expect(outcome.payload?.text, secret);
      },
    );

    test('valid Layergram payload for another identity returns notForMe',
        () async {
      final senderFixture = await _createFixture();
      final unrelatedReceiver = await _createFixtureFor(
        localIdentityId: 'unrelated',
        localDisplayName: 'Unrelated',
        localKeys: await _keyMaterial(await X25519().newKeyPair()),
        contactKeysById: {'me': senderFixture.localKeys},
      );
      addTearDown(() {
        senderFixture.identitiesRepository.dispose();
        senderFixture.messagesRepository.dispose();
        senderFixture.container.dispose();
        unrelatedReceiver.identitiesRepository.dispose();
        unrelatedReceiver.messagesRepository.dispose();
        unrelatedReceiver.container.dispose();
      });

      final senderController =
          senderFixture.container.read(homeControllerProvider);
      final hidden = await senderController.generateHiddenMessage(
        coverText: List.filled(
          30,
          'This is a normal looking carrier message.',
        ).join(' '),
        secretText: 'This is not for the unrelated receiver',
        recipient: senderFixture.contacts.first,
      );

      final outcome = await unrelatedReceiver.container
          .read(homeControllerProvider)
          .decodeHiddenMessage(hidden, hintContactId: 'me');

      expect(outcome.kind, DecodeKind.notForMe);
    });

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
