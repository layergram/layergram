import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/encryption_service.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_message_classification.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
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

        final thread = await receiverFixture.messagesRepository.getThread('me');
        final received =
            thread.singleWhere((message) => message.rawSource == hidden);
        expect(received.direction, 'incoming');
        expect(received.senderId, 'me');
        expect(received.recipientId, recipient.identityId);
        expect(received.isFsEncrypted, isTrue);
        expect(received.text, isNull);
        expect(
          await receiverController.decryptForDisplay(
            message: received,
            contact: receiverFixture.contacts.single,
          ),
          secret,
        );
      },
    );

    test(
      'Advanced FS out-of-order links decode on same identity without ratchet',
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

        const sessionId = 'session-advanced-out-of-order';
        final sessionManager = senderFixture.container.read(
          fsSessionManagerProvider(recipient.identityId),
        );
        sessionManager.setStateForTesting(
          FsSessionState.fsActive,
          sessionId: sessionId,
        );
        senderFixture.container
            .read(fsRatchetStateCacheProvider.notifier)
            .state = {sessionId: _testRatchet(sessionId)};

        final senderController =
            senderFixture.container.read(homeControllerProvider);
        final firstEncrypted = await senderController.encryptForRecipient(
          secretText: 'First Advanced FS copied message',
          recipient: recipient,
        );
        final secondEncrypted = await senderController.encryptForRecipient(
          secretText: 'Second Advanced FS copied message',
          recipient: recipient,
        );
        expect(
          firstEncrypted.classification,
          FsMessageClassification.fsWithFallback,
        );
        expect(
          secondEncrypted.classification,
          FsMessageClassification.fsWithFallback,
        );
        final firstLink =
            senderController.buildLinkPayload(firstEncrypted.message);
        final secondLink =
            senderController.buildLinkPayload(secondEncrypted.message);

        final receiverController =
            receiverFixture.container.read(homeControllerProvider);
        final secondOutcome = await receiverController.decodeHiddenMessage(
          secondLink,
          hintContactId: 'me',
        );
        final firstOutcome = await receiverController.decodeHiddenMessage(
          firstLink,
          hintContactId: 'me',
        );

        expect(secondOutcome.kind, DecodeKind.success);
        expect(
            secondOutcome.payload?.text, 'Second Advanced FS copied message');
        expect(firstOutcome.kind, DecodeKind.success);
        expect(firstOutcome.payload?.text, 'First Advanced FS copied message');
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
      'First cover from same identity device decodes after green FS handshake',
      () async {
        final x25519 = X25519();
        final disp1Keys = await _keyMaterial(await x25519.newKeyPair());
        final disp2Keys = await _keyMaterial(await x25519.newKeyPair());
        const disp1Id = 'ZDUAW7VUD2REOOXCEM42V2YLLWWEWXAHMANIQN6SSR2OUMZAA3SQ';
        const disp2Id = 'TUJLJ5VUTD7S5B3S2CMVLOHNPDNBVPWJVPDFUENAI4NRYDZIIQVA';

        final disp1Fixture = await _createFixtureFor(
          localIdentityId: disp1Id,
          localDisplayName: 'Disp1 A',
          localKeys: disp1Keys,
          contactKeysById: {disp2Id: disp2Keys},
        );
        final disp2Fixture = await _createFixtureFor(
          localIdentityId: disp2Id,
          localDisplayName: 'Disp2 B',
          localKeys: disp2Keys,
          contactKeysById: {disp1Id: disp1Keys},
        );
        final disp3Fixture = await _createFixtureFor(
          localIdentityId: disp1Id,
          localDisplayName: 'Disp3 A',
          localKeys: disp1Keys,
          contactKeysById: {disp2Id: disp2Keys},
        );
        addTearDown(() {
          disp1Fixture.identitiesRepository.dispose();
          disp1Fixture.messagesRepository.dispose();
          disp1Fixture.container.dispose();
          disp2Fixture.identitiesRepository.dispose();
          disp2Fixture.messagesRepository.dispose();
          disp2Fixture.container.dispose();
          disp3Fixture.identitiesRepository.dispose();
          disp3Fixture.messagesRepository.dispose();
          disp3Fixture.container.dispose();
        });

        final disp1Controller =
            disp1Fixture.container.read(homeControllerProvider);
        final disp2Controller =
            disp2Fixture.container.read(homeControllerProvider);
        final disp3Controller =
            disp3Fixture.container.read(homeControllerProvider);
        final disp2ContactForDisp1 = disp1Fixture.contacts.single;
        final disp1ContactForDisp2 = disp2Fixture.contacts.single;
        final disp2ContactForDisp3 = disp3Fixture.contacts.single;

        final init = await disp1Controller.encryptForRecipient(
          secretText: 'disp1 init',
          recipient: disp2ContactForDisp1,
        );
        expect(
          (await disp2Controller.decodeHiddenMessage(
            disp1Controller.buildLinkPayload(init.message),
            hintContactId: disp1Id,
          ))
              .kind,
          DecodeKind.success,
        );

        final reply = await disp2Controller.encryptForRecipient(
          secretText: 'disp2 reply',
          recipient: disp1ContactForDisp2,
        );
        expect(
          (await disp1Controller.decodeHiddenMessage(
            disp2Controller.buildLinkPayload(reply.message),
            hintContactId: disp2Id,
          ))
              .kind,
          DecodeKind.success,
        );

        final confirm = await disp1Controller.encryptForRecipient(
          secretText: 'disp1 confirm',
          recipient: disp2ContactForDisp1,
        );
        expect(
          (await disp2Controller.decodeHiddenMessage(
            disp1Controller.buildLinkPayload(confirm.message),
            hintContactId: disp1Id,
          ))
              .kind,
          DecodeKind.success,
        );

        expect(
          disp1Fixture.container.read(fsSessionManagerProvider(disp2Id)).state,
          FsSessionState.fsActive,
        );
        expect(
          disp2Fixture.container.read(fsSessionManagerProvider(disp1Id)).state,
          FsSessionState.fsActive,
        );
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider(disp2Id)).state,
          FsSessionState.legacyOnly,
        );

        const initSecret = 'first cover from disp3 A to disp2 B';
        final encrypted = await disp3Controller.encryptForRecipient(
          secretText: initSecret,
          recipient: disp2ContactForDisp3,
        );
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider(disp2Id)).state,
          FsSessionState.fsInitSent,
        );
        final rawBytes = encrypted.message.toRawBytes();
        final hidden =
            disp3Fixture.container.read(stegoEncoderProvider).encodeBytes(
                  'A' * StegoEncoder.minCoverLengthForBytes(rawBytes.length),
                  rawBytes,
                  maxTotalCharacters: 4000,
                );

        final outcome = await disp2Controller.decodeHiddenMessage(
          hidden,
          hintContactId: disp1Id,
        );

        expect(outcome.kind, DecodeKind.success);
        expect(outcome.payload?.senderId, disp1Id);
        expect(outcome.payload?.recipientId, disp2Id);
        expect(outcome.payload?.text, initSecret);

        final disp3Reply = await disp2Controller.encryptForRecipient(
          secretText: 'disp2 replies to disp3',
          recipient: disp1ContactForDisp2,
        );
        final disp3ReplyOutcome = await disp3Controller.decodeHiddenMessage(
          disp2Controller.buildLinkPayload(disp3Reply.message),
          hintContactId: disp2Id,
        );
        expect(disp3ReplyOutcome.kind, DecodeKind.success);
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider(disp2Id)).state,
          FsSessionState.fsReplySeen,
        );
        expect(
          disp3Fixture.container.read(fsStateForContactProvider(disp2Id)),
          FsSessionState.fsReplySeen,
        );

        final disp3Confirm = await disp3Controller.encryptForRecipient(
          secretText: 'disp3 confirms FS',
          recipient: disp2ContactForDisp3,
        );
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider(disp2Id)).state,
          FsSessionState.fsActive,
        );
        expect(
          disp3Fixture.container.read(fsStateForContactProvider(disp2Id)),
          FsSessionState.fsActive,
        );
        final disp3ConfirmOutcome = await disp2Controller.decodeHiddenMessage(
          disp3Controller.buildLinkPayload(disp3Confirm.message),
          hintContactId: disp1Id,
        );
        expect(disp3ConfirmOutcome.kind, DecodeKind.success);
        expect(
          disp2Fixture.container.read(fsStateForContactProvider(disp1Id)),
          FsSessionState.fsActive,
        );

        final fsMessage = await disp3Controller.encryptForRecipient(
          secretText: 'disp3 FS payload after confirm',
          recipient: disp2ContactForDisp3,
        );
        expect(fsMessage.isFsEncrypted, isTrue);
        expect(
          fsMessage.classification,
          FsMessageClassification.fsWithFallback,
        );
        expect(
          disp3Fixture.container.read(fsStateForContactProvider(disp2Id)),
          FsSessionState.fsActive,
        );
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
      'Same identity device retries FS handshake when reply is lost',
      () async {
        final x25519 = X25519();
        final disp1Keys = await _keyMaterial(await x25519.newKeyPair());
        final disp2Keys = await _keyMaterial(await x25519.newKeyPair());
        const disp1Id = 'ZDUAW7VUD2REOOXCEM42V2YLLWWEWXAHMANIQN6SSR2OUMZAA3SQ';
        const disp2Id = 'TUJLJ5VUTD7S5B3S2CMVLOHNPDNBVPWJVPDFUENAI4NRYDZIIQVA';

        final disp1Fixture = await _createFixtureFor(
          localIdentityId: disp1Id,
          localDisplayName: 'Disp1 A',
          localKeys: disp1Keys,
          contactKeysById: {disp2Id: disp2Keys},
        );
        final disp2Fixture = await _createFixtureFor(
          localIdentityId: disp2Id,
          localDisplayName: 'Disp2 B',
          localKeys: disp2Keys,
          contactKeysById: {disp1Id: disp1Keys},
        );
        final disp3Fixture = await _createFixtureFor(
          localIdentityId: disp1Id,
          localDisplayName: 'Disp3 A',
          localKeys: disp1Keys,
          contactKeysById: {disp2Id: disp2Keys},
        );
        addTearDown(() {
          disp1Fixture.identitiesRepository.dispose();
          disp1Fixture.messagesRepository.dispose();
          disp1Fixture.container.dispose();
          disp2Fixture.identitiesRepository.dispose();
          disp2Fixture.messagesRepository.dispose();
          disp2Fixture.container.dispose();
          disp3Fixture.identitiesRepository.dispose();
          disp3Fixture.messagesRepository.dispose();
          disp3Fixture.container.dispose();
        });

        final disp1Controller =
            disp1Fixture.container.read(homeControllerProvider);
        final disp2Controller =
            disp2Fixture.container.read(homeControllerProvider);
        final disp3Controller =
            disp3Fixture.container.read(homeControllerProvider);
        final disp2ContactForDisp1 = disp1Fixture.contacts.single;
        final disp1ContactForDisp2 = disp2Fixture.contacts.single;
        final disp2ContactForDisp3 = disp3Fixture.contacts.single;

        final init = await disp1Controller.encryptForRecipient(
          secretText: 'disp1 init',
          recipient: disp2ContactForDisp1,
        );
        expect(
          (await disp2Controller.decodeHiddenMessage(
            disp1Controller.buildLinkPayload(init.message),
            hintContactId: disp1Id,
          ))
              .kind,
          DecodeKind.success,
        );
        final reply = await disp2Controller.encryptForRecipient(
          secretText: 'disp2 reply',
          recipient: disp1ContactForDisp2,
        );
        expect(
          (await disp1Controller.decodeHiddenMessage(
            disp2Controller.buildLinkPayload(reply.message),
            hintContactId: disp2Id,
          ))
              .kind,
          DecodeKind.success,
        );
        final confirm = await disp1Controller.encryptForRecipient(
          secretText: 'disp1 confirm',
          recipient: disp2ContactForDisp1,
        );
        expect(
          (await disp2Controller.decodeHiddenMessage(
            disp1Controller.buildLinkPayload(confirm.message),
            hintContactId: disp1Id,
          ))
              .kind,
          DecodeKind.success,
        );
        expect(
          disp2Fixture.container.read(fsSessionManagerProvider(disp1Id)).state,
          FsSessionState.fsActive,
        );

        final lostReplyInit = await disp3Controller.encryptForRecipient(
          secretText: 'disp3 init whose reply is lost',
          recipient: disp2ContactForDisp3,
        );
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider(disp2Id)).state,
          FsSessionState.fsInitSent,
        );
        expect(
          (await disp2Controller.decodeHiddenMessage(
            disp3Controller.buildLinkPayload(lostReplyInit.message),
            hintContactId: disp1Id,
          ))
              .kind,
          DecodeKind.success,
        );
        expect(
          disp2Fixture.container
              .read(fsOpportunisticControllerProvider(disp1Id))
              .sessionManager
              .state,
          FsSessionState.fsInitSeen,
        );

        final lostReply = await disp2Controller.encryptForRecipient(
          secretText: 'disp2 reply that never reaches disp3',
          recipient: disp1ContactForDisp2,
        );
        expect(lostReply.classification, FsMessageClassification.fsNegotiation);
        expect(
          disp2Fixture.container
              .read(fsOpportunisticControllerProvider(disp1Id))
              .sessionManager
              .state,
          FsSessionState.fsReplySent,
        );

        final retryInit = await disp3Controller.encryptForRecipient(
          secretText: 'disp3 retries after lost reply',
          recipient: disp2ContactForDisp3,
        );
        expect(
          (await disp2Controller.decodeHiddenMessage(
            disp3Controller.buildLinkPayload(retryInit.message),
            hintContactId: disp1Id,
          ))
              .kind,
          DecodeKind.success,
        );
        expect(
          disp2Fixture.container
              .read(fsOpportunisticControllerProvider(disp1Id))
              .sessionManager
              .state,
          FsSessionState.fsInitSeen,
        );

        final retryReply = await disp2Controller.encryptForRecipient(
          secretText: 'disp2 replies to retry',
          recipient: disp1ContactForDisp2,
        );
        final retryReplyOutcome = await disp3Controller.decodeHiddenMessage(
          disp2Controller.buildLinkPayload(retryReply.message),
          hintContactId: disp2Id,
        );
        expect(retryReplyOutcome.kind, DecodeKind.success);
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider(disp2Id)).state,
          FsSessionState.fsReplySeen,
        );

        final retryConfirm = await disp3Controller.encryptForRecipient(
          secretText: 'disp3 confirms retry',
          recipient: disp2ContactForDisp3,
        );
        expect(
          disp3Fixture.container.read(fsSessionManagerProvider(disp2Id)).state,
          FsSessionState.fsActive,
        );
        expect(
          disp3Fixture.container.read(fsStateForContactProvider(disp2Id)),
          FsSessionState.fsActive,
        );
        expect(
          (await disp2Controller.decodeHiddenMessage(
            disp3Controller.buildLinkPayload(retryConfirm.message),
            hintContactId: disp1Id,
          ))
              .kind,
          DecodeKind.success,
        );
        expect(
          disp2Fixture.container
              .read(fsOpportunisticControllerProvider(disp1Id))
              .sessionManager
              .state,
          FsSessionState.fsActive,
        );
      },
    );

    test('Responder becomes FS active after confirm exchange', () async {
      final aliceFixture = await _createFixture();
      final bobContact = aliceFixture.contacts.first;
      final bobKeys = aliceFixture.contactKeysById[bobContact.identityId]!;
      final bobFixture = await _createFixtureFor(
        localIdentityId: bobContact.identityId,
        localDisplayName: bobContact.displayName,
        localKeys: bobKeys,
        contactKeysById: {'me': aliceFixture.localKeys},
      );
      addTearDown(() {
        aliceFixture.identitiesRepository.dispose();
        aliceFixture.messagesRepository.dispose();
        aliceFixture.container.dispose();
        bobFixture.identitiesRepository.dispose();
        bobFixture.messagesRepository.dispose();
        bobFixture.container.dispose();
      });

      final aliceController =
          aliceFixture.container.read(homeControllerProvider);
      final bobController = bobFixture.container.read(homeControllerProvider);
      final aliceContactForBob = bobFixture.contacts.single;

      final init = await aliceController.encryptForRecipient(
        secretText: 'alice init',
        recipient: bobContact,
      );
      expect(
        aliceFixture.container
            .read(fsSessionManagerProvider(bobContact.identityId))
            .state,
        FsSessionState.fsInitSent,
      );
      final initOutcome = await bobController.decodeHiddenMessage(
        aliceController.buildLinkPayload(init.message),
        hintContactId: aliceContactForBob.identityId,
      );
      expect(initOutcome.kind, DecodeKind.success);
      expect(
        bobFixture.container
            .read(fsSessionManagerProvider(aliceContactForBob.identityId))
            .state,
        FsSessionState.fsInitSeen,
      );

      final reply = await bobController.encryptForRecipient(
        secretText: 'bob reply',
        recipient: aliceContactForBob,
      );
      expect(
        bobFixture.container
            .read(fsSessionManagerProvider(aliceContactForBob.identityId))
            .state,
        FsSessionState.fsReplySent,
      );
      final replyOutcome = await aliceController.decodeHiddenMessage(
        bobController.buildLinkPayload(reply.message),
        hintContactId: bobContact.identityId,
      );
      expect(replyOutcome.kind, DecodeKind.success);
      expect(
        aliceFixture.container
            .read(fsSessionManagerProvider(bobContact.identityId))
            .state,
        FsSessionState.fsReplySeen,
      );

      final confirm = await aliceController.encryptForRecipient(
        secretText: 'alice confirm',
        recipient: bobContact,
      );
      expect(
        aliceFixture.container
            .read(fsSessionManagerProvider(bobContact.identityId))
            .state,
        FsSessionState.fsActive,
      );
      expect(
        aliceFixture.container
            .read(fsStateForContactProvider(bobContact.identityId)),
        FsSessionState.fsActive,
      );

      final confirmOutcome = await bobController.decodeHiddenMessage(
        aliceController.buildLinkPayload(confirm.message),
        hintContactId: aliceContactForBob.identityId,
      );
      expect(confirmOutcome.kind, DecodeKind.success);
      expect(
        bobFixture.container
            .read(fsSessionManagerProvider(aliceContactForBob.identityId))
            .state,
        FsSessionState.fsActive,
      );
      expect(
        bobFixture.container
            .read(fsStateForContactProvider(aliceContactForBob.identityId)),
        FsSessionState.fsActive,
      );

      final activeReply = await bobController.encryptForRecipient(
        secretText: 'bob active fs',
        recipient: aliceContactForBob,
      );
      expect(activeReply.isFsEncrypted, isTrue);
    });

    test('Restored responder keeps sending with active FS session', () async {
      final aliceFixture = await _createFixture();
      final bobContact = aliceFixture.contacts.first;
      final bobKeys = aliceFixture.contactKeysById[bobContact.identityId]!;
      final bobFixture = await _createFixtureFor(
        localIdentityId: bobContact.identityId,
        localDisplayName: bobContact.displayName,
        localKeys: bobKeys,
        contactKeysById: {'me': aliceFixture.localKeys},
      );
      addTearDown(() {
        aliceFixture.identitiesRepository.dispose();
        aliceFixture.messagesRepository.dispose();
        aliceFixture.container.dispose();
        bobFixture.identitiesRepository.dispose();
        bobFixture.messagesRepository.dispose();
        bobFixture.container.dispose();
      });

      final aliceController =
          aliceFixture.container.read(homeControllerProvider);
      final bobController = bobFixture.container.read(homeControllerProvider);
      final aliceContactForBob = bobFixture.contacts.single;

      final init = await aliceController.encryptForRecipient(
        secretText: 'alice init',
        recipient: bobContact,
      );
      expect(
        (await bobController.decodeHiddenMessage(
          aliceController.buildLinkPayload(init.message),
          hintContactId: aliceContactForBob.identityId,
        ))
            .kind,
        DecodeKind.success,
      );

      final reply = await bobController.encryptForRecipient(
        secretText: 'bob reply',
        recipient: aliceContactForBob,
      );
      expect(
        (await aliceController.decodeHiddenMessage(
          bobController.buildLinkPayload(reply.message),
          hintContactId: bobContact.identityId,
        ))
            .kind,
        DecodeKind.success,
      );

      final confirm = await aliceController.encryptForRecipient(
        secretText: 'alice confirm',
        recipient: bobContact,
      );
      expect(
        (await bobController.decodeHiddenMessage(
          aliceController.buildLinkPayload(confirm.message),
          hintContactId: aliceContactForBob.identityId,
        ))
            .kind,
        DecodeKind.success,
      );

      final bobActiveState = bobFixture.container
          .read(fsContactSecurityRegistryProvider)
          .lookup(
            contactId: aliceContactForBob.identityId,
            identityContext: 'primary',
            sessionId: bobFixture.container
                .read(fsSessionManagerProvider(aliceContactForBob.identityId))
                .activeSessionId,
          );
      expect(bobActiveState?.fsState, FsSessionState.fsActive);
      await bobFixture.container
          .read(fsStatePersistenceServiceProvider)
          .saveState(bobActiveState!);
      await bobFixture.container
          .read(fsStatePersistenceServiceProvider)
          .saveState(
            bobActiveState.copyWith(fsState: FsSessionState.fsConfirmed),
          );

      final restartedBob = await _createFixtureFor(
        localIdentityId: bobContact.identityId,
        localDisplayName: bobContact.displayName,
        localKeys: bobKeys,
        contactKeysById: {'me': aliceFixture.localKeys},
      );
      addTearDown(() {
        restartedBob.identitiesRepository.dispose();
        restartedBob.messagesRepository.dispose();
        restartedBob.container.dispose();
      });

      await restartedBob.container
          .read(fsStatePersistenceServiceProvider)
          .loadPersistedState();
      final ratchets = await restartedBob.container
          .read(fsRatchetPersistenceServiceProvider)
          .loadAllRatchetStates();
      restartedBob.container.read(fsRatchetStateCacheProvider.notifier).state =
          {
        for (final ratchet in ratchets) ratchet.sessionId: ratchet,
      };

      expect(
        restartedBob.container.read(fsStateForContactProvider('me')),
        FsSessionState.fsConfirmed,
      );
      expect(
        restartedBob.container.read(fsSessionManagerProvider('me')).state,
        FsSessionState.legacyOnly,
      );

      final afterRestart = await restartedBob.container
          .read(homeControllerProvider)
          .encryptForRecipient(
            secretText: 'bob after restart',
            recipient: restartedBob.contacts.single,
          );

      expect(afterRestart.isFsEncrypted, isTrue);
      expect(
        restartedBob.container.read(fsStateForContactProvider('me')),
        FsSessionState.fsActive,
      );
      expect(
        restartedBob.container.read(fsSessionManagerProvider('me')).state,
        FsSessionState.fsActive,
      );
    });

    test('Sender does not accept its own outbound link as an inbound message',
        () async {
      final disp2Fixture = await _createFixture();
      final disp1Contact = disp2Fixture.contacts.first;
      final disp1Keys = disp2Fixture.contactKeysById[disp1Contact.identityId]!;
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

      final disp3Controller =
          disp3Fixture.container.read(homeControllerProvider);
      final encrypted = await disp3Controller.encryptForRecipient(
        secretText: 'Outbound link must not decode locally as incoming',
        recipient: disp3Fixture.contacts.single,
      );
      final link = disp3Controller.buildLinkPayload(encrypted.message);

      final outcome = await disp3Controller.decodeHiddenMessage(
        link,
        hintContactId: 'me',
      );

      expect(outcome.kind, DecodeKind.notForMe);
      expect(disp3Fixture.messagesRepository.messages, isEmpty);
    });

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

    test('Repeated pasted legacy link remains decodable', () async {
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
      const secret = 'Manual paste can be retried';
      final encrypted = await senderController.encryptForRecipient(
        secretText: secret,
        recipient: recipient,
      );
      final link = senderController.buildLinkPayload(encrypted.message);
      final receiverController =
          receiverFixture.container.read(homeControllerProvider);

      final first = await receiverController.decodeHiddenMessage(
        link,
        hintContactId: 'me',
      );
      final second = await receiverController.decodeHiddenMessage(
        'Retrying the same copied link: $link',
        hintContactId: 'me',
      );

      expect(first.kind, DecodeKind.success);
      expect(first.payload?.text, secret);
      expect(second.kind, DecodeKind.success);
      expect(second.payload?.text, secret);
    });

    test('Out-of-order pasted legacy links decode independently', () async {
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
      final firstEncrypted = await senderController.encryptForRecipient(
        secretText: 'First copied message',
        recipient: recipient,
      );
      final secondEncrypted = await senderController.encryptForRecipient(
        secretText: 'Second copied message',
        recipient: recipient,
      );
      final firstLink =
          senderController.buildLinkPayload(firstEncrypted.message);
      final secondLink =
          senderController.buildLinkPayload(secondEncrypted.message);
      final receiverController =
          receiverFixture.container.read(homeControllerProvider);

      final secondOutcome = await receiverController.decodeHiddenMessage(
        secondLink,
        hintContactId: 'me',
      );
      final firstOutcome = await receiverController.decodeHiddenMessage(
        firstLink,
        hintContactId: 'me',
      );

      expect(secondOutcome.kind, DecodeKind.success);
      expect(secondOutcome.payload?.text, 'Second copied message');
      expect(firstOutcome.kind, DecodeKind.success);
      expect(firstOutcome.payload?.text, 'First copied message');
    });

    test('Stripped zero-width payload without link does not decode', () async {
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
      final hidden = await senderController.generateHiddenMessage(
        coverText: List.filled(
          30,
          'This normal looking carrier message.',
        ).join(' '),
        secretText: 'This hidden payload may be stripped',
        recipient: recipient,
      );
      final stripped = hidden.replaceAll(RegExp(r'[\u200B-\u200D\uFEFF]'), '');

      final outcome = await receiverFixture.container
          .read(homeControllerProvider)
          .decodeHiddenMessage(stripped, hintContactId: 'me');

      expect(outcome.kind, isNot(DecodeKind.success));
      expect(receiverFixture.messagesRepository.messages, isEmpty);
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

    test('Same identity id with a different key returns notForMe', () async {
      final oldDisp1Keys = await _keyMaterial(await X25519().newKeyPair());
      final differentDisp1Keys =
          await _keyMaterial(await X25519().newKeyPair());
      final disp2Keys = await _keyMaterial(await X25519().newKeyPair());
      final disp2Fixture = await _createFixtureFor(
        localIdentityId: 'me',
        localDisplayName: 'Disp2',
        localKeys: disp2Keys,
        contactKeysById: {'disp1': oldDisp1Keys},
      );
      final disp3Fixture = await _createFixtureFor(
        localIdentityId: 'disp1',
        localDisplayName: 'Disp1 restored with wrong key',
        localKeys: differentDisp1Keys,
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

      final encrypted = await disp3Fixture.container
          .read(homeControllerProvider)
          .encryptForRecipient(
            secretText: 'Same id but wrong key',
            recipient: disp3Fixture.contacts.single,
          );
      final link = disp3Fixture.container
          .read(homeControllerProvider)
          .buildLinkPayload(encrypted.message);

      final outcome = await disp2Fixture.container
          .read(homeControllerProvider)
          .decodeHiddenMessage(link, hintContactId: 'disp1');

      expect(outcome.kind, DecodeKind.notForMe);
      expect(disp2Fixture.messagesRepository.messages, isEmpty);
    });

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
        expect(
            (await strictController.requestMaximum(sessionId)).success, isTrue);
        expect(
            (await strictController.activateStrict(sessionId)).success, isTrue);

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

    test('Advanced FS keeps sending when another device appears', () async {
      final fixture = await _createFixture();
      addTearDown(() {
        fixture.identitiesRepository.dispose();
        fixture.messagesRepository.dispose();
        fixture.container.dispose();
      });

      final contact = fixture.contacts.first;
      const currentSessionId = 'session-advanced-current';
      const otherDeviceSessionId = 'session-advanced-other-device';
      final sessionManager =
          fixture.container.read(fsSessionManagerProvider(contact.identityId));
      sessionManager.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: currentSessionId,
      );
      fixture.container.read(fsRatchetStateCacheProvider.notifier).state = {
        currentSessionId: _testRatchet(currentSessionId),
      };

      final fsController = fixture.container.read(
        fsOpportunisticControllerProvider(contact.identityId),
      );
      fixture.container.read(fsContactSecurityRegistryProvider).upsert(
            FsContactSecurityState(
              contactId: contact.identityId,
              identityContext: fsController.identityContext,
              sessionId: otherDeviceSessionId,
              fsState: FsSessionState.fsActive,
            ),
          );

      final result = await fixture.container
          .read(homeControllerProvider)
          .encryptForRecipient(
            secretText: 'Advanced FS should stay smooth',
            recipient: contact,
          );

      expect(result.isFsEncrypted, isTrue);
      expect(result.classification, FsMessageClassification.fsWithFallback);
      expect(sessionManager.state, FsSessionState.fsActive);
    });

    test('Composer-safe cover estimate fits Advanced FS payload', () async {
      final x25519 = X25519();
      final localKeys = await _keyMaterial(await x25519.newKeyPair());
      final contactKeys = await _keyMaterial(await x25519.newKeyPair());
      final fixture = await _createFixtureFor(
        localIdentityId: 'ZDUAW7VUD2REOOXCEM42V2YLLWWEWXAHMANIQN6SSR2OUMZAA3SQ',
        localDisplayName: 'Layergram sender with realistic display name',
        localKeys: localKeys,
        contactKeysById: {
          'TUJLJ5VUTD7S5B3S2CMVLOHNPDNBVPWJVPDFUENAI4NRYDZIIQVA': contactKeys,
        },
      );
      addTearDown(() {
        fixture.identitiesRepository.dispose();
        fixture.messagesRepository.dispose();
        fixture.container.dispose();
      });

      final contact = fixture.contacts.first;
      const currentSessionId = 'session-advanced-payload-budget';
      final sessionManager =
          fixture.container.read(fsSessionManagerProvider(contact.identityId));
      sessionManager.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: currentSessionId,
      );
      fixture.container.read(fsRatchetStateCacheProvider.notifier).state = {
        currentSessionId: _testRatchet(currentSessionId),
      };

      const secret = 'x';
      final result = await fixture.container
          .read(homeControllerProvider)
          .encryptForRecipient(
            secretText: secret,
            recipient: contact,
          );
      final legacyEstimatedBytes =
          StegoEncoder.estimatedEncryptedPayloadBytes(secret);
      final composerEstimatedBytes =
          StegoEncoder.estimatedCoverMessagePayloadBytes(secret);
      final actualBytes = result.message.toRawBytes().length;
      final coverAcceptedByLegacyEstimate =
          'A' * StegoEncoder.minCoverLengthForBytes(legacyEstimatedBytes);
      final coverAcceptedByComposerEstimate =
          'A' * StegoEncoder.minCoverLengthForBytes(composerEstimatedBytes);

      expect(result.isFsEncrypted, isTrue);
      expect(actualBytes, greaterThan(legacyEstimatedBytes));
      expect(composerEstimatedBytes, greaterThanOrEqualTo(actualBytes));
      expect(
        StegoEncoder.canEmbedBytes(
          coverAcceptedByLegacyEstimate,
          legacyEstimatedBytes,
        ),
        isTrue,
      );
      expect(
        StegoEncoder.canEmbedBytes(coverAcceptedByLegacyEstimate, actualBytes),
        isFalse,
      );
      expect(
        StegoEncoder.missingCoverCapacityForBytes(
          coverAcceptedByLegacyEstimate,
          actualBytes,
        ),
        greaterThan(0),
      );
      expect(
        StegoEncoder.canEmbedBytes(
          coverAcceptedByComposerEstimate,
          actualBytes,
        ),
        isTrue,
      );
    });

    test('Strict FS blocks sending when another device appears', () async {
      final fixture = await _createFixture();
      addTearDown(() {
        fixture.identitiesRepository.dispose();
        fixture.messagesRepository.dispose();
        fixture.container.dispose();
      });

      final contact = fixture.contacts.first;
      const strictSessionId = 'session-strict-current';
      const otherDeviceSessionId = 'session-strict-other-device';
      final sessionManager =
          fixture.container.read(fsSessionManagerProvider(contact.identityId));
      sessionManager.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: strictSessionId,
      );
      fixture.container.read(fsRatchetStateCacheProvider.notifier).state = {
        strictSessionId: _testRatchet(strictSessionId),
      };

      final modeService = fixture.container.read(fsSecurityModeServiceProvider);
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
      expect((await strictController.requestMaximum(strictSessionId)).success,
          isTrue);
      expect((await strictController.activateStrict(strictSessionId)).success,
          isTrue);
      fixture.container.read(fsContactSecurityRegistryProvider).upsert(
            FsContactSecurityState(
              contactId: contact.identityId,
              identityContext: fsController.identityContext,
              sessionId: otherDeviceSessionId,
              fsState: FsSessionState.fsActive,
            ),
          );

      await expectLater(
        fixture.container.read(homeControllerProvider).encryptForRecipient(
              secretText: 'Strict FS should require repair',
              recipient: contact,
            ),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Unexpected device detected'),
          ),
        ),
      );
    });

    test('Strict FS blocks sending when local ratchet is missing', () async {
      final fixture = await _createFixture();
      addTearDown(() {
        fixture.identitiesRepository.dispose();
        fixture.messagesRepository.dispose();
        fixture.container.dispose();
      });

      final contact = fixture.contacts.first;
      const sessionId = 'session-strict-missing-ratchet';
      final sessionManager =
          fixture.container.read(fsSessionManagerProvider(contact.identityId));
      sessionManager.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: sessionId,
      );

      final modeService = fixture.container.read(fsSecurityModeServiceProvider);
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
      expect(
          (await strictController.requestMaximum(sessionId)).success, isTrue);
      expect(
          (await strictController.activateStrict(sessionId)).success, isTrue);

      fixture.container.read(fsRatchetStateCacheProvider.notifier).state = {};
      await fixture.container
          .read(fsRatchetPersistenceServiceProvider)
          .removeAllRatchetStates();

      final controller = fixture.container.read(homeControllerProvider);
      await expectLater(
        controller.encryptForRecipient(
          secretText: 'Strict FS must not downgrade',
          recipient: contact,
        ),
        throwsA(isA<StateError>()),
      );
      expect(sessionManager.state, FsSessionState.fsBroken);
    });
  });
}
