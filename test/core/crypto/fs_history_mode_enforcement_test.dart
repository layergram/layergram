/// Tests for history mode enforcement, clean undecryptable data,
/// and §14.5 warnings (FS Spec §12.2, §13.7, §14.5).
///
/// Covers:
///   1. FsHistoryModeEnforcement — keepEncrypted, volatile, ephemeral modes.
///   2. shouldPersistPlaintext — static helper for mode checks.
///   3. shouldPersistFsState — combined mode/persistence checks.
///   4. AuxRecordRepository.cleanUndecryptableRecords — §13.7.
///   5. Localization key coverage for §14.5 warnings + §13.7 cleanup.

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_history_mode_enforcement.dart';
import 'package:layergram/core/crypto/fs_passphrase_preferences.dart';
import 'package:layergram/core/crypto/fs_plaintext_cache.dart';
import 'package:layergram/core/crypto/fs_plaintext_persistence_service.dart';
import 'package:layergram/core/crypto/fs_ratchet_persistence_service.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/fs_state_persistence_service.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/l10n/fs_strings_bundle.dart';

void main() {
  late Directory tmpDir;
  late Box<Map> box;
  final masterBytes = Uint8List(32)..fillRange(0, 32, 0xAA);

  Future<SecretKey> buildAuxKey() =>
      AuxRecordCipher.deriveAuxStorageKey(masterBytes);

  Future<AuxRecordRepository> buildAuxRepo({
    String scope = 'test-scope',
  }) async {
    final key = await buildAuxKey();
    final repo = AuxRecordRepository();
    repo.setActiveContext(scopeToken: scope, auxStorageKey: key);
    return repo;
  }

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_hist_enf_');
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    box = Hive.box<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await box.clear();
  });

  // ===========================================================================
  // §12.2 — History mode enforcement
  // ===========================================================================

  group('FsHistoryModeEnforcement', () {
    late FsPlaintextCache cache;
    late AuxRecordRepository auxRepo;
    late FsPlaintextPersistenceService ptPersistence;
    late FsStatePersistenceService statePersistence;
    late FsRatchetPersistenceService ratchetPersistence;
    late FsContactSecurityRegistry registry;
    late FsHistoryModeEnforcement enforcement;

    setUp(() async {
      auxRepo = await buildAuxRepo();
      cache = FsPlaintextCache();
      ptPersistence = FsPlaintextPersistenceService(auxRepository: auxRepo);
      registry = FsContactSecurityRegistry();
      statePersistence = FsStatePersistenceService(
        auxRepository: auxRepo,
        registry: registry,
      );
      ratchetPersistence = FsRatchetPersistenceService(auxRepository: auxRepo);
      enforcement = FsHistoryModeEnforcement(
        plaintextCache: cache,
        plaintextPersistence: ptPersistence,
        statePersistence: statePersistence,
        ratchetPersistence: ratchetPersistence,
        securityRegistry: registry,
      );
    });

    test('keepEncrypted: wipes memory cache but preserves aux records', () async {
      cache.put('msg-1', 'hello from cache');
      await ptPersistence.savePlaintext(
        messageId: 'msg-1',
        plaintext: 'hello persisted',
        contactId: 'contact-1',
      );

      await enforcement.onPassphraseExpelled(
        historyMode: PassphraseHistoryMode.keepEncrypted,
        fsPersistence: PassphraseFsPersistence.persistent,
        identityContext: 'ctx-1',
      );

      // Memory cache wiped
      expect(cache.length, 0);

      // Aux record still exists (rebuild index after wipe to re-scan)
      await ptPersistence.rebuildIndex();
      final restored = await ptPersistence.loadPlaintext('msg-1');
      expect(restored, 'hello persisted');
    });

    test('volatile: wipes memory cache AND aux plaintext records', () async {
      cache.put('msg-1', 'hello from cache');
      await ptPersistence.savePlaintext(
        messageId: 'msg-1',
        plaintext: 'hello persisted',
        contactId: 'contact-1',
      );

      await enforcement.onPassphraseExpelled(
        historyMode: PassphraseHistoryMode.volatile_,
        fsPersistence: PassphraseFsPersistence.persistent,
        identityContext: 'ctx-1',
      );

      expect(cache.length, 0);
      await ptPersistence.rebuildIndex();
      final restored = await ptPersistence.loadPlaintext('msg-1');
      expect(restored, isNull);
    });

    test('volatile: preserves registry entries (FS state survives)', () async {
      registry.upsert(const FsContactSecurityState(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
        fsState: FsSessionState.fsActive,
      ));

      await enforcement.onPassphraseExpelled(
        historyMode: PassphraseHistoryMode.volatile_,
        fsPersistence: PassphraseFsPersistence.persistent,
        identityContext: 'ctx-1',
      );

      // FS state should still exist in registry (not marked broken)
      final state = registry.lookup(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
      );
      expect(state, isNotNull);
      expect(state!.fsState, FsSessionState.fsActive);
    });

    test('ephemeral: wipes cache, plaintext, AND marks registry broken', () async {
      cache.put('msg-1', 'hello from cache');
      await ptPersistence.savePlaintext(
        messageId: 'msg-1',
        plaintext: 'hello persisted',
        contactId: 'contact-1',
      );
      registry.upsert(const FsContactSecurityState(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
        fsState: FsSessionState.fsActive,
      ));

      await enforcement.onPassphraseExpelled(
        historyMode: PassphraseHistoryMode.ephemeral,
        fsPersistence: PassphraseFsPersistence.persistent,
        identityContext: 'ctx-1',
      );

      // All wiped
      expect(cache.length, 0);
      await ptPersistence.rebuildIndex();
      expect(await ptPersistence.loadPlaintext('msg-1'), isNull);

      // Registry entry marked broken
      final state = registry.lookup(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
      );
      expect(state!.fsState, FsSessionState.fsBroken);
    });

    test('ephemeral FS persistence: marks registry broken even in keepEncrypted history', () async {
      registry.upsert(const FsContactSecurityState(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
        fsState: FsSessionState.fsActive,
      ));

      await enforcement.onPassphraseExpelled(
        historyMode: PassphraseHistoryMode.keepEncrypted,
        fsPersistence: PassphraseFsPersistence.ephemeral,
        identityContext: 'ctx-1',
      );

      final state = registry.lookup(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
      );
      expect(state!.fsState, FsSessionState.fsBroken);
    });

    test('volatile + ephemeral FS: wipes plaintext AND marks registry broken', () async {
      cache.put('msg-1', 'secret');
      await ptPersistence.savePlaintext(
        messageId: 'msg-1',
        plaintext: 'secret',
        contactId: 'c1',
      );
      registry.upsert(const FsContactSecurityState(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
        fsState: FsSessionState.fsActive,
      ));

      await enforcement.onPassphraseExpelled(
        historyMode: PassphraseHistoryMode.volatile_,
        fsPersistence: PassphraseFsPersistence.ephemeral,
        identityContext: 'ctx-1',
      );

      expect(cache.length, 0);
      await ptPersistence.rebuildIndex();
      expect(await ptPersistence.loadPlaintext('msg-1'), isNull);
      final state = registry.lookup(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
      );
      expect(state!.fsState, FsSessionState.fsBroken);
    });

    test('only affects the specified identity context', () async {
      // Set up entries for two contexts
      registry.upsert(const FsContactSecurityState(
        contactId: 'c1',
        identityContext: 'ctx-1',
        sessionId: 's1',
        fsState: FsSessionState.fsActive,
      ));
      registry.upsert(const FsContactSecurityState(
        contactId: 'c1',
        identityContext: 'ctx-2',
        sessionId: 's2',
        fsState: FsSessionState.fsActive,
      ));

      await enforcement.onPassphraseExpelled(
        historyMode: PassphraseHistoryMode.ephemeral,
        fsPersistence: PassphraseFsPersistence.persistent,
        identityContext: 'ctx-1',
      );

      // ctx-1 broken, ctx-2 still active
      final s1 = registry.lookup(contactId: 'c1', identityContext: 'ctx-1', sessionId: 's1');
      final s2 = registry.lookup(contactId: 'c1', identityContext: 'ctx-2', sessionId: 's2');
      expect(s1!.fsState, FsSessionState.fsBroken);
      expect(s2!.fsState, FsSessionState.fsActive);
    });
  });

  // ===========================================================================
  // shouldPersistPlaintext / shouldPersistFsState
  // ===========================================================================

  group('Static mode helpers', () {
    test('shouldPersistPlaintext: false only for ephemeral', () {
      expect(
        FsHistoryModeEnforcement.shouldPersistPlaintext(
            PassphraseHistoryMode.keepEncrypted),
        isTrue,
      );
      expect(
        FsHistoryModeEnforcement.shouldPersistPlaintext(
            PassphraseHistoryMode.volatile_),
        isTrue,
      );
      expect(
        FsHistoryModeEnforcement.shouldPersistPlaintext(
            PassphraseHistoryMode.ephemeral),
        isFalse,
      );
    });

    test('shouldPersistFsState: false for ephemeral history or ephemeral FS', () {
      expect(
        FsHistoryModeEnforcement.shouldPersistFsState(
          historyMode: PassphraseHistoryMode.keepEncrypted,
          fsPersistence: PassphraseFsPersistence.persistent,
        ),
        isTrue,
      );

      expect(
        FsHistoryModeEnforcement.shouldPersistFsState(
          historyMode: PassphraseHistoryMode.volatile_,
          fsPersistence: PassphraseFsPersistence.persistent,
        ),
        isTrue,
      );

      expect(
        FsHistoryModeEnforcement.shouldPersistFsState(
          historyMode: PassphraseHistoryMode.keepEncrypted,
          fsPersistence: PassphraseFsPersistence.ephemeral,
        ),
        isFalse,
      );

      expect(
        FsHistoryModeEnforcement.shouldPersistFsState(
          historyMode: PassphraseHistoryMode.ephemeral,
          fsPersistence: PassphraseFsPersistence.persistent,
        ),
        isFalse,
      );

      expect(
        FsHistoryModeEnforcement.shouldPersistFsState(
          historyMode: PassphraseHistoryMode.ephemeral,
          fsPersistence: PassphraseFsPersistence.ephemeral,
        ),
        isFalse,
      );
    });
  });

  // ===========================================================================
  // §13.7 — Clean undecryptable data
  // ===========================================================================

  group('cleanUndecryptableRecords (§13.7)', () {
    test('removes records that fail decryption', () async {
      final repo = await buildAuxRepo();

      // Write a valid record
      await repo.write(payload: {'kind': 'test', 'data': 'valid'});

      // Manually insert a corrupt record
      box.put('m|test-scope|fake-corrupt-1', {
        'encryptedRecord': 'not-valid-ciphertext',
        'a': true,
        '_rid': 'fake-rid',
      });

      final deleted = await repo.cleanUndecryptableRecords();
      expect(deleted, 1);

      // Valid record still exists
      final allIds = repo.getAllAuxRecordIds();
      expect(allIds.length, 1);
    });

    test('removes records with missing encryptedRecord or _rid', () async {
      final repo = await buildAuxRepo();

      box.put('m|test-scope|missing-enc', {
        'a': true,
        '_rid': 'some-rid',
      });
      box.put('m|test-scope|missing-rid', {
        'encryptedRecord': 'data',
        'a': true,
      });

      final deleted = await repo.cleanUndecryptableRecords();
      expect(deleted, 2);
    });

    test('preserves all decryptable records', () async {
      final repo = await buildAuxRepo();

      await repo.write(payload: {'kind': 'fs_state_v1', 'v': 1});
      await repo.write(payload: {'kind': 'fs_pt_v1', 'v': 1});
      await repo.write(payload: {'kind': 'fs_pp_v1', 'v': 1});

      final deleted = await repo.cleanUndecryptableRecords();
      expect(deleted, 0);
      expect(repo.getAllAuxRecordIds().length, 3);
    });

    test('records from different key context are undecryptable', () async {
      // Write with key A
      final keyA = await AuxRecordCipher.deriveAuxStorageKey(
        Uint8List(32)..fillRange(0, 32, 0x11),
      );
      final repoA = AuxRecordRepository();
      repoA.setActiveContext(scopeToken: 'test-scope', auxStorageKey: keyA);
      await repoA.write(payload: {'kind': 'old-context', 'v': 1});

      // Switch to key B
      final keyB = await AuxRecordCipher.deriveAuxStorageKey(
        Uint8List(32)..fillRange(0, 32, 0x22),
      );
      final repoB = AuxRecordRepository();
      repoB.setActiveContext(scopeToken: 'test-scope', auxStorageKey: keyB);

      // Clean with key B — should delete key A's record
      final deleted = await repoB.cleanUndecryptableRecords();
      expect(deleted, 1);
    });

    test('returns 0 when no scope is set', () async {
      final repo = AuxRecordRepository();
      final deleted = await repo.cleanUndecryptableRecords();
      expect(deleted, 0);
    });
  });

  // ===========================================================================
  // Localization coverage for §14.5 warnings + §13.7 cleanup
  // ===========================================================================

  group('Localization key coverage', () {
    final requiredKeys = [
      'security.warn.active_passphrase',
      'security.warn.passphrase_fs',
      'security.warn.volatile_history',
      'security.warn.ephemeral_session',
      'security.warn.recoverability_title',
      'security.warn.recoverability_body',
      'security.warn.recoverability_confirm',
      'security.cleanup.title',
      'security.cleanup.subtitle',
      'security.cleanup.dialog_title',
      'security.cleanup.dialog_body',
      'security.cleanup.confirm_checkbox',
      'security.cleanup.confirm_button',
      'security.cleanup.done',
    ];

    for (final lang in ['en', 'it', 'es', 'de', 'fr', 'pt']) {
      test('$lang has all §14.5 + §13.7 keys', () {
        final bundle = FsStringsBundle.bundle[lang]!;
        for (final key in requiredKeys) {
          expect(bundle.containsKey(key), isTrue,
              reason: '$lang missing key: $key');
          expect(bundle[key]!.isNotEmpty, isTrue,
              reason: '$lang has empty value for key: $key');
        }
      });
    }
  });
}
