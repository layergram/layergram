/// Tests for FsSecurityMode and FsSecurityModeService (FS Spec §14.3, §6.1–§6.3).
///
/// Verifies:
///  1. Default mode is Advanced when no record exists.
///  2. setMode + getMode round-trip through aux records.
///  3. Per-contact isolation — different contacts can have different modes.
///  4. Per-context isolation — same contact can have different modes in
///     different identity contexts (primary vs passphrase).
///  5. rebuildIndex restores the index after cold start.
///  6. removeMode deletes a single contact's mode record.
///  7. removeAll wipes all mode records.
///  8. Base mode suppresses FS handshake initiation.
///  9. Base mode ignores incoming FS extensions.
/// 10. Strict mode triggers strict FS policy enforcement.
/// 11. Mode overwrite: setMode replaces previous value.
/// 12. Plausible deniability: mode records are opaque encrypted aux records.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_opportunistic_controller.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory tmpDir;
  late Box<Map> box;
  final masterBytes = Uint8List(32)..fillRange(0, 32, 0xBB);

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
    tmpDir = await Directory.systemTemp.createTemp('layergram_fs_mode_');
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

  // ──────────────────────────────────────────────────────────────────────────
  // § FsSecurityModeService: persistence
  // ──────────────────────────────────────────────────────────────────────────

  group('FsSecurityModeService — persistence', () {
    test('default mode is Advanced when no record exists', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      final mode = await service.getMode(
        contactId: 'alice',
        identityContext: 'primary',
      );
      expect(mode, equals(FsSecurityMode.advanced));
    });

    test('getModeSync returns Advanced by default (no index)', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      final mode = service.getModeSync(
        contactId: 'alice',
        identityContext: 'primary',
      );
      expect(mode, equals(FsSecurityMode.advanced));
    });

    test('setMode + getMode round-trips (Base)', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.base,
      );

      final mode = await service.getMode(
        contactId: 'alice',
        identityContext: 'primary',
      );
      expect(mode, equals(FsSecurityMode.base));
    });

    test('setMode + getMode round-trips (Strict)', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'bob',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );

      final mode = await service.getMode(
        contactId: 'bob',
        identityContext: 'primary',
      );
      expect(mode, equals(FsSecurityMode.strict));
    });

    test('setMode overwrites previous value', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.base,
      );
      expect(
        await service.getMode(contactId: 'alice', identityContext: 'primary'),
        equals(FsSecurityMode.base),
      );

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );
      expect(
        await service.getMode(contactId: 'alice', identityContext: 'primary'),
        equals(FsSecurityMode.strict),
      );
    });

    test('getModeSync reflects setMode (cached)', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );

      final mode = service.getModeSync(
        contactId: 'alice',
        identityContext: 'primary',
      );
      expect(mode, equals(FsSecurityMode.strict));
    });

    test('mode-change boundary is durable and monotonic', () async {
      final auxRepo = await buildAuxRepo();
      final fixed = DateTime.utc(2026, 8, 20, 12);
      final service = FsSecurityModeService(
        auxRepository: auxRepo,
        now: () => fixed,
      );

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.advanced,
      );
      expect(
        service.getModeChangedAtSync(
          contactId: 'alice',
          identityContext: 'primary',
        ),
        fixed,
      );

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );
      final second = service.getModeChangedAtSync(
        contactId: 'alice',
        identityContext: 'primary',
      );
      expect(second, fixed.add(const Duration(milliseconds: 1)));

      final restored = FsSecurityModeService(auxRepository: auxRepo);
      await restored.rebuildIndex();
      expect(
        restored.getModeChangedAtSync(
          contactId: 'alice',
          identityContext: 'primary',
        ),
        second,
      );
    });

    test('v3 policy durably excludes pre-change session IDs', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);
      const oldSessions = <String>{
        'AgICAgICAgICAgICAgICAg',
        'AQEBAQEBAQEBAQEBAQEBAQ',
      };

      await service.setProtocolV3Mode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
        existingHandshakeIds: oldSessions,
      );
      final policy = service.getV3SessionEligibilitySync(
        contactId: 'alice',
        identityContext: 'primary',
      );
      expect(policy?.isValid, isTrue);
      expect(policy?.excludedHandshakeIds, oldSessions);

      final restored = FsSecurityModeService(auxRepository: auxRepo);
      await restored.rebuildIndex();
      expect(
        restored
            .getV3SessionEligibilitySync(
              contactId: 'alice',
              identityContext: 'primary',
            )
            ?.excludedHandshakeIds,
        oldSessions,
      );
      expect(
        restored.getModeSync(
          contactId: 'alice',
          identityContext: 'primary',
        ),
        FsSecurityMode.strict,
      );
    });

    test('v3 policy rejects the reserved all-zero handshake ID', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      expect(
        () => service.setProtocolV3Mode(
          contactId: 'alice',
          identityContext: 'primary',
          mode: FsSecurityMode.advanced,
          existingHandshakeIds: const <String>{
            'AAAAAAAAAAAAAAAAAAAAAA',
          },
        ),
        throwsArgumentError,
      );
    });

    test('restore chooses the highest durable policy revision', () async {
      final auxRepo = await buildAuxRepo();
      await auxRepo.write(
        payload: <String, dynamic>{
          'kind': 'fs_mode_v1',
          'v': 2,
          'revision': 1,
          'cid': 'alice',
          'ctx': 'primary',
          'mode': 'advanced',
          'changedAt': 1000,
          'v3ExcludedHandshakeIds': <String>[],
        },
      );
      await auxRepo.write(
        payload: <String, dynamic>{
          'kind': 'fs_mode_v1',
          'v': 2,
          'revision': 2,
          'cid': 'alice',
          'ctx': 'primary',
          'mode': 'strict',
          'changedAt': 2000,
          'v3ExcludedHandshakeIds': <String>[],
        },
      );

      final restored = FsSecurityModeService(auxRepository: auxRepo);
      await restored.rebuildIndex();
      expect(
        restored.getModeSync(
          contactId: 'alice',
          identityContext: 'primary',
        ),
        FsSecurityMode.strict,
      );
      expect(
        restored
            .getV3SessionEligibilitySync(
              contactId: 'alice',
              identityContext: 'primary',
            )
            ?.revision,
        2,
      );
    });

    test('same-revision policy divergence fails closed', () async {
      final auxRepo = await buildAuxRepo();
      for (final mode in <String>['advanced', 'strict']) {
        await auxRepo.write(
          payload: <String, dynamic>{
            'kind': 'fs_mode_v1',
            'v': 2,
            'revision': 4,
            'cid': 'alice',
            'ctx': 'primary',
            'mode': mode,
            'changedAt': 4000,
            'v3ExcludedHandshakeIds': <String>[],
          },
        );
      }

      final restored = FsSecurityModeService(auxRepository: auxRepo);
      await restored.rebuildIndex();
      expect(
        restored
            .getV3SessionEligibilitySync(
              contactId: 'alice',
              identityContext: 'primary',
            )
            ?.isValid,
        isFalse,
      );
      await expectLater(
        restored.setProtocolV3Mode(
          contactId: 'alice',
          identityContext: 'primary',
          mode: FsSecurityMode.advanced,
          existingHandshakeIds: const <String>{},
        ),
        throwsStateError,
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // § Per-contact isolation
  // ──────────────────────────────────────────────────────────────────────────

  group('FsSecurityModeService — per-contact isolation', () {
    test('different contacts can have different modes', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.base,
      );
      await service.setMode(
        contactId: 'bob',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );

      expect(
        await service.getMode(contactId: 'alice', identityContext: 'primary'),
        equals(FsSecurityMode.base),
      );
      expect(
        await service.getMode(contactId: 'bob', identityContext: 'primary'),
        equals(FsSecurityMode.strict),
      );
      // Third contact should default to Advanced
      expect(
        await service.getMode(contactId: 'carol', identityContext: 'primary'),
        equals(FsSecurityMode.advanced),
      );
    });

    test('per-context isolation: same contact, different contexts', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.base,
      );
      await service.setMode(
        contactId: 'alice',
        identityContext: 'passphrase-ctx-abc123',
        mode: FsSecurityMode.strict,
      );

      expect(
        await service.getMode(
          contactId: 'alice',
          identityContext: 'primary',
        ),
        equals(FsSecurityMode.base),
      );
      expect(
        await service.getMode(
          contactId: 'alice',
          identityContext: 'passphrase-ctx-abc123',
        ),
        equals(FsSecurityMode.strict),
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // § rebuildIndex (cold start recovery)
  // ──────────────────────────────────────────────────────────────────────────

  group('FsSecurityModeService — rebuildIndex', () {
    test('rebuildIndex restores index from aux records after cold start',
        () async {
      final auxRepo = await buildAuxRepo();
      final service1 = FsSecurityModeService(auxRepository: auxRepo);

      await service1.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );
      await service1.setMode(
        contactId: 'bob',
        identityContext: 'primary',
        mode: FsSecurityMode.base,
      );

      // Simulate cold start: new service instance, same aux repo
      final service2 = FsSecurityModeService(auxRepository: auxRepo);
      await service2.rebuildIndex();

      expect(
        service2.getModeSync(contactId: 'alice', identityContext: 'primary'),
        equals(FsSecurityMode.strict),
      );
      expect(
        service2.getModeSync(contactId: 'bob', identityContext: 'primary'),
        equals(FsSecurityMode.base),
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // § removeMode / removeAll
  // ──────────────────────────────────────────────────────────────────────────

  group('FsSecurityModeService — removal', () {
    test('removeMode deletes a single contact mode', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );
      await service.setMode(
        contactId: 'bob',
        identityContext: 'primary',
        mode: FsSecurityMode.base,
      );

      await service.removeMode(
        contactId: 'alice',
        identityContext: 'primary',
      );

      // Alice should return default (advanced)
      expect(
        await service.getMode(contactId: 'alice', identityContext: 'primary'),
        equals(FsSecurityMode.advanced),
      );
      // Bob should remain as set
      expect(
        service.getModeSync(contactId: 'bob', identityContext: 'primary'),
        equals(FsSecurityMode.base),
      );
    });

    test('removeAll wipes all mode records', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );
      await service.setMode(
        contactId: 'bob',
        identityContext: 'primary',
        mode: FsSecurityMode.base,
      );

      await service.removeAll();

      expect(
        await service.getMode(contactId: 'alice', identityContext: 'primary'),
        equals(FsSecurityMode.advanced),
      );
      expect(
        await service.getMode(contactId: 'bob', identityContext: 'primary'),
        equals(FsSecurityMode.advanced),
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // § Plausible deniability
  // ──────────────────────────────────────────────────────────────────────────

  group('FsSecurityModeService — plausible deniability', () {
    test('mode records are opaque encrypted aux records in storage', () async {
      final auxRepo = await buildAuxRepo();
      final service = FsSecurityModeService(auxRepository: auxRepo);

      await service.setMode(
        contactId: 'alice',
        identityContext: 'primary',
        mode: FsSecurityMode.strict,
      );

      // All records in the Hive box should be opaque
      for (final entry in box.toMap().entries) {
        final map = Map<String, dynamic>.from(entry.value);
        // Should have encrypted payload fields only
        expect(map.containsKey('kind'), isFalse,
            reason: 'kind must not be stored in plaintext');
        expect(map.containsKey('mode'), isFalse,
            reason: 'mode must not be stored in plaintext');
        expect(map.containsKey('cid'), isFalse,
            reason: 'contactId must not be stored in plaintext');
        // Should have encryptedRecord (the opaque blob)
        expect(map.containsKey('encryptedRecord'), isTrue,
            reason: 'encrypted payload must be present');
      }
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // § Mode enforcement in FsOpportunisticController
  // ──────────────────────────────────────────────────────────────────────────

  group('FsOpportunisticController — mode enforcement', () {
    FsOpportunisticController buildController({
      FsSecurityMode mode = FsSecurityMode.advanced,
    }) {
      final sm = FsSessionManager();
      final registry = FsContactSecurityRegistry();
      final ctrl = FsOpportunisticController(
        localContactId: 'local-id',
        identityContext: 'primary',
        sessionManager: sm,
        registry: registry,
      );
      ctrl.securityMode = mode;
      return ctrl;
    }

    FsInitPayload buildInitPayload(String initId) => FsInitPayload(
          initId: initId,
          initiatorDevicePub: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
          initiatorEphemeralPub: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
          caps: ['aes-gcm-256'],
          createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
          ekAPrivBytes: Uint8List(32),
        );

    test('Base mode: buildOutgoingExtension returns null (no FS init)',
        () async {
      final ctrl = buildController(mode: FsSecurityMode.base);

      final ext = await ctrl.buildOutgoingExtension(
        pendingInit: buildInitPayload('test-init-id'),
      );

      expect(ext, isNull);
    });

    test('Advanced mode: buildOutgoingExtension attaches FS init', () async {
      final ctrl = buildController(mode: FsSecurityMode.advanced);

      final ext = await ctrl.buildOutgoingExtension(
        pendingInit: buildInitPayload('test-init-id'),
      );

      expect(ext, isNotNull);
      expect(ext!.json, isNotNull);
    });

    test('Base mode: processIncomingEnvelope ignores FS extension', () async {
      final ctrl = buildController(mode: FsSecurityMode.base);

      final result = await ctrl.processIncomingEnvelope(
        {
          'x': {
            'fs': {
              'type': 'fs_init',
              'initId': 'incoming-init',
              'ik': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
              'dk': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            },
          },
        },
        remoteContactId: 'remote-id',
      );

      expect(result.type, equals(FsIncomingType.noExtension));
    });

    test('Advanced mode: processIncomingEnvelope processes FS init', () async {
      final ctrl = buildController(mode: FsSecurityMode.advanced);

      final result = await ctrl.processIncomingEnvelope(
        {
          'x': {
            'fs': {
              'type': 'fs_init',
              'initId': 'incoming-init',
              'ik': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
              'dk': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            },
          },
        },
        remoteContactId: 'remote-id',
      );

      // Should be processed (accepted or rejected on key validation, not ignored)
      expect(result.type, isNot(equals(FsIncomingType.noExtension)));
    });

    test('Strict mode: buildOutgoingExtension attaches FS init (like Advanced)',
        () async {
      final ctrl = buildController(mode: FsSecurityMode.strict);

      final ext = await ctrl.buildOutgoingExtension(
        pendingInit: buildInitPayload('test-init-strict'),
      );

      expect(ext, isNotNull);
      expect(ext!.json, isNotNull);
    });

    test('Strict mode: processIncomingEnvelope processes FS init', () async {
      final ctrl = buildController(mode: FsSecurityMode.strict);

      final result = await ctrl.processIncomingEnvelope(
        {
          'x': {
            'fs': {
              'type': 'fs_init',
              'initId': 'strict-incoming-init',
              'ik': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
              'dk': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            },
          },
        },
        remoteContactId: 'remote-id',
      );

      expect(result.type, isNot(equals(FsIncomingType.noExtension)));
    });

    test('securityMode defaults to Advanced', () {
      final sm = FsSessionManager();
      final registry = FsContactSecurityRegistry();
      final ctrl = FsOpportunisticController(
        localContactId: 'local-id',
        identityContext: 'primary',
        sessionManager: sm,
        registry: registry,
      );

      expect(ctrl.securityMode, equals(FsSecurityMode.advanced));
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // § FsSecurityMode enum
  // ──────────────────────────────────────────────────────────────────────────

  group('FsSecurityMode enum', () {
    test('has exactly 3 values', () {
      expect(FsSecurityMode.values.length, equals(3));
    });

    test('name serialization matches expected strings', () {
      expect(FsSecurityMode.base.name, equals('base'));
      expect(FsSecurityMode.advanced.name, equals('advanced'));
      expect(FsSecurityMode.strict.name, equals('strict'));
    });
  });
}
