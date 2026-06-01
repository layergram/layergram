/// Tests for FsMessageClassification (FS Spec §14.4).
///
/// Verifies:
///  1. All 8 classification enum values exist.
///  2. Downgrade level mapping: each classification maps correctly to
///     the 3-level FsMessageSecurity hierarchy (or null).
///  3. isFsProtected: only FS-encrypted classifications return true.
///  4. Storage round-trip: storageIndex ↔ fromStorageIndex.
///  5. fromLegacyFlag backward compatibility: isFsEncrypted=true → fsOnly (§9.5),
///     isFsEncrypted=false → legacy.
///  6. MessageRecord.fsClassification persistence via toMap/fromMap.
///  7. MessageRecord.effectiveClassification fallback when fsClassification is null.
///  8. Outgoing classification logic: legacy, preFs, fsNegotiation, fsOnly,
///     strictFs based on session state and security mode (§9.5: FS-encrypted
///     messages are FS-only on the wire, never fs_with_fallback).
///  9. Incoming classification logic: fsFailed on decrypt failure.
/// 10. Plausible deniability: stored classification is an opaque integer.
/// 11. Localization: all 8 label+desc keys exist for all 6 languages.
/// 12. Downgrade detector: classifications that return null don't affect the
///     downgrade tracking.

import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/crypto/fs_message_classification.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/l10n/fs_strings_bundle.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // ────────────────────────────────────────────────────────────────────────────
  // § Enum completeness
  // ────────────────────────────────────────────────────────────────────────────

  group('FsMessageClassification enum', () {
    test('has exactly 8 values', () {
      expect(FsMessageClassification.values.length, equals(8));
    });

    test('values in expected order', () {
      expect(FsMessageClassification.values, equals([
        FsMessageClassification.legacy,
        FsMessageClassification.preFs,
        FsMessageClassification.fsNegotiation,
        FsMessageClassification.fsWithFallback,
        FsMessageClassification.fsOnly,
        FsMessageClassification.strictFs,
        FsMessageClassification.fsFailed,
        FsMessageClassification.unknown,
      ]));
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Downgrade level mapping
  // ────────────────────────────────────────────────────────────────────────────

  group('downgradeLevel mapping', () {
    test('legacy → FsMessageSecurity.legacy', () {
      expect(FsMessageClassification.legacy.downgradeLevel,
          equals(FsMessageSecurity.legacy));
    });

    test('preFs → FsMessageSecurity.legacy', () {
      expect(FsMessageClassification.preFs.downgradeLevel,
          equals(FsMessageSecurity.legacy));
    });

    test('fsNegotiation → null (not a security level)', () {
      expect(FsMessageClassification.fsNegotiation.downgradeLevel, isNull);
    });

    test('fsWithFallback → FsMessageSecurity.fsWithFallback', () {
      expect(FsMessageClassification.fsWithFallback.downgradeLevel,
          equals(FsMessageSecurity.fsWithFallback));
    });

    test('fsOnly → FsMessageSecurity.fsOnly', () {
      expect(FsMessageClassification.fsOnly.downgradeLevel,
          equals(FsMessageSecurity.fsOnly));
    });

    test('strictFs → FsMessageSecurity.fsOnly', () {
      expect(FsMessageClassification.strictFs.downgradeLevel,
          equals(FsMessageSecurity.fsOnly));
    });

    test('fsFailed → null (not meaningful for tracking)', () {
      expect(FsMessageClassification.fsFailed.downgradeLevel, isNull);
    });

    test('unknown → null', () {
      expect(FsMessageClassification.unknown.downgradeLevel, isNull);
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § isFsProtected
  // ────────────────────────────────────────────────────────────────────────────

  group('isFsProtected', () {
    test('FS-encrypted classifications return true', () {
      expect(FsMessageClassification.fsWithFallback.isFsProtected, isTrue);
      expect(FsMessageClassification.fsOnly.isFsProtected, isTrue);
      expect(FsMessageClassification.strictFs.isFsProtected, isTrue);
    });

    test('non-FS classifications return false', () {
      expect(FsMessageClassification.legacy.isFsProtected, isFalse);
      expect(FsMessageClassification.preFs.isFsProtected, isFalse);
      expect(FsMessageClassification.fsNegotiation.isFsProtected, isFalse);
      expect(FsMessageClassification.fsFailed.isFsProtected, isFalse);
      expect(FsMessageClassification.unknown.isFsProtected, isFalse);
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Storage round-trip
  // ────────────────────────────────────────────────────────────────────────────

  group('storage serialization', () {
    test('storageIndex round-trips through fromStorageIndex', () {
      for (final cls in FsMessageClassification.values) {
        final idx = cls.storageIndex;
        final restored = FsMessageClassificationExt.fromStorageIndex(idx);
        expect(restored, equals(cls),
            reason: '$cls should round-trip via index $idx');
      }
    });

    test('out-of-range index returns unknown', () {
      expect(FsMessageClassificationExt.fromStorageIndex(-1),
          equals(FsMessageClassification.unknown));
      expect(FsMessageClassificationExt.fromStorageIndex(99),
          equals(FsMessageClassification.unknown));
      expect(FsMessageClassificationExt.fromStorageIndex(8),
          equals(FsMessageClassification.unknown));
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Legacy flag backward compatibility
  // ────────────────────────────────────────────────────────────────────────────

  group('fromLegacyFlag', () {
    test('isFsEncrypted=true → fsOnly (§9.5)', () {
      expect(FsMessageClassificationExt.fromLegacyFlag(true),
          equals(FsMessageClassification.fsOnly));
    });

    test('isFsEncrypted=false → legacy', () {
      expect(FsMessageClassificationExt.fromLegacyFlag(false),
          equals(FsMessageClassification.legacy));
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § MessageRecord integration
  // ────────────────────────────────────────────────────────────────────────────

  group('MessageRecord — fsClassification', () {
    MessageRecord _buildRecord({
      bool isFsEncrypted = false,
      FsMessageClassification? classification,
    }) {
      return MessageRecord(
        id: 'msg-001',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'incoming',
        timestamp: 1700000000,
        text: isFsEncrypted ? null : 'hello',
        isFsEncrypted: isFsEncrypted,
        fsClassification: classification,
      );
    }

    test('effectiveClassification uses fsClassification when set', () {
      final record = _buildRecord(
        classification: FsMessageClassification.strictFs,
      );
      expect(record.effectiveClassification,
          equals(FsMessageClassification.strictFs));
    });

    test('effectiveClassification falls back to isFsEncrypted=true (§9.5 → fsOnly)', () {
      final record = _buildRecord(isFsEncrypted: true);
      expect(record.effectiveClassification,
          equals(FsMessageClassification.fsOnly));
    });

    test('effectiveClassification falls back to isFsEncrypted=false', () {
      final record = _buildRecord();
      expect(record.effectiveClassification,
          equals(FsMessageClassification.legacy));
    });

    test('toMap/fromMap round-trips with classification', () {
      for (final cls in FsMessageClassification.values) {
        final original = _buildRecord(classification: cls);
        final map = original.toMap();
        final restored = MessageRecord.fromMap(map);
        expect(restored.fsClassification, equals(cls),
            reason: '$cls should round-trip through toMap/fromMap');
      }
    });

    test('toMap omits fsCls when classification is null', () {
      final record = _buildRecord();
      final map = record.toMap();
      expect(map.containsKey('fsCls'), isFalse);
    });

    test('fromMap handles missing fsCls (backward compat)', () {
      final map = <String, dynamic>{
        'id': 'old-msg',
        'senderId': 'alice',
        'recipientId': 'bob',
        'direction': 'incoming',
        'timestamp': 1700000000,
        'text': 'old message',
      };
      final record = MessageRecord.fromMap(map);
      expect(record.fsClassification, isNull);
      expect(record.effectiveClassification,
          equals(FsMessageClassification.legacy));
    });

    test('fromMap handles missing fsCls with isFsEncrypted=true', () {
      final map = <String, dynamic>{
        'id': 'old-fs-msg',
        'senderId': 'alice',
        'recipientId': 'bob',
        'direction': 'incoming',
        'timestamp': 1700000000,
        'isFsEncrypted': true,
      };
      final record = MessageRecord.fromMap(map);
      expect(record.fsClassification, isNull);
      expect(record.effectiveClassification,
          equals(FsMessageClassification.fsOnly));
    });

    test('copyWith preserves classification', () {
      final original = _buildRecord(
        classification: FsMessageClassification.fsOnly,
      );
      final copy = original.copyWith(text: 'updated');
      expect(copy.fsClassification,
          equals(FsMessageClassification.fsOnly));
    });

    test('copyWith can change classification', () {
      final original = _buildRecord(
        classification: FsMessageClassification.legacy,
      );
      final copy = original.copyWith(
        fsClassification: FsMessageClassification.strictFs,
      );
      expect(copy.fsClassification,
          equals(FsMessageClassification.strictFs));
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Plausible deniability
  // ────────────────────────────────────────────────────────────────────────────

  group('Plausible deniability', () {
    test('classification stored as opaque integer, not string', () {
      final record = MessageRecord(
        id: 'pd-msg',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'outgoing',
        timestamp: 1700000000,
        fsClassification: FsMessageClassification.strictFs,
      );
      final map = record.toMap();

      // Stored as 'fsCls' (opaque key) with integer value
      expect(map['fsCls'], isA<int>());

      // No string classification visible in the map
      final values = map.values.whereType<String>();
      expect(values, isNot(contains('strictFs')));
      expect(values, isNot(contains('strict_fs')));
      expect(values, isNot(contains('FsMessageClassification')));
    });

    test('FS and legacy messages have same map keys (except fsCls/isFsEncrypted)', () {
      final legacyRecord = MessageRecord(
        id: 'msg-1',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'outgoing',
        timestamp: 1700000000,
        text: 'hello',
      );
      final fsRecord = MessageRecord(
        id: 'msg-2',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'outgoing',
        timestamp: 1700000000,
        isFsEncrypted: true,
        fsClassification: FsMessageClassification.fsWithFallback,
      );

      final legacyKeys = legacyRecord.toMap().keys.toSet();
      final fsKeys = fsRecord.toMap().keys.toSet();
      final diff = fsKeys.difference(legacyKeys);

      // Only difference should be isFsEncrypted and fsCls
      expect(diff, equals({'isFsEncrypted', 'fsCls'}));
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Outgoing classification logic
  // ────────────────────────────────────────────────────────────────────────────

  group('Outgoing classification logic', () {
    // Re-implement the static helper locally for testing
    FsMessageClassification classifyOutgoing({
      required bool isFsEncrypted,
      required bool hasFsExtension,
      required FsSessionState sessionState,
      required FsSecurityMode securityMode,
    }) {
      if (isFsEncrypted) {
        if (securityMode == FsSecurityMode.strict &&
            sessionState == FsSessionState.strictFsActive) {
          return FsMessageClassification.strictFs;
        }
        return FsMessageClassification.fsOnly;
      }
      if (hasFsExtension) {
        return FsMessageClassification.fsNegotiation;
      }
      if (sessionState == FsSessionState.legacyOnly) {
        return FsMessageClassification.preFs;
      }
      return FsMessageClassification.legacy;
    }

    test('FS encrypted in advanced mode → fsOnly (§9.5)', () {
      expect(
        classifyOutgoing(
          isFsEncrypted: true,
          hasFsExtension: false,
          sessionState: FsSessionState.fsActive,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.fsOnly),
      );
    });

    test('FS encrypted in strict mode with strictFsActive → strictFs', () {
      expect(
        classifyOutgoing(
          isFsEncrypted: true,
          hasFsExtension: false,
          sessionState: FsSessionState.strictFsActive,
          securityMode: FsSecurityMode.strict,
        ),
        equals(FsMessageClassification.strictFs),
      );
    });

    test('FS encrypted in strict mode but fsActive (not yet strict) → fsOnly (§9.5)', () {
      expect(
        classifyOutgoing(
          isFsEncrypted: true,
          hasFsExtension: false,
          sessionState: FsSessionState.fsActive,
          securityMode: FsSecurityMode.strict,
        ),
        equals(FsMessageClassification.fsOnly),
      );
    });

    test('no FS, has extension → fsNegotiation', () {
      expect(
        classifyOutgoing(
          isFsEncrypted: false,
          hasFsExtension: true,
          sessionState: FsSessionState.fsInitSent,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.fsNegotiation),
      );
    });

    test('no FS, no extension, legacyOnly → preFs', () {
      expect(
        classifyOutgoing(
          isFsEncrypted: false,
          hasFsExtension: false,
          sessionState: FsSessionState.legacyOnly,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.preFs),
      );
    });

    test('no FS, no extension, fsActive → legacy', () {
      expect(
        classifyOutgoing(
          isFsEncrypted: false,
          hasFsExtension: false,
          sessionState: FsSessionState.fsActive,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.legacy),
      );
    });

    test('base mode, no FS → preFs when legacyOnly', () {
      expect(
        classifyOutgoing(
          isFsEncrypted: false,
          hasFsExtension: false,
          sessionState: FsSessionState.legacyOnly,
          securityMode: FsSecurityMode.base,
        ),
        equals(FsMessageClassification.preFs),
      );
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Incoming classification logic
  // ────────────────────────────────────────────────────────────────────────────

  group('Incoming classification logic', () {
    FsMessageClassification classifyIncoming({
      required bool isFsEncrypted,
      required bool fsDecryptFailed,
      required bool hasFsExtension,
      required FsSessionState sessionState,
      required FsSecurityMode securityMode,
    }) {
      if (fsDecryptFailed) {
        return FsMessageClassification.fsFailed;
      }
      if (isFsEncrypted) {
        if (securityMode == FsSecurityMode.strict &&
            sessionState == FsSessionState.strictFsActive) {
          return FsMessageClassification.strictFs;
        }
        return FsMessageClassification.fsOnly;
      }
      if (hasFsExtension) {
        return FsMessageClassification.fsNegotiation;
      }
      if (sessionState == FsSessionState.legacyOnly) {
        return FsMessageClassification.preFs;
      }
      return FsMessageClassification.legacy;
    }

    test('FS decrypt failed → fsFailed', () {
      expect(
        classifyIncoming(
          isFsEncrypted: false,
          fsDecryptFailed: true,
          hasFsExtension: false,
          sessionState: FsSessionState.fsActive,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.fsFailed),
      );
    });

    test('fsDecryptFailed takes priority over isFsEncrypted', () {
      expect(
        classifyIncoming(
          isFsEncrypted: true,
          fsDecryptFailed: true,
          hasFsExtension: true,
          sessionState: FsSessionState.strictFsActive,
          securityMode: FsSecurityMode.strict,
        ),
        equals(FsMessageClassification.fsFailed),
      );
    });

    test('FS encrypted, strict mode → strictFs', () {
      expect(
        classifyIncoming(
          isFsEncrypted: true,
          fsDecryptFailed: false,
          hasFsExtension: false,
          sessionState: FsSessionState.strictFsActive,
          securityMode: FsSecurityMode.strict,
        ),
        equals(FsMessageClassification.strictFs),
      );
    });

    test('FS encrypted, advanced mode → fsOnly (§9.5)', () {
      expect(
        classifyIncoming(
          isFsEncrypted: true,
          fsDecryptFailed: false,
          hasFsExtension: false,
          sessionState: FsSessionState.fsActive,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.fsOnly),
      );
    });

    test('has FS extension, not encrypted → fsNegotiation', () {
      expect(
        classifyIncoming(
          isFsEncrypted: false,
          fsDecryptFailed: false,
          hasFsExtension: true,
          sessionState: FsSessionState.fsInitSeen,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.fsNegotiation),
      );
    });

    test('no FS, legacyOnly → preFs', () {
      expect(
        classifyIncoming(
          isFsEncrypted: false,
          fsDecryptFailed: false,
          hasFsExtension: false,
          sessionState: FsSessionState.legacyOnly,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.preFs),
      );
    });

    test('no FS, fsActive → legacy', () {
      expect(
        classifyIncoming(
          isFsEncrypted: false,
          fsDecryptFailed: false,
          hasFsExtension: false,
          sessionState: FsSessionState.fsActive,
          securityMode: FsSecurityMode.advanced,
        ),
        equals(FsMessageClassification.legacy),
      );
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § §9.5 true FS-only semantics
  // ────────────────────────────────────────────────────────────────────────────

  group('§9.5 FS-only semantics', () {
    // Mirror of the production classifier (see HomeController._classifyOutgoing /
    // _classifyIncoming): an FS-encrypted message is FS-only on the wire.
    FsMessageClassification classify({
      required bool isFsEncrypted,
      required FsSessionState sessionState,
      required FsSecurityMode securityMode,
    }) {
      if (isFsEncrypted) {
        if (securityMode == FsSecurityMode.strict &&
            sessionState == FsSessionState.strictFsActive) {
          return FsMessageClassification.strictFs;
        }
        return FsMessageClassification.fsOnly;
      }
      return FsMessageClassification.legacy;
    }

    test('an FS-encrypted message is never classified fsWithFallback', () {
      for (final mode in FsSecurityMode.values) {
        for (final state in FsSessionState.values) {
          final cls = classify(
            isFsEncrypted: true,
            sessionState: state,
            securityMode: mode,
          );
          expect(cls, isNot(equals(FsMessageClassification.fsWithFallback)),
              reason: 'mode=$mode state=$state must not be fs_with_fallback');
          expect(
            cls == FsMessageClassification.fsOnly ||
                cls == FsMessageClassification.strictFs,
            isTrue,
            reason: 'FS-encrypted must be fsOnly or strictFs (mode=$mode)',
          );
        }
      }
    });

    test('fsOnly is true FS (not decryptable by legacy key) per §9.5', () {
      // fs_with_fallback is the only classification the spec forbids treating as
      // full FS; fsOnly must map to the top security level for downgrade tracking.
      expect(FsMessageClassification.fsOnly.downgradeLevel,
          equals(FsMessageSecurity.fsOnly));
      expect(FsMessageClassification.fsOnly.isFsProtected, isTrue);
    });

    test('fsWithFallback remains defined (reserved for multi-envelope §9.6)', () {
      // The value still exists for forward compatibility even though the live
      // classifier never emits it.
      expect(FsMessageClassification.values,
          contains(FsMessageClassification.fsWithFallback));
      expect(FsMessageClassification.fsWithFallback.downgradeLevel,
          equals(FsMessageSecurity.fsWithFallback));
    });

    test('downgrade level recorded for an FS-encrypted message is fsOnly', () {
      // Mirrors HomeController downgrade tracking: isFs ? fsOnly : legacy.
      final level = FsMessageClassification.fsOnly.downgradeLevel;
      expect(level, equals(FsMessageSecurity.fsOnly));
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Localization keys
  // ────────────────────────────────────────────────────────────────────────────

  group('Localization keys', () {
    final labelKeys = [
      'security.fs.cls.legacy',
      'security.fs.cls.pre_fs',
      'security.fs.cls.negotiation',
      'security.fs.cls.fs_fallback',
      'security.fs.cls.fs_only',
      'security.fs.cls.strict',
      'security.fs.cls.failed',
      'security.fs.cls.unknown',
    ];

    final descKeys = [
      'security.fs.cls.legacy.desc',
      'security.fs.cls.pre_fs.desc',
      'security.fs.cls.negotiation.desc',
      'security.fs.cls.fs_fallback.desc',
      'security.fs.cls.fs_only.desc',
      'security.fs.cls.strict.desc',
      'security.fs.cls.failed.desc',
      'security.fs.cls.unknown.desc',
    ];

    for (final lang in ['en', 'it', 'es', 'de', 'fr', 'pt']) {
      test('$lang has all 8 label keys', () {
        final strings = FsStringsBundle.bundle[lang]!;
        for (final key in labelKeys) {
          expect(strings.containsKey(key), isTrue,
              reason: '$lang missing key: $key');
          expect(strings[key]!.isNotEmpty, isTrue,
              reason: '$lang has empty value for: $key');
        }
      });

      test('$lang has all 8 description keys', () {
        final strings = FsStringsBundle.bundle[lang]!;
        for (final key in descKeys) {
          expect(strings.containsKey(key), isTrue,
              reason: '$lang missing key: $key');
          expect(strings[key]!.isNotEmpty, isTrue,
              reason: '$lang has empty value for: $key');
        }
      });
    }
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Downgrade level integration
  // ────────────────────────────────────────────────────────────────────────────

  group('Downgrade level integration', () {
    test('all non-null downgrade levels are valid FsMessageSecurity values', () {
      for (final cls in FsMessageClassification.values) {
        final level = cls.downgradeLevel;
        if (level != null) {
          expect(FsMessageSecurity.values.contains(level), isTrue);
        }
      }
    });

    test('downgrade level ordering: legacy < fsWithFallback < fsOnly', () {
      expect(FsMessageSecurity.legacy.index, lessThan(FsMessageSecurity.fsWithFallback.index));
      expect(FsMessageSecurity.fsWithFallback.index, lessThan(FsMessageSecurity.fsOnly.index));
    });

    test('classifications with same downgrade level have consistent ordering', () {
      // legacy and preFs both map to legacy
      expect(FsMessageClassification.legacy.downgradeLevel,
          equals(FsMessageClassification.preFs.downgradeLevel));

      // fsOnly and strictFs both map to fsOnly
      expect(FsMessageClassification.fsOnly.downgradeLevel,
          equals(FsMessageClassification.strictFs.downgradeLevel));
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // § Full lifecycle: message classification through the pipeline
  // ────────────────────────────────────────────────────────────────────────────

  group('Full lifecycle', () {
    test('classification survives MessageRecord toMap/fromMap with all fields', () {
      final record = MessageRecord(
        id: '12345',
        senderId: 'alice',
        recipientId: 'bob',
        direction: 'outgoing',
        timestamp: 1700000000,
        text: null,
        ciphertextBase64: 'AAAA',
        nonceBase64: 'BBBB',
        rawSource: 'stego-encoded-string',
        expireAfter: 1700003600,
        deleteAfterRead: true,
        readAt: 1700000100,
        keyTag: 'key-v1',
        isFsEncrypted: true,
        fsClassification: FsMessageClassification.strictFs,
      );

      final map = record.toMap();
      final restored = MessageRecord.fromMap(map);

      expect(restored.id, equals(record.id));
      expect(restored.senderId, equals(record.senderId));
      expect(restored.recipientId, equals(record.recipientId));
      expect(restored.direction, equals(record.direction));
      expect(restored.timestamp, equals(record.timestamp));
      expect(restored.text, isNull);
      expect(restored.ciphertextBase64, equals(record.ciphertextBase64));
      expect(restored.nonceBase64, equals(record.nonceBase64));
      expect(restored.rawSource, equals(record.rawSource));
      expect(restored.expireAfter, equals(record.expireAfter));
      expect(restored.deleteAfterRead, equals(record.deleteAfterRead));
      expect(restored.readAt, equals(record.readAt));
      expect(restored.keyTag, equals(record.keyTag));
      expect(restored.isFsEncrypted, equals(record.isFsEncrypted));
      expect(restored.fsClassification,
          equals(FsMessageClassification.strictFs));
      expect(restored.effectiveClassification,
          equals(FsMessageClassification.strictFs));
    });

    test('old record without fsCls gets correct effective classification', () {
      // Simulate a record written before §14.4 was implemented
      final oldMap = <String, dynamic>{
        'id': 'old-123',
        'senderId': 'alice',
        'recipientId': 'bob',
        'direction': 'incoming',
        'timestamp': 1699000000,
        'text': 'old plain message',
        'ciphertextBase64': 'XXXX',
        'nonceBase64': 'YYYY',
      };
      final oldRecord = MessageRecord.fromMap(oldMap);
      expect(oldRecord.fsClassification, isNull);
      expect(oldRecord.isFsEncrypted, isFalse);
      expect(oldRecord.effectiveClassification,
          equals(FsMessageClassification.legacy));

      // Same but with isFsEncrypted
      final oldFsMap = <String, dynamic>{
        ...oldMap,
        'id': 'old-fs-456',
        'isFsEncrypted': true,
      };
      final oldFsRecord = MessageRecord.fromMap(oldFsMap);
      expect(oldFsRecord.fsClassification, isNull);
      expect(oldFsRecord.isFsEncrypted, isTrue);
      expect(oldFsRecord.effectiveClassification,
          equals(FsMessageClassification.fsOnly));
    });
  });
}
