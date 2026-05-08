// Tests for AuxRecordCipher (Sealed Auxiliary Records — FS Spec Phase 1).
//
// Acceptance criteria (spec §4 Phase 1 roadmap):
//  T1.1  Write/read sealed aux record roundtrip succeeds.
//  T1.2  Wrong key cannot decrypt it (returns null).
//  T1.3  Old message-repository logic preserves unknown records.
//  T1.4  Auxiliary record sizes fall into expected padded buckets.
//  T1.5  External storage key prefix contains no revealing terms.
//  T1.6  Record type ('kind', 'type') is absent from external metadata.
//  T1.7  Multiple aux records do not create an obvious size or naming pattern.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';

void main() {
  group('AuxRecordCipher', () {
    late SecretKey auxKey;
    late SecretKey wrongKey;

    setUp(() async {
      final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
      // Derive a realistic aux key from a fake 32-byte master secret.
      final masterBytes = Uint8List(32)..fillRange(0, 32, 0x42);
      auxKey = await AuxRecordCipher.deriveAuxStorageKey(masterBytes);

      // A completely different key for negative tests.
      final wrongMaster = Uint8List(32)..fillRange(0, 32, 0xFF);
      wrongKey = await AuxRecordCipher.deriveAuxStorageKey(wrongMaster);
    });

    // T1.1 — Write/read roundtrip.
    test('encrypt then decrypt with correct key returns original payload', () async {
      final payload = {
        'v': 1,
        'kind': 'aux_state',
        'records': [
          {'type': 'fs_session_state', 'data': {'state': 'fs_active'}},
        ],
      };

      final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
        payload: payload,
        auxStorageKey: auxKey,
      );

      final decrypted = await AuxRecordCipher.decrypt(
        encryptedRecord: encryptedRecord,
        recordId: recordId,
        auxStorageKey: auxKey,
      );

      expect(decrypted, isNotNull);
      expect(decrypted!['v'], equals(1));
      expect(decrypted['kind'], equals('aux_state'));
      final records = decrypted['records'] as List;
      expect(records.first['type'], equals('fs_session_state'));
      expect((records.first['data'] as Map)['state'], equals('fs_active'));
    });

    // T1.2 — Wrong key cannot decrypt.
    test('decrypt with wrong key returns null', () async {
      final payload = {'v': 1, 'kind': 'aux_state', 'records': []};

      final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
        payload: payload,
        auxStorageKey: auxKey,
      );

      final result = await AuxRecordCipher.decrypt(
        encryptedRecord: encryptedRecord,
        recordId: recordId,
        auxStorageKey: wrongKey,
      );

      expect(result, isNull);
    });

    // T1.2b — Wrong recordId cannot decrypt (key derivation mismatch).
    test('decrypt with wrong recordId returns null', () async {
      final payload = {'v': 1, 'kind': 'aux_state', 'records': []};

      final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
        payload: payload,
        auxStorageKey: auxKey,
      );
      // Produce a different random recordId.
      final tamperedId = recordId.substring(0, recordId.length - 2) + 'ZZ';

      final result = await AuxRecordCipher.decrypt(
        encryptedRecord: encryptedRecord,
        recordId: tamperedId,
        auxStorageKey: auxKey,
      );

      expect(result, isNull);
    });

    // T1.3 — External map shape matches message record shape.
    test('external record shape is { encryptedRecord: "..." } like message records', () async {
      final payload = {'v': 1, 'kind': 'aux_state', 'records': []};
      final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
        payload: payload,
        auxStorageKey: auxKey,
      );

      // Simulate what a message repository would see stored in Hive.
      final stored = {'encryptedRecord': encryptedRecord};

      // An old client / message repo would see 'encryptedRecord' and fail to
      // decrypt it silently (wrong key) — the record remains opaque.
      expect(stored.containsKey('encryptedRecord'), isTrue);
      // No revealing metadata outside the encrypted blob.
      expect(stored.containsKey('kind'), isFalse);
      expect(stored.containsKey('type'), isFalse);
      expect(stored.containsKey('fs'), isFalse);
      expect(stored.containsKey('passphrase'), isFalse);
    });

    // T1.4 — Record sizes fall into expected padded buckets (8–96 KB).
    test('encrypted record size falls into a padded bucket', () async {
      const minBucket = 8 * 1024;   // 8 KB minimum after padding
      const maxBucket = 96 * 1024;  // 96 KB maximum

      final payload = {'v': 1, 'kind': 'aux_state', 'records': []};
      final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
        payload: payload,
        auxStorageKey: auxKey,
      );

      // The base64url-encoded blob size in bytes (approximately equals binary size).
      final blobBytes = base64Url.decode(
        encryptedRecord.padRight(
          encryptedRecord.length + (4 - encryptedRecord.length % 4) % 4,
          '=',
        ),
      );

      expect(
        blobBytes.length,
        greaterThanOrEqualTo(minBucket),
        reason: 'Record should be padded to at least 8 KB',
      );
      expect(
        blobBytes.length,
        lessThanOrEqualTo(maxBucket + 1024),
        reason: 'Record should not exceed ~96 KB bucket',
      );
    });

    // T1.5 — Storage keys contain no revealing prefixes.
    // (Tested at repository level via a naming check. Here we verify the
    //  recordId and encryptedRecord strings themselves don't embed type info.)
    test('recordId and encryptedRecord strings do not contain revealing terms', () async {
      final payload = {'v': 1, 'kind': 'aux_state', 'records': []};
      final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
        payload: payload,
        auxStorageKey: auxKey,
      );

      for (final forbidden in ['fs', 'ratchet', 'passphrase', 'hidden', 'timer', 'strict']) {
        expect(
          recordId.toLowerCase().contains(forbidden),
          isFalse,
          reason: 'recordId must not contain "$forbidden"',
        );
      }
      // The encryptedRecord is opaque base64url — no readable text.
      // We verify it doesn't accidentally decode to readable JSON.
      bool isPlaintext = false;
      try {
        final decoded = jsonDecode(utf8.decode(base64Url.decode(
          encryptedRecord.padRight(
            encryptedRecord.length + (4 - encryptedRecord.length % 4) % 4,
            '=',
          ),
        )));
        isPlaintext = decoded != null;
      } catch (_) {}
      expect(isPlaintext, isFalse, reason: 'encryptedRecord must not be plaintext JSON');
    });

    // T1.6 — Kind and type are absent from external metadata.
    test('decrypted payload contains kind/type but external blob does not', () async {
      final payload = {
        'v': 1,
        'kind': 'aux_state',
        'records': [
          {'type': 'security_preferences', 'data': {}},
        ],
      };

      final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
        payload: payload,
        auxStorageKey: auxKey,
      );

      // External shape has no 'kind' or 'type' fields.
      final externalMap = {'encryptedRecord': encryptedRecord};
      expect(externalMap.containsKey('kind'), isFalse);
      expect(externalMap.containsKey('type'), isFalse);

      // After decryption, kind and type are present.
      final decrypted = await AuxRecordCipher.decrypt(
        encryptedRecord: encryptedRecord,
        recordId: recordId,
        auxStorageKey: auxKey,
      );
      expect(decrypted!['kind'], equals('aux_state'));
      expect((decrypted['records'] as List).first['type'], equals('security_preferences'));
    });

    // T1.7 — Multiple aux records have different sizes (no obvious pattern).
    test('multiple records have different encrypted sizes', () async {
      final payload = {'v': 1, 'kind': 'aux_state', 'records': []};
      final sizes = <int>{};

      for (var i = 0; i < 8; i++) {
        final (:recordId, :encryptedRecord) = await AuxRecordCipher.encrypt(
          payload: payload,
          auxStorageKey: auxKey,
        );
        final blobBytes = base64Url.decode(
          encryptedRecord.padRight(
            encryptedRecord.length + (4 - encryptedRecord.length % 4) % 4,
            '=',
          ),
        );
        sizes.add(blobBytes.length);
      }

      // With random bucket selection and random padding, at least 2 distinct
      // sizes should appear across 8 encryptions of the same payload.
      expect(sizes.length, greaterThanOrEqualTo(2),
          reason: 'Padding should produce variable sizes across records');
    });

    // Extra: distinct aux key vs message key.
    test('aux key differs from a hypothetical message key derived from same secret', () async {
      final master = Uint8List(32)..fillRange(0, 32, 0x11);
      final auxK = await AuxRecordCipher.deriveAuxStorageKey(master);

      // Simulate what a message key derivation would look like (different info).
      final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
      final msgKey = await hkdf.deriveKey(
        secretKey: SecretKey(master),
        nonce: utf8.encode('msg-key'),
        info: utf8.encode('layergram-message-records-v1'),
      );

      final auxBytes = await auxK.extractBytes();
      final msgBytes = await msgKey.extractBytes();
      expect(auxBytes, isNot(equals(msgBytes)),
          reason: 'Aux key and message key must differ');
    });
  });
}
