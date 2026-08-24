import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/protocol_v3_activation.dart';

String _normalized(String value) => value
    .replaceAll(RegExp(r'[`*_]'), '')
    .replaceAll(RegExp(r'\s+'), ' ')
    .trim();

void main() {
  test('public documentation describes active protocol v3 honestly', () {
    final readme = _normalized(File('README.md').readAsStringSync());
    final migration = _normalized(
      File('specs/PROTOCOL_V3_MIGRATION.md').readAsStringSync(),
    );

    expect(ProtocolV3Activation.identitySharing, isTrue);
    expect(ProtocolV3Activation.messaging, isTrue);
    expect(ProtocolV3Activation.productionApproved, isTrue);
    expect(ProtocolV3Activation.isActive, isTrue);

    expect(readme, contains('Protocol v3 Post-Quantum Protection'));
    expect(
      readme,
      contains('active in Layergram 2.0 and later'),
    );
    expect(
      migration,
      contains('active protocol v3'),
    );
  });

  test('migration contract preserves recovery but never v2 trust state', () {
    final migration = _normalized(
      File('specs/PROTOCOL_V3_MIGRATION.md').readAsStringSync(),
    );

    expect(migration, contains('same 24-word BIP39 recovery phrase'));
    expect(migration, contains('new v3 cryptographic key material'));
    expect(migration, contains('Verify the new fingerprint or SAS'));
    expect(migration, contains('verification badges are not promoted'));
    expect(migration, contains('v2 user-message sending is blocked'));
    expect(migration, contains('must never be sent to a contact'));
  });

  test('migration contract preserves every identity and message carrier', () {
    final migration = _normalized(
      File('specs/PROTOCOL_V3_MIGRATION.md').readAsStringSync(),
    );

    expect(migration, contains('Complete canonical v3 public identity'));
    expect(migration, contains('one static QR code'));
    expect(migration, contains('direct ciphertext text'));
    expect(migration, contains('message deep-link prefix'));
    expect(migration, contains('zero-width steganography'));
    expect(migration, contains('at most 4,000 characters'));
    expect(migration, contains('lost, delayed, duplicated'));
  });

  test('identity QR documentation stays aligned with the physical gate', () {
    final draft = _normalized(
      File('specs/PROTOCOL_V3_DRAFT.md').readAsStringSync(),
    );
    final migration = _normalized(
      File('specs/PROTOCOL_V3_MIGRATION.md').readAsStringSync(),
    );

    expect(draft, contains('error-correction level M'));
    expect(draft, contains('QR version 30'));
    expect(draft, contains('four-module quiet zone'));
    expect(draft, contains('20% of the complete symbol side'));
    expect(draft, contains('1,024 x 1,024 pixels'));
    expect(migration, contains('temporary 60% brightness floor'));
    expect(migration, contains('at least 35 mm per side'));
    expect(draft, isNot(contains('QR version 40')));
    expect(draft, isNot(contains('7.5% of the symbol side')));
  });

  test('migration contract preserves mode and passphrase boundaries', () {
    final migration = _normalized(
      File('specs/PROTOCOL_V3_MIGRATION.md').readAsStringSync(),
    );

    expect(migration, contains('Normal is the default'));
    expect(migration, contains('exactly one exclusive authenticated'));
    expect(migration, contains('Each mnemonic/passphrase context'));
    expect(migration, contains('plausible deniability'));
    expect(migration, contains('must not create a different wire protocol'));
  });
}
