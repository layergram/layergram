// Tests for FsStringsBundle and FsStatusIcon API — Phase 9.
//
// Mandatory tests (roadmap §12 Phase 9):
//
//  T9.1  All keys in non-English locales exist in the English (source) bundle.
//  T9.2  All mandatory key groups are present in the English bundle.
//  T9.3  Named args placeholders ({contact}, {sessionId}) present in relevant keys.
//  T9.4  No hardcoded English strings in FsStatusIcon (uses key lookup).
//  T9.5  AppStrings.registerStrings accepts the bundle without throwing.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/l10n/app_strings.dart';
import 'package:layergram/l10n/fs_strings_bundle.dart';

void main() {
  // Required key groups (spec §9.5).
  const mandatoryKeyPrefixes = [
    'security.fs.status.',
    'security.fs.warning.',
    'security.fs.action.',
    'security.fs.info.',
    'security.fs.maximum.',
    'security.passphrase.',
    'security.contact.state.',
  ];

  const en0 = FsStringsBundle.bundle;

  // T9.1 — All keys in non-English locales also exist in English.
  test('T9.1: all non-English locale keys have an English fallback', () {
    final enKeys = (en0['en'] ?? {}).keys.toSet();
    for (final entry in en0.entries) {
      if (entry.key == 'en') continue;
      for (final key in entry.value.keys) {
        expect(enKeys, contains(key),
            reason:
                'Key "$key" in locale "${entry.key}" has no English fallback');
      }
    }
  });

  // T9.2 — All mandatory key groups present in English bundle.
  test('T9.2: all mandatory key groups present in English bundle', () {
    final enKeys = (en0['en'] ?? {}).keys.toList();
    for (final prefix in mandatoryKeyPrefixes) {
      final matching = enKeys.where((k) => k.startsWith(prefix)).toList();
      expect(matching, isNotEmpty,
          reason: 'No English keys found for group "$prefix"');
    }
  });

  // T9.3 — Named placeholders are present where expected.
  test('T9.3: named placeholder {contact} in maximum.pending_notice', () {
    final en = en0['en']!;
    expect(
      en['security.fs.maximum.pending_notice'],
      contains('{contact}'),
      reason: 'pending_notice must contain {contact} placeholder',
    );
    expect(
      en['security.contact.state.session_id'],
      contains('{sessionId}'),
      reason: 'session_id must contain {sessionId} placeholder',
    );
  });

  // T9.4 — Key completeness: all status states covered.
  test('T9.4: all FS status keys are present in English bundle', () {
    final en = en0['en']!;
    const statusKeys = [
      'security.fs.status.legacy',
      'security.fs.status.upgrading',
      'security.fs.status.active',
      'security.fs.status.strict',
      'security.fs.status.suspended',
      'security.fs.status.broken',
    ];
    for (final key in statusKeys) {
      expect(en, contains(key), reason: 'Missing status key: $key');
      expect(en[key], isNotEmpty, reason: 'Empty value for: $key');
    }
  });

  // T9.5 — AppStrings.registerStrings accepts the bundle without throwing.
  test('T9.5: AppStrings.registerStrings accepts FsStringsBundle without error',
      () {
    expect(
      () => AppStrings.registerStrings(FsStringsBundle.bundle),
      returnsNormally,
      reason: 'registerStrings must accept the FS bundle without throwing',
    );
  });

  // T9.6 — Warning keys are non-empty in English.
  test('T9.6: all warning keys are non-empty in English', () {
    final en = en0['en']!;
    const warningKeys = [
      'security.fs.warning.recoverability',
      'security.fs.warning.device_bound',
      'security.fs.warning.pending_activation',
      'security.fs.warning.fallback_allowed',
      'security.fs.warning.no_silent_downgrade',
    ];
    for (final key in warningKeys) {
      expect(en, contains(key), reason: 'Missing warning key: $key');
      expect(
        (en[key] ?? '').length,
        greaterThan(20),
        reason: 'Warning key "$key" is suspiciously short',
      );
    }
  });

  // T9.7 — Info modal keys present.
  test('T9.7: info modal keys present in English bundle', () {
    final en = en0['en']!;
    const infoKeys = [
      'security.fs.info.title',
      'security.fs.info.legacy_description',
      'security.fs.info.active_description',
      'security.fs.info.active_advantage',
      'security.fs.info.strict_description',
      'security.fs.info.broken_description',
      'security.fs.info.upgrading_description',
    ];
    for (final key in infoKeys) {
      expect(en, contains(key), reason: 'Missing info key: $key');
    }
  });

  // T9.8 — All locale entries are present in the bundle map.
  test('T9.8: bundle contains expected locale codes', () {
    const expectedLocales = ['en', 'it', 'es', 'de', 'fr', 'pt'];
    for (final locale in expectedLocales) {
      expect(
        FsStringsBundle.bundle,
        contains(locale),
        reason: 'Missing locale: $locale',
      );
    }
  });

  // T9.9 — No key value equals the key itself (placeholder check).
  test('T9.9: no English value equals its key (not a passthrough)', () {
    final en = en0['en']!;
    for (final entry in en.entries) {
      expect(
        entry.value,
        isNot(equals(entry.key)),
        reason: 'Value equals key (untranslated): ${entry.key}',
      );
    }
  });

  // T9.10 — Decode failures must not reveal payload existence or identity fit.
  test('T9.10: notForMe copy is indistinguishable from generic no-data', () {
    final en = en0['en']!;
    final it = en0['it']!;

    expect(
      en['security.message_not_for_me'],
      equals('No decodable Layergram message found.'),
    );
    expect(
      it['security.message_not_for_me'],
      equals('Nessun messaggio Layergram decifrabile trovato.'),
    );

    for (final value in [
      en['security.message_not_for_me']!,
      it['security.message_not_for_me']!,
    ]) {
      expect(value.toLowerCase(), isNot(contains('found, but')));
      expect(value.toLowerCase(), isNot(contains('not encrypted')));
      expect(value.toLowerCase(), isNot(contains('questa identità')));
      expect(value.toLowerCase(), isNot(contains('stessa impronta')));
    }
  });

  // T9.11 — Public decode surfaces must not reintroduce the old oracle text.
  test('T9.11: public decode UI does not leak notForMe details', () {
    const publicDecodeFiles = [
      'lib/app.dart',
      'lib/features/home/home_view.dart',
      'lib/features/home/chat_view.dart',
      'lib/features/home/decode_view.dart',
      'lib/l10n/fs_strings_bundle.dart',
    ];
    const forbiddenFragments = [
      'Layergram message found, but',
      'Messaggio Layergram trovato',
      'not encrypted for this identity',
      'non è cifrato per questa identità',
      'Check that this device and contact use the same identity fingerprint.',
      'Verifica che questo dispositivo e il contatto usino la stessa impronta.',
    ];

    for (final path in publicDecodeFiles) {
      final source = File(path).readAsStringSync();
      for (final fragment in forbiddenFragments) {
        expect(
          source,
          isNot(contains(fragment)),
          reason: '$path must not expose "$fragment"',
        );
      }
    }
  });
}
