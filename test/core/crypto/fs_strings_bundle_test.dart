// Tests for Forward Secrecy localization coverage.
//
// The app must load user-facing Forward Secrecy strings from the main
// `assets/translations/*.json` files. `FsStringsBundle` is kept only as the
// English source inventory for required keys and release gates.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/l10n/app_strings.dart';
import 'package:layergram/l10n/fs_strings_bundle.dart';

void main() {
  const mandatoryKeyPrefixes = [
    'security.fs.status.',
    'security.fs.warning.',
    'security.fs.action.',
    'security.fs.error.',
    'security.fs.info.',
    'security.fs.maximum.',
    'security.passphrase.',
    'security.contact.state.',
  ];

  final source = FsStringsBundle.bundle['en']!;

  test('T9.1: FsStringsBundle is only the English source inventory', () {
    expect(FsStringsBundle.bundle.keys, ['en']);
  });

  test('T9.2: all mandatory key groups present in English source', () {
    final enKeys = source.keys.toList();
    for (final prefix in mandatoryKeyPrefixes) {
      final matching = enKeys.where((key) => key.startsWith(prefix)).toList();
      expect(matching, isNotEmpty,
          reason: 'No English keys found for group "$prefix"');
    }
  });

  test('T9.3: named placeholders are present where expected', () {
    expect(
      source['security.fs.maximum.pending_notice'],
      contains('{contact}'),
    );
    expect(
      source['security.contact.state.session_id'],
      contains('{sessionId}'),
    );
    expect(
      source['security.fs.progress.exchanges_remaining'],
      contains('{n}'),
    );
    expect(
      source['security.fs.mode.current_label'],
      contains('{mode}'),
    );
  });

  test('T9.4: all FS status keys are present in English source', () {
    const statusKeys = [
      'security.fs.status.legacy',
      'security.fs.status.upgrading',
      'security.fs.status.active',
      'security.fs.status.strict',
      'security.fs.status.strict_pending',
      'security.fs.status.suspended',
      'security.fs.status.broken',
    ];
    for (final key in statusKeys) {
      expect(source, contains(key), reason: 'Missing status key: $key');
      expect(source[key], isNotEmpty, reason: 'Empty value for: $key');
    }
  });

  test('T9.5: every supported locale has a main translation file', () {
    final expected = _supportedLocaleFileNames();
    final actual = _translationFiles()
        .map((file) => file.uri.pathSegments.last.replaceAll('.json', ''))
        .toSet();

    expect(actual, containsAll(expected));
    expect(expected, containsAll(actual));
  });

  test('T9.6: every translation file contains every FS source key', () {
    for (final file in _translationFiles()) {
      final locale = file.uri.pathSegments.last;
      final data = _readTranslation(file);
      for (final key in source.keys) {
        expect(data, contains(key), reason: '$locale missing key: $key');
        expect((data[key] as String).trim(), isNotEmpty,
            reason: '$locale has empty value for: $key');
      }
    }
  });

  test('T9.7: placeholders match the English source in every translation', () {
    for (final file in _translationFiles()) {
      final locale = file.uri.pathSegments.last;
      final data = _readTranslation(file);
      for (final entry in source.entries) {
        expect(
          _placeholders(data[entry.key] as String),
          _placeholders(entry.value),
          reason: '$locale placeholder mismatch for ${entry.key}',
        );
      }
    }
  });

  test('T9.8: no FS translation is a passthrough key', () {
    for (final file in _translationFiles()) {
      final locale = file.uri.pathSegments.last;
      final data = _readTranslation(file);
      for (final key in source.keys) {
        expect(data[key], isNot(equals(key)),
            reason: '$locale value equals key: $key');
      }
    }
  });

  test('T9.9: all security keys referenced by app code are translated', () {
    final referenced = _securityKeysReferencedByApp();
    expect(referenced, isNotEmpty);
    for (final key in referenced) {
      expect(source, contains(key),
          reason: 'Referenced key missing from FS source inventory: $key');
    }

    for (final file in _translationFiles()) {
      final locale = file.uri.pathSegments.last;
      final data = _readTranslation(file);
      for (final key in referenced) {
        expect(data, contains(key), reason: '$locale missing key: $key');
      }
    }
  });

  test('T9.10: notForMe copy does not reveal payload existence or identity fit',
      () {
    final en = _readTranslation(File('assets/translations/en.json'));
    final it = _readTranslation(File('assets/translations/it.json'));

    expect(
      en['security.message_not_for_me'],
      equals('No decodable Layergram message found.'),
    );
    expect(
      (it['security.message_not_for_me'] as String).toLowerCase(),
      contains('layergram'),
    );

    for (final file in _translationFiles()) {
      final value =
          (_readTranslation(file)['security.message_not_for_me'] as String)
              .toLowerCase();
      expect(value, isNot(contains('found, but')));
      expect(value, isNot(contains('not encrypted')));
      expect(value, isNot(contains('questa identità')));
      expect(value, isNot(contains('stessa impronta')));
    }
  });

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
        expect(source, isNot(contains(fragment)),
            reason: '$path must not expose "$fragment"');
      }
    }
  });

  test('T9.12: app startup does not register the FS bundle at runtime', () {
    final main = File('lib/main.dart').readAsStringSync();
    expect(main, isNot(contains('FsStringsBundle')));
    expect(main, isNot(contains('registerStrings(FsStringsBundle.bundle)')));
  });

  test('T9.13: send-blocking FS messages are localizable keys', () {
    const forbiddenRuntimeFragments = [
      'Maximum Forward Secrecy prevents sending in current state',
      'Maximum Forward Secrecy requires device repair before sending',
      'Unexpected device detected — repair required before sending',
      'Session is broken and cannot be used',
    ];

    for (final file in _dartLibFiles()) {
      final path = file.path.replaceAll('\\', '/');
      if (path.endsWith('lib/l10n/fs_strings_bundle.dart')) continue;
      final contents = file.readAsStringSync();
      for (final fragment in forbiddenRuntimeFragments) {
        expect(contents, isNot(contains(fragment)),
            reason: '$path contains hardcoded FS copy: $fragment');
      }
    }
  });
}

Map<String, dynamic> _readTranslation(File file) {
  return jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
}

List<File> _translationFiles() {
  return Directory('assets/translations')
      .listSync()
      .whereType<File>()
      .where((file) => file.path.endsWith('.json'))
      .toList()
    ..sort((a, b) => a.path.compareTo(b.path));
}

Set<String> _supportedLocaleFileNames() {
  return AppStrings.supportedLocales.map((locale) {
    final country = locale.countryCode;
    if (country == null || country.isEmpty) {
      return locale.languageCode;
    }
    return '${locale.languageCode}_$country';
  }).toSet();
}

Set<String> _placeholders(String value) {
  return RegExp(r'\{[A-Za-z0-9_]+\}')
      .allMatches(value)
      .map((match) => match.group(0)!)
      .toSet();
}

Set<String> _securityKeysReferencedByApp() {
  final keyPattern = RegExp(
    r"'(security\.(?:fs|passphrase|pp|warn|cleanup|contact\.state|message_not_for_me)[^']*)'",
  );
  final keys = <String>{};
  for (final file in _dartLibFiles()) {
    if (file.path.endsWith('lib/l10n/fs_strings_bundle.dart')) continue;
    final source = file.readAsStringSync();
    for (final match in keyPattern.allMatches(source)) {
      keys.add(match.group(1)!);
    }
  }
  return keys;
}

List<File> _dartLibFiles() {
  return Directory('lib')
      .listSync(recursive: true)
      .whereType<File>()
      .where((file) => file.path.endsWith('.dart'))
      .toList();
}
