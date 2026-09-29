import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('runtime source does not contain direct diagnostic logging', () {
    final root = Directory.current;
    final findings = <String>[];

    for (final file in _runtimeSourceFiles(root)) {
      final relativePath = file.path.substring(root.path.length + 1);
      final lines = file.readAsLinesSync();

      for (var index = 0; index < lines.length; index += 1) {
        final line = lines[index];
        for (final rule in _forbiddenLogRules) {
          if (rule.pattern.hasMatch(line)) {
            findings.add(
              '$relativePath:${index + 1}: ${rule.description}',
            );
          }
        }
      }
    }

    expect(
      findings,
      isEmpty,
      reason: 'Runtime logs can expose message content, Layergram links, '
          'ciphertexts, keys, fingerprints, or FS negotiation state. Use '
          'user-visible errors or explicitly reviewed redacted telemetry '
          'instead.\n${findings.join('\n')}',
    );
  });

  test('Android QA source sets stay outside the release logging audit', () {
    final fixture = Directory.systemTemp.createTempSync(
      'layergram-runtime-logging-audit-',
    );
    addTearDown(() => fixture.deleteSync(recursive: true));

    final sources = <String>[
      'android/app/src/main/kotlin/app/layergram/Main.kt',
      'android/app/src/profile/kotlin/app/layergram/ProfileTrace.kt',
      'android/app/src/androidTest/kotlin/app/layergram/ProbeTest.kt',
    ];
    for (final source in sources) {
      final file = File('${fixture.path}/$source');
      file.parent.createSync(recursive: true);
      file.writeAsStringSync('Log.i("LayergramKeyboardQA", "safeStage")');
    }

    final audited = _runtimeSourceFiles(fixture)
        .map((file) => file.path.substring(fixture.path.length + 1))
        .toList();

    expect(
      audited,
      ['android/app/src/main/kotlin/app/layergram/Main.kt'],
    );
  });
}

Iterable<File> _runtimeSourceFiles(Directory root) sync* {
  const roots = [
    'lib',
    'ios/Runner',
    'ios/Share Extension',
    'android/app/src',
    'macos/Runner',
    'linux',
    'windows',
  ];

  const extensions = {
    '.dart',
    '.swift',
    '.kt',
    '.java',
    '.m',
    '.mm',
    '.c',
    '.cc',
    '.cpp',
    '.h',
    '.hpp',
  };

  for (final relativeRoot in roots) {
    final directory = Directory('${root.path}/$relativeRoot');
    if (!directory.existsSync()) continue;

    for (final entity in directory.listSync(recursive: true)) {
      if (entity is! File) continue;
      final normalizedPath = entity.path.replaceAll('\\', '/');
      if (!extensions.any(normalizedPath.endsWith)) continue;
      if (normalizedPath.contains('/android/app/src/androidTest/')) continue;
      if (normalizedPath.contains('/android/app/src/profile/')) continue;
      if (normalizedPath.contains('/flutter/ephemeral/')) continue;
      if (normalizedPath.contains('/GeneratedPluginRegistrant.')) continue;
      yield entity;
    }
  }
}

final _forbiddenLogRules = [
  _ForbiddenLogRule(
    RegExp(r'(?<![A-Za-z0-9_])print\s*\('),
    'Dart/Swift/C-style print',
  ),
  _ForbiddenLogRule(
    RegExp(r'\bdebugPrint\s*\('),
    'Flutter debugPrint',
  ),
  _ForbiddenLogRule(
    RegExp(r'\bdeveloper\s*\.\s*log\s*\('),
    'dart:developer log',
  ),
  _ForbiddenLogRule(
    RegExp(r'\bNSLog\s*\('),
    'Apple NSLog',
  ),
  _ForbiddenLogRule(
    RegExp(r'\bconsole\s*\.\s*log\s*\('),
    'JavaScript console.log',
  ),
  _ForbiddenLogRule(
    RegExp(r'\bLog\s*\.\s*[divwe]\s*\('),
    'Android Log.d/i/v/w/e',
  ),
];

class _ForbiddenLogRule {
  const _ForbiddenLogRule(this.pattern, this.description);

  final RegExp pattern;
  final String description;
}
