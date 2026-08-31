import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('crypto and encrypted storage use only secure randomness', () {
    final findings = _scan(
      roots: const ['lib/core/crypto', 'lib/core/storage'],
      rules: [
        _ForbiddenSourceRule(
          RegExp(r'\b(?:math\.)?Random\s*\('),
          'non-cryptographic Random constructor',
        ),
      ],
    );

    expect(
      findings,
      isEmpty,
      reason: 'Cryptographic and encrypted-storage code must use '
          'Random.secure() or an explicitly injected secure source. '
          'Deterministic Random(seed) belongs in tests only.\n'
          '${findings.join('\n')}',
    );
  });

  test('runtime source does not disable transport authentication', () {
    final findings = _scan(
      roots: const [
        'lib',
        'ios/Runner',
        'ios/Share Extension',
        'android/app/src',
        'macos/Runner',
        'linux',
        'windows',
      ],
      rules: [
        _ForbiddenSourceRule(
          RegExp(r'\bbadCertificateCallback\b'),
          'Dart certificate-validation override',
        ),
        _ForbiddenSourceRule(
          RegExp(r'\bHttpOverrides\s*\.\s*global\b'),
          'global Dart HTTP override',
        ),
        _ForbiddenSourceRule(
          RegExp(r'\ballowBadCertificates\b', caseSensitive: false),
          'bad-certificate opt-out',
        ),
        _ForbiddenSourceRule(
          RegExp(r'\bsetAllowsAnyHTTPSCertificate\b'),
          'Apple HTTPS certificate bypass',
        ),
      ],
    );

    expect(
      findings,
      isEmpty,
      reason: 'Certificate validation must never be disabled in Layergram '
          'runtime code.\n${findings.join('\n')}',
    );
  });

  test('crypto core does not depend on plaintext preference storage', () {
    final findings = _scan(
      roots: const ['lib/core/crypto'],
      rules: [
        _ForbiddenSourceRule(
          RegExp(r"package:shared_preferences/"),
          'SharedPreferences dependency in crypto core',
        ),
      ],
    );

    expect(
      findings,
      isEmpty,
      reason: 'The cryptographic core must use its reviewed secure/encrypted '
          'storage boundaries, not plaintext application preferences.\n'
          '${findings.join('\n')}',
    );
  });
}

List<String> _scan({
  required List<String> roots,
  required List<_ForbiddenSourceRule> rules,
}) {
  final repositoryRoot = Directory.current;
  final findings = <String>[];

  for (final relativeRoot in roots) {
    final directory = Directory('${repositoryRoot.path}/$relativeRoot');
    if (!directory.existsSync()) continue;

    for (final entity in directory.listSync(recursive: true)) {
      if (entity is! File || !_isSourceFile(entity.path)) continue;
      final relativePath =
          entity.path.substring(repositoryRoot.path.length + 1);
      final lines = entity.readAsLinesSync();

      for (var index = 0; index < lines.length; index += 1) {
        final code = _withoutLineComment(lines[index]);
        for (final rule in rules) {
          if (rule.pattern.hasMatch(code)) {
            findings.add(
              '$relativePath:${index + 1}: ${rule.description}',
            );
          }
        }
      }
    }
  }

  return findings;
}

bool _isSourceFile(String path) {
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
  final normalized = path.replaceAll('\\', '/');
  if (normalized.contains('/flutter/ephemeral/') ||
      normalized.contains('/GeneratedPluginRegistrant.')) {
    return false;
  }
  return extensions.any(normalized.endsWith);
}

String _withoutLineComment(String line) {
  final comment = line.indexOf('//');
  return comment < 0 ? line : line.substring(0, comment);
}

class _ForbiddenSourceRule {
  const _ForbiddenSourceRule(this.pattern, this.description);

  final RegExp pattern;
  final String description;
}
